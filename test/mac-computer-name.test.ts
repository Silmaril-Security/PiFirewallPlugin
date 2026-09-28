import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  computerNameCachePath,
  createMacComputerNameSource,
  sanitizeDeviceName,
  type MacComputerNameSpawn,
  type MacComputerNameSpawnOptions,
} from "../src/mac-computer-name.ts";

const FIVE_MINUTES_MS = 5 * 60 * 1000;

function tempCache(): string {
  return mkdtempSync(path.join(os.tmpdir(), "silmaril-computer-name-"));
}

test("sanitizeDeviceName rejects C0, DEL, and C1 controls", () => {
  assert.equal(sanitizeDeviceName("  Office Mac \n"), "Office Mac");
  assert.equal(sanitizeDeviceName("a".repeat(256)), "a".repeat(256));
  assert.equal(sanitizeDeviceName("😀".repeat(128)), "😀".repeat(128));
  assert.equal(sanitizeDeviceName("Office\u00A0Mac"), "Office\u00A0Mac");
  assert.equal(sanitizeDeviceName("   "), undefined);
  assert.equal(sanitizeDeviceName("a".repeat(257)), undefined);
  assert.equal(sanitizeDeviceName(`${"😀".repeat(128)}x`), undefined);
  assert.equal(sanitizeDeviceName("Office\u0000Mac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u001FMac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u007FMac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u0080Mac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u0085Mac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u009FMac"), undefined);
  assert.equal(sanitizeDeviceName("Office\nMac"), undefined);
  assert.equal(sanitizeDeviceName(42), undefined);
});

test("darwin lookup accepts scutil ComputerName and caches it for five minutes", () => {
  let now = 1_000;
  const calls: Array<{ command: string; args: readonly string[]; options: MacComputerNameSpawnOptions }> = [];
  const spawn: MacComputerNameSpawn = (command, args, options) => {
    calls.push({ command, args, options });
    return { status: 0, stdout: Buffer.from("  Office Mac \n") };
  };
  const read = createMacComputerNameSource({
    platform: () => "darwin",
    now: () => now,
    spawn,
    cacheDirectory: tempCache(),
  });

  assert.equal(read(), "Office Mac");
  now = 1_000 + FIVE_MINUTES_MS - 1;
  assert.equal(read(), "Office Mac");
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], {
    command: "/usr/sbin/scutil",
    args: ["--get", "ComputerName"],
    options: {
      timeout: 100,
      maxBuffer: 1024,
      encoding: "buffer",
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
    },
  });

  now = 1_000 + FIVE_MINUTES_MS;
  assert.equal(read(), "Office Mac");
  assert.equal(calls.length, 2);
});

test("lookup failures and invalid output are omitted and do not respawn inside the cache window", () => {
  let now = 0;
  let mode: "throw" | "status" | "timeout" | "overflow" | "blank" | "control" | "long" | "bytes" | "utf8" | "c1" = "throw";
  let calls = 0;
  const spawn: MacComputerNameSpawn = () => {
    calls += 1;
    if (mode === "throw") throw new Error("ComputerName Office Mac");
    if (mode === "status") return { status: 1, stdout: Buffer.from("Office Mac\n") };
    if (mode === "timeout") {
      return { status: null, error: new Error("ETIMEDOUT"), stdout: Buffer.from("Office Mac\n") };
    }
    if (mode === "overflow") {
      return {
        status: null,
        error: Object.assign(new Error("stdout maxBuffer length exceeded"), { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" }),
        stdout: Buffer.from("Office Mac"),
      };
    }
    if (mode === "blank") return { status: 0, stdout: Buffer.from(" \n\t") };
    if (mode === "control") return { status: 0, stdout: Buffer.from("Office\u0001Mac\n") };
    if (mode === "c1") return { status: 0, stdout: Buffer.from("Office\u0085Mac\n") };
    if (mode === "long") return { status: 0, stdout: Buffer.from(`${"a".repeat(257)}\n`) };
    if (mode === "bytes") return { status: 0, stdout: Buffer.alloc(1025, 0x20) };
    return { status: 0, stdout: Buffer.from([0xc3, 0x28]) };
  };

  for (const current of ["throw", "status", "timeout", "overflow", "blank", "control", "c1", "long", "bytes", "utf8"] as const) {
    mode = current;
    calls = 0;
    now = 0;
    const cacheDirectory = tempCache();
    const source = createMacComputerNameSource({
      platform: () => "darwin",
      now: () => now,
      spawn,
      cacheDirectory,
    });
    assert.equal(source(), undefined, current);
    assert.equal(source(), undefined, current);
    assert.equal(calls, 1, current);
    assert.doesNotMatch(readFileSync(computerNameCachePath(cacheDirectory), "utf8"), /Office|Mac|\u0001|\u0085/u, current);
    now = FIVE_MINUTES_MS;
    assert.equal(source(), undefined, current);
    assert.equal(calls, 2, current);
  }
});

test("separate processes share a private cache and refresh a renamed computer after five minutes", () => {
  const cacheDirectory = tempCache();
  const spawnLog = path.join(cacheDirectory, "spawns.txt");
  const first = runLookupProcess({ cacheDirectory, spawnLog, now: 1_000, name: "Office Mac" });
  const cached = runLookupProcess({ cacheDirectory, spawnLog, now: 1_000 + FIVE_MINUTES_MS - 1, name: "Renamed Mac" });
  const renamed = runLookupProcess({ cacheDirectory, spawnLog, now: 1_000 + FIVE_MINUTES_MS, name: "Renamed Mac" });

  assert.equal(first.status, 0, first.stderr);
  assert.equal(cached.status, 0, cached.stderr);
  assert.equal(renamed.status, 0, renamed.stderr);
  assert.equal(first.stdout, "Office Mac");
  assert.equal(cached.stdout, "Office Mac");
  assert.equal(renamed.stdout, "Renamed Mac");
  assert.equal(readFileSync(spawnLog, "utf8"), "spawn\nspawn\n");
  assert.equal(lstatSync(cacheDirectory).mode & 0o777, 0o700);
  assert.equal(lstatSync(computerNameCachePath(cacheDirectory)).mode & 0o777, 0o600);
  assert.equal(lstatSync(computerNameCachePath(cacheDirectory)).isSymbolicLink(), false);
});

test("a failed lookup is cached across processes without a second scutil launch", () => {
  const cacheDirectory = tempCache();
  const spawnLog = path.join(cacheDirectory, "spawns.txt");
  const failed = runLookupProcess({ cacheDirectory, spawnLog, now: 5_000, name: "Office Mac", mode: "fail" });
  const skipped = runLookupProcess({ cacheDirectory, spawnLog, now: 5_000, name: "Office Mac", mode: "fail" });

  assert.equal(failed.status, 0, failed.stderr);
  assert.equal(skipped.status, 0, skipped.stderr);
  assert.equal(failed.stdout, "");
  assert.equal(skipped.stdout, "");
  assert.equal(readFileSync(spawnLog, "utf8"), "spawn\n");
  assert.doesNotMatch(failed.stderr + skipped.stderr, /Office Mac/u);
  assert.doesNotMatch(readFileSync(computerNameCachePath(cacheDirectory), "utf8"), /Office Mac/u);
});

test("cached control characters and untrusted cache files do not bypass scutil", () => {
  for (const planted of ["Office\u0000Mac", "Office\u007FMac", "Office\u0085Mac"]) {
    const cacheDirectory = tempCache();
    let calls = 0;
    plantCache(cacheDirectory, { expiresAt: 10_000, name: planted });
    const read = createMacComputerNameSource({
      platform: () => "darwin",
      now: () => 1_000,
      cacheDirectory,
      spawn: () => {
        calls += 1;
        return { status: 0, stdout: Buffer.from("Office Mac\n") };
      },
    });
    assert.equal(read(), "Office Mac", planted);
    assert.equal(calls, 1, planted);
  }

  const looseDirectory = tempCache();
  let looseCalls = 0;
  plantCache(looseDirectory, { expiresAt: 10_000, name: "Spoofed Host" });
  chmodSync(computerNameCachePath(looseDirectory), 0o644);
  const loose = createMacComputerNameSource({
    platform: () => "darwin",
    now: () => 1_000,
    cacheDirectory: looseDirectory,
    spawn: () => {
      looseCalls += 1;
      return { status: 0, stdout: Buffer.from("Office Mac\n") };
    },
  });
  assert.equal(loose(), "Office Mac");
  assert.equal(looseCalls, 1);

  const linkedRoot = tempCache();
  const realDirectory = path.join(linkedRoot, "real");
  const linkDirectory = path.join(linkedRoot, "link");
  mkdirSync(realDirectory);
  symlinkSync(realDirectory, linkDirectory);
  let linkCalls = 0;
  const linked = createMacComputerNameSource({
    platform: () => "darwin",
    now: () => 1_000,
    cacheDirectory: linkDirectory,
    spawn: () => {
      linkCalls += 1;
      return { status: 0, stdout: Buffer.from("Office Mac\n") };
    },
  });
  assert.equal(linked(), "Office Mac");
  assert.equal(linkCalls, 1);
  assert.equal(lstatSync(realDirectory).isDirectory(), true);
  assert.throws(() => lstatSync(computerNameCachePath(realDirectory)));
});

test("non-darwin lookups do not spawn or reuse a cached mac name", () => {
  let platform = "linux";
  let calls = 0;
  const cacheDirectory = tempCache();
  const spawn: MacComputerNameSpawn = () => {
    calls += 1;
    return { status: 0, stdout: Buffer.from("Office Mac\n") };
  };
  const read = createMacComputerNameSource({
    platform: () => platform,
    now: () => 0,
    spawn,
    cacheDirectory,
  });

  assert.equal(read(), undefined);
  assert.equal(calls, 0);
  assert.throws(() => lstatSync(computerNameCachePath(cacheDirectory)));
  platform = "darwin";
  assert.equal(read(), "Office Mac");
  assert.equal(calls, 1);
  platform = "win32";
  assert.equal(read(), undefined);
  assert.equal(calls, 1);
});

function plantCache(cacheDirectory: string, value: { expiresAt: number; name: string }): void {
  mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
  chmodSync(cacheDirectory, 0o700);
  writeFileSync(computerNameCachePath(cacheDirectory), JSON.stringify(value), { mode: 0o600 });
  chmodSync(computerNameCachePath(cacheDirectory), 0o600);
}

function runLookupProcess(input: {
  cacheDirectory: string;
  spawnLog: string;
  now: number;
  name: string;
  mode?: "ok" | "fail";
}): { status: number | null; stdout: string; stderr: string } {
  const script = `
    import { appendFileSync } from "node:fs";
    import { createMacComputerNameSource } from "./src/mac-computer-name.ts";
    const read = createMacComputerNameSource({
      platform: () => "darwin",
      now: () => Number(process.env.SILMARIL_TEST_NOW),
      cacheDirectory: process.env.SILMARIL_TEST_CACHE,
      spawn: () => {
        appendFileSync(process.env.SILMARIL_TEST_SPAWN_LOG, "spawn\\n");
        if (process.env.SILMARIL_TEST_MODE === "fail") return { status: 1, stdout: Buffer.from("hidden\\n") };
        return { status: 0, stdout: Buffer.from(String(process.env.SILMARIL_TEST_NAME) + "\\n") };
      },
    });
    process.stdout.write(read() ?? "");
  `;
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    cwd: fileURLToPath(new URL("..", import.meta.url)),
    env: {
      ...process.env,
      SILMARIL_TEST_NOW: String(input.now),
      SILMARIL_TEST_CACHE: input.cacheDirectory,
      SILMARIL_TEST_SPAWN_LOG: input.spawnLog,
      SILMARIL_TEST_NAME: input.name,
      SILMARIL_TEST_MODE: input.mode ?? "ok",
    },
    encoding: "utf8",
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
