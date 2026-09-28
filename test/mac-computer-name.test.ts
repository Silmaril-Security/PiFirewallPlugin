import assert from "node:assert/strict";
import test from "node:test";
import {
  createMacComputerNameSource,
  sanitizeDeviceName,
  type MacComputerNameSpawn,
  type MacComputerNameSpawnOptions,
} from "../src/mac-computer-name.ts";

const FIVE_MINUTES_MS = 5 * 60 * 1000;

test("sanitizeDeviceName keeps a bounded mac computer name", () => {
  assert.equal(sanitizeDeviceName("  Office Mac \n"), "Office Mac");
  assert.equal(sanitizeDeviceName("a".repeat(256)), "a".repeat(256));
  assert.equal(sanitizeDeviceName("😀".repeat(128)), "😀".repeat(128));
  assert.equal(sanitizeDeviceName("   "), undefined);
  assert.equal(sanitizeDeviceName("a".repeat(257)), undefined);
  assert.equal(sanitizeDeviceName(`${"😀".repeat(128)}x`), undefined);
  assert.equal(sanitizeDeviceName("Office\u0000Mac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u001FMac"), undefined);
  assert.equal(sanitizeDeviceName("Office\u007FMac"), undefined);
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
  let mode: "throw" | "status" | "timeout" | "overflow" | "blank" | "control" | "long" | "bytes" | "utf8" = "throw";
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
    if (mode === "long") return { status: 0, stdout: Buffer.from(`${"a".repeat(257)}\n`) };
    if (mode === "bytes") return { status: 0, stdout: Buffer.alloc(1025, 0x20) };
    return { status: 0, stdout: Buffer.from([0xc3, 0x28]) };
  };

  for (const current of ["throw", "status", "timeout", "overflow", "blank", "control", "long", "bytes", "utf8"] as const) {
    mode = current;
    calls = 0;
    now = 0;
    const source = createMacComputerNameSource({
      platform: () => "darwin",
      now: () => now,
      spawn,
    });
    assert.equal(source(), undefined, current);
    assert.equal(source(), undefined, current);
    assert.equal(calls, 1, current);
    now = FIVE_MINUTES_MS;
    assert.equal(source(), undefined, current);
    assert.equal(calls, 2, current);
  }
});

test("non-darwin lookups do not spawn or reuse a cached mac name", () => {
  let platform = "linux";
  let calls = 0;
  const spawn: MacComputerNameSpawn = () => {
    calls += 1;
    return { status: 0, stdout: Buffer.from("Office Mac\n") };
  };
  const read = createMacComputerNameSource({
    platform: () => platform,
    now: () => 0,
    spawn,
  });

  assert.equal(read(), undefined);
  assert.equal(calls, 0);
  platform = "darwin";
  assert.equal(read(), "Office Mac");
  assert.equal(calls, 1);
  platform = "win32";
  assert.equal(read(), undefined);
  assert.equal(calls, 1);
});
