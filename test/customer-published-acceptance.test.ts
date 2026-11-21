import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants } from "node:fs";
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const REPOSITORY = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DRIVER = path.join(REPOSITORY, "scripts", "customer-published-acceptance");
const HELPER = process.env.CUSTOMER_ARCHIVE_HELPER;
const SHA = execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPOSITORY, encoding: "utf8" }).trim();
const VERSION = (JSON.parse(execFileSync("node", ["-p", "JSON.stringify(require('./package.json'))"], { cwd: REPOSITORY, encoding: "utf8" })) as { version: string }).version;

async function drive(env: Record<string, string>, driver = DRIVER): Promise<{ code: number | null; result: unknown }> {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-customer-driver-test-"));
  try {
    const resultPath = path.join(root, "result.json");
    const code = await promisify(execFile)(driver, [], {
      cwd: root,
      env: { PATH: process.env.PATH, HOME: root, CUSTOMER_RESULT: resultPath, ...env },
      timeout: 240_000,
    }).then(() => 0, (error: { code?: number }) => error.code ?? null);
    return { code, result: JSON.parse(await readFile(resultPath, "utf8")) };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function candidate(root: string, packed: boolean): Promise<{ artifact: string; digest: string }> {
  const artifact = packed
    ? path.join(root, execFileSync("npm", ["pack", "--ignore-scripts", "--pack-destination", root], { cwd: REPOSITORY, encoding: "utf8" }).trim().split("\n").at(-1) ?? "")
    : path.join(root, "candidate.tgz");
  if (!packed) await writeFile(artifact, "not an archive");
  return { artifact, digest: createHash("sha256").update(await readFile(artifact)).digest("hex") };
}

test("the driver is executable and parses", () => {
  accessSync(DRIVER, constants.X_OK);
  execFileSync(process.execPath, ["--check", DRIVER]);
});

test("a wrong digest or malformed input never passes and the result holds only statuses", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-customer-driver-test-"));
  try {
    const { artifact, digest } = await candidate(root, false);
    const valid = {
      CUSTOMER_ARTIFACT: artifact,
      CUSTOMER_VERSION: VERSION,
      CUSTOMER_SOURCE_SHA: SHA,
      CUSTOMER_ARTIFACT_SHA256: digest,
      CUSTOMER_ARCHIVE_HELPER: process.execPath,
    };
    const blocked = { install: "BLOCKED", native: "BLOCKED", live: "BLOCKED" };
    const failed = { install: "FAIL", native: "BLOCKED", live: "BLOCKED" };
    for (const [overrides, expected] of [
      [{ CUSTOMER_ARTIFACT_SHA256: "0".repeat(64) }, failed],
      [{ CUSTOMER_ARTIFACT_SHA256: digest.toUpperCase() }, failed],
      [{ CUSTOMER_VERSION: "1.2" }, failed],
      [{ CUSTOMER_SOURCE_SHA: "abc" }, failed],
      [{ CUSTOMER_ARTIFACT: "relative.tgz" }, failed],
      [{ CUSTOMER_ARTIFACT: path.join(root, "absent.tgz") }, blocked],
      [{ CUSTOMER_ARCHIVE_HELPER: path.join(root, "absent.py") }, blocked],
      [{ CUSTOMER_ARTIFACT_SHA256: "" }, blocked],
    ] as const) {
      const run = await drive({ ...valid, ...overrides });
      assert.equal(run.code, 1, JSON.stringify(overrides));
      assert.deepEqual(run.result, expected, JSON.stringify(overrides));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the release can predate the QA checkout", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-customer-driver-test-"));
  try {
    const { artifact, digest } = await candidate(root, false);
    const helper = path.join(root, "extract.py");
    const marker = path.join(root, "attempted");
    await writeFile(helper, `from pathlib import Path\nPath(${JSON.stringify(marker)}).touch()\nraise SystemExit(1)\n`);
    const releaseSha = SHA === "f".repeat(40) ? "e".repeat(40) : "f".repeat(40);
    const run = await drive({
      CUSTOMER_ARTIFACT: artifact, CUSTOMER_VERSION: VERSION, CUSTOMER_SOURCE_SHA: releaseSha,
      CUSTOMER_ARTIFACT_SHA256: digest, CUSTOMER_ARCHIVE_HELPER: helper,
    });
    assert.deepEqual(run.result, { install: "FAIL", native: "BLOCKED", live: "BLOCKED" });
    accessSync(marker);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a missing result path is a usage error", async () => {
  const code = await promisify(execFile)(DRIVER, [], { env: { PATH: process.env.PATH } }).then(() => 0, (error: { code?: number }) => error.code);
  assert.equal(code, 2);
});

test("the driver accepts an installed archive receipt and blocks live without credentials", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-customer-driver-test-"));
  try {
    const { artifact, digest } = await candidate(root, true);
    const scripts = path.join(root, "scripts");
    const harness = path.join(root, "test/native-acceptance");
    await mkdir(scripts);
    await mkdir(harness, { recursive: true });
    const driver = path.join(scripts, "customer-published-acceptance");
    await copyFile(DRIVER, driver);
    for (const name of ["package.json", "package-lock.json", "node_modules"]) {
      await symlink(path.join(REPOSITORY, name), path.join(root, name));
    }
    // Only the manifest is needed for this driver contract test; the external
    // release acceptance uses the shared archive verifier and the native host.
    const helper = path.join(root, "unpack.py");
    await writeFile(helper, `import pathlib, sys, tarfile
artifact, destination, flag, prefix = sys.argv[1:]
assert (flag, prefix) == ("--prefix", "package")
root = pathlib.Path(destination)
root.mkdir()
with tarfile.open(artifact) as archive:
    (root / "package.json").write_bytes(archive.extractfile("package/package.json").read())
`);
    await writeFile(path.join(harness, "harness.ts"), `
      import { createHash } from "node:crypto";
      import { readFileSync, writeFileSync } from "node:fs";
      import path from "node:path";
      const env = process.env;
      const manifest = JSON.parse(readFileSync(path.join(env.NATIVE_ACCEPTANCE_PACKAGE_DIR, "package.json")));
      writeFileSync(env.NATIVE_ACCEPTANCE_RECEIPT, JSON.stringify({
        schema: "silmaril.native-acceptance.v1", classifier: "loopback",
        source_sha: env.CUSTOMER_SOURCE_SHA, status: "PASS",
        plugin: { installed_bytes_match: true, version: manifest.version,
          artifact_sha256: createHash("sha256").update(readFileSync(env.NATIVE_ACCEPTANCE_TARBALL)).digest("hex") },
      }));
    `);
    const run = await drive({
      CUSTOMER_ARTIFACT: artifact, CUSTOMER_ARTIFACT_SHA256: digest, CUSTOMER_VERSION: VERSION,
      CUSTOMER_SOURCE_SHA: SHA, CUSTOMER_ARCHIVE_HELPER: helper,
    }, driver);
    assert.equal(run.code, 1);
    assert.deepEqual(run.result, { install: "PASS", native: "PASS", live: "BLOCKED" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// Needs the shared archive helper (CUSTOMER_ARCHIVE_HELPER) and the public npm registry for the host's dependency install.
test("without live credentials the packed plugin passes install and native but live stays BLOCKED", { timeout: 300_000, skip: !HELPER }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-customer-driver-test-"));
  try {
    const { artifact, digest } = await candidate(root, true);
    const run = await drive({
      CUSTOMER_ARTIFACT: artifact,
      CUSTOMER_VERSION: VERSION,
      CUSTOMER_SOURCE_SHA: SHA,
      CUSTOMER_ARTIFACT_SHA256: digest,
      CUSTOMER_ARCHIVE_HELPER: HELPER ?? "",
    });
    assert.equal(run.code, 1);
    assert.deepEqual(run.result, { install: "PASS", native: "PASS", live: "BLOCKED" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
