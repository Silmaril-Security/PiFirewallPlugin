import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("pi -e . loads the extension and blocks against a mock Firewall endpoint", { timeout: 15_000 }, async () => {
  const requests: Array<Record<string, unknown>> = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requests.push(JSON.parse(body) as Record<string, unknown>);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ prediction: "MALICIOUS", score: 0.9, threshold: 0.5, primary_outcome: "unsafe_agent_control" }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const evidenceDirectory = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-cli-"));
  const child = spawn(
    path.join(process.cwd(), "node_modules", ".bin", "pi"),
    ["-e", ".", "--mode", "rpc", "--offline", "--no-session", "--approve"],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        SILMARIL_API_KEY: "test-key",
        SILMARIL_API_URL: `http://127.0.0.1:${address.port}`,
        SILMARIL_BLOCK_MALICIOUS: "true",
        SILMARIL_DEBUG: "false",
        SILMARIL_LOCAL_EVENT_DIR: evidenceDirectory,
      },
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  try {
    const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
      let stdout = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        stdout += chunk;
        while (stdout.includes("\n")) {
          const boundary = stdout.indexOf("\n");
          const line = stdout.slice(0, boundary).replace(/\r$/u, "");
          stdout = stdout.slice(boundary + 1);
          if (!line) continue;
          const value = JSON.parse(line) as Record<string, unknown>;
          if (value.type === "response" && value.id === "silmaril-smoke") resolve(value);
        }
      });
      child.once("error", reject);
      child.once("close", (code) => reject(new Error(`pi exited before the smoke response (code ${code}): ${stderr}`)));
      child.stdin.write(`${JSON.stringify({ id: "silmaril-smoke", type: "prompt", message: "exercise the Pi Firewall input boundary" })}\n`);
    });
    assert.equal(response.command, "prompt");
    assert.equal(response.success, true);
    assert.equal(requests.length, 1);
    assert.equal(requests[0]?.hook, "user_input");
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise<void>((resolve) => child.once("close", () => resolve()));
    }
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
