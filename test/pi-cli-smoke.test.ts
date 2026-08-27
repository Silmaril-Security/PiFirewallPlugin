import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("pi -e . applies malicious tool-result and assistant replacements through the host", { timeout: 20_000 }, async () => {
  const requests: Array<Record<string, unknown>> = [];
  const firewallServer = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body) as Record<string, unknown>;
      requests.push(payload);
      const malicious = payload.hook === "tool_response" || payload.hook === "llm_output";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        prediction: malicious ? "MALICIOUS" : "BENIGN",
        score: malicious ? 0.9 : 0.01,
        threshold: 0.5,
        primary_outcome: malicious ? "unsafe_agent_control" : "benign",
      }));
    });
  });
  await new Promise<void>((resolve) => firewallServer.listen(0, "127.0.0.1", resolve));
  const firewallAddress = firewallServer.address();
  assert.ok(firewallAddress && typeof firewallAddress === "object");

  const modelRequests: Array<Record<string, unknown>> = [];
  const modelServer = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      modelRequests.push(JSON.parse(body) as Record<string, unknown>);
      const firstTurn = modelRequests.length === 1;
      const chunk = firstTurn
        ? {
            id: "chatcmpl-tool",
            object: "chat.completion.chunk",
            model: "smoke-model",
            choices: [{
              index: 0,
              delta: {
                role: "assistant",
                tool_calls: [{
                  index: 0,
                  id: "call-smoke",
                  type: "function",
                  function: { name: "bash", arguments: "{\"command\":\"printf PI_RAW_TOOL_RESULT\"}" },
                }],
              },
              finish_reason: "tool_calls",
            }],
          }
        : {
            id: "chatcmpl-final",
            object: "chat.completion.chunk",
            model: "smoke-model",
            choices: [{
              index: 0,
              delta: { role: "assistant", content: "PI_RAW_ASSISTANT_OUTPUT" },
              finish_reason: "stop",
            }],
          };
      response.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      response.end(`data: ${JSON.stringify(chunk)}\n\ndata: [DONE]\n\n`);
    });
  });
  await new Promise<void>((resolve) => modelServer.listen(0, "127.0.0.1", resolve));
  const modelAddress = modelServer.address();
  assert.ok(modelAddress && typeof modelAddress === "object");

  const evidenceDirectory = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-cli-"));
  await writeFile(path.join(evidenceDirectory, "settings.json"), "{}");
  await writeFile(path.join(evidenceDirectory, "auth.json"), "{}");
  await writeFile(path.join(evidenceDirectory, "models.json"), JSON.stringify({
    providers: {
      smoke: {
        baseUrl: `http://127.0.0.1:${modelAddress.port}/v1`,
        api: "openai-completions",
        apiKey: "smoke-key",
        models: [{ id: "smoke-model", contextWindow: 8192, maxTokens: 1024 }],
      },
    },
  }));
  const child = spawn(
    path.join(process.cwd(), "node_modules", ".bin", "pi"),
    ["-e", ".", "--mode", "rpc", "--offline", "--no-session", "--approve", "--provider", "smoke", "--model", "smoke-model"],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: evidenceDirectory,
        SILMARIL_CONFIG_PATH: path.join(evidenceDirectory, "missing-config.json"),
        SILMARIL_API_KEY: "test-key",
        SILMARIL_API_URL: `http://127.0.0.1:${firewallAddress.port}`,
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
    const events: Array<Record<string, unknown>> = [];
    const waiters = new Map<string, {
      resolve: (value: Record<string, unknown>) => void;
      reject: (error: Error) => void;
    }>();
    let settledResolve: (() => void) | undefined;
    const settled = new Promise<void>((resolve) => { settledResolve = resolve; });
    const closed = new Promise<never>((_resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code) => reject(new Error(`pi exited before the smoke completed (code ${code}): ${stderr}`)));
    });
    {
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
          events.push(value);
          if (value.type === "response" && typeof value.id === "string") {
            waiters.get(value.id)?.resolve(value);
            waiters.delete(value.id);
          }
          if (value.type === "agent_settled") settledResolve?.();
        }
      });
    }
    const command = (value: Record<string, unknown>): Promise<Record<string, unknown>> => {
      const id = String(value.id);
      const result = new Promise<Record<string, unknown>>((resolve, reject) => {
        waiters.set(id, { resolve, reject });
      });
      child.stdin.write(`${JSON.stringify(value)}\n`);
      return Promise.race([result, closed]);
    };

    const response = await command({ id: "silmaril-smoke", type: "prompt", message: "exercise every Pi Firewall output boundary" });
    assert.equal(response.command, "prompt");
    assert.equal(response.success, true);
    await Promise.race([settled, closed]);
    const messagesResponse = await command({ id: "silmaril-messages", type: "get_messages" });

    assert.equal(modelRequests.length, 2);
    const providerMessages = modelRequests[1]?.messages as Array<Record<string, unknown>>;
    const providerToolResult = providerMessages.find((message) => message.role === "tool");
    assert.ok(providerToolResult);
    assert.doesNotMatch(JSON.stringify(providerToolResult), /PI_RAW_TOOL_RESULT/u);
    assert.match(JSON.stringify(providerToolResult), /Silmaril Firewall blocked potentially malicious content/u);

    const responseData = messagesResponse.data as { messages: Array<Record<string, unknown>> };
    const transcriptToolResult = responseData.messages.find((message) => message.role === "toolResult");
    const transcriptAssistant = [...responseData.messages].reverse().find((message) => message.role === "assistant");
    assert.ok(transcriptToolResult);
    assert.doesNotMatch(JSON.stringify(transcriptToolResult), /PI_RAW_TOOL_RESULT/u);
    assert.match(JSON.stringify(transcriptToolResult), /Silmaril Firewall blocked potentially malicious content/u);
    assert.ok(transcriptAssistant);
    assert.doesNotMatch(JSON.stringify(transcriptAssistant), /PI_RAW_ASSISTANT_OUTPUT/u);
    assert.match(JSON.stringify(transcriptAssistant), /Silmaril Firewall blocked potentially malicious content/u);
    const finalMessage = [...events].reverse().find((event) => event.type === "message_end");
    assert.ok(finalMessage);
    assert.doesNotMatch(JSON.stringify(finalMessage), /PI_RAW_ASSISTANT_OUTPUT/u);
    assert.match(JSON.stringify(finalMessage), /Silmaril Firewall blocked potentially malicious content/u);

    assert.deepEqual(requests.map((request) => request.hook), [
      "user_input", "tool_call", "tool_response", "llm_output",
    ]);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise<void>((resolve) => child.once("close", () => resolve()));
    }
    await new Promise<void>((resolve, reject) => firewallServer.close((error) => error ? reject(error) : resolve()));
    await new Promise<void>((resolve, reject) => modelServer.close((error) => error ? reject(error) : resolve()));
  }
});
