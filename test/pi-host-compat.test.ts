import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  discoverAndLoadExtensions,
  ExtensionRunner,
  ModelRegistry,
  SessionManager,
  type ExtensionActions,
  type ExtensionContextActions,
  type LoadExtensionsResult,
  type MessageEndEvent,
  type ModelRuntime,
  type ToolCallEvent,
  type ToolResultEvent,
} from "@earendil-works/pi-coding-agent";

const extensionPath = path.resolve("extensions/firewall.ts");

test("Pi 1.5.0 loads and consumes all four lifecycle outcomes without a model", { timeout: 20_000 }, async () => {
  const requests: Array<Record<string, any>> = [];
  const server = http.createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      const payload = JSON.parse(body) as Record<string, any>;
      requests.push(payload);
      if (payload.text.includes("ERROR_RESULT")) {
        response.writeHead(500, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "synthetic failure" }));
        return;
      }
      const malicious = /BLOCK_INPUT|BLOCK_TOOL_CALL|STRUCTURED_SECRET|SHADOW_SECRET|BLOCK_ASSISTANT/u.test(payload.text);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        prediction: malicious ? "MALICIOUS" : "BENIGN",
        score: malicious ? 0.99 : 0.01,
        threshold: 0.5,
        primary_outcome: malicious ? "unsafe_agent_control" : "benign",
      }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");

  const temporaryHome = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-host-home-"));
  const cwd = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-host-cwd-"));
  const agentDir = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-host-agent-"));
  const originalEnv = { ...process.env };
  Object.assign(process.env, {
    HOME: temporaryHome,
    SILMARIL_CONFIG_PATH: path.join(temporaryHome, "missing-config.json"),
    SILMARIL_API_KEY: "test-key",
    SILMARIL_API_URL: `http://127.0.0.1:${address.port}`,
    SILMARIL_MODE: "block",
    SILMARIL_DEBUG: "false",
    SILMARIL_LOCAL_EVENT_DIR: path.join(temporaryHome, "evidence"),
  });
  delete process.env.SILMARIL_BLOCK_MALICIOUS;

  try {
    const loaded = await discoverAndLoadExtensions([extensionPath], cwd, agentDir);
    assert.deepEqual(loaded.errors, []);
    assert.equal(loaded.extensions.length, 1);
    assert.equal(path.resolve(loaded.extensions[0]?.resolvedPath ?? ""), extensionPath);

    const sentMessages: unknown[] = [];
    const runner = createRunner(loaded, cwd, sentMessages);
    assert.deepEqual(await runner.emitInput("BLOCK_INPUT", undefined, "interactive"), { action: "handled" });

    const toolCallEvent = {
      type: "tool_call",
      toolName: "mcp__github__create_issue",
      toolCallId: "parent-call/1",
      parentToolCallId: "parent-call",
      input: { command: "BLOCK_TOOL_CALL" },
    } as ToolCallEvent;
    assert.deepEqual(await runner.emitToolCall(toolCallEvent), {
      block: true,
      reason: "Silmaril Firewall blocked potentially malicious content.",
    });

    const usage = {
      input: 1,
      output: 2,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 3,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    };
    const structuredOnly = toolResult({
      content: [],
      structuredContent: { secret: "STRUCTURED_SECRET" },
      usage,
      toolCallId: "parent-call/1",
      parentToolCallId: "parent-call",
      toolName: "mcp__github__create_issue",
    });
    const blockedResult = await runner.emitToolResult(structuredOnly);
    assert.ok(blockedResult);
    assert.deepEqual(blockedResult.content, [{
      type: "text",
      text: "Silmaril Firewall blocked potentially malicious content.",
    }]);
    assert.equal(blockedResult.structuredContent, undefined);
    assert.deepEqual(blockedResult.usage, usage);
    assert.doesNotMatch(JSON.stringify(blockedResult), /STRUCTURED_SECRET/u);

    const benignStructured = toolResult({
      content: [{ type: "text", text: "benign result" }],
      structuredContent: { safe: true },
      usage,
    });
    assert.equal(await runner.emitToolResult(benignStructured), undefined);
    assert.deepEqual(benignStructured.structuredContent, { safe: true });
    assert.deepEqual(benignStructured.usage, usage);

    process.env.SILMARIL_MODE = "warn";
    const warnedStructured = toolResult({
      content: [],
      structuredContent: { secret: "SHADOW_SECRET" },
      usage,
    });
    assert.equal(await runner.emitToolResult(warnedStructured), undefined);
    assert.deepEqual(warnedStructured.structuredContent, { secret: "SHADOW_SECRET" });
    assert.deepEqual(warnedStructured.usage, usage);

    process.env.SILMARIL_MODE = "shadow";
    const shadowStructured = toolResult({
      content: [],
      structuredContent: { secret: "SHADOW_SECRET" },
      usage,
    });
    assert.equal(await runner.emitToolResult(shadowStructured), undefined);
    assert.deepEqual(shadowStructured.structuredContent, { secret: "SHADOW_SECRET" });
    assert.deepEqual(shadowStructured.usage, usage);

    process.env.SILMARIL_MODE = "block";
    const failedStructured = toolResult({
      content: [],
      structuredContent: { secret: "ERROR_RESULT" },
      usage,
    });
    assert.equal(await runner.emitToolResult(failedStructured), undefined);
    assert.deepEqual(failedStructured.structuredContent, { secret: "ERROR_RESULT" });
    assert.deepEqual(failedStructured.usage, usage);

    const assistant = assistantMessage("BLOCK_ASSISTANT");
    const replacedAssistant = await runner.emitMessageEnd(assistant);
    assert.ok(replacedAssistant && replacedAssistant.role === "assistant");
    assert.deepEqual(replacedAssistant.content, [{
      type: "text",
      text: "Silmaril Firewall blocked potentially malicious content.",
    }]);

    const requestCount = requests.length;
    const userMessage = {
      type: "message_end",
      message: { role: "user", content: "BLOCK_ASSISTANT", timestamp: 2 },
    } as MessageEndEvent;
    assert.equal(await runner.emitMessageEnd(userMessage), undefined);
    assert.equal(requests.length, requestCount);

    const agentRequests = requests.filter((request) => request.hook === "user_input" || request.hook === "llm_output");
    assert.ok(agentRequests.length >= 2);
    for (const request of agentRequests) {
      assert.deepEqual(request.resource, { kind: "agent", id: "pi" });
      assert.deepEqual(request.metadata.silmaril.governance, {
        agent: "pi",
        resource: { kind: "agent", id: "pi" },
      });
    }

    const toolRequests = requests.filter((request) => request.hook === "tool_call" || request.hook === "tool_response");
    assert.ok(toolRequests.length >= 5);
    for (const request of toolRequests) {
      assert.deepEqual(request.resource, {
        kind: "tool",
        id: request.tool_name,
      });
      assert.equal(request.metadata.silmaril.governance.resource.kind, "tool");
      assert.equal(request.metadata.silmaril.governance.resource.parent_id, undefined);
      assert.equal(request.metadata.silmaril.sdk_version, "0.8.2");
    }
    const nestedRequest = toolRequests.find((request) => request.metadata.toolCallId === "parent-call/1");
    assert.ok(nestedRequest);
    assert.equal(nestedRequest.metadata.parentToolCallId, "parent-call");
    assert.doesNotMatch(JSON.stringify(nestedRequest), /"parentId"|"parent_id"/u);

    const observerPath = path.join(agentDir, "later-observer.ts");
    const observerKey = `__silmaril_pi_observer_${Date.now()}`;
    await writeFile(observerPath, `
      export default function observer(pi) {
        const seen = globalThis[${JSON.stringify(observerKey)}] ?? { input: 0, tool: 0 };
        globalThis[${JSON.stringify(observerKey)}] = seen;
        pi.on("input", () => { seen.input += 1; return { action: "continue" }; });
        pi.on("tool_call", () => { seen.tool += 1; return undefined; });
      }
    `);
    const observedLoad = await discoverAndLoadExtensions([extensionPath, observerPath], cwd, agentDir);
    assert.deepEqual(observedLoad.errors, []);
    assert.equal(observedLoad.extensions.length, 2);
    const observedRunner = createRunner(observedLoad, cwd, []);
    await observedRunner.emitInput("BLOCK_INPUT", undefined, "interactive");
    await observedRunner.emitToolCall(toolCallEvent);
    assert.deepEqual((globalThis as Record<string, unknown>)[observerKey], { input: 0, tool: 0 });
    await observedRunner.emitInput("benign input", undefined, "interactive");
    await observedRunner.emitToolCall({ ...toolCallEvent, input: { command: "benign" } });
    assert.deepEqual((globalThis as Record<string, unknown>)[observerKey], { input: 1, tool: 1 });
    delete (globalThis as Record<string, unknown>)[observerKey];
  } finally {
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) delete process.env[key];
    }
    Object.assign(process.env, originalEnv);
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});

function createRunner(
  loaded: LoadExtensionsResult,
  cwd: string,
  sentMessages: unknown[],
): ExtensionRunner {
  const modelRegistry = new ModelRegistry({} as ModelRuntime);
  const runner = new ExtensionRunner(
    loaded.extensions,
    loaded.runtime,
    cwd,
    SessionManager.inMemory(cwd),
    modelRegistry,
  );
  const actions: ExtensionActions = {
    sendMessage: (message, options) => { sentMessages.push({ message, options }); },
    sendUserMessage: () => undefined,
    appendEntry: () => undefined,
    setSessionName: () => undefined,
    getSessionName: () => undefined,
    setLabel: () => undefined,
    getActiveTools: () => [],
    getAllTools: () => [],
    getSettings: () => ({} as never),
    setActiveTools: () => undefined,
    refreshTools: () => undefined,
    getCommands: () => [],
    setModel: async () => false,
    getThinkingLevel: () => "off",
    setThinkingLevel: () => undefined,
  };
  const contextActions: ExtensionContextActions = {
    getModel: () => undefined,
    getScopedModels: () => [],
    isIdle: () => true,
    isProjectTrusted: () => true,
    getSignal: () => undefined,
    abort: () => undefined,
    hasPendingMessages: () => false,
    shutdown: () => undefined,
    getContextUsage: () => undefined,
    compact: () => undefined,
    getSystemPrompt: () => "",
  };
  runner.bindCore(actions, contextActions);
  runner.setUIContext(undefined, "rpc");
  return runner;
}

function toolResult(overrides: Partial<ToolResultEvent> = {}): ToolResultEvent {
  return {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "tool-1",
    input: { command: "pwd" },
    content: [{ type: "text", text: "result" }],
    details: undefined,
    isError: false,
    ...overrides,
  } as ToolResultEvent;
}

function assistantMessage(text: string): MessageEndEvent {
  return {
    type: "message_end",
    message: {
      role: "assistant",
      content: [{ type: "text", text }],
      api: "anthropic-messages",
      provider: "anthropic",
      model: "test",
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: "stop",
      timestamp: 1,
    },
  } as MessageEndEvent;
}
