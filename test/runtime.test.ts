import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Firewall } from "@silmaril-security/sdk";
import type { ExtensionAPI, ExtensionContext, InputEvent, MessageEndEvent, ToolCallEvent, ToolResultEvent } from "@earendil-works/pi-coding-agent";

import registerExtension from "../extensions/firewall.ts";
import { buildLocalProtectionEvent, writeLocalProtectionEvent } from "../src/local-evidence.ts";
import { PiFirewallRuntime, effectiveMode, extractTextContent, resolveRuntimeConfig, stableStringify, withProvenance } from "../src/runtime.ts";
import { buildDemoStatus, buildDemoUrl, normalizeBaseUrl, openBrowser, optionValue } from "../scripts/open-playground.mjs";

const NO_CONFIG_PATH = path.join(
  os.tmpdir(),
  "silmaril-pi-tests-no-user-config",
  "missing.json",
);
const BASE_ENV = {
  SILMARIL_CONFIG_PATH: NO_CONFIG_PATH,
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "false",
};

function context(notifications: string[] = []): ExtensionContext {
  return {
    hasUI: true,
    mode: "tui",
    ui: { notify: (message: string) => { notifications.push(message); } },
    sessionManager: { getSessionId: () => "session-1" },
  } as unknown as ExtensionContext;
}

function dependencies(results: Array<Record<string, unknown> | Error>, events: unknown[] = [], calls: unknown[] = []) {
  class FakeFirewall {
    constructor(options: unknown) {
      calls.push({ constructor: options });
    }
    async classify(text: string, options: unknown) {
      calls.push({ text, options });
      const result = results.shift();
      if (result instanceof Error) throw result;
      return result ?? { prediction: "BENIGN", score: 0.01, threshold: 0.5 };
    }
  }
  return {
    firewallConstructor: FakeFirewall,
    evidenceEmitter: async (event: unknown) => { events.push(event); },
  };
}

function inputEvent(text: string, source: InputEvent["source"] = "interactive"): InputEvent {
  return { type: "input", text, source };
}

function toolCall(input: Record<string, unknown> = { command: "pwd" }): ToolCallEvent {
  return { type: "tool_call", toolName: "bash", toolCallId: "tool-1", input } as ToolCallEvent;
}

function toolResult(text = "tool output"): ToolResultEvent {
  return {
    type: "tool_result",
    toolName: "bash",
    toolCallId: "tool-1",
    input: { command: "pwd" },
    content: [{ type: "text", text }],
    details: undefined,
    isError: false,
  } as ToolResultEvent;
}

function assistantMessage(text = "assistant output"): MessageEndEvent {
  return {
    type: "message_end",
    message: {
      role: "assistant",
      content: [{ type: "thinking", thinking: "private reasoning" }, { type: "text", text }],
      api: "anthropic-messages",
      provider: "anthropic",
      model: "test",
      usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
      stopReason: "stop",
      timestamp: 1234,
    },
  } as MessageEndEvent;
}

test("configured pilot override wins and backend mode controls otherwise", () => {
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }, "block"), "block");
  assert.equal(effectiveMode({ prediction: "MALICIOUS" }, "block"), "block");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "block" }, "warn"), "warn");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }, "shadow"), "shadow");
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "warn" }), "warn");
  assert.equal(effectiveMode({ prediction: "MALICIOUS" }), "shadow");
});

test("runtime configuration defaults safely", () => {
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: NO_CONFIG_PATH }), undefined);
  assert.deepEqual(resolveRuntimeConfig(BASE_ENV), {
    apiKey: "test-key",
    apiUrl: "https://firewall.example/classify",
    timeoutMs: 2500,
    mode: "shadow",
    blockMalicious: false,
    debug: false,
  });
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_TIMEOUT_MS: "10001" })?.timeoutMs, 2500);
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "on" })?.blockMalicious, true);
  assert.equal(resolveRuntimeConfig({
    ...BASE_ENV,
    SILMARIL_ENDPOINT_ID: "2b64e603-f82a-4aec-9524-9736472dc80a",
  })?.endpointId, "2b64e603-f82a-4aec-9524-9736472dc80a");
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_ENDPOINT_ID: "NOT-A-UUID" })?.endpointId, undefined);
});

test("plugin-owned provenance overwrites caller values and preserves unrelated metadata", () => {
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { integration: "pi-firewall-plugin", provenance: { endpoint_id: "spoofed", harness: "spoofed" } },
  }, "2b64e603-f82a-4aec-9524-9736472dc80a"), {
    trace: "keep",
    silmaril: {
      integration: "pi-firewall-plugin",
      provenance: {
        schema_version: 1,
        endpoint_id: "2b64e603-f82a-4aec-9524-9736472dc80a",
        harness: "pi",
      },
    },
  });
  assert.deepEqual(withProvenance({}), {
    silmaril: { provenance: { schema_version: 1, harness: "pi" } },
  });
});

test("runtime configuration treats a private host file as authoritative", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-config-"));
  const configPath = path.join(root, "silmaril-firewall.json");
  await writeFile(configPath, JSON.stringify({
    enabled: true,
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: configPath }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  });
  assert.deepEqual(resolveRuntimeConfig({
    SILMARIL_CONFIG_PATH: configPath,
    SILMARIL_API_KEY: "environment-key",
    SILMARIL_BLOCK_MALICIOUS: "false",
  }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 375,
    mode: "block",
    blockMalicious: true,
    debug: true,
  });

  await writeFile(configPath, JSON.stringify({
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({
    SILMARIL_CONFIG_PATH: configPath,
    SILMARIL_ENABLED: "false",
    SILMARIL_API_KEY: "stale-key",
    SILMARIL_API_URL: "https://stale.example/classify",
    SILMARIL_TIMEOUT_MS: "9000",
    SILMARIL_BLOCK_MALICIOUS: "true",
    SILMARIL_DEBUG: "true",
  }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    timeoutMs: 2500,
    blockMalicious: false,
    debug: false,
  });

  await chmod(configPath, 0o644);
  assert.equal(resolveRuntimeConfig({
    ...BASE_ENV,
    SILMARIL_CONFIG_PATH: configPath,
  }), undefined);
  await chmod(configPath, 0o600);
  const symlinkPath = path.join(root, "linked.json");
  await symlink(configPath, symlinkPath);
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: symlinkPath }), undefined);
});

test("the pinned SDK receives the configured timeoutMs option", () => {
  const firewall = new Firewall({
    apiKey: "test-key",
    apiUrl: "http://127.0.0.1:1",
    timeoutMs: 375,
  });
  assert.equal(firewall.timeoutMs, 375);
});

test("extension registers only the four intended Pi lifecycle events", () => {
  const handlers = new Map<string, unknown>();
  const pi = {
    on: (name: string, handler: unknown) => handlers.set(name, handler),
    sendMessage: () => undefined,
  } as unknown as ExtensionAPI;
  registerExtension(pi);
  assert.deepEqual([...handlers.keys()], ["input", "tool_call", "tool_result", "message_end"]);
});

test("extension-originated input is ignored to prevent recursion", async () => {
  const calls: unknown[] = [];
  const runtime = new PiFirewallRuntime({ sendMessage: () => undefined }, BASE_ENV, dependencies([{ prediction: "MALICIOUS" }], [], calls));
  assert.deepEqual(await runtime.handleInput(inputEvent("ignored", "extension"), context()), { action: "continue" });
  assert.equal(calls.length, 0);
});

test("shadow mode observes all native boundaries without mutation", async () => {
  const events: any[] = [];
  const calls: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    BASE_ENV,
    dependencies(Array.from({ length: 4 }, () => ({ prediction: "MALICIOUS", score: 0.9, threshold: 0.5 })), events, calls),
  );
  assert.deepEqual(await runtime.handleInput(inputEvent("raw input"), context()), { action: "continue" });
  assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  assert.equal(await runtime.handleToolResult(toolResult("raw result"), context()), undefined);
  assert.equal(await runtime.handleMessageEnd(assistantMessage("raw output"), context()), undefined);
  assert.deepEqual(calls.filter((call) => call.text).map((call) => call.options.hook), ["user_input", "tool_call", "tool_response", "llm_output"]);
  assert.ok(calls.filter((call) => call.text).every((call) => call.options.metadata.silmaril.provenance.harness === "pi"));
  assert.ok(events.every((event) => event.policyDecision === "monitor" && event.mode === "shadow"));
  assert.doesNotMatch(JSON.stringify(events), /raw input|raw result|raw output|private reasoning/u);
});

test("block mode uses Pi-native handled and block without replacement responses", async () => {
  const notifications: string[] = [];
  const events: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    dependencies(Array.from({ length: 4 }, () => ({ prediction: "MALICIOUS" })), events),
  );
  assert.deepEqual(await runtime.handleInput(inputEvent("input"), context(notifications)), { action: "handled" });
  assert.match(notifications[0] ?? "", /blocked potentially malicious/u);
  assert.deepEqual(await runtime.handleToolCall(toolCall(), context()), { block: true, reason: "Silmaril Firewall blocked potentially malicious content." });
  const resultPatch = await runtime.handleToolResult(toolResult(), context());
  assert.equal(resultPatch, undefined);
  const messagePatch = await runtime.handleMessageEnd(assistantMessage(), context());
  assert.equal(messagePatch, undefined);
  assert.equal(events[2].blockUnavailable, true);
  assert.equal(events[3].blockUnavailable, true);
});

test("warn mode surfaces bounded same-turn context where Pi supports it", async () => {
  const messages: any[] = [];
  const events: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: (message, options) => { messages.push({ message, options }); } },
    { ...BASE_ENV, SILMARIL_MODE: "warn" },
    dependencies(Array.from({ length: 4 }, () => ({ prediction: "MALICIOUS", mode: "warn", score: 0.99 })), events),
  );
  const transformed = await runtime.handleInput(inputEvent("raw input"), context());
  assert.equal(transformed.action, "transform");
  assert.match(transformed.action === "transform" ? transformed.text : "", /^Silmaril Firewall warning:/u);
  assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  assert.equal(await runtime.handleToolResult(toolResult("raw result"), context()), undefined);
  assert.equal(await runtime.handleMessageEnd(assistantMessage("raw output"), context()), undefined);
  assert.equal(messages.length, 2);
  assert.ok(messages.every(({ message }) => message.display === false && !message.content.includes("raw")));
  assert.deepEqual(events.map((event) => event.warnDelivery), ["delivered", "delivered", "delivered", "unsupported"]);
  assert.doesNotMatch(JSON.stringify(events), /raw input|raw result|raw output/u);
});

test("only exact uppercase MALICIOUS enforces", async () => {
  for (const prediction of ["malicious", "UNKNOWN", undefined]) {
    const runtime = new PiFirewallRuntime(
      { sendMessage: () => undefined },
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      dependencies([{ prediction }]),
    );
    assert.deepEqual(await runtime.handleInput(inputEvent("input"), context()), { action: "continue" });
  }
});

test("network, timeout, SDK, configuration, malformed-response, and evidence failures preserve Pi behavior", async () => {
  const timeout = new Error("request timed out");
  timeout.name = "TimeoutError";
  for (const failure of [new Error("network failure"), timeout, new Error("SDK failure")]) {
    const runtime = new PiFirewallRuntime(
      { sendMessage: () => undefined },
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      dependencies([failure]),
    );
    assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  }
  const missingConfig = new PiFirewallRuntime({ sendMessage: () => undefined }, {}, dependencies([{ prediction: "MALICIOUS" }]));
  assert.equal(await missingConfig.handleToolCall(toolCall(), context()), undefined);
  const malformed = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    dependencies([{ unexpected: "response" }]),
  );
  assert.equal(await malformed.handleToolCall(toolCall(), context()), undefined);

  const evidenceFailure = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    {
      ...dependencies([{ prediction: "MALICIOUS" }]),
      evidenceEmitter: async () => { throw new Error("disk failure"); },
    },
  );
  assert.equal((await evidenceFailure.handleToolCall(toolCall(), context()))?.block, true);
});

test("SDK client is cached per runtime and failed construction remains retryable", async () => {
  const calls: any[] = [];
  const env = { ...BASE_ENV };
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    env,
    dependencies([{ prediction: "BENIGN" }, { prediction: "BENIGN" }, { prediction: "BENIGN" }], [], calls),
  );
  await runtime.handleInput(inputEvent("one"), context());
  await runtime.handleInput(inputEvent("two"), context());
  assert.equal(calls.filter((call) => Object.hasOwn(call, "constructor")).length, 1);
  env.SILMARIL_API_KEY = "rotated-key";
  await runtime.handleInput(inputEvent("three"), context());
  assert.equal(calls.filter((call) => Object.hasOwn(call, "constructor")).length, 2);

  let attempts = 0;
  class RetryableFirewall {
    constructor() {
      attempts += 1;
      if (attempts === 1) throw new Error("not ready");
    }
    async classify() { return { prediction: "BENIGN" }; }
  }
  const retryable = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    BASE_ENV,
    { firewallConstructor: RetryableFirewall, evidenceEmitter: async () => undefined },
  );
  assert.deepEqual(await retryable.handleInput(inputEvent("one"), context()), { action: "continue" });
  assert.deepEqual(await retryable.handleInput(inputEvent("two"), context()), { action: "continue" });
  assert.equal(attempts, 2);
});

test("request IDs are stable for the same host identity", async () => {
  const calls: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    BASE_ENV,
    dependencies([{ prediction: "BENIGN" }, { prediction: "BENIGN" }], [], calls),
  );
  await runtime.handleToolCall(toolCall({ command: "one" }), context());
  await runtime.handleToolCall(toolCall({ command: "two" }), context());
  const requestIds = calls.filter((call) => call.text).map((call) => call.options.requestId);
  assert.equal(requestIds[0], requestIds[1]);
});

test("assistant extraction excludes thinking and tool calls", () => {
  assert.equal(extractTextContent([
    { type: "thinking", thinking: "secret reasoning" },
    { type: "text", text: "visible answer" },
    { type: "toolCall", name: "bash", arguments: { command: "pwd" } },
  ]), "visible answer");
  assert.equal(stableStringify({ z: 1, a: 2 }), '{"a":2,"z":1}');
});

test("local evidence remains bounded, private, atomic, and raw-content free", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-evidence-"));
  const event = buildLocalProtectionEvent({
    pluginName: "pi-firewall-plugin",
    pluginVersion: "0.2.0",
    hook: "tool_result",
    mode: "block",
    requestId: "raw-request-id",
    sessionId: "raw-session-id",
    toolName: "bash",
    classification: { prediction: "MALICIOUS", primaryOutcome: "code_execution", raw: "must-not-leak" },
    policyDecision: "block",
    nativeAction: "block_returned",
  });
  const destination = await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: root });
  assert.ok(destination);
  const encoded = await readFile(destination, "utf8");
  assert.doesNotMatch(encoded, /must-not-leak|raw-request-id|raw-session-id/u);
  assert.ok(Buffer.byteLength(encoded) <= 16 * 1024);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
  assert.ok((await import("node:fs/promises").then(({ readdir }) => readdir(root))).every((name) => !name.endsWith(".tmp")));

  const symlinkRoot = path.join(root, "symlink");
  const realRoot = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-real-"));
  await symlink(realRoot, symlinkRoot);
  assert.equal(await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: symlinkRoot }), undefined);
});

test("demo launcher is credential-safe", async () => {
  assert.equal(normalizeBaseUrl("example.com/path?key=value"), "https://example.com");
  assert.equal(buildDemoUrl("https://app.silmaril.dev", "setup"), "https://app.silmaril.dev/demo/setup-complete");
  const statusPayload = JSON.stringify(buildDemoStatus({ SILMARIL_API_KEY: "super-secret", SILMARIL_API_URL: "https://api.example/path" }));
  assert.doesNotMatch(statusPayload, /super-secret/u);

  const openedChild = new EventEmitter() as EventEmitter & { unref(): void };
  openedChild.unref = () => undefined;
  const opened = openBrowser("https://example.com", () => openedChild as never);
  openedChild.emit("spawn");
  assert.equal(await opened, true);

  const failedChild = new EventEmitter() as EventEmitter & { unref(): void };
  failedChild.unref = () => undefined;
  const failed = openBrowser("https://example.com", () => failedChild as never);
  failedChild.emit("error", new Error("missing opener"));
  assert.equal(await failed, false);
  assert.equal(await openBrowser("https://example.com", () => { throw new Error("spawn failed"); }), false);

  const originalArgs = process.argv;
  process.argv = ["node", "script", "--route", "--open"];
  assert.equal(optionValue("--route"), undefined);
  process.argv = originalArgs;
});

test("package manifest is Pi-native, SDK-pinned, and npm-ready", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.version, "0.2.0");
  assert.deepEqual(packageJson.keywords.includes("pi-package"), true);
  assert.deepEqual(packageJson.pi.extensions, ["./extensions"]);
  assert.deepEqual(packageJson.pi.skills, ["./skills"]);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.5.0");
  assert.equal(packageJson.peerDependencies["@earendil-works/pi-coding-agent"], "*");
  assert.equal(packageJson.publishConfig.access, "public");
});
