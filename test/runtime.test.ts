import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, readFile, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { Firewall, type BlockResult, type ClassifyOptions } from "@silmaril-security/sdk";
import type { ExtensionAPI, ExtensionContext, InputEvent, MessageEndEvent, ToolCallEvent, ToolResultEvent } from "@earendil-works/pi-coding-agent";

import registerExtension from "../extensions/firewall.ts";
import { buildLocalProtectionEvent, writeLocalProtectionEvent } from "../src/local-evidence.ts";
import {
  PiFirewallRuntime,
  agentGovernanceContext,
  effectiveMode,
  extractTextContent,
  extractToolResultContent,
  formatBlockMessage,
  isPolicyBlockCandidate,
  resolveRuntimeConfig,
  stableStringify,
  toolGovernanceContext,
  withProvenance,
} from "../src/runtime.ts";
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

const ALLOW: BlockResult = { action: "allow" };
const MODEL_BLOCK: BlockResult = {
  action: "block",
  source: "model",
  confidence: "very_high",
  severity: "high",
  outcome: "control_abuse",
};
const GOVERNANCE_BLOCK: BlockResult = {
  action: "block",
  source: "governance",
  governance: { action: "block", policyVersion: "synthetic-policy" },
};

function context(notifications: string[] = []): ExtensionContext {
  return {
    hasUI: true,
    mode: "tui",
    ui: { notify: (message: string) => { notifications.push(message); } },
    sessionManager: { getSessionId: () => "session-1" },
  } as unknown as ExtensionContext;
}

function dependencies(results: Array<BlockResult | Error>, events: unknown[] = [], calls: unknown[] = []) {
  class FakeFirewall {
    constructor(options: unknown) {
      calls.push({ constructor: options });
    }
    async classify(text: string, options: unknown) {
      calls.push({ text, options });
      const result = results.shift();
      if (result instanceof Error) throw result;
      return result ?? ALLOW;
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

test("the mode sent on the request is authoritative and backend mode controls only when omitted", () => {
  assert.equal(effectiveMode({ ...MODEL_BLOCK, mode: "warn" }, "block"), "block");
  assert.equal(effectiveMode(MODEL_BLOCK, "block"), "block");
  // A legacy backend can ignore the new request field and return its configured
  // Block mode. The plugin must not escalate an explicit Warn or Shadow pilot.
  assert.equal(effectiveMode({ ...MODEL_BLOCK, mode: "block" }, "warn"), "warn");
  assert.equal(effectiveMode({ ...MODEL_BLOCK, mode: "warn" }, "shadow"), "shadow");
  assert.equal(effectiveMode({ ...MODEL_BLOCK, mode: "warn" }), "warn");
  assert.equal(effectiveMode(MODEL_BLOCK), "shadow");
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
    silmaril: { integration: "pi-firewall-plugin", provenance: { endpoint_id: "spoofed", harness: "spoofed", device_name: "spoofed-host" } },
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
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { integration: "pi-firewall-plugin", provenance: { device_name: "spoofed-host", endpoint_id: "spoofed", harness: "spoofed" } },
  }, undefined, "  Office Mac \n"), {
    trace: "keep",
    silmaril: {
      integration: "pi-firewall-plugin",
      provenance: {
        schema_version: 1,
        harness: "pi",
        device_name: "Office Mac",
      },
    },
  });
  assert.deepEqual(withProvenance({}), {
    silmaril: { provenance: { schema_version: 1, harness: "pi" } },
  });
  assert.deepEqual(withProvenance({}, undefined, "Office\u0000Mac"), {
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

test("runtime clears successful deadlines and cancels a stalled logical classification", async () => {
  let behavior: "success" | "stalled" = "success";
  const signals: AbortSignal[] = [];
  class DeadlineFirewall {
    constructor(_options: unknown) {}

    async classify(
      _text: string,
      options?: ClassifyOptions,
    ): Promise<BlockResult> {
      assert.ok(options?.signal);
      signals.push(options.signal);
      return behavior === "success"
        ? ALLOW
        : new Promise<BlockResult>(() => {});
    }
  }
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_TIMEOUT_MS: "250" },
    {
      firewallConstructor: DeadlineFirewall,
      evidenceEmitter: async () => undefined,
    },
  );

  assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  assert.ok(signals[0] instanceof AbortSignal);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(signals[0]?.aborted, false);

  behavior = "stalled";
  const started = performance.now();
  assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  assert.ok(signals[1] instanceof AbortSignal);
  assert.equal(signals[1]?.aborted, true);
  assert.equal(signals[1]?.reason?.name, "TimeoutError");
  assert.ok(performance.now() - started < 1000);
  assert.notEqual(signals[1], signals[0]);
});

test("the Pi deadline cancels the pinned SDK fetch and retry wait", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const response of ["in-flight", "rate-limited"]) {
      let attempts = 0;
      let aborted = false;
      let sdkCall: Promise<unknown> | undefined;
      class ObservedFirewall {
        private readonly client: Firewall;

        constructor(options: ConstructorParameters<typeof Firewall>[0]) {
          this.client = new Firewall({ ...options, timeoutMs: 10_000 });
        }

        classify(text: string, options?: ClassifyOptions) {
          const pending = this.client.classify(text, options);
          sdkCall = pending;
          return pending.then((result) => ({ ...result }));
        }
      }
      globalThis.fetch = async (_input, init) => {
        const signal = init?.signal;
        assert.ok(signal);
        attempts++;
        if (response === "rate-limited") return new Response(null, { status: 429 });
        return new Promise((_, reject) => {
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(signal.reason);
          }, { once: true });
        });
      };
      const runtime = new PiFirewallRuntime(
        { sendMessage: () => undefined },
        { ...BASE_ENV, SILMARIL_TIMEOUT_MS: "250" },
        { firewallConstructor: ObservedFirewall, evidenceEmitter: async () => undefined },
      );
      assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
      assert.ok(sdkCall);
      await Promise.race([
        assert.rejects(sdkCall, { name: "TimeoutError" }),
        delay(1000, undefined, { ref: false }).then(() => assert.fail("SDK missed the deadline")),
      ]);
      assert.equal(attempts, 1);
      assert.equal(aborted, response === "in-flight");
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

const ATTACK_TEXT = "synthetic attack";
const GOVERNED_TEXT = "synthetic governed action";
const GOVERNANCE_WIRE = { action: "block", rule_id: "synthetic-rule", policy_version: "synthetic-policy" };

function classifierSource(text: string): "model" | "governance" | undefined {
  return text.includes(GOVERNED_TEXT) ? "governance" : text.includes(ATTACK_TEXT) ? "model" : undefined;
}

function version2Body(text: string): Record<string, unknown> {
  const source = classifierSource(text);
  return {
    results: [{
      action: source ? "block" : "allow",
      source: source ?? null,
      confidence: source === "model" ? "very_high" : null,
      severity: source === "model" ? "critical" : null,
      outcome: source === "model" ? "secret_exposure" : null,
      governance: source === "governance" ? GOVERNANCE_WIRE : null,
      model_id: "synthetic-model",
    }],
  };
}

function version1Body(text: string): Record<string, unknown> {
  const source = classifierSource(text);
  return {
    prediction: source === "model" ? "MALICIOUS" : "BENIGN",
    score: source === "model" ? 0.99 : 0.01,
    threshold: 0.5,
    primary_outcome: source === "model" ? "secret_exposure" : "benign",
    outcome_scores: source === "model" ? { secret_exposure: 0.99 } : {},
    ...(source === "governance" ? { governance: GOVERNANCE_WIRE } : {}),
  };
}

const CLASSIFIER_DEPLOYMENTS: Record<string, {
  routes: string[];
  respond(pathname: string, text: string): Response;
}> = {
  "version 2 route": {
    routes: ["/v2/classify"],
    respond: (_pathname, text) => Response.json(version2Body(text)),
  },
  "version 1 route only": {
    routes: ["/v2/classify", "/classify"],
    respond: (pathname, text) => pathname === "/classify"
      ? Response.json(version1Body(text))
      : Response.json({ message: "Not Found" }, { status: 404 }),
  },
  "version 2 route answering a version 1 body": {
    routes: ["/v2/classify"],
    respond: (_pathname, text) => Response.json(version1Body(text)),
  },
};

async function withClassifierDeployment(
  respond: (pathname: string, text: string) => Response,
  run: (pathnames: string[]) => Promise<void>,
): Promise<void> {
  const originalFetch = globalThis.fetch;
  const pathnames: string[] = [];
  globalThis.fetch = async (input, init) => {
    const { pathname } = new URL(String(input));
    pathnames.push(pathname);
    return respond(pathname, (JSON.parse(String(init?.body)) as { text: string }).text);
  };
  try {
    await run(pathnames);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("actual SDK 1.0.0 returns the decision on every classifier deployment generation", async () => {
  for (const [name, deployment] of Object.entries(CLASSIFIER_DEPLOYMENTS)) {
    await withClassifierDeployment(deployment.respond, async (pathnames) => {
      const firewall = new Firewall({
        apiKey: "test-key",
        apiUrl: "https://firewall.example/classify",
        timeoutMs: 375,
      });
      const blocked = await firewall.classify(ATTACK_TEXT, { hook: "user_input" });
      assert.deepEqual(
        { action: blocked.action, source: blocked.source, outcome: blocked.outcome },
        { action: "block", source: "model", outcome: "secret_exposure" },
        name,
      );
      assert.deepEqual(
        [blocked.confidence, blocked.severity],
        name === "version 2 route" ? ["very_high", "critical"] : [undefined, undefined],
        name,
      );
      assert.equal(isPolicyBlockCandidate(blocked), true, name);
      const governed = await firewall.classify(GOVERNED_TEXT, { hook: "tool_call" });
      assert.equal(governed.source, "governance", name);
      assert.deepEqual(governed.governance, {
        action: "block",
        ruleId: "synthetic-rule",
        policyVersion: "synthetic-policy",
      }, name);
      assert.equal(isPolicyBlockCandidate(governed), true, name);
      assert.equal(isPolicyBlockCandidate(await firewall.classify("hello", { hook: "user_input" })), false, name);
      assert.deepEqual([...new Set(pathnames)], deployment.routes, name);
    });
  }
});

test("a block is enforced through the actual SDK on every classifier deployment generation", async () => {
  for (const [name, deployment] of Object.entries(CLASSIFIER_DEPLOYMENTS)) {
    await withClassifierDeployment(deployment.respond, async (pathnames) => {
      const events: any[] = [];
      const runtime = new PiFirewallRuntime(
        { sendMessage: () => undefined },
        { ...BASE_ENV, SILMARIL_MODE: "block" },
        { firewallConstructor: Firewall, evidenceEmitter: async (event) => { events.push(event); } },
      );

      assert.deepEqual(await runtime.handleInput(inputEvent(ATTACK_TEXT), context()), { action: "handled" }, name);
      assert.deepEqual(await runtime.handleToolCall(toolCall(), context()), undefined, name);
      const resultPatch = await runtime.handleToolResult(toolResult(ATTACK_TEXT), context());
      assert.equal(
        (resultPatch?.content?.[0] as { text?: string })?.text,
        "Silmaril Firewall blocked potentially malicious content.",
        name,
      );
      const governedPatch = await runtime.handleToolResult(toolResult(GOVERNED_TEXT), context());
      assert.equal(
        (governedPatch?.content?.[0] as { text?: string })?.text,
        "Silmaril Firewall blocked this request under governance policy.",
        name,
      );
      assert.deepEqual(await runtime.handleInput(inputEvent("hello"), context()), { action: "continue" }, name);

      assert.deepEqual(
        events.map((event) => [event.prediction, event.policyDecision]),
        [["malicious", "block"], ["benign", "allow"], ["malicious", "block"], ["benign", "block"], ["benign", "allow"]],
        name,
      );
      assert.deepEqual(
        [events[0].confidence, events[0].severity],
        name === "version 2 route" ? ["very_high", "critical"] : [undefined, undefined],
        name,
      );
      assert.deepEqual([...new Set(pathnames)], deployment.routes, name);
    });
  }
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
  const runtime = new PiFirewallRuntime({ sendMessage: () => undefined }, BASE_ENV, dependencies([MODEL_BLOCK], [], calls));
  assert.deepEqual(await runtime.handleInput(inputEvent("ignored", "extension"), context()), { action: "continue" });
  assert.equal(calls.length, 0);
});

test("shadow mode observes all native boundaries without mutation", async () => {
  const events: any[] = [];
  const calls: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    BASE_ENV,
    dependencies(Array.from({ length: 4 }, () => MODEL_BLOCK), events, calls),
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

test("block mode uses Pi-native handled, block, and content replacements", async () => {
  const notifications: string[] = [];
  const events: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    dependencies(Array.from({ length: 4 }, () => MODEL_BLOCK), events),
  );
  assert.deepEqual(await runtime.handleInput(inputEvent("input"), context(notifications)), { action: "handled" });
  assert.match(notifications[0] ?? "", /blocked potentially malicious/u);
  assert.deepEqual(await runtime.handleToolCall(toolCall(), context()), { block: true, reason: "Silmaril Firewall blocked potentially malicious content." });
  const resultPatch = await runtime.handleToolResult(toolResult(), context());
  assert.deepEqual(resultPatch, {
    content: [{ type: "text", text: "Silmaril Firewall blocked potentially malicious content." }],
    details: { silmaril: { blocked: true } },
    isError: true,
  });
  assert.doesNotMatch(JSON.stringify(resultPatch), /tool output/u);
  const messagePatch = await runtime.handleMessageEnd(assistantMessage(), context());
  const patchedMessage = messagePatch?.message;
  if (!patchedMessage || patchedMessage.role !== "assistant") {
    assert.fail("expected an assistant message replacement");
  }
  assert.equal(patchedMessage.content.length, 1);
  assert.equal(patchedMessage.content[0]?.type, "text");
  assert.equal((patchedMessage.content[0] as { text?: string })?.text, "Silmaril Firewall blocked potentially malicious content.");
  assert.doesNotMatch(JSON.stringify(messagePatch), /assistant output|private reasoning/u);
  assert.equal(events[2].nativeAction, "content_replaced");
  assert.equal(events[3].nativeAction, "content_replaced");
  assert.equal(events[2].blockUnavailable, undefined);
  assert.equal(events[3].blockUnavailable, undefined);
});

test("governance-only blocks use all Pi-native boundaries and preserve benign model evidence", async () => {
  const notifications: string[] = [];
  const events: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_MODE: "block" },
    dependencies(Array.from({ length: 4 }, () => GOVERNANCE_BLOCK), events),
  );

  assert.deepEqual(await runtime.handleInput(inputEvent("input"), context(notifications)), { action: "handled" });
  assert.equal(notifications[0], "Silmaril Firewall blocked this request under governance policy.");
  assert.deepEqual(await runtime.handleToolCall(toolCall(), context()), {
    block: true,
    reason: "Silmaril Firewall blocked this request under governance policy.",
  });
  const resultPatch = await runtime.handleToolResult(toolResult(), context());
  assert.equal((resultPatch?.content?.[0] as { text?: string })?.text, "Silmaril Firewall blocked this request under governance policy.");
  const messagePatch = await runtime.handleMessageEnd(assistantMessage(), context());
  const patchedContent = (
    messagePatch?.message as { content?: Array<{ text?: string }> } | undefined
  )?.content;
  assert.equal(
    patchedContent?.[0]?.text,
    "Silmaril Firewall blocked this request under governance policy.",
  );
  assert.equal(events.length, 4);
  assert.ok(events.every((event) => (
    event.prediction === "benign"
    && event.policyDecision === "block"
    && event.blockUnavailable === undefined
    && event.provenance.pluginVersion === "0.3.0"
  )));
});

test("governance-only candidates retain Shadow and Warn mode behavior", async () => {
  const shadowEvents: any[] = [];
  const shadow = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_MODE: "shadow" },
    dependencies([GOVERNANCE_BLOCK], shadowEvents),
  );
  assert.equal(await shadow.handleToolCall(toolCall(), context()), undefined);
  assert.equal(shadowEvents[0].policyDecision, "monitor");
  assert.equal(shadowEvents[0].prediction, "benign");

  const warnEvents: any[] = [];
  const warn = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_MODE: "warn" },
    dependencies([GOVERNANCE_BLOCK], warnEvents),
  );
  const transformed = await warn.handleInput(inputEvent("input"), context());
  assert.equal(transformed.action, "transform");
  assert.equal(warnEvents[0].policyDecision, "warn");
  assert.equal(warnEvents[0].prediction, "benign");
});

test("warn mode surfaces bounded same-turn context where Pi supports it", async () => {
  const messages: any[] = [];
  const events: any[] = [];
  const runtime = new PiFirewallRuntime(
    { sendMessage: (message, options) => { messages.push({ message, options }); } },
    { ...BASE_ENV, SILMARIL_MODE: "warn" },
    dependencies(Array.from({ length: 4 }, (): BlockResult => ({ ...MODEL_BLOCK, mode: "warn" })), events),
  );
  const images = [{ type: "image", data: "cGl4ZWw=", mimeType: "image/png" }] as NonNullable<InputEvent["images"]>;
  const transformed = await runtime.handleInput({
    ...inputEvent("raw input"),
    images,
  }, context());
  assert.equal(transformed.action, "transform");
  assert.match(transformed.action === "transform" ? transformed.text : "", /^Silmaril Firewall warning:/u);
  assert.deepEqual(transformed.action === "transform" ? transformed.images : undefined, images);
  assert.equal(await runtime.handleToolCall(toolCall(), context()), undefined);
  assert.equal(await runtime.handleToolResult(toolResult("raw result"), context()), undefined);
  assert.equal(await runtime.handleMessageEnd(assistantMessage("raw output"), context()), undefined);
  assert.equal(messages.length, 2);
  assert.ok(messages.every(({ message }) => message.display === false && !message.content.includes("raw")));
  assert.deepEqual(events.map((event) => event.warnDelivery), ["delivered", "delivered", "delivered", "unsupported"]);
  assert.doesNotMatch(JSON.stringify(events), /raw input|raw result|raw output/u);
});

test("policy candidate follows the decision action and nothing else", async () => {
  const governance = GOVERNANCE_BLOCK.governance!;
  const allowed: BlockResult[] = [
    ALLOW,
    { ...MODEL_BLOCK, action: "allow" },
    { action: "allow", governance },
  ];
  for (const result of allowed) {
    assert.equal(isPolicyBlockCandidate(result), false);
    const runtime = new PiFirewallRuntime(
      { sendMessage: () => undefined },
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      dependencies([result]),
    );
    assert.deepEqual(await runtime.handleInput(inputEvent("input"), context()), { action: "continue" });
  }
  const blocked: BlockResult[] = [
    MODEL_BLOCK,
    GOVERNANCE_BLOCK,
    { action: "block" },
    { action: "block", source: "future_source" },
    { action: "block", governance: { action: "allow", policyVersion: "synthetic-policy" } },
  ];
  for (const result of blocked) {
    assert.equal(isPolicyBlockCandidate(result), true);
    const runtime = new PiFirewallRuntime(
      { sendMessage: () => undefined },
      { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
      dependencies([result]),
    );
    assert.deepEqual(await runtime.handleInput(inputEvent("input"), context()), { action: "handled" });
  }
  assert.equal(formatBlockMessage(GOVERNANCE_BLOCK), "Silmaril Firewall blocked this request under governance policy.");
  assert.equal(formatBlockMessage(MODEL_BLOCK), "Silmaril Firewall blocked potentially malicious content.");
  assert.equal(formatBlockMessage({ action: "block" }), "Silmaril Firewall blocked potentially malicious content.");
});

test("local evidence records known confidence and severity and never model scores", () => {
  const build = (classification: BlockResult) => buildLocalProtectionEvent({
    pluginName: "pi-firewall-plugin",
    pluginVersion: "0.3.0",
    hook: "tool_result",
    mode: "block",
    classification,
    policyDecision: "block",
    nativeAction: "content_replaced",
  });
  const absent = (event: object, keys: string[]) => keys.every((key) => !Object.hasOwn(event, key));
  const levels = [
    ["very_low", "minimal"],
    ["low", "low"],
    ["medium", "moderate"],
    ["high", "high"],
    ["very_high", "critical"],
  ] as const;
  for (const [confidence, severity] of levels) {
    const event = build({ action: "block", source: "model", confidence, severity });
    assert.equal(event.schemaVersion, 1);
    assert.equal(event.prediction, "malicious");
    assert.equal(event.confidence, confidence);
    assert.equal(event.severity, severity);
    assert.equal(absent(event, ["modelScore", "modelThreshold"]), true);
  }
  const unknownLevels = build({
    action: "block",
    source: "model",
    ...({ confidence: "certain", severity: "extreme" } as object),
  });
  assert.equal(absent(unknownLevels, ["confidence", "severity"]), true);
  assert.doesNotMatch(JSON.stringify(unknownLevels), /certain|extreme/u);
  const cases: Array<[BlockResult, string]> = [
    [ALLOW, "benign"],
    [GOVERNANCE_BLOCK, "benign"],
    [{ action: "block" }, "malicious"],
  ];
  for (const [classification, prediction] of cases) {
    const event = build(classification);
    assert.equal(event.prediction, prediction);
    assert.equal(absent(event, ["confidence", "severity", "modelScore", "modelThreshold"]), true);
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
  const missingConfig = new PiFirewallRuntime({ sendMessage: () => undefined }, {}, dependencies([MODEL_BLOCK]));
  assert.equal(await missingConfig.handleToolCall(toolCall(), context()), undefined);
  for (const malformedBody of [{ unexpected: "response" }, { results: [{ source: "model" }] }, { results: [] }]) {
    await withClassifierDeployment(() => Response.json(malformedBody), async () => {
      const malformed = new PiFirewallRuntime(
        { sendMessage: () => undefined },
        { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
        { firewallConstructor: Firewall, evidenceEmitter: async () => undefined },
      );
      assert.equal(await malformed.handleToolCall(toolCall(), context()), undefined);
    });
  }

  const evidenceFailure = new PiFirewallRuntime(
    { sendMessage: () => undefined },
    { ...BASE_ENV, SILMARIL_BLOCK_MALICIOUS: "true" },
    {
      ...dependencies([MODEL_BLOCK]),
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
    dependencies([ALLOW, ALLOW, ALLOW], [], calls),
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
    async classify() { return ALLOW; }
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
    dependencies([ALLOW, ALLOW], [], calls),
  );
  await runtime.handleToolCall(toolCall({ command: "one" }), context());
  await runtime.handleToolCall(toolCall({ command: "two" }), context());
  const requestIds = calls.filter((call) => call.text).map((call) => call.options.requestId);
  assert.equal(requestIds[0], requestIds[1]);
});

for (const [label, source] of [
  ["interactive", "interactive"],
  ["API-origin", "rpc"],
] as const) {
  test(`identical ${label} input callbacks receive distinct request IDs with correlated evidence`, async () => {
    const calls: any[] = [];
    const events: any[] = [];
    const runtime = new PiFirewallRuntime(
      { sendMessage: () => undefined },
      BASE_ENV,
      dependencies([ALLOW, ALLOW], events, calls),
    );
    await runtime.handleInput(inputEvent("identical input", source), context());
    await runtime.handleInput(inputEvent("identical input", source), context());
    const requestIds = calls.filter((call) => call.text).map((call) => call.options.requestId);
    assert.equal(requestIds.length, 2);
    assert.notEqual(requestIds[0], requestIds[1]);
    assert.deepEqual(
      events.map((event) => event.requestFingerprint),
      requestIds.map((requestId) => createHash("sha256").update(`request:${requestId}`).digest("hex")),
    );
  });
}

test("assistant extraction excludes thinking and tool calls", () => {
  assert.equal(extractTextContent([
    { type: "thinking", thinking: "secret reasoning" },
    { type: "text", text: "visible answer" },
    { type: "toolCall", name: "bash", arguments: { command: "pwd" } },
  ]), "visible answer");
  assert.equal(extractToolResultContent({
    content: [],
    structuredContent: { secret: "structured-only" },
  }), '{"secret":"structured-only"}');
  assert.equal(stableStringify({ z: 1, a: 2 }), '{"a":2,"z":1}');
  assert.deepEqual(agentGovernanceContext(), {
    agent: "pi",
    resource: { kind: "agent", id: "pi" },
  });
  assert.deepEqual(toolGovernanceContext("mcp__github__create_issue"), {
    agent: "pi",
    resource: { kind: "tool", id: "mcp__github__create_issue" },
  });
});

test("local evidence remains bounded, private, atomic, and raw-content free", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-pi-evidence-"));
  const event = buildLocalProtectionEvent({
    pluginName: "pi-firewall-plugin",
    pluginVersion: "0.2.4",
    hook: "tool_result",
    mode: "block",
    requestId: "raw-request-id",
    sessionId: "raw-session-id",
    toolName: "bash",
    classification: { ...MODEL_BLOCK, outcome: "code_execution", ...({ raw: "must-not-leak" } as object) },
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

test("classify metadata includes the mac computer name without an endpoint id", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env: Record<string, string> = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  const stderr = await captureStderr(async () => {
    const runtime = new PiFirewallRuntime({ sendMessage: () => undefined }, env, {
      ...dependencies([ALLOW], events, calls),
      deviceName: () => "  Office Mac \n",
    });
    assert.deepEqual(await runtime.handleInput(inputEvent("user prompt"), context()), { action: "continue" });
  });
  const metadata = calls.find((call) => call.text).options.metadata;
  assert.deepEqual(metadata.silmaril.provenance, {
    schema_version: 1,
    harness: "pi",
    device_name: "Office Mac",
  });
  assert.equal(metadata.silmaril.provenance.endpoint_id, undefined);
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

test("invalid or failed device-name lookup still classifies and drops spoofed metadata", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  const stderr = await captureStderr(async () => {
    const failing = new PiFirewallRuntime({ sendMessage: () => undefined }, env, {
      ...dependencies([ALLOW], events, calls),
      deviceName: () => {
        throw new Error("scutil failed for Office Mac");
      },
    });
    assert.deepEqual(await failing.handleInput(inputEvent("user prompt"), context()), { action: "continue" });
    for (const deviceName of ["Office\u0000Mac", "Office\u007FMac", "Office\u0085Mac"]) {
      const invalid = new PiFirewallRuntime({ sendMessage: () => undefined }, env, {
        ...dependencies([ALLOW], events, calls),
        deviceName: () => deviceName,
      });
      assert.equal(await invalid.handleToolCall(toolCall(), context()), undefined);
    }
  });
  const provenances = calls.filter((call) => call.text).map((call) => call.options.metadata.silmaril.provenance);
  assert.equal(provenances.length, 4);
  assert.ok(provenances.every((provenance: { device_name?: string; harness: string }) => (
    provenance.device_name === undefined && provenance.harness === "pi"
  )));
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

async function captureStderr(run: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    await run();
  } finally {
    process.stderr.write = original;
  }
  return chunks.join("");
}

test("package manifest is Pi-native, SDK-pinned, and npm-ready", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.name, "@silmaril-security/pi-firewall-plugin");
  assert.equal(packageJson.version, "0.3.0");
  assert.deepEqual(packageJson.keywords.includes("pi-package"), true);
  assert.deepEqual(packageJson.pi.extensions, ["./extensions"]);
  assert.deepEqual(packageJson.pi.skills, ["./skills"]);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "1.0.0");
  assert.equal(packageJson.devDependencies["@earendil-works/pi-coding-agent"], "1.5.0");
  assert.equal(packageJson.peerDependencies["@earendil-works/pi-coding-agent"], "*");
  assert.equal(packageJson.engines.node, ">=22.19.0");
  assert.equal(packageJson.publishConfig.access, "public");
});
