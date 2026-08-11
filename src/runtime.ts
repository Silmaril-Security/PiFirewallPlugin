import { Firewall, HookLabel, type FirewallOptions } from "@silmaril-security/sdk";
import { createHash } from "node:crypto";
import type {
  ExtensionAPI,
  ExtensionContext,
  InputEvent,
  InputEventResult,
  MessageEndEvent,
  ToolCallEvent,
  ToolCallEventResult,
  ToolResultEvent,
} from "@earendil-works/pi-coding-agent";
import {
  buildLocalProtectionEvent,
  writeLocalProtectionEvent,
  type LocalEvidenceInput,
  type LocalProtectionEventV1,
  type ProtectionHook,
} from "./local-evidence.ts";
import {
  resolveRuntimeConfig,
  type RuntimeConfig,
  type RuntimeEnv,
} from "./runtime-config.ts";

export { configurationPath, resolveRuntimeConfig } from "./runtime-config.ts";

export const PLUGIN_NAME = "pi-firewall-plugin";
export const PLUGIN_VERSION = "0.1.1";
const SAFE_BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content.";

export type { RuntimeConfig } from "./runtime-config.ts";
type ClassificationResult = Record<string, unknown>;
type FirewallClient = {
  classify(text: string, options?: { hook?: string; toolName?: string; metadata?: Record<string, unknown>; requestId?: string }): Promise<ClassificationResult>;
};
type FirewallConstructor = new (options: FirewallOptions) => FirewallClient;
type PiHost = Pick<ExtensionAPI, "sendMessage">;
type PiToolResultPatch = { content?: ToolResultEvent["content"]; details?: unknown; isError?: boolean };
type PiMessageEndPatch = { message?: MessageEndEvent["message"] };

export type RuntimeDependencies = {
  firewallConstructor: FirewallConstructor;
  evidenceEmitter: (event: LocalProtectionEventV1, env: RuntimeEnv) => Promise<unknown>;
};

type Evaluation = { result: ClassificationResult; blocked: boolean };

export class PiFirewallRuntime {
  private client: FirewallClient | undefined;
  private clientKey: string | undefined;

  constructor(
    private readonly pi: PiHost,
    private readonly env: RuntimeEnv = process.env,
    private readonly dependencies: RuntimeDependencies = {
      firewallConstructor: Firewall as unknown as FirewallConstructor,
      evidenceEmitter: writeLocalProtectionEvent,
    },
  ) {}

  async handleInput(event: InputEvent, ctx: ExtensionContext): Promise<InputEventResult> {
    if (event.source === "extension") return { action: "continue" };
    const evaluation = await this.evaluate({
      text: event.text,
      firewallHook: HookLabel.USER_INPUT,
      evidenceHook: "user_input",
      eventName: "input",
      identity: `${event.source}:${sha256(event.text)}`,
      ctx,
      nativeAction: "block_returned",
    });
    if (!evaluation?.blocked) return { action: "continue" };
    this.notifyBlocked(ctx);
    return { action: "handled" };
  }

  async handleToolCall(event: ToolCallEvent, ctx: ExtensionContext): Promise<ToolCallEventResult | undefined> {
    const text = stableStringify(event.input);
    if (!text) return undefined;
    const evaluation = await this.evaluate({
      text,
      firewallHook: HookLabel.TOOL_CALL,
      evidenceHook: "pre_tool",
      eventName: "tool_call",
      identity: event.toolCallId,
      toolName: event.toolName,
      ctx,
      nativeAction: "block_returned",
    });
    return evaluation?.blocked ? { block: true, reason: SAFE_BLOCK_MESSAGE } : undefined;
  }

  async handleToolResult(event: ToolResultEvent, ctx: ExtensionContext): Promise<PiToolResultPatch | undefined> {
    const text = extractTextContent(event.content);
    if (!text) return undefined;
    const evaluation = await this.evaluate({
      text,
      firewallHook: HookLabel.TOOL_RESPONSE,
      evidenceHook: "tool_result",
      eventName: "tool_result",
      identity: event.toolCallId,
      toolName: event.toolName,
      ctx,
      nativeAction: "content_replaced",
    });
    return evaluation?.blocked
      ? {
          content: [{ type: "text", text: SAFE_BLOCK_MESSAGE }],
          details: { silmaril: { blocked: true } },
          isError: true,
        }
      : undefined;
  }

  async handleMessageEnd(event: MessageEndEvent, ctx: ExtensionContext): Promise<PiMessageEndPatch | undefined> {
    if (event.message.role !== "assistant") return undefined;
    const text = extractTextContent(event.message.content);
    if (!text) return undefined;
    const evaluation = await this.evaluate({
      text,
      firewallHook: HookLabel.LLM_OUTPUT,
      evidenceHook: "llm_output",
      eventName: "message_end",
      identity: String(event.message.timestamp),
      ctx,
      nativeAction: "content_replaced",
    });
    return evaluation?.blocked
      ? { message: { ...event.message, content: [{ type: "text", text: SAFE_BLOCK_MESSAGE }] } }
      : undefined;
  }

  private async evaluate(input: {
    text: string;
    firewallHook: string;
    evidenceHook: ProtectionHook;
    eventName: string;
    identity: string;
    toolName?: string;
    ctx: ExtensionContext;
    nativeAction: "block_returned" | "content_replaced";
  }): Promise<Evaluation | undefined> {
    const config = resolveRuntimeConfig(this.env);
    if (!config || !input.text.trim()) return undefined;
    const sessionId = safeSessionId(input.ctx);
    const requestId = `pi-${sha256([sessionId, input.eventName, input.identity].join("\u0000"))}`;
    let result: ClassificationResult;
    try {
      result = await this.getClient(config).classify(input.text, {
        hook: input.firewallHook,
        ...(input.toolName ? { toolName: input.toolName } : {}),
        requestId,
        metadata: omitUndefined({
          silmaril: { integration: PLUGIN_NAME, version: PLUGIN_VERSION },
          piEvent: input.eventName,
          conversationId: sessionId,
          toolName: input.toolName,
          mode: input.ctx.mode,
        }),
      });
    } catch (error) {
      debugLog(this.env, "classification_error", {
        eventName: input.eventName,
        ...safeErrorFields(error, [config.apiKey, config.apiUrl]),
      });
      return undefined;
    }

    const malicious = result.prediction === "MALICIOUS";
    const blocked = config.blockMalicious && malicious;
    await this.emitEvidence({
      pluginName: PLUGIN_NAME,
      pluginVersion: PLUGIN_VERSION,
      hook: input.evidenceHook,
      mode: config.blockMalicious ? "block" : "shadow",
      requestId,
      sessionId,
      ...(input.toolName ? { toolName: input.toolName } : {}),
      classification: result,
      policyDecision: blocked ? "block" : malicious ? "monitor" : "allow",
      nativeAction: blocked ? input.nativeAction : "allowed",
    });
    debugLog(this.env, "classification_result", {
      eventName: input.eventName,
      hook: input.firewallHook,
      toolName: input.toolName,
      prediction: result.prediction,
      blocked,
    });
    return { result, blocked };
  }

  private getClient(config: RuntimeConfig): FirewallClient {
    const key = sha256(`${config.apiUrl}\u0000${config.apiKey}\u0000${config.timeoutMs}`);
    if (this.client && this.clientKey === key) return this.client;
    const client = new this.dependencies.firewallConstructor({
      apiKey: config.apiKey,
      apiUrl: config.apiUrl,
      timeoutMs: config.timeoutMs,
    });
    this.client = client;
    this.clientKey = key;
    return client;
  }

  private async emitEvidence(input: LocalEvidenceInput): Promise<void> {
    try {
      const event = buildLocalProtectionEvent(input);
      await Promise.resolve(this.dependencies.evidenceEmitter(event, this.env)).catch(() => undefined);
    } catch {
      // Evidence failures never alter the Pi event response.
    }
  }

  private notifyBlocked(ctx: ExtensionContext): void {
    try {
      if (ctx.hasUI) {
        ctx.ui.notify(SAFE_BLOCK_MESSAGE, "warning");
        return;
      }
      this.pi.sendMessage({ customType: "silmaril-firewall", content: SAFE_BLOCK_MESSAGE, display: true }, { triggerTurn: false });
    } catch {
      // A notice failure must not re-submit blocked input.
    }
  }
}

export function extractTextContent(content: unknown): string {
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) return "";
  return content.flatMap((part) => {
    if (!part || typeof part !== "object" || Array.isArray(part)) return [];
    const record = part as Record<string, unknown>;
    return record.type === "text" && typeof record.text === "string" && record.text.trim() ? [record.text.trim()] : [];
  }).join("\n");
}

export function stableStringify(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  const seen = new WeakSet<object>();
  try {
    return JSON.stringify(value, (_key, current) => {
      if (!current || typeof current !== "object") return current;
      if (seen.has(current)) return "[Circular]";
      seen.add(current);
      if (Array.isArray(current)) return current;
      return Object.fromEntries(Object.entries(current).sort(([left], [right]) => left.localeCompare(right)));
    }) ?? "";
  } catch {
    return "";
  }
}

function safeSessionId(ctx: ExtensionContext): string {
  try {
    return ctx.sessionManager.getSessionId() || "unknown-session";
  } catch {
    return "unknown-session";
  }
}

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value !== "string") return undefined;
  if (/^(?:1|true|yes|on)$/iu.test(value.trim())) return true;
  if (/^(?:0|false|no|off)$/iu.test(value.trim())) return false;
  return undefined;
}

function omitUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function safeErrorFields(error: unknown, secrets: string[] = []): Record<string, unknown> {
  if (!(error instanceof Error)) return {};
  const cause = (error as Error & { cause?: unknown }).cause;
  const causeRecord = cause && typeof cause === "object"
    ? cause as { code?: unknown; message?: unknown; name?: unknown }
    : undefined;
  return {
    errorName: error.name,
    errorCode: typeof (error as Error & { code?: unknown }).code === "string"
      ? (error as Error & { code: string }).code
      : undefined,
    errorMessage: safeErrorMessage(error.message, secrets),
    causeName: typeof causeRecord?.name === "string" ? causeRecord.name : undefined,
    causeCode: typeof causeRecord?.code === "string" ? causeRecord.code : undefined,
    causeMessage: typeof causeRecord?.message === "string"
      ? safeErrorMessage(causeRecord.message, secrets)
      : undefined,
  };
}

function safeErrorMessage(value: string, secrets: string[]): string | undefined {
  let message = value;
  for (const secret of secrets.filter(Boolean)) {
    message = message.split(secret).join("[redacted]");
  }
  message = message
    .replace(/\b(?:sfw|sk)-[A-Za-z0-9_-]{12,}\b/gu, "[redacted]")
    .replace(/https?:\/\/[^\s"']+/gu, "[url]")
    .replace(/[\r\n\t]+/gu, " ")
    .trim()
    .slice(0, 180);
  return message || undefined;
}

function debugLog(env: RuntimeEnv, event: string, fields: Record<string, unknown> = {}): void {
  if (!(parseBoolean(env.SILMARIL_DEBUG) ?? false)) return;
  process.stderr.write(`[silmaril] ${JSON.stringify(omitUndefined({ event, ...fields }))}\n`);
}
