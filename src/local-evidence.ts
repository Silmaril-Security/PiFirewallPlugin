import { createHash, randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, rename, rm } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import type { BlockResult, Confidence, Severity } from "@silmaril-security/sdk";

const MAX_EVENT_BYTES = 16 * 1024;
const MAX_SAFE_VALUE_LENGTH = 128;
const MAX_PROVENANCE_BYTES = 128;
const PLUGIN_POLICY_VERSION = "pi-plugin-policy-v1";
const UNSAFE_PROVENANCE_CHARACTERS = /[\p{Cc}\p{Cf}\p{Cs}]/gu;
const CONFIDENCE_LEVELS: ReadonlySet<Confidence> = new Set(["very_low", "low", "medium", "high", "very_high"]);
const SEVERITY_LEVELS: ReadonlySet<Severity> = new Set(["minimal", "low", "moderate", "high", "critical"]);
const DEFAULT_DIRECTORY = ["Library", "Application Support", "Silmaril", "Evidence", "incoming"];

export type ProtectionHook = "user_input" | "pre_tool" | "post_tool" | "tool_result" | "llm_output" | "subagent" | "unknown";
export type ProtectionCategory = "credential_exposure" | "sensitive_data_exposure" | "code_execution" | "destructive_change" | "external_communication" | "privilege_change" | "unsafe_agent_control" | "other" | "unknown";

export type LocalProtectionEventV1 = {
  schemaVersion: 1;
  id: string;
  occurredAt: string;
  host: "pi";
  hook: ProtectionHook;
  mode: "block" | "warn" | "shadow";
  requestFingerprint?: string;
  sessionFingerprint?: string;
  toolDisplayName?: string;
  riskClass: ProtectionCategory;
  attemptedConsequence: { category: ProtectionCategory; summary: string };
  prediction: "benign" | "malicious";
  confidence?: Confidence;
  severity?: Severity;
  policyDecision: "allow" | "monitor" | "warn" | "block" | "unavailable";
  nativeAction: "none" | "allowed" | "block_returned" | "content_replaced" | "warning_context_returned" | "failed" | "unavailable";
  warnDelivery?: "delivered" | "unsupported";
  blockUnavailable?: boolean;
  outcome: "not_observed";
  evidenceTruth: "plugin_reported" | "native_response_returned";
  evidenceCompleteness: "partial";
  provenance: {
    schemaVersion: 1;
    producer: string;
    producerVersion: string;
    pluginVersion: string;
    policyVersion: string;
    modelVersion?: string;
    observedAt: string;
  };
};

export type LocalEvidenceInput = {
  pluginName: string;
  pluginVersion: string;
  hook: ProtectionHook;
  mode: "block" | "warn" | "shadow";
  requestId?: string;
  sessionId?: string;
  toolName?: string;
  classification: BlockResult;
  policyDecision: LocalProtectionEventV1["policyDecision"];
  nativeAction: LocalProtectionEventV1["nativeAction"];
  warnDelivery?: "delivered" | "unsupported";
  blockUnavailable?: boolean;
  occurredAt?: Date;
};

const CONSEQUENCE_SUMMARIES: Record<ProtectionCategory, string> = {
  credential_exposure: "Potential credential exposure detected.",
  sensitive_data_exposure: "Potential sensitive-data exposure detected.",
  code_execution: "Potential unsafe code execution detected.",
  destructive_change: "Potential destructive change detected.",
  external_communication: "Potential unsafe external communication detected.",
  privilege_change: "Potential unsafe privilege change detected.",
  unsafe_agent_control: "Potential unsafe agent-control behavior detected.",
  other: "Potential harmful consequence detected.",
  unknown: "Potentially unsafe behavior detected.",
};

export function buildLocalProtectionEvent(input: LocalEvidenceInput): LocalProtectionEventV1 {
  const occurredAt = (input.occurredAt ?? new Date()).toISOString();
  const riskClass = normalizeCategory(input.classification.outcome);
  const modelVersion = boundedProvenance(input.classification.modelId);
  return omitUndefined({
    schemaVersion: 1,
    id: `event-${sha256([input.sessionId, input.requestId, occurredAt, randomUUID()].filter(Boolean).join("\u0000"))}`,
    occurredAt,
    host: "pi",
    hook: input.hook,
    mode: input.mode,
    requestFingerprint: fingerprint("request", input.requestId),
    sessionFingerprint: fingerprint("session", input.sessionId),
    toolDisplayName: safeToolName(input.toolName),
    riskClass,
    attemptedConsequence: { category: riskClass, summary: CONSEQUENCE_SUMMARIES[riskClass] },
    prediction: modelPrediction(input.classification),
    confidence: knownLevel(input.classification.confidence, CONFIDENCE_LEVELS),
    severity: knownLevel(input.classification.severity, SEVERITY_LEVELS),
    policyDecision: input.policyDecision,
    nativeAction: input.nativeAction,
    warnDelivery: input.warnDelivery,
    blockUnavailable: input.blockUnavailable,
    outcome: "not_observed",
    evidenceTruth: input.nativeAction === "block_returned" || input.nativeAction === "content_replaced"
      ? "native_response_returned"
      : "plugin_reported",
    evidenceCompleteness: "partial",
    provenance: {
      schemaVersion: 1,
      producer: bounded(input.pluginName) ?? "pi-firewall-plugin",
      producerVersion: bounded(input.pluginVersion) ?? "unknown",
      pluginVersion: bounded(input.pluginVersion) ?? "unknown",
      policyVersion: boundedProvenance(input.classification.governance?.policyVersion) ?? PLUGIN_POLICY_VERSION,
      ...(modelVersion ? { modelVersion } : {}),
      observedAt: occurredAt,
    },
  }) as LocalProtectionEventV1;
}

export async function writeLocalProtectionEvent(
  event: LocalProtectionEventV1,
  env: Record<string, string | undefined> = process.env,
): Promise<string | undefined> {
  const directory = resolveLocalEventDirectory(env);
  const encoded = Buffer.from(`${JSON.stringify(event)}\n`, "utf8");
  if (encoded.byteLength > MAX_EVENT_BYTES) return undefined;
  const digest = sha256(event.id);
  const destination = path.join(directory, `event-${digest}.json`);
  const temporary = path.join(directory, `.event-${digest}.${process.pid}.${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return undefined;
    await chmod(directory, 0o700);
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return destination;
  } catch {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    return undefined;
  }
}

export function resolveLocalEventDirectory(env: Record<string, string | undefined> = process.env): string {
  const configured = env.SILMARIL_LOCAL_EVENT_DIR?.trim();
  if (configured) return configured;
  return path.join(env.HOME?.trim() || homedir(), ...DEFAULT_DIRECTORY);
}

function modelPrediction(classification: BlockResult): LocalProtectionEventV1["prediction"] {
  return classification.action === "allow" || classification.source === "governance" ? "benign" : "malicious";
}

function knownLevel<Level extends string>(value: string | undefined, levels: ReadonlySet<Level>): Level | undefined {
  return levels.has(value as Level) ? (value as Level) : undefined;
}

function normalizeCategory(value: string | undefined): ProtectionCategory {
  if (value === undefined) return "unknown";
  const normalized = value.trim().toLowerCase();
  const mapping: Record<string, ProtectionCategory> = {
    secret_exposure: "credential_exposure",
    credential_exposure: "credential_exposure",
    sensitive_data_exposure: "sensitive_data_exposure",
    data_exfiltration: "sensitive_data_exposure",
    code_execution: "code_execution",
    destructive_change: "destructive_change",
    destructive_action: "destructive_change",
    external_communication: "external_communication",
    privilege_change: "privilege_change",
    privilege_escalation: "privilege_change",
    unsafe_agent_control: "unsafe_agent_control",
  };
  return mapping[normalized] ?? (normalized ? "other" : "unknown");
}

function safeToolName(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || /(?:token|secret|password|api[_-]?key)\s*[:=]/iu.test(trimmed)) return undefined;
  return bounded(trimmed.replace(/[^A-Za-z0-9_.:/-]/gu, "_"));
}

function fingerprint(namespace: string, value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? sha256(`${namespace}:${value}`) : undefined;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function boundedProvenance(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  let bounded = "";
  let bytes = 0;
  for (const character of value.replace(UNSAFE_PROVENANCE_CHARACTERS, "").trim()) {
    bytes += Buffer.byteLength(character, "utf8");
    if (bytes > MAX_PROVENANCE_BYTES) break;
    bounded += character;
  }
  return bounded || undefined;
}

function bounded(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, MAX_SAFE_VALUE_LENGTH) : undefined;
}

function omitUndefined(value: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}
