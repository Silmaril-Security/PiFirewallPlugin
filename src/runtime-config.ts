import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_TIMEOUT_MS = 2500;
const MIN_TIMEOUT_MS = 250;
const MAX_TIMEOUT_MS = 10_000;
const MAX_CONFIG_BYTES = 64 * 1024;

export type RuntimeEnv = Record<string, string | undefined>;
export type RuntimeConfig = {
  apiKey: string;
  apiUrl: string;
  timeoutMs: number;
  blockMalicious: boolean;
  debug: boolean;
};

type FileConfig = {
  enabled?: boolean;
  apiKey?: string;
  apiUrl?: string;
  timeoutMs?: number;
  blockMalicious?: boolean;
  debug?: boolean;
};

export function resolveRuntimeConfig(env: RuntimeEnv = process.env): RuntimeConfig | undefined {
  const file = readFileConfig(configurationPath(env));
  const enabled = file?.enabled ?? parseBoolean(env.SILMARIL_ENABLED) ?? true;
  if (!enabled) return undefined;

  const apiKey = nonEmpty(file?.apiKey) ?? nonEmpty(env.SILMARIL_API_KEY);
  const apiUrl = nonEmpty(file?.apiUrl) ?? nonEmpty(env.SILMARIL_API_URL);
  if (!apiKey || !apiUrl) return undefined;

  return {
    apiKey,
    apiUrl,
    timeoutMs: integerInRange(file?.timeoutMs)
      ?? integerInRange(env.SILMARIL_TIMEOUT_MS)
      ?? DEFAULT_TIMEOUT_MS,
    blockMalicious: file?.blockMalicious
      ?? parseBoolean(env.SILMARIL_BLOCK_MALICIOUS)
      ?? false,
    debug: parseBoolean(env.SILMARIL_DEBUG) ?? file?.debug ?? false,
  };
}

export function configurationPath(env: RuntimeEnv = process.env): string {
  return nonEmpty(env.SILMARIL_CONFIG_PATH)
    ?? join(homedir(), ".pi", "agent", "silmaril-firewall.json");
}

function readFileConfig(path: string): FileConfig | undefined {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > MAX_CONFIG_BYTES || (metadata.mode & 0o077) !== 0) {
      return undefined;
    }
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
      return undefined;
    }
    const parsed: unknown = JSON.parse(readFileSync(descriptor, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const record = parsed as Record<string, unknown>;
    return {
      enabled: booleanValue(record.enabled),
      apiKey: stringValue(record.apiKey),
      apiUrl: stringValue(record.apiUrl),
      timeoutMs: numberValue(record.timeoutMs),
      blockMalicious: booleanValue(record.blockMalicious),
      debug: booleanValue(record.debug),
    };
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function integerInRange(value: unknown): number | undefined {
  const parsed = typeof value === "string" && value.trim() ? Number(value) : value;
  return typeof parsed === "number"
    && Number.isInteger(parsed)
    && parsed >= MIN_TIMEOUT_MS
    && parsed <= MAX_TIMEOUT_MS
    ? parsed
    : undefined;
}

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value !== "string") return undefined;
  if (/^(?:1|true|yes|on)$/iu.test(value.trim())) return true;
  if (/^(?:0|false|no|off)$/iu.test(value.trim())) return false;
  return undefined;
}

function nonEmpty(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}
