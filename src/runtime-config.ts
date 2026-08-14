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
  endpointId?: string;
  timeoutMs: number;
  blockMalicious: boolean;
  debug: boolean;
};

type FileConfig = {
  enabled?: boolean;
  apiKey?: string;
  apiUrl?: string;
  endpointId?: string;
  timeoutMs?: number;
  blockMalicious?: boolean;
  debug?: boolean;
};

type FileConfigResult =
  | { state: "missing" }
  | { state: "invalid" }
  | { state: "valid"; config: FileConfig };

export function resolveRuntimeConfig(env: RuntimeEnv = process.env): RuntimeConfig | undefined {
  const fileResult = readFileConfig(configurationPath(env));
  if (fileResult.state === "invalid") return undefined;
  if (fileResult.state === "valid") {
    const file = fileResult.config;
    const enabled = file.enabled ?? true;
    if (!enabled) return undefined;
    const apiKey = nonEmpty(file.apiKey);
    const apiUrl = nonEmpty(file.apiUrl);
    if (!apiKey || !apiUrl) return undefined;
    const configuredEndpointId = endpointId(file.endpointId);
    return {
      apiKey,
      apiUrl,
      ...(configuredEndpointId ? { endpointId: configuredEndpointId } : {}),
      timeoutMs: file.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      blockMalicious: file.blockMalicious ?? false,
      debug: file.debug ?? false,
    };
  }

  const enabled = parseBoolean(env.SILMARIL_ENABLED) ?? true;
  if (!enabled) return undefined;

  const apiKey = nonEmpty(env.SILMARIL_API_KEY);
  const apiUrl = nonEmpty(env.SILMARIL_API_URL);
  if (!apiKey || !apiUrl) return undefined;
  const configuredEndpointId = endpointId(env.SILMARIL_ENDPOINT_ID);

  return {
    apiKey,
    apiUrl,
    ...(configuredEndpointId ? { endpointId: configuredEndpointId } : {}),
    timeoutMs: integerInRange(env.SILMARIL_TIMEOUT_MS) ?? DEFAULT_TIMEOUT_MS,
    blockMalicious: parseBoolean(env.SILMARIL_BLOCK_MALICIOUS) ?? false,
    debug: parseBoolean(env.SILMARIL_DEBUG) ?? false,
  };
}

export function configurationPath(env: RuntimeEnv = process.env): string {
  return nonEmpty(env.SILMARIL_CONFIG_PATH)
    ?? join(homedir(), ".pi", "agent", "silmaril-firewall.json");
}

function readFileConfig(path: string): FileConfigResult {
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.size > MAX_CONFIG_BYTES || (metadata.mode & 0o077) !== 0) {
      return { state: "invalid" };
    }
    if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
      return { state: "invalid" };
    }
    const parsed: unknown = JSON.parse(readFileSync(descriptor, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { state: "invalid" };
    }
    const record = parsed as Record<string, unknown>;
    const enabled = booleanValue(record.enabled);
    const apiKey = stringValue(record.apiKey);
    const apiUrl = stringValue(record.apiUrl);
    const endpointIdValue = stringValue(record.endpointId);
    const timeoutMs = typeof record.timeoutMs === "number"
      ? integerInRange(record.timeoutMs)
      : undefined;
    const blockMalicious = booleanValue(record.blockMalicious);
    const debug = booleanValue(record.debug);
    if (
      (Object.hasOwn(record, "enabled") && enabled === undefined)
      || (Object.hasOwn(record, "apiKey") && apiKey === undefined)
      || (Object.hasOwn(record, "apiUrl") && apiUrl === undefined)
      || (Object.hasOwn(record, "timeoutMs") && timeoutMs === undefined)
      || (Object.hasOwn(record, "blockMalicious") && blockMalicious === undefined)
      || (Object.hasOwn(record, "debug") && debug === undefined)
    ) {
      return { state: "invalid" };
    }
    return {
      state: "valid",
      config: {
        ...(enabled === undefined ? {} : { enabled }),
        ...(apiKey === undefined ? {} : { apiKey }),
        ...(apiUrl === undefined ? {} : { apiUrl }),
        ...(endpointIdValue === undefined ? {} : { endpointId: endpointIdValue }),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        ...(blockMalicious === undefined ? {} : { blockMalicious }),
        ...(debug === undefined ? {} : { debug }),
      },
    };
  } catch (error) {
    return isMissingFileError(error)
      ? { state: "missing" }
      : { state: "invalid" };
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function isMissingFileError(error: unknown): boolean {
  return error !== null
    && typeof error === "object"
    && "code" in error
    && error.code === "ENOENT";
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

function endpointId(value: unknown): string | undefined {
  const candidate = nonEmpty(value);
  return candidate && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(candidate)
    ? candidate
    : undefined;
}

function booleanValue(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}
