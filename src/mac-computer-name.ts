import { spawnSync } from "node:child_process";

const COMPUTER_NAME_COMMAND = "/usr/sbin/scutil";
const COMPUTER_NAME_ARGS = ["--get", "ComputerName"] as const;
const LOOKUP_TIMEOUT_MS = 100;
const MAX_OUTPUT_BYTES = 1024;
const MAX_NAME_UNITS = 256;
const CACHE_TTL_MS = 5 * 60 * 1000;
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/u;

export type MacComputerNameSpawnOptions = {
  timeout: number;
  maxBuffer: number;
  encoding: "buffer";
  windowsHide: boolean;
  shell: false;
  stdio: ["ignore", "pipe", "ignore"];
};

export type MacComputerNameSpawnResult = {
  status: number | null;
  stdout?: Uint8Array | null;
  error?: unknown;
};

export type MacComputerNameSpawn = (
  command: string,
  args: readonly string[],
  options: MacComputerNameSpawnOptions,
) => MacComputerNameSpawnResult;

export type MacComputerNameSourceOptions = {
  platform?: () => string;
  now?: () => number;
  spawn?: MacComputerNameSpawn;
};

type CacheEntry = {
  value: string | undefined;
  expiresAt: number;
};

export function sanitizeDeviceName(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_NAME_UNITS || CONTROL_CHARS.test(trimmed)) return undefined;
  return trimmed;
}

export function createMacComputerNameSource(
  options: MacComputerNameSourceOptions = {},
): () => string | undefined {
  const platform = options.platform ?? (() => process.platform);
  const now = options.now ?? Date.now;
  const spawn = options.spawn ?? defaultSpawn;
  let cache: CacheEntry | undefined;

  return () => {
    try {
      if (platform() !== "darwin") return undefined;
      const current = now();
      if (cache && Number.isFinite(current) && current < cache.expiresAt) return cache.value;
      const value = readComputerName(spawn);
      if (Number.isFinite(current)) cache = { value, expiresAt: current + CACHE_TTL_MS };
      return value;
    } catch {
      return undefined;
    }
  };
}

export const readCachedMacComputerName = createMacComputerNameSource();

export function resolvePluginDeviceName(read?: () => string | undefined): string | undefined {
  try {
    return sanitizeDeviceName((read ?? readCachedMacComputerName)());
  } catch {
    return undefined;
  }
}

function readComputerName(spawn: MacComputerNameSpawn): string | undefined {
  try {
    const result = spawn(COMPUTER_NAME_COMMAND, COMPUTER_NAME_ARGS, {
      timeout: LOOKUP_TIMEOUT_MS,
      maxBuffer: MAX_OUTPUT_BYTES,
      encoding: "buffer",
      windowsHide: true,
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (result.error || result.status !== 0) return undefined;
    const stdout = asBuffer(result.stdout);
    if (!stdout || stdout.byteLength > MAX_OUTPUT_BYTES) return undefined;
    const decoded = decodeUtf8(stdout);
    if (decoded === undefined) return undefined;
    return sanitizeDeviceName(decoded);
  } catch {
    return undefined;
  }
}

function defaultSpawn(
  command: string,
  args: readonly string[],
  options: MacComputerNameSpawnOptions,
): MacComputerNameSpawnResult {
  const result = spawnSync(command, [...args], options);
  const stdout = Buffer.isBuffer(result.stdout) ? result.stdout : null;
  return {
    status: result.status,
    ...(stdout ? { stdout } : {}),
    ...(result.error ? { error: result.error } : {}),
  };
}

function asBuffer(stdout: Uint8Array | null | undefined): Buffer | undefined {
  if (stdout == null) return undefined;
  return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
}

function decodeUtf8(stdout: Buffer): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch {
    return undefined;
  }
}
