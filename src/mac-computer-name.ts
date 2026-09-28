import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const COMPUTER_NAME_COMMAND = "/usr/sbin/scutil";
const COMPUTER_NAME_ARGS = ["--get", "ComputerName"] as const;
const LOOKUP_TIMEOUT_MS = 100;
const MAX_OUTPUT_BYTES = 1024;
const MAX_NAME_UNITS = 256;
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CACHE_BYTES = 4 * 1024;
const CACHE_FILE_NAME = "cache.json";
const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/u;

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
  cacheDirectory?: string;
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

export function computerNameCachePath(cacheDirectory: string): string {
  return path.join(cacheDirectory, CACHE_FILE_NAME);
}

export function createMacComputerNameSource(
  options: MacComputerNameSourceOptions = {},
): () => string | undefined {
  const platform = options.platform ?? (() => process.platform);
  const now = options.now ?? Date.now;
  const spawn = options.spawn ?? defaultSpawn;
  const cacheDirectory = options.cacheDirectory ?? defaultCacheDirectory();
  let cache: CacheEntry | undefined;

  return () => {
    try {
      if (platform() !== "darwin") return undefined;
      const current = now();
      if (!Number.isFinite(current)) return readComputerName(spawn);
      if (cache && current < cache.expiresAt) return cache.value;
      const stored = readCache(cacheDirectory, current);
      if (stored) {
        cache = stored;
        return stored.value;
      }
      const value = readComputerName(spawn);
      const entry = { value, expiresAt: current + CACHE_TTL_MS };
      cache = entry;
      writeCache(cacheDirectory, entry);
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

function defaultCacheDirectory(): string {
  const home = process.env.HOME?.trim() || homedir();
  return path.join(home, "Library", "Application Support", "Silmaril", "ComputerName");
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

function readCache(cacheDirectory: string, current: number): CacheEntry | undefined {
  try {
    if (!trustedDirectory(cacheDirectory)) return undefined;
    const filePath = computerNameCachePath(cacheDirectory);
    const info = lstatSync(filePath);
    const uid = currentUid();
    if (
      !info.isFile()
      || info.isSymbolicLink()
      || info.size > MAX_CACHE_BYTES
      || (uid !== undefined && info.uid !== uid)
      || (info.mode & 0o077) !== 0
    ) return undefined;
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    const record = parsed as { expiresAt?: unknown; name?: unknown };
    if (typeof record.expiresAt !== "number" || !Number.isFinite(record.expiresAt) || current >= record.expiresAt) {
      return undefined;
    }
    if (record.name === null) return { value: undefined, expiresAt: record.expiresAt };
    const name = sanitizeDeviceName(record.name);
    if (!name) return undefined;
    return { value: name, expiresAt: record.expiresAt };
  } catch {
    return undefined;
  }
}

function writeCache(cacheDirectory: string, entry: CacheEntry): void {
  const temporary = path.join(cacheDirectory, `.cache.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  try {
    mkdirSync(cacheDirectory, { recursive: true, mode: 0o700 });
    if (!trustedDirectory(cacheDirectory)) return;
    chmodSync(cacheDirectory, 0o700);
    const filePath = computerNameCachePath(cacheDirectory);
    try {
      if (lstatSync(filePath).isSymbolicLink()) rmSync(filePath);
    } catch {
      // The cache file is absent.
    }
    const body = JSON.stringify({ expiresAt: entry.expiresAt, name: entry.value ?? null });
    if (Buffer.byteLength(body) > MAX_CACHE_BYTES) return;
    writeFileSync(temporary, body, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, filePath);
    chmodSync(filePath, 0o600);
  } catch {
    try {
      rmSync(temporary, { force: true });
    } catch {
      // The temporary file is already gone.
    }
  }
}

function trustedDirectory(cacheDirectory: string): boolean {
  try {
    const info = lstatSync(cacheDirectory);
    const uid = currentUid();
    return info.isDirectory()
      && !info.isSymbolicLink()
      && (uid === undefined || info.uid === uid);
  } catch {
    return false;
  }
}

function currentUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
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
