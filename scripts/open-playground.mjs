import os from "node:os";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

const DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev";
const ROUTES = { setup: "/demo/setup-complete", playground: "/demo/playground" };

function hasFlag(name) {
  return process.argv.includes(name);
}

export function optionValue(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const next = process.argv[index + 1];
  return next && !next.startsWith("--") ? next : undefined;
}

export function normalizeBaseUrl(value) {
  const raw = String(value || "").trim() || DEFAULT_DEMO_BASE_URL;
  const candidate = /^https?:\/\//u.test(raw) ? raw : `https://${raw}`;
  const url = new URL(candidate);
  url.username = "";
  url.password = "";
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.origin;
}

export function buildDemoUrl(baseUrl, route = "setup") {
  const routePath = route === "playground" ? ROUTES.playground : ROUTES.setup;
  return new URL(routePath, normalizeBaseUrl(baseUrl)).href;
}

export function buildDemoStatus(env = process.env) {
  return {
    configured: Boolean(env.SILMARIL_API_KEY?.trim() && env.SILMARIL_API_URL?.trim()),
    hasApiKey: Boolean(env.SILMARIL_API_KEY?.trim()),
    apiUrlOrigin: (() => {
      try {
        return env.SILMARIL_API_URL ? new URL(env.SILMARIL_API_URL).origin : undefined;
      } catch {
        return undefined;
      }
    })(),
  };
}

function openerCommand(url) {
  if (process.platform === "darwin") return { command: "open", args: [url], options: { detached: true, stdio: "ignore" } };
  if (process.platform === "win32") return { command: "cmd", args: ["/c", "start", "", url], options: { detached: true, stdio: "ignore", windowsHide: true } };
  return { command: "xdg-open", args: [url], options: { detached: true, stdio: "ignore" } };
}

export function openBrowser(url, spawnImpl = spawn) {
  const { command, args, options } = openerCommand(url);
  try {
    const child = spawnImpl(command, args, options);
    child.once("error", () => undefined);
    child.unref();
    return true;
  } catch {
    return false;
  }
}

async function main() {
  if (hasFlag("--help") || hasFlag("-h")) {
    console.log("Usage: node scripts/open-playground.mjs [--open] [--json] [--playground] [--route <setup|playground>]");
    console.log(`Platform: ${os.platform()}`);
    return;
  }
  const route = hasFlag("--playground") ? "playground" : optionValue("--route");
  const url = buildDemoUrl(process.env.SILMARIL_DEMO_BASE_URL, route);
  const status = buildDemoStatus();
  console.log(hasFlag("--json") ? JSON.stringify({ url, ...status }) : url);
  if (hasFlag("--open") && !openBrowser(url)) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
