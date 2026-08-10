import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { PiFirewallRuntime } from "../src/runtime.ts";

export default function silmarilFirewall(pi: ExtensionAPI): void {
  const runtime = new PiFirewallRuntime(pi);
  pi.on("input", (event, ctx) => runtime.handleInput(event, ctx));
  pi.on("tool_call", (event, ctx) => runtime.handleToolCall(event, ctx));
  pi.on("tool_result", (event, ctx) => runtime.handleToolResult(event, ctx));
  pi.on("message_end", (event, ctx) => runtime.handleMessageEnd(event, ctx));
}
