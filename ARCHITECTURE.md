# Architecture

## Runtime path

Pi loads `extensions/firewall.ts` through its TypeScript extension loader. The extension creates one lazy runtime instance and registers only `input`, `tool_call`, `tool_result`, and `message_end`.

Each handler maps host-visible text to a Firewall label, derives a stable request ID from Pi's session and event identity, classifies through the pinned SDK, writes privacy-safe evidence, and returns a native Pi response only for an exact-malicious result in block mode.

All handler failures are caught. This is especially important for `tool_call`, because an uncaught Pi extension error blocks the tool while Silmaril's runtime contract requires classification failures to fail open.

## Data boundaries

Raw lifecycle content is sent only to the configured Firewall endpoint through the SDK. It is never written to logs or evidence. Assistant `message_end` extracts visible text only, excluding reasoning and tool-call parts already handled elsewhere. Tool-result replacement removes the flagged content and details before subsequent handlers and the model consume the patched result.

The cached SDK client exists only inside the Pi process and is recreated when configuration changes. Failed construction is not cached. Credentials come from an authoritative private user-owned configuration file, or from environment variables only when that file is missing. The runtime rejects symbolic links, oversized files, non-regular files, files owned by another user, files with invalid recognized fields, and files with group or world permissions.

## Rollback

Set `blockMalicious` to `false` for immediate observational behavior, or set `enabled` to `false` to disable classification without removing the package. Use `pi remove git:github.com/Silmaril-Security/PiFirewallPlugin` to remove an installed GitHub package.
