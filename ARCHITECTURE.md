# Architecture

## Runtime path

Pi loads `extensions/firewall.ts` through its TypeScript extension loader. The extension creates one lazy runtime instance and registers only `input`, `tool_call`, `tool_result`, and `message_end`.

Each handler maps host-visible text to a Firewall label (`user_input`, `tool_call`, `tool_response`, or `llm_output`), derives a stable request ID from Pi's session and event identity, classifies through the pinned `@silmaril-security/sdk` 0.6.0, and attempts to write privacy-safe evidence. Enforcement requires the exact SDK prediction `MALICIOUS`. Shadow returns the host event unchanged. Warn keeps tool results and assistant text, prefixes user input with a bounded warning, and delivers a bounded warning for `tool_call` and for `tool_result`. Assistant `message_end` has no warn delivery. Block returns a native `handled` response for `input` and Pi's native tool block for `tool_call`. Block replaces content only on the mutable `tool_result` and assistant `message_end` boundaries.

All handler failures are caught. This is especially important for `tool_call`, because an uncaught Pi extension error blocks the tool while Silmaril's runtime contract requires classification failures to fail open.

## Data boundaries

Raw lifecycle content is sent only to the configured Firewall endpoint through the SDK. It is never written to logs or evidence. Assistant `message_end` classifies visible text only, excluding reasoning and tool-call parts. In block mode the mutable tool-result patch replaces content with `Silmaril Firewall blocked potentially malicious content.`, sets `details` to `{ "silmaril": { "blocked": true } }`, and sets `isError` to true before the model receives the result. The mutable assistant patch replaces finalized message content with that same message before delivery.

Each classify request carries plugin-owned provenance: `schema_version` 1, `harness` `pi`, `endpoint_id` when the configured value is a canonical UUID v4, and `device_name` when a sanitized macOS Computer Name is available. On macOS that name may be cached for up to five minutes at `~/Library/Application Support/Silmaril/ComputerName/cache.json` (directory `0700`, file `0600`). The device name is omitted from logs and local evidence. Classification continues when the endpoint id or device name is absent.

The cached SDK client exists only inside the Pi process and is recreated when configuration changes. Failed construction is not cached. Credentials come from an authoritative private user-owned configuration file, or from environment variables only when that file is missing. The runtime rejects symbolic links, oversized files, non-regular files, files owned by another user, files with invalid recognized fields, and files with group or world permissions.

## Rollback

Set `mode` to `shadow` for immediate observational behavior. Explicit `mode` wins over legacy `blockMalicious` and over a shadow, warn, or block mode returned by the backend. When `mode` is omitted, `blockMalicious: false` selects shadow and `blockMalicious: true` selects block; omitting both leaves the mode to the backend, and a missing backend mode falls back to shadow. An unrecognized backend wire mode is an SDK error that fails open. Set `enabled` to `false` to disable classification without removing the package. Use `pi remove git:github.com/Silmaril-Security/PiFirewallPlugin` to remove an installed GitHub package.
