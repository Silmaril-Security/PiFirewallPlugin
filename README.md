# Pi Firewall Plugin

Silmaril Firewall lifecycle protection for Pi coding agents.

This Pi package classifies raw user input, tool calls, tool results, and finalized assistant text with `@silmaril-security/sdk`. Shadow is silent, Warn adds one bounded warning where Pi exposes same-turn context, and Block uses Pi-native handled or block responses only for the exact SDK prediction `MALICIOUS`. Completed content is never replaced.

## Install

After the first release is tagged, install the GitHub package with:

```sh
pi install git:github.com/Silmaril-Security/PiFirewallPlugin@v0.1.0
```

For local development or review:

```sh
git clone https://github.com/Silmaril-Security/PiFirewallPlugin.git
cd PiFirewallPlugin
npm ci
pi -e .
```

The package is npm-ready but is not published to npm in v0.2.2. GitHub installation is the supported distribution path until a separate publish approval.

## Configure

The macOS app writes a private configuration file at `~/.pi/agent/silmaril-firewall.json`:

```json
{
  "enabled": true,
  "apiUrl": "https://...",
  "apiKey": "...",
  "endpointId": "2b64e603-f82a-4aec-9524-9736472dc80a",
  "timeoutMs": 2500,
  "mode": "warn",
  "debug": false
}
```

The file must be a regular file owned by the current user with no group or world permissions. Symbolic links, files larger than 64 KiB, malformed JSON, invalid recognized fields, and insecure permissions are rejected without falling back to ambient credentials. `SILMARIL_CONFIG_PATH` can select a different private file.

Environment variables remain supported as a fallback when the private file is missing. When a valid private file exists, it is fully authoritative so stale process environment cannot disable protection, change its mode, or redirect classified content.

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_ENDPOINT_ID="2b64e603-f82a-4aec-9524-9736472dc80a"
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
export SILMARIL_ENABLED="true"
```

`SILMARIL_TIMEOUT_MS` accepts `250` through `10000`. Missing or insecure configuration, malformed event data, invalid classifier responses, SDK construction, network errors, timeouts, and local evidence failures fail open. Every Pi handler catches failures internally so Pi's fail-safe `tool_call` error semantics cannot accidentally turn a Firewall outage into a tool block.

`SILMARIL_DEBUG=true` writes metadata-only summaries to stderr. Raw prompts, assistant text, reasoning, tool arguments, and tool results are never logged.

Every classifier request carries plugin-owned `metadata.silmaril.provenance`. If the app-provided canonical UUID v4 is absent, the plugin continues with harness-only provenance.

## Coverage

| Pi event | Firewall label | Shadow behavior | Block-mode behavior |
| --- | --- | --- | --- |
| `input` | `user_input` | Continue | Return `handled` and show a bounded notice |
| `tool_call` | `tool_call` | Continue | Return Pi's native tool block response |
| `tool_result` | `tool_response` | Preserve result | Replace malicious result before model reuse |
| assistant `message_end` | `llm_output` | Preserve message | Replace malicious finalized content before delivery |

Input with `source === "extension"` is always ignored to prevent feedback loops. Assistant classification includes visible text parts only; thinking blocks and tool calls are not duplicated through `message_end`. Tool calls are protected regardless of which extension registered the tool.

Pi-specific subagent packages, worker adapters, and delegation semantics are not included in v0.1.0. This does not weaken ordinary tool-call protection.

## Enforcement semantics

Shadow mode returns no Pi mutation. Omit mode to use the backend, set `SILMARIL_MODE=block` for a pilot override, or use the legacy block boolean. A supplied mode is sent on the classify request and remains authoritative during mixed-version rollout: an older backend response cannot strengthen an explicit Shadow or Warn request into Block. Casing variants and unknown predictions never block.

The SDK client is cached per extension instance after successful construction. Failed construction is retryable on the next event. Stable logical request IDs use Pi's session ID and host event identity; no process-global synthetic counter is used.

## Local evidence

Each completed classification emits a bounded `LocalProtectionEventV1` record to:

```text
~/Library/Application Support/Silmaril/Evidence/incoming
```

The directory is private (`0700`), each file is private (`0600`), and writes use a temporary file plus atomic rename. Records contain only fingerprints, bounded consequence metadata, numeric scores, native actions, and version provenance. They never contain prompts, assistant output, tool arguments/results, reasoning, API keys, endpoints, session files, or working-directory paths.

Set `SILMARIL_LOCAL_EVENT_DIR` only when the default spool must be overridden. Evidence failure never changes the Pi response.

## Demo

The package includes a `silmaril-demo` skill and credential-safe launcher for the hosted demo:

```sh
node scripts/open-playground.mjs
node scripts/open-playground.mjs --open
node scripts/open-playground.mjs --route playground --json
SILMARIL_DEMO_BASE_URL="http://localhost:3001" node scripts/open-playground.mjs
```

JSON output reports only the URL, configuration presence, API-key presence, and API origin. It never prints the key.

## Development

```sh
npm ci
npm run lint
npm test
npm run pack:dry
pi -e .
```

Pi loads the TypeScript extension directly. Runtime dependencies are in `dependencies`; Pi's core package is a `"*"` peer dependency as required by Pi package distribution.

## Security and license

Report vulnerabilities through GitHub private vulnerability reporting. See [SECURITY.md](SECURITY.md). The plugin is licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## References

- [Silmaril documentation](https://www.silmaril.dev/docs)
- [Pi packages](https://pi.dev/docs/latest/packages)
- [Pi extensions](https://pi.dev/docs/latest/extensions)
