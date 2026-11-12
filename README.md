# Pi Firewall Plugin

Silmaril Firewall lifecycle protection for Pi coding agents. The qualified
development host is `@earendil-works/pi-coding-agent` 1.5.0 on Node.js
22.19.0 or newer.

This Pi package classifies raw user input, tool calls, tool results, and finalized assistant text with `@silmaril-security/sdk`. Shadow is silent, Warn adds one bounded warning where Pi exposes same-turn context, and Block uses Pi-native handled, block, or content-replacement responses when the model prediction is exactly `MALICIOUS` or `governance.action` is exactly `block`.

## Install

Version 0.2.10 is available in the [`v0.2.10` GitHub release](https://github.com/Silmaril-Security/PiFirewallPlugin/releases/tag/v0.2.10)
and on npm:

```sh
pi install npm:@silmaril-security/pi-firewall-plugin@0.2.10
```

The matching immutable Git tag is `v0.2.10` at commit
`8d89b1657bdbf561ef2ce61b2cd236dbf757970f`:

```sh
pi install git:github.com/Silmaril-Security/PiFirewallPlugin@v0.2.10
```

Both installations provide the released package with
`@silmaril-security/sdk` 0.8.2.

For local development or review:

```sh
git clone https://github.com/Silmaril-Security/PiFirewallPlugin.git
cd PiFirewallPlugin
npm ci
pi -e .
```

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

Environment variables remain supported as a fallback when the private file is missing. When a valid private file exists, it is fully authoritative so stale process environment cannot disable protection, change its mode, or redirect classified content. In either source, an explicit `mode` overrides `blockMalicious`. When `mode` is omitted, `blockMalicious: false` selects shadow and `true` selects block. Omitting both falls back to Shadow on current classify responses, which omit mode. Set Warn or Block explicitly; valid legacy response modes remain a compatibility fallback.

```sh
export SILMARIL_API_URL="https://..."
export SILMARIL_API_KEY="..."
export SILMARIL_ENDPOINT_ID="2b64e603-f82a-4aec-9524-9736472dc80a"
export SILMARIL_TIMEOUT_MS="2500"
export SILMARIL_BLOCK_MALICIOUS="false"
export SILMARIL_DEBUG="false"
export SILMARIL_ENABLED="true"
```

`SILMARIL_TIMEOUT_MS` accepts `250` through `10000`. Missing or insecure configuration, malformed event data, invalid classifier responses, SDK construction, network errors, and timeouts fail open. Local evidence failures leave the chosen Pi response intact. Every Pi handler catches failures internally so Pi's fail-safe `tool_call` error semantics cannot accidentally turn a Firewall outage into a tool block.

`SILMARIL_DEBUG=true` writes metadata-only summaries to stderr. Raw prompts, assistant text, reasoning, tool arguments, tool results, and device names are never logged.

Every classifier request carries plugin-owned `metadata.silmaril.provenance` with `schema_version` 1 and `harness` `pi`. A canonical UUID v4 endpoint id is included when configured. A sanitized macOS Computer Name is included as `device_name` when lookup succeeds, and classification continues when either value is absent. The device name is not written to local evidence.

## Coverage

| Pi event | Firewall label | Shadow behavior | Block-mode behavior |
| --- | --- | --- | --- |
| `input` | `user_input` | Continue | Return `handled` and show a bounded notice |
| `tool_call` | `tool_call` | Continue | Return Pi's native tool block response |
| `tool_result` | `tool_response` | Preserve result | Replace malicious text and clear malicious structured content before model reuse |
| assistant `message_end` | `llm_output` | Preserve message | Replace the finalized message; already-streamed tokens remain observable |

Input with `source === "extension"` is always ignored to prevent feedback loops. Tool-result classification includes visible text and serialized `structuredContent`, including results that have no text. Assistant classification includes visible text parts only; thinking blocks and tool calls are not duplicated through `message_end`. Tool calls are protected regardless of which extension registered the tool.

`message_end` is a finalized-message replacement boundary. It can replace the
message retained by Pi and emitted with the final event, but it cannot retract
assistant tokens that Pi already streamed to an observer before `message_end`.

This package does not include Pi-specific subagent packages, worker adapters, or delegation semantics. Ordinary tool-call protection still applies.

## Enforcement semantics

Shadow mode returns no Pi mutation. Warn keeps tool results and assistant text, prefixes user input, and delivers a bounded warning for a tool call and for a tool result. Assistant `message_end` has no warn delivery. Current responses omit mode, so omission of both local mode and the legacy boolean falls back to Shadow. Set `SILMARIL_MODE=block` for explicit enforcement, or use the legacy block boolean. An explicit mode overrides that boolean. A supplied mode is sent on the classify request and remains authoritative during mixed-version rollout: an older backend response cannot strengthen an explicit Shadow or Warn request into Block. The policy candidate is an exact `MALICIOUS` model prediction or an exact governance action of `block`; casing variants and malformed or unknown governance actions never block. Governance-only denials retain the original benign model prediction in local evidence.

The SDK client is cached per extension instance after successful construction. Failed construction is retryable on the next event. Input request IDs are callback-unique: every non-extension Pi input callback receives a fresh UUID-derived identity, and that request ID remains stable across SDK retries for that classify invocation. Tool-call and tool-result request IDs are stable for the same Pi session, lifecycle event, and host `toolCallId`; no process-global synthetic counter or content cache is used.

## Local evidence

Each completed classification attempts to write a bounded `LocalProtectionEventV1` record to:

```text
~/Library/Application Support/Silmaril/Evidence/incoming
```

The directory is private (`0700`), each file is private (`0600`), and writes use a temporary file plus atomic rename. Records contain only fingerprints, bounded consequence metadata, numeric scores, native actions, and version provenance. They never contain prompts, assistant output, tool arguments/results, reasoning, API keys, endpoints, session files, working-directory paths, or device names.

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

Pi loads the TypeScript extension directly. Runtime dependencies are in `dependencies`; `@silmaril-security/sdk` is pinned to 0.8.2 for current response validation and canonical governance-resource serialization. Pi 1.5.0 is the exact development fixture while the core package remains a `"*"` peer dependency for Pi package distribution. The package engine floor is Node.js 22.19.0, matching that qualified host.

### Native acceptance

`npm run test:native` packs this package, installs that tarball through `pi install npm:@silmaril-security/pi-firewall-plugin@<version>` from a loopback registry into a private agent directory, and drives the locked Pi host over RPC with a scripted model. It requires an allowed tool call to leave its file on disk, a blocked tool call to leave none, and a blocked tool result to stay out of the next model request. The receipt is written to `NATIVE_ACCEPTANCE_RECEIPT` or `.test-build/native-acceptance/receipt.json`. CI runs it on `main`, on manual dispatch, and nightly when `CUSTOMER_NATIVE_ENABLED` is `true`. Setting `CUSTOMER_NATIVE_CLASSIFIER=live` with `CUSTOMER_NATIVE_API_URL` and `CUSTOMER_NATIVE_API_KEY` forwards classification to the customer Cascade endpoint; classifier-caused failures are reported as `BLOCKED` with a named cause. Real model inference is outside this receipt.

## Security and license

Report vulnerabilities through GitHub private vulnerability reporting. See [SECURITY.md](SECURITY.md). The plugin is licensed under Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## References

- [Silmaril documentation](https://www.silmaril.dev/docs)
- [Pi packages](https://pi.dev/docs/latest/packages)
- [Pi extensions](https://pi.dev/docs/latest/extensions)
