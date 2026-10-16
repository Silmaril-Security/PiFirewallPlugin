# Changelog

## 0.2.8

- Add a tokenless npm trusted-publishing workflow that validates the immutable
  GitHub run/tag identity and publishes the exact tested package artifact.

## 0.2.7

- Upgrade the pinned TypeScript SDK to 0.7.6 and apply exact governance
  `action: block` decisions at the same Pi-native boundaries as malicious model
  predictions.
- Preserve the model prediction in local evidence and use policy-denial wording
  for governance-only blocks.

## 0.2.6

- Clarify that current classify responses omit mode and local settings must
  explicitly select Warn or Block when intended; omission falls back to Shadow.

## 0.2.5

- Give each distinct input callback a fresh request identity while keeping retries of the same tool event on a stable identity.

## 0.2.4

- Include the macOS Computer Name in captured endpoint provenance when available.

## 0.2.3

- Publish the package from Silmaril's owned `@silmaril-security` npm scope.

## 0.2.2

- Restore Pi-native tool-result and assistant-output replacement in Block mode.

## 0.2.1

- Preserve the backend-selected effective mode by using TypeScript SDK 0.6.0.

## 0.2.0

- Add backend-controlled Shadow, Warn, and Block modes with explicit-mode precedence.
- Deliver bounded Warn context and use only Pi-native handled or block responses without content replacement.

## 0.1.2

- Add app-managed endpoint and harness provenance to every Firewall request.

## 0.1.1

- Add authoritative private host-local JSON configuration with environment fallback when the file is missing.
- Reject insecure, linked, oversized, or foreign-owned configuration files.

## 0.1.0

- Initial public Pi package.
- Raw input, tool call, tool result, and assistant output classification.
- Optional exact-malicious native enforcement with fail-open defaults.
- Privacy-safe local evidence and hosted demo skill.
- GitHub-installable and npm-ready packaging.
