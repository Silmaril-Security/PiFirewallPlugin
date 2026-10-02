# Security Policy

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub's **Report a vulnerability** flow for this repository so maintainers can investigate privately.

Include the affected version, Pi version, lifecycle event, expected behavior, observed behavior, and a minimal reproduction. Remove API keys, endpoints, prompts, tool payloads, session data, and customer data before submitting.

## Supported versions

The latest tagged release is supported. Security fixes may require upgrading Pi or the Silmaril SDK.

## Runtime posture

When neither an explicit `mode` nor the legacy block flag is set, the backend-selected mode applies. A missing backend mode falls back to shadow. An unrecognized backend wire mode is rejected by the pinned SDK before the hook and fails open. The extension catches configuration, networking, and SDK failures so those paths stay fail open, including `tool_call`. Evidence failures leave the chosen host response intact. Enable blocking only after validating the configured endpoint and local policy expectations.
