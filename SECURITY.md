# Security Policy

## Reporting

Do not open public issues for suspected vulnerabilities. Use GitHub's **Report a vulnerability** flow for this repository so maintainers can investigate privately.

Include the affected version, Pi version, lifecycle event, expected behavior, observed behavior, and a minimal reproduction. Remove API keys, endpoints, prompts, tool payloads, session data, and customer data before submitting.

## Supported versions

The latest tagged release is supported. Security fixes may require upgrading Pi or the Silmaril SDK.

## Runtime posture

The extension defaults to shadow mode and explicitly catches event-handler failures so configuration, networking, the SDK, and evidence failures remain fail open. Enable blocking only after validating the configured endpoint and local policy expectations.
