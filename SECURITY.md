# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory feature:
https://github.com/kitelogik/kitelogik/security/advisories/new

Please include:

- Description of the vulnerability
- Steps to reproduce
- Which component is affected (Tether / Anchor / Memory / Agents / Audit / MCP)
- Potential impact — what can an attacker achieve?
- Any suggested fix or mitigating control

If you cannot use the advisory feature, email [security@kitelogik.com](mailto:security@kitelogik.com) with subject line `[SECURITY] <brief description>`. Encrypt with our PGP key if the content is sensitive (key available on keyserver.ubuntu.com, fingerprint published in the GitHub org profile).

## Response Timeline

| Event | Target |
|---|---|
| Acknowledgement | Within 72 hours |
| Status update (confirmed / not confirmed) | Within 7 days |
| Patch for critical issues (CVSS ≥ 9.0) | Within 14 days |
| Patch for high issues (CVSS 7.0–8.9) | Within 30 days |
| Patch for medium/low issues | Next scheduled release |
| CVE assignment | For confirmed vulnerabilities with CVSS ≥ 7.0 |

We will keep you informed throughout the process. If you do not receive an acknowledgement within 72 hours, follow up by email.

## Scope

**In scope** — vulnerabilities in production code paths:

- `tether/` — policy gate, OPA client, schema validation, output sanitizer
- `anchor/` — HITL queue, credential broker, audit store
- `memory/` — agent memory store, provenance metadata
- `agents/` — agent session execution loop
- `audit/` — immutable audit log
- `kitelogik/` — `@governed` decorator, `GovernedToolbox`, framework adapters, CLI
- `mcp/` — MCP client, response sanitization

**Out of scope** — not eligible for the coordinated disclosure process:

- Demo scripts (`quickstart.py`, `explore.py`)
- Documentation and example policies (`policies/examples/`, `docs/`)
- Test files (`tests/`)
- Issues that require physical access to the host machine
- Vulnerabilities in third-party dependencies — report these to the relevant upstream project

## Security Design

Kite Logik's threat model is documented in [`docs/architecture.md`](docs/architecture.md). The primary attack classes we defend against are:

- **Indirect prompt injection** — malicious instructions in tool responses
- **Memory poisoning (MINJA)** — attacker-controlled writes to agent memory
- **Credential escalation** — agent attempting to expand its own session scopes
- **Policy engine unavailability** — OPA taken offline to bypass governance

If your report relates to one of these classes, reference it in your advisory — it helps us triage quickly.

## Credit

Reporters of valid vulnerabilities (CVSS ≥ 4.0) are:

- Credited by name (or pseudonym, your choice) in the `CHANGELOG` under the Security category
- Included in the CVE acknowledgements field for issues that receive CVE assignment

We do not offer a bug bounty programme at this time.
