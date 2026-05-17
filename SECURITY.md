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

If you cannot use the advisory feature, email [security@kitelogik.com](mailto:security@kitelogik.com) with subject line `[SECURITY] <brief description>`.

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

Kite Logik is designed around a few primary attack classes we actively defend against:

- **Indirect prompt injection** — malicious instructions in tool responses
- **Memory poisoning (MINJA)** — attacker-controlled writes to agent memory
- **Credential escalation** — agent attempting to expand its own session scopes
- **Policy engine unavailability** — OPA taken offline to bypass governance

If your report relates to one of these classes, reference it in your advisory — it helps us triage quickly.

## Deployment Hardening

The bundled `docker-compose.yml` is a quick-start aid for local development. It binds OPA to `0.0.0.0:8181` so the agent process (running on the host) can reach the policy engine without extra configuration. In production:

- **Restrict network exposure.** Bind OPA to `127.0.0.1` (co-located agent and policy engine) or to a private-network interface only. The OPA REST API has no authentication by default — anyone who can reach `:8181` can read policy bundles and submit evaluation requests.
- **Front it with a reverse proxy if remote.** When the agent runs on a different host, put OPA behind a reverse proxy that terminates TLS and enforces authentication (mTLS, an auth header, or your service mesh's identity layer).
- **Review OPA's server configuration.** Disable any diagnostic or debug endpoints you do not actively use. See OPA's [Configuration → Server](https://www.openpolicyagent.org/docs/latest/configuration/#server) for the available knobs.

## Credit

Reporters of valid vulnerabilities (CVSS ≥ 4.0) are:

- Credited by name (or pseudonym, your choice) in the `CHANGELOG` under the Security category
- Included in the CVE acknowledgements field for issues that receive CVE assignment

We do not offer a bug bounty programme at this time.
