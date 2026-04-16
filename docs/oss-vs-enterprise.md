# OSS vs Enterprise — Feature Split and Strategy

## The model

**Open-core with extension packages.** The OSS repo (`kitelogik/kitelogik`) is
the complete, fully-functional runtime, licensed Apache 2.0. The enterprise
package (`kitelogik/kitelogik-enterprise`) installs alongside it, registers
additional implementations via Python entry points, and is distributed under a
commercial license to paying customers.

The OSS core is **never crippled** — every feature a developer or platform team
needs to run Kite Logik in production is in the OSS package. Enterprise adds
features that matter specifically to *organisations* with compliance, scale, and
identity requirements.

---

## Repository structure

```
kitelogik/kitelogik           ← public GitHub, Apache 2.0, PyPI
kitelogik/kitelogik-enterprise ← private GitHub, commercial license, private PyPI
```

The enterprise repo is **not a fork**. It depends on `kitelogik` as a normal
Python dependency and extends it through the entry-point plugin system
(`kitelogik.edition.load_plugin`). OSS code never imports enterprise code.

---

## Feature split

### OSS — Apache 2.0 (fully open, always free)

| Layer | What's included |
|---|---|
| **Tether (policy engine)** | OPA/Rego + Regorus (in-process, zero Docker) + HierarchicalEvaluator (2-tier global+project); YAML policy compiler; deny-by-default enforcement, schema validation, output sanitization, indirect prompt injection defence |
| **Anchor (HITL)** | Human-in-the-loop escalation queue, async approval, SQLite-backed persistence |
| **Memory** | Agent memory with full provenance metadata (source, session ID, trust tier, timestamp), SQLite backend |
| **Credentials** | Per-session scoped tokens, revocation, expiry, in-memory and SQLite-backed broker |
| **Audit** | Full audit log of every tool call, gate decision, HITL trigger, and memory event — SQLite backend |
| **Observability** | OpenTelemetry instrumentation (GenAI Semantic Conventions), OTLP export |
| **MCP tooling** | MCP client, server registry, BOM-based supply chain verification, response sanitization |
| **Python SDK** | `@governed` decorator, `GovernedToolbox`, `AgentSession`, CLI (`kitelogik compile/validate/compliance`) |
| **Framework adapters** | 11 adapters: OpenAI, LangChain, CrewAI, OpenAI Agents SDK, LangGraph, Google ADK, PydanticAI, LlamaIndex, Semantic Kernel, Haystack, Dify |
| **Policy templates** | 8 core Rego policies + 5 starter policies in `kitelogik/kitelogik/policies/library/` with OPA tests |
| **Extension interface** | `kitelogik.edition.load_plugin` — the full plugin API so the community can build on it |

### Enterprise — commercial license (kitelogik-enterprise)

| Layer | What enterprise adds | Why organisations pay for it |
|---|---|---|
| **Sandbox** | Docker runtime with hardened resource limits + gVisor support; Firecracker MicroVM runtime (hardware-enforced kernel isolation, each session gets its own Linux kernel); sandbox profiles (resource tiers); scoped volume mounts; network egress allowlisting; custom container images; secure secret injection; persistent interpreter sessions; multi-language execution; sandbox exec audit trail. See `kitelogik-enterprise/docs/sandbox-enterprise-roadmap.md` for full roadmap. | SOC 2 / FedRAMP requirement for hardware-level isolation; enterprise agents need controlled file access, network egress, and multi-language execution beyond the OSS code jail |
| **Dashboard** | Real-time governance dashboard: live event feed, HITL approve/deny UI, audit log viewer, memory browser, fleet view, trace viewer, CSV export | Ops interface for security and compliance teams; visual proof that governance is working |
| **Governance Gateway** | Centralized HTTP API for policy enforcement across multiple agents; framework adapters for OpenAI, Anthropic, MCP | Platform team product; centralized enforcement for multi-agent deployments |
| **Multi-agent Orchestrator** | Spawn and coordinate governed agent sessions with delegation chains, scope narrowing, depth limits | Fleet governance; coordinated multi-agent workflows |
| **SIEM Integration** | Webhook dispatchers for Splunk HEC, Datadog, Elastic with retry/backoff | SOC team visibility; compliance requirement for enterprise security monitoring |
| **Prometheus Metrics** | Policy decision counters, HITL queue gauges, gate latency histograms, Grafana dashboards | SRE/ops observability for production deployments |
| **MCP Mock Server** | Simulated MCP tool server for demos and integration testing | Enterprise demo and testing infrastructure |
| **Anchor REST API** | FastAPI sub-app for HITL resolution and audit reads | Dashboard and external integrations consume this API |
| **Storage backends** | PostgreSQL for all state (HITL queue, memory, audit, credentials) + Redis pub/sub for real-time events | Production HA deployments; SQLite is single-node only |
| **Identity** | SAML/OIDC SSO for the HITL reviewer interface; Azure AD / Okta integration | IT security requirement — no tool gets deployed without IdP integration |
| **RBAC** | Fine-grained role hierarchy with delegation (Org Admin → Team Admin → Reviewer → Viewer) | Multi-team deployments; the OSS HITL queue has no access control |
| **Audit integrity** | Tamper-evident audit chain with hash-linked records; direct SIEM integration (Splunk, Datadog, Elastic) | SOC 2 Type II and EU AI Act Article 9 evidence requirements |
| **Compliance exports** | Structured policy evidence packages (which policy was active during which session, who approved what, when) tied to specific regulatory frameworks (EU AI Act, NIST AI RMF, SOC 2) | Audit preparation takes weeks manually; automated evidence packs are a direct cost saving |
| **Policy version control** | Policy change history with rollback, diff view, and per-version session attribution | Regulated environments require proof that the *same* policy was active during an incident window |
| **HITL at scale** | PagerDuty/ServiceNow/Jira integration for escalations; SLA tracking with timeout escalation chains; reviewer routing by risk tier | Ops teams already work in ticketing systems; the OSS queue has no external integration |
| **Session forensics** | Full session replay — re-execute the exact tool call sequence with the exact policy state that was active | Incident investigation and root-cause analysis; not possible with logs alone |
| **Multi-tenancy** | Namespace isolation for multiple business units or clients on a single deployment | Platform teams serving multiple internal teams or reselling to clients |
| **Secrets management** | HashiCorp Vault and AWS STS integration for session-scoped credentials (beyond the SQLite credential broker) | Enterprise secret rotation requirements; Vault is the standard |
| **Support** | SLA-backed support (P1: 1hr response), named customer success manager, private Slack channel | Enterprise procurement requirement |

---

## What must never move to Enterprise

These would make the open-core model feel "crippled" and trigger community
backlash or legitimate security criticism:

- The OPA/Rego evaluation engine (the core of Tether)
- Basic authentication and TLS support
- The `load_plugin` extension interface
- Backup and restore of SQLite state
- The OpenTelemetry instrumentation
- Any feature that a solo developer or small team needs to operate securely

---

## Two-repo strategy (Temporal/Airbyte pattern)

The OSS runtime is complete and self-contained. Enterprise is an operational and
compliance layer, not a feature gate on the core engine. This is the model used
by Temporal (open-source server, Temporal Cloud sells operational reliability)
and Airbyte (open-source connectors, Airbyte Cloud sells the managed service).

**Why not the GitLab `ee/` pattern:** GitLab puts enterprise source in a public
`ee/` directory (source-available but not open-source). This works but adds
complexity and invites scrutiny of enterprise-vs-OSS boundaries. Since Kite
Logik's enterprise extensions are separate implementations (PostgreSQL vs
SQLite, Firecracker vs Docker), they are cleanly separable as a distinct package
with no shared source directory.

---

## Network effects and stickiness

The OSS flywheel:

1. Developer adopts for a single agent project → writes Rego policies
2. Policies accumulate → switching cost increases (the policy library is not portable)
3. Tool spreads within the org → security/compliance team reviews
4. Security team finds audit, RBAC, or SSO requirements → enterprise conversation opens
5. Enterprise customer's policies contribute to the community library → more developers adopt

The monetisable assets:
- The policy library (switching cost)
- Compliance evidence packages (not portable to any other tool)
- Session forensics data (accumulated history)
- IdP integration depth (IT procurement decision, not developer choice)

---

## Current status (2026-04-13)

| Item | Status |
|---|---|
| License changed to Apache 2.0 | ✅ Done |
| All BUSL-1.1 SPDX headers replaced | ✅ Done |
| Entry-point plugin system (`kitelogik.edition`) | ✅ Done |
| v0.1.0 released | ✅ Done |
| All improvement plan phases (1-4) complete | ✅ Done — 681 tests, 11 adapters, Regorus, hierarchy, YAML compiler, CLI |
| OSS repo ready to publish | ✅ See `docs/oss-publish-checklist.md` — only email/PyPI registration remaining |
| Enterprise repo created | ✅ Done |
| Enterprise feature transfer | ✅ Done — dashboard, gateway, orchestrator, sandbox, SIEM, Prometheus, MCP mock server, Anchor REST API, Postgres backends moved to `kitelogik-enterprise` |
