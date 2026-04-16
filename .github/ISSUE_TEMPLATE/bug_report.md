---
name: Bug report
about: Report a reproducible bug in Kite Logik
title: "[Bug] "
labels: bug
assignees: ""
---

## Describe the bug

A clear description of what the bug is and what you expected to happen instead.

## Component

Which layer is affected?

- [ ] Tether (policy gate / OPA evaluation)
- [ ] Anchor (HITL queue / credentials)
- [ ] Sandbox (container isolation)
- [ ] Memory (provenance store)
- [ ] Gateway (MCP gateway server)
- [ ] Dashboard
- [ ] Adapters (`@governed`, OpenAI, LangChain)
- [ ] Other

## Steps to reproduce

```
1.
2.
3.
```

## Expected behaviour

What should have happened.

## Actual behaviour

What actually happened. Include the full error message and traceback if applicable.

## Environment

- Kite Logik version:
- Python version:
- OPA version (`opa version`):
- Docker version (`docker version`):
- OS:

## Minimal reproduction

A minimal script or `pytest` test that reproduces the issue (strongly preferred over a description alone).

```python

```

## Additional context

Anything else relevant — logs, trace output, policy files, etc.
