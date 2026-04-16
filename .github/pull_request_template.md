## Summary

<!-- What does this PR do? One to three bullet points. -->

-

## Related issue

<!-- Link to the issue this PR addresses, e.g. Fixes #42 -->

Fixes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Policy change (Rego)
- [ ] Documentation
- [ ] Refactor / test improvement

## Checklist

- [ ] Tests added or updated (all new code paths covered)
- [ ] `pytest -q --ignore=tests/integration --ignore=tests/adversarial` passes locally
- [ ] `ruff check . && ruff format --check .` passes with no errors
- [ ] If Rego was changed: `opa test kitelogik/policies/ -v` passes and policy test updated
- [ ] If a new policy rule was added: default-deny case covered by OPA test
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No secrets, credentials, or API keys in diff
- [ ] No `*.db`, `*.jsonl`, or `.env` files in diff

## Testing notes

<!-- How did you test this? What edge cases did you consider? -->

## Security considerations

<!-- Does this change affect a security boundary? Note it here.
     Relevant boundaries: policy gate, credential lifecycle, sandbox isolation,
     MCP response sanitization, audit log immutability. -->
