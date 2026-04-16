# Release Process

Releases are automated via GitHub Actions. This document describes the process for maintainers.

## Checklist

Before tagging a release:

1. All CI checks pass on `main` (lint, test, OPA policy tests, pip-audit)
2. `CHANGELOG.md` is updated with the new version and release notes
3. Version in `pyproject.toml` matches the tag you're about to create
4. Coverage threshold is met (75% minimum)
5. No `pip-audit` vulnerabilities in dependencies

## How to Release

```bash
# 1. Update version in pyproject.toml
# 2. Update CHANGELOG.md
# 3. Commit and push to main
git add pyproject.toml CHANGELOG.md
git commit -m "Release v0.x.y"
git push origin main

# 4. Tag and push — this triggers the release workflow
git tag v0.x.y
git push origin v0.x.y
```

## What Happens Automatically

The `release.yml` workflow triggers on `v*` tags and:

1. **Builds** the sdist and wheel (`python -m build`)
2. **Publishes to PyPI** via trusted publishing (OIDC, no API token stored)
3. **Creates a GitHub Release** with auto-generated release notes and attached dist artifacts

## PyPI Trusted Publishing

The project uses [PyPI trusted publishing](https://docs.pypi.org/trusted-publishers/) via OpenID Connect. No API tokens are stored in GitHub secrets. Configure at:

https://pypi.org/manage/project/kitelogik/settings/publishing/

## Post-Release

- Verify the package is live: `pip install kitelogik==0.x.y`
- Check the GitHub Release page for auto-generated notes
- Announce on relevant channels
