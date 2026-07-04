# Releasing

Releases are **tag-driven**. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which builds
the distribution, publishes it to PyPI, and creates a GitHub Release. There is no
auto-bump on every push — cutting a release is a deliberate action.

## One-time setup

The publish job uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC) rather than a stored API token, so no PyPI secret is kept in the repo.

1. On PyPI, add a **Trusted Publisher** for the `metasploit-mcp` project:
   - Owner / repository: `cbdmaul/MetasploitMCP`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`
2. In the GitHub repo settings, create an **Environment** named `pypi` (this
   matches `environment: name: pypi` in the workflow).

## Cutting a release

1. Update [`CHANGELOG.md`](../CHANGELOG.md) with the new version and its changes.
2. Bump the version so `pyproject.toml` and `server.json` agree on the target:

   ```bash
   poetry version <major|minor|patch>   # or an explicit version, e.g. 3.0.1
   ```

   Update the `version` fields in [`server.json`](../server.json) (both the
   top-level and the package entry) to match.
3. Commit the version bump and merge it to `main`.
4. Tag the release commit and push the tag. The tag **must** match the
   `pyproject.toml` version (the workflow verifies this and fails otherwise):

   ```bash
   git tag v3.0.1
   git push origin v3.0.1
   ```

## What the workflow does

- **build** — installs Poetry, verifies the tag matches `pyproject.toml`, runs
  `poetry build`, and validates metadata with `twine check`.
- **pypi-publish** — publishes the built artifacts to PyPI via the `pypi`
  environment using Trusted Publishing (OIDC).
- **github-release** — creates a GitHub Release for the tag with
  auto-generated notes and attaches the built sdist and wheel.

## Verifying a release

```bash
pip install metasploit-mcp==<version>
metasploit-mcp --help
```
