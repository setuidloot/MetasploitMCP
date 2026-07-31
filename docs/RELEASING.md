# Releasing

Releases are **tag-driven**. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which builds
the distribution, publishes it to PyPI, and creates a GitHub Release. There is no
auto-bump on every push — cutting a release is a deliberate action.

## One-time setup

The publish job uses [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC) rather than a stored API token, so no PyPI secret is kept in the repo.

1. On PyPI, add a **Trusted Publisher** for the `metasploit-mcp` project:
   - Owner / repository: `setuidloot/MetasploitMCP`
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
3. Regenerate the SBOM so its root version matches the release, then commit it:

   ```bash
   make sbom        # regenerates sbom.json from poetry.lock + pyproject.toml
   make sbom-check  # verifies sbom.json is in sync (CI and the release run this)
   ```

   CI and the release build both fail if `sbom.json` is stale, so this must be
   committed alongside the version bump.
4. Commit the version bump (and regenerated `sbom.json`) and merge it to `main`.
5. Tag the release commit and push the tag. The tag **must** match the
   `pyproject.toml` version (the workflow verifies this and fails otherwise):

   ```bash
   git tag v3.0.1
   git push origin v3.0.1
   ```

## What the workflow does

- **build** — installs Poetry, verifies the tag matches `pyproject.toml`,
  verifies `sbom.json` is in sync with `poetry.lock` (`--check`), runs
  `poetry build`, and validates metadata with `twine check`. The SBOM is
  uploaded as a separate `sbom` artifact (kept out of `dist/` so the PyPI
  publish step never sees a non-package file).
- **pypi-publish** — publishes the built sdist and wheel to PyPI via the `pypi`
  environment using Trusted Publishing (OIDC).
- **github-release** — creates a GitHub Release for the tag with
  auto-generated notes and attaches the built sdist, wheel, **and `sbom.json`**.

## CI gates (on every PR and push)

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs, in addition to
the test matrix:

- **quality** — `black --check` (blocking) and `mypy` (advisory for now; a
  pre-existing type backlog is being burned down before it becomes blocking).
- **sbom freshness** — `scripts/generate_sbom.py --check`; fails if `sbom.json`
  is out of date. Fix with `make sbom` and commit the result.
- **build distribution** — `poetry build` + `twine check` so packaging errors
  are caught before a release tag is cut.

## Verifying a release

```bash
pip install metasploit-mcp==<version>
metasploit-mcp --help
```

The published GitHub Release also carries `sbom.json` (CycloneDX 1.5) as a
downloadable asset for supply-chain verification.
