## Why

MetasploitMCP already has a mature release pipeline (tag-driven PyPI Trusted Publishing, version-vs-tag verification, auto GitHub release with generated notes, a CycloneDX SBOM generator, and `docs/RELEASING.md`). Three gaps remain relative to best practice and the `nessus-export` blueprint: (1) CI runs tests only, so packaging breakage and lint/type regressions are not caught until a release tag is pushed; (2) the SBOM is generated manually and can silently drift from `poetry.lock`; and (3) the SBOM is never attached to the GitHub release or shipped with the artifacts. Closing these makes releases reproducible and supply-chain-verifiable without adding any new release mechanism.

## What Changes

- **Add a packaging-verification job to CI** (`ci.yml`): build the sdist + wheel and run `twine check dist/*` on every PR and push, so metadata/packaging errors are caught before tagging (as `nessus-export` does).
- **Add a code-quality gate to CI**: run the existing tooling (`black --check`, `mypy`) that today only exists in the `Makefile`, so formatting/type regressions fail PRs.
- **Add an SBOM freshness check to CI**: regenerate the SBOM and fail if `sbom.json` differs from what `poetry.lock` would produce, preventing drift.
- **Attach the SBOM to releases** (`release.yml`): generate/verify `sbom.json` during the release build and include it in the GitHub Release assets alongside `dist/*`.
- **Update `docs/RELEASING.md`** to document the new CI gates and SBOM-on-release behavior.

Non-goals (already implemented, unchanged): PyPI OIDC publishing, tag/version verification, GitHub Release creation, version-bump tooling.

## Capabilities

### New Capabilities
- `ci-quality-gates`: CI must verify packaging, code quality, and SBOM freshness on every PR/push, not just run the test suite.
- `sbom-release-integration`: The release process must produce a verified SBOM and publish it as a release artifact.

### Modified Capabilities
<!-- No pre-existing OpenSpec requirement specs exist for the release pipeline (OpenSpec was just initialized), so existing behavior is captured as new requirements rather than modifications. -->

## Impact

- **CI/CD**: `.github/workflows/ci.yml` (new `build` + `quality` + `sbom-check` jobs), `.github/workflows/release.yml` (SBOM generation + attach to GitHub Release).
- **Scripts**: reuse existing `scripts/generate_sbom.py`; possibly add a `--check` mode for the freshness verification.
- **Docs**: `docs/RELEASING.md`.
- **Dev experience**: PRs will now fail on packaging, formatting, typing, or stale SBOM — a stricter gate than today.
- **No changes** to publishing credentials/mechanism (OIDC Trusted Publishing remains), versioning, or the GitHub Release trigger.
