## Context

MetasploitMCP v3.0.0 ships with a working release pipeline: `.github/workflows/ci.yml` (pytest matrix, py3.10–3.13, Poetry), `.github/workflows/release.yml` (tag-driven; verifies tag == `pyproject` version, `poetry build`, `twine check`, PyPI OIDC Trusted Publishing, and a `github-release` job using `softprops/action-gh-release` with `generate_release_notes`), a deterministic offline SBOM generator (`scripts/generate_sbom.py` → CycloneDX 1.5 `sbom.json`), a `Makefile` with `sbom`/`build`/`publish`/`version-bump-*` targets, and `docs/RELEASING.md`.

The `nessus-export` repo is the stated blueprint but is actually less complete (no SBOM, no version automation, no GitHub Release job). Its one relevant idea we lack is a CI `build` job that runs `python -m build` + `twine check` on every PR. This change closes the three real gaps: no packaging/quality gate in CI, no SBOM freshness enforcement, and no SBOM shipped with releases.

## Goals / Non-Goals

**Goals:**
- Catch packaging, formatting, typing, and SBOM-drift problems on PRs — before a release tag is cut.
- Make every published release carry a verified SBOM as a downloadable asset.
- Reuse existing scripts/tooling; add the minimum new surface.

**Non-Goals:**
- Re-implementing PyPI publishing, tag/version verification, GitHub Release creation, or version-bump tooling (all already present and working).
- Switching build backend (stays `poetry.core.masonry.api`) or dependency manager.
- Signing artifacts (e.g., Sigstore) — a possible later change, out of scope here.

## Decisions

**D1 — Extend the existing `ci.yml` with parallel jobs, don't fork a new workflow.**
Add `build` (poetry build + `twine check`), `quality` (`black --check`, `mypy`), and `sbom-check` jobs alongside the existing `tests` job. Rationale: single CI surface, jobs run in parallel, matches how `nessus-export` structures test+build. Alternative: a separate `quality.yml` — rejected as redundant fan-out.
- Use Poetry (as the existing `tests` job does) rather than `python -m build`, so the toolchain stays consistent with `release.yml` (`poetry build`).

**D2 — SBOM freshness via a `--check` mode on the existing generator.**
Add a `--check` flag to `scripts/generate_sbom.py` that regenerates in-memory and diffs against the committed `sbom.json`, exiting non-zero on mismatch. Rationale: the generator is already deterministic and offline (per its docstring), so a byte-diff is reliable; reusing it keeps one source of truth. CI and release both call `--check`. Alternative: `git diff --exit-code` after regenerating in CI — workable but mutates the working tree and is less self-documenting; `--check` is cleaner and locally runnable.

**D3 — Release attaches `sbom.json` by adding it to the build job's artifact and the release `files:` glob.**
In `release.yml`, run the SBOM `--check` in the `build` job (fail fast if stale) and upload `sbom.json` in the same artifact as `dist/`; then have `github-release` include it via `files:`. Rationale: minimal change to the proven release flow; keeps the verify-then-publish ordering. Alternative: regenerate-and-commit during release — rejected (mutating the repo mid-release is fragile; we prefer verify-and-fail so the committed SBOM stays the source of truth).

**D4 — `mypy` scope is pinned to avoid a noisy first run.**
Type-check the package (`src/metasploit_mcp`) with the existing `pyproject`/Makefile `mypy` config; if a clean baseline isn't achievable immediately, keep the `quality` job's `mypy` step non-blocking initially (documented) or narrow paths, so the gate can land without a large refactor. `black --check` is expected to already pass (the repo applied black formatting recently) and is blocking from day one.

## Risks / Trade-offs

- **First `mypy` run surfaces many pre-existing errors** → land `black --check` blocking immediately; introduce `mypy` narrowed or non-blocking first, then tighten in a follow-up. Documented in the task list.
- **SBOM `--check` false-positives from nondeterminism** → the generator is documented as deterministic/offline; add a test that generate → `--check` round-trips clean, and pin the tool version.
- **Stricter CI may block unrelated PRs** → the gates target objective, auto-fixable issues (`black`, stale SBOM has a one-command fix `make sbom`); document the fixes in `docs/RELEASING.md`/`CONTRIBUTING.md`.
- **SBOM freshness depends on contributors regenerating after dep changes** → that is exactly what the CI check enforces; the failure message names `make sbom` as the fix.

## Migration Plan

1. Add `scripts/generate_sbom.py --check` mode + a unit test for round-trip.
2. Add `build`, `quality`, `sbom-check` jobs to `ci.yml` (black blocking; mypy narrowed/non-blocking initially).
3. Wire SBOM verify + attach into `release.yml`.
4. Update `docs/RELEASING.md` (and CONTRIBUTING) with the new gates and the `make sbom` fix.
5. Tighten `mypy` to blocking in a follow-up once the baseline is clean.
- **Rollback:** each job/edit is independent; reverting the workflow edits restores prior behavior with no release-mechanism impact.

## Open Questions

- Should `mypy` be blocking in this change or deferred to a follow-up? (Proposed: non-blocking/narrowed now, blocking later — depends on current error count.)
- Should the SBOM also be uploaded to PyPI (it cannot be a PyPI artifact directly) or only to the GitHub Release? (Proposed: GitHub Release only; PyPI carries sdist/wheel.)
- Do we also want `pip-audit`/`safety` in the `quality` job now, or keep that to the existing `make security-check`? (Proposed: out of scope here.)
