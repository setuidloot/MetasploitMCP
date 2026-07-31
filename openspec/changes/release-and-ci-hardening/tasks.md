## 1. SBOM freshness tooling

- [x] 1.1 Add a `--check` mode to `scripts/generate_sbom.py` that regenerates in-memory and exits non-zero if it differs from committed `sbom.json`, printing `make sbom` as the fix
- [x] 1.2 Add a unit test asserting generate → `--check` round-trips clean (deterministic output)
- [x] 1.3 Add/confirm a `make sbom-check` Makefile target that runs the `--check` mode

## 2. CI quality gates (ci.yml)

- [x] 2.1 Add a `build` job: `poetry build` + `twine check dist/*`, upload dist as artifact (runs on PR + push)
- [x] 2.2 Add a `quality` job: `black --check` (blocking) over `src` and `tests`
- [x] 2.3 Add `mypy` to the `quality` job for `src/metasploit_mcp` (non-blocking / advisory initially per design D4 — 27 pre-existing errors)
- [x] 2.4 Add a `sbom-check` job (or step) running `scripts/generate_sbom.py --check`
- [ ] 2.5 Verify all new jobs run green on this branch's PR (each step verified locally; actual PR run pending push)

## 3. SBOM-on-release (release.yml)

- [x] 3.1 In the `build` job, run the SBOM `--check` (fail fast if stale) before building
- [x] 3.2 Include `sbom.json` in the build (as a separate `sbom` artifact, so PyPI publish never sees a non-package file)
- [x] 3.3 Add `sbom.json` to the `github-release` job's `files:` so it attaches to the GitHub Release
- [x] 3.4 Confirm the attached SBOM's root component version equals the release tag version (transitively guaranteed: tag == pyproject version, and SBOM root version is read from pyproject)

## 4. Documentation

- [x] 4.1 Update `docs/RELEASING.md`: document the new CI gates, SBOM freshness check, and SBOM-on-release behavior
- [x] 4.2 Note the `make sbom` / `make format` fixes for the new gates in `CONTRIBUTING.md`

## 5. Verification & follow-up

- [x] 5.1 Run `openspec validate release-and-ci-hardening` (valid)
- [ ] 5.2 Dry-run a release on a throwaway tag (or `workflow_dispatch`) to confirm SBOM attaches and PyPI/GH-release steps still pass (requires push; build/twine/sbom steps verified locally)
- [ ] 5.3 (Follow-up) Once the baseline is clean, flip `mypy` to blocking (27 errors in 4 files as of now)
- [ ] 5.4 Archive the change once shipped
