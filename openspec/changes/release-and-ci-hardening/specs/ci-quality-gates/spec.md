## ADDED Requirements

### Requirement: CI verifies the distribution is buildable and well-formed

CI SHALL, on every pull request and push to the default branch, build the source distribution and wheel and run `twine check` against them, failing the pipeline if the build fails or metadata is invalid.

#### Scenario: Packaging error caught before release

- **WHEN** a change breaks package metadata or the build
- **THEN** the CI packaging job fails on the pull request, before any release tag is created

#### Scenario: Valid package passes

- **WHEN** the package builds and `twine check` reports no errors
- **THEN** the packaging job succeeds and uploads the built artifacts for inspection

### Requirement: CI enforces code-quality gates

CI SHALL run the project's existing formatting and type-checking tools (`black --check` and `mypy`) on every pull request and push, failing the pipeline on any violation.

#### Scenario: Unformatted code fails CI

- **WHEN** a pull request contains code that does not satisfy `black --check`
- **THEN** the CI quality job fails

#### Scenario: Type error fails CI

- **WHEN** a pull request introduces a `mypy` type error in checked paths
- **THEN** the CI quality job fails

### Requirement: CI verifies the SBOM is up to date

CI SHALL regenerate the SBOM from `poetry.lock` and fail if the committed `sbom.json` differs from the regenerated output, preventing the SBOM from drifting out of sync with the locked dependencies.

#### Scenario: Stale SBOM caught

- **WHEN** dependencies change but `sbom.json` is not regenerated in the same pull request
- **THEN** the CI SBOM-freshness check fails and reports that `sbom.json` is out of date

#### Scenario: Fresh SBOM passes

- **WHEN** `sbom.json` matches the output regenerated from the current `poetry.lock`
- **THEN** the SBOM-freshness check succeeds
