# sbom-release-integration Specification

## Purpose
TBD - created by archiving change release-and-ci-hardening. Update Purpose after archive.
## Requirements
### Requirement: Release build produces a verified SBOM

The release workflow SHALL generate the CycloneDX SBOM during the release build and verify it matches the committed `sbom.json`, failing the release if it is stale.

#### Scenario: SBOM generated at release time

- **WHEN** a release build runs for a pushed version tag
- **THEN** the workflow regenerates the SBOM from `poetry.lock` and confirms it matches the committed `sbom.json`

#### Scenario: Stale SBOM blocks release

- **WHEN** the committed `sbom.json` does not match the regenerated SBOM during a release build
- **THEN** the release build fails with a clear message before publishing

### Requirement: SBOM is published as a release artifact

The release workflow SHALL attach the SBOM to the GitHub Release alongside the built distributions, so consumers can retrieve the bill of materials for any published version.

#### Scenario: SBOM attached to GitHub Release

- **WHEN** a GitHub Release is created for a version tag
- **THEN** the release assets include `sbom.json` in addition to the sdist and wheel

#### Scenario: SBOM version matches release

- **WHEN** the SBOM is attached to a release for version X
- **THEN** the SBOM's root component version equals X

