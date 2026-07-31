# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.1] - 2026-07-31

First release published to PyPI (`pip install metasploit-mcp`).

### Security
- **Guard against console command injection via module options**
  (CVE-2026-5463 / GHSA-qpc3-8vqg-8g6w in `pymetasploit3`, unpatched upstream):
  reject newline, carriage-return, and NUL characters in module/payload option
  names and values across both the RPC and console execution paths, so a value
  like `RHOSTS=10.0.0.1\nsessions -K` can no longer inject extra console commands.
- Bump `mcp` to `>=1.28.1` to clear three high-severity advisories
  (GHSA-vj7q-gjh5-988w, GHSA-jpw9-pfvf-9f58, GHSA-hvrp-rf83-w775).

### Added
- CI quality gates (packaging build + `twine check`, `black --check`, advisory
  `mypy`) and an SBOM freshness check; the release now attaches `sbom.json`.

### Changed
- Marked the package **unofficial** with an explicit no-affiliation-with-Rapid7
  notice; credited upstream author GH05TCREW; owner references updated to
  `setuidloot`.

## [3.0.0] - 2026-04-29

### Highlights
- **Modern src layout** - Proper Python package structure with `src/metasploit_mcp/`
- **Improved CLI** - New `metasploit-mcp` command-line entry point
- **Public release** - Documentation and project structure finalized

### Breaking Changes
- Package restructured to `src/metasploit_mcp/`
- Entry point: use `metasploit-mcp` CLI command or `from metasploit_mcp import ...`
- Scripts consolidated in `scripts/` directory

## [2.0.0]

Major rewrite:
- Poetry dependency management (replaced requirements.txt)
- FastMCP HTTP transport (replaced SSE)
- Intelligent payload/module option detection
- Port availability checking
- Comprehensive test suite (92+ tests)
- Metasploitable 3 test harness
- Per-session locking for concurrent access safety

## [1.0.0]

Initial MCP server implementation:
- Core Metasploit RPC integration
- Exploit, payload, and session management
- Console command execution
- Background job management
