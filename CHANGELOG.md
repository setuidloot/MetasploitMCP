# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
