# Metasploit MCP Server

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Poetry](https://img.shields.io/badge/dependency%20management-poetry-blue.svg)](https://python-poetry.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An **unofficial**, modern, secure Model Context Protocol (MCP) server that provides AI assistants with controlled access to Metasploit Framework functionality.

> **Unofficial project — not affiliated with Rapid7.** "Metasploit" is a trademark of Rapid7. This is an
> independent, community-maintained project with **no affiliation, sponsorship, endorsement, or support
> from Rapid7**. It is not an official Rapid7 or Metasploit product.

> **Fork notice:** This project is a fork of [GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP),
> the original Metasploit MCP server created by GH05TCREW. Full credit for the original design and
> implementation goes to GH05TCREW; this fork contributes **additional features and the PyPI release**
> on top of that work. It is distributed under the same Apache License 2.0.
> See [Relationship to upstream](#relationship-to-upstream) for what this fork changes and improves.

## Features

### Core Capabilities
- **Exploit Management**: Search, configure, and execute Metasploit exploits
- **Non-destructive checks**: `check_vulnerability` runs a module's `check` without exploiting
- **Payload Generation**: Create custom payloads with advanced encoding options
- **Session Management**: Control active sessions with command execution
- **Listener Management**: Start and manage reverse handlers
- **Workspace database intelligence**: Read hosts, services, vulnerabilities, notes, credentials, and loot from the Metasploit database
- **Async results**: Retrieve results of long-running module runs with `get_module_results`

### MCP protocol features
- **Tool annotations**: every tool advertises `readOnly` / `destructive` hints
- **Structured output**: typed results with a text fallback for older clients
- **Resources**: `msf://server/info` and `msf://module/{module}` documentation
- **Elicitation**: optional client confirmation before destructive actions

See **[docs/MCP_API.md](docs/MCP_API.md)** for the full tool/resource reference,
MCP specification conformance, and a comparison with the official Rapid7 MCP.

### Security Features
- **Optional safe mode**: offensive tools (exploit/module execution, payload generation, session/listener control) are **enabled by default** (this is an offensive tool). Harden a deployment with `--safe-mode` (or `MSF_MCP_ALLOW_DANGEROUS=false`) to expose **read-only tools only**. *(This intentionally inverts the official Rapid7 server's default-off posture to avoid regressing existing users.)*
- **Optional rate limiting**: off by default; enable a per-minute cap with `--rate-limit N`
- **Optional confirmation**: `--confirm-dangerous` asks the client to approve each destructive action via MCP elicitation
- **Bind Address Validation**: Rejects bind addresses that are neither a wildcard nor an IP configured on the host
- **Input Sanitization**: Comprehensive validation of all parameters, including rejection of control characters in module options (command-injection guard)
- **Error Handling**: Prevents information leakage through proper error management

> ⚠️ **Binding default is `0.0.0.0` (all interfaces) for compatibility, not security.**
> Reverse-handler listeners default to binding all interfaces so payloads on remote
> targets can connect back. This is intentional for offensive use but is **not** a
> locked-down default — on a shared or untrusted network, restrict it by passing an
> explicit `reverselistenerbindaddress` (e.g. a specific interface IP).

### Modern Development
- **Poetry Dependency Management**: Modern Python packaging and dependency resolution
- **Comprehensive Testing**: 92+ tests covering unit, integration, and security scenarios
- **Type Hints**: Full type annotation support for better IDE experience
- **FastMCP HTTP Transport**: Modern HTTP-based MCP protocol implementation
- **Development Tools**: Integrated linting, formatting, and type checking

## Prerequisites

- **Python 3.10+** (3.11+ recommended)
- **Poetry** for dependency management ([Installation Guide](https://python-poetry.org/docs/#installation))
- **Metasploit Framework** with RPC enabled

## Quick Start

### 1. Installation

**From PyPI (recommended):**

```bash
pip install metasploit-mcp
```

This installs the `metasploit-mcp` CLI. To try it without installing into your
environment, use [`pipx`](https://pipx.pypa.io/): `pipx run metasploit-mcp --help`.

**From source (for development):**

```bash
git clone https://github.com/setuidloot/MetasploitMCP.git
cd MetasploitMCP
poetry install
poetry shell
```

### 2. Start Metasploit RPC

```bash
# Start Metasploit RPC service
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553

# Or from msfconsole
msfconsole -q
msf6 > load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=yourpassword
```

### 3. Configure Environment (Optional)

```bash
export MSF_PASSWORD=yourpassword
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553
export PAYLOAD_SAVE_DIR=/path/to/save/payloads
export MSF_RPC_PROTOCOL=msgpack  # Options: 'msgpack' (default) or 'jsonrpc'
```

**RPC Protocol Options:**
- `msgpack` (default): Uses MessagePack binary serialization (faster, more compact)
- `jsonrpc`: Uses JSON-RPC protocol (human-readable, easier to debug)

### 4. Run the Server

```bash
# Full toolset (default) — offensive tools enabled
metasploit-mcp --transport http --host 127.0.0.1 --port 8085

# Hardened: read-only tools only
metasploit-mcp --transport http --safe-mode

# Optional: require client confirmation before each destructive action
metasploit-mcp --transport http --confirm-dangerous

# Optional: cap dangerous requests per minute
metasploit-mcp --transport http --rate-limit 60

# From source
poetry run metasploit-mcp --transport stdio
make run          # or: make run-debug
```

> By default the server exposes the **full toolset** (offensive tools enabled).
> Pass `--safe-mode` (or set `MSF_MCP_ALLOW_DANGEROUS=false`) to expose read-only
> tools only. See [docs/MCP_API.md](docs/MCP_API.md#safety-model) for the full safety model.

## Development

### Development Setup

```bash
# Complete development environment setup
make dev-setup

# Or manually
poetry install
poetry run pre-commit install
make test
```

### Available Commands

```bash
# Show all available commands
make help

# Quick development workflow
make quick-check    # Format, lint, and quick test
make full-check     # Complete quality check with coverage

# Testing
make test           # Run all tests
make test-coverage  # Run with coverage report
make test-watch     # Watch mode for development

# Code quality
make format         # Format code with black
make lint           # Run linting checks
make type-check     # Run type checking
```

### Project Structure

```
MetasploitMCP/
├── src/
│   └── metasploit_mcp/           # Main package
│       ├── __init__.py           # Package entry point with main()
│       ├── server.py             # MCP server implementation
│       ├── event_loop_monitor.py # Async event loop monitoring
│       ├── instance_manager.py   # Metasploit instance management
│       └── jsonrpc_patch.py      # pymetasploit3 JSON-RPC patch
├── scripts/                      # Utility scripts
│   ├── bump_version.py           # Version bumping
│   ├── run_tests.py              # Test runners
│   └── ...
├── tests/                        # Comprehensive test suite
│   ├── conftest.py               # Pytest fixtures
│   ├── harness.py                # Metasploitable3 test harness
│   └── test_*.py                 # Test modules
├── docs/                         # Documentation
│   ├── API.md                    # Complete API reference
│   ├── DEVELOPMENT.md            # Development guide
│   ├── TROUBLESHOOTING.md        # Common issues and solutions
│   ├── METASPLOITABLE3_TESTING.md # Integration testing guide
│   └── QUICK_START_TESTING.md    # Quick start for testing
├── examples/                     # Example scripts
├── pyproject.toml                # Poetry configuration
├── Makefile                      # Development commands
├── CHANGELOG.md                  # Version history
└── CONTRIBUTING.md               # Contribution guidelines
```

## Integration

### Claude Desktop

Configure `claude_desktop_config.json` (after `pip install metasploit-mcp`):

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "metasploit-mcp",
            "args": [
                "--transport", "stdio"
            ],
            "env": {
                "MSF_PASSWORD": "yourpassword",
                "MSF_SERVER": "127.0.0.1",
                "MSF_PORT": "55553"
            }
        }
    }
}
```

Add `"--safe-mode"` to the args to expose read-only tools only. If you installed
from source instead of PyPI, use `"command": "poetry"` with
`"args": ["run", "metasploit-mcp", …]` and a `"cwd"` pointing at the checkout.

### Other MCP Clients

For HTTP-based MCP clients:

```bash
# Start HTTP server
metasploit-mcp --transport http --host 0.0.0.0 --port 8085

# MCP endpoint: http://your-server:8085/mcp
```

## Security Considerations

**IMPORTANT**: This tool provides direct access to Metasploit Framework capabilities. Use responsibly and only in authorized environments.

### Security Features

- **Bind Address Validation**: Rejects addresses that are neither a wildcard nor a host-configured IP
- **Input Sanitization**: All parameters are validated before processing; control characters in module options are rejected (command-injection guard)
- **Error Handling**: Prevents information disclosure through proper error management

> ⚠️ **Listeners bind `0.0.0.0` (all interfaces) by default** — a compatibility choice for
> catching reverse connections, **not** a hardened default. Pass an explicit
> `reverselistenerbindaddress` to restrict the binding on shared/untrusted networks.

### Best Practices

- Only use in authorized testing environments
- Restrict listener bind addresses (`reverselistenerbindaddress`) when you don't need all interfaces
- Validate all commands before execution
- Monitor generated payloads and their usage
- Use strong passwords for Metasploit RPC
- Regularly update dependencies

## API Reference

### Core Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_exploits` | Search exploit modules | `platform_filter`, `search_term` |
| `run_exploit` | Execute exploits | `module_name`, `options`, `payload_name` |
| `generate_payload` | Create payloads | `payload_type`, `format_type`, `options` |
| `start_listener` | Start handlers | `payload_type`, `lhost`, `lport` |
| `list_active_sessions` | Show sessions | None |
| `send_session_command` | Execute commands | `session_id`, `command` |

### Features in v3.0

- **Modern src layout**: Proper Python package structure
- **CLI entry point**: `metasploit-mcp` command
- **Bind Address Control**: `reverse_listener_bind_address` parameter
- **Port Binding**: `reverse_listener_bind_port` parameter
- **IP Validation**: Automatic validation of bind addresses
- **FastMCP Transport**: Modern HTTP-based MCP protocol

For complete API documentation, see [docs/API.md](docs/API.md).

## Testing

### Running Tests

```bash
# All tests with coverage
make test-coverage

# Quick test run
make test-quick

# Watch mode for development
make test-watch

# Specific test categories
make test-unit          # Unit tests only
make test-integration   # Integration tests only
```

### Test Coverage

The project maintains high test coverage with 92+ tests covering:

- **Unit Tests**: Individual function testing
- **Integration Tests**: End-to-end workflow testing
- **Security Tests**: Bind address validation and input sanitization
- **Error Handling**: Comprehensive error scenario testing

Coverage reports are generated in `htmlcov/index.html`.

### Metasploitable 3 Integration Testing

Test MetasploitMCP against real vulnerable targets using the included test harness:

```bash
# List available exploit tests
poetry run python tests/harness.py --list-tests

# Run all tests against Metasploitable 3
poetry run python tests/harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 4444

# Run specific test
poetry run python tests/harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD ModCopy Exec"
```

The harness includes tests for:
- ProFTPD ModCopy Exec
- Apache Shellshock
- Drupal Drupageddon
- phpMyAdmin RCE
- Ruby on Rails ActionPack
- UnrealIRCd Backdoor

For detailed documentation, see:
- [Quick Start Guide](docs/QUICK_START_TESTING.md)
- [Full Testing Documentation](docs/METASPLOITABLE3_TESTING.md)

## Documentation

- **[API Reference](docs/API.md)**: Complete tool documentation with examples
- **[Development Guide](docs/DEVELOPMENT.md)**: Setup, testing, and contribution guidelines
- **[Troubleshooting](docs/TROUBLESHOOTING.md)**: Common issues and solutions
- **[Integration Testing](docs/METASPLOITABLE3_TESTING.md)**: Testing with Metasploitable 3
- **[Quick Start Testing](docs/QUICK_START_TESTING.md)**: 5-minute testing setup
- **[Poetry Migration](docs/POETRY_MIGRATION.md)**: Migration from requirements.txt
- **[Releasing](docs/RELEASING.md)**: How maintainers cut a release
- **[Changelog](CHANGELOG.md)**: Version history and breaking changes
- **[Contributing](CONTRIBUTING.md)**: How to contribute to the project

## Migration from v2.x

### Key Changes in v3.0

- **src Layout**: Package moved to `src/metasploit_mcp/`
- **CLI Entry Point**: Use `metasploit-mcp` command
- **Import Path**: Use `from metasploit_mcp import ...`

### Migration Steps

```bash
# Pull latest changes
git pull

# Reinstall dependencies
poetry install

# Run tests to verify
make test
```

For detailed migration information, see [docs/POETRY_MIGRATION.md](docs/POETRY_MIGRATION.md).

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Set up development environment: `make dev-setup`
4. Make changes and add tests
5. Run quality checks: `make full-check`
6. Submit a pull request

## Relationship to upstream

This project is a fork of **[GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP)**,
the original Metasploit MCP server created by **GH05TCREW** (`harmasic@gmail.com`). Full credit for the
original design and implementation goes to the upstream author. This fork retains the upstream
**Apache License 2.0** (see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)).

**Upstream base (GH05TCREW):** core Metasploit RPC integration, exploit / payload / session / console
management, and background job handling — originally a single-file server with a `requirements.txt`
install and SSE transport.

**What this fork changes and improves:**

- **Packaging & distribution** — Poetry-based packaging, a `src/metasploit_mcp/` layout, a
  `metasploit-mcp` CLI entry point (replacing the single-file `requirements.txt` setup), and the
  **first PyPI release** of the project (`pip install metasploit-mcp`).
- **Transport** — FastMCP HTTP (streamable) transport, replacing SSE.
- **Dynamic option detection** — module/payload options are queried live from Metasploit instead of
  being hardcoded, with detection of confused module/payload options.
- **Concurrency safety** — per-session locking to prevent concurrent Meterpreter/shell access, plus a
  per-agent Metasploit instance manager for isolation.
- **Reliability** — async event-loop monitoring (blocking/backlog detection), MCP keep-alive to
  prevent client timeouts, an RPC timeout cap with client cleanup and `auth.logout`, session-ID
  normalization with fallback lookups, and force-option validation against module capabilities.
- **Quality** — a comprehensive test suite, a Metasploitable 3 integration harness, and dependency
  security updates.

See [`CHANGELOG.md`](CHANGELOG.md) for the detailed version history.

## License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](LICENSE) file for the
full text and the [`NOTICE`](NOTICE) file for attribution. As a fork, it preserves the license of the
upstream [GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP) project.

## Acknowledgments

- **[GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP)**: The original project this fork is based on — full credit to GH05TCREW for the core design and implementation
- **Metasploit Framework**: The powerful penetration testing platform, by Rapid7 (this project is unaffiliated with and unsupported by Rapid7)
- **Model Context Protocol**: The standardized AI-tool communication protocol
- **FastMCP**: Modern MCP server implementation framework
- **Poetry**: Modern Python dependency management

---

**Disclaimer**: This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before using this tool in any environment.
