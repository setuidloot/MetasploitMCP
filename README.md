# Metasploit MCP Server

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Poetry](https://img.shields.io/badge/dependency%20management-poetry-blue.svg)](https://python-poetry.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A modern, secure Model Context Protocol (MCP) server that provides AI assistants with controlled access to Metasploit Framework functionality.

## 🚀 Features

### 🎯 Core Capabilities
- **Exploit Management**: Search, configure, and execute Metasploit exploits
- **Payload Generation**: Create custom payloads with advanced encoding options
- **Session Management**: Control active sessions with command execution
- **Listener Management**: Start and manage reverse handlers
- **Security Validation**: Built-in bind address validation and input sanitization

### 🔒 Security Features
- **Bind Address Validation**: Ensures listeners only bind to authorized interfaces
- **Input Sanitization**: Comprehensive validation of all parameters
- **Secure Defaults**: Listeners default to `0.0.0.0` binding for maximum compatibility
- **Error Handling**: Prevents information leakage through proper error management

### 🛠 Modern Development
- **Poetry Dependency Management**: Modern Python packaging and dependency resolution
- **Comprehensive Testing**: 92+ tests covering unit, integration, and security scenarios
- **Type Hints**: Full type annotation support for better IDE experience
- **FastMCP HTTP Transport**: Modern HTTP-based MCP protocol implementation
- **Development Tools**: Integrated linting, formatting, and type checking

## 📋 Prerequisites

- **Python 3.8+** (3.11+ recommended)
- **Poetry** for dependency management ([Installation Guide](https://python-poetry.org/docs/#installation))
- **Metasploit Framework** with RPC enabled

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/cbdmaul/MetasploitMCP.git
cd MetasploitMCP

# Install with Poetry (recommended)
poetry install
poetry shell

# Or install with pip (legacy support)
pip install -r requirements.txt  # Note: Legacy files removed in v2.0
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
```

### 4. Run the Server

```bash
# Using Poetry (recommended)
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

# Using Make
make run

# Debug mode
make run-debug
```

## 🔧 Development

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
├── MetasploitMCP.py          # Main server implementation
├── pyproject.toml            # Poetry configuration
├── Makefile                  # Development commands
├── tests/                    # Comprehensive test suite
│   ├── test_helpers.py       # Helper function tests
│   ├── test_ip_validation.py # Security validation tests
│   ├── test_options_parsing.py # Input parsing tests
│   ├── test_tools_integration.py # Integration tests
│   └── test_metasploitable3_harness.py # Integration test harness tests
├── docs/                     # Documentation
│   ├── API.md               # Complete API reference
│   ├── DEVELOPMENT.md       # Development guide
│   ├── TROUBLESHOOTING.md   # Common issues and solutions
│   ├── METASPLOITABLE3_TESTING.md # Integration testing guide
│   └── QUICK_START_TESTING.md # Quick start for testing
├── examples/                 # Example scripts
├── CHANGELOG.md             # Version history
└── CONTRIBUTING.md          # Contribution guidelines
```

## 🔌 Integration

### Claude Desktop

Configure `claude_desktop_config.json`:

```json
{
    "mcpServers": {
        "metasploit": {
            "command": "poetry",
            "args": [
                "run", "python", "MetasploitMCP.py",
                "--transport", "stdio"
            ],
            "cwd": "/path/to/MetasploitMCP",
            "env": {
                "MSF_PASSWORD": "yourpassword"
            }
        }
    }
}
```

### Other MCP Clients

For HTTP-based MCP clients:

```bash
# Start HTTP server
poetry run python MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085

# MCP endpoint: http://your-server:8085/mcp
```

## 🛡 Security Considerations

⚠️ **IMPORTANT**: This tool provides direct access to Metasploit Framework capabilities. Use responsibly and only in authorized environments.

### Security Features

- **Bind Address Validation**: Prevents binding to unauthorized network interfaces
- **Input Sanitization**: All parameters are validated before processing
- **Secure Defaults**: Listeners default to `0.0.0.0` for maximum compatibility
- **Error Handling**: Prevents information disclosure through proper error management

### Best Practices

- Only use in authorized testing environments
- Validate all commands before execution
- Monitor generated payloads and their usage
- Use strong passwords for Metasploit RPC
- Regularly update dependencies

## 📚 API Reference

### Core Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `list_exploits` | Search exploit modules | `platform_filter`, `search_term` |
| `run_exploit` | Execute exploits | `module_name`, `options`, `payload_name` |
| `generate_payload` | Create payloads | `payload_type`, `format_type`, `options` |
| `start_listener` | Start handlers | `payload_type`, `lhost`, `lport` |
| `list_active_sessions` | Show sessions | None |
| `send_session_command` | Execute commands | `session_id`, `command` |

### New in v2.0

- **Bind Address Control**: `reverse_listener_bind_address` parameter
- **Port Binding**: `reverse_listener_bind_port` parameter  
- **IP Validation**: Automatic validation of bind addresses
- **FastMCP Transport**: Modern HTTP-based MCP protocol

For complete API documentation, see [docs/API.md](docs/API.md).

## 🧪 Testing

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
poetry run python metasploitable3_test_harness.py --list-tests

# Run all tests against Metasploitable 3
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 4444

# Run specific test
poetry run python metasploitable3_test_harness.py \
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

## 📖 Documentation

- **[API Reference](docs/API.md)**: Complete tool documentation with examples
- **[Development Guide](docs/DEVELOPMENT.md)**: Setup, testing, and contribution guidelines
- **[Troubleshooting](docs/TROUBLESHOOTING.md)**: Common issues and solutions
- **[Integration Testing](docs/METASPLOITABLE3_TESTING.md)**: Testing with Metasploitable 3
- **[Quick Start Testing](docs/QUICK_START_TESTING.md)**: 5-minute testing setup
- **[Poetry Migration](docs/POETRY_MIGRATION.md)**: Migration from requirements.txt
- **[Changelog](CHANGELOG.md)**: Version history and breaking changes
- **[Contributing](CONTRIBUTING.md)**: How to contribute to the project

## 🔄 Migration from v1.x

### Key Changes in v2.0

- **Poetry**: Replaced requirements.txt with Poetry dependency management
- **FastMCP**: Migrated from SSE to HTTP transport
- **Security**: Added bind address validation and secure defaults
- **Testing**: Expanded test suite with 92+ tests
- **Documentation**: Comprehensive docs in `docs/` directory

### Migration Steps

```bash
# Remove old virtual environment
rm -rf venv/

# Install Poetry if not already installed
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies with Poetry
poetry install

# Update configuration (same environment variables)
# Run tests to verify migration
make test
```

For detailed migration information, see [docs/POETRY_MIGRATION.md](docs/POETRY_MIGRATION.md).

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Set up development environment: `make dev-setup`
4. Make changes and add tests
5. Run quality checks: `make full-check`
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Metasploit Framework**: The powerful penetration testing platform
- **Model Context Protocol**: The standardized AI-tool communication protocol
- **FastMCP**: Modern MCP server implementation framework
- **Poetry**: Modern Python dependency management

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before using this tool in any environment.