# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Poetry dependency management with `pyproject.toml`
- Comprehensive documentation in `docs/` directory
- Modern `.gitignore` with comprehensive Python project exclusions
- Development guide and API documentation
- FastMCP HTTP transport support
- Bind address validation for listener security
- Custom bind address and port configuration for listeners
- IP address validation against local network interfaces
- Comprehensive test suite with 92+ tests
- Custom test runner for fixture isolation

### Changed
- **BREAKING**: Migrated from requirements.txt to Poetry for dependency management
- **BREAKING**: Converted from SSE transport to FastMCP HTTP transport
- Default bind address for listeners now defaults to `0.0.0.0` instead of LHOST
- Improved error handling and logging throughout
- Enhanced test coverage with integration and unit tests
- Modernized project structure and organization

### Removed
- Legacy `requirements.txt` and `requirements-test.txt` files
- SSE transport implementation and related FastAPI/Starlette dependencies
- Custom FastAPI routing and SSE endpoint implementations

### Fixed
- FastMCP HTTP transport configuration issues
- Bind address logic to ensure proper `0.0.0.0` binding
- Test fixture conflicts when running full test suite
- Async/await compatibility issues in test mocks

### Security
- Added bind address validation to prevent binding to unauthorized interfaces
- Enhanced input validation for all MCP tools
- Improved error handling to prevent information leakage

## [1.5.0] - Previous Version

### Added
- Initial MCP server implementation
- Core Metasploit integration via RPC
- Basic exploit, payload, and session management tools
- Console command execution capabilities
- Background job management

### Features
- Exploit module listing and execution
- Payload generation and management
- Active session management and command execution
- Listener (handler) management
- Health check endpoint
- Configurable timeouts and logging

## Migration Guide

### From 1.5.0 to 2.0.0

#### Dependency Management
```bash
# Old way
pip install -r requirements.txt

# New way
poetry install
poetry shell
```

#### Server Startup
```bash
# Old way (SSE transport)
python MetasploitMCP.py --transport http

# New way (HTTP transport - same command, different implementation)
poetry run python MetasploitMCP.py --transport http
```

#### Configuration
- Environment variables remain the same
- Command line arguments remain the same
- MCP tool interfaces remain the same
- Only the underlying transport mechanism changed

#### Testing
```bash
# Old way
python -m pytest tests/

# New way (recommended)
poetry run python run_all_tests.py
```

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed development setup and contribution guidelines.

## API Documentation

See [docs/API.md](docs/API.md) for complete API documentation and examples.
