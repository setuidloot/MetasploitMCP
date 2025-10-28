# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Intelligent Payload/Module Option Detection**: Automatically detects when payload options are incorrectly provided as module options
  - **Queries Metasploit directly** for valid module and payload options (100% accurate, always up-to-date)
  - No hardcoded option lists to maintain - works with all current and future modules/payloads
  - Payload-specific validation - checks against the exact payload being used
  - Provides clear, actionable error messages with actual valid option names from Metasploit
  - Shows side-by-side WRONG vs CORRECT code examples with specific option names
  - Helps AI agents and humans quickly fix configuration errors
  - Zero performance overhead for correct configurations (only queries on errors)
  - Documented in `docs/INTELLIGENT_ERROR_DETECTION.md`
- **Job Cleanup on Session Termination**: `terminate_session()` now automatically kills associated handler jobs to release ports
  - New `kill_associated_job` parameter (default: True) controls whether to kill handler job
  - Searches for job_id in session info and terminates it
  - Returns count of jobs killed in response
  - Releases ports that would otherwise remain bound after session termination
- **`kill_all_handler_jobs()` Tool**: New MCP tool to kill all active handler jobs
  - Finds all exploit/multi/handler jobs
  - Kills them to release bound ports
  - Returns detailed statistics (killed count, failed, still running)
  - Useful for cleaning up after failed exploits or test runs
- **Port Availability Checking**: MetasploitMCP now validates that LPORT is available before attempting to bind listeners
  - `check_port_available()` helper function checks if a port can be bound on specified interface
  - Pre-flight port validation in `start_listener()` - returns clear error if port is already in use
  - Pre-flight port validation in `run_exploit()` - checks LPORT in payload_options before running
  - Optional port validation in `generate_payload()` - logs warning if port is unavailable
  - Provides early, actionable error messages instead of cryptic bind failures from Metasploit
- **Metasploitable 3 Test Harness**: Comprehensive integration testing tool that acts as an MCP client to test the full MetasploitMCP server stack against real vulnerable targets
  - Tests 6 major Metasploitable 3 vulnerabilities (ProFTPD, Shellshock, Drupal, phpMyAdmin, Rails, UnrealIRCd)
  - **Automatic Session Cleanup**: Kills all active sessions before running tests to free up ports (prevents port conflicts)
  - `--no-cleanup` flag to skip session cleanup and preserve existing sessions
  - Automated session detection and verification
  - Detailed test reporting with timing metrics
  - Configurable target, LHOST, and LPORT parameters
  - Comprehensive unit tests with 92% coverage
- **Testing Documentation**:
  - `docs/METASPLOITABLE3_TESTING.md` - Complete reference guide
  - `docs/QUICK_START_TESTING.md` - Fast setup guide
  - `INTEGRATION_TEST_SETUP.md` - Step-by-step walkthrough
- **Testing Tools**:
  - `metasploitable3_test_harness.py` - Main test harness (MCP client)
  - `tests/test_metasploitable3_harness.py` - Comprehensive unit tests
  - `examples/metasploitable3_quicktest.sh` - Quick verification script
- **Makefile Targets**:
  - `make test-harness` - Run harness unit tests
  - `make test-metasploitable3` - Run integration tests
  - `make test-metasploitable3-quick` - Quick single-test verification
  - `make list-metasploitable3-tests` - List available tests
- **Dependencies**:
  - Added `httpx>=0.24.0` for MCP client HTTP communication
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
- Updated test harness to use correct `/mcp` endpoint (was incorrectly using `/mcp/sse`)
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
