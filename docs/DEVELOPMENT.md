# Development Guide

This guide covers development setup, testing, and contribution guidelines for the Metasploit MCP Server.

## Quick Start

### Prerequisites
- Python 3.8 or higher
- Poetry ([Installation Guide](https://python-poetry.org/docs/#installation))
- Metasploit Framework with RPC enabled

### Setup Development Environment

```bash
# Clone the repository
git clone <repository-url>
cd MetasploitMCP

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell

# Run tests to verify setup
poetry run pytest
```

## Development Workflow

### Running the Server

```bash
# Development mode with debug logging
poetry run metasploit-mcp --transport http --host 127.0.0.1 --port 8085

# With custom Metasploit connection
MSF_PASSWORD=yourpassword MSF_SERVER=127.0.0.1 MSF_PORT=55553 poetry run metasploit-mcp --transport http
```

### Testing

```bash
# Run all tests
poetry run pytest

# Run specific test file
poetry run pytest tests/test_helpers.py -v

# Run with coverage
poetry run pytest tests/ --cov=. --cov-report=html
```

### Code Quality

```bash
# Format code (if you add formatting tools)
poetry run black src tests

# Lint code (if you add linting tools)
poetry run flake8 src tests

# Type checking (if you add mypy)
poetry run mypy src
```

## Project Structure

```
MetasploitMCP/
├── src/
│   └── metasploit_mcp/           # Main package
│       ├── __init__.py           # Package entry point with main()
│       ├── server.py             # MCP server implementation
│       ├── event_loop_monitor.py # Async event loop monitoring
│       ├── instance_manager.py   # Metasploit instance management
│       └── jsonrpc_patch.py      # JSON-RPC monkeypatch for pymetasploit3
├── pyproject.toml            # Poetry configuration and dependencies
├── tests/                    # Test suite
│   ├── conftest.py           # Pytest configuration and fixtures
│   ├── harness.py            # Metasploitable 3 integration harness
│   └── test_*.py             # Test modules
└── docs/                     # Documentation
    ├── DEVELOPMENT.md        # This file
    ├── POETRY_MIGRATION.md   # Poetry migration guide
    └── API.md                # API documentation
```

## JSON-RPC Support

MetasploitMCP includes a monkeypatch module (`metasploit_mcp/jsonrpc_patch.py`) that adds JSON-RPC protocol support to pymetasploit3. This allows runtime selection between msgpack RPC (default) and JSON-RPC via the `MSF_RPC_PROTOCOL` environment variable.

### How It Works

The patch intercepts pymetasploit3's serialization/deserialization methods:
- `pymetasploit3.utils.encode()` - Serializes RPC requests
- `pymetasploit3.utils.decode()` - Deserializes RPC responses
- `MsfRpcClient.__init__()` - Sets HTTP Content-Type headers
- `MsfRpcClient.post_request()` - Ensures correct headers for protocol

### Protocol Selection

```bash
# Use JSON-RPC
export MSF_RPC_PROTOCOL=jsonrpc

# Use msgpack (default)
export MSF_RPC_PROTOCOL=msgpack
# or omit the variable
```

### Testing the Patch

```bash
# Run JSON-RPC patch tests
poetry run pytest tests/test_jsonrpc_patch.py -v

# Test with JSON-RPC enabled
MSF_RPC_PROTOCOL=jsonrpc poetry run metasploit-mcp --transport http
```

### Implementation Details

The patch is automatically applied when the module is imported (if JSON-RPC is enabled). It must be imported before any `MsfRpcClient` instances are created, which is why it's imported early in `metasploit_mcp/server.py`.

## Testing Guidelines

### Test Categories

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test tool workflows with mocked Metasploit backend
- **IP Validation Tests**: Test bind address validation logic

### Writing Tests

1. Use descriptive test names that explain what is being tested
2. Follow the AAA pattern: Arrange, Act, Assert
3. Mock external dependencies (Metasploit RPC, network calls)
4. Test both success and error cases
5. Use appropriate fixtures from `conftest.py`

### Test Fixtures

- `mock_asyncio_to_thread`: Mocks `asyncio.to_thread` for async testing
- `mock_client`: Provides a mocked Metasploit RPC client
- `mock_exploit_environment`: Sets up exploit testing environment

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_PASSWORD` | `yourpassword` | Metasploit RPC password |
| `MSF_SERVER` | `127.0.0.1` | Metasploit RPC server address |
| `MSF_PORT` | `55553` | Metasploit RPC port |
| `MSF_SSL` | `false` | Enable SSL for Metasploit RPC |
| `MSF_RPC_PROTOCOL` | `msgpack` | RPC protocol: `msgpack` (default) or `jsonrpc` |
| `PAYLOAD_SAVE_DIR` | `~/payloads` | Directory to save generated payloads |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |

## Contributing

### Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and add tests
4. Ensure all tests pass: `poetry run pytest`
5. Update documentation if needed
6. Commit with descriptive messages
7. Push to your fork and create a Pull Request

### Code Style

- Follow PEP 8 Python style guidelines
- Use type hints where appropriate
- Write docstrings for public functions and classes
- Keep functions focused and reasonably sized
- Use meaningful variable and function names

### Commit Messages

Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `test:` for test additions/changes
- `refactor:` for code refactoring
- `chore:` for maintenance tasks

## Debugging

### Common Issues

1. **Metasploit Connection Failed**: Ensure Metasploit RPC is running and credentials are correct
2. **Port Already in Use**: Use `--find-port` flag or specify a different port
3. **Import Errors**: Ensure Poetry environment is activated

### Debug Mode

```bash
# Enable debug logging
LOG_LEVEL=DEBUG poetry run metasploit-mcp --transport http
```

### Testing with Real Metasploit

```bash
# Start Metasploit with RPC
msfconsole -q
msf6 > load msgrpc ServerHost=127.0.0.1 ServerPort=55553 User=msf Pass=yourpassword

# In another terminal, run the server
MSF_PASSWORD=yourpassword poetry run metasploit-mcp --transport http
```
