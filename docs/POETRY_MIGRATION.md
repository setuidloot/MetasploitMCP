# Poetry Migration Guide

This project has been migrated from requirements.txt files to Poetry for better dependency management.

## Installation with Poetry

### Prerequisites
- Python 3.8 or higher
- Poetry installed ([Installation Guide](https://python-poetry.org/docs/#installation))

### Setup
```bash
# Install dependencies
poetry install

# Activate the virtual environment
poetry shell

# Or run commands in the poetry environment
poetry run python MetasploitMCP.py --help
```

### Development
```bash
# Install with development dependencies
poetry install --with dev

# Run tests
poetry run python run_all_tests.py

# Or use pytest directly
poetry run pytest tests/ -v
```

### Adding Dependencies
```bash
# Add runtime dependency
poetry add package-name

# Add development dependency  
poetry add --group dev package-name
```

## Migration from requirements.txt

The following dependencies were migrated:

### Runtime Dependencies (from requirements.txt)
- fastapi>=0.95.0
- uvicorn[standard]>=0.22.0  
- pymetasploit3>=1.0.6
- mcp>=1.6.0
- fastmcp>=2.10.3

### Development Dependencies (from requirements-test.txt)
- pytest>=7.0.0
- pytest-asyncio>=0.21.0
- pytest-mock>=3.10.0
- pytest-cov>=4.0.0
- mock>=4.0.3

## Benefits of Poetry

1. **Lock File**: `poetry.lock` ensures reproducible builds
2. **Virtual Environment**: Automatic virtual environment management
3. **Dependency Resolution**: Better dependency conflict resolution
4. **Build System**: Integrated build and publish capabilities
5. **Script Management**: Easy script definition and execution

## Legacy Support

The old requirements.txt files are kept for backward compatibility but Poetry is now the recommended approach.
