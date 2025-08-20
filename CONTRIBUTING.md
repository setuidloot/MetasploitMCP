# Contributing to Metasploit MCP Server

Thank you for your interest in contributing to the Metasploit MCP Server! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow:

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professionalism in all interactions

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Poetry for dependency management
- Git for version control
- Metasploit Framework (for testing with real backend)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/MetasploitMCP.git
   cd MetasploitMCP
   ```

2. **Install Dependencies**
   ```bash
   poetry install
   poetry shell
   ```

3. **Verify Setup**
   ```bash
   poetry run python run_all_tests.py
   ```

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use the issue template** if available
3. **Provide clear reproduction steps**
4. **Include relevant system information**

#### Bug Reports Should Include:
- Clear description of the problem
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Python version, Poetry version)
- Relevant log output
- Metasploit version (if applicable)

#### Feature Requests Should Include:
- Clear description of the proposed feature
- Use case and motivation
- Possible implementation approach
- Any breaking changes considerations

### Pull Requests

#### Before Submitting

1. **Create an issue** to discuss major changes
2. **Fork the repository** and create a feature branch
3. **Write tests** for new functionality
4. **Update documentation** as needed
5. **Ensure all tests pass**

#### Pull Request Process

1. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Your Changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation if needed

3. **Test Your Changes**
   ```bash
   # Run all tests
   poetry run python run_all_tests.py
   
   # Run specific tests
   poetry run pytest tests/test_your_feature.py -v
   ```

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

#### PR Requirements

- [ ] All tests pass
- [ ] New functionality has tests
- [ ] Documentation updated (if applicable)
- [ ] CHANGELOG.md updated
- [ ] Commit messages follow conventional format
- [ ] No merge conflicts with main branch

## Development Guidelines

### Code Style

- **Follow PEP 8** Python style guidelines
- **Use type hints** where appropriate
- **Write docstrings** for public functions and classes
- **Keep functions focused** and reasonably sized
- **Use meaningful names** for variables and functions

### Testing

#### Test Categories

- **Unit Tests**: Test individual functions (`test_helpers.py`)
- **Integration Tests**: Test tool workflows (`test_tools_integration.py`)
- **Feature Tests**: Test specific features (`test_ip_validation.py`)

#### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch

class TestYourFeature:
    """Test suite for your feature."""
    
    def test_success_case(self):
        """Test the happy path."""
        # Arrange
        input_data = {"key": "value"}
        
        # Act
        result = your_function(input_data)
        
        # Assert
        assert result["status"] == "success"
    
    def test_error_case(self):
        """Test error handling."""
        with pytest.raises(ValueError):
            your_function(invalid_input)
```

#### Test Guidelines

- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Mock external dependencies
- Test both success and error cases
- Use appropriate fixtures from `conftest.py`

### Documentation

#### Code Documentation

- **Docstrings**: Use Google-style docstrings
- **Type hints**: Include for function parameters and returns
- **Comments**: Explain complex logic, not obvious code

```python
def validate_bind_address(bind_address: str) -> Tuple[bool, str]:
    """
    Validate that a bind address is either a wildcard or locally configured.
    
    Args:
        bind_address: IP address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
        
    Raises:
        ValueError: If address format is invalid
    """
```

#### Project Documentation

- Update `README.md` for user-facing changes
- Update `docs/API.md` for new tools or parameters
- Update `docs/DEVELOPMENT.md` for development process changes
- Update `CHANGELOG.md` for all changes

### Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

#### Types:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks
- `ci:` CI/CD changes

#### Examples:
```
feat: add bind address validation for listeners

fix: resolve FastMCP HTTP transport configuration issue

docs: update API documentation for new parameters

test: add integration tests for payload generation
```

## Release Process

### Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md` with release notes
3. Ensure all tests pass
4. Create release branch
5. Tag release
6. Update documentation

## Getting Help

### Resources

- **Documentation**: Check `docs/` directory
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions

### Contact

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Pull Requests**: For code contributions

## Recognition

Contributors will be recognized in:

- `CHANGELOG.md` for significant contributions
- GitHub contributors list
- Release notes for major contributions

Thank you for contributing to the Metasploit MCP Server! 🚀
