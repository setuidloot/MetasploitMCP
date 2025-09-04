# Makefile for MetasploitMCP - Modern Poetry-based Development Workflow

.PHONY: help install dev-install test test-unit test-integration test-coverage test-watch lint format type-check pre-commit clean build publish dev-setup check ci docs serve-docs

# Colors for output
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
RESET := \033[0m

# Default target
help: ## Show this help message
	@echo "$(BLUE)MetasploitMCP Development Commands$(RESET)"
	@echo ""
	@echo "$(GREEN)Setup:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Setup:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Setup:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Development:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Development:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Development:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Testing:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Testing:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Testing:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Quality:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Quality:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Quality:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Build & Deploy:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Build & Deploy:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Build & Deploy:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(GREEN)Utilities:$(RESET)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / && /Utilities:/ {found=1; next} found && /^[a-zA-Z_-]+:.*?## / && !/Utilities:/ {found=0} found {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Setup targets
install: ## Setup: Install production dependencies only
	@echo "$(BLUE)Installing production dependencies...$(RESET)"
	poetry install --only=main

dev-install: ## Setup: Install all dependencies including development tools
	@echo "$(BLUE)Installing all dependencies...$(RESET)"
	poetry install
	@echo "$(GREEN)✓ Development environment ready!$(RESET)"

dev-setup: dev-install ## Setup: Complete development environment setup
	@echo "$(BLUE)Setting up pre-commit hooks...$(RESET)"
	poetry run pre-commit install
	@echo "$(BLUE)Running initial tests...$(RESET)"
	$(MAKE) test
	@echo "$(GREEN)✓ Development setup complete!$(RESET)"

# Development targets
run: ## Development: Run the MCP server in development mode
	@echo "$(BLUE)Starting MetasploitMCP server...$(RESET)"
	poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

run-debug: ## Development: Run server with debug logging
	@echo "$(BLUE)Starting MetasploitMCP server in debug mode...$(RESET)"
	LOG_LEVEL=DEBUG poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

shell: ## Development: Open Poetry shell
	poetry shell

# Testing targets
test: ## Testing: Run all tests using custom test runner
	@echo "$(BLUE)Running all tests...$(RESET)"
	poetry run python run_all_tests.py

test-unit: ## Testing: Run unit tests only
	@echo "$(BLUE)Running unit tests...$(RESET)"
	poetry run pytest tests/test_helpers.py tests/test_options_parsing.py -v

test-integration: ## Testing: Run integration tests only
	@echo "$(BLUE)Running integration tests...$(RESET)"
	poetry run pytest tests/test_tools_integration.py tests/test_ip_validation.py -v

test-coverage: ## Testing: Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	poetry run pytest tests/ --cov=. --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)Coverage report: file://$(PWD)/htmlcov/index.html$(RESET)"

test-watch: ## Testing: Run tests in watch mode (requires pytest-watch)
	@echo "$(BLUE)Running tests in watch mode...$(RESET)"
	poetry run ptw -- tests/

test-quick: ## Testing: Run tests without coverage (faster)
	@echo "$(BLUE)Running quick tests...$(RESET)"
	poetry run pytest tests/ -x

test-debug: ## Testing: Run tests with detailed output for debugging
	@echo "$(BLUE)Running tests in debug mode...$(RESET)"
	poetry run pytest tests/ -v --tb=long --capture=no

# Quality targets
lint: ## Quality: Run all linting checks
	@echo "$(BLUE)Running flake8...$(RESET)"
	poetry run flake8 MetasploitMCP.py tests/
	@echo "$(GREEN)✓ Linting passed!$(RESET)"

format: ## Quality: Format code with black
	@echo "$(BLUE)Formatting code with black...$(RESET)"
	poetry run black MetasploitMCP.py tests/
	@echo "$(GREEN)✓ Code formatted!$(RESET)"

format-check: ## Quality: Check if code is properly formatted
	@echo "$(BLUE)Checking code formatting...$(RESET)"
	poetry run black --check MetasploitMCP.py tests/

type-check: ## Quality: Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(RESET)"
	poetry run mypy MetasploitMCP.py
	@echo "$(GREEN)✓ Type checking passed!$(RESET)"

pre-commit: ## Quality: Run pre-commit hooks on all files
	@echo "$(BLUE)Running pre-commit hooks...$(RESET)"
	poetry run pre-commit run --all-files

check: lint type-check test ## Quality: Run all quality checks
	@echo "$(GREEN)✓ All quality checks passed!$(RESET)"

# Build & Deploy targets
build: ## Build & Deploy: Build the package
	@echo "$(BLUE)Building package...$(RESET)"
	poetry build
	@echo "$(GREEN)✓ Package built successfully!$(RESET)"

publish-test: build ## Build & Deploy: Publish to test PyPI
	@echo "$(BLUE)Publishing to test PyPI...$(RESET)"
	poetry publish --repository testpypi

publish: build ## Build & Deploy: Publish to PyPI
	@echo "$(BLUE)Publishing to PyPI...$(RESET)"
	poetry publish

# Documentation targets
docs: ## Build & Deploy: Generate documentation
	@echo "$(BLUE)Documentation available in docs/ directory$(RESET)"
	@echo "  - docs/API.md - API documentation"
	@echo "  - docs/DEVELOPMENT.md - Development guide"
	@echo "  - docs/POETRY_MIGRATION.md - Poetry migration guide"

serve-docs: ## Build & Deploy: Serve documentation locally (if using mkdocs)
	@echo "$(YELLOW)Documentation is in Markdown format in docs/ directory$(RESET)"
	@echo "$(YELLOW)Consider setting up mkdocs for live documentation serving$(RESET)"

# Utilities
clean: ## Utilities: Clean up generated files and caches
	@echo "$(BLUE)Cleaning up...$(RESET)"
	rm -rf __pycache__/
	rm -rf tests/__pycache__/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	rm -rf .mypy_cache/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleanup complete!$(RESET)"

clean-all: clean ## Utilities: Clean everything including Poetry cache
	@echo "$(BLUE)Cleaning Poetry cache...$(RESET)"
	poetry cache clear --all pypi
	@echo "$(GREEN)✓ Deep cleanup complete!$(RESET)"

deps-update: ## Utilities: Update all dependencies
	@echo "$(BLUE)Updating dependencies...$(RESET)"
	poetry update
	@echo "$(GREEN)✓ Dependencies updated!$(RESET)"

deps-show: ## Utilities: Show dependency tree
	poetry show --tree

security-check: ## Utilities: Check for security vulnerabilities
	@echo "$(BLUE)Checking for security vulnerabilities...$(RESET)"
	poetry run safety check
	@echo "$(GREEN)✓ Security check complete!$(RESET)"

version: ## Utilities: Show current version
	@poetry version

version-bump-patch: ## Utilities: Bump patch version
	poetry version patch

version-bump-minor: ## Utilities: Bump minor version
	poetry version minor

version-bump-major: ## Utilities: Bump major version
	poetry version major

# CI/CD targets
ci: ## Utilities: Run CI pipeline locally
	@echo "$(BLUE)Running CI pipeline...$(RESET)"
	$(MAKE) clean
	$(MAKE) dev-install
	$(MAKE) check
	$(MAKE) test-coverage
	@echo "$(GREEN)✓ CI pipeline completed successfully!$(RESET)"

# Development workflow shortcuts
quick-check: format lint test-quick ## Development: Quick development check (format, lint, quick test)
	@echo "$(GREEN)✓ Quick check completed!$(RESET)"

full-check: format lint type-check test-coverage ## Development: Full development check
	@echo "$(GREEN)✓ Full check completed!$(RESET)"

# Help for specific categories (hidden from main help)
help-setup:
	@echo "$(GREEN)Setup Commands:$(RESET)"
	@echo "  install      - Install production dependencies only"
	@echo "  dev-install  - Install all dependencies including dev tools"
	@echo "  dev-setup    - Complete development environment setup"

help-test:
	@echo "$(GREEN)Testing Commands:$(RESET)"
	@echo "  test         - Run all tests"
	@echo "  test-unit    - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  test-watch   - Run tests in watch mode"
	@echo "  test-quick   - Quick test run without coverage"
	@echo "  test-debug   - Debug test run with detailed output"