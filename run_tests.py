#!/usr/bin/env python3
"""
Test runner script for MetasploitMCP.
Provides convenient commands for running different test suites.
"""

import sys
import os
import argparse
import subprocess
from pathlib import Path

def run_command(cmd, description=""):
    """Run a command and handle errors."""
    if description:
        print(f"\n🔄 {description}")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✅ Success!")
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed with exit code {e.returncode}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return False

def check_dependencies():
    """Check if test dependencies are installed."""
    try:
        import pytest
        import pytest_asyncio
        import pytest_mock
        import pytest_cov
        return True
    except ImportError as e:
        print(f"❌ Missing test dependency: {e}")
        print("💡 Install test dependencies with: pip install -r requirements-test.txt")
        return False

def main():
    parser = argparse.ArgumentParser(description="MetasploitMCP Test Runner")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--options", action="store_true", help="Run options parsing tests only")
    parser.add_argument("--helpers", action="store_true", help="Run helper function tests only")
    parser.add_argument("--tools", action="store_true", help="Run MCP tools tests only")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage report")
    parser.add_argument("--html", action="store_true", help="Generate HTML coverage report")
    parser.add_argument("--slow", action="store_true", help="Include slow tests")
    parser.add_argument("--network", action="store_true", help="Include network tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--install-deps", action="store_true", help="Install test dependencies")
    
    args = parser.parse_args()
    
    # Handle dependency installation
    if args.install_deps:
        return run_command([
            sys.executable, "-m", "pip", "install", "-r", "requirements-test.txt"
        ], "Installing test dependencies")
    
    # Check dependencies
    if not check_dependencies():
        return False
    
    # Build pytest command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add verbosity
    if args.verbose:
        cmd.append("-v")
    
    # Add coverage options
    if args.coverage or args.html:
        cmd.extend(["--cov=MetasploitMCP", "--cov-report=term-missing"])
        if args.html:
            cmd.append("--cov-report=html:htmlcov")
    
    # Add slow/network test options
    if args.slow:
        cmd.append("--run-slow")
    if args.network:
        cmd.append("--run-network")
    
    # Determine which tests to run
    if args.options:
        cmd.append("tests/test_options_parsing.py")
        description = "Running options parsing tests"
    elif args.helpers:
        cmd.append("tests/test_helpers.py")
        description = "Running helper function tests"
    elif args.tools:
        cmd.append("tests/test_tools_integration.py")
        description = "Running MCP tools integration tests"
    elif args.unit:
        cmd.extend(["-m", "unit"])
        description = "Running unit tests"
    elif args.integration:
        cmd.extend(["-m", "integration"])
        description = "Running integration tests"
    elif args.all:
        cmd.append("tests/")
        description = "Running all tests"
    else:
        # Default: run all tests
        cmd.append("tests/")
        description = "Running all tests (default)"
    
    # Run the tests
    success = run_command(cmd, description)
    
    if success and (args.coverage or args.html):
        print("\n📊 Coverage report generated")
        if args.html:
            html_path = Path("htmlcov/index.html").resolve()
            print(f"📄 HTML report: file://{html_path}")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
