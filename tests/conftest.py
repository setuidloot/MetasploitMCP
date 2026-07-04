#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for MetasploitMCP tests.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch

from tests import MockMsfRpcError

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(__file__))


def pytest_configure(config):
    """Configure pytest with custom settings."""
    # Mock external dependencies that might not be available during testing
    # We only mock pymetasploit3 since other dependencies (fastmcp, uvicorn, etc.)
    # are now proper installed dependencies

    # Create mock module with the canonical MsfRpcError exception class
    mock_msfrpc = Mock()
    mock_msfrpc.MsfRpcError = MockMsfRpcError
    mock_msfrpc.MsfRpcClient = Mock
    mock_msfrpc.MsfConsole = Mock

    if "pymetasploit3.msfrpc" not in sys.modules:
        sys.modules["pymetasploit3.msfrpc"] = mock_msfrpc
    if "pymetasploit3" not in sys.modules:
        sys.modules["pymetasploit3"] = Mock(msfrpc=mock_msfrpc)


@pytest.fixture(autouse=True)
def _stable_msf_error():
    """Keep a single, stable ``MsfRpcError`` class across the server module and
    the mocked ``pymetasploit3.msfrpc``.

    Several test modules replace ``sys.modules['pymetasploit3.msfrpc']`` at
    import time with their own mock (and historically their own error class),
    so by the time tests run the class identity could differ from the one
    ``metasploit_mcp.server`` captured at import. Since ``except MsfRpcError``
    is resolved against the server module's globals at runtime, we re-assert the
    canonical class on both sides before every test. This makes error-handling
    tests deterministic regardless of collection order.
    """
    msfrpc = sys.modules.get("pymetasploit3.msfrpc")
    if msfrpc is not None:
        msfrpc.MsfRpcError = MockMsfRpcError
    server = sys.modules.get("metasploit_mcp.server")
    if server is not None:
        server.MsfRpcError = MockMsfRpcError
    yield


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add unit marker to test_options_parsing and test_helpers
        if "test_options_parsing" in item.nodeid or "test_helpers" in item.nodeid:
            item.add_marker(pytest.mark.unit)

        # Add integration marker to integration tests
        if "test_tools_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)

        # Mark network tests
        if "network" in item.name.lower():
            item.add_marker(pytest.mark.network)

        # Mark slow tests
        if any(keyword in item.name.lower() for keyword in ["slow", "timeout", "long"]):
            item.add_marker(pytest.mark.slow)


@pytest.fixture(scope="session")
def mock_msf_environment():
    """Session-scoped fixture that provides a complete mock MSF environment."""

    class MockMsfRpcClient:
        def __init__(self):
            self.modules = Mock()
            self.core = Mock()
            self.sessions = Mock()
            self.jobs = Mock()
            self.consoles = Mock()

            # Default return values
            self.core.version = {"version": "6.3.0"}
            self.modules.exploits = []
            self.modules.payloads = []
            self.sessions.list.return_value = {}
            self.jobs.list.return_value = {}

    class MockMsfConsole:
        def __init__(self, cid="test-console"):
            self.cid = cid

        def read(self):
            return {"data": "", "prompt": "msf6 > ", "busy": False}

        def write(self, command):
            return True

    class MockMsfRpcError(Exception):
        pass

    # Apply mocks
    with patch.dict(
        "sys.modules",
        {
            "pymetasploit3.msfrpc": Mock(
                MsfRpcClient=MockMsfRpcClient,
                MsfConsole=MockMsfConsole,
                MsfRpcError=MockMsfRpcError,
            )
        },
    ):
        yield {
            "client_class": MockMsfRpcClient,
            "console_class": MockMsfConsole,
            "error_class": MockMsfRpcError,
        }


@pytest.fixture
def mock_logger():
    """Fixture providing a mock logger."""
    with patch("metasploit_mcp.server.logger") as mock_log:
        yield mock_log


@pytest.fixture
def temp_payload_dir(tmp_path):
    """Fixture providing a temporary directory for payload saves."""
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()

    with patch("metasploit_mcp.server.PAYLOAD_SAVE_DIR", str(payload_dir)):
        yield str(payload_dir)


@pytest.fixture
def mock_asyncio_to_thread():
    """Fixture to mock asyncio.to_thread for testing."""

    async def mock_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    with patch("asyncio.to_thread", side_effect=mock_to_thread):
        yield


@pytest.fixture
def capture_logs(caplog):
    """Fixture to capture and provide log output."""
    import logging

    caplog.set_level(logging.DEBUG)
    return caplog


# Command line options
def pytest_addoption(parser):
    """Add custom command line options."""
    parser.addoption("--run-slow", action="store_true", default=False, help="Run slow tests")
    parser.addoption(
        "--run-network",
        action="store_true",
        default=False,
        help="Run tests that require network access",
    )


def pytest_runtest_setup(item):
    """Setup hook to skip tests based on markers and options."""
    if "slow" in item.keywords and not item.config.getoption("--run-slow"):
        pytest.skip("Skipping slow test (use --run-slow to run)")

    if "network" in item.keywords and not item.config.getoption("--run-network"):
        pytest.skip("Skipping network test (use --run-network to run)")


# Test environment setup
@pytest.fixture(autouse=True)
def reset_msf_client():
    """Automatically reset the global MSF client between tests."""
    # Only patch if MetasploitMCP is already imported
    if "metasploit_mcp.server" in sys.modules:
        with patch.object(sys.modules["metasploit_mcp.server"], "_msf_client_instance", None):
            yield
    else:
        yield
