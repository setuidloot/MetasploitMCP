#!/usr/bin/env python3
"""
Regression tests for check_port_available function to ensure it always returns Tuple[bool, str].

This test file specifically addresses the bug where check_port_available might have returned
a value that didn't match the declared return type Tuple[bool, str].
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from typing import Tuple

# Add the parent directory to the path to import metasploit_mcp.server as MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Mock the dependencies that aren't available in test environment
sys.modules["uvicorn"] = Mock()
sys.modules["fastapi"] = Mock()
sys.modules["starlette.applications"] = Mock()
sys.modules["starlette.routing"] = Mock()


# Create a special mock for FastMCP that preserves the tool decorator behavior
class MockFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self):
        # Return a decorator that just returns the original function
        def decorator(func):
            return func

        return decorator


# Mock the MCP modules with our custom FastMCP
mcp_server_fastmcp = Mock()
mcp_server_fastmcp.FastMCP = MockFastMCP
sys.modules["mcp.server.fastmcp"] = mcp_server_fastmcp
sys.modules["mcp.server.sse"] = Mock()
sys.modules["mcp.server.session"] = Mock()

# Mock pymetasploit3 module
sys.modules["pymetasploit3.msfrpc"] = Mock()

# Import the module after mocking dependencies
import metasploit_mcp.server as MetasploitMCP
from metasploit_mcp.server import check_port_available

pytestmark = pytest.mark.asyncio


class TestCheckPortAvailableReturnType:
    """Test that check_port_available always returns Tuple[bool, str]."""

    async def test_return_type_is_tuple(self):
        """Test that the function returns a tuple."""
        result = await check_port_available(8080, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"

    async def test_return_type_has_correct_types(self):
        """Test that the tuple contains bool and str."""
        result = await check_port_available(8080, "0.0.0.0")
        is_available, error_msg = result
        assert isinstance(
            is_available, bool
        ), f"First element should be bool, got {type(is_available)}"
        assert isinstance(error_msg, str), f"Second element should be str, got {type(error_msg)}"

    async def test_invalid_port_returns_tuple(self):
        """Test that invalid port returns Tuple[bool, str]."""
        result = await check_port_available(0, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is False
        assert "Invalid port" in error_msg

    async def test_invalid_port_too_high_returns_tuple(self):
        """Test that port > 65535 returns Tuple[bool, str]."""
        result = await check_port_available(70000, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is False
        assert "Invalid port" in error_msg

    @patch("metasploit_mcp.server.psutil.net_connections")
    async def test_port_in_use_via_psutil_returns_tuple(self, mock_net_connections):
        """Test that when psutil detects port in use, it returns Tuple[bool, str]."""
        # Mock a connection using the port
        mock_conn = Mock()
        mock_conn.laddr = Mock()
        mock_conn.laddr.port = 4444
        mock_conn.status = "LISTEN"
        mock_conn.raddr = None
        mock_net_connections.return_value = [mock_conn]

        result = await check_port_available(4444, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is False
        assert "already in use" in error_msg

    @patch("metasploit_mcp.server.psutil.net_connections")
    @patch("socket.socket")
    async def test_port_available_returns_tuple(self, mock_socket, mock_net_connections):
        """Test that when port is available, it returns Tuple[bool, str]."""
        # Mock psutil to return no connections
        mock_net_connections.return_value = []

        # Mock socket to successfully bind
        mock_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = await check_port_available(8080, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is True
        assert error_msg == ""

    @patch("metasploit_mcp.server.psutil.net_connections")
    @patch("socket.socket")
    async def test_port_unavailable_socket_bind_returns_tuple(
        self, mock_socket, mock_net_connections
    ):
        """Test that when socket.bind fails, it returns Tuple[bool, str]."""
        # Mock psutil to return no connections (fall through to socket check)
        mock_net_connections.return_value = []

        # Mock socket to fail on bind
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = OSError("Address already in use")
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = await check_port_available(4444, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is False
        assert "already in use" in error_msg

    @patch("metasploit_mcp.server.psutil.net_connections")
    @patch("socket.socket")
    async def test_psutil_access_denied_fallback_returns_tuple(
        self, mock_socket, mock_net_connections
    ):
        """Test that when psutil raises AccessDenied, fallback returns Tuple[bool, str]."""
        import psutil

        # Mock psutil to raise AccessDenied
        mock_net_connections.side_effect = psutil.AccessDenied()

        # Mock socket to successfully bind
        mock_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = await check_port_available(8080, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)

    @patch("metasploit_mcp.server.psutil.net_connections")
    @patch("socket.socket")
    async def test_exception_during_socket_bind_returns_tuple(
        self, mock_socket, mock_net_connections
    ):
        """Test that when an exception occurs during socket bind, it returns Tuple[bool, str]."""
        # Mock psutil to return no connections
        mock_net_connections.return_value = []

        # Mock socket to raise a generic exception
        mock_sock = MagicMock()
        mock_sock.bind.side_effect = Exception("Unexpected error")
        mock_socket.return_value.__enter__.return_value = mock_sock

        result = await check_port_available(4444, "0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"
        is_available, error_msg = result
        assert isinstance(is_available, bool)
        assert isinstance(error_msg, str)
        assert is_available is False
        assert "Error checking port" in error_msg

    async def test_all_return_paths_are_tuples(self):
        """Comprehensive test to ensure all code paths return Tuple[bool, str]."""
        test_cases = [
            # (port, host, description)
            (0, "0.0.0.0", "invalid port too low"),
            (70000, "0.0.0.0", "invalid port too high"),
            (8080, "0.0.0.0", "valid port"),
            (4444, "127.0.0.1", "valid port with specific host"),
        ]

        for port, host, description in test_cases:
            with patch("metasploit_mcp.server.psutil.net_connections", return_value=[]):
                with patch("socket.socket") as mock_socket:
                    mock_sock = MagicMock()
                    mock_socket.return_value.__enter__.return_value = mock_sock

                    result = await check_port_available(port, host)
                    assert isinstance(
                        result, tuple
                    ), f"Failed for {description}: Expected tuple, got {type(result)}"
                    assert (
                        len(result) == 2
                    ), f"Failed for {description}: Expected tuple of length 2, got {len(result)}"
                    is_available, error_msg = result
                    assert isinstance(
                        is_available, bool
                    ), f"Failed for {description}: First element should be bool, got {type(is_available)}"
                    assert isinstance(
                        error_msg, str
                    ), f"Failed for {description}: Second element should be str, got {type(error_msg)}"


class TestCheckPortAvailableUnpacking:
    """Test that check_port_available can be correctly unpacked as (bool, str)."""

    async def test_can_unpack_result(self):
        """Test that the result can be unpacked into two variables."""
        port_available, port_error = await check_port_available(8080, "0.0.0.0")
        assert isinstance(port_available, bool)
        assert isinstance(port_error, str)

    async def test_unpacking_matches_usage_pattern(self):
        """Test that unpacking matches the actual usage pattern in the codebase."""
        # This is how it's used in the codebase:
        # port_available, port_error = check_port_available(bind_port, bind_address)
        bind_port = 4444
        bind_address = "0.0.0.0"

        port_available, port_error = await check_port_available(bind_port, bind_address)

        # Verify types
        assert isinstance(port_available, bool)
        assert isinstance(port_error, str)

        # Verify the values make sense
        if port_available:
            assert port_error == ""
        else:
            assert len(port_error) > 0


class TestValidateBindAddressReturnType:
    """Test that validate_bind_address always returns Tuple[bool, str] (similar function)."""

    async def test_validate_bind_address_return_type_is_tuple(self):
        """Test that validate_bind_address returns a tuple."""
        from metasploit_mcp.server import validate_bind_address

        result = await validate_bind_address("0.0.0.0")
        assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
        assert len(result) == 2, f"Expected tuple of length 2, got {len(result)}"

    async def test_validate_bind_address_return_type_has_correct_types(self):
        """Test that the tuple contains bool and str."""
        from metasploit_mcp.server import validate_bind_address

        result = await validate_bind_address("0.0.0.0")
        is_valid, error_msg = result
        assert isinstance(is_valid, bool), f"First element should be bool, got {type(is_valid)}"
        assert isinstance(error_msg, str), f"Second element should be str, got {type(error_msg)}"

    async def test_validate_bind_address_all_paths_return_tuple(self):
        """Test all code paths return Tuple[bool, str]."""
        from metasploit_mcp.server import validate_bind_address

        test_cases = [
            ("0.0.0.0", "wildcard IPv4"),
            ("::", "wildcard IPv6"),
            ("", "empty address"),
            ("invalid.ip", "invalid format"),
            ("127.0.0.1", "loopback"),
        ]

        for address, description in test_cases:
            with patch(
                "metasploit_mcp.server.get_local_ip_addresses", return_value=["127.0.0.1", "::1"]
            ):
                result = await validate_bind_address(address)
                assert isinstance(
                    result, tuple
                ), f"Failed for {description}: Expected tuple, got {type(result)}"
                assert (
                    len(result) == 2
                ), f"Failed for {description}: Expected tuple of length 2, got {len(result)}"
                is_valid, error_msg = result
                assert isinstance(
                    is_valid, bool
                ), f"Failed for {description}: First element should be bool, got {type(is_valid)}"
                assert isinstance(
                    error_msg, str
                ), f"Failed for {description}: Second element should be str, got {type(error_msg)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
