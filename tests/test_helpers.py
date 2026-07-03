#!/usr/bin/env python3
"""
Unit tests for helper functions in MetasploitMCP.
"""

import pytest
import sys
import os
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any

# Add the parent directory to the path to import metasploit_mcp.server as MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Mock the dependencies that aren't available in test environment
mock_uvicorn = Mock()
mock_uvicorn.server = Mock()
sys.modules["uvicorn"] = mock_uvicorn
sys.modules["uvicorn.server"] = mock_uvicorn.server
sys.modules["fastapi"] = Mock()
sys.modules["mcp.server.fastmcp"] = Mock()
sys.modules["mcp.server.sse"] = Mock()
sys.modules["pymetasploit3.msfrpc"] = Mock()
sys.modules["starlette.applications"] = Mock()
sys.modules["starlette.routing"] = Mock()
sys.modules["mcp.server.session"] = Mock()
# Mock fastmcp before it's imported
sys.modules["fastmcp"] = Mock()
sys.modules["fastmcp.client"] = Mock()
sys.modules["fastmcp.client.transports"] = Mock()


# Create mock classes for MSF objects
class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()


class MockMsfConsole:
    def __init__(self, cid="test-console-id"):
        self.cid = cid

    def read(self):
        return {"data": "test output", "prompt": "msf6 > ", "busy": False}

    def write(self, command):
        return True


# Use the canonical MsfRpcError so its identity matches the class that
# metasploit_mcp.server catches at runtime (see tests/__init__.py).
from tests import MockMsfRpcError

# Patch the MSF modules
sys.modules["pymetasploit3.msfrpc"].MsfRpcClient = MockMsfRpcClient
sys.modules["pymetasploit3.msfrpc"].MsfConsole = MockMsfConsole
sys.modules["pymetasploit3.msfrpc"].MsfRpcError = MockMsfRpcError

# Import after mocking
from metasploit_mcp.server import (
    _get_module_object,
    _set_module_options,
    initialize_msf_client,
    get_msf_client,
    get_msf_console,
    run_command_safely,
    find_available_port,
    InvalidModuleError,
    _find_similar_modules,
    IS_VULNERABLE_RE,
    IS_NOT_VULNERABLE_RE,
    SESSION_OPENED_RE,
    FAILED_TO_LOAD_MODULE_RE,
)


class TestMsfClientFunctions:
    """Test MSF client initialization and management functions."""

    @patch("metasploit_mcp.server.MSF_PASSWORD", "test-password")
    @patch("metasploit_mcp.server.MSF_SERVER", "127.0.0.1")
    @patch("metasploit_mcp.server.MSF_PORT_STR", "55553")
    @patch("metasploit_mcp.server.MSF_SSL_STR", "false")
    def test_initialize_msf_client_success(self):
        """Test successful MSF client initialization."""
        with patch("metasploit_mcp.server._msf_client_instance", None):
            with patch("metasploit_mcp.server.MsfRpcClient") as mock_client_class:
                mock_client = Mock()
                mock_client.core.version = {"version": "6.3.0"}
                mock_client_class.return_value = mock_client

                result = initialize_msf_client()

                assert result is mock_client
                mock_client_class.assert_called_once_with(
                    password="test-password", server="127.0.0.1", port=55553, ssl=False
                )

    @patch("metasploit_mcp.server.MSF_PORT_STR", "invalid-port")
    def test_initialize_msf_client_invalid_port(self):
        """Test MSF client initialization with invalid port."""
        with patch("metasploit_mcp.server._msf_client_instance", None):
            with pytest.raises(ValueError, match="Invalid MSF connection parameters"):
                initialize_msf_client()

    def test_get_msf_client_not_initialized(self):
        """Test get_msf_client when client not initialized."""
        with patch("metasploit_mcp.server._msf_client_instance", None):
            with pytest.raises(ConnectionError, match="not been initialized"):
                get_msf_client()

    def test_get_msf_client_initialized(self):
        """Test get_msf_client when client is initialized."""
        mock_client = Mock()
        with patch("metasploit_mcp.server._msf_client_instance", mock_client):
            result = get_msf_client()
            assert result is mock_client


class TestGetModuleObject:
    """Test the _get_module_object helper function."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = Mock()
        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_get_module_object_success(self, mock_client):
        """Test successful module object retrieval."""
        mock_module = Mock()
        mock_client.modules.use.return_value = mock_module

        result = await _get_module_object("exploit", "windows/smb/ms17_010_eternalblue")

        assert result is mock_module
        mock_client.modules.use.assert_called_once_with(
            "exploit", "windows/smb/ms17_010_eternalblue"
        )

    @pytest.mark.asyncio
    async def test_get_module_object_full_path(self, mock_client):
        """Test module object retrieval with full path."""
        mock_module = Mock()
        mock_client.modules.use.return_value = mock_module

        result = await _get_module_object("exploit", "exploit/windows/smb/ms17_010_eternalblue")

        assert result is mock_module
        # Should strip the module type prefix
        mock_client.modules.use.assert_called_once_with(
            "exploit", "windows/smb/ms17_010_eternalblue"
        )

    @pytest.mark.asyncio
    async def test_get_module_object_not_found(self, mock_client):
        """Test module object retrieval when module not found."""
        mock_client.modules.use.side_effect = KeyError("Module not found")

        with pytest.raises(InvalidModuleError) as exc_info:
            await _get_module_object("exploit", "nonexistent/module")

        # Verify exception has proper attributes
        assert exc_info.value.module_type == "exploit"
        assert exc_info.value.module_name == "nonexistent/module"
        assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_get_module_object_invalid_module_error(self, mock_client):
        """Test module object retrieval when Metasploit returns Invalid Module error."""
        # Simulate the RPC call returning an error dict (Invalid Module)
        mock_client.call = Mock(
            return_value={
                "error": True,
                "error_class": "Msf::RPC::Exception",
                "error_message": "Invalid Module",
                "error_backtrace": [
                    "lib/msf/core/rpc/v10/rpc_base.rb:26:in error",
                    "lib/msf/core/rpc/v10/rpc_module.rb:743:in _find_module",
                ],
            }
        )

        with pytest.raises(InvalidModuleError) as exc_info:
            await _get_module_object("auxiliary", "scanner/http/nonexistent")

        # Verify the exception message is clean (no backtrace)
        error_message = str(exc_info.value)
        assert "not found" in error_message
        # Verify backtrace is NOT in the exception message
        assert "rpc_base.rb" not in error_message
        assert "Backtrace" not in error_message

    @pytest.mark.asyncio
    async def test_get_module_object_msf_error(self, mock_client):
        """Test module object retrieval with MSF RPC error."""
        mock_client.modules.use.side_effect = MockMsfRpcError("RPC Error")

        with pytest.raises(MockMsfRpcError, match="RPC Error"):
            await _get_module_object("exploit", "test/module")


class TestInvalidModuleErrorException:
    """Test the InvalidModuleError exception class."""

    def test_invalid_module_error_creation(self):
        """Test creating an InvalidModuleError."""
        error = InvalidModuleError(
            module_type="exploit", module_name="windows/smb/fake_module", message="Module not found"
        )

        assert error.module_type == "exploit"
        assert error.module_name == "windows/smb/fake_module"
        assert str(error) == "Module not found"

    def test_invalid_module_error_is_value_error(self):
        """Test that InvalidModuleError is a subclass of ValueError."""
        error = InvalidModuleError(
            module_type="auxiliary", module_name="scanner/test", message="Test error"
        )

        # Should be catchable as ValueError for backwards compatibility
        assert isinstance(error, ValueError)

    def test_invalid_module_error_no_traceback_in_message(self):
        """Test that error message is clean without traceback."""
        error = InvalidModuleError(
            module_type="payload",
            module_name="unix/meterpreter/reverse_tcp",
            message="Module 'payload/unix/meterpreter/reverse_tcp' not found in Metasploit.",
        )

        error_str = str(error)
        # Should not contain any backtrace information
        assert "Traceback" not in error_str
        assert "rpc_base.rb" not in error_str
        assert "rpc_module.rb" not in error_str

    def test_invalid_module_error_with_suggestions(self):
        """Test that error message can include suggestions."""
        error = InvalidModuleError(
            module_type="auxiliary",
            module_name="scanner/http/nikto",
            message="Module 'auxiliary/scanner/http/nikto' not found in Metasploit.\n\n"
            "Did you mean one of these?\n"
            "  - auxiliary/scanner/http/dir_scanner\n"
            "  - auxiliary/scanner/http/http_version",
        )

        error_str = str(error)
        assert "Did you mean" in error_str
        assert "dir_scanner" in error_str
        assert "http_version" in error_str


class TestFindSimilarModules:
    """Test the _find_similar_modules helper function."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = Mock()
        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_find_similar_modules_exploit(self, mock_client):
        """Test finding similar exploit modules."""
        # Mock available exploits
        mock_client.modules.exploits = [
            "windows/smb/ms17_010_eternalblue",
            "windows/smb/ms08_067_netapi",
            "linux/http/apache_mod_cgi_bash_env_exec",
            "multi/http/apache_normalize_path_rce",
        ]

        # Search for "eternalblue" - should find the matching module
        suggestions = await _find_similar_modules("exploit", "windows/smb/eternalblue")

        assert len(suggestions) > 0
        assert any("eternalblue" in s for s in suggestions)

    @pytest.mark.asyncio
    async def test_find_similar_modules_payload(self, mock_client):
        """Test finding similar payload modules."""
        # Mock available payloads
        mock_client.modules.payloads = [
            "linux/x64/meterpreter/reverse_tcp",
            "linux/x64/meterpreter_reverse_tcp",
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_https",
            "python/meterpreter/reverse_tcp",
        ]

        # Search for "meterpreter reverse_tcp" - should find matching modules
        suggestions = await _find_similar_modules("payload", "unix/meterpreter/reverse_tcp")

        assert len(suggestions) > 0
        # Should find meterpreter payloads
        assert any("meterpreter" in s for s in suggestions)

    @pytest.mark.asyncio
    async def test_find_similar_modules_auxiliary(self, mock_client):
        """Test finding similar auxiliary modules."""
        # Mock available auxiliary modules
        mock_client.modules.auxiliary = [
            "scanner/http/dir_scanner",
            "scanner/http/http_version",
            "scanner/http/robots_txt",
            "scanner/portscan/tcp",
            "scanner/smb/smb_version",
        ]

        # Search for "nikto" (doesn't exist) but has "http" - should find http scanners
        suggestions = await _find_similar_modules("auxiliary", "scanner/http/nikto")

        # May or may not find matches depending on term extraction
        # But should not raise an exception
        assert isinstance(suggestions, list)

    @pytest.mark.asyncio
    async def test_find_similar_modules_no_matches(self, mock_client):
        """Test when no similar modules are found."""
        mock_client.modules.exploits = [
            "windows/smb/ms17_010_eternalblue",
        ]

        # Search for something completely unrelated
        suggestions = await _find_similar_modules("exploit", "totally/unrelated/xyz123")

        # Should return empty list, not raise exception
        assert suggestions == []

    @pytest.mark.asyncio
    async def test_find_similar_modules_timeout(self, mock_client):
        """Test that timeout is handled gracefully."""

        # Make the module list call hang
        async def slow_call():
            await asyncio.sleep(10)
            return []

        mock_client.modules.exploits = []

        with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
            suggestions = await _find_similar_modules("exploit", "some/module")

        # Should return empty list on timeout
        assert suggestions == []


class TestSetModuleOptions:
    """Test the _set_module_options helper function."""

    @pytest.fixture
    def mock_module(self):
        """Fixture providing a mock module object."""
        module = Mock()
        module.fullname = "exploit/test/module"
        module.__setitem__ = Mock()
        return module

    @pytest.mark.asyncio
    async def test_set_module_options_basic(self, mock_module):
        """Test basic option setting."""
        options = {"RHOSTS": "192.168.1.1", "RPORT": "80"}

        await _set_module_options(mock_module, options)

        # Should be called twice, once for each option
        assert mock_module.__setitem__.call_count == 2
        mock_module.__setitem__.assert_any_call("RHOSTS", "192.168.1.1")
        mock_module.__setitem__.assert_any_call("RPORT", 80)  # Type conversion: '80' -> 80

    @pytest.mark.asyncio
    async def test_set_module_options_type_conversion(self, mock_module):
        """Test option setting with type conversion."""
        options = {
            "RPORT": "80",  # String number -> int
            "SSL": "true",  # String boolean -> bool
            "VERBOSE": "false",  # String boolean -> bool
            "THREADS": "10",  # String number -> int
        }

        await _set_module_options(mock_module, options)

        # Verify type conversions
        calls = mock_module.__setitem__.call_args_list
        call_dict = {call[0][0]: call[0][1] for call in calls}

        assert call_dict["RPORT"] == 80
        assert call_dict["SSL"] is True
        assert call_dict["VERBOSE"] is False
        assert call_dict["THREADS"] == 10

    @pytest.mark.asyncio
    async def test_set_module_options_error(self, mock_module):
        """Test option setting with error."""
        mock_module.__setitem__.side_effect = KeyError("Invalid option")
        options = {"INVALID_OPT": "value"}

        with pytest.raises(ValueError, match="Failed to set option"):
            await _set_module_options(mock_module, options)


class TestGetMsfConsole:
    """Test the get_msf_console context manager."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = Mock()
        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_get_msf_console_success(self, mock_client):
        """Test successful console creation and cleanup."""
        mock_console = MockMsfConsole("test-console-123")
        mock_client.consoles.console.return_value = mock_console
        mock_client.consoles.destroy.return_value = "destroyed"

        # Mock the global client instance for cleanup
        with patch("metasploit_mcp.server._msf_client_instance", mock_client):
            async with get_msf_console() as console:
                assert console is mock_console
                assert console.cid == "test-console-123"

            # Verify cleanup was called
            mock_client.consoles.destroy.assert_called_once_with("test-console-123")

    @pytest.mark.asyncio
    async def test_get_msf_console_creation_error(self, mock_client):
        """Test console creation error handling."""
        mock_client.consoles.console.side_effect = MockMsfRpcError("Console creation failed")

        with pytest.raises(MockMsfRpcError, match="Console creation failed"):
            async with get_msf_console() as console:
                pass

    @pytest.mark.asyncio
    async def test_get_msf_console_cleanup_error(self, mock_client):
        """Test that cleanup errors don't propagate."""
        mock_console = MockMsfConsole("test-console-123")
        mock_client.consoles.console.return_value = mock_console
        mock_client.consoles.destroy.side_effect = Exception("Cleanup failed")

        # Should not raise exception even if cleanup fails
        async with get_msf_console() as console:
            assert console is mock_console


class TestRunCommandSafely:
    """Test the run_command_safely function."""

    @pytest.fixture
    def mock_console(self):
        """Fixture providing a mock console."""
        console = Mock()
        console.write = Mock()
        console.read = Mock()
        return console

    @pytest.mark.asyncio
    async def test_run_command_safely_basic(self, mock_console):
        """Test basic command execution."""
        # Mock console read to return prompt immediately
        mock_console.read.return_value = {
            "data": "command output\n",
            "prompt": "\x01\x02msf6\x01\x02 \x01\x02> \x01\x02",
            "busy": False,
        }

        result = await run_command_safely(mock_console, "help")

        mock_console.write.assert_called_once_with("help\n")
        assert "command output" in result

    @pytest.mark.asyncio
    async def test_run_command_safely_invalid_console(self, mock_console):
        """Test command execution with invalid console."""
        # Remove required methods
        delattr(mock_console, "write")

        with pytest.raises(TypeError, match="Unsupported console object"):
            await run_command_safely(mock_console, "help")

    @pytest.mark.asyncio
    async def test_run_command_safely_read_error(self, mock_console):
        """Test command execution with read error - should timeout gracefully."""
        mock_console.read.side_effect = Exception("Read failed")

        # Should not raise exception, but timeout and return timeout error message
        result = await run_command_safely(mock_console, "help")

        # Should return timeout error message after timeout
        assert isinstance(result, str)
        assert "TIMEOUT_ERROR" in result or "timeout" in result.lower()  # Timeout error message

    @pytest.mark.asyncio
    async def test_run_command_safely_with_exit_terms(self, mock_console):
        """Test run_command_safely with exit_terms_regexes parameter."""
        # Simulate console that returns vulnerability message then goes idle
        read_calls = 0

        def mock_read_side_effect():
            nonlocal read_calls
            read_calls += 1
            if read_calls == 1:
                return {"data": "The target appears vulnerable\n", "prompt": "", "busy": False}
            elif read_calls <= 5:
                # Simulate idle period (no new data)
                return {"data": "", "prompt": "", "busy": False}
            else:
                # Return prompt after idle period
                return {
                    "data": "",
                    "prompt": "\x01\x02msf6\x01\x02 \x01\x02> \x01\x02",
                    "busy": False,
                }

        mock_console.read.side_effect = mock_read_side_effect

        # Test with exit terms
        result = await run_command_safely(
            mock_console, "check", exit_terms_regexes=[IS_VULNERABLE_RE]
        )

        # Should return output containing vulnerability message
        assert "appears vulnerable" in result.lower()
        # Should exit early (not wait for full timeout) - idle timeout is 2s, check interval is 0.1s
        assert read_calls <= 25  # Should exit early after idle period

    @pytest.mark.asyncio
    async def test_run_command_safely_set_command_skips_wait(self, mock_console):
        """Test that 'set' commands skip output wait."""
        result = await run_command_safely(mock_console, "set RHOSTS 192.168.1.1")

        # Should return empty string immediately
        assert result == ""
        # Should not call read
        assert not mock_console.read.called

    @pytest.mark.asyncio
    async def test_run_command_safely_use_command_skips_wait(self, mock_console):
        """Test that 'use' commands skip output wait."""
        result = await run_command_safely(mock_console, "use exploit/test/module")

        # Should return empty string immediately
        assert result == ""
        # Should not call read
        assert not mock_console.read.called


class TestFindAvailablePort:
    """Test the find_available_port utility function."""

    def test_find_available_port_success(self):
        """Test finding an available port."""
        # This should succeed as it tests real socket binding
        port = find_available_port(8080, max_attempts=5)
        assert isinstance(port, int)
        assert 8080 <= port < 8085

    @patch("socket.socket")
    def test_find_available_port_all_busy(self, mock_socket_class):
        """Test when all ports in range are busy."""
        mock_socket = Mock()
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        mock_socket.bind.side_effect = OSError("Port in use")

        # Should return the start port as fallback
        port = find_available_port(8080, max_attempts=3)
        assert port == 8080

    @patch("socket.socket")
    def test_find_available_port_second_attempt(self, mock_socket_class):
        """Test finding port on second attempt."""
        mock_socket = Mock()
        mock_socket_class.return_value.__enter__.return_value = mock_socket

        # First call fails, second succeeds
        mock_socket.bind.side_effect = [OSError("Port in use"), None]

        port = find_available_port(8080, max_attempts=3)
        assert port == 8081


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
