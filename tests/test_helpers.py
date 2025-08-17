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

# Add the parent directory to the path to import MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock the dependencies that aren't available in test environment
sys.modules['uvicorn'] = Mock()
sys.modules['fastapi'] = Mock()
sys.modules['mcp.server.fastmcp'] = Mock()
sys.modules['mcp.server.sse'] = Mock()
sys.modules['pymetasploit3.msfrpc'] = Mock()
sys.modules['starlette.applications'] = Mock()
sys.modules['starlette.routing'] = Mock()
sys.modules['mcp.server.session'] = Mock()

# Create mock classes for MSF objects
class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()

class MockMsfConsole:
    def __init__(self, cid='test-console-id'):
        self.cid = cid
        
    def read(self):
        return {'data': 'test output', 'prompt': 'msf6 > ', 'busy': False}
        
    def write(self, command):
        return True

class MockMsfRpcError(Exception):
    pass

# Patch the MSF modules
sys.modules['pymetasploit3.msfrpc'].MsfRpcClient = MockMsfRpcClient
sys.modules['pymetasploit3.msfrpc'].MsfConsole = MockMsfConsole  
sys.modules['pymetasploit3.msfrpc'].MsfRpcError = MockMsfRpcError

# Import after mocking
from MetasploitMCP import (
    _get_module_object, _set_module_options, initialize_msf_client, 
    get_msf_client, get_msf_console, run_command_safely,
    find_available_port
)


class TestMsfClientFunctions:
    """Test MSF client initialization and management functions."""

    @patch('MetasploitMCP.MSF_PASSWORD', 'test-password')
    @patch('MetasploitMCP.MSF_SERVER', '127.0.0.1')
    @patch('MetasploitMCP.MSF_PORT_STR', '55553')
    @patch('MetasploitMCP.MSF_SSL_STR', 'false')
    def test_initialize_msf_client_success(self):
        """Test successful MSF client initialization."""
        with patch('MetasploitMCP._msf_client_instance', None):
            with patch('MetasploitMCP.MsfRpcClient') as mock_client_class:
                mock_client = Mock()
                mock_client.core.version = {'version': '6.3.0'}
                mock_client_class.return_value = mock_client
                
                result = initialize_msf_client()
                
                assert result is mock_client
                mock_client_class.assert_called_once_with(
                    password='test-password',
                    server='127.0.0.1', 
                    port=55553,
                    ssl=False
                )

    @patch('MetasploitMCP.MSF_PORT_STR', 'invalid-port')
    def test_initialize_msf_client_invalid_port(self):
        """Test MSF client initialization with invalid port."""
        with patch('MetasploitMCP._msf_client_instance', None):
            with pytest.raises(ValueError, match="Invalid MSF connection parameters"):
                initialize_msf_client()

    def test_get_msf_client_not_initialized(self):
        """Test get_msf_client when client not initialized."""
        with patch('MetasploitMCP._msf_client_instance', None):
            with pytest.raises(ConnectionError, match="not been initialized"):
                get_msf_client()

    def test_get_msf_client_initialized(self):
        """Test get_msf_client when client is initialized."""
        mock_client = Mock()
        with patch('MetasploitMCP._msf_client_instance', mock_client):
            result = get_msf_client()
            assert result is mock_client


class TestGetModuleObject:
    """Test the _get_module_object helper function."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = Mock()
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_get_module_object_success(self, mock_client):
        """Test successful module object retrieval."""
        mock_module = Mock()
        mock_client.modules.use.return_value = mock_module
        
        result = await _get_module_object('exploit', 'windows/smb/ms17_010_eternalblue')
        
        assert result is mock_module
        mock_client.modules.use.assert_called_once_with('exploit', 'windows/smb/ms17_010_eternalblue')

    @pytest.mark.asyncio
    async def test_get_module_object_full_path(self, mock_client):
        """Test module object retrieval with full path."""
        mock_module = Mock()
        mock_client.modules.use.return_value = mock_module
        
        result = await _get_module_object('exploit', 'exploit/windows/smb/ms17_010_eternalblue')
        
        assert result is mock_module
        # Should strip the module type prefix
        mock_client.modules.use.assert_called_once_with('exploit', 'windows/smb/ms17_010_eternalblue')

    @pytest.mark.asyncio
    async def test_get_module_object_not_found(self, mock_client):
        """Test module object retrieval when module not found."""
        mock_client.modules.use.side_effect = KeyError("Module not found")
        
        with pytest.raises(ValueError, match="not found"):
            await _get_module_object('exploit', 'nonexistent/module')

    @pytest.mark.asyncio
    async def test_get_module_object_msf_error(self, mock_client):
        """Test module object retrieval with MSF RPC error."""
        mock_client.modules.use.side_effect = MockMsfRpcError("RPC Error")
        
        with pytest.raises(MockMsfRpcError, match="RPC Error"):
            await _get_module_object('exploit', 'test/module')


class TestSetModuleOptions:
    """Test the _set_module_options helper function."""

    @pytest.fixture
    def mock_module(self):
        """Fixture providing a mock module object."""
        module = Mock()
        module.fullname = 'exploit/test/module'
        module.__setitem__ = Mock()
        return module

    @pytest.mark.asyncio
    async def test_set_module_options_basic(self, mock_module):
        """Test basic option setting."""
        options = {'RHOSTS': '192.168.1.1', 'RPORT': '80'}

        await _set_module_options(mock_module, options)

        # Should be called twice, once for each option
        assert mock_module.__setitem__.call_count == 2
        mock_module.__setitem__.assert_any_call('RHOSTS', '192.168.1.1')
        mock_module.__setitem__.assert_any_call('RPORT', 80)  # Type conversion: '80' -> 80

    @pytest.mark.asyncio
    async def test_set_module_options_type_conversion(self, mock_module):
        """Test option setting with type conversion."""
        options = {
            'RPORT': '80',  # String number -> int
            'SSL': 'true',  # String boolean -> bool
            'VERBOSE': 'false',  # String boolean -> bool
            'THREADS': '10'  # String number -> int
        }
        
        await _set_module_options(mock_module, options)
        
        # Verify type conversions
        calls = mock_module.__setitem__.call_args_list
        call_dict = {call[0][0]: call[0][1] for call in calls}
        
        assert call_dict['RPORT'] == 80
        assert call_dict['SSL'] is True
        assert call_dict['VERBOSE'] is False
        assert call_dict['THREADS'] == 10

    @pytest.mark.asyncio
    async def test_set_module_options_error(self, mock_module):
        """Test option setting with error."""
        mock_module.__setitem__.side_effect = KeyError("Invalid option")
        options = {'INVALID_OPT': 'value'}
        
        with pytest.raises(ValueError, match="Failed to set option"):
            await _set_module_options(mock_module, options)


class TestGetMsfConsole:
    """Test the get_msf_console context manager."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = Mock()
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_get_msf_console_success(self, mock_client):
        """Test successful console creation and cleanup."""
        mock_console = MockMsfConsole('test-console-123')
        mock_client.consoles.console.return_value = mock_console
        mock_client.consoles.destroy.return_value = 'destroyed'

        # Mock the global client instance for cleanup
        with patch('MetasploitMCP._msf_client_instance', mock_client):
            async with get_msf_console() as console:
                assert console is mock_console
                assert console.cid == 'test-console-123'

            # Verify cleanup was called
            mock_client.consoles.destroy.assert_called_once_with('test-console-123')

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
        mock_console = MockMsfConsole('test-console-123')
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
            'data': 'command output\n',
            'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
            'busy': False
        }
        
        result = await run_command_safely(mock_console, 'help')
        
        mock_console.write.assert_called_once_with('help\n')
        assert 'command output' in result

    @pytest.mark.asyncio
    async def test_run_command_safely_invalid_console(self, mock_console):
        """Test command execution with invalid console."""
        # Remove required methods
        delattr(mock_console, 'write')
        
        with pytest.raises(TypeError, match="Unsupported console object"):
            await run_command_safely(mock_console, 'help')

    @pytest.mark.asyncio
    async def test_run_command_safely_read_error(self, mock_console):
        """Test command execution with read error - should timeout gracefully."""
        mock_console.read.side_effect = Exception("Read failed")

        # Should not raise exception, but timeout and return empty result
        result = await run_command_safely(mock_console, 'help')
        
        # Should return empty string after timeout
        assert isinstance(result, str)
        assert result == ""  # Empty result after timeout


class TestFindAvailablePort:
    """Test the find_available_port utility function."""

    def test_find_available_port_success(self):
        """Test finding an available port."""
        # This should succeed as it tests real socket binding
        port = find_available_port(8080, max_attempts=5)
        assert isinstance(port, int)
        assert 8080 <= port < 8085

    @patch('socket.socket')
    def test_find_available_port_all_busy(self, mock_socket_class):
        """Test when all ports in range are busy."""
        mock_socket = Mock()
        mock_socket_class.return_value.__enter__.return_value = mock_socket
        mock_socket.bind.side_effect = OSError("Port in use")
        
        # Should return the start port as fallback
        port = find_available_port(8080, max_attempts=3)
        assert port == 8080

    @patch('socket.socket')
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
