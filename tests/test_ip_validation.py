#!/usr/bin/env python3
"""
Tests for IP address validation functionality in MetasploitMCP.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any, List

# Add the parent directory to the path to import MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock the dependencies that aren't available in test environment
sys.modules['uvicorn'] = Mock()
sys.modules['fastapi'] = Mock()
sys.modules['starlette.applications'] = Mock()
sys.modules['starlette.routing'] = Mock()

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
sys.modules['mcp.server.fastmcp'] = mcp_server_fastmcp
sys.modules['mcp.server.sse'] = Mock()
sys.modules['mcp.server.session'] = Mock()

# Mock pymetasploit3 module
sys.modules['pymetasploit3.msfrpc'] = Mock()

# Import the module after mocking dependencies
import MetasploitMCP
from MetasploitMCP import get_local_ip_addresses, validate_bind_address


class TestGetLocalIpAddresses:
    """Test the get_local_ip_addresses function."""
    
    def test_get_local_ip_addresses_basic(self):
        """Test that get_local_ip_addresses returns a list of IP addresses."""
        with patch('socket.gethostname', return_value='test-host'):
            with patch('socket.getaddrinfo', return_value=[
                (2, 1, 6, '', ('192.168.1.100', 0)),
                (2, 1, 6, '', ('127.0.0.1', 0))
            ]):
                with patch('socket.socket') as mock_socket:
                    # Mock the socket connection for discovering routable IPs
                    mock_sock = Mock()
                    mock_sock.getsockname.return_value = ('10.0.0.1', 12345)
                    mock_socket.return_value.__enter__.return_value = mock_sock
                    
                    result = get_local_ip_addresses()
                    
                    assert isinstance(result, list)
                    assert len(result) > 0
                    assert '127.0.0.1' in result  # Loopback should always be included
                    assert '::1' in result  # IPv6 loopback should always be included

    def test_get_local_ip_addresses_fallback(self):
        """Test fallback behavior when IP discovery fails."""
        with patch('socket.gethostname', side_effect=Exception("Network error")):
            result = get_local_ip_addresses()
            
            assert isinstance(result, list)
            assert '127.0.0.1' in result
            assert '::1' in result

    def test_get_local_ip_addresses_deduplication(self):
        """Test that duplicate IP addresses are removed."""
        with patch('socket.gethostname', return_value='test-host'):
            with patch('socket.getaddrinfo', return_value=[
                (2, 1, 6, '', ('192.168.1.100', 0)),
                (2, 1, 6, '', ('192.168.1.100', 0)),  # Duplicate
                (2, 1, 6, '', ('127.0.0.1', 0))
            ]):
                with patch('socket.socket') as mock_socket:
                    mock_sock = Mock()
                    mock_sock.getsockname.return_value = ('192.168.1.100', 12345)  # Same as getaddrinfo
                    mock_socket.return_value.__enter__.return_value = mock_sock
                    
                    result = get_local_ip_addresses()
                    
                    # Count occurrences of the IP
                    count_192_168_1_100 = result.count('192.168.1.100')
                    assert count_192_168_1_100 == 1, f"Expected 1 occurrence of 192.168.1.100, got {count_192_168_1_100}"


class TestValidateBindAddress:
    """Test the validate_bind_address function."""
    
    def test_validate_wildcard_ipv4(self):
        """Test validation of IPv4 wildcard address."""
        is_valid, error_msg = validate_bind_address("0.0.0.0")
        assert is_valid is True
        assert error_msg == ""

    def test_validate_wildcard_ipv6(self):
        """Test validation of IPv6 wildcard address."""
        is_valid, error_msg = validate_bind_address("::")
        assert is_valid is True
        assert error_msg == ""

    def test_validate_empty_address(self):
        """Test validation of empty address."""
        is_valid, error_msg = validate_bind_address("")
        assert is_valid is False
        assert "cannot be empty" in error_msg

    def test_validate_invalid_format(self):
        """Test validation of invalid IP format."""
        is_valid, error_msg = validate_bind_address("invalid.ip.address")
        assert is_valid is False
        assert "Invalid IP address format" in error_msg

    def test_validate_local_address(self):
        """Test validation of local IP address."""
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100', '::1']):
            is_valid, error_msg = validate_bind_address("192.168.1.100")
            assert is_valid is True
            assert error_msg == ""

    def test_validate_non_local_address(self):
        """Test validation of non-local IP address."""
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100', '::1']):
            is_valid, error_msg = validate_bind_address("8.8.8.8")
            assert is_valid is False
            assert "not configured on this machine" in error_msg
            assert "Available addresses:" in error_msg

    def test_validate_loopback_addresses(self):
        """Test validation of loopback addresses."""
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '::1']):
            # IPv4 loopback
            is_valid, error_msg = validate_bind_address("127.0.0.1")
            assert is_valid is True
            assert error_msg == ""
            
            # IPv6 loopback
            is_valid, error_msg = validate_bind_address("::1")
            assert is_valid is True
            assert error_msg == ""


class TestBindAddressIntegration:
    """Test bind address validation integration with start_listener and generate_payload."""
    
    @pytest.fixture
    def mock_environment(self, mock_asyncio_to_thread):
        """Fixture providing mocked environment for testing."""
        with patch('MetasploitMCP.get_msf_client'):
            with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
                with patch('MetasploitMCP._get_module_object') as mock_get_module:
                    with patch('MetasploitMCP._set_module_options') as mock_set_options:
                        mock_rpc.return_value = {"status": "success", "job_id": "1234"}
                        mock_module = Mock()
                        mock_module.runoptions = {}
                        mock_module.payload_generate.return_value = b"test_payload"
                        mock_get_module.return_value = mock_module
                        yield mock_rpc, mock_get_module, mock_set_options, mock_module

    @pytest.mark.asyncio
    async def test_start_listener_valid_bind_address(self, mock_environment):
        """Test start_listener with valid bind address."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100']):
            result = await MetasploitMCP.start_listener(
                payload_type="windows/meterpreter/reverse_tcp",
                lhost="192.168.1.100",
                lport=4444,
                reverse_listener_bind_address="127.0.0.1"
            )
            
            assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_start_listener_invalid_bind_address(self, mock_environment):
        """Test start_listener with invalid bind address."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100']):
            result = await MetasploitMCP.start_listener(
                payload_type="windows/meterpreter/reverse_tcp",
                lhost="192.168.1.100",
                lport=4444,
                reverse_listener_bind_address="8.8.8.8"  # Invalid - not local
            )
            
            assert result["status"] == "error"
            assert "Invalid ReverseListenerBindAddress" in result["message"]

    @pytest.mark.asyncio
    async def test_start_listener_wildcard_bind_address(self, mock_environment):
        """Test start_listener with wildcard bind address."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        result = await MetasploitMCP.start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100",
            lport=4444,
            reverse_listener_bind_address="0.0.0.0"  # Wildcard should always be valid
        )
        
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_start_listener_default_bind_address(self, mock_environment):
        """Test start_listener with default bind address (should be 0.0.0.0)."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        result = await MetasploitMCP.start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100",
            lport=4444
            # No reverse_listener_bind_address provided - should default to 0.0.0.0
        )
        
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_start_listener_invalid_bind_port(self, mock_environment):
        """Test start_listener with invalid bind port."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        result = await MetasploitMCP.start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100",
            lport=4444,
            reverse_listener_bind_port=99999  # Invalid port
        )
        
        assert result["status"] == "error"
        assert "Invalid ReverseListenerBindPort" in result["message"]

    @pytest.mark.asyncio
    async def test_generate_payload_valid_bind_address(self, mock_environment):
        """Test generate_payload with valid bind address."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100']):
            with patch('MetasploitMCP.PAYLOAD_SAVE_DIR', '/tmp/test'):
                with patch('os.makedirs'):
                    with patch('builtins.open', create=True) as mock_open:
                        mock_open.return_value.__enter__.return_value.write = Mock()
                        
                        result = await MetasploitMCP.generate_payload(
                            payload_type="windows/meterpreter/reverse_tcp",
                            format_type="exe",
                            options={"LHOST": "192.168.1.100", "LPORT": 4444},
                            reverse_listener_bind_address="127.0.0.1"
                        )
                        
                        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_generate_payload_invalid_bind_address(self, mock_environment):
        """Test generate_payload with invalid bind address."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        with patch('MetasploitMCP.get_local_ip_addresses', return_value=['127.0.0.1', '192.168.1.100']):
            result = await MetasploitMCP.generate_payload(
                payload_type="windows/meterpreter/reverse_tcp",
                format_type="exe",
                options={"LHOST": "192.168.1.100", "LPORT": 4444},
                reverse_listener_bind_address="8.8.8.8"  # Invalid - not local
            )
            
            assert result["status"] == "error"
            assert "Invalid ReverseListenerBindAddress" in result["message"]

    @pytest.mark.asyncio
    async def test_generate_payload_default_bind_address(self, mock_environment):
        """Test generate_payload with default bind address (should be 0.0.0.0)."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        with patch('MetasploitMCP.PAYLOAD_SAVE_DIR', '/tmp/test'):
            with patch('os.makedirs'):
                with patch('builtins.open', create=True) as mock_open:
                    mock_open.return_value.__enter__.return_value.write = Mock()
                    
                    result = await MetasploitMCP.generate_payload(
                        payload_type="windows/meterpreter/reverse_tcp",
                        format_type="exe",
                        options={"LHOST": "192.168.1.100", "LPORT": 4444}
                        # No reverse_listener_bind_address provided - should default to 0.0.0.0
                    )
                    
                    assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_generate_payload_invalid_bind_port(self, mock_environment):
        """Test generate_payload with invalid bind port."""
        mock_rpc, mock_get_module, mock_set_options, mock_module = mock_environment
        
        result = await MetasploitMCP.generate_payload(
            payload_type="windows/meterpreter/reverse_tcp",
            format_type="exe",
            options={"LHOST": "192.168.1.100", "LPORT": 4444},
            reverse_listener_bind_port=99999  # Invalid port
        )
        
        assert result["status"] == "error"
        assert "Invalid ReverseListenerBindPort" in result["message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
