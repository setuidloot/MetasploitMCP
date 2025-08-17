#!/usr/bin/env python3
"""
Integration tests for MCP tools in MetasploitMCP.
These tests mock the Metasploit backend but test the full tool workflows.
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

# Create comprehensive mock classes
class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()
        
        # Setup default behaviors
        self.core.version = {'version': '6.3.0'}
        # These are properties that return lists
        self.modules.exploits = ['windows/smb/ms17_010_eternalblue', 'unix/ftp/vsftpd_234_backdoor']
        self.modules.payloads = ['windows/meterpreter/reverse_tcp', 'linux/x86/shell/reverse_tcp']
        # These are methods that return dicts
        self.sessions.list = Mock(return_value={})
        self.jobs.list = Mock(return_value={})

class MockMsfConsole:
    def __init__(self, cid='test-console-id'):
        self.cid = cid
        self._command_history = []
        
    def read(self):
        return {'data': 'msf6 > ', 'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02', 'busy': False}
        
    def write(self, command):
        self._command_history.append(command.strip())
        return True

class MockMsfModule:
    def __init__(self, fullname):
        self.fullname = fullname
        self.options = {}
        # Create a proper mock for runoptions that supports __setitem__
        self.runoptions = {}
        self.missing_required = []
        
    def __setitem__(self, key, value):
        self.options[key] = value
        
    def execute(self, payload=None):
        return {
            'job_id': 1234,
            'uuid': 'test-uuid-123',
            'error': False
        }
        
    def payload_generate(self):
        return b"test_payload_bytes"

class MockMsfRpcError(Exception):
    pass

# Apply mocks
sys.modules['pymetasploit3.msfrpc'].MsfRpcClient = MockMsfRpcClient
sys.modules['pymetasploit3.msfrpc'].MsfConsole = MockMsfConsole  
sys.modules['pymetasploit3.msfrpc'].MsfRpcError = MockMsfRpcError

# Import the module and then get the actual functions
import MetasploitMCP

# Get the actual functions (not mocked)
list_exploits = MetasploitMCP.list_exploits
list_payloads = MetasploitMCP.list_payloads
generate_payload = MetasploitMCP.generate_payload
run_exploit = MetasploitMCP.run_exploit
run_post_module = MetasploitMCP.run_post_module
run_auxiliary_module = MetasploitMCP.run_auxiliary_module
list_active_sessions = MetasploitMCP.list_active_sessions
send_session_command = MetasploitMCP.send_session_command
start_listener = MetasploitMCP.start_listener
stop_job = MetasploitMCP.stop_job
terminate_session = MetasploitMCP.terminate_session


class TestExploitListingTools:
    """Test tools for listing exploits and payloads."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock MSF client."""
        client = MockMsfRpcClient()
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_list_exploits_no_filter(self, mock_client):
        """Test listing exploits without filter."""
        mock_client.modules.exploits = [
            'windows/smb/ms17_010_eternalblue',
            'unix/ftp/vsftpd_234_backdoor',
            'windows/http/iis_webdav_upload_asp'
        ]
        
        result = await list_exploits()
        
        assert isinstance(result, list)
        assert len(result) == 3
        assert 'windows/smb/ms17_010_eternalblue' in result

    @pytest.mark.asyncio
    async def test_list_exploits_with_filter(self, mock_client):
        """Test listing exploits with search term."""
        mock_client.modules.exploits = [
            'windows/smb/ms17_010_eternalblue',
            'unix/ftp/vsftpd_234_backdoor',
            'windows/smb/ms08_067_netapi'
        ]
        
        result = await list_exploits("smb")
        
        assert isinstance(result, list)
        assert len(result) == 2
        assert all('smb' in exploit.lower() for exploit in result)

    @pytest.mark.asyncio
    async def test_list_exploits_error(self, mock_client):
        """Test listing exploits with MSF error."""
        mock_client.modules.exploits = Mock(side_effect=MockMsfRpcError("Connection failed"))
        
        result = await list_exploits()
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]

    @pytest.mark.asyncio
    async def test_list_exploits_timeout(self, mock_client):
        """Test listing exploits with timeout."""
        import asyncio
        
        def slow_exploits():
            # Simulate a slow response that would timeout
            import time
            time.sleep(35)  # Longer than RPC_CALL_TIMEOUT (30s)
            return ['exploit1', 'exploit2']
        
        mock_client.modules.exploits = slow_exploits
        
        result = await list_exploits()
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert "Timeout" in result[0]
        assert "30" in result[0]  # Should mention the timeout duration

    @pytest.mark.asyncio
    async def test_list_payloads_no_filter(self, mock_client):
        """Test listing payloads without filter."""
        mock_client.modules.payloads = [
            'windows/meterpreter/reverse_tcp',
            'linux/x86/shell/reverse_tcp',
            'windows/shell/reverse_tcp'
        ]
        
        result = await list_payloads()
        
        assert isinstance(result, list)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_list_payloads_with_platform_filter(self, mock_client):
        """Test listing payloads with platform filter."""
        mock_client.modules.payloads = [
            'windows/meterpreter/reverse_tcp',
            'linux/x86/shell/reverse_tcp', 
            'windows/shell/reverse_tcp'
        ]
        
        result = await list_payloads(platform="windows")
        
        assert isinstance(result, list)
        assert len(result) == 2
        assert all('windows' in payload.lower() for payload in result)

    @pytest.mark.asyncio
    async def test_list_payloads_with_arch_filter(self, mock_client):
        """Test listing payloads with architecture filter."""
        mock_client.modules.payloads = [
            'windows/meterpreter/reverse_tcp',
            'linux/x86/shell/reverse_tcp',
            'windows/x64/meterpreter/reverse_tcp'
        ]
        
        result = await list_payloads(arch="x86")
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert 'x86' in result[0]


class TestPayloadGeneration:
    """Test payload generation functionality."""

    @pytest.fixture
    def mock_client_and_module(self):
        """Fixture providing mocked client and module."""
        client = MockMsfRpcClient()
        module = MockMsfModule('payload/windows/meterpreter/reverse_tcp')
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._get_module_object', return_value=module):
                with patch('MetasploitMCP.PAYLOAD_SAVE_DIR', '/tmp/test'):
                    with patch('os.makedirs'):
                        with patch('builtins.open', create=True) as mock_open:
                            mock_open.return_value.__enter__.return_value.write = Mock()
                            yield client, module

    @pytest.mark.asyncio
    async def test_generate_payload_dict_options(self, mock_client_and_module):
        """Test payload generation with dictionary options."""
        client, module = mock_client_and_module
        
        options = {"LHOST": "192.168.1.100", "LPORT": 4444}
        result = await generate_payload(
            payload_type="windows/meterpreter/reverse_tcp",
            format_type="exe",
            options=options
        )
        
        assert result["status"] == "success"
        assert "server_save_path" in result
        assert result["payload_size"] == len(b"test_payload_bytes")

    @pytest.mark.asyncio
    async def test_generate_payload_string_options(self, mock_client_and_module):
        """Test payload generation with string options."""
        client, module = mock_client_and_module
        
        options = "LHOST=192.168.1.100,LPORT=4444"
        result = await generate_payload(
            payload_type="windows/meterpreter/reverse_tcp",
            format_type="exe",
            options=options
        )
        
        assert result["status"] == "success"
        # Verify the options were parsed correctly
        assert module.options["LHOST"] == "192.168.1.100"
        assert module.options["LPORT"] == 4444

    @pytest.mark.asyncio
    async def test_generate_payload_empty_options(self, mock_client_and_module):
        """Test payload generation with empty options."""
        client, module = mock_client_and_module
        
        result = await generate_payload(
            payload_type="windows/meterpreter/reverse_tcp",
            format_type="exe",
            options={}
        )
        
        assert result["status"] == "error"
        assert "required" in result["message"]

    @pytest.mark.asyncio
    async def test_generate_payload_invalid_string_options(self, mock_client_and_module):
        """Test payload generation with invalid string options."""
        client, module = mock_client_and_module
        
        result = await generate_payload(
            payload_type="windows/meterpreter/reverse_tcp",
            format_type="exe",
            options="LHOST192.168.1.100"  # Missing equals
        )
        
        assert result["status"] == "error"
        assert "Invalid options format" in result["message"]


class TestExploitExecution:
    """Test exploit execution functionality."""

    @pytest.fixture
    def mock_exploit_environment(self):
        """Fixture providing mocked exploit execution environment."""
        client = MockMsfRpcClient()
        module = MockMsfModule('exploit/windows/smb/ms17_010_eternalblue')
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
                with patch('MetasploitMCP._execute_module_console') as mock_console:
                    mock_rpc.return_value = {
                        "status": "success",
                        "message": "Exploit executed",
                        "job_id": 1234,
                        "session_id": 5678
                    }
                    mock_console.return_value = {
                        "status": "success", 
                        "message": "Exploit executed via console",
                        "module_output": "Session 1 opened"
                    }
                    yield client, mock_rpc, mock_console

    @pytest.mark.asyncio
    async def test_run_exploit_dict_payload_options(self, mock_exploit_environment):
        """Test exploit execution with dictionary payload options."""
        client, mock_rpc, mock_console = mock_exploit_environment
        
        result = await run_exploit(
            module_name="windows/smb/ms17_010_eternalblue",
            options={"RHOSTS": "192.168.1.1"},
            payload_name="windows/meterpreter/reverse_tcp",
            payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
            run_as_job=True
        )
        
        assert result["status"] == "success"
        mock_rpc.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_exploit_string_payload_options(self, mock_exploit_environment):
        """Test exploit execution with string payload options."""
        client, mock_rpc, mock_console = mock_exploit_environment
        
        result = await run_exploit(
            module_name="windows/smb/ms17_010_eternalblue",
            options={"RHOSTS": "192.168.1.1"},
            payload_name="windows/meterpreter/reverse_tcp",
            payload_options="LHOST=192.168.1.100,LPORT=4444",
            run_as_job=True
        )
        
        assert result["status"] == "success"
        # Verify RPC was called with parsed options
        call_args = mock_rpc.call_args
        payload_spec = call_args[1]['payload_spec']
        assert payload_spec['options']['LHOST'] == "192.168.1.100"
        assert payload_spec['options']['LPORT'] == 4444

    @pytest.mark.asyncio
    async def test_run_exploit_invalid_payload_options(self, mock_exploit_environment):
        """Test exploit execution with invalid payload options."""
        client, mock_rpc, mock_console = mock_exploit_environment
        
        result = await run_exploit(
            module_name="windows/smb/ms17_010_eternalblue",
            options={"RHOSTS": "192.168.1.1"},
            payload_name="windows/meterpreter/reverse_tcp",
            payload_options="LHOST192.168.1.100",  # Invalid format
            run_as_job=True
        )
        
        assert result["status"] == "error"
        assert "Invalid payload_options format" in result["message"]

    @pytest.mark.asyncio
    async def test_run_exploit_console_mode(self, mock_exploit_environment):
        """Test exploit execution in console mode."""
        client, mock_rpc, mock_console = mock_exploit_environment
        
        result = await run_exploit(
            module_name="windows/smb/ms17_010_eternalblue",
            options={"RHOSTS": "192.168.1.1"},
            payload_name="windows/meterpreter/reverse_tcp",
            payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
            run_as_job=False  # Console mode
        )
        
        assert result["status"] == "success"
        mock_console.assert_called_once()
        mock_rpc.assert_not_called()


class TestSessionManagement:
    """Test session management functionality."""

    @pytest.fixture
    def mock_session_environment(self):
        """Fixture providing mocked session management environment."""
        client = MockMsfRpcClient()
        session = Mock()
        session.run_with_output = Mock(return_value="command output")
        session.read = Mock(return_value="session data")
        session.write = Mock()
        session.stop = Mock()
        
        # Override the default Mock with actual dict return values
        client.sessions.list = Mock(return_value={
            "1": {"type": "meterpreter", "info": "Windows session"},
            "2": {"type": "shell", "info": "Linux session"}
        })
        client.sessions.session = Mock(return_value=session)
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            yield client, session

    @pytest.mark.asyncio
    async def test_list_active_sessions(self, mock_session_environment):
        """Test listing active sessions."""
        client, session = mock_session_environment
        
        result = await list_active_sessions()
        
        assert result["status"] == "success"
        assert result["count"] == 2
        assert "1" in result["sessions"]
        assert "2" in result["sessions"]

    @pytest.mark.asyncio
    async def test_send_session_command_meterpreter(self, mock_session_environment):
        """Test sending command to Meterpreter session."""
        client, session = mock_session_environment
        
        result = await send_session_command(1, "sysinfo")
        
        assert result["status"] == "success"
        session.run_with_output.assert_called_once_with("sysinfo")

    @pytest.mark.asyncio
    async def test_send_session_command_nonexistent(self, mock_session_environment):
        """Test sending command to non-existent session."""
        client, session = mock_session_environment
        client.sessions.list.return_value = {}  # No sessions
        
        result = await send_session_command(999, "whoami")
        
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_terminate_session(self, mock_session_environment):
        """Test session termination."""
        client, session = mock_session_environment
        
        # Mock session disappearing after termination
        client.sessions.list.side_effect = [
            {"1": {"type": "meterpreter"}},  # Before termination
            {}  # After termination
        ]
        
        result = await terminate_session(1)
        
        assert result["status"] == "success"
        session.stop.assert_called_once()


class TestListenerManagement:
    """Test listener and job management functionality."""

    @pytest.fixture
    def mock_job_environment(self):
        """Fixture providing mocked job management environment."""
        client = MockMsfRpcClient()
        
        # Override the default Mock with actual dict return values
        client.jobs.list = Mock(return_value={})
        client.jobs.stop = Mock(return_value="stopped")
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
                mock_rpc.return_value = {
                    "status": "success",
                    "job_id": 1234,
                    "message": "Listener started"
                }
                yield client, mock_rpc

    @pytest.mark.asyncio
    async def test_start_listener_dict_options(self, mock_job_environment):
        """Test starting listener with dictionary additional options."""
        client, mock_rpc = mock_job_environment
        
        result = await start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100",
            lport=4444,
            additional_options={"ExitOnSession": True}
        )
        
        assert result["status"] == "success"
        assert "job" in result["message"]

    @pytest.mark.asyncio
    async def test_start_listener_string_options(self, mock_job_environment):
        """Test starting listener with string additional options."""
        client, mock_rpc = mock_job_environment
        
        result = await start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100", 
            lport=4444,
            additional_options="ExitOnSession=true,Verbose=false"
        )
        
        assert result["status"] == "success"
        # Verify RPC was called with parsed options
        call_args = mock_rpc.call_args
        payload_spec = call_args[1]['payload_spec']
        assert payload_spec['options']['ExitOnSession'] is True
        assert payload_spec['options']['Verbose'] is False

    @pytest.mark.asyncio
    async def test_start_listener_invalid_port(self, mock_job_environment):
        """Test starting listener with invalid port."""
        client, mock_rpc = mock_job_environment
        
        result = await start_listener(
            payload_type="windows/meterpreter/reverse_tcp",
            lhost="192.168.1.100",
            lport=99999  # Invalid port
        )
        
        assert result["status"] == "error"
        assert "Invalid LPORT" in result["message"]

    @pytest.mark.asyncio
    async def test_stop_job(self, mock_job_environment):
        """Test stopping a job."""
        client, mock_rpc = mock_job_environment
        
        # Mock job exists before stop, gone after stop
        client.jobs.list.side_effect = [
            {"1234": {"name": "Handler Job"}},  # Before stop
            {}  # After stop  
        ]
        client.jobs.stop.return_value = "stopped"
        
        result = await stop_job(1234)
        
        assert result["status"] == "success"
        client.jobs.stop.assert_called_once_with("1234")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
