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

# Mock pymetasploit3 module BEFORE importing MetasploitMCP
# We need to set up complete mock classes first

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
        # These are properties that return dicts (not methods!)
        self.sessions.list = {}
        self.jobs.list = {}

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

# Helper function to unwrap FastMCP decorated functions
def unwrap_tool(tool_obj):
    """Unwrap a FastMCP tool to get the underlying function."""
    # Try different attributes where the actual function might be stored
    for attr in ['func', '__wrapped__', '_func', 'fn']:
        if hasattr(tool_obj, attr):
            return getattr(tool_obj, attr)
    # If it's already callable, return as-is
    if callable(tool_obj):
        return tool_obj
    # Last resort: try to get the function from the tool's internals
    if hasattr(tool_obj, '__dict__') and 'func' in tool_obj.__dict__:
        return tool_obj.__dict__['func']
    return tool_obj

# Get the actual functions (unwrapped from FastMCP decorators)
list_exploits = unwrap_tool(MetasploitMCP.list_exploits)
list_payloads = unwrap_tool(MetasploitMCP.list_payloads)
generate_payload = unwrap_tool(MetasploitMCP.generate_payload)
run_exploit = unwrap_tool(MetasploitMCP.run_exploit)
run_post_module = unwrap_tool(MetasploitMCP.run_post_module)
run_auxiliary_module = unwrap_tool(MetasploitMCP.run_auxiliary_module)
list_active_sessions = unwrap_tool(MetasploitMCP.list_active_sessions)
send_session_command = unwrap_tool(MetasploitMCP.send_session_command)
start_listener = unwrap_tool(MetasploitMCP.start_listener)
stop_job = unwrap_tool(MetasploitMCP.stop_job)
terminate_session = unwrap_tool(MetasploitMCP.terminate_session)


class TestExploitListingTools:
    """Test tools for listing exploits and payloads."""

    @pytest.fixture
    def mock_client(self, mock_asyncio_to_thread):
        """Fixture providing a mock MSF client."""
        client = MockMsfRpcClient()
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            yield client

    @pytest.mark.asyncio
    async def test_list_exploits_no_filter(self, mock_client):
        """Test listing exploits without filter."""
        exploits_list = [
            'windows/smb/ms17_010_eternalblue',
            'unix/ftp/vsftpd_234_backdoor',
            'windows/http/iis_webdav_upload_asp'
        ]
        mock_client.modules.exploits = exploits_list
        
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

    @pytest.mark.asyncio
    async def test_list_payloads_with_exploit_module(self, mock_asyncio_to_thread):
        """Test listing payloads compatible with an exploit module."""
        # Create mock client
        client = MockMsfRpcClient()
        
        # Create a mock module with compatible_payloads
        mock_module = MockMsfModule('exploit/windows/smb/ms17_010_eternalblue')
        mock_module.compatible_payloads = [
            'windows/x64/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/bind_tcp',
            'windows/x64/shell/reverse_tcp'
        ]
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._get_module_object', return_value=mock_module):
                result = await list_payloads(exploit_module="windows/smb/ms17_010_eternalblue")
        
        assert isinstance(result, list)
        assert len(result) == 3
        assert 'windows/x64/meterpreter/reverse_tcp' in result
        assert 'windows/x64/meterpreter/bind_tcp' in result

    @pytest.mark.asyncio
    async def test_list_payloads_with_exploit_module_and_filters(self, mock_asyncio_to_thread):
        """Test listing payloads with exploit module and additional filters."""
        # Create mock client
        client = MockMsfRpcClient()
        
        mock_module = MockMsfModule('exploit/windows/smb/ms17_010_eternalblue')
        mock_module.compatible_payloads = [
            'windows/x64/meterpreter/reverse_tcp',
            'windows/x64/meterpreter/bind_tcp',
            'windows/x64/shell/reverse_tcp',
            'windows/meterpreter/reverse_tcp'  # x86 version
        ]
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._get_module_object', return_value=mock_module):
                result = await list_payloads(exploit_module="windows/smb/ms17_010_eternalblue", arch="x64")
        
        assert isinstance(result, list)
        assert len(result) == 3
        # Should only include x64 payloads
        assert all('x64' in payload for payload in result)

    @pytest.mark.asyncio
    async def test_list_payloads_with_invalid_exploit_module(self, mock_asyncio_to_thread):
        """Test listing payloads with invalid exploit module."""
        # Create mock client
        client = MockMsfRpcClient()
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._get_module_object', side_effect=ValueError("Module not found")):
                result = await list_payloads(exploit_module="invalid/exploit/name")
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert "Error" in result[0]
        assert "not found" in result[0]

    @pytest.mark.asyncio
    async def test_list_payloads_exploit_module_no_compatible_payloads_attr(self, mock_asyncio_to_thread):
        """Test listing payloads when module doesn't support compatible_payloads."""
        # Create mock client
        client = MockMsfRpcClient()
        client.modules.payloads = [
            'cmd/unix/reverse',
            'cmd/unix/bind_netcat'
        ]
        
        mock_module = MockMsfModule('exploit/unix/ftp/vsftpd_234_backdoor')
        # Don't set compatible_payloads attribute to simulate older MSF versions
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._get_module_object', return_value=mock_module):
                result = await list_payloads(exploit_module="unix/ftp/vsftpd_234_backdoor")
        
        # Should fall back to listing all payloads
        assert isinstance(result, list)
        assert len(result) == 2


class TestPayloadGeneration:
    """Test payload generation functionality."""

    @pytest.fixture
    def mock_client_and_module(self, mock_asyncio_to_thread):
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
    def mock_exploit_environment(self, mock_asyncio_to_thread):
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
        
        # Mock port availability check to always return available
        with patch('MetasploitMCP.check_port_available', return_value=(True, "")):
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
        
        # Mock port availability check to always return available
        with patch('MetasploitMCP.check_port_available', return_value=(True, "")):
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

    @pytest.mark.asyncio
    async def test_run_exploit_invalid_payload_error_message_rpc(self, mock_asyncio_to_thread):
        """Test that invalid payload error includes helpful suggestion (RPC mode)."""
        client = MockMsfRpcClient()
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._execute_module_rpc') as mock_rpc:
                # Simulate an invalid payload error
                mock_rpc.return_value = {
                    "status": "error",
                    "message": "Invalid payload specified: linux/x86/shell/reverse_tcp. To view compatible payloads for this exploit, use: list_payloads(exploit_module='windows/smb/ms17_010_eternalblue')."
                }
                
                result = await run_exploit(
                    module_name="windows/smb/ms17_010_eternalblue",
                    options={"RHOSTS": "192.168.1.1"},
                    payload_name="linux/x86/shell/reverse_tcp",  # Invalid for Windows exploit
                    payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
                    run_as_job=True
                )
        
        assert result["status"] == "error"
        assert "list_payloads" in result["message"]
        assert "exploit_module" in result["message"]
        assert "ms17_010_eternalblue" in result["message"]

    @pytest.mark.asyncio
    async def test_run_exploit_invalid_payload_error_message_console(self, mock_asyncio_to_thread):
        """Test that invalid payload error includes helpful suggestion (Console mode)."""
        client = MockMsfRpcClient()
        
        with patch('MetasploitMCP.get_msf_client', return_value=client):
            with patch('MetasploitMCP._execute_module_console') as mock_console:
                # Simulate console output with invalid payload error
                mock_console.return_value = {
                    "status": "error",
                    "message": "Error during setup command 'set PAYLOAD linux/x86/shell/reverse_tcp': [-] Error setting option PAYLOAD\n\nTo view compatible payloads for this exploit, use: list_payloads(exploit_module='windows/smb/ms17_010_eternalblue')",
                    "module": "exploit/windows/smb/ms17_010_eternalblue"
                }
                
                result = await run_exploit(
                    module_name="windows/smb/ms17_010_eternalblue",
                    options={"RHOSTS": "192.168.1.1"},
                    payload_name="linux/x86/shell/reverse_tcp",
                    payload_options={"LHOST": "192.168.1.100", "LPORT": 4444},
                    run_as_job=False  # Console mode
                )
        
        assert result["status"] == "error"
        assert "list_payloads" in result["message"]
        assert "exploit_module" in result["message"]


class TestSessionManagement:
    """Test session management functionality."""

    @pytest.fixture
    def mock_session_environment(self, mock_asyncio_to_thread):
        """Fixture providing mocked session management environment."""
        client = MockMsfRpcClient()
        session = Mock()
        session.run_with_output = Mock(return_value="command output")
        session.read = Mock(return_value="session data")
        session.write = Mock()
        session.stop = Mock()
        
        # Override the default values with actual dict values
        client.sessions.list = {
            "1": {"type": "meterpreter", "info": "Windows session"},
            "2": {"type": "shell", "info": "Linux session"}
        }
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
        client.sessions.list = {}  # No sessions
        
        result = await send_session_command(999, "whoami")
        
        assert result["status"] == "error"
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_terminate_session(self, mock_session_environment):
        """Test session termination."""
        client, session = mock_session_environment
        
        # Set initial session state
        client.sessions.list = {"1": {"type": "meterpreter"}}
        
        # Mock the asyncio.to_thread calls to simulate session disappearing after termination
        call_count = 0
        
        async def mock_to_thread_for_terminate(func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            # Check if this is a lambda that accesses client.sessions.list
            try:
                result = func(*args, **kwargs)
                # If this returns the sessions dict and it's the second call, return empty
                if isinstance(result, dict) and call_count >= 2 and "1" in str(result):
                    return {}
                return result
            except:
                return func(*args, **kwargs)
        
        with patch('asyncio.to_thread', side_effect=mock_to_thread_for_terminate):
            result = await terminate_session(1)
        
        assert result["status"] == "success"
        session.stop.assert_called_once()


class TestListenerManagement:
    """Test listener and job management functionality."""

    @pytest.fixture
    def mock_job_environment(self, mock_asyncio_to_thread):
        """Fixture providing mocked job management environment."""
        client = MockMsfRpcClient()
        
        # Override the default values with actual dict values
        client.jobs.list = {}
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
        
        # Mock port availability check to always return available
        with patch('MetasploitMCP.check_port_available', return_value=(True, "")):
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
        
        # Mock port availability check to always return available
        with patch('MetasploitMCP.check_port_available', return_value=(True, "")):
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
    async def test_start_listener_port_in_use(self, mock_job_environment):
        """Test starting listener when port is already in use."""
        client, mock_rpc = mock_job_environment
        
        # Mock port availability check to return port in use
        with patch('MetasploitMCP.check_port_available', return_value=(False, "Port 4444 is already in use on 0.0.0.0. Please choose a different port or stop the service using this port.")):
            result = await start_listener(
                payload_type="windows/meterpreter/reverse_tcp",
                lhost="192.168.1.100",
                lport=4444
            )
        
        assert result["status"] == "error"
        assert "Port 4444 is already in use" in result["message"]

    @pytest.mark.asyncio
    async def test_stop_job(self, mock_job_environment):
        """Test stopping a job."""
        client, mock_rpc = mock_job_environment
        
        # Set initial job state
        client.jobs.list = {"1234": {"name": "Handler Job"}}
        client.jobs.stop.return_value = "stopped"
        
        # Mock the asyncio.to_thread calls to simulate job disappearing after stop
        call_count = 0
        
        async def mock_to_thread_for_stop_job(func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            # Check if this is a lambda that accesses client.jobs.list
            try:
                result = func(*args, **kwargs)
                # If this returns the jobs dict and it's the second call, return empty
                if isinstance(result, dict) and call_count >= 2 and "1234" in str(result):
                    return {}
                return result
            except:
                return func(*args, **kwargs)
        
        with patch('asyncio.to_thread', side_effect=mock_to_thread_for_stop_job):
            result = await stop_job(1234)
        
        assert result["status"] == "success"
        client.jobs.stop.assert_called_once_with("1234")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
