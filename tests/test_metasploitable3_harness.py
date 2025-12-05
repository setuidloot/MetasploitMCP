#!/usr/bin/env python3
"""
Tests for Metasploitable 3 Test Harness

These tests verify that the harness functions correctly without requiring
a real Metasploitable 3 target or active MCP server.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

# Import the test harness modules
import sys
from pathlib import Path

# Add parent directory to path to import the harness
sys.path.insert(0, str(Path(__file__).parent.parent))

from metasploitable3_test_harness import (
    ExploitTest,
    TestResult,
    MetasploitMCPClient,
    Metasploitable3TestHarness,
)


class TestExploitTestDataclass:
    """Test the ExploitTest dataclass."""
    
    def test_exploit_test_creation(self):
        """Test creating an ExploitTest instance."""
        test = ExploitTest(
            name="Test Exploit",
            description="Test Description",
            module="exploit/test/module",
            payload="test/payload",
            options={"RHOSTS": "10.0.0.1"},
            expected_user="testuser",
            notes="Test notes"
        )
        
        assert test.name == "Test Exploit"
        assert test.description == "Test Description"
        assert test.module == "exploit/test/module"
        assert test.payload == "test/payload"
        assert test.options == {"RHOSTS": "10.0.0.1"}
        assert test.expected_user == "testuser"
        assert test.notes == "Test notes"
    
    def test_exploit_test_optional_fields(self):
        """Test ExploitTest with optional fields."""
        test = ExploitTest(
            name="Test",
            description="Desc",
            module="module",
            payload="payload",
            options={}
        )
        
        assert test.expected_user is None
        assert test.notes is None


class TestTestResultDataclass:
    """Test the TestResult dataclass."""
    
    def test_test_result_creation(self):
        """Test creating a TestResult instance."""
        result = TestResult(
            test_name="Test",
            success=True,
            session_id=1,
            session_info={"id": 1},
            error=None,
            duration_seconds=5.5
        )
        
        assert result.test_name == "Test"
        assert result.success is True
        assert result.session_id == 1
        assert result.session_info == {"id": 1}
        assert result.error is None
        assert result.duration_seconds == 5.5
    
    def test_test_result_failure(self):
        """Test creating a failed TestResult."""
        result = TestResult(
            test_name="Test",
            success=False,
            error="Connection failed"
        )
        
        assert result.success is False
        assert result.error == "Connection failed"
        assert result.session_id is None


class TestMetasploitMCPClient:
    """Test the MCP client."""
    
    @pytest.fixture
    def client(self):
        """Create a test client."""
        return MetasploitMCPClient("http://test-server:8085")
    
    def test_client_initialization(self, client):
        """Test client initialization."""
        assert client.mcp_url == "http://test-server:8085"
        assert client.mcp_endpoint == "http://test-server:8085/mcp"
    
    def test_client_url_normalization(self):
        """Test that trailing slashes are removed."""
        client = MetasploitMCPClient("http://test-server:8085/")
        assert client.mcp_url == "http://test-server:8085"
    
    @pytest.mark.asyncio
    async def test_call_tool_success(self, client):
        """Test successful tool call."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "Success"}
                ]
            }
        }
        
        with patch.object(client.client, 'post', new=AsyncMock(return_value=mock_response)) as mock_post:
            result = await client.call_tool("test_tool", {"arg": "value"})
            
            assert result["success"] is True
            assert result["data"] == "Success"
            
            # Verify headers were sent
            call_kwargs = mock_post.call_args.kwargs
            assert "headers" in call_kwargs
            assert call_kwargs["headers"]["Content-Type"] == "application/json"
            assert call_kwargs["headers"]["Accept"] == "application/json, text/event-stream"
    
    @pytest.mark.asyncio
    async def test_call_tool_error(self, client):
        """Test tool call with error response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -1,
                "message": "Tool failed"
            }
        }
        
        with patch.object(client.client, 'post', new=AsyncMock(return_value=mock_response)):
            with pytest.raises(Exception, match="Tool call failed"):
                await client.call_tool("test_tool", {})
    
    @pytest.mark.asyncio
    async def test_run_exploit(self, client):
        """Test run_exploit wrapper method."""
        with patch.object(client, 'call_tool', new=AsyncMock(return_value={"success": True})) as mock_call:
            await client.run_exploit(
                module_name="exploit/test",
                options={"RHOSTS": "10.0.0.1"},
                payload_name="test/payload"
            )
            
            mock_call.assert_called_once_with("run_exploit", {
                "module_name": "exploit/test",
                "options": {"RHOSTS": "10.0.0.1"},
                "payload_name": "test/payload"
            })
    
    @pytest.mark.asyncio
    async def test_list_sessions(self, client):
        """Test list_sessions wrapper method."""
        with patch.object(client, 'call_tool', new=AsyncMock(return_value={"sessions": []})) as mock_call:
            await client.list_sessions()
            mock_call.assert_called_once_with("list_active_sessions", {})
    
    @pytest.mark.asyncio
    async def test_send_session_command(self, client):
        """Test send_session_command wrapper method."""
        with patch.object(client, 'call_tool', new=AsyncMock(return_value={"output": "uid=0"})) as mock_call:
            await client.send_session_command(session_id=1, command="id")
            
            mock_call.assert_called_once_with("send_session_command", {
                "session_id": 1,
                "command": "id"
            })
    
    @pytest.mark.asyncio
    async def test_start_listener(self, client):
        """Test start_listener wrapper method."""
        with patch.object(client, 'call_tool', new=AsyncMock(return_value={"job_id": 1})) as mock_call:
            await client.start_listener(
                payload_type="linux/x86/meterpreter/reverse_tcp",
                lhost="10.0.0.1",
                lport=4444
            )
            
            mock_call.assert_called_once_with("start_listener", {
                "payload_type": "linux/x86/meterpreter/reverse_tcp",
                "lhost": "10.0.0.1",
                "lport": 4444
            })


class TestMetasploitable3TestHarness:
    """Test the main test harness."""
    
    @pytest.fixture
    def harness(self):
        """Create a test harness instance."""
        return Metasploitable3TestHarness(
            target_ip="10.0.2.15",
            lhost="10.0.2.4",
            lport=4444,
            mcp_url="http://test-server:8085"
        )
    
    def test_harness_initialization(self, harness):
        """Test harness initialization."""
        assert harness.target_ip == "10.0.2.15"
        assert harness.lhost == "10.0.2.4"
        assert harness.lport == 4444
        assert harness.results == []
    
    def test_get_exploit_tests(self, harness):
        """Test getting exploit test definitions."""
        tests = harness.get_exploit_tests()
        
        assert len(tests) > 0
        assert all(isinstance(t, ExploitTest) for t in tests)
        
        # Check that all tests have target IP set
        for test in tests:
            assert test.options["RHOSTS"] == "10.0.2.15"
            assert test.options["LHOST"] == "10.0.2.4"
            assert test.options["LPORT"] == "4444"
    
    def test_exploit_tests_structure(self, harness):
        """Test that exploit tests have required fields."""
        tests = harness.get_exploit_tests()
        
        for test in tests:
            assert test.name
            assert test.description
            assert test.module
            assert test.payload
            assert isinstance(test.options, dict)
            assert "RHOSTS" in test.options
    
    def test_exploit_tests_coverage(self, harness):
        """Test that we cover key Metasploitable 3 exploits."""
        tests = harness.get_exploit_tests()
        test_names = [t.name for t in tests]
        
        # Check for key exploits from the walkthrough
        assert any("proftpd" in name.lower() for name in test_names)
        assert any("apache" in name.lower() or "shellshock" in name.lower() for name in test_names)
        assert any("drupal" in name.lower() for name in test_names)
        assert any("phpmyadmin" in name.lower() for name in test_names)
        assert any("unreal" in name.lower() for name in test_names)
    
    @pytest.mark.asyncio
    async def test_run_single_test_success(self, harness):
        """Test running a single test successfully."""
        test = ExploitTest(
            name="Test Exploit",
            description="Test",
            module="exploit/test",
            payload="test/payload",
            options={"RHOSTS": "10.0.0.1", "LHOST": "10.0.0.1", "LPORT": "4444"}
        )
        
        # Mock the MCP client methods
        with patch.object(harness.mcp_client, 'run_exploit', new=AsyncMock(
            return_value={"success": True, "data": "Session 1 opened"}
        )):
            with patch.object(harness.mcp_client, 'list_sessions', new=AsyncMock(
                return_value={"success": True, "data": "Active sessions: 1"}
            )):
                with patch.object(harness.mcp_client, 'send_session_command', new=AsyncMock(
                    return_value={"success": True, "data": "uid=1000(testuser)"}
                )):
                    result = await harness.run_single_test(test)
        
        assert isinstance(result, TestResult)
        assert result.test_name == "Test Exploit"
        assert result.success is True
        assert result.session_id == 1
        assert result.duration_seconds > 0
    
    @pytest.mark.asyncio
    async def test_run_single_test_failure(self, harness):
        """Test running a single test that fails."""
        test = ExploitTest(
            name="Test Exploit",
            description="Test",
            module="exploit/test",
            payload="test/payload",
            options={"RHOSTS": "10.0.0.1"}
        )
        
        # Mock the MCP client to raise an exception
        with patch.object(harness.mcp_client, 'run_exploit', new=AsyncMock(
            side_effect=Exception("Connection failed")
        )):
            result = await harness.run_single_test(test)
        
        assert isinstance(result, TestResult)
        assert result.success is False
        assert result.error == "Connection failed"
        assert result.session_id is None
    
    @pytest.mark.asyncio
    async def test_run_single_test_no_session(self, harness):
        """Test running a test that executes but doesn't create a session."""
        test = ExploitTest(
            name="Test Exploit",
            description="Test",
            module="exploit/test",
            payload="test/payload",
            options={"RHOSTS": "10.0.0.1"}
        )
        
        with patch.object(harness.mcp_client, 'run_exploit', new=AsyncMock(
            return_value={"success": True, "data": "Exploit completed"}
        )):
            with patch.object(harness.mcp_client, 'list_sessions', new=AsyncMock(
                return_value={"success": True, "data": "No active sessions"}
            )):
                result = await harness.run_single_test(test)
        
        assert result.success is False
        assert result.error == "No session established"
    
    @pytest.mark.asyncio
    async def test_run_all_tests(self, harness):
        """Test running all tests."""
        # Mock run_single_test to return success
        mock_result = TestResult(
            test_name="Test",
            success=True,
            session_id=1,
            duration_seconds=1.0
        )
        
        with patch.object(harness, 'run_single_test', new=AsyncMock(return_value=mock_result)):
            results = await harness.run_all_tests()
        
        assert len(results) > 0
        assert all(isinstance(r, TestResult) for r in results)
    
    @pytest.mark.asyncio
    async def test_run_all_tests_stop_on_failure(self, harness):
        """Test that run_all_tests stops on failure when requested."""
        call_count = 0
        
        async def mock_run_test(test):
            nonlocal call_count
            call_count += 1
            
            if call_count == 1:
                # First test succeeds
                return TestResult(test_name=test.name, success=True, duration_seconds=1.0)
            else:
                # Second test fails
                return TestResult(test_name=test.name, success=False, error="Failed", duration_seconds=1.0)
        
        with patch.object(harness, 'run_single_test', side_effect=mock_run_test):
            results = await harness.run_all_tests(continue_on_failure=False)
        
        # Should have stopped after the failure
        assert call_count == 2
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is False
    
    def test_print_summary(self, harness, capsys):
        """Test printing test summary."""
        harness.results = [
            TestResult(test_name="Test 1", success=True, session_id=1, duration_seconds=2.5),
            TestResult(test_name="Test 2", success=False, error="Failed", duration_seconds=1.5),
            TestResult(test_name="Test 3", success=True, session_id=2, duration_seconds=3.0),
        ]
        
        harness.print_summary()
        
        captured = capsys.readouterr()
        assert "TEST SUMMARY" in captured.out
        assert "Total Tests: 3" in captured.out
        assert "Passed: 2" in captured.out
        assert "Failed: 1" in captured.out
        assert "Success Rate: 66.7%" in captured.out
    
    @pytest.mark.asyncio
    async def test_cleanup(self, harness):
        """Test cleanup closes the MCP client."""
        with patch.object(harness.mcp_client, 'close', new=AsyncMock()) as mock_close:
            await harness.cleanup()
            mock_close.assert_called_once()


class TestSessionDetection:
    """Test session ID detection from exploit output."""
    
    @pytest.mark.asyncio
    async def test_session_detection_various_formats(self):
        """Test detection of session IDs in various output formats."""
        harness = Metasploitable3TestHarness(
            target_ip="10.0.0.1",
            lhost="10.0.0.1",
            lport=4444
        )
        
        test = ExploitTest(
            name="Test",
            description="Test",
            module="exploit/test",
            payload="test/payload",
            options={"RHOSTS": "10.0.0.1"}
        )
        
        # Test different session output formats
        test_outputs = [
            ("Meterpreter session 1 opened", 1),
            ("Command shell session 5 opened", 5),
            ("Session 42 opened", 42),
            ("* Meterpreter session 123 opened", 123),
        ]
        
        for output, expected_session_id in test_outputs:
            with patch.object(harness.mcp_client, 'run_exploit', new=AsyncMock(
                return_value={"success": True, "data": output}
            )):
                with patch.object(harness.mcp_client, 'list_sessions', new=AsyncMock(
                    return_value={"success": True}
                )):
                    with patch.object(harness.mcp_client, 'send_session_command', new=AsyncMock(
                        return_value={"success": True, "data": "uid=0"}
                    )):
                        result = await harness.run_single_test(test)
            
            assert result.session_id == expected_session_id, f"Failed to detect session ID in: {output}"


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""
    
    @pytest.mark.asyncio
    async def test_proftpd_exploit_flow(self):
        """Test a complete ProFTPD exploit flow."""
        harness = Metasploitable3TestHarness(
            target_ip="10.0.2.15",
            lhost="10.0.2.4",
            lport=4444
        )
        
        tests = harness.get_exploit_tests()
        proftpd_test = next(t for t in tests if "proftpd" in t.name.lower())
        
        # Verify test configuration
        assert proftpd_test.module == "exploit/unix/ftp/proftpd_modcopy_exec"
        assert proftpd_test.payload == "unix/reverse_perl"
        assert proftpd_test.options["RPORT"] == "80"
        assert proftpd_test.options["RPORT_FTP"] == "21"
    
    @pytest.mark.asyncio
    async def test_shellshock_exploit_flow(self):
        """Test a complete Shellshock exploit flow."""
        harness = Metasploitable3TestHarness(
            target_ip="10.0.2.15",
            lhost="10.0.2.4",
            lport=4444
        )
        
        tests = harness.get_exploit_tests()
        shellshock_test = next(t for t in tests if "shellshock" in t.name.lower())
        
        # Verify test configuration
        assert shellshock_test.module == "exploit/multi/http/apache_mod_cgi_bash_env_exec"
        assert "meterpreter" in shellshock_test.payload
        assert shellshock_test.options["TARGETURI"] == "/cgi-bin/hello_world.sh"


class TestErrorHandling:
    """Test error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_network_error_handling(self):
        """Test handling of network errors."""
        client = MetasploitMCPClient("http://invalid-server:8085")
        
        with patch.object(client.client, 'post', side_effect=Exception("Network error")):
            with pytest.raises(Exception, match="Network error"):
                await client.call_tool("test_tool", {})
    
    @pytest.mark.asyncio
    async def test_invalid_json_response(self):
        """Test handling of invalid JSON responses."""
        client = MetasploitMCPClient("http://test-server:8085")
        
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        
        with patch.object(client.client, 'post', new=AsyncMock(return_value=mock_response)):
            with pytest.raises(json.JSONDecodeError):
                await client.call_tool("test_tool", {})
    
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test handling of request timeouts."""
        import httpx
        
        client = MetasploitMCPClient("http://test-server:8085")
        
        with patch.object(client.client, 'post', side_effect=httpx.TimeoutException("Timeout")):
            with pytest.raises(Exception):
                await client.call_tool("test_tool", {})


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

