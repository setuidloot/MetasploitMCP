#!/usr/bin/env python3
"""
Unit tests for regex patterns and exit terms functionality in MetasploitMCP.
Tests the new global regex variables and exit_terms_regexes parameter support.
"""

import pytest
import sys
import os
import asyncio
import re
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any

# Add the parent directory to the path to import metasploit_mcp.server as MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock the dependencies that aren't available in test environment
mock_uvicorn = Mock()
mock_uvicorn.server = Mock()
sys.modules['uvicorn'] = mock_uvicorn
sys.modules['uvicorn.server'] = mock_uvicorn.server
sys.modules['fastapi'] = Mock()
sys.modules['mcp.server.fastmcp'] = Mock()
sys.modules['mcp.server.sse'] = Mock()
sys.modules['pymetasploit3.msfrpc'] = Mock()
sys.modules['starlette.applications'] = Mock()
sys.modules['starlette.routing'] = Mock()
sys.modules['mcp.server.session'] = Mock()
sys.modules['fastmcp'] = Mock()
sys.modules['fastmcp.client'] = Mock()
sys.modules['fastmcp.client.transports'] = Mock()

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
from metasploit_mcp.server import (
    IS_VULNERABLE_RE,
    IS_NOT_VULNERABLE_RE,
    SESSION_OPENED_RE,
    FAILED_TO_LOAD_MODULE_RE,
    CHECK_NOT_SUPPORTED_RE,
    run_command_safely,
    _execute_module_console,
    get_msf_console
)


@pytest.fixture(autouse=True)
def _mock_msf_client_instance():
    """Provide a default MSF client for console helpers."""
    client = Mock()
    console = Mock()
    console.cid = "test-console"
    console.read.return_value = {"data": "", "prompt": "", "busy": False}
    console.write.return_value = True
    client.consoles.console.return_value = console
    client.consoles.destroy.return_value = "destroyed"
    with patch.object(sys.modules['MetasploitMCP'], "_msf_client_instance", client):
        yield client


class TestRegexPatterns:
    """Test the global regex patterns for vulnerability and session detection."""

    def test_is_vulnerable_re_patterns(self):
        """Test IS_VULNERABLE_RE matches various vulnerability indicators."""
        test_cases = [
            ("The target appears vulnerable", True),
            ("Target is vulnerable to this exploit", True),
            ("The system appears to be vulnerable", True),
            ("+ vulnerable", True),
            ("VULNERABLE: Yes", False),  # Not in our pattern
            ("The target does not appear vulnerable", False),  # Negative
            ("is not vulnerable", False),  # Negative
            ("appears vulnerable and exploitable", True),
            ("IS VULNERABLE", True),  # Case insensitive
            ("Appears Vulnerable", True),  # Case insensitive
        ]
        
        for text, should_match in test_cases:
            text_bytes = text.encode('utf-8', errors='replace')
            result = bool(IS_VULNERABLE_RE.search(text_bytes))
            assert result == should_match, f"Pattern {'should' if should_match else 'should not'} match: '{text}'"

    def test_is_not_vulnerable_re_patterns(self):
        """Test IS_NOT_VULNERABLE_RE matches various non-vulnerability indicators."""
        test_cases = [
            ("The target does not appear vulnerable", True),
            ("Target is not vulnerable", True),
            ("The target is not vulnerable to this exploit", True),
            ("check failed", True),
            ("Check Failed", True),  # Case insensitive
            ("CHECK FAILED", True),  # Case insensitive
            ("The target appears vulnerable", False),  # Positive
            ("is vulnerable", False),  # Positive
            ("does not appear to be vulnerable", False),  # Close but not exact match
            ("target is not vulnerable to this", True),
        ]
        
        for text, should_match in test_cases:
            text_bytes = text.encode('utf-8', errors='replace')
            result = bool(IS_NOT_VULNERABLE_RE.search(text_bytes))
            assert result == should_match, f"Pattern {'should' if should_match else 'should not'} match: '{text}'"

    def test_session_opened_re_patterns(self):
        """Test SESSION_OPENED_RE matches session opened messages."""
        test_cases = [
            ("meterpreter session 1 opened", True),
            ("command shell session 2 opened", True),
            ("Meterpreter session 3 opened", True),  # Case insensitive
            ("COMMAND SHELL SESSION 4 OPENED", True),  # Case insensitive
            ("meterpreter session 123 opened", True),
            ("command shell session 0 opened", True),
            ("session opened", False),  # Missing type
            ("meterpreter session opened", False),  # Missing number
            ("session 1 opened", False),  # Missing type
            ("meterpreter session 1", False),  # Missing "opened"
            ("opened session 1", False),  # Wrong order
        ]
        
        for text, should_match in test_cases:
            text_bytes = text.encode('utf-8', errors='replace')
            result = bool(SESSION_OPENED_RE.search(text_bytes))
            assert result == should_match, f"Pattern {'should' if should_match else 'should not'} match: '{text}'"

    def test_failed_to_load_module_re_patterns(self):
        """Test FAILED_TO_LOAD_MODULE_RE matches various module load failure indicators."""
        test_cases = [
            ("[-] Failed to load module: exploit/multi/http/cups_ipp_remote_code_execution", True),
            ("[-] Failed to load module: exploit/windows/smb/ms17_010", True),
            ("[-] failed to load module: auxiliary/scanner/http/http_version", True),
            ("[-] FAILED TO LOAD MODULE: post/windows/gather/enum_shares", True),
            ("Failed to load module: exploit/test", False),  # Missing [-] prefix
            ("Error loading module", False),  # Different format
            ("Module loaded successfully", False),  # Should not match
            ("[-] Failed to load module:", True),  # Even without module name
        ]
        
        for text, should_match in test_cases:
            text_bytes = text.encode('utf-8', errors='replace')
            result = bool(FAILED_TO_LOAD_MODULE_RE.search(text_bytes))
            assert result == should_match, f"Pattern {'should' if should_match else 'should not'} match: '{text}'"

    def test_check_not_supported_re_patterns(self):
        """Test CHECK_NOT_SUPPORTED_RE matches module check not supported messages."""
        test_cases = [
            ("This module does not support check.", True),
            ("this module does not support check.", True),  # Case insensitive
            ("THIS MODULE DOES NOT SUPPORT CHECK.", True),  # Case insensitive
            ("This module does not support check", True),  # Without period
            ("[*] This module does not support check.", True),  # With prefix
            ("[-] This module does not support check.", True),  # With error prefix
            ("Module does not support check", False),  # Missing "This"
            ("This module supports check", False),  # Should not match
            ("Check is supported", False),  # Should not match
        ]
        
        for text, should_match in test_cases:
            text_bytes = text.encode('utf-8', errors='replace')
            result = bool(CHECK_NOT_SUPPORTED_RE.search(text_bytes))
            assert result == should_match, f"Pattern {'should' if should_match else 'should not'} match: '{text}'"

    def test_regex_patterns_are_compiled(self):
        """Test that regex patterns are properly compiled."""
        assert isinstance(IS_VULNERABLE_RE, re.Pattern)
        assert isinstance(IS_NOT_VULNERABLE_RE, re.Pattern)
        assert isinstance(SESSION_OPENED_RE, re.Pattern)
        assert isinstance(FAILED_TO_LOAD_MODULE_RE, re.Pattern)
        assert isinstance(CHECK_NOT_SUPPORTED_RE, re.Pattern)
        
        # Verify they are bytes patterns (pattern is bytes type)
        assert isinstance(IS_VULNERABLE_RE.pattern, bytes)
        assert isinstance(IS_NOT_VULNERABLE_RE.pattern, bytes)
        assert isinstance(SESSION_OPENED_RE.pattern, bytes)
        assert isinstance(FAILED_TO_LOAD_MODULE_RE.pattern, bytes)
        assert isinstance(CHECK_NOT_SUPPORTED_RE.pattern, bytes)


class TestRunCommandSafelyWithExitTerms:
    """Test run_command_safely with exit_terms_regexes parameter."""

    @pytest.fixture
    def mock_console(self):
        """Fixture providing a mock console."""
        console = Mock()
        console.write = Mock()
        console.read = Mock()
        return console

    @pytest.mark.asyncio
    async def test_run_command_safely_with_exit_terms_vulnerable(self, mock_console):
        """Test that exit terms cause early return when vulnerability detected."""
        # Simulate console output with vulnerability indicator
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First read: return vulnerability message
                return {
                    'data': 'The target appears vulnerable\n',
                    'prompt': '',
                    'busy': False
                }
            elif call_count <= 5:
                # Subsequent reads: no new data (simulating idle period)
                return {
                    'data': '',
                    'prompt': '',
                    'busy': False
                }
            else:
                # After idle period, return prompt
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Use IS_VULNERABLE_RE as exit term
        result = await run_command_safely(
            mock_console, 
            'check',
            exit_terms_regexes=[IS_VULNERABLE_RE]
        )
        
        # Should return early when exit term matches (after idle period)
        assert 'appears vulnerable' in result.lower()
        # Should not have waited for full timeout (idle timeout is 2s, check interval is 0.1s = ~20 calls)
        assert call_count <= 25  # Should exit early after idle period

    @pytest.mark.asyncio
    async def test_run_command_safely_with_exit_terms_session(self, mock_console):
        """Test that exit terms cause early return when session opened."""
        # Simulate console output with session opened message
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First read: return session opened message
                return {
                    'data': '[*] Exploit completed, but no session was created.\n[*] meterpreter session 1 opened\n',
                    'prompt': '',
                    'busy': False
                }
            elif call_count <= 5:
                # Subsequent reads: no new data (simulating idle period)
                return {
                    'data': '',
                    'prompt': '',
                    'busy': False
                }
            else:
                # After idle period, return prompt
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Use SESSION_OPENED_RE as exit term
        result = await run_command_safely(
            mock_console, 
            'exploit',
            exit_terms_regexes=[SESSION_OPENED_RE]
        )
        
        # Should return early when exit term matches
        assert 'session' in result.lower() or 'meterpreter' in result.lower()
        # Should not have waited for full timeout (idle timeout is 2s, check interval is 0.1s = ~20 calls)
        assert call_count <= 25  # Should exit early after idle period

    @pytest.mark.asyncio
    async def test_run_command_safely_with_exit_terms_no_match(self, mock_console):
        """Test that exit terms don't cause early return when no match."""
        # Simulate console output without exit terms
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    'data': 'Some regular output\n',
                    'prompt': '',
                    'busy': False
                }
            elif call_count <= 5:
                return {
                    'data': '',
                    'prompt': '',
                    'busy': False
                }
            else:
                # Return prompt after normal completion
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Use exit terms that won't match
        result = await run_command_safely(
            mock_console, 
            'help',
            exit_terms_regexes=[IS_VULNERABLE_RE, IS_NOT_VULNERABLE_RE]
        )
        
        # Should complete normally (wait for prompt)
        assert 'Some regular output' in result
        # Should have waited for prompt
        assert call_count >= 5

    @pytest.mark.asyncio
    async def test_run_command_safely_with_exit_terms_multiple_patterns(self, mock_console):
        """Test that exit terms work with multiple patterns."""
        # Simulate console output with one of the exit terms
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    'data': 'The target is not vulnerable\n',
                    'prompt': '',
                    'busy': False
                }
            elif call_count <= 5:
                return {
                    'data': '',
                    'prompt': '',
                    'busy': False
                }
            else:
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Use multiple exit terms
        result = await run_command_safely(
            mock_console, 
            'check',
            exit_terms_regexes=[IS_VULNERABLE_RE, IS_NOT_VULNERABLE_RE]
        )
        
        # Should return early when one pattern matches
        assert 'not vulnerable' in result.lower()
        # Should not have waited for full timeout (idle timeout is 2s, check interval is 0.1s = ~20 calls)
        assert call_count <= 25  # Should exit early after idle period

    @pytest.mark.asyncio
    async def test_run_command_safely_without_exit_terms(self, mock_console):
        """Test that run_command_safely works normally without exit terms."""
        # Simulate normal console output
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    'data': 'Command output\n',
                    'prompt': '',
                    'busy': False
                }
            else:
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # No exit terms
        result = await run_command_safely(mock_console, 'help')
        
        # Should complete normally
        assert 'Command output' in result
        assert call_count >= 2  # Should wait for prompt


class TestExecuteModuleConsoleWithExitTerms:
    """Test _execute_module_console with exit_terms_regexes parameter."""

    @pytest.fixture
    def mock_console(self):
        """Fixture providing a mock console."""
        console = Mock()
        console.write = Mock()
        console.read = Mock()
        return console

    @pytest.mark.asyncio
    async def test_execute_module_console_with_exit_terms(self, mock_console):
        """Test _execute_module_console passes exit terms to run_command_safely."""
        # Mock console reads
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Setup command response
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
            elif call_count == 2:
                # Module output with vulnerability
                return {
                    'data': 'The target appears vulnerable\n',
                    'prompt': '',
                    'busy': False
                }
            elif call_count <= 6:
                # Idle period
                return {
                    'data': '',
                    'prompt': '',
                    'busy': False
                }
            else:
                # Final prompt
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Mock get_msf_console
        with patch('metasploit_mcp.server.get_msf_console') as mock_get_console:
            mock_get_console.return_value.__aenter__.return_value = mock_console
            mock_get_console.return_value.__aexit__.return_value = None
            
            # Call with exit terms
            result = await _execute_module_console(
                module_type='exploit',
                module_name='test/module',
                module_options={},
                command='check',
                exit_terms_regexes=[IS_VULNERABLE_RE, IS_NOT_VULNERABLE_RE]
            )
            
            # Should return result with module output
            assert result.get('status') in ['success', 'error', 'warning', 'no_session']
            assert 'module_output' in result
            # Should have used exit terms (early return) - idle timeout is 2s, check interval is 0.1s
            assert call_count <= 30  # Should exit early after idle period

    @pytest.mark.asyncio
    async def test_execute_module_console_without_exit_terms(self, mock_console):
        """Test _execute_module_console works without exit terms."""
        # Mock console reads
        call_count = 0
        def mock_read():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
            elif call_count == 2:
                return {
                    'data': 'Module output\n',
                    'prompt': '',
                    'busy': False
                }
            else:
                return {
                    'data': '',
                    'prompt': '\x01\x02msf6\x01\x02 \x01\x02> \x01\x02',
                    'busy': False
                }
        
        mock_console.read.side_effect = mock_read
        
        # Mock get_msf_console
        with patch('metasploit_mcp.server.get_msf_console') as mock_get_console:
            mock_get_console.return_value.__aenter__.return_value = mock_console
            mock_get_console.return_value.__aexit__.return_value = None
            
            # Call without exit terms
            result = await _execute_module_console(
                module_type='auxiliary',
                module_name='test/module',
                module_options={},
                command='run'
            )
            
            # Should return result normally
            assert result.get('status') in ['success', 'error', 'warning', 'no_session']
            assert 'module_output' in result


class TestVulnerabilityCheckWithRegex:
    """Test vulnerability check using new regex patterns."""

    def test_vulnerability_detection_with_regex(self):
        """Test that vulnerability detection works with regex patterns."""
        # Test vulnerable cases
        vulnerable_outputs = [
            "The target appears vulnerable",
            "Target is vulnerable to this exploit",
            "The system appears to be vulnerable",
            "+ vulnerable",
        ]
        
        for output in vulnerable_outputs:
            output_bytes = output.encode('utf-8', errors='replace')
            is_vulnerable = bool(IS_VULNERABLE_RE.search(output_bytes))
            assert is_vulnerable, f"Should detect vulnerability in: '{output}'"
        
        # Test not vulnerable cases
        not_vulnerable_outputs = [
            "The target does not appear vulnerable",
            "Target is not vulnerable",
            "The target is not vulnerable to this exploit",
            "check failed",
        ]
        
        for output in not_vulnerable_outputs:
            output_bytes = output.encode('utf-8', errors='replace')
            is_not_vulnerable = bool(IS_NOT_VULNERABLE_RE.search(output_bytes))
            assert is_not_vulnerable, f"Should detect non-vulnerability in: '{output}'"


class TestSessionDetectionWithRegex:
    """Test session detection using new regex pattern."""

    def test_session_detection_with_regex(self):
        """Test that session detection works with regex pattern."""
        # Test session opened cases
        session_outputs = [
            "meterpreter session 1 opened",
            "command shell session 2 opened",
            "Meterpreter session 3 opened",
            "COMMAND SHELL SESSION 4 OPENED",
            "[*] meterpreter session 123 opened",
            "[*] command shell session 0 opened",
        ]
        
        for output in session_outputs:
            output_bytes = output.encode('utf-8', errors='replace')
            session_match = SESSION_OPENED_RE.search(output_bytes)
            assert session_match is not None, f"Should detect session in: '{output}'"
            
            # Verify we can extract session ID from the matched text
            matched_text = session_match.group(0)
            session_id_match = re.search(rb'session\s+(\d+)', matched_text, re.IGNORECASE)
            assert session_id_match is not None, f"Should extract session ID from matched text '{matched_text.decode('utf-8', errors='replace')}' for input: '{output}'"
        
        # Test non-session cases
        non_session_outputs = [
            "session opened",  # Missing type
            "meterpreter session opened",  # Missing number
            "session 1 opened",  # Missing type
            "opened session 1",  # Wrong order
        ]
        
        for output in non_session_outputs:
            output_bytes = output.encode('utf-8', errors='replace')
            session_match = SESSION_OPENED_RE.search(output_bytes)
            assert session_match is None, f"Should not detect session in: '{output}'"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

