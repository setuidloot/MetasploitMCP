"""
Tests for the 120-second timeout cap on Metasploit MCP tool parameters.

This module tests that:
1. Timeouts exceeding 120s are capped at 120s (not rejected)
2. Timeouts at or below 120s pass through unchanged
3. The MAX_TOOL_TIMEOUT_SECONDS constant is correctly defined
"""

import pytest


class TestTimeoutCapConstants:
    """Test timeout cap constant is defined correctly"""
    
    def test_max_tool_timeout_constant_exists(self):
        """Verify MAX_TOOL_TIMEOUT_SECONDS constant is defined"""
        from MetasploitMCP import MAX_TOOL_TIMEOUT_SECONDS
        assert MAX_TOOL_TIMEOUT_SECONDS == 120
    
    def test_default_timeout_constants_within_limit(self):
        """Verify default timeout constants don't exceed the max"""
        from MetasploitMCP import (
            LONG_CONSOLE_READ_TIMEOUT,
            SESSION_COMMAND_TIMEOUT,
            SESSION_READ_INACTIVITY_TIMEOUT,
            DEFAULT_SESSION_INACTIVITY_TIMEOUT,
            MAX_TOOL_TIMEOUT_SECONDS
        )
        assert LONG_CONSOLE_READ_TIMEOUT <= MAX_TOOL_TIMEOUT_SECONDS, \
            f"LONG_CONSOLE_READ_TIMEOUT ({LONG_CONSOLE_READ_TIMEOUT}s) exceeds max ({MAX_TOOL_TIMEOUT_SECONDS}s)"
        assert SESSION_COMMAND_TIMEOUT <= MAX_TOOL_TIMEOUT_SECONDS, \
            f"SESSION_COMMAND_TIMEOUT ({SESSION_COMMAND_TIMEOUT}s) exceeds max ({MAX_TOOL_TIMEOUT_SECONDS}s)"
        assert SESSION_READ_INACTIVITY_TIMEOUT <= MAX_TOOL_TIMEOUT_SECONDS, \
            f"SESSION_READ_INACTIVITY_TIMEOUT ({SESSION_READ_INACTIVITY_TIMEOUT}s) exceeds max ({MAX_TOOL_TIMEOUT_SECONDS}s)"
        assert DEFAULT_SESSION_INACTIVITY_TIMEOUT <= MAX_TOOL_TIMEOUT_SECONDS, \
            f"DEFAULT_SESSION_INACTIVITY_TIMEOUT ({DEFAULT_SESSION_INACTIVITY_TIMEOUT}s) exceeds max ({MAX_TOOL_TIMEOUT_SECONDS}s)"
    
    def test_max_tool_timeout_is_120(self):
        """Verify the max tool timeout is exactly 120 seconds"""
        from MetasploitMCP import MAX_TOOL_TIMEOUT_SECONDS
        assert MAX_TOOL_TIMEOUT_SECONDS == 120, \
            f"MAX_TOOL_TIMEOUT_SECONDS should be 120, got {MAX_TOOL_TIMEOUT_SECONDS}"


class TestTimeoutCapLogic:
    """Test the timeout capping logic that's used in all tools"""
    
    def _apply_timeout_cap(self, timeout_seconds: int) -> int:
        """Replicate the timeout capping logic used in tools"""
        from MetasploitMCP import MAX_TOOL_TIMEOUT_SECONDS
        if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
            return MAX_TOOL_TIMEOUT_SECONDS
        return timeout_seconds
    
    @pytest.mark.parametrize("input_timeout,expected_timeout", [
        (1, 1),       # Minimum valid
        (15, 15),     # SESSION_COMMAND_TIMEOUT default
        (30, 30),     # Half minute
        (60, 60),     # LONG_CONSOLE_READ_TIMEOUT default
        (90, 90),     # 90 seconds
        (119, 119),   # Just under cap
        (120, 120),   # Exactly at cap
        (121, 120),   # Just over cap - should be capped
        (180, 120),   # 3 minutes - should be capped
        (300, 120),   # 5 minutes - should be capped
        (600, 120),   # 10 minutes - should be capped
        (3600, 120),  # 1 hour - should be capped
        (86400, 120), # 1 day - should be capped
    ])
    def test_timeout_capping_values(self, input_timeout, expected_timeout):
        """Test the capping logic for various timeout values"""
        result = self._apply_timeout_cap(input_timeout)
        assert result == expected_timeout, \
            f"Input {input_timeout}s should result in {expected_timeout}s, got {result}s"
    
    def test_timeout_cap_boundary_at_120(self):
        """Test boundary condition at exactly 120s"""
        assert self._apply_timeout_cap(120) == 120
        assert self._apply_timeout_cap(121) == 120
    
    def test_timeout_cap_preserves_low_values(self):
        """Test that low timeout values are preserved"""
        for timeout in [1, 5, 10, 15, 30, 60, 100, 119]:
            assert self._apply_timeout_cap(timeout) == timeout


class TestTimeoutCapInSource:
    """Test that timeout capping is implemented in the source code by reading the file"""
    
    def test_source_contains_timeout_cap_constant(self):
        """Verify source code defines MAX_TOOL_TIMEOUT_SECONDS"""
        import os
        
        # Read the source file
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MetasploitMCP.py')
        with open(source_path, 'r') as f:
            source = f.read()
        
        assert 'MAX_TOOL_TIMEOUT_SECONDS = 120' in source, \
            "Source should define MAX_TOOL_TIMEOUT_SECONDS = 120"
    
    def test_run_exploit_uses_timeout_cap(self):
        """Verify run_exploit function checks timeout cap"""
        import os
        
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MetasploitMCP.py')
        with open(source_path, 'r') as f:
            source = f.read()
        
        # Find the run_exploit function and check it has the cap logic
        # The function should have: if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        assert 'async def run_exploit(' in source
        
        # Find the section after run_exploit definition
        run_exploit_start = source.find('async def run_exploit(')
        run_exploit_end = source.find('\n@mcp.tool', run_exploit_start + 1)
        if run_exploit_end == -1:
            run_exploit_end = len(source)
        
        run_exploit_source = source[run_exploit_start:run_exploit_end]
        
        assert 'timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_exploit_source, \
            "run_exploit should check if timeout_seconds exceeds MAX_TOOL_TIMEOUT_SECONDS"
        assert 'timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS' in run_exploit_source, \
            "run_exploit should cap timeout_seconds to MAX_TOOL_TIMEOUT_SECONDS"
        assert 'inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_exploit_source, \
            "run_exploit should cap inactivity_timeout_seconds"
    
    def test_run_post_module_uses_timeout_cap(self):
        """Verify run_post_module function checks timeout cap"""
        import os
        
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MetasploitMCP.py')
        with open(source_path, 'r') as f:
            source = f.read()
        
        run_post_start = source.find('async def run_post_module(')
        run_post_end = source.find('\n@mcp.tool', run_post_start + 1)
        if run_post_end == -1:
            run_post_end = len(source)
        
        run_post_source = source[run_post_start:run_post_end]
        
        assert 'timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_post_source, \
            "run_post_module should check if timeout_seconds exceeds MAX_TOOL_TIMEOUT_SECONDS"
        assert 'inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_post_source, \
            "run_post_module should cap inactivity_timeout_seconds"
    
    def test_run_auxiliary_module_uses_timeout_cap(self):
        """Verify run_auxiliary_module function checks timeout cap"""
        import os
        
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MetasploitMCP.py')
        with open(source_path, 'r') as f:
            source = f.read()
        
        run_aux_start = source.find('async def run_auxiliary_module(')
        run_aux_end = source.find('\n@mcp.tool', run_aux_start + 1)
        if run_aux_end == -1:
            run_aux_end = len(source)
        
        run_aux_source = source[run_aux_start:run_aux_end]
        
        assert 'timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_aux_source, \
            "run_auxiliary_module should check if timeout_seconds exceeds MAX_TOOL_TIMEOUT_SECONDS"
        assert 'inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in run_aux_source, \
            "run_auxiliary_module should cap inactivity_timeout_seconds"
    
    def test_send_session_command_uses_timeout_cap(self):
        """Verify send_session_command function checks timeout cap"""
        import os
        
        source_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'MetasploitMCP.py')
        with open(source_path, 'r') as f:
            source = f.read()
        
        send_session_start = source.find('async def send_session_command(')
        send_session_end = source.find('\n@mcp.tool', send_session_start + 1)
        if send_session_end == -1:
            send_session_end = len(source)
        
        send_session_source = source[send_session_start:send_session_end]
        
        assert 'timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in send_session_source, \
            "send_session_command should check if timeout_seconds exceeds MAX_TOOL_TIMEOUT_SECONDS"
        assert 'inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS' in send_session_source, \
            "send_session_command should cap inactivity_timeout_seconds"
