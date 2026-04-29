#!/usr/bin/env python3
"""
Unit tests for MCP keep-alive functionality in MetasploitMCP.

Tests the keep-alive infrastructure that prevents client timeouts during
long-running Metasploit operations.
"""

import pytest
import sys
import os
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any

# Add the parent directory to the path to import metasploit_mcp.server as MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock pymetasploit3 before importing MetasploitMCP
class MockMsfRpcError(Exception):
    pass

class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()
        self.core.version = {'version': '6.3.0'}
        self.modules.exploits = ['windows/smb/ms17_010_eternalblue']
        self.modules.payloads = ['windows/meterpreter/reverse_tcp']
        self.sessions.list = {}
        self.jobs.list = {}

class MockMsfConsole:
    def __init__(self, cid='test-console-id'):
        self.cid = cid
        
    def read(self):
        return {'data': 'msf6 > ', 'prompt': 'msf6 > ', 'busy': False}
        
    def write(self, command):
        return True

# Apply mocks before importing
mock_msfrpc = Mock()
mock_msfrpc.MsfRpcClient = MockMsfRpcClient
mock_msfrpc.MsfConsole = MockMsfConsole
mock_msfrpc.MsfRpcError = MockMsfRpcError
sys.modules['pymetasploit3.msfrpc'] = mock_msfrpc
sys.modules['pymetasploit3'] = Mock(msfrpc=mock_msfrpc)

# Import the module under test
import metasploit_mcp.server as MetasploitMCP
from metasploit_mcp.server import (
    _NoOpContextManager,
    get_keepalive_manager,
    DEFAULT_KEEPALIVE_INTERVAL,
    KEEPALIVE_AVAILABLE,
)


class TestNoOpContextManager:
    """Tests for the _NoOpContextManager class."""
    
    @pytest.mark.asyncio
    async def test_async_context_manager_entry_exit(self):
        """Test that _NoOpContextManager works as an async context manager."""
        manager = _NoOpContextManager()
        async with manager as ctx:
            assert ctx is manager
    
    @pytest.mark.asyncio
    async def test_start_is_noop(self):
        """Test that start() does nothing and completes without error."""
        manager = _NoOpContextManager()
        result = await manager.start()
        assert result is None
    
    @pytest.mark.asyncio
    async def test_stop_is_noop(self):
        """Test that stop() does nothing and completes without error."""
        manager = _NoOpContextManager()
        result = await manager.stop()
        assert result is None
    
    @pytest.mark.asyncio
    async def test_stop_with_send_completion_false(self):
        """Test that stop(send_completion=False) works correctly."""
        manager = _NoOpContextManager()
        result = await manager.stop(send_completion=False)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_multiple_start_stop_cycles(self):
        """Test that multiple start/stop cycles work correctly."""
        manager = _NoOpContextManager()
        
        await manager.start()
        await manager.stop()
        await manager.start()
        await manager.stop(send_completion=False)
        # Should not raise any errors


class TestGetKeepaliveManager:
    """Tests for the get_keepalive_manager() factory function."""
    
    def test_returns_noop_when_ctx_is_none(self):
        """Test that get_keepalive_manager returns _NoOpContextManager when ctx is None."""
        manager = get_keepalive_manager(
            ctx=None,
            operation_name="Test operation"
        )
        assert isinstance(manager, _NoOpContextManager)
    
    def test_returns_keepalive_manager_when_ctx_provided(self):
        """Test that get_keepalive_manager returns KeepAliveProgressManager when ctx is provided."""
        mock_ctx = Mock()
        manager = get_keepalive_manager(
            ctx=mock_ctx,
            operation_name="Test operation"
        )
        # When ctx is provided, it should NOT be _NoOpContextManager
        # It should be the KeepAliveProgressManager (either real or fallback)
        assert not isinstance(manager, _NoOpContextManager) or mock_ctx is None
    
    def test_passes_interval_parameter(self):
        """Test that interval parameter is passed to the manager."""
        mock_ctx = Mock()
        manager = get_keepalive_manager(
            ctx=mock_ctx,
            operation_name="Test operation",
            interval=5.0
        )
        assert hasattr(manager, 'interval')
        assert manager.interval == 5.0
    
    def test_passes_progress_parameters(self):
        """Test that progress parameters are passed to the manager."""
        mock_ctx = Mock()
        manager = get_keepalive_manager(
            ctx=mock_ctx,
            operation_name="Test operation",
            initial_progress=10,
            max_progress=80
        )
        assert hasattr(manager, 'initial_progress')
        assert hasattr(manager, 'max_progress')
        assert manager.initial_progress == 10
        assert manager.max_progress == 80
    
    def test_default_interval(self):
        """Test that DEFAULT_KEEPALIVE_INTERVAL is used when not specified."""
        mock_ctx = Mock()
        manager = get_keepalive_manager(
            ctx=mock_ctx,
            operation_name="Test operation"
        )
        assert manager.interval == DEFAULT_KEEPALIVE_INTERVAL


class TestToolsWithNoneContext:
    """Tests to verify tools work correctly when ctx is None."""
    
    @pytest.fixture
    def mock_msf_client(self):
        """Create a mock MSF client for testing."""
        with patch('metasploit_mcp.server.get_msf_client') as mock_get_client:
            client = Mock()
            client.modules.exploits = ['windows/smb/ms17_010_eternalblue', 'unix/ftp/vsftpd_234_backdoor']
            client.modules.payloads = ['windows/meterpreter/reverse_tcp', 'linux/x86/shell/reverse_tcp']
            client.sessions.list = {}
            client.jobs.list = {}
            mock_get_client.return_value = client
            yield client
    
    @pytest.fixture
    def mock_asyncio_to_thread(self):
        """Mock asyncio.to_thread to run synchronously."""
        async def mock_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)
        
        with patch('asyncio.to_thread', side_effect=mock_to_thread):
            yield
    
    @pytest.mark.asyncio
    async def test_list_exploits_with_none_ctx(self, mock_msf_client, mock_asyncio_to_thread):
        """Test that list_exploits works correctly with ctx=None."""
        # Get the underlying function
        list_exploits_fn = MetasploitMCP.list_exploits.fn
        
        result = await list_exploits_fn(search_term="", ctx=None)
        
        assert isinstance(result, list)
        assert len(result) > 0
    
    @pytest.mark.asyncio
    async def test_list_payloads_with_none_ctx(self, mock_msf_client, mock_asyncio_to_thread):
        """Test that list_payloads works correctly with ctx=None."""
        list_payloads_fn = MetasploitMCP.list_payloads.fn
        
        result = await list_payloads_fn(platform="", arch="", ctx=None)
        
        assert isinstance(result, list)


class TestToolsWithMockContext:
    """Tests to verify tools call ctx.report_progress when ctx is provided."""
    
    @pytest.fixture
    def mock_ctx(self):
        """Create a mock MCP Context."""
        ctx = Mock()
        ctx.report_progress = AsyncMock()
        return ctx
    
    @pytest.fixture
    def mock_msf_client(self):
        """Create a mock MSF client for testing."""
        with patch('metasploit_mcp.server.get_msf_client') as mock_get_client:
            client = Mock()
            client.modules.exploits = ['windows/smb/ms17_010_eternalblue']
            client.modules.payloads = ['windows/meterpreter/reverse_tcp']
            client.sessions.list = {}
            client.jobs.list = {}
            mock_get_client.return_value = client
            yield client
    
    @pytest.fixture
    def mock_asyncio_to_thread(self):
        """Mock asyncio.to_thread to run synchronously."""
        async def mock_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)
        
        with patch('asyncio.to_thread', side_effect=mock_to_thread):
            yield
    
    @pytest.mark.asyncio
    async def test_list_exploits_reports_progress(self, mock_ctx, mock_msf_client, mock_asyncio_to_thread):
        """Test that list_exploits reports progress when ctx is provided."""
        list_exploits_fn = MetasploitMCP.list_exploits.fn
        
        result = await list_exploits_fn(search_term="", ctx=mock_ctx)
        
        # Should have called report_progress at least twice (start and end)
        assert mock_ctx.report_progress.call_count >= 2
        
        # Check that initial progress was reported
        first_call = mock_ctx.report_progress.call_args_list[0]
        assert first_call.kwargs.get('progress') == 0
        
        # Check that completion progress was reported
        last_call = mock_ctx.report_progress.call_args_list[-1]
        assert last_call.kwargs.get('progress') == 100
    
    @pytest.mark.asyncio
    async def test_list_payloads_reports_progress(self, mock_ctx, mock_msf_client, mock_asyncio_to_thread):
        """Test that list_payloads reports progress when ctx is provided."""
        list_payloads_fn = MetasploitMCP.list_payloads.fn
        
        result = await list_payloads_fn(platform="", arch="", ctx=mock_ctx)
        
        # Should have called report_progress at least twice
        assert mock_ctx.report_progress.call_count >= 2


class TestKeepaliveManagerIntegration:
    """Integration tests for keep-alive manager behavior."""
    
    @pytest.mark.asyncio
    async def test_noop_manager_in_context(self):
        """Test that NoOp manager works correctly in async with context."""
        manager = get_keepalive_manager(ctx=None, operation_name="Test")
        
        async with manager:
            # Simulate some work
            await asyncio.sleep(0.01)
        
        # Should complete without errors
    
    @pytest.mark.asyncio
    async def test_noop_manager_explicit_start_stop(self):
        """Test that NoOp manager works with explicit start/stop."""
        manager = get_keepalive_manager(ctx=None, operation_name="Test")
        
        await manager.start()
        try:
            # Simulate some work
            await asyncio.sleep(0.01)
        finally:
            await manager.stop(send_completion=False)
        
        # Should complete without errors
    
    @pytest.mark.asyncio
    async def test_manager_with_mock_ctx_start_stop(self):
        """Test that manager with ctx starts and stops correctly."""
        mock_ctx = Mock()
        mock_ctx.report_progress = AsyncMock()
        
        manager = get_keepalive_manager(
            ctx=mock_ctx,
            operation_name="Test operation",
            initial_progress=5,
            max_progress=90
        )
        
        await manager.start()
        # Give it a moment to potentially send keep-alives
        await asyncio.sleep(0.01)
        await manager.stop(send_completion=False)
        
        # Should complete without errors


class TestFunctionSignatures:
    """Tests to verify function signatures have optional ctx parameter."""
    
    def test_list_exploits_ctx_is_optional(self):
        """Test that list_exploits has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.list_exploits.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_list_payloads_ctx_is_optional(self):
        """Test that list_payloads has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.list_payloads.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_generate_payload_ctx_is_optional(self):
        """Test that generate_payload has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.generate_payload.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_run_exploit_ctx_is_optional(self):
        """Test that run_exploit has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.run_exploit.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_run_post_module_ctx_is_optional(self):
        """Test that run_post_module has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.run_post_module.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_run_auxiliary_module_ctx_is_optional(self):
        """Test that run_auxiliary_module has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.run_auxiliary_module.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_send_session_command_ctx_is_optional(self):
        """Test that send_session_command has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.send_session_command.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None
    
    def test_start_listener_ctx_is_optional(self):
        """Test that start_listener has ctx as optional parameter."""
        import inspect
        fn = MetasploitMCP.start_listener.fn
        sig = inspect.signature(fn)
        params = sig.parameters
        
        assert 'ctx' in params
        assert params['ctx'].default is None


class TestKeepaliveConfiguration:
    """Tests for keep-alive configuration constants."""
    
    def test_default_keepalive_interval_exists(self):
        """Test that DEFAULT_KEEPALIVE_INTERVAL is defined."""
        assert hasattr(MetasploitMCP, 'DEFAULT_KEEPALIVE_INTERVAL')
        assert MetasploitMCP.DEFAULT_KEEPALIVE_INTERVAL > 0
    
    def test_keepalive_available_flag_exists(self):
        """Test that KEEPALIVE_AVAILABLE flag is defined."""
        assert hasattr(MetasploitMCP, 'KEEPALIVE_AVAILABLE')
        assert isinstance(MetasploitMCP.KEEPALIVE_AVAILABLE, bool)
    
    def test_default_interval_is_reasonable(self):
        """Test that the default interval is reasonable (between 1-60 seconds)."""
        assert 1.0 <= MetasploitMCP.DEFAULT_KEEPALIVE_INTERVAL <= 60.0


class TestFallbackKeepaliveManager:
    """Tests for the fallback KeepAliveProgressManager when exploitmcp is not available."""
    
    def test_fallback_class_exists(self):
        """Test that the fallback KeepAliveProgressManager class exists."""
        assert hasattr(MetasploitMCP, 'KeepAliveProgressManager')
    
    def test_fallback_class_has_required_methods(self):
        """Test that the fallback class has all required async methods."""
        manager_class = MetasploitMCP.KeepAliveProgressManager
        
        # Create an instance with mock ctx
        manager = manager_class(
            ctx=Mock(),
            interval=10.0,
            operation_name="Test",
            initial_progress=5,
            max_progress=90
        )
        
        # Check required attributes
        assert hasattr(manager, 'ctx')
        assert hasattr(manager, 'interval')
        assert hasattr(manager, 'operation_name')
        assert hasattr(manager, 'initial_progress')
        assert hasattr(manager, 'max_progress')
        
        # Check required methods
        assert callable(getattr(manager, 'start', None))
        assert callable(getattr(manager, 'stop', None))
        assert hasattr(manager, '__aenter__')
        assert hasattr(manager, '__aexit__')
    
    @pytest.mark.asyncio
    async def test_fallback_manager_async_context(self):
        """Test that fallback manager works as async context manager."""
        manager_class = MetasploitMCP.KeepAliveProgressManager
        manager = manager_class(
            ctx=Mock(),
            interval=10.0,
            operation_name="Test",
            initial_progress=5,
            max_progress=90
        )
        
        async with manager:
            # Should work without errors
            pass
    
    @pytest.mark.asyncio
    async def test_fallback_manager_start_stop(self):
        """Test that fallback manager start/stop work correctly."""
        manager_class = MetasploitMCP.KeepAliveProgressManager
        manager = manager_class(
            ctx=Mock(),
            interval=10.0,
            operation_name="Test",
            initial_progress=5,
            max_progress=90
        )
        
        await manager.start()
        await manager.stop()
        await manager.stop(send_completion=False)
        # Should complete without errors





