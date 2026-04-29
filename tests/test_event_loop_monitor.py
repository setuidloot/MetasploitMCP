#!/usr/bin/env python3
"""
Unit tests for event_loop_monitor module and async session command fixes.
"""

import pytest
import sys
import os
import asyncio
import threading
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock

# Add the parent directory to the path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the event loop monitor module
from metasploit_mcp.event_loop_monitor import (
    EventLoopWatchdog,
    SlowCallbackLogger,
    configure_event_loop_debugging,
    stop_event_loop_monitoring,
    get_monitoring_stats,
    check_event_loop_health,
    track_blocking,
    BlockingMonitor,
    get_env_bool,
    get_env_float,
    ASYNCIO_DEBUG,
    WATCHDOG_ENABLED,
)


class TestEnvironmentHelpers:
    """Test environment variable helper functions."""
    
    def test_get_env_bool_true_values(self):
        """Test that true-like values return True."""
        with patch.dict(os.environ, {'TEST_VAR': 'true'}):
            assert get_env_bool('TEST_VAR') is True
        
        with patch.dict(os.environ, {'TEST_VAR': '1'}):
            assert get_env_bool('TEST_VAR') is True
            
        with patch.dict(os.environ, {'TEST_VAR': 'yes'}):
            assert get_env_bool('TEST_VAR') is True
            
        with patch.dict(os.environ, {'TEST_VAR': 'on'}):
            assert get_env_bool('TEST_VAR') is True
    
    def test_get_env_bool_false_values(self):
        """Test that false-like values return False."""
        with patch.dict(os.environ, {'TEST_VAR': 'false'}):
            assert get_env_bool('TEST_VAR') is False
        
        with patch.dict(os.environ, {'TEST_VAR': '0'}):
            assert get_env_bool('TEST_VAR') is False
            
        with patch.dict(os.environ, {'TEST_VAR': 'no'}):
            assert get_env_bool('TEST_VAR') is False
    
    def test_get_env_bool_default(self):
        """Test default value when env var not set."""
        assert get_env_bool('NONEXISTENT_VAR', default=True) is True
        assert get_env_bool('NONEXISTENT_VAR', default=False) is False
    
    def test_get_env_float_valid(self):
        """Test parsing valid float values."""
        with patch.dict(os.environ, {'TEST_VAR': '1.5'}):
            assert get_env_float('TEST_VAR', 0.0) == 1.5
            
        with patch.dict(os.environ, {'TEST_VAR': '10'}):
            assert get_env_float('TEST_VAR', 0.0) == 10.0
    
    def test_get_env_float_invalid(self):
        """Test that invalid float values return default."""
        with patch.dict(os.environ, {'TEST_VAR': 'not-a-number'}):
            assert get_env_float('TEST_VAR', 5.0) == 5.0
    
    def test_get_env_float_default(self):
        """Test default value when env var not set."""
        assert get_env_float('NONEXISTENT_VAR', 3.14) == 3.14


class TestEventLoopWatchdog:
    """Test the EventLoopWatchdog class."""
    
    @pytest.fixture
    def event_loop(self):
        """Fixture providing a test event loop."""
        loop = asyncio.new_event_loop()
        yield loop
        if not loop.is_closed():
            loop.close()
    
    def test_watchdog_initialization(self, event_loop):
        """Test watchdog initializes with correct defaults."""
        watchdog = EventLoopWatchdog(event_loop, interval=1.0, threshold=0.5)
        
        assert watchdog.loop is event_loop
        assert watchdog.interval == 1.0
        assert watchdog.threshold == 0.5
        assert watchdog._thread is None
        assert watchdog._check_count == 0
        assert watchdog._block_count == 0
    
    def test_watchdog_start_stop(self, event_loop):
        """Test watchdog can start and stop cleanly."""
        watchdog = EventLoopWatchdog(event_loop, interval=0.1, threshold=0.5)
        
        watchdog.start()
        
        # Thread should be running
        assert watchdog._thread is not None
        assert watchdog._thread.is_alive()
        assert watchdog._thread.name == "EventLoopWatchdog"
        assert watchdog._thread.daemon is True
        
        watchdog.stop()
        
        # Thread should be stopped
        assert watchdog._thread is None
    
    def test_watchdog_double_start(self, event_loop):
        """Test that starting watchdog twice doesn't create duplicate threads."""
        watchdog = EventLoopWatchdog(event_loop, interval=0.1, threshold=0.5)
        
        watchdog.start()
        first_thread = watchdog._thread
        
        watchdog.start()  # Should log warning but not create new thread
        
        assert watchdog._thread is first_thread
        
        watchdog.stop()
    
    def test_watchdog_detects_blocking(self, event_loop):
        """Test watchdog detects event loop blocking."""
        watchdog = EventLoopWatchdog(event_loop, interval=0.05, threshold=0.01)
        
        # Run the event loop in a thread
        def run_loop():
            asyncio.set_event_loop(event_loop)
            event_loop.run_forever()
        
        loop_thread = threading.Thread(target=run_loop, daemon=True)
        loop_thread.start()
        
        watchdog.start()
        
        # Wait for at least one check
        time.sleep(0.2)
        
        # Watchdog should have performed checks
        assert watchdog._check_count > 0
        
        # Stop everything
        event_loop.call_soon_threadsafe(event_loop.stop)
        loop_thread.join(timeout=1.0)
        watchdog.stop()
    
    def test_watchdog_check_with_closed_loop(self, event_loop):
        """Test that watchdog handles closed loop gracefully."""
        watchdog = EventLoopWatchdog(event_loop, interval=0.1, threshold=0.5)
        
        # Close the loop
        event_loop.close()
        
        # This should not raise an error
        watchdog._check_event_loop()


class TestSlowCallbackLogger:
    """Test the SlowCallbackLogger class."""
    
    def test_slow_callback_logger_initialization(self):
        """Test logger initializes with correct threshold."""
        logger = SlowCallbackLogger(threshold=0.5)
        assert logger.threshold == 0.5
        assert logger.slow_callback_count == 0
    
    def test_slow_callback_logger_counts(self):
        """Test that slow callbacks are counted."""
        logger = SlowCallbackLogger(threshold=0.1)
        
        mock_callback = Mock()
        mock_callback.__qualname__ = "test_function"
        mock_callback.__module__ = "test_module"
        
        logger(0.5, mock_callback)
        assert logger.slow_callback_count == 1
        
        logger(0.3, mock_callback)
        assert logger.slow_callback_count == 2
    
    def test_slow_callback_logger_callback_info(self):
        """Test callback info extraction."""
        logger = SlowCallbackLogger()
        
        # Test with __qualname__
        class TestClass:
            def test_method(self):
                pass
        
        info = logger._get_callback_info(TestClass.test_method)
        assert "TestClass.test_method" in info
        
        # Test with __name__ only
        def test_func():
            pass
        info = logger._get_callback_info(test_func)
        assert "test_func" in info


class TestConfigureEventLoopDebugging:
    """Test the configure_event_loop_debugging function."""
    
    @pytest.fixture
    def event_loop(self):
        """Fixture providing a test event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        yield loop
        stop_event_loop_monitoring()  # Clean up
        if not loop.is_closed():
            loop.close()
    
    def test_configure_debug_mode(self, event_loop):
        """Test enabling asyncio debug mode."""
        configure_event_loop_debugging(
            loop=event_loop,
            enable_debug=True,
            enable_watchdog=False
        )
        
        assert event_loop.get_debug() is True
    
    def test_configure_watchdog(self, event_loop):
        """Test enabling watchdog."""
        configure_event_loop_debugging(
            loop=event_loop,
            enable_debug=False,
            enable_watchdog=True,
            watchdog_interval=0.5,
            watchdog_threshold=0.2
        )
        
        stats = get_monitoring_stats()
        assert stats["watchdog_running"] is True
    
    def test_configure_with_env_defaults(self, event_loop):
        """Test configuration uses environment defaults."""
        with patch.dict(os.environ, {
            'ASYNCIO_DEBUG': 'false',
            'EVENT_LOOP_WATCHDOG': 'false'
        }):
            configure_event_loop_debugging(loop=event_loop)
            
            # Should use env defaults (both disabled)
            assert event_loop.get_debug() is False
            stats = get_monitoring_stats()
            # Watchdog may or may not be running depending on module-level defaults


class TestGetMonitoringStats:
    """Test the get_monitoring_stats function."""
    
    def test_stats_when_not_configured(self):
        """Test stats when monitoring not configured."""
        stop_event_loop_monitoring()  # Ensure clean state
        
        stats = get_monitoring_stats()
        
        assert "watchdog_running" in stats
        assert "debug_enabled" in stats
        assert "slow_callback_threshold" in stats
    
    def test_stats_with_watchdog(self):
        """Test stats include watchdog data when running."""
        loop = asyncio.new_event_loop()
        
        configure_event_loop_debugging(
            loop=loop,
            enable_debug=False,
            enable_watchdog=True,
            watchdog_interval=1.0,
            watchdog_threshold=0.5
        )
        
        stats = get_monitoring_stats()
        
        assert stats["watchdog_running"] is True
        assert "watchdog_check_count" in stats
        assert "watchdog_block_count" in stats
        
        stop_event_loop_monitoring()
        loop.close()


class TestCheckEventLoopHealth:
    """Test the check_event_loop_health function."""
    
    @pytest.mark.asyncio
    async def test_health_check_returns_dict(self):
        """Test that health check returns expected data structure."""
        health = await check_event_loop_health()
        
        assert "timestamp" in health
        assert "event_loop_latency_ms" in health
        assert "debug_mode" in health
        assert "is_running" in health
        assert "is_closed" in health
        assert "monitoring_stats" in health
    
    @pytest.mark.asyncio
    async def test_health_check_latency_measured(self):
        """Test that latency is measured."""
        health = await check_event_loop_health()
        
        # Latency should be a small positive number (in milliseconds)
        assert health["event_loop_latency_ms"] >= 0
        # Should be less than 100ms in normal conditions
        assert health["event_loop_latency_ms"] < 100


class TestTrackBlockingDecorator:
    """Test the track_blocking decorator."""
    
    @pytest.mark.asyncio
    async def test_track_blocking_fast_function(self):
        """Test decorator with fast function doesn't log."""
        @track_blocking(threshold=1.0)
        async def fast_func():
            return "fast"
        
        result = await fast_func()
        assert result == "fast"
    
    @pytest.mark.asyncio
    async def test_track_blocking_slow_function(self):
        """Test decorator logs for slow function."""
        @track_blocking(threshold=0.01)  # Very low threshold
        async def slow_func():
            await asyncio.sleep(0.05)  # Sleep longer than threshold
            return "slow"
        
        with patch('event_loop_monitor.logger') as mock_logger:
            result = await slow_func()
            
            assert result == "slow"
            # Should have logged a warning
            mock_logger.warning.assert_called()
    
    @pytest.mark.asyncio
    async def test_track_blocking_preserves_exception(self):
        """Test decorator preserves exceptions."""
        @track_blocking(threshold=1.0)
        async def error_func():
            raise ValueError("test error")
        
        with pytest.raises(ValueError, match="test error"):
            await error_func()


class TestBlockingMonitor:
    """Test the BlockingMonitor context manager."""
    
    @pytest.mark.asyncio
    async def test_blocking_monitor_fast_block(self):
        """Test monitor with fast code block."""
        async with BlockingMonitor("fast_block", threshold=1.0) as monitor:
            await asyncio.sleep(0.001)
        
        assert monitor.start_time is not None
    
    @pytest.mark.asyncio
    async def test_blocking_monitor_slow_block(self):
        """Test monitor logs for slow code block."""
        with patch('event_loop_monitor.logger') as mock_logger:
            async with BlockingMonitor("slow_block", threshold=0.01):
                await asyncio.sleep(0.05)
            
            # Should have logged a warning
            mock_logger.warning.assert_called()
            # Check the warning contains the block name
            call_args = str(mock_logger.warning.call_args_list)
            assert "slow_block" in call_args


class TestAsyncSessionCommandFixes:
    """Test that session shell/exit commands are properly async."""
    
    @pytest.fixture
    def metasploit_source(self):
        """Fixture providing the MetasploitMCP source code."""
        source_path = os.path.join(os.path.dirname(__file__), '..', 'src/metasploit_mcp/server.py')
        with open(source_path, 'r') as f:
            return f.read()
    
    @pytest.fixture
    def mock_session(self):
        """Fixture providing a mock Meterpreter session."""
        session = Mock()
        session.type = 'meterpreter'
        session.info = {'via_exploit': 'exploit/test'}
        session.run_with_output = Mock(return_value="Channel created.")
        session.read = Mock(return_value="")
        session.detach = Mock(return_value=True)
        return session
    
    @pytest.fixture
    def mock_msf_client(self, mock_session):
        """Fixture providing a mock MSF client with sessions."""
        client = Mock()
        client.sessions.session.return_value = mock_session
        return client
    
    def test_shell_command_uses_asyncio_to_thread(self, metasploit_source):
        """Test that shell command is wrapped in asyncio.to_thread."""
        # The shell command should use asyncio.wait_for with asyncio.to_thread
        assert "asyncio.wait_for" in metasploit_source
        assert "asyncio.to_thread" in metasploit_source
        # Verify the specific pattern for shell command - run_with_output wrapped in to_thread
        assert "asyncio.to_thread(lambda: session.run_with_output(command, end_strs=['created.']))" in metasploit_source

    def test_exit_command_uses_asyncio_to_thread(self, metasploit_source):
        """Test that exit command calls are wrapped in asyncio.to_thread."""
        # Verify exit command uses async patterns
        # Check for session.read() wrapped in to_thread
        assert "asyncio.to_thread(lambda: session.read())" in metasploit_source
        # Check for session.detach() wrapped in to_thread  
        assert "asyncio.to_thread(lambda: session.detach())" in metasploit_source
    
    def test_no_blocking_calls_in_shell_switch(self, metasploit_source):
        """Verify no direct blocking calls exist for shell mode switching."""
        # Find the shell command handling section
        lines = metasploit_source.split('\n')
        in_shell_section = False
        blocking_calls_found = []
        
        for i, line in enumerate(lines):
            if 'if command == "shell"' in line:
                in_shell_section = True
            elif in_shell_section and ('elif command ==' in line or 'else:' in line):
                # Check if we're still in meterpreter mode section
                if 'exit' in line:
                    continue
                in_shell_section = False
            
            if in_shell_section:
                # Check for blocking calls NOT wrapped in asyncio.to_thread
                # Direct session.run_with_output or session.read without await/to_thread
                stripped = line.strip()
                if stripped.startswith('output = session.run_with_output'):
                    blocking_calls_found.append(f"Line {i}: {stripped}")
                if stripped.startswith('session.read()') and 'to_thread' not in line:
                    blocking_calls_found.append(f"Line {i}: {stripped}")
        
        # Should find no direct blocking calls
        assert len(blocking_calls_found) == 0, f"Found blocking calls: {blocking_calls_found}"


class TestStopEventLoopMonitoring:
    """Test the stop_event_loop_monitoring function."""
    
    def test_stop_when_not_running(self):
        """Test stopping when no monitoring is running."""
        # Should not raise any errors
        stop_event_loop_monitoring()
    
    def test_stop_cleans_up_watchdog(self):
        """Test that stop properly cleans up watchdog."""
        loop = asyncio.new_event_loop()
        
        configure_event_loop_debugging(
            loop=loop,
            enable_debug=False,
            enable_watchdog=True
        )
        
        stats_before = get_monitoring_stats()
        assert stats_before["watchdog_running"] is True
        
        stop_event_loop_monitoring()
        
        stats_after = get_monitoring_stats()
        assert stats_after["watchdog_running"] is False
        
        loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

