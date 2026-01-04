"""
Unit tests for MSF RPC client cleanup and connection management.

These tests verify the proper cleanup of Metasploit RPC connections,
including:
- Global client cleanup with auth.logout
- Instance manager cleanup
- Connection lifecycle management
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock


class TestMsfClientCleanup:
    """Tests for cleanup_msf_client() function"""
    
    def test_cleanup_msf_client_no_client(self):
        """Test cleanup handles None client gracefully"""
        import MetasploitMCP
        
        # Ensure no client is set
        MetasploitMCP._msf_client_instance = None
        
        # This should complete without error
        MetasploitMCP.cleanup_msf_client()
    
    def test_cleanup_msf_client_calls_logout(self):
        """Test cleanup calls auth.logout with token"""
        import MetasploitMCP
        
        # Create mock client
        mock_client = Mock()
        mock_client.token = "test-token-456"
        mock_client.call = Mock(return_value={"result": "success"})
        
        MetasploitMCP._msf_client_instance = mock_client
        
        try:
            # Perform cleanup
            MetasploitMCP.cleanup_msf_client()
            
            # Verify auth.logout was called with token
            mock_client.call.assert_called_once_with('auth.logout', ['test-token-456'])
            
            # Verify client reference was cleared
            assert MetasploitMCP._msf_client_instance is None
        finally:
            # Ensure cleanup for subsequent tests
            MetasploitMCP._msf_client_instance = None
    
    def test_cleanup_msf_client_handles_logout_error(self):
        """Test cleanup handles auth.logout error gracefully"""
        import MetasploitMCP
        
        # Create mock client that raises error on logout
        mock_client = Mock()
        mock_client.token = "test-token-789"
        mock_client.call = Mock(side_effect=Exception("Connection lost"))
        
        MetasploitMCP._msf_client_instance = mock_client
        
        try:
            # This should complete without raising exception
            MetasploitMCP.cleanup_msf_client()
            
            # Client reference should still be cleared
            assert MetasploitMCP._msf_client_instance is None
        finally:
            # Ensure cleanup for subsequent tests
            MetasploitMCP._msf_client_instance = None
    
    def test_cleanup_msf_client_no_token(self):
        """Test cleanup handles client without token"""
        import MetasploitMCP
        
        # Create mock client without token
        mock_client = Mock(spec=[])  # No attributes
        
        MetasploitMCP._msf_client_instance = mock_client
        
        try:
            # This should complete without error
            MetasploitMCP.cleanup_msf_client()
            
            # Client reference should be cleared
            assert MetasploitMCP._msf_client_instance is None
        finally:
            # Ensure cleanup for subsequent tests
            MetasploitMCP._msf_client_instance = None


class TestMsfClientCleanupAsync:
    """Tests for cleanup_msf_client_async() function"""
    
    @pytest.mark.asyncio
    async def test_cleanup_msf_client_async_no_client(self):
        """Test async cleanup handles None client gracefully"""
        import MetasploitMCP
        
        # Ensure no client is set
        MetasploitMCP._msf_client_instance = None
        
        # This should complete without error
        await MetasploitMCP.cleanup_msf_client_async()
    
    @pytest.mark.asyncio
    async def test_cleanup_msf_client_async_calls_logout(self):
        """Test async cleanup calls auth.logout with token"""
        import MetasploitMCP
        
        # Create mock client
        mock_client = Mock()
        mock_client.token = "async-test-token"
        mock_client.call = Mock(return_value={"result": "success"})
        
        MetasploitMCP._msf_client_instance = mock_client
        
        try:
            # Perform cleanup
            await MetasploitMCP.cleanup_msf_client_async()
            
            # Verify auth.logout was called (via asyncio.to_thread)
            # The actual call is wrapped, so we check that call was invoked
            assert mock_client.call.called
            
            # Verify client reference was cleared
            assert MetasploitMCP._msf_client_instance is None
        finally:
            # Ensure cleanup for subsequent tests
            MetasploitMCP._msf_client_instance = None


class TestCleanupAllMsfResources:
    """Tests for cleanup_all_msf_resources() function"""
    
    @pytest.mark.asyncio
    async def test_cleanup_all_resources_calls_both(self):
        """Test cleanup_all_msf_resources calls both instance manager and client cleanup"""
        import MetasploitMCP
        
        # Mock instance manager
        mock_instance_manager = Mock()
        mock_instance_manager.shutdown = AsyncMock()
        
        # Mock global client
        mock_client = Mock()
        mock_client.token = "all-resources-token"
        mock_client.call = Mock(return_value={"result": "success"})
        
        # Set up mocks
        original_instance_manager = MetasploitMCP._instance_manager
        MetasploitMCP._instance_manager = mock_instance_manager
        MetasploitMCP._msf_client_instance = mock_client
        
        try:
            # Perform cleanup
            await MetasploitMCP.cleanup_all_msf_resources()
            
            # Verify instance manager shutdown was called
            mock_instance_manager.shutdown.assert_called_once()
            
            # Verify client was cleaned up
            assert MetasploitMCP._msf_client_instance is None
        finally:
            # Restore original state
            MetasploitMCP._instance_manager = original_instance_manager
            MetasploitMCP._msf_client_instance = None


class TestInstanceManagerTerminateInstance:
    """Tests for MetasploitInstanceManager._terminate_instance()"""
    
    @pytest.mark.asyncio
    async def test_terminate_instance_calls_logout(self):
        """Test that _terminate_instance calls auth.logout before terminating"""
        from metasploit_instance_manager import MetasploitInstanceManager, MetasploitInstance
        
        # Create manager
        manager = MetasploitInstanceManager(base_port=55553, password="test")
        
        # Create mock instance
        mock_client = Mock()
        mock_client.token = "instance-token"
        mock_client.call = Mock(return_value={"result": "success"})
        
        mock_process = Mock()
        mock_process.poll = Mock(return_value=None)  # Process is running
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_process.pid = 12345
        
        test_instance = MetasploitInstance(
            agent_id="test-agent",
            port=55554,
            password="test",
            process=mock_process,
            client=mock_client
        )
        
        manager.instances["test-agent"] = test_instance
        
        # Terminate the instance
        await manager._terminate_instance("test-agent")
        
        # Verify auth.logout was called
        mock_client.call.assert_called_once_with('auth.logout', ['instance-token'])
        
        # Verify process was terminated
        mock_process.terminate.assert_called_once()
        
        # Verify instance was removed
        assert "test-agent" not in manager.instances
    
    @pytest.mark.asyncio
    async def test_terminate_instance_handles_logout_error(self):
        """Test that _terminate_instance handles auth.logout error gracefully"""
        from metasploit_instance_manager import MetasploitInstanceManager, MetasploitInstance
        
        # Create manager
        manager = MetasploitInstanceManager(base_port=55553, password="test")
        
        # Create mock instance with failing logout
        mock_client = Mock()
        mock_client.token = "error-token"
        mock_client.call = Mock(side_effect=Exception("Connection refused"))
        
        mock_process = Mock()
        mock_process.poll = Mock(return_value=None)
        mock_process.terminate = Mock()
        mock_process.wait = Mock()
        mock_process.pid = 12346
        
        test_instance = MetasploitInstance(
            agent_id="error-agent",
            port=55555,
            password="test",
            process=mock_process,
            client=mock_client
        )
        
        manager.instances["error-agent"] = test_instance
        
        # This should complete without raising exception
        await manager._terminate_instance("error-agent")
        
        # Process should still be terminated despite logout error
        mock_process.terminate.assert_called_once()
        
        # Instance should be removed
        assert "error-agent" not in manager.instances
    
    @pytest.mark.asyncio
    async def test_terminate_instance_not_found(self):
        """Test that _terminate_instance handles non-existent agent gracefully"""
        from metasploit_instance_manager import MetasploitInstanceManager
        
        # Create manager
        manager = MetasploitInstanceManager(base_port=55553, password="test")
        
        # This should complete without error
        await manager._terminate_instance("nonexistent-agent")


class TestInstanceManagerShutdown:
    """Tests for MetasploitInstanceManager.shutdown()"""
    
    @pytest.mark.asyncio
    async def test_shutdown_terminates_all_instances(self):
        """Test that shutdown terminates all instances"""
        from metasploit_instance_manager import MetasploitInstanceManager, MetasploitInstance
        
        # Create manager
        manager = MetasploitInstanceManager(base_port=55553, password="test")
        
        # Create mock instances
        for i in range(3):
            mock_client = Mock()
            mock_client.token = f"shutdown-token-{i}"
            mock_client.call = Mock(return_value={"result": "success"})
            
            mock_process = Mock()
            mock_process.poll = Mock(return_value=None)
            mock_process.terminate = Mock()
            mock_process.wait = Mock()
            mock_process.pid = 12350 + i
            
            test_instance = MetasploitInstance(
                agent_id=f"shutdown-agent-{i}",
                port=55560 + i,
                password="test",
                process=mock_process,
                client=mock_client
            )
            
            manager.instances[f"shutdown-agent-{i}"] = test_instance
        
        # Verify we have 3 instances
        assert len(manager.instances) == 3
        
        # Shutdown
        await manager.shutdown()
        
        # Verify all instances were removed
        assert len(manager.instances) == 0

