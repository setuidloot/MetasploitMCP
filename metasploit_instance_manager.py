"""
Metasploit Instance Manager for Per-Agent Isolation.

This module manages on-demand Metasploit RPC daemon instances, spawning a separate
msfrpcd process for each agent that requests Metasploit services. This provides
full isolation between agents at the Metasploit level.
"""

import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Dict, Optional
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcError

logger = logging.getLogger(__name__)


@dataclass
class MetasploitInstance:
    """Represents a running Metasploit RPC daemon instance for an agent."""
    agent_id: str
    port: int
    password: str
    process: subprocess.Popen
    client: Optional[MsfRpcClient] = None
    last_used: float = 0
    startup_time: float = 0
    
    def is_healthy(self) -> bool:
        """Check if the instance process is still running."""
        if not self.process:
            return False
        return self.process.poll() is None
    
    def update_last_used(self):
        """Update the last used timestamp."""
        self.last_used = time.time()


class MetasploitInstanceManager:
    """
    Manages per-agent Metasploit RPC daemon instances.
    
    Features:
    - Lazy initialization: Spawns msfrpcd only when agent requests it
    - Auto-cleanup: Terminates inactive instances after timeout
    - Port allocation: Assigns unique ports per agent
    - Health monitoring: Tracks instance health and restarts if needed
    """
    
    def __init__(
        self, 
        base_port: int = 55553,
        password: str = "msf",
        inactivity_timeout: int = 1800,  # 30 minutes
        startup_timeout: int = 30,  # 30 seconds to start
        msfrpcd_path: str = "msfrpcd"
    ):
        """
        Initialize the Metasploit Instance Manager.
        
        Args:
            base_port: Base port for Metasploit RPC (agents get base_port + offset)
            password: Password for msfrpcd authentication
            inactivity_timeout: Seconds of inactivity before instance shutdown
            startup_timeout: Seconds to wait for msfrpcd to become ready
            msfrpcd_path: Path to msfrpcd executable
        """
        self.base_port = base_port
        self.password = password
        self.inactivity_timeout = inactivity_timeout
        self.startup_timeout = startup_timeout
        self.msfrpcd_path = msfrpcd_path
        
        self.instances: Dict[str, MetasploitInstance] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info(f"MetasploitInstanceManager initialized (base_port={base_port}, "
                   f"inactivity_timeout={inactivity_timeout}s)")
    
    def _calculate_port(self, agent_id: str) -> int:
        """
        Calculate the RPC port for a specific agent.
        
        Uses a deterministic hash to assign ports, supporting up to 100 agents.
        """
        if agent_id == "default-agent":
            return self.base_port
        
        # Create deterministic hash
        import hashlib
        agent_hash = int(hashlib.md5(agent_id.encode()).hexdigest(), 16)
        agent_offset = agent_hash % 100
        port = self.base_port + agent_offset
        
        return port
    
    async def get_or_create_instance(self, agent_id: str) -> MetasploitInstance:
        """
        Get existing Metasploit instance for agent or create a new one.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            MetasploitInstance for this agent
            
        Raises:
            RuntimeError: If instance creation fails
        """
        async with self._lock:
            # Check if instance already exists
            if agent_id in self.instances:
                instance = self.instances[agent_id]
                
                # Verify instance is still healthy
                if instance.is_healthy():
                    instance.update_last_used()
                    logger.debug(f"Returning existing Metasploit instance for agent: {agent_id}")
                    return instance
                else:
                    logger.warning(f"Existing instance for agent {agent_id} is unhealthy, recreating...")
                    await self._terminate_instance(agent_id)
            
            # Create new instance
            logger.info(f"Creating new Metasploit instance for agent: {agent_id}")
            instance = await self._spawn_instance(agent_id)
            self.instances[agent_id] = instance
            
            return instance
    
    async def _spawn_instance(self, agent_id: str) -> MetasploitInstance:
        """
        Spawn a new msfrpcd process for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            MetasploitInstance with running process and connected client
            
        Raises:
            RuntimeError: If spawn or connection fails
        """
        port = self._calculate_port(agent_id)
        
        logger.info(f"Spawning msfrpcd for agent '{agent_id}' on port {port}...")
        
        # Build msfrpcd command
        # -P: password
        # -p: port
        # -a: bind address
        # -n: disable SSL
        # -f: run in foreground (we'll manage the process)
        cmd = [
            self.msfrpcd_path,
            "-P", self.password,
            "-p", str(port),
            "-a", "127.0.0.1",
            "-n",  # No SSL for simplicity
            "-f"   # Foreground
        ]
        
        try:
            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL
            )
            
            logger.info(f"msfrpcd process started (PID: {process.pid}) for agent '{agent_id}'")
            
            # Create instance object
            instance = MetasploitInstance(
                agent_id=agent_id,
                port=port,
                password=self.password,
                process=process,
                startup_time=time.time()
            )
            
            # Wait for msfrpcd to become ready
            client = await self._wait_for_ready(instance)
            instance.client = client
            instance.update_last_used()
            
            logger.info(f"Metasploit instance ready for agent '{agent_id}' on port {port}")
            return instance
            
        except Exception as e:
            logger.error(f"Failed to spawn msfrpcd for agent {agent_id}: {e}", exc_info=True)
            # Clean up process if it was started
            if 'process' in locals() and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            raise RuntimeError(f"Failed to spawn Metasploit instance: {e}") from e
    
    async def _wait_for_ready(self, instance: MetasploitInstance) -> MsfRpcClient:
        """
        Wait for msfrpcd to become ready and create RPC client.
        
        Args:
            instance: MetasploitInstance to connect to
            
        Returns:
            Connected MsfRpcClient
            
        Raises:
            RuntimeError: If connection times out or fails
        """
        start_time = time.time()
        last_error = None
        
        while (time.time() - start_time) < self.startup_timeout:
            # Check if process died
            if not instance.is_healthy():
                raise RuntimeError(f"msfrpcd process died during startup for agent {instance.agent_id}")
            
            try:
                # Attempt to connect
                client = await asyncio.to_thread(
                    lambda: MsfRpcClient(
                        password=instance.password,
                        server="127.0.0.1",
                        port=instance.port,
                        ssl=False
                    )
                )
                
                # Test connection
                await asyncio.to_thread(lambda: client.core.version)
                
                logger.info(f"Successfully connected to msfrpcd for agent '{instance.agent_id}'")
                return client
                
            except Exception as e:
                last_error = e
                # Wait a bit before retrying
                await asyncio.sleep(0.5)
        
        # Timeout reached
        raise RuntimeError(
            f"Timeout waiting for msfrpcd to become ready for agent {instance.agent_id}. "
            f"Last error: {last_error}"
        )
    
    async def _terminate_instance(self, agent_id: str):
        """
        Terminate a Metasploit instance for an agent.
        
        Args:
            agent_id: Agent identifier
        """
        if agent_id not in self.instances:
            logger.debug(f"No instance found for agent {agent_id}, nothing to terminate")
            return
        
        instance = self.instances[agent_id]
        logger.info(f"Terminating Metasploit instance for agent: {agent_id}")
        
        try:
            # Close RPC client connection
            if instance.client:
                try:
                    # Gracefully disconnect (no explicit close method, but this helps GC)
                    instance.client = None
                except Exception as e:
                    logger.warning(f"Error closing RPC client for agent {agent_id}: {e}")
            
            # Terminate process
            if instance.process and instance.is_healthy():
                logger.debug(f"Sending SIGTERM to msfrpcd (PID: {instance.process.pid})")
                instance.process.terminate()
                
                try:
                    # Wait up to 10 seconds for graceful shutdown
                    await asyncio.to_thread(instance.process.wait, timeout=10)
                    logger.info(f"msfrpcd process terminated gracefully for agent {agent_id}")
                except subprocess.TimeoutExpired:
                    logger.warning(f"msfrpcd did not terminate gracefully, killing...")
                    instance.process.kill()
                    await asyncio.to_thread(instance.process.wait, timeout=5)
                    logger.info(f"msfrpcd process killed for agent {agent_id}")
            
        except Exception as e:
            logger.error(f"Error terminating instance for agent {agent_id}: {e}", exc_info=True)
        finally:
            # Remove from registry
            del self.instances[agent_id]
    
    async def get_client(self, agent_id: str) -> MsfRpcClient:
        """
        Get the RPC client for an agent, creating instance if needed.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Connected MsfRpcClient for this agent
        """
        instance = await self.get_or_create_instance(agent_id)
        return instance.client
    
    async def start_cleanup_task(self):
        """Start the background cleanup task for inactive instances."""
        if self._running:
            logger.warning("Cleanup task already running")
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Started Metasploit instance cleanup task")
    
    async def stop_cleanup_task(self):
        """Stop the background cleanup task."""
        if not self._running:
            return
        
        self._running = False
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped Metasploit instance cleanup task")
    
    async def _cleanup_loop(self):
        """Background loop to clean up inactive instances."""
        logger.info("Metasploit instance cleanup loop started")
        
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                current_time = time.time()
                agents_to_terminate = []
                
                async with self._lock:
                    for agent_id, instance in self.instances.items():
                        # Check if instance is inactive
                        if (current_time - instance.last_used) > self.inactivity_timeout:
                            logger.info(f"Instance for agent '{agent_id}' has been inactive for "
                                      f"{current_time - instance.last_used:.0f}s, marking for termination")
                            agents_to_terminate.append(agent_id)
                        
                        # Check if instance is unhealthy
                        elif not instance.is_healthy():
                            logger.warning(f"Instance for agent '{agent_id}' is unhealthy, marking for termination")
                            agents_to_terminate.append(agent_id)
                
                # Terminate inactive instances (outside the lock to avoid deadlock)
                for agent_id in agents_to_terminate:
                    await self._terminate_instance(agent_id)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}", exc_info=True)
        
        logger.info("Metasploit instance cleanup loop stopped")
    
    async def shutdown(self):
        """Shutdown all instances and cleanup."""
        logger.info("Shutting down Metasploit Instance Manager...")
        
        # Stop cleanup task
        await self.stop_cleanup_task()
        
        # Terminate all instances
        agent_ids = list(self.instances.keys())
        for agent_id in agent_ids:
            await self._terminate_instance(agent_id)
        
        logger.info("Metasploit Instance Manager shutdown complete")
    
    def get_instance_info(self, agent_id: str) -> Optional[Dict]:
        """
        Get information about an instance.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Dict with instance info, or None if not found
        """
        if agent_id not in self.instances:
            return None
        
        instance = self.instances[agent_id]
        return {
            "agent_id": instance.agent_id,
            "port": instance.port,
            "pid": instance.process.pid if instance.process else None,
            "is_healthy": instance.is_healthy(),
            "last_used": instance.last_used,
            "uptime": time.time() - instance.startup_time if instance.startup_time else 0,
            "inactive_for": time.time() - instance.last_used if instance.last_used else 0
        }
    
    def list_instances(self) -> Dict[str, Dict]:
        """
        List all running instances.
        
        Returns:
            Dict mapping agent_id to instance info
        """
        return {
            agent_id: self.get_instance_info(agent_id)
            for agent_id in self.instances.keys()
        }

