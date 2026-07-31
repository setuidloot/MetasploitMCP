#!/usr/bin/env python3
"""Tests for the console command-injection guard on module options.

Covers CVE-2026-5463 / GHSA-qpc3-8vqg-8g6w: newline characters in module option
values (e.g. RHOSTS) must not be able to terminate the intended `set` command and
inject additional console commands.
"""

import os
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Mock dependencies that aren't available in the unit-test environment.
mock_uvicorn = Mock()
mock_uvicorn.server = Mock()
sys.modules["uvicorn"] = mock_uvicorn
sys.modules["uvicorn.server"] = mock_uvicorn.server
sys.modules["fastapi"] = Mock()
sys.modules["mcp.server.fastmcp"] = Mock()
sys.modules["mcp.server.sse"] = Mock()
sys.modules["pymetasploit3.msfrpc"] = Mock()
sys.modules["starlette.applications"] = Mock()
sys.modules["starlette.routing"] = Mock()
sys.modules["mcp.server.session"] = Mock()
sys.modules["fastmcp"] = Mock()
sys.modules["fastmcp.client"] = Mock()
sys.modules["fastmcp.client.transports"] = Mock()

from metasploit_mcp.server import _execute_module_console, _reject_unsafe_option_chars


@pytest.mark.unit
class TestRejectUnsafeOptionChars:
    def test_clean_options_pass(self):
        # Should not raise.
        _reject_unsafe_option_chars({"RHOSTS": "10.0.0.1", "RPORT": 445, "SSL": True})

    def test_newline_in_value_rejected(self):
        with pytest.raises(ValueError, match="control character"):
            _reject_unsafe_option_chars({"RHOSTS": "10.0.0.1\nsessions -K"})

    def test_carriage_return_in_value_rejected(self):
        with pytest.raises(ValueError, match="control character"):
            _reject_unsafe_option_chars({"RHOSTS": "10.0.0.1\rexit"})

    def test_nul_in_value_rejected(self):
        with pytest.raises(ValueError, match="control character"):
            _reject_unsafe_option_chars({"RHOSTS": "10.0.0.1\x00"})

    def test_newline_in_key_rejected(self):
        with pytest.raises(ValueError, match="control character"):
            _reject_unsafe_option_chars({"RHOSTS\nset LHOST 6.6.6.6": "10.0.0.1"})

    def test_non_string_values_ignored(self):
        # Ints/bools can't carry control chars; must not raise.
        _reject_unsafe_option_chars({"RPORT": 4444, "SSL": False})

    def test_non_dict_is_noop(self):
        _reject_unsafe_option_chars("not-a-dict")  # type: ignore[arg-type]


@pytest.mark.unit
class TestConsoleExecutionGuard:
    async def test_console_rejects_newline_option(self):
        """The console execution path must reject injected options before running
        any console command (no MSF connection required)."""
        with pytest.raises(ValueError, match="control character"):
            await _execute_module_console(
                module_type="exploit",
                module_name="multi/handler",
                module_options={"RHOSTS": "10.0.0.1\nsessions -K"},
                command="exploit",
            )

    async def test_console_rejects_newline_payload_option(self):
        with pytest.raises(ValueError, match="control character"):
            await _execute_module_console(
                module_type="exploit",
                module_name="windows/smb/ms17_010_eternalblue",
                module_options={"RHOSTS": "10.0.0.1"},
                command="exploit",
                payload_spec={
                    "name": "windows/x64/meterpreter/reverse_tcp",
                    "options": {"LHOST": "1.2.3.4\nsessions -K"},
                },
            )
