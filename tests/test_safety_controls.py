#!/usr/bin/env python3
"""Tests for the default-off dangerous-actions gate and rate limiting."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as server


def unwrap_tool(tool_obj):
    for attr in ("fn", "func", "__wrapped__", "_func"):
        if hasattr(tool_obj, attr):
            return getattr(tool_obj, attr)
    return tool_obj


@server.dangerous_tool
async def _dummy_dangerous():
    return {"status": "success", "ran": True}


@pytest.mark.unit
class TestDangerousGate:
    async def test_blocks_when_disabled(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", False)
        result = await _dummy_dangerous()
        assert result["status"] == "error"
        assert result["error"] == "dangerous_actions_disabled"

    async def test_allows_when_enabled(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        result = await _dummy_dangerous()
        assert result.get("ran") is True

    async def test_real_tool_gated_when_disabled(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", False)
        # Call the registered tool directly (the @dangerous_tool wrapper); do NOT
        # unwrap, or we'd bypass the gate via functools.wraps' __wrapped__.
        result = await server.stop_job(1)
        assert result["error"] == "dangerous_actions_disabled"


@pytest.mark.unit
class TestReadOnlyNotGated:
    async def test_read_only_tool_not_blocked_by_gate(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", False)

        def _raise():
            raise ConnectionError("not initialized")

        monkeypatch.setattr(server, "get_msf_client", _raise)
        list_hosts = unwrap_tool(server.list_hosts)
        result = await list_hosts()
        # Read-only tools must run regardless of the dangerous-actions gate.
        assert result.get("error") != "dangerous_actions_disabled"


@pytest.mark.unit
class TestRateLimit:
    def test_within_limit_allowed(self, monkeypatch):
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 5)
        server._rate_events.clear()
        assert all(server._rate_limit_retry_after() is None for _ in range(5))

    def test_over_limit_throttled(self, monkeypatch):
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 3)
        server._rate_events.clear()
        for _ in range(3):
            assert server._rate_limit_retry_after() is None
        retry = server._rate_limit_retry_after()
        assert retry is not None and retry > 0

    def test_zero_disables_limit(self, monkeypatch):
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        server._rate_events.clear()
        assert all(server._rate_limit_retry_after() is None for _ in range(200))

    async def test_gate_returns_rate_limited(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 1)
        server._rate_events.clear()
        first = await _dummy_dangerous()
        assert first.get("ran") is True
        second = await _dummy_dangerous()
        assert second["error"] == "rate_limited"
        assert "retry_after_seconds" in second


@pytest.mark.unit
class TestDefaults:
    def test_dangerous_enabled_by_default(self):
        # Offensive tool: dangerous actions default ON (env unset -> True).
        assert server._env_flag("MSF_MCP_SOME_UNSET_VAR", True) is True

    def test_safe_mode_env_disables(self):
        assert server._env_flag("MSF_MCP_SOME_UNSET_VAR", False) is False

    def test_rate_limit_off_by_default(self, monkeypatch):
        # No limit configured -> never throttles.
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        server._rate_events.clear()
        assert all(server._rate_limit_retry_after() is None for _ in range(100))


@pytest.mark.unit
class TestConfigureSafety:
    def test_configure_safety_sets_globals(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", False)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 60)
        server.configure_safety(allow_dangerous=True, rate_limit_per_min=10)
        assert server.DANGEROUS_ACTIONS_ENABLED is True
        assert server.RATE_LIMIT_PER_MIN == 10

    def test_configure_safety_none_is_noop(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 42)
        server.configure_safety()  # no args -> no change
        assert server.DANGEROUS_ACTIONS_ENABLED is True
        assert server.RATE_LIMIT_PER_MIN == 42
