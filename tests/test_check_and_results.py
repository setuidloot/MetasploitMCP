#!/usr/bin/env python3
"""Tests for check_vulnerability (non-destructive) and get_module_results."""

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


check_vulnerability = unwrap_tool(server.check_vulnerability)
get_module_results = unwrap_tool(server.get_module_results)


class FakeModule:
    fullname = "exploit/windows/smb/ms17_010_eternalblue"

    def __init__(self, check_return=None):
        self._check_return = (
            check_return if check_return is not None else {"uuid": "u1", "job_id": 1}
        )
        self.executed = False

    def check(self):
        return self._check_return

    def execute(self, **kwargs):  # must never be called by check_vulnerability
        self.executed = True
        return {"uuid": "should-not-happen"}


class FakeClient:
    def __init__(self, results_by_uuid=None):
        self.results_by_uuid = results_by_uuid or {}
        self.calls = []

    def call(self, method, args=None):
        self.calls.append((method, args))
        if method == "module.results":
            uuid = args[0]
            return self.results_by_uuid.get(uuid, {})
        return {}


def _wire(monkeypatch, module, client, set_options_raises=None):
    monkeypatch.setattr(server, "get_msf_client", lambda: client)

    async def _get_module_object(mtype, mname):
        return module

    async def _set_module_options(*a, **k):
        if set_options_raises:
            raise set_options_raises
        return None

    monkeypatch.setattr(server, "_get_module_object", _get_module_object)
    monkeypatch.setattr(server, "_set_module_options", _set_module_options)


@pytest.mark.unit
class TestCheckVulnerability:
    async def test_vulnerable(self, monkeypatch):
        module = FakeModule()
        client = FakeClient(
            {"u1": {"status": "completed", "result": {"code": "vulnerable", "message": "MS17-010"}}}
        )
        _wire(monkeypatch, module, client)
        result = await check_vulnerability(
            "windows/smb/ms17_010_eternalblue", {"RHOSTS": "10.0.0.1"}
        )
        assert result["status"] == "success"
        assert result["check_state"] == "vulnerable"
        assert result["session_created"] is False
        assert module.executed is False  # never fired the exploit

    async def test_safe(self, monkeypatch):
        module = FakeModule()
        client = FakeClient({"u1": {"status": "completed", "result": {"code": "safe"}}})
        _wire(monkeypatch, module, client)
        result = await check_vulnerability("exploit/x", {"RHOSTS": "10.0.0.1"})
        assert result["check_state"] == "safe"

    async def test_unsupported_when_no_uuid(self, monkeypatch):
        module = FakeModule(check_return={"job_id": 1})  # no uuid -> check unsupported
        client = FakeClient()
        _wire(monkeypatch, module, client)
        result = await check_vulnerability("exploit/x", {"RHOSTS": "10.0.0.1"})
        assert result["status"] == "error"
        assert result["error"] == "unsupported"

    async def test_missing_required_option(self, monkeypatch):
        module = FakeModule()
        client = FakeClient()
        _wire(
            monkeypatch,
            module,
            client,
            set_options_raises=ValueError("Missing required option: RHOSTS"),
        )
        result = await check_vulnerability("exploit/x", {})
        assert result["status"] == "error"
        assert result["error"] == "invalid_options"

    async def test_check_never_executes_exploit(self, monkeypatch):
        module = FakeModule()
        client = FakeClient({"u1": {"status": "completed", "result": {"code": "appears"}}})
        _wire(monkeypatch, module, client)
        await check_vulnerability("exploit/x", {"RHOSTS": "10.0.0.1"})
        # No module.execute call, and no exploit execution occurred.
        assert module.executed is False
        assert all(m != "module.execute" for m, _ in client.calls)


@pytest.mark.unit
class TestGetModuleResults:
    async def test_completed(self, monkeypatch):
        client = FakeClient({"abc": {"status": "completed", "result": {"output": "done"}}})
        monkeypatch.setattr(server, "get_msf_client", lambda: client)
        result = await get_module_results("abc")
        assert result["status"] == "success"
        assert result["execution_status"] == "completed"
        assert result["result"] == {"output": "done"}

    async def test_running(self, monkeypatch):
        client = FakeClient({"abc": {"status": "running"}})
        monkeypatch.setattr(server, "get_msf_client", lambda: client)
        result = await get_module_results("abc")
        assert result["execution_status"] == "running"

    async def test_unknown_id_not_found(self, monkeypatch):
        client = FakeClient({})  # returns {} for unknown uuid
        monkeypatch.setattr(server, "get_msf_client", lambda: client)
        result = await get_module_results("does-not-exist")
        assert result["status"] == "error"
        assert result["error"] == "not_found"

    async def test_empty_id(self, monkeypatch):
        result = await get_module_results("")
        assert result["status"] == "error"
        assert result["error"] == "not_found"
