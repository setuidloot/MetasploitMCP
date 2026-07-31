#!/usr/bin/env python3
"""Tests for the read-only MSF workspace database (db.*) intelligence tools."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as server
from metasploit_mcp.server import _db_intel, _decode_rpc


def unwrap_tool(tool_obj):
    """Unwrap a FastMCP-decorated tool to its underlying coroutine function."""
    for attr in ("fn", "func", "__wrapped__", "_func"):
        if hasattr(tool_obj, attr):
            return getattr(tool_obj, attr)
    return tool_obj


list_hosts = unwrap_tool(server.list_hosts)
list_services = unwrap_tool(server.list_services)
list_vulnerabilities = unwrap_tool(server.list_vulnerabilities)
list_notes = unwrap_tool(server.list_notes)
list_credentials = unwrap_tool(server.list_credentials)
list_loot = unwrap_tool(server.list_loot)


class FakeClient:
    """Minimal stand-in for MsfRpcClient.call routing by RPC method name."""

    def __init__(self, connected=True, data=None):
        self.connected = connected
        self.data = data or {}
        self.calls = []

    def call(self, method, args=None):
        self.calls.append((method, args))
        if method == "db.status":
            return (
                {"driver": "postgresql", "db": "msf"}
                if self.connected
                else {"driver": "postgresql"}
            )
        return self.data.get(method, {})


def _install_client(monkeypatch, client):
    monkeypatch.setattr(server, "get_msf_client", lambda: client)


@pytest.mark.unit
class TestDecodeRpc:
    def test_bytes_keys_and_values_decoded(self):
        raw = {b"hosts": [{b"address": b"10.0.0.1", b"port": 445}]}
        assert _decode_rpc(raw) == {"hosts": [{"address": "10.0.0.1", "port": 445}]}

    def test_passthrough_non_bytes(self):
        assert _decode_rpc({"a": [1, "x", True]}) == {"a": [1, "x", True]}


@pytest.mark.unit
class TestDbIntel:
    async def test_not_initialized_returns_structured_error(self, monkeypatch):
        def _raise():
            raise ConnectionError("client not initialized")

        monkeypatch.setattr(server, "get_msf_client", _raise)
        result = await _db_intel("db.hosts", "hosts")
        assert result["status"] == "error"
        assert result["error"] == "not_initialized"

    async def test_database_unavailable(self, monkeypatch):
        _install_client(monkeypatch, FakeClient(connected=False))
        result = await _db_intel("db.hosts", "hosts")
        assert result["status"] == "error"
        assert result["error"] == "database_unavailable"

    async def test_success_counts_items(self, monkeypatch):
        client = FakeClient(
            data={"db.hosts": {"hosts": [{"address": "10.0.0.1"}, {"address": "10.0.0.2"}]}}
        )
        _install_client(monkeypatch, client)
        result = await _db_intel("db.hosts", "hosts")
        assert result["status"] == "success"
        assert result["count"] == 2
        assert result["workspace"] == "default"
        assert len(result["hosts"]) == 2

    async def test_bytes_response_normalized(self, monkeypatch):
        client = FakeClient(data={"db.hosts": {b"hosts": [{b"address": b"10.0.0.1"}]}})
        _install_client(monkeypatch, client)
        result = await _db_intel("db.hosts", "hosts")
        assert result["count"] == 1
        assert result["hosts"][0]["address"] == "10.0.0.1"

    async def test_workspace_passed_in_opts(self, monkeypatch):
        client = FakeClient(data={"db.hosts": {"hosts": []}})
        _install_client(monkeypatch, client)
        await _db_intel("db.hosts", "hosts", workspace="engagement-1")
        db_calls = [c for c in client.calls if c[0] == "db.hosts"]
        assert db_calls == [("db.hosts", [{"workspace": "engagement-1"}])]

    async def test_none_filters_omitted(self, monkeypatch):
        client = FakeClient(data={"db.services": {"services": []}})
        _install_client(monkeypatch, client)
        await _db_intel("db.services", "services", None, addresses=None, ports=None)
        db_calls = [c for c in client.calls if c[0] == "db.services"]
        assert db_calls == [("db.services", [{}])]


@pytest.mark.unit
class TestTools:
    async def test_list_hosts(self, monkeypatch):
        client = FakeClient(data={"db.hosts": {"hosts": [{"address": "1.2.3.4"}]}})
        _install_client(monkeypatch, client)
        result = await list_hosts()
        assert result["status"] == "success" and result["count"] == 1

    async def test_list_services_host_filter(self, monkeypatch):
        client = FakeClient(data={"db.services": {"services": []}})
        _install_client(monkeypatch, client)
        await list_services(host="10.0.0.5", ports="445", proto="tcp")
        _, args = [c for c in client.calls if c[0] == "db.services"][0]
        assert args[0]["addresses"] == ["10.0.0.5"]
        assert args[0]["ports"] == "445"
        assert args[0]["proto"] == "tcp"

    async def test_read_only_tools_route_to_correct_method(self, monkeypatch):
        client = FakeClient(
            data={
                "db.vulns": {"vulns": [{"name": "CVE-x"}]},
                "db.notes": {"notes": []},
                "db.creds": {"creds": [{"public": "root"}]},
                "db.loots": {"loots": []},
            }
        )
        _install_client(monkeypatch, client)
        assert (await list_vulnerabilities())["count"] == 1
        assert (await list_notes())["status"] == "success"
        assert (await list_credentials())["count"] == 1
        assert (await list_loot())["status"] == "success"
        methods = {c[0] for c in client.calls}
        assert {"db.vulns", "db.notes", "db.creds", "db.loots"}.issubset(methods)
