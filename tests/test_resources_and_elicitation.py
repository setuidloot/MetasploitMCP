#!/usr/bin/env python3
"""Tests for MCP documentation resources and elicitation-based confirmation."""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as server

# --- Elicitation confirmation -------------------------------------------------


class _Accepted:
    """Mimics fastmcp AcceptedElicitation (matched by class name)."""


class _Declined:
    """Mimics fastmcp DeclinedElicitation."""


class AcceptedElicitation(_Accepted):
    pass


class DeclinedElicitation(_Declined):
    pass


class FakeCtx:
    def __init__(self, result):
        self._result = result
        self.elicited = False

    async def elicit(self, message, response_type=None, **kwargs):
        self.elicited = True
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


@server.dangerous_tool
async def _guarded(ctx=None):
    return {"status": "success", "ran": True}


@pytest.mark.unit
class TestElicitationConfirmation:
    async def test_accept_proceeds(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        monkeypatch.setattr(server, "CONFIRM_DANGEROUS", True)
        ctx = FakeCtx(AcceptedElicitation())
        result = await _guarded(ctx=ctx)
        assert ctx.elicited is True
        assert result.get("ran") is True

    async def test_decline_cancels(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        monkeypatch.setattr(server, "CONFIRM_DANGEROUS", True)
        ctx = FakeCtx(DeclinedElicitation())
        result = await _guarded(ctx=ctx)
        assert result["status"] == "cancelled"
        assert result["error"] == "cancelled_by_user"

    async def test_no_elicitation_support_falls_back_to_gate(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        monkeypatch.setattr(server, "CONFIRM_DANGEROUS", True)
        # ctx without an elicit method -> proceed (gate already permitted).
        result = await _guarded(ctx=object())
        assert result.get("ran") is True

    async def test_elicit_error_falls_back(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        monkeypatch.setattr(server, "CONFIRM_DANGEROUS", True)
        ctx = FakeCtx(RuntimeError("client does not support elicitation"))
        result = await _guarded(ctx=ctx)
        assert result.get("ran") is True

    async def test_confirmation_disabled_skips_elicit(self, monkeypatch):
        monkeypatch.setattr(server, "DANGEROUS_ACTIONS_ENABLED", True)
        monkeypatch.setattr(server, "RATE_LIMIT_PER_MIN", 0)
        monkeypatch.setattr(server, "CONFIRM_DANGEROUS", False)
        ctx = FakeCtx(DeclinedElicitation())
        result = await _guarded(ctx=ctx)
        assert ctx.elicited is False
        assert result.get("ran") is True


# --- Resources ----------------------------------------------------------------


@pytest.mark.unit
class TestResources:
    def test_server_info_resource_registered(self):
        uris = {str(r.uri) for r in asyncio.run(server.mcp._list_resources())}
        assert "msf://server/info" in uris

    def test_module_doc_resource_template_registered(self):
        templates = asyncio.run(server.mcp._list_resource_templates())
        uri_templates = {t.uri_template for t in templates}
        assert any("msf://module/" in u for u in uri_templates)

    def test_server_info_resource_read(self):
        result = asyncio.run(server.mcp.read_resource("msf://server/info"))
        # ResourceResult.contents is a list of ResourceContent(content=...).
        text = "".join(str(c.content) for c in result.contents)
        assert "MetasploitMCP" in text
        assert "safety" in text
