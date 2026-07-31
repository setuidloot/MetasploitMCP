#!/usr/bin/env python3
"""Tests that tools emit MCP structured output with a text fallback."""

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as server


def _registered_tools():
    tools = asyncio.run(server.mcp._list_tools())
    return {t.name: t for t in tools}


@pytest.mark.unit
def test_tools_expose_output_schema():
    tools = _registered_tools()
    for name in ["list_hosts", "check_vulnerability", "get_module_results", "health_check"]:
        assert tools[name].output_schema is not None, f"{name} has no output schema"


@pytest.mark.unit
def test_call_returns_structured_and_text(monkeypatch):
    def _raise():
        raise ConnectionError("no client")

    monkeypatch.setattr(server, "get_msf_client", _raise)

    content, structured = asyncio.run(server.mcp._call_tool_mcp("list_hosts", {}))

    # Structured content is a real dict clients can consume directly.
    assert isinstance(structured, dict)
    assert structured["status"] == "error"
    assert structured["error"] == "not_initialized"

    # Text representation remains for clients that don't support structured output.
    assert content and getattr(content[0], "text", None)
    assert json.loads(content[0].text)["error"] == "not_initialized"
