#!/usr/bin/env python3
"""Tests that every MCP tool advertises the expected behavior annotations."""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as server

# Tools expected to be gated by the dangerous-actions safety gate.
DESTRUCTIVE_TOOLS = {
    "run_exploit",
    "run_auxiliary_module",
    "run_post_module",
    "generate_payload",
    "send_session_command",
    "start_listener",
    "terminate_session",
    "stop_job",
    "kill_all_handler_jobs",
}


def _registered_tools():
    tools = asyncio.run(server.mcp._list_tools())
    return {t.name: t for t in tools}


@pytest.mark.unit
def test_every_tool_has_annotations():
    tools = _registered_tools()
    for name, tool in tools.items():
        assert tool.annotations is not None, f"{name} is missing annotations"


@pytest.mark.unit
def test_destructive_tools_flagged():
    tools = _registered_tools()
    for name in DESTRUCTIVE_TOOLS:
        assert name in tools, f"expected tool {name} not registered"
        assert tools[name].annotations.destructiveHint is True, name
        assert tools[name].annotations.readOnlyHint is False, name


@pytest.mark.unit
def test_read_only_tools_flagged():
    tools = _registered_tools()
    read_only = [n for n, a in server.TOOL_ANNOTATIONS.items() if a["readOnlyHint"]]
    assert read_only, "expected some read-only tools in the taxonomy"
    for name in read_only:
        assert tools[name].annotations.readOnlyHint is True, name
        assert tools[name].annotations.destructiveHint is False, name


@pytest.mark.unit
def test_annotations_match_taxonomy():
    tools = _registered_tools()
    for name, expected in server.TOOL_ANNOTATIONS.items():
        ann = tools[name].annotations
        assert ann.readOnlyHint == expected["readOnlyHint"], name
        assert ann.destructiveHint == expected["destructiveHint"], name
        assert ann.idempotentHint == expected["idempotentHint"], name
        assert ann.openWorldHint == expected["openWorldHint"], name


@pytest.mark.unit
def test_taxonomy_destructive_set_matches_gate():
    """The destructive taxonomy entries must be exactly the gated tools."""
    taxonomy_destructive = {n for n, a in server.TOOL_ANNOTATIONS.items() if a["destructiveHint"]}
    assert taxonomy_destructive == DESTRUCTIVE_TOOLS
