#!/usr/bin/env python3
"""Live probe for session channel read strategies.

Opt-in helper for debugging real Metasploit RPC session behavior. This script is
never used by CI and exits immediately when CI is detected.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import metasploit_mcp.server as mcp_module


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Probe Metasploit session command read strategies")
    parser.add_argument("--session-id", type=int, required=True, help="Metasploit session ID")
    parser.add_argument("--command", required=True, help="Command to run")
    parser.add_argument("--timeout", type=int, default=30, help="Hard timeout seconds")
    parser.add_argument(
        "--inactivity-timeout", type=int, default=10, help="Inactivity timeout seconds"
    )
    parser.add_argument(
        "--output-jsonl",
        default="probe-session-channel.jsonl",
        help="JSONL output path (relative or absolute)",
    )
    return parser.parse_args()


async def _get_session_object(session_id: int) -> Any:
    client = mcp_module.get_msf_client()
    sessions = await mcp_module._list_sessions_str_keys(client)
    session_id_str = str(session_id)
    if session_id_str not in sessions:
        raise RuntimeError(f"Session {session_id} was not found in client.sessions.list")
    return await mcp_module._get_session_object_from_map(
        client=client,
        sessions_by_str_id=sessions,
        session_id_str=session_id_str,
    )


async def _strategy_drive_shell(
    session: Any, session_id: int, command: str, timeout: int, inactivity: int
) -> Dict[str, Any]:
    return await mcp_module._drive_shell_command(
        session=session,
        command=command,
        timeout_seconds=timeout,
        inactivity_timeout_seconds=inactivity,
        session_id=session_id,
    )


async def _strategy_run_with_output(session: Any, command: str, timeout: int) -> Dict[str, Any]:
    if not hasattr(session, "run_with_output"):
        return {"status": "unsupported", "reason": "missing_run_with_output", "output": ""}
    output = await asyncio.wait_for(
        asyncio.to_thread(lambda: session.run_with_output(command, end_strs=["$ ", "# ", "> "])),
        timeout=timeout,
    )
    return {"status": "success", "reason": "run_with_output", "output": output}


async def _strategy_meterpreter_shell_helper(
    session: Any, command: str, timeout: int
) -> Dict[str, Any]:
    if not hasattr(session, "run_shell_cmd_with_output"):
        return {
            "status": "unsupported",
            "reason": "missing_run_shell_cmd_with_output",
            "output": "",
        }
    output = await asyncio.wait_for(
        asyncio.to_thread(lambda: session.run_shell_cmd_with_output(command, timeout=timeout)),
        timeout=timeout,
    )
    return {"status": "success", "reason": "run_shell_cmd_with_output", "output": output}


async def _run_probe(args: argparse.Namespace) -> List[Dict[str, Any]]:
    session = await _get_session_object(args.session_id)
    strategies = [
        (
            "drive_shell_loop",
            _strategy_drive_shell(
                session, args.session_id, args.command, args.timeout, args.inactivity_timeout
            ),
        ),
        ("run_with_output", _strategy_run_with_output(session, args.command, args.timeout)),
        (
            "run_shell_cmd_with_output",
            _strategy_meterpreter_shell_helper(session, args.command, args.timeout),
        ),
    ]
    rows: List[Dict[str, Any]] = []
    for strategy_name, coro in strategies:
        started = datetime.now(timezone.utc).isoformat()
        try:
            result = await coro
            row = {
                "timestamp": started,
                "strategy": strategy_name,
                "status": result.get("status", "unknown"),
                "reason": result.get("reason", ""),
                "output": result.get("output", ""),
                "output_len": len(result.get("output", "")),
                "meterpreter_errors": result.get("meterpreter_errors", []),
                "chunks_read": result.get("chunks_read"),
                "bytes_read": result.get("bytes_read"),
            }
        except Exception as exc:  # pragma: no cover - this is a live probe utility
            row = {
                "timestamp": started,
                "strategy": strategy_name,
                "status": "error",
                "reason": "exception",
                "error": repr(exc),
                "output": "",
                "output_len": 0,
            }
        rows.append(row)
    return rows


def _write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True) + "\n")


def main() -> int:
    if os.environ.get("CI", "").lower() in {"1", "true", "yes"}:
        print("Refusing to run probe_session_channel.py in CI.")
        return 0

    args = _parse_args()
    output_path = Path(args.output_jsonl).expanduser().resolve()
    rows = asyncio.run(_run_probe(args))
    _write_jsonl(output_path, rows)
    print(f"Wrote {len(rows)} probe rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
