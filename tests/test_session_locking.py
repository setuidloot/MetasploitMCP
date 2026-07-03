#!/usr/bin/env python3
"""
Tests for per-session locking in MetasploitMCP.

Verifies that concurrent send_session_command / terminate_session calls on the
same session are serialized, that a busy session returns status="busy" after
the wait timeout, that different sessions are independent, and that stale locks
are cleaned up when sessions disappear.
"""

import asyncio
import sys
import os
import pytest
from unittest.mock import Mock, patch, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import metasploit_mcp.server as MetasploitMCP
from metasploit_mcp.server import (
    _session_locks,
    _session_locks_guard,
    _get_session_lock,
    _cleanup_session_lock,
    _list_sessions_str_keys,
    _get_session_object_from_map,
    session_shell_type,
    SESSION_LOCK_WAIT_TIMEOUT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unwrap(tool_obj):
    for attr in ("func", "__wrapped__", "_func", "fn"):
        if hasattr(tool_obj, attr):
            return getattr(tool_obj, attr)
    return tool_obj


send_session_command = _unwrap(MetasploitMCP.send_session_command)
terminate_session = _unwrap(MetasploitMCP.terminate_session)


def _make_mock_client(sessions_dict=None):
    """Build a MockMsfRpcClient with the given sessions."""
    client = Mock()
    client.core = Mock()
    client.core.version = {"version": "6.3.0"}
    client.modules = Mock()
    client.sessions = Mock()
    client.jobs = Mock()
    client.consoles = Mock()

    if sessions_dict is None:
        sessions_dict = {}
    client.sessions.list = sessions_dict
    client.jobs.list = {}

    session_obj = Mock()
    session_obj.run_with_output = Mock(return_value="mock output")
    session_obj.read = Mock(return_value="mock output\nmeterpreter > ")
    session_obj.write = Mock()
    session_obj.stop = Mock()
    client.sessions.session = Mock(return_value=session_obj)

    return client, session_obj


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_session_lock_state():
    """Clear all session locks and mode tracking between tests."""
    _session_locks.clear()
    session_shell_type.clear()
    yield
    _session_locks.clear()
    session_shell_type.clear()


@pytest.fixture
def mock_asyncio_to_thread():
    async def _mock(func, *args, **kwargs):
        return func(*args, **kwargs)

    with patch("asyncio.to_thread", side_effect=_mock):
        yield


# ---------------------------------------------------------------------------
# Unit tests for lock helpers
# ---------------------------------------------------------------------------


class TestGetSessionLock:
    @pytest.mark.asyncio
    async def test_creates_lock_on_first_call(self):
        lock = await _get_session_lock("42")
        assert isinstance(lock, asyncio.Lock)
        assert "42" in _session_locks

    @pytest.mark.asyncio
    async def test_returns_same_lock_on_second_call(self):
        lock1 = await _get_session_lock("7")
        lock2 = await _get_session_lock("7")
        assert lock1 is lock2

    @pytest.mark.asyncio
    async def test_different_sessions_get_different_locks(self):
        lock_a = await _get_session_lock("1")
        lock_b = await _get_session_lock("2")
        assert lock_a is not lock_b


class TestCleanupSessionLock:
    @pytest.mark.asyncio
    async def test_removes_lock_and_mode(self):
        _session_locks["5"] = asyncio.Lock()
        session_shell_type["5"] = "meterpreter"

        await _cleanup_session_lock("5")

        assert "5" not in _session_locks
        assert "5" not in session_shell_type

    @pytest.mark.asyncio
    async def test_noop_for_unknown_session(self):
        await _cleanup_session_lock("999")
        assert "999" not in _session_locks


class TestSessionListNormalization:
    @pytest.mark.asyncio
    async def test_list_sessions_normalizes_int_keys(self, mock_asyncio_to_thread):
        client, _ = _make_mock_client({1: {"type": "meterpreter"}})
        normalized = await _list_sessions_str_keys(client)
        assert "1" in normalized
        assert normalized["1"]["type"] == "meterpreter"

    @pytest.mark.asyncio
    async def test_get_session_object_uses_private_constructor_path(self, mock_asyncio_to_thread):
        client, _ = _make_mock_client({1: {"type": "meterpreter"}})
        normalized = await _list_sessions_str_keys(client)
        sentinel_session = Mock()
        client.sessions._create_session = Mock(return_value=sentinel_session)
        client.sessions.session = Mock(side_effect=KeyError("broken public lookup"))

        session = await _get_session_object_from_map(client, normalized, "1")

        assert session is sentinel_session
        client.sessions._create_session.assert_called_once()


# ---------------------------------------------------------------------------
# Concurrency tests for send_session_command
# ---------------------------------------------------------------------------


class TestSendSessionCommandLocking:

    @pytest.mark.asyncio
    async def test_concurrent_same_session_serialized(self, mock_asyncio_to_thread):
        """Two concurrent calls on the SAME session execute one after the other."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )

        execution_order = []

        def tracking_write(data):
            cmd = data.strip()
            execution_order.append(f"start-{cmd}")
            execution_order.append(f"end-{cmd}")
            return None

        session_obj.write = Mock(side_effect=tracking_write)

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            r1, r2 = await asyncio.gather(
                send_session_command(1, "sysinfo"),
                send_session_command(1, "getuid"),
            )

        assert r1["status"] == "success"
        assert r2["status"] == "success"
        # Because of the lock, the first command must fully complete before the
        # second one starts.  The order of sysinfo vs getuid depends on
        # scheduling, but we know one must finish before the other starts.
        starts = [i for i, e in enumerate(execution_order) if e.startswith("start-")]
        ends = [i for i, e in enumerate(execution_order) if e.startswith("end-")]
        assert (
            ends[0] < starts[1]
        ), f"First command should finish before second starts: {execution_order}"

    @pytest.mark.asyncio
    async def test_different_sessions_not_blocked(self, mock_asyncio_to_thread):
        """Calls on DIFFERENT sessions should not block each other."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
                "2": {"type": "meterpreter", "target_host": "10.0.0.2"},
            }
        )

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            r1, r2 = await asyncio.gather(
                send_session_command(1, "sysinfo"),
                send_session_command(2, "getuid"),
            )

        assert r1["status"] == "success"
        assert r2["status"] == "success"

    @pytest.mark.asyncio
    async def test_busy_status_on_lock_timeout(self, mock_asyncio_to_thread):
        """If the lock is held longer than SESSION_LOCK_WAIT_TIMEOUT the caller
        gets status='busy'."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )

        lock = await _get_session_lock("1")
        await lock.acquire()

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("metasploit_mcp.server.SESSION_LOCK_WAIT_TIMEOUT", 0.1),
        ):
            result = await send_session_command(1, "sysinfo")

        lock.release()

        assert result["status"] == "busy"
        assert "currently in use" in result["message"]

    @pytest.mark.asyncio
    async def test_session_not_found_cleans_up_lock(self, mock_asyncio_to_thread):
        """When the session doesn't exist, the lock entry should be cleaned up."""
        client, _ = _make_mock_client({})

        _session_locks["99"] = asyncio.Lock()
        session_shell_type["99"] = "meterpreter"

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(99, "whoami")

        assert result["status"] == "error"
        assert "not found" in result["message"]
        assert "99" not in session_shell_type

    @pytest.mark.asyncio
    async def test_int_keyed_session_lookup_succeeds(self, mock_asyncio_to_thread):
        """RPC returns int session IDs; command lookup should still succeed."""
        client, _ = _make_mock_client({1: {"type": "meterpreter", "target_host": "10.0.0.1"}})
        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(1, "whoami")

        assert result["status"] == "success"
        assert result["reason"] in {"prompt", "inactivity"}

    @pytest.mark.asyncio
    async def test_meterpreter_command_returns_on_inactivity(self, mock_asyncio_to_thread):
        """Meterpreter commands with output but no prompt should complete via inactivity."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )

        read_chunks = ["uid=33(www-data)\n", "", "", ""]

        def _read():
            if read_chunks:
                return read_chunks.pop(0)
            return ""

        session_obj.read = Mock(side_effect=_read)

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(
                1,
                "getuid",
                timeout_seconds=5,
                inactivity_timeout_seconds=1,
            )

        assert result["status"] == "success"
        assert result["reason"] == "inactivity"
        assert "www-data" in result["output"]

    @pytest.mark.asyncio
    async def test_meterpreter_command_timeout_returns_partial_output(self, mock_asyncio_to_thread):
        """Timeout should still return buffered output and mark reason=timeout."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )
        session_obj.read = Mock(return_value="")

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(
                1,
                "sysinfo",
                timeout_seconds=1,
                inactivity_timeout_seconds=1,
            )

        assert result["status"] == "timeout"
        assert result["reason"] == "timeout"
        assert "elapsed_seconds" in result


# ---------------------------------------------------------------------------
# Concurrency tests for terminate_session
# ---------------------------------------------------------------------------


class TestTerminateSessionLocking:

    @pytest.mark.asyncio
    async def test_terminate_acquires_lock(self, mock_asyncio_to_thread):
        """terminate_session should wait for the lock before proceeding."""
        sessions_state = {"1": {"type": "meterpreter"}}

        client, session_obj = _make_mock_client(sessions_state)

        call_count = 0

        async def mock_to_thread(func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            result = func(*args, **kwargs)
            if isinstance(result, dict) and call_count >= 3:
                return {}
            return result

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("asyncio.to_thread", side_effect=mock_to_thread),
        ):
            result = await terminate_session(1)

        assert result["status"] == "success"
        session_obj.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_terminate_busy_when_locked(self, mock_asyncio_to_thread):
        """terminate_session returns 'busy' if a command holds the session lock."""
        client, _ = _make_mock_client({"1": {"type": "meterpreter"}})

        lock = await _get_session_lock("1")
        await lock.acquire()

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("metasploit_mcp.server.SESSION_LOCK_WAIT_TIMEOUT", 0.1),
        ):
            result = await terminate_session(1)

        lock.release()

        assert result["status"] == "busy"
        assert "currently in use" in result["message"]

    @pytest.mark.asyncio
    async def test_terminate_cleans_up_on_success(self, mock_asyncio_to_thread):
        """After successful termination, session_shell_type and lock are cleaned up."""
        client, session_obj = _make_mock_client({"1": {"type": "meterpreter"}})
        session_shell_type["1"] = "meterpreter"

        call_count = 0

        async def mock_to_thread(func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            result = func(*args, **kwargs)
            if isinstance(result, dict) and call_count >= 3:
                return {}
            return result

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("asyncio.to_thread", side_effect=mock_to_thread),
        ):
            result = await terminate_session(1)

        assert result["status"] == "success"
        assert "1" not in session_shell_type

    @pytest.mark.asyncio
    async def test_terminate_not_found_cleans_up(self, mock_asyncio_to_thread):
        """terminate_session on a missing session should clean up stale state."""
        client, _ = _make_mock_client({})
        session_shell_type["50"] = "meterpreter"
        _session_locks["50"] = asyncio.Lock()

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await terminate_session(50)

        assert result["status"] == "error"
        assert "not found" in result["message"]
        assert "50" not in session_shell_type

    @pytest.mark.asyncio
    async def test_terminate_int_keyed_session_succeeds(self, mock_asyncio_to_thread):
        """terminate_session should handle int keys from sessions.list."""
        client, session_obj = _make_mock_client({1: {"type": "meterpreter"}})
        call_count = 0

        async def mock_to_thread(func, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            result = func(*args, **kwargs)
            if isinstance(result, dict) and call_count >= 3:
                return {}
            return result

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("asyncio.to_thread", side_effect=mock_to_thread),
        ):
            result = await terminate_session(1)

        assert result["status"] == "success"
        session_obj.stop.assert_called_once()


# ---------------------------------------------------------------------------
# Lock release on error paths
# ---------------------------------------------------------------------------


class TestLockReleaseOnErrors:

    @pytest.mark.asyncio
    async def test_lock_released_after_rpc_error(self, mock_asyncio_to_thread):
        """The session lock must be released even when an RPC error occurs."""
        from pymetasploit3.msfrpc import MsfRpcError

        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )
        session_obj.write = Mock(side_effect=MsfRpcError("RPC failure"))

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(1, "sysinfo")

        assert result["status"] == "error"

        lock = await _get_session_lock("1")
        assert not lock.locked(), "Lock should be released after RPC error"

    @pytest.mark.asyncio
    async def test_lock_released_after_unexpected_exception(self, mock_asyncio_to_thread):
        """Lock must be released even on unexpected exceptions."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )
        session_obj.write = Mock(side_effect=RuntimeError("boom"))

        with patch("metasploit_mcp.server.get_msf_client", return_value=client):
            result = await send_session_command(1, "sysinfo")

        assert result["status"] == "error"

        lock = await _get_session_lock("1")
        assert not lock.locked(), "Lock should be released after unexpected error"

    @pytest.mark.asyncio
    async def test_lock_released_after_timeout(self, mock_asyncio_to_thread):
        """Lock must be released when the command itself times out."""
        client, session_obj = _make_mock_client(
            {
                "1": {"type": "meterpreter", "target_host": "10.0.0.1"},
            }
        )

        async def slow_to_thread(func, *args, **kwargs):
            result = func(*args, **kwargs)
            return result

        session_obj.read = Mock(return_value="")

        with (
            patch("metasploit_mcp.server.get_msf_client", return_value=client),
            patch("asyncio.to_thread", side_effect=slow_to_thread),
        ):
            result = await send_session_command(1, "sysinfo", timeout_seconds=1)

        assert result["status"] == "timeout"
        lock = await _get_session_lock("1")
        assert not lock.locked(), "Lock should be released after command timeout"
