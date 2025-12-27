"""
Event Loop Monitoring for MetasploitMCP

This module provides utilities to detect and log when the event loop is blocked,
helping to track down synchronous operations that are holding up async execution.

Features:
- Enables asyncio debug mode with configurable slow callback threshold
- Provides a watchdog thread that monitors event loop responsiveness
- Logs detailed warnings when the event loop is blocked
- Captures stack traces of blocking operations when possible

Configuration via environment variables:
    ASYNCIO_DEBUG: Set to 'true' to enable asyncio debug mode (default: false)
    EVENT_LOOP_SLOW_CALLBACK_THRESHOLD: Threshold in seconds for slow callbacks (default: 0.1)
    EVENT_LOOP_WATCHDOG: Set to 'false' to disable watchdog thread (default: true, enabled by default)
    EVENT_LOOP_WATCHDOG_INTERVAL: How often watchdog checks in seconds (default: 1.0)
    EVENT_LOOP_WATCHDOG_THRESHOLD: Threshold for blocked detection in seconds (default: 0.5)
    EVENT_LOOP_BACKLOG_THRESHOLD: Number of pending tasks that triggers a warning (default: 100)
"""

import asyncio
import logging
import os
import sys
import threading
import time
import traceback
from datetime import datetime
from typing import Optional, Callable, Any

logger = logging.getLogger("metasploit_mcp_server.event_loop_monitor")


def get_env_bool(key: str, default: bool = False) -> bool:
    """Get a boolean environment variable."""
    value = os.environ.get(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')


def get_env_float(key: str, default: float) -> float:
    """Get a float environment variable."""
    try:
        return float(os.environ.get(key, str(default)))
    except ValueError:
        return default


# Configuration from environment
ASYNCIO_DEBUG = get_env_bool('ASYNCIO_DEBUG', False)
SLOW_CALLBACK_THRESHOLD = get_env_float('EVENT_LOOP_SLOW_CALLBACK_THRESHOLD', 0.1)
WATCHDOG_ENABLED = get_env_bool('EVENT_LOOP_WATCHDOG', True)  # Enabled by default
WATCHDOG_INTERVAL = get_env_float('EVENT_LOOP_WATCHDOG_INTERVAL', 1.0)
WATCHDOG_THRESHOLD = get_env_float('EVENT_LOOP_WATCHDOG_THRESHOLD', 0.5)
BACKLOG_THRESHOLD = get_env_float('EVENT_LOOP_BACKLOG_THRESHOLD', 100)


class EventLoopWatchdog:
    """
    Monitors the asyncio event loop from a separate thread to detect blocking.
    
    The watchdog periodically schedules a callback on the event loop and measures
    how long it takes to execute. If the delay exceeds a threshold, it logs a warning.
    
    This is useful for detecting when synchronous code is blocking the event loop,
    preventing async tasks from running.
    """
    
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        interval: float = WATCHDOG_INTERVAL,
        threshold: float = WATCHDOG_THRESHOLD,
        backlog_threshold: int = int(BACKLOG_THRESHOLD)
    ):
        """
        Initialize the watchdog.
        
        Args:
            loop: The asyncio event loop to monitor
            interval: How often to check the event loop (seconds)
            threshold: Delay threshold that triggers a warning (seconds)
            backlog_threshold: Number of pending tasks that triggers a warning
        """
        self.loop = loop
        self.interval = interval
        self.threshold = threshold
        self.backlog_threshold = backlog_threshold
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_response_time: Optional[float] = None
        self._check_count = 0
        self._block_count = 0
        self._backlog_warning_count = 0
        
    def start(self) -> None:
        """Start the watchdog thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Watchdog already running")
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._watchdog_loop,
            name="EventLoopWatchdog",
            daemon=True
        )
        self._thread.start()
        logger.info(
            f"🐕 Event loop watchdog started (interval={self.interval}s, threshold={self.threshold}s, "
            f"backlog_threshold={self.backlog_threshold})"
        )
        
    def stop(self) -> None:
        """Stop the watchdog thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive():
                logger.warning("Watchdog thread did not stop cleanly")
            else:
                logger.info(
                    f"🐕 Event loop watchdog stopped "
                    f"(checks={self._check_count}, blocks_detected={self._block_count}, "
                    f"backlog_warnings={self._backlog_warning_count})"
                )
        self._thread = None
        
    def _watchdog_loop(self) -> None:
        """Main watchdog loop running in a separate thread."""
        while not self._stop_event.is_set():
            try:
                self._check_event_loop()
                self._check_backlog()
            except Exception as e:
                logger.error(
                    f"Error in watchdog check: {e}",
                    exc_info=True
                )
            
            # Wait for the next check interval
            self._stop_event.wait(self.interval)
            
    def _check_event_loop(self) -> None:
        """Perform a single event loop responsiveness check."""
        if self.loop.is_closed():
            logger.debug("Event loop is closed, skipping watchdog check")
            return
            
        self._check_count += 1
        check_time = time.monotonic()
        response_event = threading.Event()
        actual_callback_time: list = []  # Use list to allow modification in nested function
        
        def response_callback() -> None:
            """Callback that runs in the event loop to measure responsiveness."""
            actual_callback_time.append(time.monotonic())
            response_event.set()
            
        try:
            # Schedule the callback on the event loop
            self.loop.call_soon_threadsafe(response_callback)
            
            # Wait for the callback to execute
            # Use a timeout longer than threshold to give it a chance
            if response_event.wait(timeout=self.threshold * 3):
                # Calculate how long it took
                if actual_callback_time:
                    delay = actual_callback_time[0] - check_time
                    
                    if delay > self.threshold:
                        self._block_count += 1
                        self._log_blocking_detected(delay)
                    elif delay > self.threshold / 2:
                        # Log minor delays at debug level
                        logger.debug(
                            f"⚠️ Event loop minor delay: {delay:.3f}s "
                            f"(threshold={self.threshold}s)"
                        )
            else:
                # Callback didn't respond in time - serious blocking
                self._block_count += 1
                elapsed = time.monotonic() - check_time
                self._log_serious_blocking(elapsed)
                
        except RuntimeError as e:
            # Event loop might be closing
            if "is closed" in str(e) or "no running event loop" in str(e).lower():
                logger.debug(f"Event loop not available: {e}")
            else:
                logger.error(f"Error checking event loop: {e}", exc_info=True)
    
    def _check_backlog(self) -> None:
        """Check if the event loop has too many pending tasks."""
        if self.loop.is_closed():
            return
        
        # We need to check tasks from within the event loop context
        # Schedule a callback to count tasks
        backlog_info: list = []  # Use list to allow modification in nested function
        response_event = threading.Event()
        
        def count_tasks_callback() -> None:
            """Callback that runs in the event loop to count pending tasks."""
            try:
                # Get all tasks for this event loop
                all_tasks = asyncio.all_tasks(self.loop)
                # Count tasks that are not done
                pending_tasks = [task for task in all_tasks if not task.done()]
                backlog_count = len(pending_tasks)
                
                # Also try to get ready queue size (internal API, but useful if available)
                ready_count = 0
                try:
                    # This is an internal attribute, but it's the most accurate measure
                    if hasattr(self.loop, '_ready'):
                        ready_count = len(self.loop._ready)
                except (AttributeError, RuntimeError):
                    pass
                
                backlog_info.append({
                    'pending_tasks': backlog_count,
                    'ready_callbacks': ready_count,
                    'total_tasks': len(all_tasks)
                })
            except Exception as e:
                logger.debug(f"Error counting tasks in event loop: {e}", exc_info=True)
                backlog_info.append({
                    'pending_tasks': 0,
                    'ready_callbacks': 0,
                    'total_tasks': 0,
                    'error': str(e)
                })
            finally:
                response_event.set()
        
        try:
            # Schedule the callback on the event loop
            self.loop.call_soon_threadsafe(count_tasks_callback)
            
            # Wait for the callback to execute (with timeout)
            if response_event.wait(timeout=1.0):
                if backlog_info:
                    info = backlog_info[0]
                    pending_tasks = info.get('pending_tasks', 0)
                    ready_callbacks = info.get('ready_callbacks', 0)
                    total_tasks = info.get('total_tasks', 0)
                    
                    # Check if backlog is too high
                    if pending_tasks > self.backlog_threshold:
                        self._backlog_warning_count += 1
                        self._log_backlog_warning(
                            pending_tasks=pending_tasks,
                            ready_callbacks=ready_callbacks,
                            total_tasks=total_tasks
                        )
                    elif pending_tasks > self.backlog_threshold * 0.7:
                        # Log at debug level when approaching threshold
                        logger.debug(
                            f"📊 Event loop backlog: {pending_tasks} pending tasks "
                            f"(threshold={self.backlog_threshold}, ready={ready_callbacks})"
                        )
            else:
                # Callback didn't respond - event loop might be very busy
                logger.debug("Event loop backlog check timed out - loop may be very busy")
                
        except RuntimeError as e:
            # Event loop might be closing
            if "is closed" in str(e) or "no running event loop" in str(e).lower():
                logger.debug(f"Event loop not available for backlog check: {e}")
            else:
                logger.debug(f"Error checking event loop backlog: {e}", exc_info=True)
                
    def _log_backlog_warning(self, pending_tasks: int, ready_callbacks: int, total_tasks: int) -> None:
        """Log warning when event loop backlog is too high."""
        logger.warning(
            f"📊 EVENT LOOP BACKLOG WARNING: {pending_tasks} pending tasks "
            f"(threshold={self.backlog_threshold}, ready_callbacks={ready_callbacks}, "
            f"total_tasks={total_tasks}, warning_count={self._backlog_warning_count})"
        )
        
        # Try to get more context about what tasks are pending
        try:
            # Schedule another callback to get task details
            task_details: list = []
            details_event = threading.Event()
            
            def get_task_details_callback() -> None:
                """Get details about pending tasks."""
                try:
                    all_tasks = asyncio.all_tasks(self.loop)
                    pending = [task for task in all_tasks if not task.done()]
                    
                    # Get task names/types (limited to avoid too much output)
                    task_info = []
                    for task in pending[:10]:  # Limit to first 10
                        try:
                            coro = task.get_coro() if hasattr(task, 'get_coro') else None
                            if coro:
                                coro_name = getattr(coro, '__qualname__', getattr(coro, '__name__', 'unknown'))
                                task_info.append(coro_name)
                            else:
                                task_info.append(str(type(task).__name__))
                        except Exception:
                            task_info.append('unknown')
                    
                    task_details.append({
                        'sample_tasks': task_info,
                        'total_pending': len(pending)
                    })
                except Exception as e:
                    logger.debug(f"Error getting task details: {e}", exc_info=True)
                finally:
                    details_event.set()
            
            self.loop.call_soon_threadsafe(get_task_details_callback)
            
            if details_event.wait(timeout=0.5):
                if task_details:
                    details = task_details[0]
                    sample_tasks = details.get('sample_tasks', [])
                    if sample_tasks:
                        logger.warning(
                            f"   Sample pending tasks: {', '.join(sample_tasks[:5])}"
                            + (f" (+{len(sample_tasks) - 5} more)" if len(sample_tasks) > 5 else "")
                        )
        except Exception as e:
            logger.debug(f"Could not get detailed task information: {e}", exc_info=True)
                
    def _log_blocking_detected(self, delay: float) -> None:
        """Log that blocking was detected with details."""
        logger.warning(
            f"🚨 EVENT LOOP BLOCKED for {delay:.3f}s "
            f"(threshold={self.threshold}s, check #{self._check_count})"
        )
        
        # Try to get information about what might be blocking
        self._log_blocking_context()
        
    def _log_serious_blocking(self, elapsed: float) -> None:
        """Log serious blocking where callback didn't respond."""
        logger.error(
            f"🚨🚨 EVENT LOOP SEVERELY BLOCKED - "
            f"callback did not respond in {elapsed:.3f}s "
            f"(check #{self._check_count})"
        )
        self._log_blocking_context()
        
    def _log_blocking_context(self) -> None:
        """Log context about what might be blocking the loop."""
        # Log all running threads and their current frames
        logger.warning("=== Thread stack traces at time of blocking ===")
        
        current_thread_id = threading.current_thread().ident
        
        for thread_id, frame in sys._current_frames().items():
            if thread_id == current_thread_id:
                continue  # Skip watchdog thread
                
            thread_name = None
            for t in threading.enumerate():
                if t.ident == thread_id:
                    thread_name = t.name
                    break
                    
            thread_name = thread_name or f"Thread-{thread_id}"
            
            # Check if this is likely the main/event loop thread
            # MainThread or any thread with "asyncio" in name is interesting
            is_main = thread_name in ("MainThread", "asyncio")
            
            if is_main:
                logger.warning(f"\n--- {thread_name} (likely event loop) ---")
                for line in traceback.format_stack(frame):
                    logger.warning(line.strip())


class SlowCallbackLogger:
    """
    Custom callback that can be set as the asyncio slow callback handler.
    
    When asyncio debug mode is enabled and a callback takes longer than
    the slow_callback_duration, this logs detailed information.
    """
    
    def __init__(self, threshold: float = SLOW_CALLBACK_THRESHOLD):
        self.threshold = threshold
        self.slow_callback_count = 0
        
    def __call__(self, duration: float, callback: Any) -> None:
        """Called when a slow callback is detected."""
        self.slow_callback_count += 1
        
        # Extract callback information
        callback_info = self._get_callback_info(callback)
        
        logger.warning(
            f"⏱️ SLOW CALLBACK detected (#{self.slow_callback_count}): "
            f"took {duration:.3f}s (threshold={self.threshold}s)"
        )
        logger.warning(f"   Callback: {callback_info}")
        
    def _get_callback_info(self, callback: Any) -> str:
        """Extract human-readable information about a callback."""
        try:
            if hasattr(callback, '__qualname__'):
                return f"{callback.__module__}.{callback.__qualname__}"
            elif hasattr(callback, '__name__'):
                return f"{callback.__module__}.{callback.__name__}"
            elif hasattr(callback, '__class__'):
                return f"{callback.__class__.__module__}.{callback.__class__.__name__}"
            else:
                return str(callback)
        except Exception:
            return str(callback)


# Global watchdog instance
_watchdog: Optional[EventLoopWatchdog] = None
_slow_callback_logger: Optional[SlowCallbackLogger] = None


def configure_event_loop_debugging(
    loop: Optional[asyncio.AbstractEventLoop] = None,
    enable_debug: Optional[bool] = None,
    slow_callback_threshold: Optional[float] = None,
    enable_watchdog: Optional[bool] = None,
    watchdog_interval: Optional[float] = None,
    watchdog_threshold: Optional[float] = None,
    backlog_threshold: Optional[int] = None
) -> None:
    """
    Configure event loop debugging features.
    
    This function sets up asyncio debug mode and optionally starts
    a watchdog thread to monitor event loop responsiveness.
    
    Args:
        loop: The event loop to configure (default: current running loop)
        enable_debug: Enable asyncio debug mode (default: from env ASYNCIO_DEBUG)
        slow_callback_threshold: Threshold for slow callback warnings (default: from env)
        enable_watchdog: Enable watchdog thread (default: from env EVENT_LOOP_WATCHDOG)
        watchdog_interval: Watchdog check interval (default: from env)
        watchdog_threshold: Watchdog blocking threshold (default: from env)
        backlog_threshold: Number of pending tasks that triggers a warning (default: from env)
    """
    global _watchdog, _slow_callback_logger
    
    # Use environment defaults if not specified
    enable_debug = enable_debug if enable_debug is not None else ASYNCIO_DEBUG
    slow_callback_threshold = slow_callback_threshold or SLOW_CALLBACK_THRESHOLD
    enable_watchdog = enable_watchdog if enable_watchdog is not None else WATCHDOG_ENABLED
    watchdog_interval = watchdog_interval or WATCHDOG_INTERVAL
    watchdog_threshold = watchdog_threshold or WATCHDOG_THRESHOLD
    backlog_threshold = backlog_threshold if backlog_threshold is not None else int(BACKLOG_THRESHOLD)
    
    # Get the event loop
    if loop is None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                logger.warning("No event loop available, cannot configure debugging")
                return
    
    logger.info(
        f"🔧 Configuring event loop debugging: "
        f"debug={enable_debug}, slow_threshold={slow_callback_threshold}s, "
        f"watchdog={enable_watchdog}, backlog_threshold={backlog_threshold}"
    )
    
    # Enable asyncio debug mode
    if enable_debug:
        loop.set_debug(True)
        loop.slow_callback_duration = slow_callback_threshold
        logger.info(
            f"✅ Asyncio debug mode enabled with slow_callback_duration={slow_callback_threshold}s"
        )
        
        # Note: asyncio's debug mode will log slow callbacks automatically
        # We add extra context with our watchdog
        
    # Start watchdog if enabled
    if enable_watchdog:
        # Stop existing watchdog if any
        if _watchdog is not None:
            _watchdog.stop()
            
        _watchdog = EventLoopWatchdog(
            loop=loop,
            interval=watchdog_interval,
            threshold=watchdog_threshold,
            backlog_threshold=backlog_threshold
        )
        _watchdog.start()


def stop_event_loop_monitoring() -> None:
    """Stop all event loop monitoring."""
    global _watchdog
    
    if _watchdog is not None:
        _watchdog.stop()
        _watchdog = None
        
    logger.info("Event loop monitoring stopped")


def get_monitoring_stats() -> dict:
    """Get statistics from the event loop monitoring."""
    stats = {
        "watchdog_running": _watchdog is not None and _watchdog._thread is not None and _watchdog._thread.is_alive(),
        "debug_enabled": ASYNCIO_DEBUG,
        "slow_callback_threshold": SLOW_CALLBACK_THRESHOLD,
    }
    
    if _watchdog is not None:
        stats["watchdog_check_count"] = _watchdog._check_count
        stats["watchdog_block_count"] = _watchdog._block_count
        stats["backlog_warning_count"] = _watchdog._backlog_warning_count
        stats["backlog_threshold"] = _watchdog.backlog_threshold
        
    if _slow_callback_logger is not None:
        stats["slow_callback_count"] = _slow_callback_logger.slow_callback_count
        
    return stats


async def check_event_loop_health() -> dict:
    """
    Perform a quick event loop health check.
    
    Returns a dict with health information including backlog status.
    """
    loop = asyncio.get_running_loop()
    
    # Measure how long it takes to schedule and execute a simple callback
    start = time.monotonic()
    await asyncio.sleep(0)  # Yield to event loop
    latency = time.monotonic() - start
    
    # Count pending tasks
    all_tasks = asyncio.all_tasks(loop)
    pending_tasks = [task for task in all_tasks if not task.done()]
    pending_count = len(pending_tasks)
    
    # Try to get ready queue size
    ready_count = 0
    try:
        if hasattr(loop, '_ready'):
            ready_count = len(loop._ready)
    except (AttributeError, RuntimeError):
        pass
    
    health = {
        "timestamp": datetime.now().isoformat(),
        "event_loop_latency_ms": latency * 1000,
        "debug_mode": loop.get_debug(),
        "is_running": loop.is_running(),
        "is_closed": loop.is_closed(),
        "pending_tasks": pending_count,
        "ready_callbacks": ready_count,
        "total_tasks": len(all_tasks),
        "monitoring_stats": get_monitoring_stats()
    }
    
    # Warn if latency is high
    if latency > 0.1:  # 100ms
        logger.warning(f"⚠️ High event loop latency: {latency*1000:.1f}ms")
    
    # Warn if backlog is high
    backlog_threshold = int(BACKLOG_THRESHOLD)
    if pending_count > backlog_threshold:
        logger.warning(
            f"⚠️ High event loop backlog: {pending_count} pending tasks "
            f"(threshold={backlog_threshold}, ready_callbacks={ready_count})"
        )
        
    return health


# Decorator for tracking slow async functions
def track_blocking(threshold: float = 0.1):
    """
    Decorator to track if an async function blocks for too long.
    
    Args:
        threshold: Time in seconds after which to log a warning
        
    Usage:
        @track_blocking(threshold=0.5)
        async def potentially_slow_operation():
            ...
    """
    def decorator(func: Callable) -> Callable:
        import functools
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start = time.monotonic()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed = time.monotonic() - start
                if elapsed > threshold:
                    logger.warning(
                        f"⏱️ {func.__qualname__} took {elapsed:.3f}s "
                        f"(threshold={threshold}s)"
                    )
                    
        return wrapper
    return decorator


# Context manager for monitoring a block of code
class BlockingMonitor:
    """
    Context manager to monitor for blocking in a code block.
    
    Usage:
        async with BlockingMonitor("database_query", threshold=1.0):
            await slow_database_query()
    """
    
    def __init__(self, name: str, threshold: float = 0.5):
        self.name = name
        self.threshold = threshold
        self.start_time: Optional[float] = None
        
    async def __aenter__(self) -> "BlockingMonitor":
        self.start_time = time.monotonic()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.start_time is not None:
            elapsed = time.monotonic() - self.start_time
            if elapsed > self.threshold:
                logger.warning(
                    f"⏱️ Block '{self.name}' took {elapsed:.3f}s "
                    f"(threshold={self.threshold}s)"
                )
                if exc_type is None:
                    # No exception, but still slow - might be blocking
                    logger.debug(f"   Stack trace for slow block '{self.name}':")
                    for line in traceback.format_stack()[:-1]:
                        logger.debug(line.strip())




