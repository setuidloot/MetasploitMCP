# Event Loop Monitoring

This document describes the event loop monitoring feature that helps debug blocking operations in the async MCP server.

## Overview

The event loop monitoring module provides utilities to detect and log when the asyncio event loop is blocked. This is essential for debugging performance issues caused by synchronous operations blocking async execution.

## Features

1. **Asyncio Debug Mode**: Enables Python's built-in slow callback detection
2. **Watchdog Thread**: A separate thread that monitors event loop responsiveness
3. **Stack Trace Logging**: Captures stack traces when blocking is detected
4. **Decorator & Context Manager**: Utilities for instrumenting specific code sections

## Configuration

All configuration is done via environment variables, making it easy to enable debugging without code changes.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ASYNCIO_DEBUG` | `false` | Enable asyncio debug mode with slow callback detection |
| `EVENT_LOOP_SLOW_CALLBACK_THRESHOLD` | `0.1` | Threshold in seconds for slow callback warnings |
| `EVENT_LOOP_WATCHDOG` | `false` | Enable the watchdog thread for blocking detection |
| `EVENT_LOOP_WATCHDOG_INTERVAL` | `1.0` | How often the watchdog checks (seconds) |
| `EVENT_LOOP_WATCHDOG_THRESHOLD` | `0.5` | Delay threshold that triggers a warning (seconds) |

## Enabling Monitoring

### Quick Start

```bash
# Enable asyncio debug mode
ASYNCIO_DEBUG=true python MetasploitMCP.py

# Enable watchdog with custom thresholds
EVENT_LOOP_WATCHDOG=true \
EVENT_LOOP_WATCHDOG_INTERVAL=0.5 \
EVENT_LOOP_WATCHDOG_THRESHOLD=0.2 \
python MetasploitMCP.py
```

### Full Debug Mode

For comprehensive debugging, enable both features:

```bash
ASYNCIO_DEBUG=true \
EVENT_LOOP_WATCHDOG=true \
EVENT_LOOP_WATCHDOG_THRESHOLD=0.3 \
LOG_LEVEL=DEBUG \
python MetasploitMCP.py
```

## Log Output Examples

### Slow Callback Detection

When asyncio debug mode is enabled and a callback takes too long:

```
⏱️ SLOW CALLBACK detected (#1): took 0.200s (threshold=0.1s)
   Callback: MetasploitMCP._some_blocking_function
```

### Event Loop Blocking Detection

When the watchdog detects the event loop is blocked:

```
🚨 EVENT LOOP BLOCKED for 0.523s (threshold=0.5s, check #15)
=== Thread stack traces at time of blocking ===

--- MainThread (likely event loop) ---
File "/path/to/MetasploitMCP.py", line 342, in some_function
    result = blocking_operation()  # <- BLOCKING CALL!
```

### Severe Blocking (Callback Didn't Respond)

```
🚨🚨 EVENT LOOP SEVERELY BLOCKED - callback did not respond in 3.152s (check #42)
=== Thread stack traces at time of blocking ===
...
```

## Programmatic Usage

### Decorator for Tracking Slow Functions

```python
from event_loop_monitor import track_blocking

@track_blocking(threshold=0.5)
async def potentially_slow_operation():
    # This will log a warning if it takes more than 0.5s
    await some_io_operation()
```

### Context Manager for Specific Code Blocks

```python
from event_loop_monitor import BlockingMonitor

async def complex_operation():
    async with BlockingMonitor("rpc_call", threshold=1.0):
        # This will log if the block takes more than 1 second
        await msf_client.some_rpc_call()
```

### Health Check

```python
from event_loop_monitor import check_event_loop_health

async def health_endpoint():
    health = await check_event_loop_health()
    return {
        "event_loop_latency_ms": health["event_loop_latency_ms"],
        "debug_mode": health["debug_mode"],
        "monitoring_stats": health["monitoring_stats"]
    }
```

### Getting Monitoring Statistics

```python
from event_loop_monitor import get_monitoring_stats

stats = get_monitoring_stats()
# Returns:
# {
#     "watchdog_running": True,
#     "debug_enabled": True,
#     "slow_callback_threshold": 0.1,
#     "watchdog_check_count": 42,
#     "watchdog_block_count": 3
# }
```

## Best Practices

1. **Development**: Enable both `ASYNCIO_DEBUG=true` and `EVENT_LOOP_WATCHDOG=true` with low thresholds to catch issues early.

2. **Production Debugging**: Enable only `EVENT_LOOP_WATCHDOG=true` with reasonable thresholds (0.5s+) to avoid excessive logging.

3. **Performance Testing**: Use higher thresholds or disable after identifying issues to avoid monitoring overhead.

## Common Blocking Causes

The monitoring will help you identify:

1. **Synchronous I/O operations** - file reads, subprocess calls, etc.
2. **CPU-intensive operations** - large data processing, encryption, etc.
3. **Blocking RPC calls** - pymetasploit3 operations that block
4. **Network operations** - synchronous HTTP requests, DNS lookups, etc.

## Resolution Strategies

Once you identify blocking code:

1. **Use async alternatives**: `asyncio.to_thread()`, `aiofiles`, `aiohttp`
2. **Move to thread pool**: `loop.run_in_executor()`
3. **Break up long operations**: Yield control with `await asyncio.sleep(0)`
4. **Cache expensive operations**: Reduce frequency of blocking calls

## Recent Fixes

### Session Shell/Exit Commands (v1.x.x)

Fixed blocking calls in Meterpreter session `shell` and `exit` commands. The following operations are now properly wrapped in `asyncio.to_thread()`:

- `session.run_with_output()` for shell command
- `session.read()` for buffer clearing
- `session.detach()` for exit command

This prevents the event loop from being blocked when switching between Meterpreter and shell modes.

