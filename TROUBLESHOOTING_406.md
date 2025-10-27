# Troubleshooting: 406 Not Acceptable Error

## Error Message

```
HTTP Request: POST http://localhost:5555/mcp "HTTP/1.1 406 Not Acceptable"
ERROR - HTTP error calling tool run_exploit: Client error '406 Not Acceptable'
```

## What This Means

A **406 Not Acceptable** error means the server cannot produce a response in a format acceptable to the client. This is typically related to:
1. Missing or incorrect `Accept` header
2. Wrong endpoint URL
3. Connecting to the wrong server

## Fixes Applied

### 1. Added Correct Accept Header

**Fixed in**: `metasploitable3_test_harness.py`

```python
# FastMCP streamable-http requires accepting both JSON and SSE
response = await self.client.post(
    self.mcp_endpoint,
    json=request_data,
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"  # ← Both formats!
    }
)
```

**Why both?** FastMCP's `streamable-http` transport can return either JSON or Server-Sent Events (SSE) streams, so clients must accept both formats.

### 2. Added Debug Logging

**Fixed in**: `metasploitable3_test_harness.py`

The harness now logs:
- MCP endpoint URL
- Request payload
- Response status and headers

Run with `--verbose` to see these logs.

## Important: Check Your Server Type

**Are you using MetasploitMCP directly or through the ExploitMCP gateway?**

### Two Connection Options:

1. **Direct MetasploitMCP** (standalone): 
   - URL: `http://localhost:8085`
   - Endpoint: `/mcp`
   - Tool names: `list_exploits`, `run_exploit`, etc.
   - Command: No special flags needed

2. **ExploitMCP Gateway** (integrated with other tools):
   - URL: `http://localhost:5555`
   - Endpoint: `/mcp` (same!)
   - Tool names: `metasploit_list_exploits`, `metasploit_run_exploit`, etc. (prefixed!)
   - Command: **Must use `--gateway` flag**

The MetasploitMCP server should be started with:
```bash
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

If you see this in the startup logs, you're good:
```
INFO - Starting FastMCP HTTP server on http://127.0.0.1:8085
INFO - MCP HTTP Endpoint: /mcp
```

### If you're using ExploitMCP Gateway (port 5555)

The gateway is a unified endpoint for **all** ExploitMCP tools (nmap, nikto, sqlmap, AND metasploit).

Use the `--gateway` flag to prefix tool names:
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway
#   ^^^^^^^^^ Important! Prefixes tool names with "metasploit_"
```

**Why the flag?** The gateway uses prefixed tool names like `metasploit_run_exploit` instead of just `run_exploit` to avoid conflicts with other tools.

## Testing the Connection

Use the connection test script to verify everything works:

```bash
# Test connection to default port
poetry run python test_mcp_connection.py

# Test connection to custom port
poetry run python test_mcp_connection.py --url http://localhost:5555

# Full test including tool calls
poetry run python test_mcp_connection.py --url http://localhost:8085 --full
```

Expected output:
```
MetasploitMCP Connection Test
============================================================

Testing MCP connection to: http://localhost:8085
============================================================
Endpoint: http://localhost:8085/mcp

Test 1: Server Availability
------------------------------------------------------------
✓ Server is responding
  Status: 200
  Content-Type: text/html; charset=utf-8

Test 2: MCP Protocol - List Tools
------------------------------------------------------------
Response Status: 200
✓ MCP Protocol Working!
✓ Found 8 MCP tools
  Tools: list_exploits, run_exploit, generate_payload, start_listener, ...

============================================================
SUCCESS - All tests passed!
============================================================
```

## Common Causes

### Cause 1: Wrong Server

**Problem**: Connecting to ExploitMCP Gateway (port 5555) instead of MetasploitMCP (port 8085)

**Solution**: Use the correct URL
```bash
# Wrong
--mcp-url http://localhost:5555

# Correct (for MetasploitMCP)
--mcp-url http://localhost:8085
```

### Cause 2: Wrong Accept Header

**Problem**: Server expects `Accept: application/json, text/event-stream` (both formats)

**Solution**: ✅ Already fixed in the harness

**Why?** FastMCP's streamable-http can return either JSON or SSE, so clients must accept both.

### Cause 3: Server Not Running

**Problem**: MetasploitMCP server isn't started

**Solution**:
```bash
# Terminal 1: Start Metasploit RPC
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553

# Terminal 2: Start MetasploitMCP
export MSF_PASSWORD=mypassword
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

### Cause 4: Wrong Endpoint

**Problem**: Using `/mcp/sse` instead of `/mcp`

**Solution**: ✅ Already fixed - harness uses `/mcp`

## Debugging Steps

### Step 1: Verify Server is Running

```bash
# Check if server is listening
curl http://localhost:8085

# Should return HTML or at least a 200 response
```

### Step 2: Test MCP Endpoint

```bash
# Test tools/list
curl -X POST http://localhost:8085/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Expected response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {"name": "list_exploits", ...},
      {"name": "run_exploit", ...},
      ...
    ]
  }
}
```

### Step 3: Run Connection Test

```bash
poetry run python test_mcp_connection.py --url http://localhost:8085
```

### Step 4: Run Harness with Verbose Logging

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:8085 \
    --verbose
```

Look for these debug messages:
```
DEBUG - MCP endpoint: http://localhost:8085/mcp
DEBUG - Request payload: {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', ...}
DEBUG - Response status: 200
DEBUG - Response headers: {...}
```

## Still Getting 406?

If you're still getting a 406 error after:
1. ✅ Added Accept header (fixed in code)
2. ✅ Using correct endpoint `/mcp` (fixed in code)
3. ✅ Connecting to correct port
4. ✅ Server is running

Then check:

### Check Server Logs

Look at the MetasploitMCP server output for errors.

### Check FastMCP Version

```bash
poetry show fastmcp
```

Should be `>=2.10.3`

### Try Different Content-Type

If still failing, try modifying the harness temporarily:

```python
headers={
    "Content-Type": "application/json",
    "Accept": "*/*"  # Accept anything
}
```

## Summary

The 406 error is now fixed by:
1. ✅ Adding `Accept: application/json, text/event-stream` header (both formats!)
2. ✅ Using correct endpoint `/mcp` (not `/mcp/sse`)
3. ✅ Added debug logging
4. ✅ Tool name prefixing with `--gateway` flag

**Next step**: Make sure you're connecting to the right server URL!

```bash
# Test connection
poetry run python test_mcp_connection.py --url http://localhost:8085

# Run harness
make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4
```

---

**If this still doesn't work**, please share:
1. MetasploitMCP server startup logs
2. Output from `test_mcp_connection.py`
3. Harness output with `--verbose` flag

