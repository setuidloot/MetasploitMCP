# Metasploitable 3 Test Harness - Usage Examples

## Direct MetasploitMCP Server

### Start the Server
```bash
# Terminal 1: Start Metasploit RPC
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553

# Terminal 2: Start MetasploitMCP
cd /Users/setuidloot/Repos/MetasploitMCP
export MSF_PASSWORD=mypassword
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

### Run Tests
```bash
# Terminal 3: Run harness (NO --gateway flag)
cd /Users/setuidloot/Repos/MetasploitMCP

# Quick test
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4

# All tests
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4

# Specific test with verbose
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD" \
    --verbose
```

**What happens:**
- Connects to: `http://127.0.0.1:8085/mcp`
- Calls tools: `list_exploits`, `run_exploit`, etc. (NO prefix)

---

## ExploitMCP Gateway

### Start the Gateway
```bash
# Terminal 1: Start Metasploit RPC (if not already running)
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553

# Terminal 2: Start ExploitMCP Gateway
cd /Users/setuidloot/Repos/exploitmcp
export MSF_PASSWORD=mypassword
poetry run python -m src.exploitmcp.mcps.gateway --port 5555
```

### Run Tests
```bash
# Terminal 3: Run harness (WITH --gateway flag)
cd /Users/setuidloot/Repos/MetasploitMCP

# Quick test
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway

# All tests
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway

# Specific test with verbose
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway \
    --test "ProFTPD" \
    --verbose
```

**What happens:**
- Connects to: `http://localhost:5555/mcp`
- Calls tools: `metasploit_list_exploits`, `metasploit_run_exploit`, etc. (WITH prefix)

---

## Side-by-Side Comparison

### Direct Server
```bash
# Endpoint
http://localhost:8085/mcp

# Tool call
{
    "method": "tools/call",
    "params": {
        "name": "run_exploit",  # No prefix
        "arguments": {...}
    }
}

# Command
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4
    # No --gateway flag
```

### Gateway
```bash
# Endpoint (same path!)
http://localhost:5555/mcp

# Tool call
{
    "method": "tools/call",
    "params": {
        "name": "metasploit_run_exploit",  # Prefix added!
        "arguments": {...}
    }
}

# Command
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway  # This adds the prefix
```

---

## Common Mistakes

### ❌ Mistake 1: Using gateway URL without --gateway flag
```bash
# WRONG - will fail with "tool not found"
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555
    # Missing --gateway!
```

**Error**: Tool `run_exploit` not found (because gateway expects `metasploit_run_exploit`)

**Fix**: Add `--gateway` flag

### ❌ Mistake 2: Using --gateway with direct server
```bash
# WRONG - will fail with "tool not found"
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:8085 \
    --gateway
    # Don't use --gateway with direct server!
```

**Error**: Tool `metasploit_run_exploit` not found (because direct server expects `run_exploit`)

**Fix**: Remove `--gateway` flag

### ❌ Mistake 3: Wrong port without changing URL
```bash
# WRONG - using gateway port but no --gateway flag
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4
    # Default is http://localhost:8085, but gateway is on 5555
```

**Error**: Connection refused

**Fix**: Specify `--mcp-url http://localhost:5555 --gateway`

---

## Debugging

### Check what endpoint and tool names are being used:
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway \
    --verbose
```

Look for these log lines:
```
INFO - Initialized MCP client for ExploitMCP Gateway: http://localhost:5555
INFO - MCP endpoint: http://localhost:5555/mcp
INFO - Tool prefix: 'metasploit_'
DEBUG - Calling tool: run_exploit (actual: metasploit_run_exploit) with args: {...}
```

### Test the connection:
```bash
# Test direct server
poetry run python test_mcp_connection.py --url http://localhost:8085

# Test gateway
poetry run python test_mcp_connection.py --url http://localhost:5555
```

---

## Quick Decision Tree

```
Are you testing MetasploitMCP integration?
│
├─ YES → Using standalone MetasploitMCP server?
│   │
│   ├─ YES → Use: --mcp-url http://localhost:8085
│   │         (No --gateway flag)
│   │
│   └─ NO → Using ExploitMCP gateway?
│       │
│       └─ YES → Use: --mcp-url http://localhost:5555 --gateway
│                (Include --gateway flag)
│
└─ NO → See other documentation
```

---

## Environment Variables

Both modes respect the same Metasploit RPC environment variables:

```bash
export MSF_PASSWORD=mypassword
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553
```

These must be set before starting:
- MetasploitMCP server (direct mode)
- ExploitMCP gateway (gateway mode)

---

## Summary

| Mode | URL | Endpoint | Tool Names | Flag |
|------|-----|----------|------------|------|
| **Direct** | `http://localhost:8085` | `/mcp` | `run_exploit` | None |
| **Gateway** | `http://localhost:5555` | `/mcp` | `metasploit_run_exploit` | `--gateway` |

**Key takeaway**: The `--gateway` flag changes the **tool name prefix**, not the endpoint path!

