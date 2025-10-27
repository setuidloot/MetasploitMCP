# ExploitMCP Gateway vs Direct MetasploitMCP

## Key Difference

The **endpoint path is the same**, but the **tool names are different**.

### Direct MetasploitMCP Server

```bash
# Start server
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

# Endpoint: http://localhost:8085/mcp
# Tool names: list_exploits, run_exploit, list_active_sessions, etc.
```

**Test harness usage:**
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:8085
```

### ExploitMCP Gateway

```bash
# Start gateway
cd /Users/setuidloot/Repos/exploitmcp
poetry run python -m src.exploitmcp.mcps.gateway --port 5555

# Endpoint: http://localhost:5555/mcp (SAME PATH!)
# Tool names: metasploit_list_exploits, metasploit_run_exploit, metasploit_list_active_sessions, etc.
#             ^^^^^^^^^^^^ PREFIX ADDED
```

**Test harness usage:**
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway
#   ^^^^^^^^^ This flag prefixes tool names
```

## How It Works

### Without `--gateway` flag (Direct MetasploitMCP)

```python
# Tool call
tool_name = "list_exploits"
actual_tool_name = "list_exploits"  # No prefix

# Request to http://localhost:8085/mcp
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "list_exploits",  # Direct tool name
        "arguments": {...}
    }
}
```

### With `--gateway` flag (ExploitMCP Gateway)

```python
# Tool call
tool_name = "list_exploits"
actual_tool_name = "metasploit_list_exploits"  # Prefix added!

# Request to http://localhost:5555/mcp
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "metasploit_list_exploits",  # Prefixed tool name
        "arguments": {...}
    }
}
```

## Tool Name Mapping

| Base Tool Name | Direct Server | Gateway |
|----------------|---------------|---------|
| `list_exploits` | `list_exploits` | `metasploit_list_exploits` |
| `run_exploit` | `run_exploit` | `metasploit_run_exploit` |
| `generate_payload` | `generate_payload` | `metasploit_generate_payload` |
| `start_listener` | `start_listener` | `metasploit_start_listener` |
| `list_active_sessions` | `list_active_sessions` | `metasploit_list_active_sessions` |
| `send_session_command` | `send_session_command` | `metasploit_send_session_command` |
| `stop_listener` | `stop_listener` | `metasploit_stop_listener` |
| `list_payloads` | `list_payloads` | `metasploit_list_payloads` |

## Why The Gateway Uses Prefixes

The ExploitMCP gateway mounts **multiple tool providers** at the same `/mcp` endpoint:

- **Core tools** (no prefix): `execute_command`, `search_exploits`, etc.
- **Nmap tools**: `nmap_scan`, `nmap_list_scans`, etc.
- **Nikto tools**: `nikto_scan_web`, `nikto_list_scans`, etc.
- **Metasploit tools**: `metasploit_list_exploits`, `metasploit_run_exploit`, etc.

This prevents tool name collisions when multiple servers are mounted.

## Testing Connection

### Test Direct MetasploitMCP
```bash
poetry run python test_mcp_connection.py --url http://localhost:8085
```

### Test ExploitMCP Gateway
```bash
poetry run python test_mcp_connection.py --url http://localhost:5555
```

The connection test will show you which tools are available and their names.

## Common Error: 406 Not Acceptable

If you get a 406 error, make sure you're using the `--gateway` flag when connecting to the ExploitMCP gateway:

❌ **Wrong** (will fail with 406 or tool not found):
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555
# Missing --gateway flag!
```

✅ **Correct**:
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway
# Now it will use metasploit_ prefix
```

## Quick Reference

| Scenario | Command |
|----------|---------|
| **Test against direct MetasploitMCP** | `--mcp-url http://localhost:8085` |
| **Test against ExploitMCP gateway** | `--mcp-url http://localhost:5555 --gateway` |
| **List tools (direct)** | `curl -X POST http://localhost:8085/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'` |
| **List tools (gateway)** | `curl -X POST http://localhost:5555/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'` |

## Summary

✅ **Endpoint**: Same for both (`/mcp`)  
✅ **Tool names**: Different (gateway adds `metasploit_` prefix)  
✅ **Harness flag**: Use `--gateway` when connecting to ExploitMCP gateway  
✅ **Headers**: Both need `Content-Type: application/json` and `Accept: application/json`

