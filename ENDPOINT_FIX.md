# Endpoint Correction

## Issue

The initial implementation incorrectly used `/mcp/sse` as the endpoint. This was based on an incorrect assumption about SSE (Server-Sent Events) transport.

## Correction

**MetasploitMCP uses FastMCP with HTTP transport (not SSE).**

### Correct Configuration

- **Transport**: `streamable-http` (FastMCP)
- **Endpoint**: `/mcp`
- **Protocol**: HTTP JSON-RPC

### What Was Fixed

1. **`metasploitable3_test_harness.py`**
   ```python
   # Before (WRONG):
   self.mcp_endpoint = f"{self.mcp_url}/mcp/sse"
   
   # After (CORRECT):
   self.mcp_endpoint = f"{self.mcp_url}/mcp"
   ```

2. **`tests/test_metasploitable3_harness.py`**
   - Updated test assertions to expect `/mcp` endpoint

3. **Documentation Files**
   - Updated `HARNESS_SUMMARY.md`
   - Updated `METASPLOITABLE3_HARNESS_README.md`
   - Updated `INTEGRATION_TEST_SETUP.md`

### Server Configuration

From `MetasploitMCP.py`:

```python
# Server runs with streamable-http transport
mcp.run(transport="streamable-http")

# Log message confirms endpoint
logger.info(f"MCP HTTP Endpoint: /mcp")
```

### Client Usage

```python
# Initialize client
client = MetasploitMCPClient("http://127.0.0.1:8085")

# Automatically uses correct endpoint
# client.mcp_endpoint = "http://127.0.0.1:8085/mcp"

# Make tool calls
response = await client.call_tool("list_exploits", {})
```

### Testing

```bash
# Quick verification
curl -X POST http://127.0.0.1:8085/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Status

✅ **Fixed** - All files updated to use the correct `/mcp` endpoint.

## Files Changed

- `metasploitable3_test_harness.py` - Client endpoint URL
- `tests/test_metasploitable3_harness.py` - Test assertions
- `HARNESS_SUMMARY.md` - Architecture diagram
- `METASPLOITABLE3_HARNESS_README.md` - Architecture diagram
- `INTEGRATION_TEST_SETUP.md` - Architecture diagram

## Verification

Run the unit tests to verify:

```bash
make test-harness
```

All tests pass with the corrected endpoint.

