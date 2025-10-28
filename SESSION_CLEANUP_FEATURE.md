# Automatic Session Cleanup Feature

## Overview

The Metasploitable 3 test harness now automatically kills all active Metasploit sessions before running tests. This ensures ports are freed and prevents port conflicts that would cause test failures.

## Problem Solved

**Before this feature:**
- Previous test runs would leave active sessions
- Sessions would keep LPORT bound, preventing new tests from using it
- Tests would fail with port conflicts: `"Port 4444 is already in use"`
- Manual cleanup required: `sessions -K` in msfconsole

**After this feature:**
- ✅ Harness automatically terminates all sessions before tests
- ✅ Ports are freed for new tests
- ✅ Tests run reliably without manual intervention
- ✅ Clean slate for every test run

## Implementation

### 1. New MCP Client Method

Added `terminate_session()` to `MetasploitMCPClient`:

```python
async def terminate_session(self, session_id: int) -> Dict[str, Any]:
    """Terminate an active session.
    
    Args:
        session_id: Session ID to terminate
        
    Returns:
        Termination result
    """
    return await self.call_tool("terminate_session", {
        "session_id": session_id
    })
```

### 2. Cleanup Method in Harness

Added `cleanup_all_sessions()` to `Metasploitable3TestHarness`:

```python
async def cleanup_all_sessions(self) -> int:
    """Kill all active Metasploit sessions to free up ports.
    
    Returns:
        Number of sessions terminated
    """
    logger.info("Cleaning up all active sessions to free ports...")
    try:
        # Get list of active sessions
        sessions_result = await self.mcp_client.list_sessions()
        
        if sessions_result.get("status") != "success":
            logger.warning(f"Failed to list sessions: {sessions_result.get('message')}")
            return 0
        
        sessions = sessions_result.get("sessions", {})
        if not sessions:
            logger.info("No active sessions to clean up")
            return 0
        
        logger.info(f"Found {len(sessions)} active session(s) to terminate")
        
        # Terminate each session
        terminated_count = 0
        for session_id in sessions.keys():
            try:
                logger.info(f"Terminating session {session_id}...")
                result = await self.mcp_client.terminate_session(int(session_id))
                
                if result.get("status") == "success":
                    logger.info(f"✓ Session {session_id} terminated successfully")
                    terminated_count += 1
                else:
                    logger.warning(f"⚠ Failed to terminate session {session_id}: {result.get('message')}")
            except Exception as e:
                logger.error(f"✗ Error terminating session {session_id}: {e}")
        
        logger.info(f"Session cleanup complete: {terminated_count}/{len(sessions)} terminated")
        
        # Give Metasploit time to release ports
        if terminated_count > 0:
            logger.info("Waiting 2 seconds for ports to be released...")
            await asyncio.sleep(2)
        
        return terminated_count
        
    except Exception as e:
        logger.error(f"Error during session cleanup: {e}")
        return 0
```

### 3. Automatic Invocation

Cleanup is automatically called before running tests:

**In `run_all_tests()`:**
```python
async def run_all_tests(self, continue_on_failure: bool = True, skip_cleanup: bool = False) -> List[TestResult]:
    """Run all exploit tests."""
    # Clean up any existing sessions first to free ports (unless disabled)
    if not skip_cleanup:
        await self.cleanup_all_sessions()
    
    tests = self.get_exploit_tests()
    # ... rest of test execution
```

**In `main()` for single tests:**
```python
if args.test:
    # Clean up any existing sessions first to free ports (unless disabled)
    if not args.no_cleanup:
        await harness.cleanup_all_sessions()
    
    # Run specific test
    # ...
```

### 4. Command-Line Control

Added `--no-cleanup` flag to allow skipping cleanup:

```python
parser.add_argument(
    "--no-cleanup",
    action="store_true",
    help="Skip cleanup of existing sessions before running tests (default: cleanup enabled)"
)
```

## Usage

### Default Behavior (Cleanup Enabled)

```bash
# Cleanup happens automatically
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4
```

**Output:**
```
Cleaning up all active sessions to free ports...
Found 2 active session(s) to terminate
Terminating session 1...
✓ Session 1 terminated successfully
Terminating session 2...
✓ Session 2 terminated successfully
Session cleanup complete: 2/2 terminated
Waiting 2 seconds for ports to be released...

################################################################################
Starting Metasploitable 3 Test Suite
Total tests: 6
################################################################################
```

### Skip Cleanup (Preserve Sessions)

```bash
# Use --no-cleanup to skip session termination
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --no-cleanup
```

**Use case:** When you have important sessions from manual testing that you want to keep.

## Benefits

1. **Prevents Port Conflicts**
   - Frees up LPORT before tests run
   - No more "Port already in use" errors
   - Reliable test execution

2. **Clean State**
   - Each test run starts fresh
   - No interference from previous sessions
   - Consistent results

3. **Automation**
   - No manual cleanup required
   - Works in CI/CD pipelines
   - Saves time

4. **Flexibility**
   - Can be disabled with `--no-cleanup`
   - Respects user preference
   - Useful for debugging

## Error Handling

The cleanup process is robust:

- **If session list fails**: Logs warning, continues with tests
- **If individual termination fails**: Logs error, continues with other sessions
- **If no sessions exist**: Logs info, continues immediately
- **Unexpected errors**: Logs error, returns 0 (doesn't block tests)

## Integration with Port Availability Checking

This feature works hand-in-hand with the port availability checking feature:

1. **Cleanup runs first** → Frees ports from old sessions
2. **Port check runs** → Validates port is available
3. **Test runs** → Uses the free port

Combined, these features ensure:
- ✅ Old sessions don't block new tests
- ✅ Port conflicts are detected early
- ✅ Clear error messages if ports are still in use

## Testing

No additional unit tests were added, as this feature uses existing tested components:
- `terminate_session` MCP tool (already tested in MetasploitMCP)
- `list_active_sessions` MCP tool (already tested)
- Async/await patterns (already tested throughout)

The feature is integration-tested by actual harness runs.

## Documentation Updates

1. **METASPLOITABLE3_HARNESS_README.md**
   - Added section on automatic session cleanup
   - Added `--no-cleanup` flag documentation
   - Updated "Key Features" section

2. **CHANGELOG.md**
   - Documented automatic session cleanup feature
   - Documented `--no-cleanup` flag

3. **This Document**
   - Comprehensive feature description

## Files Modified

1. `/Users/setuidloot/Repos/MetasploitMCP/metasploitable3_test_harness.py`
   - Added `terminate_session()` to MCP client (Line 220-231)
   - Added `cleanup_all_sessions()` method (Line 268-316)
   - Updated `run_all_tests()` to call cleanup (Line 548-551)
   - Updated `main()` to call cleanup for single tests (Line 716-723)
   - Added `--no-cleanup` CLI argument (Line 683-687)
   - Added `skip_cleanup` parameter to `run_all_tests()` (Line 539)

2. `/Users/setuidloot/Repos/MetasploitMCP/METASPLOITABLE3_HARNESS_README.md`
   - Added "Automatic Session Cleanup" section
   - Added `--no-cleanup` example
   - Updated "Key Features"

3. `/Users/setuidloot/Repos/MetasploitMCP/CHANGELOG.md`
   - Documented the new feature

## Example Scenarios

### Scenario 1: Previous Test Run Left Sessions

```bash
# Previous test run created 3 sessions but didn't clean up
# Sessions 1, 2, 3 are still active, all using port 4444

# Run new test
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4

# Output:
# Cleaning up all active sessions to free ports...
# Found 3 active session(s) to terminate
# Terminating session 1...
# ✓ Session 1 terminated successfully
# Terminating session 2...
# ✓ Session 2 terminated successfully  
# Terminating session 3...
# ✓ Session 3 terminated successfully
# Session cleanup complete: 3/3 terminated
# Waiting 2 seconds for ports to be released...
# 
# Tests proceed without port conflicts ✓
```

### Scenario 2: Manual Testing Sessions Exist

```bash
# You've been manually testing and have important sessions
# Session 1: Active meterpreter session you want to keep

# Run automated tests WITHOUT destroying your work
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 5555 \  # Use different port to avoid conflict
    --no-cleanup     # Preserve your manual session

# Your session 1 is preserved ✓
# Tests run on port 5555 ✓
```

### Scenario 3: CI/CD Pipeline

```yaml
# .gitlab-ci.yml or similar
test-metasploitable:
  script:
    - msfrpcd -P ${MSF_PASSWORD} -S -a 127.0.0.1 -p 55553 &
    - poetry run python MetasploitMCP.py &
    - sleep 5
    - poetry run python metasploitable3_test_harness.py \
        --target ${TARGET_IP} \
        --lhost ${LHOST} \
        --gateway
    # Cleanup happens automatically ✓
    # No manual session management needed ✓
```

## Summary

The automatic session cleanup feature ensures reliable, repeatable test execution by:
- ✅ **Freeing ports** from previous test runs
- ✅ **Preventing conflicts** that cause test failures
- ✅ **Automating cleanup** so users don't have to remember
- ✅ **Providing control** via `--no-cleanup` flag when needed

This feature, combined with port availability checking, makes the test harness production-ready and suitable for CI/CD environments.

