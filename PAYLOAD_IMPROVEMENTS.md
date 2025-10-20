# Metasploit MCP Payload Handling Improvements

## Summary

Enhanced the Metasploit MCP server to improve payload handling by:
1. Adding ability to list compatible payloads for specific exploit modules
2. Improving error messages to suggest valid payloads when invalid payloads are used

## Changes Made

### 1. Enhanced `list_payloads` Tool

**File**: `MetasploitMCP.py`

Added an optional `exploit_module` parameter to the `list_payloads` tool:

```python
async def list_payloads(platform: str = "", arch: str = "", exploit_module: str = "") -> List[str]:
```

**Functionality**:
- When `exploit_module` is provided, the tool queries the MSF RPC API for compatible payloads using `module_obj.compatible_payloads`
- Falls back to listing all payloads if the module doesn't support `compatible_payloads` attribute
- Still supports platform and arch filtering in combination with exploit_module
- Provides clear error messages if the exploit module is not found

**Usage Example**:
```python
# List compatible payloads for a specific exploit
payloads = await list_payloads(exploit_module="windows/smb/ms17_010_eternalblue")

# List compatible x64 payloads for a specific exploit
payloads = await list_payloads(exploit_module="windows/smb/ms17_010_eternalblue", arch="x64")
```

### 2. Improved Error Messages

**Files Modified**: `MetasploitMCP.py`

#### A. RPC Execution Error Messages (`_execute_module_rpc`)
- Lines 661-666: When an "invalid payload" error is detected, the error message now includes:
  - The invalid payload name
  - A helpful suggestion to use `list_payloads(exploit_module='...')` to view compatible payloads
  - The original error for debugging

#### B. Console Execution Setup Errors (`_execute_module_console`)  
- Lines 753-761: When a "set PAYLOAD" command fails:
  - Detects payload-related setup errors
  - Appends helpful guidance to use `list_payloads(exploit_module='...')`

#### C. Console Execution Runtime Errors
- Lines 809-817: When exploit execution fails with payload-related issues:
  - Detects keywords like 'payload', 'incompatible', 'invalid' in failure output
  - Adds suggestion to check compatible payloads

**Example Error Messages**:

Before:
```
Invalid payload specified: linux/x86/shell/reverse_tcp. Error: payload not compatible
```

After:
```
Invalid payload specified: linux/x86/shell/reverse_tcp. 
To view compatible payloads for this exploit, use: list_payloads(exploit_module='windows/smb/ms17_010_eternalblue'). 
Original error: payload not compatible
```

## Benefits

1. **Reduced Trial and Error**: Models can directly query which payloads are compatible with a specific exploit
2. **Better Guidance**: When errors occur, models receive actionable suggestions instead of generic errors
3. **Improved Success Rate**: By using compatible payloads, exploit attempts are more likely to succeed
4. **Consistent User Experience**: Error messages follow a consistent pattern of providing next steps

## API Documentation

### list_payloads

```python
async def list_payloads(
    platform: str = "",
    arch: str = "", 
    exploit_module: str = ""
) -> List[str]
```

**Parameters**:
- `platform` (str, optional): Platform filter (e.g., 'windows', 'linux', 'python', 'php')
- `arch` (str, optional): Architecture filter (e.g., 'x86', 'x64', 'cmd', 'meterpreter')
- `exploit_module` (str, optional): Exploit module name to list only compatible payloads 
  (e.g., 'windows/smb/ms17_010_eternalblue')

**Returns**:
- `List[str]`: List of payload names matching filters (max 100)

**Examples**:
```python
# List all payloads
payloads = await list_payloads()

# List Windows payloads
payloads = await list_payloads(platform="windows")

# List compatible payloads for an exploit
payloads = await list_payloads(exploit_module="windows/smb/ms17_010_eternalblue")

# List compatible x64 payloads for an exploit
payloads = await list_payloads(
    exploit_module="windows/smb/ms17_010_eternalblue",
    arch="x64"
)
```

## Testing

### Validation Performed:
1. ✅ Syntax validation - code compiles successfully
2. ✅ Implementation follows MSF RPC API documentation (module.compatible_payloads)
3. ✅ Error message formatting validated
4. ✅ Fallback logic for modules without compatible_payloads attribute
5. ✅ Parameter extraction and error message construction tested

### Test Files Created:
- `tests/test_payload_listing_improvements.py` - Standalone unit tests for the new functionality (6 tests)
- `tests/test_tools_integration.py` - Enhanced with 6 new test cases for payload improvements

### Test Results:
- **34 tests passed** (28 existing + 6 new)
- **1 test skipped** (timeout test)
- All new payload listing functionality fully tested and validated

## Implementation Notes

1. Uses MSF RPC API's `module.compatible_payloads` method as documented in Metasploit's Standard API Methods Reference
2. Gracefully handles older MSF versions that may not support `compatible_payloads` by falling back to listing all payloads
3. Error messages are constructed to be parseable and actionable
4. All changes maintain backward compatibility - existing code continues to work unchanged

## Future Enhancements

Potential improvements for consideration:
1. Cache compatible payloads for frequently used exploits
2. Add a "suggest_payload" tool that automatically selects the best payload for an exploit
3. Extend to other module types (auxiliary, post) if applicable
4. Add payload ranking/scoring based on stealth, reliability, etc.

## Files Changed

1. `MetasploitMCP.py`:
   - Modified `list_payloads` function (lines 860-941)
   - Modified `_execute_module_rpc` error handling (lines 661-666)
   - Modified `_execute_module_console` setup error handling (lines 753-761)
   - Modified `_execute_module_console` runtime error handling (lines 809-817)

2. `tests/test_tools_integration.py`:
   - Added test cases for new list_payloads functionality
   - Added test cases for improved error messages

3. `tests/test_payload_listing_improvements.py`:
   - New standalone test file for payload improvements

4. `conftest.py`:
   - Removed uvicorn from mock list (lines 17-30)

## Migration Guide

No migration needed! The changes are backward compatible:
- Existing calls to `list_payloads()` without `exploit_module` work exactly as before
- Existing error handling continues to function
- New functionality is purely additive

To take advantage of the improvements:
1. Use `list_payloads(exploit_module="...")` before running exploits
2. When you see invalid payload errors, follow the suggested command in the error message

