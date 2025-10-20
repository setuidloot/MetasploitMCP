# Test Infrastructure Fixes

## Summary

Fixed the test infrastructure to work properly with FastMCP 2.x and resolved module import conflicts that were preventing tests from running.

## Problems Fixed

### 1. **FastMCP Decorator Wrapping**
**Problem**: FastMCP 2.x wraps tool functions in `FunctionTool` objects, making them not directly callable in tests.

**Solution**: Created an `unwrap_tool()` helper function that extracts the underlying callable from FastMCP decorators:

```python
def unwrap_tool(tool_obj):
    """Unwrap a FastMCP tool to get the underlying function."""
    for attr in ['func', '__wrapped__', '_func', 'fn']:
        if hasattr(tool_obj, attr):
            return getattr(tool_obj, attr)
    if callable(tool_obj):
        return tool_obj
    return tool_obj
```

### 2. **Module Mocking Conflicts**
**Problem**: `conftest.py` was mocking FastMCP and uvicorn, which are now proper dependencies, causing import errors.

**Solution**: Simplified conftest.py to only mock what's truly unavailable (pymetasploit3):

```python
def pytest_configure(config):
    """Configure pytest with custom settings."""
    # We only mock pymetasploit3 since other dependencies (fastmcp, uvicorn, etc.) 
    # are now proper installed dependencies
    mock_modules = ['pymetasploit3.msfrpc']
    
    for module in mock_modules:
        if module not in sys.modules:
            sys.modules[module] = Mock()
```

### 3. **Premature Module Import**
**Problem**: `reset_msf_client` fixture was trying to import MetasploitMCP before mocks were set up.

**Solution**: Made the fixture conditional:

```python
@pytest.fixture(autouse=True)
def reset_msf_client():
    """Automatically reset the global MSF client between tests."""
    # Only patch if MetasploitMCP is already imported
    if 'MetasploitMCP' in sys.modules:
        with patch.object(sys.modules['MetasploitMCP'], '_msf_client_instance', None):
            yield
    else:
        yield
```

### 4. **Missing Mock Client in New Tests**
**Problem**: New payload listing tests weren't providing the required `get_msf_client` mock.

**Solution**: Added proper client mocking to each test:

```python
@pytest.mark.asyncio
async def test_list_payloads_with_exploit_module(self, mock_asyncio_to_thread):
    """Test listing payloads compatible with an exploit module."""
    # Create mock client
    client = MockMsfRpcClient()
    
    with patch('MetasploitMCP.get_msf_client', return_value=client):
        # ... test code
```

## Files Modified

### 1. `/Users/setuidloot/Repos/MetasploitMCP/conftest.py`
- Removed FastMCP, uvicorn, fastapi, starlette from mock list
- Only mock pymetasploit3.msfrpc (unavailable dependency)
- Made `reset_msf_client` fixture conditional on module import

### 2. `/Users/setuidloot/Repos/MetasploitMCP/tests/test_tools_integration.py`
- Added `unwrap_tool()` helper function
- Updated all tool function references to use unwrapping
- Fixed 4 new payload listing tests to properly mock `get_msf_client`
- Removed obsolete FastMCP/uvicorn mocking code

### 3. `/Users/setuidloot/Repos/MetasploitMCP/tests/test_payload_listing_improvements.py`
- Standalone test file for payload improvements
- All 6 tests passing

## Test Results

### Before Fixes:
- 0 tests running (all failed during collection)
- Import errors: `ModuleNotFoundError: No module named 'uvicorn.server'`
- Type errors: `TypeError: 'FunctionTool' object is not callable`

### After Fixes:
```
================================ test session starts =================================
collected 35 items

tests/test_tools_integration.py::TestExploitListingTools::test_list_exploits_no_filter PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_exploits_with_filter PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_exploits_error PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_exploits_timeout SKIPPED
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_no_filter PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_platform_filter PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_arch_filter PASSED
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_exploit_module PASSED ✨
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_exploit_module_and_filters PASSED ✨
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_invalid_exploit_module PASSED ✨
tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_exploit_module_no_compatible_payloads_attr PASSED ✨
... (all other tests)
tests/test_payload_listing_improvements.py::test_list_payloads_signature PASSED ✨
tests/test_payload_listing_improvements.py::test_invalid_payload_error_message_format PASSED ✨
tests/test_payload_listing_improvements.py::test_console_payload_error_message_format PASSED ✨
tests/test_payload_listing_improvements.py::test_compatible_payloads_access_pattern PASSED ✨
tests/test_payload_listing_improvements.py::test_attribute_error_handling PASSED ✨
tests/test_payload_listing_improvements.py::test_module_name_extraction PASSED ✨

================== 34 passed, 1 skipped, 2 warnings in 3.87s ===================
```

✨ = New tests added for payload improvements

## Key Learnings

1. **FastMCP 2.x wraps tools**: Always unwrap decorated functions in tests
2. **Mock only what's unavailable**: Don't mock installed dependencies
3. **Order matters**: Set up mocks before importing modules that use them
4. **Pytest caches modules**: Clear cache when debugging import issues
5. **Fixtures should be defensive**: Check if modules exist before patching

## Testing Guidelines

### Running Tests:
```bash
# Run all integration tests
poetry run pytest tests/test_tools_integration.py -v

# Run new payload improvements tests
poetry run pytest tests/test_payload_listing_improvements.py -v

# Run specific test
poetry run pytest tests/test_tools_integration.py::TestExploitListingTools::test_list_payloads_with_exploit_module -v

# Clear cache if needed
rm -rf .pytest_cache __pycache__ tests/__pycache__
```

### Writing New Tests:
1. Always provide `mock_asyncio_to_thread` fixture
2. Mock `get_msf_client` with a `MockMsfRpcClient` instance
3. Use `unwrap_tool()` to get the actual function from FastMCP tools
4. Mock module-specific dependencies as needed

### Example Test Pattern:
```python
@pytest.mark.asyncio
async def test_your_feature(self, mock_asyncio_to_thread):
    """Test description."""
    # Create mock client
    client = MockMsfRpcClient()
    
    # Setup mocks
    with patch('MetasploitMCP.get_msf_client', return_value=client):
        # Call the unwrapped tool function
        result = await your_tool_function(param="value")
    
    # Assertions
    assert result["status"] == "success"
```

## Warnings

Two pytest warnings about unregistered markers:
- `pytest.mark.integration`
- `pytest.mark.slow`

These can be registered in `pytest.ini` if desired:
```ini
[pytest]
markers =
    integration: marks tests as integration tests
    slow: marks tests as slow running
```

## Impact

- ✅ All existing tests continue to pass
- ✅ 6 new tests for payload improvements pass
- ✅ Test infrastructure is now compatible with FastMCP 2.x
- ✅ Cleaner mocking strategy (only mock what's unavailable)
- ✅ More maintainable test code

## Next Steps

1. Consider adding the markers to pytest.ini to eliminate warnings
2. Consider refactoring other test files (test_helpers.py, test_options_parsing.py, test_ip_validation.py) to use the new mocking strategy if they have similar issues
3. Add more integration tests as new features are developed

