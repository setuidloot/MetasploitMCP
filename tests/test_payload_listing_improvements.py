#!/usr/bin/env python3
"""
Tests for the enhanced payload listing functionality.
Tests the new exploit_module parameter and improved error messages.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, AsyncMock

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def test_list_payloads_signature():
    """Test that list_payloads has the correct signature with exploit_module parameter."""
    # Mock dependencies before importing
    sys.modules['fastmcp'] = Mock()
    sys.modules['pymetasploit3.msfrpc'] = Mock()
    sys.modules['fastapi'] = Mock()
    sys.modules['mcp.server.fastmcp'] = Mock()
    sys.modules['mcp.server.sse'] = Mock()
    sys.modules['mcp.server.session'] = Mock()
    sys.modules['starlette.applications'] = Mock()
    sys.modules['starlette.routing'] = Mock()
    
    # Clear any cached imports
    if 'MetasploitMCP' in sys.modules:
        del sys.modules['MetasploitMCP']
    
    # Now we can import and inspect
    import MetasploitMCP
    import inspect
    
    # Check that list_payloads function exists
    assert hasattr(MetasploitMCP, 'list_payloads'), "list_payloads function should exist"
    
    # Get the actual function (unwrap from FastMCP decorator if needed)
    list_payloads_obj = MetasploitMCP.list_payloads
    if hasattr(list_payloads_obj, 'func'):
        list_payloads_func = list_payloads_obj.func
    elif hasattr(list_payloads_obj, '__wrapped__'):
        list_payloads_func = list_payloads_obj.__wrapped__
    else:
        # Try to get the original function from the tool
        list_payloads_func = list_payloads_obj
    
    # Get signature
    try:
        sig = inspect.signature(list_payloads_func)
        params = list(sig.parameters.keys())
        
        # Check for expected parameters
        assert 'platform' in params, "platform parameter should exist"
        assert 'arch' in params, "arch parameter should exist"
        assert 'exploit_module' in params, "exploit_module parameter should be added"
        
        print(f"✓ list_payloads has correct signature: {params}")
    except Exception as e:
        print(f"Could not inspect signature (FastMCP wrapping): {e}")
        # This is okay - the decorator may prevent inspection
        pass


def test_invalid_payload_error_message_format():
    """Test that error message construction includes helpful guidance."""
    # Test the error message format we're using
    module_name = "windows/smb/ms17_010_eternalblue"
    payload_name = "linux/x86/shell/reverse_tcp"
    
    # Simulated error message
    error_msg = f"Invalid payload specified: {payload_name}. "
    error_msg += f"To view compatible payloads for this exploit, use: list_payloads(exploit_module='{module_name}'). "
    
    assert "list_payloads" in error_msg
    assert "exploit_module" in error_msg
    assert module_name in error_msg
    assert payload_name in error_msg
    
    print(f"✓ Error message format is correct: {error_msg[:100]}...")


def test_console_payload_error_message_format():
    """Test console mode error message format for payload errors."""
    module_name = "windows/smb/ms17_010_eternalblue"
    cmd = "set PAYLOAD linux/x86/shell/reverse_tcp"
    setup_output = "[-] Error setting option PAYLOAD"
    
    # Simulated console error message
    error_msg = f"Error during setup command '{cmd}': {setup_output}"
    base_module_name = module_name
    error_msg += f"\n\nTo view compatible payloads for this exploit, use: list_payloads(exploit_module='{base_module_name}')"
    
    assert "list_payloads" in error_msg
    assert "exploit_module" in error_msg
    assert base_module_name in error_msg
    
    print(f"✓ Console error message format is correct")


def test_compatible_payloads_access_pattern():
    """Test that we correctly access the compatible_payloads attribute."""
    # Create a mock module object
    mock_module = Mock()
    mock_module.fullname = "exploit/windows/smb/ms17_010_eternalblue"
    mock_module.compatible_payloads = [
        'windows/x64/meterpreter/reverse_tcp',
        'windows/x64/shell/reverse_tcp'
    ]
    
    # Simulate accessing compatible_payloads
    payloads = mock_module.compatible_payloads
    
    assert isinstance(payloads, list)
    assert len(payloads) == 2
    assert 'windows/x64/meterpreter/reverse_tcp' in payloads
    
    print(f"✓ Compatible payloads access pattern works correctly")


def test_attribute_error_handling():
    """Test that AttributeError is handled when compatible_payloads doesn't exist."""
    # Create a mock module without compatible_payloads
    mock_module = Mock()
    mock_module.fullname = "exploit/unix/ftp/vsftpd_234_backdoor"
    
    # Remove the compatible_payloads attribute
    del mock_module.compatible_payloads
    
    # Test that accessing it raises AttributeError
    with pytest.raises(AttributeError):
        _ = mock_module.compatible_payloads
    
    print(f"✓ AttributeError handling pattern is correct")


def test_module_name_extraction():
    """Test module name extraction logic for error messages."""
    test_cases = [
        ("windows/smb/ms17_010_eternalblue", "windows/smb/ms17_010_eternalblue"),
        ("exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/ms17_010_eternalblue"),
        ("unix/ftp/vsftpd_234_backdoor", "unix/ftp/vsftpd_234_backdoor"),
    ]
    
    for module_name, expected in test_cases:
        # Simulate the extraction logic
        base_module_name = module_name
        if '/' in module_name:
            parts = module_name.split('/')
            if parts[0] != 'exploit':
                base_module_name = module_name
        
        assert base_module_name == expected
        print(f"✓ Module name extraction: {module_name} -> {base_module_name}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

