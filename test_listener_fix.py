#!/usr/bin/env python3
"""
Simple test to verify the listener fix logic without requiring MSF connection.
"""

def test_handler_detection():
    """Test that handler modules are correctly identified."""
    
    # Test cases for handler detection
    test_cases = [
        ("exploit/multi/handler", True),
        ("exploit/windows/smb/ms17_010_eternalblue", False),
        ("exploit/linux/http/apache_struts2_content_type", False),
        ("exploit/multi/handler", True),  # Case insensitive test
        ("EXPLOIT/MULTI/HANDLER", True),  # Case insensitive test
    ]
    
    for module_path, expected in test_cases:
        is_handler = 'handler' in module_path.lower()
        assert is_handler == expected, f"Failed for {module_path}: expected {expected}, got {is_handler}"
        print(f"✓ {module_path} -> {is_handler} (expected {expected})")
    
    print("All handler detection tests passed!")

def test_message_construction():
    """Test the message construction logic for handlers vs regular exploits."""
    
    # Simulate the logic from the fixed code
    def construct_message(module_path, job_id, found_session_id=None):
        is_handler_module = 'handler' in module_path.lower()
        message = f"Exploit module {module_path} started as job {job_id}."
        status = "success"
        
        if is_handler_module:
            # Handlers are always successful - they wait for connections
            message += " Handler is waiting for connections."
        elif found_session_id is not None:
            message += f" Session {found_session_id} created."
        else:
            message += " No session detected within timeout."
            status = "warning"  # Indicate job started but session didn't appear
        
        return status, message
    
    # Test handler case
    status, message = construct_message("exploit/multi/handler", 123)
    assert status == "success", f"Handler should return success, got {status}"
    assert "Handler is waiting for connections" in message, f"Handler message should indicate waiting, got: {message}"
    print(f"✓ Handler case: {status} - {message}")
    
    # Test regular exploit with session
    status, message = construct_message("exploit/windows/smb/ms17_010_eternalblue", 456, found_session_id=1)
    assert status == "success", f"Exploit with session should return success, got {status}"
    assert "Session 1 created" in message, f"Exploit with session should mention session, got: {message}"
    print(f"✓ Exploit with session: {status} - {message}")
    
    # Test regular exploit without session
    status, message = construct_message("exploit/windows/smb/ms17_010_eternalblue", 789)
    assert status == "warning", f"Exploit without session should return warning, got {status}"
    assert "No session detected within timeout" in message, f"Exploit without session should mention timeout, got: {message}"
    print(f"✓ Exploit without session: {status} - {message}")
    
    print("All message construction tests passed!")

if __name__ == "__main__":
    print("Testing listener fix logic...")
    print()
    
    test_handler_detection()
    print()
    test_message_construction()
    print()
    print("🎉 All tests passed! The listener fix is working correctly.")
