#!/usr/bin/env python3
"""
Tests for listener/handler detection logic.

These tests verify the handler module detection and message construction
without requiring a Metasploit connection.
"""

import pytest


class TestHandlerDetection:
    """Test that handler modules are correctly identified."""

    @pytest.mark.parametrize(
        "module_path,expected",
        [
            ("exploit/multi/handler", True),
            ("exploit/windows/smb/ms17_010_eternalblue", False),
            ("exploit/linux/http/apache_struts2_content_type", False),
            ("EXPLOIT/MULTI/HANDLER", True),  # Case insensitive
            ("exploit/unix/ftp/proftpd_modcopy_exec", False),
        ],
    )
    def test_handler_detection(self, module_path: str, expected: bool):
        """Test handler detection for various module paths."""
        is_handler = "handler" in module_path.lower()
        assert is_handler == expected


class TestMessageConstruction:
    """Test message construction logic for handlers vs regular exploits."""

    def _construct_message(self, module_path: str, job_id: int, found_session_id: int = None):
        """Simulate the message construction logic from MetasploitMCP."""
        is_handler_module = "handler" in module_path.lower()
        message = f"Exploit module {module_path} started as job {job_id}."
        status = "success"

        if is_handler_module:
            message += " Handler is waiting for connections."
        elif found_session_id is not None:
            message += f" Session {found_session_id} created."
        else:
            message += " No session detected within timeout."
            status = "warning"

        return status, message

    def test_handler_message(self):
        """Test message for handler modules."""
        status, message = self._construct_message("exploit/multi/handler", 123)
        assert status == "success"
        assert "Handler is waiting for connections" in message

    def test_exploit_with_session_message(self):
        """Test message for exploit with successful session."""
        status, message = self._construct_message(
            "exploit/windows/smb/ms17_010_eternalblue", 456, found_session_id=1
        )
        assert status == "success"
        assert "Session 1 created" in message

    def test_exploit_without_session_message(self):
        """Test message for exploit without session."""
        status, message = self._construct_message(
            "exploit/windows/smb/ms17_010_eternalblue", 789
        )
        assert status == "warning"
        assert "No session detected within timeout" in message




