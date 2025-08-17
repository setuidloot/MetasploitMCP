#!/usr/bin/env python3
"""
Unit tests for the options parsing functionality in MetasploitMCP.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch
from typing import Dict, Any, Union

# Add the parent directory to the path to import MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock the dependencies that aren't available in test environment
sys.modules['uvicorn'] = Mock()
sys.modules['fastapi'] = Mock()
sys.modules['mcp.server.fastmcp'] = Mock()
sys.modules['mcp.server.sse'] = Mock()
sys.modules['pymetasploit3.msfrpc'] = Mock()
sys.modules['starlette.applications'] = Mock()
sys.modules['starlette.routing'] = Mock()
sys.modules['mcp.server.session'] = Mock()

# Import the function we want to test
from MetasploitMCP import _parse_options_gracefully


class TestParseOptionsGracefully:
    """Test cases for the _parse_options_gracefully function."""

    def test_dict_format_passthrough(self):
        """Test that dictionary format is passed through unchanged."""
        input_dict = {"LHOST": "192.168.1.100", "LPORT": 4444}
        result = _parse_options_gracefully(input_dict)
        assert result == input_dict
        assert result is input_dict  # Should be the same object

    def test_none_returns_empty_dict(self):
        """Test that None input returns empty dictionary."""
        result = _parse_options_gracefully(None)
        assert result == {}
        assert isinstance(result, dict)

    def test_empty_string_returns_empty_dict(self):
        """Test that empty string returns empty dictionary."""
        result = _parse_options_gracefully("")
        assert result == {}
        
        result = _parse_options_gracefully("   ")
        assert result == {}

    def test_empty_dict_returns_empty_dict(self):
        """Test that empty dictionary returns empty dictionary."""
        result = _parse_options_gracefully({})
        assert result == {}

    def test_simple_string_format(self):
        """Test basic string format parsing."""
        input_str = "LHOST=192.168.1.100,LPORT=4444"
        expected = {"LHOST": "192.168.1.100", "LPORT": 4444}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_string_format_with_spaces(self):
        """Test string format with extra spaces."""
        input_str = " LHOST = 192.168.1.100 , LPORT = 4444 "
        expected = {"LHOST": "192.168.1.100", "LPORT": 4444}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_string_format_with_quotes(self):
        """Test string format with quoted values."""
        input_str = 'LHOST="192.168.1.100",LPORT="4444"'
        expected = {"LHOST": "192.168.1.100", "LPORT": 4444}
        result = _parse_options_gracefully(input_str)
        assert result == expected

        input_str = "LHOST='192.168.1.100',LPORT='4444'"
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_boolean_conversion(self):
        """Test boolean value conversion."""
        input_str = "ExitOnSession=true,Verbose=false,Debug=TRUE,Silent=FALSE"
        expected = {
            "ExitOnSession": True, 
            "Verbose": False,
            "Debug": True,
            "Silent": False
        }
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_numeric_conversion(self):
        """Test numeric value conversion."""
        input_str = "LPORT=4444,Timeout=30,Retries=5"
        expected = {"LPORT": 4444, "Timeout": 30, "Retries": 5}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_mixed_types(self):
        """Test parsing with mixed value types."""
        input_str = "LHOST=192.168.1.100,LPORT=4444,SSL=true,Retries=3"
        expected = {
            "LHOST": "192.168.1.100",
            "LPORT": 4444,
            "SSL": True,
            "Retries": 3
        }
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_equals_in_value(self):
        """Test parsing when value contains equals sign."""
        input_str = "LURI=/test=value,LHOST=192.168.1.1"
        expected = {"LURI": "/test=value", "LHOST": "192.168.1.1"}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_complex_values(self):
        """Test parsing complex values like file paths and URLs."""
        input_str = "CertFile=/path/to/cert.pem,URL=https://example.com:8443/api,Command=ls -la"
        expected = {
            "CertFile": "/path/to/cert.pem",
            "URL": "https://example.com:8443/api",
            "Command": "ls -la"
        }
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_single_option(self):
        """Test parsing single option."""
        input_str = "LHOST=192.168.1.100"
        expected = {"LHOST": "192.168.1.100"}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_error_missing_equals(self):
        """Test error handling for missing equals sign."""
        with pytest.raises(ValueError, match="missing '='"):
            _parse_options_gracefully("LHOST192.168.1.100")

        with pytest.raises(ValueError, match="missing '='"):
            _parse_options_gracefully("LHOST=192.168.1.100,LPORT4444")

    def test_error_empty_key(self):
        """Test error handling for empty key."""
        with pytest.raises(ValueError, match="empty key"):
            _parse_options_gracefully("=value")

        with pytest.raises(ValueError, match="empty key"):
            _parse_options_gracefully("LHOST=192.168.1.100,=4444")

    def test_error_invalid_type(self):
        """Test error handling for invalid input types."""
        with pytest.raises(ValueError, match="Options must be a dictionary"):
            _parse_options_gracefully(123)

        with pytest.raises(ValueError, match="Options must be a dictionary"):
            _parse_options_gracefully([1, 2, 3])

    def test_whitespace_handling(self):
        """Test various whitespace scenarios."""
        # Leading/trailing spaces in whole string
        result = _parse_options_gracefully("  LHOST=192.168.1.100,LPORT=4444  ")
        expected = {"LHOST": "192.168.1.100", "LPORT": 4444}
        assert result == expected

        # Spaces around commas
        result = _parse_options_gracefully("LHOST=192.168.1.100 , LPORT=4444")
        assert result == expected

        # Multiple spaces
        result = _parse_options_gracefully("LHOST=192.168.1.100,  LPORT=4444")
        assert result == expected

    def test_edge_case_empty_value(self):
        """Test handling of empty values."""
        input_str = "LHOST=192.168.1.100,EmptyValue="
        expected = {"LHOST": "192.168.1.100", "EmptyValue": ""}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_quoted_empty_value(self):
        """Test handling of quoted empty values."""
        input_str = 'LHOST=192.168.1.100,EmptyValue=""'
        expected = {"LHOST": "192.168.1.100", "EmptyValue": ""}
        result = _parse_options_gracefully(input_str)
        assert result == expected

    def test_special_characters_in_values(self):
        """Test handling of special characters in values."""
        input_str = "Password=p@ssw0rd!,Path=/home/user/file.txt,Regex=\\d+"
        expected = {
            "Password": "p@ssw0rd!",
            "Path": "/home/user/file.txt",
            "Regex": "\\d+"
        }
        result = _parse_options_gracefully(input_str)
        assert result == expected

    @pytest.mark.parametrize("input_val,expected", [
        # Basic cases
        ({"key": "value"}, {"key": "value"}),
        ("key=value", {"key": "value"}),
        (None, {}),
        ("", {}),
        
        # Type conversions
        ("port=8080", {"port": 8080}),
        ("enabled=true", {"enabled": True}),
        ("disabled=false", {"disabled": False}),
        
        # Complex cases
        ("a=1,b=true,c=text", {"a": 1, "b": True, "c": "text"}),
    ])
    def test_parametrized_cases(self, input_val, expected):
        """Parametrized test cases for various inputs."""
        result = _parse_options_gracefully(input_val)
        assert result == expected

    def test_large_number_handling(self):
        """Test handling of large numbers that might not fit in int."""
        # Python can handle very large integers, so use a string that definitely isn't a number
        mixed_num = "999999999999999999999abc"
        input_str = f"BigNumber={mixed_num}"
        result = _parse_options_gracefully(input_str)
        # The function tries int conversion but falls back to string on error
        assert result["BigNumber"] == mixed_num
        assert isinstance(result["BigNumber"], str)

    def test_logging_behavior(self):
        """Test that logging occurs during string conversion."""
        with patch('MetasploitMCP.logger') as mock_logger:
            _parse_options_gracefully("LHOST=192.168.1.100,LPORT=4444")
            # Should log the conversion
            assert mock_logger.info.call_count >= 1
            
            # Should contain conversion messages
            call_args = [call[0][0] for call in mock_logger.info.call_args_list]
            assert any("Converting string format" in msg for msg in call_args)
            assert any("Successfully converted" in msg for msg in call_args)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
