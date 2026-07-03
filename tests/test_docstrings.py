"""
Test suite for verifying docstring quality and content for model guidance.

This test ensures that critical functions have proper docstrings with clear
guidance to prevent common usage errors (e.g., duplicate listeners).
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path to import the module
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the module to test
import metasploit_mcp.server as MetasploitMCP


def get_function_description(func):
    """Helper to get description from FunctionTool or regular function."""
    if hasattr(func, "description"):
        return func.description
    return func.__doc__


class TestDocstringContent:
    """Test that docstrings contain critical guidance for AI models."""

    def test_run_exploit_docstring_exists(self):
        """Verify run_exploit has a docstring."""
        docstring = get_function_description(MetasploitMCP.run_exploit)
        assert docstring is not None
        assert len(docstring) > 100

    def test_run_exploit_warns_about_automatic_listener(self):
        """Verify run_exploit docstring warns that it creates listeners automatically."""
        docstring = get_function_description(MetasploitMCP.run_exploit)

        # Check for key warning phrases
        assert (
            "AUTOMATICALLY" in docstring.upper()
        ), "Docstring should emphasize automatic listener creation"
        assert (
            "listener" in docstring.lower() or "handler" in docstring.lower()
        ), "Docstring should mention listeners/handlers"
        assert (
            "DO NOT" in docstring.upper() or "DON'T" in docstring.upper()
        ), "Docstring should have strong warning language"

    def test_run_exploit_has_usage_examples(self):
        """Verify run_exploit docstring includes correct/incorrect usage examples."""
        docstring = get_function_description(MetasploitMCP.run_exploit)

        # Should have example sections
        assert (
            "EXAMPLE" in docstring.upper() or "Example" in docstring
        ), "Docstring should include usage examples"
        assert (
            "CORRECT" in docstring.upper() or "Correct" in docstring
        ), "Docstring should show correct usage"
        assert (
            "INCORRECT" in docstring.upper()
            or "Incorrect" in docstring
            or "DON'T" in docstring.upper()
        ), "Docstring should show incorrect usage or anti-patterns"

    def test_run_exploit_explains_when_to_use_start_listener(self):
        """Verify run_exploit explains when start_listener is appropriate."""
        docstring = get_function_description(MetasploitMCP.run_exploit)

        # Should explain the relationship
        assert (
            "start_listener" in docstring.lower()
        ), "Docstring should mention start_listener function"
        assert "when" in docstring.lower(), "Docstring should explain when to use each function"

    def test_start_listener_docstring_exists(self):
        """Verify start_listener has a docstring."""
        docstring = get_function_description(MetasploitMCP.start_listener)
        assert docstring is not None
        assert len(docstring) > 100

    def test_start_listener_warns_about_run_exploit_conflict(self):
        """Verify start_listener docstring warns about conflicts with run_exploit."""
        docstring = get_function_description(MetasploitMCP.start_listener)

        # Check for key warning phrases
        assert "run_exploit" in docstring.lower(), "Docstring should mention run_exploit"
        assert (
            "DO NOT" in docstring.upper() or "DON'T" in docstring.upper()
        ), "Docstring should have strong warning language"
        assert (
            "conflict" in docstring.lower() or "port" in docstring.lower()
        ), "Docstring should mention conflicts or port issues"

    def test_start_listener_lists_valid_use_cases(self):
        """Verify start_listener docstring lists when it should be used."""
        docstring = get_function_description(MetasploitMCP.start_listener)

        # Should have clear use cases
        assert (
            "USE" in docstring.upper() and "ONLY" in docstring.upper()
        ), "Docstring should specify when to use this function"
        assert (
            "generate_payload" in docstring.lower()
        ), "Docstring should mention generate_payload as a valid use case"

    def test_start_listener_has_usage_examples(self):
        """Verify start_listener docstring includes correct/incorrect usage examples."""
        docstring = get_function_description(MetasploitMCP.start_listener)

        # Should have example sections
        assert (
            "EXAMPLE" in docstring.upper() or "Example" in docstring
        ), "Docstring should include usage examples"
        assert (
            "CORRECT" in docstring.upper() or "Correct" in docstring
        ), "Docstring should show correct usage"
        assert (
            "INCORRECT" in docstring.upper() or "Incorrect" in docstring
        ), "Docstring should show incorrect usage"

    def test_generate_payload_docstring_exists(self):
        """Verify generate_payload has a docstring."""
        docstring = get_function_description(MetasploitMCP.generate_payload)
        assert docstring is not None
        assert len(docstring) > 100

    def test_generate_payload_mentions_listener_requirement(self):
        """Verify generate_payload docstring mentions need for listener."""
        docstring = get_function_description(MetasploitMCP.generate_payload)

        # Should mention that you need to start a listener
        assert "start_listener" in docstring.lower(), "Docstring should mention start_listener"
        assert (
            "listener" in docstring.lower() or "handler" in docstring.lower()
        ), "Docstring should mention listeners/handlers"
        assert (
            "must" in docstring.lower() or "requirement" in docstring.lower()
        ), "Docstring should emphasize the requirement"

    def test_generate_payload_has_workflow_guidance(self):
        """Verify generate_payload docstring includes workflow steps."""
        docstring = get_function_description(MetasploitMCP.generate_payload)

        # Should have workflow or steps
        assert (
            "WORKFLOW" in docstring.upper() or "EXAMPLE" in docstring.upper()
        ), "Docstring should include workflow or example"
        assert "1" in docstring and "2" in docstring, "Docstring should have numbered steps"

    def test_list_listeners_docstring_exists(self):
        """Verify list_listeners has a docstring."""
        docstring = get_function_description(MetasploitMCP.list_listeners)
        assert docstring is not None
        assert len(docstring) > 50

    def test_list_listeners_explains_purpose(self):
        """Verify list_listeners docstring explains what it returns."""
        docstring = get_function_description(MetasploitMCP.list_listeners)

        # Should explain what it returns
        assert "handlers" in docstring.lower(), "Docstring should mention handlers"
        assert "jobs" in docstring.lower(), "Docstring should mention jobs"


class TestDocstringConsistency:
    """Test that docstrings are consistent with function signatures."""

    def test_run_exploit_parameters_documented(self):
        """Verify all run_exploit parameters are documented."""
        docstring = get_function_description(MetasploitMCP.run_exploit)

        # Check that key parameters are mentioned in docstring
        assert "module" in docstring, "module parameter should be documented"
        assert "payload" in docstring, "payload parameter should be documented"
        assert "payload_options" in docstring, "payload_options parameter should be documented"

    def test_start_listener_parameters_documented(self):
        """Verify all start_listener parameters are documented."""
        docstring = get_function_description(MetasploitMCP.start_listener)

        # Check that key parameters are mentioned in docstring
        assert "payload" in docstring, "payload parameter should be documented"
        assert "lhost" in docstring, "lhost parameter should be documented"
        assert "lport" in docstring, "lport parameter should be documented"

    def test_generate_payload_parameters_documented(self):
        """Verify all generate_payload parameters are documented."""
        docstring = get_function_description(MetasploitMCP.generate_payload)

        # Check that key parameters are mentioned in docstring
        assert "payload" in docstring, "payload parameter should be documented"
        assert "format" in docstring, "format parameter should be documented"
        assert "options" in docstring, "options parameter should be documented"


class TestDocstringQuality:
    """Test overall docstring quality metrics."""

    def test_critical_functions_have_substantial_docstrings(self):
        """Verify critical functions have substantial documentation."""
        critical_functions = [
            ("run_exploit", MetasploitMCP.run_exploit),
            ("start_listener", MetasploitMCP.start_listener),
            ("generate_payload", MetasploitMCP.generate_payload),
        ]

        for func_name, func in critical_functions:
            docstring = get_function_description(func)
            assert docstring is not None, f"{func_name} must have a docstring"
            assert (
                len(docstring) > 300
            ), f"{func_name} docstring should be substantial (>300 chars), got {len(docstring)}"

    def test_docstrings_have_proper_sections(self):
        """Verify docstrings have expected sections."""
        critical_functions = [
            ("run_exploit", MetasploitMCP.run_exploit),
            ("start_listener", MetasploitMCP.start_listener),
            ("generate_payload", MetasploitMCP.generate_payload),
        ]

        for func_name, func in critical_functions:
            docstring = get_function_description(func)
            # Should have Args section
            assert (
                "Args:" in docstring or "Parameters:" in docstring
            ), f"{func_name} docstring should have Args/Parameters section"
            # Should have Returns section
            assert (
                "Returns:" in docstring or "Return:" in docstring
            ), f"{func_name} docstring should have Returns section"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
