#!/usr/bin/env python3
"""
Unit tests for describe_module and get_module_documentation tools.

These tools help agents understand Metasploit modules BEFORE using them,
reducing errors from incorrect option usage.
"""

import pytest
import sys
import os
import asyncio
import tempfile
import pathlib
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from typing import Dict, Any

# Add the parent directory to the path to import metasploit_mcp.server as MetasploitMCP
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# Create mock classes for MSF objects
class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()

    def call(self, method, args):
        """Mock RPC call method."""
        return {}


class MockMsfRpcError(Exception):
    pass


class TestDescribeModule:
    """Tests for the describe_module MCP tool."""

    @pytest.fixture
    def sample_module_info(self):
        """Sample module info response from MSF RPC."""
        return {
            "name": "ProFTPD 1.3.5 Mod_Copy Command Execution",
            "description": "This module exploits the SITE CPFR/CPTO mod_copy commands in ProFTPD version 1.3.5.",
            "authors": ["Vadim Melihow", "xistence <xistence[at]0x90.nl>"],
            "references": [
                ["CVE", "2015-3306"],
                ["EDB", "36742"],
                ["URL", "http://bugs.proftpd.org/show_bug.cgi?id=4169"],
            ],
            "platform": ["unix"],
            "arch": ["cmd"],
            "rank": "excellent",
            "privileged": False,
            "disclosure_date": "2015-04-22",
            "default_target": 0,
            "targets": [["ProFTPD 1.3.5", {}]],
            "notes": {
                "Stability": ["CRASH_SAFE"],
                "Reliability": ["REPEATABLE_SESSION"],
                "SideEffects": ["ARTIFACTS_ON_DISK", "IOC_IN_LOGS"],
            },
        }

    @pytest.fixture
    def sample_options(self):
        """Sample module options response."""
        return {
            "RHOSTS": {
                "type": "address",
                "required": True,
                "default": None,
                "desc": "The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html",
            },
            "RPORT": {"type": "port", "required": True, "default": 80, "desc": "HTTP port"},
            "RPORT_FTP": {"type": "port", "required": True, "default": 21, "desc": "FTP port"},
            "TARGETURI": {
                "type": "string",
                "required": True,
                "default": "/",
                "desc": "Base path to the website",
            },
            "SITEPATH": {
                "type": "string",
                "required": True,
                "default": "/var/www",
                "desc": "Absolute writable website path",
            },
        }

    @pytest.mark.asyncio
    async def test_describe_module_success(self, sample_module_info, sample_options):
        """Test successful module description retrieval."""
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        # Mock client.call to return different values based on the RPC method
        def mock_call(method, args):
            if method == "module.info":
                return sample_module_info
            elif method == "module.options":
                return sample_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("unix/ftp/proftpd_modcopy_exec", "exploit")

        assert result["status"] == "success"
        assert result["name"] == "ProFTPD 1.3.5 Mod_Copy Command Execution"
        assert result["full_path"] == "exploit/unix/ftp/proftpd_modcopy_exec"
        assert "RHOSTS" in result["options"]
        assert result["options"]["RHOSTS"]["required"] is True
        assert result["options"]["RPORT"]["default"] == 80
        assert len(result["references"]) == 3
        assert result["notes"]["stability"] == ["CRASH_SAFE"]
        assert result["notes"]["side_effects"] == ["ARTIFACTS_ON_DISK", "IOC_IN_LOGS"]

    @pytest.mark.asyncio
    async def test_describe_module_with_full_path(self, sample_module_info, sample_options):
        """Test describe_module when full path is provided (exploit/...)."""
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        # Mock client.call to return different values based on the RPC method
        def mock_call(method, args):
            if method == "module.info":
                return sample_module_info
            elif method == "module.options":
                return sample_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            # Provide full path with exploit/ prefix
            result = await describe_module("exploit/unix/ftp/proftpd_modcopy_exec", "auxiliary")

        # Should extract type from path and use it
        assert result["status"] == "success"
        assert result["full_path"] == "exploit/unix/ftp/proftpd_modcopy_exec"

    @pytest.mark.asyncio
    async def test_describe_module_not_found(self):
        """Test describe_module when module is not found."""
        from metasploit_mcp.server import describe_module, _find_similar_modules

        mock_client = MockMsfRpcClient()
        mock_client.call = Mock(return_value=False)
        mock_client.modules.exploits = ["windows/smb/ms17_010_eternalblue"]

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            with patch(
                "metasploit_mcp.server._find_similar_modules",
                new_callable=AsyncMock,
                return_value=[],
            ):
                result = await describe_module("nonexistent/module", "exploit")

        assert result["status"] == "not_found"
        assert "not found" in result["message"].lower()
        assert "suggestions" in result

    @pytest.mark.asyncio
    async def test_describe_module_error_response(self):
        """Test describe_module when MSF returns an error."""
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()
        mock_client.call = Mock(
            return_value={
                "error": True,
                "error_message": "Invalid module",
                "error_class": "Msf::RPC::Exception",
            }
        )

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            with patch(
                "metasploit_mcp.server._find_similar_modules",
                new_callable=AsyncMock,
                return_value=[],
            ):
                result = await describe_module("invalid/module", "exploit")

        assert result["status"] == "error"
        assert "Invalid module" in result["message"]

    @pytest.mark.asyncio
    async def test_describe_module_timeout(self):
        """Test describe_module handles timeout gracefully."""
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                result = await describe_module("some/module", "exploit")

        assert result["status"] == "error"
        assert "timeout" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_describe_module_auxiliary(self):
        """Test describe_module for auxiliary modules."""
        from metasploit_mcp.server import describe_module

        aux_info = {
            "name": "SMB Version Detection",
            "description": "Displays version information about each SMB server.",
            "authors": ["Test Author"],
            "references": [],
            "platform": [],
            "arch": [],
            "rank": "normal",
        }

        aux_options = {"RHOSTS": {"type": "address", "required": True, "desc": "Target hosts"}}

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return aux_info
            elif method == "module.options":
                return aux_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("scanner/smb/smb_version", "auxiliary")

        assert result["status"] == "success"
        assert result["full_path"] == "auxiliary/scanner/smb/smb_version"

    @pytest.mark.asyncio
    async def test_describe_module_payload(self):
        """Test describe_module for payload modules."""
        from metasploit_mcp.server import describe_module

        payload_info = {
            "name": "Linux Meterpreter Reverse TCP",
            "description": "Inject the meterpreter server payload (stageless).",
            "authors": ["Test Author"],
            "references": [],
            "platform": ["linux"],
            "arch": ["x64"],
        }

        payload_options = {
            "LHOST": {"type": "address", "required": True, "desc": "Listen address"},
            "LPORT": {"type": "port", "required": True, "default": 4444, "desc": "Listen port"},
        }

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return payload_info
            elif method == "module.options":
                return payload_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("linux/x64/meterpreter_reverse_tcp", "payload")

        assert result["status"] == "success"
        assert "LHOST" in result["options"]
        assert result["options"]["LPORT"]["default"] == 4444

    @pytest.mark.asyncio
    async def test_describe_module_options_parsing(self, sample_module_info):
        """Test that options are properly structured."""
        from metasploit_mcp.server import describe_module

        test_options = {
            "SSL": {"type": "bool", "required": False, "default": False, "desc": "Use SSL"},
            "VERBOSE": {"type": "bool", "required": False, "default": True, "desc": "Be verbose"},
            "ACTION": {
                "type": "enum",
                "required": False,
                "enums": ["CHECK", "EXPLOIT"],
                "desc": "Action to take",
            },
        }

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return sample_module_info
            elif method == "module.options":
                return test_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "success"
        assert result["options"]["SSL"]["type"] == "bool"
        assert result["options"]["SSL"]["required"] is False
        assert result["options"]["ACTION"]["enums"] == ["CHECK", "EXPLOIT"]


class TestGetModuleDocumentation:
    """Tests for the get_module_documentation MCP tool."""

    @pytest.fixture
    def temp_docs_dir(self):
        """Create a temporary documentation directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = pathlib.Path(tmpdir)

            # Create directory structure
            (docs_path / "exploit" / "unix" / "ftp").mkdir(parents=True)
            (docs_path / "exploit" / "windows" / "smb").mkdir(parents=True)
            (docs_path / "auxiliary" / "scanner" / "http").mkdir(parents=True)

            # Create sample documentation files
            proftpd_doc = docs_path / "exploit" / "unix" / "ftp" / "proftpd_modcopy_exec.md"
            proftpd_doc.write_text(
                """# ProFTPD mod_copy Command Execution

## Description

This module exploits the SITE CPFR/CPTO mod_copy commands in ProFTPD version 1.3.5.

## Vulnerable Application

ProFTPD 1.3.5 with mod_copy enabled (default).

## Verification Steps

1. Start msfconsole
2. `use exploit/unix/ftp/proftpd_modcopy_exec`
3. Set RHOSTS, SITEPATH, and TARGETURI
4. Run the exploit

## Scenarios

### ProFTPD 1.3.5 on Ubuntu

```
msf6 > use exploit/unix/ftp/proftpd_modcopy_exec
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set RHOSTS 192.168.1.10
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > set SITEPATH /var/www/html
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > run
```
"""
            )

            eternalblue_doc = docs_path / "exploit" / "windows" / "smb" / "ms17_010_eternalblue.md"
            eternalblue_doc.write_text(
                """# MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption

## Description

This module exploits the MS17-010 vulnerability in SMBv1.

## Options

- **RHOSTS** - Target IP address
- **RPORT** - Target port (default: 445)
"""
            )

            http_version_doc = docs_path / "auxiliary" / "scanner" / "http" / "http_version.md"
            http_version_doc.write_text(
                """# HTTP Version Scanner

Displays version information about target HTTP servers.
"""
            )

            yield docs_path

    @pytest.mark.asyncio
    async def test_get_documentation_success(self, temp_docs_dir):
        """Test successful documentation retrieval."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            result = await get_module_documentation("exploit/unix/ftp/proftpd_modcopy_exec")

        assert result["status"] == "success"
        assert "ProFTPD mod_copy" in result["documentation"]
        assert "RHOSTS" in result["documentation"]
        assert "Verification Steps" in result["documentation"]

    @pytest.mark.asyncio
    async def test_get_documentation_without_type_prefix(self, temp_docs_dir):
        """Test documentation retrieval without type prefix (tries all types)."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            # Should find it by trying exploit/ prefix
            result = await get_module_documentation("windows/smb/ms17_010_eternalblue")

        assert result["status"] == "success"
        assert "EternalBlue" in result["documentation"]

    @pytest.mark.asyncio
    async def test_get_documentation_not_found(self, temp_docs_dir):
        """Test documentation not found scenario."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            result = await get_module_documentation("exploit/nonexistent/module")

        assert result["status"] == "not_found"
        assert result["documentation"] is None
        assert "suggestions" in result

    @pytest.mark.asyncio
    async def test_get_documentation_with_suggestions(self, temp_docs_dir):
        """Test that similar documentation files are suggested when exact match not found."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            # Search for something close to proftpd
            result = await get_module_documentation("exploit/unix/ftp/proftpd")

        assert result["status"] == "not_found"
        # Should suggest the actual proftpd_modcopy_exec.md
        assert len(result["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_get_documentation_dir_not_exists(self):
        """Test when documentation directory doesn't exist."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", "/nonexistent/path"):
            result = await get_module_documentation("any/module")

        assert result["status"] == "not_available"
        assert "not installed" in result["message"].lower()
        assert result["documentation"] is None

    @pytest.mark.asyncio
    async def test_get_documentation_auxiliary_module(self, temp_docs_dir):
        """Test documentation retrieval for auxiliary modules."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            result = await get_module_documentation("auxiliary/scanner/http/http_version")

        assert result["status"] == "success"
        assert "HTTP Version Scanner" in result["documentation"]

    @pytest.mark.asyncio
    async def test_get_documentation_normalizes_path(self, temp_docs_dir):
        """Test that paths are properly normalized."""
        from metasploit_mcp.server import get_module_documentation

        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            # Test with leading/trailing slashes
            result = await get_module_documentation("/exploit/unix/ftp/proftpd_modcopy_exec/")

        assert result["status"] == "success"


class TestFindSimilarDocumentationFiles:
    """Tests for the _find_similar_documentation_files helper function."""

    @pytest.fixture
    def temp_docs_dir(self):
        """Create a temporary documentation directory with sample files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = pathlib.Path(tmpdir)

            # Create directory structure
            (docs_path / "exploit" / "windows" / "smb").mkdir(parents=True)
            (docs_path / "exploit" / "linux" / "http").mkdir(parents=True)
            (docs_path / "auxiliary" / "scanner" / "smb").mkdir(parents=True)

            # Create sample files
            (docs_path / "exploit" / "windows" / "smb" / "ms17_010_eternalblue.md").write_text(
                "test"
            )
            (docs_path / "exploit" / "windows" / "smb" / "ms08_067_netapi.md").write_text("test")
            (docs_path / "exploit" / "linux" / "http" / "apache_cgi.md").write_text("test")
            (docs_path / "auxiliary" / "scanner" / "smb" / "smb_version.md").write_text("test")

            yield docs_path

    @pytest.mark.asyncio
    async def test_find_similar_by_keyword(self, temp_docs_dir):
        """Test finding similar files by keyword matching."""
        from metasploit_mcp.server import _find_similar_documentation_files

        suggestions = await _find_similar_documentation_files(
            temp_docs_dir, "windows/smb/eternalblue"
        )

        assert len(suggestions) > 0
        assert any("eternalblue" in s for s in suggestions)

    @pytest.mark.asyncio
    async def test_find_similar_multiple_matches(self, temp_docs_dir):
        """Test finding multiple similar files."""
        from metasploit_mcp.server import _find_similar_documentation_files

        suggestions = await _find_similar_documentation_files(
            temp_docs_dir, "windows/smb/something"
        )

        # Should find both ms17_010 and ms08_067 in windows/smb
        smb_matches = [s for s in suggestions if "smb" in s]
        assert len(smb_matches) >= 2

    @pytest.mark.asyncio
    async def test_find_similar_no_matches(self, temp_docs_dir):
        """Test when no similar files are found."""
        from metasploit_mcp.server import _find_similar_documentation_files

        suggestions = await _find_similar_documentation_files(
            temp_docs_dir, "totally/unrelated/xyz123abc"
        )

        # Should return empty list, not error
        assert suggestions == []

    @pytest.mark.asyncio
    async def test_find_similar_respects_max_suggestions(self, temp_docs_dir):
        """Test that max_suggestions limit is respected."""
        from metasploit_mcp.server import _find_similar_documentation_files

        suggestions = await _find_similar_documentation_files(
            temp_docs_dir, "smb", max_suggestions=2  # Should match multiple files
        )

        assert len(suggestions) <= 2

    @pytest.mark.asyncio
    async def test_find_similar_empty_path(self):
        """Test with non-existent path."""
        from metasploit_mcp.server import _find_similar_documentation_files

        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = pathlib.Path(tmpdir)
            suggestions = await _find_similar_documentation_files(docs_path, "any/module")

            assert suggestions == []


class TestIntegration:
    """Integration tests for describe_module and get_module_documentation working together."""

    @pytest.fixture
    def temp_docs_dir(self):
        """Create a temporary documentation directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = pathlib.Path(tmpdir)

            (docs_path / "exploit" / "unix" / "ftp").mkdir(parents=True)

            proftpd_doc = docs_path / "exploit" / "unix" / "ftp" / "proftpd_modcopy_exec.md"
            proftpd_doc.write_text(
                """# ProFTPD mod_copy

## Scenarios

Use with RHOSTS, RPORT, RPORT_FTP, SITEPATH, TMPPATH, and TARGETURI options.
"""
            )

            yield docs_path

    @pytest.mark.asyncio
    async def test_workflow_describe_then_get_docs(self, temp_docs_dir):
        """Test the recommended workflow: describe_module -> get_module_documentation."""
        from metasploit_mcp.server import describe_module, get_module_documentation

        # Setup describe_module mocks
        module_info = {
            "name": "ProFTPD mod_copy",
            "description": "Exploits mod_copy commands",
            "authors": ["Test"],
            "references": [["CVE", "2015-3306"]],
            "notes": {"Stability": ["CRASH_SAFE"]},
            "platform": ["unix"],
            "arch": ["cmd"],
        }

        module_options = {
            "RHOSTS": {"type": "address", "required": True, "desc": "Target"},
            "SITEPATH": {
                "type": "string",
                "required": True,
                "default": "/var/www",
                "desc": "Web path",
            },
        }

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return module_info
            elif method == "module.options":
                return module_options
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        # Step 1: describe_module to get options
        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            info_result = await describe_module("unix/ftp/proftpd_modcopy_exec", "exploit")

        assert info_result["status"] == "success"
        assert "RHOSTS" in info_result["options"]
        assert "SITEPATH" in info_result["options"]

        # Step 2: get_module_documentation for usage examples
        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            docs_result = await get_module_documentation("exploit/unix/ftp/proftpd_modcopy_exec")

        assert docs_result["status"] == "success"
        assert "Scenarios" in docs_result["documentation"]

        # Agent now has all info needed to correctly use run_exploit

    @pytest.mark.asyncio
    async def test_describe_module_then_docs_not_found(self, temp_docs_dir):
        """Test when module exists but documentation doesn't."""
        from metasploit_mcp.server import describe_module, get_module_documentation

        module_info = {
            "name": "Some Module Without Docs",
            "description": "A module that has no documentation",
            "authors": ["Test"],
            "references": [],
            "platform": ["windows"],
            "arch": ["x64"],
        }

        mock_client = MockMsfRpcClient()
        mock_client.call = Mock(return_value=module_info)

        mock_module_obj = Mock()
        mock_module_obj.options = {
            "RHOSTS": {"type": "address", "required": True, "desc": "Target"}
        }

        # describe_module should succeed
        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            with patch(
                "metasploit_mcp.server._get_module_object",
                new_callable=AsyncMock,
                return_value=mock_module_obj,
            ):
                info_result = await describe_module("some/module/without_docs", "exploit")

        assert info_result["status"] == "success"

        # But documentation won't exist
        with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(temp_docs_dir)):
            docs_result = await get_module_documentation("exploit/some/module/without_docs")

        assert docs_result["status"] == "not_found"
        # Should still have options from describe_module to proceed


class TestEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_describe_module_empty_options(self):
        """Test when module has no options."""
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return {"name": "Test", "description": "Test module"}
            elif method == "module.options":
                return {}
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "success"
        assert result["options"] == {}

    @pytest.mark.asyncio
    async def test_describe_module_options_exception(self):
        """Test graceful handling when options retrieval fails."""
        from metasploit_mcp.server import describe_module

        call_count = [0]

        def mock_call(method, args):
            call_count[0] += 1
            if method == "module.info":
                return {"name": "Test", "description": "Test module"}
            elif method == "module.options":
                raise Exception("Options error")
            return {}

        mock_client = MockMsfRpcClient()
        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        # Should still return basic info even if options fail
        assert result["status"] == "success"
        assert result["options"] == {}

    @pytest.mark.asyncio
    async def test_describe_module_malformed_references(self):
        """Test handling of malformed references in module info."""
        from metasploit_mcp.server import describe_module

        module_info = {
            "name": "Test",
            "description": "Test",
            "references": [
                ["CVE", "2023-1234"],  # Valid
                "invalid_reference",  # Invalid - should be skipped
                ["URL"],  # Invalid - missing value
                {"type": "EDB", "value": "12345"},  # Dict format
            ],
        }

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return module_info
            elif method == "module.options":
                return {}
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "success"
        # Should have parsed valid references
        assert len(result["references"]) >= 1

    @pytest.mark.asyncio
    async def test_get_documentation_file_read_error(self):
        """Test handling of file read errors."""
        from metasploit_mcp.server import get_module_documentation

        with tempfile.TemporaryDirectory() as tmpdir:
            docs_path = pathlib.Path(tmpdir)
            (docs_path / "exploit").mkdir()

            # Create a file we can't read (in practice this is hard to test)
            bad_file = docs_path / "exploit" / "bad_module.md"
            bad_file.write_text("test")

            with patch("metasploit_mcp.server.MSF_DOCS_PATH", str(docs_path)):
                with patch.object(
                    pathlib.Path, "read_text", side_effect=PermissionError("Access denied")
                ):
                    result = await get_module_documentation("exploit/bad_module")

            assert result["status"] == "error"
            assert "error" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_describe_module_rpc_connection_error(self):
        """Test handling of RPC connection errors."""
        from metasploit_mcp.server import describe_module, MsfRpcError

        mock_client = MockMsfRpcClient()
        mock_client.call = Mock(side_effect=MsfRpcError("Connection refused"))

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "error"
        assert "rpc" in result["message"].lower() or "connection" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_describe_module_options_unexpected_type(self):
        """Test handling when module.options RPC returns unexpected type.

        Regression test for robustness - if RPC returns non-dict data,
        the function should handle it gracefully.
        """
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return {"name": "Test Module", "description": "Test description"}
            elif method == "module.options":
                # Simulate unexpected response - a list instead of dict
                return ["RHOSTS", "RPORT", "THREADS"]
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "success"
        assert "options" in result
        # Should default to empty dict when RPC returns unexpected type
        assert isinstance(result["options"], dict)
        assert result["options"] == {}

    @pytest.mark.asyncio
    async def test_describe_module_options_none_response(self):
        """Test handling when module.options RPC returns None.

        Edge case test for robustness.
        """
        from metasploit_mcp.server import describe_module

        mock_client = MockMsfRpcClient()

        def mock_call(method, args):
            if method == "module.info":
                return {"name": "Test Module", "description": "Test description"}
            elif method == "module.options":
                return None
            return {}

        mock_client.call = Mock(side_effect=mock_call)

        with patch("metasploit_mcp.server.get_msf_client", return_value=mock_client):
            result = await describe_module("test/module", "exploit")

        assert result["status"] == "success"
        assert "options" in result
        # Should default to empty dict when RPC returns None
        assert isinstance(result["options"], dict)
        assert result["options"] == {}
