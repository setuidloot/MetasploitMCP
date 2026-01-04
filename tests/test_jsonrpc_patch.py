#!/usr/bin/env python3
"""
Tests for pymetasploit3 JSON-RPC monkeypatch.

Tests cover:
- Protocol detection from environment variable
- JSON-RPC encoding/decoding
- Header setting
- Integration with MsfRpcClient
- Backward compatibility (msgpack)
"""

import pytest
import os
import json
import sys
from unittest.mock import Mock, patch, MagicMock
from typing import Any, Dict

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestJSONRPCPatch:
    """Test JSON-RPC monkeypatch functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        # Clear any existing patches
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        # Mock pymetasploit3 modules before importing patch
        sys.modules['pymetasploit3'] = Mock()
        sys.modules['pymetasploit3.utils'] = Mock()
        sys.modules['pymetasploit3.msfrpc'] = Mock()
        
        # Create mock encode/decode functions
        import msgpack
        self.original_encode = msgpack.packb
        self.original_decode = lambda data: msgpack.unpackb(data, strict_map_key=False)
        
        sys.modules['pymetasploit3.utils'].encode = self.original_encode
        sys.modules['pymetasploit3.utils'].decode = self.original_decode
        
        # Create mock MsfRpcClient class
        class MockMsfRpcClient:
            def __init__(self, password, **kwargs):
                self.password = password
                self.host = kwargs.get('server', '127.0.0.1')
                self.port = kwargs.get('port', 55553)
                self.uri = kwargs.get('uri', '/api/')
                self.ssl = kwargs.get('ssl', False)
                self.token = None
                self.encodings = kwargs.get('encodings', ['utf-8'])
                self.decode_error_handling = kwargs.get('decode_error_handling', 'strict')
                self.headers = {"Content-type": "binary/message-pack"}
            
            def post_request(self, url, payload):
                import requests
                return requests.post(url, data=payload, headers=self.headers, verify=False)
        
        sys.modules['pymetasploit3.msfrpc'].MsfRpcClient = MockMsfRpcClient
    
    def teardown_method(self):
        """Clean up after tests."""
        # Remove patch module from cache
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            patch_module = sys.modules['pymetasploit3_jsonrpc_patch']
            if hasattr(patch_module, 'remove_patch'):
                patch_module.remove_patch()
            del sys.modules['pymetasploit3_jsonrpc_patch']
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_protocol_detection_jsonrpc(self):
        """Test that JSON-RPC protocol is detected from environment variable."""
        # Reload module to pick up environment variable
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        assert pymetasploit3_jsonrpc_patch._is_jsonrpc_enabled() is True
        assert pymetasploit3_jsonrpc_patch._get_protocol() == 'jsonrpc'
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'msgpack'}, clear=False)
    def test_protocol_detection_msgpack(self):
        """Test that msgpack protocol is detected from environment variable."""
        # Reload module to pick up environment variable
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        assert pymetasploit3_jsonrpc_patch._is_jsonrpc_enabled() is False
        assert pymetasploit3_jsonrpc_patch._get_protocol() == 'msgpack'
    
    @patch.dict(os.environ, {}, clear=False)
    def test_protocol_detection_default(self):
        """Test that msgpack is default when environment variable is not set."""
        # Reload module to pick up environment variable
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        assert pymetasploit3_jsonrpc_patch._is_jsonrpc_enabled() is False
        assert pymetasploit3_jsonrpc_patch._get_protocol() == 'msgpack'
    
    def test_jsonrpc_encode(self):
        """Test JSON-RPC encoding function."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Test encoding a simple list (Metasploit RPC format)
        data = ['auth.login', 'username', 'password']
        encoded = pymetasploit3_jsonrpc_patch._jsonrpc_encode(data)
        
        assert isinstance(encoded, bytes)
        decoded = json.loads(encoded.decode('utf-8'))
        assert decoded == data
    
    def test_jsonrpc_decode(self):
        """Test JSON-RPC decoding function."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Test decoding JSON response
        data = {'result': 'success', 'token': 'test-token'}
        json_bytes = json.dumps(data).encode('utf-8')
        decoded = pymetasploit3_jsonrpc_patch._jsonrpc_decode(json_bytes)
        
        assert decoded == data
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_patched_encode_jsonrpc(self):
        """Test patched encode function with JSON-RPC enabled."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        data = ['method', 'arg1', 'arg2']
        encoded = pymetasploit3_jsonrpc_patch._patched_encode(data)
        
        # Should be JSON-encoded
        assert isinstance(encoded, bytes)
        decoded = json.loads(encoded.decode('utf-8'))
        assert decoded == data
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'msgpack'}, clear=False)
    def test_patched_encode_msgpack(self):
        """Test patched encode function with msgpack (should use original)."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import msgpack
        import pymetasploit3_jsonrpc_patch
        
        data = ['method', 'arg1', 'arg2']
        encoded = pymetasploit3_jsonrpc_patch._patched_encode(data)
        
        # Should be msgpack-encoded
        assert isinstance(encoded, bytes)
        # Decode with msgpack to verify
        decoded = msgpack.unpackb(encoded, strict_map_key=False)
        assert decoded == data
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_patched_init_sets_jsonrpc_headers(self):
        """Test that patched __init__ sets correct headers for JSON-RPC."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Create a mock client instance
        mock_client = Mock()
        mock_client.host = '127.0.0.1'
        mock_client.port = 55553
        mock_client.uri = '/api/'
        mock_client.ssl = False
        mock_client.token = None
        mock_client.encodings = ['utf-8']
        mock_client.decode_error_handling = 'strict'
        mock_client.headers = {}
        
        # Apply patched init
        pymetasploit3_jsonrpc_patch._patched_init(mock_client, 'password')
        
        assert mock_client.headers == {"Content-type": "application/json"}
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'msgpack'}, clear=False)
    def test_patched_init_sets_msgpack_headers(self):
        """Test that patched __init__ sets correct headers for msgpack."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Create a mock client instance
        mock_client = Mock()
        mock_client.host = '127.0.0.1'
        mock_client.port = 55553
        mock_client.uri = '/api/'
        mock_client.ssl = False
        mock_client.token = None
        mock_client.encodings = ['utf-8']
        mock_client.decode_error_handling = 'strict'
        mock_client.headers = {}
        
        # Apply patched init
        pymetasploit3_jsonrpc_patch._patched_init(mock_client, 'password')
        
        assert mock_client.headers == {"Content-type": "binary/message-pack"}
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_patched_post_request_sets_jsonrpc_headers(self):
        """Test that patched post_request sets correct headers for JSON-RPC."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Create a mock client instance
        mock_client = Mock()
        mock_client.headers = {}
        
        # Mock requests.post
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.content = b'{"result": "success"}'
            mock_post.return_value = mock_response
            
            pymetasploit3_jsonrpc_patch._patched_post_request(
                mock_client, 'http://127.0.0.1:55553/api/', b'test'
            )
            
            # Check that headers were set correctly
            assert mock_client.headers == {"Content-type": "application/json"}
            # Check that requests.post was called with correct headers
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[1]['headers'] == {"Content-type": "application/json"}
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_apply_patch(self):
        """Test that apply_patch successfully patches pymetasploit3 modules."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        # Set up mocks
        mock_utils = sys.modules['pymetasploit3.utils']
        mock_msfrpc = sys.modules['pymetasploit3.msfrpc']
        
        import pymetasploit3_jsonrpc_patch
        
        # Verify patches were applied
        assert mock_utils.encode == pymetasploit3_jsonrpc_patch._patched_encode
        assert mock_utils.decode == pymetasploit3_jsonrpc_patch._patched_decode
        assert mock_msfrpc.MsfRpcClient.__init__ == pymetasploit3_jsonrpc_patch._patched_init
        assert mock_msfrpc.MsfRpcClient.post_request == pymetasploit3_jsonrpc_patch._patched_post_request
    
    @patch.dict(os.environ, {'MSF_RPC_PROTOCOL': 'jsonrpc'}, clear=False)
    def test_remove_patch(self):
        """Test that remove_patch restores original functions."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        # Store original functions
        original_encode = sys.modules['pymetasploit3.utils'].encode
        original_decode = sys.modules['pymetasploit3.utils'].decode
        
        import pymetasploit3_jsonrpc_patch
        
        # Apply patch
        pymetasploit3_jsonrpc_patch.apply_patch()
        
        # Remove patch
        pymetasploit3_jsonrpc_patch.remove_patch()
        
        # Verify originals were restored
        assert sys.modules['pymetasploit3.utils'].encode == original_encode
        assert sys.modules['pymetasploit3.utils'].decode == original_decode
    
    def test_jsonrpc_encode_handles_complex_data(self):
        """Test JSON-RPC encoding with complex nested data structures."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Test with nested structures (common in Metasploit RPC)
        data = [
            'module.execute',
            'token123',
            {
                'RHOSTS': '192.168.1.1',
                'RPORT': 445,
                'options': {
                    'SMBUser': 'admin',
                    'SMBPass': 'password'
                }
            }
        ]
        
        encoded = pymetasploit3_jsonrpc_patch._jsonrpc_encode(data)
        decoded = json.loads(encoded.decode('utf-8'))
        
        assert decoded == data
        assert decoded[2]['options']['SMBUser'] == 'admin'
    
    def test_jsonrpc_decode_handles_errors(self):
        """Test JSON-RPC decoding error handling."""
        if 'pymetasploit3_jsonrpc_patch' in sys.modules:
            del sys.modules['pymetasploit3_jsonrpc_patch']
        
        import pymetasploit3_jsonrpc_patch
        
        # Test with invalid JSON
        invalid_json = b'not valid json {'
        
        with pytest.raises((UnicodeDecodeError, json.JSONDecodeError)):
            pymetasploit3_jsonrpc_patch._jsonrpc_decode(invalid_json)





