#!/usr/bin/env python3
"""
Monkeypatch module to add JSON-RPC support to pymetasploit3.

This module patches pymetasploit3 to support JSON-RPC protocol in addition to
the default msgpack RPC. The protocol can be selected via the MSF_RPC_PROTOCOL
environment variable (values: 'msgpack' (default) or 'jsonrpc').

The patch intercepts:
- Serialization/deserialization in pymetasploit3.utils
- HTTP headers in MsfRpcClient
- Response parsing in MsfRpcClient.call()

NOTE: Metasploit's msfrpcd uses a different endpoint for JSON-RPC:
- msgpack RPC: /api/
- JSON-RPC: /api/v1/json-rpc

The patch automatically sets the correct endpoint based on MSF_RPC_PROTOCOL.
"""

import os
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Protocol detection
_RPC_PROTOCOL = os.getenv('MSF_RPC_PROTOCOL', 'msgpack').lower()
_USE_JSONRPC = _RPC_PROTOCOL == 'jsonrpc'

# Store original functions
_original_encode: Optional[Any] = None
_original_decode: Optional[Any] = None
_original_init: Optional[Any] = None
_original_post_request: Optional[Any] = None
_original_call: Optional[Any] = None

# Request ID counter for JSON-RPC
_request_id_counter = 0


def _get_protocol() -> str:
    """Get the current RPC protocol."""
    return _RPC_PROTOCOL


def _is_jsonrpc_enabled() -> bool:
    """Check if JSON-RPC is enabled."""
    return _USE_JSONRPC


def _jsonrpc_encode(data: Any) -> bytes:
    """
    Encode data for JSON-RPC 2.0 protocol.
    
    Metasploit's JSON-RPC expects the format:
    {
        "jsonrpc": "2.0",
        "method": "method_name",
        "params": [token, ...args],
        "id": request_id
    }
    
    The input data is an array: [method, token, ...args]
    """
    global _request_id_counter
    
    try:
        if not isinstance(data, list) or len(data) < 1:
            raise ValueError(f"JSON-RPC encode expects a list with at least method name, got: {data}")
        
        method = data[0]
        params = data[1:] if len(data) > 1 else []
        
        _request_id_counter += 1
        request_id = _request_id_counter
        
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": request_id
        }
        
        json_str = json.dumps(jsonrpc_request, ensure_ascii=False)
        return json_str.encode('utf-8')
    except (TypeError, ValueError) as e:
        logger.error(f"JSON-RPC encoding error: {e}")
        raise


def _jsonrpc_decode(data: bytes) -> Any:
    """
    Decode JSON-RPC 2.0 response.
    
    Metasploit's JSON-RPC response format:
    {
        "jsonrpc": "2.0",
        "result": ...,
        "id": request_id
    }
    or
    {
        "jsonrpc": "2.0",
        "error": {...},
        "id": request_id
    }
    
    We extract the "result" field (or raise error if "error" is present).
    """
    try:
        if isinstance(data, bytes):
            json_str = data.decode('utf-8')
        else:
            json_str = data
        
        response = json.loads(json_str)
        
        # Handle JSON-RPC 2.0 response format
        if isinstance(response, dict):
            if "error" in response:
                error = response.get("error", {})
                error_code = error.get("code", -1)
                error_msg = error.get("message", "Unknown error")
                raise ValueError(f"JSON-RPC error {error_code}: {error_msg}")
            
            # Return the result field
            if "result" in response:
                return response["result"]
            
            # If it's not a standard JSON-RPC response, return as-is
            return response
        
        # If it's not a dict, return as-is (shouldn't happen with proper JSON-RPC)
        return response
        
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        logger.error(f"JSON-RPC decoding error: {e}")
        raise


def _patched_encode(data: Any) -> bytes:
    """Patched encode function that routes to JSON-RPC or msgpack based on protocol."""
    if _USE_JSONRPC:
        return _jsonrpc_encode(data)
    else:
        if _original_encode is None:
            import msgpack
            return msgpack.packb(data)
        return _original_encode(data)


def _patched_decode(data: bytes) -> Any:
    """Patched decode function that routes to JSON-RPC or msgpack based on protocol."""
    if _USE_JSONRPC:
        try:
            return _jsonrpc_decode(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.warning(f"JSON-RPC decode failed: {e}")
            raise ValueError(f"Failed to decode JSON-RPC response: {e}") from e
    else:
        if _original_decode is None:
            import msgpack
            return msgpack.unpackb(data, strict_map_key=False)
        return _original_decode(data)


def _patched_call(self, method, opts=None, is_raw=False):
    """
    Patched call method that handles JSON-RPC (no authentication) vs msgpack (with authentication).
    """
    from pymetasploit3.utils import convert
    
    if not isinstance(opts, list):
        opts = []
    
    # For JSON-RPC, skip authentication checks and token insertion
    if _USE_JSONRPC:
        # JSON-RPC doesn't require authentication, so skip token
        pass
    else:
        # For msgpack, use original authentication logic
        if method != 'auth.login':
            if self.token is None:
                from pymetasploit3.msfrpc import MsfAuthError
                raise MsfAuthError("MsfRPC: Not Authenticated")
        if method != "auth.login":
            opts.insert(0, self.token)

    if self.ssl is True:
        url = "https://%s:%s%s" % (self.host, self.port, self.uri)
    else:
        url = "http://%s:%s%s" % (self.host, self.port, self.uri)

    opts.insert(0, method)
    
    # Use patched encode/decode
    if _USE_JSONRPC:
        payload = _jsonrpc_encode(opts)
    else:
        if _original_encode:
            payload = _original_encode(opts)
        else:
            import msgpack
            payload = msgpack.packb(opts)

    r = _patched_post_request(self, url, payload)

    opts[:] = []  # Clear opts list

    if is_raw:
        return r.content

    # Use patched decode
    if _USE_JSONRPC:
        decoded = _jsonrpc_decode(r.content)
    else:
        if _original_decode:
            decoded = _original_decode(r.content)
        else:
            import msgpack
            decoded = msgpack.unpackb(r.content, strict_map_key=False)
    
    return convert(decoded, self.encodings, self.decode_error_handling)


def _patched_post_request(self, url: str, payload: bytes):
    """Patched post_request method that sets correct Content-Type header."""
    if _USE_JSONRPC:
        self.headers = {"Content-type": "application/json"}
    else:
        self.headers = {"Content-type": "binary/message-pack"}
    
    import requests
    return requests.post(url, data=payload, headers=self.headers, verify=False)


def _patched_init(self, password: str, **kwargs):
    """
    Patched __init__ method that sets correct Content-Type header and URI based on protocol.
    
    For JSON-RPC, authentication is not required, so we skip the login() call.
    """
    # Set URI and headers BEFORE calling original __init__
    if _USE_JSONRPC:
        kwargs['uri'] = '/api/v1/json-rpc'
        self.headers = {"Content-type": "application/json"}
        # Skip authentication for JSON-RPC - set token to None to prevent login()
        kwargs['token'] = None
    else:
        if 'uri' not in kwargs:
            kwargs['uri'] = '/api/'
        self.headers = {"Content-type": "binary/message-pack"}
    
    # Initialize basic attributes
    self.host = kwargs.get('server', '127.0.0.1')
    self.port = kwargs.get('port', 55553)
    self.uri = kwargs.get('uri', '/api/' if not _USE_JSONRPC else '/api/v1/json-rpc')
    self.ssl = kwargs.get('ssl', False)
    self.token = kwargs.get('token')
    self.encodings = kwargs.get('encodings', ['utf-8'])
    self.decode_error_handling = kwargs.get('decode_error_handling', 'strict')
    
    # Only call login() for msgpack (JSON-RPC doesn't require authentication)
    if not _USE_JSONRPC and self.token is None:
        if _original_init:
            # Call original __init__ which will handle login for msgpack
            _original_init(self, password, **kwargs)
        else:
            # Fallback: manually call login
            from pymetasploit3.msfrpc import MsfRpcMethod
            auth = self.call(MsfRpcMethod.AuthLogin, [kwargs.get('username', 'msf'), password])
            if auth.get('result') == 'success':
                self.token = auth.get('token')
    
    # Ensure headers and URI are still correct
    if _USE_JSONRPC:
        self.headers = {"Content-type": "application/json"}
        self.uri = '/api/v1/json-rpc'
    else:
        self.headers = {"Content-type": "binary/message-pack"}
        if not hasattr(self, 'uri') or self.uri == '/api/v1/json-rpc':
            self.uri = '/api/'


def apply_patch(utils_module, msfrpc_module):
    """
    Apply monkeypatch to pymetasploit3 modules.
    
    Args:
        utils_module: The pymetasploit3.utils module
        msfrpc_module: The pymetasploit3.msfrpc module
    """
    global _original_encode, _original_decode, _original_init, _original_post_request
    
    if not _USE_JSONRPC:
        logger.debug("JSON-RPC not enabled, skipping patch")
        return
    
    logger.info("Applying JSON-RPC monkeypatch to pymetasploit3")
    
    try:
        # Store original functions from utils
        _original_encode = utils_module.encode
        _original_decode = utils_module.decode
        
        # Store original methods from MsfRpcClient
        _original_init = msfrpc_module.MsfRpcClient.__init__
        _original_post_request = msfrpc_module.MsfRpcClient.post_request
        _original_call = msfrpc_module.MsfRpcClient.call
        
        # Patch module-level encode/decode (imported from utils with "from ... import *")
        # These are used directly in MsfRpcClient.call() as encode() and decode()
        msfrpc_module.encode = _patched_encode
        msfrpc_module.decode = _patched_decode
        
        # Also patch as class attributes for MsfRpcClient
        msfrpc_module.MsfRpcClient.encode = _patched_encode
        msfrpc_module.MsfRpcClient.decode = _patched_decode
        
        # Patch MsfRpcClient methods
        msfrpc_module.MsfRpcClient.__init__ = _patched_init
        msfrpc_module.MsfRpcClient.post_request = _patched_post_request
        msfrpc_module.MsfRpcClient.call = _patched_call
        
        logger.info("Successfully applied JSON-RPC monkeypatch to pymetasploit3")
        
    except Exception as e:
        logger.error(f"Failed to apply JSON-RPC patch: {e}", exc_info=True)
        raise
