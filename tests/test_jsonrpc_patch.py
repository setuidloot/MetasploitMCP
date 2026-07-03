#!/usr/bin/env python3
"""
Tests for the pymetasploit3 JSON-RPC monkeypatch (metasploit_mcp.jsonrpc_patch).

The patch adds optional JSON-RPC 2.0 support to pymetasploit3 (selected via the
MSF_RPC_PROTOCOL env var). These tests exercise the current implementation:

- ``_jsonrpc_encode`` wraps ``[method, *params]`` in a JSON-RPC 2.0 envelope.
- ``_jsonrpc_decode`` unwraps the ``result`` field (or raises on ``error``).
- ``_patched_encode`` / ``_patched_decode`` dispatch on the module-level
  ``_USE_JSONRPC`` flag (JSON-RPC vs. msgpack).
- ``_patched_post_request`` / ``_patched_init`` set protocol-appropriate headers.
- ``apply_patch(utils_module, msfrpc_module)`` installs the patched callables
  onto the supplied modules, and is a no-op when JSON-RPC is disabled.

The protocol flag is captured at import time, so instead of reloading the module
(fragile) we toggle the module-level globals directly within each test.
"""

import json
import contextlib

import pytest

from metasploit_mcp import jsonrpc_patch


@contextlib.contextmanager
def _use_jsonrpc(enabled: bool):
    """Temporarily force the module-level JSON-RPC flag on/off."""
    prev_use = jsonrpc_patch._USE_JSONRPC
    prev_proto = jsonrpc_patch._RPC_PROTOCOL
    jsonrpc_patch._USE_JSONRPC = enabled
    jsonrpc_patch._RPC_PROTOCOL = 'jsonrpc' if enabled else 'msgpack'
    try:
        yield
    finally:
        jsonrpc_patch._USE_JSONRPC = prev_use
        jsonrpc_patch._RPC_PROTOCOL = prev_proto


class TestProtocolHelpers:
    def test_protocol_detection_jsonrpc(self):
        with _use_jsonrpc(True):
            assert jsonrpc_patch._is_jsonrpc_enabled() is True
            assert jsonrpc_patch._get_protocol() == 'jsonrpc'

    def test_protocol_detection_msgpack(self):
        with _use_jsonrpc(False):
            assert jsonrpc_patch._is_jsonrpc_enabled() is False
            assert jsonrpc_patch._get_protocol() == 'msgpack'


class TestJSONRPCEncode:
    def test_encode_wraps_in_jsonrpc_envelope(self):
        """[method, *params] -> JSON-RPC 2.0 request envelope."""
        encoded = jsonrpc_patch._jsonrpc_encode(['auth.login', 'username', 'password'])
        assert isinstance(encoded, bytes)

        decoded = json.loads(encoded.decode('utf-8'))
        assert decoded['jsonrpc'] == '2.0'
        assert decoded['method'] == 'auth.login'
        assert decoded['params'] == ['username', 'password']
        assert isinstance(decoded['id'], int)

    def test_encode_handles_complex_nested_data(self):
        data = [
            'module.execute',
            'token123',
            {'RHOSTS': '192.168.1.1', 'RPORT': 445,
             'options': {'SMBUser': 'admin', 'SMBPass': 'password'}},
        ]
        decoded = json.loads(jsonrpc_patch._jsonrpc_encode(data).decode('utf-8'))
        assert decoded['method'] == 'module.execute'
        assert decoded['params'][0] == 'token123'
        assert decoded['params'][1]['options']['SMBUser'] == 'admin'

    def test_encode_method_only(self):
        decoded = json.loads(jsonrpc_patch._jsonrpc_encode(['core.version']).decode('utf-8'))
        assert decoded['method'] == 'core.version'
        assert decoded['params'] == []

    def test_encode_rejects_non_list(self):
        with pytest.raises(ValueError):
            jsonrpc_patch._jsonrpc_encode('not-a-list')

    def test_encode_assigns_incrementing_ids(self):
        first = json.loads(jsonrpc_patch._jsonrpc_encode(['a']).decode('utf-8'))
        second = json.loads(jsonrpc_patch._jsonrpc_encode(['b']).decode('utf-8'))
        assert second['id'] == first['id'] + 1


class TestJSONRPCDecode:
    def test_decode_extracts_result_field(self):
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'token': 'abc'}}).encode()
        assert jsonrpc_patch._jsonrpc_decode(payload) == {'token': 'abc'}

    def test_decode_raises_on_error_field(self):
        payload = json.dumps({
            'jsonrpc': '2.0', 'id': 1,
            'error': {'code': 500, 'message': 'boom'},
        }).encode()
        with pytest.raises(ValueError, match='500'):
            jsonrpc_patch._jsonrpc_decode(payload)

    def test_decode_returns_response_without_result_or_error(self):
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1}).encode()
        assert jsonrpc_patch._jsonrpc_decode(payload) == {'jsonrpc': '2.0', 'id': 1}

    def test_decode_raises_on_invalid_json(self):
        with pytest.raises((ValueError, json.JSONDecodeError)):
            jsonrpc_patch._jsonrpc_decode(b'not valid json {')


class TestPatchedEncodeDecode:
    def test_patched_encode_jsonrpc(self):
        with _use_jsonrpc(True):
            encoded = jsonrpc_patch._patched_encode(['method', 'arg1', 'arg2'])
        decoded = json.loads(encoded.decode('utf-8'))
        assert decoded['method'] == 'method'
        assert decoded['params'] == ['arg1', 'arg2']

    def test_patched_encode_msgpack(self):
        import msgpack
        with _use_jsonrpc(False):
            encoded = jsonrpc_patch._patched_encode(['method', 'arg1', 'arg2'])
        assert isinstance(encoded, bytes)
        assert msgpack.unpackb(encoded, strict_map_key=False) == ['method', 'arg1', 'arg2']

    def test_patched_decode_roundtrips_msgpack(self):
        import msgpack
        with _use_jsonrpc(False):
            assert jsonrpc_patch._patched_decode(msgpack.packb({'a': 1})) == {'a': 1}

    def test_patched_decode_jsonrpc_result(self):
        with _use_jsonrpc(True):
            payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': 'ok'}).encode()
            assert jsonrpc_patch._patched_decode(payload) == 'ok'


class TestPatchedHTTP:
    def test_patched_init_sets_jsonrpc_headers(self):
        class _Client:
            pass

        client = _Client()
        with _use_jsonrpc(True):
            jsonrpc_patch._patched_init(client, 'password')
        assert client.headers == {"Content-type": "application/json"}
        assert client.uri == '/api/v1/json-rpc'

    def test_patched_post_request_sets_jsonrpc_headers(self, mocker):
        class _Client:
            pass

        client = _Client()
        mock_post = mocker.patch('requests.post')
        with _use_jsonrpc(True):
            jsonrpc_patch._patched_post_request(client, 'http://127.0.0.1:55553/api/', b'test')
        assert client.headers == {"Content-type": "application/json"}
        assert mock_post.call_args.kwargs['headers'] == {"Content-type": "application/json"}

    def test_patched_post_request_sets_msgpack_headers(self, mocker):
        class _Client:
            pass

        client = _Client()
        mock_post = mocker.patch('requests.post')
        with _use_jsonrpc(False):
            jsonrpc_patch._patched_post_request(client, 'http://127.0.0.1:55553/api/', b'test')
        assert client.headers == {"Content-type": "binary/message-pack"}


class TestApplyPatch:
    def _fake_modules(self):
        import types

        utils = types.ModuleType('pymetasploit3.utils')
        utils.encode = lambda data: b'orig-encode'
        utils.decode = lambda data: 'orig-decode'

        msfrpc = types.ModuleType('pymetasploit3.msfrpc')

        class MsfRpcClient:
            def __init__(self, password, **kwargs):
                self.password = password

            def post_request(self, url, payload):  # pragma: no cover - replaced by patch
                return None

            def call(self, method, opts=None, is_raw=False):  # pragma: no cover
                return None

        msfrpc.MsfRpcClient = MsfRpcClient
        return utils, msfrpc

    def test_apply_patch_installs_patched_callables(self):
        utils, msfrpc = self._fake_modules()
        with _use_jsonrpc(True):
            jsonrpc_patch.apply_patch(utils, msfrpc)

        assert msfrpc.encode is jsonrpc_patch._patched_encode
        assert msfrpc.decode is jsonrpc_patch._patched_decode
        assert msfrpc.MsfRpcClient.__init__ is jsonrpc_patch._patched_init
        assert msfrpc.MsfRpcClient.post_request is jsonrpc_patch._patched_post_request
        assert msfrpc.MsfRpcClient.call is jsonrpc_patch._patched_call

    def test_apply_patch_is_noop_when_jsonrpc_disabled(self):
        utils, msfrpc = self._fake_modules()
        original_init = msfrpc.MsfRpcClient.__init__
        with _use_jsonrpc(False):
            jsonrpc_patch.apply_patch(utils, msfrpc)
        assert msfrpc.MsfRpcClient.__init__ is original_init
        assert not hasattr(msfrpc, 'encode')
