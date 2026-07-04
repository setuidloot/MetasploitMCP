# Test package for MetasploitMCP


class MockMsfRpcError(Exception):
    """Canonical mock of ``pymetasploit3.msfrpc.MsfRpcError`` shared by the
    whole test suite.

    Historically each test module defined its own ``MockMsfRpcError`` and
    replaced ``sys.modules['pymetasploit3.msfrpc']`` at import time, so the
    exception class identity depended on test-collection order. ``server.py``
    resolves ``except MsfRpcError`` against its module global at runtime, so a
    mismatched class meant errors weren't caught as expected and tests failed
    only when run together. Centralising one class here (and re-asserting it
    before every test via the ``conftest`` autouse fixture) keeps the identity
    stable regardless of collection order.
    """

    pass
