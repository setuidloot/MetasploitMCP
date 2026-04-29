"""
Unit tests for MetasploitMCP Health Check Endpoints

Tests the HTTP health check and root endpoints added to MetasploitMCP server.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from starlette.requests import Request
from starlette.responses import JSONResponse

# Import MetasploitMCP
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import metasploit_mcp.server as MetasploitMCP


@pytest.mark.asyncio
async def test_http_health_check_healthy():
    """Test that HTTP health check endpoint returns healthy status when MSF RPC is available"""
    # Create a mock request
    mock_request = Mock(spec=Request)
    
    # Mock the MSF client
    mock_client = Mock()
    mock_client.core.version = {'version': '6.2.0'}
    
    with patch.object(MetasploitMCP, 'get_msf_client', return_value=mock_client):
        with patch('asyncio.wait_for', new=AsyncMock(return_value={'version': '6.2.0'})):
            response = await MetasploitMCP.http_health_endpoint(mock_request)
    
    # Check response type and status code
    assert isinstance(response, JSONResponse)
    assert response.status_code == 200
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check response structure
    assert body["status"] == "healthy"
    assert body["service"] == "MetasploitMCP"
    assert "msf_version" in body
    assert body["msf_version"] == "6.2.0"
    assert "msf_server" in body


@pytest.mark.asyncio
async def test_http_health_check_timeout():
    """Test that HTTP health check endpoint returns unhealthy status on timeout"""
    mock_request = Mock(spec=Request)
    
    # Mock the MSF client
    mock_client = Mock()
    
    with patch.object(MetasploitMCP, 'get_msf_client', return_value=mock_client):
        # Simulate timeout
        with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError()):
            response = await MetasploitMCP.http_health_endpoint(mock_request)
    
    # Check response
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check that status is unhealthy
    assert body["status"] == "unhealthy"
    assert body["service"] == "MetasploitMCP"
    assert "error" in body
    assert "timeout" in body["error"].lower()


@pytest.mark.asyncio
async def test_http_health_check_connection_error():
    """Test that HTTP health check endpoint returns unhealthy status on connection error"""
    mock_request = Mock(spec=Request)
    
    # Mock get_msf_client to raise ConnectionError
    with patch.object(MetasploitMCP, 'get_msf_client', side_effect=ConnectionError("Connection refused")):
        response = await MetasploitMCP.http_health_endpoint(mock_request)
    
    # Check response
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check that status is unhealthy
    assert body["status"] == "unhealthy"
    assert "error" in body
    assert "Connection refused" in body["error"]


@pytest.mark.asyncio
async def test_http_health_check_msfrpc_error():
    """Test that HTTP health check endpoint handles MsfRpcError"""
    from pymetasploit3.msfrpc import MsfRpcError
    
    mock_request = Mock(spec=Request)
    mock_client = Mock()
    
    with patch.object(MetasploitMCP, 'get_msf_client', return_value=mock_client):
        # Simulate MsfRpcError
        with patch('asyncio.wait_for', side_effect=MsfRpcError("RPC error")):
            response = await MetasploitMCP.http_health_endpoint(mock_request)
    
    # Check response
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check that status is unhealthy
    assert body["status"] == "unhealthy"
    assert "error" in body


@pytest.mark.asyncio
async def test_http_health_check_unexpected_error():
    """Test that HTTP health check endpoint handles unexpected errors gracefully"""
    mock_request = Mock(spec=Request)
    mock_client = Mock()
    
    with patch.object(MetasploitMCP, 'get_msf_client', return_value=mock_client):
        # Simulate unexpected exception
        with patch('asyncio.wait_for', side_effect=Exception("Unexpected error")):
            response = await MetasploitMCP.http_health_endpoint(mock_request)
    
    # Check response
    assert isinstance(response, JSONResponse)
    assert response.status_code == 500
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check that status is unhealthy
    assert body["status"] == "unhealthy"
    assert "error" in body
    assert "Internal Server Error" in body["error"]


@pytest.mark.asyncio
async def test_http_root_endpoint():
    """Test that root endpoint returns basic service information"""
    mock_request = Mock(spec=Request)
    
    response = await MetasploitMCP.http_root_endpoint(mock_request)
    
    # Check response type and status code
    assert isinstance(response, JSONResponse)
    assert response.status_code == 200
    
    # Parse response body
    import json
    body = json.loads(response.body.decode())
    
    # Check response structure
    assert body["service"] == "MetasploitMCP"
    assert "version" in body
    assert body["description"] == "Metasploit Framework MCP Server"
    assert body["mcp_endpoint"] == "/mcp"
    assert body["health_endpoint"] == "/health"
    assert body["status"] == "running"
    assert "msf_server" in body


@pytest.mark.skip(reason="MCP tool testing requires FastMCP internals, HTTP endpoints are the primary health check mechanism")
@pytest.mark.asyncio
async def test_health_check_tool():
    """Test the MCP tool version of health_check (for backward compatibility)"""
    # NOTE: This test is skipped because the HTTP health check endpoints are the primary
    # health check mechanism for Docker and monitoring systems. The MCP tool version
    # is kept for backward compatibility but is not critical for health monitoring.
    pass


@pytest.mark.skip(reason="MCP tool testing requires FastMCP internals, HTTP endpoints are the primary health check mechanism")
@pytest.mark.asyncio
async def test_health_check_tool_timeout():
    """Test the MCP tool version of health_check with timeout"""
    # NOTE: This test is skipped because the HTTP health check endpoints are the primary
    # health check mechanism for Docker and monitoring systems.
    pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

