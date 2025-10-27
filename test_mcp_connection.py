#!/usr/bin/env python3
"""
Simple MCP connection test script.

This script tests basic connectivity to the MetasploitMCP server
and helps diagnose connection issues.

Usage:
    python test_mcp_connection.py [--url http://localhost:8085]
"""

import argparse
import asyncio
import json
import sys

import httpx


async def test_connection(mcp_url: str):
    """Test basic MCP server connection.
    
    Args:
        mcp_url: Base URL of the MCP server
    """
    print(f"Testing MCP connection to: {mcp_url}")
    print("=" * 60)
    
    endpoint = f"{mcp_url.rstrip('/')}/mcp"
    print(f"Endpoint: {endpoint}\n")
    
    # Test 1: Server availability
    print("Test 1: Server Availability")
    print("-" * 60)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(mcp_url)
            print(f"✓ Server is responding")
            print(f"  Status: {response.status_code}")
            print(f"  Content-Type: {response.headers.get('content-type', 'N/A')}")
    except httpx.ConnectError as e:
        print(f"✗ Cannot connect to server: {e}")
        print(f"\nMake sure MetasploitMCP is running:")
        print(f"  poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port {mcp_url.split(':')[-1].split('/')[0]}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False
    
    print()
    
    # Test 2: MCP tools/list
    print("Test 2: MCP Protocol - List Tools")
    print("-" * 60)
    
    request_data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    }
    
    print(f"Request: {json.dumps(request_data, indent=2)}")
    print()
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                endpoint,
                json=request_data,
                headers={
                    "Content-Type": "application/json",
                    # FastMCP streamable-http requires accepting both formats
                    "Accept": "application/json, text/event-stream"
                }
            )
            
            print(f"Response Status: {response.status_code}")
            print(f"Response Headers:")
            for key, value in response.headers.items():
                print(f"  {key}: {value}")
            print()
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ MCP Protocol Working!")
                print(f"Response: {json.dumps(result, indent=2)[:500]}...")
                
                # Count tools if available
                if "result" in result and "tools" in result.get("result", {}):
                    tools = result["result"]["tools"]
                    print(f"\n✓ Found {len(tools)} MCP tools")
                    print(f"  Tools: {', '.join([t.get('name', 'unknown') for t in tools[:5]])}...")
                
                return True
            elif response.status_code == 406:
                print(f"✗ 406 Not Acceptable Error")
                print(f"   This usually means the server doesn't accept our request format.")
                print(f"   Response body: {response.text[:200]}")
                return False
            else:
                print(f"✗ Unexpected status code: {response.status_code}")
                print(f"   Response: {response.text[:200]}")
                return False
                
    except httpx.HTTPError as e:
        print(f"✗ HTTP Error: {e}")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_tool_call(mcp_url: str):
    """Test calling an actual MCP tool.
    
    Args:
        mcp_url: Base URL of the MCP server
    """
    print("\nTest 3: MCP Tool Call - list_exploits")
    print("-" * 60)
    
    endpoint = f"{mcp_url.rstrip('/')}/mcp"
    
    request_data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "list_exploits",
            "arguments": {
                "search_term": "proftpd",
                "platform_filter": ""
            }
        }
    }
    
    print(f"Request: {json.dumps(request_data, indent=2)}")
    print()
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                endpoint,
                json=request_data,
                headers={
                    "Content-Type": "application/json",
                    # FastMCP streamable-http requires accepting both formats
                    "Accept": "application/json, text/event-stream"
                }
            )
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                print(f"✓ Tool call successful!")
                print(f"Response preview: {json.dumps(result, indent=2)[:300]}...")
                return True
            else:
                print(f"✗ Tool call failed: {response.status_code}")
                print(f"Response: {response.text[:200]}")
                return False
                
    except Exception as e:
        print(f"✗ Error calling tool: {e}")
        return False


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test MCP connection to MetasploitMCP server"
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8085",
        help="MCP server URL (default: http://127.0.0.1:8085)"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full test including tool calls"
    )
    
    args = parser.parse_args()
    
    print("MetasploitMCP Connection Test")
    print("=" * 60)
    print()
    
    # Basic connection test
    success = await test_connection(args.url)
    
    if not success:
        print("\n" + "=" * 60)
        print("FAILED - Connection test failed")
        print("=" * 60)
        return 1
    
    # Optional full test
    if args.full:
        await test_tool_call(args.url)
    
    print("\n" + "=" * 60)
    print("SUCCESS - All tests passed!")
    print("=" * 60)
    print()
    print("You can now run the test harness:")
    print(f"  make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

