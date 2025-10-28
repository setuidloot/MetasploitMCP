#!/bin/bash
#
# Quick test script for Metasploitable 3 harness
# This script runs a single quick test to verify the setup is working
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Metasploitable 3 Quick Test${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if arguments are provided
if [ $# -lt 2 ]; then
    echo -e "${RED}Error: Missing required arguments${NC}"
    echo ""
    echo "Usage: $0 <target_ip> <lhost> [lport]"
    echo ""
    echo "Example:"
    echo "  $0 10.0.2.15 10.0.2.4"
    echo "  $0 10.0.2.15 10.0.2.4 4444"
    echo ""
    exit 1
fi

TARGET_IP=$1
LHOST=$2
LPORT=${3:-4444}

echo -e "${YELLOW}Configuration:${NC}"
echo "  Target IP: $TARGET_IP"
echo "  LHOST: $LHOST"
echo "  LPORT: $LPORT"
echo ""

# Check connectivity
echo -e "${YELLOW}Checking connectivity...${NC}"
if ping -c 1 -W 2 "$TARGET_IP" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Target is reachable"
else
    echo -e "${RED}✗${NC} Target is not reachable"
    echo -e "${RED}Error: Cannot ping $TARGET_IP${NC}"
    exit 1
fi

# Check if MCP server is running
echo -e "${YELLOW}Checking MCP server...${NC}"
if curl -s -m 2 http://127.0.0.1:8085 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} MCP server is running"
else
    echo -e "${RED}✗${NC} MCP server is not responding"
    echo -e "${RED}Error: MCP server at http://127.0.0.1:8085 is not accessible${NC}"
    echo ""
    echo "Start the server with:"
    echo "  poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085"
    exit 1
fi

# Run the test
echo ""
echo -e "${YELLOW}Running ProFTPD exploit test...${NC}"
echo ""

cd "$(dirname "$0")/.."

poetry run python metasploitable3_test_harness.py \
    --target "$TARGET_IP" \
    --lhost "$LHOST" \
    --lport "$LPORT" \
    --test "ProFTPD"

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✓ Quick test PASSED${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Your setup is working correctly!"
    echo ""
    echo "Next steps:"
    echo "  1. Run all tests:"
    echo "     poetry run python metasploitable3_test_harness.py --target $TARGET_IP --lhost $LHOST"
    echo ""
    echo "  2. See all available tests:"
    echo "     poetry run python metasploitable3_test_harness.py --list-tests"
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}✗ Quick test FAILED${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "Troubleshooting tips:"
    echo "  1. Verify network connectivity"
    echo "  2. Check Metasploit RPC is running:"
    echo "     msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553"
    echo "  3. Verify LHOST is correct (target must be able to reach it)"
    echo "  4. Run with verbose mode:"
    echo "     poetry run python metasploitable3_test_harness.py --target $TARGET_IP --lhost $LHOST --test ProFTPD --verbose"
fi

exit $EXIT_CODE

