# MetasploitMCP — MCP API & Specification Conformance

> **Unofficial project.** Not affiliated with, sponsored by, or supported by
> Rapid7. "Metasploit" is a trademark of Rapid7.

This document is the reference for every tool and resource the server exposes and
for how the server maps onto the [Model Context Protocol](https://modelcontextprotocol.io)
specification. It complements the [README](../README.md) and
[`docs/API.md`](API.md).

- **Transports:** `stdio` and streamable HTTP (`--transport stdio|http`).
- **Server name:** `MetasploitMCP` · **Package:** `metasploit-mcp` (PyPI).
- **Backend:** Metasploit Framework RPC (`msfrpcd`), via `pymetasploit3`.

## Safety model

State-changing / offensive tools are **disabled by default** and must be enabled
explicitly. Read-only tools are always available.

| Control | Flag | Environment | Default |
|---|---|---|---|
| Enable destructive tools | `--allow-dangerous` | `MSF_MCP_ALLOW_DANGEROUS` | off |
| Rate limit (req/min, 0=off) | `--rate-limit N` | `MSF_MCP_RATE_LIMIT` | 60 |
| Confirm destructive via elicitation | `--confirm-dangerous` | `MSF_MCP_CONFIRM_DANGEROUS` | off |

- A blocked destructive call returns `{"status":"error","error":"dangerous_actions_disabled"}`.
- Over-limit calls return `{"status":"error","error":"rate_limited","retry_after_seconds":N}`.
- `health_check` reports the active posture under `safety`.

## Tool reference

Every tool advertises MCP annotation hints. `RO` = `readOnlyHint:true`,
`DESTRUCTIVE` = `destructiveHint:true` (gated by the safety model above).

### Discovery & module info — read-only

| Tool | Key parameters | Returns |
|---|---|---|
| `list_exploits` | `search` | List of matching exploit module paths |
| `list_payloads` | `platform`, `arch`, `compatible_with` | List of payload module paths |
| `describe_module` | `module`, `module_type` | Options, targets, metadata |
| `get_module_documentation` | `module` | Human-readable module documentation |

### Workspace database intelligence — read-only

All accept an optional `workspace` (defaults to the current workspace) and return
`{status, workspace, count, <items>}`. When no database is attached they return
`{"status":"error","error":"database_unavailable"}`.

| Tool | Extra parameters | Items key |
|---|---|---|
| `list_hosts` | — | `hosts` |
| `list_services` | `host`, `ports`, `proto` | `services` |
| `list_vulnerabilities` | `host` | `vulns` |
| `list_notes` | `host`, `ntype` | `notes` |
| `list_credentials` | — | `creds` |
| `list_loot` | `host` | `loots` |

### Assessment — read-only

| Tool | Key parameters | Returns |
|---|---|---|
| `check_vulnerability` | `module`, `options`, `module_type`, `timeout_seconds` | `{check_state: vulnerable\|safe\|unsupported\|unknown, code, message, session_created:false}` — runs the module's `check` only; never exploits |
| `get_module_results` | `execution_id` (UUID) | `{execution_status: completed\|running\|errored, result}` |

### Execution — destructive (gated)

| Tool | Key parameters | Returns |
|---|---|---|
| `run_exploit` | `module`, `options`, `payload_*`, `run_as_job` | Job/session result incl. `uuid`, `session_id` |
| `run_auxiliary_module` | `module`, `options`, `run_as_job` | Module result incl. `uuid` |
| `run_post_module` | `module`, `session_id`, `options` | Module result incl. `uuid` |
| `generate_payload` | `payload`, `format`, `options`, `encoder`, … | Generated payload metadata + server save path |

The `uuid` returned by these can be passed to `get_module_results`.

### Session, listener & job control — destructive (gated)

| Tool | Key parameters | Returns |
|---|---|---|
| `send_session_command` | `session_id`, `command` | Command output |
| `terminate_session` | `session_id`, `kill_associated_job` | Termination status |
| `start_listener` | `payload`, `lhost`, `lport`, `reverselistenerbindaddress` | Handler job info |
| `stop_job` | `job_id` | Stop status |
| `kill_all_handler_jobs` | — | Count of handlers stopped |

> **Listener binding:** handlers bind `0.0.0.0` (all interfaces) by default for
> reverse-connection compatibility — a convenience default, **not** a hardened
> one. Restrict it with `reverselistenerbindaddress` on shared networks.

### Status — read-only

| Tool | Returns |
|---|---|
| `list_active_sessions` | Active sessions map |
| `list_listeners` | Handler jobs and other jobs |
| `health_check` | `{status, msf_version, database_connected, safety:{…}}` |

## Resources

| URI | Description |
|---|---|
| `msf://server/info` | Server identity, unofficial/no-affiliation flags, safety posture, and the full tool annotation taxonomy |
| `msf://module/{module}` | Documentation for a module; `{module}` is the full path with the type as the first segment (e.g. `exploit/windows/smb/ms17_010_eternalblue`). Percent-encode slashes (`%2F`) if your client cannot place them in a single URI segment |

## Input safety

Module option names and values are rejected if they contain newline, carriage
return, or NUL characters, on both the RPC and console execution paths — a guard
against console command injection (CVE-2026-5463 in the underlying
`pymetasploit3`, which has no upstream fix).

## MCP specification conformance

| Capability | Status | Notes |
|---|---|---|
| **Tools** | ✅ | 24 tools |
| **Tool annotations** | ✅ | `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` on every tool |
| **Structured tool output** | ✅ | Tools emit `structuredContent` with an output schema; the text representation is preserved for clients without structured-output support |
| **Resources** | ✅ | `msf://server/info` |
| **Resource templates** | ✅ | `msf://module/{module}` |
| **Elicitation** | ✅ (opt-in) | Destructive-action confirmation via `ctx.elicit`; falls back to the safety gate when the client cannot elicit |
| **Progress notifications** | ✅ | Long-running tools report progress via the MCP context |
| **Logging** | ✅ | Server-side structured logging |
| **Transports** | ✅ | `stdio` and streamable HTTP |
| **Prompts** | ➖ | Not implemented |
| **Sampling** | ➖ | Not used |

Protocol features are provided through **FastMCP** (pinned `>=2.10.3,<3.4.0`;
3.4.x currently fails to import — see `pyproject.toml`) on top of the official
`mcp` SDK (`>=1.28.1`).

## Comparison with the official Rapid7 MCP

| Capability | MetasploitMCP | Official Rapid7 MCP |
|---|---|---|
| Module search / info | ✅ | ✅ |
| Module execution | ✅ typed (exploit/aux/post) | ✅ generic |
| Non-destructive check | ✅ `check_vulnerability` | ✅ `ModuleCheck` |
| Async results | ✅ `get_module_results` | ✅ `ModuleResults` |
| DB intel (hosts/services/vulns/notes/creds/loot) | ✅ | ✅ |
| Payload generation | ✅ | ❌ |
| Listener / job lifecycle | ✅ | ❌ |
| Sessions | ✅ list / interact / terminate | ✅ list / read / write / stop |
| Default-off dangerous actions | ✅ | ✅ |
| Rate limiting | ✅ | ✅ |
| Tool annotations / structured output / resources / elicitation | ✅ | partial |

## Hosting the docs (GitHub)

These Markdown files render directly on GitHub. To publish a docs **site**, enable
**GitHub Pages** (Settings → Pages → Build from `main` `/docs`), optionally with a
static generator (MkDocs/Jekyll). No site is required to read the docs in-repo.
