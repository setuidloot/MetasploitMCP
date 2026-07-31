## Why

The official Rapid7 Metasploit MCP server (`lib/msf/core/mcp`) and MetasploitMCP have grown into complementary-but-uneven tool sets: we lead on payload generation, listener/handler lifecycle, and execution ergonomics, but expose **none** of the Metasploit workspace database (hosts, services, vulns, notes, creds, loot), have no non-destructive vulnerability *check*, no async results retrieval, and no default-off safety gate. At the same time our FastMCP dependency is pinned below 3.x (`>=2.10.3,<3.4.0`) and we do not yet declare the tool metadata (annotations, structured output, elicitation) that the current MCP specification (2026-07-28) and modern clients rely on.

Closing the parity gaps makes MetasploitMCP a credible drop-in for teams evaluating the official server, and adopting the newer MCP surface keeps us compatible with hosts that increasingly gate behavior on tool annotations and structured output.

## What Changes

- **Add read-only MSF database intelligence tools** mirroring the official server: `list_hosts`, `list_services`, `list_vulnerabilities`, `list_notes`, `list_credentials`, `list_loot`, scoped to a workspace, backed by the existing RPC client (`db.*` RPC group).
- **Add a non-destructive `check_vulnerability` tool** that invokes a module's `check` method (equivalent to official `ModuleCheck`) without firing the exploit.
- **Add async execution-results retrieval** (`get_module_results`) so long-running module runs can be polled after launch (equivalent to official `ModuleResults`).
- **Add a default-off "dangerous actions" safety gate** plus per-client rate limiting, so destructive tools (exploit execution, session control, payload delivery) are disabled unless explicitly enabled — matching the official server's default-safe posture.
- **Annotate every tool** with MCP tool hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) so clients can reason about and gate tool behavior.
- **Add structured output schemas** to tool returns so clients receive typed, validated results instead of loosely-typed dicts.
- **Add elicitation-based confirmation** for destructive operations, so a compliant client can prompt the user before an exploit fires or a session is terminated.
- **Expose module documentation as MCP resources / resource links** rather than only tool return payloads.
- **Evaluate and (if viable) unblock the FastMCP 3.x upgrade path** — the dependency is currently capped at `<3.4.0`; determine what breaks and either lift the cap or document why it stays. **BREAKING** if the upgrade changes transport or decorator behavior for existing deployments.

## Capabilities

### New Capabilities
- `msf-database-intel`: Read-only tools that expose the Metasploit workspace database (hosts, services, vulnerabilities, notes, credentials, loot) over the existing RPC client, workspace-scoped.
- `module-check`: A non-destructive tool that runs a module's `check` method to assess exploitability without executing the exploit.
- `module-results`: Retrieval of results/output for asynchronously-launched module executions.
- `safety-controls`: A default-off dangerous-actions gate and per-client rate limiting governing which tools may run.
- `mcp-protocol-modernization`: Tool annotations, structured output schemas, elicitation-based confirmation, documentation resources, and the FastMCP 3.x compatibility evaluation.

### Modified Capabilities
<!-- No pre-existing OpenSpec specs exist in openspec/specs/ (this is the first change in a newly initialized OpenSpec project), so there are no prior requirement specs to modify. The modernization capability above governs behavioral changes to existing tools (annotations/structured output/elicitation) as net-new requirements. -->

## Impact

- **Code**: `src/metasploit_mcp/server.py` (new `@mcp.tool` functions, annotations, structured return models, elicitation calls, resource registration); `src/metasploit_mcp/__init__.py` (new CLI flags for the safety gate / rate limits); `src/metasploit_mcp/instance_manager.py` (RPC access for `db.*` groups).
- **APIs / RPC**: New reliance on the Metasploit `db.*` RPC group (hosts/services/vulns/notes/creds/loot) and module `check` RPC; requires a database-connected `msfrpcd`.
- **Dependencies**: Potential bump of `fastmcp` past `<3.4.0` and `mcp` to a version supporting elicitation/structured output/annotations; `pyproject.toml` + `poetry.lock` + `sbom.json` regeneration.
- **Config / deployment**: New default-off behavior for destructive tools is a posture change for existing operators (must opt in to restore current behavior); documented in `README.md` and `docs/`.
- **Tests**: New unit/integration tests under `tests/` for each tool, the safety gate, and annotation/structured-output contracts.
