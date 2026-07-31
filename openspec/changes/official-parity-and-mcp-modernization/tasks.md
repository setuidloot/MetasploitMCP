## 1. Phase 1 — Database intelligence tools (parity, additive)

- [x] 1.1 Add `db.*` RPC access helpers in `server.py` (`_db_connected` probe + `_db_intel` shared helper with workspace scoping + `_decode_rpc` msgpack normalization)
- [x] 1.2 Implement `list_hosts` tool (optional `workspace`; returns address/hostname/os/status)
- [x] 1.3 Implement `list_services` tool (filters: host, port, proto)
- [x] 1.4 Implement `list_vulnerabilities` tool (include references/CVE when present)
- [x] 1.5 Implement `list_notes`, `list_credentials`, `list_loot` tools
- [x] 1.6 Return structured "database unavailable" error when no DB is attached (all six tools, via `_db_intel`)
- [x] 1.7 Surface database-connection status in `health_check` (`database_connected` field)
- [x] 1.8 Add unit tests for each intel tool incl. degraded (no-DB) path and workspace scoping (tests/test_db_intel.py)

## 2. Phase 1 — Module check tool

- [ ] 2.1 Implement `check_vulnerability` routing through existing option-validation helpers with `action=check`
- [ ] 2.2 Map check outcomes to structured states (vulnerable / safe / unsupported / error)
- [ ] 2.3 Guard so the check path can never fall through to exploit execution
- [ ] 2.4 Tests: vulnerable, safe, unsupported-module, missing-required-option, and "no session/payload created" assertions

## 3. Phase 1 — Async module results

- [ ] 3.1 Ensure non-blocking module launches return a stable execution/job identifier
- [ ] 3.2 Implement `get_module_results(execution_id)` returning collected output + status (running/completed)
- [ ] 3.3 Handle unknown identifier with a structured not-found error
- [ ] 3.4 Tests: completed run, in-progress run, unknown id

## 4. Phase 2 — Safety controls (posture change)

- [ ] 4.1 Add `dangerous_actions_enabled` config (CLI `--allow-dangerous`, env `MSF_MCP_ALLOW_DANGEROUS`, default off) in `__init__.py`
- [ ] 4.2 Add a shared gate wrapper/decorator that classifies tools via their destructive annotation and blocks dangerous tools when disabled
- [ ] 4.3 Apply the gate to all destructive tools (run_exploit, run_auxiliary_module, run_post_module, generate_payload delivery, send_session_command, terminate_session, start_listener, stop_job, kill_all_handler_jobs)
- [ ] 4.4 Implement configurable per-client rate limiter with a safe default; reject over-limit with a structured error
- [ ] 4.5 Report safety posture (dangerous enabled?, active rate limit) in `health_check`
- [ ] 4.6 Tests: gate off blocks dangerous / allows read-only; gate on permits; rate-limit within/over/configurable
- [ ] 4.7 Document the default-off posture in `README.md`, `docs/`, and `CHANGELOG.md`; bump minor version

## 5. Phase 3 — Tool annotations

- [ ] 5.1 Define the read-only vs destructive taxonomy for every existing and new tool (single source shared with the safety gate)
- [ ] 5.2 Add `readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint` to every `@mcp.tool`
- [ ] 5.3 Test asserting each tool advertises the expected annotations

## 6. Phase 3 — Structured output

- [ ] 6.1 Define typed return models (Pydantic/TypedDict per FastMCP support) for intel, check, results, and existing tools
- [ ] 6.2 Wire models into tool signatures so FastMCP emits output schemas + structured content
- [ ] 6.3 Verify text-representation fallback remains for non-structured clients
- [ ] 6.4 Tests: structured content validates against schema; text fallback present

## 7. Phase 3 — Documentation resources & elicitation

- [ ] 7.1 Register module documentation as MCP resources / resource links
- [ ] 7.2 Add best-effort `ctx.elicit` confirmation to destructive tools, with safety-gate fallback when unsupported
- [ ] 7.3 Tests: confirm → proceeds, decline → cancelled result, no-elicitation client → gate fallback
- [ ] 7.4 Tests: module documentation retrievable as a resource

## 8. Phase 4 — FastMCP 3.x evaluation & dependency finalization

- [ ] 8.1 Attempt lifting the `fastmcp <3.4.0` cap on a branch; run the full suite
- [ ] 8.2 Confirm elicitation/structured-output/annotations behave on the selected `mcp`/`fastmcp` versions across stdio + HTTP/SSE
- [ ] 8.3 Either lift the cap or record the specific incompatibility rationale in the repo (CHANGELOG/docs)
- [ ] 8.4 Regenerate `poetry.lock` and `sbom.json`; ensure CI (black, pre-commit) passes

## 9. Verification & wrap-up

- [ ] 9.1 Run `openspec validate --change official-parity-and-mcp-modernization`
- [ ] 9.2 Full test suite green; update README parity/feature matrix vs official server
- [ ] 9.3 Archive the change with `/opsx:archive` (or `openspec archive`) once shipped and specs synced
