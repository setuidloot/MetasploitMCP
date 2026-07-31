## Context

MetasploitMCP is a standalone Python FastMCP server (`src/metasploit_mcp/`, ~7.5k LOC, tools concentrated in `server.py`) that talks to a running `msfrpcd` via `pymetasploit3` (with a local `jsonrpc_patch.py`). It currently exposes 16 tools centered on module discovery, execution (`run_exploit`/`run_auxiliary_module`/`run_post_module`), payload generation, session interaction, and listener/job lifecycle.

The official Rapid7 MCP (`lib/msf/core/mcp`) ships in-tree in the framework and takes a different shape: a generic `ModuleExecute` plus `ModuleCheck`/`ModuleResults`, six read-only database-intel tools (hosts/services/vulns/notes/creds/loot), split `SessionRead`/`SessionWrite`, `RunningStats`, and a hardened deployment layer (default-off `dangerous_actions`, per-client rate limiting, bearer-token HTTP auth, structured/sanitized logging).

Constraints:
- All new capabilities must go through the same RPC client; the `db.*` RPC group requires a database-connected `msfrpcd` (not guaranteed in every deployment).
- FastMCP is pinned `>=2.10.3,<3.4.0` (cap added deliberately in a recent commit) and `mcp >=1.6.0`. Newer protocol features (elicitation, structured output, annotations) require specific minimum versions.
- The project has an extensive existing test suite (`tests/`) and CI expectations (black, pre-commit, SBOM generation) that new code must satisfy.

## Goals / Non-Goals

**Goals:**
- Reach functional parity with the official server's *read* surface (database intel), its *check* and *async-results* tools, and its default-safe posture.
- Adopt current MCP protocol affordances (tool annotations, structured output, elicitation, documentation resources) without breaking existing clients.
- Make a defensible, tested decision on the FastMCP 3.x cap.
- Keep changes incremental and independently shippable (phased tasks), so parity can land before the heavier protocol/dependency work.

**Non-Goals:**
- Re-architecting execution into a single generic `execute_module` tool (we keep the ergonomic typed tools; parity is about coverage, not shape).
- Adding *write* database tools (host/vuln creation). Official intel tools are read-only; we match that.
- Implementing bearer-token HTTP auth in this change (tracked separately; safety-controls here covers the gate + rate limiting, which are the higher-value posture items).
- Adopting MCP "Apps"/interactive-UI extensions or the stateless-core transport rewrite from the 2026-07-28 spec.

## Decisions

**D1 — Database intel via the `db.*` RPC group, workspace-scoped, read-only.**
Implement `list_hosts/list_services/list_vulnerabilities/list_notes/list_credentials/list_loot` as thin wrappers over the existing client's `db.*` calls, each accepting an optional `workspace` and relevant filters. Rationale: reuses the established RPC path in `instance_manager.py`; keeps them trivially annotatable as read-only. Alternative considered: parsing `msfconsole` `hosts`/`services` output — rejected as brittle vs. the structured RPC.
- *Degraded mode*: when no DB is attached, return a structured "database unavailable" error (per spec) instead of throwing, and surface DB status in `health_check`.

**D2 — `check_vulnerability` reuses the module-execution plumbing with `action=check`.**
Rather than a new code path, route through the existing option-validation/module-object helpers (`_get_module_object`, `_set_module_options`, `_get_module_valid_options`) and invoke the module's check. Rationale: inherits option validation and error extraction already built for `run_exploit`. Trade-off: must ensure the check path never falls through to `exploit`.

**D3 — Async results via a launch-time execution id.**
Extend the existing async/non-blocking execution mode to return a stable identifier (job id / console id / uuid already available from the RPC layer) and add `get_module_results(execution_id)` that reads accumulated output for that id. Rationale: mirrors `ModuleResults` and fits our existing console/job model. Alternative: server-side buffering of all runs — rejected as stateful and memory-unbounded.

**D4 — Safety gate as a central decorator + config, not per-tool branching.**
Introduce a `dangerous_actions_enabled` flag (CLI `--allow-dangerous` / env `MSF_MCP_ALLOW_DANGEROUS`, default off) and a per-client rate limiter, applied via a shared decorator/wrapper that classifies each tool by its annotation (`destructiveHint`). Rationale: single source of truth, and reuses the same read-only/destructive taxonomy as D6 so classification is declared once. Alternative: manual `if not enabled` in each tool — rejected as error-prone and easy to forget on new tools.
- *Breaking-posture note*: default-off changes behavior for current operators; documented in README + CHANGELOG, with the enable flag prominently surfaced.

**D5 — Structured output via typed return models.**
Define Pydantic result models (or `TypedDict`/dataclasses per FastMCP's supported mechanism) for each tool's return, letting FastMCP emit an output schema + structured content while retaining the text representation for older clients. Rationale: FastMCP derives schemas from annotations; low-friction and backward compatible. Trade-off: touches every tool signature; do it in a dedicated phase after parity tools exist so models are written once.

**D6 — Annotations declared at the `@mcp.tool` decorator.**
Every tool declares `readOnlyHint/destructiveHint/idempotentHint/openWorldHint`. This taxonomy is authored once and consumed by both the client and the D4 safety gate.

**D7 — Elicitation is best-effort with a safety-gate fallback.**
Destructive tools attempt `ctx.elicit(...)` for confirmation when the client supports it; when unsupported, fall back to the D4 gate (i.e., require the operator to have pre-enabled dangerous actions) rather than blocking. Rationale: elicitation support varies by client; the gate guarantees a safe default regardless.

**D8 — FastMCP 3.x: evaluate on a branch, decide with tests.**
Attempt the bump in isolation, run the full suite, and either lift the cap or document the specific breakage. Rationale: the cap was intentional; we must not lift it blind. This is the last phase because annotations/structured-output/elicitation may themselves depend on the version outcome.

## Risks / Trade-offs

- **DB not attached in many deployments** → intel tools degrade to structured errors and `health_check` reports DB status; documented as a prerequisite.
- **Default-off dangerous actions surprises existing users** → prominent CHANGELOG/README note, clear enable flag, and health output showing current posture.
- **Structured-output refactor is broad and could regress return shapes** → introduce models incrementally per-tool with tests asserting both structured and text outputs; land after parity tools.
- **Elicitation/structured-output require newer `mcp`/`fastmcp` than currently pinned** → gate these behind D8; if the cap can't be lifted, implement annotations (widely supported) and defer the version-locked features with a documented follow-up.
- **`check` path accidentally exploiting** → explicit tests asserting no session/payload results from a check call.
- **Rate limiter correctness under concurrent async clients** → reuse a well-tested token-bucket approach and add concurrency tests alongside existing session-locking tests.

## Migration Plan

1. **Phase 1 (parity, additive, non-breaking):** database intel tools, `check_vulnerability`, `get_module_results`. Ship-able alone.
2. **Phase 2 (posture):** safety gate + rate limiting, default off-for-dangerous. Behavior change — bump minor version, CHANGELOG entry, README section, health-check surface.
3. **Phase 3 (protocol):** annotations (all tools) → structured output models → documentation resources → elicitation confirmation.
4. **Phase 4 (dependency):** FastMCP 3.x evaluation; lift cap or document; regenerate `poetry.lock` + `sbom.json`.
- **Rollback:** each phase is a separate commit/PR; Phase 2 posture is revertible via config (operators can enable dangerous actions to restore prior behavior without a code rollback).

## Open Questions

- Which exact `mcp`/`fastmcp` minimum versions expose elicitation + structured output in a form compatible with our transport (`stdio` + streamable HTTP/SSE)? Resolved in Phase 4/D8.
- Should rate limiting apply to `stdio` (single trusted client) or only HTTP transport? Leaning HTTP-primary with a global fallback.
- Do we also want to add `RunningStats`-equivalent monitoring, or is the existing `health_check` sufficient parity? (Proposed: fold framework stats into `health_check` rather than a new tool.)
- Should `send_session_command` be split into read/write to match `SessionRead`/`SessionWrite`, or is the combined tool preferable for ergonomics? (Proposed: keep combined; note the divergence.)
