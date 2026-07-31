# module-check Specification

## Purpose
TBD - created by archiving change official-parity-and-mcp-modernization. Update Purpose after archive.
## Requirements
### Requirement: Non-destructive vulnerability check

The system SHALL provide a tool that runs a module's `check` method against a target to assess exploitability WITHOUT executing the exploit or delivering a payload.

#### Scenario: Target reported vulnerable

- **WHEN** a client invokes the check tool for a module and target whose `check` reports the target is vulnerable
- **THEN** the system returns a structured result whose check state indicates "vulnerable" (or "appears vulnerable")

#### Scenario: Target reported safe

- **WHEN** a client invokes the check tool and the module's `check` reports the target is not exploitable
- **THEN** the system returns a structured result indicating "safe" / "not vulnerable"

#### Scenario: Module does not support check

- **WHEN** a client invokes the check tool for a module that does not implement `check`
- **THEN** the system returns a structured result indicating the check is unsupported rather than an unhandled error

#### Scenario: Check performs no exploitation

- **WHEN** the check tool runs
- **THEN** no session is created and no payload is delivered as a result of the check

### Requirement: Check tool honors option validation

The check tool SHALL validate and apply supplied module options (e.g., `RHOSTS`, `RPORT`) before running the check, and SHALL report invalid options clearly.

#### Scenario: Required option missing

- **WHEN** a client invokes the check tool without a required option such as `RHOSTS`
- **THEN** the system returns a structured error naming the missing required option

