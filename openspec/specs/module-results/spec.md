# module-results Specification

## Purpose
TBD - created by archiving change official-parity-and-mcp-modernization. Update Purpose after archive.
## Requirements
### Requirement: Retrieve results of an asynchronously launched module

The system SHALL provide a tool that retrieves the accumulated output and status of a module execution that was launched asynchronously, identified by an execution/job identifier returned at launch time.

#### Scenario: Results available for a completed run

- **WHEN** a client requests results for an execution identifier whose module run has completed
- **THEN** the system returns the collected console/framework output and a status of "completed"

#### Scenario: Run still in progress

- **WHEN** a client requests results for an execution identifier whose module run is still running
- **THEN** the system returns any partial output collected so far and a status of "running"

#### Scenario: Unknown execution identifier

- **WHEN** a client requests results for an identifier that does not correspond to a known execution
- **THEN** the system returns a structured error indicating the identifier was not found

### Requirement: Asynchronous launch surfaces a retrievable identifier

When a module-executing tool is run in a non-blocking mode, the system SHALL return an execution/job identifier that can subsequently be passed to the results-retrieval tool.

#### Scenario: Identifier returned on async launch

- **WHEN** a module-executing tool is invoked in non-blocking mode
- **THEN** the response includes an execution/job identifier usable with the results-retrieval tool

