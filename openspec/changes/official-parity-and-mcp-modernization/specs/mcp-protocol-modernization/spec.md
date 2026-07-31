## ADDED Requirements

### Requirement: Tools declare behavior annotations

Every registered tool SHALL declare MCP tool annotations describing its behavior, including at minimum `readOnlyHint` and `destructiveHint`, and SHALL set `idempotentHint` and `openWorldHint` where applicable, so clients can reason about and gate tool behavior.

#### Scenario: Read-only tool annotated

- **WHEN** a client inspects a database-intel or info/check tool
- **THEN** the tool advertises `readOnlyHint: true` and `destructiveHint: false`

#### Scenario: Destructive tool annotated

- **WHEN** a client inspects an exploit-execution or session-termination tool
- **THEN** the tool advertises `destructiveHint: true`

### Requirement: Tools return structured output

Tools SHALL return structured, schema-typed output (via declared output schemas / typed return models) so that compliant clients receive validated results, while remaining backward-compatible with clients that consume the text representation.

#### Scenario: Structured result validates against schema

- **WHEN** a client that supports structured output calls a tool
- **THEN** the returned structured content conforms to the tool's declared output schema

#### Scenario: Text fallback preserved

- **WHEN** a client that does not support structured output calls the same tool
- **THEN** the client still receives a usable text representation of the result

### Requirement: Destructive operations support elicitation-based confirmation

When the connected client supports elicitation, the system SHALL be able to request explicit user confirmation before performing a destructive operation (e.g., firing an exploit or terminating a session).

#### Scenario: User confirms a destructive action

- **WHEN** a destructive tool is invoked with confirmation required and the client supports elicitation, and the user approves
- **THEN** the operation proceeds

#### Scenario: User declines a destructive action

- **WHEN** the elicited user declines the confirmation
- **THEN** the operation is aborted and the system returns a structured "cancelled by user" result

#### Scenario: Client without elicitation support

- **WHEN** a destructive tool is invoked and the client does not support elicitation
- **THEN** the system falls back to the configured safety-gate behavior rather than blocking indefinitely

### Requirement: Module documentation exposed as resources

The system SHALL expose module documentation via MCP resources / resource links, in addition to any tool-returned documentation payloads.

#### Scenario: Documentation retrievable as a resource

- **WHEN** a client lists or reads MCP resources for a given module
- **THEN** the module's documentation is available as a resource (or referenced via a resource link) with appropriate metadata

### Requirement: FastMCP 3.x compatibility is evaluated and resolved

The system SHALL evaluate the FastMCP 3.x upgrade path (currently constrained to `<3.4.0`) and SHALL either lift the version cap after confirming compatibility or record a documented rationale for retaining it.

#### Scenario: Upgrade evaluation is documented

- **WHEN** the modernization work is complete
- **THEN** the repository records whether the FastMCP version cap was lifted, and if retained, the specific incompatibility that justifies it

#### Scenario: Test suite passes on the selected version

- **WHEN** the FastMCP version constraint is finalized
- **THEN** the existing and new test suites pass against the pinned version
