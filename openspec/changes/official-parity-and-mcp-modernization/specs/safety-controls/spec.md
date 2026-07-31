## ADDED Requirements

### Requirement: Dangerous actions disabled by default

The system SHALL treat state-changing / offensive operations (exploit execution, payload delivery, session command execution, session termination, listener/job control) as "dangerous actions" that are DISABLED by default and only enabled when the operator explicitly opts in via configuration (CLI flag or environment variable).

#### Scenario: Dangerous tool blocked when gate is off

- **WHEN** a client invokes a dangerous tool while the dangerous-actions gate is disabled (default)
- **THEN** the system refuses the operation and returns a structured error explaining that dangerous actions are disabled and how to enable them

#### Scenario: Dangerous tool allowed when gate is on

- **WHEN** the operator has explicitly enabled dangerous actions and a client invokes a dangerous tool
- **THEN** the system performs the operation normally

#### Scenario: Read-only tools always available

- **WHEN** the dangerous-actions gate is disabled and a client invokes a read-only tool (e.g., database intel, module info, check)
- **THEN** the system performs the read-only operation normally

### Requirement: Per-client rate limiting

The system SHALL enforce a configurable per-client request rate limit with a safe default, rejecting requests that exceed the limit.

#### Scenario: Requests within limit succeed

- **WHEN** a client issues requests at or below the configured rate limit
- **THEN** all requests are processed

#### Scenario: Requests over limit are throttled

- **WHEN** a client exceeds the configured rate limit within the window
- **THEN** the system rejects the excess requests with a structured rate-limit error and does not execute the underlying operation

#### Scenario: Rate limit is configurable

- **WHEN** the operator sets a rate-limit configuration value
- **THEN** the enforced limit reflects the configured value

### Requirement: Safety configuration is discoverable

The system SHALL document and expose the current safety posture (whether dangerous actions are enabled and the active rate limit) via the health/status surface.

#### Scenario: Health output reports safety posture

- **WHEN** a client queries the health/status tool
- **THEN** the response indicates whether dangerous actions are enabled and the active rate-limit setting
