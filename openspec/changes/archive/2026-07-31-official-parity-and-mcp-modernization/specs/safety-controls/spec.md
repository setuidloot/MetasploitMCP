## ADDED Requirements

### Requirement: Dangerous actions enabled by default with opt-in safe mode

Because this is an offensive-security tool whose full toolset has always been available, the system SHALL treat state-changing / offensive operations (exploit execution, payload delivery, session command execution, session termination, listener/job control) as "dangerous actions" that are ENABLED by default, and SHALL provide an opt-in "safe mode" (CLI flag or environment variable) that disables them while leaving read-only tools available. This deliberately inverts the official Rapid7 server's default-off posture to avoid regressing existing users.

#### Scenario: Dangerous tool allowed by default

- **WHEN** a client invokes a dangerous tool with no safety configuration applied
- **THEN** the system performs the operation normally

#### Scenario: Dangerous tool blocked in safe mode

- **WHEN** the operator has enabled safe mode and a client invokes a dangerous tool
- **THEN** the system refuses the operation and returns a structured error explaining that the server is in safe mode and how to re-enable dangerous tools

#### Scenario: Read-only tools always available in safe mode

- **WHEN** safe mode is enabled and a client invokes a read-only tool (e.g., database intel, module info, check)
- **THEN** the system performs the read-only operation normally

### Requirement: Optional rate limiting

The system SHALL support a configurable request rate limit that is OFF by default (to avoid throttling existing automation) and, when enabled, rejects requests that exceed the limit.

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
