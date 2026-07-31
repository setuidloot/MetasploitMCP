## ADDED Requirements

### Requirement: List hosts from the workspace database

The system SHALL provide a read-only tool that returns hosts recorded in the Metasploit workspace database, optionally scoped to a named workspace, without modifying any state.

#### Scenario: Hosts returned for the default workspace

- **WHEN** a client calls the host-listing tool with no workspace argument
- **THEN** the system returns hosts from the default workspace with at least address, hostname, OS, and status fields

#### Scenario: Hosts scoped to a named workspace

- **WHEN** a client calls the host-listing tool with a `workspace` argument
- **THEN** the system returns only hosts belonging to that workspace

#### Scenario: Database not connected

- **WHEN** the tool is invoked but the connected `msfrpcd` has no database attached
- **THEN** the system returns a structured error indicating the database is unavailable rather than raising an unhandled exception

### Requirement: List services from the workspace database

The system SHALL provide a read-only tool that returns services recorded in the workspace database, filterable by host and by port.

#### Scenario: Services returned with port and protocol

- **WHEN** a client calls the service-listing tool
- **THEN** each returned service includes host address, port, protocol, name, and state

#### Scenario: Services filtered by host

- **WHEN** a client calls the service-listing tool with a host filter
- **THEN** only services for that host are returned

### Requirement: List vulnerabilities from the workspace database

The system SHALL provide a read-only tool that returns vulnerabilities recorded in the workspace database, including any associated references.

#### Scenario: Vulnerabilities returned with references

- **WHEN** a client calls the vulnerability-listing tool
- **THEN** each returned vulnerability includes host, name, and reference identifiers (e.g., CVE) when present

### Requirement: List notes, credentials, and loot from the workspace database

The system SHALL provide read-only tools that return notes, credentials, and loot recorded in the workspace database.

#### Scenario: Notes returned

- **WHEN** a client calls the note-listing tool
- **THEN** notes are returned with host, type, and data fields

#### Scenario: Credentials returned

- **WHEN** a client calls the credential-listing tool
- **THEN** credentials are returned with associated host/service, public, and private components

#### Scenario: Loot returned

- **WHEN** a client calls the loot-listing tool
- **THEN** loot entries are returned with host, type, and stored path/name

### Requirement: Database intelligence tools are non-destructive

All database intelligence tools SHALL be read-only and SHALL NOT create, modify, or delete any workspace records.

#### Scenario: No write occurs

- **WHEN** any database intelligence tool is invoked
- **THEN** the workspace database contents are unchanged after the call
