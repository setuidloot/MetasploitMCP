# Security Policy

MetasploitMCP exposes Metasploit Framework capabilities to MCP clients. It is an
offensive-security tool intended **only** for authorized testing. Please use it
responsibly and operate it only against systems you own or are explicitly
authorized to test.

## Supported versions

Security fixes are provided for the latest released `3.x` line.

| Version | Supported |
| ------- | --------- |
| 3.x     | ✅        |
| < 3.0   | ❌        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab).

When reporting, please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version(s) and configuration.

We aim to acknowledge reports within a few business days and will coordinate a
fix and disclosure timeline with you.

## Operational guidance

- Never expose the Metasploit RPC service or this MCP server to untrusted
  networks. Bind to `127.0.0.1` unless you have a specific, secured reason not to.
- Use a strong `MSF_PASSWORD`; never commit credentials. Configuration is read
  from environment variables (see the README).
- Generated payloads and active sessions provide real attack capability — handle
  and store them accordingly.

## Known dependency advisories

- **`pymetasploit3`** (GHSA-qpc3-8vqg-8g6w) — the latest published release
  (`1.0.6`) carries a command-injection advisory in
  `console.run_module_with_output()`, and no fixed version is available upstream.
  This is a required runtime dependency. Because MetasploitMCP's purpose is to
  execute operator-chosen Metasploit modules through the RPC interface, this path
  does not add attack surface beyond the tool's intended function, and the
  operator already controls the commands being run. We track the advisory and
  will pin a fixed release as soon as one is published. Continue to run the
  Metasploit RPC service and this server only on trusted, authorized networks.
