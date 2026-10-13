# Security Policy

## Scope

AegisSOC is a lab platform. Security issues in scope include:

- Secrets or credentials exposed by AegisSOC tooling, reports, or logs.
- Tooling that disables or weakens TLS verification.
- Unsafe handling of untrusted log content (injection into reports, shells, or queries).
- Deployment defaults that expose management interfaces beyond localhost.
- Simulation or response tooling that can act outside an authorized lab.

Vulnerabilities in Wazuh, OpenSearch, Sysmon, or other upstream components should be
reported to those projects directly.

## Reporting

Use GitHub's **private vulnerability reporting** for this repository
(Security tab → Report a vulnerability). Do not open public issues for security reports.

Include affected file/version, reproduction steps, and impact. Do not include real
credentials or unsanitized logs.

## Handling rules for contributors

- Never commit `.env`, certificates, private keys, `authd.pass`, or raw endpoint logs.
- Use synthetic credentials and documentation-reserved addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.
- If a secret is committed, rotate it first, then remove it from history.
