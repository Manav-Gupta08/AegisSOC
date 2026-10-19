# Contributing

## Commit conventions

One coherent, verified change per commit. Prefixes:

| Prefix | Use |
|---|---|
| `feat:` | New capability |
| `fix:` | Bug fix (add a regression test when practical) |
| `test:` | Tests only |
| `docs:` | Documentation only |
| `build:` | Packaging, CI, deployment plumbing |
| `security:` | Hardening or security fixes |
| `detect:` | Detection rule add/change (Phase 4+) |

Reference the verification performed in the commit body (test command, health report, evidence path).

## Before opening a pull request

```sh
pytest
```

- Unit tests pass.
- No secrets, real hostnames, IPs, usernames, or raw logs in the diff.
- Docs updated when behavior or status changes (README status table included).
- Status claims are backed by evidence (PASS requires a reproducible check).

## Detection rule review (applies from Phase 4)

Every custom rule change must include:

1. Stable rule ID in the AegisSOC range for its kind (detections 100000–100799, pipeline checks 100800–100899,
   suppressions 100900–100999). IDs are never reused.
2. Rationale, required telemetry, severity, and ATT&CK mapping where justified.
3. Positive and negative test cases.
4. False-positive considerations and known limitations.
5. Investigation guidance.

Reviewers check logic, noise risk, test coverage, and that CI did not deploy anything to a
live stack. CI validates; humans approve; deployment is a manual, documented step.

## Evidence

- Synthetic fixtures are built inside the tests and must be labelled synthetic (module docstring or comment).
- Real lab evidence is sanitized before commit and stored under `reports/examples/`.
