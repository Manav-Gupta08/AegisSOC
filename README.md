# AegisSOC: Security Operations and Detection Engineering Lab

AegisSOC is a self-hosted, Wazuh-based home SOC lab built to demonstrate repeatable
security-operations engineering: reliable telemetry, detection-as-code, evidence-based
detection validation, structured incident handling, and measurable operational health.

> This is a home lab. It implements *enterprise-inspired* controls and documents which
> ones are actually implemented and verified. It is not equivalent to a staffed enterprise SOC.

## Status

Every capability is tracked with one of: **PASS** (verified with evidence), **WARNING**,
**FAIL**, **NOT IMPLEMENTED**, **NOT VERIFIED**.

| Area | Status | Notes |
|---|---|---|
| Repository foundation, threat model, architecture | PASS | Docs only |
| Wazuh single-node deployment tooling | PASS | Deployed 4.14.8 on the reference host 2026-10-13; ports bound to 127.0.0.1 only |
| Least-privilege accounts, default credential removal | PASS | Reader accounts denied write/admin (HTTP 403); upstream defaults rejected |
| Health checks | PASS | 8 checks plus an opt-in default-credential probe; 9/9 PASS live with one active agent (2026-10-13, 2026-10-14) |
| Milestone 1 end-to-end detection | PASS | Real failed auth on WSL endpoint → rule 5557 alert in 0.6 s; see `reports/examples/M1-E2E-001-linux-auth-failure.json` |
| Linux endpoint (WSL2 Ubuntu agent) | PASS (FIM realtime, journald) | FIM add/delete alerts in <1 s (M2-LNX-001). auditd NOT AVAILABLE on WSL2 (kernel audit inaccessible) |
| Windows endpoint (Sysmon + agent) | FAIL | Agent installed but enrollment rejected (wrong password entered); Sysmon not installed. Installer fixed to re-prompt |
| Custom detections (Linux) | PASS | 4 rules (100100, 100200–100202): logtest positive+negative and real-event e2e; see `docs/detection-methodology.md`, M2-LNX-002 |
| Detection-as-code tooling | PASS | `aegis detections validate` (CI), `deploy` (manual, recorded), `test` (Wazuh logtest) |
| Custom detections (Windows) | NOT IMPLEMENTED | Blocked on Windows telemetry |
| Detection validation runner (scenarios) | PASS | 5 Linux scenarios (4 positive, 1 negative) all PASSED on the live endpoint; cleanup verified. `reports/examples/M5-SCN-001-linux-scenarios.json` |
| Coverage matrix | PASS | `aegis coverage` → `reports/examples/coverage-matrix.md` (separates rule exists / tested / observed) |
| Incident workflow | PASS | Case schema, lifecycle with preconditions, hash-chained replayable audit, closure immutability, evidence hashing; real case from LNX-003 alerts → `reports/examples/CASE-example-report.md` |
| Recovery after host restart | PASS (observed) | 2026-10-14: Docker Desktop restarted; containers auto-restarted; 9/9 health PASS, custom rules intact |
| Metrics | PASS | `aegis metrics`: pass/regression rate, latency, alert volume, availability, case resolution, resources; definitions in `docs/operations.md`; baseline in `reports/examples/metrics-baseline-2026-10-14.md` |
| Noise tuning | PASS | 67% of first-week alerts were verified noise: rootcheck rust-coreutils FPs (suppression 100900, e2e: 257 → 0) and manager-container SCA (disabled) |
| Alert retention | PASS | ISM policy deletes `wazuh-alerts-*` indices after 30 days (configurable); attached to existing indices (2026-10-14) |
| Backup | PASS | `aegis backup create` ran live 2026-10-14: ~795 MB, 448 s downtime, SHA-256 manifest |
| Restore verification | NOT VERIFIED | The one live run (2026-10-14) restored agents, rules, and retention policy but stopped waiting at a partial alert count (38 of 664) and reported FAILED. The wait was fixed and unit-tested; not yet re-run live |
| Linux host (Docker Engine) | NOT VERIFIED | Tooling supports it (host kernel `vm.max_map_count`, local scenario executor, owner-only secret files); unit-tested only, no live deployment yet |
| Response playbooks | PASS (offline) | 3 reviewed playbooks; case actions are proposed, approved by a second analyst, and executed **in simulation only**, all in the hash-chained audit trail. Real execution is not implemented by design |
| AegisSOC web UI | NOT IMPLEMENTED | Alerts are investigated in the Wazuh dashboard; cases, validation, coverage, and metrics are CLI + Markdown/JSON reports |
| Network IDS (Suricata) | NOT IMPLEMENTED | Optional, Profile B |

## Architecture (Profile A, lightweight)

The stack runs on one host, either Windows with Docker Desktop or Linux with Docker Engine.

```
Windows 11 host ── Docker Desktop (WSL2 VM, capped) ── wazuh.manager / wazuh.indexer / wazuh.dashboard
     │                                                       ▲  (all ports bound to 127.0.0.1)
     ├── Wazuh agent + Sysmon (Windows endpoint)  ───────────┤ 1514/1515
     └── WSL2 Ubuntu: Wazuh agent (Linux endpoint) ──────────┘

Linux host ── Docker Engine ── wazuh.manager / wazuh.indexer / wazuh.dashboard
     │                              ▲  (all ports bound to 127.0.0.1)
     └── Wazuh agent + auditd ──────┘ 1514/1515   (the host is the Linux endpoint)
```

See [docs/architecture.md](docs/architecture.md), [docs/deployment.md](docs/deployment.md)
and [docs/threat-model.md](docs/threat-model.md).

## Quick start

Prerequisites: Docker with Compose >= 2.24.4, Python >= 3.11, >= 16 GB RAM, >= 50 GB free disk.
Windows hosts use WSL2 and Docker Desktop. Host-specific steps are in [docs/deployment.md](docs/deployment.md).

Install the tooling in a virtual environment outside the repository:

```sh
# Linux
python3 -m venv ~/.venvs/aegissoc && . ~/.venvs/aegissoc/bin/activate
```

```powershell
# Windows
py -3.12 -m venv $HOME\.venvs\aegissoc; & $HOME\.venvs\aegissoc\Scripts\Activate.ps1
```

Then, from the repository root:

```sh
pip install -e ".[dev]"

aegis preflight        # read-only host checks
aegis init-secrets     # creates .env with random credentials (never committed)
aegis prepare          # downloads pinned upstream, verifies SHA-256, generates certs, renders configs
aegis up               # starts the stack (ports bound to 127.0.0.1)
aegis provision        # least-privilege reader accounts, default API user rotation, alert retention
aegis health           # health checks; JSON report in reports/runtime/
```

Dashboard: `https://127.0.0.1:5601` (user `admin`, password from `.env`).

## Repository layout

| Path | Purpose |
|---|---|
| `src/aegissoc/` | `aegis` CLI: deployment, provisioning, health, detections, scenarios, cases, metrics, backup |
| `deployment/wazuh/` | Version lock, Compose override, and centralized agent group configs |
| `deployment/endpoints/` | Endpoint installers (Wazuh agent, Sysmon, auditd) |
| `deployment/wsl/` | Recommended WSL2 resource limits (Windows hosts) |
| `detections/` | Custom Wazuh rules and their metadata (detection-as-code) |
| `scenarios/` | Reviewed simulation manifests with expected detections |
| `playbooks/` | Reviewed response playbooks (manual steps and simulation-only actions) |
| `schemas/` | Incident case JSON Schema |
| `reports/examples/` | Sanitized evidence from the live lab |
| `benchmarks/` | Measured resource usage |
| `docs/` | Architecture, deployment, threat model, telemetry, detection, incident response, operations |
| `tests/unit/` | Offline unit tests (no live stack required) |

## Principles

- No invented telemetry, detections, or results. Synthetic unit fixtures are labelled as such.
- A simulation passing requires an observed alert, not a successful command.
- No secrets in Git; TLS verification is never disabled.
- No automated destructive response actions.

## Author

**Manav Gupta**

CyberSecurity Student | Software Developer | Backend Engineer

## License

MIT for AegisSOC code. Wazuh and other third-party components retain their own licenses.
