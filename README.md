# AegisSOC — Security Operations & Detection Engineering Platform

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
| Health checks | PASS | 9/9 PASS live with one active agent (2026-10-13) |
| Milestone 1 end-to-end detection | PASS | Real failed auth on WSL endpoint → rule 5557 alert in 0.6 s; see `reports/examples/M1-E2E-001-linux-auth-failure.json` |
| Linux endpoint (WSL2 Ubuntu agent) | PASS (FIM realtime, journald) | FIM add/delete alerts in <1 s (M2-LNX-001). auditd NOT AVAILABLE on WSL2 (kernel audit inaccessible) |
| Windows endpoint (Sysmon + agent) | FAIL | Agent installed but enrollment rejected (wrong password entered); Sysmon not installed. Installer fixed to re-prompt |
| Custom detections (Linux) | PASS | 4 rules (100100, 100200–100202): logtest positive+negative and real-event e2e; see `docs/detection-methodology.md`, M2-LNX-002 |
| Detection-as-code tooling | PASS | `aegis detections validate` (CI), `deploy` (manual, recorded), `test` (Wazuh logtest) |
| Custom detections (Windows) | NOT IMPLEMENTED | Blocked on Windows telemetry |
| Detection validation runner (scenarios) | PASS | 5 Linux scenarios (4 positive, 1 negative) all PASSED on the live endpoint; cleanup verified. `reports/examples/M5-SCN-001-linux-scenarios.json` |
| Coverage matrix | PASS | `aegis coverage` → `reports/examples/coverage-matrix.md` (separates rule exists / tested / observed) |
| Incident workflow | NOT IMPLEMENTED | Phase 6 |
| Network IDS (Suricata) | NOT IMPLEMENTED | Optional, Profile B |

## Architecture (Profile A — lightweight)

```
Windows 11 host ── Docker Desktop (WSL2 VM, capped) ── wazuh.manager / wazuh.indexer / wazuh.dashboard
     │                                                       ▲  (all ports bound to 127.0.0.1)
     ├── Wazuh agent + Sysmon (Windows endpoint)  ───────────┤ 1514/1515
     └── WSL2 Ubuntu: Wazuh agent + auditd (Linux endpoint) ─┘
```

See [docs/architecture.md](docs/architecture.md), [docs/deployment.md](docs/deployment.md)
and [docs/threat-model.md](docs/threat-model.md).

## Quick start

Prerequisites: Windows 10/11 with WSL2, Docker Desktop (Compose >= 2.24.4), Python >= 3.11,
>= 16 GB RAM, >= 50 GB free disk.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

aegis preflight        # read-only host checks
aegis init-secrets     # creates .env with random credentials (never committed)
aegis prepare          # downloads pinned upstream, verifies SHA-256, generates certs, renders configs
aegis up               # starts the stack (ports bound to 127.0.0.1)
aegis provision        # creates least-privilege reader accounts, rotates default API user
aegis health           # writes a JSON health report to reports/runtime/
```

Dashboard: `https://127.0.0.1:5601` (user `admin`, password from `.env`).

## Repository layout

| Path | Purpose |
|---|---|
| `src/aegissoc/` | Python tooling: deployment, provisioning, health checks |
| `deployment/wazuh/` | Version lock and Compose overrides for the upstream single-node stack |
| `deployment/endpoints/` | Endpoint agent installation scripts |
| `deployment/wsl/` | Recommended WSL2 resource limits |
| `docs/` | Architecture, deployment, threat model |
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
