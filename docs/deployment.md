# Deployment

## Verified host (reference)

| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200 |
| CPU | Intel i7-6700, 4 cores / 8 threads |
| RAM | 15.9 GB |
| Storage | Repository and Docker data on a drive with > 400 GB free |
| Virtualization | Hyper-V / Virtual Machine Platform enabled; WSL 2.7.14 |
| Docker | Docker Desktop 29.8.2 (WSL2 backend) |
| Python | 3.12.10 |

## Deployment profiles

### Profile A — Lightweight home lab (default)

| Component | Placement | Memory budget |
|---|---|---|
| wazuh.indexer | Docker, heap 1 GB | limit 2.5 GB |
| wazuh.manager | Docker | limit 3 GB |
| wazuh.dashboard | Docker | limit 1 GB |
| Linux endpoint | WSL2 Ubuntu distro (same VM) | ~0.3 GB |
| Windows endpoint | Host | ~0.2 GB (agent + Sysmon) |
| **WSL2 VM cap** | `.wslconfig` | **10 GB**, 6 processors, 4 GB swap |

Leaves ~6 GB for Windows. Retention target: 14–30 days of alerts, adjusted after measuring
real daily volume (Phase 7). Simulations run sequentially.

These figures are **budgets, not measurements**. Actual consumption will be recorded with
`docker stats` after deployment and stored in `benchmarks/`.

### Profile B — Expanded lab (optional, not implemented)

Adds a disposable Windows VM (~4 GB) for attack simulations, Suricata on a sensor with real
traffic visibility, and longer retention. On this host Profile B components cannot all run
at the same time as Profile A; they must be scheduled.

## Network topology

| Port | Service | Bound to | Reachable from |
|---|---|---|---|
| 1514/tcp | Agent events | `AEGIS_AGENT_BIND` (default `127.0.0.1`) | Host, WSL distros (see below) |
| 1515/tcp | Agent enrollment (password) | `AEGIS_AGENT_BIND` | Same |
| 55000/tcp | Wazuh API | `127.0.0.1` | Host only |
| 9200/tcp | Indexer | `127.0.0.1` | Host only |
| 5601/tcp | Dashboard (`AEGIS_DASHBOARD_PORT`) | `127.0.0.1` | Host only |
| 514/udp | Syslog | not published | — |

**WSL2 Ubuntu reachability (VERIFIED 2026-10-13, default NAT networking).** With Docker Desktop's
WSL2 backend, the Ubuntu distro reaches the agent ports on `127.0.0.1` without `networkingMode=mirrored`
(`nc -zv 127.0.0.1 1515` succeeded). If a future WSL/Docker change breaks this, options in order:

1. `networkingMode=mirrored` in `.wslconfig` — Windows and WSL share loopback.
2. Set `AEGIS_AGENT_BIND` to the Windows `vEthernet (WSL)` adapter IP and restrict with a
   Windows Firewall rule scoped to the WSL subnet. Never use `0.0.0.0`.

The agent install script tests connectivity before enrolling.

**Dashboard port.** The default is 5601. Port 8443 was rejected on the reference host because a
Windows service (`svchost`) already listens on it; `aegis preflight` now reports busy ports.

## Procedure

```powershell
# 0. One-time: apply WSL limits (review first, then restart WSL)
#    Copy deployment/wsl/wslconfig.example to %UserProfile%\.wslconfig, merge with any existing settings
wsl --shutdown          # restarts Docker Desktop's VM; start Docker Desktop again afterwards

# 1. Tooling
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 2. Deploy
aegis preflight
aegis init-secrets
aegis prepare
aegis up
aegis provision         # after the stack is healthy (indexer takes 1-5 minutes)
aegis health
```

### What `aegis prepare` does

1. Downloads `wazuh-docker` at the tag pinned in `deployment/wazuh/stack.lock.json` and refuses to
   continue unless its SHA-256 matches the lock file.
2. Extracts it to `deployment/wazuh/upstream/` (git-ignored) using safe tar extraction.
3. Generates the stack certificates with the upstream `wazuh-certs-generator` (skipped if present).
4. Hashes the indexer passwords with the indexer image's own `hash.sh` and renders
   `internal_users.yml` containing only `admin` and `kibanaserver` (demo users removed).
5. Renders the manager `ossec.conf` with `use_password=yes` and an `authd.pass` file.
6. Renders the dashboard `wazuh.yml` with the generated API password.

Rendered files live in `deployment/wazuh/runtime/` (git-ignored).

### Idempotency and data safety

- `prepare` never overwrites existing certificates, and only re-renders configs with `--force-render`.
- Indexer password changes after first start require the documented `securityadmin.sh` procedure;
  `prepare` warns when the indexer volume already exists.
- `aegis compose` refuses `down -v` / `--volumes`. Data volumes are never deleted by AegisSOC tooling.
- `aegis stop` stops containers; it does not remove them or their volumes.

### `vm.max_map_count`

The indexer requires `vm.max_map_count >= 262144` in the Docker Desktop VM. `aegis up` checks it and
sets it with `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` if lower. The setting does not
persist across `wsl --shutdown`; `aegis up` re-applies it.

### First-start timing (observed 2026-10-13)

- The indexer took ~6 minutes from container start to an initialized security index (HTTP 503 until
  then, 401 after). Cluster-state writes took ~10 s each, which points to slow storage for the Docker disk image.
- Run `aegis provision` only after the indexer answers 401 to unauthenticated requests.
- Wazuh API password updates can exceed the API's 10 s request timeout and return HTTP 500 even though
  the change is committed. `aegis provision` confirms the change by logging in before treating it as a failure.

### Troubleshooting notes

| Symptom | Cause | Fix |
|---|---|---|
| `ports are not available ... 127.0.0.1:8443 ... forbidden` | Port already used by a Windows service | Set `AEGIS_DASHBOARD_PORT` to a free port; check with `aegis preflight` |
| `SSLEOFError` from tooling to the indexer | Client connected by IP without SNI | Fixed: the client sends the service name as SNI and verifies it |
| `curl` (schannel) `CERT_TRUST_REVOCATION_STATUS_UNKNOWN` | Windows checks revocation; the lab CA publishes no CRL | Use `--ssl-no-revoke` for manual probes (chain and hostname are still verified) |
| `.env line 1 is not KEY=VALUE` | File saved with a UTF-8 BOM (PowerShell 5.1 / Notepad) | `aegis init-secrets` normalizes it; `aegis up` refuses a BOM `.env` |
| `find: command not found` during certificate generation | Harmless message from the upstream cert tool image | All 10 certificates were produced and verified by `aegis prepare` |

## Measured resource usage

See [benchmarks/](../benchmarks/). Idle Profile A stack (no agents): indexer 1.59 GiB, manager 0.52 GiB,
dashboard 0.16 GiB.

## Upgrade procedure

1. Read upstream release notes for the target version.
2. Update `stack.lock.json` (version, tag, URL) and compute the new archive SHA-256 from a trusted download.
3. `aegis prepare --force-render`, then `aegis up`.
4. Run `aegis health` and the detection regression suite (Phase 5) before considering the upgrade done.

## Backup and recovery

NOT IMPLEMENTED — Phase 8 (indexer snapshots + manager `etc`/rules volume export, with a restore test).
