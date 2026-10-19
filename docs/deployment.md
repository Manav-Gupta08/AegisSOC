# Deployment

AegisSOC runs the official single-node Wazuh stack on one host: Windows with Docker Desktop (WSL2 backend),
or Linux with Docker Engine. The Windows host is the verified reference; Linux host support is implemented
and unit-tested but has not been deployed live yet.

## Verified host (reference, Windows)

| Item | Value |
|---|---|
| OS | Windows 11 Pro 10.0.26200 |
| CPU | Intel i7-6700, 4 cores / 8 threads |
| RAM | 15.9 GB |
| Storage | Repository and Docker data on a drive with > 400 GB free |
| Virtualization | Hyper-V / Virtual Machine Platform enabled; WSL 2.7.14 |
| Docker | Docker Desktop 29.8.2 (WSL2 backend) |
| Python | 3.12.10 |

## Linux host (NOT VERIFIED live)

| Item | Requirement |
|---|---|
| OS | A systemd-based distribution; commands below are for Ubuntu 24.04 |
| Docker | Docker Engine with the Compose plugin >= 2.24.4 (`docker.io` + `docker-compose-v2`, or Docker's apt repository) |
| Docker access | The operator account must reach the daemon. Membership in the `docker` group is equivalent to root on the host |
| Kernel | `vm.max_map_count >= 262144` (set once by root, see below) |
| Python | >= 3.11 with the `venv` module (`python3-venv` on Ubuntu; without it `python3 -m venv` fails on `ensurepip`) |

Differences from the Windows host:

- There is no VM memory cap; the containers' `mem_limit` values bound the stack.
- The host itself is the Linux endpoint. Unlike WSL2, kernel audit is available, so `configure-auditd.sh` applies.
- Scenario commands run locally (`AEGIS_LINUX_EXECUTOR=local`); steps marked `run_as: root` use `sudo -n`.
- `.env` and the rendered runtime directory are created owner-only (`0600`/`0700`).
- Not yet verified: ownership and modes of the certificates written by the upstream generator, which runs as
  root in a container. The tooling must be able to read `root-ca.pem`, `admin.pem`, and `admin-key.pem`.

## Deployment profiles

### Profile A: lightweight home lab (default)

| Component | Placement | Memory budget |
|---|---|---|
| wazuh.indexer | Docker, heap 1 GB | limit 2.5 GB |
| wazuh.manager | Docker | limit 3 GB |
| wazuh.dashboard | Docker | limit 1 GB |
| Linux endpoint | WSL2 Ubuntu distro (same VM) on Windows; the host itself on Linux | ~0.3 GB |
| Windows endpoint | Host (Windows hosts only) | ~0.2 GB (agent + Sysmon) |
| **WSL2 VM cap** | `.wslconfig` (Windows hosts only) | **10 GB**, 6 processors, 4 GB swap |

On Windows this leaves ~6 GB for the host. Retention target: 14–30 days of alerts, adjusted after measuring
real daily volume (Phase 7). Simulations run sequentially.

These figures are **budgets, not measurements**; see [Measured resource usage](#measured-resource-usage).

### Profile B: expanded lab (optional, not implemented)

Adds a disposable Windows VM (~4 GB) for attack simulations, Suricata on a sensor with real
traffic visibility, and longer retention. On the 16 GB reference host Profile B components cannot all run
at the same time as Profile A; they must be scheduled.

## Network topology

| Port | Service | Bound to | Reachable from |
|---|---|---|---|
| 1514/tcp | Agent events | `AEGIS_AGENT_BIND` (default `127.0.0.1`) | Host, WSL distros (see below) |
| 1515/tcp | Agent enrollment (password) | `AEGIS_AGENT_BIND` | Same |
| 55000/tcp | Wazuh API | `127.0.0.1` | Host only |
| 9200/tcp | Indexer | `127.0.0.1` | Host only |
| 5601/tcp | Dashboard (`AEGIS_DASHBOARD_PORT`) | `127.0.0.1` | Host only |
| 514/udp | Syslog | not published | n/a |

On a Linux host the agent runs on the host and reaches the published ports on `127.0.0.1` directly.
Other machines (for example a lab VM) need `AEGIS_AGENT_BIND` set to a lab-only interface address plus a host
firewall rule limited to the lab subnet. Never use `0.0.0.0`.

**WSL2 Ubuntu reachability (Windows hosts; VERIFIED 2026-10-13, default NAT networking).** With Docker Desktop's
WSL2 backend, the Ubuntu distro reaches the agent ports on `127.0.0.1` without `networkingMode=mirrored`
(`nc -zv 127.0.0.1 1515` succeeded). If a future WSL/Docker change breaks this, options in order:

1. `networkingMode=mirrored` in `.wslconfig`, so Windows and WSL share loopback.
2. Set `AEGIS_AGENT_BIND` to the Windows `vEthernet (WSL)` adapter IP and restrict with a
   Windows Firewall rule scoped to the WSL subnet. Never use `0.0.0.0`.

The agent install script tests connectivity before enrolling.

**Dashboard port.** The default is 5601. Port 8443 was rejected on the reference host because a
Windows service (`svchost`) already listens on it; `aegis preflight` now reports busy ports.

## Procedure

### Windows host

```powershell
# 0. One-time: apply WSL limits (review first, then restart WSL)
#    Copy deployment/wsl/wslconfig.example to %UserProfile%\.wslconfig, merge with any existing settings
wsl --shutdown          # restarts Docker Desktop's VM; start Docker Desktop again afterwards

# 1. Tooling (virtual environment outside the repository)
py -3.12 -m venv $HOME\.venvs\aegissoc
& $HOME\.venvs\aegissoc\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Linux host

```sh
# 0. One-time, as root: kernel setting the indexer needs
echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/99-aegissoc.conf
sudo sysctl --system

# 1. Tooling (virtual environment outside the repository)
python3 -m venv ~/.venvs/aegissoc
. ~/.venvs/aegissoc/bin/activate
pip install -e ".[dev]"
```

### Both hosts

```sh
aegis preflight
aegis init-secrets
aegis prepare
aegis up
aegis provision         # after the stack is healthy (indexer takes 1-5 minutes)
aegis health
```

### Endpoints

Run `aegis agent-config apply` first: it creates the agent groups, and the Windows installer enrolls directly into
the `windows` group.

- Windows host: run `deployment/endpoints/linux/install-wazuh-agent.sh` inside WSL Ubuntu, and the Windows
  installers as described in [telemetry.md](telemetry.md#enrolling-the-windows-endpoint).
- Linux host (the host is the endpoint):

  ```sh
  sudo deployment/endpoints/linux/install-wazuh-agent.sh --manager 127.0.0.1
  sudo deployment/endpoints/linux/configure-auditd.sh
  ```

  A Windows endpoint on another machine reaches a Linux host through `AEGIS_AGENT_BIND` and a firewall rule; see
  the same telemetry section.
- Optional network sensor (Linux agents only): [telemetry.md](telemetry.md#network-sensor-optional-profile-b-group-network-sensor).

Run `aegis agent-config apply` again after enrolling so Linux agents join the `linux` group, then confirm with
`aegis health` and `aegis telemetry`.

### What `aegis prepare` does

1. Downloads `wazuh-docker` at the tag pinned in `deployment/wazuh/stack.lock.json` and refuses to
   continue unless its SHA-256 matches the lock file.
2. Extracts it to `deployment/wazuh/upstream/` (git-ignored) using safe tar extraction.
3. Generates the stack certificates with the upstream `wazuh-certs-generator` (skipped if present).
4. Hashes the indexer passwords with the indexer image's own `hash.sh` and renders
   `internal_users.yml` containing only `admin` and `kibanaserver` (demo users removed).
5. Renders the manager `ossec.conf` with `use_password=yes` and manager-container SCA disabled, plus an
   `authd.pass` file.
6. Renders the dashboard `wazuh.yml` with the generated API password.

Rendered files live in `deployment/wazuh/runtime/` (git-ignored; owner-only on POSIX hosts).

### Idempotency and data safety

- `prepare` never overwrites existing certificates. It re-renders the manager and dashboard configs only with
  `--force-render`, and `internal_users.yml` only with `--rehash-users`.
- Indexer password changes after first start also require running the indexer's `securityadmin.sh`
  (not automated); `prepare` warns when the indexer volume already exists.
- `aegis compose` refuses `down -v` / `--volumes`. Data volumes are never deleted by AegisSOC tooling.
- `aegis stop` stops containers; it does not remove them or their volumes.

### `vm.max_map_count`

The indexer requires `vm.max_map_count >= 262144` in the kernel that runs the containers.

- Windows: that is Docker Desktop's VM. `aegis up` checks it and sets it with
  `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` if lower. The setting does not persist across
  `wsl --shutdown`; `aegis up` re-applies it.
- Linux: that is the host kernel. `aegis up` refuses to start when the value is too low and prints the root
  commands; it never escalates privileges itself. The `sysctl.d` file from the procedure makes it persistent.

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
3. Pull the new images, record their digests in both `stack.lock.json` and `docker-compose.override.yml`
   (a unit test fails if the two disagree), and take a backup (`aegis backup create`).
4. `aegis prepare --force-render`, then `aegis up`.
5. Run `aegis health`, `aegis detections test`, and `aegis scenarios run --all --authorize` before considering
   the upgrade done.

## Teardown

AegisSOC tooling never deletes data volumes, so a full teardown is a deliberate manual procedure:

```sh
aegis compose down                      # removes containers and the network; volumes are kept
docker volume ls --filter label=com.docker.compose.project=aegissoc
docker volume rm <each volume listed>   # irreversible: deletes all alerts, agent keys, and configuration
```

Then remove `.env`, `deployment/wazuh/runtime/`, and `deployment/wazuh/upstream/` (includes the stack
private keys), and uninstall the agents: `sudo apt-get purge wazuh-agent` on Linux endpoints; on Windows, uninstall
"Wazuh Agent" and Sysmon (`Sysmon64.exe -u`).

## Backup and recovery

Cold backup and isolated restore verification: see [operations.md](operations.md#backup-and-restore).
