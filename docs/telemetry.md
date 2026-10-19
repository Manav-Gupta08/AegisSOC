# Telemetry

Each source records what it collects, why, expected volume, how to validate it, and its blind spots.
Volumes are **estimates** until measured (Phase 7). Status: PASS / NOT VERIFIED / NOT IMPLEMENTED.

Agent configuration is managed centrally from `deployment/wazuh/agent-groups/<group>/agent.conf`:

```sh
aegis agent-config validate   # offline; safe for CI
aegis agent-config apply      # manual, reviewed deployment to the manager; assigns agents by OS
```

The `agents` health check warns when an agent's group config is not `synced` (configuration drift).

## Linux endpoint (WSL2 Ubuntu 26.04, group `linux`)

| Source | Collects | Why | Est. volume | Validate | Blind spots | Status |
|---|---|---|---|---|---|---|
| journald (agent default) | PAM auth, sudo, sessions, systemd | Authentication and privilege events | Low | M1-E2E-001: failed password → rule 5557 | sudo-rs log format not matched by Wazuh sudo rules; events lost if agent is stopped | PASS |
| auditd `audit-wazuh-c` | `execve` as root from user sessions (`auid>=1000`) | Who ran what with privilege | Low–medium (per root command) | Run `sudo id` → rule 80792 with `audit.exe` | Kernel audit is inaccessible from WSL2 distros (`auditctl -s` fails); see M2-LNX-001 | NOT AVAILABLE on WSL2 |
| FIM real-time (directories) | `/etc` (whole directory), plus diffs for sudoers.d, cron.d, systemd/system, profile.d, sshd_config.d; `/var/spool/cron/crontabs`, `/root/.ssh` | Privilege, persistence, and account changes | Low–medium (all of /etc) | M2-LNX-001/002: add/delete alerts within 1 s; 4/4 atomic replaces of `/etc/group` alerted | **No actor attribution** (no audit on WSL2); file-level watches are lost after atomic replaces, so only directories are watched; `/home/*/.ssh` not covered | PASS (realtime) |
| FIM scheduled (agent default) | `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot` every 12 h | Baseline integrity | Low | Scan start/end in agent log | Changes between scans are seen late | PASS (scan observed) |
| Rootcheck/SCA (agent default) | Host anomalies, CIS policy | Hygiene | Rootcheck noisy (rule 510) | Alerts present | No CIS policy for Ubuntu 26.04 (skipped) | PASS (running) |

Setup: `sudo deployment/endpoints/linux/configure-auditd.sh` on Linux systems with working kernel audit
(it exits with a clear error and disables auditd on WSL2), then `sudo systemctl restart wazuh-agent`.
The audit rules are kept for a future real Linux VM endpoint (Profile B), which would also need an
`audit.log` `<localfile>` in its group config.

Default agent `localfile` entries for nginx logs remain (files absent); harmless but noted.

**Linux hosts.** When the stack runs on Linux, the host itself is the Linux endpoint. Kernel audit is normally
available there, so `configure-auditd.sh` applies, but the `linux` group config has no `audit.log` `<localfile>`
yet, so audit events are not collected (NOT IMPLEMENTED). The statuses above were measured on the WSL2 endpoint.

## Windows endpoint (host, group `windows`)

| Source | Collects | Why | Est. volume | Validate | Blind spots | Status |
|---|---|---|---|---|---|---|
| Security log (agent default) | Logons (4624/4625), account and policy changes | Authentication and privilege | Medium | Failed local logon → rule 60122 | Depends on host audit policy | NOT VERIFIED |
| Sysmon 1 | Process creation (minus noisy system helpers) | Execution visibility | Medium–high | Start `whoami.exe` → Sysmon event 1 in alerts/archives | Excluded helper binaries | NOT VERIFIED |
| Sysmon 3 | Network connections from LOLBins only | Download/C2 via living-off-the-land binaries | Low | `curl.exe` is not covered; PowerShell web request is | All other processes' connections | NOT VERIFIED |
| Sysmon 6 / 8 / 10 | Driver loads, remote threads, LSASS memory access | Rootkits, injection, credential dumping | Low | Not defined yet | Kernel-level tampering can disable Sysmon | NOT VERIFIED |
| Sysmon 11 / 12–14 | Startup-folder and task files; Run keys, Winlogon, IFEO, service ImagePath | Persistence | Low | Create/delete a Run value | WMI subscriptions, COM hijacks not covered | NOT VERIFIED |
| PowerShell 4104 | Script block logging | Malicious script content | Medium | Requires script block logging policy enabled | Disabled by default on Windows | NOT VERIFIED |
| Defender Operational | Detections, tamper events | AV signal | Low | EICAR-free: check event channel exists | Third-party AV replaces it | NOT VERIFIED |
| FIM real-time | Startup folder, `System32\Tasks` | Persistence | Low | Create test file | Per-user startup folders not covered | NOT VERIFIED |

Setup (elevated PowerShell): `install-sysmon.ps1`, then `install-wazuh-agent.ps1`, then `aegis agent-config apply`.

Sysmon disabled event types for volume on Profile A: ImageLoad (7), DNS (22), FileDelete (23/26), Pipes (17/18).

## Missing telemetry vs. quiet environment

- Agent stopped/disconnected → `agents` check WARNING. Absence of alerts is never treated as "no activity".
- Only *alerts* are indexed (archives disabled to bound storage). A source that produces no alert-level events
  cannot be distinguished from a silent source by the indexer alone; source-level heartbeat checks are planned.
