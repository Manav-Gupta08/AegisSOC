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

Setup: see [Enrolling the Windows endpoint](#enrolling-the-windows-endpoint).

Sysmon disabled event types for volume on Profile A: ImageLoad (7), DNS (22), FileDelete (23/26), Pipes (17/18).

### Enrolling the Windows endpoint

The first attempt (2026-10-13) failed because a wrong enrollment password was entered; the installer now
re-prompts. Order matters: the installer enrolls the agent directly into the `windows` group, and the manager
rejects enrollment into a group that does not exist yet.

1. Stack host: `aegis agent-config apply` (creates the `linux`, `windows`, and `network-sensor` groups).
2. If the stack runs on another machine (for example a Linux host), set `AEGIS_AGENT_BIND` to its lab-network
   address, restart the stack (`aegis up`), and allow only the Windows endpoint to reach 1514-1515/tcp, for
   example `sudo ufw allow from <windows-ip> to any port 1514:1515 proto tcp`. Never use `0.0.0.0`.
3. Windows endpoint, elevated PowerShell in `deployment\endpoints\windows`:

   ```powershell
   .\install-sysmon.ps1
   .\install-wazuh-agent.ps1 -Manager <stack address>   # prompts for WAZUH_ENROLLMENT_PASSWORD
   ```

   Both installers verify Authenticode signatures and write a transcript to `%ProgramData%\AegisSOC\logs`.
4. Stack host: `aegis health` (the `agents` check must list the Windows agent as active and synced), then
   produce a known event, a failed logon with `runas /user:aegis-nonexistent cmd` and a wrong password, and run
   `aegis telemetry`. Expected: rule 60122 for the failed logon, `windows-security@<agent>` PASS.
   `windows-sysmon` passes only once a Sysmon event reaches alert level; until then it is a WARNING.

Record the outcome in this table before changing any status to PASS.

## Network sensor (optional, Profile B, group `network-sensor`)

| Source | Collects | Why | Est. volume | Validate | Blind spots | Status |
|---|---|---|---|---|---|---|
| Suricata (IDS mode, af-packet, ET Open) | `eve.json` alerts plus flow, DNS, HTTP, TLS metadata | Network-level signatures independent of endpoint agents | Alerts low; metadata high but decoded at level 0 and not indexed | Scenario NET-001 → pipeline check 100800 | Sees only the monitored interface's traffic (no SPAN/tap); encrypted payloads; signature-based only | NOT VERIFIED |

Setup on a Linux agent with a network interface worth watching (a Linux host's own uplink, or a VM bridged to a
mirror port):

```sh
sudo deployment/endpoints/linux/install-suricata.sh --interface <iface>
aegis agent-config apply
aegis agent-config assign --agent <agent name> --group network-sensor
aegis scenarios run NET-001 --authorize
```

The installer uses the distribution's Suricata package, pins the interface with a systemd drop-in instead of
editing `suricata.yaml`, loads ET Open with `suricata-update`, and refuses to finish unless `suricata -T` passes,
signature 2100498 is loaded, and `eve.json` is being written. Suricata runs passively (no inline blocking).

On a Windows host, Suricata inside WSL2 would only see the VM's own traffic, so the sensor is not offered there.

**Zeek: not added.** Suricata's `eve.json` already provides flow, DNS, HTTP, and TLS metadata for investigation, and
Zeek would add a second sensor process, a second log format, and its own decoders without a monitored segment
that justifies it. Reconsider when a SPAN/tap or a multi-host lab segment exists and protocol logs beyond
Suricata's (for example SMB, Kerberos, or long-term connection baselining) are needed.

## Per-source checks (`aegis telemetry`)

`deployment/wazuh/telemetry-sources.yml` lists the expected sources by agent group and rule group. For every agent
in a source's group, `aegis telemetry` reports PASS when an alert from that source arrived within the source's
`max_silence_hours`, WARNING when none did or the agent is not active, and NOT_VERIFIED when no agent is in the
group (the source is not deployed). It uses the read-only accounts and writes a JSON report that `aegis ui` shows.
`aegis telemetry --validate` checks the file offline and runs in CI.

## Missing telemetry vs. quiet environment

- Agent stopped/disconnected → `agents` check WARNING. Absence of alerts is never treated as "no activity".
- Only *alerts* are indexed (archives disabled to bound storage). A source that produces no alert-level events
  cannot be distinguished from a silent source by the indexer alone. `aegis telemetry` makes that visible per
  source and agent but cannot resolve it; a true heartbeat would need archives or a source-side canary.
