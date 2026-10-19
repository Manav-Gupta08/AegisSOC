# Threat Model

Method: assets → trust boundaries → threats (STRIDE-oriented) → safeguards → residual risk.
Status of each safeguard uses PASS / NOT VERIFIED / NOT IMPLEMENTED.

## Assets

| Asset | Why it matters |
|---|---|
| Indexed alerts and archives | Evidence for investigations; tampering destroys trust |
| Detection rules and decoders | Tampering creates blind spots |
| Credentials (indexer, API, enrollment) | Full control of the SIEM |
| Stack CA and private keys | Impersonation of manager/indexer |
| Reports and case files | May contain hostnames, usernames, command lines |
| Monitored endpoints | Real host is also the analyst workstation |

## Trust boundaries

1. Endpoint ↔ manager (agents are untrusted input sources).
2. Operator workstation ↔ management interfaces.
3. Internet ↔ build inputs (upstream archive, container images, packages).
4. Git repository ↔ live deployment.

## Threats and safeguards

| # | Threat | Safeguards | Status |
|---|---|---|---|
| T1 | Compromised monitored endpoint sends forged/misleading telemetry | Treat single events as leads, not proof; corroborate across sources ([incident-response.md](incident-response.md) triage guidance); agent keys per endpoint | PASS (guidance). Residual: corroboration is not enforced by tooling |
| T2 | Malicious log content (injection into reports, terminals, queries) | Tooling never `eval`s or shells out with log data; subprocess calls use argument lists; Markdown/HTML output escaped; control characters neutralized in terminal output | PASS (unit tests inject HTML, Markdown table breaks, and ANSI escape sequences) |
| T3 | Credential exposure | Random per-install secrets in git-ignored `.env`; `.gitignore` blocks keys/certs; report redaction of known secrets; passwords passed to containers via env, not argv | PASS (2026-10-13: 0 `.env` secrets found in live health report) |
| T4 | Unauthorized dashboard/API/indexer access | Bound to 127.0.0.1; default and demo users removed or rotated; health check fails if defaults still work or ports are exposed on non-loopback addresses | PASS (2026-10-13: all ports on 127.0.0.1; defaults rejected; reader accounts get 403 on write/admin) |
| T5 | Insecure agent enrollment | `use_password=yes` with random enrollment password; enrollment port bound to loopback/lab adapter | PASS (2026-10-13: agent enrolled with password over 127.0.0.1). Residual: agents do not verify the manager's enrollment certificate yet |
| T6 | Detection-rule tampering | Rules in Git with review; CI validates but never deploys; `aegis detections deploy` is manual, refuses uncommitted rule changes, has the manager validate before restarting, and records commit and file hashes | PASS (manual deploys recorded 2026-10-13/14). Residual: nothing compares the rules loaded on the manager with Git afterwards |
| T7 | Malicious automation inputs | Response actions come only from reviewed playbooks with an allowlist of action types; targets are validated (normalized absolute paths, non-root account names, routable IPs) and must be on an affected endpoint of the case | PASS (unit tests) |
| T8 | Insecure webhooks | No webhooks in initial release | PASS (by absence) |
| T9 | Excessive log volume / disk exhaustion | Container memory limits; disk usage health check (warn 75 %, fail 85 %, matching indexer low watermark); ISM retention policy deletes alert indices after `AEGIS_RETENTION_DAYS` | PASS (retention policy attached to all alert indices, 2026-10-14). NOT VERIFIED: behavior under disk pressure |
| T10 | Indexer failure goes unnoticed | Health check reports cluster status and alert freshness; missing data is reported as WARNING, never as "no threats" | PASS (2026-10-14: stopped stack and dead manager daemons both reported FAIL; yellow cluster reported WARNING) |
| T11 | Unauthorized response actions | Actions need approval by an analyst other than the proposer, execute once, and only as a recorded simulation; nothing changes an endpoint | PASS (unit tests). Residual: analyst names are self-declared, so the two-person rule is procedural, not authenticated; real execution must not be added before authenticated identities |
| T12 | Secrets in Git history | `.gitignore`; PR checklist; unit test scanning tracked files; gitleaks over full history in CI | PASS (local test), NOT VERIFIED (CI not yet run on GitHub) |
| T13 | Unsafe test cleanup | Manifests that change state must define cleanup and a separate cleanup check; cleanup runs in `finally`, every step runs even if one fails, and failures produce `CLEANUP_REQUIRED` | PASS (unit tests; cleanup verified for LNX-003 to LNX-005 in M5-SCN-001) |
| T14 | Supply-chain tampering of upstream deployment files | Pinned tag + SHA-256 verification before extraction; safe tar extraction (`filter="data"`); images pinned by digest (TOFU, 2026-10-13) | PASS (hash verified on live fetch; traversal blocked in unit test; Compose resolves digest-pinned images) |
| T15 | Simulations affecting non-lab systems | Nothing runs without `--authorize`; the target must be the single active agent in the scenario's group; the executor must report that agent's id and name before any command runs | PASS (authorization and single-target rules: unit tests and M5-SCN-001). NOT VERIFIED live: identity check |
| T16 | Local users reading secrets on a shared Linux host | `.env` written `0600`, rendered runtime directory `0700`; backups stored with restricted access | PASS (unit test for `.env` mode). NOT VERIFIED: modes of certificates created by the upstream generator |
| T17 | Unauthorized access to the AegisSOC UI (other local users, malicious web pages, injected case text) | Binds `127.0.0.1` only; random per-start token exchanged for an `HttpOnly`, `SameSite=Strict` cookie; unexpected `Host` headers refused (DNS rebinding); read-only (`GET`/`HEAD`); CSP `default-src 'none'`; all file content HTML-escaped; token never logged | PASS (unit tests over HTTP). Residual: plain HTTP on loopback, so a local user able to sniff loopback traffic could capture the cookie |

## Known blind spots and residual risks

- **Shared host**: the SOC host is also a monitored endpoint (the Windows endpoint on Windows hosts, the Linux
  endpoint on Linux hosts). A compromise of the host compromises the SIEM. Acceptable for a lab; not acceptable
  for production.
- **WSL2 as Linux endpoint**: shares a kernel/VM with Docker Desktop and **cannot use kernel audit** (verified,
  M2-LNX-001): no auditd command auditing and no FIM actor attribution. Not representative of a real server.
- **WSL idle shutdown (observed)**: WSL stops an idle distro, which stops the agent and drops events written
  during shutdown (M1-E2E-001 attempt 1). Mitigated by `keep-wsl-endpoint-online.ps1 -Register`; the `agents`
  health check reports the gap if the endpoint goes down anyway.
- **sudo-rs on Ubuntu 26.04 (observed)**: Wazuh's classic sudo rules did not match; only the generic
  `unix_chkpwd` rule (5557) fired. Rule 100100 correlates these generic failures by user, but sudo-specific
  context (command, tty) is still not decoded. LNX-001/002 expect 5557 and must be re-baselined on endpoints
  with classic sudo, where they report INCONCLUSIVE rather than a false result.
- **No network visibility**: there is no SPAN/tap. The optional Suricata sensor sees only the traffic of the
  interface it monitors (normally its own host), so network detections cover that host, not the lab segment.
  Suricata `eve.json` fields such as HTTP hosts and URLs are attacker-controlled text and are escaped like all
  other alert content.
- **Container image trust**: images are pinned by digest recorded on first use; the digest was not independently
  verified against a vendor-published value.
- **Docker Desktop bind mounts** expose files with permissive modes inside containers; private keys on
  the host rely on Windows user-profile ACLs.
- **Docker access on Linux hosts**: membership in the `docker` group is equivalent to root. Grant it only to
  the lab operator account.
