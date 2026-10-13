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
| T1 | Compromised monitored endpoint sends forged/misleading telemetry | Treat single events as leads, not proof; corroborate across sources (Phase 6 triage guidance); agent keys per endpoint | NOT IMPLEMENTED (guidance Phase 6) |
| T2 | Malicious log content (injection into reports, terminals, queries) | Tooling never `eval`s or shells out with log data; subprocess calls use argument lists; report rendering will escape output | PASS (tooling), NOT IMPLEMENTED (rendering) |
| T3 | Credential exposure | Random per-install secrets in git-ignored `.env`; `.gitignore` blocks keys/certs; report redaction of known secrets; passwords passed to containers via env, not argv | NOT VERIFIED |
| T4 | Unauthorized dashboard/API/indexer access | Bound to 127.0.0.1; default and demo users removed or rotated; health check fails if defaults still work or ports are exposed on non-loopback addresses | NOT VERIFIED |
| T5 | Insecure agent enrollment | `use_password=yes` with random enrollment password; enrollment port bound to loopback/lab adapter | NOT VERIFIED. Residual: agents do not verify the manager's enrollment certificate yet |
| T6 | Detection-rule tampering | Rules in Git with review; CI validates but never deploys; deployment is a manual step (Phase 4/8) | NOT IMPLEMENTED |
| T7 | Malicious automation inputs | No automated response actions; future actions allowlisted and approval-gated | PASS (by absence) |
| T8 | Insecure webhooks | No webhooks in initial release | PASS (by absence) |
| T9 | Excessive log volume / disk exhaustion | Container memory limits; disk usage health check (warn 75 %, fail 85 %, matching indexer low watermark); retention policy (Phase 7) | NOT VERIFIED |
| T10 | Indexer failure goes unnoticed | Health check reports cluster status and alert freshness; missing data is reported as WARNING, never as "no threats" | NOT VERIFIED |
| T11 | Unauthorized response actions | Not implemented by design | PASS (by absence) |
| T12 | Secrets in Git history | `.gitignore`; PR checklist; secret scanning in CI (Phase 8) | NOT IMPLEMENTED (scanning) |
| T13 | Unsafe test cleanup | Scenario manifests require cleanup steps and record cleanup failures (Phase 5) | NOT IMPLEMENTED |
| T14 | Supply-chain tampering of upstream deployment files | Pinned tag + SHA-256 verification before extraction; safe tar extraction (`filter="data"`); pinned image tags | NOT VERIFIED |
| T15 | Simulations affecting non-lab systems | Simulations limited to enrolled lab endpoints; explicit approval per scenario | NOT IMPLEMENTED |

## Known blind spots and residual risks

- **Shared host**: the Windows endpoint is also the SOC host. A compromise of the host compromises the
  SIEM. Acceptable for a lab; not acceptable for production.
- **WSL2 as Linux endpoint**: shares a kernel/VM with Docker Desktop; auditd support depends on the WSL
  kernel's audit configuration and must be verified (Phase 3). Not representative of a bare-metal server.
- **No network visibility**: there is no SPAN/tap; network detections are out of scope for Profile A.
- **Container image trust**: images are pinned by tag, not digest. Digest pinning is planned (Phase 8).
- **Docker Desktop bind mounts** expose files with permissive modes inside containers; private keys on
  the host rely on Windows user-profile ACLs.
