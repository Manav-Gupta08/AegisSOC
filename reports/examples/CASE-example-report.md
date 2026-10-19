# CASE-20261014-001: sudoers drop-in created and removed on Linux endpoint

| Field | Value |
|---|---|
| Status | closed |
| Severity | low |
| Classification | test\_activity |
| Confidence | high |
| Created | 2026-10-14T03:37:35.701848+00:00 |
| Affected endpoints | \[REDACTED\] |
| Audit trail | VERIFIED |
| Evidence files | VERIFIED |

## Source alerts

| Time | Rule | Level | ATT&CK | Agent | Description |
|---|---|---|---|---|---|
| 2026-10-14T03:37:02.642+0000 | 100200 | 10 | T1548.003 | \[REDACTED\] | AegisSOC: sudoers configuration changed (/etc/sudoers.d/aegis-scenario). |
| 2026-10-14T03:37:02.654+0000 | 100200 | 10 | T1548.003 | \[REDACTED\] | AegisSOC: sudoers configuration changed (/etc/sudoers.d/aegis-scenario). |

## Evidence

| ID | Kind | Reference | SHA-256 | Description |
|---|---|---|---|---|
| EV-001 | alert | CASE-20261014-001/evidence/EV-001.json | `0a18e972c0a97c00…` | raw alert K4V8OKEBfRk-9w7OPNM\_ from wazuh-alerts-4.x-2026.10.14 |
| EV-002 | alert | CASE-20261014-001/evidence/EV-002.json | `37359e87a1b2c289…` | raw alert LIV8OKEBfRk-9w7OPNM\_ from wazuh-alerts-4.x-2026.10.14 |

## Timeline

| Time (UTC) | Source | Event |
|---|---|---|
| 2026-10-14T03:37:02+00:00 | alert | rule 100200 (level 10) on \[REDACTED\]: AegisSOC: sudoers configuration changed (/etc/sudoers.d/aegis-scenario). |
| 2026-10-14T03:37:02+00:00 | alert | rule 100200 (level 10) on \[REDACTED\]: AegisSOC: sudoers configuration changed (/etc/sudoers.d/aegis-scenario). |
| 2026-10-14T03:37:35+00:00 | audit #1 (analyst) | case created: sudoers drop-in created and removed on Linux endpoint |
| 2026-10-14T03:37:44+00:00 | audit #2 (analyst) | status -&gt; triage (rule 100200 level 10) |
| 2026-10-14T03:37:55+00:00 | audit #3 (analyst) | alert K4V8OKEBfRk-9w7OPNM\_ attached |
| 2026-10-14T03:37:55+00:00 | audit #4 (analyst) | evidence EV-001 collected |
| 2026-10-14T03:37:55+00:00 | audit #5 (analyst) | alert LIV8OKEBfRk-9w7OPNM\_ attached |
| 2026-10-14T03:37:55+00:00 | audit #6 (analyst) | evidence EV-002 collected |
| 2026-10-14T03:38:04+00:00 | audit #7 (analyst) | analyst note |
| 2026-10-14T03:38:08+00:00 | audit #8 (analyst) | analyst note |
| 2026-10-14T03:38:13+00:00 | audit #9 (analyst) | confidence set |
| 2026-10-14T03:38:17+00:00 | audit #10 (analyst) | recommendation added |
| 2026-10-14T03:38:21+00:00 | audit #11 (analyst) | recommendation added |
| 2026-10-14T03:38:28+00:00 | audit #12 (analyst) | classification set |
| 2026-10-14T03:38:32+00:00 | audit #13 (analyst) | findings set |
| 2026-10-14T03:38:37+00:00 | audit #14 (analyst) | closure\_reason set |
| 2026-10-14T03:38:40+00:00 | audit #15 (analyst) | lessons\_learned set |
| 2026-10-14T03:38:46+00:00 | audit #16 (analyst) | severity set |
| 2026-10-14T03:38:50+00:00 | audit #17 (analyst) | CORRECTION of severity: test activity; severity reduced after classification |
| 2026-10-14T03:45:37+00:00 | audit #18 (analyst) | status -&gt; investigating (two sudoers FIM alerts 12 ms apart) |
| 2026-10-14T03:45:41+00:00 | audit #19 (analyst) | status -&gt; containment\_recommended (recommendations recorded; no automated action taken) |
| 2026-10-14T03:45:44+00:00 | audit #20 (analyst) | status -&gt; resolved |
| 2026-10-14T03:45:48+00:00 | audit #21 (analyst) | status -&gt; closed |
| 2026-10-14T03:46:12+00:00 | audit #22 (analyst) | analyst note |
| 2026-10-14T03:46:18+00:00 | audit #23 (analyst) | CORRECTION of findings: added alert count |

## Findings

Alerts were produced by authorized validation scenario LNX-003 (2 alerts: add + delete); the drop-in contained only a comment and was removed.

## Recommendations (not executed)

- Confirm with the change owner before treating any future sudoers change as benign.
- If unexplained: review /etc/sudoers.d contents, recent logins, and package installs; consider disabling the account involved (manual, approved action).

## Analyst notes

- 2026-10-14T03:38:04.811649+00:00 analyst: File created and deleted within ~0.3 s; content not retained after delete. No actor attribution available (WSL2 realtime FIM).
- 2026-10-14T03:38:08.404732+00:00 analyst: Correlated with scenario run LNX-003 (authorized, --authorize) started 03:37:02Z; cleanup verified by runner.
- 2026-10-14T03:46:12.775007+00:00 analyst: Post-closure note: audit shows set operations recorded before transitions because CLI calls were interleaved; concurrency guard added.

## Closure

Authorized detection test; no malicious activity.

## Lessons learned

Detection fired in under 1 s; investigation lacked actor attribution - a VM endpoint with auditd would close this gap.

## Limitations

- Alerts reflect only telemetry the agents collected; absence of an alert is not evidence of absence.
- Linux FIM on the WSL2 endpoint has no actor attribution (kernel audit unavailable).
- Recommendations are not actions: AegisSOC performs no automated containment.
