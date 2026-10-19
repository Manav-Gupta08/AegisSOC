# Operations

## Daily routine

```powershell
aegis health                 # 9 checks; exit 0 PASS / 1 WARNING / 2 FAIL; JSON report in reports/runtime
aegis metrics --days 7       # detection, volume, availability, case, resource metrics (JSON + Markdown)
aegis scenarios run --all --authorize   # regression suite after any rule/config/version change
```

Health is never inferred from the dashboard loading. A stopped stack reports FAIL with connection errors
(observed 2026-10-14 after a host restart), never "no alerts".

## Metrics

All metrics are computed by `aegis metrics` from stored reports, the indexer (read-only account), case files,
and `docker stats`. Each output states its sample size. They describe this lab only.

| Metric | Definition | Source | Limitations |
|---|---|---|---|
| Latest pass rate | PASSED / executed, using each scenario's most recent run. Executed = PASSED, FAILED, TIMED_OUT, INCONCLUSIVE, CLEANUP_REQUIRED (SKIPPED excluded) | Scenario reports (runtime + examples, de-duplicated by `generated_at`) | Measures the scenario suite, not real-world protection |
| Regression rate | Scenarios whose previous run PASSED and latest executed run did not / scenarios whose previous run PASSED | Scenario reports | Undefined (n/a) until a scenario has two runs |
| Trigger-to-alert latency | First expected alert `timestamp` minus the runner's start time, for PASSED runs; median and max | Scenario reports | Includes command execution time (e.g. ~1.5 s per failed sudo); upper-bounded by the 5 s poll only for visibility, not for the timestamp |
| Alert volume | Count of `wazuh-alerts-*` documents in the window, by day, agent, level band (0–6, 7–11, 12+), top 10 rules | Indexer aggregations | Only alerts are indexed (archives disabled) |
| Agents all active | Health snapshots where the `agents` check is PASS / health snapshots | `reports/runtime/health-*.json` | Depends on how often `aegis health` runs; a few snapshots are not an availability SLA |
| Case resolution time | Time from case creation to the transition into `closed` or `false_positive`; median and max (minutes) | Case audit trails | Lab cases are mostly test activity |
| Analyst-labelled false positives | Count of cases classified `false_positive` | Cases | A count, not a rate: there is no labelled ground-truth dataset |
| Resource use | `docker stats --no-stream` CPU % and memory for the three stack containers | Docker | Single instantaneous sample per run |
| Bytes per alert (upper bound) | Indexer `disk.indices` / total alert documents | Indexer | Includes non-alert indices, so it overestimates |

## Baseline (2026-10-14, first metrics run, before tuning)

| Measurement | Value |
|---|---|
| Alerts, 7 days | 655 (626 on day 1, mostly setup and validation) |
| Rule 510 rootcheck "trojaned file" | 257 (39%) — verified false positives (rust-coreutils), suppressed by 100900 |
| Manager-container CIS (SCA) checks | 185 (28%) — not lab telemetry; SCA disabled on the manager |
| Scenario pass rate / regressions | 1.0 (5 executed) / 0.0 |
| Trigger-to-alert latency median / max | 0.257 s / 10.0 s (5 runs) |
| Indexer data | ~2.5 MB; disk 7% |
| Manager / indexer / dashboard memory | 1.26 GiB / 1.64 GiB / 0.27 GiB (limits 3 / 2.5 / 1 GiB) |

## Retention sizing

Upper bound observed: ~3.8 KB per alert. At the post-tuning rate (to be re-measured over a full week),
even 1,000 alerts/day for 30 days is ~115 MB — far below the 50 GB minimum. Retention is therefore limited
by policy, not disk, on Profile A.

Retention is enforced by the index lifecycle (ISM) policy `aegis-alerts-retention`: `wazuh-alerts-*` indices
are deleted `AEGIS_RETENTION_DAYS` (default 30) days after creation. `aegis provision` creates or updates it
and attaches it to existing indices; new indices get it automatically via its index template (verified: both
existing alert indices report the policy).

## Backup and restore

```powershell
aegis backup create                  # cold backup to backups/ (git-ignored) or AEGIS_BACKUP_DIR
aegis backup verify-restore [path]   # restores into an isolated project and checks it; default: latest backup
```

`create` records a snapshot (alert count, agent names, loaded AegisSOC rules, retention policy), stops the
stack, archives every stack volume with `tar` inside the pinned manager image, restarts the stack, then
archives `.env`, the lock file, rendered runtime configs, and certificates. A `manifest.json` stores the
SHA-256 of every archive.

`verify-restore` refuses tampered backups (hash check) before stopping anything. It then stops the live stack
(its volumes are never modified), restores into new volumes of project `aegissoc-restore`, and starts that
stack with agent ports on `127.0.0.2` so live agents cannot connect to it. It passes only if the restored
stack has at least the snapshot's alert count, the same agents, all AegisSOC rules loaded, and the retention
policy. It then deletes **only** the `aegissoc-restore` project and restarts the live stack. `compose down`
is refused for any other project.

The backup contains `.env` secrets and private keys: store it with restricted access, and off the host
for real disaster recovery. Agents buffer events while the stack is stopped.

| Measured (2026-10-14) | Value |
|---|---|
| Backup size | ~795 MB, of which `wazuh_queue` (vulnerability-detection feed) is ~793 MB |
| Downtime during cold backup | 448 s, dominated by compressing `wazuh_queue` |

### Incidents found while testing recovery (2026-10-14)

| Finding | Impact | Fix |
|---|---|---|
| Manager container stayed `Up` while `analysisd`, `remoted`, `apid` were dead after a restart sequence | No events processed; Docker `restart: always` never triggered (upstream 4.14 behavior; fixed upstream in 5.0) | Detected by `aegis health` (API FAIL); recovered by `aegis compose restart wazuh.manager`. Restore verification now requires two healthy checks 30 s apart |
| Health polling loops ran the default-credential probe ~30 times | 63 failed logins locked the host out of the Wazuh API for 300 s | Credential probe is opt-in (`aegis health --credential-test`), never used in loops |
| ISM system indices created with 1 replica | Cluster yellow on a single node | `aegis provision` sets them to 0 replicas using the admin client certificate (protected indices) |
| Restore check accepted the first partial alert count (38 of 664) | Misleading FAIL | Readiness waits until the snapshot count is reached or times out |

The credential probe performs deliberate failed logins: run it at most a few times per 5 minutes.

## Noise tuning policy

1. Measure (top rules by volume).
2. Investigate the cause with evidence before changing anything (e.g. `dpkg --verify` for rootcheck hits).
3. Prefer configuration fixes (disable irrelevant collection) over suppression rules.
4. Suppressions are rules 100900–100999, level 0, with metadata documenting evidence, compensating controls,
   and an end-to-end test; they are reviewed like detections.
