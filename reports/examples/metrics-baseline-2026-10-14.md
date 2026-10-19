# AegisSOC Metrics

Generated 2026-10-14T03:55:02.482959+00:00. Definitions: docs/operations.md#metrics. Lab measurements, not real-world rates.

## Detection validation

| Metric | Value | Sample |
|---|---|---|
| Latest pass rate | 1.0 | 5 executed scenarios |
| Latest failures | none | |
| Regression rate | 0.0 | scenarios with a previous PASS |
| Trigger-to-alert latency median / max (s) | 0.257 / 10.022 | 5 passing runs |
| Cleanup failures | 0 | 6 executed runs |

## Alert volume (last 7 days)

Total: 655 (AegisSOC rules: 27)

| Day | Alerts |
|---|---|
| 2026-10-13 | 626 |
| 2026-10-14 | 29 |

| Agent | Alerts |
|---|---|
| aegis-wsl-ubuntu | 462 |
| wazuh.manager | 193 |

| Level band | Alerts |
|---|---|
| 0-6 low | 254 |
| 7-11 medium | 401 |
| 12+ high | 0 |

| Top rule | Count | Description |
|---|---|---|
| 510 | 257 | Host-based anomaly detection event (rootcheck). |
| 19009 | 90 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Disable USB Storage. |
| 19008 | 50 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure Avahi Server is not installed. |
| 19007 | 45 | CIS Benchmark for Amazon Linux 2023 Benchmark v1.0.0.: Ensure AIDE is installed. |
| 554 | 33 | File added to the system. |
| 553 | 32 | File deleted. |
| 550 | 18 | Integrity checksum changed. |
| 5501 | 18 | PAM: Login session opened. |
| 100202 | 14 | AegisSOC: account database changed (/etc/group). |
| 40704 | 10 | Systemd: Service exited due to a failure. |

## Availability and cases

| Metric | Value | Sample |
|---|---|---|
| Agents all active | 0.5 | 4 health snapshots (2026-10-13T10:16:30.514893+00:00 .. 2026-10-14T03:36:32.924342+00:00) |
| Health snapshots with FAIL | 0 | |
| Cases open / closed | 0 / 1 | 1 cases |
| Resolution time median / max (min) | 8.2 / 8.2 | closed cases |
| Analyst-labelled false positives | 0 | count, not a rate |

## Resources and storage

| Container | CPU % | Memory | Limit |
|---|---|---|---|
| aegissoc-wazuh.manager-1 | 137.38 | 1.259GiB | 3GiB |
| aegissoc-wazuh.indexer-1 | 4.23 | 1.636GiB | 2.5GiB |
| aegissoc-wazuh.dashboard-1 | 0.55 | 268.3MiB | 1GiB |

Indexer data: 2520067 bytes; disk used 7%; upper-bound bytes/alert 3847 (includes non-alert indices).
