# Detection Coverage Matrix

Generated 2026-10-14T04:09:48.073587+00:00 from rule metadata, scenario manifests, and the scenario report of 2026-10-13T11:54:32.940911+00:00.

Columns are deliberately separate: a documented technique, an existing rule, a passing test, and an
observation in this lab are different claims. None of them measures real-world detection rate.

| Rule | Technique(s) | Rule exists | Logtest cases | Scenarios (+/-) | Last scenario result | Observed in lab | Min latency (s) |
|---|---|---|---|---|---|---|---|
| 100100 Repeated local authentication failures for one user | T1110.001 | yes (tested) | 2 | +1 / -1 | LNX-001: PASSED, LNX-002: PASSED | yes | 10.022 |
| 100200 sudoers configuration changed | T1548.003 | yes (tested) | 0 | +1 / -0 | LNX-003: PASSED | yes | 1.438 |
| 100201 Scheduled task or systemd unit changed | T1053.003, T1543.002 | yes (tested) | 0 | +1 / -0 | LNX-004: PASSED | yes | 0.161 |
| 100202 Local account database changed | T1136.001, T1098 | yes (tested) | 0 | +1 / -0 | LNX-005: PASSED | yes | 0.15 |

## Known gaps per rule

- **100100**: Each sudo attempt can emit 2 failure events (pam_unix + unix_chkpwd), so 6 events can be ~3 attempts.; Requires the srcuser field; failures decoded without it are not counted.; Spraying many users (one attempt each) does not trigger it.
- **100200**: On WSL2, FIM runs in real-time mode without whodata, so the actor is not recorded.; Changes reverted between FIM events may be missed if the agent is offline.
- **100201**: User-level systemd units (~/.config/systemd/user) are not monitored.; No actor attribution on WSL2 (real-time mode).; Only the systemd path has a scenario (LNX-004); the cron path (T1053.003) is untested.
- **100202**: Does not identify which account changed; review the passwd/group diff.; No actor attribution on WSL2 (real-time mode).; Depends on directory-level FIM of /etc; file-level watches are lost after atomic replaces (M2-LNX-002).
