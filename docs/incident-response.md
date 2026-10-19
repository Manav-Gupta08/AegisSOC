# Incident Response Workflow

Cases are JSON documents in `cases/` (git-ignored: real lab data), validated against
[schemas/case-1.0.json](../schemas/case-1.0.json). Sanitized reports go to `reports/examples/`.

## Lifecycle

```mermaid
stateDiagram-v2
  [*] --> new
  new --> triage
  triage --> investigating: needs >=1 alert or evidence
  triage --> false_positive: classification=false_positive + closure_reason
  investigating --> containment_recommended: needs >=1 recommendation
  investigating --> resolved: needs classification + findings
  investigating --> false_positive
  containment_recommended --> resolved
  containment_recommended --> investigating
  resolved --> closed: needs closure_reason (+ lessons_learned for true positives)
  resolved --> investigating
  closed --> [*]
  false_positive --> [*]
```

`containment_recommended` means a recommendation was **recorded**, not that anything was contained.
AegisSOC never changes an endpoint; response actions below are simulated and recorded only.

## Commands

```sh
aegis case alerts --rule 100200 --minutes 60          # find alert ids (read-only account)
aegis case new --title "..." --severity high
aegis case transition CASE-YYYYMMDD-NNN triage --reason "..."
aegis case attach CASE-... <alert_id> [<alert_id> ...]  # alert + raw evidence file with SHA-256
aegis case note | recommend | set <field> <value> | transition <status>
aegis case correct CASE-... <field> <value> --reason "..."   # only change allowed after closure
aegis case verify CASE-...                             # audit chain, replay, evidence hashes
aegis case report CASE-... --redact <hostname> <user>  # Markdown + JSON, escaped and redacted
```

## Response playbooks and actions

Playbooks in `playbooks/PB-NNN-*.yml` are reviewed like detections (`aegis playbooks validate` runs in CI).
Each applies to specific AegisSOC rules and lists manual steps and action steps. Action types are an allowlist:

| Action | Target | Simulated plan |
|---|---|---|
| `isolate_host` | the endpoint | block all traffic except to the Wazuh manager |
| `disable_account` | non-root Linux user name | lock and expire the account |
| `quarantine_file` | normalized absolute path (system directories refused) | move the file to a root-only quarantine directory |
| `block_ip` | IP address (loopback, unspecified, multicast refused) | drop traffic to and from the address |

```sh
aegis playbooks list
aegis case propose CASE-... PB-001 3 --endpoint <host> --target /etc/sudoers.d/x --purpose "..." --actor alice
aegis case approve CASE-... ACT-001 --actor bob          # must differ from the proposer
aegis case execute CASE-... ACT-001 --simulate --actor bob
aegis case reject CASE-... ACT-001 --reason "..." --actor bob
```

Safeguards, each enforced when the audit log is replayed:

- Proposals only while `investigating` or `containment_recommended`, only for playbooks that apply to the case's
  alerts, and only against an affected endpoint of the case.
- A second open proposal for the same action, endpoint, and target is refused.
- Approval by the proposer is refused; execution needs approval and happens at most once.
- Only simulated execution exists. It records the initiator, target, purpose, approver, plan, and time.
- A case cannot be resolved or marked false positive while actions are still proposed or approved.

Analyst names are self-declared (`--actor`), so the two-person rule documents intent but does not authenticate
anyone. Real execution would first need authenticated identities and endpoint-side authorization.

## Integrity model

| Control | Mechanism | Verified by |
|---|---|---|
| Tamper-evident history | Each audit entry stores SHA-256 of its content and the previous entry's hash | Unit tests; real case copy with one edited field detected |
| Body matches history | Case body is re-derived by replaying the audit log on every load/save | `aegis case verify`, unit tests |
| Immutable after closure | Only `correction` (with reason) and `note` allowed in `closed`/`false_positive` | Real case: post-close `set` refused |
| Evidence integrity | Raw alert stored as a file with SHA-256; files never overwritten | `aegis case verify` |
| No lost updates | Save refuses if the case changed on disk since it was loaded | Regression test (found when two CLI runs interleaved) |
| Safe rendering | All case text HTML-escaped and Markdown-escaped; optional term redaction | Unit test with injected `<img onerror>` and `|` |

Limitations: integrity is tamper-*evident*, not tamper-*proof*: someone with write access can rewrite the
whole file and recompute every hash. Pushing case hashes to an external append-only store would be
needed for stronger guarantees. Actor names are self-declared (`--actor`); there is no authentication.

## Triage guidance

1. Treat a single alert as a lead. Look for corroboration (other sources, same user/host, timing).
2. Check whether an authorized scenario or a known change explains the activity before escalating.
3. Record uncertainty explicitly (`confidence`) and say which telemetry was missing.
4. Recommendations must be specific and are executed manually by a human after approval.

Worked example (real lab alerts, redacted): [reports/examples/CASE-example-report.md](../reports/examples/CASE-example-report.md).
