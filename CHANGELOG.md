# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Repository foundation: license, security policy, contribution and review rules.
- Architecture, deployment profiles, and threat model documentation.
- `aegis` CLI: preflight, secret initialization, pinned upstream download with SHA-256
  verification, certificate generation, config rendering, stack start/stop.
- Compose override binding all Wazuh ports to localhost, removing demo indexer users,
  enabling password-protected agent enrollment, and applying memory limits.
- Provisioning of least-privilege reader accounts (indexer + Wazuh API) and rotation of
  the default `wazuh` API user.
- Health checks with JSON reports (containers, port exposure, API, daemons, agents,
  indexer health, disk, alert freshness, default credentials).
- Linux (WSL2 Ubuntu) agent installation script with GPG fingerprint verification.
- Preflight check for busy/reserved host ports.
- First live deployment record and idle resource measurements (`benchmarks/`).
- Milestone 1 end-to-end evidence (`reports/examples/M1-E2E-001-linux-auth-failure.json`).
- `keep-wsl-endpoint-online.ps1` to prevent WSL idle shutdown from stopping the Linux agent.
- Centralized agent group configs (`linux`, `windows`) with `aegis agent-config validate|apply`.
- Linux auditd rules (root command execution) and real-time FIM on privilege/persistence paths.
- Windows Sysmon configuration and signature-verifying installers for Sysmon and the Wazuh agent.
- `agents` health check reports group configuration drift.
- Detection-as-code: `detections/` rules + metadata, `aegis detections validate|test|deploy`, CI validation.
- Linux detections 100100 (local brute-force by user), 100200 (sudoers), 100201 (cron/systemd), 100202 (accounts).
- Detection methodology documentation.
- Scenario runner (`aegis scenarios validate|list|run --authorize`) with 5 Linux scenarios; outcomes come
  only from observed alerts; statuses PASSED/FAILED/TIMED_OUT/INCONCLUSIVE/SKIPPED/CLEANUP_REQUIRED.
- Coverage matrix generator (`aegis coverage`).
- Incident cases (`aegis case ...`): JSON Schema, lifecycle preconditions, hash-chained audit trail
  replayed on load, post-closure corrections only, SHA-256 evidence files, escaped/redacted reports.
- Metrics (`aegis metrics`) with documented definitions and sample sizes; operations guide.
- Suppression rule 100900 (rootcheck false positives on rust-coreutils) with suppression validation rules.
- `prepare --rehash-users` separated from `--force-render`.
- Images pinned by digest; ISM retention policy (30 days) via `aegis provision`.
- `aegis backup create` (cold, SHA-256 manifest) and `aegis backup verify-restore` (isolated restore project).
- Secret scanning: gitleaks in CI and a repository hygiene unit test.
- Linux host support (Docker Engine): host-kernel `vm.max_map_count` check, host-specific preflight advice,
  Linux deployment and teardown procedures. Not yet verified on a live Linux host.
- `AEGIS_LINUX_EXECUTOR` (`wsl:<distro>` or `local`) selects how scenario commands reach the Linux endpoint.
- Scenario runner confirms the endpoint's agent id and name before running anything; mismatches are SKIPPED.
- Response playbooks (`playbooks/`, `aegis playbooks validate|list`) and case response actions
  (`aegis case propose|approve|reject|execute --simulate`): allowlisted action types, validated targets,
  two-person approval, single execution, simulation only, all in the case audit trail.

### Changed
- Scenario manifests no longer name a WSL distro; the transport is a host setting.
- Documentation covers Windows and Linux hosts; tooling is installed in a virtual environment outside the repository.

### Security
- `.env` is written `0600`; the rendered runtime directory and backup folders are `0700` on POSIX hosts.
- Alert text printed by `aegis case` has control characters neutralized (no terminal escape injection).
- Metrics Markdown escapes alert-derived text (rule descriptions interpolate decoded fields such as user names).

### Fixed
- Default dashboard port moved 8443 → 5601 (8443 held by a Windows service on the reference host).
- TLS clients now send the expected service name as SNI; the indexer rejected IP-only handshakes.
- `.env` files with a UTF-8 BOM are normalized by `init-secrets` and refused by `up`.
- Provisioning tolerates Wazuh API HTTP 500 timeouts on password updates by confirming via login.
- Rule 100100 used `<same_field>` on a static field and never fired; now `<same_srcuser />`.
- Linux FIM lost real-time watches after atomic file replaces; now watches directories.
- auditd setup exits cleanly on WSL2 (kernel audit inaccessible) instead of crash-looping.
- Windows agent installer re-prompts for the enrollment password when the agent has no key; installers log transcripts.
- WSL keep-alive task re-checks every 5 minutes.
- Case saves refuse concurrent modification (lost-update found when two CLI runs interleaved).
- Rule deploy retries configuration validation on API timeouts and never restarts the manager unvalidated.
- Manager-container SCA disabled (Amazon Linux CIS checks were 28% of alert volume and not lab telemetry).
- Health polling no longer runs the default-credential probe (it locked out the API); opt-in `--credential-test`.
- ISM system indices set to 0 replicas (cluster was yellow on a single node).
- Provisioning is idempotent for existing API role links.
- Restore verification waits for full alert recovery and requires stable live health.
- A failed scenario cleanup step no longer prevents later cleanup steps from running.
- `aegis backup verify-restore` without a path ignores incomplete backup folders and explains when none exist.
- The secret-scanning test no longer flags its own search patterns.
