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
