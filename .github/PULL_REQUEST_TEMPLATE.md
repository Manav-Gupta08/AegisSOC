## Summary

<!-- What changed and why. -->

## Type

- [ ] feat
- [ ] fix
- [ ] detect (detection rule change)
- [ ] docs
- [ ] build / CI
- [ ] security

## Verification

<!-- Commands run and their results. Link sanitized evidence for live-lab claims. -->

- [ ] `pytest` passes locally
- [ ] Live-stack behavior verified (attach sanitized health report / alert evidence), or marked NOT VERIFIED

## Safety checklist

- [ ] No secrets, certificates, real hostnames/IPs/usernames, or raw logs in the diff
- [ ] TLS verification is not disabled anywhere
- [ ] No automated destructive response actions added
- [ ] Simulations (if any) target only authorized lab endpoints and include cleanup

## Detection changes only

- [ ] Rule ID in the range for its kind (100000–100799 / 100800–100899 / 100900–100999) and not reused
- [ ] Rationale, telemetry, severity, ATT&CK mapping documented
- [ ] Positive and negative tests added
- [ ] False positives and limitations documented
