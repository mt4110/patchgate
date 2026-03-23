# V2 Candidate Release Checklist

- [ ] `patchgate policy verify-v2`
- [ ] `patchgate policy diff-contract`
- [ ] `xtask ops compatibility-report`
- [ ] `xtask ops freeze-scoreboard`
- [ ] `xtask ops audit-drift-report`
- [ ] `xtask ops shadow-review`
- [ ] `xtask ops fleet-review`
- [ ] `xtask ops rc-readiness`
- [ ] provider dual-schema artifact compatibility verified
- [ ] audit dual-write artifact compatibility verified
- [ ] migration guide updated
- [ ] rollback packet updated
- [ ] RC security review attached
- [ ] benchmark sign-off attached

## Reference Command

```bash
cargo run -p xtask -- ops rc-readiness \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --provider-input artifacts/provider-dual.json \
  --benchmark-input artifacts/bench-compare.json \
  --security-review-input artifacts/security-review-template.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --provider-rollout-path docs/15_provider_rollout_checklist.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --output artifacts/v2-rc-readiness.md
```
