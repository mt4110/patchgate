# V2 Candidate Release Checklist

- [ ] `patchgate policy verify-v2`
- [ ] `patchgate policy diff-contract`
- [ ] `xtask ops compatibility-report`
- [ ] `xtask ops freeze-scoreboard`
- [ ] `xtask ops freeze-boundary`
- [ ] `xtask ops audit-drift-report`
- [ ] `xtask ops shadow-review`
- [ ] `xtask ops fleet-review`
- [ ] `xtask ops rc-readiness`
- [ ] provider dual-schema artifact compatibility verified
- [ ] audit dual-write artifact compatibility verified
- [ ] plugin v2 shadow envelope sample verified
- [ ] webhook / notification bridge metadata verified
- [ ] migration guide updated
- [ ] rollback packet updated
- [ ] v1.1 freeze boundary inventory reviewed
- [ ] v2 option matrix and risk register attached to RC packet via `--freeze-boundary-path`
- [ ] RC security review approved (`Continue` checked)
- [ ] benchmark sign-off attached

## Reference Command

```bash
cargo run -p xtask -- ops freeze-boundary \
  --output artifacts/v1.1-freeze-boundary.md
```

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
  --freeze-boundary-path artifacts/v1.1-freeze-boundary.md \
  --output artifacts/v2-rc-readiness.md
```

`artifacts/security-review-template.md` は `- [x] Continue` が必要で、`Mitigation required` を同時にチェックしてはいけません。
