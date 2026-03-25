# V2 Ops Handbook

## Core artifacts

- `compatibility-report.md`
- `v1.1-readiness.md`
- `audit-drift-report.md`
- `shadow-review.md`
- `fleet-review.md`
- `v2-rc-readiness.md`
- `v2-ga-packet.md`

## Escalation path

1. freeze scoreboard fails
2. audit drift introduces unknown codes
3. shadow review shows v2 regression
4. provider rollout checklist triggers rollback
5. fleet review exceeds cost ceiling or exposes unverified provenance
6. GA packet fails LTS/support/sunset checks

## Steady-state loop

1. collect metrics / audits
2. normalize replay evidence
3. rebuild compatibility report
4. review shadow output
5. review fleet packet
6. decide hold / widen / rollback

## GA command

```bash
cargo run -p xtask -- ops ga-packet \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --policy-input artifacts/policy.v2.toml \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --ops-handbook-path docs/19_v2_ops_handbook.md \
  --support-model-path docs/22_v2_support_model.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --phase201-backcast-path docs/20_phase201_plus_backcast.md \
  --output artifacts/v2-ga-packet.md
```
