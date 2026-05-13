# V2 Ops Handbook

## Core artifacts

- `compatibility-report.md`
- `v1.1-readiness.md`
- `v1.1-freeze-boundary.md`
- `audit-drift-report.md`
- `shadow-review.md`
- `fleet-review.md`
- `v2-rc-readiness.md`
- `v2-ga-packet.md`

## Escalation path

1. freeze scoreboard fails
2. freeze boundary inventory has an unresolved deferred / non-goal mismatch
3. audit drift introduces unknown codes
4. shadow review shows v2 regression
5. provider / plugin / delivery bridge artifact check fails
6. provider rollout checklist triggers rollback
7. fleet review exceeds cost ceiling or exposes unverified provenance
8. GA packet fails LTS/support/sunset checks

## Steady-state loop

1. collect metrics / audits
2. normalize replay evidence
3. rebuild compatibility report
4. refresh freeze boundary inventory when scope decisions change
5. review shadow output
6. verify provider, audit, plugin shadow, webhook, and notification bridge artifacts
7. review fleet packet
8. decide hold / widen / rollback

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
