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
- `diff-contract.json`
- `migration-drill.json`
- `rollback-packet.json`
- `v2-ga-go-no-go.md`

## Escalation path

1. freeze scoreboard fails
2. freeze boundary inventory has an unresolved deferred / non-goal mismatch
3. audit drift introduces unknown codes
4. shadow review shows v2 regression
5. provider / plugin / delivery bridge artifact check fails
6. provider rollout checklist triggers rollback
7. fleet review exceeds cost ceiling, fails provider negotiation, exposes unverified provenance, or has expired exceptions
8. RC readiness lacks contract freeze, migration drill, rollback packet, security review, benchmark/cost sign-off, or v1 deprecation countdown evidence
9. GA packet fails RC readiness, go/no-go, LTS/support/sunset checks

## Steady-state loop

1. collect metrics / audits
2. normalize replay evidence
3. rebuild compatibility report
4. refresh freeze boundary inventory when scope decisions change
5. review shadow output
6. verify provider, audit, plugin shadow, webhook, and notification bridge artifacts
7. review fleet packet, including segment cost, retention tier, exception governance, and Phase181+ RC prep blockers
8. generate rollback packet from current audit v1 / audit v2 / provider restore evidence
9. generate migration drill from current metrics / audit v1 / audit v2 / provider / rollback evidence
10. attach contract freeze, migration drill, rollback packet, security review, benchmark/cost sign-off, and countdown markers to RC readiness
11. for release workflow, set `rc_security_decision=continue` and `ga_decision=go` only after the packet evidence is reviewed
12. decide hold / widen / rollback

## GA command

```bash
cargo run -p xtask -- ops ga-packet \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --policy-input artifacts/policy.v2.toml \
  --rc-readiness-input artifacts/v2-rc-readiness.md \
  --go-no-go-path artifacts/v2-ga-go-no-go.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --ops-handbook-path docs/19_v2_ops_handbook.md \
  --support-model-path docs/22_v2_support_model.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --phase201-backcast-path docs/20_phase201_plus_backcast.md \
  --output artifacts/v2-ga-packet.md
```
