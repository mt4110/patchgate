# Compatibility Lab

v1 / v2 bridge の fixture を手元で確認するための最小 lab です。

## Files

- `provider-v1.json`
- `provider-dual.json`
- `audit-v1.jsonl`
- `audit-v2.jsonl`
- `scan-metrics.jsonl`
- `replay-summary.json`
- `migration-drill.json`
- `rollback-packet.json`
- `rc-security-review.md`
- `bench-compare.json`
- `policy.v2.toml`
- `v2-ga-packet.md`
- `ecosystem-migration-completion.md`
- `dual-run-decommission.md`
- `post-ga-telemetry-review.md`
- `retrospective-cleanup-queue.md`
- `plugin-shadow-input.v2.json`
- `webhook-shadow-envelope.json`
- `notification-shadow-envelope.json`

## Example

```bash
cargo run -p xtask -- ops replay-normalize \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --output target/compatibility-lab/dead-letter-evidence.json

cargo run -p xtask -- ops shadow-review \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json \
  --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json \
  --output target/compatibility-lab/shadow-review.md

cargo run -p patchgate-cli -- policy verify-v2 \
  --path examples/poc/compatibility-lab/policy.v2.toml \
  --readiness-profile ga \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --plugin-shadow-input examples/poc/compatibility-lab/plugin-shadow-input.v2.json \
  --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json \
  --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json \
  --format text
```

RC hardening fixture path:

```bash
mkdir -p target/compatibility-lab

cargo run -p patchgate-cli -- policy diff-contract \
  --path examples/poc/compatibility-lab/policy.v2.toml \
  --format json \
  --enforce > target/compatibility-lab/diff-contract.json

cargo run -p xtask -- ops freeze-boundary \
  --output target/compatibility-lab/v1.1-freeze-boundary.md

cargo run -p xtask -- ops fleet-review \
  --metrics-input examples/poc/fleet-lab/scan-metrics.jsonl \
  --audit-input examples/poc/fleet-lab/scan-audit.jsonl \
  --audit-v2-input examples/poc/fleet-lab/scan-audit-v2.jsonl \
  --provider-input examples/poc/fleet-lab/provider-dual.json \
  --provider-input examples/poc/fleet-lab/provider-internal-dual.json \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json \
  --cost-ceiling-minutes 30 \
  --output target/compatibility-lab/fleet-review.md

cargo run -p xtask -- ops audit-drift-report \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --output target/compatibility-lab/audit-drift-report.md

cargo run -p xtask -- ops shadow-review \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --output target/compatibility-lab/shadow-review.md

cargo run -p xtask -- ops rollback-packet \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --output target/compatibility-lab/rollback-packet.json

cargo run -p xtask -- ops migration-drill \
  --metrics-input examples/poc/compatibility-lab/scan-metrics.jsonl \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --rollback-packet-input target/compatibility-lab/rollback-packet.json \
  --output target/compatibility-lab/migration-drill.json

cargo run -p xtask -- ops rc-readiness \
  --metrics-input examples/poc/compatibility-lab/scan-metrics.jsonl \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --benchmark-input examples/poc/compatibility-lab/bench-compare.json \
  --security-review-input examples/poc/compatibility-lab/rc-security-review.md \
  --contract-freeze-input target/compatibility-lab/diff-contract.json \
  --migration-drill-input target/compatibility-lab/migration-drill.json \
  --rollback-packet-input target/compatibility-lab/rollback-packet.json \
  --fleet-review-input target/compatibility-lab/fleet-review.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --provider-rollout-path docs/15_provider_rollout_checklist.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --freeze-boundary-path target/compatibility-lab/v1.1-freeze-boundary.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --output target/compatibility-lab/v2-rc-readiness.md

cat > target/compatibility-lab/v2-ga-go-no-go.md <<'EOF'
# V2 GA Go / No-Go Review

## Required Evidence
- RC readiness: target/compatibility-lab/v2-rc-readiness.md
- rollback packet: target/compatibility-lab/rollback-packet.json
- LTS policy: examples/poc/compatibility-lab/policy.v2.toml
- v1 sunset notice: docs/21_v1_sunset_notice.md
- support path: docs/22_v2_support_model.md

## Decision
- [x] Go
- [ ] No-go
EOF

cargo run -p xtask -- ops ga-packet \
  --metrics-input examples/poc/compatibility-lab/scan-metrics.jsonl \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --policy-input examples/poc/compatibility-lab/policy.v2.toml \
  --rc-readiness-input target/compatibility-lab/v2-rc-readiness.md \
  --go-no-go-path target/compatibility-lab/v2-ga-go-no-go.md \
  --fleet-review-input target/compatibility-lab/fleet-review.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --ops-handbook-path docs/19_v2_ops_handbook.md \
  --support-model-path docs/22_v2_support_model.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --phase201-backcast-path docs/20_phase201_plus_backcast.md \
  --output target/compatibility-lab/v2-ga-packet.md

cargo run -p xtask -- ops migration-completion \
  --metrics-input examples/poc/compatibility-lab/scan-metrics.jsonl \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --fleet-review-input target/compatibility-lab/fleet-review.md \
  --rc-readiness-input target/compatibility-lab/v2-rc-readiness.md \
  --migration-drill-input target/compatibility-lab/migration-drill.json \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --output target/compatibility-lab/ecosystem-migration-completion.md

cargo run -p xtask -- ops dual-run-decommission \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --rollback-packet-input target/compatibility-lab/rollback-packet.json \
  --migration-drill-input target/compatibility-lab/migration-drill.json \
  --rc-readiness-input target/compatibility-lab/v2-rc-readiness.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --support-model-path docs/22_v2_support_model.md \
  --output target/compatibility-lab/dual-run-decommission.md

cargo run -p xtask -- ops post-ga-telemetry \
  --metrics-input examples/poc/compatibility-lab/scan-metrics.jsonl \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --fleet-review-input target/compatibility-lab/fleet-review.md \
  --ga-packet-input target/compatibility-lab/v2-ga-packet.md \
  --support-model-path docs/22_v2_support_model.md \
  --output target/compatibility-lab/post-ga-telemetry-review.md

cargo run -p xtask -- ops retrospective-cleanup \
  --migration-completion-input target/compatibility-lab/ecosystem-migration-completion.md \
  --dual-run-decommission-input target/compatibility-lab/dual-run-decommission.md \
  --post-ga-telemetry-input target/compatibility-lab/post-ga-telemetry-review.md \
  --ops-handbook-path docs/19_v2_ops_handbook.md \
  --support-model-path docs/22_v2_support_model.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --phase201-backcast-path docs/20_phase201_plus_backcast.md \
  --output target/compatibility-lab/retrospective-cleanup-queue.md
```
