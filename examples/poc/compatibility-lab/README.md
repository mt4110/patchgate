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
```
