# Compatibility Lab

v1 / v2 bridge の fixture を手元で確認するための最小 lab です。

## Files

- `provider-v1.json`
- `provider-dual.json`
- `audit-v1.jsonl`
- `audit-v2.jsonl`
- `replay-summary.json`
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
