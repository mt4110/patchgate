# Compatibility Lab

v1 / v2 bridge の fixture を手元で確認するための最小 lab です。

## Files

- `provider-v1.json`
- `provider-dual.json`
- `audit-v1.jsonl`
- `audit-v2.jsonl`
- `replay-summary.json`

## Example

```bash
cargo run -p xtask -- ops replay-normalize \
  --replay-summary-input examples/poc/compatibility-lab/replay-summary.json \
  --output target/compatibility-lab/dead-letter-evidence.json

cargo run -p xtask -- ops shadow-review \
  --audit-input examples/poc/compatibility-lab/audit-v1.jsonl \
  --audit-v2-input examples/poc/compatibility-lab/audit-v2.jsonl \
  --output target/compatibility-lab/shadow-review.md
```
