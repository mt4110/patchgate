# Fleet Lab

fleet / registry / exception governance をまとめて確認するための fixture 集です。

## Files

- `bundle-catalog.json`
- `plugin-registry.json`
- `exceptions.json`

provider fixture は `../compatibility-lab/provider-dual.json` を流用できます。

## Example

```bash
cargo run -p xtask -- ops fleet-review \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input examples/poc/compatibility-lab/provider-dual.json \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json \
  --cost-ceiling-minutes 30 \
  --output target/fleet-lab/fleet-review.md
```
