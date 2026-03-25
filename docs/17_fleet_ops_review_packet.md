# Fleet Ops Review Packet

複数 repo / 複数 provider の rollout をまとめて見るための review packet です。

## Inputs

- compatibility report
- freeze scoreboard
- audit drift report
- shadow review
- provider rollout checklist
- bundle catalog (`bundle-catalog.json`)
- plugin registry provenance (`plugin-registry.json`)
- org exception packet (`exceptions.json`)

## Command

```bash
cargo run -p xtask -- ops fleet-review \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json \
  --cost-ceiling-minutes 30 \
  --output artifacts/fleet-review.md
```

## Review questions

- `stabilize-v1` の repo はどこか
- dual-run を始めてよい repo はどこか
- provider / audit / replay の drift が偏っていないか
- rollback trigger に該当する repo はあるか
- segment ごとの CI cost は ceiling 内か
- provenance 未検証 plugin や期限切れ exception はあるか
