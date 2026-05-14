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
- federated metrics / audit streams (`scan-metrics.jsonl`, `scan-audit*.jsonl`)
- provider capability artifacts (`provider-*.json`)

## Command

```bash
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
  --output artifacts/fleet-review.md
```

CLI artifact validation:

```bash
cargo run -p patchgate-cli -- policy verify-v2 \
  --path examples/poc/compatibility-lab/policy.v2.toml \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json
```

`verify-v2` は v2-ready policy の確認と同じ流れで、fleet governance fixture の schema / required fields /
expiry / provenance completeness を検証します。

## Governance checks

- **multi-repo policy bundle catalog**: repo, segment, wave, retention tier, provider requirements を catalog で一元化
- **federated metrics / audit aggregation**: repo ごとの metrics / audit v1 / audit v2 数、audit drift、stream contract を表示
- **plugin registry provenance index**: verified / revoked / digest / attestation / trusted provenance を確認
- **provider capability negotiation contract**: catalog の required modes / capabilities と provider artifact を照合
- **audit retention tier policy**: hot / warm / cold window と repo assignment を検証
- **rollout wave orchestration**: wave order / max parallel / entry gate / rollback trigger を review packet に表示
- **org-level exception governance**: ticket / owner / approver / expiry / status を検証
- **fleet cost ceiling by segment**: segmentごとの実測CI minutesと ceiling を比較
- **Phase181+ RC prep review**: RC候補repoの blocker を `phase181-rc-hardening` 前に列挙

## Review questions

- `stabilize-v1` の repo はどこか
- dual-run を始めてよい repo はどこか
- provider / audit / replay の drift が偏っていないか
- rollback trigger に該当する repo はあるか
- segment ごとの CI cost は ceiling 内か
- provenance 未検証 plugin や期限切れ exception はあるか
- Phase181+ RC hardening に進める repo と、fleet-review-remediation に戻す repo はどこか
