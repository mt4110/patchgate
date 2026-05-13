# Fleet Lab

fleet / registry / exception governance をまとめて確認するための fixture 集です。

## Files

- `bundle-catalog.json`
- `plugin-registry.json`
- `exceptions.json`
- `scan-metrics.jsonl`
- `scan-audit.jsonl`
- `scan-audit-v2.jsonl`
- `provider-dual.json`
- `provider-internal-dual.json`

`bundle-catalog.json` は repo / segment / rollout wave / retention tier / provider capability contract をまとめます。
`plugin-registry.json` は provenance, digest, attestation, sandbox profile を review packet に渡します。
`exceptions.json` は org-level exception の ticket / owner / expiry を検証します。

## Example

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
  --output target/fleet-lab/fleet-review.md
```

CLI artifact validation:

```bash
cargo run -p patchgate-cli -- policy verify-v2 \
  --path examples/poc/compatibility-lab/policy.v2.toml \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json
```
