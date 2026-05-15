# patchgate SDK

`patchgate.plugin.v1` 準拠プラグインの雛形を提供します。

## Quickstart

```bash
patchgate plugin init --lang python --plugin-id sample --output ./my-plugin
patchgate plugin init --lang node --plugin-id sample-node --output ./my-node-plugin
patchgate plugin init --lang rust --plugin-id sample-rust --output ./my-rust-plugin
```

Templates:

- `sdk/templates/python-plugin`
- `sdk/templates/node-plugin`
- `sdk/templates/rust-plugin`

## Contract

- stdin: `PluginInput`
- stdout: `PluginOutput` (JSON)
- stderr: 任意診断
- timeout: `plugins.entries[].timeout_ms`
- sandbox: `plugins.sandbox.*`
- enforce trust: `plugins.entries[].manifest_path` + `plugins.lockfile_path`

`enforce` mode では signed manifest と plugin lockfile がない plugin は実行前に拒否されます。local 開発中は `warn` mode で template を動かし、配布前に manifest の artifact digest と signing key fingerprint を lockfile に固定してください。

## V2 shadow preview

- generated template には `sample-input.v2.json` も含まれます
- これは `patchgate.plugin.v2-shadow` の preview envelope で、現時点では migration 設計用サンプルです
- runtime stdin は v1 のまま維持し、v2 shadow envelope は diagnostics と `verify-v2 --plugin-shadow-input` で検証します
