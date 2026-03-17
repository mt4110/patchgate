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
