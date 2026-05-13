# Node plugin template

このテンプレートは `patchgate.plugin.v1` の最小実装です。

## Run local

```bash
node index.js < sample-input.json
```

V2 shadow preview:

```bash
node index.js < sample-input.v2.json
```

The preview keeps the runtime contract compatible with `patchgate.plugin.v1` while exposing
`api_version`, `shadow_of`, and `metadata.bridge_mode` in diagnostics for local contract checks.
