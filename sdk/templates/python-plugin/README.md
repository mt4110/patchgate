# Python plugin template

このテンプレートは `patchgate.plugin.v1` の最小実装です。

## Run local

```bash
python3 main.py < sample-input.json
```

V2 shadow preview:

```bash
python3 main.py < sample-input.v2.json
```

## Output

```json
{
  "findings": [],
  "diagnostics": ["plugin_id=sample", "changed_files=2"]
}
```
