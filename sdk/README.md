# patchgate SDK

`patchgate.plugin.v1` 準拠プラグインの雛形を提供します。

## Quickstart

```bash
cp -R sdk/templates/python-plugin my-plugin
cd my-plugin
python3 main.py <<'JSON'
{"schema_version":1,"api_version":"patchgate.plugin.v1","plugin_id":"sample","repo_root":".","mode":"warn","scope":"worktree","changed_files":[]}
JSON
```

## Contract

- stdin: `PluginInput`
- stdout: `PluginOutput` (JSON)
- stderr: 任意診断
- timeout: `plugins.entries[].timeout_ms`
- sandbox: `plugins.sandbox.*`
