# Example plugin (python)

`policy.toml` 例:

```toml
[plugins]
enabled = true
lockfile_path = "patchgate-plugin.lock"
entries = [
  { id = "python-sample", command = "python3", args = ["examples/plugins/python-sample/plugin.py"], timeout_ms = 3000, fail_mode = "fail_open" }
]

[plugins.sandbox]
profile = "restricted"
allow_network = false
env_allowlist = []
max_stdout_kib = 256
```

`enforce` mode でこの plugin を使う場合は、entry に `manifest_path` を追加し、signed manifest と `patchgate-plugin.lock` で artifact digest と signing key fingerprint を固定してください。manifest の `entrypoint` は policy の `command` と `args` をそのまま並べます。

```toml
schema_version = "patchgate.plugin.manifest.v1"
id = "python-sample"
version = "0.1.0"
entrypoint = ["python3", "examples/plugins/python-sample/plugin.py"]
runtime = "python3"

[permissions]
network = false
env = []
read_paths = ["."]
write_paths = []

[artifacts]
main = "sha256:..."
lockfile = "sha256:..."

[producer]
kind = "scanner-adapter"
emits = ["patchgate.evidence.v1"]

[signature]
key_id = "org-plugin-key-2026q2"
signature = "base64:..."
```
