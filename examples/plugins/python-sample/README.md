# Example plugin (python)

`policy.toml` 例:

```toml
[plugins]
enabled = true
entries = [
  { id = "python-sample", command = "python3", args = ["examples/plugins/python-sample/plugin.py"], timeout_ms = 3000, fail_mode = "fail_open" }
]

[plugins.sandbox]
profile = "restricted"
allow_network = false
env_allowlist = []
max_stdout_kib = 256
```
