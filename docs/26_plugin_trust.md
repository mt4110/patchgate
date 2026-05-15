# Plugin Trust

PatchGate treats plugins as evidence producers. In `enforce` mode, a plugin must be pinned by a signed manifest and by `patchgate-plugin.lock`; unsigned or tampered plugins are rejected before the process starts.

## Manifest

`plugins.entries[].manifest_path` points to a TOML manifest:

```toml
schema_version = "patchgate.plugin.manifest.v1"
id = "sample"
version = "0.1.0"
entrypoint = ["./plugins/sample/plugin.sh"]
runtime = "sh"

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

The signature covers the manifest fields that define execution identity: id, version, entrypoint, runtime, artifact digests, permissions, producer output schema, and key id. The `signature.signature` value itself is excluded from the signed payload.

`artifacts.lockfile` is the digest of the canonical lock entry binding: lockfile schema version, plugin id, plugin version, source, and signing key fingerprint. Runtime also verifies the concrete `manifest_digest` in `patchgate-plugin.lock`, which avoids a circular manifest-to-lockfile hash while still binding the signed manifest to the lock material.

## Lockfile

`plugins.lockfile_path` defaults to `patchgate-plugin.lock`.

```json
{
  "schema_version": "patchgate.plugin.lock.v1",
  "plugins": [
    {
      "id": "sample",
      "version": "0.1.0",
      "manifest_digest": "sha256:...",
      "source": "internal-registry/sample",
      "signing_key_fingerprint": "sha256:..."
    }
  ]
}
```

In `enforce` mode, the lockfile must contain the plugin id, version, manifest digest, source, and signing key fingerprint that were verified at runtime.

## Permissions

Trust v1 is deny-by-default:

- network is denied unless both the manifest requests it and policy sets `plugins.sandbox.allow_network = true`
- env is empty unless every requested variable is listed in `plugins.sandbox.env_allowlist`
- write paths are rejected in trust v1
- read paths must be repo-relative and cannot contain `..`
- stdout/stderr are capped by `plugins.sandbox.max_stdout_kib`

`isolated` uses Linux `bwrap` and passes `--unshare-net` when network is denied. `restricted` is portable and clears environment variables, but it is not OS-level network isolation.

## Cache Material

The scan cache key includes plugin trust material: manifest bytes, lockfile bytes, signature file bytes, command/argument file bytes, sandbox profile, network setting, env allowlist, and output cap. Changing a plugin artifact or trust file causes a cache miss.

## Enforce Behavior

These cases fail before plugin execution in `enforce` mode:

- missing `manifest_path`
- missing or mismatched `patchgate-plugin.lock`
- manifest signature mismatch
- revoked signing key
- artifact digest mismatch
- permission request not allowed by policy
