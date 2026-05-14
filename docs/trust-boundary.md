# Trust Boundary

PatchGate treats enforce-mode policy as the judge, not as part of the PR being judged.

## Authority Sources

Trusted sources are merged in authority order, from lowest to highest precedence:

- base branch policy, usually `policy.toml` at the PR base SHA
- protected policy ref, such as `refs/patchgate/policy/main`
- signed organization bundle (`schema_version = "patchgate.policy.bundle.v1"`)

Warn mode can still use a local policy file when no trusted source is available; that report marks `policy_authority.trusted=false`.
Enforce mode fails when only an untrusted local policy is available, unless a local operator explicitly passes `--allow-untrusted-policy-for-local-enforce`.
The base ref is a runtime trust anchor and must be supplied by CI with `--base-ref`; it is not read from PR-editable policy config.

## PR Overlay Rules

PR policy changes are treated as an overlay on top of the trusted policy.
Only stricter changes are accepted:

- raise `output.fail_threshold`
- enable language or hard-gate checks
- add dangerous or critical patterns
- reduce `scope.max_changed_files`
- change `scope.on_exceed` from `fail_open` to `fail_closed`
- increase penalties or max penalties
- add signed `fail_closed` plugins
- remove excludes or generated-code globs

Rejected changes include lowering thresholds, disabling checks, widening excludes, changing trusted keys, adding waivers, and making plugin execution fail open.

Every JSON report includes:

```json
{
  "policy_authority": {
    "trusted": true,
    "digest": "sha256:...",
    "sources": [],
    "pr_overlay": {
      "present": true,
      "accepted_keys": [],
      "rejected_keys": []
    }
  }
}
```

## GitHub Template

Use `docs/patchgate-github-trust-template-v1.yml` and configure branch protection to require:

```text
patchgate/trust-boundary
```

The template passes `--base-ref` from the pull request base SHA and publishes a check-run with the same stable name.
This check name is intentionally different from the legacy `patchgate` default, so branch-protection rules must be updated to require `patchgate/trust-boundary` before switching templates.

## Org Bundle Schema

An organization bundle is a signed TOML file:

```toml
schema_version = "patchgate.policy.bundle.v1"

[policy]
policy_version = 2

[policy.output]
mode = "enforce"
fail_threshold = 80
```

Sign the exact bundle bytes with an ed25519 key and provide the base64 public key through `PATCHGATE_POLICY_BUNDLE_PUBLIC_KEY`.
Keys and signatures may use standard or URL-safe base64, with or without padding.

```bash
patchgate policy attest \
  --bundle org-policy-bundle.toml \
  --signature org-policy-bundle.sig \
  --public-key-env PATCHGATE_POLICY_BUNDLE_PUBLIC_KEY
```
