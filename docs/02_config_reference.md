# 02 Config Reference

`policy.toml` で patchgate の挙動を調整します。

## Top-level fields

- `policy_version`
  - 推奨値は `2`
- `compatibility.v1`
  - `rc_frozen`
  - `allow_legacy_config_names`

## Existing sections

- `[output]`: `format`, `mode`, `fail_threshold`
- `[scope]`: `mode`, `max_changed_files`, `on_exceed`
- `[cache]`: `enabled`, `db_path`
- `[observability]`: metrics/audit path + schema version
- `[alerts]`: summary alert threshold
- `[exclude]`, `[generated_code]`, `[language_rules]`
- `[weights]`
  - `test_gap_max_penalty`
  - `dangerous_change_max_penalty`
  - `dependency_update_max_penalty`
  - `plugin_max_penalty`
- `[test_gap]`, `[dangerous_change]`, `[dependency_update]`
- `[waiver]`

## Plugin sections (Phase81-83)

- `[plugins]`
  - `enabled`
  - `entries = [{ id, command, args, timeout_ms, fail_mode }]`
- `[plugins.sandbox]`
  - `profile = "none" | "restricted" | "isolated"`（`isolated` は Linux + `bwrap` 前提）
  - `allow_network`
  - `env_allowlist`
  - `max_stdout_kib`
- `[plugins.signature]`
  - `required`
  - `public_key_env`（ed25519 public key を base64 で渡す環境変数名）

## Integration sections (Phase85-87)

- `[integrations.ci]`
  - `provider = "github" | "generic"`
  - `generic_output_path`（`provider = "generic"` で publish する場合は必須）
- `[integrations.webhook]`
  - `enabled`
  - `urls`
  - `secret_env`
  - `timeout_ms`
- `[integrations.notifications]`
  - `enabled`
  - `targets = [{ name, kind, url }]`
  - `retry_max_attempts`
  - `retry_backoff_ms`
  - `timeout_ms`

## Release/LTS sections (Phase94-95)

- `[release.lts]`
  - `active`
  - `branch`
  - `security_sla_hours`
  - `backport_labels`
- `[release.slo]`
  - `availability_target_pct`
  - `p95_duration_ms`
  - `false_positive_target_pct`（現行実装では `gate_failure_rate_pct` を proxy 指標として判定）

## Validation categories

- `type`: enum/URL/glob/TOML型不正
- `range`: 閾値・timeout・SLA/SLO範囲不正
- `dependency`: 相互依存不整合、期限切れwaiver、必須項目欠落

## Presets

- `strict`, `balanced`, `relaxed`
- 適用順: `default < preset < policy file < CLI override`
