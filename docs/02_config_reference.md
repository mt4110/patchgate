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
  - `audit_v2_jsonl_path`
  - `audit_v2_schema_version`
- `[alerts]`: summary alert threshold
- `[policy_authority]`: trusted policy source settings for enforce mode
  - `enforce_trusted_policy_required`
  - `protected_policy_ref`
  - `org_bundle_path`
  - `org_bundle_signature_path`
  - `org_bundle_public_key_env`
  - `allow_untrusted_local_enforce`
- `[exclude]`, `[generated_code]`, `[language_rules]`
- `[weights]`
  - `test_gap_max_penalty`
  - `dangerous_change_max_penalty`
  - `dependency_update_max_penalty`
  - `plugin_max_penalty`
- `[test_gap]`, `[dangerous_change]`, `[dependency_update]`
- `[waiver]`
  - `entries = [{ check_id, reason, approver, expires_at }]`
  - optional v1 binding fields: `waiver_id`, `gate_id`, `evidence_id`, `ticket`
  - `gate_id = "critical-supply-chain"` or `check_id = "critical_supply_chain"` can scope a waiver to the critical supply-chain hard gate.

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
  - `public_key_env`（ed25519 public key を base64 で渡す主環境変数名）
  - `trusted_key_envs`（rotation期間に追加で信頼する公開鍵env名）
  - `revoked_key_sha256`（失効した公開鍵の raw ed25519 public key sha256 hex）

## Integration sections (Phase85-87)

- `[integrations.ci]`
  - `provider = "github" | "generic"`
  - `generic_schema = "v1" | "v2" | "dual"`
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

## Compatibility sections (Phase151+)

- `[compatibility.v1]`
  - `rc_frozen`
  - `allow_legacy_config_names`
- `[compatibility.v2]`
  - `shadow_mode`
  - `bridge_mode = "off" | "provider" | "audit" | "full"`
  - `migration_guide_path`

`compatibility.v2.bridge_mode` を `audit` / `full` にする場合は
`observability.audit_v2_jsonl_path` が必要です
（プレビュー用スモークテストなどで CLI フラグや bridge のランタイム上書きで注入する場合を除く）。
`provider` / `full` の場合は `integrations.ci.generic_schema = "v2" | "dual"` が、
完全に構成された bridge 実行では必要です
（こちらもプレビュー実行では CLI オーバーライドで代替可能です）。
`full` の場合は webhook / generic notification adapter も shadow metadata を付与します。

## Validation categories

- `type`: enum/URL/glob/TOML型不正
- `range`: 閾値・timeout・SLA/SLO範囲不正
- `dependency`: 相互依存不整合、期限切れwaiver、必須項目欠落

## Presets

- `strict`, `balanced`, `relaxed`
- 適用順: `default < preset < policy file < CLI override`
- enforce mode では `--threshold`, `--max-changed-files`, `--on-exceed` の CLI 上書きは使わず、trusted base policy か stricter PR overlay に置きます。
