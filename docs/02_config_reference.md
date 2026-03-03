# 02 Config Reference

`policy.toml` で patchgate の挙動を調整します。

## Top-level fields

- `policy_version`
  - 推奨値は `2`
  - 未指定 policy は互換維持のため `v1` として解釈

## 主要セクション

- `[output]`
  - `format = "text" | "json"`
  - `mode = "warn" | "enforce"`
  - `fail_threshold = 0..=100`
- `[scope]`
  - `mode = "staged" | "worktree" | "repo"`
  - `max_changed_files = <u32>` (`> 0`)
  - `on_exceed = "fail_open" | "fail_closed"`
- `[cache]`
  - `enabled = true|false`
  - `db_path = ".patchgate/cache.db"`
- `[observability]`
  - `metrics_jsonl_path = "<path>"`（空文字で無効）
  - `audit_jsonl_path = "<path>"`（空文字で無効）
  - `audit_schema_version = 1..=10`（現在は `1`）
- `[alerts]`
  - `score_drop_threshold = 0..=100`
  - `failure_rate_increase_pct = 0..=100`
  - `duration_increase_pct = 0..=100`
- `[exclude]`
  - `globs = ["vendor/**", ...]`
- `[generated_code]`
  - `mode = "exclude" | "decay"`
  - `globs = ["**/generated/**", ...]`
  - `penalty_decay_percent = 0..=100`
- `[language_rules]`
  - `rust`, `typescript`, `python`, `go`, `java_kotlin`
- `[weights]`
  - `test_gap_max_penalty`
  - `dangerous_change_max_penalty`
  - `dependency_update_max_penalty`
- `[test_gap]`
  - `enabled`, `test_globs`, `production_ignore_globs`
  - `missing_tests_penalty`, `large_change_lines`, `large_change_penalty`
- `[dangerous_change]`
  - `enabled`, `patterns`, `critical_patterns`
  - `per_file_penalty`, `critical_bonus_penalty`
- `[dependency_update]`
  - `enabled`, `manifest_globs`, `lockfile_globs`
  - `manifest_penalty`, `lockfile_penalty`
  - `large_lockfile_churn`, `large_lockfile_penalty`
  - `lockfile_added_or_removed_penalty`
  - `lockfile_mass_update_lines`, `lockfile_mass_update_penalty`
  - `[dependency_update.ecosystem_penalties.<cargo|npm|python|go|jvm>]`
    - `manifest_bonus_penalty`
    - `lockfile_bonus_penalty`
    - `large_lockfile_bonus_penalty`
- `[waiver]`
  - `entries = [{...}]`
  - 各entry必須:
    - `check_id` (non-empty)
    - `reason` (non-empty)
    - `approver` (non-empty)
    - `expires_at` (RFC3339, 未来日時)

## Validation error categories

- `type`: enum値不正、glob構文不正、TOML型不正、waiver日時形式不正
- `range`: 値域不正
- `dependency`: 相互依存不整合、期限切れwaiver、ペナルティ上限制約違反

## Presets

- `strict`, `balanced`, `relaxed`
- 適用順: `default < preset < policy file < CLI override`
- 参照: `config/presets/*.toml`
