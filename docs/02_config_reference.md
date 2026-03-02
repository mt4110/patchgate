# 02 Config Reference

`policy.toml` で patchgate の挙動を調整します。

## Top-level fields

- `policy_version`
  - 現在の推奨値は `2`
  - 未指定 policy は互換維持のため `v1` として解釈

## 主要セクション

- `[output]`
  - `format = "text" | "json"`
  - `mode = "warn" | "enforce"`
  - `fail_threshold = 0..=100`
- `[scope]`
  - `mode = "staged" | "worktree" | "repo"`
  - `max_changed_files = <u32>` (default: `10000`)
  - `on_exceed = "fail_open" | "fail_closed"`
- `[cache]`
  - `enabled = true|false`
  - `db_path = ".patchgate/cache.db"`
- `[exclude]`
  - `globs = ["vendor/**", ...]` (`generated_code` とは別レイヤ)
- `[generated_code]`
  - `mode = "exclude" | "decay"`
  - `globs = ["**/generated/**", ...]`
  - `penalty_decay_percent = 0..=100`
- `[language_rules]`
  - `rust = true|false`
  - `typescript = true|false`
  - `python = true|false`
  - `go = true|false`
  - `java_kotlin = true|false` (`default: false`, opt-in)
- `[weights]`
  - `test_gap_max_penalty`
  - `dangerous_change_max_penalty`
  - `dependency_update_max_penalty`
- `[test_gap]`
  - `enabled`
  - `test_globs`
  - `production_ignore_globs`
  - `missing_tests_penalty`
  - `large_change_lines`
  - `large_change_penalty`
- `[dangerous_change]`
  - `enabled`
  - `patterns`
  - `critical_patterns`
  - `per_file_penalty`
  - `critical_bonus_penalty`
- `[dependency_update]`
  - `enabled`
  - `manifest_globs`
  - `lockfile_globs`
  - `manifest_penalty`
  - `lockfile_penalty`
  - `large_lockfile_churn`
  - `large_lockfile_penalty`
  - `lockfile_added_or_removed_penalty`
  - `lockfile_mass_update_lines`
  - `lockfile_mass_update_penalty`
  - `[dependency_update.ecosystem_penalties.<cargo|npm|python|go|jvm>]`
    - `manifest_bonus_penalty`
    - `lockfile_bonus_penalty`
    - `large_lockfile_bonus_penalty`

## Presets

- `strict`, `balanced`, `relaxed` を利用可能
- 参照ファイル: `config/presets/*.toml`
- 適用順は `default < preset < policy file < CLI override`

詳細例は `config/policy.toml.example` を参照してください。

## Validation error categories

`policy.toml` 読み込み時のエラーは、以下のカテゴリで返されます。

- `type`: enum値不正、glob構文不正、TOML型不正
- `range`: 値域不正（例: `large_change_lines <= 0`）
- `dependency`: 相互依存不整合（例: `critical_patterns` が `patterns` の部分集合でない）
