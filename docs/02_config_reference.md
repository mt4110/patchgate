# 02 Config Reference

`policy.toml` で patchgate の挙動を調整します。

## 主要セクション

- `[output]`
  - `format = "text" | "json"`
  - `mode = "warn" | "enforce"`
  - `fail_threshold = 0..=100`
- `[scope]`
  - `mode = "staged" | "worktree" | "repo"`
- `[cache]`
  - `enabled = true|false`
  - `db_path = ".patchgate/cache.db"`
- `[exclude]`
  - `globs = ["vendor/**", ...]`
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

詳細例は `config/policy.toml.example` を参照してください。
