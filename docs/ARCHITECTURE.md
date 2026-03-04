# Architecture

## Overview

`patchgate` は差分ベース品質ゲートです。

- `patchgate-core`
  - Git差分収集
  - built-in checks (`test_gap`, `dangerous_change`, `dependency_update`)
  - external plugin実行 (`patchgate.plugin.v1`)
  - スコアリング (0-100) とレビュー優先度判定
- `patchgate-config`
  - `policy.toml` 読み込み / バリデーション / migration
  - plugin/integration/release/compat 設定
- `patchgate-github`
  - PR comment/check-run publish
- `patchgate-cli`
  - `scan` / `doctor` / `history` / `policy`
  - provider抽象 (`github|generic`)
  - webhook / notification
  - SQLite cache
- `xtask`
  - benchmark
  - weekly ops / audit / slo / ga readiness report

## Data flow

1. CLI が policy を解決してロード
2. core が `DiffData` を生成
3. cache hit判定
4. built-in checks + plugin checks 実行
5. report を text/json + markdown に整形
6. provider publish / webhook / notifications を送信
7. metrics/audit を記録

## Plugin execution boundary

- Input: `PluginInput` JSON (stdin)
- Output: `PluginOutput` JSON (stdout)
- timeout/max stdout/fail mode は policy 管理
- `restricted` sandbox は env allowlist 方式

## CI provider boundary

- `github`: API publish (comment/check-run/label)
- `generic`: JSON artifact publish
- provider差分は CLI アダプタ層に閉じ込める

## LTS/GA automation

- LTS backport gate: `.github/workflows/lts-backport.yml`
- GA readiness: `.github/workflows/ga-readiness.yml`
- GA artifact build: `.github/workflows/release-ga.yml`
