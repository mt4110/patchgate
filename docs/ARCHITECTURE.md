# Architecture

## Overview

`patchgate` は差分ベース品質ゲートです。

- `patchgate-core` (core)
  - Git差分収集
  - 3チェック実行 (`test_gap`, `dangerous_change`, `dependency_update`)
  - スコアリング (0-100) とレビュー優先度判定
- `patchgate-config`
  - `policy.toml` の読み込みとデフォルト
- `patchgate-github`
  - PRコメント upsert
  - Check Run publish
- `patchgate-cli`
  - `scan` / `doctor`
  - `warn|enforce` のexit code制御
  - JSON/Text出力
  - SQLiteキャッシュ
  - GitHub publish 呼び出し

## Data flow

1. CLI が `policy.toml` を読み込む
2. core が git diff から `DiffData` を生成
3. `cache_key` で SQLite cache を引く
4. miss なら 3チェックを実行し score を算出
5. text/json と GitHub comment markdown を出力
6. opt-in で GitHubに comment/check-run をpublish

## Cache key contract

`scan` の cache hit/miss は次のキーで固定する:

- schema version (`v1`)
- CLI version (`CARGO_PKG_VERSION`)
- diff fingerprint
- policy hash
- mode (`warn|enforce`)
- scope (`staged|worktree|repo`)

同一キーなら hit、いずれか1要素でも変われば miss とする。  
`--no-cache` または `cache.enabled=false` では常に miss 扱いで再評価する。

## Cost model

実行はローカル/CIで完結し、クラウドは履歴集計等のメタデータのみを想定。
