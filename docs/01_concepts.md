# 01 Concepts

`patchgate` は PR差分を対象に、3つのチェック結果を単一スコアへ集約する品質ゲートです。

## Core concepts

- Diff-first: リポジトリ全体ではなく、`staged/worktree/repo` の差分を評価対象とする
- Multi-check scoring: `test_gap` / `dangerous_change` / `dependency_update` を減点合算
- Gate mode:
  - `warn`: 結果を返すのみ（exit code `0`）
  - `enforce`: `score < threshold` で失敗（exit code `1`）
- Review priority: スコア帯を `P0..P3` にマップしてレビュー優先度を固定

## JSON output contract

`scan --format json` は運用連携用の契約出力です。主要キー:

- Gate state: `score`, `threshold`, `should_fail`, `review_priority`
- Execution state: `mode`, `scope`, `fingerprint`, `duration_ms`, `skipped_by_cache`
- Details: `checks[]`, `findings[]`

## Compatibility policy (Phase1-20)

- 後方互換優先: 既存 CLI 引数と JSON キーの破壊的変更を避ける
- 変更許容（Additive）:
  - 追記（新規キー・新規タグ・新規 finding id）
  - 文言改善（`title` / `message`）
  - enum値追加（既存値の意味を維持）
- 非推奨（Deprecation）:
  - docs で明示し、最低2マイナーリリースは既存仕様を維持
- 破壊変更（Breaking）:
  - キー削除/改名
  - 既存キーの型変更
  - 既存 enum 値の意味変更
  - これらはメジャー更新時のみ許可

## Operational model

- ローカル/CIで同じ判定ロジックを実行
- SQLite cacheで同一差分の再評価を回避
- 必要時のみ GitHub publish（PRコメント/Check Run）を実行
