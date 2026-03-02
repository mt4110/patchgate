# 01 Concepts

`patchgate` は PR差分を対象に、3つのチェック結果を単一スコアへ集約する品質ゲートです。

## Core concepts

- Diff-first: リポジトリ全体ではなく、`staged/worktree/repo` の差分を評価対象とする
- Multi-check scoring: `test_gap` / `dangerous_change` / `dependency_update` を減点合算
- Gate mode:
  - `warn`: 結果を返すのみ（exit code `0`）
  - `enforce`: `score < threshold` で失敗（exit code `1`）
- Review priority: スコア帯を `P0..P3` にマップしてレビュー優先度を固定

## Policy versioning (Phase21-30)

- `policy_version` は policy schema 互換性の契約値
- 2026-03-02 時点の current version は `2`
- `policy_version` が未指定の既存 policy は互換維持のため `v1` として解釈
- `v1` の読み込み時は `policy migrate` を案内する warning を出力

### Compatibility matrix

| CLI version | policy v1 | policy v2 |
|---|---|---|
| `0.2.x` | Read OK (legacy warning) | Read OK |

非互換を導入する場合は、先に `policy migrate` を提供してから read path を更新します。

## Preset and override order

設定適用順は固定です。

`default < preset < policy file < CLI override`

この順序により、同一入力から同一判定を再現できます。

## Machine-readable findings

`findings[]` は運用連携向けに以下を含みます。

- `id`: finding識別子（後方互換維持）
- `rule_id`: ルール識別子
- `category`: ルールカテゴリ（例: `test_coverage`, `change_risk`, `dependency`）
- `docs_url`: 参照ドキュメントURL

## JSON output contract

`scan --format json` は運用連携用の契約出力です。主要キー:

- Gate state: `score`, `threshold`, `should_fail`, `review_priority`
- Execution state: `mode`, `scope`, `fingerprint`, `duration_ms`, `skipped_by_cache`
- Details: `checks[]`, `findings[]`

## Operational model

- ローカル/CIで同じ判定ロジックを実行
- SQLite cacheで同一差分の再評価を回避
- 必要時のみ GitHub publish（PRコメント/Check Run）を実行
