# 01 Concepts

`patchgate` は PR差分を対象に、3つのチェック結果を単一スコアへ集約する品質ゲートです。

## Core concepts

- Diff-first: リポジトリ全体ではなく、`staged/worktree/repo` の差分を評価対象とする
- Multi-check scoring: `test_gap` / `dangerous_change` / `dependency_update` を減点合算
- Gate mode:
  - `warn`: 結果を返すのみ（exit code `0`）
  - `enforce`: `score < threshold` で失敗（exit code `1`）
- Review priority: スコア帯を `P0..P3` にマップしてレビュー優先度を固定
- Scale guardrail: `scope.max_changed_files` 超過時は `fail_open|fail_closed` で挙動を固定
- Profiling: `scan --profile-output` で diff/check/cache/publish の時間内訳を機械可読出力

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

## GitHub publish model (Phase31-40)

- Idempotent: check-run/comment は update/create の upsert で再実行時の重複を抑制
- Resilient: 一時障害（timeout/connect/5xx/429）は retry/backoff で吸収
- Degraded operation: rate limit 時は `comment_only` / `check_only` の劣化運転を許容
- Dry-run first: 本番 publish 前に payload を確認できる
- Noise control: no-change / low-priority / rerun 条件でコメント抑制が可能

## JSON output contract

`scan --format json` は運用連携用の契約出力です。主要キー:

- Gate state: `score`, `threshold`, `should_fail`, `review_priority`
- Execution state: `mode`, `scope`, `fingerprint`, `duration_ms`, `skipped_by_cache`
- Details: `checks[]`, `findings[]`

## Operational model

- ローカル/CIで同じ判定ロジックを実行
- SQLite cacheで同一差分の再評価を回避
- 必要時のみ GitHub publish（PRコメント/Check Run）を実行

## Language-aware test gap (Phase51-60)

- Rust/TypeScript/Python/Go は既定で有効、Java/Kotlin は `language_rules.java_kotlin=true` で opt-in
- `test_gap` は `test_globs` に加え、言語別ヒューリスティクス（例: Rust `mod tests`, TS `vitest/jest`, Python `pytest/unittest` 命名）を使う
- モノレポでは package 境界を推定し、変更 package と無関係な test 更新で penalty を打ち消さない

## Dependency severity expansion (Phase56-57)

- 依存差分は base penalty に加えて ecosystem 別 bonus (`cargo/npm/python/go/jvm`) を加算
- lockfile 追加/削除 (`DU-004`) と mass update (`DU-005`) を別 finding として扱う
- severity は churn 量だけでなく変更タイプを反映する

## Performance SLO (Phase49)

- 主要ケースの `scan` 実行時間 P95 を release criterion として扱う
- 基本ケース: `ci-worktree` baseline 比較 (`xtask bench compare`)
- 大規模ケース: `ci-scale-10k` synthetic diff（別 workflow で再現）
