# 01 Concepts

`patchgate` は PR差分を対象に、複数チェックを単一スコアへ集約する品質ゲートです。

## Core concepts

- Diff-first: リポジトリ全体ではなく `staged/worktree/repo` の差分を評価
- Multi-check scoring: `test_gap` / `dangerous_change` / `dependency_update` の減点合算
- Gate mode:
  - `warn`: 判定結果のみ返す（exit code `0`）
  - `enforce`: `score < threshold` で失敗（exit code `1`）
- Review priority: スコア帯を `P0..P3` に固定マップ
- Scale guardrail: `scope.max_changed_files` と `on_exceed` で大規模差分の挙動を固定

## Observability model (Phase61-70)

- Scan metrics JSONL: `--metrics-output` で scan実行の時系列メトリクスを記録
- Audit log JSONL: `--audit-log-output` で actor/target/result/failure code を記録
- History aggregation:
  - `patchgate history summary --input <metrics.jsonl>`
  - `patchgate history trend --input <metrics.jsonl>`
- Alert thresholds: `policy.toml` の `[alerts]` で score低下/失敗率増加/処理時間悪化を基準化

## Failure taxonomy (Phase62/70/74)

機械可読コードで失敗分類を返します（例）。

- `PG-IN-001`: 入力オプション不正
- `PG-CFG-001`: 設定読み込み失敗
- `PG-GIT-001`: Git差分収集失敗
- `PG-RT-001`: 評価実行失敗
- `PG-PUB-001/002`: publish入力/API失敗
- `PG-PUB-SSO-001`: SSO未承認
- `PG-PUB-ORG-001`: Org policy制約
- `PG-GOV-001`: waiver期限切れ

失敗時は標準エラーに次アクションヒントを併記します。

## Audit contract (Phase63/73)

- `audit_format = patchgate.audit.v1`
- 監査レコードには以下を含む:
  - 実行主体 (`actor`)
  - 対象 (`target=scan`)
  - 判定結果 (`pass/gate_fail/error`)
  - 失敗分類 (`failure_code`, `failure_category`)
- schema互換方針:
  - 既存キーは削除しない
  - 新規キーは optional 追加
  - `audit_schema_version` で互換境界を明示

## Security and governance (Phase71-80)

- Least privilege token:
  - 既定は最小権限トークン前提
  - workflowでは `permissions: write-all` を禁止
- Secret masking:
  - `ghp_`, `github_pat_`, `Bearer ...` などのトークン形状をログ出力時にマスク
- Waiver management:
  - `[waiver].entries[]` は `check_id/reason/approver/expires_at` 必須
  - `expires_at` は RFC3339 かつ未来日時のみ許可

## Supply-chain supplemental signals (Phase79)

`Report.supply_chain_signals` は依存更新と危険ファイル変更を横断して補助シグナルを出力します。

- `SCM-001`: dependency + CI/infra 変更の同時発生
- `SCM-002`: lockfile追加/削除 + workflow変更の同時発生

## Operational automation

- 週次サマリ: `.github/workflows/weekly-ops-summary.yml`
- 復旧演習: `.github/workflows/recovery-drill.yml`
- 監査/承認統制: `.github/workflows/policy-governance.yml` + `.github/CODEOWNERS`
- セキュリティ定例: `.github/workflows/security-review.yml`
