# 05 Troubleshooting

## Common errors

### `PG-IN-001` (入力不正)

原因:

- `--scope` / `--mode` / `--format` などの値が不正

対処:

- `docs/03_cli_reference.md` の許可値へ修正

### `PG-CFG-001` / `PG-GOV-001` (設定・waiver)

原因:

- policy 読み込み失敗
- `waiver.entries[].expires_at` が期限切れ

対処:

- `patchgate policy lint --path <policy>`
- 期限切れwaiverを更新または削除

### `PG-GIT-001` (Git差分収集失敗)

原因:

- Git管理外ディレクトリ
- 壊れたworktree/権限不備

対処:

- `patchgate doctor` で git診断
- `--scope worktree` で再試行

### `PG-RT-001` (評価実行失敗)

原因:

- 評価途中エラー、cache破損、実行環境不整合

対処:

- `patchgate scan --no-cache` で再試行
- cache再生成（`doctor` で確認）

### `PG-PUB-SSO-001` / `PG-PUB-ORG-001`

原因:

- SSO未承認
- organization policy により comment/check/label 操作が禁止

対処:

- トークンのSSO承認を実施
- GitHub App token へ切替
- Org policy で必要権限（checks/issues/pull_requests）を確認

### publishログの秘匿情報漏えい懸念

症状:

- APIエラーメッセージにtoken類似文字列が含まれる

対処:

- patchgateは `ghp_` / `github_pat_` / `Bearer ...` を自動マスク
- 追加で `--github-dry-run` を使いpayloadのみ検証

## Operational diagnostics

- metrics: `--metrics-output artifacts/scan-metrics.jsonl`
- audit: `--audit-log-output artifacts/scan-audit.jsonl`
- summary: `patchgate history summary --input ...`
- trend: `patchgate history trend --input ...`

## Recovery drill

- `.github/workflows/recovery-drill.yml` で定期演習
- 想定シナリオ:
  - 不正CLI入力
  - publish入力不足
  - 期限切れwaiver
