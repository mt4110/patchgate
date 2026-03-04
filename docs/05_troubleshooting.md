# 05 Troubleshooting

## Common errors

### `PG-IN-001` (入力不正)

- `--scope` / `--mode` / `--format` / `--ci-provider` / `--notify-target` の値不正
- 許可値は `docs/03_cli_reference.md` を参照

### `PG-CFG-001` / `PG-GOV-001`

- policy読み込み失敗
- waiver期限切れ
- `patchgate policy lint --path <policy>` で診断

### `PG-GIT-001`

- Git管理外ディレクトリ / 壊れたworktree
- `patchgate doctor` と `--scope worktree` で再試行

### `PG-RT-001`

- 実行時エラー、cache破損、plugin fail_closed失敗
- `patchgate scan --no-cache`
- pluginは `fail_mode = "fail_open"` で切り分け可能

### `PG-PUB-SSO-001` / `PG-PUB-ORG-001`

- GitHub SSO未承認
- organization policy制約
- token権限確認、必要なら GitHub App tokenへ切替

### `PG-PUB-WEB-001`

- webhook URL 到達不可
- 署名secret未設定 (`--webhook-secret-env`)
- タイムアウト値 (`--webhook-timeout-ms`) を調整

### `PG-NOT-001`

- Slack/Teams URL不正
- 通知先が非200返却
- `--notify-retry-max-attempts` / `--notify-retry-backoff-ms` を調整

## Operational diagnostics

- metrics: `--metrics-output artifacts/scan-metrics.jsonl`
- audit: `--audit-log-output artifacts/scan-audit.jsonl`
- summary: `patchgate history summary --input ...`
- trend: `patchgate history trend --input ...`
- slo: `cargo run -p xtask -- ops slo-report ...`

## Recovery drill

- `.github/workflows/recovery-drill.yml` を定期実行
- 追加で `.github/workflows/ga-readiness.yml` をGA直前に実行
