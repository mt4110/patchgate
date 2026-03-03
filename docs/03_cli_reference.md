# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`

環境情報と設定読込診断を表示します。

### `patchgate scan`

PR差分に対して品質ゲートを実行します。

Core options:

- `--policy-preset <strict|balanced|relaxed>`
- `--format <text|json>`
- `--scope <staged|worktree|repo>`
- `--mode <warn|enforce>`
- `--threshold <0..=100>`
- `--max-changed-files <u32>`
- `--on-exceed <fail_open|fail_closed>`
- `--no-cache`
- `--profile-output <path>`
- `--metrics-output <path>` (JSONL追記)
- `--audit-log-output <path>` (JSONL追記)
- `--audit-actor <name>`

GitHub publish options:

- `--github-publish`
- `--github-repo <owner/repo>`
- `--github-pr <number>`
- `--github-sha <sha>`
- `--github-auth <token|app>`
- `--github-token-env <env_name>`
- `--github-app-token-env <env_name>`
- `--github-check-name <name>`
- `--github-retry-max-attempts <n>`
- `--github-retry-backoff-ms <ms>`
- `--github-retry-max-backoff-ms <ms>`
- `--github-dry-run`
- `--github-dry-run-output <path>`
- `--github-no-comment`
- `--github-no-check-run`
- `--github-apply-labels`
- `--github-suppress-comment-no-change`
- `--github-suppress-comment-low-priority`
- `--github-suppress-comment-rerun`

### `patchgate history summary`

メトリクスJSONLを集計します。

- `--input <metrics.jsonl>`
- `--baseline <metrics.jsonl>`（任意、アラート比較用）
- `--format <text|json>`

### `patchgate history trend`

メトリクスJSONLを repo/scope/check 単位で集計します。

- `--input <metrics.jsonl>`
- `--format <text|json>`

### `patchgate policy lint`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--require-current-version`

### `patchgate policy migrate`

- `--from <version>`
- `--to <version>`
- `--path <file>`
- `--write`

## JSON contract (`scan --format json`)

主要キー:

- `score`, `threshold`, `should_fail`, `review_priority`
- `mode`, `scope`, `fingerprint`, `duration_ms`, `skipped_by_cache`
- `changed_files`, `check_durations_ms`
- `diagnostic_hints`
- `supply_chain_signals`
- `checks[]`, `findings[]`

`supply_chain_signals[]` 要素:

- `id`
- `title`
- `severity`
- `message`
- `related_files`
- `tags`

## Metrics/Audit JSONL contract

Metrics record (`schema_version=1`) 主要キー:

- `unix_ts`, `repo`, `mode`, `scope`
- `duration_ms`, `changed_files`, `skipped_by_cache`
- `score`, `threshold`, `should_fail`
- `check_penalties`
- `failure_code`, `failure_category`
- `diagnostic_hints`

Audit record (`audit_format=patchgate.audit.v1`) 主要キー:

- `schema_version`, `audit_format`, `unix_ts`
- `actor`, `repo`, `target`
- `mode`, `scope`, `result`
- `failure_code`, `failure_category`
- `score`, `threshold`, `changed_files`

## Failure code examples

- `PG-IN-001` 入力不正
- `PG-CFG-001` 設定読み込み失敗
- `PG-GIT-001` Git差分収集失敗
- `PG-RT-001` 評価実行失敗
- `PG-OUT-001` 出力失敗
- `PG-PUB-001/002` publish失敗
- `PG-PUB-SSO-001` SSO未承認
- `PG-PUB-ORG-001` Org policy制約
- `PG-GOV-001` waiver期限切れ

## Exit code

`scan`:

- `0`: 成功（warn実行、または enforce pass）
- `1`: gate fail（enforceで`score < threshold`）
- `2`: 入力エラー
- `3`: 設定エラー
- `4`: 実行エラー
- `5`: 出力エラー
- `6`: publishエラー

`policy lint/migrate`:

- `0`: 成功
- `10`: read/parse error
- `11`: validation type
- `12`: validation range
- `13`: validation dependency
- `14`: current version requirement violation
- `15`: migration failure
- `16`: I/O failure
