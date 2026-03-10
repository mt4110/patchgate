# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`

環境情報と設定読込診断を表示します。

### `patchgate scan`

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
- `--metrics-output <path>`
- `--audit-log-output <path>`
- `--audit-actor <name>`

GitHub publish options:

- `--github-comment <path>`
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

Provider/Webhook/Notification options:

- `--publish`
- `--ci-provider <github|generic>`
- `--ci-generic-output <path>` (`--publish` かつ `ci-provider=generic` の場合は必須)
- `--webhook-url <https://...>` (repeatable)
- `--webhook-secret-env <env_name>`
- `--webhook-timeout-ms <ms>`
- `--webhook-retry-max-attempts <n>`
- `--notify-target <kind=url>` (kind: `slack|teams|generic`)
- `--notify-retry-max-attempts <n>`
- `--notify-retry-backoff-ms <ms>`
- `--notify-timeout-ms <ms>`
- `--dead-letter-output <path>` (配信失敗ペイロードをJSONL保存)

### `patchgate history summary`

- `--input <metrics.jsonl>`
- `--baseline <metrics.jsonl>`
- `--format <text|json>`

### `patchgate history trend`

- `--input <metrics.jsonl>`
- `--format <text|json>`

### `patchgate delivery replay`

- `--input <dead-letter.jsonl>`
- `--transport <webhook|notification>`
- `--max-records <n>`
- `--retry-max-attempts <n>`
- `--retry-backoff-ms <ms>`
- `--dry-run`

### `patchgate policy lint`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--require-current-version`

### `patchgate policy migrate`

- `--from <version>`
- `--to <version>`
- `--path <file>`
- `--write`

### `patchgate policy verify-v1`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--format <text|json>`
- `--readiness-profile <standard|strict|lts>`
- v1 RC/GA前提の移行準備状態を検証

### `patchgate plugin init`

- `--lang <python|node|rust>`
- `--plugin-id <id>`
- `--output <path>`
- `--force`
- `patchgate.plugin.v1` 準拠の最小pluginテンプレートを生成

## JSON contract (`scan --format json`)

主要キー:

- `score`, `threshold`, `should_fail`, `review_priority`
- `mode`, `scope`, `fingerprint`, `duration_ms`, `skipped_by_cache`
- `changed_files`, `check_durations_ms`
- `diagnostic_hints`
- `supply_chain_signals`
- `plugin_invocations`
- `checks[]`, `findings[]`

## Metrics/Audit JSONL

- Metrics (`schema_version=1`): repo/mode/scope/duration/score/failure code
- Audit (`patchgate.audit.v1`): actor/target/result/failure code

## Failure codes

- `PG-IN-001`, `PG-CFG-001`, `PG-GIT-001`, `PG-RT-001`, `PG-OUT-001`
- `PG-PUB-001`, `PG-PUB-002`, `PG-PUB-SSO-001`, `PG-PUB-ORG-001`
- `PG-PUB-WEB-001`, `PG-NOT-001`, `PG-GOV-001`

## Exit code

`scan`:

- `0`: success
- `1`: gate fail (enforce)
- `2`: input error
- `3`: config error
- `4`: runtime error
- `5`: output error
- `6`: publish/integration error

`policy lint/migrate/verify-v1`:

- `0`: success
- `10`: read/parse error
- `11`: validation type
- `12`: validation range
- `13`: validation dependency
- `14`: migration required / not ready
- `15`: migration failure
- `16`: I/O failure
