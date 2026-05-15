# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`

環境情報と設定読込診断を表示します。

主な診断項目:

- Git / config / cache の状態
- host OS
- plugin sandbox capability (`none` / `restricted` / `isolated`)
- CI template catalog (`github` / `gitlab` / `jenkins`)

### `patchgate scan`

Core options:

- `--policy-preset <strict|balanced|relaxed>`
- `--format <text|json>`
- `--scope <staged|worktree|repo|pr>`
- `--base-ref <ref>` / `--head-ref <ref>`: `--scope pr` compares `merge-base(base, head)...head`; `head` defaults to `HEAD`. In enforce mode, `--base-ref` is also used for trusted base policy resolution.
- `--mode <warn|enforce>`
- `--protected-policy-ref <ref>`
- `--org-policy-bundle <path>`
- `--org-policy-bundle-signature <path>`
- `--org-policy-public-key-env <env_name>`
- `--allow-untrusted-policy-for-local-enforce` (local escape hatch; do not use in CI templates)
- `--threshold <0..=100>`
- `--max-changed-files <u32>`
- `--on-exceed <fail_open|fail_closed>`
- `--no-cache`
- `--profile-output <path>`
- `--metrics-output <path>`
- `--audit-log-output <path>`
- `--audit-log-v2-output <path>`
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
- `--ci-generic-schema <v1|v2|dual>`
- `--webhook-url <https://...>` (repeatable)
- `--webhook-secret-env <env_name>`
- `--webhook-timeout-ms <ms>`
- `--webhook-retry-max-attempts <n>`
- `--notify-target <kind=url>` (kind: `slack|teams|generic`)
- `--notify-retry-max-attempts <n>`
- `--notify-retry-backoff-ms <ms>`
- `--notify-timeout-ms <ms>`
- `--dead-letter-output <path>` (配信失敗ペイロードをJSONL保存)

The recommended stable `--github-check-name` is `patchgate/trust-boundary`.
Configure branch protection to require that check name.
This is a trust-boundary check name, not the legacy `patchgate` default; update branch-protection rules before switching templates.
Enforce mode rejects policy-changing CLI overrides (`--threshold`, `--max-changed-files`, `--on-exceed`).

### `patchgate history summary`

- `--input <metrics.jsonl>`
- `--baseline <metrics.jsonl>`
- `--format <text|json>`

### `patchgate history trend`

- `--input <metrics.jsonl>`
- `--format <text|json>`

### `patchgate decision replay`

- `--input <decision-or-report.json>`
- `--format <text|json>`
- `patchgate.decision.v1` artifact, or a scan report containing `decision`, is replayed without rerunning diff checks.

### `patchgate delivery replay`

- `--input <dead-letter.jsonl>`
- `--transport <webhook|notification>`
- `--max-records <n>`
- `--retry-max-attempts <n>`
- `--retry-backoff-ms <ms>`
- `--rewrite-input` (成功したレコードを入力queueから除去)
- `--summary-output <path>` (replay結果のJSON summaryを書き出し)
- `--dry-run`

### `cargo run -p xtask -- ops siem-handoff`

- `--audit-v2-input <scan-audit-v2.jsonl>`
- `--output <siem-handoff.jsonl>`
- `patchgate.audit.v2` をSIEM ingest向けのflat JSONLへ正規化
- 入力が audit v2 contract 外の場合は失敗

### `patchgate policy lint`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--require-current-version`

### `patchgate policy resolve`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--mode <warn|enforce>`
- `--base-ref <ref>`
- `--head-ref <ref>` (read the PR overlay policy from this ref instead of the worktree)
- `--protected-policy-ref <ref>`
- `--org-policy-bundle <path>`
- `--org-policy-bundle-signature <path>`
- `--org-policy-public-key-env <env_name>`
- `--allow-untrusted-policy-for-local-enforce`
- `--format <text|json>`
- Prints the resolved policy digest, trusted sources, and accepted/rejected PR overlay keys.

### `patchgate policy diff`

- Uses the same authority options as `patchgate policy resolve`.
- Prints only the accepted/rejected PR overlay keys.

### `patchgate policy attest`

- `--bundle <org-policy-bundle.toml>`
- `--signature <org-policy-bundle.sig>`
- `--public-key-env <env_name>`
- `--format <text|json>`
- Verifies a signed org bundle with `schema_version = "patchgate.policy.bundle.v1"`.

### `patchgate policy verify-authority`

- Uses the same authority options as `patchgate policy resolve`.
- With `--mode enforce`, exits with migration-required when an untrusted policy, unverified bundle, or rejected PR overlay is present.

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
- `--autofix-output <path>` (safe autofix 済みpolicyを別ファイルへ出力)
- `--autofix-write` (safe autofix を入力policyへ上書き)
- v1 RC/GA前提の移行準備状態を検証
- safe autofix対象は `compatibility.v1.*`, `plugins.sandbox.profile`, `release.lts.*` の一部

### `patchgate policy verify-v2`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--format <text|json>`
- `--readiness-profile <standard|ga|lts>`
- `--provider-input <provider-dual-or-v2.json>` (repeatable)
- `--audit-input <scan-audit.jsonl>`
- `--audit-v2-input <scan-audit-v2.jsonl>`
- `--plugin-shadow-input <sample-input.v2.json>` (repeatable)
- `--webhook-envelope-input <webhook-shadow-envelope.json>` (repeatable)
- `--notification-envelope-input <notification-shadow-envelope.json>` (repeatable)
- `--bundle-catalog-input <bundle-catalog.json>`
- `--registry-input <plugin-registry.json>`
- `--exceptions-input <exceptions.json>`
- v2 shadow / bridge の準備状態を検証
- 主に `compatibility.v2.*`, `integrations.ci.generic_schema`, `observability.audit_v2_*` を確認
- `--readiness-profile ga|lts` は `release.lts.active=true`, `release.lts.branch="lts/v2"`, `security_sla_hours <= 72` も確認
- artifact input を渡した場合は provider dual/v2、audit dual-write、plugin v2 shadow envelope、webhook / notification bridge envelope の実体も確認
- fleet artifact input を渡した場合は bundle catalog、registry provenance、org exception governance の実体も確認

### `patchgate policy diff-contract`

- `--path <file>`
- `--policy-preset <strict|balanced|relaxed>`
- `--format <text|json>`
- `--enforce`
- v1 contract と v2 bridge contract の差分を要約
- `--enforce` は `breaking_change_gate_ready=false` のとき migration-required exit で止める

### `cargo run -p xtask -- ops migration-completion`

- `--metrics-input <scan-metrics.jsonl>`
- `--audit-input <scan-audit.jsonl>`
- `--audit-v2-input <scan-audit-v2.jsonl>`
- `--provider-input <provider-dual-or-v2.json>` (repeatable)
- `--fleet-review-input <fleet-review.md>`
- `--rc-readiness-input <v2-rc-readiness.md>`
- `--migration-drill-input <migration-drill.json>`
- `--migration-guide-path <docs/16_v2_migration_guide_alpha.md>`
- `--candidate-checklist-path <docs/18_v2_candidate_release_checklist.md>`
- `--output <ecosystem-migration-completion.md>`
- provider bridge / audit v2 parity / fleet governance / RC readiness を repo board として固定

### `cargo run -p xtask -- ops dual-run-decommission`

- `--audit-input <scan-audit.jsonl>`
- `--audit-v2-input <scan-audit-v2.jsonl>`
- `--replay-summary-input <dead-letter-rewrite-summary.json>`
- `--provider-input <provider-dual-or-v2.json>` (repeatable)
- `--rollback-packet-input <rollback-packet.json>`
- `--migration-drill-input <migration-drill.json>`
- `--rc-readiness-input <v2-rc-readiness.md>`
- `--sunset-notice-path <docs/21_v1_sunset_notice.md>`
- `--support-model-path <docs/22_v2_support_model.md>`
- `--output <dual-run-decommission.md>`
- dual-run停止前に rollback restore / replay recovery / sunset compatibility / support model を確認

### `cargo run -p xtask -- ops post-ga-telemetry`

- `--metrics-input <scan-metrics.jsonl>`
- `--audit-input <scan-audit.jsonl>`
- `--audit-v2-input <scan-audit-v2.jsonl>`
- `--replay-summary-input <dead-letter-rewrite-summary.json>`
- `--fleet-review-input <fleet-review.md>`
- `--ga-packet-input <v2-ga-packet.md>`
- `--support-model-path <docs/22_v2_support_model.md>`
- `--output <post-ga-telemetry-review.md>`
- GA後の SLO / audit parity / replay recovery / escalation signal をまとめる

### `cargo run -p xtask -- ops retrospective-cleanup`

- `--migration-completion-input <ecosystem-migration-completion.md>`
- `--dual-run-decommission-input <dual-run-decommission.md>`
- `--post-ga-telemetry-input <post-ga-telemetry-review.md>`
- `--ops-handbook-path <docs/19_v2_ops_handbook.md>`
- `--support-model-path <docs/22_v2_support_model.md>`
- `--sunset-notice-path <docs/21_v1_sunset_notice.md>`
- `--phase201-backcast-path <docs/20_phase201_plus_backcast.md>`
- `--output <retrospective-cleanup-queue.md>`
- GA/LTS handoff 後に残す fixture と削除候補を cleanup queue として固定

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
- Audit v2 (`patchgate.audit.v2`): operation/gate/failure/diagnostics を構造化出力
- SIEM handoff (`schema_version=1`): audit v2 を event_kind/source_format/source_schema_version/severity/failure_code つきのflat JSONLへ変換

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
