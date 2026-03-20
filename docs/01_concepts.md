# 01 Concepts

`patchgate` は PR差分を対象に、複数チェックを単一スコアへ集約する品質ゲートです。

## Core concepts

- Diff-first: リポジトリ全体ではなく `staged/worktree/repo` の差分を評価
- Multi-check scoring: `test_gap` / `dangerous_change` / `dependency_update` / `external_plugin` の減点合算
- Gate mode:
  - `warn`: 判定結果のみ返す（exit code `0`）
  - `enforce`: `score < threshold` で失敗（exit code `1`）
- Review priority: スコア帯を `P0..P3` に固定マップ
- Scale guardrail: `scope.max_changed_files` と `on_exceed` で大規模差分挙動を固定

## Plugin contract (Phase81-83)

- API version: `patchgate.plugin.v1`
- 入力: `PluginInput`（repo/scope/mode/changed_files）を `stdin` JSON で受け取る
- 出力: `PluginOutput`（`findings[]`, `diagnostics[]`）を `stdout` JSON で返す
- 実行結果は `Report.plugin_invocations[]` に保存
- sandbox制約:
  - `plugins.sandbox.profile = restricted` で最小環境変数のみ許可
  - `plugins.sandbox.profile = isolated` で Linux `bwrap` によるOS隔離実行
  - `timeout_ms` と `max_stdout_kib` を強制
  - `fail_mode = fail_open|fail_closed`
  - `plugins.signature.required = true` の場合、plugin実行前にed25519署名を検証
  - `patchgate doctor` / `policy verify-v1` で host OS ごとの capability を確認可能

## Provider / Integration contract (Phase85-87)

- CI provider abstraction:
  - `github`: check-run/comment publish
  - `generic`: 標準JSONペイロード出力
  - GitLab / Jenkins など GitHub 外CIは generic payload template で接続する
- Webhook:
  - `scan.completed` イベントを JSON 送信
  - 署名ヘッダ `X-Patchgate-Signature: sha256=...`
  - 冪等ヘッダ `X-Patchgate-Idempotency-Key` を付与
- Notification adapter:
  - `slack|teams|generic` の共通送信契約
  - retry/backoff で一時障害を吸収
  - 失敗payloadは dead-letter(JSONL) に退避可能

## Observability model (Phase61-70, 95)

- Scan metrics JSONL: `--metrics-output`
- Audit log JSONL: `--audit-log-output`
- History aggregation:
  - `patchgate history summary`
  - `patchgate history trend`
- SLO report:
  - `cargo run -p xtask -- ops slo-report`

## Failure taxonomy

- `PG-IN-001`: 入力オプション不正
- `PG-CFG-001`: 設定読み込み失敗
- `PG-GIT-001`: Git差分収集失敗
- `PG-RT-001`: 評価実行失敗
- `PG-PUB-001/002`: publish入力/API失敗
- `PG-PUB-SSO-001`: SSO未承認
- `PG-PUB-ORG-001`: Org policy制約
- `PG-PUB-WEB-001`: webhook送信失敗
- `PG-NOT-001`: 通知送信失敗
- `PG-GOV-001`: waiver期限切れ

## v1 compatibility boundary (Phase91-93)

- `patchgate policy verify-v1 --readiness-profile <standard|strict|lts>` で移行準備を検証
- v1 GA前提:
  - `policy_version = 2`
  - `compatibility.v1.rc_frozen = true`
  - `compatibility.v1.allow_legacy_config_names = false`
- 非推奨項目は段階的に縮退し、破壊変更は新バージョン契約で分離

## LTS and GA operation (Phase94-100)

- LTS:
  - `release.lts.branch`, `security_sla_hours`, `backport_labels`
  - `.github/workflows/lts-backport.yml`
- GA readiness:
  - `.github/workflows/ga-readiness.yml`
  - `cargo run -p xtask -- ops ga-readiness`
- Release artifacts:
  - `.github/workflows/release-ga.yml`
  - checksum + SBOM相当 + provenance metadata
