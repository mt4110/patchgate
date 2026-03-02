# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`
環境情報と設定ファイル探索結果を表示します。

診断項目:

- `repo_root` / `config_path` / Rust version
- `git`: repository判定、HEAD、dirty file数
- `config`: 設定読込とバリデーション結果
- `policy_version`: 実際に適用された version
- `cache`: DB存在確認と読み取り診断（副作用なし）

### `patchgate scan`
PR差分に対して品質ゲートを実行します。

Policy options:

- `--policy-preset <strict|balanced|relaxed>`

Core options:

- `--format <text|json>`
- `--scope <staged|worktree|repo>`
- `--mode <warn|enforce>`
- `--threshold <0..=100>`
- `--no-cache`

GitHub publish options:

- `--github-comment <path>`
- `--github-publish`
- `--github-repo <owner/repo>`
- `--github-pr <number>`
- `--github-sha <sha>`
- `--github-check-name <name>`
- `--github-auth <token|app>`
- `--github-token-env <env_name>` (default: `GITHUB_TOKEN`)
- `--github-app-token-env <env_name>` (default: `GITHUB_APP_INSTALLATION_TOKEN`)
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

Policy load order:

- `default < preset < policy file < CLI override`

Cache behavior:

- `cache.enabled=true` かつ `--no-cache` 未指定時に SQLite cache を使用
- cache DB 破損を検知した場合は、同一ディレクトリ内で `cache.db` を `cache.db.corrupt-<millis>-<pid>` にリネームして退避し、DBを再初期化
- 復旧に失敗した場合も scan 本体は継続（cacheなしの劣化運転）

### `patchgate policy lint`
policy を読み込み、型/範囲/依存関係と version 互換性を検査します。

Options:

- `--path <file>` (default: auto-discover `policy.toml`)
- `--policy-preset <strict|balanced|relaxed>`
- `--require-current-version` (`policy_version` が current でない場合をエラー化)

### `patchgate policy migrate`
policy version 移行の雛形コマンドです。

Options:

- `--from <version>`
- `--to <version>`
- `--path <file>` (default: auto-discover `policy.toml`)
- `--write`（未指定時は dry-run で migrated TOML を stdout 出力）

現在の実装では `v1 -> v2` をサポートします。

## GitHub publish

`--github-publish` で以下を実行します。

- PRコメントを upsert (`<!-- patchgate:report -->` マーカー)
- Check Run を idempotent update/create
- （opt-in）`review_priority` 対応ラベルを付与

### Check Run conclusion mapping

| mode | should_fail | findings | conclusion |
|---|---:|---|---|
| enforce | true | any | failure |
| any | false | none | success |
| warn | false | criticalあり | action_required |
| any | false | high/criticalあり | neutral |
| enforce | false | low/mediumのみ | success |
| warn | false | low/mediumのみ | neutral |

### Retry/backoff and degraded operation

- 一時障害（timeout/connect/5xx/429）に対して retry/backoff を実行
- rate limit 検知時は `degraded_mode` を出力し、残り経路（comment-only / check-only）を継続
- comment/check の両方が失敗した場合のみ publish エラー

### Auth abstraction

- `token` モード: PAT/GITHUB_TOKEN を使用
- `app` モード: GitHub App installation token を使用（`--github-app-token-env`）

### Dry-run

`--github-dry-run` 指定時は GitHub API を呼ばず、送信予定 payload を生成します。

- 標準エラーに JSON 表示
- `--github-dry-run-output` でファイル保存

## Score

- 100 から各チェックの penalty を減算
- `score < fail_threshold` で fail 判定
- 優先度は以下にマップ
  - `0..40`: `P0`
  - `41..65`: `P1`
  - `66..85`: `P2`
  - `86..100`: `P3`
- 表記:
  - text出力/Markdownでは `P0..P3`
  - JSON (`review_priority`) では `p0..p3`

## JSON contract (`scan --format json`)

トップレベルキー:

- `findings` (required): finding配列
- `checks` (required): チェック別スコア配列
- `score` (required): 0..100
- `threshold` (required): fail閾値
- `should_fail` (required): gate fail判定
- `mode` (required): `warn` | `enforce`
- `scope` (required): `staged` | `worktree` | `repo`
- `review_priority` (required): `p0` | `p1` | `p2` | `p3`
- `fingerprint` (required): diff fingerprint
- `duration_ms` (required): 評価時間
- `skipped_by_cache` (required): cache hit時 `true`

`finding` 要素:

- `id` (required): finding識別子
- `rule_id` (required): ルールID（例: `TG-001`）
- `category` (required): ルールカテゴリ
- `docs_url` (required): ルール説明URL
- `check` (required): `test_gap` | `dangerous_change` | `dependency_update`
- `title` (required): 短い要約
- `message` (required): 詳細説明
- `severity` (required): `low` | `medium` | `high` | `critical`
- `penalty` (required): スコア減点値
- `location` (optional): `{ file, line }`。位置がない場合は `null`
- `tags` (required): 分類タグ配列

`check` 要素:

- `check` (required): check id
- `label` (required): 表示ラベル
- `penalty` (required): 実減点
- `max_penalty` (required): 上限減点
- `triggered` (required): 該当有無

## Exit code

### `scan`

- `0`: 成功（`warn` での実行、または `enforce` で gate pass）
- `1`: gate fail（`enforce` で `score < fail_threshold`）
- `2`: 入力エラー（`scan` の不正オプション値）
- `3`: 設定エラー（設定ファイル読み込み/設定値不正）
- `4`: 実行エラー（差分収集・評価・キャッシュ処理）
- `5`: 出力エラー（JSON/レポート書き込み）
- `6`: GitHub publish エラー（publish入力解決・API実行）

### `policy lint / migrate`

- `0`: 成功
- `10`: policy read/parse error
- `11`: policy validation type error
- `12`: policy validation range error
- `13`: policy validation dependency error
- `14`: current version requirement violation (`policy lint --require-current-version`)
- `15`: migration failure（未対応パス、version不一致、移行後validation失敗）
- `16`: I/O failure（migrated policy書き込み失敗など）
