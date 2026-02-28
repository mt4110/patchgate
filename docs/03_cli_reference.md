# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`
環境情報と設定ファイル探索結果を表示します。

診断項目:

- `repo_root` / `config_path` / Rust version
- `git`: repository判定、HEAD、dirty file数
- `config`: 設定読込とバリデーション結果
- `cache`: DB存在確認と読み取り診断（副作用なし）

### `patchgate scan`
PR差分に対して品質ゲートを実行します。

Options:

- `--format <text|json>`
- `--scope <staged|worktree|repo>`
- `--mode <warn|enforce>`
- `--threshold <0..=100>`
- `--no-cache`
- `--github-comment <path>`
- `--github-publish`
- `--github-repo <owner/repo>`
- `--github-pr <number>`
- `--github-sha <sha>`
- `--github-token-env <env_name>` (default: `GITHUB_TOKEN`)
- `--github-check-name <name>`

Cache behavior:

- `cache.enabled=true` かつ `--no-cache` 未指定時に SQLite cache を使用
- cache DB 破損を検知した場合は、壊れたDBを `.corrupt-<timestamp>` に退避して再初期化
- 復旧に失敗した場合も scan 本体は継続（cacheなしの劣化運転）

## GitHub publish

`--github-publish` で以下を実行します。

- PRコメントを upsert (`<!-- patchgate:report -->` マーカー)
- Check Run を作成

### 部分成功時の挙動

- comment成功 / check失敗、またはその逆は「部分成功」として処理継続
- 両方失敗した場合のみ publish エラー（exit code `6`）
- 部分成功時は標準エラー出力に失敗理由を個別表示

### 入力解決の優先順

- `repo`: `--github-repo` > `GITHUB_REPOSITORY`
- `pr_number`: `--github-pr` > `GITHUB_EVENT_PATH` payload (`number`) > `GITHUB_REF`
- `head_sha`: `--github-sha` > `GITHUB_EVENT_PATH` payload (`pull_request.head.sha`) > `GITHUB_SHA`
- `token`: `--github-token-env`（未指定時 `GITHUB_TOKEN`）で環境変数を解決

GitHub Actionsの `pull_request` では通常、`GITHUB_REPOSITORY` / `GITHUB_SHA` / `GITHUB_EVENT_PATH` から自動解決されます。

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

- `id` (required): ルールID（例: `TG-001`）
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

### Compatibility policy (Phase1-20)

- Additive:
  - 新規キー追加は許可（既存キーの必須化はしない）
  - enum値追加は許可（既存値の意味は不変）
- Deprecation:
  - 非推奨化は docs で明示し、最低2つのマイナーリリースは互換維持
- Breaking:
  - 既存キーの削除/改名/型変更、既存enum意味変更はメジャー更新時のみ許可

## Exit code

- `0`: 成功（`warn` での実行、または `enforce` で gate pass）
- `1`: gate fail（`enforce` で `score < fail_threshold`）
- `2`: 入力エラー（`scan` の不正オプション値）
- `3`: 設定エラー（設定ファイル読み込み/設定値不正）
- `4`: 実行エラー（差分収集・評価・キャッシュ処理）
- `5`: 出力エラー（JSON/レポート書き込み）
- `6`: GitHub publish エラー（publish入力解決・API実行）
