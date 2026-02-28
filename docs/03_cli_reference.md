# 03 CLI Reference

`patchgate` は差分ベースで品質リスクを判定するCLIです。

## Commands

### `patchgate doctor`
環境情報と設定ファイル探索結果を表示します。

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

## GitHub publish

`--github-publish` で以下を実行します。

- PRコメントを upsert (`<!-- patchgate:report -->` マーカー)
- Check Run を作成

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

- 既存キーの削除・改名・型変更は行わない
- 新規キー追加は許可（追加時は defaults/optional を維持）
- enum値追加は許可（既存値の意味は変更しない）

## Exit code

- `0`: 成功（`warn` での実行、または `enforce` で gate pass）
- `1`: gate fail（`enforce` で `score < fail_threshold`）
- `2`: 入力エラー（`scan` の不正オプション値）
- `3`: 設定エラー（設定ファイル読み込み/設定値不正）
- `4`: 実行エラー（差分収集・評価・キャッシュ処理）
- `5`: 出力エラー（JSON/レポート書き込み）
- `6`: GitHub publish エラー（publish入力解決・API実行）
