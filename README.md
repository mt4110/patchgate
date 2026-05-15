# patchgate

[English](README_EN.md) | **日本語**

`patchgate` は **PR変更差分の品質ゲート** です。
セキュリティ専用ではなく、次の4軸を1つのスコア (0-100) で判定します。

- テスト不足 (`test_gap`)
- 破壊的変更リスク (`dangerous_change`)
- 依存更新リスク (`dependency_update`)
- レビュー優先度 (`P0`..`P3`)

## 方針
- **Nix前提**: 開発・CIの実行環境を固定
- **マルチプラットフォーム必須**: Linux / macOS / Windows で検証
- **低変動費設計**: 実行の主役はローカル/CI、SaaSはメタデータのみ

## クイックスタート

以下のコマンドは、**必ず `nix develop` に入ったシェルの中で実行**してください。

```bash
# Nix shell
nix develop

# 実行
cargo run -p patchgate-cli -- scan --mode warn
```

JSON出力:

```bash
cargo run -p patchgate-cli -- scan --format json
```

## policy.toml

`config/policy.toml.example` を、`patchgate` を適用したい**対象プロジェクトのルート**へ
`policy.toml` として配置して使います。

```bash
cp config/policy.toml.example /path/to/project_root/policy.toml
```

対象プロジェクトでローカル管理にしたい場合は、`.gitignore` にも追加してください。

```bash
printf '\n/policy.toml\n' >> /path/to/project_root/.gitignore
```

`patchgate` の実行も、`nix develop` に入った状態で行う前提です。

## CLI

- `patchgate scan --mode warn|enforce --scope staged|worktree|repo|pr --base-ref origin/main --head-ref HEAD --format text|json`
- `patchgate doctor`

### Exit Code

- `0`: 成功（`warn` 実行、または `enforce` で gate pass）
- `1`: `enforce` で `score < fail_threshold`（gate fail）
- `2`: 入力エラー（`scan` オプション値不正）
- `3`: 設定エラー（設定ファイル読み込み/設定値不正）
- `4`: 実行エラー（差分収集・評価・キャッシュ）
- `5`: 出力エラー（JSON/レポート書き込み）
- `6`: GitHub publish エラー

## GitHub Actions テンプレ

`docs/patchgate-action.yml` を参照してください。

## MVPに含むチェック

- 差分ベースの3チェック (テスト不足 / 危険ファイル変更 / 依存更新)
- スコアリングとfail threshold
- `warn` / `enforce` モード
- JSON出力
- SQLiteキャッシュ（同一差分は再計算スキップ）
