# 03 CLI Reference

Purpose: コマンドライン引数とサブコマンドの詳細（`--help` を一次ソースとして整理）。

- Status: Verified
- Last verified: 2025-12-18 (Entropy Guard exit codes verified)

## Overview
`veto` はローカル実行（pre-commit / pre-push / 手動）やCIで使える検証CLIです。

> [!NOTE]
> v0.2.0 で Entropy Guard が実装され、実チェックが稼働しています。

## Global options

- `--repo <REPO>`
  - スキャン対象のリポジトリルート（デフォルト: カレントディレクトリ）
- `--config <CONFIG>`
  - 設定ファイル `veto.toml` のパスを明示指定
  - 指定がない場合は **実行時カレントディレクトリ**の `veto.toml` (または `veri.toml`) を探索します
- `-h, --help`
  - ヘルプ表示: そのコマンドの使い方を表示
- `-V, --version`
  - バージョン表示: 現在のバージョンを表示（例: `veto 0.1.0`）

## Subcommands

### `veto doctor`
環境情報と基本診断を表示します。

```bash
veto doctor
```

**出力例（概要）**:
- `repo_root`: スキャン対象のルートパス
- `config`: 読み込まれた設定（custom path / default file / none）
- `rust`: Rustツールチェーンの状態（表示できる場合）

### `veto scan`
チェックを実行し、結果を text / json で出力します。

**Options:**

- `--format <text|json>`
  - 出力形式。`veto.toml` の `[output].format` を上書きします。
- `--scope <staged|worktree|repo>`
  - スキャン範囲。`veto.toml` の `[scope].mode` を上書きします。
- `--explain`
  - ヒット時の詳細メタデータ（entropy値, token長, charset判定）を表示します。
  - **重要**: 生のトークン値（secrets）は表示されません。安全です。

**Examples:**

```bash
# デフォルト（configがあれば読み、なければデフォルト）
veto scan

# JSON出力（CIなどで利用）
veto scan --format json

# 範囲を変更（作業中の全変更をスキャン）
veto scan --scope worktree
```

## Exit codes

- `0`: findings が無い、または `fail_on` しきい値未満
- `1`: しきい値以上の severity が存在する
