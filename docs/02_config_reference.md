# 02 Config Reference

Purpose: 設定ファイルの全オプションと仕様。

- Status: Verified (Schema & Behavior)
- Last verified: 2025-12-18 (Entropy Guard config applied correctly, allowlist substring match)

## Overview
`veto.toml` をプロジェクトルートに配置することで、スキャンの挙動をカスタマイズできます。

> **Implementation status (v0.2.2)**
> Entropy Guard 設定は実装済・検証済です。
> DoS対策（max_file_bytes等）が追加されました。
> `allowlist` は部分一致(substring match)として機能します。正規表現は未対応です。

## Precedence
設定の優先順位は以下の通りです（上が優先）：

1. **CLI引数** (例: `--format json`)
2. **設定ファイル** (`veto.toml` > `veri.toml` [deprecated])
3. **デフォルト値** (Code内蔵)

## Minimal Config
何も書かなくても動作しますが、よくある設定例です。

```toml
[output]
format = "text"
fail_on = "high"
```

## Full Example
全てのオプションを明示した例です。

```toml
[output]
format = "text"         # "text" | "json"
fail_on = "high"        # "low" | "medium" | "high" | "critical"

[scope]
mode = "staged"         # "staged" | "worktree" | "repo"

[allowlist]
patterns = []           # 許可するパターンのリスト

[entropy_guard]
enabled = true
min_length = 24
threshold = 4.2
ignore_ext = ["png", "jpg", "gif", "mp4", "pdf"]
max_file_bytes = 1048576       # 1MB
max_line_length = 10000
max_tokens_per_file = 2000
```

## Reference

### `[output]`
出力形式と終了コードの制御。

- **`format`** (String)
    - デフォルト: `"text"`
    - 許容値: `"text"`, `"json"`
    - 説明: スキャン結果の表示形式。CI等で機械可読が必要な場合は `json` を推奨。
- **`fail_on`** (String)
    - デフォルト: `"high"`
    - 許容値: `"low"`, `"medium"`, `"high"`, `"critical"`
    - 説明: 指定した重大度以上のissueが見つかった場合に終了コード 1 を返す。(Verified: High severity findings exit with 1)

### `[scope]`
スキャン対象の範囲。

- **`mode`** (String)
    - デフォルト: `"staged"`
    - 許容値: `"staged"`, `"worktree"`, `"repo"`
    - 説明:
        - `staged`: Gitのステージングエリアのファイルのみ（コミット前フック用）
        - `worktree`: 作業ディレクトリの変更分
        - `repo`: リポジトリ全域

### `[allowlist]`
誤検知を抑制するための例外設定。

- **`patterns`** (Vec<String>)
    - デフォルト: `[]`
    - 説明: 許可（無視）したいパターンのリスト。
    - Matching: (TBD: exact / substring / regex)

### `[entropy_guard]`
高エントロピー文字列（秘密鍵など）の検出設定。

- **`enabled`** (bool)
    - デフォルト: `true`
    - 説明: エントロピースキャンを有効にするか。
- **`min_length`** (usize)
    - デフォルト: `24`
    - 説明: チェック対象とする最小文字列長。これより短い文字列は無視。
- **`threshold`** (f64)
    - デフォルト: `4.2`
    - 説明: Shannonエントロピーの閾値。これを超えると検出される。
- **`ignore_ext`** (Vec<String>)
    - デフォルト: `["png", "jpg", "gif", "mp4", "pdf"]`
    - 説明: エントロピーチェックから除外する拡張子（バイナリファイル等）。
- **`max_file_bytes`** (u64)
    - デフォルト: `1048576` (1MB)
    - 説明: スキャンする最大ファイルサイズ。これを超えるとスキップされます（DoS対策）。
- **`max_line_length`** (usize)
    - デフォルト: `10000`
    - 説明: スキャンする1行の最大文字数。超えた行はスキップされます。
- **`max_tokens_per_file`** (usize)
    - デフォルト: `2000`
    - 説明: 1ファイルあたりに抽出する最大トークン数。超えると残りは無視されます。

## Notes
- **ファイルパス**: 設定ファイルはデフォルトで **実行時のカレントディレクトリ** の `veto.toml` を探します。
    - `veto.toml` が見つからない場合、後方互換性のため `veri.toml` を探します（**deprecated**）。
    - 別のパスを指定したい場合は `--config path/to/veto.toml` を使用してください。
    - `--repo` オプションはスキャン対象のルートを指定するものであり、設定ファイルの探索場所には影響しません（独立しています）。
- **`entropy_guard.threshold`**: 値を下げすぎると誤検知が増えます。通常はデフォルトの `4.2` 〜 `4.5` 程度が推奨です。

## TODO
- [ ] `allowlist.patterns` のマッチング仕様（正規表現対応有無）を確定させる
- [ ] `fail_on` のExit Code挙動を実装後に検証する
