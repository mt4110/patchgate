# 05 Troubleshooting

Purpose: エラーの原因と対処法。

## Common Errors

### `patchgate policy lint` が `10` で失敗する

原因:

- policy ファイルが見つからない
- TOML の構文エラー

対処:

- `--path` を明示する
- TOML 構文を修正する

### `patchgate policy lint` が `11/12/13` で失敗する

原因:

- `11`: 型エラー（enum値や型不一致）
- `12`: 範囲エラー（例: `large_change_lines = 0`）
- `13`: 依存関係エラー（例: `critical_patterns` が `patterns` の部分集合でない）

対処:

- `docs/02_config_reference.md` と `config/policy.toml.example` を基準に値を修正

### `patchgate policy lint --require-current-version` が `14` で失敗する

原因:

- `policy_version` が current ではない（または未指定で legacy 扱い）

対処:

```bash
patchgate policy migrate --from 1 --to 2 --path policy.toml --write
patchgate policy lint --path policy.toml --require-current-version
```

### GitHub publish が rate limit で不安定

症状:

- `403` + `x-ratelimit-remaining: 0`
- `429 Too Many Requests`
- `degraded mode activated` が表示される

対処:

- retry設定を増やす (`--github-retry-max-attempts`, `--github-retry-backoff-ms`)
- `--github-suppress-comment-rerun` で連続投稿ノイズを減らす
- まず `--github-dry-run` で payload 妥当性を確認する

### `github_auth=app` で publish 失敗

原因:

- `--github-app-token-env` で指定した installation token が不足/期限切れ

対処:

- GitHub App installation token を再発行
- `--github-dry-run` で auth mode と payload を検証

## Debugging

- `patchgate doctor` で config path と `policy_version` を確認
- `patchgate scan --policy-preset <preset> --format json` で effective 挙動を確認
- publish前に `--github-dry-run --github-dry-run-output` で送信内容を保存して確認
- cache影響を排除する場合は `--no-cache` を使う
