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

### `patchgate policy migrate` が `15` で失敗する

原因:

- 未対応 migration path
- `--from` と実際の policy version が不一致
- migration 後に validation が通らない

対処:

- `policy lint` で現状 version と validation を先に確認
- `--from`/`--to` を見直す

## Debugging

- `patchgate doctor` で config path と `policy_version` を確認
- `patchgate scan --policy-preset <preset> --format json` で effective 挙動を確認
- cache影響を排除する場合は `--no-cache` を使う
