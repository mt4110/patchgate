# 04 Recipes

Purpose: よくあるユースケースと設定例。

## Common Use Cases

### Legacy policy を current へ移行する

```bash
patchgate policy lint --path policy.toml
patchgate policy migrate --from 1 --to 2 --path policy.toml
patchgate policy migrate --from 1 --to 2 --path policy.toml --write
patchgate policy lint --path policy.toml --require-current-version
```

### CI で policy 互換性をゲートする

```bash
patchgate policy lint --path config/policy.toml.example --require-current-version
for preset in strict balanced relaxed; do
  patchgate policy lint --path "config/presets/${preset}.toml" --require-current-version
done
```

### リポジトリごとに preset を切り替える

```bash
patchgate scan --policy-preset strict --mode enforce
patchgate scan --policy-preset balanced --mode warn
patchgate scan --policy-preset relaxed --mode warn
```

## Policy distribution template

### 配布フロー

1. `policy/<name>.toml` を更新し、`policy_version` を明示
2. `patchgate policy lint --path policy/<name>.toml --require-current-version` を通す
3. 配布用タグを作成（例: `policy/my-team/v2026.03.02`）
4. 利用側リポジトリではタグ pin で参照
5. 問題発生時は直前タグへロールバック

### pin 運用の例

- 推奨: immutable tag（運用都合で再利用しない）
- 監査ログに `policy tag` / `commit SHA` / `lint結果` を残す

### ロールバックの基準例

- false positive が急増
- gate fail 率が閾値を超過
- migration 後に互換性 warning が残存
