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

### GitHub publish を dry-run で検証する

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --github-publish \
  --github-dry-run \
  --github-repo owner/repo \
  --github-pr 123 \
  --github-sha <sha> \
  --github-dry-run-output artifacts/github-payload.json
```

### retry/backoff と comment抑制を有効化する

```bash
patchgate scan \
  --scope worktree \
  --mode enforce \
  --github-publish \
  --github-retry-max-attempts 5 \
  --github-retry-backoff-ms 500 \
  --github-retry-max-backoff-ms 5000 \
  --github-suppress-comment-low-priority \
  --github-suppress-comment-rerun
```

### review_priority ベースのラベル付与（opt-in）

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --github-publish \
  --github-apply-labels
```

### scan の処理内訳をプロファイル出力する

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --no-cache \
  --profile-output artifacts/scan-profile.json
```

### 10kファイル想定の synthetic ベンチを比較する

```bash
cargo run -p xtask -- bench compare \
  --case ci-scale-10k \
  --output config/benchmarks/ci-scale-10k-baseline.jsonl \
  --synthetic-files 10000 \
  --synthetic-lines 1 \
  --max-regression-pct 40 \
  --report-output artifacts/bench-scale-10k.json
```

### Java/Kotlin 検知を段階有効化する

```toml
[language_rules]
java_kotlin = true
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
