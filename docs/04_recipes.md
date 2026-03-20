# 04 Recipes

## Common use cases

### Pluginを有効にしてscan

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --no-cache
```

`policy.toml` 側で `plugins.enabled = true` と `plugins.entries[]` を設定します。
署名検証を有効にする場合は `[plugins.signature] required = true` と `entries[].signature_path` を設定します。

### Pluginテンプレートを生成

```bash
patchgate plugin init --lang python --plugin-id sample --output ./plugins/sample
patchgate plugin init --lang node --plugin-id sample-node --output ./plugins/sample-node
patchgate plugin init --lang rust --plugin-id sample-rust --output ./plugins/sample-rust
```

### Generic CI provider payloadを出力

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --publish \
  --ci-provider generic \
  --ci-generic-output artifacts/ci-generic.json
```

### GitLab CI から generic provider を使う

`docs/patchgate-gitlab-ci.yml` をベースに、
`artifacts/ci-generic.json` を artifact として回収します。

### Jenkins から generic provider を使う

`docs/Jenkinsfile.patchgate` をベースに、
`artifacts/ci-generic.json` を archive します。

### 署名付きWebhook配信

```bash
export PATCHGATE_WEBHOOK_SECRET="<secret>"
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --webhook-url https://example.internal/hooks/patchgate \
  --webhook-secret-env PATCHGATE_WEBHOOK_SECRET \
  --webhook-retry-max-attempts 3 \
  --dead-letter-output artifacts/dead-letter.jsonl
```

### Slack/Teams通知

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --notify-target slack=https://hooks.slack.com/services/... \
  --notify-target teams=https://outlook.office.com/webhook/... \
  --dead-letter-output artifacts/dead-letter.jsonl
```

### dead-letterを再送

```bash
patchgate delivery replay \
  --input artifacts/dead-letter.jsonl \
  --transport notification \
  --retry-max-attempts 3 \
  --rewrite-input \
  --summary-output artifacts/dead-letter-replay-summary.json
```

成功したレコードは queue から除去され、失敗したレコードだけが `artifacts/dead-letter.jsonl` に残ります。

### `verify-v1` の safe autofix preview を出力

```bash
patchgate policy verify-v1 \
  --path policy.toml \
  --readiness-profile strict \
  --autofix-output artifacts/policy.autofix.toml \
  --format text
```

### `verify-v1` の safe autofix をそのまま適用

```bash
patchgate policy verify-v1 \
  --path policy.toml \
  --readiness-profile standard \
  --autofix-write \
  --format text
```

### 履歴サマリとトレンド

```bash
patchgate history summary \
  --input artifacts/scan-metrics.jsonl \
  --format json > artifacts/history-summary.json

patchgate history trend \
  --input artifacts/scan-metrics.jsonl \
  --format json > artifacts/history-trend.json
```

### v1移行準備チェック

```bash
patchgate policy verify-v1 \
  --path config/policy.toml.example \
  --format text
```

### SLOレポート生成

```bash
cargo run -p xtask -- ops slo-report \
  --metrics-input artifacts/scan-metrics.jsonl \
  --output artifacts/slo-report.md
```

### GA readinessレポート生成

```bash
cargo run -p xtask -- ops ga-readiness \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --output artifacts/ga-readiness.md
```
