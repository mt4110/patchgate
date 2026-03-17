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
  --retry-max-attempts 3
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
