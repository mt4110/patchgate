# 04 Recipes

## Common use cases

### Scan + metrics/audit JSONL を同時出力

```bash
patchgate scan \
  --scope worktree \
  --mode warn \
  --format json \
  --no-cache \
  --metrics-output artifacts/scan-metrics.jsonl \
  --audit-log-output artifacts/scan-audit.jsonl
```

### 履歴サマリとトレンドを作る

```bash
patchgate history summary \
  --input artifacts/scan-metrics.jsonl \
  --format json > artifacts/history-summary.json

patchgate history trend \
  --input artifacts/scan-metrics.jsonl \
  --format json > artifacts/history-trend.json
```

### ベースライン比較でアラート判定

```bash
patchgate history summary \
  --input artifacts/current-metrics.jsonl \
  --baseline artifacts/baseline-metrics.jsonl \
  --format text
```

### 週次運用サマリを生成（xtask）

```bash
cargo run -p xtask -- ops weekly-summary \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --output artifacts/weekly-ops-summary.md \
  --trend-output artifacts/weekly-ops-trend.json
```

### 監査レポートを生成（xtask）

```bash
cargo run -p xtask -- ops audit-report \
  --audit-input artifacts/scan-audit.jsonl \
  --output artifacts/audit-report.md
```

### GitHub publish dry-run（最小権限前提）

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

### policy変更の承認フロー

1. `config/policy.toml.example` または `config/presets/*` を変更
2. PRに `policy-approved` ラベルを付与
3. `policy-governance.yml` がラベルと `CODEOWNERS` を検証

### セキュリティレビュー定例

- workflow: `.github/workflows/security-review.yml`
- 生成物:
  - `artifacts/history-summary.json`
  - `artifacts/history-trend.json`
  - `artifacts/audit-report.md`
  - `artifacts/security-review-template.md`
