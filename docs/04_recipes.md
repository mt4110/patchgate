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
鍵rotation中は `plugins.signature.trusted_key_envs` に新鍵envを追加し、失効時は `plugins.signature.revoked_key_sha256` に公開鍵fingerprintを追加します。

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
  --ci-generic-schema dual \
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
`.github/workflows/dead-letter-replay.yml` は、この queue を `dead-letter-queue` branch に永続化する前提です。

### replay summary を evidence packet に正規化

```bash
cargo run -p xtask -- ops replay-normalize \
  --replay-summary-input artifacts/dead-letter-replay-summary.json \
  --output artifacts/dead-letter-evidence.json
```

### audit drift をレビュー

```bash
cargo run -p xtask -- ops audit-drift-report \
  --audit-input artifacts/scan-audit.jsonl \
  --output artifacts/audit-drift-report.md
```

### SIEM handoff JSONL を生成

```bash
cargo run -p xtask -- ops siem-handoff \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --output artifacts/siem-handoff.jsonl
```

出力は `patchgate.audit.v2` をSIEM投入しやすい flat JSONL に正規化します。GitHub Actionsでは `.github/workflows/siem-handoff.yml` を参照実装として使えます。

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

### v2 shadow / bridge 準備チェック

```bash
patchgate policy verify-v2 \
  --path config/policy.toml.example \
  --provider-input artifacts/provider-dual.json \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --plugin-shadow-input sdk/templates/python-plugin/sample-input.v2.json \
  --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json \
  --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json \
  --format text
```

### v1/v2 contract diff を確認

```bash
patchgate policy diff-contract \
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

### Compatibility report を生成

```bash
cargo run -p xtask -- ops compatibility-report \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --replay-summary-input artifacts/dead-letter-replay-summary.json \
  --output artifacts/compatibility-report.md
```

出力は `stabilize-v1` / `hold-v1.1-line` / `start-v2-seed` の posture と、
その判断に使った SLO / audit / replay 証跡をまとめます。

### v1.1 freeze scoreboard を生成

```bash
cargo run -p xtask -- ops freeze-scoreboard \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --replay-summary-input artifacts/dead-letter-replay-summary.json \
  --output artifacts/v1.1-readiness.md
```

`freeze_ready` は v1.1 freeze を継続できるかを示し、
`v2_seed_ready` は replay 証跡まで含めて v2 seed を始めてよいかを示します。

### v1.1 freeze boundary inventory を生成

```bash
cargo run -p xtask -- ops freeze-boundary \
  --output artifacts/v1.1-freeze-boundary.md
```

出力は v1.1 に入れる候補、deferred / non-goal の整理、plugin / provider の破壊変更境界、
v2 option matrix、risk register、release checklist freeze gate をまとめます。
`freeze-scoreboard` は telemetry 判定、この artifact は scope boundary の説明責務を持ちます。

### v1/v2 shadow review を生成

```bash
cargo run -p xtask -- ops shadow-review \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json \
  --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json \
  --output artifacts/shadow-review.md
```

### fleet review packet を生成

```bash
cargo run -p xtask -- ops fleet-review \
  --metrics-input examples/poc/fleet-lab/scan-metrics.jsonl \
  --audit-input examples/poc/fleet-lab/scan-audit.jsonl \
  --audit-v2-input examples/poc/fleet-lab/scan-audit-v2.jsonl \
  --provider-input examples/poc/fleet-lab/provider-dual.json \
  --provider-input examples/poc/fleet-lab/provider-internal-dual.json \
  --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json \
  --registry-input examples/poc/fleet-lab/plugin-registry.json \
  --exceptions-input examples/poc/fleet-lab/exceptions.json \
  --cost-ceiling-minutes 30 \
  --output artifacts/fleet-review.md
```

この packet は repo posture だけでなく、provider capability negotiation、registry provenance、
retention tier、rollout wave、exception governance、segment cost、Phase181+ RC prep blocker まで同じ出力で確認します。

### Rollback packet を生成

```bash
cargo run -p xtask -- ops rollback-packet \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --output artifacts/rollback-packet.json
```

`rollback-packet.json` は、audit v1/v2 の shadow alignment と provider v1 restore evidence を確認して、`bridge_mode = "off"` / `generic_schema = "v1"` の復帰先を固定します。

### Migration drill を生成

```bash
cargo run -p xtask -- ops migration-drill \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --rollback-packet-input artifacts/rollback-packet.json \
  --output artifacts/migration-drill.json
```

`migration-drill.json` は、metrics / audit v1 / audit v2 / provider dual artifact / rollback packet を同じ repo set で照合し、failed repo または blocker がある場合は失敗します。

### RC readiness packet を生成

```bash
cargo run -p xtask -- ops rc-readiness \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --provider-input artifacts/provider-dual.json \
  --benchmark-input artifacts/bench-compare.json \
  --security-review-input artifacts/security-review-template.md \
  --contract-freeze-input artifacts/diff-contract.json \
  --migration-drill-input artifacts/migration-drill.json \
  --rollback-packet-input artifacts/rollback-packet.json \
  --fleet-review-input artifacts/fleet-review.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --provider-rollout-path docs/15_provider_rollout_checklist.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --freeze-boundary-path artifacts/v1.1-freeze-boundary.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --output artifacts/v2-rc-readiness.md
```

`artifacts/security-review-template.md` は、レビュー完了後に `- [x] Continue` を付け、`Mitigation required` は未チェックのままにしてください。
`artifacts/diff-contract.json` は `patchgate policy diff-contract --format json --enforce` で生成し、`artifacts/fleet-review.md` は repo / segment cost が green の状態で添付します。

### GA packet を生成

```bash
cargo run -p xtask -- ops ga-packet \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --policy-input artifacts/policy.v2.toml \
  --rc-readiness-input artifacts/v2-rc-readiness.md \
  --go-no-go-path artifacts/v2-ga-go-no-go.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --ops-handbook-path docs/19_v2_ops_handbook.md \
  --support-model-path docs/22_v2_support_model.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --phase201-backcast-path docs/20_phase201_plus_backcast.md \
  --output artifacts/v2-ga-packet.md
```
