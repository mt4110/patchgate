# 00 Quickstart

## 1) Nix shell

```bash
nix develop
```

## 2) Install / run

```bash
cargo install --path crates/patchgate-cli --locked
patchgate --help
```

## 3) Add policy

```bash
cp config/policy.toml.example policy.toml
```

## 4) Scan

```bash
patchgate scan --mode warn
patchgate scan --mode enforce --format json
```

## 5) v1 readiness check

```bash
patchgate policy verify-v1 --path policy.toml --format text
patchgate policy verify-v1 --path policy.toml --readiness-profile strict --format text
patchgate policy verify-v1 --path policy.toml --autofix-output artifacts/policy.autofix.toml --format text
```

## 6) Optional integrations

- Generic CI provider: `--publish --ci-provider generic --ci-generic-output ...`
- Signed webhook: `--webhook-url ... --webhook-secret-env ...`
- Notifications: `--notify-target slack=...` / `--notify-target teams=...`
- Delivery fallback: `--dead-letter-output artifacts/dead-letter.jsonl`
- Replay dead-letter: `patchgate delivery replay --input artifacts/dead-letter.jsonl --rewrite-input --summary-output artifacts/dead-letter-replay-summary.json`
- Compatibility report: `cargo run -p xtask -- ops compatibility-report --metrics-input artifacts/scan-metrics.jsonl --audit-input artifacts/scan-audit.jsonl --output artifacts/compatibility-report.md`
- Freeze scoreboard: `cargo run -p xtask -- ops freeze-scoreboard --metrics-input artifacts/scan-metrics.jsonl --audit-input artifacts/scan-audit.jsonl --output artifacts/v1.1-readiness.md`
- Freeze boundary inventory: `cargo run -p xtask -- ops freeze-boundary --output artifacts/v1.1-freeze-boundary.md`
- V2 readiness: `patchgate policy verify-v2 --path policy.toml --provider-input artifacts/provider-dual.json --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --plugin-shadow-input sdk/templates/python-plugin/sample-input.v2.json --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json --registry-input examples/poc/fleet-lab/plugin-registry.json --exceptions-input examples/poc/fleet-lab/exceptions.json --format text`
- Contract freeze: `patchgate policy diff-contract --path policy.toml --format json --enforce > artifacts/diff-contract.json`
- Fleet review: `cargo run -p xtask -- ops fleet-review --metrics-input examples/poc/fleet-lab/scan-metrics.jsonl --audit-input examples/poc/fleet-lab/scan-audit.jsonl --audit-v2-input examples/poc/fleet-lab/scan-audit-v2.jsonl --provider-input examples/poc/fleet-lab/provider-dual.json --provider-input examples/poc/fleet-lab/provider-internal-dual.json --bundle-catalog-input examples/poc/fleet-lab/bundle-catalog.json --registry-input examples/poc/fleet-lab/plugin-registry.json --exceptions-input examples/poc/fleet-lab/exceptions.json --output artifacts/fleet-review.md`
- Rollback packet: `cargo run -p xtask -- ops rollback-packet --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --provider-input artifacts/provider-dual.json --output artifacts/rollback-packet.json`
- Migration drill: `cargo run -p xtask -- ops migration-drill --metrics-input artifacts/scan-metrics.jsonl --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --provider-input artifacts/provider-dual.json --rollback-packet-input artifacts/rollback-packet.json --output artifacts/migration-drill.json`
- SIEM handoff: `cargo run -p xtask -- ops siem-handoff --audit-v2-input artifacts/scan-audit-v2.jsonl --output artifacts/siem-handoff.jsonl`
- RC/GA packets: `cargo run -p xtask -- ops rc-readiness --contract-freeze-input artifacts/diff-contract.json --migration-drill-input artifacts/migration-drill.json --rollback-packet-input artifacts/rollback-packet.json --fleet-review-input artifacts/fleet-review.md ...` / `cargo run -p xtask -- ops ga-packet --rc-readiness-input artifacts/v2-rc-readiness.md --go-no-go-path artifacts/v2-ga-go-no-go.md ...`
- Post-GA handoff: `cargo run -p xtask -- ops migration-completion ...`, `cargo run -p xtask -- ops dual-run-decommission ...`, `cargo run -p xtask -- ops post-ga-telemetry ...`, `cargo run -p xtask -- ops retrospective-cleanup ...`

## 7) SDK template

- `patchgate plugin init --lang python --plugin-id sample --output ./sample-plugin`
- `patchgate plugin init --lang node --plugin-id sample-node --output ./sample-node-plugin`
- `patchgate plugin init --lang rust --plugin-id sample-rust --output ./sample-rust-plugin`

## 8) CI template

`docs/patchgate-action.yml` を `.github/workflows/patchgate.yml` にコピーして使います。

GitHub 以外では次を使います。

- GitLab: `docs/patchgate-gitlab-ci.yml`
- Jenkins: `docs/Jenkinsfile.patchgate`
