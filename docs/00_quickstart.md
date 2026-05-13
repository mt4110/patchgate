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
- V2 readiness: `patchgate policy verify-v2 --path policy.toml --format text`
- Fleet review: `cargo run -p xtask -- ops fleet-review --metrics-input artifacts/scan-metrics.jsonl --audit-input artifacts/scan-audit.jsonl --output artifacts/fleet-review.md`
- SIEM handoff: `cargo run -p xtask -- ops siem-handoff --audit-v2-input artifacts/scan-audit-v2.jsonl --output artifacts/siem-handoff.jsonl`
- RC/GA packets: `cargo run -p xtask -- ops rc-readiness ...` / `cargo run -p xtask -- ops ga-packet ...`

## 7) SDK template

- `patchgate plugin init --lang python --plugin-id sample --output ./sample-plugin`
- `patchgate plugin init --lang node --plugin-id sample-node --output ./sample-node-plugin`
- `patchgate plugin init --lang rust --plugin-id sample-rust --output ./sample-rust-plugin`

## 8) CI template

`docs/patchgate-action.yml` を `.github/workflows/patchgate.yml` にコピーして使います。

GitHub 以外では次を使います。

- GitLab: `docs/patchgate-gitlab-ci.yml`
- Jenkins: `docs/Jenkinsfile.patchgate`
