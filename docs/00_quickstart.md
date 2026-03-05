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
```

## 6) Optional integrations

- Generic CI provider: `--publish --ci-provider generic --ci-generic-output ...`
- Signed webhook: `--webhook-url ... --webhook-secret-env ...`
- Notifications: `--notify-target slack=...` / `--notify-target teams=...`
- Delivery fallback: `--dead-letter-output artifacts/dead-letter.jsonl`
- Replay dead-letter: `patchgate delivery replay --input artifacts/dead-letter.jsonl --dry-run`

## 7) SDK template

- `patchgate plugin init --lang python --plugin-id sample --output ./sample-plugin`
- `patchgate plugin init --lang node --plugin-id sample-node --output ./sample-node-plugin`
- `patchgate plugin init --lang rust --plugin-id sample-rust --output ./sample-rust-plugin`

## 8) CI template

`docs/patchgate-action.yml` を `.github/workflows/patchgate.yml` にコピーして使います。
