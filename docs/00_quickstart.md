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
```

## 6) Optional integrations

- Generic CI provider: `--publish --ci-provider generic --ci-generic-output ...`
- Signed webhook: `--webhook-url ... --webhook-secret-env ...`
- Notifications: `--notify-target slack=...` / `--notify-target teams=...`

## 7) SDK template

- `sdk/templates/python-plugin` をコピーして plugin を作成

## 8) CI template

`docs/patchgate-action.yml` を `.github/workflows/patchgate.yml` にコピーして使います。
