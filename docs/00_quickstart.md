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

## 5) CI template

`docs/patchgate-action.yml` を `.github/workflows/patchgate.yml` にコピーして使います。
