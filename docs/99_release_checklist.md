# 99 Release Checklist

Purpose: Ensure reproducible patchgate releases.

## Pre-Release
- [ ] **Cleanliness**: Ensure no `._*` or `__MACOSX` files exist in the repo.
  - `find . -name '._*' -delete`
  - `git ls-files '._*' '**/._*'` should return nothing.
- [ ] **Tests**: Run full workspace checks with Nix.
  - `nix develop --command cargo clippy --workspace --all-targets -- -D warnings`
  - `nix develop --command cargo test --workspace`
- [ ] **Docs**: Sync docs with current CLI/config behavior.
- [ ] **Version**: Bump version in:
  - `flake.nix`
  - `crates/*/Cargo.toml`

## Release
- [ ] **Tag**: Create a signed tag.
  - `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
  - `git verify-tag vX.Y.Z`
- [ ] **Archive**: Build source archive via git.
  - `git archive --format=tar.gz --prefix=patchgate-vX.Y.Z/ -o patchgate-vX.Y.Z.tar.gz vX.Y.Z`
- [ ] **Verify Archive**:
  - `tar -tf patchgate-vX.Y.Z.tar.gz | grep '._'` -> should be empty
  - `tar -tf patchgate-vX.Y.Z.tar.gz | grep 'target/'` -> should be empty

## Post-Release
- [ ] **Push**: `git push origin main --tags`
