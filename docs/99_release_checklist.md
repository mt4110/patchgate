# 99 Release Checklist

Purpose: Ensure reproducible patchgate releases.

## Automation status

以下は CI (`.github/workflows/release-precheck.yml`) で自動実行:

- `fmt/lint/test` (`just ci-check`)
- `doctor` 実行
- `policy lint`（`config/policy.toml.example` + `config/presets/*`）
- `github publish dry-run` smoke test
- `._*` 混入チェック
- ベンチ基準値比較 (`cargo run -p xtask -- bench compare --case ci-worktree --output config/benchmarks/ci-worktree-baseline.jsonl --require-baseline`)
- 比較レポート生成 (`--report-output artifacts/bench-compare.json`)
- scan profile 取得 (`cargo run -p xtask -- bench profile --profile-output artifacts/scan-profile.json`)

以下は引き続き手動:

- バージョン更新内容の最終確認
- 署名付きタグ作成/検証
- リリースアーカイブ作成と配布判断

## Pre-Release
- [ ] **Cleanliness**: Ensure no `._*` or `__MACOSX` files exist in the repo. (CI自動化済み)
  - `find . -name '._*' -delete`
  - `git ls-files '._*' '**/._*'` should return nothing.
- [ ] **Tests**: Run full workspace checks with Nix. (CI自動化済み)
  - `nix develop --command cargo clippy --workspace --all-targets -- -D warnings`
  - `nix develop --command cargo test --workspace`
- [ ] **Doctor**: `nix develop --command cargo run -p patchgate-cli -- doctor` (CI自動化済み)
- [ ] **Policy Lint**: `nix develop --command cargo run -p patchgate-cli -- policy lint --path config/policy.toml.example --require-current-version` (CI自動化済み)
- [ ] **Publish Dry-run**: `nix develop --command cargo run -p patchgate-cli -- scan --scope staged --mode warn --format json --github-publish --github-dry-run --github-repo example/repo --github-pr 1 --github-sha deadbeef --github-dry-run-output artifacts/github-payload.json` (CI自動化済み)
- [ ] **Benchmark**: `nix develop --command cargo run -p xtask -- bench compare --case ci-worktree --output config/benchmarks/ci-worktree-baseline.jsonl --require-baseline` (CI自動化済み)
- [ ] **P95/SLO Evidence**: profile + benchmark report が release artifact として保存されていることを確認
- [ ] **Scale Scenario**: `scale-benchmark.yml` の synthetic 10k 結果を確認
- [ ] **Docs**: Sync docs with current CLI/config behavior.
- [ ] **Version**: Bump version in:
  - `flake.nix`
  - `crates/*/Cargo.toml`

## Release
- [ ] **Tag**: Create a signed tag.
  - `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
  - `git verify-tag vX.Y.Z`
- [ ] **Policy Distribution**: Create immutable policy tag and pin record.
  - `git tag -s policy/<name>/vYYYY.MM.DD -m "policy release"`
  - 記録: policy tag / commit SHA / lint結果
- [ ] **Archive**: Build source archive via git.
  - `git archive --format=tar.gz --prefix=patchgate-vX.Y.Z/ -o patchgate-vX.Y.Z.tar.gz vX.Y.Z`
- [ ] **Verify Archive**:
  - `tar -tf patchgate-vX.Y.Z.tar.gz | grep '._'` -> should be empty
  - `tar -tf patchgate-vX.Y.Z.tar.gz | grep 'target/'` -> should be empty

## Post-Release
- [ ] **Push**: `git push origin main --tags`
- [ ] **Rollback readiness**: previous policy tag へ戻せることを確認
