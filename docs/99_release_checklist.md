# 99 Release Checklist

Purpose: patchgate release の再現性・監査性・ガバナンスを担保する。

## Automation status

CI/Workflowで自動化済み:

- `fmt/lint/test` (`just ci-check`)
- `doctor`
- `policy lint`（example + presets）
- publish dry-run smoke
- benchmark compare + report
- scan profile収集
- observability出力（metrics/audit/history）
- policy governance check（label + CODEOWNERS）
- weekly ops summary / security review packet

## Pre-Release

- [ ] **Policy Compatibility**: `patchgate policy lint --path config/policy.toml.example --require-current-version`
- [ ] **Waiver Freshness**: `waiver.entries` に期限切れがないこと（lintで検証）
- [ ] **Publish Dry-run**: `--github-dry-run` でpayload確認
- [ ] **Observability Contract**:
  - [ ] `scan-metrics.jsonl` が出力される
  - [ ] `scan-audit.jsonl` が `patchgate.audit.v1` で出力される
  - [ ] `patchgate history summary/trend` が実行可能
- [ ] **Security/Token Policy**:
  - [ ] workflowに `permissions: write-all` がない
  - [ ] token運用が最小権限
- [ ] **Policy Change Governance**:
  - [ ] policy変更PRに `policy-approved` ラベル
  - [ ] `.github/CODEOWNERS` の owner review が成立
- [ ] **Recovery Drill**: `recovery-drill.yml` 最新結果が成功
- [ ] **Audit Report**: `xtask ops audit-report` 出力を確認
- [ ] **Scale Scenario**: `scale-benchmark.yml` の10k結果確認
- [ ] **Docs Sync**: `docs/01..05/99` がCLI挙動と一致

## Release

- [ ] **Tag**: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
- [ ] **Policy Tag**: `git tag -s policy/<name>/vYYYY.MM.DD -m "policy release"`
- [ ] **Archive**: `git archive --format=tar.gz --prefix=patchgate-vX.Y.Z/ -o patchgate-vX.Y.Z.tar.gz vX.Y.Z`

## Post-Release

- [ ] `git push origin main --tags`
- [ ] 直前policy tagへのロールバック手順を再確認
- [ ] 次回 security review の artifact テンプレートを更新
