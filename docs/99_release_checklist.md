# 99 Release Checklist

Purpose: patchgate release の再現性・監査性・LTS運用性を担保する。

## Automation status

CI/Workflowで自動化済み:

- `fmt/lint/test` (`just ci-check`)
- `doctor`
- `policy lint`（example + presets）
- `policy verify-v1`
- publish dry-run smoke
- benchmark compare + report
- observability出力（metrics/audit/history）
- SLO report (`xtask ops slo-report`)
- GA readiness (`xtask ops ga-readiness`)
- Compatibility report (`xtask ops compatibility-report`)
- Freeze scoreboard (`xtask ops freeze-scoreboard`)
- Audit drift report (`xtask ops audit-drift-report`)
- Shadow review (`xtask ops shadow-review`)
- Fleet review (`xtask ops fleet-review`)
- RC readiness (`xtask ops rc-readiness`)
- GA packet (`xtask ops ga-packet`)
- LTS backport label check

## Pre-Release

- [ ] **Policy Compatibility**: `patchgate policy lint --path config/policy.toml.example --require-current-version`
- [ ] **v1 Readiness**: `patchgate policy verify-v1 --path config/policy.toml.example`
  - [ ] strict profile: `--readiness-profile strict`
  - [ ] lts profile: `--readiness-profile lts`
- [ ] **Plugin/Sandbox**:
  - [ ] `plugins.sandbox.profile = "restricted"`
  - [ ] plugin timeout / fail_mode が設定済み
- [ ] **Publish Dry-run**: `--github-dry-run` でpayload確認
- [ ] **Webhook/Notification**:
  - [ ] 署名secret設定確認
  - [ ] 通知先疎通確認
  - [ ] `--dead-letter-output` の保存先確認
  - [ ] dead-letter replay: `patchgate delivery replay --input artifacts/dead-letter.jsonl --dry-run`
- [ ] **Observability Contract**:
  - [ ] `scan-metrics.jsonl` 出力
  - [ ] `scan-audit.jsonl` (`patchgate.audit.v1`) 出力
  - [ ] `history summary/trend` 実行
  - [ ] `xtask ops slo-report` 実行
  - [ ] `xtask ops compatibility-report` 実行
  - [ ] `xtask ops freeze-scoreboard` 実行
  - [ ] `xtask ops audit-drift-report` 実行
  - [ ] `xtask ops shadow-review` 実行（v2 dual-write時）
- [ ] **LTS Policy**:
  - [ ] `release.lts.branch` / `security_sla_hours` / `backport_labels` を確認
  - [ ] `lts-backport.yml` の動作確認
- [ ] **GA Readiness**: `ga-readiness.yml` artifact確認
- [ ] **Compatibility Evidence**: `compatibility-report.md` で posture が意図と一致
- [ ] **Freeze Evidence**: `v1.1-readiness.md` で freeze_ready / v2_seed_ready を確認
- [ ] **V2 Bridge Evidence**: `verify-v2` / `diff-contract` / `shadow-review.md` を確認
- [ ] **Fleet Governance Evidence**: `fleet-review.md` で bundle / provenance / exception / cost を確認
- [ ] **RC Evidence**: `v2-rc-readiness.md` で candidate gate が green
- [ ] **GA Evidence**: `v2-ga-packet.md` で LTS / support / sunset / decommission を確認
- [ ] **Docs Sync**: `docs/00..05/99` がCLI実装と一致

## Release

- [ ] **Tag**: `git tag -s vX.Y.Z -m "Release vX.Y.Z"`
- [ ] **Artifact**: release binary + `SHA256SUMS`
- [ ] **SBOM-like metadata**: `sbom.cargo-metadata.json`（`cargo metadata` 出力）を生成・添付
- [ ] **Provenance metadata**: `provenance.intoto.jsonl` を生成・添付

## Post-Release

- [ ] `git push origin main --tags`
- [ ] LTS backport要否を triage
- [ ] 次回GA/LTSレビューの日程を更新
