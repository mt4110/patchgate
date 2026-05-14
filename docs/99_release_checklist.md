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
- ecosystem migration completion (`xtask ops migration-completion`)
- dual-run decommission (`xtask ops dual-run-decommission`)
- post-GA telemetry review (`xtask ops post-ga-telemetry`)
- retrospective cleanup queue (`xtask ops retrospective-cleanup`)
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
  - [ ] v2 GA policy は `release.lts.branch = "lts/v2"` / `security_sla_hours <= 72` / `backport_labels` を確認
  - [ ] `lts-backport.yml` の動作確認
- [ ] **GA Readiness**: `ga-readiness.yml` artifact確認
- [ ] **Compatibility Evidence**: `compatibility-report.md` で posture が意図と一致
- [ ] **Freeze Evidence**: `v1.1-readiness.md` で freeze_ready / v2_seed_ready を確認
- [ ] **Freeze Boundary Gate**: `v1.1-freeze-boundary.md` で scope inventory / deferred backlog / breaking-change boundary / v2 risk register を確認
  - [ ] `cargo run -p xtask -- ops freeze-boundary --output artifacts/v1.1-freeze-boundary.md`
  - [ ] v1.1に入れる候補と、deferred / non-goal / v2-seed の分類が一致
  - [ ] plugin / provider / audit / policy / docs / SDK の破壊変更境界が説明可能
  - [ ] deferred item は owner phase または non-goal rationale を持つ
- [ ] **V2 Bridge Evidence**: `verify-v2` / `diff-contract` / `shadow-review.md` を確認
- [ ] **Fleet Governance Evidence**: `fleet-review.md` で bundle / provider negotiation / provenance / retention / rollout wave / exception / segment cost / Phase181+ RC prep を確認
- [ ] **RC Contract Freeze**: `diff-contract.json` が `breaking_change_gate_ready = true`
  - [ ] `patchgate policy diff-contract --format json --enforce`
- [ ] **RC Evidence**: `v2-rc-readiness.md` で contract freeze / migration drill / audit export v2 / rollback / security / benchmark-cost / countdown gate が green
  - [ ] `cargo run -p xtask -- ops rollback-packet --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --provider-input artifacts/provider-dual.json --output artifacts/rollback-packet.json`
  - [ ] `migration-drill.json` は non-dry-run で failed repo 0
  - [ ] `cargo run -p xtask -- ops migration-drill --metrics-input artifacts/scan-metrics.jsonl --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --provider-input artifacts/provider-dual.json --rollback-packet-input artifacts/rollback-packet.json --output artifacts/migration-drill.json`
  - [ ] `rollback-packet.json` は `bridge_mode = "off"` / `generic_schema = "v1"` へ戻せる
  - [ ] `fleet-review.md` は repo / segment cost が green
- [ ] **GA Evidence**: `v2-ga-packet.md` で RC readiness / go-no-go / LTS / support / sunset / decommission を確認
  - [ ] manual release workflow input は `rc_security_decision=continue` / `ga_decision=go`
  - [ ] `post_ga_telemetry_ready = true`
- [ ] **Post-GA Handoff**:
  - [ ] `ecosystem-migration-completion.md` が provider bridge / audit v2 / fleet governance / migration drill green
  - [ ] `dual-run-decommission.md` が replay / rollback / v1 restore / support model green
  - [ ] `post-ga-telemetry-review.md` が SLO / audit parity / replay recovery green
  - [ ] `retrospective-cleanup-queue.md` が Phase201+ backcast と cleanup queue に接続
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
