# Roadmap

This roadmap tracks the patchgate pivot.

## Detailed phase design

- [Phase Backcast (1-100)](06_phase_backcast_1_100.md)
- [Phase Backcast (121+)](10_phase_backcast_121_plus.md)
- [Current State and Next Steps](11_current_state_and_next_steps.md)
- [Phase101-120 Status](12_phase101_120_status.md)
- [Phase Backcast (151-200)](13_phase151_200_backcast.md)
- [V2 Migration Guide Alpha](16_v2_migration_guide_alpha.md)
- [Provider Rollout Checklist](15_provider_rollout_checklist.md)
- [Fleet Ops Review Packet](17_fleet_ops_review_packet.md)
- [V2 Candidate Release Checklist](18_v2_candidate_release_checklist.md)
- [V2 Ops Handbook](19_v2_ops_handbook.md)
- [V1 Sunset Notice](21_v1_sunset_notice.md)
- [V2 Support Model](22_v2_support_model.md)
- [Phase Backcast (201+)](20_phase201_plus_backcast.md)
- [PR Plan: Phase1-10](07_pr_plan_phase1_10.md)
- [PR Plan: Phase11-20](08_pr_plan_phase11_20.md)
- [PR Plan: Phase21-30](../phase21_30.md)
- [PR Plan: Phase31-40](../phase31_40.md)
- [PR Plan: Phase41-50](../phase41_50.md)
- [PR Plan: Phase51-60](../phase51_60.md)
- [PR Plan: Phase61-70](../phase61_70.md)
- [PR Plan: Phase71-80](../phase71_80.md)
- [PR Plan: Phase81-90](../phase81_90.md)
- [PR Plan: Phase91-100](../phase91_100.md)
- [PR Plan: Phase101-110](../phase101_110.md)
- [PR Plan: Phase111-120](../phase111_120.md)
- [PR Plan: Phase121-130](../phase121_130.md)
- [PR Plan: Phase131-140](../phase131_140.md)
- [PR Plan: Phase141-150](../phase141_150.md)
- [PR Plan: Phase151-160](../phase151_160.md)
- [PR Plan: Phase161-170](../phase161_170.md)
- [PR Plan: Phase171-180](../phase171_180.md)
- [PR Plan: Phase181-190](../phase181_190.md)
- [PR Plan: Phase191-200](../phase191_200.md)

## Active planning horizon (updated 2026-03-23)

- Implemented baseline: Phase1-100 (minimum viable contract)
- Phase101-120: baseline implementation completed
- Phase101-120 follow-up: docs / cross-repo rollout / ops settlement continue
- Phase121-130: implementation started
- Phase131-150: design fixed / implementation follow-up ongoing
- Phase151-200: design fixed, fleet/RC/GA artifact implementation started
- Next execution focus:
  - PR151 compatibility evidence pack
  - PR152 weekly/release compatibility artifact wiring
  - PR153 v1.1 freeze evidence refresh
  - PR156 replay evidence normalization
  - PR161-165 bridge / verify-v2 / contract diff prototype
  - PR171-179 fleet governance packet
  - PR181-190 RC readiness packet
  - PR191-199 GA/LTS/support artifacts

## v0.3.9 (Phase81-90 baseline delivered)

- Plugin extension API (`patchgate.plugin.v1`) + sandbox controls
- CI provider abstraction (`github|generic`)
- Signed webhook and notification adapters (`slack|teams|generic`)
- Docs/site skeleton (`mkdocs.yml`), SDK templates, examples, contribution flow

## v1.0.0-rc (Phase91-100 baseline delivered)

- `policy verify-v1` migration readiness command
- Release/LTS policy sections in config (`release.*`, `compatibility.v1.*`)
- SLO/GA operational report commands (`xtask ops slo-report|ga-readiness`)
- LTS/GA/release workflows (`lts-backport.yml`, `ga-readiness.yml`, `release-ga.yml`)

## v1.0.x hardening+ops (Phase101-120 baseline delivered)

1. Plugin sandboxをOSレベル隔離へ拡張（process/network/fs制限の強制）
2. Plugin SDKを複数言語テンプレート化し、互換テストをCI化
3. Generic provider/Webhook/Notificationの契約テストと再送戦略を強化
4. `verify-v1` の厳格判定 + 運用データ校正 + profile化
5. リリース署名/証明書連携とSBOM標準（CycloneDX/SPDX）を本実装化
6. LTSバックポート半自動化 + SLA追跡 + 週次可視化

## Active next-phase backlog (Phase121+)

1. sandbox隔離のクロスプラットフォーム統一（macOS/Windows）
2. 非GitHub CI providerの実運用テンプレート化（GitLab/Jenkins等）
3. plugin配布の信頼基盤拡張（鍵ローテーション/失効/revocation）
4. `verify-v1` 推奨修正の自動提案（autofix/PR提案）
5. 配信障害の自動復旧ループ（dead-letter再処理の定期ジョブ化）
6. v1.1スコープ凍結とv2互換戦略の準備

## Active Phase121-130 slice

1. `policy verify-v1` に safe autofix の出力/適用を追加
2. `delivery replay` に残件書き戻し・summary 出力を追加
3. scheduled workflow で dead-letter 再処理を定期実行できるようにする
4. sandbox capability matrix を doctor / readiness に surfacing
5. GitLab / Jenkins 向け generic CI template を追加

## Active Phase151-160 slice

1. `xtask ops compatibility-report` で freeze / seed の判断 artifact を追加
2. weekly ops / ga-readiness / release-precheck に compatibility report を接続
3. `xtask ops freeze-scoreboard` で v1.1 freeze / v2 seed の gate artifact を追加
4. Phase151-200 の backcast と PR plan を固定
5. replay evidence を release precheck artifact に含める
6. generic provider / audit export / policy gate に v2 bridge prototype を追加

## Non-goals (current phase)

- Full remote source scan as primary path
- High-cost cloud inference in hot path
