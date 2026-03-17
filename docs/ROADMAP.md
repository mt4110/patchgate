# Roadmap

This roadmap tracks the patchgate pivot.

## Detailed phase design

- [Phase Backcast (1-100)](06_phase_backcast_1_100.md)
- [Phase Backcast (121+)](10_phase_backcast_121_plus.md)
- [Current State and Next Steps](11_current_state_and_next_steps.md)
- [Phase101-120 Status](12_phase101_120_status.md)
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

## Active planning horizon (updated 2026-03-05)

- Implemented baseline: Phase1-100 (minimum viable contract)
- Phase101-120: baseline implementation in progress (partial complete)
- Next execution focus:
  - PR103/107 contract test hardening
  - PR111+/114+ operational automation closure

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

## v1.0.x hardening+ops (Phase101-120, partially implemented)

1. Plugin sandboxをOSレベル隔離へ拡張（process/network/fs制限の強制）
2. Plugin SDKを複数言語テンプレート化し、互換テストをCI化
3. Generic provider/Webhook/Notificationの契約テストと再送戦略を強化
4. `verify-v1` の厳格判定 + 運用データ校正 + profile化
5. リリース署名/証明書連携とSBOM標準（CycloneDX/SPDX）を本実装化
6. LTSバックポート半自動化 + SLA追跡 + 週次可視化

## Hypothetical remaining work after Phase120 (from backcast 121+)

1. sandbox隔離のクロスプラットフォーム統一（macOS/Windows）
2. 非GitHub CI providerの実運用テンプレート化（GitLab/Jenkins等）
3. plugin配布の信頼基盤拡張（鍵ローテーション/失効/revocation）
4. `verify-v1` 推奨修正の自動提案（autofix/PR提案）
5. 配信障害の自動復旧ループ（dead-letter再処理の定期ジョブ化）
6. v1.1スコープ凍結とv2互換戦略の準備

## Non-goals (current phase)

- Full remote source scan as primary path
- High-cost cloud inference in hot path
