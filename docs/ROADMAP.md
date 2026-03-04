# Roadmap

This roadmap tracks the patchgate pivot.

## Detailed phase design

- [Phase Backcast (1-100)](06_phase_backcast_1_100.md)
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

## Active planning horizon (updated 2026-03-03)

- Completed baseline implementation: Phase1-100 (minimum viable contract)
- Stabilization focus after batch implementation:
  - plugin ecosystem hardening (sandbox isolation/SDK UX/conformance)
  - v1 migration strictness uplift (`verify-v1` pass by default)
  - LTS/GA workflow hardening (signing, SBOM, backport automation)

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

## Remaining work to GA hardening

1. Plugin sandboxをOSレベル隔離へ拡張（process/network/fs制限の強制）
2. Plugin SDKを複数言語テンプレート化し、互換テストをCI化
3. Generic provider/Webhook/Notificationの契約テストと再送戦略を強化
4. `verify-v1` の判定ルールを実運用データで調整
5. リリース署名/証明書連携とSBOM標準（CycloneDX/SPDX）を本実装化
6. LTSバックポート自動化（cherry-pick bot / conflict report）

## Non-goals (current phase)

- Full remote source scan as primary path
- High-cost cloud inference in hot path
