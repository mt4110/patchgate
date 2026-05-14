# V2 GA Go / No-Go Review

このレビューは `xtask ops ga-packet` の入力として、GA 判断を進める理由と止める理由を同じ場所で確認するためのテンプレートです。

## Required Evidence

- RC readiness: `artifacts/v2-rc-readiness.md`
- rollback packet: `artifacts/rollback-packet.json`
- v1 sunset notice: `docs/21_v1_sunset_notice.md`
- support path: `docs/22_v2_support_model.md`
- LTS policy: `artifacts/policy.v2.toml`

## Go Conditions

- RC readiness packet is green
- rollback remains available through dual-run
- v1 sunset countdown markers are published
- support and escalation owners are named
- audit drift, benchmark, and cost sign-off have no open blocker

## No-Go Conditions

- RC readiness is missing or red
- rollback cannot restore `bridge_mode = "off"` and `generic_schema = "v1"`
- v1 sunset notice lacks +30 / +60 / +90 markers
- support or security SLA owner is missing
- benchmark or fleet cost sign-off regresses

## Decision

- [ ] Go
- [ ] No-go
