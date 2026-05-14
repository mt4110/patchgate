# V2 Support Model

v2 GA 後の support / escalation ルールをまとめます。

## Support bands

- `critical`: service blocking / security / rollback trigger
- `standard`: migration question / contract drift / provider compatibility
- `advisory`: docs mismatch / template improvement / future backcast feedback

## Escalation

1. `compatibility-report.md` と `v1.1-readiness.md` を確認
2. `v1.1-freeze-boundary.md` で scope / deferred / risk register の前提差分を確認
3. `shadow-review.md` と `fleet-review.md` で drift を切り分け
4. `v2-rc-readiness.md` または `v2-ga-packet.md` で gate failure を確認
5. `rollback-packet.json` で復帰先が `bridge_mode = "off"` / `generic_schema = "v1"` になっているか確認
6. rollback trigger に一致する場合は v1 audit を authoritative signal として戻す

## Ownership

- release owner: GA packet / LTS branch / release workflow の判断を持つ
- support owner: support band triage と customer-facing escalation を持つ
- security owner: security / critical fix と LTS backport SLA の判断を持つ
- telemetry owner: post-GA telemetry review と regression handoff を持つ

## Response expectations

- critical: 24h以内に一次判断
- standard: 3 business days 以内に triage
- advisory: 次回 roadmap review で整理

## Escalation Artifacts

- `artifacts/v2-ga-packet.md`
- `artifacts/ecosystem-migration-completion.md`
- `artifacts/dual-run-decommission.md`
- `artifacts/post-ga-telemetry-review.md`
- `artifacts/retrospective-cleanup-queue.md`
