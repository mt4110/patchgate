# V2 Migration Guide Alpha

このガイドは、`patchgate` の v1.1 運用から v2 bridge へ移るための最初の手順書です。

## 1. Freeze v1.1

- `patchgate policy verify-v1 --readiness-profile strict`
- `cargo run -p xtask -- ops freeze-boundary --output artifacts/v1.1-freeze-boundary.md`
- `cargo run -p xtask -- ops freeze-scoreboard ...`
- `docs/24_v11_freeze_boundary.md` の deferred / non-goal / v2-seed 分類を確認

## 2. Enable shadow mode

```toml
[compatibility.v2]
shadow_mode = true
bridge_mode = "full"
migration_guide_path = "docs/16_v2_migration_guide_alpha.md"

[integrations.ci]
generic_schema = "dual"

[observability]
audit_v2_jsonl_path = "artifacts/scan-audit-v2.jsonl"
audit_v2_schema_version = 2
```

## 3. Verify bridge contracts

- `patchgate policy verify-v2 --format text`
- `patchgate policy diff-contract --format text`
- `patchgate policy diff-contract --format json --enforce > artifacts/diff-contract.json`
- `patchgate policy verify-v2 --provider-input artifacts/provider-dual.json --audit-input artifacts/scan-audit.jsonl --audit-v2-input artifacts/scan-audit-v2.jsonl --plugin-shadow-input sdk/templates/python-plugin/sample-input.v2.json --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json --format text`
- `cargo run -p xtask -- ops shadow-review --provider-input artifacts/provider-dual.json --webhook-envelope-input examples/poc/compatibility-lab/webhook-shadow-envelope.json --notification-envelope-input examples/poc/compatibility-lab/notification-shadow-envelope.json ...`

## 4. Promotion criteria

- provider dual artifact が downstream で読める
- audit v2 artifact がSIEM handoffへ変換できる
- plugin template の `sample-input.v2.json` が `patchgate.plugin.v2-shadow` として検証できる
- webhook / notification bridge metadata が shadow traffic review に含まれる
- dual-run の event count が安定
- `compatibility-report.md` が `start-v2-seed`
- audit drift が 0
- `v1.1-freeze-boundary.md` の v2 option と risk register が RC gate に接続済み
- `xtask ops migration-drill` で生成した `migration-drill.json` が non-dry-run / zero failed repo / rollback rehearsed
- `rollback-packet.json` が `bridge_mode = "off"` / `generic_schema = "v1"` の復帰手順を保持
- `v2-rc-readiness.md` が contract freeze / audit export v2 / security / cost を green として出力

## 5. Rollback

- `bridge_mode = "off"` へ戻す
- `generic_schema = "v1"` へ戻す
- audit v2 artifact は保持しつつ、判定の主線を v1 に戻す
- rollback packet を更新し、v1 audit を authoritative signal として再確認する
