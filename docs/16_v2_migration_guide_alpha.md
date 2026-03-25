# V2 Migration Guide Alpha

このガイドは、`patchgate` の v1.1 運用から v2 bridge へ移るための最初の手順書です。

## 1. Freeze v1.1

- `patchgate policy verify-v1 --readiness-profile strict`
- `cargo run -p xtask -- ops freeze-scoreboard ...`

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
- `cargo run -p xtask -- ops shadow-review ...`

## 4. Promotion criteria

- dual-run の event count が安定
- `compatibility-report.md` が `start-v2-seed`
- audit drift が 0

## 5. Rollback

- `bridge_mode = "off"` へ戻す
- `generic_schema = "v1"` へ戻す
- audit v2 artifact は保持しつつ、判定の主線を v1 に戻す
