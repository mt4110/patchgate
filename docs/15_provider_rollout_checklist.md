# Provider Rollout Checklist

このチェックリストは、generic provider の `v1` / `v2` / `dual` rollout を安全に進めるための運用テンプレートです。

## Before rollout

- `patchgate policy verify-v2 --format text`
- `patchgate policy diff-contract --format text`
- `patchgate policy diff-contract --format json --enforce > artifacts/diff-contract.json`
- `cargo run -p xtask -- ops compatibility-report ...`
- `cargo run -p xtask -- ops freeze-scoreboard ...`
- `cargo run -p xtask -- ops freeze-boundary --output artifacts/v1.1-freeze-boundary.md`
- `docs/24_v11_freeze_boundary.md` で generic provider v1 が v1.1 stable boundary、v2 provider payload が v2-seed boundary に分類されていることを確認

## Shadow rollout

- `integrations.ci.generic_schema = "dual"` を有効化
- `observability.audit_v2_jsonl_path` を設定
- `cargo run -p xtask -- ops shadow-review ...` を収集
- event count / failure count / diagnostics count を v1 と比較

## Promotion gate

- `shadow-review.md` の event delta が説明可能
- `audit-drift-report.md` に未知コードがない
- audit export v2 validation が schema version 2、`patchgate.audit.v2`、gate fields、v1/v2 repo/mode/scope set を確認済み
- `freeze_ready = true`
- `v2_seed_ready = true`
- provider breaking-change boundary が `v1.1-freeze-boundary.md` と一致
- RC readiness packet が rollback packet と cost sign-off を参照している

## Rollback trigger

- v2 側 failure が v1 を上回る
- generic provider artifact が downstream CI で読めない
- audit v2 dual-write の欠落が継続する
- fleet review の repo / segment cost が ceiling を超える
