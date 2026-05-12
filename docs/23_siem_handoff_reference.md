# 23 SIEM Handoff Reference

Purpose: `patchgate.audit.v2` を外部SIEMへ渡すための最小契約と参照workflowを固定します。

- Status: Active
- Last verified: 2026-05-12

## Flow

1. `patchgate scan` で `--audit-log-v2-output artifacts/scan-audit-v2.jsonl` を出力する
2. `cargo run -p xtask -- ops siem-handoff --audit-v2-input artifacts/scan-audit-v2.jsonl --output artifacts/siem-handoff.jsonl` でflat JSONLへ正規化する
3. `artifacts/siem-handoff.jsonl` をartifactとして保管し、必要に応じてSIEM ingest jobへ渡す

## Event Contract

各行は1イベントです。

- `schema_version`: SIEM handoff schema。現在は `1`
- `event_kind`: `quality_gate.audit`
- `source_format`: 元audit format。通常は `patchgate.audit.v2`
- `source_schema_version`: 元audit schema version
- `event_time_unix`: event timestamp
- `repo`, `actor`, `target`, `mode`, `scope`, `result`
- `severity`: `info` / `warning` / `error`
- `score`, `threshold`, `changed_files`
- `failure_code`, `failure_category`
- `diagnostic_count`, `diagnostics`

Input validation rejects rows that are not `patchgate.audit.v2`, have unsupported schema versions, carry unknown failure codes, or omit required identity fields such as `repo`, `actor`, `target`, `mode`, and `scope`.

## Reference Workflow

`.github/workflows/siem-handoff.yml` は、scanからhandoff JSONL生成までを行い、artifactとして保存します。外部送信は環境ごとのsecret・retention・masking方針に差が出やすいため、この参照実装ではartifact境界までに留めます。
