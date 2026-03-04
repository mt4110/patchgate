# Contributing

`patchgate` への提案・実装・運用変更の共通フローです。

## Scope

- 対象: code / policy / docs / workflow / plugin / integration
- 互換性は `v1` 契約を優先し、破壊的変更は移行ガイド同時提出を必須とします。

## Proposal flow

1. `docs/06_phase_backcast_1_100.md` と `docs/ROADMAP.md` の該当フェーズを確認する。
2. PR本文に以下を明記する。
   - 目的
   - 互換性への影響
   - ロールバック手順
   - 監査証跡（metrics/audit/release artifact）
3. policy変更を含む場合は `policy-approved` ラベルを付与する。

## Compatibility rules

- 既存JSONキーの削除は禁止（追加は optional のみ）
- 既存CLIオプションの削除は禁止（非推奨化は1 minor以上の猶予）
- plugin APIは `patchgate.plugin.v1` を維持し、破壊変更は `v2` 新設で対応

## Plugin contribution

- 公式テンプレート: `sdk/templates/python-plugin`
- pluginは JSON stdin/stdout 契約に従うこと
- `plugins.sandbox.profile = "restricted"` で動作すること

## Review gates

- `just ci-check`
- `cargo run -p patchgate-cli -- policy lint --path config/policy.toml.example --require-current-version`
- `cargo run -p patchgate-cli -- policy verify-v1 --path config/policy.toml.example`
- 必要時: `cargo run -p xtask -- ops slo-report --metrics-input <file> --output <file>`

## Maintainer operations

- LTS対象修正は `backport/lts-v1` ラベルを使用
- security修正は `release.lts.security_sla_hours` 以内に判断
- GA判定は `ga-readiness.yml` の出力を根拠に実施
