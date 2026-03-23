# Security Policy

Purpose: セキュリティポリシーと脆弱性報告の運用基準を定義します。

- Status: Active
- Last verified: 2026-03-20

## Supported versions

- Latest minor: security fixes対象
- LTS branch (`release.lts.branch`): critical/high security fixes対象

## Reporting a vulnerability

- 非公開報告を推奨（公開Issueでの0day共有は禁止）
- 報告には再現手順、影響範囲、暫定回避策を含める

## Security controls

- Least privilege token運用
- secret masking (`ghp_`, `github_pat_`, `Bearer ...`)
- plugin sandbox (`restricted` / `isolated` with Linux `bwrap`)
- plugin署名検証（`plugins.signature.required = true` + ed25519）
- signed webhook (`X-Patchgate-Signature`)
- waiver期限管理 (`waiver.entries[].expires_at`)

## Sandbox capability baseline

- `none`: 全hostで利用可能。ただし隔離なし
- `restricted`: 全hostで利用可能。env allowlist と process 制限が中心
- `isolated`: Linux + `bwrap` 前提。strict / lts readiness で plugin有効時の推奨ライン

`patchgate doctor` と `patchgate policy verify-v1` は、現在の host で `isolated` が有効かを表示します。

## SLA / LTS

- セキュリティ修正判断SLA: `release.lts.security_sla_hours`
- LTS対象修正は `backport/lts-v1` ラベルで管理
