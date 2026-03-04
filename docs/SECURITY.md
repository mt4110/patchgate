# Security Policy

Purpose: セキュリティポリシーと脆弱性報告の運用基準を定義します。

- Status: Active
- Last verified: 2026-03-03

## Supported versions

- Latest minor: security fixes対象
- LTS branch (`release.lts.branch`): critical/high security fixes対象

## Reporting a vulnerability

- 非公開報告を推奨（公開Issueでの0day共有は禁止）
- 報告には再現手順、影響範囲、暫定回避策を含める

## Security controls

- Least privilege token運用
- secret masking (`ghp_`, `github_pat_`, `Bearer ...`)
- plugin sandbox (`restricted`)
- signed webhook (`X-Patchgate-Signature`)
- waiver期限管理 (`waiver.entries[].expires_at`)

## SLA / LTS

- セキュリティ修正判断SLA: `release.lts.security_sla_hours`
- LTS対象修正は `backport/lts-v1` ラベルで管理
