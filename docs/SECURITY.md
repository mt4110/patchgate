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
- plugin配布鍵 lifecycle（`trusted_key_envs` によるrotation、`revoked_key_sha256` による失効）
- signed webhook (`X-Patchgate-Signature`)
- waiver期限管理 (`waiver.entries[].expires_at`)
- audit dual-write (`patchgate.audit.v1` / `patchgate.audit.v2`) による移行追跡

## Sandbox capability baseline

- `none`: 全hostで利用可能。ただし隔離なし
- `restricted`: 全hostで利用可能。env allowlist と process 制限が中心
- `isolated`: Linux + `bwrap` 前提。strict / lts readiness で plugin有効時の推奨ライン

`patchgate doctor` と `patchgate policy verify-v1` は、現在の host で `isolated` が有効かを表示します。

## Plugin distribution key lifecycle

1. 通常運用では `plugins.signature.public_key_env` に現行の ed25519 public key（base64）を置きます。
2. rotation開始時は新鍵の public key を別envに登録し、`plugins.signature.trusted_key_envs` に追加します。runner は主鍵と追加鍵のどちらかで署名検証できれば通します。
3. 新鍵で署名したpluginが全runnerで通ることを `.github/workflows/plugin-trust-rollout.yml` で確認してから、`public_key_env` を新鍵envへ昇格し、旧鍵envを削除します。
4. 鍵漏えい・誤配布・旧鍵の即時停止が必要な場合は、raw 32-byte ed25519 public key の sha256 hex を `plugins.signature.revoked_key_sha256` に追加します。revoked fingerprint に一致する鍵は、署名が正しくても検証に使われません。

## SLA / LTS

- セキュリティ修正判断SLA: `release.lts.security_sla_hours`
- LTS対象修正は `backport/lts-v1` ラベルで管理
