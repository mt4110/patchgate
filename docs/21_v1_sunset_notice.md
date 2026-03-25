# V1 Sunset Notice

この通知は v1.1 利用者向けに、v2 GA 後の移行期限を surprise なく伝えるための雛形です。

## Notice

- v1.1 は security / critical fix のみを継続
- 新機能は v2 系へ集約
- dual-run 終了後は v1 provider / audit bridge を段階的に停止

## Suggested timeline

1. GA 公開日: `v2` を主線として告知
2. +30日: `verify-v2` / `diff-contract` / migration guide の再通知
3. +60日: v1-only provider の warning 強化
4. +90日: dual-run decommission review

## Required artifacts

- `v2-ga-packet.md`
- `docs/16_v2_migration_guide_alpha.md`
- `docs/22_v2_support_model.md`
