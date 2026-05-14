# V1 Sunset Notice

この通知は v1.1 利用者向けに、v2 GA 後の移行期限を surprise なく伝えるための雛形です。

## Notice

- v1.1 は security / critical fix のみを継続
- 新機能は v2 系へ集約
- dual-run 終了後は v1 provider / audit bridge を段階的に停止

## Compatibility Contract

- v1.1 compatibility window は GA 公開日から +90 日を標準とする
- provider compatibility は v1 reader の復帰手順が `rollback-packet.json` に残っていることを条件に縮小する
- audit v1 は +90 review まで authoritative fallback として保持する
- support model は `docs/22_v2_support_model.md` を正とし、critical case は sunset window 中も v1 rollback を扱えること
- warning escalation は +60 marker 以降に v1-only provider / audit v1-only signal へ付与する

## Suggested timeline

1. GA 公開日: `v2` を主線として告知
2. +30日: `verify-v2` / `diff-contract` / migration guide の再通知
3. +60日: v1-only provider の warning 強化
4. +90日: dual-run decommission review

## Countdown markers

- +30: migration reminder and `diff-contract --enforce` evidence refresh
- +60: v1-only provider warning escalation
- +90: dual-run rollback/decommission review with `v2-ga-packet.md`

## Required artifacts

- `v2-ga-packet.md`
- `docs/16_v2_migration_guide_alpha.md`
- `docs/22_v2_support_model.md`
