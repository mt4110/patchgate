# Phase Backcast (201+)

Phase201+ では、v2 GA/LTS 後の steady-state 運用と、
次の大きな互換境界をどう扱うかを逆算します。

## 想定テーマ

- fleet-wide policy orchestration
- registry-backed plugin distribution
- long-lived support / sunset automation
- cost-aware governance for dual-stack removal

## Entry conditions

- v2 GA / LTS が安定
- v1 sunset 計画が公開済み
- shadow/bridge が不要な領域を切り離せる

## First planning packets

- ecosystem migration completion: `artifacts/ecosystem-migration-completion.md`
- dual-run decommission: `artifacts/dual-run-decommission.md`
- post-GA telemetry: `artifacts/post-ga-telemetry-review.md`
- retrospective cleanup: `artifacts/retrospective-cleanup-queue.md`

## Phase201-210 candidates

1. v2-only provider contract を downstream template の標準へ移す
2. audit v2 SIEM handoff を steady-state dashboard へ接続する
3. LTS branch `lts/v2` の security / critical fix SLA を週次で確認する
4. v1 sunset warning を support queue と docs refresh に接続する
5. dual-run decommission 後に残す rollback fixture と削除する bridge fixture を分ける
