# Phase101-120 Implementation Status (2026-03-05)

このドキュメントは、Phase101-120計画に対する実装進捗と残タスクを整理します。

## 実装済み（このスプリント）

- PR101-102 (部分): plugin sandbox `isolated` profile を追加
  - Linuxでは `bwrap` 利用時にOS隔離実行
  - `verify-v1` strict/lts profileで `isolated` を要求
- PR104-105: SDK多言語テンプレート + `patchgate plugin init`
  - `python|node|rust` テンプレート生成
- PR106 (部分): delivery idempotency key (`X-Patchgate-Idempotency-Key`)
- PR108/111/112 (部分): `policy verify-v1 --readiness-profile <standard|strict|lts>`
  - autofix候補出力を追加
- PR113-114 (部分): dead-letter JSONL出力と再送強化
  - `--dead-letter-output`
  - webhook retry (`--webhook-retry-max-attempts`)
- PR109/117 (部分): release workflowに provenance metadata を追加
- PR118 (部分): LTS backport workflowにSLA age checkを追加

## 未完了（残タスク）

1. PR103: plugin contract test harness の本実装（CI固定）
2. PR107: generic/webhook/notification の契約テスト網羅
3. PR109: 実署名（鍵管理）と標準SBOMの厳密運用（現状はmetadata生成中心）
4. PR110/118: LTS backport 自動PR起票・conflict report 自動生成
5. PR111: verify-v1 判定ルールの運用データ校正パイプライン
6. PR114: dead-letter 再処理コマンド（replay）の実装
7. PR115-116: SDK互換テストのCI標準化 + plugin配布署名検証
8. PR119-120: インシデント演習テンプレート強化 + v1.1 readiness最終判定

## 次アクション（実装順）

1. PR103（plugin contract test）
2. PR107（delivery contract test）
3. PR114 replay + PR111校正パイプライン
