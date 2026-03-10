# Phase Backcast (121+)

このドキュメントは、**Phase101-120 を一括実装した到達状態** を前提に、  
次フェーズ（Phase121+）のゴール逆算と残タスクを整理する設計です。

## 前提（2026-03-05）

- Phase1-100: baseline実装完了
- Phase101-110: GA hardening（sandbox/SDK/release/LTS強化）完了
- Phase111-120: 運用最適化（`verify-v1` 校正、配信QoS、provenance、SLA追跡）完了

## Phase120 の到達状態

- plugin実行がOS隔離・契約テスト・多言語SDKで運用可能
- publish/webhook/notificationが重複排除と再送を備え、QoS計測できる
- `policy verify-v1` が運用プロファイルと校正ループを持ち、CI必須ゲートとして機能
- GA/LTSリリースが署名・SBOM・provenance検証込みで再現可能
- LTS backportが半自動化され、遅延SLAを追跡できる

## 残タスク（優先順）

1. sandbox隔離のクロスプラットフォーム統一（macOS/Windows）
2. 非GitHub CI providerの実運用テンプレート化（GitLab/Jenkins等）
3. plugin配布の信頼基盤拡張（鍵ローテーション/失効/revocation）
4. `verify-v1` 推奨修正の自動提案（autofix/PR提案）
5. 配信障害の自動復旧ループ（dead-letter再処理の定期ジョブ化）
6. 大規模運用向け性能上限の再定義（高負荷時SLO/コスト）
7. 監査連携の標準化（SIEM向けエクスポート契約）
8. v1.1スコープ凍結とv2互換戦略の準備

## ゴール逆算マイルストーン

- M5: Cross-platform実行一貫性
  - Linux/macOS/Windowsでsandbox挙動と契約テスト結果を一致させる
- M6: Ecosystem信頼性
  - plugin配布物の署名検証・鍵運用・失効対応を標準運用に組み込む
- M7: Self-healing運用
  - 配信失敗の検知から再処理までを自動化し、SLA逸脱を事前抑止する
- M8: v1.1 GA readiness
  - 互換性・性能・監査要件を満たしたv1.1リリース判定を確立する

## 逆算した「最初に実装すること」（Phase121-130先行項目）

1. sandbox capability matrixとOS別互換テストを先に固定
2. provider adapter contract testをGitHub以外へ拡張
3. 署名鍵ローテーションとrevoke手順をworkflow化
4. `verify-v1` のautofix提案ルールをwarningカテゴリから段階導入
5. dead-letter再処理の定期実行ジョブと監視アラートを追加

## 完了判定（Phase121+の入口）

- クロスプラットフォームsandboxの最小互換ラインが定義済み
- provider/plugin/releaseの信頼性指標が週次レビューで追跡可能
- `verify-v1` の改善サイクルが手動調整から半自動運用へ移行
- 次期フェーズ（Phase121-130）のPR計画に着手可能な要件が揃っている
