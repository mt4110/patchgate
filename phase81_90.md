# PR Plan: Phase81-90

## 実装ステータス（2026-03-03）

- PR81-PR90: 設計完了（実装未着手）

`docs/06_phase_backcast_1_100.md` の Phase81-90（拡張性とエコシステム）を対象にしたPR実装計画です。  
Phase71-80 までで固めた運用/ガバナンス基盤を、外部拡張と採用拡大に耐える形へ進化させます。

## 方針

- 拡張性は「何でもできる」よりも「壊れない契約」を優先して定義する
- 外部連携は最初に最小契約を固定し、プロバイダ個別差分はアダプタ層に隔離する
- プラグイン/配布物はセキュリティ検証（署名・権限・実行隔離）を前提に設計する

## PR一覧

1. **PR81: 外部チェックプラグインAPI契約の策定**
   - 対応Phase: 81
   - 変更対象: `crates/patchgate-core/src/model.rs`, `docs/01_concepts.md`, `docs/03_cli_reference.md`
   - 完了条件: 入出力スキーマ、エラー契約、互換性ポリシーを明文化し、拡張ポイントを固定

2. **PR82: プラグイン実行sandbox方針の導入**
   - 対応Phase: 82
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-config/src/types.rs`, `docs/05_troubleshooting.md`
   - 完了条件: タイムアウト/リソース制限/権限境界を設定可能にし、失敗時の診断契約を追加

3. **PR83: 公式プラグインSDK雛形の提供**
   - 対応Phase: 83
   - 変更対象: `sdk/*`（新規）, `docs/04_recipes.md`, `docs/00_quickstart.md`
   - 完了条件: 最小プラグインを生成・実行できるテンプレートと開発手順を提供

4. **PR84: ルール配布形式（registry/package）設計**
   - 対応Phase: 84
   - 変更対象: `docs/01_concepts.md`, `docs/02_config_reference.md`, `docs/99_release_checklist.md`
   - 完了条件: 配布メタデータ、署名検証、バージョン解決の契約を定義

5. **PR85: CI provider抽象化（非GitHub対応）**
   - 対応Phase: 85
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-github/src/lib.rs`, `docs/03_cli_reference.md`
   - 完了条件: provider依存処理を抽象化し、GitHub以外向けの最小アダプタIFを公開

6. **PR86: Webhook連携基盤の追加**
   - 対応Phase: 86
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/04_recipes.md`, `.github/workflows/*`
   - 完了条件: 実行結果を署名付きWebhookイベントで外部配信可能

7. **PR87: カスタム通知先連携（Slack/Teams等）**
   - 対応Phase: 87
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/04_recipes.md`, `docs/05_troubleshooting.md`
   - 完了条件: 通知先アダプタの共通ペイロード契約と再送ポリシーを実装

8. **PR88: ドキュメントサイト情報設計の整備**
   - 対応Phase: 88
   - 変更対象: `docs/*`, `mkdocs.yml` or `site/*`（新規）
   - 完了条件: バージョン別参照・検索・移行導線を含む構成を提供

9. **PR89: サンプルリポジトリ群と適合テスト整備**
   - 対応Phase: 89
   - 変更対象: `examples/*`（新規）, `tests/*`, `docs/04_recipes.md`
   - 完了条件: 主要ユースケースを再現できるサンプルと自動適合テストを提供

10. **PR90: コミュニティ運用ガイド公開**
    - 対応Phase: 90
    - 変更対象: `CONTRIBUTING.md`, `docs/ROADMAP.md`, `docs/99_release_checklist.md`
    - 完了条件: 提案〜採用フロー、互換性判断基準、メンテナ運用ルールを明文化

## 依存関係

- PR81/82 を先行し、拡張契約と実行境界を固定
- PR83/84 は拡張を第三者が配布・再利用できる状態へ拡張
- PR85-87 は統合面（CI/通知/イベント）を段階的に広げる
- PR88-90 は採用・運用を持続可能にする公開資産/体制を整備

## Phase90完了時のDefinition of Done

- 外部拡張APIが互換性契約付きで公開され、sandboxで安全に実行できる
- 配布・通知・CI連携が標準インタフェースで扱え、実装差分を局所化できる
- サンプル/ドキュメント/運用ガイドにより、第三者が自走導入できる
- コミュニティ提案から採用までの判断フローが再現可能になっている
