# PR Plan: Phase71-80

## 実装ステータス（2026-03-02）

- PR71-PR80: 実装済み（CLI/Config/Core/GitHub/Workflow/Docs反映）

`docs/06_phase_backcast_1_100.md` の Phase71-80（セキュリティ/ガバナンス）を対象にしたPR実装計画です。  
Phase61-70 で整備した可観測性を土台に、監査対応と権限制御を標準運用へ引き上げます。

## 方針

- セキュリティ強化は「運用不能な厳格化」を避け、段階導入可能な設計にする
- 例外運用（waiver）は必ず期限と承認履歴を持つ形で管理する
- 監査証跡は人間可読と機械可読の両方を提供し、外部監査に再利用できる形で固定する

## PR一覧

1. **PR71: 認証トークン最小権限ガイドと検証追加**
   - 対応Phase: 71
   - 変更対象: `docs/01_concepts.md`, `docs/03_cli_reference.md`, `.github/workflows/*`
   - 完了条件: 必要権限一覧と過剰権限検知ルールを明文化し、CIで逸脱を検知

2. **PR72: 秘匿情報マスキングの強化**
   - 対応Phase: 72
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `crates/patchgate-cli/src/main.rs`, `docs/05_troubleshooting.md`
   - 完了条件: token/secret/pattern類似値の出力マスクを強化し、ログリークを防止

3. **PR73: 監査証跡フォーマットの固定**
   - 対応Phase: 73
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/02_config_reference.md`, `docs/03_cli_reference.md`
   - 完了条件: 監査ログのバージョン付きスキーマを定義し、後方互換ルールを設定

4. **PR74: 組織制約（SSO/Org Policy）対応方針の実装**
   - 対応Phase: 74
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `docs/04_recipes.md`, `docs/05_troubleshooting.md`
   - 完了条件: SSO未承認・Org制限時の失敗分類/案内メッセージ/回避手順を標準化

5. **PR75: ルール変更の承認フロー導入**
   - 対応Phase: 75
   - 変更対象: `crates/patchgate-config/src/lib.rs`, `.github/workflows/*`, `docs/99_release_checklist.md`
   - 完了条件: policy変更を承認ラベル/CODEOWNERS連携で強制できる運用テンプレを提供

6. **PR76: waiver（例外承認）の期限管理**
   - 対応Phase: 76
   - 変更対象: `crates/patchgate-config/src/types.rs`, `config/policy.toml.example`, `docs/02_config_reference.md`
   - 完了条件: waiverに有効期限・理由・承認者を必須化し、期限切れを検知

7. **PR77: 監査レポート自動生成**
   - 対応Phase: 77
   - 変更対象: `crates/xtask/src/main.rs`, `.github/workflows/*`, `docs/04_recipes.md`
   - 完了条件: 期間指定で監査レポート（例外一覧/失敗分類/変更履歴）を自動出力

8. **PR78: コンプライアンスチェックリスト整備**
   - 対応Phase: 78
   - 変更対象: `docs/99_release_checklist.md`, `docs/01_concepts.md`
   - 完了条件: リリース/運用時に確認すべき必須項目をチェックリスト化

9. **PR79: サプライチェーン観点の補助検知追加**
   - 対応Phase: 79
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-core/src/model.rs`, `docs/01_concepts.md`
   - 完了条件: 依存更新と危険ファイル変更を横断した補助シグナルを出力可能

10. **PR80: セキュリティレビュー定例化テンプレート**
    - 対応Phase: 80
    - 変更対象: `docs/04_recipes.md`, `docs/99_release_checklist.md`, `.github/workflows/*`
    - 完了条件: 定例レビューの入力（履歴/例外/失敗分類）と判定基準を運用テンプレ化

## 依存関係

- PR71-74 は認証・ログ・監査の基盤契約を先に固定
- PR75/76 は policy変更と例外運用の統制ルールとして後続導入
- PR77/78 は監査実務の自動化と標準化を整備
- PR79/80 はセキュリティ観点の検知強化と定例運用へ接続

## Phase80完了時のDefinition of Done

- 認証・ログ・監査の契約が統一され、漏えい/権限逸脱リスクを抑制できる
- policy変更とwaiverが承認・期限・理由付きで追跡可能
- 監査レポートを定期自動生成し、コンプライアンス確認を継続実施できる
- セキュリティレビューが定例運用として再現可能な手順で回る
