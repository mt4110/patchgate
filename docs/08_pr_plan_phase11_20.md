# PR Plan: Phase11-20

`docs/06_phase_backcast_1_100.md` の Phase11-20 を対象にしたPR実装計画です。  
Phase1-10 が完了し、MVP基盤が固定されている前提で進めます。

## 方針

- 運用耐性（失敗時の挙動、復旧、計測）を優先
- GitHub連携とCLI出力の後方互換を維持
- Phase11-20 完了時点で「日常運用できる最小構成」を達成

## PR一覧

1. **PR11: policyバリデーション体系化**
   - 対応Phase: 11
   - 変更対象: `crates/patchgate-config/src/lib.rs`, `crates/patchgate-config/src/types.rs`
   - 完了条件: 入力不正がカテゴリ別に返る（型/範囲/相互依存）

2. **PR12: default/example整合**
   - 対応Phase: 12
   - 変更対象: `config/policy.toml.example`, `crates/patchgate-config/*`
   - 完了条件: デフォルト値とexampleの意味差分を解消

3. **PR13: doctor診断強化**
   - 対応Phase: 13
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: git状態、config読込、cache接続を診断表示

4. **PR14: GitHub publish部分成功処理**
   - 対応Phase: 14
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `crates/patchgate-cli/src/main.rs`
   - 完了条件: comment失敗/check成功などを区別して報告

5. **PR15: CI環境解決テスト**
   - 対応Phase: 15
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-cli/tests/*`
   - 完了条件: `GITHUB_EVENT_PATH`, `GITHUB_REF`, override引数の優先順を固定

6. **PR16: 出力後方互換ポリシー**
   - 対応Phase: 16
   - 変更対象: `docs/03_cli_reference.md`, `docs/01_concepts.md`
   - 完了条件: 互換ポリシー（追加可能/非推奨/破壊変更）を文書化

7. **PR17: cache破損復旧フロー**
   - 対応Phase: 17
   - 変更対象: `crates/patchgate-cli/src/main.rs`
   - 完了条件: DB破損時に再初期化または安全劣化運転が可能

8. **PR18: ベンチ基準値導入**
   - 対応Phase: 18
   - 変更対象: `crates/xtask/src/main.rs`, `docs/99_release_checklist.md`
   - 完了条件: 基準ケースで実行時間の記録と比較が可能

9. **PR19: 主要経路の結合テスト**
   - 対応Phase: 19
   - 変更対象: `crates/patchgate-cli/tests/*`, `crates/patchgate-core/tests/*`
   - 完了条件: `scan -> report -> (optional)publish` の回帰が検知できる

10. **PR20: リリース前チェック自動化拡張**
   - 対応Phase: 20
   - 変更対象: `.github/workflows/*`, `docs/99_release_checklist.md`
   - 完了条件: 手動確認項目をCIに移管し、残る手動項目を明示

## 依存関係

- PR14 は PR15 の環境解決仕様に依存
- PR17 は PR11/12 の設定エラー分類と整合させる
- PR20 は PR18/19 の成果を取り込んで最終化

## Phase20完了時のDefinition of Done

- 失敗時挙動（config不正、GitHub API失敗、cache破損）が再現テスト済み
- CLI/JSON/Markdown出力の互換方針が文書化済み
- リリース前に必要な確認の大半が自動実行できる
