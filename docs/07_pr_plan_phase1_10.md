# PR Plan: Phase1-10

`docs/06_phase_backcast_1_100.md` の Phase1-10 を、レビューしやすいPR単位に分解した計画です。

## 方針

- 1 PR = 1テーマ（大きくても2フェーズ分まで）
- 各PRで `実装 / テスト / docs` を完結
- `patchgate-cli` の外部I/F (CLI引数、JSON主要キー) は維持

## PR一覧

1. **PR01: 開発基盤の固定**
   - 対応Phase: 1
   - 変更対象: `justfile`, `.github/workflows/*`, `docs/PRECOMMIT.md`
   - 完了条件: CIで `fmt/lint/test` が共通手順で通る

2. **PR02: scan系エラー制御の統一**
   - 対応Phase: 2
   - 変更対象: `crates/patchgate-cli/src/main.rs`
   - 完了条件: エラー分類と終了コードのテスト追加、メッセージ一貫化

3. **PR03: ScopeMode境界テスト**
   - 対応Phase: 3
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-core/tests/*`
   - 完了条件: `staged/worktree/repo` の差分取得仕様がテストで固定

4. **PR04: test_gap誤検知低減**
   - 対応Phase: 4
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `config/policy.toml.example`
   - 完了条件: 代表ケース(テスト有/無、除外対象)で誤判定率を低減

5. **PR05: dangerous_change判定整理**
   - 対応Phase: 5
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `config/policy.toml.example`
   - 完了条件: critical/non-critical の境界が設定ファイルで説明可能

6. **PR06: dependency_update精度改善**
   - 対応Phase: 6
   - 変更対象: `crates/patchgate-core/src/runner.rs`
   - 完了条件: manifest/lockfile差分の検知テストが拡充される

7. **PR07: スコア境界値テスト固定**
   - 対応Phase: 7
   - 変更対象: `crates/patchgate-core/src/model.rs`, `crates/patchgate-core/tests/*`
   - 完了条件: `score`, `review_priority`, `threshold` の境界テスト網羅

8. **PR08: JSON契約の明文化**
   - 対応Phase: 8
   - 変更対象: `docs/03_cli_reference.md`, `docs/01_concepts.md`
   - 完了条件: JSONキーの意味、互換性方針、必須/任意を明記

9. **PR09: GitHubコメント改善**
   - 対応Phase: 9
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/patchgate-action.yml`
   - 完了条件: 重要findingと優先度が先頭で読めるコメントに更新

10. **PR10: キャッシュキー固定**
   - 対応Phase: 10
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/ARCHITECTURE.md`
   - 完了条件: cache hit/miss 条件が仕様化され、再現テストが通る

## 依存関係

- PR04, PR05, PR06 は PR03 の差分境界テストを前提
- PR09 は PR08 の出力契約定義後に着手
- PR10 は PR07 のスコア仕様固定後に着手

## 受け入れゲート

- 全PRで `cargo test --workspace` が通る
- CLIの主要利用例 (`scan --mode warn|enforce --format text|json`) が回帰しない
- docs更新が同PRに含まれる
