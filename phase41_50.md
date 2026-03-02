# PR Plan: Phase41-50

`docs/06_phase_backcast_1_100.md` の Phase41-50（性能とスケール）を対象にしたPR実装計画です。  
Phase31-40 までで固めた運用安定性を維持したまま、実行コストと大規模差分耐性を引き上げます。

## 方針

- スループット改善より先に、判定結果の決定性と再現性を崩さない
- 性能最適化は「計測可能な指標」とセットで導入する
- Linux/macOS/Windows で回帰検知できるベンチ運用を標準化する

## PR一覧

1. **PR41: diff収集パスのプロセス起動最適化**
   - 対応Phase: 41
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-cli/src/main.rs`
   - 完了条件: 同一scan中のgit呼び出し重複を削減し、実行時間短縮をベンチで確認

2. **PR42: 大規模差分向けメモリ使用量削減**
   - 対応Phase: 42
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-core/tests/*`
   - 完了条件: 変更ファイル数が多いケースでピークメモリが抑制され、既存判定と一致

3. **PR43: チェック並列化基盤の導入**
   - 対応Phase: 43
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-core/src/model.rs`
   - 完了条件: `test_gap`/`dangerous_change`/`dependency_update` の評価を並列実行可能にし、結果順序契約を固定

4. **PR44: cache I/Oバッチ化**
   - 対応Phase: 44
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-cli/tests/*`
   - 完了条件: cache read/writeの往復回数を削減し、破損復旧フローとの整合を維持

5. **PR45: 変更ファイル数上限時の挙動定義**
   - 対応Phase: 45
   - 変更対象: `crates/patchgate-config/src/types.rs`, `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: 上限超過時の `fail-open/fail-closed` 方針とexit code/警告が明文化される

6. **PR46: プロファイル計測コマンド追加**
   - 対応Phase: 46
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/xtask/src/main.rs`, `docs/04_recipes.md`
   - 完了条件: `scan` の処理時間内訳（diff/各check/cache/publish）を機械可読で出力可能

7. **PR47: 10kファイル想定の負荷試験整備**
   - 対応Phase: 47
   - 変更対象: `config/benchmarks/*`, `crates/xtask/src/main.rs`, `.github/workflows/*`
   - 完了条件: 10kファイル相当シナリオの再現可能な負荷試験ジョブを提供

8. **PR48: Windows性能劣化の診断と是正**
   - 対応Phase: 48
   - 変更対象: `.github/workflows/ci.yml`, `docs/05_troubleshooting.md`, `docs/99_release_checklist.md`
   - 完了条件: Windows固有のボトルネックを特定し、暫定回避策または恒久対策を文書化

9. **PR49: 実行時間SLO (P95) 定義**
   - 対応Phase: 49
   - 変更対象: `docs/01_concepts.md`, `docs/99_release_checklist.md`
   - 完了条件: 対象スコープ別のP95 SLOと測定条件が固定される

10. **PR50: 性能回帰CIゲート導入**
   - 対応Phase: 50
   - 変更対象: `.github/workflows/release-precheck.yml`, `config/benchmarks/*`, `docs/03_cli_reference.md`
   - 完了条件: ベースライン比較で閾値超過時にCIが失敗し、差分レポートを出力

## 依存関係

- PR42/43 は PR41 でdiff収集コストを安定化してから実施
- PR44/45 は PR42/43 の負荷特性を踏まえて境界条件を定義
- PR46 は PR41-45 の計測可視化として導入
- PR47-50 は計測基盤（PR46）を前提に段階導入

## Phase50完了時のDefinition of Done

- `scan` の性能改善が定量指標（P50/P95/ピークメモリ）で示される
- 大規模差分・多ファイル変更でも判定結果の再現性が維持される
- OS差異を含む性能回帰がCIで自動検知される
- 運用者が性能劣化を診断できる計測手段とrunbookが整備される
