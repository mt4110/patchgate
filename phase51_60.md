# PR Plan: Phase51-60

`docs/06_phase_backcast_1_100.md` の Phase51-60（言語別検知の強化）を対象にしたPR実装計画です。  
Phase41-50 で確立した性能基盤を活かし、主要言語・モノレポ運用での誤検知/見逃しを減らします。

## 方針

- ルール追加は「誤検知率の低下」と「計算コスト」の両面で評価する
- 言語ごとの差異は共通契約（finding schema, score, severity）を維持して実装する
- 既存利用者への影響を抑えるため、段階的有効化（opt-in/既定値）を明示する

## PR一覧

1. **PR51: Rust向けテスト検知精度改善**
   - 対応Phase: 51
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `config/policy.toml.example`, `docs/02_config_reference.md`
   - 完了条件: `mod tests`, integration tests, workspace構成の検知漏れを削減

2. **PR52: TypeScript向けテスト検知精度改善**
   - 対応Phase: 52
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `docs/04_recipes.md`
   - 完了条件: `vitest/jest` 系パターンの判定精度を改善し、既存TSリポジトリで回帰なし

3. **PR53: Python向けテスト検知精度改善**
   - 対応Phase: 53
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `config/policy.toml.example`
   - 完了条件: `pytest/unittest` の命名・配置差異を吸収し、過剰penaltyを抑制

4. **PR54: Go向けテスト検知精度改善**
   - 対応Phase: 54
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `docs/02_config_reference.md`
   - 完了条件: `*_test.go` と package境界の扱いを整理し、誤判定を低減

5. **PR55: Java/Kotlin向け検知追加**
   - 対応Phase: 55
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `config/policy.toml.example`, `docs/01_concepts.md`
   - 完了条件: `src/test` 系ディレクトリと主要buildツール構成を検知できる

6. **PR56: 依存更新リスクのエコシステム別拡張**
   - 対応Phase: 56
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `crates/patchgate-config/src/types.rs`
   - 完了条件: npm/pip/cargo/go等でmanifest/lock差分の重みを個別制御可能

7. **PR57: lockfile差分の重大度モデル拡張**
   - 対応Phase: 57
   - 変更対象: `crates/patchgate-core/src/model.rs`, `crates/patchgate-core/src/runner.rs`
   - 完了条件: churn量だけでなく変更タイプ（追加/削除/大規模更新）をseverityへ反映

8. **PR58: 生成コードの扱い方針追加**
   - 対応Phase: 58
   - 変更対象: `crates/patchgate-config/src/types.rs`, `config/policy.toml.example`, `docs/03_cli_reference.md`
   - 完了条件: 生成コードの除外/減衰ルールを設定可能にし、運用方針を明文化

9. **PR59: モノレポ向けパッケージ境界判定**
   - 対応Phase: 59
   - 変更対象: `crates/patchgate-core/src/runner.rs`, `docs/04_recipes.md`, `docs/05_troubleshooting.md`
   - 完了条件: 変更パッケージ単位で関連テスト要求を判定し、過剰な全体penaltyを回避

10. **PR60: 言語別ルール有効化戦略の整理**
   - 対応Phase: 60
   - 変更対象: `crates/patchgate-config/src/lib.rs`, `docs/01_concepts.md`, `docs/99_release_checklist.md`
   - 完了条件: デフォルト有効範囲、opt-in項目、移行手順が契約化される

## 依存関係

- PR51-55 は言語別検知の基礎整備として先行実施
- PR56/57 は PR51-55 の実データを踏まえて重みモデルを調整
- PR58/59 は誤検知抑制（生成コード/モノレポ境界）の実運用対応
- PR60 は PR51-59 の有効化ポリシーを統合して最終化

## Phase60完了時のDefinition of Done

- 主要言語（Rust/TS/Python/Go/Java/Kotlin）でテスト検知の精度が向上
- 依存更新評価がエコシステム特性を反映し、severity説明可能性が向上
- 生成コード・モノレポ運用での誤検知が抑制される
- 言語別ルールの有効化戦略が設定・ドキュメント・CIで一貫する
