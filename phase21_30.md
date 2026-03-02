# PR Plan: Phase21-30

`docs/06_phase_backcast_1_100.md` の Phase21-30（Policy管理と互換性）を対象にしたPR実装計画です。  
Phase11-20 までで確立した出力契約・運用診断を前提に、設定進化を安全に進めます。

## 方針

- Policy変更は「互換性ルール」と「移行手段」をセットで提供する
- 設定の決定性を優先し、同一入力で同一判定を保証する
- 破壊的変更は `policy migrate` の明示実行を必須にする

## PR一覧

1. **PR21: policy version 導入**
   - 対応Phase: 21
   - 変更対象: `crates/patchgate-config/src/types.rs`, `crates/patchgate-config/src/lib.rs`, `config/policy.toml.example`
   - 完了条件: `policy_version` の既定値・許容値・未指定時挙動が固定される

2. **PR22: policy migrate コマンド雛形**
   - 対応Phase: 22
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: `patchgate policy migrate --from --to --write` のI/Fとdry-run動作を提供

3. **PR23: 互換性マトリクス文書化**
   - 対応Phase: 23
   - 変更対象: `docs/01_concepts.md`, `docs/03_cli_reference.md`, `docs/ROADMAP.md`
   - 完了条件: policy version x CLI version の互換表と非互換時挙動が明文化

4. **PR24: ルールプリセット導入**
   - 対応Phase: 24
   - 変更対象: `config/presets/strict.toml`, `config/presets/balanced.toml`, `config/presets/relaxed.toml`, `crates/patchgate-config/src/lib.rs`
   - 完了条件: `--policy-preset <strict|balanced|relaxed>` で同一ルール集合を再現できる

5. **PR25: override評価順の固定**
   - 対応Phase: 25
   - 変更対象: `crates/patchgate-config/src/lib.rs`, `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: 適用順（default < preset < policy file < CLI override）がテストで固定

6. **PR26: 重み・しきい値再設計**
   - 対応Phase: 26
   - 変更対象: `crates/patchgate-core/src/model.rs`, `crates/patchgate-config/src/types.rs`, `config/policy.toml.example`
   - 完了条件: check別重み調整時も `score/review_priority` の単調性を維持

7. **PR27: ルール説明の機械可読化**
   - 対応Phase: 27
   - 変更対象: `crates/patchgate-core/src/model.rs`, `docs/01_concepts.md`
   - 完了条件: 各findingが `rule_id`, `category`, `docs_url` を出力できる

8. **PR28: policy lint コマンド追加**
   - 対応Phase: 28
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-config/src/lib.rs`, `.github/workflows/*`
   - 完了条件: CIで `patchgate policy lint` を実行し、エラー種別をexit codeで判別可能

9. **PR29: 破壊的設定変更の検出**
   - 対応Phase: 29
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-config/src/lib.rs`, `docs/05_troubleshooting.md`
   - 完了条件: 旧版policy読込時に破壊的差分を警告し、migrateを案内

10. **PR30: policy配布標準化**
   - 対応Phase: 30
   - 変更対象: `docs/04_recipes.md`, `docs/99_release_checklist.md`, `.github/workflows/*`
   - 完了条件: policy配布（タグ、pin、検証、ロールバック）の運用手順をテンプレ化

## 依存関係

- PR22 は PR21 の versionモデル確定後に実装
- PR24/25 は PR23 の互換表に従って仕様固定
- PR29 は PR22/23/28 の成果（migration/lint/互換表）を前提
- PR30 は PR24-29 の運用手順を統合して最終化

## Phase30完了時のDefinition of Done

- policy version付き設定が `load/validate/lint/migrate` の全経路で扱える
- preset/overrideの適用順に関する仕様と実装が一致している
- 破壊的変更が自動検知され、利用者が回避手順を取れる
- CIでpolicy品質ゲート（lint + migration安全性確認）が実行される
