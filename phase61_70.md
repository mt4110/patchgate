# PR Plan: Phase61-70

`docs/06_phase_backcast_1_100.md` の Phase61-70（運用監視と可観測性）を対象にしたPR実装計画です。  
Phase51-60 までで高めた判定精度を、継続運用で計測・診断・改善できる状態へ進めます。

## 方針

- 監視機能は「後付け解析」ではなく、実行時に最小コストで収集できる形で入れる
- 失敗の説明責務を強化し、運用者が数分で原因仮説を立てられる出力を優先する
- CIとローカルの両方で同じ運用データ契約（JSON schema, code分類）を使う

## PR一覧

1. **PR61: 実行メトリクスJSONL出力の導入**
   - 対応Phase: 61
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: scanごとの主要メトリクス（duration/score/changed_files/cache hit等）をJSONLで追記出力可能

2. **PR62: 失敗分類コード体系の追加**
   - 対応Phase: 62
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-config/src/lib.rs`, `docs/01_concepts.md`
   - 完了条件: 設定・入力・Git・Runtime・Publishなど失敗カテゴリを機械可読コードで一意化

3. **PR63: 監査ログ最小要件の実装**
   - 対応Phase: 63
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/02_config_reference.md`, `docs/05_troubleshooting.md`
   - 完了条件: 実行主体/対象/判定結果/失敗分類を含む監査ログ契約を定義し、出力設定を追加

4. **PR64: 実行履歴集計CLI（サマリ）追加**
   - 対応Phase: 64
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`, `docs/04_recipes.md`
   - 完了条件: JSONL履歴から期間別の件数・失敗率・平均実行時間を集計するコマンドを提供

5. **PR65: リポジトリ別トレンド集計基盤**
   - 対応Phase: 65
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-core/src/model.rs`, `docs/04_recipes.md`
   - 完了条件: repo/scope/check単位の時系列トレンドを同一フォーマットで出力可能

6. **PR66: 急激悪化アラート閾値の定義**
   - 対応Phase: 66
   - 変更対象: `crates/patchgate-config/src/types.rs`, `config/policy.toml.example`, `docs/02_config_reference.md`
   - 完了条件: score低下・失敗率上昇・実行時間悪化を閾値判定できる設定を追加

7. **PR67: 週次サマリ生成の自動化ワークフロー**
   - 対応Phase: 67
   - 変更対象: `.github/workflows/*`, `crates/xtask/src/main.rs`, `docs/04_recipes.md`
   - 完了条件: 定期実行で運用サマリを生成し、artifactまたはコメントとして取得可能

8. **PR68: 運用runbookの体系化**
   - 対応Phase: 68
   - 変更対象: `docs/05_troubleshooting.md`, `docs/99_release_checklist.md`
   - 完了条件: 代表障害（設定不備/認証/レート制限/性能劣化）ごとに診断手順を標準化

9. **PR69: 障害復旧演習シナリオ整備**
   - 対応Phase: 69
   - 変更対象: `.github/workflows/*`, `docs/04_recipes.md`, `docs/05_troubleshooting.md`
   - 完了条件: フェイルケースを再現する演習手順と期待復旧時間を定義

10. **PR70: MTTR短縮の診断出力改善**
    - 対応Phase: 70
    - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-core/src/runner.rs`, `docs/01_concepts.md`
    - 完了条件: 失敗時に次アクションを示す診断ヒントを標準出力/JSONに含める

## 依存関係

- PR61/62/63 は可観測性の基礎契約として先行導入
- PR64/65 は PR61-63 の履歴データ契約を前提に集計機能を拡張
- PR66 は PR64/65 の集計指標を参照して閾値モデルを確定
- PR67-70 は運用自動化・復旧速度改善として段階導入

## Phase70完了時のDefinition of Done

- 実行結果が履歴として継続保存され、失敗分類を横断集計できる
- 異常検知閾値が設定可能で、週次単位で状態を追跡できる
- 障害時の診断手順と復旧演習が文書・CI運用に組み込まれる
- MTTR短縮に必要な診断情報がCLI/JSON契約で一貫して提供される
