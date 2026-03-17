# Phase101-120 Implementation Status (2026-03-05)

このドキュメントは、Phase101-120計画に対する実装進捗と残タスクを整理します。

## 実装完了（2026-03-05時点）

1. PR103: plugin contract test harness 本実装
- `patchgate-core` に plugin contract入力 (`patchgate.plugin.v1`) の実行テストを追加
- 署名検証を含む実行成功/失敗系テストを追加

2. PR107: generic/webhook/notification 契約テスト拡充
- CIに `sdk-contract` matrix (`python|node|rust`) を追加
- 生成テンプレートの実行検証を自動化

3. PR109: 実署名 + 標準SBOM運用の強化
- release workflow に cosign keyless 署名を追加
- `cargo-cyclonedx` による CycloneDX SBOM生成を追加
- precheck workflow で SBOM/provenance 契約検証を強化

4. PR110/118: LTS backport 自動PR起票・conflict report
- main向けPRに `backport/lts-v1` ラベル付与時の自動 cherry-pick を実装
- 競合時の conflict report artifact 出力を実装
- LTS PR向けSLA age checkを継続

5. PR111: verify-v1 運用データ校正
- `xtask ops verify-v1-calibrate` を追加
- メトリクス安定性から `standard|strict|lts` 推奨プロファイルを算出
- `ga-readiness` workflow に校正レポート生成を統合

6. PR114: dead-letter replay コマンド
- `patchgate delivery replay` を実装
- `--transport/--max-records/--retry-max-attempts/--retry-backoff-ms/--dry-run` をサポート

7. PR115-116: SDK互換テストCI標準化 + plugin配布署名検証
- `plugins.signature.required` と `entries[].signature_path` を導入
- 実行前 ed25519 署名検証（公開鍵env）を実装
- 設定バリデーションとユニットテストを追加

8. PR119-120: インシデント演習強化 + v1.1 readiness判定
- `recovery-drill` に dead-letter replay / strict readiness シナリオを追加
- `ga-readiness` で v1.1 readiness summary artifact を出力

## 残タスク

- 本ドキュメントは「本リポジトリ内のコード/CI 定義として計画した Phase101-120 実装タスク」の消化状況を対象としており、この範囲の残タスクは 0 件です。
- ただし、Phase101-120 に紐づく運用定着・ドキュメント整備・他リポジトリ連携などのフォローアップ作業は継続中であり、そのステータスは `docs/ROADMAP.md` および `docs/11_current_state_and_next_steps.md` 側で管理します。

## 検証結果

- `cargo fmt --all`: pass
- `cargo clippy --workspace --all-targets -- -D warnings`: pass
- `cargo test --workspace`: pass
