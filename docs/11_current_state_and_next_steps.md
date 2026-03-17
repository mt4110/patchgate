# Current State and Next Steps (2026-03-05)

このドキュメントは、現在地点の明確化と「次に実装する項目」を固定するための実行ガイドです。

## 現在地点（事実）

1. 実装済み:
   - Phase1-100（baseline）
   - PR104-105相当: multi-language SDK template + `patchgate plugin init`
   - PR101-102/108/112相当: sandbox `isolated` profile + `verify-v1 --readiness-profile`
   - PR106/113/114相当: delivery idempotency key + dead-letter fallback
   - PR109/117/118相当: release provenance artifact + precheck検証 + LTS SLA age check
2. 設計済み（フォローアップ管理用）:
   - [PR Plan: Phase101-110](../phase101_110.md)
   - [PR Plan: Phase111-120](../phase111_120.md)
3. したがって現時点は「Phase101-120のベースライン実装完了（運用ループ整備フェーズ）」

## ソフトウェアのゴール（現フェーズ）

1. v1.0.x を「導入できる」状態から「安全に長期運用できる」状態へ引き上げる
2. 拡張機構（plugin/provider/notification）を契約テストで守り、破壊的変更を先に検知する
3. GA/LTS運用で監査可能性（署名/SBOM/provenance）を継続的に担保する

## 次に進むべき実装（優先1-3, 更新版）

1. Priority 1: PR103（plugin contract test harness）
   - 理由: `isolated` sandboxの回帰を止める契約テストがまだ不足
   - 主対象:
     - `crates/patchgate-core/tests/*`
     - `examples/plugins/*`
     - `docs/04_recipes.md`
   - 完了判定:
     - `patchgate.plugin.v1` 入出力/失敗契約をCIで自動検証

2. Priority 2: PR107（generic/webhook/notification契約テスト拡充）
   - 理由: idempotency/dead-letterを入れたため、配信契約の自動回帰検知が必要
   - 主対象:
     - `crates/patchgate-cli/tests/scan_integration.rs`
     - `crates/patchgate-github/tests/publish_contract.rs`
     - `docs/04_recipes.md`
   - 完了判定:
     - provider/webhook/notificationのpayload互換性を自動検証

3. Priority 3: PR111-120残件（運用データ校正と復旧自動化）
   - 理由: readiness/profileは入ったが、データ校正と自動復旧の運用ループが未完成
   - 主対象:
     - `crates/patchgate-cli/src/main.rs`
     - `crates/xtask/src/main.rs`
     - `.github/workflows/*`
   - 完了判定:
     - verify-v1校正レポート、dead-letter再処理、LTS自動起票が運用可能

## 実装ごとのテストゲート（毎回必須）

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. 変更範囲別の追加検証:
   - sandbox関連: `crates/patchgate-core/tests/*` の追加ケース
   - CLI関連: `crates/patchgate-cli/tests/scan_integration.rs`
   - workflow関連: ドキュメントに手動検証手順を明記

## 着手順（固定）

1. PR103 契約テスト
2. PR107 配信契約テスト
3. PR111-120残件（校正/復旧自動化）

この順序を崩すのは、セキュリティインシデント対応など緊急割り込み時のみとする。
