# Current State and Next Steps (2026-03-20)

このドキュメントは、現在地点の明確化と「次に実装する項目」を固定するための実行ガイドです。

## 現在地点（事実）

1. 実装済み:
   - Phase1-100（baseline）
   - PR104-105相当: multi-language SDK template + `patchgate plugin init`
   - PR101-102/108/112相当: sandbox `isolated` profile + `verify-v1 --readiness-profile`
   - PR106/113/114相当: delivery idempotency key + dead-letter fallback
   - PR109/117/118相当: release provenance artifact + precheck検証 + LTS SLA age check
   - PR103/107/111-120相当: contract test / calibration / replay / readiness hardening まで baseline完了
2. 設計済み（フォローアップ管理用）:
   - [PR Plan: Phase101-110](../phase101_110.md)
   - [PR Plan: Phase111-120](../phase111_120.md)
   - [PR Plan: Phase121-130](../phase121_130.md)
3. したがって現時点は「Phase101-120のベースライン実装完了」かつ「Phase121-130の先行実装着手」

## ソフトウェアのゴール（現フェーズ）

1. v1.0.x を「導入できる」状態から「安全に長期運用できる」状態へ引き上げる
2. 拡張機構（plugin/provider/notification）を契約テストで守り、破壊的変更を先に検知する
3. GA/LTS運用で監査可能性（署名/SBOM/provenance）を継続的に担保する

## 次に進むべき実装（優先1-4, 更新版）

1. Priority 1: PR124（`verify-v1` safe autofix）
   - 理由: readiness warning は出せるが、そのまま直せる導線が不足している
   - 主対象:
     - `crates/patchgate-cli/src/main.rs`
     - `docs/03_cli_reference.md`
     - `docs/04_recipes.md`
   - 完了判定:
     - `verify-v1` warning のうち安全なものを preview / write できる

2. Priority 2: PR125（dead-letter replay self-healing loop）
   - 理由: replay はあるが、成功済みレコードの掃除と定期実行向け summary が不足している
   - 主対象:
     - `crates/patchgate-cli/src/main.rs`
     - `.github/workflows/dead-letter-replay.yml`
     - `docs/04_recipes.md`
   - 完了判定:
     - replay 成功分だけ queue から除去し、失敗/保持件数を summary で追跡できる

3. Priority 3: PR121/122（sandbox capability matrix / non-GitHub CI template）
   - 理由: cross-platform と provider 拡張は、先に capability/contract を固定しないと実装が散らばる
   - 主対象:
     - `crates/patchgate-core/src/runner.rs`
     - `crates/patchgate-cli/src/main.rs`
     - `docs/SECURITY.md`
     - `docs/patchgate-action.yml`
   - 完了判定:
     - OS別sandbox capability と generic CI template の前提差分が明文化される

4. Priority 4: PR123（plugin鍵 rotation / revocation）
   - 理由: 署名検証は入ったが、鍵運用 lifecycle を持たないと OSS 配布品質として弱い
   - 主対象:
     - `crates/patchgate-core/src/runner.rs`
     - `docs/SECURITY.md`
     - `.github/workflows/*`
   - 完了判定:
     - 鍵ローテーションと失効手順が workflow / docs / validation に接続される

## 実装ごとのテストゲート（毎回必須）

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets -- -D warnings`
3. `cargo test --workspace`
4. 変更範囲別の追加検証:
   - `verify-v1` 関連: autofix preview / write / strict profile の追加ケース
   - delivery関連: rewrite-input / summary-output / failure retention の追加ケース
   - workflow関連: schedule 想定の replay 手順を recipe に明記

## 着手順（固定）

1. PR124 `verify-v1` safe autofix
2. PR125 dead-letter replay self-healing loop
3. PR121/122 capability matrix / provider template
4. PR123 trust lifecycle

この順序を崩すのは、セキュリティインシデント対応など緊急割り込み時のみとする。
