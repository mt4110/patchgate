# PR Plan: Phase31-40

`docs/06_phase_backcast_1_100.md` の Phase31-40（GitHub連携の本番化）を対象にしたPR実装計画です。  
Phase21-30 で整理したpolicy互換性を前提に、CI/PR運用で壊れにくいpublish基盤を固めます。

## 方針

- コメント更新・Check Run作成を再実行安全（idempotent）にする
- 一時障害（rate limit, 5xx, timeout）で停止しすぎない設計にする
- publish系の失敗理由を分離し、運用者が次アクションを即判断できる形で出力する

## PR一覧

1. **PR31: Check Run結論マッピング精緻化**
   - 対応Phase: 31
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `docs/03_cli_reference.md`
   - 完了条件: `mode`, `should_fail`, `findings` の組み合わせと `conclusion` の対応表が固定

2. **PR32: コメントidempotent更新強化**
   - 対応Phase: 32
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `crates/patchgate-github/tests/*`
   - 完了条件: 同一PR再実行で comment重複を作らず、既存コメントを確実に更新

3. **PR33: publish retry/backoff 実装**
   - 対応Phase: 33
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `crates/patchgate-cli/src/main.rs`
   - 完了条件: 再試行対象エラー、最大試行回数、待機戦略が設定可能

4. **PR34: rate limit時の劣化運転**
   - 対応Phase: 34
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `docs/05_troubleshooting.md`
   - 完了条件: rate limit検知時にcheck-only/comment-onlyへ段階的に劣化し、理由を明示

5. **PR35: 認証抽象化 (App/token)**
   - 対応Phase: 35
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `crates/patchgate-cli/src/main.rs`, `docs/patchgate-action.yml`
   - 完了条件: token認証とGitHub App認証の共通インターフェースを提供

6. **PR36: 自動ラベル連携（任意）**
   - 対応Phase: 36
   - 変更対象: `crates/patchgate-github/src/lib.rs`, `docs/04_recipes.md`
   - 完了条件: `review_priority` に応じたラベル付与を opt-in で実行可能

7. **PR37: PRテンプレ連携の文言改善**
   - 対応Phase: 37
   - 変更対象: `crates/patchgate-core/src/model.rs`, `docs/promptbook.md`, `docs/patchgate-action.yml`
   - 完了条件: findingメッセージがPRテンプレ文脈に沿って読める形式に統一

8. **PR38: コメント抑制ルール導入**
   - 対応Phase: 38
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `crates/patchgate-github/src/lib.rs`
   - 完了条件: 変化なし/低重要度のみ/連続再実行時にコメント投稿を抑制可能

9. **PR39: publish dry-run モード**
   - 対応Phase: 39
   - 変更対象: `crates/patchgate-cli/src/main.rs`, `docs/03_cli_reference.md`
   - 完了条件: GitHub APIを呼ばずに送信予定payloadを確認できる

10. **PR40: GitHub連携E2Eテスト整備**
   - 対応Phase: 40
   - 変更対象: `crates/patchgate-cli/tests/*`, `crates/patchgate-github/tests/*`, `.github/workflows/*`
   - 完了条件: `scan -> publish(comment/check) -> retry/degrade` の主要経路がCIで再現

## 依存関係

- PR33/34 は PR31/32 の契約固定後に着手
- PR35 は PR33/34 と衝突しやすいためインターフェースを先に切り出す
- PR38/39 は PR31-37 のpublish挙動を前提に仕様化
- PR40 は PR31-39 の統合検証として最後に実施

## Phase40完了時のDefinition of Done

- publishは部分成功・一時障害・認証差異を吸収して継続可能
- コメント重複を防ぎ、再実行時のノイズが抑制される
- dry-runで本番前の送信内容確認ができる
- GitHub連携の主要シナリオがE2Eテストで回帰検知できる
