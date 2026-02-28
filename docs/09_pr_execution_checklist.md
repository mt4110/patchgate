# PR Execution Checklist Template

`docs/07_pr_plan_phase1_10.md` と `docs/08_pr_plan_phase11_20.md` を実行するための、着手チェックリストです。  
コミット時にも同じ観点でチェックを入れられるよう、`.gitmessage.patchgate.txt` と対応させています。

## 使い方

1. 着手するPR番号（例: `PR03`）を決める
2. このファイルの「共通チェック」を確認して作業開始
3. コミット時に `.gitmessage.patchgate.txt` のチェックを埋める
4. PR本文にも同じチェック状態を転記する

## 共通チェック（PR01-20）

- [ ] 対応Phase/PR番号を明記した
- [ ] 変更対象ファイルが計画ドキュメントと一致している
- [ ] 実装が完了した
- [ ] テストを追加または更新した
- [ ] ドキュメントを更新した
- [ ] `nix develop --command cargo test --workspace` が通過した
- [ ] 互換性影響（CLI/JSON/出力）を確認した
- [ ] 既知の未対応項目をコミットメッセージに記載した

## PR別 追加チェック

### PR01-PR10

- [ ] PR01: `fmt/lint/test` の共通手順がCIで確認できる
- [ ] PR02: エラー分類と終了コードのテストがある
- [ ] PR03: `staged/worktree/repo` の境界テストがある
- [ ] PR04: `test_gap` の代表誤検知ケースを潰した
- [ ] PR05: `dangerous_change` のcritical境界を説明可能
- [ ] PR06: `dependency_update` のmanifest/lock判定テストがある
- [ ] PR07: スコア境界値テストがある
- [ ] PR08: JSON契約の説明がdocsにある
- [ ] PR09: GitHubコメントの可読性改善が確認できる
- [ ] PR10: cache hit/miss 条件が仕様化されている

### PR11-PR20

- [ ] PR11: policy不正がカテゴリ別に返る
- [ ] PR12: default/example の意味差分が解消された
- [ ] PR13: `doctor` が git/config/cache を診断できる
- [ ] PR14: publish 部分成功を区別して報告できる
- [ ] PR15: GitHub環境変数解決の優先順がテストで固定された
- [ ] PR16: 出力後方互換ポリシーが文書化された
- [ ] PR17: cache破損時の復旧または劣化運転が動作する
- [ ] PR18: ベンチ基準値を記録・比較できる
- [ ] PR19: 主要経路の結合テストがある
- [ ] PR20: リリース前チェックの自動化範囲が拡張された

## コミットメッセージ例

```text
PR03(core): add scope boundary tests

Phase: 3
Checklist:
- [x] impl
- [x] test
- [x] docs
- [x] cargo test --workspace
- [x] compatibility impact checked

Notes:
- scope=repo on empty diff returns score=100
```
