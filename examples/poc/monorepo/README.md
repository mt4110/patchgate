# Large-scale PoC template

このテンプレートは多数PR/モノレポ導入の検証観点を定義します。

## Checklist

- 差分サイズ上限 (`scope.max_changed_files`) の定義
- plugin sandbox 実行時間上限 (`plugins.entries[].timeout_ms`) の定義
- metrics/audit の保存先と保存期間
- webhook/通知の再送戦略
- LTSバックポート対象ブランチの運用
