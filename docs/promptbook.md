# Promptbook

Purpose: AI支援開発のためのプロンプト集。

## Planning Prompts

- 「`phase31_40.md` に沿って、GitHub publish の retry/backoff、degraded mode、dry-run を一気通貫で実装し、`cargo test --workspace` まで完了してください。」
- 「`patchgate scan --github-dry-run` の payload をレビューし、Check Run conclusion mapping が `docs/03_cli_reference.md` の表と一致するか検証してください。」

## Debugging Prompts

- 「`patchgate scan --github-publish` 実行時の `comment_error/check_run_error/degraded_mode` を読み、どのAPI失敗が primary cause か切り分けてください。」
- 「`github_auth=app` の publish 失敗時に、環境変数と token期限、dry-run payload を使って再現・診断手順を提示してください。」
