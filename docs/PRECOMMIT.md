# Pre-commit integration (snippet)

Example `.git/hooks/pre-commit` (bash, Nix-first):

```bash
#!/usr/bin/env bash
set -euo pipefail

nix develop --command patchgate scan --scope staged --mode warn
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

## Local preflight

Before commit/PR, run the same shared checks as CI:

```bash
just ci-check
```

## Commit template (checklist)

Enable commit template:

```bash
just install-commit-template
```

Or directly:

```bash
git config commit.template .gitmessage.patchgate.txt
```

Template file:

- `.gitmessage.patchgate.txt`
- `docs/09_pr_execution_checklist.md`
