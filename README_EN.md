# patchgate

**patchgate** is a diff-based quality gate for pull requests.
It computes a single score (0-100) from:

- Missing test coverage (`test_gap`)
- Dangerous file changes (`dangerous_change`)
- Dependency update risk (`dependency_update`)
- Review priority (`P0`..`P3`)

## Principles
- Nix-first developer workflow
- Multi-platform validation (Linux / macOS / Windows)
- Low variable cost (run logic locally/CI, cloud only for metadata)

## Quickstart

Run the commands below **inside the `nix develop` shell**.

```bash
nix develop
cargo run -p patchgate-cli -- scan --mode warn
```

JSON output:

```bash
cargo run -p patchgate-cli -- scan --format json
```

Publish PR comment and check run to GitHub:

```bash
GITHUB_TOKEN=... cargo run -p patchgate-cli -- scan --github-publish
```

## Policy file

Copy `config/policy.toml.example` into the **target project root** as `policy.toml`.

```bash
cp config/policy.toml.example /path/to/project_root/policy.toml
```

If you want to keep the policy local to that project, add it to `.gitignore` as well.

```bash
printf '\n/policy.toml\n' >> /path/to/project_root/.gitignore
```

The expected workflow is to run `patchgate` while still inside the `nix develop` shell.

## CLI

- `patchgate scan --mode warn|enforce --scope staged|worktree|repo --format text|json`
- `patchgate doctor`

Exit code:
- `0`: success (`warn`, or `enforce` gate pass)
- `1`: gate failed in `enforce` (`score < fail_threshold`)
- `2`: input error (invalid `scan` option value)
- `3`: config error (config load or config value validation)
- `4`: runtime error (diff collection, evaluation, cache)
- `5`: output error (JSON/report write)
- `6`: GitHub publish error
