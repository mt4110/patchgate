set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

fmt:
  nix develop --command cargo fmt --all

fmt-check:
  nix develop --command cargo fmt --all -- --check

lint:
  nix develop --command cargo clippy --workspace --all-targets -- -D warnings

clippy: lint

test:
  nix develop --command cargo test --workspace

run:
  nix develop --command cargo run -p patchgate-cli -- scan --mode warn

ci-check: fmt-check lint test

ci: ci-check

install-commit-template:
  git config commit.template .gitmessage.patchgate.txt

commit:
  git commit
