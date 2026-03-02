# Roadmap

This roadmap tracks the patchgate pivot.

## Detailed phase design

- [Phase Backcast (1-100)](06_phase_backcast_1_100.md)
- [PR Plan: Phase1-10](07_pr_plan_phase1_10.md)
- [PR Plan: Phase11-20](08_pr_plan_phase11_20.md)
- [PR Plan: Phase21-30](../phase21_30.md)
- [PR Plan: Phase31-40](../phase31_40.md)
- [PR Execution Checklist Template](09_pr_execution_checklist.md)

## Active planning horizon

- Completed design: Phase1-20
- New design scope in this update: Phase21-40
- Next execution unit:
  - Phase21-30: policy compatibility and migration
  - Phase31-40: production-grade GitHub integration

## v0.3.0 (MVP)
- Diff-based quality gate with 3 checks
  - `test_gap`
  - `dangerous_change`
  - `dependency_update`
- Score `0..100` and `fail_threshold`
- `warn|enforce` execution mode
- JSON output + GitHub comment markdown
- SQLite cache for unchanged diff fingerprint

## v0.3.1
- Check result explainability improvements
- Better language-specific test heuristics
- More precise dependency risk signals

## v0.3.2
- GitHub adapter as standalone crate
- Check-run + PR comment posting helpers
- Policy distribution and version pinning

## v0.3.3 (Phase21-30 target)
- Policy schema versioning and migration workflow
- Preset/override compatibility contract
- Policy linting and breaking-change detection

### Phase21-30 implementation notes
- Compatibility matrix published in `docs/01_concepts.md` and `docs/03_cli_reference.md`
- `policy lint` / `policy migrate` command set introduced
- Presets standardized under `config/presets/{strict,balanced,relaxed}.toml`

## v0.3.4 (Phase31-40 target)
- Robust check-run/comment publishing with retry/backoff
- Rate-limit-aware degraded operation
- Dry-run and E2E verification for GitHub publishing

### Phase31-40 implementation notes
- Check Run and PR comment are idempotent upsert operations
- Publish has retry/backoff policy and rate-limit degraded mode
- Auth abstraction supports `token|app` mode
- Optional review-priority label integration and comment suppression rules
- Dry-run payload generation is available via CLI and workflow

## v0.4.0
- Historical trend API (metadata only)
- Team/repo policy presets
- Review-priority analytics dashboard

## Non-goals (current phase)
- Full remote source scan as primary path
- High-cost cloud inference in hot path
