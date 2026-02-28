# Roadmap

This roadmap tracks the patchgate pivot.

## Detailed phase design

- [Phase Backcast (1-100)](06_phase_backcast_1_100.md)
- [PR Plan: Phase1-10](07_pr_plan_phase1_10.md)
- [PR Plan: Phase11-20](08_pr_plan_phase11_20.md)
- [PR Execution Checklist Template](09_pr_execution_checklist.md)

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

## v0.4.0
- Historical trend API (metadata only)
- Team/repo policy presets
- Review-priority analytics dashboard

## Non-goals (current phase)
- Full remote source scan as primary path
- High-cost cloud inference in hot path
