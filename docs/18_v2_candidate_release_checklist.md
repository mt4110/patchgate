# V2 Candidate Release Checklist

- [ ] `patchgate policy verify-v2`
- [ ] `patchgate policy diff-contract`
- [ ] `xtask ops compatibility-report`
- [ ] `xtask ops freeze-scoreboard`
- [ ] `xtask ops freeze-boundary`
- [ ] `xtask ops audit-drift-report`
- [ ] `xtask ops shadow-review`
- [ ] `xtask ops fleet-review`
- [ ] `xtask ops rc-readiness`
- [ ] provider dual-schema artifact compatibility verified
- [ ] audit dual-write artifact compatibility verified
- [ ] plugin v2 shadow envelope sample verified
- [ ] webhook / notification bridge metadata verified
- [ ] PR181 v2 RC contract freeze: enforced `diff-contract` JSON attached
- [ ] PR182 breaking-change enforcement: `patchgate policy diff-contract --enforce` passes
- [ ] PR183 v1 deprecation countdown: +30 / +60 / +90 markers published
- [ ] PR184 large-scale migration drill: non-dry-run drill has zero failed repos
- [ ] PR185 audit export v2 validation: strict v2 schema and v1/v2 event sets validated
- [ ] PR186 rollback packet: `bridge_mode = "off"` / `generic_schema = "v1"` restore path rehearsed
- [ ] PR187 RC security review: inputs, criteria, Continue decision, and no mitigation blocker
- [ ] PR188 benchmark / cost sign-off: non-regressing benchmark plus fleet cost green
- [ ] PR189 candidate checklist: this checklist is attached to RC packet
- [ ] PR190 GA go / no-go: go/no-go review prepared for GA packet
- [ ] migration guide updated
- [ ] rollback packet updated
- [ ] v1.1 freeze boundary inventory reviewed
- [ ] v2 option matrix and risk register attached to RC packet via `--freeze-boundary-path`
- [ ] fleet governance packet shows provider negotiation, registry provenance, retention tier, exception governance, and segment cost clean
- [ ] Phase181+ RC prep review has no `fleet-review-remediation` blocker for candidate repos
- [ ] RC security review approved (`Continue` checked)
- [ ] benchmark sign-off attached

## Reference Command

```bash
cargo run -p xtask -- ops freeze-boundary \
  --output artifacts/v1.1-freeze-boundary.md
```

```bash
cargo run -p xtask -- ops rollback-packet \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --output artifacts/rollback-packet.json
```

```bash
cargo run -p xtask -- ops migration-drill \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --provider-input artifacts/provider-dual.json \
  --rollback-packet-input artifacts/rollback-packet.json \
  --output artifacts/migration-drill.json
```

```bash
cargo run -p xtask -- ops rc-readiness \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --audit-v2-input artifacts/scan-audit-v2.jsonl \
  --replay-summary-input artifacts/dead-letter-rewrite-summary.json \
  --provider-input artifacts/provider-dual.json \
  --benchmark-input artifacts/bench-compare.json \
  --security-review-input artifacts/security-review-template.md \
  --contract-freeze-input artifacts/diff-contract.json \
  --migration-drill-input artifacts/migration-drill.json \
  --rollback-packet-input artifacts/rollback-packet.json \
  --fleet-review-input artifacts/fleet-review.md \
  --migration-guide-path docs/16_v2_migration_guide_alpha.md \
  --provider-rollout-path docs/15_provider_rollout_checklist.md \
  --candidate-checklist-path docs/18_v2_candidate_release_checklist.md \
  --freeze-boundary-path artifacts/v1.1-freeze-boundary.md \
  --sunset-notice-path docs/21_v1_sunset_notice.md \
  --output artifacts/v2-rc-readiness.md
```

`artifacts/security-review-template.md` は `- [x] Continue` が必要で、`Mitigation required` を同時にチェックしてはいけません。
`artifacts/diff-contract.json` は `patchgate policy diff-contract --format json --enforce` で生成し、`breaking_change_gate_ready = true` を含めます。
