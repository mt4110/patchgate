# RC Security Review Packet

## Inputs

- audit-drift: `target/compatibility-lab/audit-drift-report.md`
- shadow-review: `target/compatibility-lab/shadow-review.md`
- fleet-review: `target/compatibility-lab/fleet-review.md`
- rollback packet: `examples/poc/compatibility-lab/rollback-packet.json`

## Review Criteria

- unknown failure codes are absent
- audit v1/v2 event identity and failure counts match
- rollback packet restores provider and audit authority to v1
- cost and provenance signals have no open blockers

## Decision

- [x] Continue
- [ ] Mitigation required
