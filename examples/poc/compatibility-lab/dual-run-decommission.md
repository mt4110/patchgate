# Dual-Run Decommission Plan

- generated_at: 2026-05-14T00:00:00Z
- decommission_ready: true
- repo_count: 1
- replay_clean: true
- shadow_aligned: true
- audit_drift_clean: true
- provider_v1_restore_ready: true
- rollback_packet_ready: true
- migration_drill_ready: true
- rc_readiness_ready: true
- sunset_notice_ready: true
- support_model_ready: true

## Sequence
- Freeze writes to dual-run bridge settings during the change window.
- Preserve audit v1 and audit v2 artifacts before changing provider schema.
- Switch `compatibility.v2.bridge_mode` to `off` after rollback packet verification.
- Switch generic provider output to `v2` after downstream readers confirm v1 restore remains available.
- Keep rollback packet and support escalation open through the +90 review window.

## Rollback Triggers
- audit v2 event count diverges from v1 during the decommission window
- downstream provider reader rejects v2-only payloads
- delivery replay or notification recovery retains failed records
- support model classifies the incident as critical
