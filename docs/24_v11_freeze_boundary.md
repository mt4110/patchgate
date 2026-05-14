# v1.1 Freeze Boundary

Phase141-150 の設計を、公開docsと release artifact へ落とすための境界台帳です。

この文書は `xtask ops freeze-boundary` が生成する
`artifacts/v1.1-freeze-boundary.md` と同じ判断軸を持ちます。
`freeze-scoreboard` が telemetry による動的判定を担当し、この文書は
「v1.1 に入れるもの / 入れないもの / v2 seed へ送るもの」の説明責務を持ちます。

## Artifact

```bash
cargo run -p xtask -- ops freeze-boundary \
  --output artifacts/v1.1-freeze-boundary.md
```

Paired dynamic gate:

```bash
cargo run -p xtask -- ops freeze-scoreboard \
  --metrics-input artifacts/scan-metrics.jsonl \
  --audit-input artifacts/scan-audit.jsonl \
  --replay-summary-input artifacts/dead-letter-replay-summary.json \
  --output artifacts/v1.1-readiness.md
```

## v1.1 Scope Candidate Inventory

| Candidate | Decision | v1.1 boundary | Evidence |
| --- | --- | --- | --- |
| `verify-v1` strict / lts readiness profiles | `v1.1` | Release-facing compatibility gateとして維持 | `ga-readiness.md`, release checklist |
| dead-letter replay summary / replay evidence packet | `v1.1` | recovery evidence を freeze / v2 seed 判定へ接続 | `dead-letter-replay-summary.json`, `replay-evidence.json` |
| `compatibility-report` / `freeze-scoreboard` | `v1.1` | telemetry posture から hold / seed を判断 | `compatibility-report.md`, `v1.1-readiness.md` |
| plugin signature / sandbox / provenance trust loop | `v1.1` | `patchgate.plugin.v1` と SDK template compatibility を維持 | `fleet-review.md`, `docs/SECURITY.md` |
| generic provider v1 output | `v1.1` | downstream CI が読む `provider` / `summary` / `report` を維持 | `docs/15_provider_rollout_checklist.md` |
| audit v2 / SIEM handoff | `v2-seed` | audit v1 を主線にし、v2 は dual-write evidence として扱う | `shadow-review.md`, `siem-handoff.jsonl` |
| `verify-v2` / `diff-contract` | `v2-seed` | v1.1 ユーザーに v2 policy semantics を必須化しない | migration guide, RC readiness packet |
| remote source scan / hot-path cloud inference | `non-goal` | local / CI-first のコスト境界を維持 | roadmap non-goals |

## Deferred Backlog / Non-Goal Reconciliation

| Item | Disposition | Owner phase | Reconciliation |
| --- | --- | --- | --- |
| fleet registry UI / operator dashboard | `deferred` | Phase171-180 | v1.1 では `fleet-review.md` と bundle / registry / exception / provider capability JSON inputs を governance artifact とする |
| audit v2 as sole authoritative stream | `v2-seed` | Phase161-170 | dual-write の shadow evidence が clean になるまで audit v1 を主線にする |
| generic provider v2 default output | `v2-seed` | Phase161-170 | `generic_schema = "dual"` を先に通し、downstream break を観測する |
| full remote source scan | `non-goal` | none | local / CI-first の運用哲学とコスト境界に合わない |
| cloud inference in release hot path | `non-goal` | none | deterministic freeze gate に不要で、変動費と再現性のリスクが増える |
| automatic migration of all plugin manifests | `deferred` | Phase181-190 | v1.1 では compatibility notice と manual rollout checklist で扱う |

## Plugin / Provider Breaking-Change Boundary

| Surface | v1.1 contract | v2 change allowed | Guardrail |
| --- | --- | --- | --- |
| Plugin command contract | `patchgate.plugin.v1` は既存 SDK template から呼べる | manifest metadata / stronger provenance を要求できる | v1 template と contract test を v2 seed 中も維持 |
| Generic provider artifact | v1 `provider` / `summary` / `report` は安定 | `publish_format` / `gate` / `artifacts` / bridge payload を追加できる | `generic_schema = "dual"` を経由 |
| Audit stream | `patchgate.audit.v1` JSONL を release signal として維持 | `operation` / `gate` / `failure` / `diagnostics` の構造化 | `shadow-review` と `audit-drift-report` を必須化 |
| Policy configuration | `policy_version` と `compatibility.v1` を受け付ける | bridge defaults や `compatibility.v2` semantics を強められる | `verify-v1`, `verify-v2`, `diff-contract` を併用 |
| Docs / SDK templates | v1.1 setup と `plugin init` flow を壊さない | v2 parallel examples を追加できる | migration guide と compatibility notice を同時更新 |

## Migration Narrative

1. v1.1 freeze は `verify-v1`, `compatibility-report`, `freeze-scoreboard`, `freeze-boundary` が一致したときだけ確定する。
2. v1.1 の provider / plugin / audit / docs contract は維持し、v2 は shadow または dual mode で始める。
3. v2 seed は provider bridge と audit bridge から開始し、`shadow-review` と `audit-drift-report` が clean な範囲だけ広げる。
4. RC では migration guide, provider rollout checklist, candidate checklist, benchmark sign-off, security review をまとめる。
5. rollback は provider output を v1 に戻し、bridge mode を off にして、v2 audit artifact は診断 evidence として保持する。

## v2 Option Matrix

| Option | Fit | Tradeoff | Decision |
| --- | --- | --- | --- |
| provider-first bridge | downstream CI consumer の schema proof が必要なとき最適 | audit semantics は別途証明が必要 | seed work の第一候補 |
| audit-first bridge | SIEM / ops diagnostics が主リスクのとき有効 | provider compatibility は別 gate | provider evidence の後に並走 |
| full dual-contract | provider と audit shadow が安定した RC posture | CI / review cost が増える | RC readiness で使用 |
| hold v1.1 line | telemetry は安定しているが replay / bridge evidence が不足 | v2 learning が遅れる | valid freeze outcome |
| direct v2 cutover | isolated experiment のみ | ecosystem rollback margin がない | shared release line では使わない |

## v2 Risk Register

| Risk | Trigger | Mitigation | Gate |
| --- | --- | --- | --- |
| Provider artifact drift | dual / v2 payload を existing CI reader が読めない | v1 output を残し provider rollout evidence を添付 | `rc-readiness` provider bridge artifact |
| Audit stream mismatch | v2 event count / failure total が v1 とズレる | v1 を authoritative に保ち shadow delta を調査 | `shadow-review`, `audit-drift-report` |
| Plugin trust regression | unsigned / unverified / revoked provenance が release wave に入る | registry provenance と sandbox profile を review | `fleet-review` registry provenance |
| Migration narrative gap | checklist / migration guide / provider rollout docs が食い違う | docs を同時更新し、path resolve まで RC を止める | candidate checklist, migration guide |
| Replay residue | dead-letter replay に failed / retained records が残る | drain / justify / defer してから v2 seed へ進める | `compatibility-report`, replay evidence packet |
| Performance or cost regression | benchmark regression または fleet / segment cost ceiling 超過 | rollout wave を止め、dual-run scope を縮小 | benchmark sign-off, `fleet-review` |
| Security review unresolved | `Continue` 未承認、または mitigation required | reviewer sign-off が clean になるまで hold | `rc-readiness` security review |

## Release Checklist Freeze Gate

v1.1 freeze を release checklist 上で完了扱いにするには、次を揃える。

- `artifacts/v1.1-freeze-boundary.md` が生成されている
- scope inventory の各項目が `v1.1` / `deferred` / `non-goal` / `v2-seed` のどれかに分類されている
- deferred item は owner phase を持つか、non-goal rationale を持つ
- plugin / provider / audit / policy / docs / SDK の破壊変更境界が説明できる
- `artifacts/v1.1-readiness.md` で `freeze_ready = true`
- `compatibility-report.md` の posture が `stabilize-v1` ではない
- v2 option と risk register が RC gate artifact に接続されている
