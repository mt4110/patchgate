# Phase Backcast (151-200)

このドキュメントは、Phase141-150 で整理した v1.1 scope freeze / v2 compatibility seed を前提に、
Phase151-200 の目標を逆算する設計です。

## 前提（2026-03-23）

- Phase1-120: baseline 実装完了
- Phase121-150: self-healing / trust / compatibility 境界の設計が確定
- v1.1 に残す境界と、v2 で壊してよい境界の候補が docs 上で説明可能
- `docs/24_v11_freeze_boundary.md` と `artifacts/v1.1-freeze-boundary.md` で scope inventory / deferred backlog / breaking-change boundary / risk register を確認できる

## Phase150 の出口状態

- v1.1 に入れる候補 / defer する候補が inventory 化されている
- plugin / provider / docs / SDK の breaking-change 境界が文章化されている
- v2 seed に進むには、運用 telemetry を artifact として束ねる必要がある
- release checklist 上の freeze gate が `freeze-scoreboard` と `freeze-boundary` の二層で説明できる

## Phase151-200 で解くこと

1. compatibility evidence を週次運用と release gate の共通 artifact にする
2. v1.1 維持と v2 seed 着手の判断を telemetry から再現可能にする
3. plugin / provider / audit export の dual-contract 移行を shadow mode で始める
4. 複数 repo / 複数 provider を跨ぐ fleet 運用へ拡張する
5. v2 RC/GA を決めるための migration narrative と rollback packet を揃える

## ゴール逆算マイルストーン

- M9: Evidence-driven freeze
  - v1.1 freeze の判断が compatibility report で再現できる
- M10: Dual-track migration
  - v1.1 と v2 seed を shadow/bridge で並走できる
- M11: Fleet governance
  - repo 群・provider 群・plugin 群をまとめて運用判断できる
- M12: v2 RC readiness
  - dual-contract のまま性能・監査・rollback が検証済み
- M13: v2 GA / LTS launch
  - v2 を主線へ昇格し、v1 sunset を計画的に進められる

## フェーズ分割

- Phase151-160: compatibility evidence pack と freeze gate の自動化
- Phase161-170: dual-contract / migration tooling の bootstrap
- Phase171-180: fleet governance / provider orchestration / registry view
- Phase181-190: v2 RC hardening / ecosystem migration / rollback drill
- Phase191-200: v2 GA freeze / LTS 運用 / Phase201+ の逆算

## 最初に実装すること

1. `xtask ops compatibility-report` を追加し、SLO / audit / replay 証跡を 1 つの判断 artifact に束ねる
2. weekly ops / GA readiness / release precheck で compatibility report を生成する
3. Phase151-200 の PR 設計を先に固定し、v2 着手順序をぶらさない
4. Phase141-150 の freeze boundary artifact を release checklist に添付し、v2 risk register を RC gate の入力にする

## 完了判定（Phase151+ の入口）

- `compatibility-report.md` が週次運用と release precheck で生成される
- `v1.1-freeze-boundary.md` が release checklist の freeze gate と一致する
- posture (`stabilize-v1` / `hold-v1.1-line` / `start-v2-seed`) の判定根拠が docs と artifact で一致する
- Phase151-200 の各 phase plan に、次の 50 PR の順序と責務が定義されている
