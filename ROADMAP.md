# Ion Drift Roadmap

Path from the current release to Drift 1.0. Milestones are additive — earlier versions lock in what later versions build on. Dates are targets, not commitments; shipping quality trumps shipping on schedule.

## Current: 0.5.0 (2026-04-10)

- Per-device router queue (CRS326 session-accumulation crash fixed)
- Engine consolidation: shared identity helpers, dedup resolution maps, alerting moved to storage crate
- VLAN anomalies surfaced inline on the Investigation page drill-down
- **Module API v1.0** — stable plugin contract (`ion-drift-module-api` 1.0.0)
- Module API hardening sprint: auth bypass closed, panic-isolated lifecycle, host-stamped event provenance, per-kind event channels, spawn_blocking storage, capability cleanup, namespace-scoped secrets, full test harness

## 0.6.0 — Module API wiring + engine health

- Wire `ConnectionRead`, `SnapshotRead`, `DeviceManagerRead` trait objects into the host (v1.0 shipped them as forward-compatible scaffolding with `None` accessors)
- Surface per-kind event lag as diagnostic counters so modules can detect forwarder-boundary drops
- First-party observability: `/api/system/health` with per-engine liveness + last-cycle timestamps
- Poller diagnostics: per-device queue depth, backoff state, circuit breaker trips exposed on the stats page
- Snapshot generation metrics and visible freshness on the topology page

## 0.7.0 — Alerting expansion + investigation polish

- Alert channel additions: email (via existing SMTP surface), webhook, ntfy, Discord, Matrix
- Per-rule alert test endpoint that sends a synthetic event end-to-end
- Investigation engine: evidence-chain UI with collapsible sub-findings
- Verdict feedback loop: operator corrections feed back into future verdict weighting
- Suppression rule editor with scope preview

## 0.8.0 — Policy + deviation maturity

- HTTP/TLS policy deviation detection (TLS 1.0/1.1, self-signed, wildcard usage inside the trust zone)
- SMB/LDAP egress policies
- Policy simulation mode: apply a draft policy to N days of historical traffic and preview deviations before committing
- Router policy drift detection (config divergence from the last approved snapshot)

## 0.9.0 — Multi-site + federation

- Multi-router support at a single Drift instance (currently one primary + managed switches)
- Per-site scoping for behavior baselines, topology, and policies
- Aggregated dashboards across sites
- Site-to-site baseline templating (apply one site's approved policies as a starting point for another)

## 1.0.0 — Production maturity

- Stable REST API contract (semver) for anything modules or operators script against
- Documented upgrade path from every 0.x minor
- Long-lived deployment story: 12+ months of continuous operation proven without manual intervention
- Release cadence: predictable monthly minor bumps on `development`, quarterly cuts to `main`

---

## Parallel tracks

These ship alongside the version tracks above as they're ready.

- **Module ecosystem** — the v1.0 Module API is the foundation; downstream modules (first-party and third-party) evolve on their own schedules
- **Backup and disaster recovery** — in-app snapshot export, encrypted offsite upload, one-click restore
- **Docs and onboarding** — video walkthroughs, deployment recipes for common homelab stacks
- **Hardware profile coverage** — additional SNMP vendor profiles as the community contributes

## Out of scope for 1.x

- Multi-tenant isolation (single-tenant per Drift instance is the deployment model)
- Cloud-hosted Drift (self-hosted only; no phone-home, no telemetry)
- Distributed agents / edge collectors (single-host deployment only)
- True module sandboxing (modules run in-process; operators extend the same trust they give any first-party Drift binary)
