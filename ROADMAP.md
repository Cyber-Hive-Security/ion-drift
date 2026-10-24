# Ion Drift Roadmap

Path from the current release to Drift 1.0. Milestones are additive: earlier versions lock in what later versions build on. Dates are targets, not commitments; shipping quality trumps shipping on schedule.

Drift 1.0 is a complete product on its own: a self-hosted security and behavior monitor for one RouterOS router and unlimited RouterOS, SwOS, and SNMP switches. Anything that exists to serve a companion product (automated response, multi-site) lands after 1.0 and is listed at the end.

## Current: 0.5.6 (maintenance)

- Clippy at zero across the workspace and blocking in CI
- ESLint flat config for the web app with accessibility rules, blocking in CI
- Every SonarQube finding from the October 2026 scan resolved or ruled won't-fix with a reason
- Internal lab identifiers replaced with documentation values; repo guard in pre-commit and CI so they cannot return
- Floating-promise, regex, and `Number.isNaN` fixes in the web app; labels and keyboard reachability on settings and identity pages

## 0.5.7 — The router as a target

New read-only collectors and findings for the router itself. Each collector ships with a MockRouter fixture, an enrollment baseline ("what was present at enrollment is normal, anything new is a finding"), and a default alert rule.

- Persistence: `/system/scheduler`, `/system/script`, `/user/ssh-keys`, `/user/active`, `/file`, `/container`
- Post-exploitation services: `/ip/socks`, `/ip/proxy`, `/ip/upnp`, `/ip/cloud`
- Hidden rules: `/ip/firewall/raw` (filter, NAT, and mangle are already read)
- Exposure beyond `/ip/service`: MAC server, bandwidth server, RoMON, neighbor discovery interfaces, firewall service ports, DNS remote requests
- Control-plane exposure finding against a declared trusted-management list
- Failed-login brute-force finding from logs already ingested
- Certificate hygiene finding: expiring, self-signed, or weak keys bound to www-ssl or api-ssl
- Dormant accounts: local users and PPP secrets unused for N days
- Guest-VLAN isolation finding
- Poll cadence tiers (live, minutes, hourly) so the new endpoints do not raise load on small boards; CPU ceiling measured on a hEX and recorded as a test
- Onboarding script generator: the setup wizard emits a pasted RouterOS command block that creates a least-privilege read-only user and syslog target. Drift never writes router configuration itself.

## 0.5.8 — Read the detectors RouterOS already has

- `/system/history` becomes the config-change finding, with user and time
- Export diff attached to change findings if REST can run `/export` (spike first)
- `/ip/dhcp-server/alert` rogue DHCP finding
- `/tool/netwatch` state read instead of probing
- `/ip/kid-control/device` byte counters as interim per-device volume baselines
- Firewall rule counter deltas
- `/system/routerboard` and `/system/package` versions into advisory matching

## 0.5.9 — Identity and blind spots

- Wireless registration tables and CAPsMAN: clients get an AP locus in topology and identity
- Per-port PoE draw as a device fingerprint and swap detector
- DHCP vendor class (`class-id`) fingerprinting
- `/interface/detect-internet` as a WAN/LAN authority input
- Tunnel-peer inventory (WireGuard, PPP, L2TP, GRE) with new-peer and changed-endpoint findings
- `/system/health`, NTP, and clock-drift findings
- BGP and OSPF adjacency change findings
- `/ipv6/neighbor` into identity (IPv6 firewall follows in 0.6)
- Per-MAC path timeline from existing MAC observations
- Dormant-device-reappeared finding

## 0.6.0 — Flows

Flows carry behavior; REST carries identity; joined on IP at a point in time.

- IPFIX/NetFlow v9 listener as a third ingest path, hardened like syslog: opt-in, management-segment bind, source allowlist, rate cap, lower trust tier. Shared listener hardening brings syslog the opt-in flag and per-source quotas.
- Aggregation at ingest: (device, destination, port, protocol) per five-minute bucket; short raw window
- Identity join through existing ARP, DHCP, and bridge host bindings; unresolvable source is a finding
- Behavior engine fed from flows: destination sets, hour-of-week volume, new destination, beaconing, slow trickle, cumulative daily and weekly volume, VLAN occupancy, first-seen versus returning. Conntrack polling stays for the live explorer and as the fallback baseline.
- Confidence rule: flow-only evidence scores below corroborated evidence
- Gap detection: sequence numbers and conntrack reconciliation surface collector loss as a health finding
- `/api/system/health` with per-engine liveness and last-cycle timestamps; poller diagnostics; event lag counters; snapshot freshness on the topology page
- IPv6 address type through storage and the CIDR matcher; `/ipv6/firewall/filter` exposure finding

## 0.7.0 — Signal to humans

- Plain-English daily digest: what changed since yesterday, by email and webhook
- Alert channels: Telegram, ntfy, Teams, Slack, Discord, Matrix; per-rule synthetic test endpoint
- Investigation UI: evidence chain with collapsible sub-findings; verdict feedback loop
- Suppression rule editor wired to the existing `advisory_suppression` table
- Opt-in threat-intel correlation: known-bad-peer finding from flow destinations, under the same consent pattern as the advisory feed
- DGA heuristic in the DNS anomaly engine

## 0.8.0 — Posture

- Explain-my-firewall: shadowed, unreachable, and overly permissive rules in plain language
- TLS and HTTP policy deviations inside the trust zone
- Golden baseline: a human-blessed config snapshot compared against live
- Explainable posture score and a client-facing PDF report
- Generic resolver query-log adapter as an optional DNS observation source

## 0.9.0 — Operators and organizations

- RBAC: admin, operator, viewer; permission matrix test covers every mutating route
- Local accounts: multiple users, TOTP, recovery codes, password rotation with KEK re-wrap, concurrent session cap
- Generic OIDC verified against Entra ID, Google Workspace, Okta, and Authentik
- Operator audit trail
- API v1 frozen at `/api/v1` with `/api` alias through 1.x; OpenAPI; service tokens for read endpoints
- Encrypted backups; restore drill documented

## 1.0.0 — Production

- Signed images, SBOM per release, base images pinned by digest, full test battery in the release workflow
- Third-party penetration test and fix window
- Packaging: compose primary, plus OVA and deb
- Setup under 15 minutes from container start to first finding
- Documented and CI-tested upgrade path from every 0.x minor
- License model decided and implemented

---

## Future — considered, not yet scheduled

- **TZSP packet capture (data-plane fingerprinting)** — receive mirrored traffic from RouterOS `/tool/sniffer` streaming to unlock signals the REST control plane can't see: mDNS/SSDP/UPnP device announcements, JA3/JA4 TLS client fingerprints, p0f-style TCP stack fingerprinting, and DHCP option 55/60 fingerprinting. **Hard requirements:** opt-in only (default off — never enabled by install, upgrade, or provisioning), scoped per-interface rather than all-VLANs, and guarded by router load monitoring with automatic capture shutoff so Drift can never degrade the router it's watching. Rationale: mirroring is the one feature that can make a passive monitor harm the network it observes. Flows (0.6) come first.
- Multi-router at a single site. The license model is one router plus unlimited switches; whether a second edge or a CHR hub is in scope is an open product decision.

## Post-1.0

- Ion Arc: governed automated response (quarantine, address-list blocking with time-bounded entries and rollback, approvals)
- Ion Fabric: multi-site findings roll-up
- Module API trait wiring (`ConnectionRead`, `SnapshotRead`, `DeviceManagerRead`) and the module ecosystem
- Distributor and partner program, compliance mappings, PSA connectors

## Parallel tracks

- **Docs and onboarding** — deployment recipes, operator guides written for an evaluator rather than a homelab reader
- **Hardware profile coverage** — additional SNMP vendor profiles as the community contributes

## Out of scope for 1.x

- Multi-tenant isolation (single-tenant per Drift instance is the deployment model)
- Cloud-hosted Drift (self-hosted only; no phone-home, no telemetry)
- Distributed agents / edge collectors (single-host deployment only)
- True module sandboxing (modules run in-process; operators extend the same trust they give any first-party Drift binary)
