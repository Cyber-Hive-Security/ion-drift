Interfaces help: Running is defined, but not used anywhere. Maybe it's supposed to be status?

Interfaces: Move VLANs to the left and make it the default.

firewall help: include something about the brigther the highlight, the more frequently the rule is used.

Identity Manager help: Port Violation is defined, but doesn't appear anywhere on the page.Implementation Plan

Security fixes
Order	Item	Priority	Difficulty	Affected files/modules	AI-assisted safe?	Human review required?
1	Enforce admin authz on all mutating topology/identity routes	P0	M	routes/mod.rs, routes/identity.rs, routes/topology.rs, routes/vlans.rs, routes/backbone.rs, routes/neighbor_aliases.rs	Yes	Yes
2	Add CSRF protection for cookie-authenticated non-GET endpoints	P0	L	main.rs, auth middleware/routes	Partial	Yes
3	Remove plaintext geo lookup fallback (http://ip-api.com)	P0	S	geo.rs	Yes	Yes
4	Replace panic paths (unwrap/expect) in request/runtime flows with typed errors	P1	M	web routes/services, swos_client.rs	Yes	Yes
5	Eliminate sensitive error/data leakage in logs and API errors	P1	M	web handlers, middleware, task modules	Partial	Yes
Config/env abstraction
Order	Item	Priority	Difficulty	Affected files/modules	AI-assisted safe?	Human review required?
6	Extract hardcoded router defaults (192.168.88.1) to config/env with validation	P0	M	config, CLI, mikrotik-core defaults, docs	Yes	Yes
7	Replace hardcoded interface name (1-WAN) with configurable/default-discovery strategy	P0	M	tasks/traffic.rs, task wiring, core callers	Partial	Yes
8	Externalize syslog bind host/port (0.0.0.0:5514) and add startup conflict checks	P1	M	task spawn/startup config	Yes	Yes
9	Remove hardcoded /usr/bin/nmap; discover binary path or make configurable	P1	S	scan/discovery modules	Yes	Yes
10	Relax hardcoded cert path assumptions (/app/data/certs, /app/certs)	P1	M	cert/config loaders, startup checks	Yes	Yes
11	Centralize all runtime config in one schema and generate example.env/example.toml	P1	M	config module + repo root templates	Yes	Yes
Refactors
Order	Item	Priority	Difficulty	Affected files/modules	AI-assisted safe?	Human review required?
12	Introduce task supervisor (health, restart policy, structured shutdown)	P0	L	tasks/mod.rs, main.rs	Partial	Yes
13	Move env-specific logic out of domain services into adapters/providers	P1	L	web services, mikrotik-core integration seams	Partial	Yes
14	Replace let _ = migration/DB writes with explicit error handling and fail-fast policy	P1	M	switch.rs, storage crate	Yes	Yes
15	Harden session/state architecture for multi-instance deploys (shared session backend)	P1	L	auth/session store, state wiring	Partial	Yes
16	Add backpressure/timeouts/retry policy wrappers around external calls	P2	M	task modules, HTTP clients, device pollers	Yes	Yes
Testing gaps
Order	Item	Priority	Difficulty	Affected files/modules	AI-assisted safe?	Human review required?
17	Add authz regression tests for all write routes (admin vs non-admin)	P0	M	route tests/integration tests	Yes	Yes
18	Add CSRF tests for cookie flows and cross-origin request attempts	P0	M	auth/middleware integration tests	Partial	Yes
19	Add migration integrity tests (fresh DB + upgrade path + rollback expectations)	P1	M	ion-drift-storage tests	Yes	Yes
20	Add task reliability tests (restart behavior, timeout handling, idempotency)	P1	L	tasks + runtime orchestration tests	Partial	Yes
21	Add environment portability tests (path/config overrides, container assumptions)	P2	M	config loaders/startup validation	Yes	Yes
Docs/onboarding gaps
Order	Item	Priority	Difficulty	Affected files/modules	AI-assisted safe?	Human review required?
22	Update README/FEATURES to match actual capabilities and constraints	P0	S	README.md, FEATURES.md	Yes	Yes
23	Publish deployment guide: single-node, container, VPS, reverse proxy/TLS	P1	M	docs folder + README links	Yes	Yes
24	Add configuration reference (every env/config key, defaults, required/optional)	P1	M	docs + config module	Yes	Yes
25	Add security operations guide (secrets rotation, cookie/session hardening, least privilege)	P1	M	docs/security	Yes	Yes
26	Add troubleshooting/runbook (health checks, common failures, recovery steps)	P2	M	docs/operations	Yes	Yes
Suggested execution sequence
Security P0 items (1-3).
Config portability P0 items (6-7).
Core reliability refactor (12) and DB safety refactor (14).
Security and migration tests (17-19).
Remaining P1 config/refactor/testing items (8-11, 13, 15, 20).
Docs/onboarding completion (22-25), then nice-to-have hardening (16, 21, 26).