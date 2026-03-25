# Known Issues

Tracked issues from external code reviews and internal testing.

## Resolved

### [HIGH] Blocking SQLite I/O in StatsStore (stats_store.rs)
**Source:** External review 2026-03-25
**Fixed:** `16b587c` (development)

StatsStore used `tokio::sync::Mutex` with synchronous rusqlite calls, blocking Tokio worker threads during I/O and WAL checkpoints. Fixed by switching to `std::sync::Mutex` + `spawn_blocking` for all database operations.

### [HIGH] Uncaught Synchronous Panic in Task Supervisor (task_supervisor.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

The factory function call is wrapped in `std::panic::catch_unwind` (lines 121-130). The reviewer was working from an older snapshot.

### [MEDIUM] DNS Deviation Query Nondeterminism (policy_deviation_detector.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed in v0.2.4

Query groups by all identity columns `(src_mac, src_ip, src_vlan, dst_ip)` — no `MAX()` aggregation. Fixed in v0.2.4.

### [MEDIUM] VLAN/Global Policy Merge on Authorize (policy_deviations.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed in v0.2.4

Authorize action filters `p.vlan_scope.is_some()` to merge only VLAN-scoped targets, keeping global policies separate. Fixed in v0.2.4.

### [MEDIUM] Missing Jitter in Exponential Backoff (task_supervisor.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

Backoff includes ±25% jitter: `rand::random::<f64>() * 0.5 + 0.75` (line 182).

### [LOW] Magic Numbers for IANA ifType (snmp_profile.rs)
**Source:** External review 2026-03-25
**Status:** Already fixed prior to review

Named constants `IFTYPE_L2_VLAN` and `IFTYPE_SOFTWARE_LOOPBACK` are used.

## Won't Fix

### [LOW] Panic Message Information Leak (task_supervisor.rs)
**Source:** External review 2026-03-25

Panic payloads are logged directly. We don't put secrets in `expect()` messages, and these are container-internal logs, not user-facing output. The sanitization overhead isn't warranted.

### [LOW] Commented-Out Vendor Profile Code (snmp_profile.rs)
**Source:** External review 2026-03-25

The commented code was already removed prior to review. The reviewer was working from an older snapshot.

### [LOW] Policy Lookup Mixed Responsibilities (behavior.rs)
**Source:** External review 2026-03-25

`get_policies_for_service` combines fetching, filtering, and VLAN matching in one method. This is a style/refactor suggestion, not a bug. The current implementation is correct and the method is well-scoped. Refactoring would add abstraction without reducing defect risk.

## Open

### [HIGH] Router Queue Poller Starvation
**Source:** Internal testing 2026-03-25
**Fixed:** `16b587c` (development)

Low-priority pollers (`log_aggregation`, `behavior-fw-cache`) were permanently starved by a steady stream of higher-priority batches. Fixed with age-based priority promotion (batches waiting >120s promoted to High priority) and reduced starvation log noise (warn once per threshold crossing instead of every loop iteration).
