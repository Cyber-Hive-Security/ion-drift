# Problem Fix Item 19 — Migration Integrity Tests

## Priority: P1 | Difficulty: M | Safe for AI: Yes | Needs human review: Yes

## Problem

ion-drift uses SQLite with schema migrations that run on startup. Each store (`BehaviorStore`, `SwitchStore`, `MetricsStore`, `ConnectionStore`, `TrafficTracker`) creates tables and adds columns via ALTER TABLE in its constructor. There are no tests verifying:

1. A fresh database initializes correctly
2. An old database schema upgrades correctly (migrations apply cleanly)
3. Migrations are idempotent (running twice doesn't fail)

## Goal

Add tests that verify migration integrity for all SQLite stores.

## Scope

### 1. Identify all stores and their migrations

| Store | Crate | Constructor | Tables |
|-------|-------|-------------|--------|
| `BehaviorStore` | mikrotik-core | `BehaviorStore::new(path)` | device_profiles, device_observations, device_anomalies, device_baselines, anomaly_links, vlan_config, task_watermarks |
| `SwitchStore` | mikrotik-core | `SwitchStore::new(path)` | switch_port_metrics, switch_mac_table, switch_neighbors, switch_port_roles, network_identities, observed_services, port_mac_bindings, port_violations, alert_rules, alert_channels, alert_state_cache, alert_history, neighbor_aliases, topology_positions |
| `MetricsStore` | mikrotik-core | `MetricsStore::new(path)` | system_metrics, drop_metrics, connection_metrics, vlan_metrics, log_trends |
| `TrafficTracker` | mikrotik-core | `TrafficTracker::new(path, iface)` | traffic_history |
| `ConnectionStore` | ion-drift-web | `ConnectionStore::new(path)` | connection_history, geo_cache, port_baselines, traffic_classifications |

### 2. Test: fresh database

For each store, create a temporary database and verify the constructor succeeds:

```rust
#[test]
fn behavior_store_fresh_db() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("behavior.db");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let store = rt.block_on(async {
        BehaviorStore::new(&path).await
    });
    assert!(store.is_ok() || /* constructor doesn't return Result */ true);
}
```

Note: Some constructors return `Self` directly (panicking on failure) while others return `Result`. Check each one.

### 3. Test: idempotent migrations

Create a database, construct the store (runs migrations), then construct again:

```rust
#[test]
fn behavior_store_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("behavior.db");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let _store1 = BehaviorStore::new(&path).await;
        drop(_store1);
        let _store2 = BehaviorStore::new(&path).await;
        // If this doesn't panic, migrations are idempotent
    });
}
```

### 4. Test: old schema upgrade

For each store that has ALTER TABLE migrations, create a database with the old schema (without the new columns), then run the constructor to verify migrations apply:

```rust
#[test]
fn behavior_store_upgrades_missing_confidence_column() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("behavior.db");

    // Create old schema without confidence column
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("
        CREATE TABLE device_anomalies (
            id INTEGER PRIMARY KEY,
            mac TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            -- ... old columns without 'confidence'
        );
    ").unwrap();
    drop(conn);

    // Constructor should add the missing column
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = BehaviorStore::new(&path).await;
        // Verify confidence column exists by inserting a record
    });
}
```

### 5. Test: basic CRUD after migration

For each store, verify that after construction, basic operations work:

```rust
#[test]
fn switch_store_crud_after_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("switch.db");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let store = SwitchStore::new(&path).await;
        // Insert a port metric
        let entries = vec![("ether1", 1000u64, 500u64, "1Gbps", true, 1709856000i64)];
        store.record_port_metrics("device1", &entries).await.unwrap();
        // Read it back
        let metrics = store.get_port_metrics("device1", 0).await.unwrap();
        assert_eq!(metrics.len(), 1);
    });
}
```

## Key files

| File | Action |
|------|--------|
| `crates/mikrotik-core/tests/migration_test.rs` | NEW — tests for mikrotik-core stores |
| `crates/ion-drift-web/tests/migration_test.rs` | NEW — tests for ConnectionStore |
| Both `Cargo.toml` files | Add `tempfile` to dev-dependencies |

## Constraints

- Use `tempfile::tempdir()` for all test databases — no hardcoded paths
- Tests must be independent — each creates its own temp directory
- Do NOT modify store constructors to return `Result` if they currently don't
- Tests should run in < 10 seconds total
- Focus on schema correctness, not business logic

## Verification

1. `cargo test -p mikrotik-core` passes with migration tests
2. `cargo test -p ion-drift-web` passes with migration tests
3. All 5 stores have fresh-db, idempotent, and basic-CRUD tests
4. At least one ALTER TABLE upgrade test exists for stores with column migrations
