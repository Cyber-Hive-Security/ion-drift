# Problem Fix Item 13 — Extract Env-Specific Logic into Adapters

## Priority: P1 | Difficulty: L | Safe for AI: Partial | Needs human review: Yes

## Problem

Several modules contain environment-specific logic mixed into domain/business logic:
- `correlation_engine.rs` — DNS resolution uses a hardcoded resolver builder with Hickory DNS; the resolver construction is tangled with the correlation loop
- `geo.rs` — MaxMind database loading, HTTP-based geo fallback, and geo caching are all in one struct; download logic is mixed with lookup logic
- `connection_store.rs` — syslog parsing, connection persistence, and geo-enrichment are interleaved
- `bootstrap.rs` — Keycloak-specific API calls are hardcoded; no abstraction for alternative identity providers

The issue is testability and portability — these modules can't be tested without real network access, real databases, or real MaxMind files.

## Goal

Introduce clean adapter boundaries so that:
1. Domain logic can be tested with mock implementations
2. Environment-specific setup (DNS resolver, MaxMind, Keycloak) is isolated
3. No functional changes — this is purely structural

## Scope

### 1. Extract DNS resolution adapter

**Current state:** `correlation_engine.rs` calls `build_ptr_resolver()` which constructs a Hickory `AsyncResolver` inline.

**Target:** Create a trait + two implementations:

```rust
// crates/ion-drift-web/src/dns.rs
pub trait DnsResolver: Send + Sync {
    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String>;
}

pub struct HickoryResolver { resolver: AsyncResolver<...> }
pub struct SystemResolver; // falls back to tokio::net::lookup_addr
```

Wire `HickoryResolver` in production, but the trait allows test doubles.

**Files:**
- NEW: `crates/ion-drift-web/src/dns.rs`
- MODIFY: `crates/ion-drift-web/src/correlation_engine.rs` — accept `Arc<dyn DnsResolver>` instead of building inline
- MODIFY: `crates/ion-drift-web/src/main.rs` — construct resolver and pass it in

### 2. Extract geo lookup adapter

**Current state:** `geo.rs` has `GeoCache` which combines: MaxMind MMDB loading, SQLite caching, and HTTP fallback lookup. The `resolve()` method chains all three.

**Target:** Separate the lookup provider from the cache:

```rust
// Keep GeoCache as the caching layer, but extract the lookup source
pub trait GeoProvider: Send + Sync {
    async fn lookup(&self, ip: &str) -> Option<GeoResult>;
}

pub struct MaxMindProvider { ... }
// HTTP fallback provider (ip-api.com) was already removed — do NOT re-add
```

This is a lighter change — `GeoCache` stays as-is but its `resolve()` method delegates to an injected provider instead of directly reading MMDB files.

**Files:**
- MODIFY: `crates/ion-drift-web/src/geo.rs` — add trait, refactor `GeoCache::resolve()`

### 3. Do NOT refactor bootstrap or connection_store

The bootstrap module is Keycloak-specific by design (mTLS KEK retrieval). There's no near-term need for alternative identity providers.

The connection store's syslog parsing is tightly coupled to RouterOS format by design. Abstracting it would add complexity without benefit.

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/src/dns.rs` | NEW — DNS resolver trait + implementations |
| `crates/ion-drift-web/src/correlation_engine.rs` | Accept `Arc<dyn DnsResolver>` |
| `crates/ion-drift-web/src/geo.rs` | Add `GeoProvider` trait, refactor cache |
| `crates/ion-drift-web/src/main.rs` | Construct adapters and inject them |

## Constraints

- Do NOT create traits for things that have only one implementation and no testability need
- Do NOT change public API signatures beyond what's needed for injection
- Do NOT change the `AppState` struct — adapters are injected at construction time, not stored in state
- Keep traits minimal — 1-2 methods, not kitchen-sink interfaces
- `async fn` in traits requires `async-trait` crate OR Rust 1.75+ RPITIT — check current MSRV before choosing

## Verification

1. `cargo check --workspace` passes
2. `correlation_engine.rs` no longer imports Hickory directly
3. `geo.rs` lookup logic is behind a trait
4. No behavioral changes when running the server
