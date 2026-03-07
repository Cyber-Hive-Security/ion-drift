# Problem Fix Item 15 — Session/State Architecture Hardening

## Priority: P1 | Difficulty: L | Safe for AI: Partial | Needs human review: Yes

## Problem

Sessions are stored in-memory using `DashMap`. This means:
1. All sessions are lost on server restart (users must re-authenticate)
2. Multiple ion-drift instances can't share sessions (no horizontal scaling)
3. No session activity tracking (last-accessed time, IP, user-agent)

For a single-instance homelab deployment, (1) is the primary pain point. (2) and (3) are secondary but worth addressing while touching sessions.

## Goal

1. Persist sessions to SQLite so they survive restarts
2. Add session metadata (last_accessed, created_ip, user_agent)
3. Design the store interface so it could be swapped to Redis later (but don't implement Redis now)

## Scope

### 1. Create SQLite-backed session store

Replace the current `DashMap`-only store with a SQLite + in-memory hybrid:
- DashMap remains as a hot cache (fast reads, no DB query per request)
- SQLite provides persistence across restarts
- On startup, load all non-expired sessions from SQLite into DashMap
- On session create: write to both DashMap and SQLite
- On session access: update `last_accessed` in DashMap; flush to SQLite periodically (every 5 min)
- On session delete/expire: remove from both

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    email TEXT,
    roles TEXT NOT NULL,        -- JSON array
    created_at INTEGER NOT NULL,
    last_accessed INTEGER NOT NULL,
    created_ip TEXT,
    user_agent TEXT
);

CREATE INDEX idx_sessions_expiry ON sessions (created_at);
```

**Files:**
- MODIFY: `crates/ion-drift-web/src/auth.rs` — extend `SessionStore` with SQLite
- MODIFY: `crates/ion-drift-web/src/auth.rs` — extend `SessionData` with `last_accessed`, `created_ip`, `user_agent`
- MODIFY: `crates/ion-drift-web/src/middleware.rs` — capture IP and user-agent from request on session access
- MODIFY: `crates/ion-drift-web/src/main.rs` — pass data directory to `SessionStore::new()`

### 2. Add session metadata to auth callback

When a session is created in `auth::callback()`, capture:
- `created_ip`: from `ConnectInfo` or `X-Forwarded-For` header
- `user_agent`: from `User-Agent` header
- `last_accessed`: set to `created_at` initially

### 3. Update session access to track last-accessed

In `SessionStore::get()`, update `last_accessed` on the in-memory entry. The periodic flush task writes dirty entries to SQLite.

### 4. Add admin session list endpoint

Add `GET /api/settings/sessions` (admin only) that returns active sessions:

```json
{
  "sessions": [
    {
      "username": "yodaadmin",
      "created_at": "2026-03-07T10:00:00Z",
      "last_accessed": "2026-03-07T14:30:00Z",
      "created_ip": "10.20.30.93",
      "user_agent": "Mozilla/5.0...",
      "is_current": true
    }
  ]
}
```

And `DELETE /api/settings/sessions/{session_id}` to revoke a specific session.

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/src/auth.rs` | Major changes — SQLite persistence, metadata |
| `crates/ion-drift-web/src/middleware.rs` | Capture IP/UA on session access |
| `crates/ion-drift-web/src/main.rs` | Pass data dir to session store |
| `crates/ion-drift-web/src/routes/settings.rs` | Add session list/revoke endpoints |
| `crates/ion-drift-web/src/routes/mod.rs` | Register new routes |

## Constraints

- The DashMap hot cache is critical for performance — every request checks the session. Do NOT remove it.
- SQLite writes must NOT block request handling — use async/spawn for flushes
- Session IDs are generated with `rand` — do NOT change the generation algorithm
- The `cleanup()` method must clean both DashMap and SQLite
- `clear_all()` (used by session secret regeneration) must also clear SQLite
- Do NOT implement Redis — just structure the code so `SessionStore` could be trait-ified later
- The session DB should live in the data directory alongside other SQLite files

## Important: !Send pattern

The session SQLite DB must follow the same pattern as other stores in this codebase:
- `rusqlite::Connection` is `!Send` — it cannot be held across `.await` points
- Use `tokio::sync::Mutex` or `std::sync::Mutex` and scope DB access in non-async blocks
- See `BehaviorStore` and `ConnectionStore` for reference patterns

## Verification

1. `cargo check --workspace` passes
2. Server restarts preserve active sessions (user stays logged in)
3. `GET /api/settings/sessions` returns active session list
4. `DELETE /api/settings/sessions/{id}` revokes a session
5. Expired sessions are cleaned from both DashMap and SQLite
6. `clear_all()` clears both stores
7. No performance regression on session-heavy request flows
