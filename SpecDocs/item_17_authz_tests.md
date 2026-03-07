# Problem Fix Item 17 — Authorization Regression Tests

## Priority: P0 | Difficulty: M | Safe for AI: Yes | Needs human review: Yes

## Problem

All mutating API routes require `RequireAdmin` authorization, but there are no tests verifying this. A refactor could accidentally downgrade a route from `RequireAdmin` to `RequireAuth` (or remove auth entirely) without detection.

## Goal

Add integration tests that verify:
1. All POST/PUT/DELETE routes reject unauthenticated requests (401)
2. All admin-only routes reject non-admin authenticated requests (403)
3. All admin-only routes accept admin authenticated requests (200 or appropriate success)

## Scope

### 1. Create test infrastructure

Create a test helper module that can:
- Build an `AppState` with mock/test stores (in-memory SQLite, no real router)
- Create test sessions (admin and non-admin) in the session store
- Build an Axum test client using `axum::Router` directly (no network)

**File:** `crates/ion-drift-web/tests/common/mod.rs`

```rust
use axum::Router;
use axum_test::TestServer; // or use tower::ServiceExt directly

pub struct TestApp {
    pub router: Router,
    pub admin_cookie: String,
    pub viewer_cookie: String,
}

impl TestApp {
    pub async fn new() -> Self { ... }
}
```

**Dependencies to add to `Cargo.toml` `[dev-dependencies]`:**
- `axum-test` or use `tower::ServiceExt` with `oneshot()` — check which is simpler
- `tempfile` for temporary SQLite databases

### 2. Enumerate all admin-only routes

Extract the complete list from `routes/mod.rs`. As of current code, admin-only routes include:

**POST routes (admin):**
- `/api/devices` (create_device)
- `/api/devices/test` (test_connection)
- `/api/devices/{id}/test` (test_device)
- `/api/behavior/anomalies/{id}/resolve`
- `/api/behavior/anomaly-links/{id}/resolve`
- `/api/behavior/port-baseline/compute`
- `/api/network/identities/bulk-confirm`
- `/api/network/identities/bulk-disposition`
- `/api/network/topology/refresh`
- `/api/alerts/rules` (create_rule)
- `/api/alerts/channels/{channel}/test`
- `/api/settings/secrets/session/regenerate`

**PUT routes (admin):**
- `/api/devices/{id}` (update_device)
- `/api/settings/secrets` (update_secrets)
- `/api/network/identities/{mac}`
- `/api/network/identities/{mac}/disposition`
- `/api/network/port-bindings/{device_id}/{port}`
- `/api/network/topology/positions/{nodeId}`
- `/api/alerts/rules/{id}`
- `/api/alerts/channels/{channel}`

**DELETE routes (admin):**
- `/api/devices/{id}` (delete_device)
- `/api/network/port-bindings/{device_id}/{port}`
- `/api/network/topology/positions/{nodeId}`
- `/api/alerts/rules/{id}`
- `/api/alerts/history`

### 3. Write test cases

**File:** `crates/ion-drift-web/tests/authz_test.rs`

For each route category, write:

```rust
#[tokio::test]
async fn post_devices_rejects_unauthenticated() {
    let app = TestApp::new().await;
    let resp = app.post("/api/devices").send().await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn post_devices_rejects_non_admin() {
    let app = TestApp::new().await;
    let resp = app.post("/api/devices")
        .cookie(&app.viewer_cookie)
        .json(&json!({}))
        .send().await;
    assert_eq!(resp.status(), 403);
}
```

Use a table-driven pattern to avoid boilerplate:

```rust
const ADMIN_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/devices"),
    ("POST", "/api/devices/test"),
    ("PUT", "/api/devices/test-id"),
    ("DELETE", "/api/devices/test-id"),
    // ... etc
];

#[tokio::test]
async fn all_admin_routes_reject_unauthenticated() {
    let app = TestApp::new().await;
    for (method, path) in ADMIN_ROUTES {
        let resp = app.request(method, path).send().await;
        assert_eq!(resp.status(), 401, "expected 401 for {method} {path}");
    }
}

#[tokio::test]
async fn all_admin_routes_reject_viewer() {
    let app = TestApp::new().await;
    for (method, path) in ADMIN_ROUTES {
        let resp = app.request(method, path)
            .cookie(&app.viewer_cookie)
            .json(&json!({}))
            .send().await;
        assert!(
            resp.status() == 403 || resp.status() == 415,
            "expected 403/415 for {method} {path}, got {}",
            resp.status()
        );
    }
}
```

Note: 415 is acceptable for POST routes that receive empty bodies and hit the CSRF Content-Type check before the auth check. The key assertion is that the response is NOT 200/201/204.

### 4. Verify GET routes require authentication

Also test that all `/api/*` GET routes return 401 without a session cookie:

```rust
const API_GET_ROUTES: &[&str] = &[
    "/api/system/resources",
    "/api/system/identity",
    "/api/interfaces",
    // ... all GET routes
];

#[tokio::test]
async fn all_api_get_routes_require_auth() {
    let app = TestApp::new().await;
    for path in API_GET_ROUTES {
        let resp = app.get(path).send().await;
        assert_eq!(resp.status(), 401, "expected 401 for GET {path}");
    }
}
```

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/tests/common/mod.rs` | NEW — test harness |
| `crates/ion-drift-web/tests/authz_test.rs` | NEW — auth regression tests |
| `crates/ion-drift-web/Cargo.toml` | Add dev-dependencies |

## Constraints

- Tests must NOT require a real router, real Keycloak, or network access
- Use in-memory or tempfile SQLite databases
- The `MikrotikClient` in test state can be a real client pointed at a non-existent host — the tests only check auth, not business logic
- Tests should be fast (< 5 seconds total)
- Do NOT modify production code to make it testable — work with the existing structure

## Verification

1. `cargo test -p ion-drift-web` passes
2. All admin routes are covered
3. All GET routes are covered
4. Tests fail if auth is removed from a route (verify by temporarily removing `RequireAdmin` from one handler)
