# Problem Fix Item 18 — CSRF Protection Tests

## Priority: P0 | Difficulty: M | Safe for AI: Partial | Needs human review: Yes

## Problem

CSRF protection was added via a `csrf_guard_layer` middleware that rejects non-GET requests with bodies that don't have `Content-Type: application/json`. Combined with SameSite=Lax cookies and CORS, this provides defense-in-depth. But there are no tests verifying this works.

## Goal

Add tests that verify:
1. POST/PUT/DELETE requests with `Content-Type: application/x-www-form-urlencoded` are rejected (415)
2. POST/PUT/DELETE requests with `Content-Type: multipart/form-data` are rejected (415)
3. POST/PUT/DELETE requests with `Content-Type: application/json` are accepted (pass through to auth)
4. POST/PUT/DELETE requests with no body (Content-Length: 0) are accepted (pass through to auth)
5. GET/HEAD/OPTIONS requests are not affected by the CSRF guard

## Scope

### 1. Unit test the middleware directly

The CSRF guard is a standalone middleware function in `routes/mod.rs`:

```rust
async fn csrf_guard_layer(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response { ... }
```

Test it by building requests with different Content-Type headers and passing them through the middleware with a mock `Next` handler.

**File:** `crates/ion-drift-web/tests/csrf_test.rs`

### 2. Test cases

```rust
#[tokio::test]
async fn csrf_rejects_form_urlencoded_post() {
    // POST with Content-Type: application/x-www-form-urlencoded and body
    // Should return 415
}

#[tokio::test]
async fn csrf_rejects_multipart_post() {
    // POST with Content-Type: multipart/form-data and body
    // Should return 415
}

#[tokio::test]
async fn csrf_rejects_text_plain_post() {
    // POST with Content-Type: text/plain and body
    // Should return 415
}

#[tokio::test]
async fn csrf_allows_json_post() {
    // POST with Content-Type: application/json and body
    // Should pass through (200 from mock handler)
}

#[tokio::test]
async fn csrf_allows_empty_body_post() {
    // POST with Content-Length: 0 and no Content-Type
    // Should pass through
}

#[tokio::test]
async fn csrf_allows_get_requests() {
    // GET with any Content-Type
    // Should pass through
}

#[tokio::test]
async fn csrf_allows_options_requests() {
    // OPTIONS (CORS preflight)
    // Should pass through
}
```

### 3. Integration test via router

Also test through the full router stack using the test harness from item 17:

```rust
#[tokio::test]
async fn full_stack_csrf_form_post_rejected() {
    let app = TestApp::new().await;
    let resp = app.post("/api/devices")
        .cookie(&app.admin_cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("host=evil.com&port=443")
        .send().await;
    assert_eq!(resp.status(), 415);
}
```

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/tests/csrf_test.rs` | NEW — CSRF unit tests |
| `crates/ion-drift-web/src/routes/mod.rs` | May need to make `csrf_guard_layer` pub(crate) for testing |

## Constraints

- Reuse the test harness from item 17 if available
- If `csrf_guard_layer` is private, either make it `pub(crate)` or test through the full router
- Tests should be fast
- The middleware is in the API routes layer — `/auth/*` and `/health` are NOT protected by CSRF (they're outside the nest)

## Verification

1. `cargo test -p ion-drift-web` passes
2. All 3 dangerous Content-Types are tested (form-urlencoded, multipart, text/plain)
3. JSON and empty-body requests pass through
4. GET/OPTIONS are unaffected
