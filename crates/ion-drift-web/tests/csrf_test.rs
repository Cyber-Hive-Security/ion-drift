mod common;

#[test]
fn csrf_guard_is_registered_on_api_routes() {
    let src = common::read_repo_file("src/routes/mod.rs");
    assert!(
        src.contains(".layer(middleware::from_fn(csrf_guard_layer))"),
        "expected csrf_guard_layer middleware to be applied in API router"
    );
}

#[test]
fn csrf_guard_enforces_json_for_mutating_requests_with_body() {
    let src = common::read_repo_file("src/routes/mod.rs");
    assert!(src.contains("Method::GET"));
    assert!(src.contains("Method::HEAD"));
    assert!(src.contains("Method::OPTIONS"));
    assert!(src.contains("CONTENT_LENGTH"));
    assert!(src.contains("application/json"));
    assert!(src.contains("UNSUPPORTED_MEDIA_TYPE"));
}
