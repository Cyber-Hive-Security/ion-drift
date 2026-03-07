mod common;

use std::collections::HashSet;
use std::fs;

fn extract_mutating_routes() -> Vec<(String, String, String)> {
    let src = common::read_repo_file("src/routes/mod.rs");
    let mut out = Vec::new();

    for line in src.lines().map(str::trim) {
        if !line.starts_with(".route(\"/") {
            continue;
        }
        if line.contains("\"/auth/") || line.contains("\"/health\"") {
            continue;
        }
        for method in ["post", "put", "delete"] {
            let needle = format!("{method}(");
            if let Some(idx) = line.find(&needle) {
                let path_start = line.find('"').expect("path start quote") + 1;
                let path_end = line[path_start..]
                    .find('"')
                    .map(|i| path_start + i)
                    .expect("path end quote");
                let path = line[path_start..path_end].to_string();
                let after = &line[idx + needle.len()..];
                let handler_end = after.find(')').expect("handler close paren");
                let handler = after[..handler_end].trim().to_string();
                out.push((method.to_uppercase(), path, handler));
            }
        }
    }

    out
}

#[test]
fn api_routes_have_global_auth_layer() {
    let src = common::read_repo_file("src/routes/mod.rs");
    assert!(
        src.contains(".layer(middleware::from_fn_with_state(state.clone(), require_auth_layer))"),
        "expected /api global auth middleware in routes/mod.rs"
    );
}

#[test]
fn all_mutating_api_handlers_require_admin_extractor() {
    let mutating = extract_mutating_routes();
    assert!(
        !mutating.is_empty(),
        "expected to find mutating routes in src/routes/mod.rs"
    );

    let mut route_sources = String::new();
    for path in common::source_paths_under("src/routes") {
        route_sources.push_str(&fs::read_to_string(path).expect("route source"));
        route_sources.push('\n');
    }

    // Mutating routes should require RequireAdmin in handler signature.
    // We tolerate auth/logout because it's not in /api routes.
    let mut missing = Vec::new();
    for (_method, path, handler) in mutating {
        let signature_needle = format!("pub async fn {handler}(");
        if let Some(sig_start) = route_sources.find(&signature_needle) {
            let tail = &route_sources[sig_start..route_sources.len().min(sig_start + 300)];
            if !tail.contains("RequireAdmin") {
                missing.push((path, handler));
            }
        } else {
            missing.push((path, handler));
        }
    }

    assert!(
        missing.is_empty(),
        "mutating handlers missing RequireAdmin: {missing:?}"
    );
}

#[test]
fn route_inventory_is_generated_from_current_router() {
    let mutating = extract_mutating_routes();
    let unique: HashSet<_> = mutating.iter().map(|(m, p, _)| format!("{m}:{p}")).collect();
    assert_eq!(
        unique.len(),
        mutating.len(),
        "duplicate mutating route entries detected"
    );
}
