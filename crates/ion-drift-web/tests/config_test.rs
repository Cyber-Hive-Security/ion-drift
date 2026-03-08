use ion_drift_web::config::ServerConfig;

#[test]
fn config_loads_minimal_toml() {
    let toml = r#"
        [server]
        [router]
        [oidc]
        issuer_url = "https://auth.example.com/realms/test"
        client_id = "test-client"
        redirect_uri = "http://localhost:3000/auth/callback"
    "#;
    let config: ServerConfig = toml::from_str(toml).expect("parse minimal config");
    assert_eq!(config.server.listen_port, 3000);
    assert_eq!(config.router.host, "192.168.88.1");
    assert_eq!(config.session.max_age_seconds, 86400);
}

#[test]
fn config_loads_full_example_toml() {
    let toml = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/server.example.toml"),
    )
    .expect("read server example");
    let config: ServerConfig = toml::from_str(&toml).expect("parse full config");
    assert!(!config.router.host.is_empty());
    assert!(config.server.listen_port > 0);
}

#[test]
fn config_handles_unknown_fields_current_behavior() {
    let toml = r#"
        [server]
        listen_port = 8080
        unknown_field = "ignored"
        [router]
        [oidc]
        issuer_url = "https://auth.example.com/realms/test"
        client_id = "test"
        redirect_uri = "http://localhost:3000/auth/callback"
    "#;
    let result: Result<ServerConfig, _> = toml::from_str(toml);
    assert!(result.is_ok(), "unknown fields should currently be ignored");
}

#[test]
fn tls_default_paths_are_absolute() {
    let tls = ion_drift_web::config::TlsSection::default();
    assert!(tls.client_cert.starts_with('/'));
    assert!(tls.client_key.starts_with('/'));
}

#[test]
fn env_var_names_are_referenced_in_config_code() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config.rs"),
    )
    .expect("read config.rs");
    for name in [
        "HIVE_ROUTER_PASSWORD",
        "HIVE_ROUTER_OIDC_SECRET",
        "HIVE_ROUTER_SESSION_SECRET",
        "HIVE_ROUTER_DNS_SERVER",
    ] {
        assert!(src.contains(name), "missing env var reference: {name}");
    }
}
