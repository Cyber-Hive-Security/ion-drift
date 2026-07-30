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
        "DRIFT_ROUTER_PASSWORD",
        "DRIFT_OIDC_SECRET",
        "DRIFT_SESSION_SECRET",
        "DRIFT_ROUTER_DNS_SERVER",
        "DRIFT_ROUTER_LOCAL_SOURCE_IP",
    ] {
        assert!(src.contains(name), "missing env var reference: {name}");
    }
}

/// `[router] local_source_ip` has to be reachable from the environment.
///
/// Drift's own deployments are containers (`Dockerfile`,
/// `config/production.example.toml`), where an operator drives config by env
/// var. With no override for this field they cannot set it at all, so they stay
/// silently on the loopback-only fallback — and Drift's own retries with a stale
/// stored router password get reported as a brute-force attack, which is the
/// exact false positive the field exists to prevent.
///
/// One test rather than several because it mutates a process-global: no other
/// test in this binary reads `DRIFT_ROUTER_LOCAL_SOURCE_IP` or calls
/// `ServerConfig::load`, so nothing can observe it mid-flight.
#[test]
fn local_source_ip_is_env_overridable_and_bad_values_are_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("server.toml");
    std::fs::write(&path, "[server]\n[router]\nhost = \"192.168.1.1\"\n").expect("write config");

    // SAFETY: see the doc comment — this variable is confined to this test.
    unsafe { std::env::set_var("DRIFT_ROUTER_LOCAL_SOURCE_IP", "10.20.25.27") };
    let config = ServerConfig::load(&path).expect("load with env override");
    assert_eq!(
        config.router.local_source_ip.as_deref(),
        Some("10.20.25.27"),
        "the env var must reach [router] local_source_ip"
    );

    // A compose file routinely hands over a padded value; the comparison in
    // `alerting::is_own_source` is on parsed addresses, so store it canonical.
    unsafe { std::env::set_var("DRIFT_ROUTER_LOCAL_SOURCE_IP", "  10.20.25.27  ") };
    let config = ServerConfig::load(&path).expect("load with padded env override");
    assert_eq!(config.router.local_source_ip.as_deref(), Some("10.20.25.27"));

    // A typo must not sit there looking configured while matching nothing: it is
    // dropped, so the documented loopback-only fallback is what actually runs.
    // And it must never stop a monitoring server from starting.
    unsafe { std::env::set_var("DRIFT_ROUTER_LOCAL_SOURCE_IP", "10.20.25.27:443") };
    let config = ServerConfig::load(&path).expect("a bad value must not fail startup");
    assert_eq!(config.router.local_source_ip, None);

    unsafe { std::env::remove_var("DRIFT_ROUTER_LOCAL_SOURCE_IP") };
    let config = ServerConfig::load(&path).expect("load without env override");
    assert_eq!(config.router.local_source_ip, None);
}

/// The validator's own contract, asserted on its return rather than on a log
/// line. Anything that is not an `IpAddr` is rejected — a port suffix, a CIDR
/// mask, a hostname — because `alerting::is_own_source` parses before it
/// compares, so an unparseable value suppresses nothing while still counting as
/// "configured" and disabling the source-less/loopback fallback.
#[test]
fn local_source_ip_validator_rejects_non_addresses() {
    use ion_drift_web::config::validate_local_source_ip;

    assert_eq!(
        validate_local_source_ip(Some("10.20.25.27")),
        Some("10.20.25.27".parse().unwrap())
    );
    assert_eq!(
        validate_local_source_ip(Some(" 2001:db8::1 ")),
        Some("2001:db8::1".parse().unwrap()),
        "surrounding whitespace is not a typo worth rejecting"
    );

    for bad in [
        "",
        "   ",
        "not-an-ip",
        "10.20.25.27:443",
        "10.20.25.0/24",
        "10.20.25.999",
        "localhost",
    ] {
        assert_eq!(
            validate_local_source_ip(Some(bad)),
            None,
            "{bad:?} is not an address and must be rejected"
        );
    }
    assert_eq!(validate_local_source_ip(None), None);
}

/// Both shipped configs have to name the env var, not just the TOML key — the
/// container deployment can only use the env var.
#[test]
fn example_configs_document_local_source_ip_env_var() {
    for rel in [
        "../../config/server.example.toml",
        "../../config/production.example.toml",
    ] {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel),
        )
        .unwrap_or_else(|e| panic!("read {rel}: {e}"));
        assert!(
            src.contains("local_source_ip"),
            "{rel} must document the local_source_ip field"
        );
        assert!(
            src.contains("DRIFT_ROUTER_LOCAL_SOURCE_IP"),
            "{rel} must name the env var alongside the field"
        );
    }
}
