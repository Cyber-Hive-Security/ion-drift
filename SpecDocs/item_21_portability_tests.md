# Problem Fix Item 21 — Environment Portability Tests

## Priority: P2 | Difficulty: M | Safe for AI: Yes | Needs human review: Yes

## Problem

ion-drift has several environment assumptions that could break when deploying to different systems:
1. Config file paths assume specific locations (`/app/data/certs/`, etc.)
2. Default values reference Mikrotik factory defaults that may not match user's router
3. Environment variable names are scattered across code
4. Data directory creation is implicit
5. No validation that required external dependencies (MaxMind DBs, CA certs) exist

## Goal

Add tests that verify the application handles different environment configurations gracefully — missing files, missing env vars, custom paths, etc.

## Scope

### 1. Config loading tests

Verify that `ServerConfig` loads correctly from TOML with various configurations:

```rust
#[test]
fn config_loads_minimal_toml() {
    // Only required fields: oidc.issuer_url, oidc.client_id, oidc.redirect_uri
    let toml = r#"
    [server]
    [router]
    [oidc]
    issuer_url = "https://auth.example.com/realms/test"
    client_id = "test-client"
    redirect_uri = "http://localhost:3000/auth/callback"
    "#;
    let config: ServerConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.server.listen_port, 3000);
    assert_eq!(config.router.host, "192.168.88.1");
    assert_eq!(config.session.max_age_seconds, 86400);
}

#[test]
fn config_loads_full_toml() {
    // All fields specified
    let toml = std::fs::read_to_string("config/server.example.toml").unwrap();
    let config: ServerConfig = toml::from_str(&toml).unwrap();
    // Verify all sections loaded
    assert!(!config.router.host.is_empty());
    assert!(config.server.listen_port > 0);
}

#[test]
fn config_handles_unknown_fields_gracefully() {
    // TOML with extra fields that don't exist in the struct
    let toml = r#"
    [server]
    listen_port = 8080
    unknown_field = "should be ignored"
    [router]
    [oidc]
    issuer_url = "https://auth.example.com/realms/test"
    client_id = "test"
    redirect_uri = "http://localhost:3000/auth/callback"
    "#;
    // This should either succeed (serde ignore) or fail clearly
    let result: Result<ServerConfig, _> = toml::from_str(toml);
    // Document current behavior — does serde deny_unknown_fields?
}
```

### 2. Default value tests

Verify all defaults are sane:

```rust
#[test]
fn config_defaults_are_valid() {
    let config = ServerConfig {
        server: ServerSection { listen_addr: "0.0.0.0".into(), listen_port: 3000 },
        router: RouterSection { /* defaults */ },
        oidc: OidcSection { /* minimal */ },
        session: SessionSection::default(),
        data: DataSection::default(),
        tls: TlsSection::default(),
        certwarden: CertWardenSection::default(),
        syslog: SyslogSection::default(),
    };
    // Validate each default
    assert!(config.server.listen_port > 0 && config.server.listen_port < 65535);
    assert!(config.router.port > 0);
    assert!(config.session.max_age_seconds > 0);
    assert!(!config.session.cookie_name.is_empty());
}
```

### 3. Environment variable override tests

Verify that env var loading works correctly:

```rust
#[test]
fn env_vars_are_read() {
    // Test that the expected env vars are documented
    // This is a documentation test — verify the list is correct
    let expected_env_vars = [
        "HIVE_ROUTER_PASSWORD",
        "HIVE_ROUTER_OIDC_SECRET",
        "HIVE_ROUTER_SESSION_SECRET",
        "HIVE_ROUTER_DNS_SERVER",
    ];
    // Verify these are referenced in the code
    for var in &expected_env_vars {
        // grep-like check that the var appears in config.rs or main.rs
        // This is a compile-time constant check
    }
}
```

### 4. Path handling tests

Verify that paths work with different configurations:

```rust
#[test]
fn tls_default_paths_are_absolute() {
    let tls = TlsSection::default();
    assert!(tls.client_cert.starts_with('/'), "cert path should be absolute");
    assert!(tls.client_key.starts_with('/'), "key path should be absolute");
}

#[test]
fn data_directory_creation() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    // Verify that store constructors create the directory if needed
    // (or document that they don't)
}
```

### 5. MikrotikConfig validation tests

Test the `validate()` method on `MikrotikConfig`:

```rust
#[test]
fn mikrotik_config_rejects_empty_host() {
    let config = MikrotikConfig {
        host: "".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    assert!(config.validate().is_err());
}

#[test]
fn mikrotik_config_warns_on_default_host() {
    let config = MikrotikConfig {
        host: "192.168.88.1".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    let warnings = config.validate().unwrap();
    assert!(!warnings.is_empty(), "should warn about factory default host");
}

#[test]
fn mikrotik_config_accepts_custom_host() {
    let config = MikrotikConfig {
        host: "10.0.0.1".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    let warnings = config.validate().unwrap();
    assert!(warnings.is_empty());
}
```

## Key files

| File | Action |
|------|--------|
| `crates/ion-drift-web/tests/config_test.rs` | NEW — config and env tests |
| `crates/mikrotik-core/tests/config_test.rs` | NEW — MikrotikConfig validation tests |
| Both `Cargo.toml` files | Add `tempfile` to dev-dependencies if not already present |

## Constraints

- Do NOT set/unset real environment variables in tests — use test-specific config structs
- Use `tempfile` for all path tests
- Tests must work on any OS (Linux/macOS) — no OS-specific path assumptions
- Do NOT modify production code — test what exists
- Tests should complete in < 5 seconds

## Verification

1. `cargo test -p ion-drift-web config` passes
2. `cargo test -p mikrotik-core config` passes
3. Config loading with minimal/full TOML tested
4. Default values validated
5. MikrotikConfig validation tested
