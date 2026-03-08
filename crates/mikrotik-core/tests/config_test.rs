use mikrotik_core::MikrotikConfig;

#[test]
fn mikrotik_config_rejects_empty_host() {
    let cfg = MikrotikConfig {
        host: "".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    assert!(cfg.validate().is_err());
}

#[test]
fn mikrotik_config_warns_on_default_host() {
    let cfg = MikrotikConfig {
        host: "192.168.88.1".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    let warnings = cfg.validate().expect("validate");
    assert!(!warnings.is_empty());
}

#[test]
fn mikrotik_config_accepts_custom_host() {
    let cfg = MikrotikConfig {
        host: "10.0.0.1".into(),
        port: 443,
        tls: true,
        ca_cert_path: None,
        username: "admin".into(),
        password: "secret".into(),
    };
    let warnings = cfg.validate().expect("validate");
    assert!(warnings.is_empty());
}
