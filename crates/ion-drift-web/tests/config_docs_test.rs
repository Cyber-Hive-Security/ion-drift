mod common;

fn flatten(prefix: &str, v: &toml::Value, out: &mut Vec<String>) {
    if let Some(table) = v.as_table() {
        for (k, child) in table {
            let key = if prefix.is_empty() {
                k.to_string()
            } else {
                format!("{prefix}.{k}")
            };
            if child.is_table() {
                flatten(&key, child, out);
            } else {
                out.push(key);
            }
        }
    }
}

#[test]
fn server_example_contains_documented_keys() {
    let src = common::read_repo_file("../../config/server.example.toml");
    let parsed: toml::Value = toml::from_str(&src).expect("parse server.example.toml");
    let mut keys = Vec::new();
    flatten("", &parsed, &mut keys);

    let required = [
        "server.listen_addr",
        "server.listen_port",
        "router.host",
        "router.port",
        "router.tls",
        "router.ca_cert_path",
        "router.username",
        "router.wan_interface",
        "oidc.issuer_url",
        "oidc.client_id",
        "oidc.redirect_uri",
        "session.cookie_name",
        "session.max_age_seconds",
        "session.secure",
        "session.same_site",
    ];

    for k in required {
        assert!(keys.iter().any(|x| x == k), "missing key in server example: {k}");
    }
}

#[test]
fn cli_example_contains_documented_keys() {
    let src = common::read_repo_file("../../config/cli.example.toml");
    let parsed: toml::Value = toml::from_str(&src).expect("parse cli.example.toml");
    let mut keys = Vec::new();
    flatten("", &parsed, &mut keys);

    let required = [
        "router.host",
        "router.port",
        "router.tls",
        "router.username",
    ];

    for k in required {
        assert!(keys.iter().any(|x| x == k), "missing key in cli example: {k}");
    }
}
