use std::path::PathBuf;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use secrecy::SecretString;

use crate::bootstrap;
use crate::certwarden;
use crate::config::{OidcBootstrapSection, TlsSection};
use crate::secrets::{DecryptedSecrets, SecretsManager};

/// Shared state for the minimal setup-mode server.
/// During first-run setup, there's no SecretsManager yet — the setup form
/// submit handler creates one after fetching the cert and KEK.
#[derive(Clone)]
pub struct SetupState {
    pub db_path: PathBuf,
    pub router_username: String,
    pub tls_config: TlsSection,
    pub oidc_bootstrap: Option<OidcBootstrapSection>,
    pub ca_cert_path: String,
    pub certwarden_base_url: Option<String>,
    pub certwarden_cert_name: Option<String>,
}

/// `GET /setup` — Render the setup form.
pub async fn setup_page(State(state): State<SetupState>) -> Html<String> {
    let username = &state.router_username;
    let cw_url = state.certwarden_base_url.as_deref().unwrap_or("");
    let cw_name = state.certwarden_cert_name.as_deref().unwrap_or("");
    Html(render_setup_html(username, cw_url, cw_name, None))
}

#[derive(serde::Deserialize)]
pub struct SetupForm {
    router_username: String,
    router_password: String,
    oidc_client_secret: String,
    certwarden_cert_api_key: String,
    certwarden_key_api_key: String,
}

/// `POST /setup` — Process the setup form:
/// 1. Fetch cert+key from CertWarden using provided API keys
/// 2. Write cert+key to disk at TLS paths
/// 3. Build mTLS client with the new cert
/// 4. Authenticate to Keycloak → get/generate KEK
/// 5. Create SecretsManager with KEK
/// 6. Encrypt all 6 secrets → SQLite
/// 7. Exit for Docker restart
pub async fn setup_submit(
    State(state): State<SetupState>,
    axum::extract::Form(form): axum::extract::Form<SetupForm>,
) -> Response {
    let cw_url = state.certwarden_base_url.as_deref().unwrap_or("");
    let cw_name = state.certwarden_cert_name.as_deref().unwrap_or("");

    // Validate inputs
    if form.router_username.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some("Router username is required"),
        ))
        .into_response();
    }
    if form.router_password.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some("Router password is required"),
        ))
        .into_response();
    }
    if form.oidc_client_secret.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some("OIDC client secret is required"),
        ))
        .into_response();
    }
    if form.certwarden_cert_api_key.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some("CertWarden Certificate API Key is required"),
        ))
        .into_response();
    }
    if form.certwarden_key_api_key.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some("CertWarden Private Key API Key is required"),
        ))
        .into_response();
    }

    // Step 1: Fetch cert+key from CertWarden
    let cw_config = match state.certwarden_base_url.as_ref().zip(state.certwarden_cert_name.as_ref()) {
        Some((base_url, cert_name)) => {
            let resolved = crate::config::ResolvedCertWarden {
                base_url: base_url.clone(),
                cert_name: cert_name.clone(),
                renewal_threshold_days: 30,
                check_interval_hours: 1,
            };
            Some(resolved)
        }
        None => None,
    };

    let cw_resolved = match cw_config {
        Some(ref cfg) => cfg,
        None => {
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some("CertWarden base_url and cert_name must be set in config"),
            ))
            .into_response();
        }
    };

    let cw_client = match certwarden::CertWardenClient::new(cw_resolved, &state.ca_cert_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to create CertWarden client: {e}");
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some(&format!("Failed to create CertWarden client: {e}")),
            ))
            .into_response();
        }
    };

    let (cert_pem, key_pem) = match cw_client
        .fetch_cert_and_key(
            form.certwarden_cert_api_key.trim(),
            form.certwarden_key_api_key.trim(),
        )
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!("CertWarden fetch failed: {e}");
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some(&format!("Failed to fetch cert from CertWarden: {e}")),
            ))
            .into_response();
        }
    };

    // Step 2: Write cert+key to disk
    if let Err(e) = certwarden::write_cert_and_key(
        &state.tls_config.client_cert,
        &state.tls_config.client_key,
        &cert_pem,
        &key_pem,
    ) {
        tracing::error!("failed to write cert/key: {e}");
        return Html(render_setup_html(
            &form.router_username, cw_url, cw_name,
            Some(&format!("Failed to write cert/key to disk: {e}")),
        ))
        .into_response();
    }

    // Step 3+4: Build mTLS client and fetch KEK from Keycloak
    let bootstrap_config = match &state.oidc_bootstrap {
        Some(b) => {
            let client_id = match &b.client_id {
                Some(id) => id.clone(),
                None => {
                    return Html(render_setup_html(
                        &form.router_username, cw_url, cw_name,
                        Some("oidc.bootstrap.client_id not configured"),
                    ))
                    .into_response();
                }
            };
            let token_url = match &b.token_url {
                Some(u) => u.clone(),
                None => {
                    return Html(render_setup_html(
                        &form.router_username, cw_url, cw_name,
                        Some("oidc.bootstrap.token_url not configured"),
                    ))
                    .into_response();
                }
            };
            let admin_url = match &b.admin_url {
                Some(u) => u.clone(),
                None => {
                    return Html(render_setup_html(
                        &form.router_username, cw_url, cw_name,
                        Some("oidc.bootstrap.admin_url not configured"),
                    ))
                    .into_response();
                }
            };
            crate::config::ResolvedBootstrap {
                cert_path: state.tls_config.client_cert.clone(),
                key_path: state.tls_config.client_key.clone(),
                client_id,
                token_url,
                admin_url,
                kek_attribute: b.kek_attribute.clone(),
            }
        }
        None => {
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some("oidc.bootstrap section not configured"),
            ))
            .into_response();
        }
    };

    let mtls_client = match bootstrap::build_mtls_client(&bootstrap_config, &state.ca_cert_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build mTLS client: {e}");
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some(&format!("Failed to build mTLS client: {e}")),
            ))
            .into_response();
        }
    };

    let data_dir = state.db_path.parent().unwrap_or(std::path::Path::new("."));
    let kek_result = match bootstrap::fetch_or_generate_kek(&mtls_client, &bootstrap_config, data_dir, &state.tls_config.client_cert).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("KEK bootstrap failed: {e}");
            return Html(render_setup_html(
                &form.router_username, cw_url, cw_name,
                Some(&format!("Keycloak KEK bootstrap failed: {e}")),
            ))
            .into_response();
        }
    };

    // Step 5: Create SecretsManager
    let sm = match SecretsManager::new(&state.db_path, kek_result.kek) {
        Ok(sm) => sm,
        Err(e) => {
            tracing::error!("failed to init secrets manager: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(render_setup_html(
                    &form.router_username, cw_url, cw_name,
                    Some("Failed to initialize secrets manager. Check server logs."),
                )),
            )
                .into_response();
        }
    };

    // Step 6: Generate session secret and encrypt all 6 secrets
    let session_bytes: [u8; 32] = rand::random();
    let session_secret = hex::encode(session_bytes);

    let secrets = DecryptedSecrets {
        router_username: form.router_username.trim().to_string(),
        router_password: SecretString::from(form.router_password),
        oidc_client_secret: SecretString::from(form.oidc_client_secret),
        session_secret: SecretString::from(session_secret),
        certwarden_cert_api_key: Some(SecretString::from(form.certwarden_cert_api_key)),
        certwarden_key_api_key: Some(SecretString::from(form.certwarden_key_api_key)),
        maxmind_account_id: None,
        maxmind_license_key: None,
    };

    if let Err(e) = sm.store_all(&secrets).await {
        tracing::error!("failed to store secrets: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render_setup_html(
                &secrets.router_username, cw_url, cw_name,
                Some("Failed to store secrets. Check server logs."),
            )),
        )
            .into_response();
    }

    tracing::info!("setup complete — cert fetched, KEK bootstrapped, secrets encrypted, restarting...");

    // Step 7: Return success page, then exit after a short delay so Docker restarts us
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        std::process::exit(0);
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        render_complete_html(),
    )
        .into_response()
}

fn render_setup_html(username: &str, cw_url: &str, cw_name: &str, error: Option<&str>) -> String {
    let error_html = error
        .map(|e| {
            let escaped = e.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
            format!(
                r#"<div style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:12px 16px;border-radius:8px;margin-bottom:24px;font-size:14px">{escaped}</div>"#
            )
        })
        .unwrap_or_default();

    let username_escaped = username
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    let cw_url_escaped = cw_url
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    let cw_name_escaped = cw_name
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ion-drift setup</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0 }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; display: flex; align-items: center; justify-content: center }}
  .card {{ background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 40px; width: 100%; max-width: 480px }}
  h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; color: #f5f5f5 }}
  .subtitle {{ color: #a3a3a3; font-size: 14px; margin-bottom: 32px; line-height: 1.5 }}
  .section-label {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: #737373; margin-bottom: 12px; margin-top: 24px }}
  .section-label:first-of-type {{ margin-top: 0 }}
  label {{ display: block; font-size: 13px; font-weight: 500; color: #d4d4d4; margin-bottom: 6px }}
  input {{ width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #404040; border-radius: 8px; color: #f5f5f5; font-size: 14px; margin-bottom: 16px; outline: none; transition: border-color 0.2s }}
  input:focus {{ border-color: #3b82f6 }}
  input[readonly] {{ color: #737373; cursor: not-allowed }}
  .auto {{ background: #0f172a; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 13px; color: #93c5fd }}
  .info {{ background: #1a1a2e; border: 1px solid #2d2d5e; border-radius: 8px; padding: 12px 16px; margin-bottom: 16px; font-size: 12px; color: #a3a3a3 }}
  button {{ width: 100%; padding: 12px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s }}
  button:hover {{ background: #2563eb }}
  hr {{ border: none; border-top: 1px solid #262626; margin: 24px 0 }}
</style>
</head>
<body>
<div class="card">
  <h1>ion-drift setup</h1>
  <p class="subtitle">First-run configuration. Provide CertWarden API keys and router credentials.</p>
  {error_html}
  <form method="POST" action="/setup">

    <div class="section-label">CertWarden (mTLS Certificate)</div>
    <div class="info">CertWarden URL: <strong>{cw_url_escaped}</strong> &middot; Certificate: <strong>{cw_name_escaped}</strong></div>

    <label for="certwarden_cert_api_key">Certificate API Key</label>
    <input type="password" id="certwarden_cert_api_key" name="certwarden_cert_api_key" autocomplete="off">

    <label for="certwarden_key_api_key">Private Key API Key</label>
    <input type="password" id="certwarden_key_api_key" name="certwarden_key_api_key" autocomplete="off">

    <hr>
    <div class="section-label">Router Credentials</div>

    <label for="router_username">Router Username</label>
    <input type="text" id="router_username" name="router_username" value="{username_escaped}" autocomplete="off">

    <label for="router_password">Router Password</label>
    <input type="password" id="router_password" name="router_password" autocomplete="new-password">

    <hr>
    <div class="section-label">OIDC</div>

    <label for="oidc_client_secret">OIDC Client Secret</label>
    <input type="password" id="oidc_client_secret" name="oidc_client_secret" autocomplete="off">

    <div class="auto">Session secret will be auto-generated (32 random bytes)</div>

    <button type="submit">Complete Setup</button>
  </form>
</div>
</body>
</html>"##
    )
}

fn render_complete_html() -> String {
    r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ion-drift setup complete</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0 }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; display: flex; align-items: center; justify-content: center }
  .card { background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 40px; width: 100%; max-width: 440px; text-align: center }
  h1 { font-size: 24px; font-weight: 700; margin-bottom: 12px; color: #22c55e }
  p { color: #a3a3a3; font-size: 14px; line-height: 1.5 }
  .spinner { display: inline-block; width: 20px; height: 20px; border: 2px solid #404040; border-top-color: #22c55e; border-radius: 50%; animation: spin 0.8s linear infinite; margin-bottom: 16px }
  @keyframes spin { to { transform: rotate(360deg) } }
</style>
<meta http-equiv="refresh" content="5">
</head>
<body>
<div class="card">
  <div class="spinner"></div>
  <h1>Setup Complete</h1>
  <p>Certificate fetched, KEK bootstrapped, secrets encrypted and stored.</p>
  <p style="margin-top:8px">Restarting server...</p>
  <p style="margin-top:12px;color:#737373">This page will reload automatically.</p>
</div>
</body>
</html>"##
        .to_string()
}
