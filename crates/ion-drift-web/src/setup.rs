use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use secrecy::SecretString;

use crate::secrets::{DecryptedSecrets, SecretsManager};

/// Shared state for the minimal setup-mode server.
#[derive(Clone)]
pub struct SetupState {
    pub secrets_manager: Arc<SecretsManager>,
    pub router_username: String,
}

/// `GET /setup` — Render the setup form.
pub async fn setup_page(State(state): State<SetupState>) -> Html<String> {
    let username = &state.router_username;
    Html(render_setup_html(username, None))
}

#[derive(serde::Deserialize)]
pub struct SetupForm {
    router_username: String,
    router_password: String,
    oidc_client_secret: String,
}

/// `POST /setup` — Process the setup form, encrypt and store secrets.
pub async fn setup_submit(
    State(state): State<SetupState>,
    axum::extract::Form(form): axum::extract::Form<SetupForm>,
) -> Response {
    // Validate inputs
    if form.router_username.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username,
            Some("Router username is required"),
        ))
        .into_response();
    }
    if form.router_password.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username,
            Some("Router password is required"),
        ))
        .into_response();
    }
    if form.oidc_client_secret.trim().is_empty() {
        return Html(render_setup_html(
            &form.router_username,
            Some("OIDC client secret is required"),
        ))
        .into_response();
    }

    // Generate session secret (32 random bytes, hex-encoded = 64 chars)
    let session_bytes: [u8; 32] = rand::random();
    let session_secret = hex::encode(session_bytes);

    let secrets = DecryptedSecrets {
        router_username: form.router_username.trim().to_string(),
        router_password: SecretString::from(form.router_password),
        oidc_client_secret: SecretString::from(form.oidc_client_secret),
        session_secret: SecretString::from(session_secret),
    };

    if let Err(e) = state.secrets_manager.store_all(&secrets).await {
        tracing::error!("failed to store secrets: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(render_setup_html(
                &secrets.router_username,
                Some("Failed to store secrets. Check server logs."),
            )),
        )
            .into_response();
    }

    tracing::info!("setup complete — secrets encrypted and stored, restarting...");

    // Return success page, then exit after a short delay so Docker restarts us
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

fn render_setup_html(username: &str, error: Option<&str>) -> String {
    let error_html = error
        .map(|e| {
            format!(
                r#"<div style="background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:12px 16px;border-radius:8px;margin-bottom:24px;font-size:14px">{e}</div>"#
            )
        })
        .unwrap_or_default();

    let username_escaped = username
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
  .card {{ background: #171717; border: 1px solid #262626; border-radius: 12px; padding: 40px; width: 100%; max-width: 440px }}
  h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 8px; color: #f5f5f5 }}
  .subtitle {{ color: #a3a3a3; font-size: 14px; margin-bottom: 32px; line-height: 1.5 }}
  label {{ display: block; font-size: 13px; font-weight: 500; color: #d4d4d4; margin-bottom: 6px }}
  input {{ width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #404040; border-radius: 8px; color: #f5f5f5; font-size: 14px; margin-bottom: 20px; outline: none; transition: border-color 0.2s }}
  input:focus {{ border-color: #3b82f6 }}
  .auto {{ background: #0f172a; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 13px; color: #93c5fd }}
  button {{ width: 100%; padding: 12px; background: #3b82f6; color: white; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s }}
  button:hover {{ background: #2563eb }}
</style>
</head>
<body>
<div class="card">
  <h1>ion-drift setup</h1>
  <p class="subtitle">Encryption key loaded. Configure your secrets to get started.</p>
  {error_html}
  <form method="POST" action="/setup">
    <label for="router_username">Router Username</label>
    <input type="text" id="router_username" name="router_username" value="{username_escaped}" autocomplete="off">

    <label for="router_password">Router Password</label>
    <input type="password" id="router_password" name="router_password" autocomplete="new-password">

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
  <p>Secrets encrypted and stored. Restarting server...</p>
  <p style="margin-top:12px;color:#737373">This page will reload automatically.</p>
</div>
</body>
</html>"##
        .to_string()
}
