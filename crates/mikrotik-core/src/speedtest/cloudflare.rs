//! Cloudflare speed test provider.
//!
//! Endpoints: `speed.cloudflare.com/__down?bytes=N` and `/__up`

use super::{ProviderResult, concurrent_download, concurrent_upload, measure_latency};

const BASE: &str = "https://speed.cloudflare.com";

pub async fn run(client: &reqwest::Client) -> Result<ProviderResult, Box<dyn std::error::Error + Send + Sync>> {
    // Server location
    let location = get_location(client).await.ok();

    // Latency (5 probes, zero-byte download)
    let latency_ms = measure_latency(client, &format!("{BASE}/__down?bytes=0"), 5).await?;

    // Concurrent download (10MB chunks, 6 workers, 10s)
    let download_mbps = concurrent_download(
        client,
        &format!("{BASE}/__down?bytes=10000000"),
    ).await?;

    // Concurrent upload (5MB chunks, 6 workers, 10s)
    let upload_mbps = concurrent_upload(
        client,
        &format!("{BASE}/__up"),
        5_000_000,
    ).await?;

    Ok(ProviderResult {
        provider: "Cloudflare".into(),
        download_mbps,
        upload_mbps,
        latency_ms,
        server_location: location,
    })
}

async fn get_location(client: &reqwest::Client) -> Result<String, reqwest::Error> {
    let text = client
        .get(format!("{BASE}/cdn-cgi/trace"))
        .send()
        .await?
        .text()
        .await?;

    for line in text.lines() {
        if let Some(colo) = line.strip_prefix("colo=") {
            return Ok(colo.to_string());
        }
    }
    Ok("unknown".to_string())
}
