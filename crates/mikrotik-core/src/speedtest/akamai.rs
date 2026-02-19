//! Akamai/Linode speed test provider.
//!
//! Uses Linode's public speed test servers (`garbage.php?ckSize=N` endpoint).
//! Download-only — upload speed is derived from the other two providers.
//!
//! Available datacenters sorted by proximity are probed at startup;
//! the fastest-responding one is used for the test.

use super::{ProviderResult, concurrent_download, measure_latency};

/// Linode speed test datacenters (US).
const DATACENTERS: &[(&str, &str)] = &[
    ("fremont", "Fremont, CA"),
    ("dallas", "Dallas, TX"),
    ("atlanta", "Atlanta, GA"),
    ("newark", "Newark, NJ"),
];

pub async fn run(client: &reqwest::Client) -> Result<ProviderResult, Box<dyn std::error::Error + Send + Sync>> {
    // Probe datacenters to find the nearest one
    let (dc_host, dc_name) = find_nearest(client).await?;

    // Latency (5 probes with 1-byte download)
    let latency_url = format!("https://speedtest.{dc_host}.linode.com/garbage.php?ckSize=0");
    let latency_ms = measure_latency(client, &latency_url, 5).await?;

    // Concurrent download (10MB chunks via garbage.php)
    let download_url = format!("https://speedtest.{dc_host}.linode.com/garbage.php?ckSize=10");
    let download_mbps = concurrent_download(client, &download_url).await?;

    Ok(ProviderResult {
        provider: "Akamai".into(),
        download_mbps,
        upload_mbps: 0.0, // Linode doesn't have an upload endpoint
        latency_ms,
        server_location: Some(dc_name.to_string()),
    })
}

/// Probe each datacenter with a tiny download and return the fastest.
async fn find_nearest(client: &reqwest::Client) -> Result<(&'static str, &'static str), Box<dyn std::error::Error + Send + Sync>> {
    let mut best: Option<(&str, &str, f64)> = None;

    for &(host, name) in DATACENTERS {
        let url = format!("https://speedtest.{host}.linode.com/garbage.php?ckSize=0");
        let start = std::time::Instant::now();
        if client.get(&url).send().await.is_ok() {
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            if best.as_ref().map_or(true, |(_, _, best_ms)| ms < *best_ms) {
                best = Some((host, name, ms));
            }
        }
    }

    best.map(|(h, n, _)| (h, n))
        .ok_or_else(|| "all Linode datacenters unreachable".into())
}
