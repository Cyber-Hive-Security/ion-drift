//! Netflix/Fast.com speed test provider.
//!
//! Uses the Fast.com API to get Netflix CDN test endpoints, then runs
//! concurrent download/upload tests against them.

use serde::Deserialize;

use super::{ProviderResult, measure_latency};

/// The Fast.com API token — hardcoded in their JavaScript, stable for years.
const FAST_TOKEN: &str = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm";
const FAST_API: &str = "https://api.fast.com/netflix/speedtest/v2";

#[derive(Deserialize)]
struct FastResponse {
    targets: Vec<FastTarget>,
}

#[derive(Deserialize)]
struct FastTarget {
    url: String,
    location: Option<FastLocation>,
}

#[derive(Deserialize)]
struct FastLocation {
    city: Option<String>,
    #[allow(dead_code)]
    country: Option<String>,
}

pub async fn run(client: &reqwest::Client) -> Result<ProviderResult, Box<dyn std::error::Error + Send + Sync>> {
    // Get test URLs from Fast.com API
    let api_url = format!("{FAST_API}?https=true&token={FAST_TOKEN}&urlCount=5");
    let resp: FastResponse = client
        .get(&api_url)
        .send()
        .await?
        .json()
        .await?;

    if resp.targets.is_empty() {
        return Err("Fast.com returned no test targets".into());
    }

    let target = &resp.targets[0];
    let location = target.location.as_ref().and_then(|l| l.city.clone());

    // The target URL includes a byte range like /range/0-26214400
    // We can use it directly for download, or modify the range for different sizes
    let download_url = &target.url;

    // Latency
    let latency_ms = measure_latency(client, download_url, 5).await?;

    // Concurrent download — use all targets round-robin across workers
    let download_mbps = concurrent_download_multi(client, &resp.targets).await?;

    // Concurrent upload — POST to target URLs
    let upload_mbps = concurrent_upload_multi(client, &resp.targets).await?;

    Ok(ProviderResult {
        provider: "Netflix".into(),
        download_mbps,
        upload_mbps,
        latency_ms,
        server_location: location,
    })
}

/// Concurrent download using multiple Netflix CDN targets.
async fn concurrent_download_multi(
    client: &reqwest::Client,
    targets: &[FastTarget],
) -> Result<f64, reqwest::Error> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    let num_workers = super::NUM_WORKERS;
    let start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(num_workers);

    for i in 0..num_workers {
        let client = client.clone();
        // Round-robin across targets
        let url = targets[i % targets.len()].url.clone();
        let stop = stop.clone();
        let total = total_bytes.clone();

        handles.push(tokio::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match client.get(&url).send().await {
                    Ok(resp) => match resp.bytes().await {
                        Ok(body) => {
                            total.fetch_add(body.len() as u64, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    },
                    Err(_) => break,
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_secs_f64(super::TEST_DURATION_SECS)).await;
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let bytes = total_bytes.load(Ordering::Relaxed);
    Ok((bytes as f64 * 8.0) / elapsed / 1_000_000.0)
}

/// Concurrent upload using multiple Netflix CDN targets.
async fn concurrent_upload_multi(
    client: &reqwest::Client,
    targets: &[FastTarget],
) -> Result<f64, reqwest::Error> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    let chunk_size: usize = 5_000_000;
    let num_workers = super::NUM_WORKERS;
    let start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(num_workers);

    for i in 0..num_workers {
        let client = client.clone();
        let url = targets[i % targets.len()].url.clone();
        let stop = stop.clone();
        let total = total_bytes.clone();
        let payload = vec![b'0'; chunk_size];

        handles.push(tokio::spawn(async move {
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match client.post(&url).body(payload.clone()).send().await {
                    Ok(_) => {
                        total.fetch_add(chunk_size as u64, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
        }));
    }

    tokio::time::sleep(std::time::Duration::from_secs_f64(super::TEST_DURATION_SECS)).await;
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let bytes = total_bytes.load(Ordering::Relaxed);
    Ok((bytes as f64 * 8.0) / elapsed / 1_000_000.0)
}
