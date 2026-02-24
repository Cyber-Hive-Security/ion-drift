//! Multi-provider speed test with persistent history.
//!
//! Runs concurrent download/upload tests against Cloudflare, Netflix (Fast.com),
//! and Akamai (Linode). Results are stored in SQLite for long-term tracking.

pub mod akamai;
pub mod cloudflare;
pub mod netflix;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::Mutex;

/// Number of concurrent download/upload workers per provider.
const NUM_WORKERS: usize = 6;

/// Duration in seconds for each download/upload phase.
const TEST_DURATION_SECS: f64 = 10.0;

/// Result from a single provider's speed test.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderResult {
    pub provider: String,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: f64,
    pub server_location: Option<String>,
}

/// Aggregated result from all providers.
#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    pub providers: Vec<ProviderResult>,
    pub median_download_mbps: f64,
    pub median_upload_mbps: f64,
    pub median_latency_ms: f64,
    pub timestamp: i64,
}

/// Persistent speed test history backed by SQLite.
pub struct SpeedTestStore {
    db: Arc<Mutex<Connection>>,
}

impl SpeedTestStore {
    /// Open (or create) the speed test database at `db_path`.
    pub fn new(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS speedtest_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                provider TEXT NOT NULL,
                download_mbps REAL NOT NULL,
                upload_mbps REAL NOT NULL,
                latency_ms REAL NOT NULL,
                server_location TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_speedtest_ts ON speedtest_results (timestamp);
            CREATE TABLE IF NOT EXISTS speedtest_aggregates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                median_download_mbps REAL NOT NULL,
                median_upload_mbps REAL NOT NULL,
                median_latency_ms REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_speedtest_agg_ts ON speedtest_aggregates (timestamp);",
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Store a full speed test result (all providers + aggregate).
    pub async fn save(&self, result: &SpeedTestResult) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;

        for p in &result.providers {
            db.execute(
                "INSERT INTO speedtest_results (timestamp, provider, download_mbps, upload_mbps, latency_ms, server_location)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    result.timestamp, p.provider, p.download_mbps, p.upload_mbps, p.latency_ms, p.server_location,
                ],
            )?;
        }

        db.execute(
            "INSERT INTO speedtest_aggregates (timestamp, median_download_mbps, median_upload_mbps, median_latency_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                result.timestamp, result.median_download_mbps, result.median_upload_mbps, result.median_latency_ms,
            ],
        )?;

        Ok(())
    }

    /// Get the most recent N aggregate results with their per-provider details.
    pub async fn recent(&self, limit: usize) -> Result<Vec<SpeedTestResult>, rusqlite::Error> {
        let db = self.db.lock().await;

        let mut agg_stmt = db.prepare(
            "SELECT timestamp, median_download_mbps, median_upload_mbps, median_latency_ms
             FROM speedtest_aggregates ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let mut prov_stmt = db.prepare(
            "SELECT provider, download_mbps, upload_mbps, latency_ms, server_location
             FROM speedtest_results WHERE timestamp = ?1 ORDER BY provider",
        )?;

        let aggregates: Vec<(i64, f64, f64, f64)> = agg_stmt
            .query_map([limit], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut results = Vec::new();
        for (ts, med_dl, med_ul, med_lat) in aggregates {
            let providers = prov_stmt
                .query_map([ts], |row| {
                    Ok(ProviderResult {
                        provider: row.get(0)?,
                        download_mbps: row.get(1)?,
                        upload_mbps: row.get(2)?,
                        latency_ms: row.get(3)?,
                        server_location: row.get(4)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            results.push(SpeedTestResult {
                providers,
                median_download_mbps: med_dl,
                median_upload_mbps: med_ul,
                median_latency_ms: med_lat,
                timestamp: ts,
            });
        }

        Ok(results)
    }

    /// Get the most recent result, if any.
    pub async fn latest(&self) -> Result<Option<SpeedTestResult>, rusqlite::Error> {
        let mut results = self.recent(1).await?;
        Ok(results.pop())
    }
}

/// Run a full speed test against all providers, returning aggregate + per-provider results.
///
/// Uses concurrent downloads (6 workers, 10s per phase) for each provider.
/// Providers that fail are skipped gracefully.
pub async fn run_speedtest(http_client: &reqwest::Client) -> SpeedTestResult {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Run providers SEQUENTIALLY — each needs full bandwidth to get accurate results.
    let mut providers = Vec::new();

    // Provider 1: Cloudflare
    eprintln!("  [1/3] Testing Cloudflare...");
    match cloudflare::run(http_client).await {
        Ok(r) => {
            eprintln!("         {:.1} / {:.1} Mbps", r.download_mbps, r.upload_mbps);
            providers.push(r);
        }
        Err(e) => eprintln!("         failed: {e}"),
    }

    // Provider 2: Netflix / Fast.com
    eprintln!("  [2/3] Testing Netflix (Fast.com)...");
    match netflix::run(http_client).await {
        Ok(r) => {
            eprintln!("         {:.1} / {:.1} Mbps", r.download_mbps, r.upload_mbps);
            providers.push(r);
        }
        Err(e) => eprintln!("         failed: {e}"),
    }

    // Provider 3: Akamai / Linode (download-only)
    eprintln!("  [3/3] Testing Akamai (Linode)...");
    match akamai::run(http_client).await {
        Ok(r) => {
            eprintln!("         {:.1} Mbps down", r.download_mbps);
            providers.push(r);
        }
        Err(e) => eprintln!("         failed: {e}"),
    }
    eprintln!();

    let median_download = median_of(&providers, |p| Some(p.download_mbps));
    // Exclude providers with no upload (Akamai is download-only)
    let median_upload = median_of(&providers, |p| {
        if p.upload_mbps > 0.0 { Some(p.upload_mbps) } else { None }
    });
    let median_latency = median_of(&providers, |p| Some(p.latency_ms));

    SpeedTestResult {
        providers,
        median_download_mbps: median_download,
        median_upload_mbps: median_upload,
        median_latency_ms: median_latency,
        timestamp,
    }
}

// ── Shared helpers for all providers ──────────────────────────────

/// Run a concurrent download test. Returns speed in Mbps.
///
/// Spawns `NUM_WORKERS` tasks that each download from the given URL for
/// `TEST_DURATION_SECS`. Total throughput = total bytes / wall time.
pub(crate) async fn concurrent_download(
    client: &reqwest::Client,
    url: &str,
) -> Result<f64, reqwest::Error> {
    let start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(NUM_WORKERS);

    for _ in 0..NUM_WORKERS {
        let client = client.clone();
        let url = url.to_string();
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

    // Let it run for the test duration
    tokio::time::sleep(std::time::Duration::from_secs_f64(TEST_DURATION_SECS)).await;
    stop.store(true, Ordering::Relaxed);

    // Wait for all workers to finish their current request
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let bytes = total_bytes.load(Ordering::Relaxed);
    Ok((bytes as f64 * 8.0) / elapsed / 1_000_000.0)
}

/// Run a concurrent upload test. Returns speed in Mbps.
pub(crate) async fn concurrent_upload(
    client: &reqwest::Client,
    url: &str,
    chunk_size: usize,
) -> Result<f64, reqwest::Error> {
    let start = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(NUM_WORKERS);

    for _ in 0..NUM_WORKERS {
        let client = client.clone();
        let url = url.to_string();
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

    tokio::time::sleep(std::time::Duration::from_secs_f64(TEST_DURATION_SECS)).await;
    stop.store(true, Ordering::Relaxed);

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let bytes = total_bytes.load(Ordering::Relaxed);
    Ok((bytes as f64 * 8.0) / elapsed / 1_000_000.0)
}

/// Measure latency by sending zero/tiny requests. Returns median of samples in ms.
pub(crate) async fn measure_latency(
    client: &reqwest::Client,
    url: &str,
    samples: usize,
) -> Result<f64, reqwest::Error> {
    let mut times = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = client.get(url).send().await?;
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Ok(times[times.len() / 2])
}

/// Compute the median of a float field from a slice, skipping None values.
fn median_of(items: &[ProviderResult], f: impl Fn(&ProviderResult) -> Option<f64>) -> f64 {
    let mut vals: Vec<f64> = items.iter().filter_map(|i| f(i)).collect();
    if vals.is_empty() {
        return 0.0;
    }
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    vals[vals.len() / 2]
}
