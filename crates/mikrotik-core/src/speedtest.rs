//! Cloudflare-based speed test with persistent history.
//!
//! Uses `speed.cloudflare.com` endpoints to measure download, upload, and
//! latency. Results are stored in SQLite for long-term tracking.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use rusqlite::Connection;
use serde::Serialize;
use tokio::sync::Mutex;

const CF_BASE: &str = "https://speed.cloudflare.com";

/// Result of a single speed test run.
#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    /// Download speed in Mbps.
    pub download_mbps: f64,
    /// Upload speed in Mbps.
    pub upload_mbps: f64,
    /// Latency (ping) in milliseconds.
    pub latency_ms: f64,
    /// Cloudflare edge location (e.g. "ORD", "DFW").
    pub server_location: Option<String>,
    /// Unix timestamp when the test was run.
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
                download_mbps REAL NOT NULL,
                upload_mbps REAL NOT NULL,
                latency_ms REAL NOT NULL,
                server_location TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_speedtest_ts ON speedtest_results (timestamp);",
        )?;

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Store a speed test result.
    pub async fn save(&self, result: &SpeedTestResult) -> Result<(), rusqlite::Error> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO speedtest_results (timestamp, download_mbps, upload_mbps, latency_ms, server_location)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                result.timestamp,
                result.download_mbps,
                result.upload_mbps,
                result.latency_ms,
                result.server_location,
            ],
        )?;
        Ok(())
    }

    /// Get the most recent N results.
    pub async fn recent(&self, limit: usize) -> Result<Vec<SpeedTestResult>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT timestamp, download_mbps, upload_mbps, latency_ms, server_location
             FROM speedtest_results ORDER BY timestamp DESC LIMIT ?1",
        )?;

        let results = stmt
            .query_map([limit], |row| {
                Ok(SpeedTestResult {
                    timestamp: row.get(0)?,
                    download_mbps: row.get(1)?,
                    upload_mbps: row.get(2)?,
                    latency_ms: row.get(3)?,
                    server_location: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get all results since a unix timestamp.
    pub async fn since(&self, since_ts: i64) -> Result<Vec<SpeedTestResult>, rusqlite::Error> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT timestamp, download_mbps, upload_mbps, latency_ms, server_location
             FROM speedtest_results WHERE timestamp >= ?1 ORDER BY timestamp ASC",
        )?;

        let results = stmt
            .query_map([since_ts], |row| {
                Ok(SpeedTestResult {
                    timestamp: row.get(0)?,
                    download_mbps: row.get(1)?,
                    upload_mbps: row.get(2)?,
                    latency_ms: row.get(3)?,
                    server_location: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get the most recent result, if any.
    pub async fn latest(&self) -> Result<Option<SpeedTestResult>, rusqlite::Error> {
        let mut results = self.recent(1).await?;
        Ok(results.pop())
    }
}

/// Run a full speed test (download + upload + latency) using Cloudflare.
///
/// The test performs:
/// - 5 latency probes (reports median)
/// - Download: 1 MB warmup, then 10 MB x3 and 25 MB x2 (reports 90th percentile)
/// - Upload: 1 MB warmup, then 5 MB x3 and 10 MB x2 (reports 90th percentile)
pub async fn run_speedtest(http_client: &reqwest::Client) -> Result<SpeedTestResult, reqwest::Error> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Get server location
    let server_location = get_server_location(http_client).await.ok();

    // Latency (median of 5 probes)
    let latency_ms = measure_latency(http_client, 5).await?;

    // Download test
    let download_mbps = measure_download(http_client).await?;

    // Upload test
    let upload_mbps = measure_upload(http_client).await?;

    Ok(SpeedTestResult {
        download_mbps,
        upload_mbps,
        latency_ms,
        server_location,
        timestamp,
    })
}

/// Measure latency by sending zero-byte download probes.
async fn measure_latency(client: &reqwest::Client, samples: usize) -> Result<f64, reqwest::Error> {
    let url = format!("{CF_BASE}/__down?bytes=0");
    let mut times = Vec::with_capacity(samples);

    for _ in 0..samples {
        let start = Instant::now();
        let _ = client
            .get(&url)
            .header("Referer", "https://speed.cloudflare.com/")
            .send()
            .await?;
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = times[times.len() / 2];
    Ok(median)
}

/// Measure download speed. Returns Mbps.
async fn measure_download(client: &reqwest::Client) -> Result<f64, reqwest::Error> {
    // Warmup with 1 MB
    download_chunk(client, 1_000_000).await?;

    let mut speeds = Vec::new();

    // 10 MB x 3
    for _ in 0..3 {
        speeds.push(download_chunk(client, 10_000_000).await?);
    }
    // 25 MB x 2
    for _ in 0..2 {
        speeds.push(download_chunk(client, 25_000_000).await?);
    }

    Ok(percentile_90(&mut speeds))
}

/// Download a single chunk and return speed in Mbps.
async fn download_chunk(client: &reqwest::Client, bytes: u64) -> Result<f64, reqwest::Error> {
    let url = format!("{CF_BASE}/__down?bytes={bytes}");
    let start = Instant::now();
    let resp = client
        .get(&url)
        .header("Referer", "https://speed.cloudflare.com/")
        .send()
        .await?;
    let body = resp.bytes().await?;
    let elapsed = start.elapsed().as_secs_f64();
    let mbps = (body.len() as f64 * 8.0) / elapsed / 1_000_000.0;
    Ok(mbps)
}

/// Measure upload speed. Returns Mbps.
async fn measure_upload(client: &reqwest::Client) -> Result<f64, reqwest::Error> {
    // Warmup with 1 MB
    upload_chunk(client, 1_000_000).await?;

    let mut speeds = Vec::new();

    // 5 MB x 3
    for _ in 0..3 {
        speeds.push(upload_chunk(client, 5_000_000).await?);
    }
    // 10 MB x 2
    for _ in 0..2 {
        speeds.push(upload_chunk(client, 10_000_000).await?);
    }

    Ok(percentile_90(&mut speeds))
}

/// Upload a single chunk and return speed in Mbps.
async fn upload_chunk(client: &reqwest::Client, bytes: usize) -> Result<f64, reqwest::Error> {
    let url = format!("{CF_BASE}/__up");
    let payload = vec![b'0'; bytes];
    let start = Instant::now();
    let _ = client
        .post(&url)
        .header("Referer", "https://speed.cloudflare.com/")
        .body(payload)
        .send()
        .await?;
    let elapsed = start.elapsed().as_secs_f64();
    let mbps = (bytes as f64 * 8.0) / elapsed / 1_000_000.0;
    Ok(mbps)
}

/// Get the Cloudflare edge server location.
async fn get_server_location(client: &reqwest::Client) -> Result<String, reqwest::Error> {
    let text = client
        .get(format!("{CF_BASE}/cdn-cgi/trace"))
        .send()
        .await?
        .text()
        .await?;

    // Parse key=value pairs, look for "colo"
    for line in text.lines() {
        if let Some(colo) = line.strip_prefix("colo=") {
            return Ok(colo.to_string());
        }
    }
    Ok("unknown".to_string())
}

/// Compute the 90th percentile from a mutable slice of f64s.
fn percentile_90(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((values.len() as f64 * 0.9) - 1.0).max(0.0) as usize;
    values[idx.min(values.len() - 1)]
}
