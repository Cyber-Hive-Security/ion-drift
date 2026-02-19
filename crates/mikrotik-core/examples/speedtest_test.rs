//! Quick test of the multi-provider speed test.
//!
//! Usage:
//!   cargo run --example speedtest_test

use mikrotik_core::speedtest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    println!("Running speed test against 3 providers...");
    println!("(this will take ~60-90 seconds)\n");

    let result = speedtest::run_speedtest(&client).await;

    for p in &result.providers {
        println!(
            "{:<12} {:>8}  DL: {:>7.1} Mbps  UL: {:>7.1} Mbps  Ping: {:>5.1} ms",
            p.provider,
            p.server_location.as_deref().unwrap_or(""),
            p.download_mbps,
            p.upload_mbps,
            p.latency_ms,
        );
    }

    println!(
        "\nMedian:  DL: {:.1} Mbps  UL: {:.1} Mbps  Ping: {:.1} ms",
        result.median_download_mbps,
        result.median_upload_mbps,
        result.median_latency_ms,
    );

    if result.providers.is_empty() {
        println!("\nWARNING: All providers failed!");
        return Ok(());
    }

    // Test the store
    let db_path = std::env::temp_dir().join("ion-drift-speedtest-test.db");
    let store = speedtest::SpeedTestStore::new(&db_path)?;
    store.save(&result).await?;

    let latest = store.latest().await?.unwrap();
    println!(
        "\nStored: {} providers, median {:.1}/{:.1} Mbps",
        latest.providers.len(),
        latest.median_download_mbps,
        latest.median_upload_mbps,
    );

    std::fs::remove_file(&db_path)?;
    println!("Speed test passed!");
    Ok(())
}
