//! Quick test of the Cloudflare speed test.
//!
//! Usage:
//!   cargo run --example speedtest_test

use mikrotik_core::speedtest;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    println!("Running Cloudflare speed test...");
    println!("(this will take ~30-60 seconds)\n");

    let result = speedtest::run_speedtest(&client).await?;

    println!("Server:   {}", result.server_location.as_deref().unwrap_or("unknown"));
    println!("Latency:  {:.1} ms", result.latency_ms);
    println!("Download: {:.1} Mbps", result.download_mbps);
    println!("Upload:   {:.1} Mbps", result.upload_mbps);

    // Test the store
    let db_path = std::env::temp_dir().join("ion-drift-speedtest-test.db");
    let store = speedtest::SpeedTestStore::new(&db_path)?;
    store.save(&result).await?;

    let latest = store.latest().await?.unwrap();
    println!("\nStored and retrieved: {:.1}/{:.1} Mbps at ts {}",
        latest.download_mbps, latest.upload_mbps, latest.timestamp);

    std::fs::remove_file(&db_path)?;
    println!("Speed test passed!");

    Ok(())
}
