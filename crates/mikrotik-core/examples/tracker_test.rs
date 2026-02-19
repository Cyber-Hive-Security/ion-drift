//! Quick test of the traffic tracker against a live router.
//!
//! Usage:
//!   cargo run --example tracker_test -- --password <pass>

use mikrotik_core::{MikrotikClient, MikrotikConfig, TrafficTracker};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let password = get_arg(&args, "--password").expect("--password required");

    let config = MikrotikConfig {
        host: "router.kaziik.xyz".into(),
        port: 443,
        tls: true,
        ca_cert_path: Some(PathBuf::from("./certs/root_ca.crt")),
        username: "ion-drift".into(),
        password,
    };

    let client = MikrotikClient::new(config)?;

    // Use a temp file for the test DB
    let db_path = std::env::temp_dir().join("ion-drift-tracker-test.db");
    println!("DB path: {}", db_path.display());

    let tracker = TrafficTracker::new(&db_path, "1-WAN")?;

    // First poll
    let totals = tracker.poll(&client).await?;
    println!(
        "Poll 1 — RX: {:.2} GB, TX: {:.2} GB",
        totals.rx_bytes as f64 / 1_073_741_824.0,
        totals.tx_bytes as f64 / 1_073_741_824.0
    );

    // Second poll (should show same or slightly higher values)
    let totals = tracker.poll(&client).await?;
    println!(
        "Poll 2 — RX: {:.2} GB, TX: {:.2} GB",
        totals.rx_bytes as f64 / 1_073_741_824.0,
        totals.tx_bytes as f64 / 1_073_741_824.0
    );

    // Get totals without polling
    let totals = tracker.get_totals().await?;
    println!(
        "Cached — RX: {:.2} GB, TX: {:.2} GB",
        totals.rx_bytes as f64 / 1_073_741_824.0,
        totals.tx_bytes as f64 / 1_073_741_824.0
    );

    // Clean up test DB
    std::fs::remove_file(&db_path)?;

    println!("Tracker test passed!");
    Ok(())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
