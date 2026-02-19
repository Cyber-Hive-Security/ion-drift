use clap::Args;
use mikrotik_core::{MikrotikClient, TrafficTracker};

use super::{OutputFormat, format_bytes, print_single};

#[derive(Args)]
pub struct TrafficCommand {
    /// WAN interface name to track
    #[arg(long, default_value = "1-WAN")]
    pub interface: String,
}

pub async fn run(
    cmd: TrafficCommand,
    client: &MikrotikClient,
    format: OutputFormat,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let db_path = data_dir.join("traffic.db");
    let tracker = TrafficTracker::new(&db_path, &cmd.interface)?;

    let totals = tracker.poll(client).await?;

    print_single(&totals, format, &[
        ("Interface", totals.interface.clone()),
        ("Download", format_bytes(totals.rx_bytes)),
        ("Upload", format_bytes(totals.tx_bytes)),
    ]);

    Ok(())
}
