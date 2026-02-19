use clap::Args;
use mikrotik_core::MikrotikClient;

use super::{OutputFormat, print_rows};

#[derive(Args)]
pub struct LogCommand {
    /// Filter by topic (e.g. firewall, dhcp, system)
    #[arg(long)]
    pub topics: Option<String>,
    /// Limit number of entries (default: 50, from most recent)
    #[arg(long, default_value = "50")]
    pub limit: usize,
}

pub async fn run(
    cmd: LogCommand,
    client: &MikrotikClient,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let mut entries = client.log_entries().await?;

    if let Some(ref topic_filter) = cmd.topics {
        entries.retain(|e| {
            e.topics
                .as_deref()
                .map(|t| t.contains(topic_filter.as_str()))
                .unwrap_or(false)
        });
    }

    // Take the last N entries (most recent)
    let start = entries.len().saturating_sub(cmd.limit);
    let entries = &entries[start..];

    print_rows(entries, format,
        &["Time", "Topics", "Message"],
        |e| vec![
            e.time.clone(),
            e.topics.clone().unwrap_or_default(),
            e.message.clone(),
        ],
    );

    Ok(())
}
