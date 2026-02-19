use clap::Args;
use mikrotik_core::speedtest;

use super::{OutputFormat, print_rows};

#[derive(Args)]
pub struct SpeedTestCommand {
    /// Show last N results instead of running a new test
    #[arg(long)]
    pub history: Option<usize>,
}

pub async fn run(cmd: SpeedTestCommand, format: OutputFormat, data_dir: &std::path::Path) -> anyhow::Result<()> {
    let db_path = data_dir.join("speedtest.db");
    let store = speedtest::SpeedTestStore::new(&db_path)?;

    if let Some(limit) = cmd.history {
        let results = store.recent(limit).await?;
        for result in &results {
            let ts = format_timestamp(result.timestamp);
            println!("Test: {ts}");
            print_provider_table(&result.providers, format);
            println!(
                "  Median: {:.1} Mbps down / {:.1} Mbps up / {:.1} ms\n",
                result.median_download_mbps, result.median_upload_mbps, result.median_latency_ms,
            );
        }
        if results.is_empty() {
            println!("(no results)");
        }
        return Ok(());
    }

    eprintln!("Running speed test against 3 providers (Cloudflare, Netflix, Akamai)...");
    eprintln!("(each runs separately — this will take ~2-3 minutes)\n");

    let client = reqwest::Client::new();
    let result = speedtest::run_speedtest(&client).await;

    if result.providers.is_empty() {
        anyhow::bail!("all providers failed — check internet connectivity");
    }

    // Save to DB
    store.save(&result).await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        _ => {
            print_provider_table(&result.providers, format);
            println!(
                "\n  Median: {:.1} Mbps down / {:.1} Mbps up / {:.1} ms",
                result.median_download_mbps, result.median_upload_mbps, result.median_latency_ms,
            );
        }
    }

    Ok(())
}

fn print_provider_table(providers: &[mikrotik_core::ProviderResult], format: OutputFormat) {
    print_rows(providers, format,
        &["Provider", "Server", "Download", "Upload", "Latency"],
        |p| vec![
            p.provider.clone(),
            p.server_location.clone().unwrap_or_default(),
            if p.download_mbps > 0.0 { format!("{:.1} Mbps", p.download_mbps) } else { "—".into() },
            if p.upload_mbps > 0.0 { format!("{:.1} Mbps", p.upload_mbps) } else { "—".into() },
            format!("{:.1} ms", p.latency_ms),
        ],
    );
}

fn format_timestamp(ts: i64) -> String {
    let secs_per_day = 86400u64;
    let ts = ts as u64;
    let days = ts / secs_per_day;
    let rem = ts % secs_per_day;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02} UTC")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
