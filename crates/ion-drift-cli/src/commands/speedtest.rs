use clap::Args;
use mikrotik_core::speedtest;

use super::{OutputFormat, print_rows, print_single};

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
        print_rows(&results, format,
            &["Time", "Download", "Upload", "Latency", "Server"],
            |r| vec![
                format_timestamp(r.timestamp),
                format!("{:.1} Mbps", r.download_mbps),
                format!("{:.1} Mbps", r.upload_mbps),
                format!("{:.1} ms", r.latency_ms),
                r.server_location.clone().unwrap_or_default(),
            ],
        );
        return Ok(());
    }

    eprintln!("Running Cloudflare speed test...");

    let client = reqwest::Client::new();
    let result = speedtest::run_speedtest(&client).await?;

    // Save to DB
    store.save(&result).await?;

    print_single(&result, format, &[
        ("Server", result.server_location.clone().unwrap_or_else(|| "unknown".into())),
        ("Latency", format!("{:.1} ms", result.latency_ms)),
        ("Download", format!("{:.1} Mbps", result.download_mbps)),
        ("Upload", format!("{:.1} Mbps", result.upload_mbps)),
    ]);

    Ok(())
}

fn format_timestamp(ts: i64) -> String {
    // Simple UTC formatting without pulling in chrono
    let secs_per_day = 86400u64;
    let ts = ts as u64;
    let days = ts / secs_per_day;
    let rem = ts % secs_per_day;
    let hours = rem / 3600;
    let minutes = (rem % 3600) / 60;

    // Days since epoch to Y-M-D (simplified)
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
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
