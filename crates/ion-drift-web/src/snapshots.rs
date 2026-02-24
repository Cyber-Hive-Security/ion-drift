//! Weekly snapshot generation for connection history.
//!
//! Computes aggregated world map, VLAN Sankey, and port Sankey data
//! from the connection_history table and stores them as JSON snapshots.

use std::sync::Arc;

use crate::connection_store::ConnectionStore;

/// Compute and store weekly snapshots. Called by the background task every Sunday.
pub fn generate_weekly_snapshots(store: &ConnectionStore) -> anyhow::Result<()> {
    let week = current_iso_week();
    let (period_start, period_end) = week_boundaries(&week);

    tracing::info!("generating weekly snapshots for {week}");

    // World map snapshot
    match store.geo_summary(7) {
        Ok(geo_data) => {
            let summary = format!(
                "{} connections · {} countries · {} unique destinations",
                geo_data.iter().map(|g| g.connection_count).sum::<i64>(),
                geo_data.len(),
                geo_data.iter().map(|g| g.unique_destinations).sum::<i64>(),
            );
            let data = serde_json::to_string(&geo_data).unwrap_or_else(|_| "[]".into());
            if let Err(e) = store.save_snapshot(&week, "world_map", &data, &summary) {
                tracing::warn!("failed to save world_map snapshot: {e}");
            }
        }
        Err(e) => tracing::warn!("failed to compute geo summary for snapshot: {e}"),
    }

    // Port Sankey snapshot
    match store.port_summary(7, "") {
        Ok(port_data) => {
            let summary = format!(
                "{} flows · {} ports",
                port_data.iter().map(|p| p.flow_count).sum::<i64>(),
                port_data.len(),
            );
            let data = serde_json::to_string(&port_data).unwrap_or_else(|_| "[]".into());
            if let Err(e) = store.save_snapshot(&week, "sankey_port", &data, &summary) {
                tracing::warn!("failed to save sankey_port snapshot: {e}");
            }
        }
        Err(e) => tracing::warn!("failed to compute port summary for snapshot: {e}"),
    }

    tracing::info!("weekly snapshots for {week} complete");
    Ok(())
}

/// Spawn the weekly snapshot generator background task.
pub fn spawn_snapshot_generator(store: Arc<ConnectionStore>) {
    tokio::spawn(async move {
        // Wait 6 hours before first check (avoid startup load)
        tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;

        loop {
            // Check if it's Sunday (day of week = 0)
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            // Day of week: 0=Thursday for epoch, so (days + 4) % 7: 0=Sun, 1=Mon, ..., 6=Sat
            let days = now / 86400;
            let dow = (days + 4) % 7; // 0=Sun

            if dow == 0 {
                if let Err(e) = generate_weekly_snapshots(&store) {
                    tracing::warn!("weekly snapshot generation failed: {e}");
                }
                // Sleep until next Sunday (~7 days)
                tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 3600)).await;
            } else {
                // Sleep until midnight (simplified: sleep 1 hour and check again)
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        }
    });
}

/// Get current ISO week string: "2026-W09"
fn current_iso_week() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = now / 86400;
    // ISO week calculation
    // Jan 1, 1970 was a Thursday (day 4 of ISO week)
    // ISO weeks start on Monday
    let dow = ((days + 3) % 7) as i64; // 0=Monday
    let week_start = days - dow;
    // Get the Thursday of the week (ISO 8601 says week belongs to the year containing its Thursday)
    let thursday = week_start + 3;
    let (year, _, _) = days_to_ymd(thursday);
    // Week number = 1 + floor((thursday - first_thursday_of_year) / 7)
    let jan1 = ymd_to_days(year, 1, 1);
    let jan1_dow = ((jan1 + 3) % 7) as i64;
    let first_thursday = jan1 + ((10 - jan1_dow) % 7);
    let week_num = 1 + (thursday - first_thursday) / 7;
    format!("{year}-W{week_num:02}")
}

/// Get ISO week boundaries (Monday 00:00 to Sunday 23:59:59).
fn week_boundaries(week: &str) -> (String, String) {
    // Parse "YYYY-Www" format
    let parts: Vec<&str> = week.split("-W").collect();
    if parts.len() != 2 {
        return (week.to_string(), week.to_string());
    }
    let year: i64 = parts[0].parse().unwrap_or(2026);
    let week_num: i64 = parts[1].parse().unwrap_or(1);

    // Find January 1 of the year, then find the first Monday
    let jan1 = ymd_to_days(year, 1, 1);
    let jan1_dow = ((jan1 + 3) % 7) as i64; // 0=Monday
    let first_monday = if jan1_dow <= 3 {
        jan1 - jan1_dow // Monday of the week containing Jan 1
    } else {
        jan1 + (7 - jan1_dow) // Next Monday
    };

    let monday = first_monday + (week_num - 1) * 7;
    let sunday = monday + 6;

    let (sy, sm, sd) = days_to_ymd(monday);
    let (ey, em, ed) = days_to_ymd(sunday);

    (
        format!("{sy:04}-{sm:02}-{sd:02}T00:00:00Z"),
        format!("{ey:04}-{em:02}-{ed:02}T23:59:59Z"),
    )
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
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

fn ymd_to_days(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
