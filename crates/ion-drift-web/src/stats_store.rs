//! Page view statistics store backed by SQLite.
//!
//! Tracks page navigation events for the Statistics/Diagnostic Report feature.
//! Uses a separate `stats.db` database to avoid impacting the main data stores.
//!
//! All SQLite operations are offloaded to `spawn_blocking` to avoid blocking
//! Tokio worker threads during I/O or WAL checkpoints.

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use serde::Serialize;

/// A single page view aggregate entry.
#[derive(Debug, Clone, Serialize)]
pub struct PageViewEntry {
    pub page: String,
    pub context: String,
    pub view_date: String,
    pub view_count: i64,
}

/// Persistent page view statistics store backed by SQLite.
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) because the lock is held
/// only inside `spawn_blocking` closures — never across `.await` points.
pub struct StatsStore {
    db: Arc<std::sync::Mutex<Connection>>,
}

impl StatsStore {
    /// Create a new store, opening (or creating) the SQLite database at `db_path`.
    pub fn new(db_path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        // Performance pragmas matching MetricsStore pattern
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS page_views (
                 page TEXT NOT NULL,
                 context TEXT NOT NULL DEFAULT '',
                 view_date TEXT NOT NULL,
                 view_count INTEGER NOT NULL DEFAULT 1,
                 PRIMARY KEY (page, context, view_date)
             );
             CREATE INDEX IF NOT EXISTS idx_page_views_date ON page_views (view_date);",
        )?;

        Ok(Self {
            db: Arc::new(std::sync::Mutex::new(conn)),
        })
    }

    /// Record a page view, upserting the count for today's date.
    pub async fn record_page_view(&self, page: &str, context: &str) {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let db = self.db.clone();
        let page = page.to_string();
        let context = context.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let db = db.lock().expect("stats db mutex poisoned");
            db.execute(
                "INSERT INTO page_views (page, context, view_date, view_count)
                 VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT (page, context, view_date)
                 DO UPDATE SET view_count = view_count + 1",
                rusqlite::params![page, context, today],
            )
        })
        .await;
        match result {
            Ok(Err(e)) => tracing::warn!("stats: page view insert failed: {e}"),
            Err(e) => tracing::warn!("stats: page view task failed: {e}"),
            _ => {}
        }
    }

    /// Return all page views within the last N days.
    pub async fn get_page_views(&self, days: u32) -> Result<Vec<PageViewEntry>, String> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let db = db.lock().map_err(|e| format!("stats db lock: {e}"))?;
            let mut stmt = db
                .prepare(
                    "SELECT page, context, view_date, view_count
                     FROM page_views
                     WHERE view_date >= ?1
                     ORDER BY view_date DESC, view_count DESC",
                )
                .map_err(|e| format!("page_views query prepare: {e}"))?;

            let rows = stmt
                .query_map(rusqlite::params![cutoff], |row| {
                    Ok(PageViewEntry {
                        page: row.get(0)?,
                        context: row.get(1)?,
                        view_date: row.get(2)?,
                        view_count: row.get(3)?,
                    })
                })
                .map_err(|e| format!("page_views query: {e}"))?;

            let mut entries = Vec::new();
            for row in rows {
                entries.push(row.map_err(|e| format!("page_views row: {e}"))?);
            }
            Ok(entries)
        })
        .await
        .map_err(|e| format!("stats task failed: {e}"))?
    }

    /// Delete page view rows older than `retain_days`.
    pub async fn prune_old_views(&self, retain_days: u32) {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(retain_days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let db = self.db.clone();
        let result = tokio::task::spawn_blocking(move || {
            let db = db.lock().expect("stats db mutex poisoned");
            db.execute(
                "DELETE FROM page_views WHERE view_date < ?1",
                rusqlite::params![cutoff],
            )
        })
        .await;
        match result {
            Ok(Ok(count)) if count > 0 => {
                tracing::info!("stats: pruned {count} old page view rows");
            }
            Ok(Err(e)) => tracing::warn!("stats: page view prune failed: {e}"),
            Err(e) => tracing::warn!("stats: page view prune task failed: {e}"),
            _ => {}
        }
    }
}
