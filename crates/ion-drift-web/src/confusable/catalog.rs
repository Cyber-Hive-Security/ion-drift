//! Confusable watchlist loader — bundled seed files plus an operator overlay.
//!
//! Watchlist JSON is untrusted third-party data, so nothing here trusts a file
//! to be well-formed. A truncated, unreadable or malformed file is
//! `warn!`-logged, recorded in the load report and skipped; rows are only ever
//! upserted, never deleted, so a bad load degrades into "last known good"
//! instead of an empty watchlist. No input path may panic.
//!
//! Two directories are read, in order:
//!
//! 1. `seed_dir` — brands shipped with Drift (`source = "bundled"`).
//! 2. `data_dir` — operator-supplied overlay files (`source = "operator"`).
//!
//! Merge semantics live in the store's upsert: higher `catalog_version` wins
//! and a tie goes to the later write, so the operator overlay layers over a
//! bundled file carrying the same version.
//!
//! File format:
//!
//! ```json
//! {
//!   "catalog_version": 1,
//!   "entries": [
//!     { "brand": "PayPal", "domain": "paypal.com" },
//!     { "brand": "our own lookalike", "domain": "examp1e-corp.com", "allow": true }
//!   ]
//! }
//! ```

use std::path::{Path, PathBuf};

use ion_drift_storage::dns::{DnsStore, WatchlistEntry};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::skeleton::skeleton_of;

const SOURCE_BUNDLED: &str = "bundled";
const SOURCE_OPERATOR: &str = "operator";

/// Outcome of one watchlist load pass.
#[derive(Clone, Debug, Default, Serialize)]
pub struct WatchlistLoadReport {
    pub entries_loaded: usize,
    /// `"<path>: <reason>"` per rejected file or entry, for the degraded state.
    pub files_rejected: Vec<String>,
    pub degraded: bool,
}

impl WatchlistLoadReport {
    fn reject_file(&mut self, path: &Path, reason: String) {
        warn!(path = %path.display(), reason = %reason, "confusable watchlist file rejected");
        self.files_rejected.push(format!("{}: {reason}", path.display()));
        self.degraded = true;
    }

    fn reject_entry(&mut self, path: &Path, domain: &str, reason: String) {
        warn!(
            path = %path.display(),
            domain = %domain,
            reason = %reason,
            "confusable watchlist entry rejected"
        );
        self.files_rejected
            .push(format!("{}: {domain}: {reason}", path.display()));
        self.degraded = true;
    }
}

#[derive(Debug, Deserialize)]
struct WatchlistFile {
    catalog_version: i64,
    #[serde(default)]
    entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    #[serde(default)]
    brand: String,
    domain: String,
    #[serde(default)]
    allow: bool,
}

/// Load, validate and upsert every watchlist file under `seed_dir` and
/// `data_dir`.
///
/// Fail-soft: returns `Err` only when the store itself is unusable. Malformed
/// files and invalid entries are skipped and reported through
/// [`WatchlistLoadReport::degraded`].
pub async fn load_watchlist(
    store: &DnsStore,
    seed_dir: &Path,
    data_dir: &Path,
) -> Result<WatchlistLoadReport, String> {
    let mut report = WatchlistLoadReport::default();

    for (dir, source) in [(seed_dir, SOURCE_BUNDLED), (data_dir, SOURCE_OPERATOR)] {
        for path in json_files(dir, &mut report) {
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    report.reject_file(&path, format!("unreadable: {e}"));
                    continue;
                }
            };
            let file: WatchlistFile = match serde_json::from_str(&text) {
                Ok(f) => f,
                Err(e) => {
                    report.reject_file(&path, format!("malformed JSON: {e}"));
                    continue;
                }
            };

            for raw in file.entries {
                // Staging rejects what can never match — empty, over-length,
                // or a single label, since `candidate_suffixes` only yields
                // 2+ label suffixes and the row would sit matching nothing.
                let Some(domain) = crate::staging::stage_dns_name(&raw.domain) else {
                    report.reject_entry(
                        &path,
                        &crate::staging::stage_text(&raw.domain, crate::staging::MAX_DNS_NAME),
                        "domain must be a bounded name of at least two labels".to_string(),
                    );
                    continue;
                };
                let entry = WatchlistEntry {
                    skeleton: skeleton_of(&domain),
                    domain,
                    // Catalog text reaches finding titles an operator reads.
                    brand: crate::staging::stage_text(&raw.brand, crate::staging::MAX_BRAND),
                    allow: raw.allow,
                    source: source.to_string(),
                    catalog_version: file.catalog_version,
                };
                store
                    .upsert_watchlist_entry(&entry)
                    .await
                    .map_err(|e| format!("watchlist upsert failed for {}: {e}", entry.domain))?;
                report.entries_loaded += 1;
            }
        }
    }

    info!(
        entries = report.entries_loaded,
        rejected = report.files_rejected.len(),
        degraded = report.degraded,
        "confusable watchlist loaded"
    );

    Ok(report)
}

/// List `*.json` under `dir`, sorted, so load order is deterministic.
///
/// A missing directory is normal — Drift ships without an operator overlay —
/// so it is not a degraded state. A directory that exists but cannot be read
/// is, since brands the operator expects would silently vanish.
fn json_files(dir: &Path, report: &mut WatchlistLoadReport) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(dir = %dir.display(), "confusable watchlist directory absent; skipping");
            return Vec::new();
        }
        Err(e) => {
            report.reject_file(dir, format!("directory unreadable: {e}"));
            return Vec::new();
        }
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| match entry {
            Ok(e) => Some(e.path()),
            Err(e) => {
                debug!(dir = %dir.display(), error = %e, "skipping unreadable directory entry");
                None
            }
        })
        .filter(|p| p.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("json")))
        .collect();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn loads_seed_then_operator_overlay() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(
            seed.path().join("baseline.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"PayPal","domain":"paypal.com"}]}"#,
        )
        .unwrap();
        std::fs::write(
            data.path().join("local.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"Our Bank","domain":"examplebank.com"}]}"#,
        )
        .unwrap();

        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert_eq!(report.entries_loaded, 2);
        assert!(!report.degraded);

        let list = store.list_watchlist().await.unwrap();
        let sources: Vec<&str> = list.iter().map(|e| e.source.as_str()).collect();
        assert!(sources.contains(&"bundled") && sources.contains(&"operator"));
        assert!(
            list.iter().all(|e| !e.skeleton.is_empty()),
            "skeleton computed at load"
        );
    }

    #[tokio::test]
    async fn malformed_file_degrades_without_stopping_the_load() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("bad.json"), "{truncated").unwrap();
        std::fs::write(
            seed.path().join("good.json"),
            r#"{"catalog_version":1,"entries":[{"brand":"GitHub","domain":"github.com"}]}"#,
        )
        .unwrap();

        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert!(report.degraded);
        assert_eq!(report.entries_loaded, 1, "good file still lands");
        assert_eq!(report.files_rejected.len(), 1);
    }

    #[tokio::test]
    async fn single_label_domain_costs_the_entry_not_the_file() {
        let seed = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        std::fs::write(
            seed.path().join("mixed.json"),
            r#"{"catalog_version":1,"entries":[
                {"brand":"bad","domain":"localhost"},
                {"brand":"GitHub","domain":"github.com"}]}"#,
        )
        .unwrap();

        let f = NamedTempFile::new().unwrap();
        let store = DnsStore::new(f.path()).await.unwrap();
        let report = load_watchlist(&store, seed.path(), data.path()).await.unwrap();
        assert_eq!(report.entries_loaded, 1);
        assert!(report.degraded, "the rejected entry is visible in the report");
        assert_eq!(store.list_watchlist().await.unwrap()[0].domain, "github.com");
    }
}
