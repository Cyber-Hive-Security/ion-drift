//! Advisory catalog loader — bundled seed files plus an operator overlay.
//!
//! Catalog JSON is untrusted third-party data, so nothing here trusts a file to
//! be well-formed. A truncated, unreadable or malformed file is `warn!`-logged,
//! recorded in the load report and skipped; rows are only ever upserted, never
//! deleted, so a bad load degrades into "last known good" instead of an empty
//! catalog. No input path may panic.
//!
//! Two directories are read, in order:
//!
//! 1. `seed_dir` — advisories shipped with Drift (`source = "bundled"`).
//! 2. `data_dir` — operator-supplied overlay files (`source = "operator"`).
//!
//! Neither path is derived here. The caller owns the data directory (main.rs
//! already resolves it) and passes both in.
//!
//! Entries merge by `advisory_id`: the higher `catalog_version` wins, and a tie
//! breaks toward the file read later, so an operator file layers over a bundled
//! file carrying the same version.
//!
//! Validation rejects an entry whose surface class core cannot evaluate — it
//! would otherwise sit in the database matching nothing. A signal core cannot
//! emit costs that one link rather than the whole entry, so an advisory keeps
//! its narrative and mitigations as long as one usable link remains.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ion_drift_storage::advisory::{AdvisoryRecord, AdvisoryStore};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::signals::is_known_signal;

/// Surface classes the exposure evaluator understands. An advisory scoped to
/// anything else cannot be matched against observed state.
pub const KNOWN_SURFACE_CLASSES: &[&str] = &["service"];

/// Confidence levels accepted by the `advisory_signal` CHECK constraint.
const KNOWN_CONFIDENCE: &[&str] = &["strong", "corroborating"];

/// Severity levels a finding can carry.
const KNOWN_SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

const SOURCE_BUNDLED: &str = "bundled";
const SOURCE_OPERATOR: &str = "operator";

/// Outcome of one catalog load pass.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CatalogLoadReport {
    pub advisories_loaded: usize,
    pub signals_loaded: usize,
    /// `"<path>: <reason>"` per rejected file or entry, for the degraded state.
    pub files_rejected: Vec<String>,
    pub degraded: bool,
}

impl CatalogLoadReport {
    fn reject_file(&mut self, path: &Path, reason: String) {
        warn!(path = %path.display(), reason = %reason, "advisory catalog file rejected");
        self.files_rejected.push(format!("{}: {reason}", path.display()));
        self.degraded = true;
    }

    fn reject_entry(&mut self, path: &Path, advisory_id: &str, reason: String) {
        warn!(
            path = %path.display(),
            advisory = %advisory_id,
            reason = %reason,
            "advisory catalog entry rejected"
        );
        self.files_rejected
            .push(format!("{} [{advisory_id}]: {reason}", path.display()));
        self.degraded = true;
    }
}

/// One catalog file as it sits on disk.
#[derive(Debug, Deserialize)]
struct CatalogFile {
    catalog_version: i64,
    #[serde(default)]
    generated_at: String,
    #[serde(default)]
    advisories: Vec<RawAdvisory>,
}

#[derive(Debug, Deserialize)]
struct RawAdvisory {
    advisory_id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    narrative: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    requires_surface_class: String,
    #[serde(default)]
    requires_surface_names: Vec<String>,
    #[serde(default)]
    requires_state: Vec<String>,
    #[serde(default)]
    version_constraint: Option<serde_json::Value>,
    #[serde(default)]
    no_fixed_release: bool,
    #[serde(default)]
    fixed_versions: Vec<String>,
    #[serde(default)]
    mitigations: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    attack_techniques: Vec<String>,
    #[serde(default)]
    signals: Vec<RawSignal>,
}

#[derive(Clone, Debug, Deserialize)]
struct RawSignal {
    signal_id: String,
    confidence: String,
    #[serde(default)]
    description: String,
}

/// A validated entry waiting to be written, plus the version that won it.
struct MergedAdvisory {
    record: AdvisoryRecord,
    signals: Vec<RawSignal>,
}

/// Load, merge, validate and upsert every catalog file under `seed_dir` and
/// `data_dir`.
///
/// Fail-soft: returns `Err` only when the store itself is unusable. Malformed
/// files and invalid entries are skipped and reported through
/// [`CatalogLoadReport::degraded`].
pub async fn load_catalog(
    store: &AdvisoryStore,
    seed_dir: &Path,
    data_dir: &Path,
) -> Result<CatalogLoadReport, String> {
    let mut report = CatalogLoadReport::default();
    let mut merged: BTreeMap<String, MergedAdvisory> = BTreeMap::new();

    for (dir, source) in [(seed_dir, SOURCE_BUNDLED), (data_dir, SOURCE_OPERATOR)] {
        for path in json_files(dir, &mut report) {
            merge_file(&path, source, &mut merged, &mut report);
        }
    }

    for entry in merged.into_values() {
        store
            .upsert_advisory(&entry.record)
            .await
            .map_err(|e| format!("advisory upsert failed for {}: {e}", entry.record.advisory_id))?;
        report.advisories_loaded += 1;

        for sig in &entry.signals {
            store
                .upsert_signal(
                    &entry.record.advisory_id,
                    &sig.signal_id,
                    &sig.confidence,
                    &sig.description,
                )
                .await
                .map_err(|e| {
                    format!(
                        "signal upsert failed for {} / {}: {e}",
                        entry.record.advisory_id, sig.signal_id
                    )
                })?;
            report.signals_loaded += 1;
        }
    }

    info!(
        advisories = report.advisories_loaded,
        signals = report.signals_loaded,
        rejected = report.files_rejected.len(),
        degraded = report.degraded,
        "advisory catalog loaded"
    );

    Ok(report)
}

/// List `*.json` under `dir`, sorted, so merge order is deterministic.
///
/// A missing directory is normal — Drift ships without an operator overlay —
/// so it is not a degraded state. A directory that exists but cannot be read
/// is, since advisories the operator expects would silently vanish.
fn json_files(dir: &Path, report: &mut CatalogLoadReport) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(dir = %dir.display(), "advisory catalog directory absent; skipping");
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

/// Parse one file and fold its entries into `merged`.
fn merge_file(
    path: &Path,
    source: &str,
    merged: &mut BTreeMap<String, MergedAdvisory>,
    report: &mut CatalogLoadReport,
) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            report.reject_file(path, format!("unreadable: {e}"));
            return;
        }
    };

    let file: CatalogFile = match serde_json::from_str(&text) {
        Ok(f) => f,
        Err(e) => {
            report.reject_file(path, format!("malformed JSON: {e}"));
            return;
        }
    };

    for raw in file.advisories {
        match validate(raw, file.catalog_version, &file.generated_at, source) {
            Ok((entry, rejected_signals)) => {
                for reason in rejected_signals {
                    report.reject_entry(path, &entry.record.advisory_id, reason);
                }
                insert_merged(merged, entry, file.catalog_version);
            }
            Err((advisory_id, reason)) => report.reject_entry(path, &advisory_id, reason),
        }
    }
}

/// Insert unless an entry with a strictly higher `catalog_version` is already
/// held. Ties fall through to the insert so a later file — the operator overlay
/// — layers over an equal-version bundled entry.
fn insert_merged(
    merged: &mut BTreeMap<String, MergedAdvisory>,
    candidate: MergedAdvisory,
    candidate_version: i64,
) {
    if let Some(existing) = merged.get(&candidate.record.advisory_id)
        && existing.record.catalog_version > candidate_version
    {
        debug!(
            advisory = %candidate.record.advisory_id,
            kept = existing.record.catalog_version,
            discarded = candidate_version,
            "keeping higher catalog_version"
        );
        return;
    }
    merged.insert(candidate.record.advisory_id.clone(), candidate);
}

/// Validate one raw entry into a storable record.
///
/// On rejection returns `(advisory_id, reason)` so the caller can attribute the
/// failure without re-reading the entry. On success the second element holds a
/// reason per signal link that was dropped — the entry itself survived, so the
/// caller records those against it rather than losing the whole advisory.
fn validate(
    raw: RawAdvisory,
    catalog_version: i64,
    generated_at: &str,
    source: &str,
) -> Result<(MergedAdvisory, Vec<String>), (String, String)> {
    let advisory_id = raw.advisory_id.trim().to_string();
    if advisory_id.is_empty() {
        return Err(("<unnamed>".to_string(), "empty advisory_id".to_string()));
    }

    let surface_class = raw.requires_surface_class.trim().to_lowercase();
    if surface_class.is_empty() {
        return Err((advisory_id, "empty requires_surface_class".to_string()));
    }
    if !KNOWN_SURFACE_CLASSES.contains(&surface_class.as_str()) {
        return Err((
            advisory_id,
            format!("unknown requires_surface_class '{surface_class}'"),
        ));
    }
    // A service-class advisory has to name the services it applies to.
    // `requires_surface_names` is `#[serde(default)]`, so omitting it is not a
    // parse error — it just yields an empty list, and
    // `exploitation::advisory_covers_surface` fails closed on one. Rejecting the
    // entry here turns "matches nothing, forever, silently" into a reported
    // rejection, the same way an unknown `requires_surface_class` is handled.
    if surface_class == "service"
        && raw
            .requires_surface_names
            .iter()
            .all(|name| name.trim().is_empty())
    {
        return Err((
            advisory_id,
            "empty requires_surface_names for requires_surface_class 'service'".to_string(),
        ));
    }

    let severity = raw.severity.trim().to_lowercase();
    if !KNOWN_SEVERITIES.contains(&severity.as_str()) {
        return Err((advisory_id, format!("unknown severity '{severity}'")));
    }

    // A constraint is either absent or a non-empty list of version ranges the
    // matcher can evaluate. Anything else is rejected rather than stored and
    // silently ignored: an advisory must never claim coverage the engine
    // cannot compute.
    if let Some(vc) = raw
        .version_constraint
        .as_ref()
        .filter(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()))
    {
        let ranges = serde_json::from_value::<Vec<crate::advisory::version::VersionRange>>(vc.clone())
            .ok()
            .filter(|ranges| !ranges.is_empty());
        let Some(ranges) = ranges else {
            return Err((
                advisory_id,
                "unrecognised version_constraint: expected a non-empty array of version ranges".to_string(),
            ));
        };
        if ranges.iter().any(|r| r.mixes_exact_with_bounds()) {
            return Err((
                advisory_id,
                "invalid version_constraint: exact cannot be combined with start/end bounds in one range"
                    .to_string(),
            ));
        }
    }

    // An unusable link costs the advisory that one link, not its narrative and
    // mitigations: those still describe a real exposure even when the catalog
    // names a behaviour this build has no detector for. Only an entry whose
    // every declared link is unusable is dropped, since nothing about it could
    // ever correlate.
    let declared_signals = raw.signals.len();
    let mut signals = Vec::with_capacity(declared_signals);
    let mut rejected_signals = Vec::new();
    for mut sig in raw.signals {
        sig.signal_id = sig.signal_id.trim().to_string();
        sig.confidence = sig.confidence.trim().to_lowercase();

        if !is_known_signal(&sig.signal_id) {
            rejected_signals.push(format!("unknown signal_id '{}'", sig.signal_id));
            continue;
        }
        if !KNOWN_CONFIDENCE.contains(&sig.confidence.as_str()) {
            rejected_signals.push(format!(
                "unknown confidence '{}' for signal '{}'",
                sig.confidence, sig.signal_id
            ));
            continue;
        }
        signals.push(sig);
    }
    if declared_signals > 0 && signals.is_empty() {
        return Err((
            advisory_id,
            format!("no usable signals: {}", rejected_signals.join("; ")),
        ));
    }

    let record = AdvisoryRecord {
        advisory_id: advisory_id.clone(),
        title: raw.title,
        narrative: raw.narrative,
        severity,
        requires_surface_class: surface_class,
        requires_surface_names: raw.requires_surface_names,
        requires_state: raw.requires_state,
        version_constraint: version_constraint_string(raw.version_constraint),
        no_fixed_release: raw.no_fixed_release,
        fixed_versions: raw.fixed_versions,
        mitigations: raw.mitigations,
        references: crate::staging::stage_references(&raw.references),
        attack_techniques: raw.attack_techniques,
        source: source.to_string(),
        catalog_version,
        generated_at: generated_at.to_string(),
    };

    Ok((MergedAdvisory { record, signals }, rejected_signals))
}

/// Flatten `version_constraint` into the JSON string the store holds. Only
/// `null` or an array of version ranges reaches here: validation rejects a
/// bare string such as `"< 7.16"` before the record is built.
fn version_constraint_string(value: Option<serde_json::Value>) -> Option<String> {
    match value {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => None,
        Some(serde_json::Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    //! Loader tests run against a real `AdvisoryStore` on a tempfile so the
    //! merge result is checked as persisted rows, not just as in-memory state.

    use super::*;
    use tempfile::TempDir;

    /// A catalog file with one valid advisory carrying two known signals.
    fn valid_catalog(version: i64, title: &str) -> String {
        format!(
            r#"{{
  "catalog_version": {version},
  "generated_at": "2026-07-28",
  "advisories": [
    {{
      "advisory_id": "CVE-2026-16347",
      "title": "{title}",
      "narrative": "unbounded credential guessing on the api service",
      "severity": "high",
      "requires_surface_class": "service",
      "requires_surface_names": ["api", "api-ssl"],
      "requires_state": ["exposed"],
      "version_constraint": null,
      "no_fixed_release": true,
      "fixed_versions": [],
      "mitigations": ["scope the service to management sources"],
      "references": ["https://example.invalid/advisory"],
      "attack_techniques": ["T1110"],
      "signals": [
        {{ "signal_id": "auth.login_failure_same_second_burst", "confidence": "strong",
           "description": "same-second burst" }},
        {{ "signal_id": "auth.login_failure_burst", "confidence": "corroborating",
           "description": "run of failures" }}
      ]
    }}
  ]
}}"#
        )
    }

    fn write(dir: &TempDir, name: &str, body: &str) {
        std::fs::write(dir.path().join(name), body).expect("write catalog fixture");
    }

    async fn store_in(dir: &TempDir) -> AdvisoryStore {
        AdvisoryStore::new(&dir.path().join("advisory.db"))
            .await
            .expect("advisory store")
    }

    #[tokio::test]
    async fn valid_catalog_loads() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        write(&seed, "mikrotik.json", &valid_catalog(1, "api brute force"));

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert_eq!(report.advisories_loaded, 1);
        assert_eq!(report.signals_loaded, 2);
        assert!(report.files_rejected.is_empty());
        assert!(!report.degraded);

        let stored = store.list_advisories().await.expect("list");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].advisory_id, "CVE-2026-16347");
        assert_eq!(stored[0].requires_surface_names, vec!["api", "api-ssl"]);
        assert_eq!(stored[0].source, "bundled");
        assert!(stored[0].version_constraint.is_none());

        let linked = store
            .advisories_for_signal("auth.login_failure_same_second_burst")
            .await
            .expect("signal lookup");
        assert_eq!(linked, vec![("CVE-2026-16347".to_string(), "strong".to_string())]);
    }

    #[tokio::test]
    async fn truncated_file_degrades_without_losing_good_rows() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        write(&seed, "good.json", &valid_catalog(1, "api brute force"));
        // Truncated mid-object — the classic half-written download.
        write(&seed, "truncated.json", r#"{"catalog_version": 1, "advisories": [{"advisory_id": "#);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("malformed input must not be fatal");

        assert!(report.degraded);
        assert_eq!(report.files_rejected.len(), 1);
        assert!(report.files_rejected[0].contains("truncated.json"));
        // The healthy file still landed.
        assert_eq!(report.advisories_loaded, 1);
        assert_eq!(store.list_advisories().await.expect("list").len(), 1);
    }

    #[tokio::test]
    async fn empty_file_is_rejected_not_panicked() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        write(&seed, "empty.json", "");

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("empty input must not be fatal");

        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(store.list_advisories().await.expect("list").is_empty());
    }

    /// An unusable link costs the advisory that link, not its narrative and
    /// mitigations. Dropping the whole entry threw away everything an operator
    /// could act on because one signal name was ahead of this build.
    #[tokio::test]
    async fn unknown_signal_id_rejects_only_that_link() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace("auth.login_failure_burst\", \"confidence\": \"corroborating", "auth.not_a_signal\", \"confidence\": \"corroborating");
        write(&seed, "mikrotik.json", &body);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert!(report.degraded, "a dropped link is still a degraded load");
        assert_eq!(report.files_rejected.len(), 1);
        assert!(report.files_rejected[0].contains("auth.not_a_signal"));
        assert!(report.files_rejected[0].contains("CVE-2026-16347"));

        // The advisory itself survived with its one usable link.
        assert_eq!(report.advisories_loaded, 1);
        assert_eq!(report.signals_loaded, 1);
        let stored = store.list_advisories().await.expect("list");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].mitigations.len(), 1);
        assert_eq!(
            store
                .advisories_for_signal("auth.login_failure_same_second_burst")
                .await
                .expect("signal lookup"),
            vec![("CVE-2026-16347".to_string(), "strong".to_string())]
        );
        assert!(
            store
                .advisories_for_signal("auth.not_a_signal")
                .await
                .expect("signal lookup")
                .is_empty()
        );
    }

    /// The exception: an entry whose every declared link is unusable can never
    /// correlate, so it is still rejected outright.
    #[tokio::test]
    async fn advisory_with_no_usable_signal_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace("auth.login_failure_same_second_burst", "auth.not_a_signal")
            .replace("auth.login_failure_burst", "auth.also_not_a_signal");
        write(&seed, "mikrotik.json", &body);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert_eq!(report.signals_loaded, 0);
        assert_eq!(report.files_rejected.len(), 1);
        assert!(report.files_rejected[0].contains("no usable signals"));
        assert!(store.list_advisories().await.expect("list").is_empty());
    }

    /// A confidence level the `advisory_signal` CHECK constraint would refuse
    /// takes the same path as an unknown id — the link, not the entry.
    #[tokio::test]
    async fn unknown_confidence_rejects_only_that_link() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace(r#""confidence": "corroborating""#, r#""confidence": "vibes""#);
        write(&seed, "mikrotik.json", &body);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 1);
        assert_eq!(report.signals_loaded, 1);
        assert!(report.files_rejected[0].contains("vibes"));
    }

    #[tokio::test]
    async fn unknown_surface_class_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace(r#""requires_surface_class": "service""#, r#""requires_surface_class": "teapot""#);
        write(&seed, "mikrotik.json", &body);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(report.files_rejected[0].contains("teapot"));
    }

    /// A service-class advisory that names no services is rejected at load.
    ///
    /// `requires_surface_names` is `#[serde(default)]`, so an entry omitting it
    /// parses cleanly into an empty list — and an empty scope now matches no
    /// surface at all (`exploitation::advisory_covers_surface` fails closed).
    /// Loading it would leave an advisory that can never correlate with
    /// anything and no sign of why, so the entry is refused and the catalog is
    /// marked degraded, the same as an unknown `requires_surface_class`.
    #[tokio::test]
    async fn service_advisory_without_surface_names_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();

        // The field omitted entirely.
        let omitted = valid_catalog(1, "api brute force")
            .replace(r#""requires_surface_names": ["api", "api-ssl"],"#, "");
        assert!(!omitted.contains("requires_surface_names"));
        write(&seed, "mikrotik.json", &omitted);

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(
            report.files_rejected[0].contains("requires_surface_names"),
            "rejection must name the field: {:?}",
            report.files_rejected
        );
        assert!(store.list_advisories().await.expect("list").is_empty());

        // Present but empty, and present but blank, are the same thing.
        for names in [r#""requires_surface_names": [],"#, r#""requires_surface_names": ["  "],"#] {
            let seed = TempDir::new().unwrap();
            let data = TempDir::new().unwrap();
            let db = TempDir::new().unwrap();
            let body = valid_catalog(1, "api brute force")
                .replace(r#""requires_surface_names": ["api", "api-ssl"],"#, names);
            write(&seed, "mikrotik.json", &body);

            let store = store_in(&db).await;
            let report = load_catalog(&store, seed.path(), data.path())
                .await
                .expect("load");
            assert!(report.degraded, "{names} must be rejected");
            assert_eq!(report.advisories_loaded, 0, "{names} must not load");
        }
    }

    #[tokio::test]
    async fn higher_catalog_version_wins_on_merge() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        write(&seed, "mikrotik.json", &valid_catalog(1, "bundled title"));
        write(&data, "mikrotik.json", &valid_catalog(2, "operator title"));

        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        assert_eq!(report.advisories_loaded, 1);
        let stored = store.list_advisories().await.expect("list");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].title, "operator title");
        assert_eq!(stored[0].catalog_version, 2);
        assert_eq!(stored[0].source, "operator");
    }

    #[tokio::test]
    async fn lower_catalog_version_does_not_override() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        write(&seed, "mikrotik.json", &valid_catalog(5, "bundled title"));
        write(&data, "stale.json", &valid_catalog(2, "stale operator title"));

        let store = store_in(&db).await;
        load_catalog(&store, seed.path(), data.path())
            .await
            .expect("load");

        let stored = store.list_advisories().await.expect("list");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].title, "bundled title");
        assert_eq!(stored[0].catalog_version, 5);
        assert_eq!(stored[0].source, "bundled");
    }

    #[tokio::test]
    async fn missing_directories_are_not_degraded() {
        let db = TempDir::new().unwrap();
        let store = store_in(&db).await;
        let report = load_catalog(
            &store,
            Path::new("/nonexistent/ion-drift/seed"),
            Path::new("/nonexistent/ion-drift/data"),
        )
        .await
        .expect("load");

        assert!(!report.degraded);
        assert_eq!(report.advisories_loaded, 0);
    }

    #[test]
    fn version_constraint_flattens_to_json_string() {
        assert_eq!(version_constraint_string(None), None);
        assert_eq!(version_constraint_string(Some(serde_json::Value::Null)), None);
        assert_eq!(
            version_constraint_string(Some(serde_json::json!("< 7.16"))),
            Some("< 7.16".to_string())
        );
        assert_eq!(
            version_constraint_string(Some(serde_json::json!({ "lt": "7.16" }))),
            Some(r#"{"lt":"7.16"}"#.to_string())
        );
    }

    #[tokio::test]
    async fn version_constraint_ranges_are_accepted() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force").replace(
            r#""version_constraint": null"#,
            r#""version_constraint": [{"start_including": "7.0", "end_excluding": "7.24.2"}]"#,
        );
        write(&seed, "mikrotik.json", &body);
        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path()).await.expect("load");
        assert!(!report.degraded);
        assert_eq!(report.advisories_loaded, 1);
        let stored = store.list_advisories().await.unwrap();
        let ranges: Vec<crate::advisory::version::VersionRange> =
            serde_json::from_str(stored[0].version_constraint.as_deref().unwrap()).unwrap();
        assert_eq!(ranges[0].end_excluding.as_deref(), Some("7.24.2"));
    }

    #[tokio::test]
    async fn unrecognised_version_constraint_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force")
            .replace(r#""version_constraint": null"#, r#""version_constraint": "< 7.16""#);
        write(&seed, "mikrotik.json", &body);
        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path()).await.expect("load");
        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(report.files_rejected[0].contains("version_constraint"));
    }

    #[tokio::test]
    async fn exact_combined_with_bounds_version_constraint_is_rejected() {
        let seed = TempDir::new().unwrap();
        let data = TempDir::new().unwrap();
        let db = TempDir::new().unwrap();
        let body = valid_catalog(1, "api brute force").replace(
            r#""version_constraint": null"#,
            r#""version_constraint": [{"exact": "7.0", "end_excluding": "7.24.2"}]"#,
        );
        write(&seed, "mikrotik.json", &body);
        let store = store_in(&db).await;
        let report = load_catalog(&store, seed.path(), data.path()).await.expect("load");
        assert!(report.degraded);
        assert_eq!(report.advisories_loaded, 0);
        assert!(report.files_rejected[0].contains("version_constraint"));
        assert!(report.files_rejected[0].contains("exact"));
    }
}
