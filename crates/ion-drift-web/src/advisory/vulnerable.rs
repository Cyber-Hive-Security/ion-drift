//! Version-based vulnerability findings.
//!
//! A finding here says exactly one thing: this device's RouterOS version falls
//! in a published affected range. It does not claim the affected feature is
//! enabled — fetched CVEs carry no machine-readable configuration condition —
//! and every finding's narrative says so.
//!
//! Lifecycle: Drift resolves a finding only when the device is positively
//! outside every affected range, and reopens only findings it resolved itself
//! (`resolved_by = 'system'`) when the device falls back into a range. An
//! acknowledged finding whose severity escalates (e.g. the CVE is added to
//! CISA KEV) is reopened with a note. An operator's manual resolution always
//! sticks.

use std::collections::{BTreeMap, BTreeSet};

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingSubject, FindingV1};
use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
use tracing::warn;

use crate::advisory::exploitation::ADVISORY_MODULE;
use crate::advisory::exposure::{label, rank, ESCALATION_MARKER};
use crate::advisory::version::{self, Applicability, VersionRange};

pub(crate) const VULN_CATEGORY: &str = "advisory_vulnerable";

pub(crate) fn vuln_finding_id(device_id: &str, cve_id: &str) -> String {
    format!("{device_id}:ver:{cve_id}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VulnSource {
    Nvd,
    Catalog,
}

#[derive(Clone, Debug)]
pub(crate) struct VulnInput {
    pub cve_id: String,
    /// Catalog title when curated; `None` for fetched CVEs.
    pub title: Option<String>,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub ranges: Vec<VersionRange>,
    pub kev_date_added: Option<String>,
    pub mitigations: Vec<String>,
    /// Curated references from the catalog; empty for fetched CVEs.
    pub references: Vec<String>,
    pub source: VulnSource,
}

#[derive(Debug, Default)]
pub(crate) struct VulnAssessment {
    pub device_version: String,
    pub affected: Vec<FindingV1>,
    /// Finding ids for CVEs positively evaluated as not affecting this device.
    pub not_affected: BTreeSet<String>,
    /// CVE ids that could not be evaluated. Never resolved, never raised.
    pub cannot_evaluate: Vec<String>,
}

/// KEV-listed → Critical, whatever the score; otherwise CVSS bands.
pub(crate) fn severity_for(cvss: Option<f64>, on_kev: bool) -> FindingSeverity {
    if on_kev {
        return FindingSeverity::Critical;
    }
    match cvss {
        Some(s) if s >= 7.0 => FindingSeverity::High,
        Some(s) if s >= 4.0 => FindingSeverity::Medium,
        Some(_) => FindingSeverity::Low,
        None => FindingSeverity::Medium,
    }
}

pub(crate) fn assess(device_id: &str, device_version: &str, inputs: &[VulnInput], now: i64) -> VulnAssessment {
    let mut out = VulnAssessment { device_version: device_version.to_string(), ..Default::default() };
    for input in inputs {
        let id = vuln_finding_id(device_id, &input.cve_id);
        match version::evaluate(device_version, &input.ranges) {
            (Applicability::Affected, Some(matched)) => {
                out.affected.push(build_finding(&id, device_id, device_version, input, matched, now));
            }
            (Applicability::NotAffected, _) => {
                out.not_affected.insert(id);
            }
            _ => out.cannot_evaluate.push(input.cve_id.clone()),
        }
    }
    out
}

fn upgrade_action(matched: &VersionRange) -> String {
    match (&matched.end_excluding, &matched.end_including) {
        (Some(fixed), _) => format!("Upgrade RouterOS to {fixed} or later on this release branch."),
        (None, Some(last)) => format!("Upgrade RouterOS beyond {last}."),
        _ => "No fixed RouterOS version is recorded for this range; restrict access to the affected feature.".to_string(),
    }
}

fn build_finding(
    finding_id: &str,
    device_id: &str,
    device_version: &str,
    input: &VulnInput,
    matched: &VersionRange,
    now: i64,
) -> FindingV1 {
    let version_label = device_version.split_whitespace().next().unwrap_or(device_version);
    let on_kev = input.kev_date_added.is_some();
    let headline = input.title.clone().unwrap_or_else(|| input.cve_id.clone());
    let exploited = if on_kev { " — actively exploited" } else { "" };
    let attribution = match input.source {
        VulnSource::Nvd => format!("Description from the National Vulnerability Database (NVD), {}.", input.cve_id),
        VulnSource::Catalog => "Description from the Ion Drift advisory catalog.".to_string(),
    };
    let narrative = format!(
        "{}\n\nYour RouterOS version is in the affected range. Drift has not checked \
         whether the affected feature is enabled on this router.{}\n\n{attribution}",
        input.description,
        match &input.kev_date_added {
            Some(d) => format!(" CISA lists this vulnerability as known to be exploited in the wild (added {d})."),
            None => String::new(),
        },
    );
    let mut recommended_actions = vec![upgrade_action(matched)];
    recommended_actions.extend(input.mitigations.iter().cloned());
    let mut references = input.references.clone();
    if input.cve_id.starts_with("CVE-") {
        let nvd = format!("https://nvd.nist.gov/vuln/detail/{}", input.cve_id);
        if !references.contains(&nvd) {
            references.push(nvd);
        }
    }

    FindingV1 {
        finding_id: finding_id.to_string(),
        title: format!("{headline} — RouterOS {version_label} is affected{exploited}"),
        narrative,
        severity: severity_for(input.cvss_score, on_kev),
        category: VULN_CATEGORY.to_string(),
        recommended_actions,
        evidence: vec![FindingEvidence::Custom {
            label: "version match".to_string(),
            payload: serde_json::json!({
                "cve_id": input.cve_id,
                "device_id": device_id,
                "device_version": device_version,
                "matched_range": matched,
                "kev_date_added": input.kev_date_added,
            }),
        }],
        references,
        subjects: vec![FindingSubject::device(device_id)],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "cve_id": input.cve_id,
            "cvss_score": input.cvss_score,
            "cvss_vector": input.cvss_vector,
            "kev_date_added": input.kev_date_added,
            "source": match input.source { VulnSource::Nvd => "nvd", VulnSource::Catalog => "catalog" },
        })),
    }
}

/// Apply one device's assessment. Resolves only findings for CVEs positively
/// evaluated as not affected; `cannot_evaluate` CVEs are left exactly as they are.
///
/// Lifecycle rules for an affected finding:
/// - acknowledged, and the severity escalated (e.g. High → Critical when CISA
///   lists the CVE as exploited): reopened with an escalation note; unchanged
///   or lowered severity keeps the acknowledgment.
/// - resolved by Drift itself (`resolved_by = 'system'`, i.e. a regression
///   after an upgrade): reopened.
/// - resolved by an operator: refreshed but stays resolved.
///
/// The escalation note is carried forward on later cycles while the finding
/// stays at the severity it escalated to. If the escalation reopen fails, the
/// finding is not written that cycle: the row stays acknowledged at its old
/// severity and the escalation is re-detected next cycle.
pub(crate) async fn reconcile(store: &FindingsStore, assessment: &VulnAssessment) -> Result<(), String> {
    // Value: (status, severity, resolved by Drift itself, stored narrative).
    let held: BTreeMap<String, (FindingStatus, FindingSeverity, bool, String)> = store
        .list_findings(&FindingsQuery {
            module_name: Some(ADVISORY_MODULE.to_string()),
            category: Some(VULN_CATEGORY.to_string()),
            ..Default::default()
        })
        .await?
        .into_iter()
        .map(|f| {
            let system_resolved = f.resolved_by.as_deref() == Some("system");
            (f.finding_id, (f.status, f.severity, system_resolved, f.narrative))
        })
        .collect();

    for finding in &assessment.affected {
        let mut finding = finding.clone();
        match held.get(&finding.finding_id) {
            Some((FindingStatus::Acknowledged, prior, _, _)) if rank(finding.severity) > rank(*prior) => {
                if let Err(e) = store.reopen_acknowledged_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: vulnerability escalation reopen failed; finding left unchanged this cycle");
                    continue;
                }
                finding.narrative.push_str(&format!(
                    "{ESCALATION_MARKER}{} to {}: the vulnerability's severity rose after this finding \
                     was acknowledged (for example, CISA listed it as actively exploited), so it has \
                     been reopened for review.",
                    label(*prior),
                    label(finding.severity)
                ));
            }
            // Re-open first: upsert preserves lifecycle state, so a finding Drift
            // closed after an upgrade would otherwise stay resolved after a downgrade.
            Some((FindingStatus::Resolved, _, true, _)) => {
                if let Err(e) = store.reopen_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: vulnerability reopen failed");
                }
            }
            Some((_, prior, _, narrative)) if *prior == finding.severity => {
                if let Some(at) = narrative.find(ESCALATION_MARKER) {
                    finding.narrative.push_str(&narrative[at..]);
                }
            }
            _ => {}
        }
        if let Err(e) = store.upsert_finding(ADVISORY_MODULE, &finding, None, None).await {
            warn!(finding_id = %finding.finding_id, error = %e, "advisory: vulnerability upsert failed");
        }
    }

    let version_label = assessment.device_version.split_whitespace().next().unwrap_or("");
    let note = format!("No longer affected: RouterOS {version_label} is outside every affected range.");
    let unresolved = held
        .iter()
        .filter(|(_, (status, ..))| *status != FindingStatus::Resolved)
        .map(|(id, _)| id);
    for id in unresolved.filter(|id| assessment.not_affected.contains(*id)) {
        if let Err(e) = store.resolve_by_key(ADVISORY_MODULE, id, &note).await {
            warn!(finding_id = %id, error = %e, "advisory: vulnerability resolve failed");
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
    use tempfile::NamedTempFile;

    fn r(si: &str, ee: &str) -> VersionRange {
        VersionRange { start_including: Some(si.into()), end_excluding: Some(ee.into()), ..Default::default() }
    }

    fn input(id: &str, score: Option<f64>, kev: bool) -> VulnInput {
        VulnInput {
            cve_id: id.into(),
            title: None,
            description: "RouterOS contains an argument-handling flaw in the SSH login path.".into(),
            cvss_score: score,
            cvss_vector: Some("CVSS:4.0/AV:N".into()),
            ranges: vec![r("6.0", "6.49.21"), r("7.0", "7.23.4"), r("7.24", "7.24.2")],
            kev_date_added: kev.then(|| "2026-09-10".to_string()),
            mitigations: Vec::new(),
            references: vec![],
            source: VulnSource::Nvd,
        }
    }

    #[test]
    fn severity_prefers_kev_then_cvss_bands() {
        assert_eq!(severity_for(Some(5.0), true), FindingSeverity::Critical);
        assert_eq!(severity_for(Some(8.8), false), FindingSeverity::High);
        assert_eq!(severity_for(Some(7.0), false), FindingSeverity::High);
        assert_eq!(severity_for(Some(6.9), false), FindingSeverity::Medium);
        assert_eq!(severity_for(Some(4.0), false), FindingSeverity::Medium);
        assert_eq!(severity_for(Some(3.9), false), FindingSeverity::Low);
        assert_eq!(severity_for(None, false), FindingSeverity::Medium);
    }

    #[test]
    fn kev_listed_affected_cve_is_critical_and_honest_about_scope() {
        let a = assess("dev1", "7.24.1 (stable)", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert_eq!(a.affected.len(), 1);
        let f = &a.affected[0];
        assert_eq!(f.subjects, vec![FindingSubject::device("dev1")]);
        assert_eq!(f.finding_id, "dev1:ver:CVE-2026-86060");
        assert_eq!(f.category, VULN_CATEGORY);
        assert_eq!(f.severity, FindingSeverity::Critical);
        assert!(f.title.contains("actively exploited"));
        assert!(f.narrative.contains("Your RouterOS version is in the affected range."));
        assert!(f.narrative.contains(
            "Drift has not checked whether the affected feature is enabled on this router."
        ));
        assert!(f.recommended_actions[0].contains("7.24.2"));
        assert!(!f.recommended_actions.iter().any(|a| a.contains("nvd.nist.gov")), "URL lives in references now");
        assert_eq!(f.references, vec!["https://nvd.nist.gov/vuln/detail/CVE-2026-86060".to_string()]);
    }

    #[test]
    fn non_cve_advisory_gets_no_nvd_link() {
        let a = assess("dev1", "7.24.1 (stable)", &[input("MT-2026-0001", None, false)], 1);
        assert!(a.affected[0].references.is_empty(), "no NVD page exists for a vendor id");
    }

    #[test]
    fn curated_references_come_first_and_nvd_is_not_duplicated() {
        let mut i = input("CVE-2026-86060", Some(9.2), false);
        i.references = vec![
            "https://mikrotik.com/advisory/x".to_string(),
            "https://nvd.nist.gov/vuln/detail/CVE-2026-86060".to_string(),
        ];
        let a = assess("dev1", "7.24.1 (stable)", &[i], 1);
        assert_eq!(
            a.affected[0].references,
            vec![
                "https://mikrotik.com/advisory/x".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2026-86060".to_string(),
            ]
        );
    }

    #[test]
    fn fixed_version_is_not_affected() {
        let a = assess("dev1", "7.24.2", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert!(a.affected.is_empty());
        assert!(a.not_affected.contains("dev1:ver:CVE-2026-86060"));
    }

    #[test]
    fn unparseable_version_is_neither_affected_nor_cleared() {
        let a = assess("dev1", "garbage", &[input("CVE-2026-86060", Some(9.2), true)], 1);
        assert!(a.affected.is_empty());
        assert!(a.not_affected.is_empty());
        assert_eq!(a.cannot_evaluate, vec!["CVE-2026-86060".to_string()]);
    }

    async fn vuln_rows(store: &FindingsStore) -> Vec<ion_drift_storage::Finding> {
        store
            .list_findings(&FindingsQuery { category: Some(VULN_CATEGORY.into()), ..Default::default() })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reconcile_opens_resolves_and_reopens() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];

        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);

        // Upgraded past the fix point.
        reconcile(&store, &assess("dev1", "7.24.2", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Resolved);
        assert!(rows[0].resolution_note.as_deref().unwrap().contains("7.24.2"));

        // Downgraded back into the range.
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 3)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);
    }

    #[tokio::test]
    async fn operator_resolution_survives_a_still_affected_pass() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        let row_id = vuln_rows(&store).await[0].id;
        store
            .resolve(row_id, "operator", Some("Accepted risk: SSH is LAN-only.".into()))
            .await
            .unwrap();

        // Same affected version: Drift must not undo the operator's decision.
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Resolved);
        assert_eq!(rows[0].resolved_by.as_deref(), Some("operator"));
        assert_eq!(rows[0].resolution_note.as_deref(), Some("Accepted risk: SSH is LAN-only."));
    }

    #[tokio::test]
    async fn acknowledged_finding_reopens_when_it_becomes_actively_exploited() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, &assess("dev1", "7.24.1", &[input("CVE-2026-86060", Some(8.8), false)], 1)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].severity, FindingSeverity::High);
        store.acknowledge(vuln_rows(&store).await[0].id, "scott").await.unwrap();

        // Same version, but CISA has since added the CVE to KEV.
        let kev = [input("CVE-2026-86060", Some(8.8), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &kev, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Open);
        assert_eq!(rows[0].severity, FindingSeverity::Critical);
        assert!(rows[0].narrative.contains("Escalated from high to critical"));

        // The note survives the next rebuild of the narrative, exactly once.
        reconcile(&store, &assess("dev1", "7.24.1", &kev, 3)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Open);
        assert_eq!(rows[0].severity, FindingSeverity::Critical);
        assert_eq!(rows[0].narrative.matches("Escalated from high to critical").count(), 1);
    }

    #[tokio::test]
    async fn acknowledged_finding_stays_acknowledged_while_nothing_changes() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(8.8), false)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        store.acknowledge(vuln_rows(&store).await[0].id, "scott").await.unwrap();
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Acknowledged);
        assert!(!rows[0].narrative.contains("Escalated from"));
    }

    #[tokio::test]
    async fn operator_resolution_survives_an_escalation() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, &assess("dev1", "7.24.1", &[input("CVE-2026-86060", Some(8.8), false)], 1)).await.unwrap();
        let row_id = vuln_rows(&store).await[0].id;
        store.resolve(row_id, "operator", Some("Accepted risk.".into())).await.unwrap();
        reconcile(&store, &assess("dev1", "7.24.1", &[input("CVE-2026-86060", Some(8.8), true)], 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows[0].status, FindingStatus::Resolved);
        assert_eq!(rows[0].resolved_by.as_deref(), Some("operator"));
    }

    #[tokio::test]
    async fn cannot_evaluate_leaves_an_open_finding_alone() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        reconcile(&store, &assess("dev1", "garbage", &inputs, 2)).await.unwrap();
        assert_eq!(vuln_rows(&store).await[0].status, FindingStatus::Open);
    }

    #[tokio::test]
    async fn other_devices_are_not_touched() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let inputs = [input("CVE-2026-86060", Some(9.2), true)];
        reconcile(&store, &assess("dev1", "7.24.1", &inputs, 1)).await.unwrap();
        reconcile(&store, &assess("dev2", "7.24.2", &inputs, 2)).await.unwrap();
        let rows = vuln_rows(&store).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, FindingStatus::Open);
    }
}
