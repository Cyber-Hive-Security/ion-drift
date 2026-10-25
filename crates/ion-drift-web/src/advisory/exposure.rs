//! Service exposure findings.
//!
//! "Your configuration makes this advisory reachable." For every bundled
//! advisory scoped to named services, an enabled service is an exposure.
//! Severity follows the service's own `address` restriction: reachable from
//! anywhere is High, restricted to listed sources is Low. Exposure is reported
//! alongside exploitation and vulnerability findings, never instead of them.

use std::collections::{BTreeMap, BTreeSet};

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingSubject, FindingV1};
use ion_drift_storage::{AdvisoryRecord, FindingStatus, FindingsQuery, FindingsStore};
use mikrotik_core::resources::ip::IpService;
use tracing::warn;

use crate::advisory::exploitation::{surface_key, ADVISORY_MODULE};
use crate::staging::{scrub, stage_addresses, stage_service};

pub(crate) const EXPOSURE_CATEGORY: &str = "advisory_exposure";
const CEASED_NOTE: &str =
    "Exposure ceased: the service is disabled or no longer present on this device.";
/// Start of the escalation note appended to a narrative. Always the last
/// paragraph, so everything from this marker on is the note. Shared with
/// vulnerability findings, which follow the same escalation rule.
pub(crate) const ESCALATION_MARKER: &str = "\n\nEscalated from ";

pub(crate) fn exposure_finding_id(device_id: &str, service: &str, advisory_id: &str) -> String {
    format!("{}:{advisory_id}:exposure", surface_key(device_id, service))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Unrestricted,
    Restricted(Vec<String>),
}

/// Any open entry (`0.0.0.0/0`, `::/0`) or an empty list means unrestricted.
/// Open entries are detected on the full raw list, before staging caps it at
/// `MAX_LIST_ITEMS`: truncation must never hide an open entry and turn an
/// unrestricted service into a restricted one.
pub(crate) fn scope_of(address: Option<&str>) -> Scope {
    let raw: Vec<String> = address.unwrap_or("").split(',').map(str::to_owned).collect();
    let open = raw.iter().any(|a| matches!(scrub(a).trim(), "0.0.0.0/0" | "::/0"));
    let list = stage_addresses(&raw);
    if open || list.is_empty() {
        Scope::Unrestricted
    } else {
        Scope::Restricted(list)
    }
}

#[derive(Debug, Default)]
pub(crate) struct ExposureAssessment {
    pub exposed: Vec<FindingV1>,
    /// Finding ids for advisory surfaces present in the catalog but not enabled.
    pub not_exposed: BTreeSet<String>,
}

pub(crate) fn assess(
    device_id: &str,
    services: &[IpService],
    catalog: &[AdvisoryRecord],
    now: i64,
) -> ExposureAssessment {
    let enabled: BTreeMap<String, &IpService> = services
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| (stage_service(&s.name), s))
        .collect();
    let mut out = ExposureAssessment::default();
    for adv in catalog.iter().filter(|a| a.requires_surface_class == "service") {
        for raw_name in &adv.requires_surface_names {
            // Catalog names are stored raw; stage them exactly as router names are.
            let name = stage_service(raw_name);
            let id = exposure_finding_id(device_id, &name, &adv.advisory_id);
            match enabled.get(name.as_str()) {
                Some(svc) => out.exposed.push(build_finding(&id, device_id, svc, adv, now)),
                None => {
                    out.not_exposed.insert(id);
                }
            }
        }
    }
    out
}

fn build_finding(finding_id: &str, device_id: &str, svc: &IpService, adv: &AdvisoryRecord, now: i64) -> FindingV1 {
    let service = stage_service(&svc.name);
    let scope = scope_of(svc.address.as_deref());
    let (severity, reach, scope_json) = match &scope {
        Scope::Unrestricted => (
            FindingSeverity::High,
            "from any address that can reach the router".to_string(),
            serde_json::json!("unrestricted"),
        ),
        Scope::Restricted(list) => (
            FindingSeverity::Low,
            format!("only from {}", list.join(", ")),
            serde_json::json!(list),
        ),
    };
    let port = svc.port.map(|p| p.to_string()).unwrap_or_else(|| "default".to_string());
    FindingV1 {
        finding_id: finding_id.to_string(),
        title: format!("{} — exposed on {service}", adv.title),
        narrative: format!(
            "{}\n\nThe {service} service is enabled on this router (port {port}) and accepts \
             connections {reach}. This is the configuration the advisory applies to; no attack has \
             been observed. Exploitation, if it occurs, is reported as a separate finding.",
            adv.narrative
        ),
        severity,
        category: EXPOSURE_CATEGORY.to_string(),
        recommended_actions: adv.mitigations.clone(),
        evidence: vec![FindingEvidence::Custom {
            label: "service exposure".to_string(),
            payload: serde_json::json!({
                "advisory_id": adv.advisory_id,
                "device_id": device_id,
                "service": service,
                "port": svc.port,
                "scope": scope_json,
                "observed_at_unix": now,
            }),
        }],
        references: vec![],
        subjects: vec![FindingSubject::device(device_id)],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "advisory_id": adv.advisory_id,
            "references": adv.references,
            "no_fixed_release": adv.no_fixed_release,
            "fixed_versions": adv.fixed_versions,
            "catalog_version": adv.catalog_version,
            "source": adv.source,
        })),
    }
}

pub(crate) fn rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 4,
        FindingSeverity::High => 3,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 1,
        FindingSeverity::Info => 0,
    }
}

pub(crate) fn label(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
        FindingSeverity::Info => "info",
    }
}

/// Apply one device's exposure assessment. Called only after a successful
/// `/ip/service` read.
///
/// Lifecycle rules for an exposed surface:
/// - acknowledged, and the severity escalated (e.g. Low → High): reopened;
///   unchanged or improved config keeps the acknowledgment.
/// - resolved by Drift itself (`resolved_by == "system"`, i.e. exposure
///   ceased earlier): reopened, since the exposure is back.
/// - resolved by an operator: stays resolved. An operator's manual resolution
///   sticks; only the finding body is refreshed.
///
/// The escalation note ("Escalated from X to Y ...") is carried forward on
/// later cycles while the finding stays at the severity it escalated to, so
/// the rebuilt narrative does not drop it. If the escalation reopen fails, the
/// finding is not written that cycle: the row stays acknowledged at its old
/// severity and the escalation is re-detected next cycle.
pub(crate) async fn reconcile(store: &FindingsStore, assessment: ExposureAssessment) -> Result<(), String> {
    // Value: (status, severity, resolved by Drift itself, stored narrative).
    let held: BTreeMap<String, (FindingStatus, FindingSeverity, bool, String)> = store
        .list_findings(&FindingsQuery {
            module_name: Some(ADVISORY_MODULE.to_string()),
            category: Some(EXPOSURE_CATEGORY.to_string()),
            ..Default::default()
        })
        .await?
        .into_iter()
        .map(|f| {
            let system_resolved = f.resolved_by.as_deref() == Some("system");
            (f.finding_id, (f.status, f.severity, system_resolved, f.narrative))
        })
        .collect();

    for mut finding in assessment.exposed {
        match held.get(&finding.finding_id) {
            Some((FindingStatus::Acknowledged, prior, _, _)) if rank(finding.severity) > rank(*prior) => {
                if let Err(e) = store.reopen_acknowledged_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure escalation reopen failed; finding left unchanged this cycle");
                    continue;
                }
                finding.narrative.push_str(&format!(
                    "{ESCALATION_MARKER}{} to {}: the service's address restriction was removed or \
                     widened after this finding was acknowledged, so it has been reopened for review.",
                    label(*prior),
                    label(finding.severity)
                ));
            }
            Some((FindingStatus::Resolved, _, true, _)) => {
                if let Err(e) = store.reopen_by_key(ADVISORY_MODULE, &finding.finding_id).await {
                    warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure reopen failed");
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
            warn!(finding_id = %finding.finding_id, error = %e, "advisory: exposure upsert failed");
        }
    }

    for id in &assessment.not_exposed {
        if matches!(held.get(id), Some((FindingStatus::Open | FindingStatus::Acknowledged, _, _, _)))
            && let Err(e) = store.resolve_by_key(ADVISORY_MODULE, id, CEASED_NOTE).await {
                warn!(finding_id = %id, error = %e, "advisory: exposure resolve failed");
            }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{FindingStatus, FindingsQuery, FindingsStore};
    use tempfile::NamedTempFile;

    fn svc(name: &str, disabled: bool, address: Option<&str>) -> IpService {
        serde_json::from_value(serde_json::json!({
            ".id": "*1", "name": name, "port": "8729",
            "disabled": if disabled { "true" } else { "false" },
            "address": address,
        }))
        .unwrap()
    }

    fn advisory() -> AdvisoryRecord {
        AdvisoryRecord {
            advisory_id: "CVE-2026-16347".into(), title: "RouterOS API accepts unlimited login attempts".into(),
            narrative: "catalog narrative".into(), severity: "high".into(),
            requires_surface_class: "service".into(),
            requires_surface_names: vec!["api".into(), "api-ssl".into()],
            requires_state: vec![], version_constraint: None, no_fixed_release: true,
            fixed_versions: vec![], mitigations: vec!["/ip/service set api-ssl address=<mgmt-cidr>".into()],
            references: vec![], attack_techniques: vec![], source: "bundled".into(),
            catalog_version: 2, generated_at: "2026-07-28".into(),
        }
    }

    const ID: &str = "dev1:svc:api-ssl:CVE-2026-16347:exposure";

    #[test]
    fn scope_classification() {
        assert_eq!(scope_of(None), Scope::Unrestricted);
        assert_eq!(scope_of(Some("")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("0.0.0.0/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("192.168.1.17/32,0.0.0.0/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("::/0")), Scope::Unrestricted);
        assert_eq!(scope_of(Some("192.168.1.17/32")), Scope::Restricted(vec!["192.168.1.17/32".into()]));
    }

    #[test]
    fn open_entry_is_found_even_past_the_staging_list_cap() {
        // `::/0` sorts after IPv4 prefixes, so list truncation would drop it.
        let mut entries: Vec<String> = (1..=17).map(|i| format!("10.0.0.{i}/32")).collect();
        entries.push("::/0".into());
        assert_eq!(scope_of(Some(&entries.join(","))), Scope::Unrestricted);
        // Scrubbed and padded open entries count too.
        entries.pop();
        entries.push(" 0.0.0.0/0\u{200B} ".into());
        assert_eq!(scope_of(Some(&entries.join(","))), Scope::Unrestricted);
    }

    #[test]
    fn unrestricted_enabled_service_is_high() {
        let a = assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1);
        assert_eq!(a.exposed.len(), 1);
        let f = &a.exposed[0];
        assert_eq!(f.subjects, vec![FindingSubject::device("dev1")]);
        assert_eq!(f.finding_id, ID);
        assert_eq!(f.category, EXPOSURE_CATEGORY);
        assert_eq!(f.severity, FindingSeverity::High);
        assert!(f.narrative.contains("no attack has been observed"));
        // api is absent, so its surface counts as not exposed.
        assert!(a.not_exposed.contains("dev1:svc:api:CVE-2026-16347:exposure"));
    }

    #[test]
    fn restricted_enabled_service_is_low_with_scope_in_evidence() {
        let a = assess("dev1", &[svc("api-ssl", false, Some("192.168.1.17/32"))], &[advisory()], 1);
        let f = &a.exposed[0];
        assert_eq!(f.severity, FindingSeverity::Low);
        let ion_drift_module_api::FindingEvidence::Custom { payload, .. } = &f.evidence[0] else {
            panic!("expected custom evidence")
        };
        assert_eq!(payload["scope"], serde_json::json!(["192.168.1.17/32"]));
    }

    #[test]
    fn disabled_service_is_not_exposed() {
        let a = assess("dev1", &[svc("api-ssl", true, Some(""))], &[advisory()], 1);
        assert!(a.exposed.is_empty());
        assert!(a.not_exposed.contains(ID));
    }

    #[test]
    fn unrelated_service_raises_nothing() {
        let a = assess("dev1", &[svc("ssh", false, Some(""))], &[advisory()], 1);
        assert!(a.exposed.is_empty());
    }

    async fn rows(store: &FindingsStore) -> Vec<ion_drift_storage::Finding> {
        store.list_findings(&FindingsQuery { category: Some(EXPOSURE_CATEGORY.into()), ..Default::default() }).await.unwrap()
    }

    #[tokio::test]
    async fn exposure_ceases_when_service_is_disabled() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1)).await.unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", true, Some(""))], &[advisory()], 2)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Resolved);
        assert!(r[0].resolution_note.as_deref().unwrap().contains("Exposure ceased"));
    }

    #[tokio::test]
    async fn acknowledged_low_reopens_when_widened_to_unrestricted() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some("192.168.1.17/32"))], &[advisory()], 1)).await.unwrap();
        store.acknowledge(rows(&store).await[0].id, "scott").await.unwrap();

        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 2)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Open);
        assert_eq!(r[0].severity, FindingSeverity::High);
        assert!(r[0].narrative.contains("Escalated from low to high"));
    }

    #[tokio::test]
    async fn acknowledged_finding_stays_acknowledged_while_config_is_unchanged() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let reads = [svc("api-ssl", false, Some("192.168.1.17/32"))];
        reconcile(&store, assess("dev1", &reads, &[advisory()], 1)).await.unwrap();
        store.acknowledge(rows(&store).await[0].id, "scott").await.unwrap();
        reconcile(&store, assess("dev1", &reads, &[advisory()], 2)).await.unwrap();
        assert_eq!(rows(&store).await[0].status, FindingStatus::Acknowledged);
    }

    #[tokio::test]
    async fn exposure_vulnerability_and_exploitation_coexist() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let mut other = assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1).exposed.remove(0);
        for (id, cat) in [
            ("dev1:svc:api-ssl:CVE-2026-16347:exploit", "advisory_exploitation"),
            ("dev1:ver:CVE-2026-86060", "advisory_vulnerable"),
        ] {
            other.finding_id = id.into();
            other.category = cat.into();
            store.upsert_finding(ADVISORY_MODULE, &other, None, None).await.unwrap();
        }
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 2)).await.unwrap();
        let all = store
            .list_findings(&FindingsQuery { module_name: Some(ADVISORY_MODULE.into()), ..Default::default() })
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|f| f.status == FindingStatus::Open));
    }

    #[tokio::test]
    async fn operator_resolved_exposure_stays_resolved_while_service_is_enabled() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        let reads = [svc("api-ssl", false, Some(""))];
        reconcile(&store, assess("dev1", &reads, &[advisory()], 1)).await.unwrap();
        let id = rows(&store).await[0].id;
        store.resolve(id, "scott", Some("accepted risk: mgmt VLAN only".into())).await.unwrap();

        reconcile(&store, assess("dev1", &reads, &[advisory()], 2)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Resolved);
        assert_eq!(r[0].resolved_by.as_deref(), Some("scott"));
        assert_eq!(r[0].resolution_note.as_deref(), Some("accepted risk: mgmt VLAN only"));
    }

    #[tokio::test]
    async fn system_resolved_exposure_reopens_when_service_is_re_enabled() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 1)).await.unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", true, Some(""))], &[advisory()], 2)).await.unwrap();
        assert_eq!(rows(&store).await[0].status, FindingStatus::Resolved);

        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some(""))], &[advisory()], 3)).await.unwrap();
        assert_eq!(rows(&store).await[0].status, FindingStatus::Open);
    }

    #[tokio::test]
    async fn escalation_note_persists_on_later_cycles() {
        let f = NamedTempFile::new().unwrap();
        let store = FindingsStore::new(f.path()).unwrap();
        reconcile(&store, assess("dev1", &[svc("api-ssl", false, Some("192.168.1.17/32"))], &[advisory()], 1)).await.unwrap();
        store.acknowledge(rows(&store).await[0].id, "scott").await.unwrap();
        let widened = [svc("api-ssl", false, Some(""))];
        reconcile(&store, assess("dev1", &widened, &[advisory()], 2)).await.unwrap();
        assert!(rows(&store).await[0].narrative.contains("Escalated from low to high"));

        reconcile(&store, assess("dev1", &widened, &[advisory()], 3)).await.unwrap();
        let r = rows(&store).await;
        assert_eq!(r[0].status, FindingStatus::Open);
        assert_eq!(r[0].severity, FindingSeverity::High);
        assert!(r[0].narrative.contains("Escalated from low to high"));
        assert_eq!(r[0].narrative.matches("Escalated from").count(), 1);
    }

    #[test]
    fn catalog_surface_names_are_staged_before_matching() {
        let mut adv = advisory();
        adv.requires_surface_names = vec![" api-ssl ".into()];
        let a = assess("dev1", &[svc("api-ssl", false, Some(""))], &[adv], 1);
        assert_eq!(a.exposed.len(), 1);
        assert_eq!(a.exposed[0].finding_id, ID);
        assert!(a.not_exposed.is_empty());
    }
}
