//! Per-device advisory pass.
//!
//! Each evaluator cycle reads every enabled RouterOS device once — through its
//! router queue, never directly — and reconciles its version (vulnerability)
//! findings and its service exposure findings. A device whose read fails is
//! skipped for the cycle: a failed read is not evidence of anything, so it can
//! neither raise nor resolve a finding.

use std::collections::BTreeMap;
use std::fmt::Display;

use ion_drift_storage::{AdvisoryRecord, FeedCve, FeedKev};
use mikrotik_core::resources::ip::IpService;
use serde_json::Value;

use crate::advisory::exploitation::now_unix;
use crate::advisory::exposure;
use crate::advisory::version::{RouterOsVersion, VersionRange};
use crate::advisory::vulnerable::{self, VulnInput, VulnSource};
use crate::router_queue::{Priority, QueuedRequest, RouterQueue};
use crate::staging::stage_text;
use crate::state::AppState;

/// `router_queue` poller id. Must not collide with another submitter's.
const POLLER_ID: &str = "advisory-device-pass";

/// Fetched CVEs joined with KEV; a bundled advisory that carries a version
/// constraint replaces the feed entry for the same id (curated beats fetched)
/// while keeping the feed's CVSS data. Bundled advisories without a constraint
/// are service-scoped and handled by exposure findings, not here.
pub(crate) fn merge_inputs(feed: Vec<FeedCve>, kev: Vec<FeedKev>, catalog: &[AdvisoryRecord]) -> Vec<VulnInput> {
    let kev: BTreeMap<String, String> = kev.into_iter().map(|k| (k.cve_id, k.date_added)).collect();
    let mut by_id: BTreeMap<String, VulnInput> = BTreeMap::new();
    for c in feed {
        let ranges: Vec<VersionRange> = serde_json::from_str(&c.ranges_json).unwrap_or_default();
        by_id.insert(
            c.cve_id.clone(),
            VulnInput {
                kev_date_added: kev.get(&c.cve_id).cloned(),
                cve_id: c.cve_id,
                title: None,
                description: c.description,
                cvss_score: c.cvss_score,
                cvss_vector: c.cvss_vector,
                ranges,
                mitigations: Vec::new(),
                source: VulnSource::Nvd,
            },
        );
    }
    for a in catalog {
        let Some(vc) = a.version_constraint.as_deref() else {
            continue;
        };
        let ranges = match serde_json::from_str::<Vec<VersionRange>>(vc) {
            Ok(ranges) => ranges,
            Err(e) => {
                tracing::warn!(advisory = %a.advisory_id, error = %e, "advisory: stored version_constraint does not parse; advisory skipped");
                continue;
            }
        };
        let prior = by_id.remove(&a.advisory_id);
        by_id.insert(
            a.advisory_id.clone(),
            VulnInput {
                cve_id: a.advisory_id.clone(),
                title: Some(a.title.clone()),
                description: a.narrative.clone(),
                cvss_score: prior.as_ref().and_then(|p| p.cvss_score),
                cvss_vector: prior.as_ref().and_then(|p| p.cvss_vector.clone()),
                ranges,
                kev_date_added: kev.get(&a.advisory_id).cloned(),
                mitigations: a.mitigations.clone(),
                source: VulnSource::Catalog,
            },
        );
    }
    by_id.into_values().collect()
}

#[derive(Debug, Default)]
pub(crate) struct DeviceReads {
    pub version: Option<String>,
    /// `None` when the read failed or was malformed — never an empty list, so
    /// a failed read cannot look like "every service disabled".
    pub services: Option<Vec<IpService>>,
}

/// Results arrive in request order: `[system/resource, ip/service]`.
pub(crate) fn parse_device_reads<E: Display>(results: &[Result<Value, E>]) -> DeviceReads {
    let version = match results.first() {
        Some(Ok(v)) => v
            .get("version")
            .and_then(Value::as_str)
            .map(|s| stage_text(s, 64))
            .filter(|s| !s.is_empty()),
        _ => None,
    };
    let services = match results.get(1) {
        Some(Ok(v)) => serde_json::from_value::<Vec<IpService>>(v.clone()).ok(),
        _ => None,
    };
    DeviceReads { version, services }
}

struct Target {
    device_id: String,
    queue: RouterQueue,
}

async fn routeros_targets(state: &AppState) -> Vec<Target> {
    let entries: Vec<(String, bool, mikrotik_core::MikrotikClient)> = {
        let dm = state.device_manager.read().await;
        dm.all_devices()
            .into_iter()
            .filter(|d| d.record.enabled)
            .filter_map(|d| {
                d.client
                    .as_routeros()
                    .map(|c| (d.record.id.clone(), d.record.is_primary, c.clone()))
            })
            .collect()
    };
    let mut out = Vec::with_capacity(entries.len());
    for (device_id, primary, client) in entries {
        let queue = if primary {
            state.router_queue.clone()
        } else {
            state.device_queues.write().await.get_or_create(&device_id, &client)
        };
        out.push(Target { device_id, queue });
    }
    out
}

pub(crate) async fn evaluate_devices(state: &AppState) -> Result<(), String> {
    let catalog = state.advisory_store.list_advisories().await?;
    let inputs = merge_inputs(
        state.advisory_store.list_feed_cves().await?,
        state.advisory_store.list_feed_kev().await?,
        &catalog,
    );
    let now = now_unix();
    for target in routeros_targets(state).await {
        let results = match target
            .queue
            .submit(
                POLLER_ID,
                Priority::Low,
                vec![QueuedRequest::get("system/resource"), QueuedRequest::get("ip/service")],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(device = %target.device_id, error = %e, "advisory: device read failed; findings unchanged");
                continue;
            }
        };
        let reads = parse_device_reads(&results);

        match reads.version {
            Some(version) => {
                if RouterOsVersion::parse(&version).is_none() {
                    tracing::warn!(device = %target.device_id, version = %version, "advisory: RouterOS version does not parse; no CVE can be evaluated for this device");
                }
                let assessment = vulnerable::assess(&target.device_id, &version, &inputs, now);
                if !assessment.cannot_evaluate.is_empty() {
                    tracing::debug!(device = %target.device_id, count = assessment.cannot_evaluate.len(), "advisory: CVEs not evaluable for this version");
                }
                if let Err(e) = vulnerable::reconcile(&state.findings_store, &assessment).await {
                    tracing::warn!(device = %target.device_id, error = %e, "advisory: vulnerability reconcile failed");
                }
            }
            None => tracing::warn!(device = %target.device_id, "advisory: no RouterOS version read; version findings unchanged"),
        }

        match reads.services {
            Some(services) => {
                let assessment = exposure::assess(&target.device_id, &services, &catalog, now);
                if let Err(e) = exposure::reconcile(&state.findings_store, assessment).await {
                    tracing::warn!(device = %target.device_id, error = %e, "advisory: exposure reconcile failed");
                }
            }
            None => tracing::warn!(device = %target.device_id, "advisory: /ip/service read failed; exposure findings unchanged"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ion_drift_storage::{AdvisoryRecord, FeedCve, FeedKev};

    fn feed(id: &str, ranges_json: &str) -> FeedCve {
        FeedCve {
            cve_id: id.into(), published: "p".into(), last_modified: "m".into(),
            description: "nvd text".into(), cvss_version: Some("4.0".into()), cvss_score: Some(8.8),
            cvss_vector: Some("CVSS:4.0/AV:N".into()), cwe: None, nvd_status: "Analyzed".into(),
            ranges_json: ranges_json.into(),
        }
    }

    fn catalog(id: &str, constraint: Option<&str>) -> AdvisoryRecord {
        AdvisoryRecord {
            advisory_id: id.into(), title: "Curated title".into(), narrative: "curated text".into(),
            severity: "high".into(), requires_surface_class: "service".into(),
            requires_surface_names: vec!["api-ssl".into()], requires_state: vec![],
            version_constraint: constraint.map(Into::into), no_fixed_release: false,
            fixed_versions: vec![], mitigations: vec!["scope the service".into()], references: vec![],
            attack_techniques: vec![], source: "bundled".into(), catalog_version: 1,
            generated_at: "2026-09-24".into(),
        }
    }

    const RANGE: &str = r#"[{"start_including":"7.0","end_excluding":"7.24.2"}]"#;

    #[test]
    fn feed_entries_join_kev() {
        let kev = vec![FeedKev { cve_id: "CVE-2026-86060".into(), date_added: "2026-09-10".into(), due_date: None }];
        let inputs = merge_inputs(vec![feed("CVE-2026-86060", RANGE), feed("CVE-2018-14847", RANGE)], kev, &[]);
        assert_eq!(inputs.len(), 2);
        let k = inputs.iter().find(|i| i.cve_id == "CVE-2026-86060").unwrap();
        assert_eq!(k.kev_date_added.as_deref(), Some("2026-09-10"));
        assert_eq!(k.ranges.len(), 1);
    }

    #[test]
    fn curated_entry_with_constraint_replaces_feed_entry_but_keeps_its_score() {
        let inputs = merge_inputs(
            vec![feed("CVE-2026-86060", RANGE)],
            vec![],
            &[catalog("CVE-2026-86060", Some(RANGE))],
        );
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].source, VulnSource::Catalog);
        assert_eq!(inputs[0].title.as_deref(), Some("Curated title"));
        assert_eq!(inputs[0].cvss_score, Some(8.8));
        assert_eq!(inputs[0].mitigations, vec!["scope the service".to_string()]);
    }

    #[test]
    fn bundled_entry_without_constraint_is_not_a_version_finding() {
        let inputs = merge_inputs(vec![], vec![], &[catalog("CVE-2026-16347", None)]);
        assert!(inputs.is_empty());
    }

    #[test]
    fn corrupt_ranges_become_empty_and_so_cannot_be_evaluated() {
        let inputs = merge_inputs(vec![feed("CVE-2026-86060", "not json")], vec![], &[]);
        assert!(inputs[0].ranges.is_empty());
    }

    #[test]
    fn device_reads_extract_version() {
        let ok: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1 (stable)", "uptime": "1d"}))];
        assert_eq!(parse_device_reads(&ok).version.as_deref(), Some("7.24.1 (stable)"));
    }

    #[test]
    fn failed_or_missing_version_read_yields_none() {
        let failed: Vec<Result<serde_json::Value, String>> = vec![Err("timeout".into())];
        assert!(parse_device_reads(&failed).version.is_none());
        let empty: Vec<Result<serde_json::Value, String>> = vec![Ok(serde_json::json!({}))];
        assert!(parse_device_reads(&empty).version.is_none());
        let none: Vec<Result<serde_json::Value, String>> = vec![];
        assert!(parse_device_reads(&none).version.is_none());
    }

    #[test]
    fn device_reads_extract_services() {
        let ok: Vec<Result<serde_json::Value, String>> = vec![
            Ok(serde_json::json!({"version": "7.24.1"})),
            Ok(serde_json::json!([{ ".id": "*8", "name": "api-ssl", "disabled": "false", "address": "" }])),
        ];
        let reads = parse_device_reads(&ok);
        assert_eq!(reads.services.unwrap()[0].name, "api-ssl");
    }

    #[test]
    fn failed_service_read_yields_none_so_exposure_is_left_alone() {
        let partial: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1"})), Err("timeout".into())];
        let reads = parse_device_reads(&partial);
        assert!(reads.version.is_some());
        assert!(reads.services.is_none());
        let malformed: Vec<Result<serde_json::Value, String>> =
            vec![Ok(serde_json::json!({"version": "7.24.1"})), Ok(serde_json::json!({"not": "a list"}))];
        assert!(parse_device_reads(&malformed).services.is_none());
    }
}
