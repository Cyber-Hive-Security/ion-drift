//! NVD and CISA KEV feed parsing.
//!
//! Everything here is untrusted third-party input. Parsing is lenient about
//! shape (unknown fields ignored, missing optionals tolerated, one bad record
//! never sinks the page) and strict about content: every string is staged and
//! bounded, CVE ids are validated, and a record that fails any of that is
//! skipped and counted rather than stored. Nothing in this module does I/O.

use std::collections::BTreeSet;

use ion_drift_storage::{FeedCve, FeedKev};
use serde::Deserialize;

use crate::advisory::version::VersionRange;
use crate::staging::stage_text;

/// Hard ceiling on a feed response. The RouterOS NVD set is ~0.5 MB and the
/// full KEV catalog ~1.5 MB (2026-09); 16 MB is headroom, not a target.
pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_DESCRIPTION: usize = 4000;
const MAX_VERSION: usize = 32;
const MAX_RANGES: usize = 64;
const ROUTEROS_CPE_PREFIX: &str = "cpe:2.3:o:mikrotik:routeros:";

#[derive(Debug)]
pub(crate) struct NvdPage {
    pub total_results: u64,
    pub start_index: u64,
    pub results_per_page: u64,
    pub cves: Vec<FeedCve>,
    /// Records dropped: malformed, invalid id, duplicate, or no RouterOS range.
    pub skipped: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    #[serde(default)]
    results_per_page: u64,
    #[serde(default)]
    start_index: u64,
    #[serde(default)]
    total_results: u64,
    /// Kept as raw values so one malformed record is skipped, not fatal.
    #[serde(default)]
    vulnerabilities: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    descriptions: Vec<LangValue>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    weaknesses: Vec<NvdWeakness>,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
}

#[derive(Deserialize)]
struct LangValue {
    lang: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct NvdMetrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<NvdMetric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<NvdMetric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetric {
    cvss_data: CvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    #[serde(default)]
    version: String,
    base_score: f64,
    #[serde(default)]
    vector_string: String,
}

#[derive(Deserialize)]
struct NvdWeakness {
    #[serde(default)]
    description: Vec<LangValue>,
}

#[derive(Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdNode {
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    #[serde(default)]
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

pub(crate) fn parse_nvd(body: &[u8]) -> Result<NvdPage, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err(format!("NVD response too large: {} bytes", body.len()));
    }
    let resp: NvdResponse = serde_json::from_slice(body)
        .map_err(|e| format!("NVD response is not valid JSON: {e}"))?;
    let mut cves = Vec::new();
    let mut seen = BTreeSet::new();
    let mut skipped = 0;
    for item in resp.vulnerabilities {
        match stage_nvd_item(item) {
            Some(c) if seen.insert(c.cve_id.clone()) => cves.push(c),
            _ => skipped += 1,
        }
    }
    Ok(NvdPage {
        total_results: resp.total_results,
        start_index: resp.start_index,
        results_per_page: resp.results_per_page,
        cves,
        skipped,
    })
}

fn stage_nvd_item(item: serde_json::Value) -> Option<FeedCve> {
    let cve: NvdCve = serde_json::from_value(item.get("cve")?.clone()).ok()?;
    let cve_id = stage_text(&cve.id, 32);
    if !is_cve_id(&cve_id) {
        return None;
    }
    let ranges = routeros_ranges(&cve.configurations);
    if ranges.is_empty() {
        return None;
    }
    let description = cve
        .descriptions
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| stage_text(&d.value, MAX_DESCRIPTION))
        .unwrap_or_default();
    let metric = cve.metrics.v40.first().or(cve.metrics.v31.first());
    let (cvss_version, cvss_score, cvss_vector) = match metric {
        Some(m) if (0.0..=10.0).contains(&m.cvss_data.base_score) => (
            Some(stage_text(&m.cvss_data.version, 8)),
            Some(m.cvss_data.base_score),
            Some(stage_text(&m.cvss_data.vector_string, 256)),
        ),
        _ => (None, None, None),
    };
    let cwe = cve
        .weaknesses
        .iter()
        .flat_map(|w| &w.description)
        .find(|d| d.lang == "en")
        .map(|d| stage_text(&d.value, 64));
    Some(FeedCve {
        cve_id,
        published: stage_text(&cve.published, 40),
        last_modified: stage_text(&cve.last_modified, 40),
        description,
        cvss_version,
        cvss_score,
        cvss_vector,
        cwe,
        nvd_status: stage_text(&cve.vuln_status, 40),
        ranges_json: serde_json::to_string(&ranges).ok()?,
    })
}

/// Vulnerable RouterOS matches only, deduplicated, capped at [`MAX_RANGES`].
/// A CPE version of `-` ("not applicable") with no bounds is skipped: turning
/// it into a boundless range would claim every version is affected.
fn routeros_ranges(configs: &[NvdConfiguration]) -> Vec<VersionRange> {
    let mut out: Vec<VersionRange> = Vec::new();
    for m in configs.iter().flat_map(|c| &c.nodes).flat_map(|n| &n.cpe_match) {
        if !m.vulnerable || !m.criteria.starts_with(ROUTEROS_CPE_PREFIX) {
            continue;
        }
        let has_bounds = m.version_start_including.is_some()
            || m.version_start_excluding.is_some()
            || m.version_end_including.is_some()
            || m.version_end_excluding.is_some();
        let version_field = m.criteria.split(':').nth(5).unwrap_or("*");
        if version_field == "-" && !has_bounds {
            continue;
        }
        let bound = |b: &Option<String>| {
            b.as_deref()
                .map(|s| stage_text(s, MAX_VERSION))
                .filter(|s| !s.is_empty())
        };
        let exact = match version_field {
            "*" | "" => None,
            v if !has_bounds => Some(stage_text(v, MAX_VERSION)),
            _ => None,
        };
        let range = VersionRange {
            start_including: bound(&m.version_start_including),
            start_excluding: bound(&m.version_start_excluding),
            end_including: bound(&m.version_end_including),
            end_excluding: bound(&m.version_end_excluding),
            exact,
        };
        if !out.contains(&range) {
            out.push(range);
        }
        if out.len() >= MAX_RANGES {
            break;
        }
    }
    out
}

#[derive(Deserialize)]
struct KevResponse {
    #[serde(default)]
    vulnerabilities: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KevItem {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    due_date: Option<String>,
}

/// MikroTik entries from the full KEV catalog.
pub(crate) fn parse_kev(body: &[u8]) -> Result<Vec<FeedKev>, String> {
    if body.len() > MAX_BODY_BYTES {
        return Err(format!("KEV response too large: {} bytes", body.len()));
    }
    let resp: KevResponse = serde_json::from_slice(body)
        .map_err(|e| format!("KEV response is not valid JSON: {e}"))?;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for v in resp.vulnerabilities {
        let Ok(item) = serde_json::from_value::<KevItem>(v) else {
            continue;
        };
        if !item.vendor_project.to_ascii_lowercase().contains("mikrotik") {
            continue;
        }
        let cve_id = stage_text(&item.cve_id, 32);
        if !is_cve_id(&cve_id) || !seen.insert(cve_id.clone()) {
            continue;
        }
        out.push(FeedKev {
            cve_id,
            date_added: stage_text(&item.date_added, 40),
            due_date: item
                .due_date
                .map(|d| stage_text(&d, 40))
                .filter(|d| !d.is_empty()),
        });
    }
    Ok(out)
}

/// `CVE-YYYY-NNNN…` — four-digit year, four or more digit sequence.
pub(crate) fn is_cve_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=19).contains(&seq.len())
        && seq.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// One page shaped like NVD API 2.0: CVE-2026-86060 as published
    /// 2026-09-05, a CVE for another product, a malformed id, and an item
    /// with no `cve` object.
    pub(crate) fn nvd_body() -> Vec<u8> {
        serde_json::json!({
            "resultsPerPage": 4, "startIndex": 0, "totalResults": 4,
            "vulnerabilities": [
                { "cve": {
                    "id": "CVE-2026-86060",
                    "published": "2026-09-05T15:15:00.000",
                    "lastModified": "2026-09-10T20:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        { "lang": "es", "value": "no" },
                        { "lang": "en", "value": "RouterOS contains an argument-handling flaw in the SSH login path." }
                    ],
                    "metrics": { "cvssMetricV40": [ { "cvssData": {
                        "version": "4.0", "baseScore": 9.2,
                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    } } ] },
                    "weaknesses": [ { "description": [ { "lang": "en", "value": "CWE-88" } ] } ],
                    "configurations": [ { "nodes": [ { "cpeMatch": [
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "6.0", "versionEndExcluding": "6.49.21" },
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "7.0", "versionEndExcluding": "7.23.4" },
                        { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                          "versionStartIncluding": "7.24", "versionEndExcluding": "7.24.2" },
                        { "vulnerable": false, "criteria": "cpe:2.3:h:mikrotik:rb4011:-:*:*:*:*:*:*:*" }
                    ] } ] } ]
                } },
                { "cve": {
                    "id": "CVE-2026-11111",
                    "configurations": [ { "nodes": [ { "cpeMatch": [
                        { "vulnerable": true, "criteria": "cpe:2.3:o:other:thing:*:*:*:*:*:*:*:*",
                          "versionEndExcluding": "1.0" }
                    ] } ] } ]
                } },
                { "cve": { "id": "not-a-cve" } },
                { "unexpected": true }
            ]
        })
        .to_string()
        .into_bytes()
    }

    pub(crate) fn kev_body() -> Vec<u8> {
        serde_json::json!({
            "catalogVersion": "2026.09.23", "count": 3,
            "vulnerabilities": [
                { "cveID": "CVE-2026-86060", "vendorProject": "MikroTik", "product": "RouterOS",
                  "dateAdded": "2026-09-10", "dueDate": "2026-10-01" },
                { "cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
                  "dateAdded": "2021-12-10" },
                { "cveID": "bogus", "vendorProject": "MikroTik", "dateAdded": "2026-01-01" }
            ]
        })
        .to_string()
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::version::VersionRange;

    fn ranges_of(c: &ion_drift_storage::FeedCve) -> Vec<VersionRange> {
        serde_json::from_str(&c.ranges_json).unwrap()
    }

    #[test]
    fn parses_published_ranges_for_cve_2026_86060() {
        let page = parse_nvd(&fixtures::nvd_body()).unwrap();
        assert_eq!(page.cves.len(), 1);
        let c = &page.cves[0];
        assert_eq!(c.cve_id, "CVE-2026-86060");
        assert_eq!(c.cvss_score, Some(9.2));
        assert_eq!(c.cwe.as_deref(), Some("CWE-88"));
        assert!(c.description.starts_with("RouterOS contains"));
        let r = ranges_of(c);
        assert_eq!(r.len(), 3);
        assert_eq!(r[2].start_including.as_deref(), Some("7.24"));
        assert_eq!(r[2].end_excluding.as_deref(), Some("7.24.2"));
    }

    #[test]
    fn counts_skipped_records_and_keeps_the_rest() {
        let page = parse_nvd(&fixtures::nvd_body()).unwrap();
        assert_eq!(page.skipped, 3);
        assert_eq!(page.total_results, 4);
    }

    #[test]
    fn rejects_oversized_body() {
        let body = vec![b' '; MAX_BODY_BYTES + 1];
        assert!(parse_nvd(&body).unwrap_err().contains("too large"));
        assert!(parse_kev(&body).unwrap_err().contains("too large"));
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_nvd(b"<html>rate limited</html>").is_err());
    }

    #[test]
    fn stages_hostile_description() {
        let hostile = format!("\u{202E}evil{}", "A".repeat(10_000));
        let body = serde_json::json!({
            "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "vulnerabilities": [ { "cve": {
                "id": "CVE-2026-86060",
                "descriptions": [ { "lang": "en", "value": hostile } ],
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
                      "versionEndExcluding": "7.24.2" } ] } ] } ]
            } } ]
        })
        .to_string();
        let page = parse_nvd(body.as_bytes()).unwrap();
        let d = &page.cves[0].description;
        assert!(!d.contains('\u{202E}'));
        assert!(d.chars().count() <= 4000);
    }

    #[test]
    fn dash_version_without_bounds_is_not_a_wildcard() {
        let body = serde_json::json!({
            "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "vulnerabilities": [ { "cve": {
                "id": "CVE-2026-22222",
                "configurations": [ { "nodes": [ { "cpeMatch": [
                    { "vulnerable": true, "criteria": "cpe:2.3:o:mikrotik:routeros:-:*:*:*:*:*:*:*" }
                ] } ] } ]
            } } ]
        })
        .to_string();
        let page = parse_nvd(body.as_bytes()).unwrap();
        assert!(page.cves.is_empty(), "N/A version must not become 'every version affected'");
    }

    #[test]
    fn kev_keeps_only_mikrotik_entries_with_valid_ids() {
        let kev = parse_kev(&fixtures::kev_body()).unwrap();
        assert_eq!(kev.len(), 1);
        assert_eq!(kev[0].cve_id, "CVE-2026-86060");
        assert_eq!(kev[0].date_added, "2026-09-10");
        assert_eq!(kev[0].due_date.as_deref(), Some("2026-10-01"));
    }

    #[test]
    fn cve_id_validation() {
        for ok in ["CVE-2018-14847", "CVE-2026-86060", "CVE-2026-1234567"] {
            assert!(is_cve_id(ok), "{ok}");
        }
        for bad in ["CVE-18-14847", "cve-2018-14847", "CVE-2018-123", "CVE-2018-14847x", "not-a-cve", ""] {
            assert!(!is_cve_id(bad), "{bad}");
        }
    }
}
