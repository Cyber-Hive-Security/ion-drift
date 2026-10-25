//! Detector core — pure skeleton matching plus the finding it produces.
//!
//! The matching rule, in order, per candidate suffix (shortest first):
//!
//! 1. A suffix that string-equals a watchlist domain IS the brand (or its
//!    subdomain) — never flagged. Shortest-first ordering makes this check
//!    hit before any longer suffix could.
//! 2. A skeleton collision with an `allow: true` entry is a known-good
//!    lookalike — suppressed.
//! 3. Any other skeleton collision is reported.
//!
//! Known limitation, accepted for v1: suffix matching flags `paypa1.com` and
//! `login.paypa1.com` but not brand-embedding like `paypal.com.evil.com` —
//! the registrable suffix there is `evil.com`, whose skeleton is its own.

use std::collections::{BTreeMap, BTreeSet};

use ion_drift_module_api::{FindingEvidence, FindingSeverity, FindingSubject, FindingV1};
use ion_drift_storage::dns::WatchlistEntry;

use super::skeleton::{candidate_suffixes, skeleton_of};

/// `module_name` every confusable finding is stamped with. The module
/// registry reserves this name so nothing external can collide with it.
pub(crate) const CONFUSABLE_MODULE: &str = "confusable";
/// `category` every finding this module emits carries.
pub(crate) const CONFUSABLE_CATEGORY: &str = "confusable_domain";

/// One skeleton collision: an observed name resembling a watchlist brand.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConfusableHit {
    pub observed: String,
    pub matched_suffix: String,
    pub watchlist_domain: String,
    pub brand: String,
}

/// Watchlist indexed for matching. Rebuilt per poll cycle — the list is
/// small and rebuilding keeps operator overlay edits live without a restart.
pub(crate) struct WatchIndex {
    by_skeleton: BTreeMap<String, Vec<WatchlistEntry>>,
    exact_domains: BTreeSet<String>,
}

impl WatchIndex {
    pub fn build(entries: &[WatchlistEntry]) -> Self {
        let mut by_skeleton: BTreeMap<String, Vec<WatchlistEntry>> = BTreeMap::new();
        let mut exact_domains = BTreeSet::new();
        for e in entries {
            exact_domains.insert(e.domain.clone());
            by_skeleton.entry(e.skeleton.clone()).or_default().push(e.clone());
        }
        Self {
            by_skeleton,
            exact_domains,
        }
    }

    /// Match one normalized name against the watchlist. `None` means either
    /// no collision or a collision the rules above suppress.
    pub fn match_name(&self, normalized_name: &str) -> Option<ConfusableHit> {
        for suffix in candidate_suffixes(normalized_name) {
            // The brand itself (or its subdomain) is the one name that must
            // never be flagged — its skeleton collides with itself by
            // definition.
            if self.exact_domains.contains(&suffix) {
                return None;
            }
            if let Some(entries) = self.by_skeleton.get(&skeleton_of(&suffix)) {
                if entries.iter().any(|e| e.allow) {
                    return None;
                }
                if let Some(e) = entries.first() {
                    return Some(ConfusableHit {
                        observed: normalized_name.to_string(),
                        matched_suffix: suffix,
                        watchlist_domain: e.domain.clone(),
                        brand: e.brand.clone(),
                    });
                }
            }
        }
        None
    }
}

/// Every observation of one confusable *registration*, merged.
///
/// The unit of triage is the registered domain, not the name that happened to
/// resolve: `login.paypa1.com` and `a1.paypa1.com` are one attacker asset and
/// must be one finding. Keying findings on the observed name instead let a
/// single registration mint unlimited findings — one per subdomain — which is
/// both unbounded storage (findings are auto-resolved but never deleted) and
/// the kind of alert fatigue that hides the real one.
#[derive(Debug, PartialEq)]
pub(crate) struct ConfusableGroup {
    pub matched_suffix: String,
    pub watchlist_domain: String,
    pub brand: String,
    /// Distinct names seen resolving under this registration, sorted and
    /// capped — an attacker controls how many there are.
    pub observed_names: Vec<String>,
    /// Union of resolved addresses across those names, sorted and capped.
    pub addresses: Vec<String>,
}

/// Merge per-name hits into one group per (watchlist domain, matched suffix).
pub(crate) fn group_hits(hits: Vec<(ConfusableHit, Vec<String>)>) -> Vec<ConfusableGroup> {
    let mut merged: BTreeMap<(String, String), ConfusableGroup> = BTreeMap::new();
    for (hit, addresses) in hits {
        let key = (hit.watchlist_domain.clone(), hit.matched_suffix.clone());
        let group = merged.entry(key).or_insert_with(|| ConfusableGroup {
            matched_suffix: hit.matched_suffix.clone(),
            watchlist_domain: hit.watchlist_domain.clone(),
            brand: hit.brand.clone(),
            observed_names: Vec::new(),
            addresses: Vec::new(),
        });
        group.observed_names.push(hit.observed);
        group.addresses.extend(addresses);
    }
    merged
        .into_values()
        .map(|mut g| {
            for list in [&mut g.observed_names, &mut g.addresses] {
                list.sort();
                list.dedup();
                list.truncate(crate::staging::MAX_LIST_ITEMS);
            }
            g
        })
        .collect()
}

/// The finding one confusable registration turns into. Rebuilt every cycle
/// from current state; `upsert_finding` overwrites, so re-observation refines
/// in place.
pub(crate) fn build_finding(group: &ConfusableGroup, now: i64) -> FindingV1 {
    let also_seen = match group.observed_names.len() {
        0 | 1 => String::new(),
        n => format!(
            " Seen as {} name{} under that registration, including {}.",
            n,
            if n == 1 { "" } else { "s" },
            group.observed_names.join(", "),
        ),
    };
    FindingV1 {
        // Stable per (brand-domain, matched suffix): every subdomain of one
        // lookalike registration refines this finding rather than minting a
        // new one to triage.
        finding_id: format!(
            "confusable:{}:{}",
            group.watchlist_domain, group.matched_suffix
        ),
        title: format!(
            "Confusable domain — {} resembles {}",
            group.matched_suffix, group.watchlist_domain
        ),
        narrative: format!(
            "A device on the network resolved {suffix}, whose UTS #39 skeleton is \
             identical to {domain} ({brand}). Visually-confusable registrations are the \
             standard delivery mechanism for credential phishing; browsers only police \
             this inside the address bar, not in mail clients, chat, or terminals.{also_seen} \
             Verify which device asked for it and why.",
            suffix = group.matched_suffix,
            domain = group.watchlist_domain,
            brand = group.brand,
        ),
        severity: FindingSeverity::High,
        category: CONFUSABLE_CATEGORY.to_string(),
        recommended_actions: vec![
            format!(
                "Identify the device that resolved {} (DNS cache / connection history)",
                group.matched_suffix
            ),
            "If unexpected, block the domain at the firewall and check the device for \
             phishing exposure"
                .to_string(),
            "If this is a legitimate domain, add it to the operator watchlist overlay \
             with \"allow\": true"
                .to_string(),
        ],
        evidence: vec![FindingEvidence::Custom {
            label: "dns observation".to_string(),
            payload: serde_json::json!({
                "observed_names": group.observed_names,
                "matched_suffix": group.matched_suffix,
                "watchlist_domain": group.watchlist_domain,
                "brand": group.brand,
                "resolved_addresses": group.addresses,
            }),
        }],
        references: vec![],
        subjects: vec![FindingSubject::domain(group.matched_suffix.clone())],
        device_macs: Vec::new(),
        timestamp_unix: now,
        metadata: Some(serde_json::json!({
            "watchlist_domain": group.watchlist_domain,
            "brand": group.brand,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(brand: &str, domain: &str, allow: bool) -> WatchlistEntry {
        WatchlistEntry {
            domain: domain.into(),
            brand: brand.into(),
            skeleton: skeleton_of(domain),
            allow,
            source: "bundled".into(),
            catalog_version: 1,
        }
    }

    #[test]
    fn flags_ascii_lookalike_and_names_the_brand() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        let hit = idx.match_name("paypa1.com").expect("must flag");
        assert_eq!(hit.watchlist_domain, "paypal.com");
        assert_eq!(hit.brand, "PayPal");
        assert_eq!(hit.matched_suffix, "paypa1.com");
    }

    #[test]
    fn flags_lookalike_under_a_subdomain() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        let hit = idx.match_name("login.paypa1.com").expect("must flag the suffix");
        assert_eq!(hit.matched_suffix, "paypa1.com");
    }

    #[test]
    fn never_flags_the_brand_itself_or_its_subdomains() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        assert!(idx.match_name("paypal.com").is_none());
        assert!(idx.match_name("www.paypal.com").is_none());
    }

    #[test]
    fn allow_entry_suppresses_the_collision() {
        let idx = WatchIndex::build(&[
            entry("PayPal", "paypal.com", false),
            entry("our own test domain", "paypa1.com", true),
        ]);
        assert!(idx.match_name("paypa1.com").is_none(), "operator allowlisted");
    }

    #[test]
    fn unrelated_names_pass_clean() {
        let idx = WatchIndex::build(&[entry("PayPal", "paypal.com", false)]);
        assert!(idx.match_name("example.com").is_none());
        assert!(idx.match_name("localhost").is_none(), "single label matches nothing");
    }

    fn hit(observed: &str, suffix: &str) -> ConfusableHit {
        ConfusableHit {
            observed: observed.into(),
            matched_suffix: suffix.into(),
            watchlist_domain: "paypal.com".into(),
            brand: "PayPal".into(),
        }
    }

    #[test]
    fn finding_id_is_stable_per_pair() {
        let group = ConfusableGroup {
            matched_suffix: "paypa1.com".into(),
            watchlist_domain: "paypal.com".into(),
            brand: "PayPal".into(),
            observed_names: vec!["paypa1.com".into()],
            addresses: vec!["203.0.113.9".into()],
        };
        let a = build_finding(&group, 100);
        let b = build_finding(&group, 200);
        assert_eq!(a.finding_id, b.finding_id, "re-observation refines, never re-mints");
        assert_eq!(a.category, "confusable_domain");
        assert_eq!(a.subjects, vec![FindingSubject::domain("paypa1.com")]);
        assert!(matches!(a.severity, FindingSeverity::High));
    }

    /// The flood fix: unlimited subdomains of one registered lookalike must
    /// collapse into ONE finding, because they describe one registration.
    #[test]
    fn subdomains_of_one_lookalike_collapse_into_one_finding() {
        let hits = vec![
            (hit("paypa1.com", "paypa1.com"), vec!["203.0.113.9".to_string()]),
            (hit("login.paypa1.com", "paypa1.com"), vec!["203.0.113.9".to_string()]),
            (hit("a1.paypa1.com", "paypa1.com"), vec!["203.0.113.7".to_string()]),
        ];
        let groups = group_hits(hits);
        assert_eq!(groups.len(), 1, "one registration, one finding");

        let g = &groups[0];
        assert_eq!(g.matched_suffix, "paypa1.com");
        assert_eq!(
            g.observed_names,
            vec!["a1.paypa1.com", "login.paypa1.com", "paypa1.com"],
            "every observed name is kept as evidence, sorted"
        );
        assert_eq!(
            g.addresses,
            vec!["203.0.113.7", "203.0.113.9"],
            "addresses union, deduped and sorted"
        );

        let ids: Vec<String> = groups.iter().map(|g| build_finding(g, 100).finding_id).collect();
        assert_eq!(ids, vec!["confusable:paypal.com:paypa1.com".to_string()]);
    }

    #[test]
    fn distinct_lookalikes_stay_distinct_findings() {
        let mut second = hit("paypal-secure.com", "paypal-secure.com");
        second.watchlist_domain = "paypal.com".into();
        let hits = vec![
            (hit("paypa1.com", "paypa1.com"), vec![]),
            (second, vec![]),
        ];
        assert_eq!(group_hits(hits).len(), 2, "two registrations, two findings");
    }

    /// An attacker with one lookalike domain can resolve unbounded unique
    /// subdomains; the evidence list must not grow without limit.
    #[test]
    fn observed_names_evidence_is_capped() {
        let hits: Vec<(ConfusableHit, Vec<String>)> = (0..500)
            .map(|i| (hit(&format!("s{i}.paypa1.com"), "paypa1.com"), vec![]))
            .collect();
        let groups = group_hits(hits);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].observed_names.len(),
            crate::staging::MAX_LIST_ITEMS,
            "evidence list bounded"
        );
    }
}
