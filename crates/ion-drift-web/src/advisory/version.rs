//! RouterOS version parsing and affected-range matching.
//!
//! Advisory applicability is decided here and nowhere else. The rules are
//! conservative on purpose: anything that cannot be parsed is
//! [`Applicability::CannotEvaluate`], never "not affected", so a malformed feed
//! record or an unexpected version string can only withhold a claim — it can
//! never produce a false all-clear.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// Pre-release channel. Orders below the release it precedes; beta < rc.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PreRelease {
    Beta(u32),
    Rc(u32),
}

/// A RouterOS version: numeric components plus an optional pre-release tag.
/// Equality and ordering treat missing trailing components as zero, so
/// `7.24 == 7.24.0`.
#[derive(Clone, Debug)]
pub(crate) struct RouterOsVersion {
    parts: Vec<u32>,
    pre: Option<PreRelease>,
}

/// RouterOS uses at most three components; four leaves headroom, more is garbage.
const MAX_COMPONENTS: usize = 4;

impl RouterOsVersion {
    /// Parse `7.24.1`, `7.24.1 (stable)`, `7.25rc1`, `7.25beta2`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let token = raw.split_whitespace().next()?;
        let (numeric, pre) = split_pre_release(token)?;
        let parts = numeric
            .split('.')
            .map(|p| p.parse::<u32>().ok())
            .collect::<Option<Vec<u32>>>()?;
        if parts.is_empty() || parts.len() > MAX_COMPONENTS {
            return None;
        }
        Some(Self { parts, pre })
    }
}

fn split_pre_release(token: &str) -> Option<(&str, Option<PreRelease>)> {
    let tags: [(&str, fn(u32) -> PreRelease); 2] =
        [("beta", PreRelease::Beta), ("rc", PreRelease::Rc)];
    for (tag, make) in tags {
        if let Some(at) = token.find(tag) {
            let digits = &token[at + tag.len()..];
            let n = if digits.is_empty() { 0 } else { digits.parse::<u32>().ok()? };
            return Some((&token[..at], Some(make(n))));
        }
    }
    Some((token, None))
}

impl Ord for RouterOsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.parts.len().max(other.parts.len());
        for i in 0..len {
            let a = self.parts.get(i).copied().unwrap_or(0);
            let b = other.parts.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => {}
                unequal => return unequal,
            }
        }
        match (self.pre, other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => a.cmp(&b),
        }
    }
}

impl PartialOrd for RouterOsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RouterOsVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for RouterOsVersion {}

/// One affected range, in the shape shared by the NVD feed and the bundled
/// catalog. Every bound is optional. A range with no bounds and no `exact`
/// matches every version (NVD's wildcard CPE match). `exact` is exclusive with
/// the bounds: a range that sets both is ambiguous and cannot be evaluated.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applicability {
    Affected,
    NotAffected,
    CannotEvaluate,
}

impl VersionRange {
    /// True when `exact` is set together with any start/end bound. Such a
    /// range has no single meaning, so neither the catalog nor the matcher
    /// accepts it.
    pub(crate) fn mixes_exact_with_bounds(&self) -> bool {
        self.exact.is_some()
            && (self.start_including.is_some()
                || self.start_excluding.is_some()
                || self.end_including.is_some()
                || self.end_excluding.is_some())
    }

    /// `None` when a bound in this range cannot be parsed, or when the range
    /// mixes `exact` with bounds — letting either side win could turn an
    /// in-range device into a false "not affected".
    fn contains(&self, v: &RouterOsVersion) -> Option<bool> {
        if self.mixes_exact_with_bounds() {
            return None;
        }
        if let Some(exact) = &self.exact {
            return Some(*v == RouterOsVersion::parse(exact)?);
        }
        let bound = |b: &Option<String>| -> Option<Option<RouterOsVersion>> {
            match b {
                None => Some(None),
                Some(s) => RouterOsVersion::parse(s).map(Some),
            }
        };
        let start_incl = bound(&self.start_including)?;
        let start_excl = bound(&self.start_excluding)?;
        let end_incl = bound(&self.end_including)?;
        let end_excl = bound(&self.end_excluding)?;
        Some(
            start_incl.is_none_or(|b| *v >= b)
                && start_excl.is_none_or(|b| *v > b)
                && end_incl.is_none_or(|b| *v <= b)
                && end_excl.is_none_or(|b| *v < b),
        )
    }
}

/// Decide whether `device_version` falls in any of `ranges`.
///
/// Returns the first matching range when affected, so callers can derive the
/// fix point. An empty range list is `CannotEvaluate` — "no data" must never
/// read as "not affected".
pub(crate) fn evaluate<'a>(
    device_version: &str,
    ranges: &'a [VersionRange],
) -> (Applicability, Option<&'a VersionRange>) {
    let Some(v) = RouterOsVersion::parse(device_version) else {
        return (Applicability::CannotEvaluate, None);
    };
    if ranges.is_empty() {
        return (Applicability::CannotEvaluate, None);
    }
    let mut unknown = false;
    for r in ranges {
        match r.contains(&v) {
            Some(true) => return (Applicability::Affected, Some(r)),
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown {
        (Applicability::CannotEvaluate, None)
    } else {
        (Applicability::NotAffected, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> RouterOsVersion {
        RouterOsVersion::parse(s).unwrap_or_else(|| panic!("failed to parse {s}"))
    }

    fn range(si: Option<&str>, ee: Option<&str>) -> VersionRange {
        VersionRange {
            start_including: si.map(Into::into),
            end_excluding: ee.map(Into::into),
            ..Default::default()
        }
    }

    /// CVE-2026-86060 / CVE-2026-67277 as published by NVD on 2026-09-05.
    fn kev_2026_09() -> Vec<VersionRange> {
        vec![
            range(Some("6.0"), Some("6.49.21")),
            range(Some("7.0"), Some("7.23.4")),
            range(Some("7.24"), Some("7.24.2")),
        ]
    }

    #[test]
    fn parses_router_reported_version_with_channel() {
        assert_eq!(v("7.24.1 (stable)"), v("7.24.1"));
        assert_eq!(v("6.49.20 (long-term)"), v("6.49.20"));
    }

    #[test]
    fn orders_components_numerically_not_lexically() {
        assert!(v("7.24.10") > v("7.24.9"));
        assert!(v("6.49.21") < v("7.0"));
        assert!(v("7.24.1") < v("7.24.2"));
    }

    #[test]
    fn missing_trailing_component_is_zero() {
        assert_eq!(v("7.24"), v("7.24.0"));
    }

    #[test]
    fn pre_releases_order_below_their_release() {
        assert!(v("7.25rc1") < v("7.25"));
        assert!(v("7.25beta3") < v("7.25rc1"));
        assert!(v("7.25rc2") > v("7.25rc1"));
        assert!(v("7.25rc1") > v("7.24.9"));
    }

    #[test]
    fn rejects_garbage() {
        for s in ["", "stable", "7..1", "rc1", "7.24.1.1.1", "7.x", "7.24."] {
            assert!(RouterOsVersion::parse(s).is_none(), "should reject {s:?}");
        }
    }

    #[test]
    fn kev_2026_09_ranges_match_published_fix_points() {
        let r = kev_2026_09();
        for affected in ["7.24.1", "7.24", "7.23.3", "7.0", "6.49.20", "6.0"] {
            assert_eq!(evaluate(affected, &r).0, Applicability::Affected, "{affected}");
        }
        for fixed in ["7.24.2", "7.25", "7.23.4", "7.23.10", "6.49.21", "5.26"] {
            assert_eq!(evaluate(fixed, &r).0, Applicability::NotAffected, "{fixed}");
        }
    }

    #[test]
    fn affected_returns_the_matching_range() {
        let r = kev_2026_09();
        let (_, matched) = evaluate("7.24.1", &r);
        assert_eq!(matched.unwrap().end_excluding.as_deref(), Some("7.24.2"));
    }

    #[test]
    fn unparseable_device_version_cannot_be_evaluated() {
        assert_eq!(evaluate("unknown", &kev_2026_09()).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn empty_range_list_cannot_be_evaluated() {
        assert_eq!(evaluate("7.24.1", &[]).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn unparseable_bound_withholds_the_all_clear() {
        let r = vec![range(Some("7.0"), Some("seven"))];
        assert_eq!(evaluate("7.1", &r).0, Applicability::CannotEvaluate);
    }

    #[test]
    fn unparseable_bound_does_not_mask_a_real_match() {
        let r = vec![range(Some("7.0"), Some("seven")), range(Some("7.0"), Some("7.24.2"))];
        assert_eq!(evaluate("7.1", &r).0, Applicability::Affected);
    }

    #[test]
    fn boundless_range_matches_every_version() {
        assert_eq!(evaluate("7.1", &[VersionRange::default()]).0, Applicability::Affected);
    }

    #[test]
    fn exact_version_matches_only_itself() {
        let r = vec![VersionRange { exact: Some("6.42".into()), ..Default::default() }];
        assert_eq!(evaluate("6.42", &r).0, Applicability::Affected);
        assert_eq!(evaluate("6.42.1", &r).0, Applicability::NotAffected);
    }

    #[test]
    fn inclusive_and_exclusive_bounds() {
        let end_incl = vec![VersionRange { end_including: Some("6.42".into()), ..Default::default() }];
        assert_eq!(evaluate("6.42", &end_incl).0, Applicability::Affected);
        assert_eq!(evaluate("6.42.1", &end_incl).0, Applicability::NotAffected);
        let start_excl = vec![VersionRange { start_excluding: Some("6.0".into()), ..Default::default() }];
        assert_eq!(evaluate("6.0", &start_excl).0, Applicability::NotAffected);
        assert_eq!(evaluate("6.0.1", &start_excl).0, Applicability::Affected);
    }

    #[test]
    fn range_json_round_trips_and_rejects_unknown_fields() {
        let r: Vec<VersionRange> =
            serde_json::from_str(r#"[{"start_including":"7.0","end_excluding":"7.23.4"}]"#).unwrap();
        assert_eq!(r[0].end_excluding.as_deref(), Some("7.23.4"));
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"[{"start_including":"7.0","end_excluding":"7.23.4"}]"#
        );
        assert!(serde_json::from_str::<Vec<VersionRange>>(r#"[{"lt":"7.16"}]"#).is_err());
    }

    #[test]
    fn exact_combined_with_bounds_cannot_be_evaluated() {
        let r = vec![VersionRange {
            exact: Some("7.0".into()),
            end_excluding: Some("7.24.2".into()),
            ..Default::default()
        }];
        assert_eq!(evaluate("7.1", &r).0, Applicability::CannotEvaluate);
        assert_eq!(evaluate("7.0", &r).0, Applicability::CannotEvaluate);
    }
}
