//! UTS #39 skeleton primitives — pure string functions, no I/O.
//!
//! Script-agnostic on purpose: browsers have enforced mixed-script display
//! rules since ~2017, so "contains Cyrillic" detects nothing an attacker still
//! uses in the address bar. Skeleton collision also catches the pure-ASCII
//! lookalikes browsers deliberately allow (paypa1.com, rnicrosoft.com).

/// Canonical form for comparison: trimmed, no trailing dot, lowercased,
/// punycode labels decoded to Unicode so `xn--pple-43d.com` and the raw
/// Cyrillic form skeleton identically.
pub(crate) fn normalize_domain(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.').to_lowercase();
    // A label idna cannot decode comes back best-effort; never panic on
    // attacker-controlled input.
    let (unicode, _result) = idna::domain_to_unicode(&trimmed);
    unicode
}

/// UTS #39 confusable skeleton. Two domains are confusable iff equal here.
pub(crate) fn skeleton_of(domain: &str) -> String {
    unicode_security::skeleton(domain).collect()
}

/// The suffixes worth matching against a watchlist of registrable domains:
/// the last 2..=4 labels, shortest first, so `paypal.com` is checked before
/// `login.paypal.com` and an exact brand match short-circuits as legitimate.
pub(crate) fn candidate_suffixes(name: &str) -> Vec<String> {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    (2..=4)
        .filter(|n| *n <= labels.len())
        .map(|n| labels[labels.len() - n..].join("."))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lookalikes_share_a_skeleton() {
        assert_eq!(skeleton_of("paypa1.com"), skeleton_of("paypal.com"), "1 vs l");
        assert_eq!(
            skeleton_of("rnicrosoft.com"),
            skeleton_of("microsoft.com"),
            "rn vs m"
        );
        assert_ne!(skeleton_of("example.com"), skeleton_of("paypal.com"));
    }

    #[test]
    fn cross_script_lookalikes_share_a_skeleton() {
        // Cyrillic а (U+0430) in place of Latin a.
        assert_eq!(skeleton_of("аpple.com"), skeleton_of("apple.com"));
    }

    #[test]
    fn normalize_decodes_punycode_and_case() {
        // xn--pple-43d.com is аpple.com (Cyrillic а).
        assert_eq!(normalize_domain("XN--PPLE-43D.COM."), "аpple.com");
        assert_eq!(normalize_domain("Login.PayPal.com"), "login.paypal.com");
    }

    #[test]
    fn candidate_suffixes_shortest_first_min_two_labels() {
        assert_eq!(
            candidate_suffixes("a.b.c.d.e"),
            vec!["d.e".to_string(), "c.d.e".into(), "b.c.d.e".into()],
            "last 2..=4 labels"
        );
        assert_eq!(candidate_suffixes("paypal.com"), vec!["paypal.com".to_string()]);
        assert!(
            candidate_suffixes("localhost").is_empty(),
            "single label: nothing to match"
        );
    }
}
