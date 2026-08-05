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
    // Strip display-hostile characters before anything else. A bidi override
    // or zero-width character surviving into a name would reach finding
    // titles, database rows and structured log lines — spoofing what an
    // operator reads. Legitimate confusables (Cyrillic а and friends) are
    // deliberately untouched: they are the signal, not the noise.
    let scrubbed = crate::staging::scrub(raw);
    let trimmed = scrubbed.trim().trim_end_matches('.').to_lowercase();
    // A label idna cannot decode comes back best-effort; never panic on
    // attacker-controlled input. The error is worth seeing when chasing a
    // name that did not match as expected, but it is not an operator concern.
    let (unicode, result) = idna::domain_to_unicode(&trimmed);
    if let Err(e) = result {
        tracing::debug!(raw = %trimmed, error = %e, "confusable: IDNA decode was lossy");
    }
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
    fn normalize_strips_display_hostile_characters() {
        // The bidi override must not survive into a finding title or a log
        // line; the Cyrillic а must, because it is the confusability itself.
        assert_eq!(normalize_domain("\u{202E}\u{0430}pple.com"), "\u{0430}pple.com");
        assert_eq!(normalize_domain("pay\u{200B}pal.com"), "paypal.com");
    }

    #[test]
    fn normalize_never_panics_on_malformed_punycode() {
        // Attacker-controlled input reaches this function directly; an IDNA
        // failure must degrade, never abort the poll cycle.
        for bad in ["xn--.com", "xn--bad-.com", "xn--a-ecp.ru", "..", "-.-"] {
            let _ = normalize_domain(bad);
        }
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
