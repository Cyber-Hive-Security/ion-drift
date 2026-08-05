//! Boundary staging — bounds, charset and shape checks applied to every value
//! that crosses into Drift from the router or a catalog file, before it
//! reaches the database.
//!
//! This is **not** injection defence. Every SQL statement in the storage crate
//! is a static string with bound parameters, so injection is structurally
//! impossible regardless of what lands here. This module exists for
//! garbage-in containment: bounding what an attacker-influenced field can cost
//! in storage, in log legibility, and in operator display.
//!
//! Two rules run through everything below:
//!
//! 1. **Bound, don't drop.** A value that is too long is truncated and the
//!    truncation logged, never silently discarded — evidence an operator needs
//!    must survive contact with a length limit.
//! 2. **Unknown is not invalid.** A service name Drift has not met is tagged,
//!    not rejected. The log parser defines `service` as everything after
//!    `" via "`, so a wording change in a future RouterOS release must degrade
//!    to "still counted, flagged unknown" and never to silence. This mirrors
//!    the reasoning already recorded on the parser's `src_ip` handling.

/// Longest legal DNS name.
pub(crate) const MAX_DNS_NAME: usize = 253;
/// Longest service token worth keeping. RouterOS service names are short;
/// anything longer is a parser artefact, not a service.
pub(crate) const MAX_SERVICE: usize = 32;
/// Longest textual IP address (IPv6 with an embedded IPv4 suffix).
pub(crate) const MAX_ADDRESS: usize = 45;
/// Longest brand label a catalog may contribute to a finding title.
pub(crate) const MAX_BRAND: usize = 128;
/// Most elements kept in a JSON list column (`src_ips`, `addresses`). A
/// distributed sweep is characterised by its first dozen sources; the rest
/// add storage, not evidence.
pub(crate) const MAX_LIST_ITEMS: usize = 16;

/// RouterOS services Drift recognises. Used to *tag*, never to filter — see
/// the module docs on why an unknown service must still be counted.
const KNOWN_SERVICES: &[&str] = &[
    "api", "api-ssl", "ssh", "telnet", "winbox", "ftp", "www", "www-ssl", "console",
];

/// True for characters that corrupt a log line or spoof a rendered string.
///
/// Covers every C0/C1 control plus the display-affecting subset of Unicode
/// `Cf`: bidirectional overrides, zero-width characters, and the BOM. This is
/// deliberately not all of `Cf` — the test is "can this character make text
/// display or log as something other than what it is", and the enumerated set
/// is what does that. Legitimate IDN characters are untouched, including the
/// confusables the detector exists to report.
fn is_display_hostile(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'                        // soft hyphen
            | '\u{061C}'                      // Arabic letter mark
            | '\u{180E}'                      // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}'         // zero-width + LTR/RTL marks
            | '\u{202A}'..='\u{202E}'         // bidi embedding / override
            | '\u{2060}'..='\u{2064}'         // word joiner, invisible operators
            | '\u{2066}'..='\u{206F}'         // bidi isolates + deprecated formats
            | '\u{FEFF}'                      // BOM / zero-width no-break space
            | '\u{FFF9}'..='\u{FFFB}'         // interlinear annotation
        )
}

/// Drop every display-hostile character. Length is unchanged otherwise.
pub(crate) fn scrub(s: &str) -> String {
    s.chars().filter(|c| !is_display_hostile(*c)).collect()
}

/// Truncate to `max` *characters*, never mid-codepoint.
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Scrub, collapse runs of whitespace to one space, trim, truncate.
///
/// Whitespace collapsing matters for anything rendered next to a label: a
/// brand carrying newlines could otherwise fake a column break in a finding
/// title or a log line.
pub(crate) fn stage_text(raw: &str, max: usize) -> String {
    let scrubbed = scrub(raw);
    let collapsed = scrubbed.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&collapsed, max)
}

/// Normalize a DNS name and accept it only if it can be matched at all.
///
/// `None` means "nothing usable here" — empty, empty after scrubbing, over
/// [`MAX_DNS_NAME`], or a single label (which `candidate_suffixes` can never
/// match against a watchlist, so storing it would be dead weight).
pub(crate) fn stage_dns_name(raw: &str) -> Option<String> {
    // Scrub before normalizing, not after: a bidi override or zero-width
    // character inside a label can derail the IDNA decode, and the staging
    // boundary must not depend on the normalizer's internals to be safe.
    let normalized = crate::confusable::skeleton::normalize_domain(&scrub(raw));
    let name = normalized.trim().trim_end_matches('.').to_string();
    if name.is_empty() || name.len() > MAX_DNS_NAME || !name.contains('.') {
        return None;
    }
    Some(name)
}

/// Bound a service token without ever discarding it.
pub(crate) fn stage_service(raw: &str) -> String {
    truncate_chars(scrub(raw).trim(), MAX_SERVICE)
}

/// True when `service` is a RouterOS service Drift recognises. A `false` here
/// is a tag, not a rejection.
pub(crate) fn is_known_service(service: &str) -> bool {
    KNOWN_SERVICES.contains(&service)
}

/// Bound a list column: scrub and truncate each element, drop the ones that
/// scrub away to nothing, dedup, sort, and cap the list.
pub(crate) fn stage_addresses(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = raw
        .iter()
        .map(|a| truncate_chars(scrub(a).trim(), MAX_ADDRESS))
        .filter(|a| !a.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_LIST_ITEMS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_strips_bidi_and_zero_width() {
        // U+202E RIGHT-TO-LEFT OVERRIDE is the display-spoofing workhorse.
        assert_eq!(scrub("ev\u{202E}il.com"), "evil.com");
        // Zero-width space, zero-width joiner, BOM.
        assert_eq!(scrub("a\u{200B}b\u{200D}c\u{FEFF}"), "abc");
        // Soft hyphen renders as nothing but survives copy/paste.
        assert_eq!(scrub("pay\u{00AD}pal"), "paypal");
    }

    #[test]
    fn scrub_strips_control_chars_that_would_break_log_lines() {
        assert_eq!(scrub("evil\nINFO: fake log line"), "evilINFO: fake log line");
        assert_eq!(scrub("a\tb\rc\0d"), "abcd");
    }

    #[test]
    fn scrub_keeps_legitimate_unicode() {
        // Cyrillic а — a real IDN character, and precisely what the confusable
        // detector exists to catch. Scrubbing it would blind the detector.
        assert_eq!(scrub("\u{0430}pple.com"), "\u{0430}pple.com");
        assert_eq!(scrub("münchen.de"), "münchen.de");
        assert_eq!(scrub("Acme Corp. (EU)"), "Acme Corp. (EU)");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        // Naive byte slicing here would panic mid-codepoint.
        let s = "ααααα";
        assert_eq!(truncate_chars(s, 3), "ααα");
        assert_eq!(truncate_chars("abc", 10), "abc");
    }

    #[test]
    fn stage_text_bounds_and_scrubs() {
        let blob = "x".repeat(10_000);
        assert_eq!(stage_text(&blob, MAX_BRAND).len(), MAX_BRAND);
        assert_eq!(stage_text("  PayPal\u{202E}  ", MAX_BRAND), "PayPal");
        // Interior whitespace collapses so a brand cannot smuggle a fake
        // column break into a log line or a finding title.
        assert_eq!(stage_text("Acme   \n  Corp", MAX_BRAND), "Acme Corp");
    }

    #[test]
    fn stage_dns_name_accepts_a_normal_name() {
        assert_eq!(stage_dns_name("Login.PayPal.com."), Some("login.paypal.com".to_string()));
    }

    #[test]
    fn stage_dns_name_rejects_unusable_shapes() {
        assert_eq!(stage_dns_name(""), None, "empty");
        assert_eq!(stage_dns_name("   "), None, "whitespace only");
        assert_eq!(stage_dns_name("\u{202E}\u{200B}"), None, "empty after scrub");
        assert_eq!(stage_dns_name("localhost"), None, "single label matches nothing");
        let too_long = format!("{}.com", "a".repeat(300));
        assert_eq!(stage_dns_name(&too_long), None, "over MAX_DNS_NAME");
    }

    #[test]
    fn stage_dns_name_strips_control_chars_but_keeps_the_lookalike() {
        // The bidi override goes; the Cyrillic а stays, because that is the
        // very confusability the detector is built to report.
        let staged = stage_dns_name("\u{202E}\u{0430}pple.com").expect("must stage");
        assert_eq!(staged, "\u{0430}pple.com");
    }

    #[test]
    fn stage_service_bounds_but_never_drops() {
        assert_eq!(stage_service("  ssh  "), "ssh");
        assert_eq!(stage_service("api-ssl"), "api-ssl");
        // An unrecognised service is preserved, not dropped — see module docs.
        assert_eq!(stage_service("some-future-service"), "some-future-service");
        assert_eq!(stage_service(&"x".repeat(200)).len(), MAX_SERVICE);
        assert_eq!(stage_service("ss\u{202E}h"), "ssh");
    }

    #[test]
    fn known_services_are_recognised_and_others_are_not() {
        for s in ["api", "api-ssl", "ssh", "telnet", "winbox", "ftp", "www", "www-ssl", "console"] {
            assert!(is_known_service(s), "{s} must be known");
        }
        assert!(!is_known_service("some-future-service"));
        assert!(!is_known_service(""));
    }

    #[test]
    fn stage_addresses_bounds_dedups_and_sorts() {
        let raw = vec![
            "10.0.0.9".to_string(),
            "10.0.0.5".to_string(),
            "10.0.0.9".to_string(),
        ];
        assert_eq!(stage_addresses(&raw), vec!["10.0.0.5", "10.0.0.9"]);
    }

    #[test]
    fn stage_addresses_caps_the_list_and_each_element() {
        let raw: Vec<String> = (0..100).map(|i| format!("10.0.{}.{}", i / 256, i % 256)).collect();
        let staged = stage_addresses(&raw);
        assert_eq!(staged.len(), MAX_LIST_ITEMS, "list capped");

        let blob = vec!["z".repeat(500)];
        assert_eq!(stage_addresses(&blob)[0].len(), MAX_ADDRESS, "element capped");
    }

    #[test]
    fn stage_addresses_drops_values_that_are_empty_after_scrub() {
        let raw = vec!["\u{200B}".to_string(), "10.0.0.5".to_string()];
        assert_eq!(stage_addresses(&raw), vec!["10.0.0.5"]);
    }
}
