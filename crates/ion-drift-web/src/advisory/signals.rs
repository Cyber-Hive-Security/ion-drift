//! Signal registry — the behavioural signal ids Drift core is able to emit.
//!
//! The advisory catalog is untrusted third-party data that names the signals it
//! wants correlated. This registry is the only thing that says whether core can
//! actually produce them, so a catalog entry referencing an unknown id is
//! rejected at load time rather than sitting in `advisory_signal` matching
//! nothing forever.
//!
//! Ids describe an observed behaviour, never a vendor or a CVE — the linkage
//! from a signal to an advisory lives in catalog rows, not in this file.

/// Signal ids core can emit. The catalog is validated against this registry.
pub const EMITTED_SIGNALS: &[&str] = &[
    "auth.login_failure_burst",
    "auth.login_failure_same_second_burst",
    "auth.login_failure_distributed",
    "auth.login_failure_sustained",
];

/// True when `id` is a signal core knows how to emit.
pub fn is_known_signal(id: &str) -> bool {
    EMITTED_SIGNALS.contains(&id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_signals_are_recognized() {
        for id in EMITTED_SIGNALS {
            assert!(is_known_signal(id), "{id} must be recognized");
        }
    }

    #[test]
    fn unknown_signal_is_rejected() {
        assert!(!is_known_signal("auth.login_failure"));
        assert!(!is_known_signal(""));
        assert!(!is_known_signal("AUTH.LOGIN_FAILURE_BURST"));
    }
}
