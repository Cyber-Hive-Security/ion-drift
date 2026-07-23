//! Shared SSRF guard for outbound requests whose destination is
//! operator/config/module-influenced (module registration + probes, device
//! connections).
//!
//! Policy: Ion Drift legitimately talks to hosts on the LAN, so RFC1918 and
//! IPv6 unique-local (ULA) are ALLOWED. What must be blocked is the
//! link-local range (which includes cloud metadata 169.254.169.254 and
//! fe80::/10), the unspecified/broadcast/0.0.0.0-8 ranges, and — the bypass
//! class the per-literal checks used to miss — any IPv6 that *embeds* an
//! IPv4 address (IPv4-mapped `::ffff:a.b.c.d`, deprecated IPv4-compatible
//! `::a.b.c.d`, and NAT64 `64:ff9b::/96`): those are unwrapped and re-checked
//! against the IPv4 rules so an attacker can't smuggle 169.254.169.254 past
//! the v6 test.
//!
//! Loopback is caller-policy: modules may run on the same host (allowed);
//! managed routers do not live on localhost (blocked).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// True if `v4` is in a range outbound requests must never reach.
/// `allow_loopback` lets same-host callers (modules) permit 127.0.0.0/8.
fn ipv4_is_blocked(v4: Ipv4Addr, allow_loopback: bool) -> bool {
    v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_link_local() // 169.254.0.0/16 — includes cloud metadata
        || v4.octets()[0] == 0 // 0.0.0.0/8
        || (!allow_loopback && v4.is_loopback())
}

/// Extract an IPv4 address embedded in an IPv6 address, if any:
/// IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`, deprecated),
/// or NAT64 (`64:ff9b::/96`). Returns None for a native IPv6 address.
fn embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    // NAT64 well-known prefix 64:ff9b::/96 -> last 32 bits are the v4.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0
    {
        return Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    // IPv4-mapped ::ffff:a.b.c.d
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    // IPv4-compatible ::a.b.c.d (deprecated but still routable if crafted):
    // first 96 bits zero, last 32 bits non-trivial. Exclude ::/:: 1 which are
    // handled by the unspecified/loopback checks already.
    if seg[0..6].iter().all(|&s| s == 0) && !(seg[6] == 0 && seg[7] <= 1) {
        return Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ));
    }
    None
}

/// True if `v6` is in a range outbound requests must never reach.
fn ipv6_is_blocked(v6: Ipv6Addr, allow_loopback: bool) -> bool {
    if v6.is_unspecified() {
        return true;
    }
    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
        return true; // fe80::/10 link-local
    }
    if !allow_loopback && v6.is_loopback() {
        return true; // ::1
    }
    // Re-check any embedded IPv4 against the v4 rules (bypass class).
    if let Some(v4) = embedded_ipv4(v6) {
        return ipv4_is_blocked(v4, allow_loopback);
    }
    false
}

/// True if `ip` must not be an outbound destination under the given policy.
pub fn ip_is_blocked(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_blocked(v4, allow_loopback),
        IpAddr::V6(v6) => ipv6_is_blocked(v6, allow_loopback),
    }
}

/// Resolve `host` and return true if ANY resolved address is blocked.
/// Unresolvable hosts return `false` (not blocked here — the request fails
/// later with a clearer error). `allow_loopback` per caller policy.
///
/// NOTE: this resolves at check time; a subsequent independent resolution by
/// the HTTP client can differ (DNS rebinding). Callers that connect after a
/// gap should re-run this immediately before connecting (see the device path's
/// revalidate step and the module probe guard), and outbound clients MUST set
/// a no-redirect policy so a 3xx can't move the connection to an unvetted host.
pub fn host_resolves_to_blocked(host: &str, allow_loopback: bool) -> bool {
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().any(|a| ip_is_blocked(a.ip(), allow_loopback)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_link_local_and_metadata() {
        assert!(ip_is_blocked("169.254.169.254".parse().unwrap(), true));
        assert!(ip_is_blocked("169.254.1.1".parse().unwrap(), false));
        assert!(ip_is_blocked(IpAddr::V6(v6("fe80::1")), true));
    }

    #[test]
    fn blocks_ipv4_mapped_and_nat64_metadata() {
        // The bypass class: v6 literals embedding 169.254.169.254.
        assert!(ip_is_blocked(IpAddr::V6(v6("::ffff:169.254.169.254")), true));
        assert!(ip_is_blocked(IpAddr::V6(v6("64:ff9b::169.254.169.254")), true));
        // IPv4-compatible ::169.254.169.254
        assert!(ip_is_blocked(IpAddr::V6(v6("::a9fe:a9fe")), true));
    }

    #[test]
    fn loopback_is_policy() {
        assert!(!ip_is_blocked("127.0.0.1".parse().unwrap(), true)); // modules allow
        assert!(ip_is_blocked("127.0.0.1".parse().unwrap(), false)); // devices block
        assert!(ip_is_blocked(IpAddr::V6(v6("::1")), false));
        // IPv4-mapped loopback must also honor the policy.
        assert!(ip_is_blocked(IpAddr::V6(v6("::ffff:127.0.0.1")), false));
        assert!(!ip_is_blocked(IpAddr::V6(v6("::ffff:127.0.0.1")), true));
    }

    #[test]
    fn allows_lan_and_public() {
        // RFC1918 + ULA + public are allowed (Ion Drift talks to the LAN).
        assert!(!ip_is_blocked("192.168.1.1".parse().unwrap(), false));
        assert!(!ip_is_blocked("10.20.25.1".parse().unwrap(), false));
        assert!(!ip_is_blocked(IpAddr::V6(v6("fc00::1")), false)); // ULA allowed
        assert!(!ip_is_blocked("1.1.1.1".parse().unwrap(), false));
    }

    #[test]
    fn blocks_unspecified() {
        assert!(ip_is_blocked("0.0.0.0".parse().unwrap(), true));
        assert!(ip_is_blocked(IpAddr::V6(v6("::")), true));
    }
}
