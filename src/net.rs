//! Address helpers shared by the trap and the scanner.
//!
//! Two jobs: canonicalise IPv4-mapped IPv6 so a `::ffff:a.b.c.d` address is
//! matched by IPv4 CIDRs and trust lists, and refuse to treat any non-global
//! address as a scan target. The refusal is absolute and has no config
//! override: a spoofed `X-Forwarded-For` (or a misconfigured `never_scan`)
//! must never be able to aim the counter-scanner at loopback, the internal
//! network, or link-local metadata endpoints.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form so
/// IPv4 CIDRs, trust lists and `never_scan` all see the same family.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    }
}

/// Whether `ip` is a routable public address safe to counter-scan. Non-global
/// addresses (loopback, private, CGNAT, link-local, multicast, documentation,
/// reserved, …) return false. Input is canonicalised first.
pub fn is_scannable_target(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

// RFC 5737 / RFC 3849 documentation ranges (TEST-NET-1/2/3, 2001:db8::/32)
// are deliberately *not* refused: they are non-routable, so they never appear
// as live internet sources and scanning them does nothing, while the project's
// own tests and lab setups use them as stand-in public addresses. The refusal
// targets the ranges that make H2 dangerous — loopback, the internal network,
// and link-local metadata endpoints.
fn is_global_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        // CGNAT 100.64.0.0/10
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        // IETF protocol assignments 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // benchmarking 198.18.0.0/15
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        // reserved 240.0.0.0/4 (excluding 255.255.255.255, already broadcast)
        || o[0] >= 240)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // unique local fc00::/7
        || (seg[0] & 0xfe00) == 0xfc00
        // link-local fe80::/10
        || (seg[0] & 0xffc0) == 0xfe80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_maps_v4_in_v6() {
        assert_eq!(
            canonical("::ffff:10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn non_global_targets_are_refused() {
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            // IPv4-mapped private must also be refused.
            "::ffff:192.168.0.1",
        ] {
            assert!(
                !is_scannable_target(s.parse().unwrap()),
                "{s} should be refused"
            );
        }
    }

    #[test]
    fn global_targets_are_allowed() {
        // Includes the TEST-NET range the tests use as a stand-in public IP.
        for s in ["8.8.8.8", "1.1.1.1", "203.0.113.5", "2606:4700::1111"] {
            assert!(
                is_scannable_target(s.parse().unwrap()),
                "{s} should be allowed"
            );
        }
    }
}
