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
        // "this network" 0.0.0.0/8 (RFC 1122): never a destination
        || o[0] == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        // CGNAT 100.64.0.0/10
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
        // IETF protocol assignments 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // deprecated 6to4 relay anycast 192.88.99.0/24 (RFC 7526)
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        // benchmarking 198.18.0.0/15
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
        // reserved 240.0.0.0/4 (excluding 255.255.255.255, already broadcast)
        || o[0] >= 240)
}

/// The IPv4 address embedded in `seg[at]` and `seg[at + 1]`.
fn v4_at(seg: &[u16; 8], at: usize) -> Ipv4Addr {
    let (hi, lo) = (seg[at], seg[at + 1]);
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    let seg = ip.segments();
    // Forms that embed an IPv4 address are only as global as that address:
    // the NAT64 well-known prefix 64:ff9b::/96 (RFC 6052) and 6to4
    // 2002::/16 (RFC 3056). `64:ff9b::127.0.0.1` must not reach loopback
    // through a NAT64 gateway on the scanner's network.
    if seg[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_global_v4(v4_at(&seg, 6));
    }
    if seg[0] == 0x2002 {
        return is_global_v4(v4_at(&seg, 1));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // IPv4-compatible ::a.b.c.d (deprecated, RFC 4291 §2.5.5.1); the
        // whole ::/96, so :: and ::1 too.
        || seg[..6] == [0; 6]
        // local-use NAT64 64:ff9b:1::/48 (RFC 8215)
        || seg[..3] == [0x64, 0xff9b, 1]
        // discard-only 100::/64 (RFC 6666)
        || seg[..4] == [0x100, 0, 0, 0]
        // IETF protocol assignments 2001::/23: Teredo 2001::/32, ORCHID,
        // AMT, AS112, ... A few sub-blocks are routable, but none is a
        // source worth scanning, so the whole block is refused.
        || (seg[0] == 0x2001 && seg[1] < 0x200)
        // SRv6 SIDs 5f00::/16 (RFC 9602)
        || seg[0] == 0x5f00
        // unique local fc00::/7
        || (seg[0] & 0xfe00) == 0xfc00
        // link-local fe80::/10
        || (seg[0] & 0xffc0) == 0xfe80
        // deprecated site-local fec0::/10
        || (seg[0] & 0xffc0) == 0xfec0)
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
            // "this network" 0.0.0.0/8, 6to4 relay anycast
            "0.1.2.3",
            "192.88.99.1",
            // NAT64 / 6to4 embedding a non-global IPv4
            "64:ff9b::127.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::169.254.169.254",
            "2002:7f00:1::1",
            "2002:c0a8:101::1",
            // local-use NAT64, whatever it embeds
            "64:ff9b:1::808:808",
            // IPv4-compatible, whatever it embeds
            "::8.8.8.8",
            "::127.0.0.1",
            // discard-only
            "100::1",
            // IETF assignments, Teredo included
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1::1",
            "2001:1ff::1",
            // SRv6 SIDs
            "5f00::1",
            // site-local
            "fec0::1",
            "feff::1",
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
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "203.0.113.5",
            "2606:4700::1111",
            // the documentation prefix, a stand-in public address in tests
            "2001:db8::5",
            // just past 2001::/23
            "2001:200::1",
            // NAT64 / 6to4 embedding a global IPv4
            "64:ff9b::8.8.8.8",
            "2002:808:808::1",
        ] {
            assert!(
                is_scannable_target(s.parse().unwrap()),
                "{s} should be allowed"
            );
        }
    }
}
