//! The names a decoy uses: the node's made-up site (fixed per node, never
//! resolves) and the return host (the address the scanner used, when that
//! reaches us).
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Words a site is named from. Part of the dataset's contract: never
/// reordered or changed without a new decoy version.
pub const WORDS: [&str; 32] = [
    "shop",
    "portal",
    "crm",
    "billing",
    "intranet",
    "booking",
    "support",
    "store",
    "app",
    "dashboard",
    "members",
    "orders",
    "invoice",
    "payments",
    "tickets",
    "inventory",
    "customers",
    "partners",
    "reports",
    "hr",
    "wiki",
    "forms",
    "events",
    "media",
    "docs",
    "api",
    "account",
    "checkout",
    "catalog",
    "newsletter",
    "jobs",
    "status",
];

/// The node's site word. `node_id` None (a standalone node) hashes nothing.
pub fn word(node_id: Option<&[u8]>) -> &'static str {
    let mut h = Sha256::new();
    h.update(b"peephole-site-v1\0");
    h.update(node_id.unwrap_or_default());
    WORDS[h.finalize()[0] as usize % WORDS.len()]
}

/// The node's site: `<word>.internal` (`.internal` is reserved for private
/// use, so it never resolves to anyone).
pub fn site(node_id: Option<&[u8]>) -> String {
    format!("{}.internal", word(node_id))
}

/// The request's host as stored: the `Host` header, else `:authority`
/// (HTTP/2). Not the other way round: in HTTP/1 a stored `:authority` is a
/// proxy-form target, which names a third party.
pub fn request_host(headers: &[(String, String)]) -> Option<&str> {
    let find = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    find("host").or_else(|| find(":authority"))
}

/// Where a decoy's links point: the Host as sent when it is a public IP or
/// a DNS name (the scanner just reached us with it), else the site.
pub fn return_host(host: Option<&str>, site: &str) -> String {
    let Some(h) = host.filter(|h| !h.is_empty() && h.len() <= 255) else {
        return site.to_string();
    };
    let bare = if let Some(rest) = h.strip_prefix('[') {
        match rest.split_once(']') {
            Some((ip, port)) if port.is_empty() || is_port(port) => ip,
            _ => return site.to_string(),
        }
    } else if h.matches(':').count() == 1 {
        let (name, port) = h.split_once(':').expect("one colon");
        if !is_port(&format!(":{port}")) {
            return site.to_string();
        }
        name
    } else {
        h
    };
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return match ip {
            _ if !crate::net::is_scannable_target(ip) => site.to_string(),
            // Unbracketed in the Host header; a URL needs the brackets.
            IpAddr::V6(_) if !h.starts_with('[') => format!("[{h}]"),
            _ => h.to_string(),
        };
    }
    if is_public_name(bare) {
        h.to_string()
    } else {
        site.to_string()
    }
}

fn is_port(p: &str) -> bool {
    p.strip_prefix(':')
        .is_some_and(|d| !d.is_empty() && d.len() <= 5 && d.bytes().all(|b| b.is_ascii_digit()))
}

/// A dotted DNS name with a letter TLD, not `localhost` or a local suffix.
fn is_public_name(n: &str) -> bool {
    let lower = n.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    labels.len() >= 2
        && n.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|t| t.bytes().all(|b| b.is_ascii_alphabetic()))
        && ![
            "localhost",
            "local",
            "internal",
            "lan",
            "home",
            "test",
            "invalid",
        ]
        .contains(labels.last().expect("non-empty"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_is_fixed_per_node() {
        let a = [7u8; 32];
        assert_eq!(site(Some(&a)), site(Some(&a)));
        assert!(site(Some(&a)).ends_with(".internal"));
        assert!(WORDS.contains(&word(None)));
        // The 32 words are distinct and DNS-safe.
        let mut w = WORDS.to_vec();
        w.sort();
        w.dedup();
        assert_eq!(w.len(), 32);
        assert!(
            WORDS
                .iter()
                .all(|w| w.bytes().all(|b| b.is_ascii_lowercase()))
        );
    }

    #[test]
    fn request_host_prefers_the_host_header() {
        // A proxy-form target (`GET http://third.example/`) names a third
        // party, not us; HTTP/2 has only `:authority`.
        let h = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        };
        assert_eq!(
            request_host(&h(&[("host", "a.example")])),
            Some("a.example")
        );
        assert_eq!(
            request_host(&h(&[("host", "a.example"), (":authority", "b.example")])),
            Some("a.example")
        );
        assert_eq!(
            request_host(&h(&[("Host", "c.example")])),
            Some("c.example")
        );
        assert_eq!(
            request_host(&h(&[(":authority", "d.example")])),
            Some("d.example")
        );
        assert_eq!(request_host(&h(&[])), None);
    }

    #[test]
    fn return_host_uses_public_hosts_as_sent() {
        let s = "shop.internal";
        for h in [
            "203.0.113.7",
            "203.0.113.7:8080",
            "[2001:db8::1]:443",
            "forensics.cc24.dev",
            "Mikoshi.de:80",
        ] {
            assert_eq!(return_host(Some(h), s), h, "{h}");
        }
        for h in [
            "localhost",
            "localhost:80",
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1:8080",
            "169.254.169.254",
            "[::1]",
            "web01",
            "x.localhost",
            "",
        ] {
            assert_eq!(return_host(Some(h), s), s, "{h}");
        }
        assert_eq!(return_host(None, s), s);
        // A bare IPv6 literal is bracketed, so links built from it parse.
        assert_eq!(return_host(Some("2001:db8::1"), s), "[2001:db8::1]");
    }

    #[test]
    fn return_host_refuses_junk() {
        let s = "shop.internal";
        for h in [
            "a b.example",
            "a.example\r\nx: y",
            "\"a.example\"",
            "user@a.example",
            "a..example",
            "-a.example",
            "a.example/x",
            &"a".repeat(300),
        ] {
            assert_eq!(return_host(Some(h), s), s, "{h:?}");
        }
    }
}
