//! What a node presents as: one of five hard-coded personas, picked per
//! request from the node key and the public DNS name it was reached with.
//! Stored on every row, so a render or an analysis reads it back and never
//! re-derives it.
use crate::canary::site;
use sha2::{Digest, Sha256};

/// A product the trap presents as.
#[derive(Debug, PartialEq, Eq)]
pub struct Persona {
    /// Stored on the row and exported; part of the dataset's contract.
    pub name: &'static str,
}

/// The personas, in the order the hash picks from. Part of the dataset's
/// contract: never reordered or changed without a new hash prefix.
pub const ALL: [Persona; 5] = [
    Persona { name: "wordpress" },
    Persona { name: "fortinet" },
    Persona { name: "gpu-box" },
    Persona { name: "gitlab" },
    Persona {
        name: "exchange-owa",
    },
];

/// The persona of a request. `node_id` None (a standalone node) hashes
/// nothing; `host` is the stored host ([`site::request_host`]).
pub fn resolve(node_id: Option<&[u8]>, host: Option<&str>) -> &'static Persona {
    let mut h = Sha256::new();
    h.update(b"peephole-persona-v1\0");
    h.update(node_id.unwrap_or_default());
    h.update(b"\0");
    h.update(host_key(host).as_bytes());
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    &ALL[n as usize % ALL.len()]
}

/// The host a persona is keyed on: a public DNS name, lowercased, without
/// port. Anything else (an IP literal, `localhost`, a local suffix, junk,
/// no host) is `""`, the node persona.
fn host_key(host: Option<&str>) -> String {
    host.filter(|h| h.len() <= site::HOST_MAX)
        .and_then(site::bare_host)
        .map(str::to_ascii_lowercase)
        .filter(|n| site::is_public_name(n))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &[u8] = &[1; 32];

    #[test]
    fn resolve_is_pure_and_pinned() {
        // Pinned: a change here changes what every stored persona meant.
        assert_eq!(resolve(None, None).name, "gpu-box");
        assert_eq!(resolve(Some(K1), None).name, "gitlab");
        assert_eq!(resolve(Some(K1), Some("a.example.com")).name, "gitlab");
        assert_eq!(resolve(Some(K1), Some("b.example.com")).name, "fortinet");
        assert_eq!(resolve(Some(K1), None), resolve(Some(K1), None));
    }

    #[test]
    fn standalone_hashes_nothing() {
        assert_eq!(resolve(None, None), resolve(Some(&[]), None));
        assert_eq!(resolve(None, Some("203.0.113.7")), resolve(None, None));
    }

    #[test]
    fn node_keys_differ() {
        assert_ne!(resolve(Some(K1), None), resolve(Some(&[2; 32]), None));
    }

    #[test]
    fn non_public_hosts_give_the_node_persona() {
        let node = resolve(Some(K1), None);
        for h in [
            "",
            "203.0.113.7",
            "203.0.113.7:8080",
            "[2001:db8::1]:443",
            "[2001:db8::1]",
            "2001:db8::1",
            "localhost",
            "localhost:80",
            "x.localhost",
            "web01",
            "a b.example",
            "[junk",
        ] {
            assert_eq!(resolve(Some(K1), Some(h)), node, "{h:?}");
        }
    }

    #[test]
    fn public_names_are_keyed_case_and_port_blind() {
        for n in ["a.example.com", "b.example.com"] {
            let p = resolve(Some(K1), Some(n));
            assert_eq!(resolve(Some(K1), Some(&n.to_uppercase())), p);
            assert_eq!(resolve(Some(K1), Some(&format!("{n}:8443"))), p);
        }
    }

    #[test]
    fn names_are_unique() {
        let names: std::collections::HashSet<&str> = ALL.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), ALL.len());
    }
}
