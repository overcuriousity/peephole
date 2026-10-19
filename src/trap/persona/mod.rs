//! What a node presents as: one of five hard-coded personas, picked per
//! request from the node key and the public DNS name it was reached with.
//! Stored on every row, so a render or an analysis reads it back and never
//! re-derives it. A persona changes the banner only (owner, MIK-560): the
//! landing at `/`, the `Server` header and its kin, and the AI decoys'
//! identity pool; every decoy answers under every persona.
use crate::canary::site;
use crate::model::ai_id::AiId;
use sha2::{Digest, Sha256};

mod exchange_owa;
mod fortinet;
mod gitlab;
mod gpu_box;
mod wordpress;

/// A product the trap presents as. Every field is static: nothing of a
/// request is rendered into a persona beyond the page token link.
#[derive(Debug)]
pub struct Persona {
    /// Stored on the row and exported; part of the dataset's contract.
    pub name: &'static str,
    /// The product it looks like, for the operator.
    pub product: &'static str,
    /// The `Server` header on every trap response (None: none sent).
    pub server: Option<&'static str>,
    /// Further headers on every trap response.
    pub extra_headers: &'static [(&'static str, &'static str)],
    /// The page at `/`: `(page_token, helper_prefix)`.
    pub landing: fn(&str, &str) -> String,
    /// MCP server names a node answers `initialize` with under this persona.
    pub mcp_servers: &'static [&'static str],
    /// Whether the LLM gateway lists the large local models too.
    pub large_models: bool,
}

/// A persona is its name (the field stored).
impl PartialEq for Persona {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for Persona {}

impl Persona {
    /// The phpinfo decoy's `SERVER_SOFTWARE`.
    pub fn server_software(&self) -> &'static str {
        self.server.unwrap_or("Apache")
    }

    /// Sets this persona's banner headers on a trap response.
    pub fn stamp(&self, h: &mut axum::http::HeaderMap) {
        use axum::http::HeaderValue;
        if let Some(s) = self.server {
            h.insert(axum::http::header::SERVER, HeaderValue::from_static(s));
        }
        for (k, v) in self.extra_headers {
            h.insert(*k, HeaderValue::from_static(v));
        }
    }
}

/// The personas, in the order the hash picks from. Part of the dataset's
/// contract: never reordered or changed without a new hash prefix.
pub static ALL: [Persona; 5] = [
    wordpress::PERSONA,
    fortinet::PERSONA,
    gpu_box::PERSONA,
    gitlab::PERSONA,
    exchange_owa::PERSONA,
];

/// The persona stored as `name` (None: unknown).
pub fn by_name(name: &str) -> Option<&'static Persona> {
    ALL.iter().find(|p| p.name == name)
}

/// What the AI decoys answer as: the serving node's `ident` and the
/// persona it biases. Read from the row (`decoy_in` `"i"`, `"p"`), so a
/// render never depends on the current key. No `ident`: the fixed identity
/// (decoy version 4 and older); no or an unknown persona: the node-neutral
/// identity (decoy version 5 rows written before personas rendered).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AiIdentity {
    pub id: Option<AiId>,
    pub persona: Option<&'static Persona>,
}

impl AiIdentity {
    pub fn derive(ident: Option<&str>, persona: Option<&str>) -> Self {
        let id = AiId::parse(ident);
        AiIdentity {
            id,
            persona: id.and(persona.and_then(by_name)),
        }
    }
}

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
    fn ai_identity_needs_an_ident_and_a_known_persona() {
        let i = Some("a1b2c3d4");
        assert_eq!(
            AiIdentity::derive(i, Some("gpu-box")).persona,
            Some(&ALL[2])
        );
        assert_eq!(AiIdentity::derive(i, None).persona, None);
        assert_eq!(AiIdentity::derive(i, Some("nope")).persona, None);
        assert_eq!(AiIdentity::derive(None, Some("gpu-box")).persona, None);
    }

    #[test]
    fn banners_follow_the_table() {
        let banner = |n: &str| {
            let mut h = axum::http::HeaderMap::new();
            by_name(n).unwrap().stamp(&mut h);
            let mut v: Vec<String> = h
                .iter()
                .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap()))
                .collect();
            v.sort();
            v
        };
        assert_eq!(banner("wordpress"), ["server: Apache/2.4.62 (Debian)"]);
        assert!(banner("fortinet").is_empty());
        assert_eq!(banner("gpu-box"), ["server: uvicorn"]);
        assert_eq!(banner("gitlab"), ["server: nginx"]);
        assert_eq!(
            banner("exchange-owa"),
            ["server: Microsoft-IIS/10.0", "x-powered-by: ASP.NET"]
        );
    }

    /// One pinned render per persona: a markup change is deliberate.
    #[test]
    fn landings_are_pinned_and_carry_the_token_link() {
        let tok = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let mut got = vec![];
        for p in &ALL {
            let page = (p.landing)(tok, "/_pp");
            assert!(page.starts_with("<!DOCTYPE html>"), "{}", p.name);
            assert!(
                page.contains(&format!("window.PEEPHOLE_TOKEN = \"{tok}\";")),
                "{}",
                p.name
            );
            assert!(
                page.contains("window.PEEPHOLE_BASE = \"/_pp\";"),
                "{}",
                p.name
            );
            assert!(
                page.contains("<script src=\"/_pp/collect.js\" defer></script>"),
                "{}",
                p.name
            );
            assert!(!page.contains("__"), "{}: placeholder left", p.name);
            got.push((
                p.name,
                Sha256::digest(page.as_bytes())[..8]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ));
        }
        assert_eq!(
            got,
            [
                ("wordpress", "35a8a9280ebdd78d"),
                ("fortinet", "107e4941cb5f2aca"),
                ("gpu-box", "c6439e641dec42c0"),
                ("gitlab", "d2e9353c84fe8574"),
                ("exchange-owa", "ad2eee90ee89b745"),
            ]
            .map(|(n, d)| (n, d.to_string())),
            "a landing changed"
        );
    }

    #[test]
    fn mcp_pools_are_disjoint() {
        let mut seen = std::collections::HashSet::new();
        for p in &ALL {
            assert!(p.mcp_servers.len() >= 6, "{}", p.name);
            for s in p.mcp_servers {
                assert!(seen.insert(*s), "{s} twice");
            }
        }
    }

    #[test]
    fn names_are_unique() {
        let names: std::collections::HashSet<&str> = ALL.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), ALL.len());
    }
}
