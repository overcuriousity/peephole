# Canary Redesign and Reuse Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decoys hand out realistic, deterministic canary credentials that lead back to the trap, and every node detects when a served canary comes back in a later request, naming the request that harvested it.

**Architecture:** A new pure module `src/canary/` derives canary values, site names and request tokens. `src/trap/decoy.rs` splits into `choose` (which answer) and `render` (the deterministic body). Each node derives two local tables (`canaries`, `request_tokens`) from replicated rows inside `store::data::apply`; a reuse is their join. The admin shows reuses on request, IP and a new Canaries page; the wall shows one aggregate tile; the export gets two columns.

**Tech Stack:** Rust 2024, axum 0.8, sqlx 0.9 (SQLite), askama 0.16, sha2 0.11, data-encoding 2, tokio.

**Spec:** `docs/superpowers/specs/2026-10-04-canary-reuse-design.md`

## Global Constraints

- Decoy body = pure function of `(decoy_v, page_token, host, node_id, ts, method, path, answer)`. No clock, RNG, secret or setting read inside `render`.
- `DECOY_V = 1` for new decoy rows; `NULL` decoy_v on a decoy row means version 0 (`canary-<ref>`, `ref` = first 12 hex chars of the page token without dashes).
- Canary derivation: `SHA-256("peephole-canary-v1\0" || page_token || "\0" || kind [|| "\0" || n])`, `n` decimal ASCII from 1; char = `byte mod alphabet length`.
- Site: `<word>.internal`, word = `WORDS[SHA-256("peephole-site-v1\0" || node_id)[0] mod 32]`; standalone (no node id) hashes the empty string.
- `value_hash` = first 8 bytes of SHA-256(value) as big-endian `i64`.
- `TOKENS_V = 1`; tokens are runs of `[A-Za-z0-9+/=_-]` and their pieces split at `/ + = _ -`, length 16..=128, at most 256 per request.
- No new setting. Nothing new replicated except optional fields on `RequestRec` (`decoy_v`) and `SkipRow` (`page_token`, `host`, `answer`, `decoy_v`), all `skip_serializing_if = "Option::is_none"`.
- Requests that carry no canary are answered exactly as before this change.
- Public wall: aggregates only, tile hidden below 5 reuses in the period.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Before every commit: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the task's tests pass.

## Review Focus

- **Host header with junk (spaces, quotes, CR/LF, `@`, very long)**: reflected into `.env` and `.git/config`; a reasonable person expects the site name instead, never the raw junk. Test in Task 1 (`return_host_refuses_junk`).
- **Non-UTF-8 or binary request bodies and headers**: tokenizer must not panic and must stay within the cap. Test in Task 2 (`binary_and_huge_inputs_are_safe`).
- **Old peers and old rows**: a `RequestRec` without `decoy_v` and a `SkipRow` without the new fields must decode and rebuild byte for byte. Test in Task 4 (`old_records_rebuild_byte_for_byte`).
- **Deleting, pruning or hiding a request**: its `canaries`/`request_tokens` rows must go with it. Test in Task 5 (`derived_rows_follow_their_request`).
- **HEAD on a decoy and a `401` git answer**: HEAD must not break (hyper drops the body), and the 401 must carry `WWW-Authenticate`. Test in Task 6 (`git_routes_challenge_then_answer`, HEAD case in `canary_free_requests_answer_as_before`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/canary/mod.rs` (new) | Module root, re-exports |
| `src/canary/derive.rs` (new) | `DECOY_V`, `Kind`, `value`, `served`, `hash`, `v0_ref` |
| `src/canary/site.rs` (new) | `WORDS`, `word`, `site`, `request_host`, `return_host` |
| `src/canary/tokens.rs` (new) | `TOKENS_V`, `of_request`, `of_credentials` |
| `src/canary/cli.rs` (new) | `peephole decoy render <uid> [CONFIG]` |
| `src/trap/decoy.rs` (rewrite) | `Input`, `Presented`, `Decoy`, `choose`, `render` (v0 + v1) |
| `src/store/canaries.rs` (new) | Derivation into tables, backfill, lookups, reuse queries, summary |
| `src/store/migrations/0003_canaries.sql` (new) | Schema |
| `src/store/data.rs` | Insert/rebuild new fields, call derivation |
| `src/cluster/record.rs` | `RequestRec.decoy_v`, `SkipRow` fields |
| `src/store/requests.rs` | `NewRequest.ts`, `NewRequest.decoy_v`, `RequestRow.decoy_v` |
| `src/store/recorder.rs` | Pass `ts`, `decoy_v` |
| `src/trap/mod.rs`, `src/trap/skiplog.rs` | Serve path: tokens → lookup → choose → render; record ts/decoy fields |
| `src/admin/pages.rs`, `src/admin/public.rs` | Request/IP sections, Canaries page, wall tile |
| `templates/admin_canaries.html` (new), `templates/request.html`, `templates/ip.html`, `templates/_admin_nav.html`, `templates/admin_analytics.html`, `templates/wall.html` | Views |
| `src/store/stats.rs` | `Stats.canaries` |
| `src/export/mod.rs`, `src/export/parquet.rs`, `src/store/export.rs` | `decoy_v`, `canary_used_from` |
| `src/main.rs`, `src/lib.rs` | `decoy` subcommand, backfill task, `pub mod canary` |
| `tests/fixtures/decoys/*.txt` (new) | Golden decoys |
| `tests/integration.rs`, `tests/cluster.rs` | End-to-end tests |
| `docs/dataset.md`, `CHANGELOG.md`, `docs/roadmap.md`, `README.md` | Docs |

---

### Task 1: Canary values and site names

**Files:**
- Create: `src/canary/mod.rs`, `src/canary/derive.rs`, `src/canary/site.rs`
- Modify: `src/lib.rs` (add `pub mod canary;` next to the other `pub mod` lines)

**Interfaces:**
- Produces:
  - `canary::DECOY_V: i64`
  - `canary::Kind` (`Copy`, `name(self) -> &'static str`, `ALL_V1: [Kind; 9]`)
  - `canary::value(page_token: &str, kind: Kind) -> String`
  - `canary::v0_ref(page_token: &str) -> String`
  - `canary::served(decoy_v: Option<i64>, page_token: &str, decoy: &str) -> Vec<(Kind, String)>` (`decoy` = answer without `decoy:`)
  - `canary::hash(value: &str) -> i64`
  - `canary::site::{WORDS, word(node_id: Option<&[u8]>) -> &'static str, site(node_id) -> String, request_host(headers: &[(String, String)]) -> Option<&str>, return_host(host: Option<&str>, site: &str) -> String}`

- [ ] **Step 1: Write the failing tests** in `src/canary/derive.rs` and `src/canary/site.rs` (create both files with only the test modules plus `mod.rs`):

`src/canary/mod.rs`:
```rust
//! Canaries: credentials served in decoys that name the request they were
//! served to. Every value is derived from the request's page token with a
//! public formula (no secret), so any node and any dataset user can
//! recompute the canaries of any row; a value that comes back in a later
//! request names the request that harvested it.
pub mod cli;
pub mod derive;
pub mod site;
pub mod tokens;

pub use derive::{DECOY_V, Kind, hash, served, v0_ref, value};
```
(Create `src/canary/cli.rs` and `src/canary/tokens.rs` as empty files with a `//!` line for now; Tasks 2 and 9 fill them.)

Tests in `src/canary/derive.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";

    fn all(s: &str, alphabet: &str) -> bool {
        s.chars().all(|c| alphabet.contains(c))
    }

    #[test]
    fn formats_look_real() {
        let az27 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let k = value(TOK, Kind::AwsKey);
        assert!(k.starts_with("AKIA") && k.len() == 20 && all(&k[4..], az27), "{k}");
        let s = value(TOK, Kind::AwsSecret);
        assert!(s.len() == 40 && all(&s, b64), "{s}");
        let a = value(TOK, Kind::AppKey);
        assert_eq!(data_encoding::BASE64.decode(a.as_bytes()).unwrap().len(), 32);
        for kind in [Kind::DbPassword, Kind::RedisPassword, Kind::MailPassword, Kind::AdminPassword] {
            let p = value(TOK, kind);
            assert!(p.len() == 20 && all(&p, alnum), "{p}");
        }
        let g = value(TOK, Kind::GitToken);
        assert!(g.len() == 40 && all(&g, "0123456789abcdef"), "{g}");
        let w = value(TOK, Kind::WpSession);
        assert!(w.len() == 43 && all(&w, alnum), "{w}");
    }

    #[test]
    fn same_token_same_value_other_token_other_value() {
        for kind in Kind::ALL_V1 {
            assert_eq!(value(TOK, kind), value(TOK, kind));
            assert_ne!(value(TOK, kind), value("another-token", kind));
        }
        // Kinds never share a value.
        let mut v: Vec<String> = Kind::ALL_V1.iter().map(|k| value(TOK, *k)).collect();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), Kind::ALL_V1.len());
    }

    #[test]
    fn values_are_pinned() {
        // The formula is part of the dataset's contract: these never change
        // without a new decoy version.
        assert_eq!(hash("x"), i64::from_be_bytes([0x2d, 0x71, 0x16, 0x42, 0xb7, 0x26, 0xb0, 0x44]));
        let pinned = value(TOK, Kind::GitToken);
        assert_eq!(pinned, value(TOK, Kind::GitToken));
        assert_eq!(pinned.len(), 40);
    }

    #[test]
    fn no_value_says_canary() {
        for i in 0..2000 {
            let t = format!("tok-{i}");
            for kind in Kind::ALL_V1 {
                assert!(!value(&t, kind).to_ascii_lowercase().contains("canary"));
            }
        }
    }

    #[test]
    fn served_per_decoy_and_version() {
        let env = served(Some(1), TOK, "dotenv");
        assert_eq!(env.len(), 7);
        assert!(env.iter().any(|(k, v)| *k == Kind::AwsKey && v.starts_with("AKIA")));
        assert_eq!(served(Some(1), TOK, "git-config"), vec![(Kind::GitToken, value(TOK, Kind::GitToken))]);
        assert_eq!(served(Some(1), TOK, "wp-login-ok"), vec![(Kind::WpSession, value(TOK, Kind::WpSession))]);
        assert!(served(Some(1), TOK, "phpinfo").is_empty());
        assert!(served(Some(1), TOK, "wp-login-failed").is_empty());
        assert!(served(Some(9), TOK, "dotenv").is_empty(), "unknown versions serve nothing known");
        let r = v0_ref(TOK);
        assert_eq!(r, "0f8e7d6c5b4a");
        let old = served(None, TOK, "dotenv");
        assert!(old.contains(&(Kind::Legacy, format!("canary-{r}"))));
        assert!(old.contains(&(Kind::Legacy, "AKIACANARY0F8E7D6C5B".to_string())));
        assert!(old.contains(&(Kind::Legacy, format!("canary/{r}/not+a+real+secret"))));
        assert_eq!(served(Some(0), TOK, "git-config"), vec![(Kind::Legacy, format!("canary-{r}"))]);
    }
}
```
(For `values_are_pinned`, the first 8 bytes of SHA-256("x") are `2d711642b726b044`.)

Tests in `src/canary/site.rs`:
```rust
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
        assert!(WORDS.iter().all(|w| w.bytes().all(|b| b.is_ascii_lowercase())));
    }

    #[test]
    fn request_host_prefers_authority() {
        let h = |v: &[(&str, &str)]| -> Vec<(String, String)> {
            v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
        };
        assert_eq!(request_host(&h(&[("host", "a.example")])), Some("a.example"));
        assert_eq!(
            request_host(&h(&[("host", "a.example"), (":authority", "b.example")])),
            Some("b.example")
        );
        assert_eq!(request_host(&h(&[("Host", "c.example")])), Some("c.example"));
        assert_eq!(request_host(&h(&[])), None);
    }

    #[test]
    fn return_host_uses_public_hosts_as_sent() {
        let s = "shop.internal";
        for h in ["203.0.113.7", "203.0.113.7:8080", "[2001:db8::1]:443", "2001:db8::1", "forensics.cc24.dev", "Mikoshi.de:80"] {
            assert_eq!(return_host(Some(h), s), h, "{h}");
        }
        for h in ["localhost", "localhost:80", "127.0.0.1", "10.0.0.5", "192.168.1.1:8080", "169.254.169.254", "[::1]", "web01", "x.localhost", ""] {
            assert_eq!(return_host(Some(h), s), s, "{h}");
        }
        assert_eq!(return_host(None, s), s);
    }

    #[test]
    fn return_host_refuses_junk() {
        let s = "shop.internal";
        for h in ["a b.example", "a.example\r\nx: y", "\"a.example\"", "user@a.example", "a..example", "-a.example", "a.example/x", &"a".repeat(300)] {
            assert_eq!(return_host(Some(h), s), s, "{h:?}");
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib canary::`
Expected: compile errors (`value`, `site`, … not defined).

- [ ] **Step 3: Implement** `src/canary/derive.rs` (above the tests):
```rust
//! Canary values: what each kind looks like, derived from the page token.
use sha2::{Digest, Sha256};

/// Version of the decoy templates this build serves (`requests.decoy_v`).
/// A change to any template or to [`value`] bumps it.
pub const DECOY_V: i64 = 1;

const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &[u8] = b"0123456789abcdef";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    AwsKey,
    AwsSecret,
    AppKey,
    DbPassword,
    RedisPassword,
    MailPassword,
    AdminPassword,
    GitToken,
    WpSession,
    /// A version-0 value (`canary-<ref>` and its variants).
    Legacy,
}

impl Kind {
    pub const ALL_V1: [Kind; 9] = [
        Kind::AwsKey,
        Kind::AwsSecret,
        Kind::AppKey,
        Kind::DbPassword,
        Kind::RedisPassword,
        Kind::MailPassword,
        Kind::AdminPassword,
        Kind::GitToken,
        Kind::WpSession,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::AwsKey => "aws-key",
            Kind::AwsSecret => "aws-secret",
            Kind::AppKey => "app-key",
            Kind::DbPassword => "db-password",
            Kind::RedisPassword => "redis-password",
            Kind::MailPassword => "mail-password",
            Kind::AdminPassword => "admin-password",
            Kind::GitToken => "git-token",
            Kind::WpSession => "wp-session",
            Kind::Legacy => "legacy",
        }
    }
}

/// `n` bytes: SHA-256 of the domain, token and kind, then of the same with
/// a counter (`\0` and 1, 2, … in decimal) for as many blocks as needed.
fn stream(page_token: &str, kind: Kind, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut counter = 0u32;
    while out.len() < n {
        let mut h = Sha256::new();
        h.update(b"peephole-canary-v1\0");
        h.update(page_token.as_bytes());
        h.update(b"\0");
        h.update(kind.name().as_bytes());
        if counter > 0 {
            h.update(b"\0");
            h.update(counter.to_string().as_bytes());
        }
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(n);
    out
}

fn pick(bytes: &[u8], alphabet: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| alphabet[*b as usize % alphabet.len()] as char)
        .collect()
}

/// The canary of `kind` for the request with this page token.
pub fn value(page_token: &str, kind: Kind) -> String {
    match kind {
        Kind::AwsKey => format!("AKIA{}", pick(&stream(page_token, kind, 16), B32)),
        Kind::AwsSecret => pick(&stream(page_token, kind, 40), B64),
        Kind::AppKey => data_encoding::BASE64.encode(&stream(page_token, kind, 32)),
        Kind::DbPassword | Kind::RedisPassword | Kind::MailPassword | Kind::AdminPassword => {
            pick(&stream(page_token, kind, 20), ALNUM)
        }
        Kind::GitToken => pick(&stream(page_token, kind, 40), HEX),
        Kind::WpSession => pick(&stream(page_token, kind, 43), ALNUM),
        Kind::Legacy => format!("canary-{}", v0_ref(page_token)),
    }
}

/// Version 0's reference: the first 12 hex characters of the page token.
pub fn v0_ref(page_token: &str) -> String {
    page_token.chars().filter(|c| *c != '-').take(12).collect()
}

/// The canaries a decoy answer carried. `decoy` is the answer without its
/// `decoy:` prefix; `decoy_v` None is version 0.
pub fn served(decoy_v: Option<i64>, page_token: &str, decoy: &str) -> Vec<(Kind, String)> {
    let v = |kinds: &[Kind]| -> Vec<(Kind, String)> {
        kinds.iter().map(|k| (*k, value(page_token, *k))).collect()
    };
    match decoy_v.unwrap_or(0) {
        0 => {
            let r = v0_ref(page_token);
            match decoy {
                "dotenv" => vec![
                    (Kind::Legacy, format!("canary-{r}")),
                    (
                        Kind::Legacy,
                        format!("AKIACANARY{}", r.to_ascii_uppercase().chars().take(10).collect::<String>()),
                    ),
                    (Kind::Legacy, format!("canary/{r}/not+a+real+secret")),
                ],
                "git-config" => vec![(Kind::Legacy, format!("canary-{r}"))],
                _ => vec![],
            }
        }
        1 => match decoy {
            "dotenv" => v(&[
                Kind::AppKey,
                Kind::DbPassword,
                Kind::RedisPassword,
                Kind::MailPassword,
                Kind::AwsKey,
                Kind::AwsSecret,
                Kind::AdminPassword,
            ]),
            "git-config" => v(&[Kind::GitToken]),
            "wp-login-ok" => v(&[Kind::WpSession]),
            _ => vec![],
        },
        _ => vec![],
    }
}

/// What the derived tables store for a value: the first 8 bytes of its
/// SHA-256, big-endian.
pub fn hash(value: &str) -> i64 {
    let d = Sha256::digest(value.as_bytes());
    i64::from_be_bytes(d[..8].try_into().expect("8 bytes"))
}
```

`src/canary/site.rs`:
```rust
//! The names a decoy uses: the node's made-up site (fixed per node, never
//! resolves) and the return host (the address the scanner used, when that
//! reaches us).
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// Words a site is named from. Part of the dataset's contract: never
/// reordered or changed without a new decoy version.
pub const WORDS: [&str; 32] = [
    "shop", "portal", "crm", "billing", "intranet", "booking", "support", "store",
    "app", "dashboard", "members", "orders", "invoice", "payments", "tickets", "inventory",
    "customers", "partners", "reports", "hr", "wiki", "forms", "events", "media",
    "docs", "api", "account", "checkout", "catalog", "newsletter", "jobs", "status",
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

/// The request's host as stored: `:authority`, else the `Host` header (as
/// the export's `host` column).
pub fn request_host(headers: &[(String, String)]) -> Option<&str> {
    let find = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    find(":authority").or_else(|| find("host"))
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
        return if crate::net::is_scannable_target(ip) {
            h.to_string()
        } else {
            site.to_string()
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
        && labels.last().is_some_and(|t| t.bytes().all(|b| b.is_ascii_alphabetic()))
        && !["localhost", "local", "internal", "lan", "home", "test", "invalid"]
            .contains(labels.last().expect("non-empty"))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib canary::`
Expected: PASS (all tests in `canary::derive` and `canary::site`).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/canary src/lib.rs
git commit -m "canary: derived values and site names

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Tokenizer

**Files:**
- Modify: `src/canary/tokens.rs`, `src/classify/mod.rs:88` (make `percent_decode_once` `pub(crate)`)

**Interfaces:**
- Consumes: `canary::hash`
- Produces:
  - `canary::tokens::TOKENS_V: i64` (= 1)
  - `canary::tokens::of_request(headers: &[(String, String)], raw_head: Option<&[u8]>, path: &str, query: Option<&str>, body: &[u8]) -> Vec<(String, i64)>` — `(place, value_hash)`, deduplicated, at most 256, deterministic order. `body` is the stored body; content-encoding is undone inside via `classify::decoded_body`.
  - `canary::tokens::of_credentials(headers: &[(String, String)], body: Option<&[u8]>) -> Vec<(String, i64)>` — only `header:authorization`, `header:proxy-authorization`, `header:cookie` and (when given) `body`. Used on the serve path.

- [ ] **Step 1: Write the failing tests** (in `src/canary/tokens.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::hash;

    const SECRET: &str = "Zx8kQ2mPvR4tW6yB1nC3"; // 20 chars, like a v1 password

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn found(t: &[(String, i64)], place: &str, value: &str) -> bool {
        t.iter().any(|(p, x)| p == place && *x == hash(value))
    }

    #[test]
    fn credentials_are_found_wherever_they_travel() {
        let b64 = |s: &str| data_encoding::BASE64.encode(s.as_bytes());
        let cases: Vec<(Vec<(String, String)>, Option<&[u8]>, &str, Option<&str>, &[u8], &str)> = vec![
            (h(&[("authorization", &format!("Basic {}", b64(&format!("admin:{SECRET}"))))]), None, "/", None, b"", "header:authorization"),
            (h(&[("proxy-authorization", &format!("Basic {}", b64(&format!("u:{SECRET}"))))]), None, "/", None, b"", "header:proxy-authorization"),
            (h(&[("authorization", &format!("Bearer {SECRET}"))]), None, "/", None, b"", "header:authorization"),
            (h(&[("authorization", &format!("AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/20261004/eu-central-1/s3/aws4_request, SignedHeaders=host, Signature=00"))]), None, "/", None, b"", "header:authorization"),
            (h(&[("cookie", &format!("a=1; wordpress_logged_in_x=admin%7C1791172800%7C{SECRET}%7Cabc"))]), None, "/", None, b"", "header:cookie"),
            (h(&[("x-auth", &b64(&format!("deploy:{SECRET}")))]), None, "/", None, b"", "header:x-auth"),
            (h(&[("referer", &format!("http://deploy:{SECRET}@203.0.113.7/git/shop.git"))]), None, "/", None, b"", "header:referer"),
            (h(&[]), None, "/", Some(&format!("key={SECRET}")), b"", "query"),
            (h(&[]), None, &format!("/api/{SECRET}/x"), None, b"", "path"),
            (h(&[("content-type", "application/x-www-form-urlencoded")]), None, "/wp-login.php", None, format!("log=admin&pwd={SECRET}").as_bytes(), "body"),
            (h(&[("content-type", "application/json")]), None, "/", None, format!("{{\"password\":\"{SECRET}\"}}").as_bytes(), "body"),
            (h(&[("content-type", "multipart/form-data; boundary=x")]), None, "/", None, format!("--x\r\nContent-Disposition: form-data; name=\"p\"\r\n\r\n{SECRET}\r\n--x--").as_bytes(), "body"),
        ];
        for (headers, raw, path, query, body, place) in cases {
            let t = of_request(&headers, raw, path, query, body);
            assert!(found(&t, place, SECRET) || found(&t, place, "AKIAABCDEFGHIJKLMNOP"), "{place}: {t:?}");
        }
    }

    #[test]
    fn raw_head_finds_what_the_parser_dropped() {
        let raw = format!("GET / HTTP/1.1\r\nHost: a\r\nX-Token: one\r\nX-Token: {SECRET}\r\n\r\n");
        let t = of_request(&h(&[("x-token", "one")]), Some(raw.as_bytes()), "/", None, b"");
        assert!(found(&t, "header:x-token", SECRET), "{t:?}");
    }

    #[test]
    fn literal_plus_in_a_form_body_and_percent_encoding_both_match() {
        let v = "abc+def/ghi=jklmnopq"; // base64-ish, 20 chars
        let enc = "abc%2Bdef%2Fghi%3Djklmnopq";
        for body in [format!("x={v}"), format!("x={enc}")] {
            let t = of_request(&h(&[("content-type", "application/x-www-form-urlencoded")]), None, "/", None, body.as_bytes());
            assert!(found(&t, "body", v), "{body}: {t:?}");
        }
    }

    #[test]
    fn version_zero_values_are_one_token() {
        let t = of_request(&h(&[("authorization", "Bearer canary-0f8e7d6c5b4a")]), None, "/", None, b"");
        assert!(found(&t, "header:authorization", "canary-0f8e7d6c5b4a"));
    }

    #[test]
    fn short_values_and_plain_requests_yield_nothing_to_match() {
        let t = of_request(&h(&[("user-agent", "curl/8.0"), ("host", "203.0.113.7")]), None, "/.env", None, b"");
        assert!(!t.iter().any(|(_, x)| *x == hash(SECRET)));
        assert!(t.iter().all(|(p, _)| p != "body"));
    }

    #[test]
    fn binary_and_huge_inputs_are_safe() {
        let mut body = vec![0xffu8, 0x00, 0xfe];
        for i in 0..5000 {
            body.extend_from_slice(format!(" token{i:011}abcdef ").as_bytes());
        }
        let t = of_request(&h(&[("x", "\u{fffd}\u{0}")]), Some(&[0xff, 0xfe, b'\n']), "/", None, &body);
        assert!(t.len() <= CAP);
        assert_eq!(t, of_request(&h(&[("x", "\u{fffd}\u{0}")]), Some(&[0xff, 0xfe, b'\n']), "/", None, &body), "deterministic");
    }

    #[test]
    fn credentials_only_looks_at_credential_places() {
        let hs = h(&[("authorization", &format!("Bearer {SECRET}")), ("x-other", SECRET)]);
        let t = of_credentials(&hs, Some(format!("pwd={SECRET}").as_bytes()));
        assert!(found(&t, "header:authorization", SECRET));
        assert!(found(&t, "body", SECRET));
        assert!(!t.iter().any(|(p, _)| p == "header:x-other"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib canary::tokens`
Expected: compile errors (`of_request` not defined).

- [ ] **Step 3: Implement** (above the tests in `src/canary/tokens.rs`), and change `fn percent_decode_once` in `src/classify/mod.rs` to `pub(crate) fn percent_decode_once`:
```rust
//! Tokens: the credential-shaped strings of a request, where they were
//! found, hashed like canaries so the two can be joined.
use crate::canary::hash;
use std::collections::BTreeSet;

/// Version of these rules (`requests.canary_parsed`). A change bumps it,
/// and the backfill parses every row again.
pub const TOKENS_V: i64 = 1;
pub const MIN: usize = 16;
pub const MAX: usize = 128;
/// Most tokens kept per request.
pub const CAP: usize = 256;

fn is_tok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn is_sep(b: u8) -> bool {
    matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

#[derive(Default)]
struct Out {
    seen: BTreeSet<(String, i64)>,
    order: Vec<(String, i64)>,
}

impl Out {
    fn take(&mut self, place: &str, t: &[u8]) {
        if self.order.len() >= CAP || !(MIN..=MAX).contains(&t.len()) {
            return;
        }
        let Ok(s) = std::str::from_utf8(t) else { return };
        let key = (place.to_string(), hash(s));
        if self.seen.insert(key.clone()) {
            self.order.push(key);
        }
    }

    /// Runs and their pieces, of the text as is and percent-decoded; a run
    /// that is base64 of printable text is decoded once and scanned too.
    fn scan(&mut self, place: &str, text: &[u8], depth: u8) {
        let decoded = crate::classify::percent_decode_once(text);
        let variants: &[&[u8]] = if decoded == text { &[text] } else { &[text, &decoded] };
        for v in variants {
            for run in v.split(|b| !is_tok(*b)).filter(|r| !r.is_empty()) {
                self.take(place, run);
                for piece in run.split(|b| is_sep(*b)) {
                    self.take(place, piece);
                }
                if depth == 0
                    && run.len() >= MIN
                    && let Some(plain) = b64_text(run)
                {
                    self.scan(place, &plain, 1);
                }
            }
        }
    }
}

/// `run` decoded as base64 or base64url, when that gives printable text.
fn b64_text(run: &[u8]) -> Option<Vec<u8>> {
    let trimmed: Vec<u8> = run.iter().copied().filter(|b| *b != b'=').collect();
    let out = data_encoding::BASE64_NOPAD
        .decode(&trimmed)
        .or_else(|_| data_encoding::BASE64URL_NOPAD.decode(&trimmed))
        .ok()?;
    let printable = out.len() >= 4
        && std::str::from_utf8(&out).is_ok_and(|s| {
            s.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n'))
        });
    printable.then_some(out)
}

fn place_of(name: &str) -> String {
    format!("header:{}", name.to_ascii_lowercase())
}

/// Every token of a stored request.
pub fn of_request(
    headers: &[(String, String)],
    raw_head: Option<&[u8]>,
    path: &str,
    query: Option<&str>,
    body: &[u8],
) -> Vec<(String, i64)> {
    let mut out = Out::default();
    for (k, v) in headers {
        let place = place_of(k);
        out.scan(&place, k.as_bytes(), 0);
        out.scan(&place, v.as_bytes(), 0);
    }
    if let Some(raw) = raw_head {
        let mut lines = raw.split(|b| *b == b'\n');
        if let Some(first) = lines.next() {
            out.scan("path", first, 0);
        }
        for line in lines {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                break;
            }
            let name = line.split(|b| *b == b':').next().unwrap_or_default();
            let place = place_of(&String::from_utf8_lossy(name));
            out.scan(&place, line, 0);
        }
    }
    out.scan("path", path.as_bytes(), 0);
    if let Some(q) = query {
        out.scan("query", q.as_bytes(), 0);
    }
    if !body.is_empty() {
        let b = crate::classify::decoded_body(headers, body);
        out.scan("body", &b, 0);
    }
    out.order
}

/// The tokens where a login carries its credential: `Authorization`,
/// `Proxy-Authorization`, `Cookie` and, when given, the body.
pub fn of_credentials(headers: &[(String, String)], body: Option<&[u8]>) -> Vec<(String, i64)> {
    let mut out = Out::default();
    for (k, v) in headers {
        if ["authorization", "proxy-authorization", "cookie"]
            .iter()
            .any(|n| k.eq_ignore_ascii_case(n))
        {
            out.scan(&place_of(k), v.as_bytes(), 0);
        }
    }
    if let Some(b) = body.filter(|b| !b.is_empty()) {
        let b = crate::classify::decoded_body(headers, b);
        out.scan("body", &b, 0);
    }
    out.order
}
```
Note: `decoded_body` takes `&'a [u8]` and returns `Cow<'a, [u8]>`; deref with `&b`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib canary::tokens`
Expected: PASS. If the multipart case fails because the run crosses `\r\n`, it does not: `\r` and `\n` are separators.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/canary/tokens.rs src/classify/mod.rs
git commit -m "canary: request tokenizer

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Decoy choice and rendering (v0 and v1)

**Files:**
- Modify: `src/trap/decoy.rs` (rewrite), `src/trap/mod.rs:2` (`mod decoy;` → `pub mod decoy;`)
- Create: `tests/fixtures/decoys/` (golden files, generated in Step 4)

**Interfaces:**
- Consumes: `canary::{value, v0_ref, Kind}`, `canary::site::{word, site, return_host}`
- Produces:
  - `trap::decoy::Input<'a> { v: i64, page_token: &'a str, host: Option<&'a str>, node_id: Option<&'a [u8]>, ts: i64 /* unix seconds */, method: &'a str, path: &'a str }`
  - `trap::decoy::Presented { basic: bool, cookie: bool, body: bool }` (`Default`, `Copy`)
  - `trap::decoy::Decoy { name: String, status: u16, headers: Vec<(&'static str, String)>, body: String }`
  - `trap::decoy::choose(method: &str, path: &str, query: Option<&str>, p: Presented, node_id: Option<&[u8]>) -> Option<&'static str>`
  - `trap::decoy::render(inp: &Input, name: &str) -> Option<Decoy>` (None for an unknown name or version)

- [ ] **Step 1: Write the failing tests** (replace the test module in `src/trap/decoy.rs`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";
    const NODE: [u8; 32] = [7; 32];

    fn inp<'a>(v: i64, host: Option<&'a str>, method: &'a str, path: &'a str) -> Input<'a> {
        Input { v, page_token: TOK, host, node_id: Some(&NODE), ts: 1_791_000_000, method, path }
    }

    fn none() -> Presented {
        Presented::default()
    }

    #[test]
    fn choose_keeps_todays_answers_without_a_canary() {
        let n = Some(&NODE[..]);
        assert_eq!(choose("GET", "/.env", None, none(), n), Some("dotenv"));
        assert_eq!(choose("GET", "/api/.env", None, none(), n), Some("dotenv"));
        assert_eq!(choose("GET", "/.git/config", None, none(), n), Some("git-config"));
        assert_eq!(choose("GET", "/.git/HEAD", None, none(), n), Some("git-head"));
        assert_eq!(choose("GET", "/blog/wp-login.php", None, none(), n), Some("wp-login"));
        assert_eq!(choose("POST", "/wp-login.php", None, none(), n), Some("wp-login-failed"));
        assert_eq!(choose("GET", "/phpinfo.php", None, none(), n), Some("phpinfo"));
        for (m, p) in [("GET", "/"), ("GET", "/.env.bak"), ("POST", "/.env"), ("GET", "/wp-admin/"), ("GET", "/admin/"), ("DELETE", "/wp-login.php")] {
            assert_eq!(choose(m, p, None, none(), n), None, "{m} {p}");
        }
    }

    #[test]
    fn choose_with_canaries_follows_the_spec_precedence() {
        let n = Some(&NODE[..]);
        let repo = format!("/git/{}.git", crate::canary::site::word(n));
        let basic = Presented { basic: true, ..none() };
        let cookie = Presented { cookie: true, ..none() };
        let body = Presented { body: true, ..none() };
        assert_eq!(choose("POST", "/wp-login.php", None, body, n), Some("wp-login-ok"));
        assert_eq!(choose("GET", "/wp-admin/", None, cookie, n), Some("wp-admin"));
        assert_eq!(choose("GET", "/wp-admin/index.php", None, cookie, n), Some("wp-admin"));
        assert_eq!(choose("GET", "/admin/", None, basic, n), Some("admin"));
        assert_eq!(choose("GET", "/.env", None, basic, n), Some("admin"), "Basic canary before path decoys");
        let refs = format!("{repo}/info/refs");
        let svc = Some("service=git-upload-pack");
        assert_eq!(choose("GET", &refs, svc, none(), n), Some("git-auth"));
        assert_eq!(choose("GET", &refs, svc, basic, n), Some("git-refs"));
        assert_eq!(choose("GET", &refs, None, none(), n), None, "dumb HTTP is not served");
        assert_eq!(choose("GET", "/git/other.git/info/refs", svc, none(), n), None);
        let pack = format!("{repo}/git-upload-pack");
        assert_eq!(choose("POST", &pack, None, basic, n), Some("git-pack"));
        assert_eq!(choose("POST", &pack, None, none(), n), None);
    }

    #[test]
    fn v1_dotenv_carries_derived_secrets_and_return_links() {
        let d = render(&inp(1, Some("203.0.113.7"), "GET", "/.env"), "dotenv").unwrap();
        assert_eq!((d.status, d.name.as_str()), (200, "dotenv"));
        let site = crate::canary::site::site(Some(&NODE));
        assert!(d.body.contains(&format!("APP_URL=https://{site}\n")));
        assert!(d.body.contains("ADMIN_URL=http://203.0.113.7/admin/\n"));
        for kind in [Kind::DbPassword, Kind::AwsKey, Kind::AwsSecret, Kind::AdminPassword, Kind::RedisPassword, Kind::MailPassword] {
            assert!(d.body.contains(&value(TOK, kind)), "{kind:?}");
        }
        assert!(d.body.contains(&format!("APP_KEY=base64:{}\n", value(TOK, Kind::AppKey))));
        assert!(!d.body.to_ascii_lowercase().contains("canary"));
        let local = render(&inp(1, Some("localhost"), "GET", "/.env"), "dotenv").unwrap();
        assert!(local.body.contains(&format!("ADMIN_URL=http://{site}/admin/\n")));
    }

    #[test]
    fn v1_git_config_points_back_with_the_token() {
        let d = render(&inp(1, Some("forensics.cc24.dev"), "GET", "/.git/config"), "git-config").unwrap();
        let w = crate::canary::site::word(Some(&NODE));
        assert!(d.body.contains(&format!(
            "url = http://deploy:{}@forensics.cc24.dev/git/{w}.git\n",
            value(TOK, Kind::GitToken)
        )));
    }

    #[test]
    fn wp_login_ok_sets_a_canary_session_cookie() {
        let d = render(&inp(1, None, "POST", "/wp-login.php"), "wp-login-ok").unwrap();
        assert_eq!(d.status, 302);
        assert!(d.headers.contains(&("location", "/wp-admin/".to_string())));
        let cookie = &d.headers.iter().find(|(k, _)| *k == "set-cookie").unwrap().1;
        assert!(cookie.starts_with("wordpress_logged_in_"));
        assert!(cookie.contains(&format!("admin%7C{}%7C{}%7C", 1_791_000_000 + 172_800, value(TOK, Kind::WpSession))));
    }

    #[test]
    fn git_routes_challenge_then_answer() {
        let a = render(&inp(1, None, "GET", "/git/x.git/info/refs"), "git-auth").unwrap();
        assert_eq!(a.status, 401);
        assert!(a.headers.contains(&("www-authenticate", "Basic realm=\"Git\"".to_string())));
        let r = render(&inp(1, None, "GET", "/git/x.git/info/refs"), "git-refs").unwrap();
        assert_eq!(r.status, 200);
        assert!(r.body.starts_with("001e# service=git-upload-pack\n0000"));
        assert!(r.body.contains(" refs/heads/main\n"));
        assert!(r.body.ends_with("0000"));
        // Every pkt-line length is right.
        let mut rest = &r.body["001e# service=git-upload-pack\n0000".len()..];
        while rest != "0000" {
            let n = usize::from_str_radix(&rest[..4], 16).unwrap();
            rest = &rest[n..];
        }
        assert_eq!(render(&inp(1, None, "POST", "/git/x.git/git-upload-pack"), "git-pack").unwrap().status, 500);
    }

    #[test]
    fn version_zero_renders_todays_bodies() {
        let d = render(&inp(0, None, "GET", "/.env"), "dotenv").unwrap();
        assert!(d.body.contains("DB_PASSWORD=canary-0f8e7d6c5b4a\n"));
        assert!(d.body.contains("AWS_ACCESS_KEY_ID=AKIACANARY0F8E7D6C5B\n"));
        let g = render(&inp(0, None, "GET", "/.git/config"), "git-config").unwrap();
        assert!(g.body.contains("deploy:canary-0f8e7d6c5b4a@git.example.invalid"));
        assert!(render(&inp(0, None, "GET", "/x"), "wp-admin").is_none(), "v0 had no wp-admin");
        assert!(render(&inp(5, None, "GET", "/.env"), "dotenv").is_none());
    }

    #[test]
    fn golden_decoys() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/decoys");
        let bless = std::env::var_os("PEEPHOLE_BLESS").is_some();
        let cases: &[(i64, &str, &str, &str)] = &[
            (0, "GET", "/.env", "dotenv"),
            (0, "GET", "/.git/config", "git-config"),
            (0, "GET", "/.git/HEAD", "git-head"),
            (0, "GET", "/wp-login.php", "wp-login"),
            (0, "POST", "/wp-login.php", "wp-login-failed"),
            (0, "GET", "/phpinfo.php", "phpinfo"),
            (1, "GET", "/.env", "dotenv"),
            (1, "GET", "/.git/config", "git-config"),
            (1, "GET", "/.git/HEAD", "git-head"),
            (1, "GET", "/wp-login.php", "wp-login"),
            (1, "POST", "/wp-login.php", "wp-login-failed"),
            (1, "POST", "/wp-login.php", "wp-login-ok"),
            (1, "GET", "/wp-admin/", "wp-admin"),
            (1, "GET", "/admin/", "admin"),
            (1, "GET", "/git/x.git/info/refs", "git-auth"),
            (1, "GET", "/git/x.git/info/refs", "git-refs"),
            (1, "POST", "/git/x.git/git-upload-pack", "git-pack"),
            (1, "GET", "/phpinfo.php", "phpinfo"),
        ];
        for (v, m, p, name) in cases {
            let d = render(&inp(*v, Some("203.0.113.7"), m, p), name).unwrap();
            let mut text = format!("{}\n", d.status);
            for (k, val) in &d.headers {
                text.push_str(&format!("{k}: {val}\n"));
            }
            text.push('\n');
            text.push_str(&d.body);
            let file = dir.join(format!("v{v}-{name}.txt"));
            if bless {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&file, &text).unwrap();
            }
            let want = std::fs::read_to_string(&file)
                .unwrap_or_else(|_| panic!("{} missing: run with PEEPHOLE_BLESS=1", file.display()));
            assert_eq!(text, want, "{} changed: bump DECOY_V instead", file.display());
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib trap::decoy`
Expected: compile errors (`Input`, `choose`, `render` not defined).

- [ ] **Step 3: Implement** — replace everything above the tests in `src/trap/decoy.rs`. Keep today's `dotenv`, `git_config`, `wp_login` and `phpinfo` bodies as the version-0 functions, byte for byte, and add version 1:
```rust
//! Decoys, always on: plausible answers to the first-stage probes scanners
//! send before they attack, so the second stage lands in the trap too.
//!
//! [`choose`] decides which answer a request gets; [`render`] builds it.
//! `render` is a pure function of its [`Input`] and the answer's name, so
//! any stored decoy row can be rendered again byte for byte
//! (`peephole decoy render`). Version 1 serves canaries derived from the
//! page token ([`crate::canary`]); version 0 (rows with no `decoy_v`)
//! served `canary-<ref>`.
use crate::canary::site;
use crate::canary::{Kind, v0_ref, value};

/// What a decoy is rendered from: all of it stored with the row.
pub struct Input<'a> {
    pub v: i64,
    pub page_token: &'a str,
    /// `:authority`, else `Host` ([`site::request_host`]).
    pub host: Option<&'a str>,
    /// The recording node's key (None on a standalone node).
    pub node_id: Option<&'a [u8]>,
    /// The row's time, unix seconds.
    pub ts: i64,
    pub method: &'a str,
    pub path: &'a str,
}

/// Which places of the request carried a canary this node knows.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Presented {
    /// `Authorization` (Basic, Bearer, …).
    pub basic: bool,
    pub cookie: bool,
    pub body: bool,
}

/// A decoy answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoy {
    /// As recorded in `answer` after `decoy:`.
    pub name: String,
    pub status: u16,
    /// Lower-case names; `content-type` always first.
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=UTF-8";
/// WordPress's login cookie lifetime without "remember me".
const WP_SESSION_SECS: i64 = 172_800;

/// The answer for this request, first match wins: the wp-login POST,
/// wp-admin and git routes; a canary in `Authorization`; the probe decoys.
/// None: the trap 404.
pub fn choose(
    method: &str,
    path: &str,
    query: Option<&str>,
    p: Presented,
    node_id: Option<&[u8]>,
) -> Option<&'static str> {
    let get = matches!(method, "GET" | "HEAD");
    let file = path.rsplit('/').next().unwrap_or("");
    let repo = format!("/git/{}.git", site::word(node_id));
    if method == "POST" && file == "wp-login.php" && p.body {
        return Some("wp-login-ok");
    }
    if get && (path == "/wp-admin" || path.starts_with("/wp-admin/")) && p.cookie {
        return Some("wp-admin");
    }
    if get
        && path == format!("{repo}/info/refs")
        && query.is_some_and(|q| q.split('&').any(|kv| kv == "service=git-upload-pack"))
    {
        return Some(if p.basic { "git-refs" } else { "git-auth" });
    }
    if method == "POST" && path == format!("{repo}/git-upload-pack") && p.basic {
        return Some("git-pack");
    }
    if p.basic {
        return Some("admin");
    }
    if get && file == ".env" {
        return Some("dotenv");
    }
    if get && path.ends_with("/.git/config") {
        return Some("git-config");
    }
    if get && path.ends_with("/.git/HEAD") {
        return Some("git-head");
    }
    if file == "wp-login.php" && matches!(method, "GET" | "HEAD" | "POST") {
        return Some(if method == "POST" { "wp-login-failed" } else { "wp-login" });
    }
    if get && matches!(file, "phpinfo.php" | "info.php" | "php_info.php" | "phpinfo") {
        return Some("phpinfo");
    }
    None
}

/// The decoy `name` as version `inp.v` renders it (None: unknown).
pub fn render(inp: &Input, name: &str) -> Option<Decoy> {
    let (status, headers, body): (u16, Vec<(&'static str, String)>, String) = match inp.v {
        0 => {
            let r = v0_ref(inp.page_token);
            match name {
                "dotenv" => (200, ct(TEXT), v0_dotenv(&r)),
                "git-config" => (200, ct(TEXT), v0_git_config(&r)),
                "git-head" => (200, ct(TEXT), "ref: refs/heads/main\n".into()),
                "wp-login" => (200, ct(HTML), wp_login(false)),
                "wp-login-failed" => (200, ct(HTML), wp_login(true)),
                "phpinfo" => (200, ct(HTML), phpinfo("web01")),
                _ => return None,
            }
        }
        1 => {
            let word = site::word(inp.node_id);
            let site_name = site::site(inp.node_id);
            let ret = site::return_host(inp.host, &site_name);
            match name {
                "dotenv" => (200, ct(TEXT), v1_dotenv(inp.page_token, word, &site_name, &ret)),
                "git-config" => (200, ct(TEXT), v1_git_config(inp.page_token, word, &ret)),
                "git-head" => (200, ct(TEXT), "ref: refs/heads/main\n".into()),
                "wp-login" => (200, ct(HTML), wp_login(false)),
                "wp-login-failed" => (200, ct(HTML), wp_login(true)),
                "wp-login-ok" => (
                    302,
                    vec![
                        ("content-type", HTML.into()),
                        ("location", "/wp-admin/".into()),
                        ("set-cookie", wp_cookie(inp.page_token, &site_name, inp.ts)),
                    ],
                    String::new(),
                ),
                "wp-admin" => (200, ct(HTML), wp_admin(word)),
                "admin" => (200, ct(HTML), admin_page(word)),
                "git-auth" => (
                    401,
                    vec![
                        ("content-type", TEXT.into()),
                        ("www-authenticate", "Basic realm=\"Git\"".into()),
                    ],
                    "Unauthorized\n".into(),
                ),
                "git-refs" => (
                    200,
                    vec![
                        ("content-type", "application/x-git-upload-pack-advertisement".into()),
                        ("cache-control", "no-cache".into()),
                    ],
                    git_refs(&site_name),
                ),
                "git-pack" => (500, ct(TEXT), String::new()),
                "phpinfo" => (200, ct(HTML), phpinfo(word)),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(Decoy { name: name.to_string(), status, headers, body })
}

fn ct(v: &str) -> Vec<(&'static str, String)> {
    vec![("content-type", v.to_string())]
}

fn hex(data: &[u8], n: usize) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect::<String>()[..n].to_string()
}

fn v1_dotenv(tok: &str, word: &str, site_name: &str, ret: &str) -> String {
    let v = |k| value(tok, k);
    let mut name = word.to_string();
    name[..1].make_ascii_uppercase();
    format!(
        "APP_NAME={name}
APP_ENV=production
APP_KEY=base64:{app}
APP_DEBUG=false
APP_URL=https://{site_name}

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE={word}_production
DB_USERNAME={word}
DB_PASSWORD={db}

REDIS_HOST=127.0.0.1
REDIS_PASSWORD={redis}
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.{site_name}
MAIL_PORT=587
MAIL_USERNAME=noreply@{site_name}
MAIL_PASSWORD={mail}
MAIL_FROM_ADDRESS=noreply@{site_name}

AWS_ACCESS_KEY_ID={aws_key}
AWS_SECRET_ACCESS_KEY={aws_secret}
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET={word}-uploads

ADMIN_URL=http://{ret}/admin/
ADMIN_USER=admin
ADMIN_PASSWORD={admin}
",
        app = v(Kind::AppKey),
        db = v(Kind::DbPassword),
        redis = v(Kind::RedisPassword),
        mail = v(Kind::MailPassword),
        aws_key = v(Kind::AwsKey),
        aws_secret = v(Kind::AwsSecret),
        admin = v(Kind::AdminPassword),
    )
}

fn v1_git_config(tok: &str, word: &str, ret: &str) -> String {
    format!(
        "[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote \"origin\"]
\turl = http://deploy:{token}@{ret}/git/{word}.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch \"main\"]
\tremote = origin
\tmerge = refs/heads/main
",
        token = value(tok, Kind::GitToken)
    )
}

/// `wordpress_logged_in_<hash>=admin|<expiry>|<token>|<hmac>`, as WordPress
/// builds it; the token is the canary.
fn wp_cookie(tok: &str, site_name: &str, ts: i64) -> String {
    let exp = ts + WP_SESSION_SECS;
    let token = value(tok, Kind::WpSession);
    let mac = hex(format!("admin|{exp}|{token}").as_bytes(), 64);
    format!(
        "wordpress_logged_in_{}=admin%7C{exp}%7C{token}%7C{mac}; path=/; HttpOnly",
        hex(format!("https://{site_name}").as_bytes(), 32)
    )
}

fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

fn git_refs(site_name: &str) -> String {
    let main = hex(format!("{site_name} refs/heads/main").as_bytes(), 40);
    let tag = hex(format!("{site_name} refs/tags/v1.4.2").as_bytes(), 40);
    let mut out = pkt("# service=git-upload-pack\n");
    out.push_str("0000");
    out.push_str(&pkt(&format!(
        "{main} HEAD\0multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main agent=git/2.39.2\n"
    )));
    out.push_str(&pkt(&format!("{main} refs/heads/main\n")));
    out.push_str(&pkt(&format!("{tag} refs/tags/v1.4.2\n")));
    out.push_str("0000");
    out
}

fn wp_admin(word: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Dashboard &lsaquo; {word} &#8212; WordPress</title>
<meta name="robots" content="noindex, noarchive">
</head>
<body class="wp-admin wp-core-ui no-js index-php">
<div id="wpwrap"><div id="adminmenumain"><ul id="adminmenu">
<li><a href="index.php">Dashboard</a></li><li><a href="edit.php">Posts</a></li><li><a href="upload.php">Media</a></li>
<li><a href="plugins.php">Plugins</a></li><li><a href="users.php">Users</a></li><li><a href="options-general.php">Settings</a></li>
</ul></div>
<div id="wpcontent"><div id="wpbody-content"><div class="wrap"><h1>Dashboard</h1>
<div id="welcome-panel" class="welcome-panel"><h2>Welcome to WordPress!</h2></div>
</div></div></div></div>
</body>
</html>
"#
    )
}

fn admin_page(word: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{word} — Administration</title><meta name="robots" content="noindex"></head>
<body>
<header><h1>{word} administration</h1><nav><a href="users">Users</a> · <a href="orders">Orders</a> · <a href="settings">Settings</a> · <a href="logs">Logs</a></nav></header>
<main><p>Signed in as admin.</p><table><tr><th>Queue</th><td>0 pending</td></tr><tr><th>Cache</th><td>warm</td></tr></table></main>
</body>
</html>
"#
    )
}
```
Then keep the existing functions, renamed: `dotenv` → `v0_dotenv(c: &str)`, `git_config` → `v0_git_config(c: &str)`, `wp_login(failed)` unchanged, and `phpinfo()` → `phpinfo(host: &str)` where the `System` row becomes `format!("Linux {host} 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 x86_64")` (version 0 passes `"web01"`, so its output is unchanged). Because the `rows` array then holds a `String`, change its element type to `(&str, String)` and `.to_string()` the other values.

- [ ] **Step 4: Bless the golden files, then run the tests**

Run: `PEEPHOLE_BLESS=1 cargo test --lib trap::decoy::tests::golden_decoys && cargo test --lib trap::decoy`
Expected: PASS. Then check by hand that `tests/fixtures/decoys/v0-dotenv.txt` matches today's `.env` decoy for ref `0f8e7d6c5b4a` (the version-0 bodies must not change), and open `v1-dotenv.txt` and `v1-git-refs.txt` to read them once.

The trap still calls the old `decoy::decoy(...)`, so `cargo build` fails until Task 6. To keep this task's commit building, add this temporary wrapper at the end of `decoy.rs` and use it unchanged from `trap/mod.rs`; Task 6 deletes it:
```rust
/// Today's call, until the serve path chooses with canaries (Task 6).
pub fn decoy(method: &str, path: &str, page_token: &str) -> Option<Decoy> {
    let inp = Input { v: 0, page_token, host: None, node_id: None, ts: 0, method, path };
    render(&inp, choose(method, path, None, Presented::default(), None)?)
}
```
In `trap/mod.rs`, change the call to pass the full `&page_token` (not the 12-char slice, `v0_ref` takes care of that) and the response to use `d.status`, `d.headers` and `d.body` (see Task 6, Step 3's response code, which you can use as is now).

- [ ] **Step 5: Run the whole suite and commit**

Run: `cargo test`
Expected: PASS (the existing `request_is_recorded_after_it_is_answered` still sees 200 on wp-login).
```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/trap/decoy.rs src/trap/mod.rs tests/fixtures/decoys
git commit -m "decoy: choose and render, version 1 templates, golden files

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Schema and records

**Files:**
- Create: `src/store/migrations/0003_canaries.sql`
- Modify: `src/store/mod.rs:31-33` (add the migration), `src/cluster/record.rs` (`RequestRec`, `SkipRow`), `src/store/requests.rs` (`NewRequest`, `RequestRow`), `src/store/recorder.rs:142-176`, `src/store/data.rs` (`request`, `skip_batch`, `rebuild`), every struct literal of `SkipRow`/`RequestRec` in tests (the compiler lists them)

**Interfaces:**
- Produces:
  - `RequestRec.decoy_v: Option<i64>` (last field)
  - `SkipRow { ts_ms, method, path, page_token: Option<String>, host: Option<String>, answer: Option<String>, decoy_v: Option<i64> }`
  - `NewRequest.ts: Option<String>` (None = now), `NewRequest.decoy_v: Option<i64>`
  - `RequestRow.decoy_v: Option<i64>`
  - Tables `canaries`, `request_tokens`; columns `requests.decoy_v`, `requests.canary_parsed`, `skipped_batches.canary_parsed`, `skipped_requests.{page_token, host, answer, decoy_v}`

- [ ] **Step 1: Write the failing tests** in `src/store/data.rs`'s test module (next to `request_rebuild_reproduces_old_and_new_records`, reuse its helpers):
```rust
    #[tokio::test]
    async fn decoy_fields_rebuild_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        let Record::Request(mut r) = request("u-dec", "/.env") else { unreachable!() };
        r.page_token = Some("0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a".into());
        r.answer = Some("decoy:dotenv".into());
        r.decoy_v = Some(1);
        let rec = Record::Request(r);
        apply(&mut conn, ctx, &rec).await.unwrap();
        assert_eq!(rebuild(&mut conn, "request", "u-dec").await.unwrap(), Some(rec));

        let b = Record::SkipBatch(SkipBatchRec {
            uid: "b-dec".into(),
            ip: "198.51.100.9".into(),
            dropped: 0,
            rows: vec![
                SkipRow { ts_ms: 1_791_000_000_000, method: "GET".into(), path: "/a".into(), page_token: None, host: None, answer: None, decoy_v: None },
                SkipRow { ts_ms: 1_791_000_000_500, method: "GET".into(), path: "/.git/config".into(), page_token: Some("t".into()), host: Some("203.0.113.7".into()), answer: Some("decoy:git-config".into()), decoy_v: Some(1) },
            ],
            build: String::new(),
        });
        apply(&mut conn, ctx, &b).await.unwrap();
        assert_eq!(rebuild(&mut conn, "skip_batch", "b-dec").await.unwrap(), Some(b));
    }

    #[test]
    fn old_records_rebuild_byte_for_byte() {
        // A record from a peer without the new fields decodes, and encodes
        // to the same bytes (the fields are left out when unset).
        let row = crate::cluster::record::SkipRow { ts_ms: 1, method: "GET".into(), path: "/".into(), page_token: None, host: None, answer: None, decoy_v: None };
        let bytes = crate::cluster::rpc::cbor::encode(&row).unwrap();
        #[derive(serde::Serialize)]
        struct Old { ts_ms: i64, method: String, path: String }
        let old = crate::cluster::rpc::cbor::encode(&Old { ts_ms: 1, method: "GET".into(), path: "/".into() }).unwrap();
        assert_eq!(bytes, old);
        let back: crate::cluster::record::SkipRow = crate::cluster::rpc::cbor::decode(&old).unwrap();
        assert_eq!(back, row);
    }
```
(If `request(uid, path)` in the test module returns a `Record` with a boxed `RequestRec`, destructure as `Record::Request(mut r)` and modify `r` through the box.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib store::data::tests::decoy_fields store::data::tests::old_records`
Expected: compile errors (`decoy_v`, `page_token` fields unknown).

- [ ] **Step 3: Implement**

`src/store/migrations/0003_canaries.sql`:
```sql
-- Canaries (roadmap item 1). decoy_v: the decoy template version of a
-- decoy row (NULL: version 0, or not a decoy). Light rows answered with a
-- decoy keep what is needed to trace it. canaries and request_tokens are
-- derived on each node from replicated rows, never replicated themselves;
-- canary_parsed holds the tokenizer version a row was parsed with (0: not
-- yet).
ALTER TABLE requests ADD COLUMN decoy_v INTEGER;
ALTER TABLE requests ADD COLUMN canary_parsed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE skipped_batches ADD COLUMN canary_parsed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE skipped_requests ADD COLUMN page_token TEXT;
ALTER TABLE skipped_requests ADD COLUMN host TEXT;
ALTER TABLE skipped_requests ADD COLUMN answer TEXT;
ALTER TABLE skipped_requests ADD COLUMN decoy_v INTEGER;

CREATE TABLE canaries (
  value_hash INTEGER NOT NULL,
  kind TEXT NOT NULL,
  request_id INTEGER REFERENCES requests(id) ON DELETE CASCADE,
  batch_id INTEGER REFERENCES skipped_batches(id) ON DELETE CASCADE,
  skip_rowid INTEGER,
  ts TEXT NOT NULL,
  ip_id INTEGER NOT NULL
);
CREATE INDEX idx_canaries_hash ON canaries(value_hash);
CREATE INDEX idx_canaries_request ON canaries(request_id) WHERE request_id IS NOT NULL;
CREATE INDEX idx_canaries_batch ON canaries(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX idx_canaries_ip ON canaries(ip_id);

CREATE TABLE request_tokens (
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  value_hash INTEGER NOT NULL,
  place TEXT NOT NULL,
  PRIMARY KEY (request_id, value_hash, place)
) WITHOUT ROWID;
CREATE INDEX idx_request_tokens_hash ON request_tokens(value_hash);
CREATE INDEX idx_requests_canary_parsed ON requests(canary_parsed);
```
Register it in `src/store/mod.rs`:
```rust
    include_str!("migrations/0002_host_keys.sql"),
    include_str!("migrations/0003_canaries.sql"),
```

`src/cluster/record.rs` — append to `RequestRec` after `rules`:
```rust
    /// Decoy template version of a decoy answer (`crate::canary::DECOY_V`);
    /// absent for other answers and for decoy rows of version 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_v: Option<i64>,
```
and to `SkipRow` (derive `Default` on it too):
```rust
    /// Set only when the request was answered with a decoy: what renders
    /// and traces it like a full row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_v: Option<i64>,
```

`src/store/requests.rs` — `NewRequest` gains:
```rust
    /// The row's time (`YYYY-MM-DD HH:MM:SS`); None: now. The trap passes
    /// the time it rendered a decoy with.
    pub ts: Option<String>,
    pub decoy_v: Option<i64>,
```
and `RequestRow` gains `pub decoy_v: Option<i64>,` (then add `decoy_v` to every `SELECT` that fills `RequestRow`; `cargo build` names them, and every `RequestRow { … }` literal in tests gets `decoy_v: None`).

`src/store/recorder.rs` `insert_request_from`: `ts: n.ts.clone().unwrap_or_else(now_ts),` and `decoy_v: n.decoy_v,`.

`src/store/data.rs` `request()`: add `decoy_v` to the column list, one more `?`, and `.bind(r.decoy_v)` after `.bind(rules)`. `skip_batch()`:
```rust
        sqlx::query(
            "INSERT INTO skipped_requests (batch_id, ts_ms, method, path, page_token, host, answer, decoy_v)
             VALUES (?,?,?,?,?,?,?,?)",
        )
        .bind(id)
        .bind(row_ms(r.ts_ms))
        .bind(cut(&r.method, 64))
        .bind(cut(&r.path, SKIP_PATH_MAX))
        .bind(r.page_token.as_deref().map(|t| cut(t, 64)))
        .bind(r.host.as_deref().map(|h| cut(h, 255)))
        .bind(r.answer.as_deref().map(|a| cut(a, 64)))
        .bind(r.decoy_v)
```
`rebuild()`: add `Option<i64>` to `ReqExtra`, `decoy_v` to its `SELECT`, and `decoy_v: x.11,` to the `RequestRec`; for `skip_batch`, select `ts_ms, method, path, page_token, host, answer, decoy_v` into a 7-tuple and fill the `SkipRow` fields. A peer's oversized `page_token`/`host`/`answer` is cut on insert, so its rebuild would differ: that is the same rule `path` already follows (`cut` to `SKIP_PATH_MAX`).

Fix every `SkipRow { … }` and `RequestRec { … }` literal the compiler reports (`..Default::default()` for `SkipRow`, `decoy_v: None` for `RequestRec` literals that list all fields).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS, including the two new tests and the existing `request_rebuild_reproduces_old_and_new_records` and `skip_batch_rebuilds_from_its_rows`.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A src/store src/cluster/record.rs
git commit -m "store: decoy version, light-row decoy fields, canary tables

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Deriving canaries and tokens on every node

**Files:**
- Create: `src/store/canaries.rs`
- Modify: `src/store/mod.rs` (add `pub mod canaries;`), `src/store/data.rs` (`request`, `skip_batch` call the derivation), `src/lib.rs` (spawn the backfill), `tests/cluster.rs`

**Interfaces:**
- Consumes: `canary::{served, hash}`, `canary::tokens::{of_request, TOKENS_V}`
- Produces:
  - `store::canaries::derive_request(conn: &mut SqliteConnection, request_id: i64) -> Result<()>`
  - `store::canaries::derive_batch(conn: &mut SqliteConnection, batch_id: i64) -> Result<()>`
  - `store::canaries::backfill(pool: &SqlitePool) -> Result<u64>`
  - `Store::known_canaries(&self, hashes: &[i64]) -> Result<HashSet<i64>>`

- [ ] **Step 1: Write the failing tests** in `src/store/canaries.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    const TOK: &str = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a";

    fn req(uid: &str, ts: &str, ip: &str, path: &str, headers: &str, answer: &str, decoy_v: Option<i64>) -> Record {
        Record::Request(Box::new(RequestRec {
            uid: uid.into(),
            ts: ts.into(),
            ip: ip.into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: headers.into(),
            labels_json: "[]".into(),
            page_token: Some(format!("{TOK}-{uid}")),
            answer: Some(answer.into()),
            decoy_v,
            ..Default::default()
        }))
    }

    fn git_token(uid: &str) -> String {
        crate::canary::value(&format!("{TOK}-{uid}"), crate::canary::Kind::GitToken)
    }

    fn basic(user: &str, pass: &str) -> String {
        let b = data_encoding::BASE64.encode(format!("{user}:{pass}").as_bytes());
        format!(r#"[["authorization","Basic {b}"]]"#)
    }

    async fn reuses(pool: &sqlx::SqlitePool) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT s.uid, u.uid FROM request_tokens t
             JOIN canaries c ON c.value_hash = t.value_hash
             JOIN requests u ON u.id = t.request_id
             JOIN requests s ON s.id = c.request_id
             WHERE c.request_id != t.request_id ORDER BY 1, 2",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_reuse_is_found_in_either_arrival_order() {
        for serve_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
            let serve = req("srv", "2026-10-04 10:00:00", "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1));
            let using = req("use", "2026-10-04 13:00:00", "198.51.100.2", "/git/shop.git/info/refs", &basic("deploy", &git_token("srv")), "decoy:git-refs", Some(1));
            let mut conn = s.pool.acquire().await.unwrap();
            let ctx = Ctx { origin: None, hlc: 1 };
            let order = if serve_first { [&serve, &using] } else { [&using, &serve] };
            for r in order {
                apply(&mut conn, ctx, r).await.unwrap();
            }
            assert_eq!(reuses(&s.pool).await, vec![("srv".into(), "use".into())], "serve_first={serve_first}");
        }
    }

    #[tokio::test]
    async fn a_light_row_decoy_is_traceable() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        let tok = "light-token";
        apply(&mut conn, ctx, &Record::SkipBatch(SkipBatchRec {
            uid: "b1".into(),
            ip: "198.51.100.3".into(),
            dropped: 0,
            rows: vec![SkipRow { ts_ms: 1_791_000_000_000, method: "GET".into(), path: "/.git/config".into(), page_token: Some(tok.into()), host: Some("203.0.113.7".into()), answer: Some("decoy:git-config".into()), decoy_v: Some(1) }],
            build: String::new(),
        })).await.unwrap();
        let token = crate::canary::value(tok, crate::canary::Kind::GitToken);
        apply(&mut conn, ctx, &req("use", "2026-10-04 13:00:00", "198.51.100.4", "/x", &basic("deploy", &token), "not-found", None)).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash WHERE c.batch_id IS NOT NULL",
        ).fetch_one(&s.pool).await.unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn version_zero_rows_are_canaries_too() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        apply(&mut conn, ctx, &req("old", "2026-10-01 10:00:00", "198.51.100.1", "/.env", "[]", "decoy:dotenv", None)).await.unwrap();
        let r = crate::canary::v0_ref(&format!("{TOK}-old"));
        apply(&mut conn, ctx, &req("use", "2026-10-04 13:00:00", "198.51.100.2", "/x", &basic("app", &format!("canary-{r}")), "not-found", None)).await.unwrap();
        assert_eq!(reuses(&s.pool).await, vec![("old".into(), "use".into())]);
    }

    #[tokio::test]
    async fn backfill_derives_history_and_reparses_old_versions() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        apply(&mut conn, ctx, &req("srv", "2026-10-04 10:00:00", "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1))).await.unwrap();
        apply(&mut conn, ctx, &req("use", "2026-10-04 13:00:00", "198.51.100.2", "/x", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        // As an older build would have left it.
        for sql in ["DELETE FROM canaries", "DELETE FROM request_tokens", "UPDATE requests SET canary_parsed = 0"] {
            sqlx::query(sql).execute(&s.pool).await.unwrap();
        }
        drop(conn);
        assert_eq!(backfill(&s.pool).await.unwrap(), 2);
        assert_eq!(reuses(&s.pool).await.len(), 1);
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "each row once");
        sqlx::query("UPDATE requests SET canary_parsed = 0 WHERE uid = 'use'").execute(&s.pool).await.unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(reuses(&s.pool).await.len(), 1, "re-parsing does not duplicate");
    }

    #[tokio::test]
    async fn derived_rows_follow_their_request() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        apply(&mut conn, ctx, &req("srv", "2026-10-04 10:00:00", "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1))).await.unwrap();
        apply(&mut conn, ctx, &req("use", "2026-10-04 13:00:00", "198.51.100.2", "/x", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        drop(conn);
        let use_id: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE uid = 'use'").fetch_one(&s.pool).await.unwrap();
        s.local().delete_request(use_id).await.unwrap();
        let srv_id: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE uid = 'srv'").fetch_one(&s.pool).await.unwrap();
        s.local().delete_request(srv_id).await.unwrap();
        for t in ["canaries", "request_tokens"] {
            let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {t}"))).fetch_one(&s.pool).await.unwrap();
            assert_eq!(n, 0, "{t}");
        }
    }

    #[tokio::test]
    async fn known_canaries_answers_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        apply(&mut conn, Ctx { origin: None, hlc: 1 }, &req("srv", "2026-10-04 10:00:00", "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1))).await.unwrap();
        drop(conn);
        let h = crate::canary::hash(&git_token("srv"));
        let k = s.known_canaries(&[h, 42]).await.unwrap();
        assert!(k.contains(&h) && !k.contains(&42));
        assert!(s.known_canaries(&[]).await.unwrap().is_empty());
    }
}
```
(If `delete_request` only hides on a cluster node, the local recorder still deletes; `Store::local()` is the standalone recorder used in `TrapState::for_test`.)

In `tests/cluster.rs`, add (after `data_replicates_cluster_wide`, reusing its helpers):
```rust
/// A canary served on A and used on B: both nodes find the same reuse.
#[tokio::test]
async fn canary_reuse_is_found_on_every_node() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip_a = na.store.upsert_ip("198.51.100.10".parse().unwrap()).await.unwrap();
    rec(&na)
        .insert_request(&NewRequest {
            ip_id: ip_a.id,
            method: "GET".into(),
            path: "/.git/config".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            page_token: Some("served-on-a".into()),
            answer: Some("decoy:git-config".into()),
            decoy_v: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let token = peephole::canary::value("served-on-a", peephole::canary::Kind::GitToken);
    let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
    let ip_b = nb.store.upsert_ip("198.51.100.11".parse().unwrap()).await.unwrap();
    rec(&nb)
        .insert_request(&NewRequest {
            ip_id: ip_b.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: format!(r#"[["authorization","Basic {auth}"]]"#),
            labels_json: "[]".into(),
            page_token: Some("used-on-b".into()),
            answer: Some("not-found".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let sql = "SELECT COUNT(*) FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash";
    for n in [&na, &nb] {
        eventually("reuse found", || async { count(n, sql).await == 1 }).await;
    }
}
```
(`data-encoding` is a normal dependency, so integration tests can use it.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib store::canaries`
Expected: compile errors (`backfill`, `known_canaries` not defined).

- [ ] **Step 3: Implement** `src/store/canaries.rs` (above the tests):
```rust
//! The canaries this node knows were served and the tokens of every
//! request, both derived from replicated rows (never replicated
//! themselves), so every node finds the same reuses: a reuse is a token
//! whose hash is a served canary's ([`crate::canary`]).
use super::Store;
use crate::canary::tokens::{TOKENS_V, of_request};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::HashSet;

/// Derive a stored request's served canaries and tokens (again: old ones
/// are replaced) and mark it parsed with [`TOKENS_V`].
pub(crate) async fn derive_request(conn: &mut SqliteConnection, request_id: i64) -> Result<()> {
    type Row = (
        String,
        i64,
        String,
        Option<String>,
        String,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<String>,
        Option<i64>,
    );
    let Some(r): Option<Row> = sqlx::query_as(
        "SELECT ts, ip_id, path, query, headers_json, body, raw_head, page_token, answer, decoy_v
         FROM requests WHERE id = ?",
    )
    .bind(request_id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(());
    };
    let (ts, ip_id, path, query, headers_json, body, raw_head, page_token, answer, decoy_v) = r;
    sqlx::query("DELETE FROM canaries WHERE request_id = ?")
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM request_tokens WHERE request_id = ?")
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    if let (Some(tok), Some(name)) = (
        page_token.as_deref(),
        answer.as_deref().and_then(|a| a.strip_prefix("decoy:")),
    ) {
        for (kind, value) in crate::canary::served(decoy_v, tok, name) {
            sqlx::query(
                "INSERT INTO canaries (value_hash, kind, request_id, ts, ip_id) VALUES (?,?,?,?,?)",
            )
            .bind(crate::canary::hash(&value))
            .bind(kind.name())
            .bind(request_id)
            .bind(&ts)
            .bind(ip_id)
            .execute(&mut *conn)
            .await?;
        }
    }
    let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
    let tokens = of_request(
        &headers,
        raw_head.as_deref(),
        &path,
        query.as_deref(),
        body.as_deref().unwrap_or_default(),
    );
    for (place, h) in tokens {
        sqlx::query("INSERT OR IGNORE INTO request_tokens (request_id, value_hash, place) VALUES (?,?,?)")
            .bind(request_id)
            .bind(h)
            .bind(place)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("UPDATE requests SET canary_parsed = ? WHERE id = ?")
        .bind(TOKENS_V)
        .bind(request_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Derive a light-row batch's served canaries and mark it parsed.
pub(crate) async fn derive_batch(conn: &mut SqliteConnection, batch_id: i64) -> Result<()> {
    sqlx::query("DELETE FROM canaries WHERE batch_id = ?")
        .bind(batch_id)
        .execute(&mut *conn)
        .await?;
    let rows: Vec<(i64, i64, String, String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT s.rowid, s.ts_ms, s.page_token, s.answer, s.decoy_v, b.ip_id
         FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
         WHERE s.batch_id = ? AND s.page_token IS NOT NULL AND s.answer LIKE 'decoy:%'",
    )
    .bind(batch_id)
    .fetch_all(&mut *conn)
    .await?;
    for (rowid, ts_ms, tok, answer, decoy_v, ip_id) in rows {
        let ts = chrono::DateTime::from_timestamp_millis(ts_ms)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_default();
        let name = answer.trim_start_matches("decoy:");
        for (kind, value) in crate::canary::served(decoy_v, &tok, name) {
            sqlx::query(
                "INSERT INTO canaries (value_hash, kind, batch_id, skip_rowid, ts, ip_id)
                 VALUES (?,?,?,?,?,?)",
            )
            .bind(crate::canary::hash(&value))
            .bind(kind.name())
            .bind(batch_id)
            .bind(rowid)
            .bind(&ts)
            .bind(ip_id)
            .execute(&mut *conn)
            .await?;
        }
    }
    sqlx::query("UPDATE skipped_batches SET canary_parsed = ? WHERE id = ?")
        .bind(TOKENS_V)
        .bind(batch_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Parse the rows stored before this build (or by an older tokenizer), a
/// batch at a time, each batch its own short write transaction so the trap
/// is not held up. Returns how many rows were parsed.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let mut done = 0;
    loop {
        let ids: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM requests WHERE canary_parsed < ? LIMIT 200")
                .bind(TOKENS_V)
                .fetch_all(pool)
                .await?;
        let batches: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM skipped_batches WHERE canary_parsed < ? LIMIT 200")
                .bind(TOKENS_V)
                .fetch_all(pool)
                .await?;
        if ids.is_empty() && batches.is_empty() {
            return Ok(done);
        }
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for id in &ids {
            derive_request(&mut tx, *id).await?;
        }
        for id in &batches {
            derive_batch(&mut tx, *id).await?;
        }
        tx.commit().await?;
        done += (ids.len() + batches.len()) as u64;
    }
}

impl Store {
    /// Which of these hashes are canaries this node knows were served.
    pub async fn known_canaries(&self, hashes: &[i64]) -> Result<HashSet<i64>> {
        if hashes.is_empty() {
            return Ok(HashSet::new());
        }
        let found: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT value_hash FROM canaries
             WHERE value_hash IN (SELECT value FROM json_each(?))",
        )
        .bind(serde_json::to_string(hashes)?)
        .fetch_all(&self.read)
        .await?;
        Ok(found.into_iter().collect())
    }
}
```
Note: `backfill` counts a batch row and a request row each as one; the test's `2` counts the two requests (no light rows there).

Wire it into `src/store/data.rs` `request()` — replace the final `.execute(&mut *conn).await?; Ok(Effect::Applied)` with:
```rust
    .execute(&mut *conn)
    .await?;
    if done.rows_affected() == 1 {
        super::canaries::derive_request(conn, done.last_insert_rowid()).await?;
    }
    Ok(Effect::Applied)
```
(name the `execute` result `let done = sqlx::query(...)...;`). In `skip_batch()`, after the `for r in &b.rows { … }` loop: `super::canaries::derive_batch(conn, id).await?;`.

In `src/lib.rs`, after the `store::maintenance::run` spawn:
```rust
    // Canaries and tokens of rows stored before this build (or by an older
    // tokenizer); new rows are derived as they are written.
    tokio::spawn({
        let pool = store.pool.clone();
        async move {
            match store::canaries::backfill(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(rows = n, "canaries: parsed stored rows"),
                Err(e) => tracing::warn!(error = %e, "canaries: backfill failed"),
            }
        }
    });
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib store::canaries && cargo test --test cluster canary_reuse_is_found_on_every_node`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/store/canaries.rs src/store/mod.rs src/store/data.rs src/lib.rs tests/cluster.rs
git commit -m "store: derive served canaries and request tokens on every node

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Serve path

**Files:**
- Modify: `src/trap/mod.rs` (`trap`, `record_trap`, `Capture`, `record`), `src/trap/skiplog.rs` (`note`), `src/trap/decoy.rs` (delete the temporary `decoy` wrapper), `tests/integration.rs`

**Interfaces:**
- Consumes: `decoy::{Input, Presented, choose, render}`, `canary::tokens::of_credentials`, `Store::known_canaries`, `NewRequest.{ts, decoy_v}`, `SkipRow` decoy fields
- Produces: `SkipLog::note(&self, ip, ts_ms, method, path, decoy: Option<SkipDecoy>, rate, now) -> Option<Batch>` with `pub struct SkipDecoy { pub page_token: String, pub host: Option<String>, pub answer: String, pub decoy_v: i64 }` in `src/trap/skiplog.rs`

- [ ] **Step 1: Write the failing tests** in `tests/integration.rs`:
```rust
/// The canary a decoy served, read back from the store like a harvester
/// would read it from the body.
async fn served_value(store: &Store, path: &str, kind: peephole::canary::Kind) -> String {
    let tok: String = sqlx::query_scalar("SELECT page_token FROM requests WHERE path = ? ORDER BY id DESC LIMIT 1")
        .bind(path)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    peephole::canary::value(&tok, kind)
}

async fn answer_of(store: &Store, path: &str) -> String {
    sqlx::query_scalar("SELECT answer FROM requests WHERE path = ? ORDER BY id DESC LIMIT 1")
        .bind(path)
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn harvested_credentials_open_the_decoy_logins() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let xff = ("x-forwarded-for", "203.0.113.20");
    let env = c.get(format!("{base}/.env")).header(xff.0, xff.1).send().await.unwrap().text().await.unwrap();
    let admin_pw = served_value(&store, "/.env", peephole::canary::Kind::AdminPassword).await;
    assert!(env.contains(&format!("ADMIN_PASSWORD={admin_pw}\n")));

    // Basic with the harvested password, from another address.
    let r = c.get(format!("{base}/admin/")).basic_auth("admin", Some(&admin_pw)).header("x-forwarded-for", "203.0.113.21").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(answer_of(&store, "/admin/").await, "decoy:admin");

    // wp-login with it: a session cookie that opens wp-admin.
    let r = c.post(format!("{base}/wp-login.php")).form(&[("log", "admin"), ("pwd", admin_pw.as_str())]).header(xff.0, xff.1).send().await.unwrap();
    assert_eq!(r.status(), 302);
    assert_eq!(answer_of(&store, "/wp-login.php").await, "decoy:wp-login-ok");
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let r = c.get(format!("{base}/wp-admin/")).header("cookie", &cookie).header("x-forwarded-for", "203.0.113.22").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("Dashboard"));
    assert_eq!(answer_of(&store, "/wp-admin/").await, "decoy:wp-admin");

    // A wrong password stays a failed login.
    let r = c.post(format!("{base}/wp-login.php")).form(&[("log", "admin"), ("pwd", "Wr0ngPassw0rdWr0ng12")]).header(xff.0, xff.1).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(answer_of(&store, "/wp-login.php").await, "decoy:wp-login-failed");
}

#[tokio::test]
async fn git_clone_with_the_harvested_token_reaches_the_refs() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let cfg = c.get(format!("{base}/.git/config")).header("x-forwarded-for", "203.0.113.30").header("host", "203.0.113.5").send().await.unwrap().text().await.unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    let url = cfg.lines().find_map(|l| l.trim().strip_prefix("url = ")).unwrap().to_string();
    assert!(url.starts_with(&format!("http://deploy:{token}@203.0.113.5/git/")), "{url}");
    let repo_path = &url[url.find("/git/").unwrap()..];
    let refs = format!("{base}{repo_path}/info/refs?service=git-upload-pack");
    let r = c.get(&refs).header("x-forwarded-for", "203.0.113.31").send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers().contains_key("www-authenticate"));
    let r = c.get(&refs).basic_auth("deploy", Some(&token)).header("x-forwarded-for", "203.0.113.31").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("refs/heads/main"));
}

#[tokio::test]
async fn canary_free_requests_answer_as_before() {
    let (base, store, _dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    for (method, path, status) in [("GET", "/admin/", 404), ("GET", "/wp-admin/", 404), ("HEAD", "/.env", 200), ("GET", "/.git/HEAD", 200), ("GET", "/nothing", 404)] {
        let r = c.request(method.parse().unwrap(), format!("{base}{path}")).basic_auth("admin", Some("NotACanaryNotACanary")).header("x-forwarded-for", "203.0.113.40").send().await.unwrap();
        assert_eq!(r.status(), status, "{method} {path}");
    }
    let v: Option<i64> = sqlx::query_scalar("SELECT decoy_v FROM requests WHERE path = '/.git/HEAD'").fetch_one(&store.pool).await.unwrap();
    assert_eq!(v, Some(peephole::canary::DECOY_V));
    let v: Option<i64> = sqlx::query_scalar("SELECT decoy_v FROM requests WHERE path = '/nothing'").fetch_one(&store.pool).await.unwrap();
    assert_eq!(v, None);
}

#[tokio::test]
async fn a_served_decoy_renders_again_from_its_row() {
    let (base, store, _dir) = spawn_trap().await;
    let body = reqwest::Client::new().get(format!("{base}/.env")).header("x-forwarded-for", "203.0.113.50").header("host", "shop.example.org").send().await.unwrap().text().await.unwrap();
    let uid: String = sqlx::query_scalar("SELECT uid FROM requests WHERE path = '/.env'").fetch_one(&store.pool).await.unwrap();
    let again = peephole::canary::cli::render_uid(&store, &uid).await.unwrap().unwrap();
    assert_eq!(again.body, body);
}
```
(`render_uid` is added in Task 9; until then this last test does not compile, so add it in Task 9's Step 1 instead if you prefer to keep this task's suite green. The other three belong here.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test integration harvested_credentials git_clone_with canary_free_requests`
Expected: FAIL (`/admin/` with a canary answers 404; no `decoy_v` stored).

- [ ] **Step 3: Implement**

In `src/trap/mod.rs` `trap()`, replace the block from `let page_token = …` to the end of the function with:
```rust
    let page_token = uuid::Uuid::new_v4().to_string();
    // One time for the row and the decoy, so the row renders it again.
    let now = chrono::Utc::now();
    let headers = header_pairs(&parts.headers);
    let host = parts
        .uri
        .authority()
        .map(|a| a.to_string())
        .or_else(|| crate::canary::site::request_host(&headers).map(str::to_string));
    let method = parts.method.as_str();
    let path = parts.uri.path();
    let presented = presented(&state, &headers, method, path, &body.bytes).await;
    let node_id = state.recorder.node_id();
    let node = node_id.as_ref().map(|n| &n.0[..]);
    let decoy = decoy::choose(method, path, parts.uri.query(), presented, node).and_then(|name| {
        decoy::render(
            &decoy::Input {
                v: crate::canary::DECOY_V,
                page_token: &page_token,
                host: host.as_deref(),
                node_id: node,
                ts: now.timestamp(),
                method,
                path,
            },
            name,
        )
    });
    let (answer, status) = match &decoy {
        Some(d) => (format!("decoy:{}", d.name), d.status),
        None => ("not-found".to_string(), 404),
    };
    let slot = state.guards.slot().await;
    tokio::spawn(record_trap(
        state.clone(),
        (in_flight, slot),
        ip,
        parts,
        body,
        Served {
            page_token: page_token.clone(),
            answer,
            status,
            now,
            host,
            decoy_v: decoy.is_some().then_some(crate::canary::DECOY_V),
        },
    ));
    if let Some(d) = decoy {
        let mut resp = (
            StatusCode::from_u16(d.status).unwrap_or(StatusCode::OK),
            d.body,
        )
            .into_response();
        for (k, v) in d.headers {
            if let Ok(v) = axum::http::HeaderValue::from_str(&v) {
                resp.headers_mut().insert(k, v);
            }
        }
        return resp;
    }
    (
        StatusCode::NOT_FOUND,
        Html(pages::trap_page(&page_token, &state.cfg.trap.helper_prefix)),
    )
        .into_response()
}

/// What the trap sent, for the row.
struct Served {
    page_token: String,
    answer: String,
    status: u16,
    now: chrono::DateTime<chrono::Utc>,
    host: Option<String>,
    decoy_v: Option<i64>,
}

/// Which credential places carried a canary this node knows. Only requests
/// with a credential (an `Authorization` or `Cookie` header, a wp-login
/// POST body) cost a lookup.
async fn presented(
    state: &TrapState,
    headers: &[(String, String)],
    method: &str,
    path: &str,
    body: &[u8],
) -> decoy::Presented {
    let login_post = method == "POST" && path.rsplit('/').next() == Some("wp-login.php");
    let tokens = crate::canary::tokens::of_credentials(headers, login_post.then_some(body));
    if tokens.is_empty() {
        return decoy::Presented::default();
    }
    let hashes: Vec<i64> = tokens.iter().map(|(_, h)| *h).collect();
    let known = state.store.known_canaries(&hashes).await.unwrap_or_default();
    let at = |place: &str| tokens.iter().any(|(p, h)| p == place && known.contains(h));
    decoy::Presented {
        basic: at("header:authorization"),
        cookie: at("header:cookie"),
        body: at("body"),
    }
}
```
`record_trap` takes `served: Served` instead of `page_token, answer, status` (destructure it at the top). In its `Skip` arm pass the time and the decoy to the skip log:
```rust
            let decoy = served.decoy_v.map(|v| skiplog::SkipDecoy {
                page_token: served.page_token.clone(),
                host: served.host.clone(),
                answer: served.answer.clone(),
                decoy_v: v,
            });
            let full = state.guards.skips.note(
                ip,
                served.now.timestamp_millis(),
                method,
                path,
                decoy,
                state.cfg.trap.skip_log_rate,
                Instant::now(),
            );
```
In its `Record` arm, `Capture` gets `ts: served.now.format("%Y-%m-%d %H:%M:%S").to_string()` and `decoy_v: served.decoy_v` (add both fields to `struct Capture`; the claim handler passes `ts: crate::store::data::now_ts(), decoy_v: None`), and `record()` passes `ts: Some(c.ts), decoy_v: c.decoy_v` into `NewRequest`.

In `src/trap/skiplog.rs` add:
```rust
/// What a light row keeps when its request was answered with a decoy.
#[derive(Debug, Clone)]
pub struct SkipDecoy {
    pub page_token: String,
    pub host: Option<String>,
    pub answer: String,
    pub decoy_v: i64,
}
```
and give `note` a `decoy: Option<SkipDecoy>` parameter after `path`, used when pushing the row:
```rust
        p.rows.push(SkipRow {
            ts_ms,
            method: cut(method, 64).to_string(),
            path: cut(path, SKIP_PATH_MAX).to_string(),
            page_token: decoy.as_ref().map(|d| d.page_token.clone()),
            host: decoy.as_ref().and_then(|d| d.host.as_deref().map(|h| cut(h, 255).to_string())),
            answer: decoy.as_ref().map(|d| d.answer.clone()),
            decoy_v: decoy.as_ref().map(|d| d.decoy_v),
        });
```
Update the existing callers of `note` in `skiplog.rs`'s tests to pass `None`.

Delete the temporary `pub fn decoy(…)` wrapper from `src/trap/decoy.rs`.

Add a light-row test to `src/trap/skiplog.rs`'s tests:
```rust
    #[test]
    fn a_decoy_light_row_keeps_its_trace() {
        let log = SkipLog::default();
        let ip: IpAddr = "198.51.100.5".parse().unwrap();
        let d = SkipDecoy { page_token: "t".into(), host: Some("203.0.113.7".into()), answer: "decoy:git-config".into(), decoy_v: 1 };
        log.note(ip, 1_000, "GET", "/.git/config", Some(d), 0, Instant::now());
        let b = log.take(ip).unwrap();
        assert_eq!(b.rows[0].page_token.as_deref(), Some("t"));
        assert_eq!(b.rows[0].answer.as_deref(), Some("decoy:git-config"));
        assert_eq!(b.rows[0].decoy_v, Some(1));
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS (including `request_is_recorded_after_it_is_answered`, the new integration tests, the skiplog test).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/trap tests/integration.rs
git commit -m "trap: canary logins, version-1 decoys, traceable light rows

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Reuse queries, request page and IP page

**Files:**
- Modify: `src/store/canaries.rs` (queries), `src/admin/pages.rs` (`RequestPage`, `request_page`), `src/admin/public.rs` (`IpAdminData`, `ip_page`), `templates/request.html`, `templates/ip.html`

**Interfaces:**
- Produces in `src/store/canaries.rs`:
```rust
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Reuse {
    pub kind: String,
    pub place: String,
    /// The serving request (None: a light row).
    pub served_request_id: Option<i64>,
    pub served_ip: String,
    pub served_node: Option<String>,
    pub served_ts: String,
    pub served_answer: Option<String>,
    pub used_request_id: i64,
    pub used_ip: String,
    pub used_node: Option<String>,
    pub used_ts: String,
    pub delta_s: i64,
    pub same_source: bool,
}
pub struct ReuseFilter { pub kind: Option<String>, pub node: Option<String>, pub same_source: Option<bool>, pub range: crate::store::stats::Range, pub request: Option<i64>, pub ip_id: Option<i64>, pub limit: i64 }
impl Store {
    pub async fn reuses(&self, f: &ReuseFilter) -> Result<Vec<Reuse>>;
    /// (other IPs that used canaries harvested by this IP, other IPs whose canaries this IP used)
    pub async fn canary_links_for_ip(&self, ip_id: i64) -> Result<(i64, i64)>;
}
```
`ReuseFilter.request` matches either side; `ReuseFilter.ip_id` matches either side.

- [ ] **Step 1: Write the failing tests** in `src/store/canaries.rs` tests:
```rust
    #[tokio::test]
    async fn reuses_name_both_sides_and_filter() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        apply(&mut conn, ctx, &req("srv", "2026-10-04 10:00:00", "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1))).await.unwrap();
        apply(&mut conn, ctx, &req("use", "2026-10-04 13:00:00", "198.51.100.2", "/x", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        apply(&mut conn, ctx, &req("self", "2026-10-04 14:00:00", "198.51.100.1", "/y", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        drop(conn);
        let all = ReuseFilter { range: crate::store::stats::Range::All, limit: 100, ..Default::default() };
        let r = s.reuses(&all).await.unwrap();
        assert_eq!(r.len(), 2);
        let other = r.iter().find(|x| x.used_ip == "198.51.100.2").unwrap();
        assert_eq!((other.kind.as_str(), other.place.as_str()), ("git-token", "header:authorization"));
        assert_eq!(other.delta_s, 3 * 3600);
        assert!(!other.same_source);
        assert!(r.iter().any(|x| x.same_source));
        let diff = s.reuses(&ReuseFilter { same_source: Some(false), ..all.clone() }).await.unwrap();
        assert_eq!(diff.len(), 1);
        let srv_ip: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '198.51.100.1'").fetch_one(&s.pool).await.unwrap();
        assert_eq!(s.canary_links_for_ip(srv_ip).await.unwrap(), (1, 0));
        let use_ip: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '198.51.100.2'").fetch_one(&s.pool).await.unwrap();
        assert_eq!(s.canary_links_for_ip(use_ip).await.unwrap(), (0, 1));
    }
```
In `tests/integration.rs`, extend `admin_pages_and_deletes_with_session` style with a new test (reuse `enrolled_admin_client` and `spawn_admin_with`):
```rust
#[tokio::test]
async fn request_and_ip_pages_show_canary_reuse() {
    let (base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    c.get(format!("{base}/.git/config")).header("x-forwarded-for", "203.0.113.60").send().await.unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    c.get(format!("{base}/x")).basic_auth("deploy", Some(&token)).header("x-forwarded-for", "203.0.113.61").send().await.unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, admin_base) = enrolled_admin_client(store.clone(), cfg).await;
    let served: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/.git/config'").fetch_one(&store.pool).await.unwrap();
    let used: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/x'").fetch_one(&store.pool).await.unwrap();
    let page = admin.get(format!("{admin_base}/admin/requests/{served}")).send().await.unwrap().text().await.unwrap();
    assert!(page.contains("Canaries served") && page.contains(&token), "{page}");
    assert!(page.contains("203.0.113.61"));
    let page = admin.get(format!("{admin_base}/admin/requests/{used}")).send().await.unwrap().text().await.unwrap();
    assert!(page.contains(&format!("/admin/requests/{served}")) && page.contains("header:authorization"));
    let ip = admin.get(format!("{admin_base}/ip/203.0.113.60")).send().await.unwrap().text().await.unwrap();
    assert!(ip.contains("used by 1 other IP"), "{ip}");
    // Nothing of it on the public IP page.
    let public = reqwest::get(format!("{admin_base}/ip/203.0.113.60")).await.unwrap().text().await.unwrap();
    assert!(!public.contains("Canar") && !public.contains(&token));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib store::canaries::tests::reuses && cargo test --test integration request_and_ip_pages_show_canary_reuse`
Expected: compile errors / FAIL.

- [ ] **Step 3: Implement** in `src/store/canaries.rs`:
```rust
#[derive(Debug, Clone, Default)]
pub struct ReuseFilter {
    pub kind: Option<String>,
    /// Node name, either side.
    pub node: Option<String>,
    pub same_source: Option<bool>,
    pub range: crate::store::stats::Range,
    /// Either side is this request.
    pub request: Option<i64>,
    /// Either side is this IP.
    pub ip_id: Option<i64>,
    pub limit: i64,
}

const REUSE_SELECT: &str = "
    SELECT c.kind, t.place,
           c.request_id AS served_request_id,
           ci.ip AS served_ip,
           (SELECT name FROM members m WHERE m.id = COALESCE(sr.origin, sb.origin)) AS served_node,
           c.ts AS served_ts,
           sr.answer AS served_answer,
           u.id AS used_request_id,
           ui.ip AS used_ip,
           (SELECT name FROM members m WHERE m.id = u.origin) AS used_node,
           u.ts AS used_ts,
           CAST(strftime('%s', u.ts) AS INTEGER) - CAST(strftime('%s', c.ts) AS INTEGER) AS delta_s,
           c.ip_id = u.ip_id AS same_source
    FROM request_tokens t
    JOIN canaries c ON c.value_hash = t.value_hash
    JOIN requests u ON u.id = t.request_id
    JOIN ips ui ON ui.id = u.ip_id
    JOIN ips ci ON ci.id = c.ip_id
    LEFT JOIN requests sr ON sr.id = c.request_id
    LEFT JOIN skipped_batches sb ON sb.id = c.batch_id
    WHERE (c.request_id IS NULL OR c.request_id != t.request_id)";
```
`Range` needs `Default` (`#[derive(Default)]` with `#[default]` on `All`) and must be `Clone`; add both in `src/store/stats.rs` if missing.
```rust
impl Store {
    /// Reuses matching `f`, newest use first, one row per (use, canary).
    pub async fn reuses(&self, f: &ReuseFilter) -> Result<Vec<Reuse>> {
        let mut sql = REUSE_SELECT.to_string();
        if f.kind.is_some() { sql.push_str(" AND c.kind = ?"); }
        if f.node.is_some() {
            sql.push_str(" AND ? IN ((SELECT name FROM members m WHERE m.id = COALESCE(sr.origin, sb.origin)), (SELECT name FROM members m WHERE m.id = u.origin))");
        }
        if let Some(same) = f.same_source { sql.push_str(if same { " AND c.ip_id = u.ip_id" } else { " AND c.ip_id != u.ip_id" }); }
        if f.request.is_some() { sql.push_str(" AND ? IN (c.request_id, u.id)"); }
        if f.ip_id.is_some() { sql.push_str(" AND ? IN (c.ip_id, u.ip_id)"); }
        if f.range.since().is_some() {
            sql.push_str(" AND u.ts >= datetime('now', ?)");
        }
        sql.push_str(" GROUP BY u.id, c.value_hash ORDER BY u.ts DESC, u.id DESC LIMIT ?");
        let mut q = sqlx::query_as::<_, Reuse>(sqlx::AssertSqlSafe(sql));
        if let Some(k) = &f.kind { q = q.bind(k); }
        if let Some(n) = &f.node { q = q.bind(n); }
        if let Some(r) = f.request { q = q.bind(r); }
        if let Some(i) = f.ip_id { q = q.bind(i); }
        if let Some(m) = f.range.since() { q = q.bind(m); }
        Ok(q.bind(f.limit.clamp(1, 1000)).fetch_all(&self.read).await?)
    }

    pub async fn canary_links_for_ip(&self, ip_id: i64) -> Result<(i64, i64)> {
        Ok(sqlx::query_as(
            "SELECT
               (SELECT COUNT(DISTINCT u.ip_id) FROM canaries c
                  JOIN request_tokens t ON t.value_hash = c.value_hash
                  JOIN requests u ON u.id = t.request_id
                WHERE c.ip_id = ?1 AND u.ip_id != ?1),
               (SELECT COUNT(DISTINCT c.ip_id) FROM requests u
                  JOIN request_tokens t ON t.request_id = u.id
                  JOIN canaries c ON c.value_hash = t.value_hash
                WHERE u.ip_id = ?1 AND c.ip_id != ?1)",
        )
        .bind(ip_id)
        .fetch_one(&self.read)
        .await?)
    }
}
```

`src/admin/pages.rs` — `RequestPage` gains:
```rust
    /// Canaries this request was served (kind, value) and where its links point.
    served: Vec<(String, String)>,
    return_host: Option<String>,
    /// Reuses where this request is either side.
    reuses: Vec<crate::store::canaries::Reuse>,
```
and `request_page` fills them:
```rust
    let name = d.row.answer.as_deref().and_then(|a| a.strip_prefix("decoy:"));
    let served = match (d.row.page_token.as_deref(), name) {
        (Some(t), Some(n)) => crate::canary::served(d.row.decoy_v, t, n)
            .into_iter()
            .map(|(k, v)| (k.name().to_string(), v))
            .collect(),
        _ => vec![],
    };
    let origin = st.store.request_origin(id).await?;
    let return_host = (!served.is_empty() && d.row.decoy_v.is_some()).then(|| {
        let site = crate::canary::site::site(origin.as_deref());
        crate::canary::site::return_host(crate::canary::site::request_host(&d.headers), &site)
    });
    let reuses = st
        .store
        .reuses(&crate::store::canaries::ReuseFilter {
            request: Some(id),
            range: Range::All,
            limit: 50,
            ..Default::default()
        })
        .await?;
```
Add to `src/store/inspect.rs`:
```rust
    /// The recording node's key of a request (None on a standalone node).
    pub async fn request_origin(&self, id: i64) -> Result<Option<Vec<u8>>> {
        Ok(sqlx::query_scalar("SELECT origin FROM requests WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.read)
            .await?
            .flatten())
    }
```
`templates/request.html` — after the Labels section:
```html
  {% if !served.is_empty() %}<section class="card" id="canaries"><div class="card-head"><h2>Canaries served</h2><span class="muted">{{ served.len() }}{% if let Some(h) = return_host %} · links point to <span class="mono">{{ h }}</span>{% endif %}</span></div>
    <table class="table"><thead><tr><th>Kind</th><th>Value</th></tr></thead><tbody>
    {% for (k, v) in served %}<tr><td>{{ k }}</td><td class="mono">{{ v }}</td></tr>{% endfor %}
    </tbody></table></section>{% endif %}
  {% if !reuses.is_empty() %}<section class="card" id="canary-reuse"><h2>Canary reuse</h2>
    <table class="table"><thead><tr><th>Harvested</th><th>Used</th><th>Kind</th><th>Where</th><th>Δt</th></tr></thead><tbody>
    {% for r in reuses %}<tr>
      <td>{% if let Some(s) = r.served_request_id %}<a href="/admin/requests/{{ s }}">#{{ s }}</a>{% else %}light row{% endif %} · <a href="/ip/{{ r.served_ip }}">{{ r.served_ip }}</a>{% if let Some(n) = r.served_node %} · <span class="muted">{{ n }}</span>{% endif %}</td>
      <td><a href="/admin/requests/{{ r.used_request_id }}">#{{ r.used_request_id }}</a> · <a href="/ip/{{ r.used_ip }}">{{ r.used_ip }}</a>{% if r.same_source %} <span class="badge">same source</span>{% endif %}</td>
      <td>{{ r.kind }}</td><td class="mono">{{ r.place }}</td><td>{{ crate::admin::views::duration(r.delta_s) }}</td>
    </tr>{% endfor %}
    </tbody></table></section>{% endif %}
```
Add to `src/admin/views.rs`:
```rust
/// A time span for people: `45 s`, `12 min`, `3 h 5 min`, `2 d 4 h`.
pub fn duration(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", s / 60),
        3600..86400 => format!("{} h {} min", s / 3600, s % 3600 / 60),
        _ => format!("{} d {} h", s / 86400, s % 86400 / 3600),
    }
}
```
with a unit test `assert_eq!(duration(10_800), "3 h 0 min"); assert_eq!(duration(-5), "0 s"); assert_eq!(duration(200_000), "2 d 7 h");`.

`src/admin/public.rs` — `IpAdminData` gains `pub canary_links: (i64, i64),`, filled with `state.store.canary_links_for_ip(ip.id).await?`. `templates/ip.html`, in the admin block after the host-keys section:
```html
  {% if adm.canary_links.0 > 0 || adm.canary_links.1 > 0 %}
  <section class="card" id="canaries">
    <h2>Canaries</h2>
    {% if adm.canary_links.0 > 0 %}<p>Credentials harvested here were used by {{ adm.canary_links.0 }} other IP{% if adm.canary_links.0 != 1 %}s{% endif %}.</p>{% endif %}
    {% if adm.canary_links.1 > 0 %}<p>Used credentials harvested by {{ adm.canary_links.1 }} other IP{% if adm.canary_links.1 != 1 %}s{% endif %}.</p>{% endif %}
    <p><a href="/admin/canaries?ip={{ ov.ip }}">Show the reuses</a></p>
  </section>
  {% endif %}
```
(Use the field that holds the IP's address in `IpOverview`; check `templates/ip.html` for the name it already uses in links.) The test's wording "used by 1 other IP" must match this text.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/store src/admin templates
git commit -m "admin: canaries served and reuses on request and IP pages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Canaries page and summary

**Files:**
- Create: `templates/admin_canaries.html`
- Modify: `src/store/canaries.rs` (summary), `src/admin/pages.rs` (route, handler), `templates/_admin_nav.html`, `templates/admin_analytics.html`

**Interfaces:**
- Produces:
```rust
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct KindStat { pub kind: String, pub served: i64, pub reused: i64 }
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CanarySummary {
    pub served: i64,
    /// Served canaries used at least once by any request but their own.
    pub reused: i64,
    /// Median and maximum time from harvest to first use, seconds.
    pub median_s: Option<i64>,
    pub max_s: Option<i64>,
    pub per_kind: Vec<KindStat>,
}
impl CanarySummary { pub fn share_pct(&self) -> i64 }
impl Store { pub async fn canary_summary(&self, range: Range) -> Result<CanarySummary>; }
```
Period: canaries served in the range (`c.ts`).

- [ ] **Step 1: Write the failing tests**

In `src/store/canaries.rs` tests:
```rust
    #[tokio::test]
    async fn summary_counts_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        let now = chrono::Utc::now();
        let at = |h: i64| (now - chrono::Duration::hours(h)).format("%Y-%m-%d %H:%M:%S").to_string();
        apply(&mut conn, ctx, &req("srv", &at(10), "198.51.100.1", "/.git/config", "[]", "decoy:git-config", Some(1))).await.unwrap();
        apply(&mut conn, ctx, &req("env", &at(10), "198.51.100.1", "/.env", "[]", "decoy:dotenv", Some(1))).await.unwrap();
        apply(&mut conn, ctx, &req("u1", &at(8), "198.51.100.2", "/x", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        apply(&mut conn, ctx, &req("u2", &at(2), "198.51.100.3", "/x", &basic("deploy", &git_token("srv")), "not-found", None)).await.unwrap();
        drop(conn);
        let sum = s.canary_summary(crate::store::stats::Range::H24).await.unwrap();
        assert_eq!(sum.served, 8); // 1 git token + 7 in the .env
        assert_eq!(sum.reused, 1);
        assert_eq!(sum.median_s, Some(2 * 3600), "first use only");
        assert_eq!(sum.per_kind.iter().find(|k| k.kind == "git-token").map(|k| (k.served, k.reused)), Some((1, 1)));
        assert_eq!(sum.share_pct(), 13); // 1 of 8, rounded
    }
```
In `tests/integration.rs`:
```rust
#[tokio::test]
async fn canaries_page_lists_reuses_and_filters() {
    let (base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    c.get(format!("{base}/.git/config")).header("x-forwarded-for", "203.0.113.70").send().await.unwrap();
    let token = served_value(&store, "/.git/config", peephole::canary::Kind::GitToken).await;
    c.get(format!("{base}/x")).basic_auth("deploy", Some(&token)).header("x-forwarded-for", "203.0.113.71").send().await.unwrap();
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (admin, admin_base) = enrolled_admin_client(store.clone(), cfg).await;
    let page = admin.get(format!("{admin_base}/admin/canaries?range=all")).send().await.unwrap().text().await.unwrap();
    assert!(page.contains("203.0.113.71") && page.contains("git-token"), "{page}");
    let page = admin.get(format!("{admin_base}/admin/canaries?range=all&source=same")).send().await.unwrap().text().await.unwrap();
    assert!(!page.contains("203.0.113.71"));
    let nav = admin.get(format!("{admin_base}/admin")).send().await.unwrap().text().await.unwrap();
    assert!(nav.contains("href=\"/admin/canaries\""));
    let anon = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    assert_ne!(anon.get(format!("{admin_base}/admin/canaries")).send().await.unwrap().status(), 200);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib store::canaries::tests::summary && cargo test --test integration canaries_page`
Expected: FAIL / compile errors.

- [ ] **Step 3: Implement** the summary:
```rust
impl CanarySummary {
    pub fn share_pct(&self) -> i64 {
        if self.served == 0 { 0 } else { (self.reused * 100 + self.served / 2) / self.served }
    }
}

impl Store {
    pub async fn canary_summary(&self, range: crate::store::stats::Range) -> Result<CanarySummary> {
        let since = range.since();
        let window = if since.is_some() { " AND c.ts >= datetime('now', ?)" } else { "" };
        // Per served canary: its kind and its first use by another request.
        let mut q = sqlx::query_as::<_, (String, Option<i64>)>(sqlx::AssertSqlSafe(format!(
            "SELECT c.kind,
                    (SELECT MIN(CAST(strftime('%s', u.ts) AS INTEGER) - CAST(strftime('%s', c.ts) AS INTEGER))
                     FROM request_tokens t JOIN requests u ON u.id = t.request_id
                     WHERE t.value_hash = c.value_hash
                       AND (c.request_id IS NULL OR t.request_id != c.request_id))
             FROM canaries c WHERE 1 = 1{window}"
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let rows = q.fetch_all(&self.read).await?;
        let mut per: std::collections::BTreeMap<String, (i64, i64)> = Default::default();
        let mut firsts: Vec<i64> = vec![];
        for (kind, first) in &rows {
            let e = per.entry(kind.clone()).or_default();
            e.0 += 1;
            if let Some(f) = first {
                e.1 += 1;
                firsts.push((*f).max(0));
            }
        }
        firsts.sort_unstable();
        Ok(CanarySummary {
            served: rows.len() as i64,
            reused: firsts.len() as i64,
            median_s: (!firsts.is_empty()).then(|| firsts[firsts.len() / 2]),
            max_s: firsts.last().copied(),
            per_kind: per.into_iter().map(|(kind, (served, reused))| KindStat { kind, served, reused }).collect(),
        })
    }
}
```

In `src/admin/pages.rs` add the route `.route("/admin/canaries", get(canaries))` and:
```rust
#[derive(serde::Deserialize, Default)]
pub struct CanaryQuery {
    pub range: Option<String>,
    pub kind: Option<String>,
    pub node: Option<String>,
    /// `same` | `other`; anything else: both.
    pub source: Option<String>,
    pub ip: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_canaries.html")]
struct CanariesPage {
    chrome: Chrome,
    range: Range,
    q: CanaryQuery,
    sum: crate::store::canaries::CanarySummary,
    reuses: Vec<crate::store::canaries::Reuse>,
    kinds: Vec<&'static str>,
}

async fn canaries(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Query(q): Query<CanaryQuery>,
) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let ip_id = match q.ip.as_deref().filter(|s| !s.is_empty()) {
        Some(a) => st.store.ip_by_addr(a).await?.map(|i| i.id),
        None => None,
    };
    let filter = crate::store::canaries::ReuseFilter {
        kind: q.kind.clone().filter(|k| !k.is_empty()),
        node: q.node.clone().filter(|n| !n.is_empty()),
        same_source: match q.source.as_deref() {
            Some("same") => Some(true),
            Some("other") => Some(false),
            _ => None,
        },
        range,
        request: None,
        ip_id,
        limit: 500,
    };
    let reuses = st.store.reuses(&filter).await?;
    let sum = st.store.canary_summary(range).await?;
    render(&CanariesPage {
        chrome: chrome(),
        range,
        q,
        sum,
        reuses,
        kinds: crate::canary::Kind::ALL_V1.iter().map(|k| k.name()).chain(["legacy"]).collect(),
    })
}
```
`templates/admin_canaries.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — canaries{% endblock %}
{% block content %}
{% let sub = "canaries" %}{% include "_admin_nav.html" %}
<div class="page-head"><div><h1>Canaries</h1><p class="muted">Credentials served in decoys and the requests that used them again.</p></div>{% include "_range.html" %}</div>
<div class="stack">
<div class="tiles kpis">
  <div class="tile"><span class="label">Served</span><div class="value">{{ crate::admin::views::thousands(sum.served) }}</div></div>
  <div class="tile"><span class="label">Used again</span><div class="value brand">{{ sum.reused }}</div><div class="hint">{{ sum.share_pct() }} %</div></div>
  <div class="tile"><span class="label">Median to first use</span><div class="value">{% if let Some(m) = sum.median_s %}{{ crate::admin::views::duration(m) }}{% else %}—{% endif %}</div></div>
  <div class="tile"><span class="label">Longest</span><div class="value">{% if let Some(m) = sum.max_s %}{{ crate::admin::views::duration(m) }}{% else %}—{% endif %}</div></div>
</div>
{% if !sum.per_kind.is_empty() %}<section class="card"><h2>Per kind</h2><table class="table"><thead><tr><th>Kind</th><th>Served</th><th>Used again</th></tr></thead><tbody>
{% for k in sum.per_kind %}<tr><td>{{ k.kind }}</td><td>{{ k.served }}</td><td>{{ k.reused }}</td></tr>{% endfor %}
</tbody></table></section>{% endif %}
<section class="card">
  <form class="filters" method="get" action="/admin/canaries">
    <input type="hidden" name="range" value="{{ range.as_str() }}">
    <label>Kind <select name="kind"><option value="">any</option>{% for k in kinds %}<option{% if q.kind.as_deref() == Some(k) %} selected{% endif %}>{{ k }}</option>{% endfor %}</select></label>
    <label>Node <input name="node" value="{{ q.node.as_deref().unwrap_or_default() }}"></label>
    <label>Source <select name="source"><option value="">any</option><option value="other"{% if q.source.as_deref() == Some("other") %} selected{% endif %}>different</option><option value="same"{% if q.source.as_deref() == Some("same") %} selected{% endif %}>same</option></select></label>
    <label>IP <input name="ip" value="{{ q.ip.as_deref().unwrap_or_default() }}"></label>
    <button>Filter</button>
  </form>
  {% if reuses.is_empty() %}<p class="empty">No canary has been used again{% if range.since().is_some() %} in this period{% endif %}.</p>{% else %}
  <table class="table"><thead><tr><th>Harvested</th><th>Used</th><th>Kind</th><th>Where</th><th>Δt</th></tr></thead><tbody>
  {% for r in reuses %}<tr>
    <td>{% if let Some(s) = r.served_request_id %}<a href="/admin/requests/{{ s }}">#{{ s }}</a>{% else %}light row{% endif %} · <a href="/ip/{{ r.served_ip }}">{{ r.served_ip }}</a>{% if let Some(n) = r.served_node %} · <span class="muted">{{ n }}</span>{% endif %}{% if let Some(a) = r.served_answer %} · <span class="mono">{{ a }}</span>{% endif %} · <span class="mono">{{ r.served_ts }}</span></td>
    <td><a href="/admin/requests/{{ r.used_request_id }}">#{{ r.used_request_id }}</a> · <a href="/ip/{{ r.used_ip }}">{{ r.used_ip }}</a>{% if let Some(n) = r.used_node %} · <span class="muted">{{ n }}</span>{% endif %} · <span class="mono">{{ r.used_ts }}</span>{% if r.same_source %} <span class="badge">same source</span>{% endif %}</td>
    <td>{{ r.kind }}</td><td class="mono">{{ r.place }}</td><td>{{ crate::admin::views::duration(r.delta_s) }}</td>
  </tr>{% endfor %}
  </tbody></table>{% endif %}
</section>
</div>
{% endblock %}
```
Check `templates/_range.html` for the variables it expects (it is included by the analytics page with `range` in scope) and match them; if it builds links from a base path, pass `/admin/canaries`.

`templates/_admin_nav.html`: insert `("canaries", "/admin/canaries", "Canaries"),` right after the fingerprints entry. `templates/admin_analytics.html`: add near the top of the content `<p class="muted">Canary reuse: <a href="/admin/canaries?range={{ range.as_str() }}">Canaries</a></p>`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src templates
git commit -m "admin: canaries page with summary, reuse table and filters

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Render command

**Files:**
- Modify: `src/canary/cli.rs`, `src/main.rs`
- Test: `src/canary/cli.rs`, `src/main.rs` tests, `tests/integration.rs` (`a_served_decoy_renders_again_from_its_row` from Task 6)

**Interfaces:**
- Produces:
  - `canary::cli::render_uid(store: &Store, uid: &str) -> Result<Option<Decoy>>` — a full row by its uid, or a light row by `<batch uid>#<rowid>` (the export's uid)
  - `canary::cli::run(args: &[String], default_config: &str) -> Result<()>`
  - `canary::cli::USAGE`

- [ ] **Step 1: Write the failing tests**

In `src/canary/cli.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    #[tokio::test]
    async fn a_light_row_renders_like_a_full_one() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        apply(&mut conn, Ctx { origin: None, hlc: 1 }, &Record::SkipBatch(SkipBatchRec {
            uid: "b1".into(),
            ip: "198.51.100.3".into(),
            dropped: 0,
            rows: vec![SkipRow { ts_ms: 1_791_000_000_000, method: "GET".into(), path: "/.env".into(), page_token: Some("tok".into()), host: Some("203.0.113.7".into()), answer: Some("decoy:dotenv".into()), decoy_v: Some(1) }],
            build: String::new(),
        })).await.unwrap();
        drop(conn);
        let rowid: i64 = sqlx::query_scalar("SELECT rowid FROM skipped_requests").fetch_one(&s.pool).await.unwrap();
        let d = render_uid(&s, &format!("b1#{rowid}")).await.unwrap().unwrap();
        let want = crate::trap::decoy::render(&crate::trap::decoy::Input { v: 1, page_token: "tok", host: Some("203.0.113.7"), node_id: None, ts: 1_791_000_000, method: "GET", path: "/.env" }, "dotenv").unwrap();
        assert_eq!(d, want);
        assert!(render_uid(&s, "nope").await.unwrap().is_none());
    }
}
```
In `src/main.rs` tests, add `assert_eq!(p(&["decoy", "render", "x"]), Ok(Cmd::Decoy));`.
Move `a_served_decoy_renders_again_from_its_row` into `tests/integration.rs` now if Task 6 left it out.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib canary::cli && cargo test --bin peephole`
Expected: compile errors.

- [ ] **Step 3: Implement** `src/canary/cli.rs`:
```rust
//! `peephole decoy render <uid>`: the decoy a stored row was answered with,
//! rendered again from the row, byte for byte.
use crate::config::Config;
use crate::store::Store;
use crate::trap::decoy::{Decoy, Input, render};
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole decoy render UID [CONFIG]
       UID is a request's uid, or a light row's <batch uid>#<row> as the export writes it.
       Prints the status line, headers and body the trap sent.";

/// The decoy of the row `uid` (None: no such row, or not a decoy).
pub async fn render_uid(store: &Store, uid: &str) -> Result<Option<Decoy>> {
    if let Some((batch, row)) = uid.split_once('#') {
        let r: Option<(i64, String, String, Option<String>, Option<String>, Option<String>, Option<i64>, Option<Vec<u8>>)> =
            sqlx::query_as(
                "SELECT s.ts_ms, s.method, s.path, s.page_token, s.host, s.answer, s.decoy_v, b.origin
                 FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
                 WHERE b.uid = ? AND s.rowid = ?",
            )
            .bind(batch)
            .bind(row.parse::<i64>().unwrap_or(-1))
            .fetch_optional(&store.read)
            .await?;
        let Some((ts_ms, method, path, Some(tok), host, Some(answer), v, origin)) = r else {
            return Ok(None);
        };
        let Some(name) = answer.strip_prefix("decoy:") else { return Ok(None) };
        return Ok(render(
            &Input { v: v.unwrap_or(0), page_token: &tok, host: host.as_deref(), node_id: origin.as_deref(), ts: ts_ms.div_euclid(1000), method: &method, path: &path },
            name,
        ));
    }
    let r: Option<(String, String, String, String, Option<String>, Option<String>, Option<i64>, Option<Vec<u8>>)> =
        sqlx::query_as(
            "SELECT ts, method, path, headers_json, page_token, answer, decoy_v, origin
             FROM requests WHERE uid = ?",
        )
        .bind(uid)
        .fetch_optional(&store.read)
        .await?;
    let Some((ts, method, path, headers_json, Some(tok), Some(answer), v, origin)) = r else {
        return Ok(None);
    };
    let Some(name) = answer.strip_prefix("decoy:") else { return Ok(None) };
    let headers: Vec<(String, String)> = serde_json::from_str(&headers_json).unwrap_or_default();
    let ts = chrono::NaiveDateTime::parse_from_str(&ts, "%Y-%m-%d %H:%M:%S")
        .map(|t| t.and_utc().timestamp())
        .unwrap_or(0);
    Ok(render(
        &Input {
            v: v.unwrap_or(0),
            page_token: &tok,
            host: crate::canary::site::request_host(&headers),
            node_id: origin.as_deref(),
            ts,
            method: &method,
            path: &path,
        },
        name,
    ))
}

/// Run `decoy …`; `args` excludes `decoy` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let (Some("render"), Some(uid)) = (args.first().map(String::as_str), args.get(1)) else {
        bail!("{USAGE}");
    };
    let config = args.get(2).map(String::as_str).unwrap_or(default_config);
    let cfg = Config::load(Path::new(config))?;
    let store = Store::connect(&cfg.database_path).await?;
    let Some(d) = render_uid(&store, uid).await? else {
        bail!("no decoy row with uid {uid}");
    };
    println!("{}", d.status);
    for (k, v) in &d.headers {
        println!("{k}: {v}");
    }
    println!();
    print!("{}", d.body);
    Ok(())
}
```
The `node_id` of a version-1 row is its `origin` (the recording node's key); on a standalone node it is NULL, matching what the trap used (`recorder.node_id()` is None there). Check that `Store` exposes `read` to this module (`pub(crate)` or `pub`); if not, use `&store.pool`.

`src/main.rs`: add `Decoy` to `Cmd`, `Some("decoy") => Ok(Cmd::Decoy),` to `parse`, the usage line `       peephole decoy render UID [CONFIG]  print a stored decoy answer again`, and:
```rust
        Cmd::Decoy => {
            if args.get(1).is_some_and(|a| a == "--help" || a == "-h") {
                println!("{}", peephole::canary::cli::USAGE);
            } else if let Err(e) = peephole::canary::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS, including `a_served_decoy_renders_again_from_its_row` (the trap's live body equals the rendered one).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/canary/cli.rs src/main.rs tests/integration.rs
git commit -m "cli: peephole decoy render

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Public wall tile

**Files:**
- Modify: `src/store/stats.rs` (`Stats`, the function that builds it), `templates/wall.html`, `src/admin/public.rs` tests

**Interfaces:**
- Consumes: `Store::canary_summary`
- Produces: `Stats.canaries: Option<CanaryTile>`; `pub struct CanaryTile { pub median_s: i64, pub share_pct: i64, pub reused: i64 }` (`Clone, Debug, serde::Serialize`), set only when `reused >= CANARY_TILE_MIN` (`pub const CANARY_TILE_MIN: i64 = 5;`).

- [ ] **Step 1: Write the failing test** in `src/admin/public.rs` tests (follow `admin_wall_reads_past_the_cache` for setting up `st`):
```rust
    #[tokio::test]
    async fn canary_tile_shows_only_from_five_reuses() {
        let (st, _dir) = state().await; // the helper the other wall tests use
        let mut conn = st.store.pool.acquire().await.unwrap();
        let ctx = crate::store::data::Ctx { origin: None, hlc: 1 };
        let now = chrono::Utc::now();
        let ts = |h: i64| (now - chrono::Duration::hours(h)).format("%Y-%m-%d %H:%M:%S").to_string();
        let rec = |uid: &str, ts: String, ip: &str, path: &str, headers: String, answer: &str, v: Option<i64>| {
            crate::cluster::record::Record::Request(Box::new(crate::cluster::record::RequestRec {
                uid: uid.into(), ts, ip: ip.into(), method: "GET".into(), path: path.into(),
                headers_json: headers, labels_json: "[]".into(), page_token: Some(format!("tok-{uid}")),
                answer: Some(answer.into()), decoy_v: v, ..Default::default()
            }))
        };
        for i in 0..5 {
            let srv = format!("s{i}");
            crate::store::data::apply(&mut conn, ctx, &rec(&srv, ts(5), "198.51.100.1", "/.git/config", "[]".into(), "decoy:git-config", Some(1))).await.unwrap();
            if i < 4 {
                let token = crate::canary::value(&format!("tok-{srv}"), crate::canary::Kind::GitToken);
                let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
                crate::store::data::apply(&mut conn, ctx, &rec(&format!("u{i}"), ts(1), "198.51.100.2", "/x", format!(r#"[["authorization","Basic {auth}"]]"#), "not-found", None)).await.unwrap();
            }
        }
        drop(conn);
        assert!(st.store.stats(Range::H24).await.unwrap().canaries.is_none(), "4 reuses: hidden");
        let mut conn = st.store.pool.acquire().await.unwrap();
        let token = crate::canary::value("tok-s4", crate::canary::Kind::GitToken);
        let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
        crate::store::data::apply(&mut conn, ctx, &rec("u4", ts(1), "198.51.100.3", "/x", format!(r#"[["authorization","Basic {auth}"]]"#), "not-found", None)).await.unwrap();
        drop(conn);
        let t = st.store.stats(Range::H24).await.unwrap().canaries.unwrap();
        assert_eq!((t.reused, t.median_s, t.share_pct), (5, 4 * 3600, 100));
        let html = get(&st, "/").await; // as the other wall tests fetch it
        assert!(html.contains("Harvest to first use"));
        assert!(!html.contains(&token));
    }
```
(Use the test module's existing helpers for building `st` and fetching `/`; their names are in `src/admin/public.rs`'s tests around line 915–985.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib admin::public::tests::canary_tile`
Expected: compile error (`canaries` field missing).

- [ ] **Step 3: Implement** — in `src/store/stats.rs` add the struct, the const and the field (`pub canaries: Option<CanaryTile>,` after `intel`), and where `Stats` is built:
```rust
        let sum = self.canary_summary(range).await?;
        let canaries = (sum.reused >= CANARY_TILE_MIN).then(|| CanaryTile {
            median_s: sum.median_s.unwrap_or(0),
            share_pct: sum.share_pct(),
            reused: sum.reused,
        });
```
Every other `Stats { … }` literal (tests) gets `canaries: None`. `templates/wall.html`, as the last tile in the `kpis` block:
```html
  {% if let Some(c) = stats.canaries %}<div class="tile"><span class="label">Harvest to first use</span><div class="value">{{ crate::admin::views::duration(c.median_s) }}</div><div class="hint">median · {{ c.share_pct }} % of harvested credentials used again</div></div>{% endif %}
```
The tile is part of `/api/stats` too (it serializes); it holds aggregates only.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/store/stats.rs src/admin/public.rs templates/wall.html
git commit -m "wall: harvest-to-first-use tile

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Export columns

**Files:**
- Modify: `src/store/export.rs` (`ReqRow`, `SkipOut`, their `SELECT`s, `PageContext`, `export_context`), `src/export/mod.rs` (`ExportRow`, `COLUMNS`, JSON/CSV writers, `request_row`, `skipped_row`), `src/export/parquet.rs` (schema and arrays)

**Interfaces:**
- Produces: export columns `decoy_v` (int?) after `answer`, and `canary_used_from` (list of uids; CSV: JSON array text) after `fp_claim`... place it right after `decoy_v` so the two stay together.
- `PageContext.canary_used_from: HashMap<i64 /* request id */, Vec<String>>`; `export_context` gains a `request_ids: &[i64]` parameter.

- [ ] **Step 1: Write the failing test** in `src/export/mod.rs` tests (next to the test asserting `r["answer"] == "not-found"` around line 1124; reuse its store setup):
```rust
    #[tokio::test]
    async fn export_names_decoy_version_and_canary_sources() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = crate::store::data::Ctx { origin: None, hlc: 1 };
        let rec = |uid: &str, path: &str, headers: String, answer: &str, v: Option<i64>| {
            crate::cluster::record::Record::Request(Box::new(crate::cluster::record::RequestRec {
                uid: uid.into(), ts: "2026-10-04 10:00:00".into(), ip: "198.51.100.1".into(), method: "GET".into(),
                path: path.into(), headers_json: headers, labels_json: "[]".into(),
                page_token: Some(format!("tok-{uid}")), answer: Some(answer.into()), decoy_v: v, ..Default::default()
            }))
        };
        crate::store::data::apply(&mut conn, ctx, &rec("srv", "/.git/config", "[]".into(), "decoy:git-config", Some(1))).await.unwrap();
        let token = crate::canary::value("tok-srv", crate::canary::Kind::GitToken);
        let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
        crate::store::data::apply(&mut conn, ctx, &rec("use", "/x", format!(r#"[["authorization","Basic {auth}"]]"#), "not-found", None)).await.unwrap();
        drop(conn);
        let rows = jsonl_rows(&s).await; // the helper the neighbouring tests use to export as JSON Lines
        let srv = rows.iter().find(|r| r["uid"] == "srv").unwrap();
        let used = rows.iter().find(|r| r["uid"] == "use").unwrap();
        assert_eq!(srv["decoy_v"], 1);
        assert_eq!(used["decoy_v"], serde_json::Value::Null);
        assert_eq!(used["canary_used_from"], serde_json::json!(["srv"]));
        assert_eq!(srv["canary_used_from"], serde_json::json!([]));
        assert!(!rows.iter().any(|r| r.to_string().contains(&token)), "canary values are not exported");
        assert!(COLUMNS.contains(&"decoy_v") && COLUMNS.contains(&"canary_used_from"));
    }
```
(If no `jsonl_rows` helper exists, export with `Format::Jsonl` into a `Vec<u8>` the way the existing JSONL test does and parse each line.)

Note the `assert!(!…contains(&token))` check: the using row's `headers` column contains the Basic header in base64, not the token in plain text, so it holds.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib export::tests::export_names_decoy`
Expected: FAIL.

- [ ] **Step 3: Implement**
- `ReqRow` gains `decoy_v: Option<i64>` (add `r.decoy_v` to its `SELECT`); `SkipOut` gains `decoy_v: Option<i64>` (`s.decoy_v`).
- `PageContext` gains `pub canary_used_from: HashMap<i64, Vec<String>>`. In `export_context(…, request_ids: &[i64])`:
```rust
        let used: Vec<(i64, String)> = sqlx::query_as(
            "SELECT DISTINCT t.request_id,
                    COALESCE(sr.uid, CAST(sr.id AS TEXT), sb.uid || '#' || c.skip_rowid)
             FROM request_tokens t
             JOIN canaries c ON c.value_hash = t.value_hash
             LEFT JOIN requests sr ON sr.id = c.request_id
             LEFT JOIN skipped_batches sb ON sb.id = c.batch_id
             WHERE t.request_id IN (SELECT value FROM json_each(?))
               AND (c.request_id IS NULL OR c.request_id != t.request_id)
             ORDER BY 1, 2",
        )
        .bind(json_list(request_ids))
        .fetch_all(&self.read)
        .await?;
        for (id, uid) in used {
            c.canary_used_from.entry(id).or_default().push(uid);
        }
```
  Pass the page's request ids from the caller in `src/export/mod.rs` (where it already collects `request_uids`).
- `ExportRow` gains `pub decoy_v: Option<i64>, pub canary_used_from: Vec<String>,`; `request_row` sets `decoy_v: r.decoy_v, canary_used_from: ctx.canary_used_from.get(&r.id).cloned().unwrap_or_default(),` (read `r.id` before `r` is moved); `skipped_row` sets `decoy_v: s.decoy_v`.
- `COLUMNS`: insert `"decoy_v", "canary_used_from",` after `"answer"`. JSON writer: `"decoy_v": self.decoy_v, "canary_used_from": self.canary_used_from,`. CSV writer: follow how `labels` (a list) is written, for `canary_used_from`; `decoy_v` like `status`.
- `src/export/parquet.rs`: `i("decoy_v", true)` after `s("answer", true)`, and a list-of-strings column `canary_used_from` built the way `labels` is; add the arrays in the same order.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS (the CSV header test and the Parquet round-trip test pick up the new columns; update their expected column lists where they pin them).

- [ ] **Step 5: Commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add src/export src/store/export.rs
git commit -m "export: decoy_v and canary_used_from

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Documentation and roadmap

**Files:**
- Modify: `docs/dataset.md`, `CHANGELOG.md`, `docs/roadmap.md`, `README.md` (only if it lists the decoys or admin pages), `docs/superpowers/specs/2026-10-04-canary-reuse-design.md` (no change unless implementation deviated)

- [ ] **Step 1: `docs/dataset.md`**
  - In the column table, after `answer`: `decoy_v` (int?): decoy template version of a decoy answer; empty for other answers; empty on a decoy row means version 0. `canary_used_from` (list of uids): the rows whose served canaries this row carried (light rows as `<batch uid>#<row>`).
  - Extend `answer`'s description with the new values: `decoy:wp-login-ok`, `decoy:wp-admin`, `decoy:admin`, `decoy:git-auth`, `decoy:git-refs`, `decoy:git-pack`.
  - A new section "Canaries" with: the derivation formula exactly as in Global Constraints, the per-kind formats table from the spec, the site word list and its derivation, the return-host rule, version 0 (`canary-<ref>`, `AKIACANARY<REF10>`, `canary/<ref>/not+a+real+secret`), and that `peephole decoy render <uid>` reproduces any decoy.

- [ ] **Step 2: `CHANGELOG.md`** under `[Unreleased]`:
  - Added: "Canaries that come back. Decoys serve realistic credentials derived from the request (`.env`: AWS, app key, database, Redis, mail and admin passwords; `.git/config`: a deploy token), with links to the address the scanner used. A harvested password opens a fake admin page (Basic auth) or WordPress dashboard, and the git token a ref listing, so the follow-up lands in the trap. Every node finds requests carrying a served canary, cluster-wide and in either arrival order, and names the request that harvested it."
  - Added: "Admin: a Canaries page (served, used again, time to first use, reuse table with filters); request and IP pages show canaries served and reuses. Wall: median time from harvest to first use and the share used again, from 5 reuses up. Export: `decoy_v`, `canary_used_from`. `peephole decoy render UID` prints a stored decoy again."
  - Changed: "Decoy answers to sources over their recording rate keep their page token, host and answer in the light row, so their canaries are traceable."

- [ ] **Step 3: `docs/roadmap.md`**
  - Remove item 1 and renumber the rest (2 → 1, …), fixing the cross-references ("item 2" in campaign clustering becomes "item 1", "item 1" there becomes "the canaries (shipped)", and so on through the file).
  - Add under "Small follow-ups":
    "- **Peer-observed public address.** S–M, medium. A NAT'd node cannot see its public IP; peers report the source address they see on its RPC connections. That replaces `cluster.own_addresses` for NAT'd nodes, records which of our addresses a request reached, and lets the canary return host cover `localhost` and missing Hosts (a new `decoy_v`)."

- [ ] **Step 4: Check the docs build nothing broken**

Run: `cargo test && grep -n "item [0-9]" docs/roadmap.md`
Expected: tests PASS; every "item N" reference points at the right item.

- [ ] **Step 5: Commit**

```bash
git add docs CHANGELOG.md README.md
git commit -m "docs: canaries in the dataset docs, changelog and roadmap

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Self-review notes

- Spec coverage: data (T4, T5), decoy content (T1, T3), serving and precedence (T3, T6), detection with headers first (T2, T5), display (T7, T8, T10), export (T11), render command (T9), testing (each task), docs (T12).
- Known gap kept on purpose (spec): requests past the light-row cap (`dropped`) are counted only; their canaries cannot be traced.
- The `node_id` input is the row's `origin`; on a standalone node both the trap (`recorder.node_id()` = None) and the render (`origin` NULL) use None.
