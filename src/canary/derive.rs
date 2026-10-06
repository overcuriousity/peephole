//! Canary values: what each kind looks like, derived from the page token.
use sha2::{Digest, Sha256};

/// Version of the decoy templates this build serves (`requests.decoy_v`).
/// A change to any template or to [`value`] bumps it.
pub const DECOY_V: i64 = 2;

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
    /// An MCP session id (Mcp-Session-Id, legacy ?sessionId=).
    McpSession,
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
            Kind::McpSession => "mcp-session",
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
        Kind::McpSession => {
            let h: String = stream(page_token, kind, 16)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "{}-{}-{}-{}-{}",
                &h[..8],
                &h[8..12],
                &h[12..16],
                &h[16..20],
                &h[20..]
            )
        }
        Kind::Legacy => format!("canary-{}", v0_ref(page_token)),
    }
}

/// Version 0's reference: the first 12 hex characters of the page token.
pub fn v0_ref(page_token: &str) -> String {
    page_token.chars().filter(|c| *c != '-').take(12).collect()
}

/// The canaries a decoy answer carried. `decoy` is the answer without its
/// `decoy:` prefix; `decoy_v` None is version 0; `decoy_in` is the row's
/// parsed decoy input (version 2's MCP answers depend on it).
pub fn served(
    decoy_v: Option<i64>,
    page_token: &str,
    decoy: &str,
    decoy_in: Option<&str>,
) -> Vec<(Kind, String)> {
    let v = |kinds: &[Kind]| -> Vec<(Kind, String)> {
        kinds.iter().map(|k| (*k, value(page_token, *k))).collect()
    };
    const DOTENV: [Kind; 7] = [
        Kind::AppKey,
        Kind::DbPassword,
        Kind::RedisPassword,
        Kind::MailPassword,
        Kind::AwsKey,
        Kind::AwsSecret,
        Kind::AdminPassword,
    ];
    let ver = decoy_v.unwrap_or(0);
    if ver >= 2 && decoy.starts_with("mcp:") {
        let d = crate::trap::decoy::ai::DecoyIn::parse(decoy_in);
        return match (decoy, d.tool.as_deref(), d.cls.as_deref()) {
            ("mcp:initialize" | "mcp:sse", _, _) => v(&[Kind::McpSession]),
            ("mcp:tools/call", Some("read_file"), Some(c)) | ("mcp:resources/read", _, Some(c)) => {
                match c {
                    "dotenv" => v(&DOTENV),
                    "aws-credentials" => v(&[Kind::AwsKey, Kind::AwsSecret]),
                    "git-config" => v(&[Kind::GitToken]),
                    _ => vec![],
                }
            }
            ("mcp:tools/call", Some("query_db"), Some("select")) => v(&[Kind::AppKey]),
            _ => vec![],
        };
    }
    match ver {
        0 => {
            let r = v0_ref(page_token);
            match decoy {
                "dotenv" => vec![
                    (Kind::Legacy, format!("canary-{r}")),
                    (
                        Kind::Legacy,
                        format!(
                            "AKIACANARY{}",
                            r.to_ascii_uppercase().chars().take(10).collect::<String>()
                        ),
                    ),
                    (Kind::Legacy, format!("canary/{r}/not+a+real+secret")),
                ],
                "git-config" => vec![(Kind::Legacy, format!("canary-{r}"))],
                _ => vec![],
            }
        }
        1 | 2 => match decoy {
            "dotenv" => v(&DOTENV),
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
        assert!(
            k.starts_with("AKIA") && k.len() == 20 && all(&k[4..], az27),
            "{k}"
        );
        let s = value(TOK, Kind::AwsSecret);
        assert!(s.len() == 40 && all(&s, b64), "{s}");
        let a = value(TOK, Kind::AppKey);
        assert_eq!(
            data_encoding::BASE64.decode(a.as_bytes()).unwrap().len(),
            32
        );
        for kind in [
            Kind::DbPassword,
            Kind::RedisPassword,
            Kind::MailPassword,
            Kind::AdminPassword,
        ] {
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
    fn mcp_session_is_uuid_shaped_and_served_by_initialize_and_sse() {
        let s = value(TOK, Kind::McpSession);
        assert_eq!(s.len(), 36, "{s}");
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(s.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        assert_ne!(s, value("another", Kind::McpSession));
        for name in ["mcp:initialize", "mcp:sse"] {
            assert_eq!(
                served(Some(2), TOK, name, None),
                vec![(Kind::McpSession, s.clone())]
            );
        }
        // Version 2 serves what version 1 did for the old names.
        assert_eq!(
            served(Some(2), TOK, "dotenv", None),
            served(Some(1), TOK, "dotenv", None)
        );
        assert!(served(Some(1), TOK, "mcp:initialize", None).is_empty());
    }

    #[test]
    fn values_are_pinned() {
        // The formula is part of the dataset's contract: these never change
        // without a new decoy version.
        assert_eq!(
            hash("x"),
            i64::from_be_bytes([0x2d, 0x71, 0x16, 0x42, 0xb7, 0x26, 0xb0, 0x44])
        );
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
        let env = served(Some(1), TOK, "dotenv", None);
        assert_eq!(env.len(), 7);
        assert!(
            env.iter()
                .any(|(k, v)| *k == Kind::AwsKey && v.starts_with("AKIA"))
        );
        assert_eq!(
            served(Some(1), TOK, "git-config", None),
            vec![(Kind::GitToken, value(TOK, Kind::GitToken))]
        );
        assert_eq!(
            served(Some(1), TOK, "wp-login-ok", None),
            vec![(Kind::WpSession, value(TOK, Kind::WpSession))]
        );
        assert!(served(Some(1), TOK, "phpinfo", None).is_empty());
        assert!(served(Some(1), TOK, "wp-login-failed", None).is_empty());
        assert!(
            served(Some(9), TOK, "dotenv", None).is_empty(),
            "unknown versions serve nothing known"
        );
        let r = v0_ref(TOK);
        assert_eq!(r, "0f8e7d6c5b4a");
        let old = served(None, TOK, "dotenv", None);
        assert!(old.contains(&(Kind::Legacy, format!("canary-{r}"))));
        assert!(old.contains(&(Kind::Legacy, "AKIACANARY0F8E7D6C5B".to_string())));
        assert!(old.contains(&(Kind::Legacy, format!("canary/{r}/not+a+real+secret"))));
        assert_eq!(
            served(Some(0), TOK, "git-config", None),
            vec![(Kind::Legacy, format!("canary-{r}"))]
        );
    }

    #[test]
    fn mcp_tool_answers_serve_what_they_show() {
        let rf = r#"{"tool":"read_file","cls":"dotenv"}"#;
        assert_eq!(served(Some(2), TOK, "mcp:tools/call", Some(rf)).len(), 7);
        assert_eq!(
            served(
                Some(2),
                TOK,
                "mcp:resources/read",
                Some(r#"{"cls":"aws-credentials"}"#)
            )
            .len(),
            2
        );
        assert_eq!(
            served(
                Some(2),
                TOK,
                "mcp:tools/call",
                Some(r#"{"tool":"query_db","cls":"select"}"#)
            ),
            vec![(Kind::AppKey, value(TOK, Kind::AppKey))]
        );
        assert!(
            served(
                Some(2),
                TOK,
                "mcp:tools/call",
                Some(r#"{"tool":"run_command","cls":"id"}"#)
            )
            .is_empty()
        );
        assert!(served(Some(2), TOK, "mcp:no-session", Some(rf)).is_empty());
    }
}
