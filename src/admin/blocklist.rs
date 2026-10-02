//! `/api/blocklist`: the addresses that sent requests of a given severity
//! in a time window, as plain text for nginx `deny`, nftables sets, ipset,
//! fail2ban or CrowdSec. Public, like the IP directory it is drawn from:
//! only addresses and prefixes leave this node, never request contents.
//!
//! Excluded, so that a member's real sites never block what the trap
//! would never scan: Tor exits, addresses a scanner refused as a verified
//! crawler, cluster members' addresses, this node's own addresses and its
//! `never_scan` networks, and non-global addresses.
use crate::admin::AdminState;
use axum::{
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_HOURS: u32 = 24;
pub const MAX_HOURS: u32 = 24 * 30;
pub const DEFAULT_MIN_SEVERITY: i64 = 3;
/// Entries per response; the newest come first.
pub const MAX_ENTRIES: i64 = 50_000;
/// A /24 (or IPv6 /64) with this many listed addresses is emitted as one
/// prefix when `networks=1` is asked.
pub const NET_MIN_IPS: usize = 3;
/// The response is recomputed at most this often per parameter set.
pub const TTL: Duration = Duration::from_secs(60);
/// Distinct parameter sets cached.
pub const CACHE_MAX: usize = 32;

/// Raw query parameters: every value is lenient, an unusable one means
/// its default (a wrong value must not make a firewall script fail open).
#[derive(serde::Deserialize, Default, Debug)]
pub struct RawParams {
    pub hours: Option<String>,
    pub min_severity: Option<String>,
    pub networks: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub hours: u32,
    pub min_severity: i64,
    /// Collapse a /24 (IPv6 /64) with [`NET_MIN_IPS`] or more entries.
    pub networks: bool,
}

impl Params {
    pub fn parse(q: &RawParams) -> Self {
        let num = |v: &Option<String>| v.as_deref().and_then(|s| s.trim().parse::<i64>().ok());
        Self {
            hours: num(&q.hours)
                .map(|h| h.clamp(1, i64::from(MAX_HOURS)) as u32)
                .unwrap_or(DEFAULT_HOURS),
            min_severity: num(&q.min_severity)
                .map(|s| s.clamp(1, 4))
                .unwrap_or(DEFAULT_MIN_SEVERITY),
            networks: matches!(
                q.networks.as_deref().map(str::trim),
                Some("1" | "true" | "yes" | "24")
            ),
        }
    }

    /// The cache key (and the canonical query string).
    pub fn key(&self) -> String {
        format!(
            "hours={}&min_severity={}&networks={}",
            self.hours, self.min_severity, self.networks as u8
        )
    }
}

pub async fn feed(State(state): State<Arc<AdminState>>, Query(q): Query<RawParams>) -> Response {
    let p = Params::parse(&q);
    let st = state.clone();
    let body = state
        .stats_cache
        .blocklist(p.key(), TTL, move || {
            let state = st.clone();
            Box::pin(async move { build(&state, p).await })
        })
        .await;
    match body {
        Ok(text) => (
            [
                (
                    header::CONTENT_TYPE,
                    "text/plain; charset=utf-8".to_string(),
                ),
                (
                    header::CACHE_CONTROL,
                    format!("public, max-age={}", TTL.as_secs()),
                ),
            ],
            text.as_str().to_owned(),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(?e, "blocklist failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "blocklist unavailable").into_response()
        }
    }
}

/// `since` for a window of `hours`, in the database's timestamp format.
fn since(hours: u32) -> String {
    (chrono::Utc::now() - chrono::Duration::hours(i64::from(hours)))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

async fn build(state: &AdminState, p: Params) -> anyhow::Result<String> {
    let rows = state
        .store
        .blocklist_ips(&crate::store::blocklist::BlocklistQuery {
            since: since(p.hours),
            min_severity: p.min_severity,
            limit: MAX_ENTRIES,
        })
        .await?;
    let mut safety = state.safety.lock().await;
    safety
        .refresh(&state.cfg, state.recorder.node().map(|n| &**n))
        .await;
    let never = &state.cfg.scan.never_scan;
    let mut ips: Vec<IpAddr> = rows
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(crate::net::canonical)
        .filter(|ip| crate::net::is_scannable_target(*ip))
        .filter(|ip| safety.refuses(ip).is_none() && safety.listed(ip).is_none())
        .filter(|ip| !never.iter().any(|n| n.contains(ip)))
        .collect();
    drop(safety);
    ips.sort_unstable();
    ips.dedup();
    let entries = if p.networks {
        collapse(&ips)
    } else {
        ips.iter().map(ToString::to_string).collect()
    };
    let mut out = String::with_capacity(entries.len() * 18 + 400);
    out.push_str("# peephole blocklist\n");
    out.push_str(&format!(
        "# generated {}; requests of severity {}+ in the last {} hour{}; {} entr{}{}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        p.min_severity,
        p.hours,
        if p.hours == 1 { "" } else { "s" },
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" },
        if rows.len() as i64 >= MAX_ENTRIES {
            " (capped; narrow the window)"
        } else {
            ""
        }
    ));
    out.push_str(
        "# excluded: Tor exits, verified crawlers, cluster members, this node's own networks\n",
    );
    out.push_str(&format!(
        "# parameters: hours=1..{MAX_HOURS} min_severity=1..4 networks=1 (collapse /24 and /64 with {NET_MIN_IPS}+ entries)\n"
    ));
    for e in &entries {
        out.push_str(e);
        out.push('\n');
    }
    Ok(out)
}

/// Addresses, with every /24 (IPv6 /64) holding [`NET_MIN_IPS`] or more
/// of them replaced by the prefix. Sorted, prefixes where their first
/// address would be.
pub fn collapse(ips: &[IpAddr]) -> Vec<String> {
    let mut nets: BTreeMap<IpNet, Vec<IpAddr>> = BTreeMap::new();
    for ip in ips {
        let len = if ip.is_ipv4() { 24 } else { 64 };
        let net = IpNet::new(*ip, len).expect("valid prefix length").trunc();
        nets.entry(net).or_default().push(*ip);
    }
    let mut out = Vec::with_capacity(ips.len());
    for (net, members) in nets {
        if members.len() >= NET_MIN_IPS {
            out.push(net.to_string());
        } else {
            out.extend(members.iter().map(ToString::to_string));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(hours: &str, sev: &str, nets: &str) -> RawParams {
        RawParams {
            hours: Some(hours.into()),
            min_severity: Some(sev.into()),
            networks: Some(nets.into()),
        }
    }

    #[test]
    fn parameters_are_lenient_and_bounded() {
        let d = Params::parse(&RawParams::default());
        assert_eq!((d.hours, d.min_severity, d.networks), (24, 3, false));
        let p = Params::parse(&raw("99999", "0", "1"));
        assert_eq!((p.hours, p.min_severity, p.networks), (MAX_HOURS, 1, true));
        let p = Params::parse(&raw("abc", "9", "no"));
        assert_eq!((p.hours, p.min_severity, p.networks), (24, 4, false));
        assert_eq!(p.key(), "hours=24&min_severity=4&networks=0");
    }

    #[test]
    fn networks_collapse_at_three_entries() {
        let ips: Vec<IpAddr> = [
            "203.0.113.1",
            "203.0.113.2",
            "203.0.113.200",
            "198.51.100.7",
            "198.51.100.8",
            "2001:db8:1::1",
            "2001:db8:1::2",
            "2001:db8:1::3",
            "2001:db8:2::1",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(
            collapse(&ips),
            [
                "198.51.100.7",
                "198.51.100.8",
                "203.0.113.0/24",
                "2001:db8:1::/64",
                "2001:db8:2::1"
            ]
        );
    }

    async fn app() -> (axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cfg: crate::config::Config = toml::from_str(&format!(
            r#"
admin_listen = "127.0.0.1:1"
database_path = "{db}"
data_dir = "{d}"
[roles]
listener = false
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
[scan]
never_scan = ["198.51.100.0/24"]
"#,
            db = dir.path().join("t.db").display(),
            d = dir.path().display()
        ))
        .unwrap();
        let store = crate::store::Store::connect(&cfg.database_path)
            .await
            .unwrap();
        // (address, severity, tor exit)
        let rows = [
            ("203.0.113.9", 3, false),  // listed
            ("203.0.113.10", 4, false), // listed
            ("203.0.113.11", 4, false), // listed; with the two above, a /24
            ("192.0.2.5", 2, false),    // below the default threshold
            ("192.0.2.6", 4, true),     // Tor exit
            ("10.1.2.3", 4, false),     // non-global
            ("198.51.100.4", 4, false), // never_scan
        ];
        for (ip, sev, tor) in rows {
            let row = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
            if tor {
                sqlx::query("UPDATE ips SET is_tor_exit = 1 WHERE id = ?")
                    .bind(row.id)
                    .execute(&store.pool)
                    .await
                    .unwrap();
            }
            store
                .insert_request(&crate::store::requests::NewRequest {
                    ip_id: row.id,
                    method: "GET".into(),
                    path: "/x".into(),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    severity: sev,
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let state = Arc::new(AdminState::public_only(store, cfg));
        (crate::admin::full_router(state), dir)
    }

    async fn get(app: &axum::Router, path: &str) -> (axum::http::HeaderMap, String) {
        use tower::ServiceExt;
        let r = app
            .clone()
            .oneshot(
                axum::http::Request::get(path)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{path}");
        let headers = r.headers().clone();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        (headers, String::from_utf8_lossy(&b).into_owned())
    }

    fn entries(text: &str) -> Vec<&str> {
        text.lines().filter(|l| !l.starts_with('#')).collect()
    }

    #[tokio::test]
    async fn the_feed_lists_severe_sources_and_spares_the_excluded() {
        let (app, _d) = app().await;
        let (h, text) = get(&app, "/api/blocklist").await;
        assert!(
            h[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/plain")
        );
        assert!(text.starts_with("# peephole blocklist\n"));
        assert_eq!(
            entries(&text),
            ["203.0.113.9", "203.0.113.10", "203.0.113.11"]
        );
        let (_, text) = get(&app, "/api/blocklist?min_severity=4").await;
        assert_eq!(entries(&text), ["203.0.113.10", "203.0.113.11"]);
        let (_, text) = get(&app, "/api/blocklist?min_severity=1&networks=1").await;
        assert_eq!(entries(&text), ["192.0.2.5", "203.0.113.0/24"]);
        // Different spellings of the same parameters share one cache entry
        // and never bypass the clamp.
        let (_, again) = get(&app, "/api/blocklist?hours=24&min_severity=3&networks=0").await;
        assert_eq!(
            entries(&again),
            ["203.0.113.9", "203.0.113.10", "203.0.113.11"]
        );
    }
}
