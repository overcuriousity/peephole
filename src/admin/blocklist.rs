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
use crate::scan::safety::nets_overlap;
use crate::store::evidence::Shared;
use axum::{
    extract::{Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::collections::{BTreeMap, BTreeSet};
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
    // Tor exits and verified crawlers inside a prefix keep it from being
    // collapsed. Only those the trap has seen in the window are known here
    // (checking every address of a prefix against the exit list is not
    // worth it); the rest of the exclusions are complete.
    let spared: BTreeSet<IpAddr> = if p.networks {
        state
            .store
            .blocklist_spared_ips(&since(p.hours))
            .await?
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(crate::net::canonical)
            .collect()
    } else {
        BTreeSet::new()
    };
    // Addresses with a shared reading (rules 2, 4, 5, 6), listed or not:
    // their entries get a comment line, and their /24 is never collapsed.
    let shared: BTreeMap<IpAddr, Shared> = state
        .store
        .shared_readings(None)
        .await?
        .into_iter()
        .filter_map(|(_, ip, s)| Some((crate::net::canonical(ip.parse().ok()?), s)))
        .collect();
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
    ips.sort_unstable();
    ips.dedup();
    let entries = if p.networks {
        collapse(&ips, |net| {
            safety.overlaps(net)
                || never.iter().any(|n| nets_overlap(n, net))
                || spared
                    .range(net.network()..=net.broadcast())
                    .next()
                    .is_some()
                || shared
                    .range(net.network()..=net.broadcast())
                    .next()
                    .is_some()
        })
    } else {
        ips.iter().map(ToString::to_string).collect()
    };
    drop(safety);
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
    out.push_str(
        "# shared: a comment line before an entry the operator's naming calls a pool or a reassigned line; a cost warning (a block hits other people, and such an address changes hands within days or hours), not a verdict; never collapsed by networks=1\n",
    );
    out.push_str("# documentation: /api\n");
    for e in &entries {
        if let Some(s) = e.parse::<IpAddr>().ok().and_then(|ip| shared.get(&ip)) {
            out.push_str(&s.note(e));
            out.push('\n');
        }
        out.push_str(e);
        out.push('\n');
    }
    Ok(out)
}

/// Addresses, with every /24 (IPv6 /64) holding [`NET_MIN_IPS`] or more
/// of them replaced by the prefix, unless `spared` says the prefix holds
/// an excluded address or one with a shared reading. Sorted, prefixes where their first address would be.
pub fn collapse(ips: &[IpAddr], spared: impl Fn(&IpNet) -> bool) -> Vec<String> {
    let mut nets: BTreeMap<IpNet, Vec<IpAddr>> = BTreeMap::new();
    for ip in ips {
        let len = if ip.is_ipv4() { 24 } else { 64 };
        let net = IpNet::new(*ip, len).expect("valid prefix length").trunc();
        nets.entry(net).or_default().push(*ip);
    }
    let mut out = Vec::with_capacity(ips.len());
    for (net, members) in nets {
        if members.len() >= NET_MIN_IPS && !spared(&net) {
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
            collapse(&ips, |_| false),
            [
                "198.51.100.7",
                "198.51.100.8",
                "203.0.113.0/24",
                "2001:db8:1::/64",
                "2001:db8:2::1"
            ]
        );
    }

    #[test]
    fn networks_holding_an_excluded_address_stay_split() {
        let ips: Vec<IpAddr> = ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let member: IpAddr = "203.0.113.77".parse().unwrap();
        assert_eq!(
            collapse(&ips, |net| net.contains(&member)),
            ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
        );
    }

    /// Every address an entry covers, among `of`.
    fn covered(entries: &[String], of: &[IpAddr]) -> BTreeSet<IpAddr> {
        of.iter()
            .copied()
            .filter(|ip| {
                entries.iter().any(|e| match e.parse::<IpNet>() {
                    Ok(n) => n.contains(ip),
                    Err(_) => e.parse::<IpAddr>().ok() == Some(*ip),
                })
            })
            .collect()
    }

    /// MIK-646: the skip for /24s holding a shared reading only narrows.
    /// Every listed address stays listed, and what is covered with the
    /// skip is a subset of what is covered without it.
    #[test]
    fn the_shared_skip_only_narrows() {
        let ips: Vec<IpAddr> = [
            "203.0.113.1",
            "203.0.113.2",
            "203.0.113.3",
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "198.51.100.4",
            "192.0.2.9",
            "2001:db8:1::1",
            "2001:db8:1::2",
            "2001:db8:1::3",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        // Every address of the /24s and /64s involved, listed or not.
        let mut universe: Vec<IpAddr> = (0..=255u8)
            .flat_map(|n| {
                [
                    format!("203.0.113.{n}"),
                    format!("198.51.100.{n}"),
                    format!("192.0.2.{n}"),
                    format!("2001:db8:1::{n:x}"),
                ]
            })
            .map(|s| s.parse().unwrap())
            .collect();
        universe.sort_unstable();
        let shared_sets: &[&[&str]] = &[
            &[],
            &["203.0.113.2"],
            &["203.0.113.77", "2001:db8:1::9"],
            &["198.51.100.4", "192.0.2.9", "2001:db8:1::1"],
        ];
        let without = collapse(&ips, |_| false);
        let all = covered(&without, &universe);
        for set in shared_sets {
            let shared: BTreeSet<IpAddr> = set.iter().map(|s| s.parse().unwrap()).collect();
            let with = collapse(&ips, |net| {
                shared
                    .range(net.network()..=net.broadcast())
                    .next()
                    .is_some()
            });
            let some = covered(&with, &universe);
            assert!(some.is_subset(&all), "{set:?}: {with:?}");
            assert!(ips.iter().all(|ip| some.contains(ip)), "{set:?}: {with:?}");
            for ip in &shared {
                let net = IpNet::new(*ip, if ip.is_ipv4() { 24 } else { 64 })
                    .unwrap()
                    .trunc();
                assert!(!with.contains(&net.to_string()), "{set:?}: {with:?}");
            }
        }
    }

    async fn app() -> (axum::Router, tempfile::TempDir) {
        app_with(false).await
    }

    /// `shared`: 203.0.113.10 carries a carrier-NAT name (rule 4).
    async fn app_with(shared: bool) -> (axum::Router, tempfile::TempDir) {
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
        if shared {
            let ip = store
                .upsert_ip("203.0.113.10".parse().unwrap())
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 VALUES (?, '0-0-0-10.cgn-wdsl.example.it', 'ptr', datetime('now'), datetime('now'), 1)",
            )
            .bind(ip.id)
            .execute(&store.pool)
            .await
            .unwrap();
            crate::store::maintenance::recompute_campaigns(&store).await;
            let shared = store.shared_readings(None).await.unwrap();
            assert_eq!(shared.len(), 1, "{shared:?}");
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
        assert!(text.contains("\n# documentation: /api\n"), "{text}");
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

    /// MIK-646: a shared reading adds a `#` line before its entry and
    /// nothing else: without the `#` lines the feed is what it was, and
    /// with `networks=1` its /24 is listed address by address.
    #[tokio::test]
    async fn a_shared_reading_is_a_comment_line_and_keeps_its_net_split() {
        let (plain, _d1) = app_with(false).await;
        let (shared, _d2) = app_with(true).await;
        for q in ["", "?min_severity=4", "?min_severity=1"] {
            let path = format!("/api/blocklist{q}");
            let (_, a) = get(&plain, &path).await;
            let (_, b) = get(&shared, &path).await;
            assert_eq!(entries(&a), entries(&b), "{path}");
        }
        let (_, text) = get(&shared, "/api/blocklist").await;
        let note = "# shared 203.0.113.10 rule=4 v=3: shared pool, by the operator's naming; \
                    not verified by behaviour";
        assert!(
            text.contains(&format!("\n{note}\n203.0.113.10\n")),
            "{text}"
        );
        assert_eq!(text.matches("\n# shared 2").count(), 1, "{text}");
        assert!(
            !text.contains("cgn-wdsl"),
            "no operator text in the feed: {text}"
        );
        let (_, text) = get(&plain, "/api/blocklist?min_severity=1&networks=1").await;
        assert_eq!(entries(&text), ["192.0.2.5", "203.0.113.0/24"]);
        let (_, text) = get(&shared, "/api/blocklist?min_severity=1&networks=1").await;
        assert_eq!(
            entries(&text),
            ["192.0.2.5", "203.0.113.9", "203.0.113.10", "203.0.113.11"]
        );
    }
}
