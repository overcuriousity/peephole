//! The scan guard's record-backed half (see [`crate::store::guard`]): the
//! evidence recorded about an IP and the queue budgets, read from the
//! store. Enqueuing applies them; a scanner checks a job against them.

use crate::classify::Classifier;
use crate::classify::stored::{History, StoredRequest};
use crate::cluster::identity::NodeId;
use crate::config::ScanSafety;
use anyhow::Result;
use ipnet::IpNet;
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::net::IpAddr;

/// What the records about one IP justify.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Evidence {
    /// Highest level a request (or fingerprint) of the IP asked for.
    pub max_level: u8,
    /// Requests recorded from the IP (false-positive claims excluded).
    pub requests: u32,
    /// Distinct rule labels across those requests.
    pub labels: u32,
}

impl Evidence {
    /// Whether the evidence is thin: fewer than `full_scan_min_requests`
    /// requests, and not two requests with different labels.
    pub fn thin(&self, s: &ScanSafety) -> bool {
        self.requests < s.full_scan_min_requests && !(self.requests >= 2 && self.labels >= 2)
    }

    /// Highest level this evidence allows.
    pub fn allowed_level(&self, s: &ScanSafety) -> u8 {
        if self.thin(s) {
            self.max_level.min(s.single_request_max_level)
        } else {
            self.max_level
        }
    }
}

/// Which origins' records count as evidence. Rows without an origin were
/// written standalone (by this node).
#[derive(Debug, Clone)]
pub enum Origins {
    Any,
    /// This node plus the listed ones.
    Only {
        me: Option<NodeId>,
        others: HashSet<NodeId>,
    },
}

impl Origins {
    /// From `scan.trusted_origins` (validated by `Config::load`).
    pub fn from_config(s: &ScanSafety, me: Option<NodeId>) -> Self {
        match &s.trusted_origins {
            None => Origins::Any,
            Some(list) => Origins::Only {
                me,
                others: list.iter().filter_map(|o| NodeId::parse(o).ok()).collect(),
            },
        }
    }

    pub(crate) fn admits(&self, origin: Option<&[u8]>) -> bool {
        match (self, origin) {
            (Origins::Any, _) | (_, None) => true,
            (Origins::Only { me, others }, Some(o)) => {
                let Ok(id) = NodeId::from_slice(o) else {
                    return false;
                };
                *me == Some(id) || others.contains(&id)
            }
        }
    }
}

/// Requests and fingerprints considered per IP (newest first).
const EVIDENCE_ROWS: i64 = 1000;
const FINGERPRINT_ROWS: i64 = 50;
/// Requests classified again per evidence check, at most.
const RECLASSIFY_ROWS: usize = 200;

/// The evidence recorded about `ip` (its text as stored in `ips`).
///
/// With `verify`, each request counts for what this node's rules make of
/// it, not only for what its origin stored: its level is the lower of the
/// stored one and the one `verify` gives it again
/// ([`crate::classify::stored`]), and its labels are those `verify` gives
/// it. So a node with tampered rules cannot make others scan harder than
/// their own rules allow. Rows are examined highest stored level first, and
/// only until no row left can raise the level (its stored level caps it)
/// and two labels are known (all [`Evidence::thin`] asks of them), at most
/// [`RECLASSIFY_ROWS`]; `labels` is then a lower bound.
///
/// Without `verify`, the stored verdicts count as they are: for the trap
/// queueing a scan on what it has just classified itself. A scanner always
/// verifies, with the rules built into its binary.
pub async fn evidence(
    pool: &SqlitePool,
    ip: &str,
    origins: &Origins,
    verify: Option<&Classifier>,
) -> Result<Evidence> {
    type Req = (i64, i64, String, Option<Vec<u8>>);
    let rows: Vec<Req> = sqlx::query_as(
        "SELECT r.id, r.scan_level, r.labels_json, r.origin
         FROM requests r JOIN ips i ON i.id = r.ip_id
         WHERE i.ip = ? AND r.is_fp_claim = 0 ORDER BY r.id DESC LIMIT ?",
    )
    .bind(ip)
    .bind(EVIDENCE_ROWS)
    .fetch_all(pool)
    .await?;
    let mut rows: Vec<Req> = rows
        .into_iter()
        .filter(|r| origins.admits(r.3.as_deref()))
        .collect();
    let mut ev = Evidence {
        requests: rows.len() as u32,
        ..Evidence::default()
    };
    let level = |l: i64| l.clamp(0, 4) as u8;
    let mut labels = HashSet::new();
    match verify {
        None => {
            for (_, stored, labels_json, _) in rows {
                ev.max_level = ev.max_level.max(level(stored));
                if let Ok(l) = serde_json::from_str::<Vec<String>>(&labels_json) {
                    labels.extend(l);
                }
            }
        }
        Some(c) => {
            // Stable: newest first within a level.
            rows.sort_by_key(|r| std::cmp::Reverse(r.1));
            for (n, (id, stored, _, _)) in rows.into_iter().enumerate() {
                let stored = level(stored);
                if n >= RECLASSIFY_ROWS || (stored <= ev.max_level && labels.len() >= 2) {
                    break;
                }
                let Some(row) = StoredRequest::load(pool, id).await? else {
                    continue;
                };
                let local = row.reclassify(pool, c, History::Seen).await?;
                ev.max_level = ev.max_level.max(stored.min(local.scan_level));
                labels.extend(local.labels);
            }
        }
    }
    ev.labels = labels.len() as u32;
    // A browser fingerprint that gives a bot away escalates a scan (trap
    // `/collect`): webdriver to level 2, an inhuman form fill to level 3.
    type Fp = (Option<String>, Option<String>, Option<Vec<u8>>);
    let fps: Vec<Fp> = sqlx::query_as(
        "SELECT f.attributes_json, f.behavior_summary_json, f.origin
         FROM fingerprints f JOIN ips i ON i.id = f.ip_id
         WHERE i.ip = ? ORDER BY f.id DESC LIMIT ?",
    )
    .bind(ip)
    .bind(FINGERPRINT_ROWS)
    .fetch_all(pool)
    .await?;
    for (attrs, behavior, origin) in fps {
        if !origins.admits(origin.as_deref()) {
            continue;
        }
        let parse = |s: Option<String>| {
            s.and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null)
        };
        let tells = crate::fingerprint::bot_tells(&parse(attrs), &parse(behavior));
        let level = if tells.inhuman_fill {
            3
        } else if tells.webdriver {
            2
        } else {
            0
        };
        ev.max_level = ev.max_level.max(level);
    }
    Ok(ev)
}

/// The /24 (IPv4) or /64 (IPv6) network of an address.
pub fn network(ip: IpAddr) -> IpNet {
    let ip = crate::net::canonical(ip);
    let len = if ip.is_ipv4() { 24 } else { 64 };
    IpNet::new(ip, len)
        .expect("prefix length fits the family")
        .trunc()
}

/// Other IPs of `ip`'s network with a job queued in the last
/// `window_hours` (refused and superseded jobs excluded). Exact: matched on
/// the indexed `ip_key` range, so every spelling of an address counts once.
pub async fn queued_in_network(pool: &SqlitePool, ip: &str, window_hours: i64) -> Result<usize> {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return Ok(0);
    };
    let net = network(addr);
    let (lo, hi) = crate::store::net_key_range(&net);
    // IPv4 keys live in ::ffff:0:0/96, inside ::/64; an IPv6 network still
    // means IPv6 addresses only.
    let v4_keys = if net.addr().is_ipv6() {
        "00000000000000000000ffff%"
    } else {
        ""
    };
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT i.ip_key) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
         WHERE j.queued_at > datetime('now', ?) AND j.status NOT IN ('refused','superseded')
           AND i.ip_key BETWEEN ? AND ? AND i.ip_key != ? AND i.ip_key NOT LIKE ?",
    )
    .bind(format!("-{window_hours} hours"))
    .bind(lo)
    .bind(hi)
    .bind(crate::store::ip_key(addr))
    .bind(v4_keys)
    .fetch_one(pool)
    .await?;
    Ok(n as usize)
}

/// Jobs queued in the last hour for IPs of autonomous system `asn`.
pub async fn queued_in_asn_last_hour(pool: &SqlitePool, asn: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
         WHERE i.asn = ? AND j.queued_at > datetime('now', '-1 hour')
           AND j.status NOT IN ('refused','superseded')",
    )
    .bind(asn)
    .fetch_one(pool)
    .await?)
}

/// What enqueuing applies besides the per-IP cooldown.
#[derive(Debug, Clone)]
pub struct EnqueuePolicy {
    pub cooldown_hours: i64,
    /// None: no evidence cap (tests, callers that checked already).
    pub safety: Option<ScanSafety>,
}

impl EnqueuePolicy {
    /// The trap's policy: `[scan]` safety settings and the current cooldown.
    pub fn new(s: &ScanSafety, cooldown_hours: i64) -> Self {
        Self {
            cooldown_hours,
            safety: Some(s.clone()),
        }
    }

    /// Only the per-IP cooldown (what `enqueue_scan` always did).
    pub fn cooldown_only(cooldown_hours: i64) -> Self {
        Self {
            cooldown_hours,
            safety: None,
        }
    }
}
