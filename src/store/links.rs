//! What ties source IPs together, for the admin Links pages. Browser
//! fingerprints, SSH host keys, TLS certificates and reused canaries point
//! to one operator ("identity"); JA4, JA4H, HASSH, JA4X, favicon, JARM and
//! page hashes only to the same software. Each kind is read as sightings: a value seen on an IP at a
//! time, by a node. Admin-only.
use super::Store;
use super::browse::{PAGE_SIZE, Page, lenient_i64, nonempty, ts_bound};
use crate::scan::hostkeys::{
    FAVICON, HASSH, HTTP_404, HTTP_BODY, JA4X, JARM, SSH_HOSTKEY, TLS_CERT,
};
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    Fp,
    Ssh,
    Tls,
    Canary,
    Ja4,
    Ja4h,
    Hassh,
    Ja4x,
    Favicon,
    Jarm,
    HttpBody,
    Http404,
}

use LinkKind::*;

impl LinkKind {
    pub const ALL: [LinkKind; 12] = [
        Fp, Ssh, Tls, Canary, Ja4, Ja4h, Hassh, Ja4x, Favicon, Jarm, HttpBody, Http404,
    ];
    /// The kinds the index lists (canaries have their own tab).
    pub const LIST: [LinkKind; 11] = [
        Fp, Ssh, Tls, Ja4, Ja4h, Hassh, Ja4x, Favicon, Jarm, HttpBody, Http404,
    ];
    pub const IDENTITY: [LinkKind; 4] = [Fp, Ssh, Tls, Canary];

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.key() == s)
    }

    /// Its name in URLs and graph ids.
    pub fn key(self) -> &'static str {
        match self {
            Fp => "fp",
            Ssh => "ssh",
            Tls => "tls",
            Canary => "canary",
            Ja4 => "ja4",
            Ja4h => "ja4h",
            Hassh => "hassh",
            Ja4x => "ja4x",
            Favicon => "favicon",
            Jarm => "jarm",
            HttpBody => "http-body",
            Http404 => "http-404",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Fp => "Browser fingerprint",
            Ssh => "SSH host key",
            Tls => "TLS certificate",
            Canary => "Canary",
            Ja4 => "JA4",
            Ja4h => "JA4H",
            Hassh => "HASSH",
            Ja4x => "JA4X",
            Favicon => "Favicon",
            Jarm => "JARM",
            HttpBody => "Page body",
            Http404 => "404 page",
        }
    }

    /// Ties sources to one operator, not only to the same software.
    pub fn identity(self) -> bool {
        matches!(self, Fp | Ssh | Tls | Canary)
    }

    /// Recorded by a node (requests); host keys come from scans instead.
    pub fn by_node(self) -> bool {
        matches!(self, Fp | Canary | Ja4 | Ja4h)
    }

    /// Its `host_keys.kind`, for the kinds read from scans.
    pub fn host_kind(self) -> Option<&'static str> {
        match self {
            Ssh => Some(SSH_HOSTKEY),
            Tls => Some(TLS_CERT),
            Hassh => Some(HASSH),
            Ja4x => Some(JA4X),
            Favicon => Some(FAVICON),
            Jarm => Some(JARM),
            HttpBody => Some(HTTP_BODY),
            Http404 => Some(HTTP_404),
            _ => None,
        }
    }

    pub fn of_host_kind(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.host_kind() == Some(kind))
    }

    fn legs(self) -> &'static [Leg] {
        match self {
            Fp => &FP_LEGS,
            Ja4 => &JA4_LEGS,
            Ja4h => &JA4H_LEGS,
            Ssh => &SSH_LEGS,
            Tls => &TLS_LEGS,
            Hassh => &HASSH_LEGS,
            Ja4x => &JA4X_LEGS,
            Favicon => &FAVICON_LEGS,
            Jarm => &JARM_LEGS,
            HttpBody => &HTTP_BODY_LEGS,
            Http404 => &HTTP_404_LEGS,
            Canary => &CANARY_LEGS,
        }
    }
}

const FP_LEGS: [Leg; 1] = [Leg::row(
    "fingerprints f",
    "f.fp_hash",
    "f.ip_id",
    "f.ts",
    "f.origin",
)];
const JA4_LEGS: [Leg; 1] = [Leg::row(
    "requests r",
    "r.ja4",
    "r.ip_id",
    "r.ts",
    "r.origin",
)];
const JA4H_LEGS: [Leg; 1] = [Leg::row(
    "requests r",
    "r.ja4h",
    "r.ip_id",
    "r.ts",
    "r.origin",
)];
// The literals are the `scan::hostkeys` kinds (checked by a test).
const SSH_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'ssh-hostkey'")];
const TLS_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'tls-cert'")];
const HASSH_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'hassh'")];
const JA4X_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'ja4x'")];
const FAVICON_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'favicon'")];
const JARM_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'jarm'")];
const HTTP_BODY_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'http-body'")];
const HTTP_404_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'http-404'")];

/// One source of sightings.
struct Leg {
    from: &'static str,
    /// The value as text.
    text: &'static str,
    /// The stored column matched by value (indexed).
    col: &'static str,
    ip: &'static str,
    ts: &'static str,
    /// The recording member's id, or `NULL`.
    origin: &'static str,
    cond: &'static str,
}

impl Leg {
    /// A table with the value in a column of its own.
    const fn row(
        from: &'static str,
        col: &'static str,
        ip: &'static str,
        ts: &'static str,
        origin: &'static str,
    ) -> Leg {
        Leg {
            from,
            text: col,
            col,
            ip,
            ts,
            origin,
            cond: "",
        }
    }

    /// `host_keys` of one kind; its time is the scan's or the probe's.
    const fn host_key(cond: &'static str) -> Leg {
        Leg {
            from: "host_keys h LEFT JOIN scans s ON s.id = h.scan_id LEFT JOIN probes p ON p.id = h.probe_id",
            text: "h.fingerprint",
            col: "h.fingerprint",
            ip: "h.ip_id",
            ts: "COALESCE(s.finished_at, p.finished_at)",
            origin: "NULL",
            cond,
        }
    }
}

/// A canary used again (as `canaries::REUSE_SELECT` defines it) is seen
/// where it was served and where it was used.
const CANARY_LEGS: [Leg; 2] = [
    Leg {
        from: "canaries c LEFT JOIN requests sr ON sr.id = c.request_id
               LEFT JOIN skipped_batches sb ON sb.id = c.batch_id",
        text: "CAST(c.value_hash AS TEXT)",
        col: "c.value_hash",
        ip: "c.ip_id",
        ts: "c.ts",
        origin: "COALESCE(sr.origin, sb.origin)",
        cond: "EXISTS (SELECT 1 FROM request_tokens t WHERE t.value_hash = c.value_hash
               AND (c.request_id IS NULL OR t.request_id != c.request_id))",
    },
    Leg {
        from: "request_tokens t JOIN requests u ON u.id = t.request_id",
        text: "CAST(t.value_hash AS TEXT)",
        col: "t.value_hash",
        ip: "u.ip_id",
        ts: "u.ts",
        origin: "u.origin",
        cond: "EXISTS (SELECT 1 FROM canaries c WHERE c.value_hash = t.value_hash
               AND (c.request_id IS NULL OR c.request_id != t.request_id))",
    },
];

/// Conditions on sightings; each applies to every leg.
#[derive(Default)]
struct Where<'a> {
    value: Option<&'a str>,
    prefix: Option<String>,
    ip_id: Option<i64>,
    from: Option<String>,
    to: Option<String>,
    country: Option<String>,
    node: Option<String>,
}

/// `SELECT v, ip_id, ts, origin` over `kind`'s sightings matching `w`, and
/// its binds (repeated per leg). Values are bound as text: SQLite converts
/// them for integer columns (`value_hash`, `ip_id`), so indexes still apply.
fn sightings(kind: LinkKind, w: &Where) -> (String, Vec<String>) {
    let mut parts = vec![];
    let mut binds = vec![];
    for l in kind.legs() {
        let mut sql = format!(
            "SELECT {} AS v, {} AS ip_id, {} AS ts, {} AS origin FROM {} WHERE {} IS NOT NULL",
            l.text, l.ip, l.ts, l.origin, l.from, l.col
        );
        if !l.cond.is_empty() {
            sql.push_str(&format!(" AND {}", l.cond));
        }
        if let Some(v) = w.value {
            sql.push_str(&format!(" AND {} = ?", l.col));
            binds.push(v.to_string());
        }
        if let Some(p) = &w.prefix {
            sql.push_str(&format!(" AND {} LIKE ? ESCAPE '\\'", l.text));
            let esc = p
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            binds.push(format!("{esc}%"));
        }
        if let Some(i) = w.ip_id {
            sql.push_str(&format!(" AND {} = ?", l.ip));
            binds.push(i.to_string());
        }
        if let Some(v) = &w.from {
            sql.push_str(&format!(" AND {} >= ?", l.ts));
            binds.push(ts_bound(v, false));
        }
        if let Some(v) = &w.to {
            sql.push_str(&format!(" AND {} <= ?", l.ts));
            binds.push(ts_bound(v, true));
        }
        if let Some(c) = &w.country {
            sql.push_str(&format!(
                " AND {} IN (SELECT id FROM ips WHERE country = ?)",
                l.ip
            ));
            binds.push(c.to_ascii_uppercase());
        }
        if kind.by_node()
            && let Some(n) = &w.node
        {
            sql.push_str(&format!(
                " AND {} IN (SELECT id FROM members WHERE name = ?)",
                l.origin
            ));
            binds.push(n.clone());
        }
        parts.push(sql);
    }
    (parts.join(" UNION ALL "), binds)
}

/// The index's filter; names and formats as `RequestFilter`, so the
/// drill-down chips (piece D) can share them.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct LinkFilter {
    pub kind: Option<String>,
    /// Start of the value.
    pub q: Option<String>,
    /// `0`: values on any number of IPs; otherwise only those on two or more.
    pub shared: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub country: Option<String>,
    /// The recording node (request-based kinds only).
    pub node: Option<String>,
    /// `ips` (default) | `sightings` | `recent`.
    pub sort: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub page: Option<i64>,
    /// An anchor of the old fingerprints page (`/admin/fingerprints#<x>`).
    pub anchor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct LinkRow {
    pub value: String,
    pub ips: i64,
    pub sightings: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct LinkIp {
    pub ip: String,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub sightings: i64,
    pub last_seen: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LinkItem {
    pub kind: LinkKind,
    pub value: String,
    pub ips: i64,
    pub sightings: i64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub countries: Vec<String>,
    /// Nodes that recorded it (request-based kinds).
    pub nodes: Vec<String>,
    /// nmap's description (SSH key type, certificate subject).
    pub detail: String,
    /// Most sightings first, at most [`ITEM_IPS`].
    pub ip_rows: Vec<LinkIp>,
}

impl LinkFilter {
    pub fn kind(&self) -> LinkKind {
        self.kind.as_deref().and_then(LinkKind::parse).unwrap_or(Fp)
    }
    pub fn shared(&self) -> bool {
        self.shared.as_deref() != Some("0")
    }
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).clamp(1, 100_000) as u32
    }
}

/// IPs listed on an item page.
pub const ITEM_IPS: i64 = 1000;

impl Store {
    /// One page of `f.kind()`'s values, counts over the matching sightings.
    pub async fn links_list(&self, f: &LinkFilter) -> Result<Page<LinkRow>> {
        let w = Where {
            prefix: nonempty(&f.q),
            from: nonempty(&f.from),
            to: nonempty(&f.to),
            country: nonempty(&f.country),
            node: nonempty(&f.node),
            ..Default::default()
        };
        let (s, binds) = sightings(f.kind(), &w);
        let having = if f.shared() {
            " HAVING COUNT(DISTINCT ip_id) > 1"
        } else {
            ""
        };
        let order = match f.sort.as_deref() {
            Some("sightings") => "sightings DESC, ips DESC, value",
            Some("recent") => "last_seen DESC, value",
            _ => "ips DESC, sightings DESC, value",
        };
        let page = f.page();
        let sql = format!(
            "SELECT v AS value, COUNT(DISTINCT ip_id) AS ips, COUNT(*) AS sightings,
                    MIN(ts) AS first_seen, MAX(ts) AS last_seen
             FROM ({s}) GROUP BY v{having} ORDER BY {order} LIMIT {} OFFSET {}",
            PAGE_SIZE + 1,
            (page as i64 - 1) * PAGE_SIZE
        );
        let mut q = sqlx::query_as::<_, LinkRow>(sqlx::AssertSqlSafe(sql));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(Page::from_rows(q.fetch_all(&self.read).await?, page))
    }

    pub async fn link_item(&self, kind: LinkKind, value: &str) -> Result<Option<LinkItem>> {
        let (s, binds) = sightings(
            kind,
            &Where {
                value: Some(value),
                ..Default::default()
            },
        );
        let mut q =
            sqlx::query_as::<_, (i64, i64, Option<String>, Option<String>)>(sqlx::AssertSqlSafe(
                format!("SELECT COUNT(*), COUNT(DISTINCT ip_id), MIN(ts), MAX(ts) FROM ({s})"),
            ));
        for b in &binds {
            q = q.bind(b);
        }
        let (sightings, ips, first_seen, last_seen) = q.fetch_one(&self.read).await?;
        if sightings == 0 {
            return Ok(None);
        }
        let mut q = sqlx::query_as::<_, LinkIp>(sqlx::AssertSqlSafe(format!(
            "SELECT i.ip, i.country, i.asn, COUNT(*) AS sightings, MAX(s.ts) AS last_seen
             FROM ({s}) s JOIN ips i ON i.id = s.ip_id
             GROUP BY s.ip_id ORDER BY sightings DESC, i.ip LIMIT {ITEM_IPS}"
        )));
        for b in &binds {
            q = q.bind(b);
        }
        let ip_rows = q.fetch_all(&self.read).await?;
        let mut q = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
            "SELECT DISTINCT i.country FROM ({s}) s JOIN ips i ON i.id = s.ip_id
             WHERE i.country IS NOT NULL ORDER BY 1"
        )));
        for b in &binds {
            q = q.bind(b);
        }
        let countries = q.fetch_all(&self.read).await?;
        let nodes = if kind.by_node() {
            let mut q = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
                "SELECT name FROM members WHERE id IN (SELECT origin FROM ({s})) ORDER BY name"
            )));
            for b in &binds {
                q = q.bind(b);
            }
            q.fetch_all(&self.read).await?
        } else {
            vec![]
        };
        let detail = match kind.host_kind() {
            Some(h) => {
                sqlx::query_scalar(
                    "SELECT COALESCE(MAX(detail), '') FROM host_keys
                     WHERE kind = ? AND fingerprint = ?",
                )
                .bind(h)
                .bind(value)
                .fetch_one(&self.read)
                .await?
            }
            None => String::new(),
        };
        Ok(Some(LinkItem {
            kind,
            value: value.to_string(),
            ips,
            sightings,
            first_seen,
            last_seen,
            countries,
            nodes,
            detail,
            ip_rows,
        }))
    }

    /// The listed kinds (not canaries: their values are internal) that
    /// hold exactly `value`, in [`LinkKind::LIST`] order.
    pub async fn find_value(&self, value: &str) -> Result<Vec<LinkKind>> {
        let value = value.trim();
        let mut out = vec![];
        if value.is_empty() {
            return Ok(out);
        }
        for kind in LinkKind::LIST {
            let (s, binds) = sightings(
                kind,
                &Where {
                    value: Some(value),
                    ..Default::default()
                },
            );
            let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
                "SELECT EXISTS (SELECT 1 FROM ({s}))"
            )));
            for b in &binds {
                q = q.bind(b);
            }
            if q.fetch_one(&self.read).await? == 1 {
                out.push(kind);
            }
        }
        Ok(out)
    }

    /// The item an anchor of the old fingerprints page named: a browser
    /// fingerprint's hash, or `ssh-`/`tls-` and the start of a host key
    /// ([`super::hostkeys::anchor`] drops characters, so it is recomputed
    /// over that kind's stored values rather than matched).
    pub async fn resolve_anchor(&self, a: &str) -> Result<Option<(LinkKind, String)>> {
        let a = a.trim();
        let fp: Option<String> =
            sqlx::query_scalar("SELECT fp_hash FROM fingerprints WHERE fp_hash = ? LIMIT 1")
                .bind(a)
                .fetch_optional(&self.read)
                .await?;
        if fp.is_some() {
            return Ok(Some((Fp, a.to_string())));
        }
        for kind in [Ssh, Tls] {
            if !a.starts_with(&format!("{}-", kind.key())) {
                continue;
            }
            let stored = kind.host_kind().unwrap_or_default();
            let fps: Vec<String> =
                sqlx::query_scalar("SELECT DISTINCT fingerprint FROM host_keys WHERE kind = ?")
                    .bind(stored)
                    .fetch_all(&self.read)
                    .await?;
            if let Some(f) = fps
                .into_iter()
                .find(|f| super::hostkeys::anchor(stored, f) == a)
            {
                return Ok(Some((kind, f)));
            }
        }
        Ok(None)
    }
}

/// A value on more IPs than this is drawn as one group node.
pub const GROUP_AT: i64 = 25;
/// IPs listed when a group is expanded.
pub const GROUP_MAX: i64 = 500;
/// Nodes in one graph.
pub const GRAPH_MAX: usize = 400;
/// Values of one kind read per IP.
pub const PER_IP: i64 = 50;

/// What a graph is centred on, as the API names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Focus {
    Item(LinkKind, String),
    Ip(String),
}

impl Focus {
    /// `<kind>:<value>` or `ip:<addr>`.
    pub fn parse(s: &str) -> Option<Focus> {
        let (k, v) = s.split_once(':')?;
        if v.is_empty() {
            return None;
        }
        if k == "ip" {
            return Some(Focus::Ip(super::browse::canonical_ip(v)));
        }
        Some(Focus::Item(LinkKind::parse(k)?, v.to_string()))
    }

    pub fn id(&self) -> String {
        match self {
            Focus::Item(k, v) => format!("{}:{v}", k.key()),
            Focus::Ip(a) => format!("ip:{a}"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphNode {
    pub id: String,
    /// `ip`, `group`, or a kind's key.
    pub kind: String,
    /// The address, the item's value, or (group) the collapsed item's value.
    pub value: String,
    /// Hops from the focus.
    pub hop: u32,
    pub identity: bool,
    pub ips: Option<i64>,
    pub sightings: Option<i64>,
    pub last_seen: Option<String>,
    pub country: Option<String>,
    /// A group: the collapsed item's kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GraphEdge {
    pub a: String,
    pub b: String,
    pub identity: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct LinkGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Stopped at [`GRAPH_MAX`] nodes.
    pub truncated: bool,
}

impl LinkGraph {
    fn has(&self, id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == id)
    }

    fn link(&mut self, a: &str, b: &str, identity: bool) {
        let dup = self
            .edges
            .iter()
            .any(|e| (e.a == a && e.b == b) || (e.a == b && e.b == a));
        if !dup {
            self.edges.push(GraphEdge {
                a: a.into(),
                b: b.into(),
                identity,
            });
        }
    }
}

impl Store {
    /// The neighbourhood of `focus`: breadth-first, `depth` hops (1–3), one
    /// hop being item → its IPs or IP → its values of `types` (the focus'
    /// own kind always walked). A value on more than [`GROUP_AT`] IPs is
    /// one group node and not walked through, unless `all` (expanding a
    /// group: the focus' IPs, up to [`GROUP_MAX`]).
    pub async fn link_graph(
        &self,
        focus: &Focus,
        depth: u32,
        types: &[LinkKind],
        all: bool,
    ) -> Result<LinkGraph> {
        let depth = depth.clamp(1, 3);
        let mut types = types.to_vec();
        if let Focus::Item(k, _) = focus
            && !types.contains(k)
        {
            types.push(*k);
        }
        let mut g = LinkGraph::default();
        let Some(first) = self.graph_node(focus, 0).await? else {
            return Ok(g);
        };
        g.nodes.push(first);
        let mut frontier = vec![focus.clone()];
        'walk: for hop in 1..=depth {
            let mut next = vec![];
            for f in &frontier {
                let from = f.id();
                let found: Vec<Focus> = match f {
                    Focus::Item(k, v) => {
                        let ips = g
                            .nodes
                            .iter()
                            .find(|n| n.id == from)
                            .and_then(|n| n.ips)
                            .unwrap_or(0);
                        if ips > GROUP_AT && !(all && hop == 1) {
                            let gid = format!("group:{from}");
                            if !g.has(&gid) {
                                if g.nodes.len() >= GRAPH_MAX {
                                    g.truncated = true;
                                    break 'walk;
                                }
                                g.nodes.push(GraphNode {
                                    id: gid.clone(),
                                    kind: "group".into(),
                                    value: v.clone(),
                                    hop,
                                    identity: k.identity(),
                                    ips: Some(ips),
                                    sightings: None,
                                    last_seen: None,
                                    country: None,
                                    of: Some(k.key().into()),
                                });
                            }
                            g.link(&from, &gid, k.identity());
                            continue;
                        }
                        let limit = if all { GROUP_MAX } else { GROUP_AT };
                        self.item_ips(*k, v, limit)
                            .await?
                            .into_iter()
                            .map(Focus::Ip)
                            .collect()
                    }
                    Focus::Ip(addr) => self
                        .ip_values(addr, &types)
                        .await?
                        .into_iter()
                        .map(|(k, v)| Focus::Item(k, v))
                        .collect(),
                };
                for n in found {
                    let id = n.id();
                    let identity = match (f, &n) {
                        (Focus::Item(k, _), _) | (_, Focus::Item(k, _)) => k.identity(),
                        _ => true,
                    };
                    if !g.has(&id) {
                        if g.nodes.len() >= GRAPH_MAX {
                            g.truncated = true;
                            break 'walk;
                        }
                        let Some(node) = self.graph_node(&n, hop).await? else {
                            continue;
                        };
                        g.nodes.push(node);
                        next.push(n);
                    }
                    g.link(&from, &id, identity);
                }
            }
            frontier = next;
        }
        Ok(g)
    }

    /// A node's facts; `None` when nothing is stored for it.
    async fn graph_node(&self, f: &Focus, hop: u32) -> Result<Option<GraphNode>> {
        match f {
            Focus::Ip(addr) => {
                let row: Option<(String, Option<String>, i64, Option<String>)> = sqlx::query_as(
                    "SELECT ip, country, request_count, last_seen FROM ips WHERE ip = ?",
                )
                .bind(addr)
                .fetch_optional(&self.read)
                .await?;
                Ok(row.map(|(ip, country, n, last_seen)| GraphNode {
                    id: f.id(),
                    kind: "ip".into(),
                    value: ip,
                    hop,
                    identity: true,
                    ips: None,
                    sightings: Some(n),
                    last_seen,
                    country,
                    of: None,
                }))
            }
            Focus::Item(k, v) => {
                let (s, binds) = sightings(
                    *k,
                    &Where {
                        value: Some(v),
                        ..Default::default()
                    },
                );
                let mut q = sqlx::query_as::<_, (i64, i64, Option<String>)>(sqlx::AssertSqlSafe(
                    format!("SELECT COUNT(*), COUNT(DISTINCT ip_id), MAX(ts) FROM ({s})"),
                ));
                for b in &binds {
                    q = q.bind(b);
                }
                let (n, ips, last_seen) = q.fetch_one(&self.read).await?;
                Ok((n > 0).then(|| GraphNode {
                    id: f.id(),
                    kind: k.key().into(),
                    value: v.clone(),
                    hop,
                    identity: k.identity(),
                    ips: Some(ips),
                    sightings: Some(n),
                    last_seen,
                    country: None,
                    of: None,
                }))
            }
        }
    }

    /// Addresses a value was seen on, most sightings first.
    async fn item_ips(&self, kind: LinkKind, value: &str, limit: i64) -> Result<Vec<String>> {
        let (s, binds) = sightings(
            kind,
            &Where {
                value: Some(value),
                ..Default::default()
            },
        );
        let mut q = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
            "SELECT i.ip FROM ({s}) s JOIN ips i ON i.id = s.ip_id
             GROUP BY s.ip_id ORDER BY COUNT(*) DESC, i.ip LIMIT {limit}"
        )));
        for b in &binds {
            q = q.bind(b);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    /// Values of `kinds` seen on an address, at most [`PER_IP`] per kind.
    async fn ip_values(&self, addr: &str, kinds: &[LinkKind]) -> Result<Vec<(LinkKind, String)>> {
        let ip_id: Option<i64> = sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
            .bind(addr)
            .fetch_optional(&self.read)
            .await?;
        let Some(ip_id) = ip_id else {
            return Ok(vec![]);
        };
        let mut out = vec![];
        for k in kinds {
            let (s, binds) = sightings(
                *k,
                &Where {
                    ip_id: Some(ip_id),
                    ..Default::default()
                },
            );
            let mut q = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(format!(
                "SELECT DISTINCT v FROM ({s}) ORDER BY v LIMIT {PER_IP}"
            )));
            for b in &binds {
                q = q.bind(b);
            }
            out.extend(q.fetch_all(&self.read).await?.into_iter().map(|v| (*k, v)));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::parse_nmap_xml;
    use crate::store::requests::NewRequest;

    /// a, b, c, d: fp "F" on a and b, fp "G" on c; JA4 "J" on a, b, c and
    /// "K" on d; the host-key fixture scanned on a and d (two SSH keys, one
    /// certificate, HASSH, JA4X); canary 77 served on a and used on c.
    async fn seeded() -> (Store, [i64; 4]) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mut ids = [0; 4];
        for (i, a) in ["203.0.113.1", "203.0.113.2", "198.51.100.3", "198.51.100.4"]
            .iter()
            .enumerate()
        {
            ids[i] = s.upsert_ip(a.parse().unwrap()).await.unwrap().id;
        }
        sqlx::query("UPDATE ips SET country = 'DE' WHERE id = ?")
            .bind(ids[2])
            .execute(&s.pool)
            .await
            .unwrap();
        for (ip, h) in [(ids[0], "F"), (ids[1], "F"), (ids[2], "G")] {
            s.insert_fingerprint(None, ip, h, None, "{}", "{}", b"[]")
                .await
                .unwrap();
        }
        let mut req_of = [0; 4];
        for (i, j) in [(0, "J"), (1, "J"), (2, "J"), (3, "K")] {
            req_of[i] = s
                .insert_request(&NewRequest {
                    ip_id: ids[i],
                    method: "GET".into(),
                    path: "/".into(),
                    headers_json: "[]".into(),
                    labels_json: "[]".into(),
                    ja4: Some(j.into()),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        for ip in [ids[0], ids[3]] {
            s.enqueue_scan(ip, 2, 0).await.unwrap();
            let job = s.next_queued_job().await.unwrap().unwrap();
            let res =
                parse_nmap_xml(include_bytes!("../../tests/fixtures/nmap-hostkeys.xml")).unwrap();
            s.finish_job(job.id, Some(&res), None).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO canaries (value_hash, kind, request_id, ts, ip_id)
             VALUES (77, 'git-token', ?, datetime('now'), ?)",
        )
        .bind(req_of[0])
        .bind(ids[0])
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO request_tokens (request_id, value_hash, place) VALUES (?, 77, 'header')",
        )
        .bind(req_of[2])
        .execute(&s.pool)
        .await
        .unwrap();
        (s, ids)
    }

    fn filter(kind: &str) -> LinkFilter {
        LinkFilter {
            kind: Some(kind.into()),
            ..Default::default()
        }
    }

    fn values(p: &Page<LinkRow>) -> Vec<&str> {
        p.items.iter().map(|r| r.value.as_str()).collect()
    }

    #[test]
    fn kinds_round_trip_and_name_the_stored_host_key_kinds() {
        for k in LinkKind::ALL {
            assert_eq!(LinkKind::parse(k.key()), Some(k));
            if let Some(h) = k.host_kind() {
                assert_eq!(LinkKind::of_host_kind(h), Some(k));
            }
        }
        assert_eq!(
            LinkKind::Ssh.host_kind(),
            Some(crate::scan::hostkeys::SSH_HOSTKEY)
        );
        assert_eq!(
            LinkKind::Tls.host_kind(),
            Some(crate::scan::hostkeys::TLS_CERT)
        );
        assert_eq!(
            LinkKind::Hassh.host_kind(),
            Some(crate::scan::hostkeys::HASSH)
        );
        assert_eq!(
            LinkKind::Ja4x.host_kind(),
            Some(crate::scan::hostkeys::JA4X)
        );
        assert_eq!(LinkKind::parse("ip"), None);
    }

    /// Two addresses, each with one `host_keys` row of `kind` and `value`
    /// that a probe stored.
    async fn two_ips_with_probe_keys(kind: &str, value: &str) -> (Store, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mut ids = [0; 2];
        for (i, a) in ["203.0.113.1", "198.51.100.2"].iter().enumerate() {
            ids[i] = s.upsert_ip(a.parse().unwrap()).await.unwrap().id;
            let probe: i64 = sqlx::query_scalar(
                "INSERT INTO probes (uid, group_uid, ip_id, asker, started_at, finished_at)
                 VALUES (?, 'g', ?, x'01', datetime('now'), datetime('now')) RETURNING id",
            )
            .bind(format!("p{i}"))
            .bind(ids[i])
            .fetch_one(&s.pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO host_keys (probe_id, ip_id, port, kind, fingerprint)
                 VALUES (?, ?, 443, ?, ?)",
            )
            .bind(probe)
            .bind(ids[i])
            .bind(kind)
            .bind(value)
            .execute(&s.pool)
            .await
            .unwrap();
        }
        (s, ids[0], ids[1])
    }

    #[tokio::test]
    async fn probe_hashes_link_addresses_softly() {
        let (s, a, b) = two_ips_with_probe_keys("favicon", "-1234567").await;
        let item = s
            .link_item(LinkKind::Favicon, "-1234567")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(item.ips, 2);
        assert!(item.first_seen.is_some(), "time from the probe");
        let _ = (a, b);
        assert!(!LinkKind::Favicon.identity());
        assert!(!LinkKind::Favicon.by_node());
        assert_eq!(LinkKind::parse("http-404"), Some(LinkKind::Http404));
        assert_eq!(LinkKind::of_host_kind("jarm"), Some(LinkKind::Jarm));
        assert!(!LinkKind::IDENTITY.contains(&LinkKind::Jarm));
        assert!(LinkKind::LIST.contains(&LinkKind::HttpBody));
    }

    #[tokio::test]
    async fn list_shared_by_default_all_on_request() {
        let (s, _) = seeded().await;
        assert_eq!(values(&s.links_list(&filter("fp")).await.unwrap()), ["F"]);
        let mut f = filter("fp");
        f.shared = Some("0".into());
        assert_eq!(values(&s.links_list(&f).await.unwrap()), ["F", "G"]);
        let j = s.links_list(&filter("ja4")).await.unwrap();
        assert_eq!(values(&j), ["J"]);
        assert_eq!((j.items[0].ips, j.items[0].sightings), (3, 3));
        // Both SSH keys and the certificate are on a and d.
        assert_eq!(s.links_list(&filter("ssh")).await.unwrap().items.len(), 2);
        assert_eq!(s.links_list(&filter("tls")).await.unwrap().items.len(), 1);
        assert_eq!(s.links_list(&filter("hassh")).await.unwrap().items.len(), 1);
        let c = s.links_list(&filter("canary")).await.unwrap();
        assert_eq!(values(&c), ["77"]);
        assert_eq!(c.items[0].ips, 2, "served and used side");
    }

    #[tokio::test]
    async fn list_filters_prefix_country_dates_node_and_sorts() {
        let (s, ids) = seeded().await;
        let mut f = filter("ssh");
        f.q = Some("sha256:".into());
        assert_eq!(
            s.links_list(&f).await.unwrap().items.len(),
            2,
            "prefix, any case"
        );
        f.q = Some("nomatch".into());
        assert!(s.links_list(&f).await.unwrap().items.is_empty());
        // Country keeps the sightings in that country: J has one there.
        let mut f = filter("ja4");
        f.country = Some("de".into());
        f.shared = Some("0".into());
        let p = s.links_list(&f).await.unwrap();
        assert_eq!(values(&p), ["J"]);
        assert_eq!(p.items[0].ips, 1);
        let mut f = filter("ja4");
        f.from = Some("2999-01-01".into());
        assert!(s.links_list(&f).await.unwrap().items.is_empty());
        let mut f = filter("ja4");
        f.to = Some("2999-01-01".into());
        assert_eq!(s.links_list(&f).await.unwrap().items.len(), 1);
        // Node: only the request recorded by node "n1".
        sqlx::query(
            "INSERT INTO members (id, name, sponsor, info_hlc, admitted_hlc)
             VALUES (x'01', 'n1', x'01', 0, 0)",
        )
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE requests SET origin = x'01' WHERE ip_id = ?")
            .bind(ids[3])
            .execute(&s.pool)
            .await
            .unwrap();
        let mut f = filter("ja4");
        f.shared = Some("0".into());
        f.node = Some("n1".into());
        assert_eq!(values(&s.links_list(&f).await.unwrap()), ["K"]);
        // Scan kinds have no node: the filter is ignored.
        let mut f = filter("ssh");
        f.node = Some("n1".into());
        assert_eq!(s.links_list(&f).await.unwrap().items.len(), 2);
        // Sorts.
        let mut f = filter("ja4");
        f.shared = Some("0".into());
        assert_eq!(
            values(&s.links_list(&f).await.unwrap()),
            ["J", "K"],
            "by IPs"
        );
        f.sort = Some("recent".into());
        assert_eq!(s.links_list(&f).await.unwrap().items.len(), 2);
        f.sort = Some("sightings".into());
        assert_eq!(values(&s.links_list(&f).await.unwrap())[0], "J");
    }

    #[tokio::test]
    async fn list_pages() {
        let (s, ids) = seeded().await;
        for n in 0..(PAGE_SIZE + 5) {
            s.insert_fingerprint(None, ids[3], &format!("P{n:04}"), None, "{}", "{}", b"[]")
                .await
                .unwrap();
        }
        let mut f = filter("fp");
        f.shared = Some("0".into());
        let p1 = s.links_list(&f).await.unwrap();
        assert_eq!(p1.items.len() as i64, PAGE_SIZE);
        assert!(p1.has_next);
        f.page = Some(2);
        let p2 = s.links_list(&f).await.unwrap();
        assert_eq!(p2.items.len(), 7, "105 P + F + G = 107 values");
        assert!(!p2.has_next);
    }

    #[tokio::test]
    async fn item_facts_and_ips() {
        let (s, _) = seeded().await;
        let j = s.link_item(LinkKind::Ja4, "J").await.unwrap().unwrap();
        assert_eq!((j.ips, j.sightings), (3, 3));
        assert_eq!(j.countries, ["DE"]);
        assert_eq!(j.ip_rows.len(), 3);
        let ssh = s.links_list(&filter("ssh")).await.unwrap().items[0]
            .value
            .clone();
        let k = s.link_item(LinkKind::Ssh, &ssh).await.unwrap().unwrap();
        assert!(!k.detail.is_empty(), "nmap's key type");
        assert_eq!(k.ips, 2);
        let c = s.link_item(LinkKind::Canary, "77").await.unwrap().unwrap();
        assert_eq!(c.ips, 2);
        assert!(s.link_item(LinkKind::Fp, "nope").await.unwrap().is_none());
        assert!(
            s.link_item(LinkKind::Canary, "abc")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_value_is_found_in_every_kind_that_has_it() {
        let (s, _) = seeded().await;
        assert_eq!(s.find_value("F").await.unwrap(), [LinkKind::Fp]);
        assert_eq!(s.find_value("J").await.unwrap(), [LinkKind::Ja4]);
        let ssh = s.links_list(&filter("ssh")).await.unwrap().items[0]
            .value
            .clone();
        assert_eq!(s.find_value(&ssh).await.unwrap(), [LinkKind::Ssh]);
        // The same value under two kinds: both.
        s.insert_fingerprint(None, 1, "J", None, "{}", "{}", b"[]")
            .await
            .unwrap();
        assert_eq!(
            s.find_value("J").await.unwrap(),
            [LinkKind::Fp, LinkKind::Ja4]
        );
        assert!(s.find_value("nothing").await.unwrap().is_empty());
        assert!(s.find_value("").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn anchors_resolve_to_items() {
        let (s, _) = seeded().await;
        assert_eq!(
            s.resolve_anchor("F").await.unwrap(),
            Some((LinkKind::Fp, "F".into()))
        );
        let ssh = s.links_list(&filter("ssh")).await.unwrap().items[0]
            .value
            .clone();
        let a = crate::store::hostkeys::anchor(crate::scan::hostkeys::SSH_HOSTKEY, &ssh);
        assert_eq!(
            s.resolve_anchor(&a).await.unwrap(),
            Some((LinkKind::Ssh, ssh))
        );
        assert_eq!(s.resolve_anchor("ssh-000000000000").await.unwrap(), None);
        assert_eq!(s.resolve_anchor("nothing").await.unwrap(), None);
    }

    fn ids(g: &LinkGraph) -> Vec<&str> {
        let mut v: Vec<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        v.sort();
        v
    }

    #[test]
    fn focus_parses() {
        assert_eq!(
            Focus::parse("fp:F"),
            Some(Focus::Item(LinkKind::Fp, "F".into()))
        );
        assert_eq!(
            Focus::parse("ssh:SHA256:a/b+c"),
            Some(Focus::Item(LinkKind::Ssh, "SHA256:a/b+c".into()))
        );
        assert_eq!(
            Focus::parse("ip:2001:DB8::1"),
            Some(Focus::Ip("2001:db8::1".into()))
        );
        assert_eq!(Focus::parse("nope:x"), None);
        assert_eq!(Focus::parse("fp:"), None);
        assert_eq!(Focus::parse("fp"), None);
    }

    #[tokio::test]
    async fn walks_identity_links_by_default() {
        let (s, _) = seeded().await;
        let f = Focus::Item(LinkKind::Fp, "F".into());
        let g = s
            .link_graph(&f, 2, &LinkKind::IDENTITY, false)
            .await
            .unwrap();
        // F → a, b → a's host keys, cert and canary (not J: software).
        assert!(ids(&g).contains(&"ip:203.0.113.1") && ids(&g).contains(&"ip:203.0.113.2"));
        assert!(ids(&g).contains(&"canary:77"));
        assert!(g.nodes.iter().any(|n| n.kind == "ssh"));
        assert!(!g.nodes.iter().any(|n| n.kind == "ja4" || n.kind == "hassh"));
        assert_eq!(g.nodes[0].id, "fp:F");
        assert_eq!(g.nodes[0].hop, 0);
        assert!(!g.truncated);
        // Depth 3 reaches through canary 77 to c.
        let g3 = s
            .link_graph(&f, 3, &LinkKind::IDENTITY, false)
            .await
            .unwrap();
        assert!(ids(&g3).contains(&"ip:198.51.100.3"));
        assert!(!ids(&g).contains(&"ip:198.51.100.3"), "not at depth 2");
    }

    #[tokio::test]
    async fn software_kinds_on_request_and_the_focus_kind_always() {
        let (s, _) = seeded().await;
        let f = Focus::Item(LinkKind::Fp, "F".into());
        let g = s.link_graph(&f, 2, &[LinkKind::Ja4], false).await.unwrap();
        assert!(ids(&g).contains(&"ja4:J"));
        assert!(
            ids(&g).contains(&"ip:203.0.113.1"),
            "fp walked: the focus' kind"
        );
        let e = g
            .edges
            .iter()
            .find(|e| e.a == "ja4:J" || e.b == "ja4:J")
            .unwrap();
        assert!(!e.identity);
        // From an IP.
        let g = s
            .link_graph(
                &Focus::Ip("198.51.100.3".into()),
                1,
                &LinkKind::IDENTITY,
                false,
            )
            .await
            .unwrap();
        assert_eq!(ids(&g), ["canary:77", "fp:G", "ip:198.51.100.3"]);
    }

    #[tokio::test]
    async fn edges_are_not_duplicated() {
        let (s, _) = seeded().await;
        let f = Focus::Item(LinkKind::Fp, "F".into());
        let g = s.link_graph(&f, 3, &LinkKind::ALL, false).await.unwrap();
        let mut keys: Vec<(String, String)> = g
            .edges
            .iter()
            .map(|e| {
                if e.a < e.b {
                    (e.a.clone(), e.b.clone())
                } else {
                    (e.b.clone(), e.a.clone())
                }
            })
            .collect();
        let n = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), n);
        let mut node_ids = ids(&g);
        let m = node_ids.len();
        node_ids.dedup();
        assert_eq!(node_ids.len(), m);
        for e in &g.edges {
            assert!(
                node_ids.contains(&e.a.as_str()) && node_ids.contains(&e.b.as_str()),
                "{e:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_crowded_value_collapses_into_a_group() {
        let (s, _) = seeded().await;
        for n in 0..(GROUP_AT + 5) {
            let ip = s
                .upsert_ip(format!("192.0.2.{}", n + 1).parse().unwrap())
                .await
                .unwrap();
            s.insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ja4: Some("J".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let f = Focus::Ip("203.0.113.1".into());
        let g = s.link_graph(&f, 2, &[LinkKind::Ja4], false).await.unwrap();
        let grp = g.nodes.iter().find(|n| n.kind == "group").expect("a group");
        assert_eq!(grp.id, "group:ja4:J");
        assert_eq!(grp.of.as_deref(), Some("ja4"));
        assert_eq!(grp.ips, Some(GROUP_AT + 5 + 3));
        assert!(!ids(&g).contains(&"ip:192.0.2.1"), "not walked through");
        // Expanding the group lists them all.
        let all = s
            .link_graph(&Focus::Item(LinkKind::Ja4, "J".into()), 1, &[], true)
            .await
            .unwrap();
        assert_eq!(all.nodes.len() as i64, 1 + GROUP_AT + 5 + 3);
        assert!(!all.nodes.iter().any(|n| n.kind == "group"));
    }

    #[tokio::test]
    async fn says_when_it_truncates() {
        let (s, _) = seeded().await;
        // Value Y on 20 IPs (below GROUP_AT), each IP with 30 more values:
        // 1 + 20 + 20 × 30 = 621 nodes at depth 2.
        for n in 0..20 {
            let ip = s
                .upsert_ip(format!("10.9.{n}.1").parse().unwrap())
                .await
                .unwrap();
            s.insert_fingerprint(None, ip.id, "Y", None, "{}", "{}", b"[]")
                .await
                .unwrap();
            for m in 0..30 {
                s.insert_fingerprint(None, ip.id, &format!("Y{n}-{m}"), None, "{}", "{}", b"[]")
                    .await
                    .unwrap();
            }
        }
        let g = s
            .link_graph(
                &Focus::Item(LinkKind::Fp, "Y".into()),
                2,
                &LinkKind::IDENTITY,
                false,
            )
            .await
            .unwrap();
        assert!(g.truncated);
        assert_eq!(g.nodes.len(), GRAPH_MAX);
    }

    #[tokio::test]
    async fn unknown_focus_is_an_empty_graph() {
        let (s, _) = seeded().await;
        let g = s
            .link_graph(
                &Focus::Item(LinkKind::Fp, "nope".into()),
                2,
                &LinkKind::IDENTITY,
                false,
            )
            .await
            .unwrap();
        assert!(g.nodes.is_empty() && g.edges.is_empty());
        let g = s
            .link_graph(
                &Focus::Ip("192.0.2.200".into()),
                2,
                &LinkKind::IDENTITY,
                false,
            )
            .await
            .unwrap();
        assert!(g.nodes.is_empty());
    }
}
