//! Campaigns (roadmap item 2): source IPs tied together by evidence edges.
//! Hard edges are the identity links of [`super::links`] (SSH host key, TLS
//! certificate, browser fingerprint, reused canary); a soft edge (`paths`)
//! joins two IPs whose path shapes ([`super::shapes`]) match closely. The
//! connected components of two or more IPs are the campaigns.
//!
//! Recomputed on each node from replicated rows, never replicated, never
//! written by a person. Every order and tie-break that reaches the output
//! goes by IP text, never by a node's row ids, so nodes holding the same
//! rows compute the same campaigns.
use super::Store;
use super::links::{LinkKind, all_sightings};
use crate::model::shape::SHAPE_V;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Duration;

/// Version of the algorithm and its constants; a change recomputes.
pub const CAMPAIGN_V: i64 = 1;
/// Weighted-Jaccard score a `paths` edge needs.
pub const PATHS_T: f64 = 0.60;
/// The score it needs when the two IPs share a JA4 and JA4H pair (which
/// never forms an edge on its own).
pub const PATHS_T_SUPPORTED: f64 = 0.45;
/// Fewest rare shapes (on at most [`DF_RARE`] IPs) a `paths` edge shares.
pub const MIN_SHARED_RARE: usize = 3;
/// A shape on more IPs than this is common: it weighs in a score but never
/// makes two IPs a candidate pair.
pub const DF_RARE: usize = 50;
/// A `paths` edge joins only IPs whose path activity is at most this many
/// days apart; hard edges have no window.
pub const WINDOW_DAYS: i64 = 30;
/// Shapes considered per IP, its newest first.
pub const MAX_SHAPES_PER_IP: usize = 2000;
/// A hard value on more IPs than this is a shared image or default, not an
/// operator: it forms no edge and is listed as excluded.
pub const HARD_FANOUT_MAX: usize = 50;
/// How often maintenance recomputes (when the inputs changed).
pub const RECOMPUTE_EVERY: Duration = Duration::from_secs(3600);

/// The inputs' signature at the last pass (`settings`).
const KEY_SIGNATURE: &str = "campaigns.signature";
/// The last pass's [`Report`] as JSON (`settings`).
const KEY_REPORT: &str = "campaigns.report";
const PATHS: &str = "paths";

/// What one pass did.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Report {
    /// The inputs had not changed since the last pass: nothing was done.
    pub unchanged: bool,
    pub campaigns: usize,
    pub members: usize,
    /// Edges by kind.
    pub edges: BTreeMap<String, usize>,
    /// Hard values on more than [`HARD_FANOUT_MAX`] IPs.
    pub excluded: Vec<Excluded>,
    pub seconds: f64,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Excluded {
    pub kind: String,
    pub value: String,
    pub ips: usize,
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.unchanged {
            return write!(f, "inputs unchanged since the last pass: nothing to do");
        }
        writeln!(
            f,
            "{} campaigns, {} member IPs, in {:.2} s",
            self.campaigns, self.members, self.seconds
        )?;
        let edges: Vec<String> = self.edges.iter().map(|(k, n)| format!("{k} {n}")).collect();
        writeln!(
            f,
            "edges: {}",
            if edges.is_empty() {
                "none".into()
            } else {
                edges.join(", ")
            }
        )?;
        write!(f, "excluded values (on more than {HARD_FANOUT_MAX} IPs): ")?;
        if self.excluded.is_empty() {
            return write!(f, "none");
        }
        for e in &self.excluded {
            write!(f, "\n  {} {} on {} IPs", e.kind, e.value, e.ips)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct CampaignRow {
    pub key: String,
    pub num: i64,
    pub size: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub hard_edges: i64,
    pub soft_edges: i64,
    pub v: i64,
    pub computed_at: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct Member {
    pub ip_id: i64,
    pub ip: String,
}

/// An evidence edge; `a`'s IP text sorts before `b`'s.
#[derive(Debug, Clone, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct Edge {
    pub a_id: i64,
    pub a: String,
    pub b_id: i64,
    pub b: String,
    pub kind: String,
    /// The shared value of a hard kind; empty for `paths`.
    pub value: String,
    pub score: Option<f64>,
    pub shared: Option<i64>,
    pub fp_support: bool,
    pub first_ts: String,
    pub last_ts: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Campaign {
    pub row: CampaignRow,
    /// By IP text.
    pub members: Vec<Member>,
    /// By `a`, `b`, kind, value.
    pub edges: Vec<Edge>,
}

const ROW_COLS: &str =
    "key, num, size, first_seen, last_seen, hard_edges, soft_edges, v, computed_at";

impl Store {
    /// Recompute every campaign from the stored rows (one read snapshot,
    /// then one write transaction). Unless `force`, does nothing when the
    /// inputs' signature is the last pass's.
    pub async fn recompute_campaigns(&self, force: bool) -> Result<Report> {
        let started = std::time::Instant::now();
        let mut tx = self.pool.begin().await?;
        let sig = signature(&mut tx).await?;
        if !force {
            let last: Option<String> =
                sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
                    .bind(KEY_SIGNATURE)
                    .fetch_optional(&mut *tx)
                    .await?;
            if last.as_deref() == Some(sig.as_str()) {
                tx.rollback().await?;
                return Ok(Report {
                    unchanged: true,
                    ..Report::default()
                });
            }
        }
        let input = Input::read(&mut tx).await?;
        tx.rollback().await?;
        let out = compute(&input);
        let now = super::data::now_ts();

        let mut report = Report {
            unchanged: false,
            campaigns: out.campaigns.len(),
            members: out.members.len(),
            edges: BTreeMap::new(),
            excluded: out.excluded.clone(),
            seconds: 0.0,
        };
        for e in &out.edges {
            *report.edges.entry(e.kind.to_string()).or_default() += 1;
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for sql in [
            "DELETE FROM campaign_edges",
            "DELETE FROM campaign_members",
            "DELETE FROM campaigns",
        ] {
            sqlx::query(sql).execute(&mut *tx).await?;
        }
        for c in &out.campaigns {
            sqlx::query(
                "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
                                        hard_edges, soft_edges, v, computed_at)
                 VALUES (?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(&c.key)
            .bind(c.num)
            .bind(c.anchor_ip_id)
            .bind(c.size)
            .bind(&c.first_seen)
            .bind(&c.last_seen)
            .bind(c.hard_edges)
            .bind(c.soft_edges)
            .bind(CAMPAIGN_V)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        for (ip_id, key) in &out.members {
            sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?,?)")
                .bind(ip_id)
                .bind(key)
                .execute(&mut *tx)
                .await?;
        }
        for e in &out.edges {
            sqlx::query(
                "INSERT INTO campaign_edges (a, b, kind, value, score, shared, fp_support,
                                             first_ts, last_ts)
                 VALUES (?,?,?,?,?,?,?,?,?)",
            )
            .bind(e.a)
            .bind(e.b)
            .bind(e.kind)
            .bind(&e.value)
            .bind(e.score)
            .bind(e.shared)
            .bind(e.fp_support)
            .bind(&e.first_ts)
            .bind(&e.last_ts)
            .execute(&mut *tx)
            .await?;
        }
        report.seconds = started.elapsed().as_secs_f64();
        for (key, value) in [
            (KEY_SIGNATURE, sig),
            (KEY_REPORT, serde_json::to_string(&report)?),
        ] {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(report)
    }

    /// The last pass's report (it lists the excluded values), if any.
    pub async fn campaign_report(&self) -> Result<Option<Report>> {
        let json: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
            .bind(KEY_REPORT)
            .fetch_optional(&self.pool)
            .await?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// Every campaign, by number.
    pub async fn campaign_list(&self) -> Result<Vec<CampaignRow>> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {ROW_COLS} FROM campaigns ORDER BY num"
        )))
        .fetch_all(&self.pool)
        .await?)
    }

    /// A campaign by key, with its members and edges.
    pub async fn campaign(&self, key: &str) -> Result<Option<Campaign>> {
        let Some(row) = sqlx::query_as::<_, CampaignRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {ROW_COLS} FROM campaigns WHERE key = ?"
        )))
        .bind(key)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let members = sqlx::query_as(
            "SELECT m.ip_id, i.ip FROM campaign_members m JOIN ips i ON i.id = m.ip_id
             WHERE m.campaign_key = ? ORDER BY i.ip",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        let edges = sqlx::query_as(
            "SELECT e.a AS a_id, ia.ip AS a, e.b AS b_id, ib.ip AS b, e.kind, e.value,
                    e.score, e.shared, e.fp_support, e.first_ts, e.last_ts
             FROM campaign_edges e
             JOIN campaign_members m ON m.ip_id = e.a
             JOIN ips ia ON ia.id = e.a JOIN ips ib ON ib.id = e.b
             WHERE m.campaign_key = ?
             ORDER BY ia.ip, ib.ip, e.kind, e.value",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        Ok(Some(Campaign {
            row,
            members,
            edges,
        }))
    }

    /// The campaign (key, number) an IP is a member of.
    pub async fn campaign_of_ip(&self, ip_id: i64) -> Result<Option<(String, i64)>> {
        Ok(sqlx::query_as(
            "SELECT c.key, c.num FROM campaign_members m JOIN campaigns c ON c.key = m.campaign_key
             WHERE m.ip_id = ?",
        )
        .bind(ip_id)
        .fetch_optional(&self.pool)
        .await?)
    }
}

/// What the inputs look like: when it is unchanged, so is the result.
async fn signature(conn: &mut sqlx::SqliteConnection) -> Result<String> {
    let n: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM requests), (SELECT COALESCE(MAX(id), 0) FROM requests),
                (SELECT COUNT(*) FROM requests WHERE shape_v = ?1),
                (SELECT COUNT(*) FROM requests WHERE ja4h IS NOT NULL),
                (SELECT COUNT(*) FROM skipped_batches),
                (SELECT COUNT(*) FROM skipped_batches WHERE shape_v = ?1),
                (SELECT COUNT(*) FROM host_keys), (SELECT COUNT(*) FROM fingerprints),
                (SELECT COUNT(*) FROM canaries), (SELECT COUNT(*) FROM request_tokens)",
    )
    .bind(SHAPE_V)
    .fetch_one(&mut *conn)
    .await?;
    Ok(format!(
        "v{CAMPAIGN_V} s{SHAPE_V} {} {} {} {} {} {} {} {} {} {}",
        n.0, n.1, n.2, n.3, n.4, n.5, n.6, n.7, n.8, n.9
    ))
}

/// The rows a pass reads, as read.
#[derive(Default)]
struct Input {
    /// IP text by id.
    ips: HashMap<i64, String>,
    /// Hard sightings: kind, value, IP, time.
    sightings: Vec<(LinkKind, String, i64, Option<String>)>,
    /// Shapes asked for: IP, shape, first and last time.
    shapes: Vec<(i64, i64, String, String)>,
    /// (JA4, JA4H) pairs seen per IP.
    tls: Vec<(i64, String, String)>,
}

impl Input {
    async fn read(conn: &mut sqlx::SqliteConnection) -> Result<Input> {
        let mut input = Input {
            ips: sqlx::query_as::<_, (i64, String)>("SELECT id, ip FROM ips")
                .fetch_all(&mut *conn)
                .await?
                .into_iter()
                .collect(),
            ..Input::default()
        };
        for kind in LinkKind::IDENTITY {
            let rows: Vec<(String, i64, Option<String>)> = sqlx::query_as(sqlx::AssertSqlSafe(
                format!("SELECT v, ip_id, ts FROM ({})", all_sightings(kind)),
            ))
            .fetch_all(&mut *conn)
            .await?;
            input
                .sightings
                .extend(rows.into_iter().map(|(v, ip, ts)| (kind, v, ip, ts)));
        }
        input.shapes = sqlx::query_as(
            "SELECT ip_id, shape, MIN(ts), MAX(ts) FROM requests
             WHERE shape IS NOT NULL GROUP BY ip_id, shape",
        )
        .fetch_all(&mut *conn)
        .await?;
        let light: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT b.ip_id, s.shape, MIN(s.ts_ms), MAX(s.ts_ms)
             FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
             WHERE s.shape IS NOT NULL GROUP BY b.ip_id, s.shape",
        )
        .fetch_all(&mut *conn)
        .await?;
        input
            .shapes
            .extend(light.into_iter().map(|(ip, shape, first, last)| {
                (
                    ip,
                    shape,
                    super::shapes::ts_text(first),
                    super::shapes::ts_text(last),
                )
            }));
        input.tls = sqlx::query_as(
            "SELECT DISTINCT ip_id, ja4, ja4h FROM requests
             WHERE ja4 IS NOT NULL AND ja4h IS NOT NULL",
        )
        .fetch_all(&mut *conn)
        .await?;
        Ok(input)
    }
}

struct CampaignOut {
    key: String,
    num: i64,
    anchor_ip_id: i64,
    size: i64,
    first_seen: String,
    last_seen: String,
    hard_edges: i64,
    soft_edges: i64,
}

struct EdgeOut {
    /// ip ids.
    a: i64,
    b: i64,
    kind: &'static str,
    value: String,
    score: Option<f64>,
    shared: Option<i64>,
    fp_support: bool,
    first_ts: String,
    last_ts: String,
}

struct Output {
    campaigns: Vec<CampaignOut>,
    /// (ip id, campaign key).
    members: Vec<(i64, String)>,
    edges: Vec<EdgeOut>,
    excluded: Vec<Excluded>,
}

/// An edge between nodes `a < b` (indexes in IP-text order).
struct Link {
    a: usize,
    b: usize,
    kind: &'static str,
    value: String,
    score: Option<f64>,
    shared: Option<i64>,
    fp_support: bool,
    first: Option<String>,
    last: Option<String>,
}

/// A first and last time, either unknown.
type Span = (Option<String>, Option<String>);

fn widen(span: &mut Span, first: Option<&str>, last: Option<&str>) {
    if let Some(f) = first
        && span.0.as_deref().is_none_or(|s| f < s)
    {
        span.0 = Some(f.to_string());
    }
    if let Some(l) = last
        && span.1.as_deref().is_none_or(|s| l > s)
    {
        span.1 = Some(l.to_string());
    }
}

/// Seconds since the epoch of a time as the rows hold it.
fn epoch(ts: &str) -> Option<i64> {
    let t = ts.get(..19)?.replacen('T', " ", 1);
    chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc().timestamp())
}

/// Whether two spans of activity are more than [`WINDOW_DAYS`] apart.
fn apart(x: &Span, y: &Span) -> bool {
    let (Some(xf), Some(xl), Some(yf), Some(yl)) = (
        x.0.as_deref().and_then(epoch),
        x.1.as_deref().and_then(epoch),
        y.0.as_deref().and_then(epoch),
        y.1.as_deref().and_then(epoch),
    ) else {
        return false;
    };
    xf.max(yf) - xl.min(yl) > WINDOW_DAYS * 86_400
}

fn find(parent: &mut [usize], mut i: usize) -> usize {
    while parent[i] != i {
        parent[i] = parent[parent[i]];
        i = parent[i];
    }
    i
}

/// The campaigns `input` makes; a pure function of the rows (ids are only
/// carried through, never compared).
fn compute(input: &Input) -> Output {
    // The universe in IP-text order: node i is `nodes[i]`.
    let mut ids: BTreeSet<i64> = input.sightings.iter().map(|s| s.2).collect();
    ids.extend(input.shapes.iter().map(|s| s.0));
    let mut nodes: Vec<(&str, i64)> = ids
        .into_iter()
        .filter_map(|id| input.ips.get(&id).map(|ip| (ip.as_str(), id)))
        .collect();
    nodes.sort();
    let index: HashMap<i64, usize> = nodes.iter().enumerate().map(|(i, n)| (n.1, i)).collect();
    let n = nodes.len();
    // When each node was active (requests, light rows, hard sightings), and
    // when it asked for paths.
    let mut active: Vec<Span> = vec![(None, None); n];
    let mut path_active: Vec<Span> = vec![(None, None); n];
    let mut links: Vec<Link> = vec![];
    let mut excluded = vec![];

    // Hard edges: every pair of IPs sharing a value, unless too many do.
    let mut values: BTreeMap<(&'static str, &str), BTreeMap<usize, Span>> = BTreeMap::new();
    for (kind, value, ip, ts) in &input.sightings {
        let Some(&i) = index.get(ip) else { continue };
        widen(&mut active[i], ts.as_deref(), ts.as_deref());
        let span = values
            .entry((kind.key(), value.as_str()))
            .or_default()
            .entry(i)
            .or_insert((None, None));
        widen(span, ts.as_deref(), ts.as_deref());
    }
    for ((kind, value), ips) in &values {
        if ips.len() > HARD_FANOUT_MAX {
            excluded.push(Excluded {
                kind: kind.to_string(),
                value: value.to_string(),
                ips: ips.len(),
            });
            continue;
        }
        let ips: Vec<(usize, &Span)> = ips.iter().map(|(&i, s)| (i, s)).collect();
        for (x, &(a, sa)) in ips.iter().enumerate() {
            for &(b, sb) in &ips[x + 1..] {
                let mut span = sa.clone();
                widen(&mut span, sb.0.as_deref(), sb.1.as_deref());
                links.push(Link {
                    a,
                    b,
                    kind,
                    value: value.to_string(),
                    score: None,
                    shared: None,
                    fp_support: false,
                    first: span.0,
                    last: span.1,
                });
            }
        }
    }

    // Shape sets: per node, shape → when asked for, the newest
    // MAX_SHAPES_PER_IP kept, in shape order.
    let mut asked: Vec<BTreeMap<i64, (&str, &str)>> = vec![BTreeMap::new(); n];
    for (ip, shape, first, last) in &input.shapes {
        let Some(&i) = index.get(ip) else { continue };
        widen(&mut active[i], Some(first), Some(last));
        widen(&mut path_active[i], Some(first), Some(last));
        let e = asked[i].entry(*shape).or_insert((first, last));
        e.0 = e.0.min(first.as_str());
        e.1 = e.1.max(last.as_str());
    }
    let sets: Vec<Vec<(i64, &str, &str)>> = asked
        .into_iter()
        .map(|m| {
            let mut v: Vec<(i64, &str, &str)> =
                m.into_iter().map(|(s, (f, l))| (s, f, l)).collect();
            if v.len() > MAX_SHAPES_PER_IP {
                v.sort_by(|x, y| y.2.cmp(x.2).then(x.0.cmp(&y.0)));
                v.truncate(MAX_SHAPES_PER_IP);
                v.sort_by_key(|x| x.0);
            }
            v
        })
        .collect();
    // Document frequency: the nodes asking for each shape, in node order.
    let mut df: HashMap<i64, Vec<usize>> = HashMap::new();
    for (i, set) in sets.iter().enumerate() {
        for s in set {
            df.entry(s.0).or_default().push(i);
        }
    }
    let weight = |shape: i64| (1.0 + n as f64 / df[&shape].len() as f64).ln();
    let rare = |shape: i64| df[&shape].len() <= DF_RARE;

    // Candidates: pairs sharing a rare shape.
    let mut pairs: BTreeSet<(usize, usize)> = BTreeSet::new();
    for ips in df.values().filter(|v| (2..=DF_RARE).contains(&v.len())) {
        for (x, &a) in ips.iter().enumerate() {
            for &b in &ips[x + 1..] {
                pairs.insert((a, b));
            }
        }
    }
    let mut tls: Vec<BTreeSet<(&str, &str)>> = vec![BTreeSet::new(); n];
    for (ip, ja4, ja4h) in &input.tls {
        if let Some(&i) = index.get(ip) {
            tls[i].insert((ja4, ja4h));
        }
    }
    for (a, b) in pairs {
        if apart(&path_active[a], &path_active[b]) {
            continue;
        }
        let (sa, sb) = (&sets[a], &sets[b]);
        let (mut x, mut y) = (0, 0);
        let (mut shared_w, mut union_w) = (0.0, 0.0);
        let (mut shared, mut shared_rare) = (0i64, 0usize);
        let mut span: Span = (None, None);
        while x < sa.len() || y < sb.len() {
            let ord = match (sa.get(x), sb.get(y)) {
                (Some(p), Some(q)) => p.0.cmp(&q.0),
                (Some(_), None) => std::cmp::Ordering::Less,
                _ => std::cmp::Ordering::Greater,
            };
            match ord {
                std::cmp::Ordering::Less => {
                    union_w += weight(sa[x].0);
                    x += 1;
                }
                std::cmp::Ordering::Greater => {
                    union_w += weight(sb[y].0);
                    y += 1;
                }
                std::cmp::Ordering::Equal => {
                    let (p, q) = (sa[x], sb[y]);
                    let w = weight(p.0);
                    shared_w += w;
                    union_w += w;
                    shared += 1;
                    shared_rare += rare(p.0) as usize;
                    widen(&mut span, Some(p.1.min(q.1)), Some(p.2.max(q.2)));
                    x += 1;
                    y += 1;
                }
            }
        }
        if shared_rare < MIN_SHARED_RARE || union_w <= 0.0 {
            continue;
        }
        let score = shared_w / union_w;
        if score < PATHS_T_SUPPORTED {
            continue;
        }
        let fp_support = tls[a].iter().any(|p| tls[b].contains(p));
        if score
            < if fp_support {
                PATHS_T_SUPPORTED
            } else {
                PATHS_T
            }
        {
            continue;
        }
        links.push(Link {
            a,
            b,
            kind: PATHS,
            value: String::new(),
            score: Some(score),
            shared: Some(shared),
            fp_support,
            first: span.0,
            last: span.1,
        });
    }

    // Components of two or more nodes.
    let mut parent: Vec<usize> = (0..n).collect();
    for l in &links {
        let (ra, rb) = (find(&mut parent, l.a), find(&mut parent, l.b));
        if ra != rb {
            parent[ra.max(rb)] = ra.min(rb);
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }
    let mut hard: HashMap<usize, i64> = HashMap::new();
    let mut soft: HashMap<usize, i64> = HashMap::new();
    for l in &links {
        let r = find(&mut parent, l.a);
        *if l.kind == PATHS {
            &mut soft
        } else {
            &mut hard
        }
        .entry(r)
        .or_default() += 1;
    }
    // Per component: its anchor (the member active first, ties by IP text,
    // members with no known time last) and span.
    let mut found: Vec<(usize, usize, Span, i64)> = vec![];
    for (r, members) in &groups {
        if members.len() < 2 {
            continue;
        }
        let anchor = *members
            .iter()
            .min_by(|&&x, &&y| {
                let (fx, fy) = (&active[x].0, &active[y].0);
                (fx.is_none(), fx, x).cmp(&(fy.is_none(), fy, y))
            })
            .expect("two or more members");
        let mut span: Span = (None, None);
        for &m in members {
            widen(&mut span, active[m].0.as_deref(), active[m].1.as_deref());
        }
        found.push((*r, anchor, span, members.len() as i64));
    }
    // Numbered by (first seen, key); unknown times last.
    found.sort_by(|x, y| {
        (x.2.0.is_none(), &x.2.0, nodes[x.1].0).cmp(&(y.2.0.is_none(), &y.2.0, nodes[y.1].0))
    });
    let mut campaigns = vec![];
    let mut key_of: HashMap<usize, String> = HashMap::new();
    for (num, (r, anchor, span, size)) in found.into_iter().enumerate() {
        let key = nodes[anchor].0.to_string();
        key_of.insert(r, key.clone());
        campaigns.push(CampaignOut {
            key,
            num: num as i64 + 1,
            anchor_ip_id: nodes[anchor].1,
            size,
            first_seen: span.0.unwrap_or_default(),
            last_seen: span.1.unwrap_or_default(),
            hard_edges: hard.get(&r).copied().unwrap_or(0),
            soft_edges: soft.get(&r).copied().unwrap_or(0),
        });
    }
    let mut members = vec![];
    for (r, ms) in &groups {
        if let Some(key) = key_of.get(r) {
            members.extend(ms.iter().map(|&m| (nodes[m].1, key.clone())));
        }
    }
    let edges = links
        .into_iter()
        .map(|l| EdgeOut {
            a: nodes[l.a].1,
            b: nodes[l.b].1,
            kind: l.kind,
            value: l.value,
            score: l.score,
            shared: l.shared,
            fp_support: l.fp_support,
            first_ts: l.first.unwrap_or_default(),
            last_ts: l.last.unwrap_or_default(),
        })
        .collect();
    Output {
        campaigns,
        members,
        edges,
        excluded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    const CTX: Ctx<'static> = Ctx {
        origin: None,
        hlc: 1,
    };

    /// A step of a fixture: a replicated record, or a host key a probe
    /// stored at a time.
    enum Op {
        Rec(Record),
        Key(&'static str, &'static str, String, &'static str),
    }

    fn req(ip: &str, ts: &str, path: &str) -> Op {
        Op::Rec(Record::Request(Box::new(RequestRec {
            uid: format!("{ip} {ts} {path}"),
            ts: ts.into(),
            ip: ip.into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })))
    }

    fn light(ip: &str, ts_ms: i64, paths: &[String]) -> Op {
        Op::Rec(Record::SkipBatch(SkipBatchRec {
            uid: format!("{ip} {ts_ms}"),
            ip: ip.into(),
            dropped: 0,
            rows: paths
                .iter()
                .map(|p| SkipRow {
                    ts_ms,
                    method: "GET".into(),
                    path: p.clone(),
                    page_token: None,
                    host: None,
                    answer: None,
                    decoy_v: None,
                    decoy_site: None,
                    held_ms: None,
                    decoy_in: None,
                })
                .collect(),
            build: String::new(),
        }))
    }

    /// Letters only (digits would all be one shape, `{n}`).
    fn word(i: usize) -> String {
        format!(
            "{}{}",
            (b'a' + (i / 26) as u8) as char,
            (b'a' + (i % 26) as u8) as char
        )
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (s, dir)
    }

    async fn feed(s: &Store, ops: impl IntoIterator<Item = Op>) {
        for op in ops {
            match op {
                Op::Rec(r) => {
                    let mut conn = s.pool.acquire().await.unwrap();
                    apply(&mut conn, CTX, &r).await.unwrap();
                }
                Op::Key(ip, kind, value, ts) => {
                    let ip_id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
                    let probe: i64 = sqlx::query_scalar(
                        "INSERT INTO probes (uid, group_uid, ip_id, asker, started_at, finished_at)
                         VALUES (?, 'g', ?, x'01', ?3, ?3) RETURNING id",
                    )
                    .bind(format!("{ip} {kind} {value}"))
                    .bind(ip_id)
                    .bind(ts)
                    .fetch_one(&s.pool)
                    .await
                    .unwrap();
                    sqlx::query(
                        "INSERT INTO host_keys (probe_id, ip_id, port, kind, fingerprint)
                         VALUES (?, ?, 22, ?, ?)",
                    )
                    .bind(probe)
                    .bind(ip_id)
                    .bind(kind)
                    .bind(value)
                    .execute(&s.pool)
                    .await
                    .unwrap();
                }
            }
        }
    }

    /// Give an IP's requests a JA4 and JA4H.
    async fn tls(s: &Store, ip: &str, ja4: &str, ja4h: &str) {
        sqlx::query(
            "UPDATE requests SET ja4 = ?, ja4h = ? WHERE ip_id = (SELECT id FROM ips WHERE ip = ?)",
        )
        .bind(ja4)
        .bind(ja4h)
        .bind(ip)
        .execute(&s.pool)
        .await
        .unwrap();
    }

    /// 2026-10-04 12:00:00 UTC, in ms.
    const NOON: i64 = 1_791_115_200_000;

    /// (a) three IPs sharing an SSH host key, the last by IP text active
    /// first; (b) a 132-path sweep and a 131-path one, partly as light rows;
    /// (c) two crawlers sharing only robots.txt and favicon.ico; (d) two
    /// pairs at about 0.5, one sharing JA4 and JA4H (`tls_fixture`); (e) a
    /// TLS certificate on 60 IPs that also crawl.
    fn fixture() -> Vec<Op> {
        let mut ops = vec![
            req("192.0.2.1", "2026-09-02 10:00:00", "/alpha"),
            req("192.0.2.2", "2026-09-03 10:00:00", "/beta"),
            req("192.0.2.3", "2026-09-01 10:00:00", "/gamma"),
        ];
        for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
            ops.push(Op::Key(
                ip,
                "ssh-hostkey",
                "SHA256:operator".into(),
                "2026-09-05 00:00:00",
            ));
        }
        let sweep: Vec<String> = (0..132).map(|i| format!("/{}/.env", word(i))).collect();
        for p in &sweep {
            ops.push(req("198.51.100.10", "2026-10-04 11:00:00", p));
        }
        for p in &sweep[1..100] {
            ops.push(req("198.51.100.11", "2026-10-04 13:00:00", p));
        }
        ops.push(light("198.51.100.11", NOON + 3_600_000, &sweep[100..]));
        for ip in ["203.0.113.20", "203.0.113.21"] {
            ops.push(req(ip, "2026-10-01 00:00:00", "/robots.txt"));
            ops.push(req(ip, "2026-10-01 00:00:01", "/favicon.ico"));
        }
        for (pair, ips) in [
            ("d", ["198.51.100.30", "198.51.100.31"]),
            ("e", ["198.51.100.40", "198.51.100.41"]),
        ] {
            for i in 0..8 {
                for ip in ips {
                    ops.push(req(
                        ip,
                        "2026-10-02 00:00:00",
                        &format!("/{pair}shared/{}", word(i)),
                    ));
                }
            }
            for (side, ip) in ips.iter().enumerate() {
                for i in 0..3 {
                    ops.push(req(
                        ip,
                        "2026-10-02 00:00:00",
                        &format!("/{pair}own{side}/{}", word(i)),
                    ));
                }
            }
        }
        for i in 1..=60 {
            let ip: &'static str = Box::leak(format!("10.0.0.{i}").into_boxed_str());
            ops.push(req(ip, "2026-10-03 00:00:00", "/robots.txt"));
            ops.push(req(ip, "2026-10-03 00:00:01", "/favicon.ico"));
            ops.push(Op::Key(
                ip,
                "tls-cert",
                "SHA256:image".into(),
                "2026-10-03 00:00:02",
            ));
        }
        ops
    }

    async fn tls_fixture(s: &Store) {
        tls(s, "198.51.100.30", "t13d1516h2_x", "ge11nn05enus_y").await;
        tls(s, "198.51.100.31", "t13d1516h2_x", "ge11nn05enus_y").await;
        tls(s, "198.51.100.40", "t13d1516h2_x", "ge11nn05enus_y").await;
        tls(s, "198.51.100.41", "t13d1516h2_z", "ge11nn05enus_y").await;
    }

    type Dump = (
        Vec<(String, i64, String, i64, String, String, i64, i64, i64)>,
        Vec<(String, String)>,
        Vec<(
            String,
            String,
            String,
            String,
            Option<f64>,
            Option<i64>,
            bool,
            String,
            String,
        )>,
    );

    /// The three tables keyed by IP text, never by a node's ids.
    async fn dump(s: &Store) -> Dump {
        let campaigns = sqlx::query_as(
            "SELECT c.key, c.num, i.ip, c.size, c.first_seen, c.last_seen, c.hard_edges,
                    c.soft_edges, c.v
             FROM campaigns c JOIN ips i ON i.id = c.anchor_ip_id ORDER BY c.key",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        let members = sqlx::query_as(
            "SELECT i.ip, m.campaign_key FROM campaign_members m JOIN ips i ON i.id = m.ip_id
             ORDER BY i.ip",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        let edges = sqlx::query_as(
            "SELECT ia.ip, ib.ip, e.kind, e.value, e.score, e.shared, e.fp_support,
                    e.first_ts, e.last_ts
             FROM campaign_edges e JOIN ips ia ON ia.id = e.a JOIN ips ib ON ib.id = e.b
             ORDER BY 1, 2, 3, 4",
        )
        .fetch_all(&s.pool)
        .await
        .unwrap();
        (campaigns, members, edges)
    }

    async fn ip_id(s: &Store, ip: &str) -> i64 {
        sqlx::query_scalar("SELECT id FROM ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_fixture_makes_the_expected_campaigns() {
        let (s, _dir) = store().await;
        feed(&s, fixture()).await;
        tls_fixture(&s).await;
        let r = s.recompute_campaigns(false).await.unwrap();
        eprintln!("fixture pass: {:.3} s\n{r}", r.seconds);
        assert!(!r.unchanged);
        assert_eq!(r.campaigns, 3, "{r}");
        assert_eq!(r.members, 3 + 2 + 2);
        assert_eq!(
            r.edges,
            BTreeMap::from([("paths".to_string(), 2), ("ssh".to_string(), 3)])
        );
        // (e) excluded, and listed in the report and the stored one.
        let excluded = vec![Excluded {
            kind: "tls".into(),
            value: "SHA256:image".into(),
            ips: 60,
        }];
        assert_eq!(r.excluded, excluded);
        assert_eq!(s.campaign_report().await.unwrap().unwrap(), r);

        // (a) one campaign of SSH edges, keyed by the member active first.
        let a = s.campaign("192.0.2.3").await.unwrap().unwrap();
        assert_eq!(a.row.num, 1);
        assert_eq!(a.row.size, 3);
        assert_eq!((a.row.hard_edges, a.row.soft_edges), (3, 0));
        assert_eq!(a.row.first_seen, "2026-09-01 10:00:00");
        assert_eq!(a.row.last_seen, "2026-09-05 00:00:00");
        let ips: Vec<&str> = a.members.iter().map(|m| m.ip.as_str()).collect();
        assert_eq!(ips, ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
        assert!(
            a.edges
                .iter()
                .all(|e| e.kind == "ssh" && e.value == "SHA256:operator")
        );
        assert!(a.edges.iter().all(|e| e.a < e.b));

        // (b) one campaign, a paths edge above 0.9.
        let b = s.campaign("198.51.100.10").await.unwrap().unwrap();
        assert_eq!(b.row.size, 2);
        assert_eq!(b.edges.len(), 1);
        let e = &b.edges[0];
        assert_eq!((e.kind.as_str(), e.value.as_str()), ("paths", ""));
        assert!(e.score.unwrap() > 0.9, "{e:?}");
        assert_eq!(e.shared, Some(131));
        assert!(!e.fp_support);

        // (c) no campaign for the crawlers.
        for ip in ["203.0.113.20", "203.0.113.21"] {
            assert_eq!(s.campaign_of_ip(ip_id(&s, ip).await).await.unwrap(), None);
        }

        // (d) at about 0.5, an edge only with JA4 and JA4H support.
        let d = s.campaign("198.51.100.30").await.unwrap().unwrap();
        let e = &d.edges[0];
        assert!(e.fp_support, "{e:?}");
        let score = e.score.unwrap();
        assert!((PATHS_T_SUPPORTED..PATHS_T).contains(&score), "{score}");
        assert_eq!(e.shared, Some(8));
        for ip in ["198.51.100.40", "198.51.100.41"] {
            assert_eq!(s.campaign_of_ip(ip_id(&s, ip).await).await.unwrap(), None);
        }
        assert_eq!(
            s.campaign_of_ip(ip_id(&s, "198.51.100.31").await)
                .await
                .unwrap(),
            Some(("198.51.100.30".to_string(), d.row.num))
        );

        // (e) none of the 60 is a member.
        assert_eq!(
            s.campaign_of_ip(ip_id(&s, "10.0.0.7").await).await.unwrap(),
            None
        );

        let list = s.campaign_list().await.unwrap();
        let keys: Vec<(&str, i64)> = list.iter().map(|c| (c.key.as_str(), c.num)).collect();
        assert_eq!(
            keys,
            [("192.0.2.3", 1), ("198.51.100.30", 2), ("198.51.100.10", 3)]
        );
        assert!(list.iter().all(|c| c.v == CAMPAIGN_V));
    }

    #[tokio::test]
    async fn nodes_with_the_same_rows_agree_whatever_their_ids() {
        let (s1, _d1) = store().await;
        let (s2, _d2) = store().await;
        feed(&s1, fixture()).await;
        feed(&s2, fixture().into_iter().rev()).await;
        tls_fixture(&s1).await;
        tls_fixture(&s2).await;
        assert_ne!(
            ip_id(&s1, "192.0.2.3").await,
            ip_id(&s2, "192.0.2.3").await,
            "the two stores number IPs differently"
        );
        s1.recompute_campaigns(false).await.unwrap();
        s2.recompute_campaigns(false).await.unwrap();
        let d1 = dump(&s1).await;
        assert_eq!(d1.0.len(), 3);
        assert_eq!(d1, dump(&s2).await);
        // And again, the same.
        s1.recompute_campaigns(true).await.unwrap();
        assert_eq!(d1, dump(&s1).await);
    }

    #[tokio::test]
    async fn soft_edges_need_activity_within_the_window() {
        let (s, _dir) = store().await;
        let paths: Vec<String> = (0..5).map(|i| format!("/{}/wp", word(i))).collect();
        let mut ops = vec![];
        for p in &paths {
            ops.push(req("192.0.2.50", "2026-08-01 00:00:00", p));
            ops.push(req("192.0.2.51", "2026-09-10 00:00:00", p));
        }
        feed(&s, ops).await;
        let r = s.recompute_campaigns(false).await.unwrap();
        assert_eq!((r.campaigns, r.edges.len()), (0, 0), "40 days apart");
        feed(
            &s,
            ["192.0.2.50", "192.0.2.51"]
                .map(|ip| Op::Key(ip, "ssh-hostkey", "SHA256:k".into(), "2026-09-10 00:00:00")),
        )
        .await;
        let r = s.recompute_campaigns(false).await.unwrap();
        assert_eq!(r.campaigns, 1);
        assert_eq!(r.edges, BTreeMap::from([("ssh".to_string(), 1)]));
        let c = s.campaign("192.0.2.50").await.unwrap().unwrap();
        assert_eq!(c.row.size, 2);
    }

    #[tokio::test]
    async fn unchanged_inputs_write_nothing() {
        let (s, _dir) = store().await;
        feed(&s, fixture()).await;
        assert!(!s.recompute_campaigns(false).await.unwrap().unchanged);
        let mark = "2000-01-01 00:00:00";
        sqlx::query("UPDATE campaigns SET computed_at = ?")
            .bind(mark)
            .execute(&s.pool)
            .await
            .unwrap();
        let r = s.recompute_campaigns(false).await.unwrap();
        assert!(r.unchanged);
        let at: Vec<String> = sqlx::query_scalar("SELECT DISTINCT computed_at FROM campaigns")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        assert_eq!(at, [mark]);
        // A new row changes the signature.
        feed(&s, [req("192.0.2.9", "2026-10-05 00:00:00", "/x")]).await;
        assert!(!s.recompute_campaigns(false).await.unwrap().unchanged);
        let at: Vec<String> = sqlx::query_scalar("SELECT DISTINCT computed_at FROM campaigns")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        assert_ne!(at, [mark]);
    }

    #[tokio::test]
    async fn a_failed_pass_is_only_logged() {
        let (s, _dir) = store().await;
        feed(&s, fixture()).await;
        sqlx::query("DROP TABLE campaign_edges")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(s.recompute_campaigns(false).await.is_err());
        // Returns (logs a warning) rather than panicking or stopping.
        crate::store::maintenance::recompute_campaigns(&s).await;
    }

    #[test]
    fn spans_apart_by_more_than_the_window() {
        let span = |f: &str, l: &str| (Some(f.to_string()), Some(l.to_string()));
        let x = span("2026-08-01 00:00:00", "2026-08-02 00:00:00");
        assert!(!apart(
            &x,
            &span("2026-09-01 00:00:00", "2026-09-03 00:00:00")
        ));
        assert!(apart(
            &x,
            &span("2026-09-01 00:00:01", "2026-09-03 00:00:00")
        ));
        assert!(!apart(
            &x,
            &span("2026-07-01 00:00:00", "2026-09-03 00:00:00")
        ));
        assert!(!apart(&x, &(None, None)));
    }
}
