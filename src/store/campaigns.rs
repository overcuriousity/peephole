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
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration;

/// Version of the algorithm and its constants; a change recomputes.
pub const CAMPAIGN_V: i64 = 2;
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
/// Soft edges two groups of two or more IPs need between them to merge.
pub const K_SOFT_MERGE: usize = 2;
/// Fewest shared shapes a pair needs for an order term.
pub const ORDER_MIN_SHARED: usize = 8;
/// Fewest untied pairs of shared shapes a pair needs for an order term (8
/// distinct ranks).
pub const ORDER_MIN_PAIRS: usize = 28;
/// The rarest shared shapes the order term looks at.
pub const ORDER_MAX: usize = 500;
/// An order agreement at or above this supports a pair like a shared JA4
/// and JA4H.
pub const ORDER_AGREE: f64 = 0.5;
/// An order agreement at or below this: the pair forms no edge (a tuning
/// value; [`Params::V2`] has no veto).
pub const ORDER_VETO: f64 = -0.3;
/// Shared shapes stored per `paths` edge for its page, the rarest first.
pub const EDGE_SHAPES_MAX: usize = 100;
/// How often maintenance recomputes (when the inputs changed).
pub const RECOMPUTE_EVERY: Duration = Duration::from_secs(3600);

/// The inputs' signature at the last pass (`settings`).
const KEY_SIGNATURE: &str = "campaigns.signature";
/// The last pass's [`Report`] as JSON (`settings`).
const KEY_REPORT: &str = "campaigns.report";
const PATHS: &str = "paths";

/// The knobs of [`compute`]: whether the order of the shared shapes counts
/// (`agree` and `veto` apply only then) and how many soft edges two groups
/// need to merge (`None`: one, as in v1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    pub order: bool,
    pub agree: f64,
    pub veto: Option<f64>,
    pub guard: Option<usize>,
}

impl Params {
    pub const V1: Params = Params {
        order: false,
        agree: ORDER_AGREE,
        veto: Some(ORDER_VETO),
        guard: None,
    };
    pub const V2: Params = Params {
        order: true,
        agree: ORDER_AGREE,
        veto: None,
        guard: Some(K_SOFT_MERGE),
    };
}

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
    /// When the pass ran (as `requests.ts`); absent in reports written
    /// before it was recorded.
    #[serde(default)]
    pub at: Option<String>,
    /// Soft edges between groups that did not merge (not stored).
    #[serde(default)]
    pub withheld: usize,
    /// Candidate pairs whose shapes came in opposite orders.
    #[serde(default)]
    pub vetoed: usize,
    /// Pairs whose shape sets scored high enough for the order term.
    #[serde(default)]
    pub candidates: usize,
    /// Of those, the pairs with an order agreement.
    #[serde(default)]
    pub ordered: usize,
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
        writeln!(
            f,
            "withheld soft edges {}, vetoed pairs {}, order known for {} of {} candidate pairs",
            self.withheld, self.vetoed, self.ordered, self.candidates
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
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub requests: i64,
}

/// The admin list's filter (`/admin/evidence/campaigns`); empty or unparsable
/// values are ignored.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct CampaignFilter {
    /// ISO 3166 alpha-2: a member is there.
    pub country: Option<String>,
    /// `64496` or `AS64496`: a member is in it.
    pub asn: Option<String>,
    /// At least this many members.
    pub min: Option<String>,
    /// Active on or after / on or before this day (`YYYY-MM-DD`, UTC).
    pub from: Option<String>,
    pub to: Option<String>,
}

impl CampaignFilter {
    fn country(&self) -> Option<String> {
        self.country
            .as_deref()
            .map(str::trim)
            .filter(|c| c.len() == 2)
            .map(str::to_ascii_uppercase)
    }

    fn asn(&self) -> Option<i64> {
        let a = self.asn.as_deref()?.trim();
        let a = a
            .strip_prefix("AS")
            .or_else(|| a.strip_prefix("as"))
            .unwrap_or(a);
        a.parse().ok()
    }

    fn min(&self) -> Option<i64> {
        self.min.as_deref()?.trim().parse().ok()
    }

    fn day(d: &Option<String>) -> Option<&str> {
        d.as_deref()
            .map(str::trim)
            .filter(|d| d.len() == 10 && chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").is_ok())
    }
}

/// A campaign as the admin list shows it: the row and where its members
/// are, most members first.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CampaignListItem {
    pub row: CampaignRow,
    /// (country, members); members of unknown country are not counted.
    pub countries: Vec<(String, i64)>,
    /// (ASN, organisation, members).
    pub asns: Vec<(i64, Option<String>, i64)>,
    /// Agent-driven: a member carries an agent label.
    pub agent: bool,
}

/// A path shape the members asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct CampaignShape {
    pub text: String,
    /// Members that asked for it.
    pub members: i64,
    /// IPs that asked for it, over the whole dataset.
    pub df: i64,
    pub first_seen: String,
    /// The exploit wave it formed, if one.
    pub wave: Option<super::waves::WaveMark>,
}

/// A webshell command the members ran.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct CampaignCommand {
    /// Attacker-controlled (`requests.cmd`, capped).
    pub cmd: String,
    pub count: i64,
    /// Members that ran it.
    pub ips: i64,
    pub last_ts: String,
}

/// Shapes listed on a campaign's page.
pub const CAMPAIGN_SHAPES: i64 = 25;

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
    /// A `paths` edge's order agreement, -1..1, when known.
    pub agreement: Option<f64>,
}

/// What tied a `paths` edge, as the pass stored it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EdgeDetail {
    /// The shared shapes (text, document frequency), the rarest
    /// [`EDGE_SHAPES_MAX`] first.
    pub shapes: Vec<(String, i64)>,
    /// The (JA4, JA4H) pairs both IPs sent.
    pub tls: Vec<(String, String)>,
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
        self.recompute_with(force, &Params::V2).await
    }

    /// [`Self::recompute_campaigns`] with the given parameters.
    pub(crate) async fn recompute_with(&self, force: bool, p: &Params) -> Result<Report> {
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
        let out = compute(&input, p);
        let now = super::data::now_ts();

        let mut report = Report {
            unchanged: false,
            campaigns: out.campaigns.len(),
            members: out.members.len(),
            edges: BTreeMap::new(),
            excluded: out.excluded.clone(),
            seconds: 0.0,
            at: Some(now.clone()),
            withheld: out.withheld,
            vetoed: out.vetoed,
            candidates: out.candidates,
            ordered: out.ordered,
        };
        for e in &out.edges {
            *report.edges.entry(e.kind.to_string()).or_default() += 1;
        }

        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for sql in [
            "DELETE FROM campaign_edges",
            "DELETE FROM campaign_edge_shapes",
            "DELETE FROM campaign_edge_tls",
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
                                             first_ts, last_ts, agreement)
                 VALUES (?,?,?,?,?,?,?,?,?,?)",
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
            .bind(e.agreement)
            .execute(&mut *tx)
            .await?;
            for (shape, df) in &e.shapes {
                sqlx::query("INSERT INTO campaign_edge_shapes (a, b, shape, df) VALUES (?,?,?,?)")
                    .bind(e.a)
                    .bind(e.b)
                    .bind(shape)
                    .bind(df)
                    .execute(&mut *tx)
                    .await?;
            }
            for (ja4, ja4h) in &e.tls {
                sqlx::query("INSERT INTO campaign_edge_tls (a, b, ja4, ja4h) VALUES (?,?,?,?)")
                    .bind(e.a)
                    .bind(e.b)
                    .bind(ja4)
                    .bind(ja4h)
                    .execute(&mut *tx)
                    .await?;
            }
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

    /// The key of campaign number `num` (the `#N` on the pages).
    pub async fn campaign_by_num(&self, num: i64) -> Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT key FROM campaigns WHERE num = ?")
                .bind(num)
                .fetch_optional(&self.pool)
                .await?,
        )
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
            "SELECT m.ip_id, i.ip, i.country, i.asn, i.asn_org, i.first_seen, i.last_seen,
                    i.request_count AS requests
             FROM campaign_members m JOIN ips i ON i.id = m.ip_id
             WHERE m.campaign_key = ? ORDER BY i.ip",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        let edges = sqlx::query_as(
            "SELECT e.a AS a_id, ia.ip AS a, e.b AS b_id, ib.ip AS b, e.kind, e.value,
                    e.score, e.shared, e.fp_support, e.first_ts, e.last_ts, e.agreement
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

    /// The detail of each `paths` edge of a campaign, by (a, b) ip ids.
    pub async fn campaign_edge_detail(&self, key: &str) -> Result<HashMap<(i64, i64), EdgeDetail>> {
        let shapes: Vec<(i64, i64, String, i64)> = sqlx::query_as(
            "SELECT e.a, e.b, COALESCE(s.text, '#' || e.shape), e.df
             FROM campaign_edge_shapes e
             JOIN campaign_members m ON m.ip_id = e.a
             LEFT JOIN shapes s ON s.hash = e.shape
             WHERE m.campaign_key = ? ORDER BY e.a, e.b, e.df, e.shape",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        let tls: Vec<(i64, i64, String, String)> = sqlx::query_as(
            "SELECT e.a, e.b, e.ja4, e.ja4h FROM campaign_edge_tls e
             JOIN campaign_members m ON m.ip_id = e.a
             WHERE m.campaign_key = ? ORDER BY e.a, e.b, e.ja4, e.ja4h",
        )
        .bind(key)
        .fetch_all(&self.pool)
        .await?;
        let mut out: HashMap<(i64, i64), EdgeDetail> = HashMap::new();
        for (a, b, text, df) in shapes {
            out.entry((a, b)).or_default().shapes.push((text, df));
        }
        for (a, b, ja4, ja4h) in tls {
            out.entry((a, b)).or_default().tls.push((ja4, ja4h));
        }
        Ok(out)
    }

    /// The campaigns `f` lets through, most recently active first, with
    /// their members' countries and ASNs.
    pub async fn campaign_index(&self, f: &CampaignFilter) -> Result<Vec<CampaignListItem>> {
        type Where = (String, Option<String>, Option<i64>, Option<String>);
        let spread: Vec<Where> = sqlx::query_as(
            "SELECT m.campaign_key, i.country, i.asn, i.asn_org
             FROM campaign_members m JOIN ips i ON i.id = m.ip_id",
        )
        .fetch_all(&self.read)
        .await?;
        type Spread = (BTreeMap<String, i64>, BTreeMap<i64, (Option<String>, i64)>);
        let mut by_key: BTreeMap<String, Spread> = BTreeMap::new();
        for (key, country, asn, org) in spread {
            let (countries, asns) = by_key.entry(key).or_default();
            if let Some(c) = country {
                *countries.entry(c).or_default() += 1;
            }
            if let Some(a) = asn {
                let e = asns.entry(a).or_insert((None, 0));
                e.1 += 1;
                if e.0.is_none() {
                    e.0 = org;
                }
            }
        }
        let agent = self.agent_campaigns(None).await?;
        let (country, asn, min) = (f.country(), f.asn(), f.min());
        let (from, to) = (CampaignFilter::day(&f.from), CampaignFilter::day(&f.to));
        let mut out: Vec<CampaignListItem> = self
            .campaign_list()
            .await?
            .into_iter()
            .filter(|r| min.is_none_or(|m| r.size >= m))
            .filter(|r| from.is_none_or(|d| r.last_seen.get(..10).is_some_and(|l| l >= d)))
            .filter(|r| to.is_none_or(|d| r.first_seen.get(..10).is_some_and(|l| l <= d)))
            .filter_map(|row| {
                let (countries, asns) = by_key.remove(&row.key).unwrap_or_default();
                if country.as_ref().is_some_and(|c| !countries.contains_key(c))
                    || asn.is_some_and(|a| !asns.contains_key(&a))
                {
                    return None;
                }
                let mut countries: Vec<(String, i64)> = countries.into_iter().collect();
                countries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                let mut asns: Vec<(i64, Option<String>, i64)> =
                    asns.into_iter().map(|(a, (o, n))| (a, o, n)).collect();
                asns.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
                Some(CampaignListItem {
                    agent: agent.contains(&row.key),
                    row,
                    countries,
                    asns,
                })
            })
            .collect();
        out.sort_by(|a, b| {
            b.row
                .last_seen
                .cmp(&a.row.last_seen)
                .then_with(|| a.row.num.cmp(&b.row.num))
        });
        Ok(out)
    }

    /// Requests per day across a campaign's members, over the IP page's
    /// calendar window.
    pub async fn campaign_calendar(&self, key: &str) -> Result<Vec<super::browse::CalendarDay>> {
        Ok(sqlx::query_as(
            "SELECT date(r.ts) AS day, COUNT(*) AS count, MAX(r.severity) AS max_severity
             FROM campaign_members m JOIN requests r ON r.ip_id = m.ip_id
             WHERE m.campaign_key = ? AND r.ts >= date('now', ?)
             GROUP BY day ORDER BY day",
        )
        .bind(key)
        .bind(format!("-{} days", super::browse::CALENDAR_DAYS - 1))
        .fetch_all(&self.read)
        .await?)
    }

    /// The shapes most of a campaign's members asked for (light rows
    /// included), with how many IPs of the dataset asked for each.
    pub async fn campaign_shapes(&self, key: &str) -> Result<Vec<CampaignShape>> {
        type Row = (
            String,
            i64,
            i64,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT s.text, COUNT(DISTINCT x.ip_id) AS members, s.ips AS df, s.first_seen,
                    w.ips, w.window_start, w.detected_at FROM (
               SELECT r.ip_id, r.shape FROM campaign_members m
               JOIN requests r ON r.ip_id = m.ip_id
               WHERE m.campaign_key = ?1 AND r.shape IS NOT NULL
               UNION
               SELECT b.ip_id, q.shape FROM campaign_members m
               JOIN skipped_batches b ON b.ip_id = m.ip_id
               JOIN skipped_requests q ON q.batch_id = b.id
               WHERE m.campaign_key = ?1 AND q.shape IS NOT NULL
             ) x JOIN shapes s ON s.hash = x.shape
             LEFT JOIN waves w ON w.shape = x.shape
             GROUP BY x.shape ORDER BY members DESC, df, s.text LIMIT ?2",
        )
        .bind(key)
        .bind(CAMPAIGN_SHAPES)
        .fetch_all(&self.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(text, members, df, first_seen, wi, ws, wd)| CampaignShape {
                    text,
                    members,
                    df,
                    first_seen,
                    wave: super::waves::WaveMark::from_join(wi, ws, wd),
                },
            )
            .collect())
    }

    /// Up to `limit` of the members' uploads, newest first.
    pub async fn campaign_uploads(
        &self,
        key: &str,
        limit: i64,
    ) -> Result<Vec<super::uploads::UploadRow>> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {} JOIN campaign_members m ON m.ip_id = u.ip_id
             WHERE m.campaign_key = ? ORDER BY u.id DESC LIMIT ?",
            super::uploads::UPLOAD_COLS
        )))
        .bind(key)
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// Up to `limit` of the webshell commands the members ran, most run
    /// first: the partial `idx_requests_cmd` holds only command rows.
    pub async fn campaign_commands(&self, key: &str, limit: i64) -> Result<Vec<CampaignCommand>> {
        Ok(sqlx::query_as(
            "SELECT r.cmd, COUNT(*) AS count, COUNT(DISTINCT r.ip_id) AS ips, MAX(r.ts) AS last_ts
             FROM requests r
             WHERE r.cmd IS NOT NULL
               AND r.ip_id IN (SELECT ip_id FROM campaign_members WHERE campaign_key = ?)
             GROUP BY r.cmd ORDER BY count DESC, last_ts DESC, r.cmd LIMIT ?",
        )
        .bind(key)
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// The keys of the agent-driven campaigns (any member IP carries an
    /// agent label), or only `key`'s if it is one; read from `ip_labels`,
    /// never stored on `campaigns`.
    pub async fn agent_campaigns(&self, key: Option<&str>) -> Result<BTreeSet<String>> {
        let [art, tool] = crate::classify::AGENT_LABELS;
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT m.campaign_key FROM ip_labels l
             JOIN campaign_members m ON m.ip_id = l.ip_id
             WHERE l.label IN (?, ?) AND l.count > 0 AND (?3 IS NULL OR m.campaign_key = ?3)
             GROUP BY m.campaign_key",
        )
        .bind(art)
        .bind(tool)
        .bind(key)
        .fetch_all(&self.read)
        .await?;
        Ok(keys.into_iter().collect())
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
pub(crate) struct Input {
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
    pub(crate) async fn read(conn: &mut sqlx::SqliteConnection) -> Result<Input> {
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
    /// Not stored yet (campaign v2, S3).
    #[cfg_attr(not(test), allow(dead_code))]
    agreement: Option<f64>,
    first_ts: String,
    last_ts: String,
    /// As [`Link::shapes`], [`Link::tls`].
    shapes: Vec<(i64, i64)>,
    tls: Vec<(String, String)>,
}

struct Output {
    campaigns: Vec<CampaignOut>,
    /// (ip id, campaign key).
    members: Vec<(i64, String)>,
    edges: Vec<EdgeOut>,
    excluded: Vec<Excluded>,
    /// As in [`Report`].
    withheld: usize,
    vetoed: usize,
    candidates: usize,
    ordered: usize,
    /// Every candidate pair, for [`evaluate`].
    scored: Vec<Scored>,
}

/// A pair whose shape sets scored high enough for the order term.
struct Scored {
    /// ip ids.
    a: i64,
    b: i64,
    score: f64,
    agreement: Option<f64>,
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
    agreement: Option<f64>,
    first: Option<String>,
    last: Option<String>,
    /// A `paths` edge's shared shapes and their document frequency, the
    /// rarest [`EDGE_SHAPES_MAX`]; its shared (JA4, JA4H) pairs.
    shapes: Vec<(i64, i64)>,
    tls: Vec<(String, String)>,
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
pub(crate) fn epoch(ts: &str) -> Option<i64> {
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

/// How far two IPs first asked for their shared shapes in the same order,
/// from −1 (reversed) to 1, over `(shape, first time a, first time b)` and
/// a shape's document frequency: concordant minus discordant over the pairs
/// of shapes ordered on both sides (a tie on either side tells nothing).
/// `None` with fewer than [`ORDER_MIN_SHARED`] shapes or
/// [`ORDER_MIN_PAIRS`] untied pairs; only the [`ORDER_MAX`] rarest count.
fn order_agreement(shared: &[(i64, &str, &str)], df: impl Fn(i64) -> usize) -> Option<f64> {
    if shared.len() < ORDER_MIN_SHARED {
        return None;
    }
    let mut v = shared.to_vec();
    if v.len() > ORDER_MAX {
        v.sort_by_key(|x| (df(x.0), x.0));
        v.truncate(ORDER_MAX);
    }
    let (mut concordant, mut discordant) = (0usize, 0usize);
    for (i, x) in v.iter().enumerate() {
        for y in &v[i + 1..] {
            let (a, b) = (x.1.cmp(y.1), x.2.cmp(y.2));
            if a.is_eq() || b.is_eq() {
                continue;
            }
            if a == b {
                concordant += 1;
            } else {
                discordant += 1;
            }
        }
    }
    let effective = concordant + discordant;
    if effective < ORDER_MIN_PAIRS {
        return None;
    }
    Some((concordant as f64 - discordant as f64) / effective as f64)
}

/// The campaigns `input` makes; a pure function of the rows (ids are only
/// carried through, never compared).
fn compute(input: &Input, p: &Params) -> Output {
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
                    agreement: None,
                    first: span.0,
                    last: span.1,
                    shapes: vec![],
                    tls: vec![],
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
    let (mut vetoed, mut candidates, mut ordered) = (0, 0, 0);
    let mut scored = vec![];
    for (a, b) in pairs {
        if apart(&path_active[a], &path_active[b]) {
            continue;
        }
        let (sa, sb) = (&sets[a], &sets[b]);
        let (mut x, mut y) = (0, 0);
        let (mut shared_w, mut union_w) = (0.0, 0.0);
        let (mut shared, mut shared_rare) = (0i64, 0usize);
        let mut span: Span = (None, None);
        // (shape, first asked by a, by b), for the order term.
        let mut firsts: Vec<(i64, &str, &str)> = vec![];
        let mut common: Vec<i64> = vec![];
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
                    let (q, r) = (sa[x], sb[y]);
                    let w = weight(q.0);
                    shared_w += w;
                    union_w += w;
                    shared += 1;
                    common.push(q.0);
                    shared_rare += rare(q.0) as usize;
                    widen(&mut span, Some(q.1.min(r.1)), Some(q.2.max(r.2)));
                    if p.order {
                        firsts.push((q.0, q.1, r.1));
                    }
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
        candidates += 1;
        let agreement = if p.order {
            order_agreement(&firsts, |s| df[&s].len())
        } else {
            None
        };
        ordered += agreement.is_some() as usize;
        let veto = matches!((p.veto, agreement), (Some(v), Some(x)) if x <= v);
        scored.push(Scored {
            a: nodes[a].1,
            b: nodes[b].1,
            score,
            agreement,
        });
        if veto {
            vetoed += 1;
            continue;
        }
        let both: Vec<(String, String)> = tls[a]
            .intersection(&tls[b])
            .map(|&(x, y)| (x.to_string(), y.to_string()))
            .collect();
        let fp_support = !both.is_empty();
        let support = fp_support || agreement.is_some_and(|x| x >= p.agree);
        if score < if support { PATHS_T_SUPPORTED } else { PATHS_T } {
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
            agreement,
            first: span.0,
            last: span.1,
            shapes: {
                let mut v: Vec<(i64, i64)> =
                    common.iter().map(|&s| (s, df[&s].len() as i64)).collect();
                v.sort_by_key(|&(s, d)| (d, s));
                v.truncate(EDGE_SHAPES_MAX);
                v
            },
            tls: both,
        });
    }

    // Components of two or more nodes: hard links first, then (with a
    // guard) soft links only where they join a group strongly enough.
    let mut parent: Vec<usize> = (0..n).collect();
    let mut size: Vec<usize> = vec![1; n];
    let union = |parent: &mut [usize], size: &mut [usize], ra: usize, rb: usize| {
        let (lo, hi) = (ra.min(rb), ra.max(rb));
        parent[hi] = lo;
        size[lo] += size[hi];
    };
    for l in links
        .iter()
        .filter(|l| p.guard.is_none() || l.kind != PATHS)
    {
        let (ra, rb) = (find(&mut parent, l.a), find(&mut parent, l.b));
        if ra != rb {
            union(&mut parent, &mut size, ra, rb);
        }
    }
    let mut withheld = 0;
    if let Some(k) = p.guard {
        // One merge per round: the pair of groups with the most soft links
        // between them, ties by root IP text, among those with at least
        // min(size, size, k); until none qualifies.
        loop {
            let mut support: BTreeMap<(usize, usize), usize> = BTreeMap::new();
            for l in links.iter().filter(|l| l.kind == PATHS) {
                let (ra, rb) = (find(&mut parent, l.a), find(&mut parent, l.b));
                if ra != rb {
                    *support.entry((ra.min(rb), ra.max(rb))).or_default() += 1;
                }
            }
            let best = support
                .into_iter()
                .filter(|&((ra, rb), count)| count >= size[ra].min(size[rb]).min(k))
                .min_by_key(|&((ra, rb), count)| {
                    (std::cmp::Reverse(count), nodes[ra].0, nodes[rb].0)
                });
            let Some(((ra, rb), _)) = best else { break };
            union(&mut parent, &mut size, ra, rb);
        }
        // Soft links between groups that stayed apart are not edges.
        let before = links.len();
        links.retain(|l| l.kind != PATHS || find(&mut parent, l.a) == find(&mut parent, l.b));
        withheld = before - links.len();
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
            agreement: l.agreement,
            first_ts: l.first.unwrap_or_default(),
            last_ts: l.last.unwrap_or_default(),
            shapes: l.shapes,
            tls: l.tls,
        })
        .collect();
    Output {
        campaigns,
        members,
        edges,
        excluded,
        withheld,
        vetoed,
        candidates,
        ordered,
        scored,
    }
}

/// The tuning grid [`evaluate`] runs: `agree` × `veto` × K.
const GRID_AGREE: [f64; 3] = [0.3, 0.5, 0.7];
const GRID_VETO: [Option<f64>; 4] = [Some(-0.2), Some(-0.3), Some(-0.5), None];
const GRID_K: [usize; 2] = [2, 3];
/// Vetoed pairs [`evaluate`] prints, and shared shapes per pair.
const EVAL_PAIRS: usize = 20;
const EVAL_SHAPES: usize = 12;

/// What `peephole store campaigns-eval` prints for one `input`: v1, the
/// guard alone and the default v2 in full, the tuning grid against v1, the
/// default run's order agreements, a sample of the pairs the loosest veto
/// drops, and how the largest v1 campaigns are chained. Writes nothing.
pub(crate) fn evaluate(input: &Input) -> String {
    use std::fmt::Write;
    let run = |p: &Params| {
        let started = std::time::Instant::now();
        let out = compute(input, p);
        (out, started.elapsed().as_secs_f64())
    };
    let mut o = String::new();
    let (v1, v1_s) = run(&Params::V1);
    let v1_keys = keys_of(&v1);
    let guard = Params {
        guard: Some(K_SOFT_MERGE),
        ..Params::V1
    };
    let (g, g_s) = run(&guard);
    let (v2, v2_s) = run(&Params::V2);
    block(&mut o, "V1", &v1, v1_s, &v1_keys);
    block(&mut o, "guard only (order off, K = 2)", &g, g_s, &v1_keys);
    block(
        &mut o,
        &format!("V2 default (K = {K_SOFT_MERGE}, agree {ORDER_AGREE}, veto none)"),
        &v2,
        v2_s,
        &v1_keys,
    );
    let _ = writeln!(
        o,
        "\npass seconds: V1 {v1_s:.2}, V2 {v2_s:.2}, ratio {:.2}",
        v2_s / v1_s.max(1e-9)
    );

    let _ = writeln!(o, "\n== grid (changed versus V1) ==");
    let _ = writeln!(
        o,
        "| agree | veto | K | campaigns | edges | withheld | vetoed | changed % | seconds |"
    );
    let _ = writeln!(o, "|---|---|---|---|---|---|---|---|---|");
    for agree in GRID_AGREE {
        for veto in GRID_VETO {
            for k in GRID_K {
                let p = Params {
                    order: true,
                    agree,
                    veto,
                    guard: Some(k),
                };
                let (out, secs) = run(&p);
                let _ = writeln!(
                    o,
                    "| {agree:.1} | {} | {k} | {} | {} | {} | {} | {:.2} | {secs:.2} |",
                    veto.map_or("none".to_string(), |v| format!("{v:.1}")),
                    out.campaigns.len(),
                    out.edges.len(),
                    out.withheld,
                    out.vetoed,
                    changed(&v1_keys, &out),
                );
            }
        }
    }
    let v1_paths = v1.edges.iter().filter(|e| e.kind == PATHS).count();
    let _ = writeln!(o, "V1 paths edges: {v1_paths}");

    // Agreement over the default run's candidates, buckets of 0.2.
    let _ = writeln!(o, "\n== agreement of the V2 default candidates ==");
    let mut buckets = [0usize; 10];
    let mut none = 0;
    for s in &v2.scored {
        match s.agreement {
            Some(x) => buckets[(((x + 1.0) / 0.2).floor() as usize).min(9)] += 1,
            None => none += 1,
        }
    }
    for (i, n) in buckets.iter().enumerate() {
        let lo = -1.0 + 0.2 * i as f64;
        let close = if i == 9 { ']' } else { ')' };
        let _ = writeln!(o, "[{lo:+.1}, {:+.1}{close} {n}", lo + 0.2);
    }
    let _ = writeln!(o, "None {none}");

    // The pairs the loosest veto drops, spread evenly over their agreement.
    let ip = |id: i64| input.ips.get(&id).map_or("?", String::as_str);
    let loosest = GRID_VETO.iter().flatten().fold(f64::MIN, |m, &v| m.max(v));
    let mut dropped: Vec<&Scored> = v2
        .scored
        .iter()
        .filter(|s| s.agreement.is_some_and(|x| x <= loosest))
        .collect();
    dropped.sort_by(|x, y| {
        x.agreement
            .partial_cmp(&y.agreement)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| (ip(x.a), ip(x.b)).cmp(&(ip(y.a), ip(y.b))))
    });
    let picked: Vec<&Scored> = if dropped.len() <= EVAL_PAIRS {
        dropped.clone()
    } else {
        (0..EVAL_PAIRS)
            .map(|i| dropped[i * dropped.len() / EVAL_PAIRS])
            .collect()
    };
    let _ = writeln!(
        o,
        "\n== vetoed pairs (agreement <= {loosest:.1}): {} of {} ==",
        picked.len(),
        dropped.len()
    );
    let wanted: HashSet<i64> = picked.iter().flat_map(|s| [s.a, s.b]).collect();
    let mut firsts: HashMap<i64, BTreeMap<i64, &str>> = HashMap::new();
    for (id, shape, first, _) in &input.shapes {
        if wanted.contains(id) {
            let e = firsts
                .entry(*id)
                .or_default()
                .entry(*shape)
                .or_insert(first);
            *e = (*e).min(first.as_str());
        }
    }
    let empty = BTreeMap::new();
    for s in &picked {
        let caught: Vec<String> = GRID_VETO
            .iter()
            .flatten()
            .filter(|&&v| s.agreement.is_some_and(|x| x <= v))
            .map(|v| format!("{v:.1}"))
            .collect();
        let _ = writeln!(
            o,
            "{} {} score {:.2} agreement {:+.2} vetoed at {}",
            ip(s.a),
            ip(s.b),
            s.score,
            s.agreement.unwrap_or_default(),
            caught.join(" ")
        );
        let (fa, fb) = (
            firsts.get(&s.a).unwrap_or(&empty),
            firsts.get(&s.b).unwrap_or(&empty),
        );
        let mut shared: Vec<(&str, &str, i64)> = fa
            .iter()
            .filter_map(|(shape, a)| fb.get(shape).map(|b| (*a, *b, *shape)))
            .collect();
        shared.sort();
        for (a, b, shape) in shared.iter().take(EVAL_SHAPES) {
            let _ = writeln!(o, "  shape {shape} a {a} b {b}");
        }
    }

    chaining(&mut o, input, &v1, &v2);
    o
}

/// Campaign key by ip id.
fn keys_of(out: &Output) -> HashMap<i64, &str> {
    out.members
        .iter()
        .map(|(id, k)| (*id, k.as_str()))
        .collect()
}

/// The share of IPs in either run whose campaign key differs, in percent.
fn changed(v1: &HashMap<i64, &str>, out: &Output) -> f64 {
    let other = keys_of(out);
    let union: HashSet<i64> = v1.keys().chain(other.keys()).copied().collect();
    if union.is_empty() {
        return 0.0;
    }
    let diff = union
        .iter()
        .filter(|id| v1.get(id) != other.get(id))
        .count();
    100.0 * diff as f64 / union.len() as f64
}

/// One run in full.
fn block(o: &mut String, title: &str, out: &Output, secs: f64, v1: &HashMap<i64, &str>) {
    use std::fmt::Write;
    let _ = writeln!(o, "\n== {title} ==");
    let _ = writeln!(
        o,
        "campaigns {}, members {}",
        out.campaigns.len(),
        out.members.len()
    );
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &out.edges {
        *kinds.entry(e.kind).or_default() += 1;
    }
    let kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{k} {n}")).collect();
    let _ = writeln!(
        o,
        "edges: {}",
        if kinds.is_empty() {
            "none".to_string()
        } else {
            kinds.join(", ")
        }
    );
    let _ = writeln!(o, "withheld {}, vetoed {}", out.withheld, out.vetoed);
    let pct = if out.candidates == 0 {
        "-".to_string()
    } else {
        format!(
            "{:.1} %",
            100.0 * out.ordered as f64 / out.candidates as f64
        )
    };
    let _ = writeln!(
        o,
        "coverage: ordered {} of {} candidates ({pct})",
        out.ordered, out.candidates
    );
    let _ = writeln!(o, "changed versus V1: {:.2} %", changed(v1, out));
    let _ = writeln!(o, "seconds {secs:.2}");
    let mut sizes = [0usize; 5];
    for c in &out.campaigns {
        sizes[match c.size {
            ..=2 => 0,
            3..=5 => 1,
            6..=10 => 2,
            11..=50 => 3,
            _ => 4,
        }] += 1;
    }
    let _ = writeln!(
        o,
        "sizes: 2: {}, 3-5: {}, 6-10: {}, 11-50: {}, 51+: {}",
        sizes[0], sizes[1], sizes[2], sizes[3], sizes[4]
    );
    let _ = writeln!(o, "largest (key size hard soft):");
    for c in largest(out) {
        let _ = writeln!(
            o,
            "  {} {} {} {}",
            c.key, c.size, c.hard_edges, c.soft_edges
        );
    }
}

/// The ten largest campaigns, ties by key.
fn largest(out: &Output) -> Vec<&CampaignOut> {
    let mut v: Vec<&CampaignOut> = out.campaigns.iter().collect();
    v.sort_by(|x, y| y.size.cmp(&x.size).then_with(|| x.key.cmp(&y.key)));
    v.truncate(10);
    v
}

/// For each of the largest v1 campaigns: its hard cores (components of two
/// or more without its soft edges) and the soft edges between two cores,
/// `CHAINED` where fewer than the largest grid K join them.
fn chaining(o: &mut String, input: &Input, v1: &Output, v2: &Output) {
    use std::fmt::Write;
    let ip = |id: i64| input.ips.get(&id).map_or("?", String::as_str);
    let v1_keys = keys_of(v1);
    let v2_keys = keys_of(v2);
    let k_max = GRID_K.iter().copied().max().unwrap_or(K_SOFT_MERGE);
    let _ = writeln!(o, "\n== chaining of the largest V1 campaigns ==");
    for c in largest(v1) {
        let members: Vec<i64> = v1
            .members
            .iter()
            .filter(|m| m.1 == c.key)
            .map(|m| m.0)
            .collect();
        let at: HashMap<i64, usize> = members.iter().enumerate().map(|(i, &m)| (m, i)).collect();
        let edges: Vec<&EdgeOut> = v1
            .edges
            .iter()
            .filter(|e| v1_keys.get(&e.a) == Some(&c.key.as_str()))
            .collect();
        let mut parent: Vec<usize> = (0..members.len()).collect();
        for e in edges.iter().filter(|e| e.kind != PATHS) {
            let (ra, rb) = (find(&mut parent, at[&e.a]), find(&mut parent, at[&e.b]));
            if ra != rb {
                parent[ra.max(rb)] = ra.min(rb);
            }
        }
        // Per root: its members' IP text, smallest first.
        let mut comps: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
        for (i, &m) in members.iter().enumerate() {
            comps.entry(find(&mut parent, i)).or_default().push(ip(m));
        }
        for v in comps.values_mut() {
            v.sort();
        }
        let cores = comps.values().filter(|v| v.len() >= 2).count();
        let split: BTreeSet<&str> = members
            .iter()
            .filter_map(|m| v2_keys.get(m).copied())
            .collect();
        let gone = members.iter().filter(|m| !v2_keys.contains_key(m)).count();
        let _ = writeln!(
            o,
            "{} size {} hard {} soft {}: {} cores, {} singletons; under V2 in {} campaigns, {} unclustered",
            c.key,
            c.size,
            c.hard_edges,
            c.soft_edges,
            cores,
            comps.len() - cores,
            split.len(),
            gone
        );
        let mut between: BTreeMap<(usize, usize), Vec<f64>> = BTreeMap::new();
        for e in edges.iter().filter(|e| e.kind == PATHS) {
            let (ra, rb) = (find(&mut parent, at[&e.a]), find(&mut parent, at[&e.b]));
            if ra != rb && comps[&ra].len() >= 2 && comps[&rb].len() >= 2 {
                between
                    .entry((ra.min(rb), ra.max(rb)))
                    .or_default()
                    .push(e.score.unwrap_or_default());
            }
        }
        for ((ra, rb), scores) in &between {
            let flag = if scores.len() < K_SOFT_MERGE {
                " CHAINED (K = 2 splits)"
            } else if scores.len() < k_max {
                " CHAINED at K = 3 (K = 2 merges)"
            } else {
                ""
            };
            let scores: Vec<String> = scores.iter().map(|s| format!("{s:.2}")).collect();
            let _ = writeln!(
                o,
                "  core {} ({}) - core {} ({}): {} soft edges [{}]{flag}",
                comps[ra][0],
                comps[ra].len(),
                comps[rb][0],
                comps[rb].len(),
                scores.len(),
                scores.join(" ")
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cluster::record::{Record, RequestRec, SkipBatchRec, SkipRow};
    use crate::store::data::{Ctx, apply};

    const CTX: Ctx<'static> = Ctx {
        origin: None,
        hlc: 1,
    };

    /// A step of a fixture: a replicated record, or a host key a probe
    /// stored at a time.
    pub(crate) enum Op {
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
                    persona: None,
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

    pub(crate) async fn feed(s: &Store, ops: impl IntoIterator<Item = Op>) {
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
    pub(crate) fn fixture() -> Vec<Op> {
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

    pub(crate) async fn tls_fixture(s: &Store) {
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
            Option<f64>,
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
                    e.first_ts, e.last_ts, e.agreement
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

    /// A user agent is software, not an operator: one UA on every request,
    /// across all the fixture's campaigns, changes nothing (MIK-504).
    #[tokio::test]
    async fn user_agents_are_not_campaign_evidence() {
        let shared_ua = |ops: Vec<Op>| {
            ops.into_iter().map(|op| match op {
                Op::Rec(Record::Request(mut r)) => {
                    r.headers_json = r#"[["User-Agent","Mozilla/5.0 (shared)"]]"#.into();
                    Op::Rec(Record::Request(r))
                }
                op => op,
            })
        };
        let mut runs = vec![];
        for with_ua in [false, true] {
            let (s, _dir) = store().await;
            if with_ua {
                feed(&s, shared_ua(fixture())).await;
                let ips: i64 = sqlx::query_scalar(
                    "SELECT COUNT(DISTINCT ip_id) FROM requests
                     WHERE user_agent = 'Mozilla/5.0 (shared)'",
                )
                .fetch_one(&s.pool)
                .await
                .unwrap();
                assert!(ips > 7, "the UA spans the campaigns: {ips}");
                let mut conn = s.pool.acquire().await.unwrap();
                let input = Input::read(&mut conn).await.unwrap();
                assert!(input.sightings.iter().all(|x| x.0 != LinkKind::Ua));
            } else {
                feed(&s, fixture()).await;
            }
            tls_fixture(&s).await;
            let mut r = s.recompute_campaigns(false).await.unwrap();
            (r.seconds, r.at) = (0.0, None);
            let d = dump(&s).await;
            assert!(d.2.iter().all(|e| e.2 != "ua"), "{:?}", d.2);
            runs.push((r, d));
        }
        assert_eq!(runs[0].0.campaigns, 3);
        assert_eq!(runs[0], runs[1]);
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
        // Each sweep in one second: no edge has an order agreement.
        let d = dump(&s).await;
        assert!(d.2.iter().all(|e| e.9.is_none()), "{:?}", d.2);

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

        // The same under v2, with the v2 fixtures too.
        let all = || fixture().into_iter().chain(v2_fixtures());
        let (s3, _d3) = store().await;
        let (s4, _d4) = store().await;
        feed(&s3, all()).await;
        feed(&s4, all().collect::<Vec<_>>().into_iter().rev()).await;
        tls_fixture(&s3).await;
        tls_fixture(&s4).await;
        let r = s3.recompute_with(false, &V2_VETO).await.unwrap();
        assert!(r.vetoed > 0 && r.ordered > 0, "{r}");
        s4.recompute_with(false, &V2_VETO).await.unwrap();
        let d3 = dump(&s3).await;
        assert_eq!(d3, dump(&s4).await);
        s3.recompute_with(true, &V2_VETO).await.unwrap();
        assert_eq!(d3, dump(&s3).await);
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

    /// Artifacts of the fixture's campaign 192.0.2.3 (members 192.0.2.1-3)
    /// and of an outsider: one upload by 192.0.2.1, `ls -la` run twice by
    /// 192.0.2.1 and once by 192.0.2.2, `id` once by 192.0.2.2; the
    /// outsider 203.0.113.9 uploads and runs `uname`.
    pub(crate) async fn seed_artifacts(s: &Store) {
        let ws = |ip: &'static str, cmd: &'static str| async move {
            let ip_id = s.upsert_ip(ip.parse().unwrap()).await.unwrap().id;
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id,
                method: "GET".into(),
                path: "/s.php".into(),
                query: Some(format!("cmd={cmd}")),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                answer: Some("webshell".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        };
        crate::store::uploads::seed_upload(s, "192.0.2.1", "/drop.php", b"<?php x").await;
        crate::store::uploads::seed_upload(s, "203.0.113.9", "/out.php", b"<?php y").await;
        ws("192.0.2.1", "ls+-la").await;
        ws("192.0.2.1", "ls+-la").await;
        ws("192.0.2.2", "ls+-la").await;
        ws("192.0.2.2", "id").await;
        ws("203.0.113.9", "uname").await;
    }

    #[tokio::test]
    async fn a_campaign_lists_its_members_artifacts_and_events() {
        let (s, _d) = store().await;
        feed(&s, fixture()).await;
        s.recompute_campaigns(true).await.unwrap();
        seed_artifacts(&s).await;

        let ups = s.campaign_uploads("192.0.2.3", 50).await.unwrap();
        assert_eq!(ups.len(), 1, "{ups:?}");
        assert_eq!(
            (ups[0].ip.as_str(), ups[0].answered_path.as_str()),
            ("192.0.2.1", "/drop.php")
        );
        let cmds = s.campaign_commands("192.0.2.3", 50).await.unwrap();
        let got: Vec<_> = cmds
            .iter()
            .map(|c| (c.cmd.as_str(), c.count, c.ips))
            .collect();
        assert_eq!(got, [("ls -la", 3, 2), ("id", 1, 1)]);
        assert_eq!(s.campaign_commands("192.0.2.3", 1).await.unwrap().len(), 1);

        let ev = s.campaign_events("192.0.2.3", None, 100).await.unwrap();
        // 3 fixture requests and host-key probes, 1 upload request and
        // its upload, 4 commands.
        assert_eq!(ev.items.len(), 12, "{:?}", ev.items);
        assert!(ev.next.is_none());
        let ips: std::collections::BTreeSet<_> =
            ev.items.iter().filter_map(|e| e.ip.as_deref()).collect();
        assert_eq!(
            ips.into_iter().collect::<Vec<_>>(),
            ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
        assert!(ev.items.iter().all(|e| e.ip.is_some()), "{:?}", ev.items);
        assert!(ev.items.windows(2).all(|w| w[0].ts >= w[1].ts));
        let kinds = |k| ev.items.iter().filter(|e| e.kind() == k).count();
        use crate::store::events::EventKind;
        assert_eq!(
            (kinds(EventKind::Webshell), kinds(EventKind::Upload)),
            (4, 1)
        );
        let page = s.campaign_events("192.0.2.3", None, 2).await.unwrap();
        assert_eq!(page.items.len(), 2);
        let rest = s
            .campaign_events("192.0.2.3", page.next.as_ref(), 100)
            .await
            .unwrap();
        assert_eq!(rest.items.len(), 10);

        assert!(s.campaign_uploads("nope", 50).await.unwrap().is_empty());
        assert!(s.campaign_commands("nope", 50).await.unwrap().is_empty());
        assert!(
            s.campaign_events("nope", None, 100)
                .await
                .unwrap()
                .items
                .is_empty()
        );
    }

    #[tokio::test]
    async fn admin_readers_filter_and_describe_a_campaign() {
        let (s, _d) = store().await;
        feed(&s, fixture()).await;
        tls_fixture(&s).await;
        let r = s.recompute_campaigns(true).await.unwrap();
        assert!(r.at.is_some());
        sqlx::query(
            "UPDATE ips SET country = 'DE', asn = 64496, asn_org = 'Example'
             WHERE ip IN ('192.0.2.1', '192.0.2.2')",
        )
        .execute(&s.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE ips SET country = 'FR' WHERE ip = '192.0.2.3'")
            .execute(&s.pool)
            .await
            .unwrap();

        let keys = |l: Vec<CampaignListItem>| -> Vec<String> {
            l.into_iter().map(|c| c.row.key).collect()
        };
        let all = s.campaign_index(&CampaignFilter::default()).await.unwrap();
        // Most recently active first.
        assert_eq!(
            keys(all.clone()),
            ["198.51.100.10", "198.51.100.30", "192.0.2.3"]
        );
        let a = all.iter().find(|c| c.row.key == "192.0.2.3").unwrap();
        assert_eq!(a.countries, [("DE".to_string(), 2), ("FR".to_string(), 1)]);
        assert_eq!(a.asns, [(64496, Some("Example".to_string()), 2)]);
        let f = |country: &str, asn: &str, min: &str, from: &str, to: &str| CampaignFilter {
            country: Some(country.into()),
            asn: Some(asn.into()),
            min: Some(min.into()),
            from: Some(from.into()),
            to: Some(to.into()),
        };
        let only = |c: CampaignFilter| {
            let s = &s;
            async move { keys(s.campaign_index(&c).await.unwrap()) }
        };
        assert_eq!(only(f("de", "", "", "", "")).await, ["192.0.2.3"]);
        assert_eq!(only(f("", "AS64496", "", "", "")).await, ["192.0.2.3"]);
        assert_eq!(only(f("", "", "3", "", "")).await, ["192.0.2.3"]);
        assert_eq!(
            only(f("", "", "", "2026-10-03", "")).await,
            ["198.51.100.10"]
        );
        assert_eq!(only(f("", "", "", "", "2026-09-30")).await, ["192.0.2.3"]);
        // Unparsable values are ignored, not matched.
        assert_eq!(only(f("x", "nope", "-", "soon", "later")).await.len(), 3);

        let b = s.campaign("198.51.100.10").await.unwrap().unwrap();
        let m = &b.members[0];
        assert_eq!((m.ip.as_str(), m.requests), ("198.51.100.10", 132));
        let shapes = s.campaign_shapes("198.51.100.10").await.unwrap();
        assert_eq!(shapes.len(), CAMPAIGN_SHAPES as usize);
        // Light rows count: every listed shape is asked by both members.
        assert!(
            shapes.iter().all(|x| x.members == 2 && x.df >= 2),
            "{shapes:?}"
        );
        assert!(
            shapes.iter().all(|x| x.text.ends_with("/.env")),
            "{shapes:?}"
        );

        sqlx::query("UPDATE requests SET ts = datetime('now') WHERE ip_id IN (SELECT id FROM ips WHERE ip LIKE '192.0.2.%')")
            .execute(&s.pool)
            .await
            .unwrap();
        let cal = s.campaign_calendar("192.0.2.3").await.unwrap();
        assert_eq!(cal.len(), 1);
        assert_eq!(cal[0].count, 3);
        assert!(s.campaign_shapes("nope").await.unwrap().is_empty());

        // The page says when the order agrees.
        use crate::admin::campaigns::EdgeView;
        let reason = |b: &Campaign| EdgeView::new(b.edges[0].clone(), Default::default()).reason;
        assert!(!reason(&b).contains("order"), "{}", reason(&b));
        sqlx::query("UPDATE campaign_edges SET agreement = ? WHERE kind = 'paths'")
            .bind(ORDER_AGREE)
            .execute(&s.pool)
            .await
            .unwrap();
        let b = s.campaign("198.51.100.10").await.unwrap().unwrap();
        assert_eq!(b.edges[0].agreement, Some(ORDER_AGREE));
        assert!(reason(&b).ends_with(", order agrees"), "{}", reason(&b));
    }

    #[tokio::test]
    async fn signature_changes_with_the_version() {
        let (s, _d) = store().await;
        feed(&s, fixture()).await;
        s.recompute_campaigns(false).await.unwrap();
        assert!(s.recompute_campaigns(false).await.unwrap().unchanged);
        let mut conn = s.pool.acquire().await.unwrap();
        let sig = signature(&mut conn).await.unwrap();
        drop(conn);
        assert!(sig.starts_with(&format!("v{CAMPAIGN_V} ")), "{sig}");
        // A pass stored by the previous version is redone.
        sqlx::query("UPDATE settings SET value = ? WHERE key = ?")
            .bind(sig.replacen(&format!("v{CAMPAIGN_V} "), "v1 ", 1))
            .bind(KEY_SIGNATURE)
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(!s.recompute_campaigns(false).await.unwrap().unchanged);
    }

    #[tokio::test]
    async fn campaign_edges_have_an_agreement_column() {
        let (s, _d) = store().await;
        let cols: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('campaign_edges')")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(cols.iter().any(|c| c == "agreement"), "{cols:?}");
    }

    /// [`Params::V2`] with the veto the tuning grid tries.
    const V2_VETO: Params = Params {
        veto: Some(ORDER_VETO),
        ..Params::V2
    };

    /// What a pass under `p` would write, before storage.
    async fn computed(s: &Store, p: &Params) -> Output {
        let mut conn = s.pool.acquire().await.unwrap();
        compute(&Input::read(&mut conn).await.unwrap(), p)
    }

    /// `n` paths `/{tag}/{word}`.
    fn paths(tag: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("/{tag}/{}", word(i))).collect()
    }

    /// One request per second from `start`, in list order.
    fn ordered(ip: &str, start: &str, paths: &[String]) -> Vec<Op> {
        let t0 = chrono::NaiveDateTime::parse_from_str(start, "%Y-%m-%d %H:%M:%S").unwrap();
        paths
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let ts = t0 + chrono::Duration::seconds(i as i64);
                req(ip, &ts.format("%Y-%m-%d %H:%M:%S").to_string(), p)
            })
            .collect()
    }

    /// The same five paths from each IP, all in one second.
    fn sweep(ips: &[&str], tag: &str) -> Vec<Op> {
        let paths = paths(tag, 5);
        ips.iter()
            .flat_map(|ip| paths.iter().map(|p| req(ip, "2026-10-04 11:00:00", p)))
            .collect()
    }

    /// Three IPs on one SSH host key.
    fn group(ips: [&'static str; 3], key: &str) -> Vec<Op> {
        ips.map(|ip| {
            Op::Key(
                ip,
                "ssh-hostkey",
                format!("SHA256:{key}"),
                "2026-10-04 00:00:00",
            )
        })
        .into()
    }

    /// Two pairs sharing 12 rare shapes over distinct seconds, each IP
    /// with 3 own shapes (alone, a score of about 0.58): .60 and .61 in the
    /// same order, .62 and .63 in reversed order.
    fn order_fixture() -> Vec<Op> {
        let mut ops = vec![];
        for (tag, ips, reverse) in [
            ("osame", ["192.0.2.60", "192.0.2.61"], false),
            ("orev", ["192.0.2.62", "192.0.2.63"], true),
        ] {
            for (side, ip) in ips.iter().enumerate() {
                let mut list = paths(tag, 12);
                if reverse && side == 1 {
                    list.reverse();
                }
                list.extend(paths(&format!("{tag}own{}", ["x", "y"][side]), 3));
                ops.extend(ordered(ip, "2026-10-04 12:00:00", &list));
            }
        }
        ops
    }

    /// Two IPs with the same 12 rare shapes, reversed, nothing else.
    fn reversed_fixture() -> Vec<Op> {
        let list = paths("rrev", 12);
        let mut ops = ordered("192.0.2.70", "2026-10-04 12:00:00", &list);
        let rev: Vec<String> = list.into_iter().rev().collect();
        ops.extend(ordered("192.0.2.71", "2026-10-04 12:00:00", &rev));
        ops
    }

    const H1: [&str; 3] = ["192.0.2.80", "192.0.2.81", "192.0.2.82"];
    const H2: [&str; 3] = ["192.0.2.83", "192.0.2.84", "192.0.2.85"];

    /// Hard groups H1 and H2 with a sweep between their first IPs, and
    /// with `second`, another between their second ones.
    fn chain_fixture(second: bool) -> Vec<Op> {
        let mut ops = group(H1, "hone");
        ops.extend(group(H2, "htwo"));
        ops.extend(sweep(&[H1[0], H2[0]], "gone"));
        if second {
            ops.extend(sweep(&[H1[1], H2[1]], "gtwo"));
        }
        ops
    }

    /// Hard groups A, B, C with two soft edges A–B, two B–C, one A–C.
    fn three_groups_fixture() -> Vec<Op> {
        let a = ["203.0.113.1", "203.0.113.2", "203.0.113.3"];
        let b = ["203.0.113.4", "203.0.113.5", "203.0.113.6"];
        let c = ["203.0.113.7", "203.0.113.8", "203.0.113.9"];
        let mut ops = group(a, "ga");
        ops.extend(group(b, "gb"));
        ops.extend(group(c, "gc"));
        // a1–b1, b1–c1, a1–c1.
        ops.extend(sweep(&[a[0], b[0], c[0]], "tabc"));
        ops.extend(sweep(&[a[1], b[1]], "tab"));
        ops.extend(sweep(&[b[2], c[1]], "tbc"));
        ops
    }

    fn v2_fixtures() -> Vec<Op> {
        let mut ops = order_fixture();
        ops.extend(reversed_fixture());
        ops.extend(chain_fixture(true));
        ops.extend(three_groups_fixture());
        ops
    }

    /// 2026-10-04 12:mm:ss, `i` seconds in.
    fn at(i: usize) -> String {
        format!("2026-10-04 12:{:02}:{:02}", i / 60, i % 60)
    }

    /// Order agreement of shapes 0.. ranked `(on a, on b)`.
    fn agreement(ranks: &[(usize, usize)], df: impl Fn(i64) -> usize) -> Option<f64> {
        let ts: Vec<(i64, String, String)> = ranks
            .iter()
            .enumerate()
            .map(|(s, &(x, y))| (s as i64, at(x), at(y)))
            .collect();
        let v: Vec<(i64, &str, &str)> = ts.iter().map(|(s, x, y)| (*s, &**x, &**y)).collect();
        order_agreement(&v, df)
    }

    #[test]
    fn order_agreement_is_none_below_eight_shared() {
        let ranks: Vec<_> = (0..7).map(|i| (i, i)).collect();
        assert_eq!(agreement(&ranks, |_| 2), None);
    }

    #[test]
    fn order_agreement_is_none_when_one_side_is_all_ties() {
        let ranks: Vec<_> = (0..12).map(|i| (i, 0)).collect();
        assert_eq!(agreement(&ranks, |_| 2), None);
    }

    #[test]
    fn identical_order_is_one_and_reversed_is_minus_one() {
        let same: Vec<_> = (0..12).map(|i| (i, i)).collect();
        assert_eq!(agreement(&same, |_| 2), Some(1.0));
        let reversed: Vec<_> = (0..12).map(|i| (i, 11 - i)).collect();
        assert_eq!(agreement(&reversed, |_| 2), Some(-1.0));
    }

    #[test]
    fn one_neighbour_swap_moves_agreement_by_two_over_pairs() {
        let ranks: Vec<_> = (0..12)
            .map(|i| match i {
                5 => (5, 6),
                6 => (6, 5),
                _ => (i, i),
            })
            .collect();
        let got = agreement(&ranks, |_| 2).unwrap();
        assert!((got - (1.0 - 2.0 / 66.0)).abs() < 1e-12, "{got}");
    }

    #[test]
    fn more_than_order_max_keeps_the_rarest() {
        // Shapes 0..100 are the commonest and reversed; the 500 others agree.
        let ranks: Vec<_> = (0..600)
            .map(|i| (i, if i < 100 { 599 - i } else { i }))
            .collect();
        let df = |s: i64| if s < 100 { 1000 } else { 1 };
        assert_eq!(agreement(&ranks, df), Some(1.0));
    }

    #[tokio::test]
    async fn same_order_supports_a_pair_below_the_threshold() {
        let (s, _d) = store().await;
        feed(&s, order_fixture()).await;
        let r = s.recompute_with(true, &Params::V1).await.unwrap();
        assert_eq!(r.campaigns, 0, "below PATHS_T without support: {r}");

        let r = s.recompute_campaigns(true).await.unwrap();
        assert_eq!((r.campaigns, r.vetoed), (1, 0), "{r}");
        assert_eq!((r.ordered, r.candidates), (2, 2), "{r}");
        let d = dump(&s).await;
        assert_eq!(d.2.len(), 1);
        assert!(d.2[0].9.is_some_and(|x| x >= ORDER_AGREE), "{:?}", d.2);
        let c = s.campaign("192.0.2.60").await.unwrap().unwrap();
        assert_eq!(c.row.size, 2);
        assert_eq!(c.edges.len(), 1);
        let e = &c.edges[0];
        assert_eq!((e.kind.as_str(), e.b.as_str()), ("paths", "192.0.2.61"));
        assert!(!e.fp_support);
        assert!(e.agreement.is_some_and(|x| x >= ORDER_AGREE), "{e:?}");
        let score = e.score.unwrap();
        assert!((PATHS_T_SUPPORTED..PATHS_T).contains(&score), "{score}");
        // The reversed twin forms no edge.
        for ip in ["192.0.2.62", "192.0.2.63"] {
            assert_eq!(s.campaign_of_ip(ip_id(&s, ip).await).await.unwrap(), None);
        }
        let out = computed(&s, &Params::V2).await;
        assert_eq!(out.edges.len(), 1);
        assert!(out.edges[0].agreement.unwrap() >= ORDER_AGREE);
    }

    #[tokio::test]
    async fn ties_in_the_same_second_decide_by_score_alone() {
        // Today's fixture puts each sweep in one second: v2 stores what v1
        // does, and no edge has an order agreement.
        let (s, _d) = store().await;
        feed(&s, fixture()).await;
        tls_fixture(&s).await;
        s.recompute_with(true, &Params::V1).await.unwrap();
        let v1 = dump(&s).await;
        assert_eq!(v1.0.len(), 3);
        let r = s.recompute_with(true, &Params::V2).await.unwrap();
        assert_eq!(dump(&s).await, v1);
        assert_eq!((r.withheld, r.vetoed, r.ordered), (0, 0, 0), "{r}");
        assert!(r.candidates > 0, "{r}");
        let out = computed(&s, &Params::V2).await;
        assert!(!out.edges.is_empty());
        assert!(out.edges.iter().all(|e| e.agreement.is_none()));
    }

    #[tokio::test]
    async fn reversed_order_vetoes_an_identical_set() {
        let (s, _d) = store().await;
        feed(&s, reversed_fixture()).await;
        let r = s.recompute_with(true, &Params::V1).await.unwrap();
        assert_eq!(r.campaigns, 1, "{r}");
        assert_eq!(r.edges, BTreeMap::from([("paths".to_string(), 1)]));
        let r = s.recompute_with(true, &V2_VETO).await.unwrap();
        assert_eq!((r.campaigns, r.edges.len(), r.vetoed), (0, 0, 1), "{r}");
        // V2 has no veto: the reversed pair stays an edge.
        let r = s.recompute_campaigns(true).await.unwrap();
        assert_eq!((r.campaigns, r.vetoed), (1, 0), "{r}");
    }

    /// Campaign sizes and soft edge counts, by key.
    fn shape_of(d: &Dump) -> Vec<(i64, i64)> {
        d.0.iter().map(|c| (c.3, c.7)).collect()
    }

    #[tokio::test]
    async fn one_soft_edge_does_not_chain_two_hard_groups() {
        let (s, _d) = store().await;
        feed(&s, chain_fixture(false)).await;
        let r = s.recompute_with(true, &Params::V1).await.unwrap();
        assert_eq!(shape_of(&dump(&s).await), [(6, 1)], "{r}");

        let r = s.recompute_with(true, &Params::V2).await.unwrap();
        assert_eq!(r.withheld, 1, "{r}");
        let d = dump(&s).await;
        assert_eq!(shape_of(&d), [(3, 0), (3, 0)]);
        assert!(d.2.iter().all(|e| e.2 != "paths"), "{:?}", d.2);
    }

    #[tokio::test]
    async fn k_soft_edges_merge_two_hard_groups() {
        let (s, _d) = store().await;
        feed(&s, chain_fixture(true)).await;
        let r = s.recompute_with(true, &Params::V2).await.unwrap();
        assert_eq!(r.withheld, 0, "{r}");
        assert_eq!(shape_of(&dump(&s).await), [(6, 2)]);
    }

    #[tokio::test]
    async fn a_singleton_joins_a_group_on_one_soft_edge() {
        let (s, _d) = store().await;
        let mut ops = group(H1, "hone");
        ops.extend(sweep(&[H1[0], "192.0.2.86"], "gone"));
        feed(&s, ops).await;
        let r = s.recompute_with(true, &Params::V2).await.unwrap();
        assert_eq!(r.withheld, 0, "{r}");
        assert_eq!(shape_of(&dump(&s).await), [(4, 1)]);
    }

    #[tokio::test]
    async fn merges_go_by_support_then_ip_text() {
        let (s1, _d1) = store().await;
        let (s2, _d2) = store().await;
        feed(&s1, three_groups_fixture()).await;
        feed(&s2, three_groups_fixture().into_iter().rev()).await;
        let r = s1.recompute_with(true, &Params::V2).await.unwrap();
        assert_eq!(r.withheld, 0, "{r}");
        s2.recompute_with(true, &Params::V2).await.unwrap();
        let d = dump(&s1).await;
        // A–B first (two edges each way, A's root first), then C on three.
        assert_eq!(shape_of(&d), [(9, 5)]);
        assert_eq!(d, dump(&s2).await);
    }

    async fn evaluated(ops: Vec<Op>) -> String {
        let (s, _d) = store().await;
        feed(&s, ops).await;
        let mut conn = s.pool.acquire().await.unwrap();
        evaluate(&Input::read(&mut conn).await.unwrap())
    }

    /// The lines of the `== title… ==` block of `out`.
    pub(crate) fn section<'a>(out: &'a str, title: &str) -> Vec<&'a str> {
        out.lines()
            .skip_while(|l| !l.starts_with(&format!("== {title}")))
            .skip(1)
            .take_while(|l| !l.is_empty())
            .collect()
    }

    #[tokio::test]
    async fn evaluate_reports_a_chained_fixture() {
        let out = evaluated(chain_fixture(false)).await;
        let chain = section(&out, "chaining");
        assert!(
            chain[0].starts_with("192.0.2.80 size 6 hard 6 soft 1: 2 cores"),
            "{out}"
        );
        assert!(chain[1].contains("CHAINED (K = 2 splits)"), "{out}");
        assert!(
            section(&out, "V2 default").contains(&"changed versus V1: 50.00 %"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn evaluate_reports_coverage() {
        let out = evaluated(order_fixture()).await;
        let v2 = section(&out, "V2 default");
        assert!(
            v2.contains(&"coverage: ordered 2 of 2 candidates (100.0 %)"),
            "{out}"
        );
        assert!(v2.contains(&"withheld 0, vetoed 0"), "{out}");
        // The reversed pair is the one the veto drops, with its shapes.
        let vetoed = section(&out, "vetoed pairs");
        assert!(vetoed[0].starts_with("192.0.2.62 192.0.2.63 "), "{out}");
        assert!(vetoed[0].ends_with("vetoed at -0.2 -0.3 -0.5"), "{out}");
        assert_eq!(vetoed.len(), 1 + EVAL_SHAPES, "{out}");
        assert!(
            section(&out, "agreement").contains(&"[+0.8, +1.0] 1"),
            "{out}"
        );
    }

    /// The agent mark: a campaign with a member labelled by either agent
    /// rule, none on one whose members carry other labels (MIK-566).
    #[tokio::test]
    async fn agent_mark_comes_from_member_ip_labels() {
        let (s, _d) = store().await;
        for (key, num) in [("192.0.2.1", 1), ("192.0.2.3", 2), ("192.0.2.5", 3)] {
            sqlx::query(
                "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
                   hard_edges, soft_edges, v, computed_at)
                 VALUES (?, ?, 0, 2, '2026-10-01 00:00:00', '2026-10-01 00:00:00', 1, 0, 1, '')",
            )
            .bind(key)
            .bind(num)
            .execute(&s.pool)
            .await
            .unwrap();
        }
        let members = [
            (1, "192.0.2.1"),
            (2, "192.0.2.1"),
            (3, "192.0.2.3"),
            (4, "192.0.2.3"),
            (5, "192.0.2.5"),
        ];
        for (ip_id, key) in members {
            sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, ?)")
                .bind(ip_id)
                .bind(key)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        // 2: artifact; 3: tooling; 5: other labels and a spent agent row.
        for (ip_id, label, n) in [
            (2, "ai-agent-artifact", 1),
            (3, "ai-agent-tooling", 2),
            (4, "sqli", 1),
            (5, "wp", 3),
            (5, "ai-agent-tooling", 0),
        ] {
            sqlx::query("INSERT INTO ip_labels (ip_id, label, count) VALUES (?, ?, ?)")
                .bind(ip_id)
                .bind(label)
                .bind(n)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        let all = s.agent_campaigns(None).await.unwrap();
        assert_eq!(
            all.iter().map(String::as_str).collect::<Vec<_>>(),
            ["192.0.2.1", "192.0.2.3"]
        );
        assert!(
            s.agent_campaigns(Some("192.0.2.5"))
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(s.agent_campaigns(Some("192.0.2.3")).await.unwrap().len(), 1);
        let marks: Vec<(String, bool)> = s
            .campaign_index(&CampaignFilter::default())
            .await
            .unwrap()
            .into_iter()
            .map(|c| (c.row.key, c.agent))
            .collect();
        assert_eq!(
            marks,
            [
                ("192.0.2.1".to_string(), true),
                ("192.0.2.3".to_string(), true),
                ("192.0.2.5".to_string(), false)
            ]
        );
        assert!(s.ip_has_agent_label(2).await.unwrap());
        assert!(s.ip_has_agent_label(3).await.unwrap());
        assert!(!s.ip_has_agent_label(4).await.unwrap());
        assert!(!s.ip_has_agent_label(5).await.unwrap());
    }
}
