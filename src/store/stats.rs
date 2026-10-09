//! Aggregates for the public wall of shame, per time range, plus a short
//! TTL cache so anonymous traffic cannot hammer SQLite.
use super::Store;
use super::browse::Audience;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Range {
    H24,
    D7,
    D30,
    #[default]
    All,
}

impl Range {
    pub const ALL: [Range; 4] = [Range::H24, Range::D7, Range::D30, Range::All];

    pub fn parse(s: Option<&str>) -> Range {
        match s {
            Some("7d") => Range::D7,
            Some("30d") => Range::D30,
            Some("all") => Range::All,
            _ => Range::H24,
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Range::H24 => "24h",
            Range::D7 => "7d",
            Range::D30 => "30d",
            Range::All => "all",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Range::H24 => "Last 24 hours",
            Range::D7 => "Last 7 days",
            Range::D30 => "Last 30 days",
            Range::All => "All time",
        }
    }
    /// SQLite modifier for `datetime('now', ?)`; `None` = no bound.
    pub fn since(self) -> Option<&'static str> {
        match self {
            Range::H24 => Some("-24 hours"),
            Range::D7 => Some("-7 days"),
            Range::D30 => Some("-30 days"),
            Range::All => None,
        }
    }
    pub fn hourly(self) -> bool {
        matches!(self, Range::H24 | Range::D7)
    }
    /// `WHERE`-fragment and bind value for a timestamp column.
    pub(crate) fn ts_clause(self, col: &str) -> (String, Option<&'static str>) {
        match self.since() {
            Some(m) => (format!(" AND {col} >= datetime('now', ?)"), Some(m)),
            None => (String::new(), None),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct Named {
    pub name: String,
    pub count: i64,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct TopIp {
    pub ip: String,
    pub count: i64,
    pub country: Option<String>,
    pub max_severity: i64,
    pub is_tor: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Bucket {
    pub ts: String,
    pub count: i64,
    /// The bucket's requests per severity 0..4.
    pub by_severity: [i64; 5],
}

/// The window just before the selected one, as long as it, for trends.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Previous {
    pub total_requests: i64,
    pub unique_ips: i64,
}

/// A port found open on the scanned sources: how many distinct IPs.
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct PortStat {
    pub port: i64,
    pub proto: String,
    pub service: Option<String>,
    pub ips: i64,
}

/// A port is shown publicly only once it was found open on this many
/// distinct scanned IPs, so the panel never describes a single host.
pub const PORT_MIN_IPS: i64 = 3;

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecentRequest {
    pub id: i64,
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub severity: i64,
    pub labels: Vec<String>,
    /// The family of each label, in the same order (for badge colours).
    pub families: Vec<&'static str>,
    pub owasp: Vec<String>,
    pub country: Option<String>,
    pub is_tor: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Stats {
    pub range: &'static str,
    pub generated_at: String,
    pub total_requests: i64,
    pub unique_ips: i64,
    pub countries: i64,
    pub tor_ips: i64,
    pub scans_done: i64,
    pub top_ips: Vec<TopIp>,
    pub top_countries: Vec<Named>,
    pub top_asns: Vec<Named>,
    pub top_labels: Vec<Named>,
    pub severity_distribution: Vec<Named>,
    pub timeline: Vec<Bucket>,
    /// Requests per weekday (0 = Monday) and UTC hour over the last 7
    /// days, whatever the range.
    pub heatmap: Vec<[i64; 24]>,
    /// The previous window of the same length; `None` for all time.
    pub previous: Option<Previous>,
    /// IPs first seen in the range.
    pub new_ips: i64,
    /// The newest request's time (UTC), in the whole dataset.
    pub last_request: Option<String>,
    /// Requests per label family (`classify::FAMILIES` order, non-zero
    /// only): a request counts once per family it touched.
    pub families: Vec<Named>,
    /// Requests per OWASP tag, most frequent first.
    pub owasp: Vec<Named>,
    /// Ports most often open on the scanned sources (finished in the range),
    /// each on at least [`PORT_MIN_IPS`] distinct IPs.
    pub ports: Vec<PortStat>,
    /// Distinct IPs with a scan finished in the range.
    pub scanned_ips: i64,
    /// The newest requests of the last 24 hours (up to [`RECENT_MAX`]) this
    /// audience may see, for the wall's 'Recent requests'. Not serialized to
    /// `/api/stats`.
    #[serde(skip_serializing)]
    pub recent: Vec<RecentRequest>,
    pub intel: HashMap<String, String>,
    /// Harvest to first use of the canaries served in the range; only from
    /// [`CANARY_TILE_MIN`] reuses up, so no single event shows.
    pub canaries: Option<CanaryTile>,
    /// Milliseconds the tarpit held clients, over the requests in the range
    /// recorded in full (light rows are never public).
    pub tarpit_held_ms: i64,
    /// The AI decoys' aggregates; only from [`super::decoys::AI_TILE_MIN`]
    /// requests up.
    pub ai_decoys: Option<super::decoys::AiDecoys>,
}

/// Most rows "Recent requests" can show (`[public] recent_rows` is at most
/// this).
pub const RECENT_MAX: i64 = 200;

/// Fewest reused harvests (distinct decoy answers) before the wall shows
/// the canary tile.
pub const CANARY_TILE_MIN: i64 = 5;

#[derive(Clone, Debug, serde::Serialize)]
pub struct CanaryTile {
    pub median_s: i64,
    pub share_pct: i64,
    pub reused: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MapCounts {
    pub range: &'static str,
    pub generated_at: String,
    pub countries: HashMap<String, i64>,
    pub max: i64,
}

/// Bind the optional range modifier onto a query builder.
macro_rules! bind_since {
    ($q:expr, $since:expr) => {{
        let mut q = $q;
        if let Some(m) = $since {
            q = q.bind(m);
        }
        q
    }};
}

/// The parts of [`Stats`] that are counted per IP.
struct IpAggregates {
    total_requests: i64,
    unique_ips: i64,
    countries: i64,
    tor_ips: i64,
    top_ips: Vec<TopIp>,
    top_countries: Vec<Named>,
    top_asns: Vec<Named>,
    top_labels: Vec<Named>,
}

pub(crate) type RecentTuple = (
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<String>,
    bool,
);

pub(crate) fn recent_from(
    (id, ts, ip, method, path, severity, labels, owasp, country, is_tor): RecentTuple,
) -> RecentRequest {
    let labels: Vec<String> = serde_json::from_str(&labels).unwrap_or_default();
    RecentRequest {
        id,
        ts,
        ip,
        method,
        path,
        severity,
        families: labels
            .iter()
            .map(|l| crate::classify::label_family(l))
            .collect(),
        labels,
        owasp: serde_json::from_str(&owasp).unwrap_or_default(),
        country,
        is_tor,
    }
}

impl Store {
    async fn count_where(&self, sql: &str, since: Option<&'static str>) -> Result<i64> {
        Ok(bind_since!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql)),
            since
        )
        .fetch_one(&self.read)
        .await?)
    }

    async fn named(&self, sql: &str, since: Option<&'static str>) -> Result<Vec<Named>> {
        Ok(
            bind_since!(sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(sql)), since)
                .fetch_all(&self.read)
                .await?,
        )
    }

    /// Per-IP aggregates over all time, from the `ips` read models
    /// (`request_count`, `max_severity`, `ip_labels`) instead of every
    /// request. IPs without requests (scan-only) are left out, as in the
    /// ranged queries.
    async fn all_time_ip_aggregates(&self, a: Audience) -> Result<IpAggregates> {
        let p = a.rm();
        let lc = a.label_count();
        let (total_requests, unique_ips, countries, tor_ips): (i64, i64, i64, i64) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT COALESCE(SUM({p}request_count), 0), COUNT(*),
                        COUNT(DISTINCT country), COALESCE(SUM(is_tor_exit = 1), 0)
                 FROM ips WHERE {p}request_count > 0"
            )))
            .fetch_one(&self.read)
            .await?;
        let top_ips = sqlx::query_as::<_, TopIp>(sqlx::AssertSqlSafe(format!(
            "SELECT ip, {p}request_count AS count, country, {p}max_severity AS max_severity,
                    is_tor_exit AS is_tor
             FROM ips WHERE {p}request_count > 0
             ORDER BY {p}request_count DESC, {p}last_seen DESC LIMIT 20"
        )))
        .fetch_all(&self.read)
        .await?;
        let top_countries = self
            .named(
                &format!(
                    "SELECT COALESCE(country,'??') AS name, COUNT(*) AS count
                     FROM ips WHERE {p}request_count > 0
                     GROUP BY country ORDER BY count DESC LIMIT 20"
                ),
                None,
            )
            .await?;
        let top_asns = self
            .named(
                &format!(
                    "SELECT COALESCE(MAX(asn_org), 'AS' || asn, 'unknown') AS name, COUNT(*) AS count
                     FROM ips WHERE {p}request_count > 0
                     GROUP BY asn ORDER BY count DESC LIMIT 20"
                ),
                None,
            )
            .await?;
        let top_labels = self
            .named(
                &format!(
                    "SELECT label AS name, SUM({lc}) AS count FROM ip_labels WHERE {lc} > 0
                     GROUP BY label ORDER BY count DESC LIMIT 20"
                ),
                None,
            )
            .await?;
        Ok(IpAggregates {
            total_requests,
            unique_ips,
            countries,
            tor_ips,
            top_ips,
            top_countries,
            top_asns,
            top_labels,
        })
    }

    /// Per-IP aggregates over the requests of a time range.
    async fn ranged_ip_aggregates(&self, r: Range, a: Audience) -> Result<IpAggregates> {
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let total_requests = self
            .count_where(
                &format!("SELECT COUNT(*) FROM requests r WHERE 1=1{w}"),
                since,
            )
            .await?;
        let unique_ips = self
            .count_where(
                &format!("SELECT COUNT(DISTINCT r.ip_id) FROM requests r WHERE 1=1{w}"),
                since,
            )
            .await?;
        let countries = self
            .count_where(
                &format!(
                    "SELECT COUNT(DISTINCT i.country) FROM requests r JOIN ips i ON r.ip_id = i.id
                     WHERE i.country IS NOT NULL{w}"
                ),
                since,
            )
            .await?;
        let tor_ips = self
            .count_where(
                &format!(
                    "SELECT COUNT(DISTINCT r.ip_id) FROM requests r JOIN ips i ON r.ip_id = i.id
                     WHERE i.is_tor_exit = 1{w}"
                ),
                since,
            )
            .await?;
        let sql = format!(
            "SELECT i.ip, COUNT(*) AS count, i.country, MAX(r.severity) AS max_severity,
                    i.is_tor_exit AS is_tor
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             GROUP BY i.id ORDER BY count DESC LIMIT 20"
        );
        let top_ips = bind_since!(
            sqlx::query_as::<_, TopIp>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.read)
        .await?;
        let top_countries = self
            .named(
                &format!(
                    "SELECT COALESCE(i.country,'??') AS name, COUNT(DISTINCT i.id) AS count
                     FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
                     GROUP BY i.country ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        let top_asns = self
            .named(
                &format!(
                    // Group by ASN (not the org text): different ASNs can
                    // share an org name, and one ASN can carry slightly
                    // different org strings. Show a representative org, else
                    // the AS number.
                    "SELECT COALESCE(MAX(i.asn_org), 'AS' || i.asn, 'unknown') AS name,
                            COUNT(DISTINCT i.id) AS count
                     FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
                     GROUP BY i.asn ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        let top_labels = self
            .named(
                &format!(
                    // A request counts once per distinct label, as in
                    // the all-time `ip_labels`.
                    "SELECT je.value AS name, COUNT(DISTINCT r.id) AS count
                     FROM requests r, json_each(CASE WHEN json_valid(r.labels_json) THEN r.labels_json ELSE '[]' END) je WHERE 1=1{w}
                     GROUP BY je.value ORDER BY count DESC LIMIT 20"
                ),
                since,
            )
            .await?;
        Ok(IpAggregates {
            total_requests,
            unique_ips,
            countries,
            tor_ips,
            top_ips,
            top_countries,
            top_asns,
            top_labels,
        })
    }

    /// Everything, as an admin sees it.
    pub async fn stats(&self, r: Range) -> Result<Stats> {
        self.stats_as(r, Audience::Admin).await
    }

    /// The newest requests of the last 24 hours this audience may see,
    /// newest first.
    pub async fn recent_requests(&self, limit: i64, a: Audience) -> Result<Vec<RecentRequest>> {
        let sql = format!(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.ts >= datetime('now', '-24 hours'){}
             ORDER BY r.id DESC LIMIT ?",
            a.released("r")
        );
        Ok(
            sqlx::query_as::<_, RecentTuple>(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(limit)
                .fetch_all(&self.read)
                .await?
                .into_iter()
                .map(recent_from)
                .collect(),
        )
    }

    pub async fn stats_as(&self, r: Range, a: Audience) -> Result<Stats> {
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let IpAggregates {
            total_requests,
            unique_ips,
            countries,
            tor_ips,
            top_ips,
            top_countries,
            top_asns,
            top_labels,
        } = match r {
            Range::All => self.all_time_ip_aggregates(a).await?,
            _ => self.ranged_ip_aggregates(r, a).await?,
        };
        let (ws, since_s) = r.ts_clause("s.finished_at");
        let ws = ws + &a.scans("s");
        let scans_done = self
            .count_where(
                &format!("SELECT COUNT(*) FROM scans s WHERE 1=1{ws}"),
                since_s,
            )
            .await?;
        let severity_distribution = self
            .named(
                &format!(
                    "SELECT CAST(r.severity AS TEXT) AS name, COUNT(*) AS count
                     FROM requests r WHERE 1=1{w} GROUP BY r.severity ORDER BY r.severity"
                ),
                since,
            )
            .await?;
        let (timeline, heatmap) = self.timeline_and_heatmap(r, a).await?;
        let previous = match r.since() {
            Some(m) => Some(self.previous_window(m, a).await?),
            None => None,
        };
        let new_ips = match r {
            Range::All => unique_ips,
            _ => {
                let p = a.rm();
                self.count_where(
                    &format!(
                        "SELECT COUNT(*) FROM ips i WHERE i.{p}request_count > 0{}",
                        r.ts_clause(&format!("i.{p}first_seen")).0
                    ),
                    since,
                )
                .await?
            }
        };
        let last_request: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT MAX(r.ts) FROM requests r WHERE 1=1{}",
            a.released("r")
        )))
        .fetch_one(&self.read)
        .await?;
        let (families, owasp) = self.families_and_owasp(r, a).await?;
        let ports = bind_since!(
            sqlx::query_as::<_, PortStat>(sqlx::AssertSqlSafe(format!(
                "SELECT p.port, p.proto, MAX(p.service) AS service, COUNT(DISTINCT s.ip_id) AS ips
                 FROM ports p JOIN scans s ON p.scan_id = s.id
                 WHERE p.state = 'open'{ws}
                 GROUP BY p.port, p.proto HAVING COUNT(DISTINCT s.ip_id) >= {PORT_MIN_IPS}
                 ORDER BY ips DESC, p.port LIMIT 15"
            ))),
            since_s
        )
        .fetch_all(&self.read)
        .await?;
        let scanned_ips = self
            .count_where(
                &format!("SELECT COUNT(DISTINCT s.ip_id) FROM scans s WHERE 1=1{ws}"),
                since_s,
            )
            .await?;
        let recent = self.recent_requests(RECENT_MAX, a).await?;
        // Only the public refresh timestamps — never the whole intel_meta
        // table, which also holds webauthn_setup_token_hash. `intel` is
        // serialized into the public /api/stats response.
        let intel = sqlx::query_as::<_, (String, String)>(
            "SELECT key, value FROM intel_meta
             WHERE key IN ('tor_last_fetch','maxmind_last_fetch','maxmind_cluster_seen')",
        )
        .fetch_all(&self.read)
        .await?
        .into_iter()
        .collect();
        let tarpit_held_ms = self
            .count_where(
                &format!(
                    "SELECT COALESCE(SUM(r.held_ms), 0) FROM requests r
                     WHERE r.held_ms IS NOT NULL{w}"
                ),
                since,
            )
            .await?;
        let ai_decoys = self.ai_decoys_as(r, a).await?;
        let sum = self.canary_summary_as(r, a).await?;
        // Counted per harvest, not per value: one request carrying many
        // values of one decoy is one event.
        let canaries = (sum.harvests_reused >= CANARY_TILE_MIN).then(|| CanaryTile {
            median_s: sum.harvest_median_s.unwrap_or(0),
            share_pct: sum.harvest_share_pct(),
            reused: sum.harvests_reused,
        });
        Ok(Stats {
            range: r.key(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_requests,
            unique_ips,
            countries,
            tor_ips,
            scans_done,
            top_ips,
            top_countries,
            top_asns,
            top_labels,
            severity_distribution,
            timeline,
            heatmap,
            previous,
            new_ips,
            last_request,
            families,
            owasp,
            ports,
            scanned_ips,
            recent,
            intel,
            canaries,
            tarpit_held_ms,
            ai_decoys,
        })
    }

    /// The timeline (hourly or daily, as the range wants) with each bucket
    /// split by severity, and the weekday × hour heatmap. The heatmap always
    /// covers the last 7 days, whatever the range, so every weekday shows;
    /// on the 7-day range both come from one pass of hourly buckets.
    async fn timeline_and_heatmap(
        &self,
        r: Range,
        a: Audience,
    ) -> Result<(Vec<Bucket>, Vec<[i64; 24]>)> {
        let rows = self.hourly_by_severity(r, a).await?;
        let week = match r {
            Range::D7 => None,
            _ => Some(self.hourly_by_severity(Range::D7, a).await?),
        };
        let mut heatmap = vec![[0i64; 24]; 7];
        for (h, _, n) in week.as_ref().unwrap_or(&rows) {
            if let Ok(t) = chrono::NaiveDateTime::parse_from_str(h, "%Y-%m-%dT%H:%M") {
                use chrono::{Datelike, Timelike};
                heatmap[t.weekday().num_days_from_monday() as usize][t.hour() as usize] += n;
            }
        }
        let mut timeline: Vec<Bucket> = Vec::new();
        for (h, sev, n) in rows {
            let key = if r.hourly() { h } else { h[..10].to_string() };
            if timeline.last().map(|b| b.ts != key).unwrap_or(true) {
                timeline.push(Bucket {
                    ts: key,
                    count: 0,
                    by_severity: [0; 5],
                });
            }
            let b = timeline.last_mut().expect("pushed above");
            b.count += n;
            b.by_severity[sev.clamp(0, 4) as usize] += n;
        }
        Ok((timeline, heatmap))
    }

    /// Request counts per UTC hour (`%Y-%m-%dT%H:00`) and severity, oldest
    /// first.
    async fn hourly_by_severity(&self, r: Range, a: Audience) -> Result<Vec<(String, i64, i64)>> {
        let (sql, since) = hourly_sql(r, a);
        let rows = bind_since!(
            sqlx::query_as::<_, (Option<String>, i64, i64)>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.read)
        .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(h, sev, n)| Some((h?, sev, n)))
            .collect())
    }

    /// Requests and distinct IPs in the window of the same length just
    /// before `datetime('now', since)`.
    async fn previous_window(&self, since: &'static str, a: Audience) -> Result<Previous> {
        // "-24 hours" → the window [now -48 h, now -24 h).
        let earlier = match since {
            "-24 hours" => "-48 hours",
            "-7 days" => "-14 days",
            _ => "-60 days",
        };
        let (total_requests, unique_ips): (i64, i64) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT COUNT(*), COUNT(DISTINCT r.ip_id) FROM requests r
             WHERE r.ts >= datetime('now', ?) AND r.ts < datetime('now', ?){}",
                a.released("r")
            )))
            .bind(earlier)
            .bind(since)
            .fetch_one(&self.read)
            .await?;
        Ok(Previous {
            total_requests,
            unique_ips,
        })
    }

    /// Requests per label family and per OWASP tag. Grouped by the stored
    /// lists first (few distinct combinations), so each request counts once
    /// per family or tag without unpacking every row's JSON.
    async fn families_and_owasp(&self, r: Range, a: Audience) -> Result<(Vec<Named>, Vec<Named>)> {
        let (sql, since) = families_sql(r, a);
        let rows = bind_since!(
            sqlx::query_as::<_, (String, String, i64)>(sqlx::AssertSqlSafe(sql.as_str())),
            since
        )
        .fetch_all(&self.read)
        .await?;
        let mut fam: HashMap<&'static str, i64> = HashMap::new();
        let mut tags: HashMap<String, i64> = HashMap::new();
        for (labels, owasp, n) in rows {
            let labels: Vec<String> = serde_json::from_str(&labels).unwrap_or_default();
            for f in crate::classify::request_families(&labels) {
                *fam.entry(f).or_default() += n;
            }
            let mut owasp: Vec<String> = serde_json::from_str(&owasp).unwrap_or_default();
            owasp.sort_unstable();
            owasp.dedup();
            for t in owasp {
                *tags.entry(t).or_default() += n;
            }
        }
        let families = crate::classify::FAMILIES
            .iter()
            .filter_map(|f| {
                fam.get(f).map(|&count| Named {
                    name: (*f).to_string(),
                    count,
                })
            })
            .collect();
        let mut owasp: Vec<Named> = tags
            .into_iter()
            .map(|(name, count)| Named { name, count })
            .collect();
        owasp.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        Ok((families, owasp))
    }

    /// Everything, as an admin sees it.
    pub async fn map_counts(&self, r: Range) -> Result<MapCounts> {
        self.map_counts_as(r, Audience::Admin).await
    }

    pub async fn map_counts_as(&self, r: Range, a: Audience) -> Result<MapCounts> {
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let p = a.rm();
        let sql = match r {
            Range::All => format!(
                "SELECT country AS name, COUNT(*) AS count FROM ips
                 WHERE country IS NOT NULL AND {p}request_count > 0 GROUP BY country"
            ),
            _ => format!(
                "SELECT i.country AS name, COUNT(DISTINCT i.id) AS count
                 FROM requests r JOIN ips i ON r.ip_id = i.id
                 WHERE i.country IS NOT NULL{w} GROUP BY i.country"
            ),
        };
        let rows = self.named(&sql, since).await?;
        let max = rows.iter().map(|n| n.count).max().unwrap_or(0);
        Ok(MapCounts {
            range: r.key(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            countries: rows.into_iter().map(|n| (n.name, n.count)).collect(),
            max,
        })
    }
}

/// [`Store::hourly_by_severity`]'s query and its bind. It reads only
/// `idx_requests_stats`, not the rows.
fn hourly_sql(r: Range, a: Audience) -> (String, Option<&'static str>) {
    let (w, since) = r.ts_clause("r.ts");
    let w = w + &a.released("r");
    let sql = format!(
        "SELECT strftime('%Y-%m-%dT%H:00', r.ts) AS h, r.severity, COUNT(*) FROM requests r
         WHERE 1=1{w} GROUP BY h, r.severity ORDER BY h"
    );
    (sql, since)
}

/// [`Store::families_and_owasp`]'s query and its bind. It reads only
/// `idx_requests_stats`, not the rows.
fn families_sql(r: Range, a: Audience) -> (String, Option<&'static str>) {
    let (w, since) = r.ts_clause("r.ts");
    let w = w + &a.released("r");
    let sql = format!(
        "SELECT r.labels_json, r.owasp_json, COUNT(*) FROM requests r
         WHERE 1=1{w} GROUP BY r.labels_json, r.owasp_json"
    );
    (sql, since)
}

/// Warn when Tor/MaxMind data is missing or older than 48h (original spec §9).
/// GeoIP counts as current on a cluster node without its own databases while
/// a member offers lookups (`maxmind_cluster_seen`).
pub fn intel_stale(intel: &HashMap<String, String>) -> bool {
    let stale = |key: &str| {
        intel
            .get(key)
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() > 48)
            .unwrap_or(true)
    };
    stale("tor_last_fetch") || (stale("maxmind_last_fetch") && stale("maxmind_cluster_seen"))
}

/// How long a cached aggregate is fresh. Longer ranges change slowly
/// relative to their size and cost the most to recompute.
pub fn ttl(r: Range) -> Duration {
    match r {
        Range::H24 => Duration::from_secs(15),
        Range::D7 => Duration::from_secs(60),
        Range::D30 | Range::All => Duration::from_secs(300),
    }
}

/// Fresh lifetime of cached IP-directory and IP pages.
pub const PAGE_TTL: Duration = Duration::from_secs(30);

/// A stale value is served (while one task refreshes it) for at most this
/// many TTLs; older than that, callers wait for the recomputation.
const STALE_FACTOR: u32 = 20;

/// Bound on cached IP-directory pages (anonymous traffic only).
pub const IPS_CACHE_MAX: usize = 64;

/// Bound on cached per-IP overviews (anonymous traffic only).
pub const IP_CACHE_MAX: usize = 256;

type BoxFut<V> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<V>> + Send>>;

struct Entry<V> {
    value: Option<(Instant, Arc<V>)>,
    /// Held while the value is computed: one computation per key at a time.
    flight: Arc<tokio::sync::Mutex<()>>,
    /// A background refresh of a stale value is under way.
    refreshing: bool,
}

impl<V> Entry<V> {
    fn empty() -> Self {
        Self {
            value: None,
            flight: Arc::new(tokio::sync::Mutex::new(())),
            refreshing: false,
        }
    }
}

/// Keyed cache for anonymous traffic: per-key single flight, and
/// serve-stale-while-revalidate. A fresh value is returned as is. A stale
/// one is returned at once while a single background task recomputes it,
/// so an expiry under load costs one query, not one per visitor. A missing
/// (or very old) value is computed by one caller while the others for the
/// same key wait; other keys are not held up.
pub struct SwrCache<K, V> {
    inner: Arc<std::sync::Mutex<HashMap<K, Entry<V>>>>,
    max: usize,
}

impl<K, V> SwrCache<K, V>
where
    K: std::hash::Hash + Eq + Clone + Send + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max,
        }
    }

    pub async fn get<F>(&self, key: K, ttl: Duration, compute: F) -> Result<Arc<V>>
    where
        F: Fn() -> BoxFut<V>,
    {
        let flight = {
            let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let e = map.entry(key.clone()).or_insert_with(Entry::empty);
            match &e.value {
                Some((at, v)) if at.elapsed() < ttl => return Ok(v.clone()),
                Some((at, v)) if at.elapsed() < ttl * STALE_FACTOR => {
                    let v = v.clone();
                    if !e.refreshing {
                        e.refreshing = true;
                        self.spawn_refresh(key, compute());
                    }
                    return Ok(v);
                }
                _ => e.flight.clone(),
            }
        };
        let _guard = flight.lock().await;
        // Another caller may have computed it while this one waited.
        if let Some((at, v)) = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .and_then(|e| e.value.clone())
            && at.elapsed() < ttl
        {
            return Ok(v);
        }
        let fresh = Arc::new(compute().await?);
        self.store(key, fresh.clone());
        Ok(fresh)
    }

    fn spawn_refresh(&self, key: K, fut: BoxFut<V>) {
        let inner = self.inner.clone();
        let max = self.max;
        tokio::spawn(async move {
            let result = fut.await;
            let mut map = inner.lock().unwrap_or_else(|p| p.into_inner());
            match result {
                Ok(v) => Self::insert(&mut map, max, key, Arc::new(v)),
                // The row was deleted: the next caller finds out.
                Err(e) if e.is::<Gone>() => {
                    map.remove(&key);
                }
                Err(e) => {
                    tracing::warn!(?e, "cache refresh failed; serving the stale value");
                    if let Some(entry) = map.get_mut(&key) {
                        entry.refreshing = false;
                    }
                }
            }
        });
    }

    fn store(&self, key: K, v: Arc<V>) {
        let mut map = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::insert(&mut map, self.max, key, v);
    }

    fn insert(map: &mut HashMap<K, Entry<V>>, max: usize, key: K, v: Arc<V>) {
        let e = map.entry(key.clone()).or_insert_with(Entry::empty);
        e.value = Some((Instant::now(), v));
        e.refreshing = false;
        // Bounded: drop entries without a value (a computation that failed
        // or is still running) first, then the oldest values.
        while map.len() > max {
            let Some(victim) = map
                .iter()
                .filter(|(k, _)| **k != key)
                .min_by_key(|(_, e)| e.value.as_ref().map(|(t, _)| *t))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            map.remove(&victim);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

type IpsPage = super::browse::Page<super::browse::IpSummary>;

/// Aggregates and pages for anonymous traffic, plus the admin's aggregates
/// (short TTL).
pub struct StatsCache {
    stats: SwrCache<Range, Stats>,
    map: SwrCache<Range, MapCounts>,
    /// Keyed by the normalised filter (query string incl. page).
    ips: SwrCache<String, IpsPage>,
    /// Per-IP overview, keyed by the IP's row id.
    ip: SwrCache<i64, super::browse::IpOverview>,
    /// `/api/blocklist` bodies, keyed by their canonical parameters.
    blocklist: SwrCache<String, String>,
    /// Admin analytics: aggregates only, so a short staleness is fine and
    /// repeated views of the expensive ranges cost one query each.
    analytics: SwrCache<Range, super::analytics::Analytics>,
    /// Admin aggregates (Overview tiles): every row, released or not.
    admin_stats: SwrCache<Range, Stats>,
}

impl Default for StatsCache {
    fn default() -> Self {
        Self {
            stats: SwrCache::new(Range::ALL.len()),
            map: SwrCache::new(Range::ALL.len()),
            ips: SwrCache::new(IPS_CACHE_MAX),
            ip: SwrCache::new(IP_CACHE_MAX),
            blocklist: SwrCache::new(crate::admin::blocklist::CACHE_MAX),
            analytics: SwrCache::new(Range::ALL.len()),
            admin_stats: SwrCache::new(Range::ALL.len()),
        }
    }
}

impl StatsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn stats(&self, store: &Store, r: Range) -> Result<Arc<Stats>> {
        let store = store.clone();
        self.stats
            .get(r, ttl(r), move || {
                let store = store.clone();
                Box::pin(async move { store.stats_as(r, Audience::Public).await })
            })
            .await
    }

    /// [`Stats`] as an admin sees them: unreleased rows included.
    pub async fn admin_stats(&self, store: &Store, r: Range) -> Result<Arc<Stats>> {
        let store = store.clone();
        self.admin_stats
            .get(r, ttl(r), move || {
                let store = store.clone();
                Box::pin(async move { store.stats_as(r, Audience::Admin).await })
            })
            .await
    }

    /// Public IP-directory pages.
    pub async fn ips(
        &self,
        store: &Store,
        f: &super::browse::IpFilter,
        key: String,
    ) -> Result<Arc<IpsPage>> {
        let store = store.clone();
        let f = f.clone();
        self.ips
            .get(key, PAGE_TTL, move || {
                let (store, f) = (store.clone(), f.clone());
                Box::pin(
                    async move { store.list_ips_as(&f, super::browse::Audience::Public).await },
                )
            })
            .await
    }

    /// Public per-IP overview; `None` when the IP is gone or has no released
    /// request.
    pub async fn ip(
        &self,
        store: &Store,
        ip_id: i64,
    ) -> Result<Option<Arc<super::browse::IpOverview>>> {
        let store = store.clone();
        let got = self
            .ip
            .get(ip_id, PAGE_TTL, move || {
                let store = store.clone();
                Box::pin(async move {
                    store
                        .ip_overview_as(ip_id, super::browse::Audience::Public)
                        .await?
                        .ok_or_else(|| anyhow::Error::new(Gone))
                })
            })
            .await;
        match got {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.is::<Gone>() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A blocklist body, recomputed by `compute` after `ttl`.
    pub async fn blocklist<F>(&self, key: String, ttl: Duration, compute: F) -> Result<Arc<String>>
    where
        F: Fn() -> BoxFut<String>,
    {
        self.blocklist.get(key, ttl, compute).await
    }

    #[cfg(test)]
    pub async fn ips_len(&self) -> usize {
        self.ips.len()
    }

    pub async fn analytics(
        &self,
        store: &Store,
        r: Range,
    ) -> Result<Arc<super::analytics::Analytics>> {
        let store = store.clone();
        self.analytics
            .get(r, ttl(r), move || {
                let store = store.clone();
                Box::pin(async move { store.analytics(r).await })
            })
            .await
    }

    pub async fn map(&self, store: &Store, r: Range) -> Result<Arc<MapCounts>> {
        let store = store.clone();
        self.map
            .get(r, ttl(r), move || {
                let store = store.clone();
                Box::pin(async move { store.map_counts_as(r, Audience::Public).await })
            })
            .await
    }
}

/// The cached row no longer exists.
#[derive(Debug)]
struct Gone;

impl std::fmt::Display for Gone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("gone")
    }
}

impl std::error::Error for Gone {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::browse::Audience;
    use crate::store::requests::NewRequest;

    async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        s.set_ip_geo(a.id, Some("DE"), Some(3320), Some("Deutsche Telekom"))
            .await
            .unwrap();
        s.set_ip_geo(b.id, Some("US"), Some(15169), Some("Google"))
            .await
            .unwrap();
        s.set_ip_tor(b.id, true).await.unwrap();
        let req = |ip_id, path: &str, sev| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: r#"["sensitive-path"]"#.into(),
            owasp_json: Some(r#"["OAT-018"]"#.into()),
            severity: sev,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        };
        s.insert_request(&req(a.id, "/.env", 3)).await.unwrap();
        s.insert_request(&req(a.id, "/wp-login.php", 2))
            .await
            .unwrap();
        s.insert_request(&req(b.id, "/", 0)).await.unwrap();
        // One request 3 days old: outside 24h, inside 7d.
        sqlx::query("INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity) VALUES ('raw-old', datetime('now','-3 days'), ?, 'GET', '/old', '[]', '[]', 1)")
            .bind(b.id).execute(&s.pool).await.unwrap();
        s
    }

    #[test]
    fn range_parse_falls_back_to_24h() {
        assert_eq!(Range::parse(Some("7d")), Range::D7);
        assert_eq!(Range::parse(Some("all")), Range::All);
        assert_eq!(Range::parse(Some("1y")), Range::H24);
        assert_eq!(Range::parse(None), Range::H24);
    }

    #[tokio::test]
    async fn stats_intel_excludes_setup_token_hash() {
        let s = seeded().await;
        s.intel_set("webauthn_setup_token_hash", "deadbeef")
            .await
            .unwrap();
        s.intel_set("tor_last_fetch", "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let st = s.stats(Range::All).await.unwrap();
        assert!(
            !st.intel.contains_key("webauthn_setup_token_hash"),
            "setup token hash must never reach public /api/stats"
        );
        assert!(st.intel.contains_key("tor_last_fetch"));
    }

    #[tokio::test]
    async fn stats_respect_range() {
        let s = seeded().await;
        let h24 = s.stats(Range::H24).await.unwrap();
        assert_eq!(h24.total_requests, 3);
        assert_eq!(h24.unique_ips, 2);
        assert_eq!(h24.countries, 2);
        assert_eq!(h24.tor_ips, 1);
        assert_eq!(h24.top_ips[0].ip, "203.0.113.1");
        assert_eq!(h24.top_ips[0].count, 2);
        assert_eq!(h24.top_ips[0].max_severity, 3);
        assert_eq!(h24.top_labels[0].name, "sensitive-path");
        assert_eq!(h24.top_labels[0].count, 3);
        assert_eq!(h24.recent.len(), 3);
        assert_eq!(h24.recent[0].labels, vec!["sensitive-path".to_string()]);
        assert_eq!(h24.recent[0].owasp, vec!["OAT-018".to_string()]);
        let d7 = s.stats(Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 4);
        assert!(d7.timeline.iter().map(|b| b.count).sum::<i64>() == 4);
        assert!(d7.timeline.len() >= 2, "hourly buckets over 7 days");
        let all = s.stats(Range::All).await.unwrap();
        assert_eq!(all.total_requests, 4);
        assert!(
            all.timeline.iter().all(|b| b.ts.len() == 10),
            "daily buckets are YYYY-MM-DD"
        );
    }

    #[tokio::test]
    async fn ranged_top_labels_count_requests_and_survive_bad_json() {
        let s = seeded().await;
        let ip: i64 = sqlx::query_scalar("SELECT id FROM ips LIMIT 1")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        for (uid, labels) in [
            ("dup", r#"["sensitive-path","sensitive-path"]"#),
            ("bad", "{not json"),
        ] {
            sqlx::query("INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity) VALUES (?, datetime('now'), ?, 'GET', '/x', '[]', ?, 1)")
                .bind(uid).bind(ip).bind(labels).execute(&s.pool).await.unwrap();
        }
        let h24 = s.stats(Range::H24).await.unwrap();
        assert_eq!(h24.top_labels[0].name, "sensitive-path");
        assert_eq!(
            h24.top_labels[0].count, 4,
            "a request counts once per label"
        );
    }

    #[tokio::test]
    async fn map_counts_unique_ips_per_country() {
        let s = seeded().await;
        let m = s.map_counts(Range::All).await.unwrap();
        assert_eq!(m.countries.get("DE"), Some(&1));
        assert_eq!(m.countries.get("US"), Some(&1));
        assert_eq!(m.max, 1);
    }

    #[tokio::test]
    async fn cache_serves_same_instance_within_ttl() {
        let s = seeded().await;
        let c = StatsCache::new();
        let a = c.stats(&s, Range::H24).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: 1,
            method: "GET".into(),
            path: "/new".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 0,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        })
        .await
        .unwrap();
        let b = c.stats(&s, Range::H24).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(b.total_requests, 3, "stale within ttl by design");
        let d7 = c.stats(&s, Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 5, "other range is computed fresh");
    }

    #[tokio::test]
    async fn ip_directory_cache_is_keyed_and_bounded() {
        use crate::store::browse::IpFilter;
        let s = seeded().await;
        let c = StatsCache::new();
        let f = IpFilter::default();
        let a = c.ips(&s, &f, "".into()).await.unwrap();
        let b = c.ips(&s, &f, "".into()).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let other = c
            .ips(
                &s,
                &IpFilter {
                    country: Some("DE".into()),
                    ..Default::default()
                },
                "country=DE&".into(),
            )
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&a, &other));
        assert_eq!(other.items.len(), 1);
        for i in 0..(IPS_CACHE_MAX + 5) {
            c.ips(&s, &f, format!("k{i}&")).await.unwrap();
        }
        assert!(c.ips_len().await <= IPS_CACHE_MAX);
    }

    /// A counter as the cached computation, so tests see how often it ran.
    fn counting(
        n: Arc<std::sync::atomic::AtomicUsize>,
        delay: Duration,
    ) -> impl Fn() -> BoxFut<usize> {
        move || {
            let n = n.clone();
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(n.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1)
            })
        }
    }

    #[tokio::test]
    async fn a_miss_is_computed_once_for_all_waiting_callers() {
        let c: SwrCache<u8, usize> = SwrCache::new(4);
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ttl = Duration::from_secs(60);
        let f = counting(n.clone(), Duration::from_millis(100));
        let (a, b, d) = tokio::join!(c.get(1, ttl, &f), c.get(1, ttl, &f), c.get(1, ttl, &f));
        assert_eq!((*a.unwrap(), *b.unwrap(), *d.unwrap()), (1, 1, 1));
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Another key does not wait for this one's flight.
        let other = counting(n.clone(), Duration::ZERO);
        assert_eq!(*c.get(2, ttl, &other).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn a_stale_value_is_served_while_one_task_refreshes_it() {
        let c: SwrCache<u8, usize> = SwrCache::new(4);
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ttl = Duration::from_millis(50);
        let f = counting(n.clone(), Duration::from_millis(50));
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Stale: returned at once, refreshed in the background, once.
        let started = Instant::now();
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 1);
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 1);
        assert!(started.elapsed() < Duration::from_millis(40), "no waiting");
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 2);
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A refresh that finds the row gone drops the stale value: the next
    /// caller learns it is gone instead of being served it for minutes.
    #[tokio::test]
    async fn a_refresh_that_finds_the_row_gone_evicts_it() {
        let c: SwrCache<u8, usize> = SwrCache::new(4);
        let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ttl = Duration::from_millis(20);
        let f = {
            let gone = gone.clone();
            move || -> BoxFut<usize> {
                let gone = gone.load(std::sync::atomic::Ordering::SeqCst);
                Box::pin(async move {
                    if gone {
                        Err(anyhow::Error::new(Gone))
                    } else {
                        Ok(1)
                    }
                })
            }
        };
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 1);
        gone.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Stale: served once while the refresh finds it gone.
        assert_eq!(*c.get(1, ttl, &f).await.unwrap(), 1);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let e = c.get(1, ttl, &f).await.unwrap_err();
        assert!(e.is::<Gone>(), "{e:#}");
    }

    #[tokio::test]
    async fn all_time_stats_come_from_the_read_models() {
        let s = seeded().await;
        let all = s.stats(Range::All).await.unwrap();
        assert_eq!(all.total_requests, 4);
        assert_eq!(all.unique_ips, 2);
        assert_eq!(all.countries, 2);
        assert_eq!(all.tor_ips, 1);
        let a = all.top_ips.iter().find(|t| t.ip == "203.0.113.1").unwrap();
        assert_eq!((a.count, a.max_severity, a.is_tor), (2, 3, false));
        let b = all.top_ips.iter().find(|t| t.ip == "198.51.100.2").unwrap();
        assert_eq!((b.count, b.max_severity, b.is_tor), (2, 1, true));
        assert_eq!(all.top_labels[0].name, "sensitive-path");
        assert_eq!(all.top_labels[0].count, 3);
        // A scan-only IP (no requests) is not counted.
        s.upsert_ip("192.0.2.9".parse().unwrap()).await.unwrap();
        assert_eq!(s.stats(Range::All).await.unwrap().unique_ips, 2);
    }

    #[tokio::test]
    async fn heatmap_covers_the_last_week_whatever_the_range() {
        let s = seeded().await;
        // The 3-day-old request is outside 24h but still on the heatmap.
        let day = s.stats(Range::H24).await.unwrap();
        assert_eq!(day.timeline.iter().map(|b| b.count).sum::<i64>(), 3);
        assert_eq!(day.heatmap.iter().flatten().sum::<i64>(), 4);
        let all = s.stats(Range::All).await.unwrap();
        assert_eq!(all.heatmap, s.stats(Range::D7).await.unwrap().heatmap);
    }

    #[tokio::test]
    async fn timeline_is_split_by_severity_and_heatmap_adds_up() {
        let s = seeded().await;
        let st = s.stats(Range::D7).await.unwrap();
        let sum: i64 = st.timeline.iter().map(|b| b.count).sum();
        assert_eq!(sum, 4);
        for b in &st.timeline {
            assert_eq!(b.by_severity.iter().sum::<i64>(), b.count, "{b:?}");
        }
        let sev3: i64 = st.timeline.iter().map(|b| b.by_severity[3]).sum();
        assert_eq!(sev3, 1);
        assert_eq!(st.heatmap.len(), 7);
        assert_eq!(st.heatmap.iter().flatten().sum::<i64>(), 4);
        // Daily buckets keep the split.
        let all = s.stats(Range::All).await.unwrap();
        assert!(all.timeline.iter().all(|b| b.ts.len() == 10));
        assert_eq!(
            all.timeline.iter().map(|b| b.by_severity[1]).sum::<i64>(),
            1
        );
    }

    #[tokio::test]
    async fn trends_compare_with_the_previous_window() {
        let s = seeded().await;
        sqlx::query("INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity) VALUES ('prev', datetime('now','-30 hours'), 1, 'GET', '/p', '[]', '[]', 0)")
            .execute(&s.pool).await.unwrap();
        let h24 = s.stats(Range::H24).await.unwrap();
        let p = h24.previous.as_ref().unwrap();
        assert_eq!((p.total_requests, p.unique_ips), (1, 1));
        assert!(s.stats(Range::All).await.unwrap().previous.is_none());
        assert_eq!(h24.new_ips, 2);
        assert!(h24.last_request.is_some());
    }

    #[tokio::test]
    async fn families_and_owasp_count_each_request_once() {
        let s = seeded().await;
        sqlx::query("INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, owasp_json, severity) VALUES ('mix', datetime('now'), 1, 'GET', '/x', '[]', '[\"sqli\",\"xss\",\"env-probe\"]', '[\"A03:2021\",\"A03:2021\"]', 4)")
            .execute(&s.pool).await.unwrap();
        let st = s.stats(Range::H24).await.unwrap();
        let get = |v: &[Named], k: &str| v.iter().find(|n| n.name == k).map(|n| n.count);
        // sqli and xss are both injection: one request, counted once.
        assert_eq!(get(&st.families, "inject"), Some(1));
        assert_eq!(get(&st.families, "recon"), Some(1));
        // The three seeded requests carry "sensitive-path".
        assert_eq!(get(&st.families, "exposure"), Some(3));
        assert_eq!(get(&st.families, "other"), None);
        assert_eq!(get(&st.owasp, "A03:2021"), Some(1));
        assert_eq!(get(&st.owasp, "OAT-018"), Some(3));
        assert_eq!(st.owasp[0].name, "OAT-018", "most frequent first");
    }

    /// The timeline and the families read an index, never the rows (whose
    /// headers and bodies make a full scan slow), for every range and
    /// audience.
    #[tokio::test]
    async fn timeline_and_families_read_only_an_index() {
        let s = seeded().await;
        for r in Range::ALL {
            for a in [Audience::Admin, Audience::Public] {
                for (sql, since) in [hourly_sql(r, a), families_sql(r, a)] {
                    let plan: Vec<(i64, i64, i64, String)> = bind_since!(
                        sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}"))),
                        since
                    )
                    .fetch_all(&s.read)
                    .await
                    .unwrap();
                    let reads: Vec<&str> = plan
                        .iter()
                        .map(|p| p.3.as_str())
                        .filter(|d| d.starts_with("SCAN r ") || d.starts_with("SEARCH r "))
                        .collect();
                    assert!(!reads.is_empty(), "{plan:?}");
                    for d in reads {
                        assert!(
                            d.contains("COVERING INDEX idx_requests_stats"),
                            "{r:?} {a:?}: {d}"
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn open_ports_need_several_distinct_ips() {
        let s = seeded().await;
        let mut ids = vec![];
        for a in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
            ids.push(s.upsert_ip(a.parse().unwrap()).await.unwrap().id);
        }
        for (n, ip) in ids.iter().enumerate() {
            sqlx::query("INSERT INTO scan_jobs (id, ip_id, level, status, queued_at) VALUES (?, ?, 1, 'done', datetime('now'))")
                .bind(n as i64 + 1).bind(ip).execute(&s.pool).await.unwrap();
            sqlx::query("INSERT INTO scans (id, job_id, ip_id, level, started_at, finished_at) VALUES (?, ?, ?, 1, datetime('now'), datetime('now'))")
                .bind(n as i64 + 1).bind(n as i64 + 1).bind(ip).execute(&s.pool).await.unwrap();
            // 22 open on all three, 8080 on one only.
            sqlx::query("INSERT INTO ports (scan_id, port, proto, state, service) VALUES (?, 22, 'tcp', 'open', 'ssh')")
                .bind(n as i64 + 1).execute(&s.pool).await.unwrap();
            if n == 0 {
                sqlx::query("INSERT INTO ports (scan_id, port, proto, state, service) VALUES (1, 8080, 'tcp', 'open', 'http-proxy')")
                    .execute(&s.pool).await.unwrap();
            }
        }
        let st = s.stats(Range::H24).await.unwrap();
        assert_eq!(st.scanned_ips, 3);
        assert_eq!(st.ports.len(), 1, "{:?}", st.ports);
        assert_eq!((st.ports[0].port, st.ports[0].ips), (22, 3));
        assert_eq!(st.ports[0].service.as_deref(), Some("ssh"));
    }

    async fn delayed() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // One released request from a known IP ...
        let known = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        s.set_ip_geo(known.id, Some("DE"), Some(3320), Some("DTAG"))
            .await
            .unwrap();
        s.insert_request(&NewRequest {
            ip_id: known.id,
            method: "GET".into(),
            path: "/old".into(),
            headers_json: "[]".into(),
            labels_json: r#"["wp"]"#.into(),
            severity: 1,
            ..Default::default()
        })
        .await
        .unwrap();
        // ... then pending ones: the known IP again, and a new IP.
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        s.insert_request(&NewRequest {
            ip_id: known.id,
            method: "POST".into(),
            path: "/new".into(),
            headers_json: "[]".into(),
            labels_json: r#"["sqli"]"#.into(),
            severity: 4,
            ..Default::default()
        })
        .await
        .unwrap();
        let fresh = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        s.set_ip_geo(fresh.id, Some("US"), Some(15169), Some("G"))
            .await
            .unwrap();
        s.insert_request(&NewRequest {
            ip_id: fresh.id,
            method: "GET".into(),
            path: "/fresh".into(),
            headers_json: "[]".into(),
            labels_json: r#"["sqli"]"#.into(),
            severity: 4,
            ..Default::default()
        })
        .await
        .unwrap();
        (s, dir)
    }

    #[tokio::test]
    async fn public_stats_count_released_rows_only() {
        let (s, _d) = delayed().await;
        for r in Range::ALL {
            let p = s.stats_as(r, Audience::Public).await.unwrap();
            assert_eq!((p.total_requests, p.unique_ips), (1, 1), "{r:?}");
            assert_eq!(p.top_ips.len(), 1, "{r:?}");
            assert_eq!(p.top_ips[0].max_severity, 1, "{r:?}");
            assert!(p.top_labels.iter().all(|l| l.name != "sqli"), "{r:?}");
            assert!(p.recent.iter().all(|x| x.path == "/old"), "{r:?}");
            assert_eq!(p.top_countries.len(), 1, "{r:?}");
            let a = s.stats_as(r, Audience::Admin).await.unwrap();
            assert_eq!((a.total_requests, a.unique_ips), (3, 2), "{r:?}");
        }
        let h = s.stats_as(Range::H24, Audience::Public).await.unwrap();
        assert_eq!(h.new_ips, 1);
        assert_eq!(h.timeline.iter().map(|b| b.count).sum::<i64>(), 1);
        let m = s.map_counts_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!(m.countries.get("US"), None);
        assert_eq!(m.countries.get("DE"), Some(&1));
        let m = s.map_counts_as(Range::H24, Audience::Public).await.unwrap();
        assert_eq!(m.countries.get("US"), None);
    }

    #[tokio::test]
    async fn ai_decoys_card_only_from_released_rows() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        for i in 0..6 {
            let ip = s
                .upsert_ip(format!("203.0.113.{}", i % 2 + 1).parse().unwrap())
                .await
                .unwrap();
            s.insert_request(&NewRequest {
                ip_id: ip.id,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                answer: Some("decoy:llm:chat-completions".into()),
                decoy_in: Some(r#"{"api":"openai","model":"llama3:70b"}"#.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        assert!(p.ai_decoys.is_none(), "pending rows");
        assert!(
            s.stats_as(Range::All, Audience::Admin)
                .await
                .unwrap()
                .ai_decoys
                .is_some()
        );
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        s.release_due().await.unwrap();
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        let a = p.ai_decoys.as_ref().expect("card shown");
        assert!(a.models.iter().any(|n| n.name == "llama3:70b"));
        let json = serde_json::to_value(&p).unwrap();
        assert!(json["ai_decoys"]["models"].is_array());
    }

    #[tokio::test]
    async fn time_held_counts_only_released_rows_publicly() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let held = |path: &str, ms: Option<i64>| NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            answer: ms.map(|_| "tarpit".into()),
            held_ms: ms,
            ..Default::default()
        };
        s.insert_request(&held("/released", Some(3_600_000)))
            .await
            .unwrap();
        s.insert_request(&held("/plain", None)).await.unwrap();
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        s.insert_request(&held("/pending", Some(7_200_000)))
            .await
            .unwrap();
        let admin = s.stats_as(Range::H24, Audience::Admin).await.unwrap();
        assert_eq!(admin.tarpit_held_ms, 10_800_000);
        let public = s.stats_as(Range::H24, Audience::Public).await.unwrap();
        assert_eq!(public.tarpit_held_ms, 3_600_000, "only released rows");
    }

    #[tokio::test]
    async fn released_rows_appear_publicly() {
        let (s, _d) = delayed().await;
        sqlx::query("UPDATE requests SET public_at = datetime('now', '-1 seconds') WHERE public_at IS NOT NULL")
            .execute(&s.pool).await.unwrap();
        s.release_due().await.unwrap();
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!((p.total_requests, p.unique_ips), (3, 2));
        assert_eq!(
            s.recent_requests(RECENT_MAX, Audience::Public)
                .await
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn recent_requests_cover_the_last_day_newest_first() {
        let (s, _d) = delayed().await;
        let admin = s.recent_requests(2, Audience::Admin).await.unwrap();
        assert_eq!(
            admin.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            ["/fresh", "/new"]
        );
        sqlx::query("UPDATE requests SET ts = datetime('now', '-25 hours') WHERE path = '/old'")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(
            s.recent_requests(RECENT_MAX, Audience::Public)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn public_scans_wait_for_the_delay_and_a_public_ip() {
        let (s, _d) = delayed().await;
        s.set_publish_delay(Duration::from_secs(300), Duration::ZERO)
            .await
            .unwrap();
        sqlx::query("INSERT INTO scan_jobs (id, ip_id, level, status, queued_at) VALUES (1, 1, 1, 'done', datetime('now'))")
            .execute(&s.pool).await.unwrap();
        // A scan of the public IP finished long ago, one just now, and one
        // of the pending-only IP long ago.
        for (ip, ago) in [
            ("203.0.113.1", "-1 hours"),
            ("203.0.113.1", "-0 seconds"),
            ("198.51.100.2", "-1 hours"),
        ] {
            sqlx::query(
                "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at)
                 VALUES (1, (SELECT id FROM ips WHERE ip = ?), 1, datetime('now', ?), datetime('now', ?))",
            )
            .bind(ip).bind(ago).bind(ago)
            .execute(&s.pool).await.unwrap();
        }
        let p = s.stats_as(Range::All, Audience::Public).await.unwrap();
        assert_eq!((p.scans_done, p.scanned_ips), (1, 1));
        let a = s.stats_as(Range::All, Audience::Admin).await.unwrap();
        assert_eq!((a.scans_done, a.scanned_ips), (3, 2));
    }

    #[tokio::test]
    async fn admin_stats_read_everything() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
        s.insert_request(&crate::store::requests::NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        let a = StatsCache::new().admin_stats(&s, Range::H24).await.unwrap();
        assert_eq!((a.total_requests, a.unique_ips), (1, 1));
    }

    #[test]
    fn intel_stale_when_missing_or_old() {
        let mut m = HashMap::new();
        assert!(intel_stale(&m));
        m.insert("tor_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        m.insert(
            "maxmind_last_fetch".into(),
            (chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339(),
        );
        assert!(intel_stale(&m));
        m.insert("maxmind_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        assert!(!intel_stale(&m));
        // A cluster node without its own databases: a member's lookups count.
        m.remove("maxmind_last_fetch");
        assert!(intel_stale(&m));
        m.insert(
            "maxmind_cluster_seen".into(),
            chrono::Utc::now().to_rfc3339(),
        );
        assert!(!intel_stale(&m));
    }
}
