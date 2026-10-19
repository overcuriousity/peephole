//! Aggregates for the admin analytics page: what the trap's requests asked
//! for and what the counter-scans found, per time range. Admin-only — the
//! paths, user agents and JA4/JA4H fingerprints describe request contents.
use super::Store;
use super::browse::Audience;
use super::stats::{Named, PortStat, Range, RecentRequest, RecentTuple, recent_from};
use anyhow::Result;
use std::collections::HashMap;

/// A value, how many requests carried it and from how many IPs.
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct NamedIps {
    pub name: String,
    pub count: i64,
    pub ips: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Analytics {
    pub range: &'static str,
    pub generated_at: String,
    pub total_requests: i64,
    pub paths: Vec<NamedIps>,
    pub user_agents: Vec<NamedIps>,
    pub ja4: Vec<NamedIps>,
    pub ja4h: Vec<NamedIps>,
    pub methods: Vec<Named>,
    pub transports: Vec<Named>,
    pub answers: Vec<Named>,
    /// Open ports of scans finished in the range, no threshold.
    pub ports: Vec<PortStat>,
    /// Product strings nmap reported on open ports.
    pub products: Vec<NamedIps>,
    pub os_guesses: Vec<NamedIps>,
    /// HASSH-server and JA4X of the scanned sources (`host_keys`).
    pub hassh: Vec<NamedIps>,
    pub ja4x: Vec<NamedIps>,
    /// IPs active in the range by AbuseIPDB score band.
    pub abuse: Vec<Named>,
    /// Scans finished in the range per level.
    pub scan_levels: Vec<Named>,
    /// Jobs queued in the range per status.
    pub job_status: Vec<Named>,
    /// Requests per persona the nodes presented as (MIK-560 D8), most
    /// requested first; rows without a persona (older builds) left out.
    pub personas: Vec<PersonaStat>,
    /// Sources and campaigns with AI-agent traces (MIK-560 D12).
    pub agent: AgentShare,
}

/// One persona's requests in a range, cluster-wide.
#[derive(Clone, Debug, serde::Serialize)]
pub struct PersonaStat {
    pub name: String,
    pub requests: i64,
    /// Distinct source IPs, which is also the number of (IP, persona)
    /// first contacts the follow-up rate is taken over.
    pub ips: i64,
    /// First contacts followed by another request from the same IP, on
    /// any node and as any persona, within 24 hours (0 when not counted).
    pub followed: i64,
    /// Requests per label family (`classify::FAMILIES` order, non-zero
    /// only).
    pub families: Vec<Named>,
}

/// One bucket of the agent share: distinct IPs and active campaigns, and
/// how many of them carried an AI-agent label in the bucket.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AgentBucket {
    pub ts: String,
    pub ips: i64,
    pub agent_ips: i64,
    pub campaigns: i64,
    pub agent_campaigns: i64,
}

/// The agent share over the whole range (`total`, no bucket key) and per
/// hour or day (`series`, oldest first).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AgentShare {
    pub total: AgentBucket,
    pub series: Vec<AgentBucket>,
}

/// A request carries an AI-agent label (`classify::AGENT_LABELS`): both
/// start with this, and a stored label list quotes every label.
pub(crate) const AGENT_LIKE: &str = "r.labels_json LIKE '%\"ai-agent-%'";

/// The rows of a known persona (`trap::persona::ALL`): one seek per
/// persona on `idx_requests_persona`, and a member's replicated free text
/// in the column never reaches a page.
fn persona_in() -> String {
    let names: Vec<String> = crate::trap::persona::ALL
        .iter()
        .map(|p| format!("'{}'", p.name))
        .collect();
    format!("r.persona IN ({})", names.join(","))
}

/// The per-persona counts. With `followed`, one grouped query over the
/// (IP, persona) first contacts of the range: each first request's IP is
/// looked up again in the 24 hours after it (`idx_requests_ip_ts`).
fn persona_sql(w: &str, followed: bool) -> String {
    let f = if followed {
        "SUM(EXISTS (SELECT 1 FROM requests q WHERE q.ip_id = f.ip_id
                     AND q.ts > f.t0 AND q.ts <= datetime(f.t0, '+24 hours')))"
    } else {
        "0"
    };
    let known = persona_in();
    format!(
        "SELECT f.persona, SUM(f.n), COUNT(*), {f}
         FROM (SELECT r.persona, r.ip_id, MIN(r.ts) AS t0, COUNT(*) AS n
               FROM requests r INDEXED BY idx_requests_persona
               WHERE {known}{w} GROUP BY r.persona, r.ip_id) f
         GROUP BY f.persona ORDER BY 2 DESC, f.persona"
    )
}

/// Per bucket of the range: distinct IPs and those with an agent label,
/// and the same for campaigns (a campaign is active through any member's
/// request, agent-driven through any member's request with the label).
/// Without a bucket key, one row for the whole range.
fn agent_sql(bucket: Option<&str>, w: &str) -> [String; 2] {
    let (b, g) = match bucket {
        Some(fmt) => (format!("strftime('{fmt}', r.ts)"), " GROUP BY 1 ORDER BY 1"),
        None => ("''".to_string(), ""),
    };
    [
        format!(
            "SELECT {b}, COUNT(DISTINCT r.ip_id),
                    COUNT(DISTINCT CASE WHEN {AGENT_LIKE} THEN r.ip_id END)
             FROM requests r WHERE 1=1{w}{g}"
        ),
        format!(
            "SELECT {b}, COUNT(DISTINCT m.campaign_key),
                    COUNT(DISTINCT CASE WHEN {AGENT_LIKE} THEN m.campaign_key END)
             FROM requests r JOIN campaign_members m ON m.ip_id = r.ip_id WHERE 1=1{w}{g}"
        ),
    ]
}

/// Rows per ranked list.
const TOP: i64 = 15;

/// The User-Agent of a stored `headers_json` (`[[name, value], …]`).
pub(crate) const UA_SQL: &str = "COALESCE((SELECT json_extract(h.value, '$[1]')
      FROM json_each(CASE WHEN json_valid(r.headers_json) THEN r.headers_json ELSE '[]' END) h
      WHERE lower(json_extract(h.value, '$[0]')) = 'user-agent' LIMIT 1), '(none)')";

/// The top values of a fingerprint column, rows without one left out; `w`
/// is the time window's `AND …` (or nothing). In a window, `+` keeps a
/// partial index on the column out of the plan: it would read every
/// fingerprinted row to find the window's.
fn ranked_fp(col: &str, w: &str) -> String {
    let plus = if w.is_empty() { "" } else { "+" };
    format!(
        "SELECT r.{col} AS name, COUNT(*) AS count, COUNT(DISTINCT r.ip_id) AS ips
         FROM requests r WHERE {plus}r.{col} IS NOT NULL{w}
         GROUP BY name ORDER BY count DESC, name LIMIT {TOP}"
    )
}

impl Store {
    async fn named_ips(&self, sql: String, since: Option<&'static str>) -> Result<Vec<NamedIps>> {
        let mut q = sqlx::query_as::<_, NamedIps>(sqlx::AssertSqlSafe(sql));
        if let Some(m) = since {
            q = q.bind(m);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    async fn named_in(&self, sql: String, since: Option<&'static str>) -> Result<Vec<Named>> {
        let mut q = sqlx::query_as::<_, Named>(sqlx::AssertSqlSafe(sql));
        if let Some(m) = since {
            q = q.bind(m);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    pub async fn analytics(&self, r: Range) -> Result<Analytics> {
        let since = r.since();
        let w = if since.is_some() {
            " AND r.ts >= datetime('now', ?)"
        } else {
            ""
        };
        let ws = if since.is_some() {
            " AND s.finished_at >= datetime('now', ?)"
        } else {
            ""
        };
        let ranked = |expr: &str| {
            format!(
                "SELECT {expr} AS name, COUNT(*) AS count, COUNT(DISTINCT r.ip_id) AS ips
                 FROM requests r WHERE 1=1{w} GROUP BY name ORDER BY count DESC, name LIMIT {TOP}"
            )
        };
        let shares = |expr: &str| {
            format!(
                "SELECT {expr} AS name, COUNT(*) AS count
                 FROM requests r WHERE 1=1{w} GROUP BY name ORDER BY count DESC, name LIMIT {TOP}"
            )
        };
        let mut total = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) FROM requests r WHERE 1=1{w}"
        )));
        if let Some(m) = since {
            total = total.bind(m);
        }
        let total_requests = total.fetch_one(&self.read).await?;
        let paths = self.named_ips(ranked("r.path"), since).await?;
        let user_agents = self.named_ips(ranked(UA_SQL), since).await?;
        let ja4 = self.named_ips(ranked_fp("ja4", w), since).await?;
        let ja4h = self.named_ips(ranked_fp("ja4h", w), since).await?;
        let methods = self.named_in(shares("r.method"), since).await?;
        let transports = self
            .named_in(shares("COALESCE(r.transport, 'unknown')"), since)
            .await?;
        let answers = self
            .named_in(shares("COALESCE(r.answer, 'unknown')"), since)
            .await?;
        let mut ports = sqlx::query_as::<_, PortStat>(sqlx::AssertSqlSafe(format!(
            "SELECT p.port, p.proto, MAX(p.service) AS service, COUNT(DISTINCT s.ip_id) AS ips
             FROM ports p JOIN scans s ON p.scan_id = s.id
             WHERE p.state = 'open'{ws}
             GROUP BY p.port, p.proto ORDER BY ips DESC, p.port LIMIT 20"
        )));
        if let Some(m) = since {
            ports = ports.bind(m);
        }
        let ports = ports.fetch_all(&self.read).await?;
        let products = self
            .named_ips(
                format!(
                    "SELECT p.product || COALESCE(' ' || p.version, '') AS name, COUNT(*) AS count,
                            COUNT(DISTINCT s.ip_id) AS ips
                     FROM ports p JOIN scans s ON p.scan_id = s.id
                     WHERE p.state = 'open' AND p.product IS NOT NULL AND p.product != ''{ws}
                     GROUP BY name ORDER BY ips DESC, name LIMIT {TOP}"
                ),
                since,
            )
            .await?;
        let os_guesses = self
            .named_ips(
                format!(
                    "SELECT s.os_guess AS name, COUNT(*) AS count, COUNT(DISTINCT s.ip_id) AS ips
                     FROM scans s WHERE s.os_guess IS NOT NULL AND s.os_guess != ''{ws}
                     GROUP BY name ORDER BY ips DESC, name LIMIT {TOP}"
                ),
                since,
            )
            .await?;
        // Counter-scans only: probes are an admin's choice and would bias
        // the top lists, so the join on scans leaves their keys out.
        let host_key = |kind: &str| {
            format!(
                "SELECT h.fingerprint AS name, COUNT(*) AS count, COUNT(DISTINCT h.ip_id) AS ips
                 FROM host_keys h JOIN scans s ON s.id = h.scan_id
                 WHERE h.kind = '{kind}'{ws}
                 GROUP BY name ORDER BY ips DESC, name LIMIT {TOP}"
            )
        };
        let hassh = self
            .named_ips(host_key(crate::model::hostkeys::HASSH), since)
            .await?;
        let ja4x = self
            .named_ips(host_key(crate::model::hostkeys::JA4X), since)
            .await?;
        // Bands in display order; an IP active in the range counts once.
        let active = match r {
            Range::All => "SELECT abuse_score FROM ips WHERE request_count > 0".to_string(),
            _ => "SELECT abuse_score FROM ips
                  WHERE request_count > 0 AND last_seen >= datetime('now', ?)"
                .to_string(),
        };
        let abuse = self
            .named_in(
                format!(
                    "SELECT CASE WHEN abuse_score IS NULL THEN 'not looked up'
                                 WHEN abuse_score = 0 THEN '0'
                                 WHEN abuse_score < 25 THEN '1–24'
                                 WHEN abuse_score < 50 THEN '25–49'
                                 WHEN abuse_score < 75 THEN '50–74'
                                 WHEN abuse_score < 100 THEN '75–99'
                                 ELSE '100' END AS name,
                            COUNT(*) AS count
                     FROM ({active})
                     GROUP BY name
                     ORDER BY CASE name WHEN '0' THEN 0 WHEN '1–24' THEN 1 WHEN '25–49' THEN 2
                              WHEN '50–74' THEN 3 WHEN '75–99' THEN 4 WHEN '100' THEN 5 ELSE 6 END"
                ),
                since,
            )
            .await?;
        let scan_levels = self
            .named_in(
                format!(
                    "SELECT 'level ' || s.level AS name, COUNT(*) AS count
                     FROM scans s WHERE 1=1{ws} GROUP BY s.level ORDER BY s.level"
                ),
                since,
            )
            .await?;
        let wj = if since.is_some() {
            " AND j.queued_at >= datetime('now', ?)"
        } else {
            ""
        };
        let job_status = self
            .named_in(
                format!(
                    "SELECT j.status AS name, COUNT(*) AS count
                     FROM scan_jobs j WHERE 1=1{wj} GROUP BY j.status ORDER BY count DESC"
                ),
                since,
            )
            .await?;
        Ok(Analytics {
            range: r.key(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_requests,
            paths,
            user_agents,
            ja4,
            ja4h,
            methods,
            transports,
            answers,
            ports,
            products,
            os_guesses,
            hassh,
            ja4x,
            abuse,
            scan_levels,
            job_status,
            personas: self.personas_as(r, Audience::Admin, true).await?,
            agent: self.agent_share(r).await?,
        })
    }

    /// Requests, IPs and family mix per persona over the range this
    /// audience may see; the follow-up count only with `followed`.
    pub(crate) async fn personas_as(
        &self,
        r: Range,
        a: Audience,
        followed: bool,
    ) -> Result<Vec<PersonaStat>> {
        let (w, since) = r.ts_clause("r.ts");
        let w = w + &a.released("r");
        let mut q = sqlx::query_as::<_, (String, i64, i64, i64)>(sqlx::AssertSqlSafe(persona_sql(
            &w, followed,
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let counts = q.fetch_all(&self.read).await?;
        let mut q = sqlx::query_as::<_, (String, String, i64)>(sqlx::AssertSqlSafe(format!(
            "SELECT r.persona, r.labels_json, COUNT(*) FROM requests r
             WHERE {}{w} GROUP BY r.persona, r.labels_json",
            persona_in()
        )));
        if let Some(m) = since {
            q = q.bind(m);
        }
        let mut fam: HashMap<String, HashMap<&'static str, i64>> = HashMap::new();
        for (persona, labels, n) in q.fetch_all(&self.read).await? {
            let labels: Vec<String> = serde_json::from_str(&labels).unwrap_or_default();
            let per = fam.entry(persona).or_default();
            for f in crate::classify::request_families(&labels) {
                *per.entry(f).or_default() += n;
            }
        }
        Ok(counts
            .into_iter()
            .map(|(name, requests, ips, followed)| {
                let per = fam.remove(&name).unwrap_or_default();
                PersonaStat {
                    families: crate::classify::FAMILIES
                        .iter()
                        .filter_map(|f| {
                            per.get(f).map(|&count| Named {
                                name: (*f).to_string(),
                                count,
                            })
                        })
                        .collect(),
                    name,
                    requests,
                    ips,
                    followed,
                }
            })
            .collect())
    }

    async fn agent_rows(
        &self,
        sql: String,
        since: Option<&'static str>,
    ) -> Result<Vec<(Option<String>, i64, i64)>> {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(sql));
        if let Some(m) = since {
            q = q.bind(m);
        }
        Ok(q.fetch_all(&self.read).await?)
    }

    /// The agent share of the range, per hour (24 h, 7 d) or day.
    async fn agent_share(&self, r: Range) -> Result<AgentShare> {
        let (w, since) = r.ts_clause("r.ts");
        let fmt = if r.hourly() {
            "%Y-%m-%dT%H:00"
        } else {
            "%Y-%m-%d"
        };
        let [ips, campaigns] = agent_sql(Some(fmt), &w);
        let mut series: Vec<AgentBucket> = self
            .agent_rows(ips, since)
            .await?
            .into_iter()
            .map(|(ts, ips, agent_ips)| AgentBucket {
                ts: ts.unwrap_or_default(),
                ips,
                agent_ips,
                ..Default::default()
            })
            .collect();
        for (ts, n, a) in self.agent_rows(campaigns, since).await? {
            // Every campaign request is a request: its bucket exists.
            if let Some(b) = series.iter_mut().find(|b| Some(&b.ts) == ts.as_ref()) {
                (b.campaigns, b.agent_campaigns) = (n, a);
            }
        }
        let [ips, campaigns] = agent_sql(None, &w);
        let (_, ips, agent_ips) = self.agent_rows(ips, since).await?.pop().unwrap_or_default();
        let (_, campaigns, agent_campaigns) = self
            .agent_rows(campaigns, since)
            .await?
            .pop()
            .unwrap_or_default();
        Ok(AgentShare {
            total: AgentBucket {
                ts: String::new(),
                ips,
                agent_ips,
                campaigns,
                agent_campaigns,
            },
            series,
        })
    }

    /// The newest `limit` requests recorded after the row `after` (local
    /// row ids), oldest first: a live view that falls behind skips ahead.
    /// Replicated rows get new local ids, so a cursor on the id sees them.
    pub async fn requests_after(&self, after: i64, limit: i64) -> Result<Vec<RecentRequest>> {
        let sql = format!(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit, {}
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.id > ? ORDER BY r.id DESC LIMIT ?",
            super::waves::feed_flags_sql()
        );
        let rows: Vec<RecentTuple> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(after)
            .bind(limit)
            .fetch_all(&self.read)
            .await?;
        Ok(rows.into_iter().rev().map(recent_from).collect())
    }

    /// The newest local request row id (0 for none).
    pub async fn max_request_id(&self) -> Result<i64> {
        Ok(
            sqlx::query_scalar::<_, Option<i64>>("SELECT MAX(id) FROM requests")
                .fetch_one(&self.read)
                .await?
                .unwrap_or(0),
        )
    }

    /// Other requests of the same IP, newest first.
    pub async fn related_by_ip(&self, ip_id: i64, except: i64) -> Result<Vec<RecentRequest>> {
        let rows: Vec<RecentTuple> = sqlx::query_as(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit, 0, 0
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.ip_id = ? AND r.id != ? ORDER BY r.ts DESC, r.id DESC LIMIT 10",
        )
        .bind(ip_id)
        .bind(except)
        .fetch_all(&self.read)
        .await?;
        Ok(rows.into_iter().map(recent_from).collect())
    }

    /// Requests from other IPs with the same JA4 in the last
    /// [`RELATED_JA4_DAYS`] days (newest first, at most 10), and how many
    /// distinct other IPs sent one. Bounded by time: JA4 is not indexed.
    pub async fn related_by_ja4(&self, ja4: &str, ip_id: i64) -> Result<(Vec<RecentRequest>, i64)> {
        let since = format!("-{RELATED_JA4_DAYS} days");
        let rows: Vec<RecentTuple> = sqlx::query_as(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit, 0, 0
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.ts >= datetime('now', ?) AND r.ja4 = ? AND r.ip_id != ?
             ORDER BY r.ts DESC, r.id DESC LIMIT 10",
        )
        .bind(&since)
        .bind(ja4)
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?;
        let ips: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT ip_id) FROM requests
             WHERE ts >= datetime('now', ?) AND ja4 = ? AND ip_id != ?",
        )
        .bind(&since)
        .bind(ja4)
        .bind(ip_id)
        .fetch_one(&self.read)
        .await?;
        Ok((rows.into_iter().map(recent_from).collect(), ips))
    }
}

/// How far back the request page looks for the same JA4.
pub const RELATED_JA4_DAYS: i64 = 7;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        let req = |ip_id, path: &str, ua: &str, ja4: Option<&str>| NewRequest {
            ip_id,
            method: "GET".into(),
            path: path.into(),
            headers_json: serde_json::to_string(&[("Host", "x"), ("User-Agent", ua)]).unwrap(),
            labels_json: "[]".into(),
            ja4: ja4.map(String::from),
            // zgrab sends one header more: another JA4H.
            raw_head: Some(
                format!(
                    "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: {ua}\r\n{}\r\n",
                    if ua == "zgrab" { "Accept: */*\r\n" } else { "" }
                )
                .into_bytes(),
            ),
            transport: Some("https".into()),
            ..Default::default()
        };
        s.insert_request(&req(a.id, "/.env", "curl/8", Some("t13d_a")))
            .await
            .unwrap();
        s.insert_request(&req(a.id, "/.env", "curl/8", Some("t13d_a")))
            .await
            .unwrap();
        s.insert_request(&req(b.id, "/.env", "zgrab", Some("t13d_a")))
            .await
            .unwrap();
        s.insert_request(&req(b.id, "/", "zgrab", None))
            .await
            .unwrap();
        s
    }

    #[tokio::test]
    async fn ranks_paths_agents_and_ja4_with_distinct_ips() {
        let s = seeded().await;
        let a = s.analytics(Range::H24).await.unwrap();
        assert_eq!(a.total_requests, 4);
        assert_eq!(
            (a.paths[0].name.as_str(), a.paths[0].count, a.paths[0].ips),
            ("/.env", 3, 2)
        );
        let ua: Vec<_> = a
            .user_agents
            .iter()
            .map(|n| (n.name.as_str(), n.count))
            .collect();
        assert!(
            ua.contains(&("curl/8", 2)) && ua.contains(&("zgrab", 2)),
            "{ua:?}"
        );
        assert_eq!((a.ja4[0].count, a.ja4[0].ips), (3, 2));
        let ja4h: Vec<_> = a.ja4h.iter().map(|n| (n.count, n.ips)).collect();
        assert_eq!(ja4h, [(2, 1), (2, 1)], "one per header order");
        assert!(a.ja4h.iter().all(|n| n.name.starts_with("ge11nn")));
        assert_eq!(a.transports[0].name, "https");
        assert_eq!(a.abuse[0].name, "not looked up");
        assert_eq!(a.abuse[0].count, 2);
    }

    /// Over a time window the fingerprint lists read the window through
    /// the time index, not every fingerprinted row through the JA4 / JA4H
    /// one.
    #[tokio::test]
    async fn fingerprint_lists_read_only_the_window() {
        let s = seeded().await;
        for col in ["ja4", "ja4h"] {
            let sql = ranked_fp(col, " AND r.ts >= datetime('now', ?)");
            let plan: Vec<(i64, i64, i64, String)> =
                sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                    .bind("-24 hours")
                    .fetch_all(&s.pool)
                    .await
                    .unwrap();
            assert!(
                plan.iter().any(|p| p.3.contains("idx_requests_ts")),
                "{col}: {plan:?}"
            );
        }
    }

    /// A lookup by value reads the JA4 index.
    #[tokio::test]
    async fn ja4_lookups_use_their_index() {
        let s = seeded().await;
        let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN SELECT ip_id FROM requests r WHERE r.ja4 IS NOT NULL AND r.ja4 = ?",
        )
        .bind("t13d_a")
        .fetch_all(&s.pool)
        .await
        .unwrap();
        assert!(
            plan.iter().any(|p| p.3.contains("idx_requests_ja4")),
            "{plan:?}"
        );
    }

    #[tokio::test]
    async fn live_cursor_and_related_requests() {
        let s = seeded().await;
        let max = s.max_request_id().await.unwrap();
        assert_eq!(s.requests_after(max - 2, 10).await.unwrap().len(), 2);
        assert!(s.requests_after(max, 10).await.unwrap().is_empty());
        let newest = s.requests_after(0, 2).await.unwrap();
        assert_eq!(newest.len(), 2);
        assert_eq!(newest[1].id, max, "newest last, the backlog skipped");
        let by_ip = s.related_by_ip(1, 1).await.unwrap();
        assert_eq!(by_ip.len(), 1);
        let (rows, ips) = s.related_by_ja4("t13d_a", 1).await.unwrap();
        assert_eq!((rows.len(), ips), (1, 1));
        assert_eq!(rows[0].ip, "198.51.100.2");
    }

    /// Rows `hours` ago from the IP, as the persona (None: a row of an
    /// older build), with these labels.
    async fn personas_seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mut ip = Vec::new();
        for a in ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"] {
            ip.push(s.upsert_ip(a.parse().unwrap()).await.unwrap().id);
        }
        let rows: [(usize, i64, Option<&str>, &str); 7] = [
            // A: followed one hour later, as another persona.
            (0, 50, Some("wordpress"), r#"["sqli"]"#),
            (0, 49, Some("gpu-box"), r#"["probe","ai-agent-tooling"]"#),
            // B: back only after 30 hours, not a follow-up.
            (1, 40, Some("wordpress"), r#"["sensitive-path"]"#),
            (1, 10, Some("wordpress"), r#"["sensitive-path"]"#),
            // C: followed by a legacy row, which counts as "another request".
            (2, 5, Some("wordpress"), r#"["sensitive-path"]"#),
            (2, 4, None, "[]"),
            // D: legacy only, left out of every persona.
            (3, 3, None, r#"["sqli"]"#),
        ];
        for (who, hours, persona, labels) in rows {
            let ts = (chrono::Utc::now() - chrono::Duration::hours(hours))
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();
            s.insert_request(&NewRequest {
                ip_id: ip[who],
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: labels.into(),
                ts: Some(ts),
                persona: persona.map(String::from),
                ..Default::default()
            })
            .await
            .unwrap();
        }
        // A and B form a campaign; A's request carries the agent label.
        sqlx::query(
            "INSERT INTO campaigns (key, num, anchor_ip_id, size, first_seen, last_seen,
                                    hard_edges, soft_edges, v, computed_at)
             VALUES ('k', 1, ?, 2, '', '', 1, 0, 1, '')",
        )
        .bind(ip[0])
        .execute(&s.pool)
        .await
        .unwrap();
        for who in [0, 1] {
            sqlx::query("INSERT INTO campaign_members (ip_id, campaign_key) VALUES (?, 'k')")
                .bind(ip[who])
                .execute(&s.pool)
                .await
                .unwrap();
        }
        s
    }

    #[tokio::test]
    async fn personas_count_requests_ips_families_and_follow_ups() {
        let s = personas_seeded().await;
        let a = s.analytics(Range::D7).await.unwrap();
        let got: Vec<_> = a
            .personas
            .iter()
            .map(|p| (p.name.as_str(), p.requests, p.ips, p.followed))
            .collect();
        assert_eq!(got, [("wordpress", 4, 3, 2), ("gpu-box", 1, 1, 0)]);
        let fam: Vec<_> = a.personas[0]
            .families
            .iter()
            .map(|n| (n.name.as_str(), n.count))
            .collect();
        assert_eq!(fam, [("exposure", 3), ("inject", 1)]);
        // In the last 24 hours B (back at 10 h) is first seen there, and
        // not followed.
        let a = s.analytics(Range::H24).await.unwrap();
        let got: Vec<_> = a
            .personas
            .iter()
            .map(|p| (p.name.as_str(), p.requests, p.ips, p.followed))
            .collect();
        assert_eq!(got, [("wordpress", 2, 2, 1)]);
    }

    #[tokio::test]
    async fn agent_share_per_bucket_and_over_the_range() {
        let s = personas_seeded().await;
        let a = s.analytics(Range::D7).await.unwrap();
        let t = &a.agent.total;
        assert_eq!(
            (t.ips, t.agent_ips, t.campaigns, t.agent_campaigns),
            (4, 1, 1, 1)
        );
        let agent: Vec<_> = a.agent.series.iter().filter(|b| b.agent_ips > 0).collect();
        assert_eq!(agent.len(), 1, "{:?}", a.agent.series);
        assert_eq!(
            (agent[0].ips, agent[0].campaigns, agent[0].agent_campaigns),
            (1, 1, 1)
        );
        assert_eq!(
            a.agent.series.iter().map(|b| b.ips).sum::<i64>(),
            7,
            "one IP per hour"
        );
        let a = s.analytics(Range::H24).await.unwrap();
        let t = &a.agent.total;
        assert_eq!(
            (t.ips, t.agent_ips, t.campaigns, t.agent_campaigns),
            (3, 0, 1, 0)
        );
    }

    /// The wall: a persona only from three IPs up, an agent count only.
    #[tokio::test]
    async fn public_personas_need_three_ips() {
        let s = personas_seeded().await;
        for r in [Range::D7, Range::All] {
            let st = s.stats_as(r, Audience::Public).await.unwrap();
            let names: Vec<_> = st.personas.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["wordpress"], "{r:?}: gpu-box has one IP");
            assert_eq!(st.agent_ips, 1, "{r:?}");
            let json = serde_json::to_value(&st).unwrap();
            assert!(json.get("personas").is_none(), "{json}");
            assert_eq!(json["agent_ips"], 1);
        }
        let st = s.stats_as(Range::H24, Audience::Public).await.unwrap();
        assert!(st.personas.is_empty(), "two IPs in the last 24 hours");
        assert_eq!(st.agent_ips, 0);
    }

    /// Per-persona counts read the (persona, ts) index, the follow-up
    /// lookup the (ip_id, ts) one.
    #[tokio::test]
    async fn persona_counts_read_the_persona_index() {
        let s = personas_seeded().await;
        let sql = persona_sql(" AND r.ts >= datetime('now', ?)", true);
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                .bind("-24 hours")
                .fetch_all(&s.pool)
                .await
                .unwrap();
        assert!(
            plan.iter().any(|p| p.3.contains("idx_requests_persona")),
            "{plan:?}"
        );
        assert!(
            plan.iter().any(|p| p.3.contains("idx_requests_ip_ts")),
            "{plan:?}"
        );
    }
}
