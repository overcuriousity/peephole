//! Aggregates for the admin analytics page: what the trap's requests asked
//! for and what the counter-scans found, per time range. Admin-only — the
//! paths, user agents and JA4/JA4H fingerprints describe request contents.
use super::Store;
use super::stats::{Named, PortStat, Range, RecentRequest, RecentTuple, recent_from};
use anyhow::Result;

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
            .named_ips(host_key(crate::scan::hostkeys::HASSH), since)
            .await?;
        let ja4x = self
            .named_ips(host_key(crate::scan::hostkeys::JA4X), since)
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
        })
    }

    /// The newest `limit` requests recorded after the row `after` (local
    /// row ids), oldest first: a live view that falls behind skips ahead.
    /// Replicated rows get new local ids, so a cursor on the id sees them.
    pub async fn requests_after(&self, after: i64, limit: i64) -> Result<Vec<RecentRequest>> {
        let rows: Vec<RecentTuple> = sqlx::query_as(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, r.owasp_json,
                    i.country, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id
             WHERE r.id > ? ORDER BY r.id DESC LIMIT ?",
        )
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
                    i.country, i.is_tor_exit
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
                    i.country, i.is_tor_exit
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
}
