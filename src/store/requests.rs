use super::Store;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::net::IpAddr;

#[derive(Default)]
pub struct NewRequest {
    pub ip_id: i64,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers_json: String,
    pub body: Option<Vec<u8>>,
    pub labels_json: String,
    pub severity: i64,
    pub scan_level: i64,
    pub is_fp_claim: bool,
    pub page_token: Option<String>,
    /// Dataset fields; see `cluster::record::RequestRec`.
    pub answer: Option<String>,
    pub status: Option<i64>,
    pub unrecorded: Option<i64>,
    pub transport: Option<String>,
    pub via_proxy: Option<bool>,
    pub raw_head: Option<Vec<u8>>,
    pub tls_client_hello: Option<Vec<u8>>,
    pub ja4: Option<String>,
    /// JSON array of OWASP tags from the verdict; None stores `'[]'`.
    pub owasp_json: Option<String>,
    /// Fingerprint of the ruleset that classified it (None for claims).
    pub rules: Option<String>,
    /// The row's time (`YYYY-MM-DD HH:MM:SS`); None: now. The trap passes
    /// the time it rendered a decoy with.
    pub ts: Option<String>,
    pub decoy_v: Option<i64>,
    /// The site word a version-1 decoy was served under.
    pub decoy_site: Option<String>,
    /// How long a `tarpit` answer held the client, in milliseconds.
    pub held_ms: Option<i64>,
}

#[derive(sqlx::FromRow)]
pub struct IpRow {
    pub id: i64,
    pub ip: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub is_tor_exit: bool,
    pub fp_claimed: bool,
    pub notes: Option<String>,
    /// Read models kept by triggers (migration 0019).
    pub request_count: i64,
    pub max_severity: i64,
}

#[derive(sqlx::FromRow)]
pub struct RequestRow {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub ip_id: i64,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers_json: String,
    pub body: Option<Vec<u8>>,
    pub labels_json: String,
    pub owasp_json: String,
    pub severity: i64,
    pub scan_level: i64,
    pub is_fp_claim: bool,
    pub page_token: Option<String>,
    pub answer: Option<String>,
    pub status: Option<i64>,
    pub unrecorded: Option<i64>,
    pub transport: Option<String>,
    pub via_proxy: Option<bool>,
    pub ja4: Option<String>,
    /// Derived from `raw_head` on this node (`store::ja4h`).
    pub ja4h: Option<String>,
    pub rules: Option<String>,
    pub decoy_v: Option<i64>,
    pub decoy_site: Option<String>,
    /// How long a `tarpit` answer held the client, in milliseconds.
    pub held_ms: Option<i64>,
}

/// Distinct refresh intervals; later lookups reuse the last one (over
/// 1.5^29 × N days, far beyond any dataset's life).
const REFRESH_STEPS: i32 = 30;

/// What [`Store::intel_candidates`] selects.
pub struct IntelCandidates<'a> {
    pub provider: &'a str,
    pub step_secs: i64,
    pub refresh_after_days: f64,
    pub ipv6: bool,
    pub skip: &'a [String],
    pub covered_by: Option<&'a str>,
    pub limit: i64,
}

impl Store {
    pub async fn upsert_ip(&self, ip: IpAddr) -> Result<IpRow> {
        let s = ip.to_string();
        // One transaction: a result applied between the insert and the
        // refresh would otherwise be overwritten by a stale view.
        let mut conn = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let created = sqlx::query(
            "INSERT OR IGNORE INTO ips (ip, ip_key, first_seen, last_seen)
             VALUES (?, ?, datetime('now'), datetime('now'))",
        )
        .bind(&s)
        .bind(super::ip_key(ip))
        .execute(&mut *conn)
        .await?
        .rows_affected()
            == 1;
        if created {
            // Results may have arrived before the IP did.
            super::data::refresh_ip_view(&mut conn, &s).await?;
        } else {
            sqlx::query("UPDATE ips SET last_seen = datetime('now') WHERE ip = ?")
                .bind(&s)
                .execute(&mut *conn)
                .await?;
        }
        let row = sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE ip = ?")
            .bind(&s)
            .fetch_one(&mut *conn)
            .await?;
        conn.commit().await?;
        Ok(row)
    }

    pub async fn ip_by_id(&self, id: i64) -> Result<Option<IpRow>> {
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Set an IP's GeoIP facts (this node's MaxMind result; Tor is untouched).
    pub async fn set_ip_geo(
        &self,
        ip_id: i64,
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
    ) -> Result<()> {
        self.local()
            .record_geo(ip_id, None, country, asn, asn_org)
            .await
    }

    /// IPs first seen at least `older_than_secs` ago that have no result
    /// from `provider`, oldest first.
    pub async fn ips_missing_intel(
        &self,
        provider: &str,
        older_than_secs: i64,
        limit: i64,
    ) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT i.ip FROM ips i
             WHERE i.first_seen <= datetime('now', ?)
               AND NOT EXISTS (SELECT 1 FROM ip_intel t WHERE t.ip = i.ip AND t.provider = ?)
             ORDER BY i.id LIMIT ?",
        )
        .bind(format!("-{older_than_secs} seconds"))
        .bind(provider)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// IPs an API provider should look up now, newest `last_seen` first: no
    /// result from it yet (first seen at least `step_secs` ago), or — with
    /// `refresh_after_days > 0` — `k` results, the newest at `t`, and seen
    /// again since `t + N × 1.5^(k−1)` days, at least `step_secs` ago. IPs
    /// in `skip`, IPv6 addresses unless `ipv6`, and IPs with a result from
    /// `covered_by` are left out.
    pub async fn intel_candidates(&self, q: &IntelCandidates<'_>) -> Result<Vec<String>> {
        // Interval in seconds after the k-th lookup, k = 1..; the last one
        // repeats (SQLite may lack pow()).
        let intervals: Vec<i64> = (0..REFRESH_STEPS)
            .map(|k| (q.refresh_after_days * 86400.0 * 1.5f64.powi(k)).min(1e12) as i64)
            .collect();
        Ok(sqlx::query_scalar(
            "WITH s AS (
               SELECT ip, COUNT(*) AS k, MAX(fetched_at) AS last_at
               FROM ip_intel_log WHERE provider = ?1 GROUP BY ip)
             SELECT i.ip FROM ips i LEFT JOIN s ON s.ip = i.ip
             WHERE (
                 (s.ip IS NULL AND i.first_seen <= datetime('now', ?2))
                 OR (?3 > 0 AND s.ip IS NOT NULL
                     AND i.last_seen >= datetime(s.last_at, '+' ||
                         json_extract(?4, '$[' || (min(s.k, ?5) - 1) || ']') || ' seconds')
                     AND datetime(s.last_at, '+' ||
                         json_extract(?4, '$[' || (min(s.k, ?5) - 1) || ']') || ' seconds')
                         <= datetime('now', ?2)))
               AND (?6 OR instr(i.ip, ':') = 0)
               AND i.ip NOT IN (SELECT value FROM json_each(?7))
               AND (?8 IS NULL OR NOT EXISTS (
                     SELECT 1 FROM ip_intel c WHERE c.ip = i.ip AND c.provider = ?8))
             ORDER BY i.last_seen DESC, i.id DESC LIMIT ?9",
        )
        .bind(q.provider)
        .bind(format!("-{} seconds", q.step_secs))
        .bind(q.refresh_after_days)
        .bind(serde_json::to_string(&intervals)?)
        .bind(REFRESH_STEPS)
        .bind(q.ipv6)
        .bind(serde_json::to_string(q.skip)?)
        .bind(q.covered_by)
        .bind(q.limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Set an IP's Tor flag (this node's Tor result; GeoIP is untouched).
    pub async fn set_ip_tor(&self, ip_id: i64, is_tor: bool) -> Result<()> {
        self.local().record_tor(ip_id, is_tor).await
    }

    pub async fn insert_request(&self, n: &NewRequest) -> Result<i64> {
        self.local().insert_request(n).await
    }

    pub async fn request_by_id(&self, id: i64) -> Result<Option<RequestRow>> {
        Ok(
            sqlx::query_as::<_, RequestRow>("SELECT * FROM requests WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    pub async fn insert_fp_claim(
        &self,
        ip_id: i64,
        request_id: i64,
        email: Option<&str>,
        ua: &str,
    ) -> Result<()> {
        self.local()
            .insert_fp_claim(ip_id, request_id, email, ua)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::net::IpAddr;

    async fn test_store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir); // keep the directory alive for the test's duration
        Store::connect(&path).await.unwrap()
    }

    fn candidates<'a>(provider: &'a str, skip: &'a [String]) -> IntelCandidates<'a> {
        IntelCandidates {
            provider,
            step_secs: 0,
            refresh_after_days: 30.0,
            ipv6: true,
            skip,
            covered_by: None,
            limit: 100,
        }
    }

    async fn set_times(s: &Store, ip: &str, first: &str, last: &str) {
        sqlx::query("UPDATE ips SET first_seen = datetime('now', ?), last_seen = datetime('now', ?) WHERE ip = ?")
            .bind(first)
            .bind(last)
            .bind(ip)
            .execute(&s.pool)
            .await
            .unwrap();
    }

    /// Move every recorded lookup of `ip` back by `days`.
    async fn age_lookups(s: &Store, ip: &str, days: i64) {
        sqlx::query("UPDATE ip_intel_log SET fetched_at = datetime(fetched_at, ?) WHERE ip = ?")
            .bind(format!("-{days} days"))
            .bind(ip)
            .execute(&s.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn api_candidates_are_new_ips_newest_first_then_returning_ones() {
        let s = test_store().await;
        let p = crate::intel::ABUSEIPDB;
        for (ip, last) in [("198.51.100.1", "-3 hours"), ("198.51.100.2", "-1 hours")] {
            s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            set_times(&s, ip, "-5 hours", last).await;
        }
        s.upsert_ip("2001:db8::1".parse().unwrap()).await.unwrap();
        set_times(&s, "2001:db8::1", "-5 hours", "-2 hours").await;
        let got = s.intel_candidates(&candidates(p, &[])).await.unwrap();
        assert_eq!(got, ["198.51.100.2", "2001:db8::1", "198.51.100.1"]);
        let v4 = IntelCandidates {
            ipv6: false,
            ..candidates(p, &[])
        };
        assert_eq!(
            s.intel_candidates(&v4).await.unwrap(),
            ["198.51.100.2", "198.51.100.1"]
        );
        let skip = vec!["198.51.100.2".to_string()];
        let got = s.intel_candidates(&candidates(p, &skip)).await.unwrap();
        assert!(!got.contains(&"198.51.100.2".to_string()));
        // A later rank waits: none of them is ten hours old.
        let late = IntelCandidates {
            step_secs: 10 * 3600,
            ..candidates(p, &[])
        };
        assert!(s.intel_candidates(&late).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_looked_up_ip_is_due_again_only_when_it_returns_after_n_then_1_5_n_days() {
        let s = test_store().await;
        let p = crate::intel::ABUSEIPDB;
        let ip = "198.51.100.7";
        s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        set_times(&s, ip, "-100 days", "-1 hours").await;
        let rec = s.local();
        let due = |s: &Store| {
            let s = s.clone();
            async move { s.intel_candidates(&candidates(p, &[])).await.unwrap() }
        };
        assert_eq!(due(&s).await, [ip], "never looked up");
        rec.record_lookup(ip, p, None, serde_json::json!({"score": 10}))
            .await
            .unwrap();
        assert!(due(&s).await.is_empty(), "just looked up");
        // 31 days later, but it has not come back since.
        age_lookups(&s, ip, 31).await;
        set_times(&s, ip, "-100 days", "-32 days").await;
        assert!(due(&s).await.is_empty(), "did not return");
        // It returns: due again.
        set_times(&s, ip, "-100 days", "-1 hours").await;
        assert_eq!(due(&s).await, [ip]);
        // Second lookup, an identical answer: still recorded.
        rec.record_lookup(ip, p, None, serde_json::json!({"score": 10}))
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_intel_log WHERE ip = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "every lookup is in the history");
        // Now the interval is 45 days: 40 is too early, 46 is not.
        age_lookups(&s, ip, 40).await;
        assert!(due(&s).await.is_empty(), "45 days after the second lookup");
        age_lookups(&s, ip, 6).await;
        assert_eq!(due(&s).await, [ip]);
        // Refresh off: never again.
        let off = IntelCandidates {
            refresh_after_days: 0.0,
            ..candidates(p, &[])
        };
        assert!(s.intel_candidates(&off).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn internetdb_leaves_ips_with_a_shodan_result_alone() {
        let s = test_store().await;
        let ip = "198.51.100.9";
        s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let q = IntelCandidates {
            covered_by: Some(crate::intel::SHODAN),
            ..candidates(crate::intel::INTERNETDB, &[])
        };
        assert_eq!(s.intel_candidates(&q).await.unwrap(), [ip]);
        s.local()
            .record_lookup(ip, crate::intel::SHODAN, None, serde_json::json!({}))
            .await
            .unwrap();
        assert!(s.intel_candidates(&q).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn abuse_score_and_tags_follow_the_newest_result_and_go_with_the_ip() {
        let s = test_store().await;
        let ip = "198.51.100.10";
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let rec = s.local();
        rec.record_lookup(
            ip,
            crate::intel::ABUSEIPDB,
            None,
            serde_json::json!({"score": 40, "categories": ["SSH"]}),
        )
        .await
        .unwrap();
        rec.record_lookup(
            ip,
            crate::intel::GREYNOISE,
            None,
            serde_json::json!({"noise": true, "riot": false, "classification": "malicious"}),
        )
        .await
        .unwrap();
        rec.record_lookup(
            ip,
            crate::intel::ABUSEIPDB,
            None,
            serde_json::json!({"score": 90}),
        )
        .await
        .unwrap();
        let score: Option<i64> = sqlx::query_scalar("SELECT abuse_score FROM ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(score, Some(90));
        let tags = s.intel_tags().await.unwrap();
        assert!(
            tags.contains(&"greynoise:malicious".to_string()),
            "{tags:?}"
        );
        assert!(tags.contains(&"greynoise:noise".to_string()));
        assert!(
            !tags.contains(&"abuseipdb:SSH".to_string()),
            "older result's tag is gone"
        );
        let f = crate::store::browse::IpFilter {
            tag: Some("greynoise:malicious".into()),
            min_abuse: Some(50),
            intel: Some(crate::intel::GREYNOISE.into()),
            ..Default::default()
        };
        assert_eq!(s.list_ips(&f).await.unwrap().items.len(), 1);
        let f = crate::store::browse::IpFilter {
            nointel: Some(crate::intel::SHODAN.into()),
            sort: Some("abuse".into()),
            ..Default::default()
        };
        assert_eq!(s.list_ips(&f).await.unwrap().items[0].abuse_score, Some(90));
        assert!(s.delete_ip(row.id).await.unwrap());
        for table in ["ip_intel", "ip_intel_log", "ip_intel_tags"] {
            let n: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                    .fetch_one(&s.pool)
                    .await
                    .unwrap();
            assert_eq!(n, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn upsert_ip_is_idempotent_and_updates_last_seen() {
        let s = test_store().await;
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let a = s.upsert_ip(ip).await.unwrap();
        let b = s.upsert_ip(ip).await.unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.ip, "203.0.113.7");
        assert!(!a.is_tor_exit);
    }

    #[tokio::test]
    async fn a_result_stored_before_the_ip_shows_once_the_trap_sees_it() {
        let s = test_store().await;
        s.local()
            .record_intel(
                "203.0.113.8",
                crate::intel::MAXMIND,
                None,
                serde_json::json!({"country": "NL"}),
            )
            .await
            .unwrap();
        let ip = s.upsert_ip("203.0.113.8".parse().unwrap()).await.unwrap();
        assert_eq!(ip.country.as_deref(), Some("NL"));
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/".into(),
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
        let row = s.ip_by_id(ip.id).await.unwrap().unwrap();
        assert_eq!(row.country.as_deref(), Some("NL"));
    }

    #[tokio::test]
    async fn a_migrated_result_that_says_the_same_is_not_written_again() {
        let s = test_store().await;
        let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
        // As migration 0017 leaves it: explicit nulls, hlc 0.
        sqlx::query(
            "INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
             VALUES ('203.0.113.9', 'maxmind-geolite2', x'', 0, '2026-01-01 00:00:00', NULL,
                     '{\"country\":\"DE\",\"asn\":null,\"asn_org\":null}')",
        )
        .execute(&s.pool)
        .await
        .unwrap();
        s.set_ip_geo(ip.id, Some("DE"), None, None).await.unwrap();
        let hlc: i64 = sqlx::query_scalar("SELECT hlc FROM ip_intel")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(hlc, 0, "same facts: nothing written");
        s.set_ip_geo(ip.id, Some("NL"), None, None).await.unwrap();
        let row = s.ip_by_id(ip.id).await.unwrap().unwrap();
        assert_eq!(row.country.as_deref(), Some("NL"));
    }

    #[tokio::test]
    async fn insert_request_roundtrip() {
        let s = test_store().await;
        let ip = s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap();
        let id = s
            .insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/wp-login.php".into(),
                query: None,
                headers_json: r#"[["user-agent","sqlmap/1.7"]]"#.into(),
                body: None,
                labels_json: r#"["scanner-ua","sensitive-path"]"#.into(),
                owasp_json: Some(r#"["A03:2021"]"#.into()),
                severity: 3,
                scan_level: 2,
                is_fp_claim: false,
                page_token: None,
                ..Default::default()
            })
            .await
            .unwrap();
        let row = s.request_by_id(id).await.unwrap().unwrap();
        assert_eq!(row.path, "/wp-login.php");
        assert_eq!(row.severity, 3);
        assert_eq!(row.owasp_json, r#"["A03:2021"]"#);
    }

    #[tokio::test]
    async fn owasp_json_defaults_to_an_empty_array() {
        let s = test_store().await;
        let ip = s.upsert_ip("198.51.100.11".parse().unwrap()).await.unwrap();
        let id = s
            .insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let row = s.request_by_id(id).await.unwrap().unwrap();
        assert_eq!(row.owasp_json, "[]");
    }

    #[tokio::test]
    async fn fp_claim_marks_ip() {
        let s = test_store().await;
        let ip = s.upsert_ip("192.0.2.5".parse().unwrap()).await.unwrap();
        let rid = s
            .insert_request(&NewRequest {
                ip_id: ip.id,
                method: "POST".into(),
                path: "/i-landed-here-by-accident".into(),
                query: None,
                headers_json: "[]".into(),
                body: None,
                labels_json: "[]".into(),
                severity: 0,
                scan_level: 0,
                is_fp_claim: true,
                page_token: None,
                ..Default::default()
            })
            .await
            .unwrap();
        s.insert_fp_claim(ip.id, rid, Some("human@example.org"), "Mozilla/5.0")
            .await
            .unwrap();
        let row = s.ip_by_id(ip.id).await.unwrap().unwrap();
        assert!(row.fp_claimed);
    }
}
