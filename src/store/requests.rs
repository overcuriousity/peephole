use super::Store;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::net::IpAddr;

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
    /// Read models kept by triggers (migration 0020).
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
    pub severity: i64,
    pub scan_level: i64,
    pub is_fp_claim: bool,
    pub page_token: Option<String>,
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

    /// `(id, ip, country)` for IPs whose country is not an ISO alpha-2 code.
    pub async fn ips_with_legacy_country(&self) -> Result<Vec<(i64, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, ip, country FROM ips WHERE country IS NOT NULL AND length(country) != 2",
        )
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
                severity: 3,
                scan_level: 2,
                is_fp_claim: false,
                page_token: None,
            })
            .await
            .unwrap();
        let row = s.request_by_id(id).await.unwrap().unwrap();
        assert_eq!(row.path, "/wp-login.php");
        assert_eq!(row.severity, 3);
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
