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
        sqlx::query(
            "INSERT INTO ips (ip, first_seen, last_seen) VALUES (?, datetime('now'), datetime('now'))
             ON CONFLICT(ip) DO UPDATE SET last_seen = datetime('now')",
        ).bind(&s).execute(&self.pool).await?;
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE ip = ?")
            .bind(&s)
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn ip_by_id(&self, id: i64) -> Result<Option<IpRow>> {
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Set an IP's GeoIP facts (keeps its Tor flag).
    pub async fn set_ip_geo(
        &self,
        ip_id: i64,
        country: Option<&str>,
        asn: Option<u32>,
        asn_org: Option<&str>,
    ) -> Result<()> {
        let tor: Option<bool> = sqlx::query_scalar("SELECT is_tor_exit FROM ips WHERE id = ?")
            .bind(ip_id)
            .fetch_optional(&self.pool)
            .await?;
        self.local()
            .enrich_ip(ip_id, country, asn, asn_org, tor.unwrap_or(false))
            .await
    }

    /// `(id, ip, country)` for IPs whose country is not an ISO alpha-2 code.
    pub async fn ips_with_legacy_country(&self) -> Result<Vec<(i64, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, ip, country FROM ips WHERE country IS NOT NULL AND length(country) != 2",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn set_ip_tor(&self, ip_id: i64, is_tor: bool) -> Result<()> {
        let row = self.ip_by_id(ip_id).await?;
        let Some(r) = row else { return Ok(()) };
        self.local()
            .enrich_ip(
                ip_id,
                r.country.as_deref(),
                r.asn.map(|a| a as u32),
                r.asn_org.as_deref(),
                is_tor,
            )
            .await
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
