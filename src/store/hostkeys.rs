//! Host keys, certificates, JA4X and HASSH of scanned sources
//! (`scan::hostkeys`), kept in `host_keys` and read back per IP, per scan
//! and across IPs.

use super::Store;
use super::inspect::{MAX_RAW_XML, zstd_decode_capped};
use crate::scan::hostkeys::{HASSH, JA4X, SSH_HOSTKEY, TLS_CERT, extract};
use anyhow::Result;
use sqlx::SqliteConnection;

/// One identifier as the IP and scan pages show it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct HostKeyRow {
    pub kind: String,
    pub port: i64,
    pub fingerprint: String,
    pub detail: String,
    /// Distinct other source IPs with the same identifier.
    pub other_ips: i64,
}

impl HostKeyRow {
    /// Shared host keys and certificates tie sources together; shared JA4X
    /// and HASSH only say they run the same software.
    pub fn identifies(&self) -> bool {
        is_identity(&self.kind)
    }

    pub fn kind_name(&self) -> &'static str {
        kind_name(&self.kind)
    }

    /// Its page under Links.
    pub fn link_href(&self) -> String {
        let kind =
            crate::store::links::LinkKind::of_host_kind(&self.kind).map_or("ssh", |k| k.key());
        crate::admin::views::link_href(kind, &self.fingerprint)
    }
}

fn is_identity(kind: &str) -> bool {
    kind == SSH_HOSTKEY || kind == TLS_CERT
}

pub fn kind_name(kind: &str) -> &'static str {
    match kind {
        SSH_HOSTKEY => "SSH host key",
        TLS_CERT => "TLS certificate",
        JA4X => "JA4X",
        HASSH => "HASSH",
        _ => "other",
    }
}

/// Read the identifiers out of a stored scan (zstd-compressed nmap XML)
/// and mark the scan as read. Unreadable XML yields none; only database
/// errors fail.
pub(crate) async fn derive(
    conn: &mut SqliteConnection,
    scan_id: i64,
    ip_id: i64,
    raw_xml: Option<&[u8]>,
) -> Result<()> {
    let keys = match raw_xml.map(|b| zstd_decode_capped(b, MAX_RAW_XML)) {
        Some(Ok(xml)) => extract(&xml),
        Some(Err(e)) => {
            tracing::debug!(scan_id, "host keys: scan XML unreadable: {e:#}");
            vec![]
        }
        None => vec![],
    };
    for k in keys {
        sqlx::query(
            "INSERT OR IGNORE INTO host_keys (scan_id, ip_id, port, kind, fingerprint, detail)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(scan_id)
        .bind(ip_id)
        .bind(k.port as i64)
        .bind(k.kind)
        .bind(&k.fingerprint)
        .bind(&k.detail)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("UPDATE scans SET keys_parsed = 1 WHERE id = ?")
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Read the scans stored before `host_keys` existed, or by an older build
/// sharing the database. A batch at a time; returns how many were read.
pub(crate) async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    let mut done = 0;
    loop {
        let rows: Vec<(i64, i64, Option<Vec<u8>>)> =
            sqlx::query_as("SELECT id, ip_id, raw_xml FROM scans WHERE keys_parsed = 0 LIMIT 50")
                .fetch_all(pool)
                .await?;
        if rows.is_empty() {
            return Ok(done);
        }
        let mut tx = pool.begin().await?;
        for (id, ip_id, xml) in &rows {
            derive(&mut tx, *id, *ip_id, xml.as_deref()).await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
    }
}

const ROW_SELECT: &str = "SELECT h.kind, h.port, h.fingerprint, MAX(h.detail) AS detail,
        (SELECT COUNT(DISTINCT o.ip_id) FROM host_keys o
         WHERE o.kind = h.kind AND o.fingerprint = h.fingerprint AND o.ip_id != h.ip_id) AS other_ips
     FROM host_keys h";

impl Store {
    /// Every identifier any scan found on this IP, once each.
    pub async fn host_keys_for_ip(&self, ip_id: i64) -> Result<Vec<HostKeyRow>> {
        Ok(sqlx::query_as::<_, HostKeyRow>(sqlx::AssertSqlSafe(format!(
            "{ROW_SELECT} WHERE h.ip_id = ? GROUP BY h.kind, h.port, h.fingerprint
             ORDER BY h.port, h.kind"
        )))
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?)
    }

    pub async fn host_keys_for_scan(&self, scan_id: i64) -> Result<Vec<HostKeyRow>> {
        Ok(sqlx::query_as::<_, HostKeyRow>(sqlx::AssertSqlSafe(format!(
            "{ROW_SELECT} WHERE h.scan_id = ? GROUP BY h.kind, h.port, h.fingerprint
             ORDER BY h.port, h.kind"
        )))
        .bind(scan_id)
        .fetch_all(&self.read)
        .await?)
    }
}

/// A short id for a host key or certificate, usable as a page anchor:
/// `ssh-` or `tls-` and 12 characters of the fingerprint.
pub fn anchor(kind: &str, fingerprint: &str) -> String {
    let prefix = if kind == SSH_HOSTKEY { "ssh" } else { "tls" };
    let body: String = fingerprint
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect();
    format!("{prefix}-{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::parse_nmap_xml;

    /// A scan stored for `ip` (as the scanner stores it), and its id.
    async fn scan(s: &Store, ip: &str, xml: &[u8]) -> i64 {
        let ip = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 2, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = parse_nmap_xml(xml).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();
        sqlx::query_scalar("SELECT MAX(id) FROM scans")
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn stored_scans_yield_host_keys_shared_across_ips() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let xml = include_bytes!("../../tests/fixtures/nmap-hostkeys.xml");
        let a = scan(&s, "192.0.2.7", xml).await;
        scan(&s, "192.0.2.8", xml).await;
        let plain = scan(
            &s,
            "192.0.2.9",
            include_bytes!("../../tests/fixtures/nmap-basic.xml"),
        )
        .await;

        let rows = s.host_keys_for_scan(a).await.unwrap();
        assert_eq!(rows.len(), 5, "{rows:?}");
        assert!(rows.iter().all(|r| r.other_ips == 1), "{rows:?}");
        assert!(s.host_keys_for_scan(plain).await.unwrap().is_empty());

        // Two SSH host keys and one certificate, each on both IPs.
        for (kind, n) in [("ssh", 2), ("tls", 1)] {
            let shared = s
                .links_list(&crate::store::links::LinkFilter {
                    kind: Some(kind.into()),
                    ..Default::default()
                })
                .await
                .unwrap();
            assert_eq!(shared.items.len(), n, "{kind}");
            assert!(shared.items.iter().all(|c| c.ips == 2));
        }

        let a = s.analytics(crate::store::stats::Range::All).await.unwrap();
        assert_eq!((a.hassh.len(), a.ja4x.len()), (1, 1));
        assert_eq!((a.hassh[0].ips, a.ja4x[0].ips), (2, 2));

        let parsed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans WHERE keys_parsed = 1")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(parsed, 3);
    }

    #[tokio::test]
    async fn backfill_reads_scans_stored_before() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(
            &s,
            "192.0.2.7",
            include_bytes!("../../tests/fixtures/nmap-hostkeys.xml"),
        )
        .await;
        // As an older build would have left it.
        sqlx::query("DELETE FROM host_keys")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scans SET keys_parsed = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(s.host_keys_for_scan(id).await.unwrap().len(), 5);
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "each scan once");
    }

    #[tokio::test]
    async fn deleting_a_scan_deletes_its_host_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(
            &s,
            "192.0.2.7",
            include_bytes!("../../tests/fixtures/nmap-hostkeys.xml"),
        )
        .await;
        sqlx::query("DELETE FROM ports")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(id)
            .execute(&s.pool)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_keys")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn anchors_are_short_and_safe() {
        assert_eq!(
            anchor(SSH_HOSTKEY, "SHA256:ab+/cdEF0123456789"),
            "ssh-abcdEF012345"
        );
        assert_eq!(anchor(TLS_CERT, "0123456789abcdef"), "tls-0123456789ab");
    }
}
