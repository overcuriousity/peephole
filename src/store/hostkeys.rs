//! Host keys, certificates, JA4X and HASSH of scanned sources
//! (`scan::hostkeys`), kept in `host_keys` and read back per IP, per scan
//! and across IPs.

use super::Store;
use super::inspect::{MAX_RAW_XML, zstd_decode_capped};
use crate::scan::hostkeys::{
    FAVICON, HASSH, HOSTKEYS_V, HTTP_404, HTTP_BODY, HTTP_ETAG, HostKey, JA4X, JARM, SSH_HOSTKEY,
    TLS_CERT, extract,
};
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
    /// Set when a probe found it rather than a scan.
    pub probe_id: Option<i64>,
    /// When that probe finished.
    pub probe_at: Option<String>,
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

pub(crate) fn is_identity(kind: &str) -> bool {
    kind == SSH_HOSTKEY || kind == TLS_CERT
}

pub fn kind_name(kind: &str) -> &'static str {
    match kind {
        SSH_HOSTKEY => "SSH host key",
        TLS_CERT => "TLS certificate",
        JA4X => "JA4X",
        HASSH => "HASSH",
        FAVICON => "Favicon",
        JARM => "JARM",
        HTTP_BODY => "HTTP body",
        HTTP_404 => "HTTP 404 page",
        HTTP_ETAG => "HTTP ETag",
        _ => "other",
    }
}

/// Most PTR names kept of one scan.
const MAX_PTR_NAMES: usize = 16;

/// Read the identifiers out of a stored scan (zstd-compressed nmap XML)
/// and mark the scan as read at `HOSTKEYS_V`. Unreadable XML yields none;
/// only database errors fail.
pub(crate) async fn derive(
    conn: &mut SqliteConnection,
    scan_id: i64,
    ip_id: i64,
    raw_xml: Option<&[u8]>,
) -> Result<()> {
    let (keys, names) = match raw_xml.map(|b| zstd_decode_capped(b, MAX_RAW_XML)) {
        Some(Ok(xml)) => (extract(&xml), crate::scan::hostkeys::ptr_names(&xml)),
        Some(Err(e)) => {
            tracing::debug!(scan_id, "host keys: scan XML unreadable: {e:#}");
            (vec![], vec![])
        }
        None => (vec![], vec![]),
    };
    // The PTR names nmap saw: local and derived like the keys, never
    // replicated on their own.
    if !names.is_empty() {
        let seen: Option<String> = sqlx::query_scalar("SELECT finished_at FROM scans WHERE id = ?")
            .bind(scan_id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
        let seen = seen.unwrap_or_else(super::data::now_ts);
        for name in names.iter().take(MAX_PTR_NAMES) {
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 VALUES (?1, ?2, 'ptr', ?3, ?3, 1)
                 ON CONFLICT(ip_id, name, source) DO UPDATE
                   SET first_seen = min(first_seen, excluded.first_seen),
                       last_seen = max(last_seen, excluded.last_seen)",
            )
            .bind(ip_id)
            .bind(name)
            .bind(&seen)
            .execute(&mut *conn)
            .await?;
        }
    }
    // Read again (a newer HOSTKEYS_V): what an older parse left goes.
    sqlx::query("DELETE FROM host_keys WHERE scan_id = ?")
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
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
    sqlx::query("UPDATE scans SET keys_parsed = ? WHERE id = ?")
        .bind(HOSTKEYS_V)
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Scans read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 50;
/// Pause between [`backfill`]'s transactions, so the trap's and
/// replication's writes get the lock in between.
const BACKFILL_PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// Read the scans whose `keys_parsed` is below `below`: stored before
/// `host_keys` existed, by an older build sharing the database, or by an
/// older parser. Walks the table once by id, a short transaction per batch
/// with a pause after it. Returns how many were read.
pub async fn backfill(pool: &sqlx::SqlitePool, below: i64) -> Result<u64> {
    let mut done = 0;
    let mut after = 0i64;
    loop {
        let rows: Vec<(i64, i64, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT id, ip_id, raw_xml FROM scans WHERE keys_parsed < ? AND id > ?
             ORDER BY id LIMIT ?",
        )
        .bind(below)
        .bind(after)
        .bind(BACKFILL_BATCH)
        .fetch_all(pool)
        .await?;
        let Some((last, _, _)) = rows.last() else {
            return Ok(done);
        };
        after = *last;
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        for (id, ip_id, xml) in &rows {
            derive(&mut tx, *id, *ip_id, xml.as_deref()).await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
}

/// Store what a probe found (the same keys a scan's XML yields).
pub(crate) async fn insert_probe_keys(
    conn: &mut SqliteConnection,
    probe_id: i64,
    ip_id: i64,
    keys: &[HostKey],
) -> Result<()> {
    for k in keys {
        sqlx::query(
            "INSERT OR IGNORE INTO host_keys (probe_id, ip_id, port, kind, fingerprint, detail)
             VALUES (?,?,?,?,?,?)",
        )
        .bind(probe_id)
        .bind(ip_id)
        .bind(k.port as i64)
        .bind(k.kind)
        .bind(&k.fingerprint)
        .bind(&k.detail)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

const ROW_SELECT: &str = "SELECT h.kind, h.port, h.fingerprint, MAX(h.detail) AS detail,
        (SELECT COUNT(DISTINCT o.ip_id) FROM host_keys o
         WHERE o.kind = h.kind AND o.fingerprint = h.fingerprint AND o.ip_id != h.ip_id) AS other_ips,
        MAX(h.probe_id) AS probe_id, MAX(p.finished_at) AS probe_at
     FROM host_keys h LEFT JOIN probes p ON p.id = h.probe_id";

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

        let parsed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans WHERE keys_parsed = 2")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(parsed, 3);
    }

    #[tokio::test]
    async fn ptr_names_are_read_from_a_scan_and_shown() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let xml = String::from_utf8(include_bytes!("../../tests/fixtures/nmap-basic.xml").to_vec())
            .unwrap()
            .replacen(
                r#"<status state="up" reason="syn-ack"/>"#,
                r#"<status state="up" reason="syn-ack"/><hostnames><hostname name="Mail.Example.COM" type="PTR"/><hostname name="user.example.com" type="user"/></hostnames>"#,
                1,
            );
        scan(&s, "192.0.2.7", xml.as_bytes()).await;
        let ip = s.ip_by_addr("192.0.2.7").await.unwrap().unwrap();
        let names = s.names_for_ip(ip.id).await.unwrap();
        assert_eq!(names.len(), 1, "only the PTR name: {names:?}");
        assert_eq!(
            (
                names[0].name.as_str(),
                names[0].source.as_str(),
                names[0].agreed
            ),
            ("mail.example.com", "ptr", true)
        );
        // Read again (the backfill): one row still.
        sqlx::query("UPDATE scans SET keys_parsed = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        backfill(&s.pool, HOSTKEYS_V).await.unwrap();
        assert_eq!(s.names_for_ip(ip.id).await.unwrap().len(), 1);
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
        assert_eq!(backfill(&s.pool, HOSTKEYS_V).await.unwrap(), 1);
        assert_eq!(s.host_keys_for_scan(id).await.unwrap().len(), 5);
        assert_eq!(
            backfill(&s.pool, HOSTKEYS_V).await.unwrap(),
            0,
            "each scan once"
        );
    }

    #[tokio::test]
    async fn opening_reads_only_scans_never_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let s = Store::connect(&path).await.unwrap();
        let xml = include_bytes!("../../tests/fixtures/nmap-hostkeys.xml");
        let (old, never) = (
            scan(&s, "192.0.2.7", xml).await,
            scan(&s, "192.0.2.8", xml).await,
        );
        for (id, v) in [(old, 1), (never, 0)] {
            sqlx::query("UPDATE scans SET keys_parsed = ? WHERE id = ?")
                .bind(v)
                .bind(id)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        s.pool.close().await;
        s.read.close().await;
        // The version reparse is left to the backfill task.
        let s = Store::connect(&path).await.unwrap();
        let v: Vec<i64> = sqlx::query_scalar("SELECT keys_parsed FROM scans ORDER BY id")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        assert_eq!(v, vec![1, HOSTKEYS_V]);
        assert_eq!(backfill(&s.pool, HOSTKEYS_V).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn reparse_replaces_scan_keys_and_keeps_probe_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(
            &s,
            "192.0.2.7",
            include_bytes!("../../tests/fixtures/nmap-http-headers.xml"),
        )
        .await;
        let ip_id: i64 = sqlx::query_scalar("SELECT ip_id FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let probe: i64 = sqlx::query_scalar(
            "INSERT INTO probes (uid, group_uid, ip_id, asker, started_at, finished_at)
             VALUES ('p', 'g', ?, x'01', datetime('now'), datetime('now')) RETURNING id",
        )
        .bind(ip_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO host_keys (probe_id, ip_id, port, kind, fingerprint)
             VALUES (?, ?, 443, 'jarm', 'j')",
        )
        .bind(probe)
        .bind(ip_id)
        .execute(&s.pool)
        .await
        .unwrap();
        // As a build before ETags left it: read, but at version 1.
        sqlx::query("UPDATE scans SET keys_parsed = 1")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool, HOSTKEYS_V).await.unwrap(), 1);
        assert_eq!(
            backfill(&s.pool, HOSTKEYS_V).await.unwrap(),
            0,
            "each scan once"
        );
        let rows = s.host_keys_for_scan(id).await.unwrap();
        assert_eq!(
            rows.iter().filter(|r| r.kind == HTTP_ETAG).count(),
            2,
            "{rows:?}"
        );
        assert_eq!(rows[0].kind_name(), "HTTP ETag");
        assert!(rows.iter().all(|r| !r.identifies()));
        assert!(
            rows[0]
                .link_href()
                .starts_with("/admin/links/http-etag/%22")
        );
        let probe_keys: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM host_keys WHERE probe_id IS NOT NULL")
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert_eq!(probe_keys, 1, "a scan's reparse leaves probe keys alone");
        let v: i64 = sqlx::query_scalar("SELECT keys_parsed FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(v, HOSTKEYS_V);
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
