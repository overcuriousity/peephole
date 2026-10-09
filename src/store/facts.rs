//! What a scan says a source serves and calls itself (`scan::facts`), kept
//! in `ports` (the service details) and `scan_facts`, derived from the
//! stored XML on every node like host keys, and read back per scan.
use super::Store;
use super::inspect::{MAX_RAW_XML, PortRow, zstd_decode_capped};
use crate::scan::facts::{FACTS_V, Facts, extract, kind_label};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::HashMap;

/// One fact as the pages show it. `port` None: about the host.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FactRow {
    pub port: Option<i64>,
    pub kind: String,
    pub value: String,
}

impl FactRow {
    pub fn label(&self) -> &'static str {
        kind_label(&self.kind)
    }
}

/// Read the facts out of a stored scan (zstd-compressed nmap XML) into
/// `ports` and `scan_facts`, and mark the scan as read at `FACTS_V`.
/// Unreadable XML yields none; only database errors fail.
pub(crate) async fn derive(
    conn: &mut SqliteConnection,
    scan_id: i64,
    raw_xml: Option<&[u8]>,
) -> Result<()> {
    let f = match raw_xml.map(|b| zstd_decode_capped(b, MAX_RAW_XML)) {
        Some(Ok(xml)) => extract(&xml),
        Some(Err(e)) => {
            tracing::debug!(scan_id, "scan facts: scan XML unreadable: {e:#}");
            Facts::default()
        }
        None => Facts::default(),
    };
    for p in &f.ports {
        let cpe = (!p.cpe.is_empty()).then(|| serde_json::to_string(&p.cpe).unwrap_or_default());
        sqlx::query(
            "UPDATE ports SET extrainfo = ?, ostype = ?, devicetype = ?, hostname = ?, cpe = ?
             WHERE scan_id = ? AND port = ? AND proto = ?",
        )
        .bind(&p.extrainfo)
        .bind(&p.ostype)
        .bind(&p.devicetype)
        .bind(&p.hostname)
        .bind(cpe)
        .bind(scan_id)
        .bind(p.port as i64)
        .bind(&p.proto)
        .execute(&mut *conn)
        .await?;
    }
    // Read again (a newer FACTS_V): what an older parse left goes.
    sqlx::query("DELETE FROM scan_facts WHERE scan_id = ?")
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
    for x in &f.facts {
        sqlx::query(
            "INSERT INTO scan_facts (scan_id, port, proto, kind, value) VALUES (?,?,?,?,?)",
        )
        .bind(scan_id)
        .bind(x.port.as_ref().map(|p| p.0 as i64))
        .bind(x.port.as_ref().map(|p| p.1.as_str()))
        .bind(x.kind)
        .bind(&x.value)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("UPDATE scans SET facts_parsed = ? WHERE id = ?")
        .bind(FACTS_V)
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

/// Read the scans whose `facts_parsed` is below `below`: stored before
/// `scan_facts` existed, by an older build sharing the database, or by an
/// older parser. Walks the table once by id, a short transaction per
/// batch with a pause after it. Returns how many were read.
pub async fn backfill(pool: &sqlx::SqlitePool, below: i64) -> Result<u64> {
    let mut done = 0;
    let mut after = 0i64;
    loop {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(i64, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT id, raw_xml FROM scans WHERE facts_parsed < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(below)
        .bind(after)
        .bind(BACKFILL_BATCH)
        .fetch_all(&mut *tx)
        .await?;
        let Some((last, _)) = rows.last() else {
            return Ok(done);
        };
        after = *last;
        for (id, xml) in &rows {
            derive(&mut tx, *id, xml.as_deref()).await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
}

/// Give each port its facts (`facts` are one scan's, host facts included
/// and left alone).
pub(crate) fn attach(ports: &mut [PortRow], facts: &[FactRow]) {
    for p in ports {
        p.facts = facts
            .iter()
            .filter(|f| f.port == Some(p.port))
            .cloned()
            .collect();
    }
}

impl Store {
    /// Every fact of each scan, host facts first, by scan id.
    pub(crate) async fn facts_for_scans(
        &self,
        scan_ids: &[i64],
    ) -> Result<HashMap<i64, Vec<FactRow>>> {
        let mut out: HashMap<i64, Vec<FactRow>> = HashMap::new();
        for chunk in scan_ids.chunks(400) {
            let sql = format!(
                "SELECT scan_id, port, kind, value FROM scan_facts WHERE scan_id IN ({})
                 ORDER BY scan_id, port IS NOT NULL, port, id",
                vec!["?"; chunk.len()].join(",")
            );
            let mut q =
                sqlx::query_as::<_, (i64, Option<i64>, String, String)>(sqlx::AssertSqlSafe(sql));
            for id in chunk {
                q = q.bind(id);
            }
            for (scan_id, port, kind, value) in q.fetch_all(&self.read).await? {
                out.entry(scan_id)
                    .or_default()
                    .push(FactRow { port, kind, value });
            }
        }
        Ok(out)
    }

    /// The facts about the host itself (`smb-os-discovery`) of one scan.
    pub async fn host_facts_for_scan(&self, scan_id: i64) -> Result<Vec<FactRow>> {
        Ok(self
            .host_facts_for_scans(&[scan_id])
            .await?
            .remove(&scan_id)
            .unwrap_or_default())
    }

    pub async fn host_facts_for_scans(
        &self,
        scan_ids: &[i64],
    ) -> Result<HashMap<i64, Vec<FactRow>>> {
        let mut all = self.facts_for_scans(scan_ids).await?;
        for v in all.values_mut() {
            v.retain(|f| f.port.is_none());
        }
        Ok(all)
    }
}

/// Most entries in [`serves`].
const SERVES_MAX: usize = 3;

/// What the source serves, for a scan's heading on the IP page: distinct
/// titles and servers, at most three, each with its port
/// (`8443 PentAGI · 9000 MinIO · 80 nginx/1.18.0`).
pub fn serves(ports: &[PortRow]) -> String {
    let mut seen: Vec<&str> = vec![];
    let mut out: Vec<String> = vec![];
    for p in ports {
        for f in &p.facts {
            if (f.kind == crate::scan::facts::HTTP_TITLE
                || f.kind == crate::scan::facts::HTTP_SERVER)
                && !seen.contains(&f.value.as_str())
            {
                seen.push(&f.value);
                out.push(format!("{} {}", p.port, f.value));
                if out.len() == SERVES_MAX {
                    return out.join(" · ");
                }
            }
        }
    }
    out.join(" · ")
}

/// The Windows computer name and domain, when known: from the SMB host
/// script first, else from RDP's NTLM reply.
pub fn windows_names(host: &[FactRow], ports: &[PortRow]) -> String {
    use crate::scan::facts::{NTLM_NETBIOS_COMPUTER, NTLM_NETBIOS_DOMAIN, SMB_DOMAIN, SMB_SERVER};
    let first = |kind: &str| -> Option<&str> {
        host.iter()
            .chain(ports.iter().flat_map(|p| p.facts.iter()))
            .find(|f| f.kind == kind)
            .map(|f| f.value.as_str())
    };
    let computer = first(SMB_SERVER).or_else(|| first(NTLM_NETBIOS_COMPUTER));
    let domain = first(SMB_DOMAIN).or_else(|| first(NTLM_NETBIOS_DOMAIN));
    [computer, domain]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::parse_nmap_xml;
    use crate::store::Store;

    const FACTS: &[u8] = include_bytes!("../../tests/fixtures/nmap-facts.xml");
    const BASIC: &[u8] = include_bytes!("../../tests/fixtures/nmap-basic.xml");

    /// A scan stored for `ip` (as the scanner stores it), and its id.
    async fn scan(s: &Store, ip: &str, xml: &[u8]) -> i64 {
        let ip = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 3, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = parse_nmap_xml(xml).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();
        sqlx::query_scalar("SELECT MAX(id) FROM scans")
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_stored_scan_yields_its_port_details_and_facts() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        let ports = s.ports_for_scan(id).await.unwrap();
        let ssh = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));
        assert_eq!(
            ssh.cpes(),
            vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
        );
        assert_eq!(ssh.system(), "Linux · general purpose · host-7.example.net");
        assert_eq!(ssh.described(), "OpenSSH 9.6p1 Ubuntu Linux; protocol 2.0");
        assert!(ssh.facts.is_empty());
        let http = ports.iter().find(|p| p.port == 80).unwrap();
        assert!(http.cpes().is_empty() && http.extrainfo.is_none());
        let kinds: Vec<&str> = http.facts.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["http.title", "http.redirect", "http.server", "http.auth"]
        );
        assert_eq!(http.facts[0].label(), "Title");
        let host = s.host_facts_for_scan(id).await.unwrap();
        assert_eq!(host.len(), 8, "{host:?}");
        assert!(host.iter().all(|f| f.port.is_none()));
        let v: i64 = sqlx::query_scalar("SELECT facts_parsed FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(v, FACTS_V);
        // A plain scan: read, nothing found.
        let plain = scan(&s, "192.0.2.8", BASIC).await;
        assert!(s.host_facts_for_scan(plain).await.unwrap().is_empty());
        assert!(
            s.ports_for_scan(plain)
                .await
                .unwrap()
                .iter()
                .all(|p| p.facts.is_empty())
        );
    }

    #[tokio::test]
    async fn backfill_reads_scans_stored_before() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        // As an older build would have left it.
        sqlx::query("DELETE FROM scan_facts")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE ports SET extrainfo = NULL, cpe = NULL")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scans SET facts_parsed = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool, FACTS_V).await.unwrap(), 1);
        assert_eq!(s.host_facts_for_scan(id).await.unwrap().len(), 8);
        assert!(s.ports_for_scan(id).await.unwrap()[0].extrainfo.is_some());
        assert_eq!(
            backfill(&s.pool, FACTS_V).await.unwrap(),
            0,
            "each scan once"
        );
    }

    #[tokio::test]
    async fn two_nodes_derive_the_same_rows() {
        let dir = tempfile::tempdir().unwrap();
        let a = Store::connect(&dir.path().join("a.db")).await.unwrap();
        let b = Store::connect(&dir.path().join("b.db")).await.unwrap();
        let (ia, ib) = (
            scan(&a, "192.0.2.7", FACTS).await,
            scan(&b, "192.0.2.7", FACTS).await,
        );
        let rows = |s: &Store, id: i64| {
            let s = s.clone();
            async move {
                sqlx::query_as::<_, (Option<i64>, Option<String>, String, String)>(
                    "SELECT port, proto, kind, value FROM scan_facts WHERE scan_id = ? ORDER BY id",
                )
                .bind(id)
                .fetch_all(&s.pool)
                .await
                .unwrap()
            }
        };
        assert_eq!(rows(&a, ia).await, rows(&b, ib).await);
    }

    #[tokio::test]
    async fn deleting_a_scan_deletes_its_facts() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        sqlx::query("DELETE FROM ports")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM host_keys")
            .execute(&s.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM scans WHERE id = ?")
            .bind(id)
            .execute(&s.pool)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_facts")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn the_ip_page_summaries() {
        let fact = |port: Option<i64>, kind: &str, value: &str| FactRow {
            port,
            kind: kind.into(),
            value: value.into(),
        };
        let port = |port: i64, facts: Vec<FactRow>| crate::store::inspect::PortRow {
            port,
            proto: "tcp".into(),
            state: "open".into(),
            service: None,
            product: None,
            version: None,
            extrainfo: None,
            ostype: None,
            devicetype: None,
            hostname: None,
            cpe: None,
            facts,
        };
        let ports = vec![
            port(8443, vec![fact(Some(8443), "http.title", "PentAGI")]),
            port(
                9000,
                vec![
                    fact(Some(9000), "http.title", "MinIO"),
                    fact(Some(9000), "http.server", "MinIO"),
                ],
            ),
            port(80, vec![fact(Some(80), "http.server", "nginx/1.18.0")]),
            port(81, vec![fact(Some(81), "http.title", "PentAGI")]),
            port(82, vec![fact(Some(82), "http.title", "one more")]),
            port(
                3389,
                vec![
                    fact(Some(3389), "ntlm.netbios_computer", "WIN-1"),
                    fact(Some(3389), "ntlm.netbios_domain", "WORKGROUP"),
                ],
            ),
        ];
        assert_eq!(
            serves(&ports),
            "8443 PentAGI · 9000 MinIO · 80 nginx/1.18.0"
        );
        assert_eq!(windows_names(&[], &ports), "WIN-1 · WORKGROUP");
        let host = vec![
            fact(None, "smb.server", "SRV"),
            fact(None, "smb.domain", "CORP"),
        ];
        assert_eq!(
            windows_names(&host, &ports),
            "SRV · CORP",
            "the host script wins"
        );
        assert_eq!(serves(&[]), "");
        assert_eq!(windows_names(&[], &[]), "");
    }
}
