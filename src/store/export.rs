//! Reads for the dataset export (`crate::export`): requests and light rows
//! page by page (keyset paging, so an export of any size holds no long read
//! transaction), and everything known about the IPs and requests of a page.
use super::Store;
use crate::export::ExportFilter;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// A recorded request with every stored column.
#[derive(sqlx::FromRow)]
pub struct ReqRow {
    pub id: i64,
    pub uid: Option<String>,
    pub origin: Option<Vec<u8>>,
    pub ts: String,
    pub ip_id: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers_json: String,
    pub body: Option<Vec<u8>>,
    pub labels_json: String,
    pub owasp_json: String,
    pub severity: i64,
    pub scan_level: i64,
    pub answer: Option<String>,
    pub status: Option<i64>,
    pub unrecorded: Option<i64>,
    pub transport: Option<String>,
    pub via_proxy: Option<bool>,
    pub raw_head: Option<Vec<u8>>,
    pub tls_client_hello: Option<Vec<u8>>,
    pub ja4: Option<String>,
    pub ja4h: Option<String>,
    pub build: String,
    pub rules: Option<String>,
    pub decoy_v: Option<i64>,
    pub held_ms: Option<i64>,
    pub decoy_in: Option<String>,
}

/// A light row with its batch.
#[derive(sqlx::FromRow)]
pub struct SkipOut {
    pub rowid: i64,
    /// Its position in its batch, from 1: the same on every node.
    pub row: i64,
    pub ts_ms: i64,
    pub method: String,
    pub path: String,
    pub ip_id: i64,
    pub ip: String,
    pub uid: String,
    pub origin: Option<Vec<u8>>,
    pub build: String,
    pub dropped: i64,
    pub decoy_v: Option<i64>,
    /// Set when the request was answered with a decoy.
    pub answer: Option<String>,
    pub host: Option<String>,
    /// How long a `tarpit` answer held the client, in milliseconds.
    pub held_ms: Option<i64>,
    /// What an MCP or LLM decoy was rendered from (compact JSON).
    pub decoy_in: Option<String>,
    /// The batch's last light row (it carries the batch's drops).
    pub last_in_batch: bool,
}

#[derive(sqlx::FromRow)]
pub struct IntelOut {
    pub ip: String,
    pub provider: String,
    pub fetched_at: String,
    pub source_version: Option<String>,
    pub origin: Vec<u8>,
    pub data_json: String,
    pub build: String,
}

#[derive(sqlx::FromRow)]
pub struct ScanOut {
    pub id: i64,
    pub ip_id: i64,
    pub level: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub os_guess: Option<String>,
    /// zstd-compressed, as stored.
    pub raw_xml: Option<Vec<u8>>,
    pub status: Option<String>,
    pub scanner: Option<Vec<u8>>,
    pub origin: Option<Vec<u8>>,
    pub build: String,
    pub uid: Option<String>,
    pub audit_of: Option<String>,
}

#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PortOut {
    #[serde(skip)]
    pub scan_id: i64,
    pub port: i64,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct FpOut {
    pub request_uid: String,
    pub origin: Option<Vec<u8>>,
    pub build: String,
    pub ts: String,
    pub fp_hash: Option<String>,
    pub visitor_id: Option<String>,
    pub attributes_json: Option<String>,
    pub behavior_summary_json: Option<String>,
    /// zstd-compressed, as stored.
    pub event_blob: Option<Vec<u8>>,
}

/// An agreed name of an address (`ip_names`).
#[derive(sqlx::FromRow)]
pub struct NameOut {
    pub ip_id: i64,
    pub name: String,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub votes: i64,
    pub answered: i64,
}

/// Everything about the IPs and requests of one page.
#[derive(Default)]
pub struct PageContext {
    /// Every lookup per IP, oldest first.
    pub intel: HashMap<String, Vec<IntelOut>>,
    pub scans: HashMap<i64, Vec<(ScanOut, Vec<PortOut>)>>,
    /// The agreed names per IP id (looked up or PTR), by name.
    pub names: HashMap<i64, Vec<NameOut>>,
    pub fingerprints: HashMap<String, Vec<FpOut>>,
    /// Per request id: the uids of the rows whose served canaries it
    /// carried (light rows as `<batch uid>#<row>`).
    pub canary_used_from: HashMap<i64, Vec<String>>,
    /// IPs that filed a false-positive claim.
    pub claimed: HashSet<i64>,
}

/// `[a, b, …]` as JSON, for `IN (SELECT value FROM json_each(?))`.
fn json_list<T: serde::Serialize>(v: &[T]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}

impl Store {
    /// One page of recorded requests matching `f` after `after` (`(ts, id)`),
    /// oldest first.
    pub async fn export_requests(
        &self,
        f: &ExportFilter,
        after: Option<&(String, i64)>,
        limit: i64,
    ) -> Result<Vec<ReqRow>> {
        let mut sql = String::from(
            "SELECT r.id, r.uid, r.origin, r.ts, r.ip_id, i.ip, r.method, r.path, r.query,
                    r.headers_json, r.body, r.labels_json, r.owasp_json, r.severity, r.scan_level, r.answer,
                    r.status, r.unrecorded, r.transport, r.via_proxy, r.raw_head,
                    r.tls_client_hello, r.ja4, r.ja4h, r.build, r.rules, r.decoy_v, r.held_ms, r.decoy_in
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1",
        );
        if after.is_some() {
            // A row value, so the (ts, rowid) index serves the range.
            sql.push_str(" AND (r.ts, r.id) > (?, ?)");
        }
        if f.from.is_some() {
            sql.push_str(" AND r.ts >= ?");
        }
        if f.to.is_some() {
            sql.push_str(" AND r.ts <= ?");
        }
        if f.ip.is_some() {
            sql.push_str(" AND i.ip = ?");
        }
        if f.label.is_some() {
            // Exact label match via json_each, matching the admin search.
            sql.push_str(
                " AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(r.labels_json) THEN r.labels_json ELSE '[]' END) je WHERE je.value = ?)",
            );
        }
        if f.min_severity.is_some() {
            sql.push_str(" AND r.severity >= ?");
        }
        sql.push_str(" ORDER BY r.ts, r.id LIMIT ?");
        let mut q = sqlx::query_as::<_, ReqRow>(sqlx::AssertSqlSafe(sql));
        if let Some((ts, id)) = after {
            q = q.bind(ts).bind(id);
        }
        for v in [&f.from, &f.to, &f.ip, &f.label].into_iter().flatten() {
            q = q.bind(v);
        }
        if let Some(v) = f.min_severity {
            q = q.bind(v);
        }
        Ok(q.bind(limit).fetch_all(&self.read).await?)
    }

    /// One page of light rows matching the time and IP filters after
    /// `after` (`(ts_ms, rowid)`), oldest first.
    pub async fn export_skipped(
        &self,
        f: &ExportFilter,
        after: Option<&(i64, i64)>,
        limit: i64,
    ) -> Result<Vec<SkipOut>> {
        let mut sql = String::from(
            "SELECT s.rowid AS rowid,
                    (SELECT COUNT(*) FROM skipped_requests x
                     WHERE x.batch_id = s.batch_id AND x.rowid <= s.rowid) AS row,
                    s.ts_ms, s.method, s.path, b.ip_id, i.ip, b.uid, b.origin,
                    b.build, b.dropped, s.decoy_v, s.answer, s.host, s.held_ms, s.decoy_in,
                    s.rowid = (SELECT MAX(x.rowid) FROM skipped_requests x
                               WHERE x.batch_id = s.batch_id) AS last_in_batch
             FROM skipped_requests s JOIN skipped_batches b ON b.id = s.batch_id
             JOIN ips i ON i.id = b.ip_id WHERE 1=1",
        );
        if after.is_some() {
            sql.push_str(" AND (s.ts_ms, s.rowid) > (?, ?)");
        }
        if f.from.is_some() {
            sql.push_str(" AND s.ts_ms >= CAST(strftime('%s', ?) AS INTEGER) * 1000");
        }
        if f.to.is_some() {
            sql.push_str(" AND s.ts_ms < (CAST(strftime('%s', ?) AS INTEGER) + 1) * 1000");
        }
        if f.ip.is_some() {
            sql.push_str(" AND i.ip = ?");
        }
        sql.push_str(" ORDER BY s.ts_ms, s.rowid LIMIT ?");
        let mut q = sqlx::query_as::<_, SkipOut>(sqlx::AssertSqlSafe(sql));
        if let Some((ts, id)) = after {
            q = q.bind(ts).bind(id);
        }
        for v in [&f.from, &f.to, &f.ip].into_iter().flatten() {
            q = q.bind(v);
        }
        Ok(q.bind(limit).fetch_all(&self.read).await?)
    }

    /// Lookups, scans, fingerprints and claims for one page's IPs and
    /// requests.
    pub async fn export_context(
        &self,
        ips: &[String],
        ip_ids: &[i64],
        request_uids: &[String],
        request_ids: &[i64],
    ) -> Result<PageContext> {
        let mut c = PageContext::default();
        let intel: Vec<IntelOut> = sqlx::query_as(
            "SELECT ip, provider, fetched_at, source_version, origin, data_json, build
             FROM ip_intel_log WHERE ip IN (SELECT value FROM json_each(?))
             ORDER BY fetched_at, hlc",
        )
        .bind(json_list(ips))
        .fetch_all(&self.read)
        .await?;
        for i in intel {
            c.intel.entry(i.ip.clone()).or_default().push(i);
        }
        let scans: Vec<ScanOut> = sqlx::query_as(
            // An audit carries the job of the scan it checks: its scanner
            // is the auditor, and it is done once it has finished.
            "SELECT s.id, s.ip_id, s.level, s.started_at, s.finished_at, s.os_guess, s.raw_xml,
                    CASE WHEN s.audit_of IS NULL THEN j.status
                         WHEN s.finished_at IS NOT NULL THEN 'done' END AS status,
                    CASE WHEN s.audit_of IS NULL THEN j.scanner ELSE s.origin END AS scanner,
                    s.origin, s.build, s.uid, s.audit_of
             FROM scans s LEFT JOIN scan_jobs j ON j.id = s.job_id
             WHERE s.ip_id IN (SELECT value FROM json_each(?)) ORDER BY s.id",
        )
        .bind(json_list(ip_ids))
        .fetch_all(&self.read)
        .await?;
        let scan_ids: Vec<i64> = scans.iter().map(|s| s.id).collect();
        let mut ports: HashMap<i64, Vec<PortOut>> = HashMap::new();
        let rows: Vec<PortOut> = sqlx::query_as(
            "SELECT scan_id, port, proto, state, service, product, version FROM ports
             WHERE scan_id IN (SELECT value FROM json_each(?)) ORDER BY scan_id, port",
        )
        .bind(json_list(&scan_ids))
        .fetch_all(&self.read)
        .await?;
        for p in rows {
            ports.entry(p.scan_id).or_default().push(p);
        }
        for s in scans {
            let p = ports.remove(&s.id).unwrap_or_default();
            c.scans.entry(s.ip_id).or_default().push((s, p));
        }
        let fps: Vec<FpOut> = sqlx::query_as(
            "SELECT request_uid, origin, build, ts, fp_hash, visitor_id, attributes_json, behavior_summary_json,
                    event_blob
             FROM fingerprints WHERE request_uid IN (SELECT value FROM json_each(?)) ORDER BY id",
        )
        .bind(json_list(request_uids))
        .fetch_all(&self.read)
        .await?;
        for f in fps {
            c.fingerprints
                .entry(f.request_uid.clone())
                .or_default()
                .push(f);
        }
        let names: Vec<NameOut> = sqlx::query_as(
            "SELECT ip_id, name, source, first_seen, last_seen, votes, answered FROM ip_names
             WHERE agreed = 1 AND ip_id IN (SELECT value FROM json_each(?))
             ORDER BY ip_id, name, source",
        )
        .bind(json_list(ip_ids))
        .fetch_all(&self.read)
        .await?;
        for n in names {
            c.names.entry(n.ip_id).or_default().push(n);
        }
        let claimed: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT ip_id FROM fp_claims WHERE ip_id IN (SELECT value FROM json_each(?))",
        )
        .bind(json_list(ip_ids))
        .fetch_all(&self.read)
        .await?;
        c.claimed = claimed.into_iter().collect();
        let used: Vec<(i64, String)> = sqlx::query_as(
            "SELECT DISTINCT t.request_id,
                    COALESCE(sr.uid, CAST(sr.id AS TEXT), sb.uid || '#' || c.skip_row)
             FROM request_tokens t
             JOIN canaries c ON c.value_hash = t.value_hash
             LEFT JOIN requests sr ON sr.id = c.request_id
             LEFT JOIN skipped_batches sb ON sb.id = c.batch_id
             WHERE t.request_id IN (SELECT value FROM json_each(?))
               AND (c.request_id IS NULL OR c.request_id != t.request_id)
             ORDER BY 1, 2",
        )
        .bind(json_list(request_ids))
        .fetch_all(&self.read)
        .await?;
        for (id, uid) in used {
            c.canary_used_from.entry(id).or_default().push(uid);
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use crate::cluster::identity::NodeId;
    use crate::cluster::record::{IpNameRec, Record};
    use crate::store::Store;
    use crate::store::data::{new_uid, now_ts};

    #[tokio::test]
    async fn agreed_names_are_exported_disputed_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let r = IpNameRec {
            uid: new_uid(),
            name: "example.com".into(),
            at: now_ts(),
            answers: vec![
                (NodeId([1; 32]), Ok(vec![ip("203.0.113.1")])),
                (NodeId([2; 32]), Ok(vec![ip("203.0.113.1")])),
                (NodeId([3; 32]), Ok(vec![ip("203.0.113.7")])),
            ],
            build: String::new(),
        };
        store.local().write(vec![Record::IpName(r)]).await.unwrap();
        let agreed = store.ip_by_addr("203.0.113.1").await.unwrap().unwrap().id;
        let disputed = store.ip_by_addr("203.0.113.7").await.unwrap().unwrap().id;
        let c = store
            .export_context(&[], &[agreed, disputed], &[], &[])
            .await
            .unwrap();
        assert!(!c.names.contains_key(&disputed));
        let col = crate::export::names_json(&c.names[&agreed]);
        assert_eq!(col[0]["name"], "example.com");
        assert_eq!(col[0]["source"], "dns");
        assert_eq!(
            (col[0]["votes"].as_i64(), col[0]["answered"].as_i64()),
            (Some(2), Some(3))
        );
        assert!(col[0]["first_seen"].as_str().unwrap().contains('T'));
    }
}
