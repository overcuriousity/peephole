//! Observational probes (`scan::probe`): the `probe_result` record's rows
//! (`probes`, `probe_ports`), the host keys they yield, and the readers.

use super::Store;
use super::data::{Ctx, Effect, ensure_ip, erased_by};
use super::hostkeys::insert_probe_keys;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{IpNameRec, ProbeResultRec};
use crate::scan::hostkeys::{
    FAVICON, HASSH, HTTP_404, HTTP_BODY, HostKey, JARM, SSH_HOSTKEY, TLS_CERT,
};
use anyhow::Result;
use serde_json::Value;
use sqlx::SqliteConnection;

/// Bounds on what a peer may send.
const MAX_UID: usize = 64;
const MAX_PORTS: usize = 16;
const MAX_DETAIL: usize = 64 * 1024;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProbeRow {
    pub id: i64,
    pub uid: String,
    pub group_uid: String,
    pub ip_id: i64,
    pub origin: Option<Vec<u8>>,
    pub asker: Vec<u8>,
    pub vantage_ip: Option<String>,
    pub vantage_ip_source: String,
    pub started_at: String,
    pub finished_at: String,
    pub rtt_min_ms: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProbePortRow {
    pub port: i64,
    pub protocol: String,
    pub outcome: String,
    pub detail_json: String,
}

/// 64 lowercase hex digits.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The identifiers one port's probe detail holds. Anything missing or
/// malformed yields no key (peers can send anything).
pub fn keys_of(port: u16, detail: &Value) -> Vec<HostKey> {
    let str_at = |v: &'_ Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
    let mut keys = vec![];
    let mut push = |kind, fingerprint: String, detail: String| {
        keys.push(HostKey {
            port,
            kind,
            fingerprint,
            detail,
        });
    };
    if let Some(tls) = detail.get("tls")
        && let Some(fp) = str_at(tls, "leaf_sha256").filter(|f| is_sha256_hex(f))
    {
        let subject = str_at(tls, "subject").unwrap_or_default();
        let not_after = str_at(tls, "not_after").unwrap_or_default();
        push(TLS_CERT, fp, format!("{subject} · valid until {not_after}"));
    }
    if let Some(ssh) = detail.get("ssh") {
        if let Some(fp) = str_at(ssh, "host_key_sha256").filter(|f| !f.is_empty()) {
            push(
                SSH_HOSTKEY,
                format!("SHA256:{fp}"),
                str_at(ssh, "host_key_type").unwrap_or_default(),
            );
        }
        if let Some(h) = str_at(ssh, "hassh").filter(|h| !h.is_empty()) {
            push(HASSH, h, str_at(ssh, "kex_algorithms").unwrap_or_default());
        }
    }
    if let Some(j) = str_at(detail, "jarm")
        && !j.is_empty()
        && j.bytes().any(|b| b != b'0')
    {
        push(JARM, j, String::new());
    }
    if let Some(f) = str_at(detail, "favicon_mmh3").filter(|f| !f.is_empty()) {
        push(
            FAVICON,
            f,
            str_at(detail, "favicon_sha256").unwrap_or_default(),
        );
    }
    if let Some(b) = str_at(detail, "body_sha256").filter(|b| is_sha256_hex(b)) {
        let len = detail.get("body_len").and_then(Value::as_u64).unwrap_or(0);
        push(HTTP_BODY, b, format!("{len} bytes"));
    }
    if let Some(nf) = detail.get("not_found")
        && let Some(b) = str_at(nf, "body_sha256").filter(|b| is_sha256_hex(b))
    {
        let status = nf.get("status").and_then(Value::as_u64).unwrap_or(0);
        push(HTTP_404, b, format!("status {status}"));
    }
    keys
}

pub(crate) async fn apply_probe_result(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &ProbeResultRec,
) -> Result<Effect> {
    if r.uid.len() > MAX_UID
        || r.group.len() > MAX_UID
        || r.ports.len() > MAX_PORTS
        || r.ports.iter().any(|p| p.detail_json.len() > MAX_DETAIL)
    {
        return Ok(Effect::Ignored);
    }
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let Some(ip_id) = ensure_ip(conn, &r.ip, None).await? else {
        return Ok(Effect::Ignored);
    };
    // Standalone nodes have no origin: the asker stands in, so
    // `probed_recently` works there too.
    let origin = ctx.origin_bytes().unwrap_or_else(|| r.asker.0.to_vec());
    let res = sqlx::query(
        "INSERT OR IGNORE INTO probes (uid, group_uid, ip_id, origin, hlc, asker, vantage_ip,
           vantage_ip_source, started_at, finished_at, rtt_min_ms, build)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&r.uid)
    .bind(&r.group)
    .bind(ip_id)
    .bind(origin)
    .bind(ctx.hlc as i64)
    .bind(&r.asker.0[..])
    .bind(r.vantage_ip.map(|a| crate::net::canonical(a).to_string()))
    .bind(&r.vantage_ip_source)
    .bind(&r.started_at)
    .bind(&r.finished_at)
    .bind(r.rtt_min_ms.map(i64::from))
    .bind(&r.build)
    .execute(&mut *conn)
    .await?;
    if res.rows_affected() == 1 {
        let probe_id = res.last_insert_rowid();
        for p in &r.ports {
            sqlx::query(
                "INSERT INTO probe_ports (probe_id, port, protocol, outcome, detail_json)
                 VALUES (?,?,?,?,?)",
            )
            .bind(probe_id)
            .bind(p.port as i64)
            .bind(&p.protocol)
            .bind(&p.outcome)
            .bind(&p.detail_json)
            .execute(&mut *conn)
            .await?;
            let detail: Value = serde_json::from_str(&p.detail_json).unwrap_or(Value::Null);
            insert_probe_keys(conn, probe_id, ip_id, &keys_of(p.port, &detail)).await?;
        }
    }
    Ok(Effect::Applied)
}

/// Filled in by the DNS lookup task; until then the record is accepted
/// into the log and changes no table.
pub(crate) async fn apply_ip_name(
    _conn: &mut SqliteConnection,
    _ctx: Ctx<'_>,
    _r: &IpNameRec,
) -> Result<Effect> {
    Ok(Effect::Ignored)
}

impl Store {
    /// The newest probes of an address, newest first.
    pub async fn probes_for_ip(&self, ip_id: i64) -> Result<Vec<ProbeRow>> {
        Ok(sqlx::query_as::<_, ProbeRow>(
            "SELECT id, uid, group_uid, ip_id, origin, asker, vantage_ip, vantage_ip_source,
                    started_at, finished_at, rtt_min_ms
             FROM probes WHERE ip_id = ? ORDER BY id DESC LIMIT 200",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?)
    }

    pub async fn probe_ports(&self, probe_id: i64) -> Result<Vec<ProbePortRow>> {
        Ok(sqlx::query_as::<_, ProbePortRow>(
            "SELECT port, protocol, outcome, detail_json FROM probe_ports
             WHERE probe_id = ? ORDER BY port, id",
        )
        .bind(probe_id)
        .fetch_all(&self.read)
        .await?)
    }

    /// Whether `origin` probed `ip` within the last `hours`.
    pub async fn probed_recently(&self, ip: &str, origin: &NodeId, hours: i64) -> Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM probes p JOIN ips i ON i.id = p.ip_id
             WHERE i.ip = ? AND p.origin = ? AND p.finished_at > datetime('now', ?)",
        )
        .bind(ip)
        .bind(&origin.0[..])
        .bind(format!("-{hours} hours"))
        .fetch_one(&self.read)
        .await?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::NodeId;
    use crate::cluster::record::{ProbePortRec, ProbeResultRec, Record};
    use crate::store::Store;
    use crate::store::data::{Ctx, Effect, apply, new_uid, now_ts};

    fn rec(ip: &str, origin: u8) -> ProbeResultRec {
        ProbeResultRec {
            uid: new_uid(), group: new_uid(), ip: ip.into(), asker: NodeId([origin; 32]),
            vantage_ip: Some("198.51.100.1".parse().unwrap()), vantage_ip_source: "public".into(),
            started_at: now_ts(), finished_at: now_ts(), rtt_min_ms: Some(12),
            ports: vec![ProbePortRec {
                port: 443, protocol: "https".into(), outcome: "ok".into(),
                detail_json: serde_json::json!({
                    "status": 200, "server": "nginx", "body_sha256": "ab".repeat(32), "body_len": 1234,
                    "favicon_mmh3": "-1234567", "jarm": "1".repeat(62),
                    "tls": {"leaf_sha256": "cd".repeat(32), "subject": "CN=x", "not_after": "2027-01-01"}
                }).to_string(),
            }],
            build: String::new(),
        }
    }

    #[tokio::test]
    async fn a_probe_result_lands_in_probes_ports_and_host_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        let r = rec("203.0.113.9", 7);
        let ctx = Ctx {
            origin: Some(&NodeId([7; 32])),
            hlc: 5,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(
            apply(&mut conn, ctx, &Record::ProbeResult(r.clone()))
                .await
                .unwrap(),
            Effect::Applied
        );
        apply(&mut conn, ctx, &Record::ProbeResult(r))
            .await
            .unwrap(); // twice: no duplicate
        drop(conn);
        let probes = store.probes_for_ip(ip.id).await.unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].rtt_min_ms, Some(12));
        assert_eq!(store.probe_ports(probes[0].id).await.unwrap()[0].port, 443);
        let keys = store.host_keys_for_ip(ip.id).await.unwrap();
        let kinds: Vec<&str> = keys.iter().map(|k| k.kind.as_str()).collect();
        for k in ["tls-cert", "favicon", "jarm", "http-body"] {
            assert!(kinds.contains(&k), "{kinds:?}");
        }
        assert!(
            store
                .probed_recently("203.0.113.9", &NodeId([7; 32]), 24)
                .await
                .unwrap()
        );
        assert!(
            !store
                .probed_recently("203.0.113.9", &NodeId([8; 32]), 24)
                .await
                .unwrap()
        );
    }

    #[test]
    fn oversized_or_malformed_records_yield_no_keys() {
        let v = serde_json::json!({"jarm": "0".repeat(62), "body_sha256": "zz"});
        let keys = keys_of(80, &v);
        assert!(
            keys.iter().all(|k| k.kind != "jarm"),
            "an all-zero JARM is 'no TLS', not a key"
        );
        assert!(
            keys.iter().all(|k| k.kind != "http-body"),
            "not a sha256 hex"
        );
    }
}
