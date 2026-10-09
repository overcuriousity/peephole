//! Observational probes (`scan::probe`): the `probe_result` record's rows
//! (`probes`, `probe_ports`), the host keys they yield, and the readers.

use super::Store;
use super::data::{Ctx, Effect, ensure_ip, erased_by};
use super::hostkeys::insert_probe_keys;
use super::requests::IpRow;
use crate::cluster::record::{IpNameRec, ProbeResultRec};
use crate::scan::hostkeys::{
    FAVICON, HASSH, HTTP_404, HTTP_BODY, HostKey, JARM, SSH_HOSTKEY, TLS_CERT,
};
use anyhow::Result;
use serde_json::Value;
use sqlx::SqliteConnection;

/// Bounds on what a peer may send.
const MAX_UID: usize = 64;
const MAX_PORTS: usize = 1024;
const MAX_DETAIL: usize = 64 * 1024;
/// Longest protocol, outcome, address source and build text accepted.
const MAX_SHORT: usize = 64;

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
    pub charged_mc: i64,
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
    let date = |d: &str| chrono::NaiveDateTime::parse_from_str(d, "%Y-%m-%d %H:%M:%S").is_ok();
    if r.uid.len() > MAX_UID
        || r.group.len() > MAX_UID
        || r.ports.len() > MAX_PORTS
        || r.ports.iter().any(|p| {
            p.detail_json.len() > MAX_DETAIL
                || p.protocol.len() > MAX_SHORT
                || p.outcome.len() > MAX_SHORT
        })
        || r.vantage_ip_source.len() > MAX_SHORT
        || r.build.len() > MAX_SHORT
        || !date(&r.started_at)
        || !date(&r.finished_at)
    {
        return Ok(Effect::Ignored);
    }
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let Some(ip_id) = ensure_ip(conn, &r.ip, None).await? else {
        return Ok(Effect::Ignored);
    };
    // Standalone nodes have no origin: the asker stands in as the
    // probe's origin.
    let origin = ctx.origin_bytes().unwrap_or_else(|| r.asker.0.to_vec());
    let res = sqlx::query(
        "INSERT OR IGNORE INTO probes (uid, group_uid, ip_id, origin, hlc, asker, vantage_ip,
           vantage_ip_source, started_at, finished_at, rtt_min_ms, build, charged_mc)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
    .bind(i64::from(r.charged_mc))
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

/// Names an admin looked up (`intel::dns`). The votes are derived here
/// from the resolvers' answers, never taken from the sender; addresses
/// outside global unicast get no row.
pub(crate) async fn apply_ip_name(
    conn: &mut SqliteConnection,
    _ctx: Ctx<'_>,
    r: &IpNameRec,
) -> Result<Effect> {
    use crate::intel::dns;
    if r.uid.len() > MAX_UID
        || dns::valid_name(&r.name).as_deref() != Some(r.name.as_str())
        || r.answers.len() > dns::MAX_QUORUM
        || r.answers
            .iter()
            .any(|(_, a)| a.as_ref().is_ok_and(|v| v.len() > dns::MAX_ADDRS))
        || chrono::NaiveDateTime::parse_from_str(&r.at, "%Y-%m-%d %H:%M:%S").is_err()
    {
        return Ok(Effect::Ignored);
    }
    if let Some(t) = erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let t = dns::tally(&r.answers);
    for v in &t.votes {
        let Some(ip_id) = ensure_ip(conn, &v.addr.to_string(), None).await? else {
            continue;
        };
        sqlx::query(
            "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen)
             VALUES (?1, ?2, 'dns', ?3, ?3)
             ON CONFLICT(ip_id, name, source) DO UPDATE
               SET first_seen = min(first_seen, excluded.first_seen)",
        )
        .bind(ip_id)
        .bind(&r.name)
        .bind(&r.at)
        .execute(&mut *conn)
        .await?;
        // The newest lookup's votes stand, whatever order records arrive in.
        sqlx::query(
            "UPDATE ip_names SET last_seen = ?1, agreed = ?2, asked = ?3, answered = ?4,
                    votes = ?5, record_uid = ?6
             WHERE ip_id = ?7 AND name = ?8 AND source = 'dns'
               AND (last_seen < ?1 OR (last_seen = ?1 AND record_uid <= ?6))",
        )
        .bind(&r.at)
        .bind(v.agreed)
        .bind(t.asked as i64)
        .bind(t.answered as i64)
        .bind(v.votes as i64)
        .bind(&r.uid)
        .bind(ip_id)
        .bind(&r.name)
        .execute(&mut *conn)
        .await?;
    }
    Ok(Effect::Applied)
}

/// A name of an address: looked up by an admin (`dns`) or the PTR name of
/// a scan (`ptr`).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NameRow {
    pub name: String,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub agreed: bool,
    pub asked: i64,
    pub answered: i64,
    pub votes: i64,
}

impl NameRow {
    /// The day it was last seen.
    pub fn day(&self) -> &str {
        self.last_seen.get(..10).unwrap_or(&self.last_seen)
    }
}

impl Store {
    /// The newest probes of an address, newest first.
    pub async fn probes_for_ip(&self, ip_id: i64) -> Result<Vec<ProbeRow>> {
        Ok(sqlx::query_as::<_, ProbeRow>(
            "SELECT id, uid, group_uid, ip_id, origin, asker, vantage_ip, vantage_ip_source,
                    started_at, finished_at, rtt_min_ms, charged_mc
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

    /// The names of an address, agreed ones first.
    pub async fn names_for_ip(&self, ip_id: i64) -> Result<Vec<NameRow>> {
        Ok(sqlx::query_as::<_, NameRow>(
            "SELECT name, source, first_seen, last_seen, agreed, asked, answered, votes
             FROM ip_names WHERE ip_id = ?
             ORDER BY agreed DESC, last_seen DESC, name LIMIT 200",
        )
        .bind(ip_id)
        .fetch_all(&self.read)
        .await?)
    }

    /// The addresses a name is known for, agreed ones first.
    pub async fn ips_named(&self, name: &str) -> Result<Vec<(IpRow, NameRow)>> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT ip_id FROM ip_names WHERE name = ? GROUP BY ip_id
             ORDER BY max(agreed) DESC, max(last_seen) DESC LIMIT 200",
        )
        .bind(name)
        .fetch_all(&self.read)
        .await?;
        let mut out = vec![];
        for ip_id in ids {
            let ip = sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE id = ?")
                .bind(ip_id)
                .fetch_optional(&self.read)
                .await?;
            let names = self.names_for_ip(ip_id).await?;
            if let (Some(ip), Some(n)) = (ip, names.into_iter().find(|n| n.name == name)) {
                out.push((ip, n));
            }
        }
        Ok(out)
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
            charged_mc: 0,
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
    }

    #[tokio::test]
    async fn a_probed_ip_survives_its_last_scan_and_goes_with_its_probe() {
        use crate::cluster::identity::Identity;
        use crate::cluster::record::{SkipBatchRec, TombstoneRec};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let a = Identity::generate().unwrap().id;
        let ctx = |hlc| Ctx {
            origin: Some(&a),
            hlc,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        let skip = format!("{}skip", a.uid_prefix());
        let batch = Record::SkipBatch(SkipBatchRec {
            build: String::new(),
            uid: skip.clone(),
            ip: "203.0.113.9".into(),
            dropped: 1,
            rows: vec![],
        });
        apply(&mut conn, ctx(1), &batch).await.unwrap();
        let mut r = rec("203.0.113.9", 7);
        r.uid = format!("{}probe", a.uid_prefix());
        apply(&mut conn, ctx(2), &Record::ProbeResult(r.clone()))
            .await
            .unwrap();
        let tomb = |uid: &str, hlc| {
            Record::Tombstone(TombstoneRec {
                uid: format!("{}tomb{hlc}", a.uid_prefix()),
                uids: vec![uid.to_string()],
                seqs: vec![],
            })
        };
        let n = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql);
        // The last record besides the probe goes: the probe keeps the IP.
        apply(&mut conn, ctx(3), &tomb(&skip, 3)).await.unwrap();
        assert_eq!(
            n("SELECT COUNT(*) FROM ips")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            1
        );
        // The probe goes, with its ports and keys, and the IP after it.
        apply(&mut conn, ctx(4), &tomb(&r.uid, 4)).await.unwrap();
        for sql in [
            "SELECT COUNT(*) FROM probes",
            "SELECT COUNT(*) FROM probe_ports",
            "SELECT COUNT(*) FROM host_keys",
            "SELECT COUNT(*) FROM ips",
        ] {
            assert_eq!(n(sql).fetch_one(&mut *conn).await.unwrap(), 0, "{sql}");
        }
    }

    #[tokio::test]
    async fn votes_are_derived_locally_not_trusted() {
        use crate::cluster::record::IpNameRec;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // A record whose answers name a private address and an address only one of three returned.
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let r = IpNameRec {
            uid: new_uid(),
            name: "example.com".into(),
            at: now_ts(),
            answers: vec![
                (NodeId([1; 32]), Ok(vec![ip("203.0.113.1"), ip("10.0.0.1")])),
                (NodeId([2; 32]), Ok(vec![ip("203.0.113.1")])),
                (NodeId([3; 32]), Ok(vec![ip("203.0.113.7")])),
            ],
            build: String::new(),
        };
        let ctx = Ctx {
            origin: Some(&NodeId([1; 32])),
            hlc: 5,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        let bad = IpNameRec {
            name: "Not A Name".into(),
            ..r.clone()
        };
        assert_eq!(
            apply(&mut conn, ctx, &Record::IpName(bad)).await.unwrap(),
            Effect::Ignored
        );
        assert_eq!(
            apply(&mut conn, ctx, &Record::IpName(r.clone()))
                .await
                .unwrap(),
            Effect::Applied
        );
        drop(conn);
        let names = |a: &str| {
            let store = store.clone();
            let a = a.to_string();
            async move {
                match store.ip_by_addr(&a).await.unwrap() {
                    Some(row) => store.names_for_ip(row.id).await.unwrap(),
                    None => vec![],
                }
            }
        };
        let one = names("203.0.113.1").await;
        assert_eq!(one.len(), 1);
        assert_eq!(
            (one[0].agreed, one[0].votes, one[0].answered, one[0].asked),
            (true, 2, 3, 3)
        );
        assert_eq!(one[0].source, "dns");
        let seven = names("203.0.113.7").await;
        assert_eq!((seven[0].agreed, seven[0].votes), (false, 1));
        assert!(store.ip_by_addr("10.0.0.1").await.unwrap().is_none());
        let named = store.ips_named("example.com").await.unwrap();
        assert_eq!(named.len(), 2);
        assert_eq!(named[0].0.ip, "203.0.113.1", "the agreed address first");
    }

    #[tokio::test]
    async fn no_answer_at_all_writes_no_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let rec = store.local();
        let geo: crate::intel::SharedGeo = std::sync::Arc::new(std::sync::RwLock::new(None));
        // `.invalid` never resolves (RFC 6761).
        let (t, r) = crate::intel::dns::lookup(&rec, &geo, "peephole-test.invalid")
            .await
            .unwrap();
        assert_eq!((t.asked, t.answered), (1, 0));
        assert!(r.is_none());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_names")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let logged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM repl_log")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(logged, 0);
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

    #[tokio::test]
    async fn a_peer_may_send_more_than_sixteen_ports() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut r = rec("203.0.113.10", 7);
        r.ports = (0u16..17)
            .map(|i| ProbePortRec {
                port: 1000 + i,
                protocol: "banner".into(),
                outcome: "ok".into(),
                detail_json: "{}".into(),
            })
            .collect();
        let ctx = Ctx {
            origin: Some(&NodeId([7; 32])),
            hlc: 5,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(
            apply(&mut conn, ctx, &Record::ProbeResult(r))
                .await
                .unwrap(),
            Effect::Applied
        );
    }

    #[tokio::test]
    async fn a_peer_record_over_the_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut r = rec("203.0.113.10", 7);
        r.ports = (0u16..1025)
            .map(|i| ProbePortRec {
                port: 1000 + i,
                protocol: "banner".into(),
                outcome: "ok".into(),
                detail_json: "{}".into(),
            })
            .collect();
        let ctx = Ctx {
            origin: Some(&NodeId([7; 32])),
            hlc: 5,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        assert_eq!(
            apply(&mut conn, ctx, &Record::ProbeResult(r))
                .await
                .unwrap(),
            Effect::Ignored
        );
    }
}
