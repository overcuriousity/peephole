//! Audits: a second look at a scan. Signatures settle what nodes say to
//! each other and re-running settles computations over shared data;
//! whether a scan really ran is a statement about the outside world, and
//! only looking again can check it. A scanner re-runs a share of the
//! other nodes' fresh scans (`Picker`), the two results are compared
//! (`compare`), and a node believes the audits it made itself and those
//! of its own fleet.
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::{BTreeSet, HashMap};

/// How an audit compares with the scan it checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Agrees,
    Differs,
    /// The audit found no open TCP port: a source that vanished cannot be
    /// told from one that was never scanned.
    Inconclusive,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Agrees => "agrees",
            Outcome::Differs => "differs",
            Outcome::Inconclusive => "inconclusive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "agrees" => Some(Outcome::Agrees),
            "differs" => Some(Outcome::Differs),
            "inconclusive" => Some(Outcome::Inconclusive),
            _ => None,
        }
    }
}

/// What a scan found, as far as audits compare it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Found {
    pub open_tcp: BTreeSet<u16>,
    /// `(port, kind, fingerprint)` of the SSH host keys and TLS
    /// certificates it saw.
    pub keys: BTreeSet<(u16, String, String)>,
}

/// Compare an audit with the scan it checks. A pure function of the two
/// stored results.
pub fn compare(original: &Found, audit: &Found) -> Outcome {
    if audit.open_tcp.is_empty() {
        return Outcome::Inconclusive;
    }
    // A port open in both that carries the same host key or certificate.
    let same_key = audit.keys.iter().any(|k| {
        original.keys.contains(k)
            && original.open_tcp.contains(&k.0)
            && audit.open_tcp.contains(&k.0)
    });
    if same_key {
        return Outcome::Agrees;
    }
    let reported = audit
        .open_tcp
        .iter()
        .filter(|p| original.open_tcp.contains(p))
        .count();
    if reported * 2 >= audit.open_tcp.len() {
        Outcome::Agrees
    } else {
        Outcome::Differs
    }
}

/// What the stored scan `scan_id` found.
pub async fn found(pool: &SqlitePool, scan_id: i64) -> Result<Found> {
    let ports: Vec<i64> = sqlx::query_scalar(
        "SELECT port FROM ports WHERE scan_id = ? AND proto = 'tcp' AND state = 'open'",
    )
    .bind(scan_id)
    .fetch_all(pool)
    .await?;
    let keys: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT port, kind, fingerprint FROM host_keys WHERE scan_id = ?")
            .bind(scan_id)
            .fetch_all(pool)
            .await?;
    let port = |p: i64| u16::try_from(p).ok();
    Ok(Found {
        open_tcp: ports.into_iter().filter_map(port).collect(),
        keys: keys
            .into_iter()
            .filter(|(_, kind, _)| crate::store::hostkeys::is_identity(kind))
            .filter_map(|(p, kind, fp)| Some((port(p)?, kind, fp)))
            .collect(),
    })
}

/// Audits compared per pass.
const SETTLE_BATCH: i64 = 200;

/// Compare the audits whose scan is held here and that have no result
/// yet, and keep the result with the audit. Returns how many.
pub async fn settle(pool: &SqlitePool) -> Result<usize> {
    let pairs: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT a.id, o.id FROM scans a JOIN scans o ON o.uid = a.audit_of
         WHERE a.audit_of IS NOT NULL AND a.audit_result IS NULL AND o.audit_of IS NULL
         ORDER BY a.id LIMIT ?",
    )
    .bind(SETTLE_BATCH)
    .fetch_all(pool)
    .await?;
    for (audit, original) in &pairs {
        let outcome = compare(&found(pool, *original).await?, &found(pool, *audit).await?);
        sqlx::query("UPDATE scans SET audit_result = ? WHERE id = ?")
            .bind(outcome.as_str())
            .bind(audit)
            .execute(pool)
            .await?;
    }
    Ok(pairs.len())
}

/// A scanner fails the audit gate when at least 5 counted audits of it
/// were conclusive and at least half of those differ.
pub fn audits_fail(conclusive: u32, differing: u32) -> bool {
    conclusive >= 5 && differing * 2 >= conclusive
}

/// How many audits of one scanner by one auditor came out one way.
#[derive(Debug, Clone, PartialEq)]
pub struct Count {
    pub scanner: NodeId,
    pub auditor: NodeId,
    pub outcome: Outcome,
    pub n: u32,
}

/// The compared audits dated `since_hlc` or later. A scanner's audits of
/// its own scans are left out: they say nothing.
pub async fn counts(pool: &SqlitePool, since_hlc: u64) -> Result<Vec<Count>> {
    let rows: Vec<(Vec<u8>, Vec<u8>, String, i64)> = sqlx::query_as(
        "SELECT o.origin, a.origin, a.audit_result, COUNT(*)
         FROM scans a JOIN scans o ON o.uid = a.audit_of
         WHERE a.audit_result IS NOT NULL AND a.hlc >= ?
           AND a.origin IS NOT NULL AND o.origin IS NOT NULL AND a.origin != o.origin
         GROUP BY o.origin, a.origin, a.audit_result",
    )
    .bind(hlc::to_db(since_hlc))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(scanner, auditor, result, n)| {
            Some(Count {
                scanner: NodeId::from_slice(&scanner).ok()?,
                auditor: NodeId::from_slice(&auditor).ok()?,
                outcome: Outcome::parse(&result)?,
                n: n.clamp(0, u32::MAX as i64) as u32,
            })
        })
        .collect())
}

/// Per audited scanner, the `(conclusive, differing)` audits made by
/// `auditors`: this node and its fleet. Audits by other operators are
/// shown but do not count, or a few throwaway nodes could strip an honest
/// scanner of its earnings.
pub fn counted(counts: &[Count], auditors: &[NodeId]) -> HashMap<NodeId, (u32, u32)> {
    let mut out: HashMap<NodeId, (u32, u32)> = HashMap::new();
    for c in counts {
        if !auditors.contains(&c.auditor) || c.outcome == Outcome::Inconclusive {
            continue;
        }
        let e = out.entry(c.scanner).or_default();
        e.0 += c.n;
        if c.outcome == Outcome::Differs {
            e.1 += c.n;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    fn found(ports: &[u16], keys: &[(u16, &str, &str)]) -> Found {
        Found {
            open_tcp: ports.iter().copied().collect(),
            keys: keys
                .iter()
                .map(|(p, k, f)| (*p, k.to_string(), f.to_string()))
                .collect(),
        }
    }

    #[test]
    fn comparing_an_audit_with_the_scan_it_checks() {
        use Outcome::*;
        let none = found(&[], &[]);
        let original = found(&[22, 80, 443], &[(22, "ssh-hostkey", "aa")]);
        // The audit found no open port: the source may be gone.
        assert_eq!(compare(&original, &none), Inconclusive);
        assert_eq!(compare(&none, &none), Inconclusive);
        // Half of what the audit found open was reported: agrees.
        assert_eq!(compare(&original, &found(&[22, 8080], &[])), Agrees);
        assert_eq!(compare(&original, &found(&[22, 80, 443], &[])), Agrees);
        // Less than half: differs.
        assert_eq!(compare(&original, &found(&[22, 8080, 8443], &[])), Differs);
        // Nothing reported, something found: a made-up result.
        assert_eq!(compare(&none, &found(&[22], &[])), Differs);
        // The same host key on a port open in both settles it, whatever
        // else changed.
        let moved = found(&[22, 1, 2, 3, 4], &[(22, "ssh-hostkey", "aa")]);
        assert_eq!(compare(&original, &moved), Agrees);
        // Another key on that port does not; the ports decide.
        let other = found(&[22, 1, 2, 3, 4], &[(22, "ssh-hostkey", "bb")]);
        assert_eq!(compare(&original, &other), Differs);
        // The same key reported for a port that is not open in both.
        let elsewhere = found(&[2222, 1, 2], &[(2222, "ssh-hostkey", "aa")]);
        assert_eq!(compare(&original, &elsewhere), Differs);
        for o in [Agrees, Differs, Inconclusive] {
            assert_eq!(Outcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(Outcome::parse("x"), None);
    }

    #[test]
    fn the_audit_gate_needs_five_conclusive_audits_and_half_of_them_differing() {
        assert!(!audits_fail(4, 4), "too few");
        assert!(audits_fail(5, 3));
        assert!(!audits_fail(5, 2));
        assert!(audits_fail(6, 3), "half");
        assert!(!audits_fail(0, 0));
    }

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    /// A scan row with one open port per entry of `ports`.
    async fn scan(
        store: &Store,
        uid: &str,
        origin: u8,
        audit_of: Option<&str>,
        ports: &[u16],
    ) -> i64 {
        let ip = store
            .upsert_ip("203.0.113.9".parse().unwrap())
            .await
            .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO scan_jobs (uid, ip_id, level, status, queued_at)
             VALUES ('job', ?, 1, 'done', datetime('now'))",
        )
        .bind(ip.id)
        .execute(&store.pool)
        .await
        .unwrap();
        let id: i64 = sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, audit_of)
             VALUES (?, ?, ?, (SELECT id FROM scan_jobs WHERE uid = 'job'), 'job', ?, 1,
                     datetime('now'), ?)",
        )
        .bind(uid)
        .bind(&self::id(origin).0[..])
        .bind((hlc::wall_ms() << 16) as i64)
        .bind(ip.id)
        .bind(audit_of)
        .execute(&store.pool)
        .await
        .unwrap()
        .last_insert_rowid();
        for p in ports {
            sqlx::query(
                "INSERT INTO ports (scan_id, port, proto, state) VALUES (?, ?, 'tcp', 'open')",
            )
            .bind(id)
            .bind(*p as i64)
            .execute(&store.pool)
            .await
            .unwrap();
        }
        id
    }

    #[tokio::test]
    async fn audits_are_compared_once_and_counted_per_auditor() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        // Scanner 1 reported nothing; auditors 2 and 3 found a port.
        let orig = scan(&store, "o1", 1, None, &[]).await;
        scan(&store, "a1", 2, Some("o1"), &[22]).await;
        scan(&store, "a2", 3, Some("o1"), &[22]).await;
        // An honest scan of scanner 1, audited by 2: agrees. A closed, UDP
        // and filtered port do not count as open TCP.
        let honest = scan(&store, "o2", 1, None, &[22, 80]).await;
        sqlx::query(
            "INSERT INTO ports (scan_id, port, proto, state) VALUES
               (?1, 53, 'udp', 'open'), (?1, 81, 'tcp', 'closed'), (?1, 82, 'tcp', 'filtered')",
        )
        .bind(honest)
        .execute(&store.pool)
        .await
        .unwrap();
        scan(&store, "a3", 2, Some("o2"), &[22]).await;
        // The audit found nothing; and one whose scan is not held here.
        scan(&store, "a4", 2, Some("o2"), &[]).await;
        scan(&store, "a5", 2, Some("gone"), &[22]).await;
        assert_eq!(
            super::found(&store.pool, orig).await.unwrap(),
            Found::default()
        );
        assert_eq!(
            super::found(&store.pool, honest).await.unwrap().open_tcp,
            [22u16, 80].into_iter().collect()
        );

        assert_eq!(settle(&store.pool).await.unwrap(), 4);
        assert_eq!(settle(&store.pool).await.unwrap(), 0, "once");
        let pool = &store.pool;
        let result = |uid: &'static str| async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT audit_result FROM scans WHERE uid = ?")
                .bind(uid)
                .fetch_one(pool)
                .await
                .unwrap()
        };
        assert_eq!(result("a1").await.as_deref(), Some("differs"));
        assert_eq!(result("a3").await.as_deref(), Some("agrees"));
        assert_eq!(result("a4").await.as_deref(), Some("inconclusive"));
        assert_eq!(result("a5").await, None, "nothing to compare with");

        let all = counts(&store.pool, 0).await.unwrap();
        let n = |auditor: u8, o: Outcome| {
            all.iter()
                .find(|c| c.scanner == id(1) && c.auditor == id(auditor) && c.outcome == o)
                .map_or(0, |c| c.n)
        };
        assert_eq!((n(2, Outcome::Differs), n(2, Outcome::Agrees)), (1, 1));
        assert_eq!(n(2, Outcome::Inconclusive), 1);
        assert_eq!(n(3, Outcome::Differs), 1);
        // Only the auditors a node believes count; inconclusive ones never.
        assert_eq!(counted(&all, &[id(2)]).get(&id(1)), Some(&(2, 1)));
        assert_eq!(counted(&all, &[id(2), id(3)]).get(&id(1)), Some(&(3, 2)));
        assert_eq!(counted(&all, &[id(9)]).get(&id(1)), None);
        // A scanner's audit of its own scan counts for nothing.
        scan(&store, "a6", 1, Some("o1"), &[22]).await;
        settle(&store.pool).await.unwrap();
        let all = counts(&store.pool, 0).await.unwrap();
        assert_eq!(counted(&all, &[id(1), id(2)]).get(&id(1)), Some(&(2, 1)));
    }
}
