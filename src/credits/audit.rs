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
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::time::Instant;

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

/// An audit must start within this long after the audited scan ended: the
/// source may be gone later, and a late audit proves little.
pub const AUDIT_WINDOW_MS: u64 = 30 * 60 * 1000;
/// Audits waiting for a free worker.
const MAX_WAITING: usize = 1000;

/// A scan of another node to run again.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub scan_uid: String,
    pub job_uid: String,
    pub ip: String,
    pub level: u8,
    /// Wall-clock milliseconds after which it is dropped.
    pub deadline_ms: u64,
}

/// Chooses the scans this scanner audits: each fresh scan of another node
/// with probability `share`, from this node's own random source. Nobody
/// can predict or verify the choice, and nobody needs to.
pub struct Picker {
    share: f64,
    /// The newest scan row looked at; None before the first look.
    last_id: Option<i64>,
    queue: VecDeque<Task>,
    /// When this scanner started its audits of the last hour.
    started: VecDeque<Instant>,
}

fn chance(share: f64) -> bool {
    if share >= 1.0 {
        return true;
    }
    let mut b = [0u8; 4];
    if aws_lc_rs::rand::fill(&mut b).is_err() {
        return false;
    }
    (u32::from_le_bytes(b) as f64) < share * (u32::MAX as f64 + 1.0)
}

/// A row time (`YYYY-MM-DD HH:MM:SS`, UTC) as wall-clock milliseconds.
fn ms_of(ts: &str) -> Option<u64> {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|t| t.and_utc().timestamp_millis().max(0) as u64)
}

/// Scans read per look; a burst larger than this is read over several.
const POLL_BATCH: i64 = 500;

impl Picker {
    pub fn new(share: f64) -> Self {
        Self {
            share,
            last_id: None,
            queue: VecDeque::new(),
            started: VecDeque::new(),
        }
    }

    /// Look at the scans that arrived since the last look and pick some of
    /// those other nodes ran.
    pub async fn poll(&mut self, pool: &SqlitePool, me: &NodeId) -> Result<()> {
        if self.share <= 0.0 {
            return Ok(());
        }
        let Some(last) = self.last_id else {
            // What was there before this scanner started is not audited.
            let max: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM scans")
                .fetch_one(pool)
                .await?;
            self.last_id = Some(max.unwrap_or(0));
            return Ok(());
        };
        // The mark moves to `top` only once every row up to it was read:
        // rows of this node's own scans and of audits move it too, and
        // rows that arrive meanwhile lie above it.
        let top: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM scans")
            .fetch_one(pool)
            .await?;
        let rows: Vec<(i64, String, String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT s.id, s.uid, s.job_uid, i.ip, s.level, s.finished_at
             FROM scans s JOIN ips i ON i.id = s.ip_id
             WHERE s.id > ? AND s.id <= ? AND s.audit_of IS NULL AND s.uid IS NOT NULL
               AND s.job_uid IS NOT NULL AND s.origin IS NOT NULL AND s.origin != ?
             ORDER BY s.id LIMIT ?",
        )
        .bind(last)
        .bind(top)
        .bind(&me.0[..])
        .bind(POLL_BATCH)
        .fetch_all(pool)
        .await?;
        let all_read = rows.len() < POLL_BATCH as usize;
        let now = hlc::wall_ms();
        for (id, scan_uid, job_uid, ip, level, finished_at) in rows {
            self.last_id = Some(id);
            let Some(ended) = finished_at.as_deref().and_then(ms_of) else {
                continue;
            };
            let deadline_ms = ended + AUDIT_WINDOW_MS;
            if now >= deadline_ms || !(1..=4).contains(&level) || !chance(self.share) {
                continue;
            }
            if self.queue.len() < MAX_WAITING {
                self.queue.push_back(Task {
                    scan_uid,
                    job_uid,
                    ip,
                    level: level as u8,
                    deadline_ms,
                });
            }
        }
        if all_read {
            self.last_id = Some(top.max(last));
        }
        Ok(())
    }

    /// The next audit to start now: still in time, and not of a level in
    /// `exclude` (the scanner is at its share of that level).
    pub fn take(&mut self, exclude: &[u8]) -> Option<Task> {
        let now = hlc::wall_ms();
        self.queue.retain(|t| t.deadline_ms > now);
        let i = self
            .queue
            .iter()
            .position(|t| !exclude.contains(&t.level))?;
        self.queue.remove(i)
    }

    /// An audit was started: it counts against the scanner's hourly limit.
    pub fn started(&mut self) {
        self.started.push_back(Instant::now());
    }

    pub fn started_last_hour(&mut self) -> i64 {
        let hour = std::time::Duration::from_secs(3600);
        while self.started.front().is_some_and(|t| t.elapsed() >= hour) {
            self.started.pop_front();
        }
        self.started.len() as i64
    }
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

    /// A scan row by `origin` that finished `mins_ago` minutes ago.
    async fn finished(store: &Store, uid: &str, origin: u8, mins_ago: i64, level: i64) {
        let id = scan(store, uid, origin, None, &[22]).await;
        sqlx::query("UPDATE scans SET level = ?, finished_at = datetime('now', ?) WHERE id = ?")
            .bind(level)
            .bind(format!("-{mins_ago} minutes"))
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fresh_scans_of_other_nodes_are_picked_by_chance() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let me = id(9);
        finished(&store, "before", 1, 1, 1).await;
        let mut all = Picker::new(1.0);
        let mut none = Picker::new(0.0);
        // The first look only notes where the table stands.
        all.poll(&store.pool, &me).await.unwrap();
        none.poll(&store.pool, &me).await.unwrap();
        assert!(all.take(&[]).is_none());

        finished(&store, "fresh", 1, 1, 1).await;
        finished(&store, "mine", 9, 1, 1).await;
        finished(&store, "late", 1, 31, 1).await;
        finished(&store, "big", 1, 2, 4).await;
        scan(&store, "an-audit", 1, Some("fresh"), &[22]).await;
        all.poll(&store.pool, &me).await.unwrap();
        none.poll(&store.pool, &me).await.unwrap();
        assert!(none.take(&[]).is_none(), "share 0 audits nothing");

        // Level 4 is held back while this scanner is at its level-4 share.
        let t = all.take(&[4]).expect("the fresh scan of another node");
        assert_eq!(
            (t.scan_uid.as_str(), t.job_uid.as_str(), t.level),
            ("fresh", "job", 1)
        );
        assert_eq!(t.ip, "203.0.113.9");
        assert!(all.take(&[4]).is_none());
        assert_eq!(all.take(&[]).unwrap().scan_uid, "big");
        assert!(
            all.take(&[]).is_none(),
            "not its own, not an old one, not an audit"
        );
        // Seen once: the next look does not offer them again.
        all.poll(&store.pool, &me).await.unwrap();
        assert!(all.take(&[]).is_none());

        // An audit that was not started in time is dropped.
        finished(&store, "slow", 1, 29, 1).await;
        all.poll(&store.pool, &me).await.unwrap();
        all.queue[0].deadline_ms = hlc::wall_ms() - 1;
        assert!(all.take(&[]).is_none());

        assert_eq!(all.started_last_hour(), 0);
        all.started();
        all.started();
        assert_eq!(all.started_last_hour(), 2);
    }

    /// A burst larger than one look is read over several: the mark does
    /// not jump past the rows that were not read yet.
    #[tokio::test]
    async fn a_burst_of_scans_is_read_whole() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let me = id(9);
        let mut p = Picker::new(1.0);
        p.poll(&store.pool, &me).await.unwrap();
        for i in 0..POLL_BATCH {
            finished(&store, &format!("late-{i}"), 1, 31, 1).await;
        }
        finished(&store, "fresh", 1, 1, 1).await;
        p.poll(&store.pool, &me).await.unwrap();
        assert!(p.take(&[]).is_none(), "the first look reads the late ones");
        p.poll(&store.pool, &me).await.unwrap();
        assert_eq!(p.take(&[]).unwrap().scan_uid, "fresh");
    }
}
