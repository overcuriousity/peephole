//! What a hostile or careless member cannot do to a node: invalid or
//! excessive scan jobs, premature or grinded job takeovers, sybil
//! admissions, unbounded parking and storage, future-dated timestamps.
//! Single offline nodes fed signed entries directly.
use peephole::cluster::record::{
    IntelManifestRec, IpIntelRec, JobAdoptRec, JobStatusRec, MemberInfo, Record, RequestRec,
    ScanJobRec, WireEntry,
};
use peephole::cluster::{Node, NodeParams, block, identity::Identity, identity::NodeId};
use peephole::cluster::{members, repl};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use peephole::store::Store;
use std::sync::Arc;

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// An HLC `ms` from now (negative: in the past); `n` keeps values distinct.
fn hlc_in(ms: i64, n: u64) -> u64 {
    (((wall_ms() as i64 + ms) as u64) << 16) + n
}

const HOUR: i64 = 3600 * 1000;
const DAY: i64 = 24 * HOUR;

/// A node signing entries by hand, numbering them itself.
struct Origin {
    id: Identity,
    seq: u64,
}

impl Origin {
    fn new() -> Self {
        Self {
            id: Identity::generate().unwrap(),
            seq: 0,
        }
    }

    fn key(&self) -> NodeId {
        self.id.id
    }

    fn at(&mut self, hlc: u64, r: Record) -> WireEntry {
        self.seq += 1;
        WireEntry::sign(&self.id, self.seq, hlc, &r).unwrap()
    }

    fn now(&mut self, r: Record) -> WireEntry {
        let n = self.seq;
        self.at(hlc_in(0, n), r)
    }

    fn uid(&self, s: &str) -> String {
        format!("{}{s}", self.key().uid_prefix())
    }
}

fn info(id: NodeId, name: &str) -> MemberInfo {
    MemberInfo {
        id,
        name: name.into(),
        address: None,
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
        remote_config: false,
    }
}

/// A node that trusts `peers` (from its config) and never touches the
/// network.
async fn offline(
    peers: &[&Origin],
    tweak: impl FnOnce(&mut ClusterConfig),
) -> (Arc<Node>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let mut cluster = ClusterConfig {
        node_name: "x".into(),
        listen: "127.0.0.1:0".parse().unwrap(),
        advertise: None,
        key_path: None,
        takeover_hours: 6.0,
        lease_secs: 120,
        remote_config: false,
        origin_quota_mb: 20 * 1024,
        peers: peers
            .iter()
            .enumerate()
            .map(|(i, p)| PeerConfig {
                name: format!("p{i}"),
                address: "127.0.0.1:1".into(),
                public_key: p.key().to_string(),
            })
            .collect(),
    };
    tweak(&mut cluster);
    let node = Node::open(NodeParams {
        identity: Identity::generate().unwrap(),
        cluster,
        roles: Roles::default(),
        store,
        proto: (2, 2),
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();
    (node, dir)
}

async fn count(n: &Node, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

async fn apply(n: &Node, entries: Vec<WireEntry>) -> repl::Applied {
    repl::apply_batch(n, entries).await.unwrap()
}

fn job(o: &Origin, uid: &str, ip: &str, level: i64) -> Record {
    Record::ScanJob(ScanJobRec {
        uid: o.uid(uid),
        ip: ip.into(),
        level,
        queued_at: "2026-10-01 00:00:00".into(),
    })
}

fn request(o: &Origin, uid: &str) -> Record {
    Record::Request(RequestRec {
        uid: o.uid(uid),
        ts: "2026-10-01 00:00:00".into(),
        ip: "203.0.113.20".into(),
        method: "GET".into(),
        path: format!("/{uid}"),
        query: None,
        headers_json: "[]".into(),
        body: None,
        labels_json: "[]".into(),
        severity: 1,
        scan_level: 0,
        is_fp_claim: false,
        page_token: None,
        ..Default::default()
    })
}

async fn arbiter_of(n: &Node, uid: &str) -> Option<Vec<u8>> {
    sqlx::query_scalar("SELECT arbiter FROM scan_jobs WHERE uid = ?")
        .bind(uid)
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

async fn log_state(n: &Node, origin: NodeId, seq: u64) -> i64 {
    sqlx::query_scalar("SELECT applied FROM repl_log WHERE origin = ? AND seq = ?")
        .bind(&origin.0[..])
        .bind(seq as i64)
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// A member's scan jobs must name a level the scanners know and a public
/// address, and come at a sane rate.
#[tokio::test]
async fn replicated_scan_jobs_are_validated_and_rate_limited() {
    let (mut a, mut b) = (Origin::new(), Origin::new());
    let (x, _d) = offline(&[&a, &b], |_| {}).await;
    let entries = vec![
        a.now(job(&a, "l0", "203.0.113.5", 0)),
        a.now(job(&a, "l99", "203.0.113.5", 99)),
        a.now(job(&a, "lan", "10.0.0.1", 2)),
        a.now(job(&a, "lo", "127.0.0.1", 2)),
        a.now(job(&a, "junk", "not-an-ip", 2)),
        a.now(job(&a, "meta", "169.254.169.254", 2)),
        a.now(job(&a, "ok", "203.0.113.5", 2)),
    ];
    let st = apply(&x, entries).await;
    assert_eq!(st.applied, 7, "all logged and relayed: {st:?}");
    let uids: Vec<String> = sqlx::query_scalar("SELECT uid FROM scan_jobs")
        .fetch_all(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(uids, vec![a.uid("ok")]);

    // At most SCAN_JOBS_PER_HOUR per origin and hour.
    let limit = peephole::store::data::SCAN_JOBS_PER_HOUR as usize;
    let flood: Vec<WireEntry> = (0..=limit)
        .map(|i| {
            let r = job(
                &b,
                &format!("f{i}"),
                &format!("198.51.100.{}", i % 250 + 1),
                1,
            );
            b.at(hlc_in(-HOUR / 2, i as u64), r)
        })
        .collect();
    apply(&x, flood).await;
    let origin_jobs = format!(
        "SELECT COUNT(*) FROM scan_jobs WHERE origin = x'{}'",
        hex(&b.key())
    );
    assert_eq!(count(&x, &origin_jobs).await, limit as i64);
}

fn hex(id: &NodeId) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// A takeover applies only once this node itself considers the job's
/// arbiter silent or the job stale; contested takeovers are settled by a
/// rank nobody can grind; blocked nodes cannot take jobs over.
#[tokio::test]
async fn job_takeovers_are_judged_locally() {
    let (mut a, mut b, mut c) = (Origin::new(), Origin::new(), Origin::new());
    let (x, _dx) = offline(&[&a, &b, &c], |_| {}).await;
    let (y, _dy) = offline(&[&a, &b, &c], |_| {}).await;

    // A fresh job of a live arbiter: B's takeover waits.
    let fresh = a.now(job(&a, "fresh", "203.0.113.30", 2));
    apply(&x, vec![fresh]).await;
    let adopt = |o: &mut Origin, from: NodeId, uid: String| {
        o.now(Record::JobAdopt(JobAdoptRec {
            from,
            job_uids: vec![uid],
        }))
    };
    let early = adopt(&mut b, a.key(), a.uid("fresh"));
    let early_seq = early.seq;
    apply(&x, vec![early]).await;
    assert_eq!(
        arbiter_of(&x, &a.uid("fresh")).await,
        Some(a.key().0.to_vec())
    );
    assert_eq!(log_state(&x, b.key(), early_seq).await, 0, "deferred");
    // Time passes without the job changing: the takeover becomes due.
    sqlx::query("UPDATE scan_jobs SET hlc = ? WHERE uid = ?")
        .bind(hlc_in(-7 * HOUR, 0) as i64)
        .bind(a.uid("fresh"))
        .execute(&x.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE repl_log SET retry_after = 0")
        .execute(&x.store.pool)
        .await
        .unwrap();
    repl::retry_due(&x).await.unwrap();
    assert_eq!(
        arbiter_of(&x, &a.uid("fresh")).await,
        Some(b.key().0.to_vec())
    );
    assert_eq!(log_state(&x, b.key(), early_seq).await, 1);

    // Contested: B and C adopt the same stale job; both orders agree, and
    // the winner is the lower hash rank, not the lower key.
    let stale = a.at(hlc_in(-7 * HOUR, 0), job(&a, "stale", "203.0.113.31", 2));
    let by_b = adopt(&mut b, a.key(), a.uid("stale"));
    let by_c = adopt(&mut c, a.key(), a.uid("stale"));
    apply(&x, vec![stale.clone()]).await;
    apply(&x, vec![by_b.clone()]).await;
    apply(&x, vec![by_c.clone()]).await;
    // Y gets the same history in the other order.
    let a_log = repl::entries_after(&x.store, &[(a.key(), 0)], 100, usize::MAX)
        .await
        .unwrap();
    apply(&y, a_log.entries).await;
    let c_log = repl::entries_after(&x.store, &[(c.key(), 0)], 100, usize::MAX)
        .await
        .unwrap();
    apply(&y, c_log.entries).await;
    let b_log = repl::entries_after(&x.store, &[(b.key(), 0)], 100, usize::MAX)
        .await
        .unwrap();
    apply(&y, b_log.entries).await;
    let uid = a.uid("stale");
    let rank = |k: &NodeId| peephole::store::data::adopt_rank(&uid, k);
    let winner = if rank(&b.key()) < rank(&c.key()) {
        b.key()
    } else {
        c.key()
    };
    assert_eq!(arbiter_of(&x, &uid).await, Some(winner.0.to_vec()));
    assert_eq!(arbiter_of(&y, &uid).await, Some(winner.0.to_vec()));

    // A node blocked here takes nothing over here.
    let mut d = Origin::new();
    apply(&x, vec![a.now(Record::MemberAdd(info(d.key(), "d")))]).await;
    block::block(&x, d.key()).await.unwrap();
    let other = a.at(hlc_in(-7 * HOUR, 1), job(&a, "other", "203.0.113.32", 2));
    apply(&x, vec![other]).await;
    let by_d = adopt(&mut d, a.key(), a.uid("other"));
    apply(&x, vec![by_d]).await;
    assert_eq!(
        arbiter_of(&x, &a.uid("other")).await,
        Some(a.key().0.to_vec())
    );
}

/// A job left "running" by an arbiter that never finishes it does not keep
/// its IP from being scanned again.
#[tokio::test]
async fn dead_running_jobs_do_not_shield_their_ip() {
    use peephole::store::recorder::Recorder;
    use peephole::store::scans::EnqueueOutcome;
    let (x, _d) = offline(&[], |_| {}).await;
    let rec = Recorder::Cluster(x.clone());
    let ip = x
        .store
        .upsert_ip("203.0.113.40".parse().unwrap())
        .await
        .unwrap();
    rec.enqueue_scan(ip.id, 4, 24).await.unwrap();
    sqlx::query("UPDATE scan_jobs SET status = 'running', started_at = datetime('now')")
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert!(matches!(
        rec.enqueue_scan(ip.id, 1, 24).await.unwrap(),
        EnqueueOutcome::Cooldown
    ));
    // A level-4 scan may run for hours: still shielding after 6 h.
    sqlx::query("UPDATE scan_jobs SET started_at = datetime('now', '-6 hours')")
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert!(matches!(
        rec.enqueue_scan(ip.id, 1, 24).await.unwrap(),
        EnqueueOutcome::Cooldown
    ));
    // Longer than any scan may run: dead.
    sqlx::query("UPDATE scan_jobs SET started_at = datetime('now', '-14 hours')")
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert!(matches!(
        rec.enqueue_scan(ip.id, 1, 24).await.unwrap(),
        EnqueueOutcome::Queued(_)
    ));
}

/// Admissions are limited per sponsor and day; a node that left admits
/// nobody; blocking a sponsor's subtree catches what it admitted.
#[tokio::test]
async fn admissions_are_limited_per_sponsor() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], |_| {}).await;
    let limit = members::ADMISSIONS_PER_DAY as usize;
    let mut ids: Vec<Origin> = (0..2 * limit + 1).map(|_| Origin::new()).collect();
    // Two days ago: a day's worth. Now: another, and one too many.
    let mut entries = vec![];
    for (i, m) in ids.iter().enumerate() {
        let hlc = if i < limit {
            hlc_in(-2 * DAY, i as u64)
        } else {
            hlc_in(0, i as u64)
        };
        entries.push(a.at(hlc, Record::MemberAdd(info(m.key(), &format!("m{i}")))));
    }
    apply(&x, entries).await;
    let admitted = |id: NodeId| {
        let x = x.clone();
        async move {
            members::all(&x.store)
                .await
                .unwrap()
                .iter()
                .any(|m| m.id == id && m.standing != members::Standing::NotAdmitted)
        }
    };
    for m in &ids[..2 * limit] {
        assert!(admitted(m.key()).await);
    }
    assert!(
        !admitted(ids[2 * limit].key()).await,
        "over the daily limit"
    );

    // A member that left cannot admit anyone afterwards.
    let m0 = &mut ids[0];
    let z = Identity::generate().unwrap();
    let left = vec![
        m0.now(Record::MemberUpdate(info(m0.key(), "m0"))),
        m0.now(Record::MemberRevoke { id: m0.key() }),
        m0.now(Record::MemberAdd(info(z.id, "z"))),
    ];
    apply(&x, left).await;
    assert!(!admitted(z.id).await);

    // Blocking A's subtree blocks everything it admitted, not this node.
    let (blocked, _) = block::block_subtree(&x, a.key()).await.unwrap();
    assert_eq!(blocked.len(), 1 + 2 * limit);
    assert!(x.is_blocked(&a.key()) && x.is_blocked(&ids[1].key()));
    assert!(!x.is_blocked(&x.id()));
}

/// Entries of a node nobody admitted are parked only up to a small limit,
/// are not asked for once that is full, and expire.
#[tokio::test]
async fn parking_for_unknown_nodes_is_bounded_and_expires() {
    let mut u = Origin::new();
    let (x, _d) = offline(&[], |_| {}).await;
    let entries: Vec<WireEntry> = (0..150)
        .map(|i| u.now(Record::MemberUpdate(info(u.key(), &format!("u{i}")))))
        .collect();
    let st = apply(&x, entries).await;
    let cap = repl::PARK_UNTRUSTED_ENTRIES as usize;
    assert_eq!((st.parked, st.rejected), (cap, 150 - cap), "{st:?}");
    assert!(repl::refused_origins(&x).await.unwrap().contains(&u.key()));
    let relayed = repl::entries_after(&x.store, &[(u.key(), 0)], 10_000, usize::MAX)
        .await
        .unwrap();
    assert_eq!(relayed.entries.len(), cap);

    sqlx::query("UPDATE repl_pending SET received_at = datetime('now', '-8 days')")
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(repl::expire_parked(&x).await.unwrap(), 1);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM repl_pending").await, 0);
    let heads = repl::heads(&x.store).await.unwrap();
    assert_eq!(repl::head_in(&heads, &u.key()), 0, "fetched again later");
}

/// Over its storage quota an origin's stream stops here; a purge deletes a
/// blocked node's entries and stops relaying it until it is unblocked.
#[tokio::test]
async fn quota_and_purge() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], |c| c.origin_quota_mb = 1).await;
    let st = apply(&x, vec![a.now(request(&a, "r1"))]).await;
    assert_eq!(st.applied, 1);
    sqlx::query("UPDATE origin_usage SET bytes = 2 * 1024 * 1024 WHERE origin = ?")
        .bind(&a.key().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    let over = a.now(request(&a, "r2"));
    let st = apply(&x, vec![over.clone()]).await;
    assert_eq!((st.applied, st.rejected), (0, 1));
    assert!(repl::refused_origins(&x).await.unwrap().contains(&a.key()));
    sqlx::query("UPDATE origin_usage SET bytes = 0")
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(apply(&x, vec![over]).await.applied, 1);

    // Purge needs a block first.
    assert!(block::purge(&x, a.key()).await.is_err());
    block::block(&x, a.key()).await.unwrap();
    assert!(block::purge(&x, a.key()).await.unwrap() >= 2);
    let a_log = format!(
        "SELECT COUNT(*) FROM repl_log WHERE origin = x'{}'",
        hex(&a.key())
    );
    assert_eq!(count(&x, &a_log).await, 0);
    let st = apply(&x, vec![a.now(request(&a, "r3"))]).await;
    assert_eq!(st.rejected, 1);
    assert!(
        repl::entries_after(&x.store, &[(a.key(), 0)], 100, usize::MAX)
            .await
            .unwrap()
            .entries
            .is_empty(),
        "not relayed"
    );
    // Unblocking fetches everything again.
    block::unblock(&x, a.key()).await.unwrap();
    let heads = repl::heads(&x.store).await.unwrap();
    assert_eq!(repl::head_in(&heads, &a.key()), 0);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM purged_origins").await, 0);
}

/// Deferred entries back off, become due when their parent arrives, and
/// are given up after a week.
#[tokio::test]
async fn deferred_entries_back_off_and_give_up() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], |_| {}).await;
    let status = |o: &Origin, uid: &str| {
        Record::JobStatus(JobStatusRec {
            job_uid: o.uid(uid),
            status: "done".into(),
            started_at: None,
            finished_at: None,
            error: None,
            attempts: 1,
            scanner: None,
        })
    };
    let early = a.now(status(&a, "j1"));
    let seq = early.seq;
    apply(&x, vec![early]).await;
    let (applied, attempts, after, wait): (i64, i64, i64, Option<String>) = sqlx::query_as(
        "SELECT applied, retry_attempts, retry_after, wait_uid FROM repl_log
         WHERE origin = ? AND seq = ?",
    )
    .bind(&a.key().0[..])
    .bind(seq as i64)
    .fetch_one(&x.store.pool)
    .await
    .unwrap();
    assert_eq!((applied, attempts), (0, 1));
    assert!(after as u64 > wall_ms(), "backs off");
    assert_eq!(wait, Some(a.uid("j1")));
    // Its job arrives (by another route, A's own job here): the status
    // applies at once, without waiting for the backoff.
    let mut b = Origin::new();
    apply(&x, vec![a.now(Record::MemberAdd(info(b.key(), "b")))]).await;
    let j = a.now(job(&a, "j1", "203.0.113.50", 1));
    apply(&x, vec![j]).await;
    let st: String = sqlx::query_scalar("SELECT status FROM scan_jobs")
        .fetch_one(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(st, "done");
    assert_eq!(log_state(&x, a.key(), seq).await, 1);

    // A status for a job that never comes is given up after a week.
    let orphan = b.now(Record::JobStatus(JobStatusRec {
        job_uid: b.uid("never"),
        status: "done".into(),
        started_at: None,
        finished_at: None,
        error: None,
        attempts: 1,
        scanner: None,
    }));
    let oseq = orphan.seq;
    apply(&x, vec![orphan]).await;
    sqlx::query(
        "UPDATE repl_log SET retry_after = 0, received_at = datetime('now', '-8 days')
         WHERE origin = ?",
    )
    .bind(&b.key().0[..])
    .execute(&x.store.pool)
    .await
    .unwrap();
    repl::retry_due(&x).await.unwrap();
    assert_eq!(log_state(&x, b.key(), oseq).await, 3);
}

/// Timestamps from the future buy nothing: results, announcements and
/// liveness are ordered by the time this node received them (plus the
/// allowed drift), and a blocked node's announcement is not used.
#[tokio::test]
async fn future_dated_entries_are_ordered_by_their_receipt() {
    let (mut a, mut b) = (Origin::new(), Origin::new());
    let (x, _d) = offline(&[&a, &b], |_| {}).await;
    let far = hlc_in(400 * DAY, 0);
    let latest = ((wall_ms() + 5 * 60 * 1000 + 60_000) << 16) as i64;
    apply(
        &x,
        vec![
            a.now(request(&a, "r")),
            a.at(
                far,
                Record::IpIntel(IpIntelRec {
                    ip: "203.0.113.20".into(),
                    provider: "tor-exits".into(),
                    fetched_at: "2026-10-01 00:00:00".into(),
                    source_version: None,
                    data_json: r#"{"exit":true}"#.into(),
                }),
            ),
            a.at(
                far + 1,
                Record::IntelManifest(IntelManifestRec {
                    kind: "tor-exits".into(),
                    sha256: "aa".repeat(32),
                    size: 10,
                    fetched_at: "2099-01-01 00:00:00".into(),
                }),
            ),
        ],
    )
    .await;
    let h: i64 = sqlx::query_scalar("SELECT hlc FROM ip_intel")
        .fetch_one(&x.store.pool)
        .await
        .unwrap();
    assert!(h > 0 && h < latest, "clamped to receipt + drift");
    let m = peephole::intel::share::manifests(&x.store).await.unwrap();
    let tor = &m["tor-exits"];
    assert!(tor.fetched_at.as_str() < "2099", "{}", tor.fetched_at);
    assert!(tor.age_hours() > -1.0);

    // B announces an older version; once A is blocked, B's is used.
    apply(
        &x,
        vec![b.at(
            hlc_in(-HOUR, 0),
            Record::IntelManifest(IntelManifestRec {
                kind: "tor-exits".into(),
                sha256: "bb".repeat(32),
                size: 10,
                fetched_at: "2026-10-01 00:00:00".into(),
            }),
        )],
    )
    .await;
    assert_eq!(
        peephole::intel::share::manifests(&x.store).await.unwrap()["tor-exits"].sha256,
        "aa".repeat(32)
    );
    block::block(&x, a.key()).await.unwrap();
    assert_eq!(
        peephole::intel::share::manifests(&x.store).await.unwrap()["tor-exits"].sha256,
        "bb".repeat(32)
    );

    // Liveness: A's last entry claims to be from the future, but it was
    // received 31 days ago and nothing since: pruned.
    let old = hlc_in(-40 * DAY, 0) as i64;
    sqlx::query("UPDATE repl_log SET received_at = datetime('now', '-31 days') WHERE origin = ?")
        .bind(&a.key().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE members SET admitted_hlc = ? WHERE id = ?")
        .bind(old)
        .bind(&a.key().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    let rows = members::all(&x.store).await.unwrap();
    let ma = rows.iter().find(|m| m.id == a.key()).unwrap();
    assert_eq!(ma.standing, members::Standing::Pruned);
}

/// Member descriptions are cleaned on apply: nobody can make other nodes
/// dial an arbitrary string or show control characters.
#[tokio::test]
async fn member_descriptions_are_cleaned_on_apply() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], |_| {}).await;
    let n = Identity::generate().unwrap();
    let mut bad = info(n.id, "\u{1b}[31mred");
    bad.address = Some("evil host;rm -rf:1".into());
    bad.roles = vec!["scanner".into(), "root".into()];
    apply(&x, vec![a.now(Record::MemberAdd(bad))]).await;
    let rows = members::all(&x.store).await.unwrap();
    let m = rows.iter().find(|m| m.id == n.id).unwrap();
    assert_eq!(m.name, format!("node-{}", n.id.short()));
    assert_eq!(m.address, None);
    assert_eq!(m.roles, vec!["scanner".to_string()]);
}
