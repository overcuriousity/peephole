//! History floors: a node that keeps only a window of the history drops
//! old records and log entries locally, serves what it holds, and takes
//! history from a peer's floor. Single offline nodes fed signed entries.
use peephole::cluster::record::{IpIntelRec, MemberInfo, Record, RequestRec, WireEntry};
use peephole::cluster::{Node, NodeParams, identity::Identity, identity::NodeId};
use peephole::cluster::{history, repl};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use peephole::store::Store;
use std::sync::Arc;

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// An HLC `days` ago; `n` keeps values distinct.
fn days_ago(days: u64, n: u64) -> u64 {
    ((wall_ms() - days * 24 * 3600 * 1000) << 16) + n
}

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

    fn uid(&self, s: &str) -> String {
        format!("{}{s}", self.key().uid_prefix())
    }

    fn request(&self, name: &str) -> Record {
        Record::Request(Box::new(RequestRec {
            uid: self.uid(name),
            ts: "2026-10-01 00:00:00".into(),
            ip: "203.0.113.20".into(),
            method: "GET".into(),
            path: format!("/{name}"),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 1,
            ..Default::default()
        }))
    }

    fn describe(&self, name: &str) -> Record {
        Record::MemberUpdate(MemberInfo {
            id: self.key(),
            name: name.into(),
            address: None,
            roles: vec![],
            proto_min: 2,
            proto_max: 2,
            remote_config: false,
        })
    }
}

/// A node that trusts `peers` (from its config), keeps `retention_days`,
/// and never touches the network.
async fn offline(peers: &[&Origin], retention_days: u32) -> (Arc<Node>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let cluster = ClusterConfig {
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
    let node = Node::open(NodeParams {
        identity: Identity::generate().unwrap(),
        cluster,
        roles: Roles::default(),
        store,
        proto: (2, 2),
        data_dir: dir.path().to_path_buf(),
        retention_days,
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

fn tor(ip: &str) -> Record {
    Record::IpIntel(IpIntelRec {
        ip: ip.into(),
        provider: peephole::intel::TOR.into(),
        fetched_at: "2026-09-01 00:00:00".into(),
        source_version: None,
        data_json: r#"{"exit":true}"#.into(),
        build: String::new(),
    })
}

/// Sequences of `origin` held in the log.
async fn held(n: &Node, origin: NodeId) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM repl_log WHERE origin = ? ORDER BY seq")
        .bind(&origin.0[..])
        .fetch_all(&n.store.pool)
        .await
        .unwrap()
}

async fn floor(n: &Node, origin: NodeId) -> u64 {
    let mut conn = n.store.pool.acquire().await.unwrap();
    history::floor_of(&mut conn, &origin).await.unwrap()
}

async fn usage(n: &Node, origin: NodeId) -> (i64, i64) {
    sqlx::query_as("SELECT bytes, entries FROM origin_usage WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// a's history: a description and three records far outside a week, two
/// inside it.
fn old_and_new(a: &mut Origin) -> Vec<WireEntry> {
    vec![
        a.at(days_ago(40, 1), a.describe("alpha")),
        a.at(days_ago(40, 2), a.request("r1")),
        a.at(days_ago(40, 3), tor("203.0.113.20")),
        a.at(days_ago(30, 4), a.request("r2")),
        a.at(days_ago(1, 5), a.request("r3")),
        a.at(days_ago(0, 6), a.request("r4")),
    ]
}

/// Old records and their entries go; membership, the window and the
/// floor stay; the origin's quota counts only what is held.
#[tokio::test]
async fn pruning_drops_old_history_but_keeps_membership() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], 7).await;
    assert_eq!(apply(&x, old_and_new(&mut a)).await.applied, 6);
    let (bytes, entries) = usage(&x, a.key()).await;
    let gone: i64 = sqlx::query_scalar(
        "SELECT SUM(accounted) FROM repl_log WHERE origin = ? AND seq IN (2, 3, 4)",
    )
    .bind(&a.key().0[..])
    .fetch_one(&x.store.pool)
    .await
    .unwrap();
    assert_eq!(history::prune(&x).await.unwrap(), 3);
    assert_eq!(held(&x, a.key()).await, [1, 5, 6]);
    assert_eq!(floor(&x, a.key()).await, 5);
    assert_eq!(
        repl::head_in(&repl::heads(&x.store).await.unwrap(), &a.key()),
        6
    );
    let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM requests ORDER BY path")
        .fetch_all(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(paths, ["/r3", "/r4"]);
    for t in ["ip_intel", "ip_intel_log"] {
        assert_eq!(
            count(&x, &format!("SELECT COUNT(*) FROM {t}")).await,
            0,
            "{t}"
        );
    }
    assert_eq!(
        count(&x, "SELECT COUNT(*) FROM members WHERE name = 'alpha'").await,
        1
    );
    assert_eq!(usage(&x, a.key()).await, (bytes - gone, entries - 3));
    // Nothing more to do.
    assert_eq!(history::prune(&x).await.unwrap(), 0);
}

/// The newest entry of an origin always stays, however old.
#[tokio::test]
async fn pruning_keeps_the_newest_entry() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], 7).await;
    let old = vec![
        a.at(days_ago(40, 1), a.request("r1")),
        a.at(days_ago(30, 2), a.request("r2")),
    ];
    apply(&x, old).await;
    assert_eq!(history::prune(&x).await.unwrap(), 1);
    assert_eq!(held(&x, a.key()).await, [2]);
    assert_eq!(floor(&x, a.key()).await, 2);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 1);
}

/// A node that keeps everything prunes nothing.
#[tokio::test]
async fn a_full_node_prunes_nothing() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], 0).await;
    apply(&x, old_and_new(&mut a)).await;
    assert_eq!(history::prune(&x).await.unwrap(), 0);
    assert_eq!(held(&x, a.key()).await, [1, 2, 3, 4, 5, 6]);
    assert_eq!(floor(&x, a.key()).await, 1);
}

/// Purging an origin drops its whole log, its floor with it: unblocked
/// again, it is fetched like a new origin.
#[tokio::test]
async fn purging_an_origin_forgets_its_floor() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], 7).await;
    apply(&x, old_and_new(&mut a)).await;
    history::prune(&x).await.unwrap();
    assert_eq!(floor(&x, a.key()).await, 5);
    peephole::cluster::block::block(&x, a.key()).await.unwrap();
    peephole::cluster::block::purge(&x, a.key()).await.unwrap();
    assert_eq!(floor(&x, a.key()).await, 1);
}

async fn serve(
    n: &Node,
    origin: NodeId,
    after: u64,
    since_hlc: u64,
) -> (Vec<u64>, Vec<(NodeId, u64)>) {
    let b = repl::entries_after(
        &n.store,
        &[(origin, after)],
        since_hlc,
        1000,
        usize::MAX,
        false,
    )
    .await
    .unwrap();
    (b.entries.iter().map(|e| e.seq).collect(), b.floors)
}

/// A node serves from its floor, with the membership entries below it, and
/// says where the full history it sends starts.
#[tokio::test]
async fn a_windowed_node_serves_from_its_floor() {
    let mut a = Origin::new();
    let (x, _d) = offline(&[&a], 7).await;
    apply(&x, old_and_new(&mut a)).await;
    history::prune(&x).await.unwrap();
    assert_eq!(
        serve(&x, a.key(), 0, 0).await,
        (vec![1, 5, 6], vec![(a.key(), 5)])
    );
    assert_eq!(
        serve(&x, a.key(), 2, 0).await,
        (vec![5, 6], vec![(a.key(), 5)])
    );
    assert_eq!(serve(&x, a.key(), 4, 0).await, (vec![5, 6], vec![]));
    assert_eq!(serve(&x, a.key(), 6, 0).await, (vec![], vec![]));
}

/// A node that keeps everything sends a windowed receiver only its window
/// (and the membership before it).
#[tokio::test]
async fn a_full_node_serves_a_window_on_request() {
    let mut a = Origin::new();
    let (f, _d) = offline(&[&a], 0).await;
    apply(&f, old_and_new(&mut a)).await;
    let week = history::window_hlc(7, wall_ms());
    assert_eq!(
        serve(&f, a.key(), 0, week).await,
        (vec![1, 5, 6], vec![(a.key(), 5)])
    );
    assert_eq!(serve(&f, a.key(), 0, 0).await, ((1..=6).collect(), vec![]));
    // Already past the window start: nothing changes.
    assert_eq!(serve(&f, a.key(), 5, week).await, (vec![6], vec![]));
}

/// x keeps a week of a's history (floor 5); returns it with a's origin.
async fn windowed_holder() -> (Origin, Arc<Node>, tempfile::TempDir) {
    let mut a = Origin::new();
    let (x, d) = offline(&[&a], 7).await;
    apply(&x, old_and_new(&mut a)).await;
    history::prune(&x).await.unwrap();
    (a, x, d)
}

async fn batch_from(n: &Node, origin: NodeId, after: u64) -> peephole::cluster::sync::Batch {
    repl::entries_after(&n.store, &[(origin, after)], 0, 1000, usize::MAX, false)
        .await
        .unwrap()
}

/// A node keeping a window takes an origin's history from a peer's floor,
/// membership included.
#[tokio::test]
async fn a_windowed_node_starts_at_a_peer_floor() {
    let (a, x, _d) = windowed_holder().await;
    let (w, _e) = offline(&[&a], 7).await;
    let st = repl::apply_batch_with(&w, batch_from(&x, a.key(), 0).await, |_| true)
        .await
        .unwrap();
    assert_eq!((st.applied, st.rejected), (3, 0), "{st:?}");
    assert_eq!(held(&w, a.key()).await, [1, 5, 6]);
    assert_eq!(floor(&w, a.key()).await, 5);
    assert_eq!(count(&w, "SELECT COUNT(*) FROM requests").await, 2);
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM members WHERE name = 'alpha'").await,
        1
    );
    // Offered again: nothing new.
    let st = repl::apply_batch_with(&w, batch_from(&x, a.key(), 0).await, |_| true)
        .await
        .unwrap();
    assert_eq!(st.applied, 0);
}

/// A node that keeps everything never skips history, also one that once
/// kept a window (it keeps its floor and waits for a full member).
#[tokio::test]
async fn a_full_node_rejects_a_jump() {
    let (mut a, x, _d) = windowed_holder().await;
    let (f, _e) = offline(&[&a], 0).await;
    // Only what follows on from what it holds (seq 1 does).
    let st = repl::apply_batch(&f, batch_from(&x, a.key(), 0).await)
        .await
        .unwrap();
    assert_eq!((st.applied, st.rejected), (1, 2), "{st:?}");
    assert_eq!(held(&f, a.key()).await, [1]);
    // Holding 1..=2, offered 5.. : still a gap.
    a.seq = 1;
    let second = old_and_new(&mut a).into_iter().take(1).collect();
    apply(&f, second).await;
    let st = repl::apply_batch(&f, batch_from(&x, a.key(), 2).await)
        .await
        .unwrap();
    assert_eq!(st.applied, 0, "{st:?}");
    assert_eq!(held(&f, a.key()).await, [1, 2]);
    assert_eq!(floor(&f, a.key()).await, 1);
}

/// A windowed node that fell behind every peer's floor (offline for longer
/// than the window) moves its floor up instead of stalling; the history
/// below goes with the next prune.
#[tokio::test]
async fn a_windowed_node_jumps_to_a_peer_floor() {
    let (mut a, x, _d) = windowed_holder().await;
    let (w, _e) = offline(&[&a], 7).await;
    a.seq = 0;
    let first = old_and_new(&mut a).into_iter().take(2).collect();
    apply(&w, first).await;
    let st = repl::apply_batch_with(&w, batch_from(&x, a.key(), 2).await, |_| true)
        .await
        .unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    assert_eq!(floor(&w, a.key()).await, 5);
    assert_eq!(held(&w, a.key()).await, [1, 2, 5, 6]);
    history::prune(&w).await.unwrap();
    assert_eq!(held(&w, a.key()).await, [1, 5, 6]);
    assert_eq!(
        count(&w, "SELECT COUNT(*) FROM requests WHERE path = '/r1'").await,
        0
    );
}

/// Whether a sponsor was silent for 30 days before an admission cannot be
/// judged across a gap in its history: the admission stands.
#[tokio::test]
async fn an_admission_after_a_gap_in_the_sponsors_history_counts() {
    let (mut a, mut b, c) = (Origin::new(), Origin::new(), Origin::new());
    let (w, _d) = offline(&[&b], 7).await;
    let admit = |o: &Origin| {
        Record::MemberAdd(MemberInfo {
            id: o.key(),
            name: "m".into(),
            address: None,
            roles: vec![],
            proto_min: 2,
            proto_max: 2,
            remote_config: false,
        })
    };
    // b admitted a 100 days ago; a's history up to seq 4 is not held.
    let b1 = b.at(days_ago(100, 1), admit(&a));
    a.seq = 4;
    let a5 = a.at(days_ago(1, 2), admit(&c));
    let batch = peephole::cluster::sync::Batch {
        entries: vec![b1, a5],
        proofs: vec![],
        floors: vec![(a.key(), 5)],
        bounds: vec![],
        membership: vec![],
    };
    let st = repl::apply_batch_with(&w, batch, |_| true).await.unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    let admitted: i64 = sqlx::query_scalar("SELECT admitted_hlc FROM members WHERE id = ?")
        .bind(&c.key().0[..])
        .fetch_one(&w.store.pool)
        .await
        .unwrap();
    assert!(admitted > 0);
}

/// A batch cut short after the membership below a sender's start still
/// moves the floor (and the head) to that start, so what follows connects
/// there and nothing in between is taken as held.
#[tokio::test]
async fn the_floor_moves_before_the_membership_below_it() {
    let (a, x, _d) = windowed_holder().await;
    let (w, _e) = offline(&[&a], 7).await;
    let cut_short = repl::entries_after(&x.store, &[(a.key(), 0)], 0, 1, usize::MAX, false)
        .await
        .unwrap();
    assert_eq!(cut_short.entries.len(), 1);
    repl::apply_batch_with(&w, cut_short, |_| true)
        .await
        .unwrap();
    assert_eq!(floor(&w, a.key()).await, 5);
    // The rest connects (asked for after what is held).
    let st = repl::apply_batch_with(&w, batch_from(&x, a.key(), 1).await, |_| true)
        .await
        .unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
}

/// A windowed node skips history only on proof that what it skips is
/// older than its window (the signed entry right before the start), or
/// when its own sync round allows it (no peer keeping more is reachable).
/// A declared start alone — e.g. pushed by a member — is not enough.
#[tokio::test]
async fn a_jump_needs_proof_or_permission() {
    let (a, x, _d) = windowed_holder().await;
    let (w, _e) = offline(&[&a], 7).await;
    // Only what connects (seq 1); nothing is skipped.
    let st = repl::apply_batch(&w, batch_from(&x, a.key(), 0).await)
        .await
        .unwrap();
    assert_eq!((st.applied, st.rejected), (1, 2), "{st:?}");
    assert_eq!(held(&w, a.key()).await, [1]);
    assert_eq!(floor(&w, a.key()).await, 1);
    // From a node holding everything, the window comes with its proof.
    let mut a = a;
    a.seq = 0;
    let (f, _g) = offline(&[&a], 0).await;
    apply(&f, old_and_new(&mut a)).await;
    let week = history::window_hlc(7, wall_ms());
    let proven = repl::entries_after(&f.store, &[(a.key(), 0)], week, 1000, usize::MAX, false)
        .await
        .unwrap();
    assert_eq!(proven.bounds.len(), 1);
    let st = repl::apply_batch(&w, proven).await.unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    assert_eq!(held(&w, a.key()).await, [1, 5, 6]);
}

/// A windowed node cut off from every peer keeps its own records, however
/// old, until a peer is known to hold them: they may be the only copy.
#[tokio::test]
async fn own_history_stays_until_a_peer_holds_it() {
    let a = Origin::new();
    let (x, _d) = offline(&[&a], 7).await;
    let me = x.id();
    let r = peephole::store::recorder::Recorder::Cluster(x.clone());
    let ip = x
        .store
        .upsert_ip("203.0.113.9".parse().unwrap())
        .await
        .unwrap();
    for path in ["/mine1", "/mine2"] {
        r.insert_request(&peephole::store::requests::NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    }
    // Age everything of ours past the window.
    sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
        .bind(days_ago(40, 0) as i64)
        .bind(&me.0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    let head = held(&x, me).await.last().copied().unwrap() as u64;
    assert_eq!(history::prune(&x).await.unwrap(), 0);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 2);
    // A peer holds all but our newest entry.
    x.own_acked
        .store(head - 1, std::sync::atomic::Ordering::Relaxed);
    assert!(history::prune(&x).await.unwrap() > 0);
    assert_eq!(floor(&x, me).await, head);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 1);
}
