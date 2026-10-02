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
        Record::Request(RequestRec {
            uid: self.uid(name),
            ts: "2026-10-01 00:00:00".into(),
            ip: "203.0.113.20".into(),
            method: "GET".into(),
            path: format!("/{name}"),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 1,
            ..Default::default()
        })
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
    let b = repl::entries_after(&n.store, &[(origin, after)], since_hlc, 1000, usize::MAX)
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
