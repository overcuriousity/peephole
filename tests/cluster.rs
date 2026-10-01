//! Multi-node tests: several in-process nodes on localhost.
use peephole::cluster::record::{Record, WireEntry};
use peephole::cluster::{self, Node, NodeParams, identity::Identity, identity::NodeId};
use peephole::cluster::{invite, members, repl};
use peephole::config::{ClusterConfig, PeerConfig, Roles};
use peephole::store::Store;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    // Tests run in parallel: the OS may hand the same ephemeral port to two
    // of them once the probe socket is closed, so never give one out twice.
    static TAKEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut taken = TAKEN.lock().unwrap();
        if !taken.contains(&port) {
            taken.push(port);
            return port;
        }
    }
}

/// Public facts about a test node: what its peers put in their config.
#[derive(Clone)]
struct Addr {
    name: &'static str,
    id: NodeId,
    port: u16,
}

impl Addr {
    fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

fn new_node(name: &'static str) -> (Identity, Addr) {
    let identity = Identity::generate().unwrap();
    let addr = Addr {
        name,
        id: identity.id,
        port: free_port(),
    };
    (identity, addr)
}

struct TestNode {
    node: Arc<Node>,
    dir: tempfile::TempDir,
    _stop: tokio::sync::watch::Sender<bool>,
    pace: peephole::scan::pace::SharedPace,
    workers: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(w) = self.workers.take() {
            w.abort();
        }
    }
}

impl std::ops::Deref for TestNode {
    type Target = Node;
    fn deref(&self) -> &Node {
        &self.node
    }
}

#[derive(Clone)]
struct Opts {
    proto: Option<(u32, u32)>,
    /// false: outbound-only (no advertise address).
    advertise: bool,
    lease_secs: u64,
    takeover_hours: f64,
    never_scan: Vec<String>,
    /// Run scan workers with this fake nmap.
    scanner: Option<std::path::PathBuf>,
    workers: usize,
}

const DEFAULT: Opts = Opts {
    proto: None,
    advertise: true,
    lease_secs: 120,
    takeover_hours: 6.0,
    never_scan: vec![],
    scanner: None,
    workers: 1,
};

async fn boot(identity: Identity, me: &Addr, peers: &[&Addr], o: Opts) -> TestNode {
    boot_in(tempfile::tempdir().unwrap(), identity, me, peers, o).await
}

/// Like [`boot`], on an existing data dir (standalone history is adopted,
/// as `peephole::run` does).
async fn boot_in(
    dir: tempfile::TempDir,
    identity: Identity,
    me: &Addr,
    peers: &[&Addr],
    o: Opts,
) -> TestNode {
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let cluster = ClusterConfig {
        node_name: me.name.into(),
        listen: me.address().parse().unwrap(),
        advertise: o.advertise.then(|| me.address()),
        key_path: None,
        takeover_hours: o.takeover_hours,
        lease_secs: o.lease_secs,
        peers: peers
            .iter()
            .map(|p| PeerConfig {
                name: p.name.into(),
                address: p.address(),
                public_key: p.id.to_string(),
            })
            .collect(),
    };
    let roles = Roles {
        listener: true,
        scanner: o.scanner.is_some(),
        web: false,
    };
    let node = Node::open(NodeParams {
        identity,
        cluster,
        roles,
        never_scan: o.never_scan.clone(),
        store,
        proto: o.proto.unwrap_or((
            cluster::rpc::proto::PROTO_MIN,
            cluster::rpc::proto::PROTO_VERSION,
        )),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    cluster::adopt::adopt_history(&node).await.unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    peephole::scan::arbiter::Arbiter::start(node.clone(), rx.clone())
        .await
        .unwrap();
    let pace = peephole::scan::pace::SharedPace::new(peephole::scan::pace::Pace {
        max_workers: o.workers,
        max_scans_per_hour: 3600,
        timeout_secs: 60,
    });
    let workers = o.scanner.as_ref().map(|nmap| {
        peephole::scan::pace::serve_remote(&node, pace.clone());
        tokio::spawn(peephole::scan::arbiter::takeover_loop(
            node.clone(),
            rx.clone(),
        ));
        tokio::spawn(peephole::scan::run_workers(
            peephole::store::recorder::Recorder::Cluster(node.clone()),
            scan_config(&o.never_scan),
            pace.clone(),
            nmap.clone(),
            rx.clone(),
            peephole::events::Notifier::new(),
        ))
    });
    cluster::start(node.clone(), rx).await.unwrap();
    TestNode {
        node,
        dir,
        _stop: tx,
        pace,
        workers,
    }
}

/// Config for the scan workers (argv presets, never_scan, cooldown).
fn scan_config(never_scan: &[String]) -> peephole::config::Config {
    let list = never_scan
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");
    toml::from_str(&format!(
        "database_path = \"/x\"\ndata_dir = \"/x\"\n[scan]\nnever_scan = [{list}]\n"
    ))
    .unwrap()
}

/// Poll `f` until it holds or 15 s pass.
async fn eventually<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while !f().await {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn knows(n: &Node, id: NodeId, active: bool) -> bool {
    members::all(&n.store)
        .await
        .unwrap()
        .iter()
        .any(|m| m.id == id && m.active == active)
}

#[tokio::test]
async fn members_greet_each_other_over_pinned_mtls() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    assert_eq!(na.hello(b.id, &b.address()).await.unwrap().node_name, "b");
    assert_eq!(nb.hello(a.id, &a.address()).await.unwrap().node_name, "a");
    // Each learns the other's self-description (roles, never_scan, ...).
    eventually("a sees b's self-description", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.info_hlc > 0 && m.roles == ["listener"])
    })
    .await;
}

#[tokio::test]
async fn non_member_key_is_refused() {
    let (ia, a) = new_node("a");
    let (ix, x) = new_node("x");
    let _na = boot(ia, &a, &[], DEFAULT).await;
    // x pins a's key, but a does not know x.
    let nx = boot(ix, &x, &[&a], DEFAULT).await;
    let e = nx.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");
}

#[tokio::test]
async fn client_refuses_a_server_with_another_key() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let impostor = Identity::generate().unwrap().id;
    let _na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    // Dial a's address while pinning a different key: TLS must fail
    // before any request is sent.
    let e = nb.hello(impostor, &a.address()).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("invalid peer certificate"), "{msg}");
}

#[tokio::test]
async fn incompatible_protocol_ranges_are_reported() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(
        ia,
        &a,
        &[&b],
        Opts {
            proto: Some((1, 1)),
            ..DEFAULT
        },
    )
    .await;
    let _nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            proto: Some((2, 3)),
            ..DEFAULT
        },
    )
    .await;
    let e = na.hello(b.id, &b.address()).await.unwrap_err();
    let msg = format!("{e:#}");
    assert!(msg.contains("incompatible protocol"), "{msg}");
    assert!(msg.contains("2..=3"), "{msg}");
}

/// A–B configured; C joins through B's invite. A learns C (and C learns
/// A) without anyone touching A.
#[tokio::test]
async fn invited_member_propagates_cluster_wide() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    let inviter = invite::join(&nc, &token).await.unwrap();
    assert_eq!(inviter.id, b.id);
    eventually("a admits c", || knows(&na, c.id, true)).await;
    eventually("c admits a", || knows(&nc, a.id, true)).await;
    // And A accepts C's RPC calls now.
    eventually("c greets a", || async {
        nc.hello(a.id, &a.address()).await.is_ok()
    })
    .await;
}

/// C has no advertise address: nobody can dial it, yet its records reach
/// A (via B or by C pushing), and A's reach C.
#[tokio::test]
async fn outbound_only_member_syncs_both_ways() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[],
        Opts {
            advertise: false,
            ..DEFAULT
        },
    )
    .await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a has c's self-description", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == c.id && m.info_hlc > 0 && m.address.is_none())
    })
    .await;
    // A new record on A reaches outbound-only C promptly (long-poll).
    let (_, d) = new_node("d");
    let rec = Record::MemberRevoke { id: d.id };
    repl::append(&na, &[rec]).await.unwrap();
    eventually("c sees a's newest record", || async {
        members::all(&nc.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == d.id)
    })
    .await;
}

#[tokio::test]
async fn invites_are_single_use_and_expire() {
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id_, d) = new_node("d");
    let nb = boot(ib, &b, &[], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let nd = boot(id_, &d, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    let e = invite::join(&nd, &token).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("invalid, used or expired"),
        "{e:#}"
    );

    let token = invite::create(&nb, 1).await.unwrap();
    sqlx::query(
        "UPDATE invites SET expires_at = datetime('now','-1 minute') WHERE used_at IS NULL",
    )
    .execute(&nb.store.pool)
    .await
    .unwrap();
    let e = invite::join(&nd, &token).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("invalid, used or expired"),
        "{e:#}"
    );
    assert!(!knows(&nb, d.id, true).await);
    // A node that already joined a cluster refuses a second one.
    let token = invite::create(&nd, 1).await.unwrap();
    let e = invite::join(&nc, &token).await.unwrap_err();
    assert!(format!("{e:#}").contains("already belongs"), "{e:#}");
}

#[tokio::test]
async fn revocation_spreads_and_locks_the_node_out() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, 1).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a admits c", || knows(&na, c.id, true)).await;
    repl::append(&nb, &[Record::MemberRevoke { id: c.id }])
        .await
        .unwrap();
    eventually("a revokes c", || knows(&na, c.id, false)).await;
    assert!(!na.is_member(&c.id));
    let e = nc.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");
    // C cannot re-admit itself.
    repl::append(
        &nc,
        &[Record::MemberUpdate(
            peephole::cluster::record::MemberInfo {
                name: "c-again".into(),
                ..nc.self_info()
            },
        )],
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(knows(&na, c.id, false).await);
}

/// Entries are applied only with a valid origin signature, and entries
/// from a not-yet-trusted origin wait until it is admitted.
#[tokio::test]
async fn forged_entries_are_rejected_and_unknown_origins_parked() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let me = Identity::generate().unwrap();
    let (a_id, b_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let node = Node::open(NodeParams {
        identity: me,
        cluster: ClusterConfig {
            node_name: "me".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            key_path: None,
            takeover_hours: 6.0,
            lease_secs: 120,
            peers: vec![PeerConfig {
                name: "a".into(),
                address: "127.0.0.1:1".into(),
                public_key: a_id.id.to_string(),
            }],
        },
        roles: Roles::default(),
        never_scan: vec![],
        store,
        proto: (1, 1),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();

    let info = |id: &Identity, name: &str| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: name.into(),
        address: None,
        roles: vec![],
        never_scan: vec![],
        proto_min: 1,
        proto_max: 1,
    };
    // Forgery: b signs an entry claiming to come from a.
    let mut forged =
        WireEntry::sign(&b_id, 1, 1, &Record::MemberUpdate(info(&a_id, "evil"))).unwrap();
    forged.origin = a_id.id;
    let st = repl::apply_batch(&node, vec![forged]).await.unwrap();
    assert_eq!((st.applied, st.rejected), (0, 1));

    // b is unknown: its own (valid) entry is parked...
    let b1 = WireEntry::sign(&b_id, 1, 10, &Record::MemberUpdate(info(&b_id, "b"))).unwrap();
    let st = repl::apply_batch(&node, vec![b1]).await.unwrap();
    assert_eq!((st.applied, st.parked), (0, 1));
    // ...a gap is rejected...
    let b3 = WireEntry::sign(&b_id, 3, 12, &Record::MemberUpdate(info(&b_id, "b3"))).unwrap();
    assert_eq!(
        repl::apply_batch(&node, vec![b3]).await.unwrap().rejected,
        1
    );
    // ...and once trusted a admits b, the parked entry applies.
    let a1 = WireEntry::sign(&a_id, 1, 20, &Record::MemberAdd(info(&b_id, "b-by-a"))).unwrap();
    let st = repl::apply_batch(&node, vec![a1]).await.unwrap();
    assert_eq!(st.applied, 2, "{st:?}");
    let rows = members::all(&node.store).await.unwrap();
    let b = rows.iter().find(|m| m.id == b_id.id).unwrap();
    assert!(b.active);
    assert_eq!(b.name, "b", "self-description wins over the sponsor's");
    let heads = repl::heads(&node.store).await.unwrap();
    assert_eq!(repl::head_in(&heads, &b_id.id), 1);
}

// ---------------------------------------------------------------- data

use peephole::store::recorder::Recorder;
use peephole::store::requests::NewRequest;

fn rec(n: &TestNode) -> Recorder {
    Recorder::Cluster(n.node.clone())
}

fn new_request(ip_id: i64, path: &str) -> NewRequest {
    NewRequest {
        ip_id,
        method: "POST".into(),
        path: path.into(),
        query: Some("q=1".into()),
        headers_json: r#"[["user-agent","sqlmap/1.7"]]"#.into(),
        body: Some(b"user=admin&pass=' OR 1=1--".to_vec()),
        labels_json: r#"["sqli"]"#.into(),
        severity: 4,
        scan_level: 3,
        is_fp_claim: false,
        page_token: Some("tok-1".into()),
    }
}

async fn count(n: &Node, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

fn fixture_scan() -> peephole::scan::nmap_xml::ScanResult {
    peephole::scan::nmap_xml::parse_nmap_xml(
        &std::fs::read("tests/fixtures/nmap-basic.xml").unwrap(),
    )
    .unwrap()
}

/// Everything recorded on A reaches C (which joined via B), byte for byte;
/// large records travel without being stored twice.
#[tokio::test]
async fn data_replicates_cluster_wide() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    invite::join(&nc, &invite::create(&nb, 1).await.unwrap())
        .await
        .unwrap();

    let r = rec(&na);
    let ip = na
        .store
        .upsert_ip("198.51.100.77".parse().unwrap())
        .await
        .unwrap();
    r.enrich_ip(ip.id, Some("DE"), Some(64500), Some("Example AS"), true)
        .await
        .unwrap();
    let req = r
        .insert_request(&new_request(ip.id, "/login"))
        .await
        .unwrap();
    r.insert_fp_claim(ip.id, req, Some("me@example.org"), "Mozilla")
        .await
        .unwrap();
    r.insert_fingerprint(Some(req), ip.id, "fp1", Some("v1"), "{}", "{}", b"events")
        .await
        .unwrap();
    let job = match r.enqueue_scan(ip.id, 3, 24).await.unwrap() {
        peephole::store::scans::EnqueueOutcome::Queued(j) => j,
        o => panic!("{o:?}"),
    };
    assert_eq!(r.next_queued_job().await.unwrap().unwrap().id, job);
    r.finish_job(job, Some(&fixture_scan()), None)
        .await
        .unwrap();

    eventually("c has the scan", || async {
        count(&nc, "SELECT COUNT(*) FROM ports").await == 3
    })
    .await;
    let row: (String, Vec<u8>, String, Option<String>, i64) = sqlx::query_as(
        "SELECT r.path, r.body, i.ip, i.country, i.is_tor_exit
         FROM requests r JOIN ips i ON i.id = r.ip_id",
    )
    .fetch_one(&nc.store.pool)
    .await
    .unwrap();
    assert_eq!(row.0, "/login");
    assert_eq!(row.1, b"user=admin&pass=' OR 1=1--");
    assert_eq!(row.2, "198.51.100.77");
    assert_eq!(row.3.as_deref(), Some("DE"));
    assert_eq!(row.4, 1);
    assert_eq!(count(&nc, "SELECT COUNT(*) FROM fp_claims").await, 1);
    assert_eq!(count(&nc, "SELECT COUNT(*) FROM fingerprints").await, 1);
    assert_eq!(
        count(&nc, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await,
        1
    );
    for n in [&na, &nc] {
        assert_eq!(
            count(
                n,
                "SELECT COUNT(*) FROM repl_log
                 WHERE kind IN ('request','fingerprint','scan_result') AND payload IS NOT NULL"
            )
            .await,
            0,
            "row-backed payloads are rebuilt, not stored"
        );
    }
    // C's copy is attributed to A.
    let origin: Vec<u8> = sqlx::query_scalar("SELECT origin FROM requests")
        .fetch_one(&nc.store.pool)
        .await
        .unwrap();
    assert_eq!(origin, a.id.0.to_vec());
    // C does not scan A's jobs (A arbitrates them).
    assert!(rec(&nc).next_queued_job().await.unwrap().is_none());
}

/// A node with the given trusted peers that never touches the network.
async fn offline_node(peers: &[&Addr]) -> (Arc<Node>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let node = Node::open(NodeParams {
        identity: Identity::generate().unwrap(),
        cluster: ClusterConfig {
            node_name: "offline".into(),
            listen: "127.0.0.1:0".parse().unwrap(),
            advertise: None,
            key_path: None,
            takeover_hours: 6.0,
            lease_secs: 120,
            peers: peers
                .iter()
                .map(|p| PeerConfig {
                    name: p.name.into(),
                    address: p.address(),
                    public_key: p.id.to_string(),
                })
                .collect(),
        },
        roles: Roles::default(),
        never_scan: vec![],
        store,
        proto: (1, 1),
        has_maxmind: false,
        data_dir: dir.path().to_path_buf(),
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();
    (node, dir)
}

async fn log_of(n: &Node, origin: NodeId) -> Vec<WireEntry> {
    repl::entries_after(&n.store, &[(origin, 0)], 10_000, usize::MAX)
        .await
        .unwrap()
}

#[tokio::test]
async fn deletes_propagate_and_stay_deleted() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.66".parse().unwrap())
        .await
        .unwrap();
    let r1 = rec(&na)
        .insert_request(&new_request(ip.id, "/one"))
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/two"))
        .await
        .unwrap();
    rec(&na)
        .insert_fp_claim(ip.id, r1, None, "ua")
        .await
        .unwrap();
    eventually("b has both", || async {
        count(&nb, "SELECT COUNT(*) FROM fp_claims").await == 1
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 2
    })
    .await;
    // A's stream as an offline node would have it before the delete.
    let a_before = log_of(&na, a.id).await;

    // Delete /one on B (with its claim): gone on A too.
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert!(rec(&nb).delete_request(one_on_b).await.unwrap());
    eventually("a deleted /one", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    assert_eq!(count(&na, "SELECT COUNT(*) FROM fp_claims").await, 0);
    assert_eq!(
        count(
            &na,
            "SELECT COUNT(*) FROM repl_log WHERE erased_by IS NOT NULL"
        )
        .await,
        2,
        "request and claim payloads are erased from the log"
    );
    let b_stream = log_of(&nb, b.id).await;
    let a_after = log_of(&na, a.id).await;

    // Late arrival: X sees the tombstone first, then A's old entries with
    // full payloads. /one must not come back.
    let (x, _dx) = offline_node(&[&a, &b]).await;
    repl::apply_batch(&x, b_stream.clone()).await.unwrap();
    repl::apply_batch(&x, a_before).await.unwrap();
    let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM requests")
        .fetch_all(&x.store.pool)
        .await
        .unwrap();
    assert_eq!(paths, ["/two"]);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM fp_claims").await, 0);

    // Erased stubs from a trusted origin are accepted immediately: the
    // tombstone that erased them comes *later* in the same in-order stream, so
    // waiting for it would stall the origin forever. Applying A's stream alone
    // (without B's tombstone yet) must converge to A's head and keep /one
    // deleted, not reject-and-stall.
    let (y, _dy) = offline_node(&[&a, &b]).await;
    let st = repl::apply_batch(&y, a_after.clone()).await.unwrap();
    assert_eq!(st.rejected, 0, "stub must not stall the stream: {st:?}");
    assert_eq!(
        repl::head_in(&repl::heads(&y.store).await.unwrap(), &a.id),
        repl::head_in(&repl::heads(&na.store).await.unwrap(), &a.id),
        "A's log fully applied, no stall at the erased stub"
    );
    // Re-applying B's stream and A's stream stays idempotent and deleted.
    repl::apply_batch(&y, b_stream).await.unwrap();
    repl::apply_batch(&y, a_after).await.unwrap();
    let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM requests")
        .fetch_all(&y.store.pool)
        .await
        .unwrap();
    assert_eq!(paths, ["/two"]);

    // Deleting the IP on A clears it everywhere.
    assert!(rec(&na).delete_ip(ip.id).await.unwrap());
    eventually("b dropped the ip", || async {
        count(&nb, "SELECT COUNT(*) FROM ips").await == 0
    })
    .await;
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 0);
}

/// A standalone install that switches to distributed mode brings its
/// history along; a new member backfills all of it.
#[tokio::test]
async fn standalone_history_is_adopted_and_backfilled() {
    let dir = tempfile::tempdir().unwrap();
    {
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = s.upsert_ip("192.0.2.200".parse().unwrap()).await.unwrap();
        s.set_ip_geo(ip.id, Some("NL"), Some(1), Some("x"))
            .await
            .unwrap();
        for i in 0..150 {
            s.insert_request(&new_request(ip.id, &format!("/p{i}")))
                .await
                .unwrap();
        }
        let job = match s.enqueue_scan(ip.id, 2, 24).await.unwrap() {
            peephole::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        s.finish_job(job, Some(&fixture_scan()), None)
            .await
            .unwrap();
        s.pool.close().await;
    }
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot_in(dir, ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    eventually("b backfilled everything", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 150
            && count(&nb, "SELECT COUNT(*) FROM ports").await == 3
    })
    .await;
    assert_eq!(
        count(&nb, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await,
        1
    );
    let country: Option<String> = sqlx::query_scalar("SELECT country FROM ips")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(country.as_deref(), Some("NL"));
    assert_eq!(
        count(&na, "SELECT COUNT(*) FROM requests WHERE origin IS NULL").await,
        0
    );
    // A restart adopts nothing twice.
    assert_eq!(cluster::adopt::adopt_history(&na).await.unwrap(), 0);
}

/// Only a job's arbiter may change its state.
#[tokio::test]
async fn job_status_from_a_non_arbiter_is_ignored() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.9".parse().unwrap())
        .await
        .unwrap();
    rec(&na).enqueue_scan(ip.id, 2, 24).await.unwrap();
    eventually("b has the job", || async {
        count(&nb, "SELECT COUNT(*) FROM scan_jobs").await == 1
    })
    .await;
    let uid: String = sqlx::query_scalar("SELECT uid FROM scan_jobs")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    repl::append(
        &nb,
        &[Record::JobStatus(peephole::cluster::record::JobStatusRec {
            job_uid: uid,
            status: "done".into(),
            started_at: None,
            finished_at: None,
            error: None,
            attempts: 9,
            scanner: None,
        })],
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    for n in [&na, &nb] {
        assert_eq!(
            count(n, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'").await,
            1
        );
    }
}

// ---------------------------------------------------------- scan queue

/// A fake nmap that prints the fixture after `secs`, and logs each target.
fn fake_nmap(dir: &std::path::Path, secs: f64) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let xml = dir.join("nmap.xml");
    std::fs::copy("tests/fixtures/nmap-basic.xml", &xml).unwrap();
    let log = dir.join("targets.log");
    let p = dir.join(format!("fake-nmap-{secs}"));
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nfor a; do t=$a; done\necho $t >> {log}\nsleep {secs}\ncat {xml}\n",
            log = log.display(),
            xml = xml.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

async fn enqueue(n: &TestNode, ip: &str, level: u8) {
    let row = n.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    let out = rec(n).enqueue_scan(row.id, level, 24).await.unwrap();
    assert!(
        matches!(out, peephole::store::scans::EnqueueOutcome::Queued(_)),
        "{out:?}"
    );
}

async fn scans_by(n: &Node, scanner: NodeId) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM scan_jobs WHERE status = 'done' AND scanner = ?")
        .bind(&scanner.0[..])
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// A listener without a scanner fills the queue; two scanners drain it
/// and share it about evenly.
#[tokio::test]
async fn scanners_share_a_listeners_queue() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.5);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let scan = Opts {
        scanner: Some(nmap),
        ..DEFAULT
    };
    let _nb = boot(ib, &b, &[&a, &c], scan.clone()).await;
    let _nc = boot(ic, &c, &[&a, &b], scan).await;
    for i in 0..6 {
        enqueue(&na, &format!("198.51.100.{}", 10 + i), 2).await;
    }
    eventually_for(Duration::from_secs(40), "all six scanned", || async {
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 6
    })
    .await;
    let (by_b, by_c) = (scans_by(&na, b.id).await, scans_by(&na, c.id).await);
    assert_eq!(by_b + by_c, 6);
    assert!(by_b >= 2 && by_c >= 2, "uneven: b={by_b} c={by_c}");
    // Results come from the scanners, attributed to them.
    eventually("a has all results", || async {
        count(&na, "SELECT COUNT(*) FROM scans").await == 6
    })
    .await;
    let origins: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT origin) FROM scans")
        .fetch_one(&na.store.pool)
        .await
        .unwrap();
    assert_eq!(origins, 2);
}

/// Poll `f` until it holds or `limit` passes.
async fn eventually_for<F, Fut>(limit: Duration, what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + limit;
    while !f().await {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A scanner that dies mid-scan stops renewing; the lease expires and
/// another scanner finishes the job.
#[tokio::test]
async fn expired_lease_moves_the_job_to_another_scanner() {
    let tools = tempfile::tempdir().unwrap();
    let hang = fake_nmap(tools.path(), 60.0);
    let quick = fake_nmap(tools.path(), 0.2);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(
        ia,
        &a,
        &[&b, &c],
        Opts {
            lease_secs: 2,
            ..DEFAULT
        },
    )
    .await;
    let mut nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(hang),
            ..DEFAULT
        },
    )
    .await;
    enqueue(&na, "203.0.113.50", 2).await;
    eventually("b runs the job", || async {
        count(
            &na,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'running'",
        )
        .await
            == 1
    })
    .await;
    // B's scanner dies (nmap is killed with it).
    nb.workers.take().unwrap().abort();
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(quick),
            ..DEFAULT
        },
    )
    .await;
    eventually_for(Duration::from_secs(20), "c finished it", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
    let attempts: i64 = sqlx::query_scalar("SELECT attempts FROM scan_jobs")
        .fetch_one(&na.store.pool)
        .await
        .unwrap();
    assert_eq!(attempts, 2);
}

/// Queued jobs of an arbiter that went silent are adopted and scanned.
#[tokio::test]
async fn silent_arbiters_queue_is_taken_over() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.2);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            scanner: Some(nmap),
            workers: 0, // paused: nothing is claimed while A is up
            takeover_hours: 3.0 / 3600.0,
            ..DEFAULT
        },
    )
    .await;
    enqueue(&na, "203.0.113.70", 3).await;
    eventually("b sees a's job and heartbeat", || async {
        count(&nb, "SELECT COUNT(*) FROM scan_jobs").await == 1 && nb.status.known(&a.id).is_some()
    })
    .await;
    drop(na); // A goes silent
    eventually_for(Duration::from_secs(20), "b adopted the job", || async {
        let arb: Option<Vec<u8>> = sqlx::query_scalar("SELECT arbiter FROM scan_jobs")
            .fetch_one(&nb.store.pool)
            .await
            .unwrap();
        arb == Some(b.id.0.to_vec())
    })
    .await;
    nb.pace
        .set(
            &nb.store,
            peephole::scan::pace::Pace {
                max_workers: 1,
                max_scans_per_hour: 3600,
                timeout_secs: 60,
            },
        )
        .await
        .unwrap()
        .unwrap();
    eventually_for(Duration::from_secs(20), "b scanned it", || async {
        scans_by(&nb, b.id).await == 1
    })
    .await;
}

/// Any member's never_scan protects a target cluster-wide: the scanner
/// refuses it without running nmap.
#[tokio::test]
async fn never_scan_of_any_member_is_honoured() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            never_scan: vec!["192.0.2.0/24".into()],
            ..DEFAULT
        },
    )
    .await;
    eventually("a knows c's never_scan", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == c.id && !m.never_scan.is_empty())
    })
    .await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    eventually("b knows c's never_scan", || async {
        members::all(&nb.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == c.id && !m.never_scan.is_empty())
    })
    .await;
    enqueue(&na, "192.0.2.10", 2).await;
    eventually("job refused", || async {
        count(
            &na,
            "SELECT COUNT(*) FROM scan_jobs WHERE status = 'refused'",
        )
        .await
            == 1
    })
    .await;
    assert!(
        !tools.path().join("targets.log").exists(),
        "nmap must not run"
    );
}

/// Two listeners queue the same IP before they hear of each other's job:
/// one scan runs, the other job is superseded.
#[tokio::test]
async fn duplicate_jobs_are_superseded() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.5);
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let ip = "198.51.100.200";
    enqueue(&na, ip, 2).await;
    // B queues the same IP as if it had not seen A's job yet.
    nb.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    rec(&nb)
        .write(vec![Record::ScanJob(
            peephole::cluster::record::ScanJobRec {
                uid: "dup-job".into(),
                ip: ip.into(),
                level: 2,
                queued_at: peephole::store::data::now_ts(),
            },
        )])
        .await
        .unwrap();
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    eventually_for(
        Duration::from_secs(20),
        "one done, one superseded",
        || async {
            count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
                && count(
                    &na,
                    "SELECT COUNT(*) FROM scan_jobs WHERE status = 'superseded'",
                )
                .await
                    == 1
        },
    )
    .await;
    let runs = std::fs::read_to_string(tools.path().join("targets.log")).unwrap();
    assert_eq!(runs.lines().count(), 1, "{runs}");
}

/// A scanner nobody can dial still gets jobs and reports back (answers
/// travel through the arbiter's outbox it long-polls).
#[tokio::test]
async fn outbound_only_scanner_drains_the_queue() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("a");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[],
        Opts {
            advertise: false,
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    invite::join(&nc, &invite::create(&na, 1).await.unwrap())
        .await
        .unwrap();
    enqueue(&na, "203.0.113.90", 2).await;
    eventually_for(Duration::from_secs(20), "c scanned a's job", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
}

/// A web node changes a headless scanner's pace; it is applied, persisted
/// there and visible in the scanner's heartbeat.
#[tokio::test]
async fn pace_is_set_remotely() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("a");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&c], DEFAULT).await;
    let nc = boot(
        ic,
        &c,
        &[&a],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    let new = peephole::scan::pace::Pace {
        max_workers: 3,
        max_scans_per_hour: 42,
        timeout_secs: 600,
    };
    peephole::scan::pace::set_remote(&na.node, c.id, new)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(nc.pace.get(), new);
    let saved = nc
        .store
        .setting_get("scan.max_scans_per_hour")
        .await
        .unwrap();
    assert_eq!(saved.as_deref(), Some("42"));
    // Invalid values are refused by the scanner, which keeps its pace.
    let bad = peephole::scan::pace::Pace {
        max_workers: 999,
        ..new
    };
    assert!(
        peephole::scan::pace::set_remote(&na.node, c.id, bad)
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(nc.pace.get(), new);
    eventually_for(Duration::from_secs(40), "a sees c's new pace", || async {
        na.status
            .known(&c.id)
            .and_then(|k| k.hb.pace)
            .is_some_and(|p| p.max_scans_per_hour == 42)
    })
    .await;
}

// --------------------------------------------------------------- intel

use peephole::intel::share;

/// A fetches the GeoLite2 databases; B copies them by hash from A, C from
/// whichever peer still holds that exact version.
#[tokio::test]
async fn intel_files_are_shared_by_hash() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    share::publish(&na, na.dir.path(), &[share::CITY, share::ASN])
        .await
        .unwrap();
    eventually("b knows the manifests", || async {
        share::manifests(&nb.store).await.unwrap().len() == 2
    })
    .await;
    let mut got = share::sync_files(&nb, nb.dir.path()).await.unwrap();
    got.sort();
    assert_eq!(got, [share::ASN, share::CITY]);
    let g = peephole::intel::geo::GeoIp::load(nb.dir.path()).unwrap();
    assert_eq!(
        g.lookup(&"2.125.160.216".parse().unwrap())
            .country
            .as_deref(),
        Some("GB")
    );
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );

    // A's copy changes without a new announcement: A no longer serves it,
    // B still does.
    std::fs::write(na.dir.path().join("GeoLite2-City.mmdb"), b"tampered").unwrap();
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("c knows the manifests", || async {
        share::manifests(&nc.store).await.unwrap().len() == 2
    })
    .await;
    eventually("c knows b", || async { nc.status.reached_recently(&b.id) }).await;
    let got = share::sync_files(&nc, nc.dir.path()).await.unwrap();
    assert_eq!(got.len(), 2, "{got:?}");
    let (sha, _) = share::file_hash(&nc.dir.path().join("GeoLite2-City.mmdb")).unwrap();
    let (want, _) = share::file_hash(&nb.dir.path().join("GeoLite2-City.mmdb")).unwrap();
    assert_eq!(sha, want);
}

// ---------------------------------------------------------------- admin UI

/// The admin router of `n` (cluster recorder) on an ephemeral port, with an
/// enrolled soft passkey. Returns the logged-in client and base URL.
async fn admin_on(n: &TestNode) -> (reqwest::Client, String) {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let cfg: peephole::config::Config = toml::from_str(
        r#"
database_path = "/x"
data_dir = "/x"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
    )
    .unwrap();
    let token = peephole::admin::auth::ensure_setup_token(&n.store, n.dir.path())
        .await
        .unwrap()
        .expect("setup token");
    let state = Arc::new(
        peephole::admin::AdminState::new(
            n.store.clone(),
            cfg,
            peephole::events::Notifier::new(),
            n.pace.clone(),
        )
        .with_recorder(Recorder::Cluster(n.node.clone())),
    );
    let app = peephole::admin::full_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let mut soft = SoftPasskey::new(true);
    let cco: serde_json::Value = client
        .post(format!("{base}/enroll/start"))
        .json(&serde_json::json!({"setup_token": token, "label": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions =
        serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let cred = soft
        .perform_register(Url::parse("https://localhost").unwrap(), options, 60_000)
        .unwrap();
    let r = client
        .post(format!("{base}/enroll/finish"))
        .json(&serde_json::json!({"credential": cred}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    (client, base)
}

async fn text(c: &reqwest::Client, url: String) -> String {
    let r = c.get(&url).send().await.unwrap();
    assert!(r.status().is_success(), "{url}: {}", r.status());
    r.text().await.unwrap()
}

#[tokio::test]
async fn admin_cluster_page_and_private_attribution() {
    let tools = tempfile::tempdir().unwrap();
    let nmap = fake_nmap(tools.path(), 0.1);
    let (ia, a) = new_node("sensor-alpha");
    let (ib, b) = new_node("sensor-bravo");
    let (ic, c) = new_node("sensor-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(nmap),
            ..DEFAULT
        },
    )
    .await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    // A records a request and queues a scan; B scans it.
    let mut job_events = na.job_events.subscribe();
    let ip = na
        .store
        .upsert_ip("198.51.100.150".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/admin.php"))
        .await
        .unwrap();
    rec(&na).enqueue_scan(ip.id, 2, 24).await.unwrap();
    eventually_for(Duration::from_secs(20), "b scanned", || async {
        scans_by(&na, b.id).await == 1 && count(&na, "SELECT COUNT(*) FROM scans").await == 1
    })
    .await;
    // The live queue hears about the job's changes, including B's remote
    // progress applied on A.
    let mut seen = 0;
    while job_events.try_recv().is_ok() {
        seen += 1;
    }
    assert!(seen >= 3, "queued, running, done: {seen}");
    eventually_for(
        Duration::from_secs(40),
        "a has b's heartbeat with pace",
        || async { na.status.known(&b.id).is_some_and(|k| k.hb.pace.is_some()) },
    )
    .await;

    let (admin, base) = admin_on(&na).await;
    let page = text(&admin, format!("{base}/admin/cluster")).await;
    for want in [
        "sensor-alpha",
        "sensor-bravo",
        "sensor-charlie",
        &b.id.short(),
        "Scanner pace",
    ] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
    // Remote pace from the UI.
    let r = admin
        .post(format!("{base}/admin/cluster/pace"))
        .form(&[
            ("key", b.id.to_string()),
            ("max_workers", "2".into()),
            ("max_scans_per_hour", "77".into()),
            ("timeout_minutes", "15".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    // Invites are shown once.
    let r = admin
        .post(format!("{base}/admin/cluster/invite"))
        .form(&[("ttl_hours", "2")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("peephole1:"));
    // Attribution on admin views.
    let queue = text(&admin, format!("{base}/admin/queue")).await;
    assert!(
        queue.contains("sensor-bravo") && queue.contains("via sensor-alpha"),
        "queue"
    );
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(scans.contains("sensor-bravo"), "scans");
    let reqs = text(&admin, format!("{base}/requests?node=sensor-alpha")).await;
    assert!(
        reqs.contains("/admin.php") && reqs.contains("<th>Node</th>"),
        "requests"
    );
    let none = text(&admin, format!("{base}/requests?node=sensor-charlie")).await;
    assert!(!none.contains("/admin.php"), "node filter");
    // Revoke from the UI.
    let r = admin
        .post(format!("{base}/admin/cluster/revoke"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(knows(&na, c.id, false).await);

    // Nothing about the cluster leaks to the public.
    let public = reqwest::Client::new();
    let secrets = [
        "sensor-alpha".to_string(),
        "sensor-bravo".into(),
        "sensor-charlie".into(),
        a.id.short(),
        b.id.short(),
        a.id.to_string(),
        b.id.to_string(),
    ];
    for path in [
        "/".to_string(),
        "/ips".into(),
        "/ip/198.51.100.150".into(),
        "/api/stats".into(),
        "/api/map".into(),
        "/api/countries".into(),
    ] {
        let body = text(&public, format!("{base}{path}")).await;
        for s in &secrets {
            assert!(!body.contains(s.as_str()), "{path} leaks {s}");
        }
    }
    // Request search (and its node filter) is admin-only.
    let noredir = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for path in ["/requests", "/requests?node=sensor-alpha", "/admin/cluster"] {
        let resp = noredir.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path} should require a session");
        assert_eq!(resp.headers().get("location").unwrap(), "/login", "{path}");
    }
}
