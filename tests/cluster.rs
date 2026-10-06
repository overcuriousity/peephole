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
    settings: peephole::settings::Settings,
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
    /// Days of history kept (0: all).
    retention_days: u32,
    /// Share of other nodes' fresh scans this scanner audits.
    audit_share: f64,
}

const DEFAULT: Opts = Opts {
    proto: None,
    advertise: true,
    lease_secs: 120,
    takeover_hours: 6.0,
    never_scan: vec![],
    scanner: None,
    workers: 1,
    retention_days: 0,
    audit_share: 0.0,
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
        remote_config: false,
        origin_quota_mb: 20 * 1024,
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
        store,
        proto: o.proto.unwrap_or((
            cluster::rpc::proto::PROTO_MIN,
            cluster::rpc::proto::PROTO_VERSION,
        )),
        data_dir: dir.path().to_path_buf(),
        retention_days: o.retention_days,
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
    let settings = peephole::settings::Settings::with_pace(
        node.store.clone(),
        &scan_config(&o.never_scan, o.audit_share),
        pace.clone(),
    );
    cluster::remote::serve(&node, settings.clone());
    cluster::owner::fleet::serve(&node);
    cluster::owner::cmd::serve(&node, settings.clone());
    peephole::credits::fleet::serve(&node);
    let workers = o.scanner.as_ref().map(|nmap| {
        tokio::spawn(peephole::scan::arbiter::takeover_loop(
            node.clone(),
            rx.clone(),
        ));
        tokio::spawn(peephole::scan::run_workers(
            peephole::store::recorder::Recorder::Cluster(node.clone()),
            scan_config(&o.never_scan, o.audit_share),
            pace.clone(),
            nmap.clone(),
            rx.clone(),
            peephole::events::Notifier::new(),
            peephole::classify::Classifier::builtin(),
        ))
    });
    cluster::start(node.clone(), rx).await.unwrap();
    TestNode {
        node,
        dir,
        _stop: tx,
        pace,
        settings,
        workers,
    }
}

/// Config for the scan workers (argv presets, never_scan, cooldown).
fn scan_config(never_scan: &[String], audit_share: f64) -> peephole::config::Config {
    let list = never_scan
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(",");
    // No Tor list and no DNS in tests: neither check may hold scans back.
    toml::from_str(&format!(
        "database_path = \"/x\"\ndata_dir = \"/x\"\n[scan]\nnever_scan = [{list}]\n\
         tor_unknown = \"scan\"\nverify_crawlers = false\n[credits]\naudit_share = {audit_share}\n"
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
    let token = invite::create(&nb, &Default::default()).await.unwrap();
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
    let token = invite::create(&nb, &Default::default()).await.unwrap();
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
    let rec = Record::MemberAdd(peephole::cluster::record::MemberInfo {
        id: d.id,
        name: "d".into(),
        address: None,
        roles: vec![],
        proto_min: 0,
        proto_max: 0,
        remote_config: false,
    });
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
async fn invites_are_reusable_until_limited_expired_or_revoked() {
    use invite::InviteOpts;
    let boot1 = |name: &'static str| async move {
        let (i, a) = new_node(name);
        boot(i, &a, &[], DEFAULT).await
    };
    let nb = boot1("b").await;
    let (nc, nd, ne, nf, ng) = (
        boot1("c").await,
        boot1("d").await,
        boot1("e").await,
        boot1("f").await,
        boot1("g").await,
    );
    let refused = |e: anyhow::Error| {
        let m = format!("{e:#}");
        assert!(m.contains("invalid, revoked, exhausted or expired"), "{m}");
    };

    // One invite, handed to a peer group, redeemed one by one.
    let token = invite::create(
        &nb,
        &InviteOpts {
            label: "peer group".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    invite::join(&nc, &token).await.unwrap();
    invite::join(&nd, &token).await.unwrap();
    let rows = invite::list(&nb.store).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].label, "peer group");
    assert_eq!((rows[0].uses, rows[0].usable), (2, true));
    assert_eq!(rows[0].joined.len(), 2);
    assert!(rows[0].joined.contains(&nc.id()) && rows[0].joined.contains(&nd.id()));

    // Revoked: no further joins; revoking twice reports nothing to do.
    assert!(invite::revoke(&nb.store, rows[0].id).await.unwrap());
    assert!(!invite::revoke(&nb.store, rows[0].id).await.unwrap());
    refused(invite::join(&ne, &token).await.unwrap_err());

    // Use limit.
    let token = invite::create(
        &nb,
        &InviteOpts {
            max_uses: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    invite::join(&ne, &token).await.unwrap();
    refused(invite::join(&nf, &token).await.unwrap_err());

    // Expiry.
    let token = invite::create(
        &nb,
        &InviteOpts {
            ttl_hours: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE invites SET expires_at = datetime('now','-1 minute')
         WHERE id = (SELECT MAX(id) FROM invites)",
    )
    .execute(&nb.store.pool)
    .await
    .unwrap();
    refused(invite::join(&nf, &token).await.unwrap_err());
    assert!(!knows(&nb, nf.id(), true).await);

    // A member of one cluster refuses an invite into an unrelated one.
    let token = invite::create(&ng, &InviteOpts::default()).await.unwrap();
    let e = invite::join(&nc, &token).await.unwrap_err();
    assert!(format!("{e:#}").contains("already belongs"), "{e:#}");

    // Nonsense options are refused.
    for bad in [
        InviteOpts {
            ttl_hours: Some(0),
            ..Default::default()
        },
        InviteOpts {
            max_uses: Some(0),
            ..Default::default()
        },
    ] {
        assert!(invite::create(&nb, &bad).await.is_err());
    }
}

/// Nobody can remove another node; a node removes itself by leaving, and
/// comes back with an invite.
#[tokio::test]
async fn only_a_node_itself_can_leave() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nc = boot(ic, &c, &[], DEFAULT).await;
    let token = invite::create(&nb, &Default::default()).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    eventually("a admits c", || knows(&na, c.id, true)).await;

    // B tries to revoke C: every node ignores it.
    repl::append(&nb, &[Record::MemberRevoke { id: c.id }])
        .await
        .unwrap();
    eventually("a holds b's newest entry", || async {
        let on_a = repl::heads(&na.store).await.unwrap();
        let on_b = repl::heads(&nb.store).await.unwrap();
        repl::head_in(&on_a, &b.id) == repl::head_in(&on_b, &b.id)
    })
    .await;
    assert!(knows(&na, c.id, true).await && knows(&nb, c.id, true).await);
    assert!(nc.hello(a.id, &a.address()).await.is_ok());

    // C leaves by itself.
    let told = cluster::leave(&nc).await.unwrap();
    assert!(told >= 1, "at least the inviter heard it");
    assert_eq!(nc.detached(), Some(cluster::Detached::Left));
    assert!(
        nc.dial_targets().is_empty(),
        "a node that left stops dialling"
    );
    eventually("a sees c gone", || knows(&na, c.id, false)).await;
    let e = nc.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");

    // Rejoining takes an invite.
    let token = invite::create(&na, &Default::default()).await.unwrap();
    invite::join(&nc, &token).await.unwrap();
    assert_eq!(nc.detached(), None);
    eventually("a re-admits c", || knows(&na, c.id, true)).await;
}

/// Leaving with nobody reachable still detaches the node.
#[tokio::test]
async fn leaving_without_reachable_peers_still_detaches() {
    let (_, a) = new_node("a");
    let (x, _dx) = offline_node(&[&a]).await;
    assert_eq!(cluster::leave(&x).await.unwrap(), 0);
    assert_eq!(x.detached(), Some(cluster::Detached::Left));
}

/// A node that left admits nobody: leaving revokes its invites, and it
/// refuses to redeem any invite while detached. Before, a joiner could
/// still redeem an old token and be vouched for by a node that was gone.
#[tokio::test]
async fn a_node_that_left_admits_nobody() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (id, d) = new_node("d");
    let _na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let nd = boot(id, &d, &[], DEFAULT).await;
    let old = invite::create(&nb, &Default::default()).await.unwrap();
    cluster::leave(&nb).await.unwrap();
    assert!(
        invite::list(&nb.store)
            .await
            .unwrap()
            .iter()
            .all(|i| i.revoked)
    );
    // An invite made after leaving does not admit anyone either.
    let new = invite::create(&nb, &Default::default()).await.unwrap();
    for token in [old, new] {
        let e = invite::join(&nd, &token).await.unwrap_err();
        assert!(
            format!("{e:#}").contains("not in a cluster any more"),
            "{e:#}"
        );
    }
    assert!(!members::can_admit(&nb, &d.id).await.unwrap());
    assert!(!knows(&nb, d.id, true).await);
}

/// What a member recorded stays acceptable after it left: a node that
/// syncs later still applies all of it.
#[tokio::test]
async fn entries_of_a_departed_member_still_apply() {
    let a_id = Identity::generate().unwrap();
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = |name: &str| peephole::cluster::record::MemberInfo {
        id: a_id.id,
        name: name.into(),
        address: None,
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
        remote_config: false,
    };
    let entries = vec![
        WireEntry::sign(&a_id, 1, 10, &Record::MemberUpdate(info("a"))).unwrap(),
        WireEntry::sign(&a_id, 2, 20, &Record::MemberRevoke { id: a_id.id }).unwrap(),
        WireEntry::sign(&a_id, 3, 30, &Record::MemberUpdate(info("late"))).unwrap(),
    ];
    let st = repl::apply_batch(&x, entries).await.unwrap();
    assert_eq!((st.applied, st.parked), (3, 0), "{st:?}");
    let rows = members::all(&x.store).await.unwrap();
    let row = rows.iter().find(|m| m.id == a_id.id).unwrap();
    assert_eq!(row.name, "late");
}

/// An HLC `days` in the past (`n` keeps values distinct).
fn hlc_days_ago(days: u64, n: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    ((now - days * 24 * 3600 * 1000) << 16) + n
}

#[tokio::test]
async fn members_silent_for_30_days_are_pruned_and_revive_with_a_sign_of_life() {
    let a_id = Identity::generate().unwrap();
    let b_id = Identity::generate().unwrap();
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = |id: &Identity| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: "b".into(),
        address: Some("127.0.0.1:2".into()),
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
        remote_config: false,
    };
    // A admitted B 40 days ago; B described itself then and went silent.
    let st = repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &a_id,
                1,
                hlc_days_ago(40, 1),
                &Record::MemberAdd(info(&b_id)),
            )
            .unwrap(),
            WireEntry::sign(
                &b_id,
                1,
                hlc_days_ago(40, 2),
                &Record::MemberUpdate(info(&b_id)),
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        st.applied, 2,
        "a pruned member's records are still applied: {st:?}"
    );
    let row = |rows: Vec<members::MemberRow>| rows.into_iter().find(|m| m.id == b_id.id).unwrap();
    let b = row(members::all(&x.store).await.unwrap());
    assert_eq!(b.standing, members::Standing::Pruned);
    assert!(!b.active && !x.is_member(&b_id.id));
    assert_eq!(x.standing_of(&b_id.id), Some(members::Standing::Pruned));
    assert!(x.dial_targets().iter().all(|t| t.0 != b_id.id));
    // A fresh entry signed by B, relayed by anyone, revives it.
    repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &b_id,
                2,
                hlc_days_ago(0, 3),
                &Record::MemberUpdate(info(&b_id)),
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    assert!(row(members::all(&x.store).await.unwrap()).active);
    assert!(x.is_member(&b_id.id));
}

#[tokio::test]
async fn a_running_node_leaves_a_sign_of_life_once_a_day() {
    let (_, a) = new_node("a");
    let (x, _dx) = offline_node(&[&a]).await;
    assert!(
        !x.keepalive().await.unwrap(),
        "fresh entries: nothing to do"
    );
    sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
        .bind(hlc_days_ago(2, 0) as i64)
        .bind(&x.id().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    assert!(x.keepalive().await.unwrap());
    assert!(!x.keepalive().await.unwrap());
}

/// A node that was offline longer than the prune window knows it was
/// dropped, instead of judging everyone else by its outdated log.
#[tokio::test]
async fn a_node_offline_for_over_30_days_starts_detached() {
    let (_, a) = new_node("a");
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    Identity::load_or_create(&key).unwrap();
    let open = || async {
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        Node::open(NodeParams {
            identity: Identity::load(&key).unwrap(),
            cluster: ClusterConfig {
                node_name: "x".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![PeerConfig {
                    name: "a".into(),
                    address: a.address(),
                    public_key: a.id.to_string(),
                }],
            },
            roles: Roles::default(),
            store,
            proto: (2, 2),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap()
    };
    let x = open().await;
    x.bootstrap().await.unwrap();
    assert_eq!(x.detached(), None);
    sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
        .bind(hlc_days_ago(31, 0) as i64)
        .bind(&x.id().0[..])
        .execute(&x.store.pool)
        .await
        .unwrap();
    drop(x);
    let x = open().await;
    assert_eq!(x.detached(), Some(cluster::Detached::Pruned));
}

/// A record's uid is bound to the node that created it. Nobody can create
/// a record under another node's uid, so nobody can delete or shadow it.
#[tokio::test]
async fn a_uid_not_bound_to_its_origin_is_rejected() {
    let (a_id, b_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (a, b) = (
        Addr {
            name: "a",
            id: a_id.id,
            port: 1,
        },
        Addr {
            name: "b",
            id: b_id.id,
            port: 2,
        },
    );
    let (x, _dx) = offline_node(&[&a, &b]).await;
    let request = |uid: String| {
        Record::Request(Box::new(peephole::cluster::record::RequestRec {
            uid,
            ts: "2026-01-01 00:00:00".into(),
            ip: "203.0.113.80".into(),
            method: "GET".into(),
            path: "/x".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }))
    };
    let a_uid = format!("{}one", a_id.id.uid_prefix());
    let st = repl::apply_batch(
        &x,
        vec![WireEntry::sign(&a_id, 1, hlc_days_ago(0, 1), &request(a_uid.clone())).unwrap()],
    )
    .await
    .unwrap();
    assert_eq!(st.applied, 1, "{st:?}");
    // B signs a record under A's uid, then one under an unbound uid.
    for uid in [a_uid, "plain".to_string()] {
        let st = repl::apply_batch(
            &x,
            vec![WireEntry::sign(&b_id, 1, hlc_days_ago(0, 2), &request(uid)).unwrap()],
        )
        .await
        .unwrap();
        assert_eq!((st.applied, st.rejected), (0, 1), "{st:?}");
    }
    assert_eq!(head_of(&x, b_id.id).await, 0);
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 1);
}

/// A sponsor cannot keep a node from leaving by dating its admission into
/// the future.
#[tokio::test]
async fn a_future_dated_admission_cannot_keep_a_node_from_leaving() {
    let (a_id, w_id) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let a = Addr {
        name: "a",
        id: a_id.id,
        port: 1,
    };
    let (x, _dx) = offline_node(&[&a]).await;
    let info = peephole::cluster::record::MemberInfo {
        id: w_id.id,
        name: "w".into(),
        address: None,
        roles: vec![],
        proto_min: 2,
        proto_max: 2,
        remote_config: false,
    };
    // A admits W, then dates a re-admission far ahead: that one is not
    // taken before its time (A's stream waits there).
    let far = hlc_days_ago(0, 4) + ((400u64 * 24 * 3600 * 1000) << 16);
    let st = repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(
                &a_id,
                1,
                hlc_days_ago(0, 1),
                &Record::MemberAdd(info.clone()),
            )
            .unwrap(),
            WireEntry::sign(&a_id, 2, far, &Record::MemberAdd(info.clone())).unwrap(),
        ],
    )
    .await
    .unwrap();
    assert_eq!((st.applied, st.rejected), (1, 1), "{st:?}");
    repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(&w_id, 1, hlc_days_ago(0, 2), &Record::MemberUpdate(info)).unwrap(),
            WireEntry::sign(
                &w_id,
                2,
                hlc_days_ago(0, 3),
                &Record::MemberRevoke { id: w_id.id },
            )
            .unwrap(),
        ],
    )
    .await
    .unwrap();
    let rows = members::all(&x.store).await.unwrap();
    let w = rows.iter().find(|m| m.id == w_id.id).unwrap();
    assert_eq!(w.standing, members::Standing::Left);
}

/// A node that kept running but was cut off for 30 days keeps probing the
/// members it believes pruned, and learns from them that it is the one
/// that was pruned.
#[tokio::test]
async fn a_node_cut_off_for_30_days_learns_it_was_pruned() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("everyone knows everyone", || async {
        knows(&na, c.id, true).await
            && knows(&nb, c.id, true).await
            && knows(&nc, a.id, true).await
            && knows(&nc, b.id, true).await
    })
    .await;
    // Let every log reach every node first, so no late admission arrives
    // after the clocks are turned back below.
    eventually("logs converged", || async {
        let mut same = true;
        for origin in [a.id, b.id, c.id] {
            let h = head_of(&na, origin).await;
            same &= h > 0 && h == head_of(&nb, origin).await && h == head_of(&nc, origin).await;
        }
        same
    })
    .await;
    // 40 days without contact, as each side sees the other.
    let forget = |n: &TestNode, who: NodeId| {
        let pool = n.store.pool.clone();
        async move {
            let old = hlc_days_ago(40, 0) as i64;
            sqlx::query("UPDATE repl_log SET hlc = ? WHERE origin = ?")
                .bind(old)
                .bind(&who.0[..])
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("UPDATE members SET admitted_hlc = ? WHERE id = ?")
                .bind(old)
                .bind(&who.0[..])
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    forget(&na, c.id).await;
    forget(&nb, c.id).await;
    forget(&nc, a.id).await;
    forget(&nc, b.id).await;
    eventually_for(
        Duration::from_secs(90),
        "c learns it was pruned",
        || async { nc.detached() == Some(cluster::Detached::Pruned) },
    )
    .await;
    assert_eq!(na.detached(), None);
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
            remote_config: false,
            origin_quota_mb: 20 * 1024,
            peers: vec![PeerConfig {
                name: "a".into(),
                address: "127.0.0.1:1".into(),
                public_key: a_id.id.to_string(),
            }],
        },
        roles: Roles::default(),
        store,
        proto: (1, 1),
        data_dir: dir.path().to_path_buf(),
        retention_days: 0,
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();

    let info = |id: &Identity, name: &str| peephole::cluster::record::MemberInfo {
        id: id.id,
        name: name.into(),
        address: None,
        roles: vec![],
        proto_min: 1,
        proto_max: 1,
        remote_config: false,
    };
    // Forgery: b signs an entry claiming to come from a.
    let mut forged =
        WireEntry::sign(&b_id, 1, 1, &Record::MemberUpdate(info(&a_id, "evil"))).unwrap();
    forged.origin = a_id.id;
    let st = repl::apply_batch(&node, vec![forged]).await.unwrap();
    assert_eq!((st.applied, st.rejected), (0, 1));

    // b is unknown: its own (valid) entry is parked...
    let b1 = WireEntry::sign(
        &b_id,
        1,
        hlc_days_ago(0, 10),
        &Record::MemberUpdate(info(&b_id, "b")),
    )
    .unwrap();
    let st = repl::apply_batch(&node, vec![b1]).await.unwrap();
    assert_eq!((st.applied, st.parked), (0, 1));
    // ...a gap is rejected...
    let b3 = WireEntry::sign(
        &b_id,
        3,
        hlc_days_ago(0, 12),
        &Record::MemberUpdate(info(&b_id, "b3")),
    )
    .unwrap();
    assert_eq!(
        repl::apply_batch(&node, vec![b3]).await.unwrap().rejected,
        1
    );
    // ...and once trusted a admits b, the parked entry applies.
    let a1 = WireEntry::sign(
        &a_id,
        1,
        hlc_days_ago(0, 20),
        &Record::MemberAdd(info(&b_id, "b-by-a")),
    )
    .unwrap();
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
        // What this build's rules make of the request: the credits' rules
        // gate compares a member's newest requests with them.
        labels_json: r#"["form-interaction","scanner-ua","sqli"]"#.into(),
        severity: 4,
        scan_level: 3,
        is_fp_claim: false,
        page_token: Some("tok-1".into()),
        ..Default::default()
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
    invite::join(
        &nc,
        &invite::create(&nb, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();

    let r = rec(&na);
    let ip = na
        .store
        .upsert_ip("198.51.100.77".parse().unwrap())
        .await
        .unwrap();
    r.record_geo(ip.id, None, Some("DE"), Some(64500), Some("Example AS"))
        .await
        .unwrap();
    r.record_tor(ip.id, true).await.unwrap();
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

/// A canary served on A and used on B: both nodes find the same reuse.
#[tokio::test]
async fn canary_reuse_is_found_on_every_node() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip_a = na
        .store
        .upsert_ip("198.51.100.10".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&NewRequest {
            ip_id: ip_a.id,
            method: "GET".into(),
            path: "/.git/config".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            page_token: Some("served-on-a".into()),
            answer: Some("decoy:git-config".into()),
            decoy_v: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    let token = peephole::canary::value("served-on-a", peephole::canary::Kind::GitToken);
    let auth = data_encoding::BASE64.encode(format!("deploy:{token}").as_bytes());
    let ip_b = nb
        .store
        .upsert_ip("198.51.100.11".parse().unwrap())
        .await
        .unwrap();
    rec(&nb)
        .insert_request(&NewRequest {
            ip_id: ip_b.id,
            method: "GET".into(),
            path: "/x".into(),
            headers_json: format!(r#"[["authorization","Basic {auth}"]]"#),
            labels_json: "[]".into(),
            page_token: Some("used-on-b".into()),
            answer: Some("not-found".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let sql =
        "SELECT COUNT(*) FROM request_tokens t JOIN canaries c ON c.value_hash = t.value_hash";
    for n in [&na, &nb] {
        eventually("reuse found", || async { count(n, sql).await == 1 }).await;
    }
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
            remote_config: false,
            origin_quota_mb: 20 * 1024,
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
        store,
        proto: (1, 1),
        data_dir: dir.path().to_path_buf(),
        retention_days: 0,
    })
    .await
    .unwrap();
    node.bootstrap().await.unwrap();
    (node, dir)
}

async fn batch_of(n: &Node, origin: NodeId) -> peephole::cluster::sync::Batch {
    repl::entries_after(&n.store, &[(origin, 0)], 0, 10_000, usize::MAX)
        .await
        .unwrap()
}

/// How far `n` holds `origin`'s log.
async fn head_of(n: &Node, origin: NodeId) -> u64 {
    repl::head_in(&repl::heads(&n.store).await.unwrap(), &origin)
}

async fn request_uid(n: &Node, path: &str) -> String {
    sqlx::query_scalar("SELECT uid FROM requests WHERE path = ?")
        .bind(path)
        .fetch_one(&n.store.pool)
        .await
        .unwrap()
}

/// Request paths in `n`'s tables, sorted.
async fn paths(n: &Node) -> Vec<String> {
    let mut p: Vec<String> = sqlx::query_scalar("SELECT path FROM requests")
        .fetch_all(&n.store.pool)
        .await
        .unwrap();
    p.sort();
    p
}

/// An erased entry is accepted only with the origin's own tombstone: a
/// relay cannot make other nodes drop somebody's records.
#[tokio::test]
async fn erased_stubs_need_the_origins_tombstone() {
    use peephole::cluster::sync::Batch;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.70".parse().unwrap())
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
    let (one, two) = (
        request_uid(&na, "/one").await,
        request_uid(&na, "/two").await,
    );
    let before = batch_of(&na, a.id).await;
    assert!(before.proofs.is_empty());
    rec(&na).delete_request(r1).await.unwrap();
    let after = batch_of(&na, a.id).await;
    assert_eq!(after.proofs.len(), 1, "the stub travels with its tombstone");
    let tomb = after.proofs[0].uid.clone().unwrap();
    let a_head = head_of(&na, a.id).await;
    let strip = |batch: &mut Batch, uid: &str, by: Option<String>| {
        let e = batch
            .entries
            .iter_mut()
            .find(|e| e.uid.as_deref() == Some(uid))
            .unwrap();
        e.payload = None;
        e.sig = None;
        e.erased_by = by;
    };

    // A relay strips /two and claims A's tombstone erased it.
    let (x, _dx) = offline_node(&[&a, &b]).await;
    let mut forged = Batch {
        bounds: vec![],
        floors: vec![],
        entries: before.entries.clone(),
        proofs: after.proofs.clone(),
    };
    strip(&mut forged, &two, Some(tomb.clone()));
    let st = repl::apply_batch(&x, forged).await.unwrap();
    assert!(st.rejected >= 1, "{st:?}");
    assert!(
        head_of(&x, a.id).await < a_head,
        "the stream stops at the forgery"
    );
    assert_eq!(
        count(&x, "SELECT COUNT(*) FROM requests WHERE path = '/two'").await,
        0
    );
    // The honest stream still applies afterwards.
    let st = repl::apply_batch(&x, batch_of(&na, a.id).await)
        .await
        .unwrap();
    assert_eq!(st.rejected, 0, "{st:?}");
    assert_eq!(head_of(&x, a.id).await, a_head);
    assert_eq!(paths(&x).await, ["/two"]);
    // X can pass the erasure on with its proof.
    assert_eq!(batch_of(&x, a.id).await.proofs.len(), 1);

    // A relay relabels the live /two entry as the erased /one: the proof
    // names /one's own position in A's log, so it does not cover this one.
    let (w, _dw) = offline_node(&[&a, &b]).await;
    let mut relabel = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: after.proofs.clone(),
    };
    let e = relabel
        .entries
        .iter_mut()
        .find(|e| e.uid.as_deref() == Some(two.as_str()))
        .unwrap();
    e.payload = None;
    e.sig = None;
    e.uid = Some(one.clone());
    e.erased_by = Some(tomb.clone());
    let st = repl::apply_batch(&w, relabel).await.unwrap();
    assert!(st.rejected >= 1, "relabelled entry: {st:?}");
    assert!(head_of(&w, a.id).await < a_head);

    // No proof, a proof from another origin, a stub without a uid: rejected.
    let stub_only = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: vec![],
    };
    let other = Identity::generate().unwrap();
    let wrong_origin = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: vec![
            WireEntry::sign(
                &other,
                1,
                1,
                &Record::Tombstone(peephole::cluster::record::TombstoneRec {
                    uid: tomb.clone(),
                    uids: vec![one.clone()],
                    seqs: vec![1],
                }),
            )
            .unwrap(),
        ],
    };
    let mut no_uid = Batch {
        bounds: vec![],
        floors: vec![],
        entries: after.entries.clone(),
        proofs: after.proofs.clone(),
    };
    no_uid
        .entries
        .iter_mut()
        .find(|e| e.payload.is_none())
        .unwrap()
        .uid = None;
    for (what, bad) in [
        ("no proof", stub_only),
        ("foreign proof", wrong_origin),
        ("stub without uid", no_uid),
    ] {
        let (y, _dy) = offline_node(&[&a, &b]).await;
        let st = repl::apply_batch(&y, bad).await.unwrap();
        assert!(st.rejected >= 1, "{what}: {st:?}");
        assert!(head_of(&y, a.id).await < a_head, "{what}");
    }
}

#[tokio::test]
async fn deletes_reach_only_the_deleters_own_records() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip_a = na
        .store
        .upsert_ip("203.0.113.66".parse().unwrap())
        .await
        .unwrap();
    let r1 = rec(&na)
        .insert_request(&new_request(ip_a.id, "/one"))
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip_a.id, "/two"))
        .await
        .unwrap();
    rec(&na)
        .insert_fp_claim(ip_a.id, r1, None, "ua")
        .await
        .unwrap();
    let ip_b = nb
        .store
        .upsert_ip("203.0.113.66".parse().unwrap())
        .await
        .unwrap();
    rec(&nb)
        .insert_request(&new_request(ip_b.id, "/three"))
        .await
        .unwrap();
    eventually("both have three requests", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 3
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 3
    })
    .await;
    eventually("b has the claim", || async {
        count(&nb, "SELECT COUNT(*) FROM fp_claims").await == 1
    })
    .await;

    // B cannot delete A's request for the cluster: it only hides it locally.
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 2);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 3);

    // A deletes its own: gone everywhere, with its claim, and erased from
    // every log, also where it was only hidden.
    let out = rec(&na).delete_request(r1).await.unwrap();
    assert_eq!(out.deleted, 1);
    eventually("b erased /one and its claim from its log", || async {
        count(
            &nb,
            "SELECT COUNT(*) FROM repl_log WHERE erased_by IS NOT NULL",
        )
        .await
            == 2
    })
    .await;
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM fp_claims").await, 0);

    // Deleting the IP on A removes what A recorded everywhere. B's request
    // for that IP stays in the cluster; A only hides it for itself.
    let out = rec(&na).delete_ips(&[ip_a.id]).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (1, 1));
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 0);
    assert_eq!(count(&na, "SELECT COUNT(*) FROM ips").await, 0);
    eventually("only b's request is left on b", || async {
        paths(&nb).await == ["/three"]
    })
    .await;

    // B deletes the IP: now it is gone on both.
    assert!(rec(&nb).delete_ip(ip_b.id).await.unwrap());
    eventually("ip gone everywhere", || async {
        count(&na, "SELECT COUNT(*) FROM ips").await == 0
            && count(&nb, "SELECT COUNT(*) FROM ips").await == 0
    })
    .await;
}

/// Deleting another node's record hides it here and nowhere else, and this
/// node keeps relaying it.
#[tokio::test]
async fn foreign_delete_hides_locally_and_keeps_relaying() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.71".parse().unwrap())
        .await
        .unwrap();
    let mut first = None;
    for path in ["/one", "/two"] {
        let id = rec(&na)
            .insert_request(&new_request(ip.id, path))
            .await
            .unwrap();
        first.get_or_insert(id);
    }
    // /one comes with a browser fingerprint.
    rec(&na)
        .insert_fingerprint(first, ip.id, "fp1", Some("v1"), "{}", "{}", b"events")
        .await
        .unwrap();
    eventually("b has both, and the fingerprint", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM fingerprints").await == 1
    })
    .await;
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
    assert_eq!(
        count(&nb, "SELECT COUNT(*) FROM fingerprints").await,
        0,
        "the hidden request's fingerprint is hidden with it"
    );
    // Repeating it finds nothing and fails nothing.
    let again = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((again.deleted, again.hidden), (0, 0));
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 2);

    // A node fed only from B's copy still gets all of A's records, signed.
    let from_b = batch_of(&nb, a.id).await;
    assert!(from_b.proofs.is_empty());
    assert!(from_b.entries.iter().all(|e| e.verify()), "payloads intact");
    let (x, _dx) = offline_node(&[&a, &b]).await;
    repl::apply_batch(&x, from_b).await.unwrap();
    assert_eq!(count(&x, "SELECT COUNT(*) FROM requests").await, 2);

    // Hidden stays hidden, also across a re-application of the log.
    repl::rematerialize(&nb).await.unwrap();
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
}

/// Record a request for `ip` on `n`.
async fn record(n: &TestNode, ip: &str, path: &str) {
    let row = n.store.upsert_ip(ip.parse().unwrap()).await.unwrap();
    rec(n)
        .insert_request(&new_request(row.id, path))
        .await
        .unwrap();
}

/// Blocking a peer takes its records out of this node's view, keeps them
/// flowing to others, and is undone by unblocking.
#[tokio::test]
async fn blocking_a_peer_hides_its_records_until_unblocked() {
    use peephole::cluster::block;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    record(&na, "203.0.113.72", "/a1").await;
    record(&nb, "203.0.113.73", "/b1").await;
    rec(&na)
        .insert_skip_batch(
            "203.0.113.72",
            1,
            vec![peephole::cluster::record::SkipRow {
                ts_ms: 1,
                method: "GET".into(),
                path: "/a0".into(),
                ..Default::default()
            }],
        )
        .await
        .unwrap();
    eventually("everyone has both", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nc, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM skipped_requests").await == 1
    })
    .await;

    assert!(block::block(&nb, nb.id()).await.is_err(), "not oneself");
    assert_eq!(
        block::block(&nb, a.id).await.unwrap(),
        2,
        "its request and light rows"
    );
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM skipped_batches").await, 0);
    assert_eq!(
        block::block(&nb, a.id).await.unwrap(),
        0,
        "repeat is harmless"
    );
    assert!(nb.is_blocked(&a.id));
    assert!(nb.dial_targets().iter().all(|t| t.0 != a.id));
    assert_eq!(paths(&nb).await, ["/b1"]);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM ips").await, 1);
    let e = na.hello(b.id, &b.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("blocked"), "{e:#}");

    // A keeps recording. B receives it through C, stores it for relaying,
    // and does not show it.
    record(&na, "203.0.113.72", "/a2").await;
    eventually("b holds a's stream via c", || async {
        head_of(&nb, a.id).await == head_of(&na, a.id).await
    })
    .await;
    assert_eq!(paths(&nb).await, ["/b1"]);
    assert_eq!(paths(&nc).await, ["/a1", "/a2", "/b1"]);
    assert!(
        batch_of(&nb, a.id).await.entries.iter().all(|e| e.verify()),
        "b can still relay a's records"
    );

    assert!(block::unblock(&nb, a.id).await.unwrap());
    assert!(
        !block::unblock(&nb, a.id).await.unwrap(),
        "repeat is harmless"
    );
    assert_eq!(paths(&nb).await, ["/a1", "/a2", "/b1"]);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM skipped_requests").await, 1);
    assert!(!nb.is_blocked(&a.id));
}

/// A cluster node's admin cannot delete records: the data belongs to the
/// cluster, and retention prunes it.
#[tokio::test]
async fn admin_cannot_delete_on_a_cluster_node() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let ip = na
        .store
        .upsert_ip("203.0.113.74".parse().unwrap())
        .await
        .unwrap();
    rec(&na)
        .insert_request(&new_request(ip.id, "/one"))
        .await
        .unwrap();
    eventually("b has it", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM requests")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let (admin, base) = admin_on(&nb).await;
    let page = admin
        .get(format!("{base}/admin/requests/{id}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("/delete"), "no delete button");
    let r = admin
        .post(format!("{base}/admin/requests/{id}/delete"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 1);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM hidden").await, 0);
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
        // Two API lookups while standalone: both are history.
        for score in [10, 20] {
            s.local()
                .record_lookup(
                    "192.0.2.200",
                    peephole::intel::ABUSEIPDB,
                    None,
                    serde_json::json!({ "score": score }),
                )
                .await
                .unwrap();
        }
        for i in 0..150 {
            s.insert_request(&new_request(ip.id, &format!("/p{i}")))
                .await
                .unwrap();
        }
        let light = |path: &str| peephole::cluster::record::SkipRow {
            ts_ms: 1,
            method: "GET".into(),
            path: path.into(),
            ..Default::default()
        };
        s.local()
            .insert_skip_batch("192.0.2.200", 3, vec![light("/s1"), light("/s2")])
            .await
            .unwrap();
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
            && count(&nb, "SELECT COUNT(*) FROM skipped_requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM ports").await == 3
            && count(
                &nb,
                "SELECT COUNT(*) FROM ip_intel_log WHERE provider = 'abuseipdb'",
            )
            .await
                == 2
    })
    .await;
    assert_eq!(
        count(&na, "SELECT COUNT(*) FROM ip_intel_log WHERE origin = x''").await
            + count(&na, "SELECT COUNT(*) FROM ip_intel WHERE origin = x''").await,
        0,
        "every standalone result is now a's"
    );
    let score: Option<i64> = sqlx::query_scalar("SELECT abuse_score FROM ips")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(score, Some(20), "the newest lookup wins");
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
    // Scanners only run jobs the IP's requests back (three, so the level
    // is not capped as thin evidence).
    for i in 0..3 {
        rec(n)
            .insert_request(&new_request(row.id, &format!("/probe{i}")))
            .await
            .unwrap();
    }
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
                max_workers: peephole::scan::pace::MIN_WORKERS,
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

async fn knows_scanner(n: &Node, id: NodeId) -> bool {
    members::all(&n.store)
        .await
        .unwrap()
        .iter()
        .any(|m| m.id == id && m.roles.iter().any(|r| r == "scanner"))
}

/// never_scan is local: B leaves the target alone, C scans it.
#[tokio::test]
async fn never_scan_is_local_to_its_scanner() {
    let (tools_b, tools_c) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let _nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            never_scan: vec!["192.0.2.0/24".into()],
            scanner: Some(fake_nmap(tools_b.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    let _nc = boot(
        ic,
        &c,
        &[&a, &b],
        Opts {
            scanner: Some(fake_nmap(tools_c.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    eventually("a knows both scanners", || async {
        knows_scanner(&na, b.id).await && knows_scanner(&na, c.id).await
    })
    .await;
    enqueue(&na, "192.0.2.10", 2).await;
    eventually_for(Duration::from_secs(30), "c scanned it", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
    assert!(
        !tools_b.path().join("targets.log").exists(),
        "b's nmap must not run"
    );
}

/// When every scanner declines, the job ends as refused instead of
/// circling in the queue.
#[tokio::test]
async fn job_declined_by_every_scanner_is_refused() {
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            never_scan: vec!["192.0.2.0/24".into()],
            scanner: Some(fake_nmap(tools.path(), 0.1)),
            ..DEFAULT
        },
    )
    .await;
    eventually("a knows the scanner", || knows_scanner(&na, b.id)).await;
    enqueue(&na, "192.0.2.10", 2).await;
    eventually_for(Duration::from_secs(30), "job refused", || async {
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
                uid: format!("{}dup-job", b.id.uid_prefix()),
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
    invite::join(
        &nc,
        &invite::create(&na, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    enqueue(&na, "203.0.113.90", 2).await;
    eventually_for(Duration::from_secs(20), "c scanned a's job", || async {
        scans_by(&na, c.id).await == 1
    })
    .await;
}

use peephole::intel::share;

/// The Tor exit list is shared as a file; GeoLite2 databases are not.
#[tokio::test]
async fn only_the_tor_list_is_shared_as_a_file() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    std::fs::write(na.dir.path().join("tor-exit.txt"), tor_list(200)).unwrap();
    std::fs::copy(
        "tests/fixtures/GeoLite2-City-Test.mmdb",
        na.dir.path().join("GeoLite2-City.mmdb"),
    )
    .unwrap();
    share::publish(&na, na.dir.path(), &[share::TOR])
        .await
        .unwrap();
    assert!(
        share::publish(&na, na.dir.path(), &["geolite2-city"])
            .await
            .is_err(),
        "a database is never announced"
    );
    eventually("b knows the manifest", || async {
        share::manifests(&nb.store).await.unwrap().len() == 1
    })
    .await;
    assert_eq!(
        share::sync_files(&nb, nb.dir.path()).await.unwrap(),
        [share::TOR]
    );
    assert!(nb.dir.path().join("tor-exit.txt").exists());
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // The copy carries the fetcher's time, which the stale-intel warning reads.
    let m = share::manifests(&nb.store).await.unwrap();
    peephole::intel::note_cluster_intel(&nb, nb.dir.path(), true, &m)
        .await
        .unwrap();
    assert_eq!(
        nb.store.intel_get("tor_last_fetch").await.unwrap(),
        m[share::TOR].fetched_rfc3339()
    );
    // A manifest for a database, written by a peer on its own, is ignored.
    repl::append(
        &na,
        &[Record::IntelManifest(
            peephole::cluster::record::IntelManifestRec {
                kind: "geolite2-city".into(),
                sha256: "00".into(),
                size: 1,
                fetched_at: peephole::store::data::now_ts(),
            },
        )],
    )
    .await
    .unwrap();
    eventually("b holds a's newest entry", || async {
        head_of(&nb, a.id).await == head_of(&na, a.id).await
    })
    .await;
    assert_eq!(share::manifests(&nb.store).await.unwrap().len(), 1);
}

/// An exit list with `n` addresses.
fn tor_list(n: u32) -> String {
    (0..n)
        .map(|i| format!("198.18.{}.{}\n", i / 250, i % 250 + 1))
        .collect()
}

/// A peer's exit list passes the same sanity check as a downloaded one,
/// and an announcement older than three days is not copied.
#[tokio::test]
async fn a_tiny_or_stale_tor_list_is_not_copied_from_a_peer() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let good = tor_list(200);
    std::fs::write(nb.dir.path().join("tor-exit.txt"), &good).unwrap();
    // Tiny list, freshly announced: hash matches, content does not pass.
    std::fs::write(na.dir.path().join("tor-exit.txt"), "192.0.2.1\n192.0.2.2\n").unwrap();
    share::publish(&na, na.dir.path(), &[share::TOR])
        .await
        .unwrap();
    eventually("b knows the manifest", || async {
        share::manifests(&nb.store).await.unwrap().len() == 1
    })
    .await;
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_to_string(nb.dir.path().join("tor-exit.txt")).unwrap(),
        good,
        "b keeps its own list"
    );
    // A big list announced as fetched four days ago.
    std::fs::write(na.dir.path().join("tor-exit.txt"), tor_list(300)).unwrap();
    let (sha256, size) = share::file_hash(&na.dir.path().join("tor-exit.txt")).unwrap();
    let old = (chrono::Utc::now() - chrono::Duration::days(4))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    repl::append(
        &na,
        &[Record::IntelManifest(
            peephole::cluster::record::IntelManifestRec {
                kind: share::TOR.into(),
                sha256: sha256.clone(),
                size,
                fetched_at: old,
            },
        )],
    )
    .await
    .unwrap();
    eventually("b knows the old manifest", || async {
        share::manifests(&nb.store).await.unwrap()[share::TOR].sha256 == sha256
    })
    .await;
    assert!(
        share::sync_files(&nb, nb.dir.path())
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        std::fs::read_to_string(nb.dir.path().join("tor-exit.txt")).unwrap(),
        good
    );
}

/// A node without the databases gets GeoIP facts from one that has them;
/// the database itself does not travel.
#[tokio::test]
async fn geo_results_come_from_a_node_that_has_the_database() {
    use peephole::intel::provider::MaxMind;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    let geo: peephole::intel::SharedGeo = Default::default();
    *geo.write().unwrap() = Some(peephole::intel::geo::GeoIp::load(na.dir.path()).unwrap());
    let providers: peephole::intel::Providers = vec![Arc::new(MaxMind(geo))];
    // B, which cannot look anything up, records a request.
    record(&nb, "2.125.160.216", "/x").await;
    let nothing: peephole::intel::Providers = vec![Arc::new(MaxMind(Default::default()))];
    assert_eq!(
        peephole::intel::enrich_once(&rec(&nb), &nothing)
            .await
            .unwrap(),
        0
    );
    eventually("a has b's request", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    assert_eq!(
        peephole::intel::enrich_once(&rec(&na), &providers)
            .await
            .unwrap(),
        1
    );
    assert_eq!(na.providers(), [peephole::intel::MAXMIND]);
    eventually("b shows the country", || async {
        sqlx::query_scalar::<_, Option<String>>("SELECT country FROM ips")
            .fetch_one(&nb.store.pool)
            .await
            .unwrap()
            .as_deref()
            == Some("GB")
    })
    .await;
    assert!(!nb.dir.path().join("GeoLite2-City.mmdb").exists());
    // Asked once: a second pass has nothing to do.
    assert_eq!(
        peephole::intel::enrich_once(&rec(&na), &providers)
            .await
            .unwrap(),
        0
    );
}

/// A peer this node blocked does not take a turn in the lookup order.
#[tokio::test]
async fn a_blocked_peer_does_not_hold_up_enrichment() {
    use peephole::cluster::block;
    use peephole::intel::provider::MaxMind;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    for f in ["GeoLite2-City", "GeoLite2-ASN"] {
        std::fs::copy(
            format!("tests/fixtures/{f}-Test.mmdb"),
            na.dir.path().join(format!("{f}.mmdb")),
        )
        .unwrap();
    }
    let geo: peephole::intel::SharedGeo = Default::default();
    *geo.write().unwrap() = Some(peephole::intel::geo::GeoIp::load(na.dir.path()).unwrap());
    let providers: peephole::intel::Providers = vec![Arc::new(MaxMind(geo))];
    // Both can look up; the lower key goes first.
    let (first, second) = if a.id < b.id { (&na, &nb) } else { (&nb, &na) };
    assert_eq!(
        peephole::intel::enrich_once(&rec(first), &providers)
            .await
            .unwrap(),
        0
    );
    eventually("second knows first can look up", || async {
        second
            .status
            .known(&first.id())
            .is_some_and(|k| k.hb.providers == [peephole::intel::MAXMIND])
    })
    .await;
    record(second, "2.125.160.216", "/x").await;
    assert_eq!(
        peephole::intel::enrich_once(&rec(second), &providers)
            .await
            .unwrap(),
        0,
        "first's turn"
    );
    block::block(second, first.id()).await.unwrap();
    assert_eq!(
        peephole::intel::enrich_once(&rec(second), &providers)
            .await
            .unwrap(),
        1
    );
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
        .with_recorder(Recorder::Cluster(n.node.clone()))
        .with_settings(n.settings.clone()),
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

/// The Members page and every node page it links to, as one string.
async fn cluster_pages(admin: &reqwest::Client, base: &str) -> String {
    let mut all = text(admin, format!("{base}/admin/cluster")).await;
    let keys: Vec<String> = all
        .split("href=\"/admin/cluster/node/")
        .skip(1)
        .filter_map(|s| s.split('"').next().map(str::to_string))
        .collect();
    for k in keys {
        all.push_str(&text(admin, format!("{base}/admin/cluster/node/{k}")).await);
    }
    all
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
    let page = cluster_pages(&admin, &base).await;
    for want in [
        "sensor-alpha",
        "sensor-bravo",
        "sensor-charlie",
        &b.id.short(),
        // B and C recorded nothing to classify again, and run no trap.
        "no requests to compare",
        "none recorded",
    ] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    let head = members
        .split("<thead>")
        .nth(1)
        .unwrap()
        .split("</thead>")
        .next()
        .unwrap();
    assert_eq!(head.matches("<th>").count(), 5, "five columns: {head}");
    let sys = text(&admin, format!("{base}/admin/system")).await;
    assert!(
        sys.contains("built in")
            && sys.contains(&peephole::classify::Classifier::builtin().fingerprint()[..12])
    );
    // Unknown and malformed keys are 404.
    for bad in ["zz".to_string(), "00".repeat(32)] {
        let r = admin
            .get(format!("{base}/admin/cluster/node/{bad}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{bad}");
    }
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(
        scans.contains("id=\"scanners\"") && scans.contains(&b.id.short()),
        "scanner pace on the Scans page"
    );
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
    assert_ne!(
        nb.pace.get().max_scans_per_hour,
        77,
        "the pace of another node is not changed from the pace row"
    );
    // Invites are shown once.
    let r = admin
        .post(format!("{base}/admin/cluster/invite"))
        .form(&[("ttl_hours", "2")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("peephole1:"));
    // Attribution on admin views.
    let scans = text(&admin, format!("{base}/admin/scans")).await;
    assert!(
        scans.contains("sensor-bravo") && scans.contains("via sensor-alpha"),
        "scan history names scanner and arbiter"
    );
    let reqs = text(&admin, format!("{base}/requests?node=sensor-alpha")).await;
    assert!(
        reqs.contains("/admin.php") && reqs.contains("<th>Node</th>"),
        "requests"
    );
    let none = text(&admin, format!("{base}/requests?node=sensor-charlie")).await;
    assert!(!none.contains("/admin.php"), "node filter");
    // Removing another node is not offered.
    let r = admin
        .post(format!("{base}/admin/cluster/revoke"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success(), "revoke route is gone");
    assert!(knows(&na, c.id, true).await);
    let access = text(&admin, format!("{base}/admin/cluster/access")).await;
    assert!(
        access.contains("Leave cluster") && access.contains("Create invite"),
        "access page"
    );
    assert!(!page.contains("Create invite"), "invites left Members");
    let r = admin
        .post(format!("{base}/admin/cluster/block"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(
        r.url().path().starts_with("/admin/cluster/node/"),
        "back to the node page: {}",
        r.url()
    );

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

/// Enrichment results replicate with their origin; a blocked peer's results
/// stop counting and come back on unblock.
#[tokio::test]
async fn enrichment_results_replicate_and_follow_blocks() {
    use peephole::cluster::block;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.90", "/x").await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    let country = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT country FROM ips WHERE ip = '203.0.113.90'",
            )
            .fetch_optional(&pool)
            .await
            .unwrap()
            .flatten()
        }
    };
    eventually("b shows a's result", || async {
        country(&nb).await.as_deref() == Some("NL")
    })
    .await;
    let origin: Vec<u8> = sqlx::query_scalar("SELECT origin FROM ip_intel")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(origin, a.id.0.to_vec(), "provenance is kept");
    // The same result again writes nothing.
    let head = head_of(&na, a.id).await;
    rec(&na)
        .record_intel(
            "203.0.113.90",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL", "asn": 1}),
        )
        .await
        .unwrap();
    assert_eq!(head_of(&na, a.id).await, head);

    block::block(&nb, a.id).await.unwrap();
    assert_eq!(
        country(&nb).await,
        None,
        "a blocked peer's results do not count"
    );
    block::unblock(&nb, a.id).await.unwrap();
    assert_eq!(country(&nb).await.as_deref(), Some("NL"));
}

/// API lookups are each kept: the history replicates, follows blocks, and
/// exports with UTC times; the admin-only score never reaches public pages.
#[tokio::test]
async fn api_lookup_history_replicates_and_follows_blocks() {
    use peephole::cluster::block;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.92", "/x").await;
    for _ in 0..2 {
        rec(&na)
            .record_lookup(
                "203.0.113.92",
                peephole::intel::ABUSEIPDB,
                None,
                serde_json::json!({"score": 77, "categories": ["SSH"]}),
            )
            .await
            .unwrap();
    }
    let history = "SELECT COUNT(*) FROM ip_intel_log WHERE ip = '203.0.113.92'";
    eventually("b has both lookups", || async {
        count(&nb, history).await == 2
    })
    .await;
    let score = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>(
                "SELECT abuse_score FROM ips WHERE ip = '203.0.113.92'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(score(&nb).await, Some(77));
    let (admin, base) = admin_on(&nb).await;
    let body = text(&admin, format!("{base}/admin/export/download?format=jsonl")).await;
    let row: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    let lookups: Vec<&serde_json::Value> = row["intel"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["provider"] == "abuseipdb")
        .collect();
    assert_eq!(lookups.len(), 2, "{body}");
    assert_eq!(lookups[0]["node"], "node-alpha");
    assert!(
        lookups[0]["fetched_at"]
            .as_str()
            .unwrap()
            .ends_with("+00:00"),
        "{body}"
    );
    let html = text(&admin, format!("{base}/ips?tag=abuseipdb:SSH&min_abuse=50")).await;
    assert!(html.contains("203.0.113.92"));
    let anon = reqwest::Client::new();
    let public = anon
        .get(format!("{base}/ip/203.0.113.92"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !public.contains("AbuseIPDB"),
        "admin-only provider on a public page"
    );

    block::block(&nb, a.id).await.unwrap();
    assert_eq!(count(&nb, history).await, 0, "a blocked peer's lookups go");
    assert_eq!(score(&nb).await, None);
    block::unblock(&nb, a.id).await.unwrap();
    assert_eq!(count(&nb, history).await, 2);
    assert_eq!(score(&nb).await, Some(77));
}

/// A node that consulted only GeoIP writes no Tor result of its own and
/// leaves another node's Tor result alone.
#[tokio::test]
async fn a_geo_only_write_leaves_tor_alone() {
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.91", "/x").await;
    rec(&na)
        .record_intel(
            "203.0.113.91",
            peephole::intel::TOR,
            None,
            serde_json::json!({"exit": true}),
        )
        .await
        .unwrap();
    let tor = |n: &TestNode| {
        let pool = n.store.pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>("SELECT is_tor_exit FROM ips WHERE ip = '203.0.113.91'")
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    eventually("b shows a's tor result", || async { tor(&nb).await }).await;
    let ip_id: i64 = sqlx::query_scalar("SELECT id FROM ips WHERE ip = '203.0.113.91'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    rec(&nb)
        .record_geo(ip_id, Some("2026-09-30"), Some("NL"), Some(1), None)
        .await
        .unwrap();
    let mine: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ip_intel WHERE provider = 'tor-exits' AND origin = ?",
    )
    .bind(&b.id.0[..])
    .fetch_one(&nb.store.pool)
    .await
    .unwrap();
    assert_eq!(mine, 0, "no Tor row of its own");
    assert!(tor(&nb).await, "a's Tor result still shows");
}

/// Enrichment results go out with each request, with their provenance.
#[tokio::test]
async fn enrichment_results_are_exported_with_provenance() {
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    record(&nb, "203.0.113.91", "/x").await;
    rec(&nb)
        .record_intel(
            "203.0.113.91",
            peephole::intel::MAXMIND,
            Some("2026-09-30"),
            serde_json::json!({"country": "NL"}),
        )
        .await
        .unwrap();
    eventually("a has the result", || async {
        count(&na, "SELECT COUNT(*) FROM ip_intel").await == 1
    })
    .await;
    // A result whose IP has no row any more is not exported.
    sqlx::query(
        "INSERT INTO ip_intel (ip, provider, origin, hlc, fetched_at, source_version, data_json)
         VALUES ('198.51.100.7', 'maxmind-geolite2', x'', 0, '2026-01-01T00:00:00Z', NULL, '{}')",
    )
    .execute(&na.store.pool)
    .await
    .unwrap();
    let (admin, base) = admin_on(&na).await;
    let body = text(&admin, format!("{base}/admin/export/download?format=jsonl")).await;
    assert_eq!(body.lines().count(), 1, "{body}");
    let row: serde_json::Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    assert_eq!(row["ip"], "203.0.113.91");
    assert_eq!(row["node"], "node-bravo");
    // Full provenance: the creating node's key and the build it ran.
    assert_eq!(row["node_id"], b.id.to_string());
    assert_eq!(row["build"], peephole::COMMIT);
    let geo = row["intel"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["provider"] == "maxmind-geolite2")
        .unwrap();
    assert_eq!(geo["source_version"], "2026-09-30");
    assert_eq!(geo["node"], "node-bravo");
    assert_eq!(geo["node_id"], b.id.to_string());
    assert_eq!(geo["build"], peephole::COMMIT);
    assert_eq!(geo["data"]["country"], "NL");
    assert!(
        !body.contains("198.51.100.7"),
        "results without a request stay out"
    );
    // Not public.
    let anon = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = anon
        .get(format!("{base}/admin/export/download?format=jsonl"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}

/// A node outside the test cluster, signing entries by hand (admitted by a
/// member, never dialled: it has no address).
struct Writer {
    id: Identity,
    seq: u64,
}

impl Writer {
    fn new() -> Self {
        Self {
            id: Identity::generate().unwrap(),
            seq: 0,
        }
    }

    fn at(&mut self, days_ago: u64, r: Record) -> WireEntry {
        self.seq += 1;
        WireEntry::sign(&self.id, self.seq, hlc_days_ago(days_ago, self.seq), &r).unwrap()
    }

    fn info(&self, name: &str) -> peephole::cluster::record::MemberInfo {
        peephole::cluster::record::MemberInfo {
            id: self.id.id,
            name: name.into(),
            address: None,
            roles: vec![],
            proto_min: cluster::rpc::proto::PROTO_MIN,
            proto_max: cluster::rpc::proto::PROTO_VERSION,
            remote_config: false,
        }
    }

    fn request(&self, path: &str) -> Record {
        Record::Request(Box::new(peephole::cluster::record::RequestRec {
            uid: format!(
                "{}{}",
                self.id.id.uid_prefix(),
                path.trim_start_matches('/')
            ),
            ts: "2026-09-01 00:00:00".into(),
            ip: "203.0.113.66".into(),
            method: "GET".into(),
            path: path.into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            severity: 1,
            ..Default::default()
        }))
    }

    /// A description, two records far outside a week and one inside.
    fn history(&mut self) -> Vec<WireEntry> {
        vec![
            self.at(40, Record::MemberUpdate(self.info("writer"))),
            self.at(40, self.request("/old1")),
            self.at(30, self.request("/old2")),
            self.at(0, self.request("/new1")),
        ]
    }
}

/// `o`'s sequences held by `n`.
async fn seqs_of(n: &Node, o: NodeId) -> Vec<i64> {
    sqlx::query_scalar("SELECT seq FROM repl_log WHERE origin = ? ORDER BY seq")
        .bind(&o.0[..])
        .fetch_all(&n.store.pool)
        .await
        .unwrap()
}

/// Sync rounds all of `nodes` run over a few quiet seconds. A loop that
/// re-syncs without pause runs hundreds, even on a slow machine.
async fn quiet_rounds(nodes: &[&Node]) -> u64 {
    let total = || {
        nodes
            .iter()
            .map(|n| n.sync_rounds.load(std::sync::atomic::Ordering::Relaxed))
            .sum::<u64>()
    };
    let before = total();
    tokio::time::sleep(Duration::from_secs(3)).await;
    total() - before
}

/// One node keeps a week: old history leaves it and only it, new records
/// keep reaching it, a node joining later with the full history gets it
/// from the full members, one joining with a window gets only its window,
/// and nobody re-syncs without pause.
#[tokio::test]
async fn a_history_floor_is_local() {
    let (ia, a) = new_node("full-a");
    let (ib, b) = new_node("full-b");
    let (ip, p) = new_node("window-p");
    let week = Opts {
        retention_days: 7,
        ..DEFAULT
    };
    let na = boot(ia, &a, &[&b, &p], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &p], DEFAULT).await;
    let np = boot(ip, &p, &[&a, &b], week.clone()).await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    let st = repl::apply_batch(&na, o.history()).await.unwrap();
    assert_eq!(st.applied, 4, "{st:?}");
    eventually("b has o's history", || async {
        seqs_of(&nb, o.id.id).await.len() == 4
    })
    .await;
    // p asks only for its window (and the membership before it).
    eventually("p has o's window", || async {
        seqs_of(&np, o.id.id).await == [1, 4]
    })
    .await;
    assert_eq!(cluster::history::prune(&np).await.unwrap(), 0);
    assert_eq!(paths(&np).await, ["/new1"]);
    assert_eq!(paths(&nb).await, ["/new1", "/old1", "/old2"]);
    // New records keep coming.
    let late = o.at(0, o.request("/new2"));
    repl::apply_batch(&na, vec![late]).await.unwrap();
    eventually("p gets new records", || async {
        paths(&np).await == ["/new1", "/new2"]
    })
    .await;
    // The others learn where p's history starts.
    np.reload_floors().await.unwrap();
    np.publish_status();
    eventually("a knows p's floor", || async {
        na.peer_floor(&p.id, &o.id.id) == 4
    })
    .await;

    // A node keeping everything joins through p: the history comes from
    // the full members.
    let (i_f, f) = new_node("full-f");
    let nf = boot(i_f, &f, &[], DEFAULT).await;
    invite::join(
        &nf,
        &invite::create(&np, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("f backfills everything", || async {
        seqs_of(&nf, o.id.id).await == [1, 2, 3, 4, 5]
    })
    .await;
    // A node keeping a week joins: only its window, and the membership.
    let (iw, w) = new_node("window-w");
    let nw = boot(iw, &w, &[], week).await;
    invite::join(
        &nw,
        &invite::create(&na, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("w gets its window", || async {
        paths(&nw).await == ["/new1", "/new2"]
    })
    .await;
    assert_eq!(seqs_of(&nw, o.id.id).await, [1, 4, 5]);
    assert!(
        members::all(&nw.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == o.id.id && m.name == "writer")
    );

    let rounds = quiet_rounds(&[&na, &nb, &np, &nf, &nw]).await;
    assert!(rounds <= 30, "{rounds} sync rounds in 3 s");

    // The admin page says who keeps what.
    let (admin, base) = admin_on(&na).await;
    let page = cluster_pages(&admin, &base).await;
    for want in ["keeps 7 days", "full history"] {
        assert!(page.contains(want), "cluster page lacks {want}");
    }
}

/// A node keeping everything whose only reachable peer keeps a window, and
/// a node that purged an origin its peer still has: neither re-syncs
/// without pause, and the first says it waits for a full member.
#[tokio::test]
async fn unservable_history_does_not_make_peers_spin() {
    let (ia, a) = new_node("full-a");
    let (ip, p) = new_node("window-p");
    let na = boot(ia, &a, &[&p], DEFAULT).await;
    let np = boot(
        ip,
        &p,
        &[&a],
        Opts {
            retention_days: 7,
            ..DEFAULT
        },
    )
    .await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    repl::apply_batch(&na, o.history()).await.unwrap();
    eventually("p has o's window", || async {
        seqs_of(&np, o.id.id).await == [1, 4]
    })
    .await;
    np.reload_floors().await.unwrap();
    np.publish_status();

    // a purges o while p still has it, and gets ahead: p's next entry of o.
    peephole::cluster::block::block(&na, o.id.id).await.unwrap();
    peephole::cluster::block::purge(&na, o.id.id).await.unwrap();
    repl::apply_batch(&np, vec![o.at(0, o.request("/new2"))])
        .await
        .unwrap();
    let rounds = quiet_rounds(&[&na, &np]).await;
    assert!(
        rounds <= 15,
        "{rounds} sync rounds in 3 s with a purged origin"
    );

    // A full node joins while only p is up.
    drop(na);
    let (i_f, f) = new_node("full-f");
    let nf = boot(i_f, &f, &[], DEFAULT).await;
    invite::join(
        &nf,
        &invite::create(&np, &Default::default()).await.unwrap(),
    )
    .await
    .unwrap();
    eventually("f knows p's floor", || async {
        nf.peer_floor(&p.id, &o.id.id) == 4
    })
    .await;
    let rounds = quiet_rounds(&[&nf, &np]).await;
    assert!(rounds <= 15, "{rounds} sync rounds in 3 s next to a window");
    assert!(seqs_of(&nf, o.id.id).await.is_empty() || seqs_of(&nf, o.id.id).await == [1]);
    let (admin, base) = admin_on(&nf).await;
    let page = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(
        page.contains("waiting for a full member"),
        "cluster page lacks the warning"
    );
}

/// The cluster page counts what each member contributed, by data type.
#[tokio::test]
async fn admin_page_shows_contributions_per_node() {
    let (ia, a) = new_node("counter-a");
    let na = boot(ia, &a, &[], DEFAULT).await;
    let mut o = Writer::new();
    repl::append(&na, &[Record::MemberAdd(o.info("writer"))])
        .await
        .unwrap();
    let batch = vec![
        o.at(0, o.request("/one")),
        o.at(0, o.request("/two")),
        o.at(0, o.request("/three")),
    ];
    repl::apply_batch(&na, batch).await.unwrap();
    let (admin, base) = admin_on(&na).await;
    let page = text(&admin, format!("{base}/admin/cluster/node/{}", o.id.id)).await;
    let section = page
        .split("<h2>Contributions</h2>")
        .nth(1)
        .expect("contributions section")
        .split("</table>")
        .next()
        .unwrap();
    assert!(
        section.contains(r#"<td class="num">3</td>"#),
        "writer's three requests: {section}"
    );
    let own = text(&admin, format!("{base}/admin/cluster/node/{}", a.id)).await;
    assert!(
        own.contains("<h2>Contributions</h2>") && own.contains("this node"),
        "{own}"
    );
    // The members table shows each node's share at a glance.
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    let row = members
        .split(&format!("/admin/cluster/node/{}\"", o.id.id))
        .nth(1)
        .expect("writer row")
        .split("</tr>")
        .next()
        .unwrap();
    assert!(
        row.contains(r#"<td class="num">3 · 100 %</td>"#),
        "writer's share: {row}"
    );
}

/// Nodes with one ownership key find each other; nobody else is a sibling,
/// and a released node is dropped at the next round.
#[tokio::test]
async fn fleet_nodes_find_each_other_and_nobody_else() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id, d) = new_node("d");
    let na = boot(ia, &a, &[&b, &c, &d], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c, &d], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b, &d], DEFAULT).await;
    let nd = boot(id, &d, &[&a, &b, &c], DEFAULT).await;
    // a and b share a key, c has its own, d has none.
    let k1 = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &k1, false).await.unwrap();
    owner::create(&nc.store, c.id).await.unwrap();

    eventually("a and b find each other", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
            && fleet::siblings(&nb.store).await.unwrap() == vec![a.id]
    })
    .await;
    eventually("c and d reach the others and find nobody", || async {
        nc.live_members(Duration::from_secs(45)).len() == 4
            && nd.live_members(Duration::from_secs(45)).len() == 4
    })
    .await;
    assert!(fleet::discover(&nc.node).await.unwrap().is_empty());
    assert!(fleet::discover(&nd.node).await.unwrap().is_empty());
    assert!(fleet::siblings(&nd.store).await.unwrap().is_empty());

    // b cannot read its owner for a moment: it does not answer, and a
    // keeps it as a sibling instead of forgetting it.
    let cert = nb.store.setting_get("owner.cert").await.unwrap().unwrap();
    nb.store.setting_set("owner.cert", "!").await.unwrap();
    assert_eq!(fleet::discover(&na.node).await.unwrap(), vec![b.id]);
    nb.store.setting_set("owner.cert", &cert).await.unwrap();

    // b is released on its own console: a learns it at its next round.
    owner::release(&nb.store).await.unwrap();
    eventually("a drops b", || async {
        fleet::discover(&na.node).await.unwrap().is_empty()
    })
    .await;
}

/// A managing node changes a sibling's settings; nobody else can, and a
/// command works only once.
#[tokio::test]
async fn a_managing_node_changes_a_siblings_settings() {
    use peephole::cluster::owner::{self, cmd, fleet};
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id, d) = new_node("d");
    let na = boot(ia, &a, &[&b, &c, &d], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c, &d], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b, &d], DEFAULT).await;
    let _nd = boot(id, &d, &[&a, &b, &c], DEFAULT).await;
    // Adopted while the nodes run: no restart is needed.
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    let stranger = owner::create(&nc.store, c.id).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;

    // Commands go only to members known to speak version 3: wait until a
    // and c have b's and d's own descriptions.
    eventually("the nodes know each other's version", || async {
        [&na, &nc].iter().all(|n| {
            let m = n.members();
            [b.id, d.id]
                .iter()
                .all(|id| m.get(id).is_some_and(|x| x.proto_max >= 3))
        })
    })
    .await;

    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    assert_eq!((st.counter, st.state.version), (0, 0));
    let faster = cmd::OwnerCmd::Settings {
        base_version: 0,
        changes: Changes {
            max_scans_per_hour: Some(77),
            ..Default::default()
        },
    };
    let note = cmd::run(&na.node, &key, b.id, 0, faster.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(note.contains("version 1"), "{note}");
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 1);
    let log = cmd::log_rows(&nb.store, 10).await.unwrap();
    assert_eq!(log.len(), 1, "status is not logged");
    assert_eq!(log[0].from, a.id);
    assert!(log[0].command.contains("scans/h=77"), "{}", log[0].command);

    // The same counter again (a replay, or a second manager): refused.
    let e = cmd::run(&na.node, &key, b.id, 0, faster.clone())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("changed meanwhile"), "{e}");

    // The settings' own rules still apply; the counter is used up anyway.
    let none = cmd::OwnerCmd::Settings {
        base_version: 1,
        changes: Changes {
            listener: Some(false),
            scanner: Some(false),
            web: Some(false),
            ..Default::default()
        },
    };
    let e = cmd::run(&na.node, &key, b.id, 1, none)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("at least one role"), "{e}");
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 2);

    // Another owner's key is not accepted, and nothing changes.
    let e = cmd::run(&nc.node, &stranger, b.id, 2, faster.clone())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 2);

    // A node that does not keep the key has nothing to send with.
    let e = cmd::kept_key(&nb.node).await.err().unwrap().to_string();
    assert!(e.contains("not kept on this node"), "{e}");

    // A node without an owner refuses.
    let e = cmd::run(&na.node, &key, d.id, 0, faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no owner"), "{e}");
}

/// A sibling that only dials out gets its commands from the outbox of a
/// member it dials, once.
#[tokio::test]
async fn owner_commands_reach_an_outbound_only_sibling() {
    use peephole::cluster::owner::{self, cmd};
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ir, r) = new_node("r");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&r], DEFAULT).await;
    let nr = boot(ir, &r, &[&a], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[],
        Opts {
            advertise: false,
            ..DEFAULT
        },
    )
    .await;
    let token = invite::create(&nr, &Default::default()).await.unwrap();
    invite::join(&nb, &token).await.unwrap();
    eventually("a knows b, which has no address", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.info_hlc > 0 && m.address.is_none())
    })
    .await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    let slower = cmd::OwnerCmd::Settings {
        base_version: 0,
        changes: Changes {
            cooldown_hours: Some(48),
            ..Default::default()
        },
    };
    eventually_for(Duration::from_secs(40), "the command arrives", || async {
        matches!(
            cmd::run(&na.node, &key, b.id, 0, slower.clone()).await,
            Ok(Ok(_))
        ) || nb.settings.snapshot().cooldown_hours == 48
    })
    .await;
    assert_eq!(nb.settings.snapshot().cooldown_hours, 48);
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 1, "applied once");
}

/// The owner's other commands on a sibling: block and unblock a peer,
/// revoke an invite, release the node, have it leave.
#[tokio::test]
async fn owner_commands_block_revoke_release_and_leave() {
    use peephole::cluster::owner::{self, cmd, cmd::OwnerCmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    // Each command with the counter the node reports.
    let go = |c: OwnerCmd| {
        let (node, key) = (na.node.clone(), &key);
        async move {
            let st = cmd::status(&node, key, b.id).await.unwrap();
            cmd::run(&node, key, b.id, st.counter, c).await.unwrap()
        }
    };

    go(OwnerCmd::Block {
        node: c.id,
        subtree: false,
    })
    .await
    .unwrap();
    assert!(nb.is_blocked(&c.id));
    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    assert_eq!(st.blocked, vec![c.id]);
    // A node is not told to block the node that manages it.
    let e = go(OwnerCmd::Block {
        node: a.id,
        subtree: false,
    })
    .await
    .unwrap_err();
    assert!(e.contains("manages it"), "{e}");
    go(OwnerCmd::Unblock { node: c.id }).await.unwrap();
    eventually("b unblocked c", || async { !nb.is_blocked(&c.id) }).await;

    invite::create(&nb, &Default::default()).await.unwrap();
    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    let inv = st.invites.iter().find(|i| i.usable).expect("an invite").id;
    go(OwnerCmd::InviteRevoke { id: inv }).await.unwrap();
    let e = go(OwnerCmd::InviteRevoke { id: inv }).await.unwrap_err();
    assert!(e.contains("no usable invite"), "{e}");

    // Released: b has no owner, a no longer counts it, commands end.
    go(OwnerCmd::Release).await.unwrap();
    assert!(owner::load(&nb.store, b.id).await.unwrap().is_none());
    assert!(fleet::siblings(&na.store).await.unwrap().is_empty());
    let e = cmd::run(&na.node, &key, b.id, 0, OwnerCmd::Leave)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no owner"), "{e}");

    // Leave: adopted again, then told to leave.
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    go(OwnerCmd::Leave).await.unwrap();
    eventually("a sees that b left", || async {
        knows(&na, b.id, false).await
    })
    .await;
}

/// Rotation moves the siblings that answer to the new key and keeps the
/// old one for the rest until they are moved or given up.
#[tokio::test]
async fn rotating_the_key_moves_reachable_siblings_and_retries_the_rest() {
    use peephole::cluster::owner::{self, cmd, cmd::OwnerCmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let old = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &old, false).await.unwrap();
    owner::adopt(&nc.store, c.id, &old, false).await.unwrap();
    eventually("a finds b and c", || async {
        fleet::discover(&na.node).await.unwrap().len() == 2
    })
    .await;
    // c cannot answer a for now: a drops what a blocked peer says.
    peephole::cluster::block::block(&na.node, c.id)
        .await
        .unwrap();

    let rot = cmd::rotate(&na.node, &[]).await.unwrap();
    assert_eq!(rot.moved, vec![b.id]);
    assert_eq!(rot.pending.len(), 1);
    assert_eq!(rot.pending[0].0, c.id);
    assert_ne!(rot.key.id, old.id);
    let mine = owner::load(&na.store, a.id).await.unwrap().unwrap();
    assert_eq!(mine.id, rot.key.id);
    assert!(mine.managing());
    assert_eq!(
        owner::load(&nb.store, b.id).await.unwrap().unwrap().id,
        rot.key.id
    );
    assert_eq!(fleet::siblings(&na.store).await.unwrap(), vec![b.id]);
    assert_eq!(cmd::pending(&na.store).await.unwrap(), vec![c.id]);
    let why = cmd::pending_reasons(&na.store).await.unwrap();
    assert!(why[0].1.contains("no answer"), "{why:?}");
    // A second rotation would forget c and the key it is still on: refused
    // while c is pending.
    let e = cmd::rotate(&na.node, &[])
        .await
        .err()
        .expect("refused")
        .to_string();
    assert!(e.contains("retry or give up"), "{e}");
    assert_eq!(cmd::pending(&na.store).await.unwrap(), vec![c.id]);
    assert_eq!(
        owner::load(&nb.store, b.id).await.unwrap().unwrap().id,
        rot.key.id,
        "b was not moved again"
    );
    // Forgetting the key now would strand c on the old one: the page refuses.
    let (admin, base) = admin_on(&na).await;
    let r = admin
        .post(format!("{base}/admin/cluster/ownership/forget-key"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(
        owner::load(&na.store, a.id)
            .await
            .unwrap()
            .unwrap()
            .managing()
    );
    assert_eq!(cmd::pending(&na.store).await.unwrap(), vec![c.id]);
    // b no longer takes the old key.
    let e = cmd::run(&na.node, &old, b.id, 0, OwnerCmd::Leave)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    // c is still on the old key.
    assert_eq!(
        owner::load(&nc.store, c.id).await.unwrap().unwrap().id,
        old.id
    );

    // Reachable again: the retry moves it and the old key is dropped.
    peephole::cluster::block::unblock(&na.node, c.id)
        .await
        .unwrap();
    // Until it is moved, c does not take the new key.
    eventually_for(Duration::from_secs(40), "c refuses the new key", || async {
        cmd::status(&na.node, &rot.key, c.id)
            .await
            .is_err_and(|e| e.to_string().contains("not accepted"))
    })
    .await;
    eventually_for(Duration::from_secs(40), "the retry moves c", || async {
        cmd::retry(&na.node)
            .await
            .unwrap()
            .iter()
            .all(|(_, r)| r.is_ok())
    })
    .await;
    assert_eq!(
        owner::load(&nc.store, c.id).await.unwrap().unwrap().id,
        rot.key.id
    );
    assert!(cmd::pending(&na.store).await.unwrap().is_empty());
    assert!(
        na.store
            .setting_get("owner.old_seed")
            .await
            .unwrap()
            .is_none()
    );
    let mut sibs = fleet::siblings(&na.store).await.unwrap();
    sibs.sort();
    let mut want = vec![b.id, c.id];
    want.sort();
    assert_eq!(sibs, want);

    // Giving up on the rest instead: nothing pending, no old key.
    na.store
        .setting_set("owner.old_seed", "AAAA")
        .await
        .unwrap();
    cmd::discard(&na.store).await.unwrap();
    assert!(
        na.store
            .setting_get("owner.old_seed")
            .await
            .unwrap()
            .is_none()
    );
}

/// "Collect credits here": the siblings that answer forward to this node,
/// one blocked here is not asked, and the page says where each node's
/// credits go.
#[tokio::test]
async fn collecting_credits_here_tells_the_siblings_and_shows_where_credits_go() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    owner::adopt(&nc.store, c.id, &key, false).await.unwrap();
    eventually("a finds b and c", || async {
        fleet::discover(&na.node).await.unwrap().len() == 2
    })
    .await;
    peephole::cluster::block::block(&na.node, c.id)
        .await
        .unwrap();
    let (admin, base) = admin_on(&na).await;
    let page = format!("{base}/admin/cluster/ownership");
    let r = admin
        .post(format!("{page}/collect-here"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.settings.snapshot().collect_to, Some(a.id));
    assert_eq!(nc.settings.snapshot().collect_to, None, "not asked");
    assert_eq!(na.settings.snapshot().collect_to, None);

    eventually("b's status reaches the page", || async {
        let html = text(&admin, page.clone()).await;
        html.contains("Credits go") && html.contains("→ this node")
    })
    .await;
    let html = text(&admin, page.clone()).await;
    assert!(html.contains("keeps them"), "a keeps its own: {html}");
    assert!(html.contains("offline"), "c is not asked: {html}");
}

/// The Ownership page: create a key (shown once), adopt it on a second
/// node, see that node listed, see received commands, forget and release.
#[tokio::test]
async fn admin_takes_and_gives_up_ownership_in_the_web_interface() {
    use peephole::cluster::owner::{self, cmd, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let (admin_a, base_a) = admin_on(&na).await;
    let (admin_b, base_b) = admin_on(&nb).await;
    let page_a = format!("{base_a}/admin/cluster/ownership");
    let page_b = format!("{base_b}/admin/cluster/ownership");

    let html = text(&admin_a, page_a.clone()).await;
    assert!(html.contains("No owner"), "{html}");
    assert!(html.contains("Ownership</a>"), "the tab is there");

    // Create: the key is on the answer, and nowhere afterwards.
    let r = admin_a
        .post(format!("{page_a}/create"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let html = r.text().await.unwrap();
    let key = html
        .split("peephole-own1:")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .map(|s| format!("peephole-own1:{}", s.trim()))
        .expect("the key is shown");
    let html = text(&admin_a, page_a.clone()).await;
    assert!(!html.contains("peephole-own1:"), "shown once");
    assert!(html.contains("key kept here"), "{html}");
    // A second create does not replace the owner.
    let before = owner::load(&na.store, a.id).await.unwrap().unwrap().id;
    admin_a
        .post(format!("{page_a}/create"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        owner::load(&na.store, a.id).await.unwrap().unwrap().id,
        before
    );

    // On b: an invite token is not a key; the real key is adopted, not kept.
    admin_b
        .post(format!("{page_b}/adopt"))
        .form(&[("key", "peephole1:abc")])
        .send()
        .await
        .unwrap();
    assert!(owner::load(&nb.store, b.id).await.unwrap().is_none());
    let r = admin_b
        .post(format!("{page_b}/adopt"))
        .form(&[("key", key.as_str())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let html = text(&admin_b, page_b.clone()).await;
    assert!(html.contains("key not kept here"), "{html}");

    // a lists b under My nodes; b lists what a told it to do.
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    let html = text(&admin_a, page_a.clone()).await;
    assert!(
        html.contains("My nodes") && html.contains("node-bravo"),
        "{html}"
    );
    let kept = cmd::kept_key(&na.node).await.unwrap();
    cmd::run(
        &na.node,
        &kept,
        b.id,
        0,
        cmd::OwnerCmd::Settings {
            base_version: 0,
            changes: peephole::settings::Changes {
                cooldown_hours: Some(12),
                ..Default::default()
            },
        },
    )
    .await
    .unwrap()
    .unwrap();
    let html = text(&admin_b, page_b.clone()).await;
    assert!(
        html.contains("Commands received") && html.contains("settings: cooldown=12h"),
        "{html}"
    );
    assert!(html.contains("node-alpha"), "who sent it");

    // Show key again, forget it, release b.
    let r = admin_a
        .post(format!("{page_a}/show-key"))
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains(&key));
    admin_a
        .post(format!("{page_a}/forget-key"))
        .send()
        .await
        .unwrap();
    let html = text(&admin_a, page_a.clone()).await;
    assert!(html.contains("key not kept here"), "{html}");
    admin_b
        .post(format!("{page_b}/release"))
        .send()
        .await
        .unwrap();
    let html = text(&admin_b, page_b).await;
    assert!(html.contains("No owner"), "{html}");
}

/// A node of an earlier version sends a config key request: it is told
/// what replaced it, and no node reports itself open any more.
#[tokio::test]
async fn old_config_key_requests_are_answered_with_the_replacement() {
    use peephole::cluster::msg::Msg;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    eventually("b answers", || async {
        peephole::cluster::remote::get(&na.node, b.id).await.is_ok()
    })
    .await;
    assert!(
        !peephole::cluster::remote::get(&na.node, b.id)
            .await
            .unwrap()
            .open
    );
    let old = Msg::ConfigSet {
        base_version: 0,
        changes: Default::default(),
        mac: serde_bytes::ByteBuf::new(),
    };
    match na
        .node
        .request(b.id, old, Duration::from_secs(10))
        .await
        .unwrap()
    {
        Msg::ConfigSetReply {
            version: None,
            error: Some(e),
        } => assert!(e.contains("replaced by the ownership key"), "{e}"),
        other => panic!("{other:?}"),
    }
}

/// The counter a member page's forms carry.
fn counter_on(html: &str) -> String {
    html.split("name=\"counter\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("the page carries the counter")
        .to_string()
}

/// The admin of a managing node changes a sibling from its page.
#[tokio::test]
async fn admin_manages_a_sibling_from_its_page() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let b_page = format!("{base}/admin/cluster/node/{}", b.id);

    let members = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(members.contains(">yours<"), "b is marked in the table");
    let html = text(&admin, b_page.clone()).await;
    assert!(html.contains("node-bravo") && html.contains(">yours<"));
    assert!(html.contains("name=\"base_version\" value=\"0\""), "{html}");
    assert!(
        !html.contains("Remote configuration"),
        "the old line is gone"
    );
    // c is a member, not a sibling.
    let c_html = text(&admin, format!("{base}/admin/cluster/node/{}", c.id)).await;
    assert!(c_html.contains("Not one of your nodes"), "{c_html}");

    let r = admin
        .post(b_page.clone())
        .form(&[
            ("counter", counter_on(&html).as_str()),
            ("base_version", "0"),
            ("max_workers", "3"),
            ("max_scans_per_hour", "55"),
            ("timeout_minutes", "20"),
            ("cooldown_hours", "12"),
            ("listener", "on"),
            ("web", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let s = nb.settings.snapshot();
    assert_eq!((s.pace.max_workers, s.pace.max_scans_per_hour), (3, 55));
    assert_eq!(s.pace.timeout_secs, 1200);
    assert_eq!(s.cooldown_hours, 12);
    assert!(
        s.roles.listener && s.roles.web && !s.roles.scanner,
        "unchecked role is off"
    );

    // The pace row cannot change b behind the version check.
    let r = admin
        .post(format!("{base}/admin/cluster/pace"))
        .form(&[
            ("key", b.id.to_string()),
            ("max_workers", "1".into()),
            ("max_scans_per_hour", "11".into()),
            ("timeout_minutes", "5".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.settings.snapshot().pace.max_scans_per_hour, 55);

    // An owner action: b blocks c, and the page then lists it.
    let html = text(&admin, b_page.clone()).await;
    let r = admin
        .post(format!("{b_page}/owner"))
        .form(&[
            ("counter", counter_on(&html)),
            ("action", "block".into()),
            ("target", c.id.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(nb.is_blocked(&c.id));
    let html = text(&admin, b_page.clone()).await;
    assert!(
        html.contains("Blocked there") && html.contains("node-charlie"),
        "{html}"
    );

    // A stale form (the counter moved on) changes nothing.
    let r = admin
        .post(format!("{b_page}/owner"))
        .form(&[
            ("counter", "0".to_string()),
            ("action", "unblock".to_string()),
            ("target", c.id.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(nb.is_blocked(&c.id));

    // This node's own settings from its own page, as before.
    let page = text(&admin, format!("{base}/admin/system/settings")).await;
    let shown = na.settings.snapshot().version;
    assert!(
        page.contains(&format!("name=\"base_version\" value=\"{shown}\"")),
        "own form carries the version"
    );
    let r = admin
        .post(format!("{base}/admin/cluster/settings"))
        .form(&[
            ("base_version", shown.to_string()),
            ("cooldown_hours", "6".into()),
            ("listener", "on".into()),
            ("scanner", "on".into()),
            ("web", "on".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(na.settings.snapshot().cooldown_hours, 6);
    // Where it forwards its credits is set here too (spec §9), and
    // cleared with an empty field.
    let page = text(&admin, format!("{base}/admin/system/settings")).await;
    assert!(page.contains("name=\"collect_to\""), "{page}");
    for (to, want) in [(b.id.to_string(), Some(b.id)), (String::new(), None)] {
        let shown = na.settings.snapshot().version;
        let r = admin
            .post(format!("{base}/admin/cluster/settings"))
            .form(&[
                ("base_version", shown.to_string()),
                ("cooldown_hours", "6".into()),
                ("listener", "on".into()),
                ("scanner", "on".into()),
                ("web", "on".into()),
                ("collect_to", to),
            ])
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
        assert_eq!(na.settings.snapshot().collect_to, want);
    }

    // A crafted form cannot aim an owner command at this node itself, or
    // at a member that is not one of the operator's nodes.
    let mine = owner::counter(&na.store).await.unwrap().to_string();
    for target in [a.id, c.id] {
        let r = admin
            .post(format!("{base}/admin/cluster/node/{target}/owner"))
            .form(&[("counter", mine.as_str()), ("action", "release")])
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success());
    }
    assert!(
        owner::load(&na.store, a.id).await.unwrap().is_some(),
        "not released through its own form"
    );
    assert_eq!(owner::counter(&na.store).await.unwrap().to_string(), mine);

    // b stops answering: only the settings card says so. Its server
    // shuts down in the background, so ask until it is gone; one ask
    // waits out the 15 s status timeout.
    drop(nb);
    eventually_for(
        Duration::from_secs(60),
        "b's page says it did not answer",
        || async {
            let r = admin.get(&b_page).send().await.unwrap();
            assert_eq!(r.status(), 200);
            let html = r.text().await.unwrap();
            html.contains("did not answer") && html.contains("Contributions")
        },
    )
    .await;
}

/// On a node that does not keep the key, a sibling's page says so and
/// nothing can be sent from it.
#[tokio::test]
async fn a_node_without_the_key_shows_its_siblings_read_only() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("b knows a as a sibling", || async {
        fleet::discover(&nb.node).await.unwrap() == vec![a.id]
    })
    .await;
    let (admin, base) = admin_on(&nb).await;
    let a_page = format!("{base}/admin/cluster/node/{}", a.id);
    let html = text(&admin, a_page.clone()).await;
    assert!(html.contains(">yours<"), "{html}");
    assert!(
        html.contains("The ownership key is not kept on this node"),
        "{html}"
    );
    assert!(
        !html.contains("name=\"counter\""),
        "no form without the key"
    );
    // Posted anyway: nothing is sent, nothing changes.
    for (path, form) in [
        (
            a_page.clone(),
            vec![
                ("counter", "0"),
                ("base_version", "0"),
                ("cooldown_hours", "1"),
                ("listener", "on"),
            ],
        ),
        (
            format!("{a_page}/owner"),
            vec![("counter", "0"), ("action", "leave")],
        ),
    ] {
        let r = admin.post(path).form(&form).send().await.unwrap();
        assert!(r.status().is_success());
    }
    assert_eq!(owner::counter(&na.store).await.unwrap(), 0);
    assert_eq!(na.settings.snapshot().version, 0);
    assert!(knows(&nb, a.id, true).await);
}

/// A subtree block that would take in the managing node is refused: the
/// owner cannot lock itself out of a node from afar.
#[tokio::test]
async fn a_subtree_block_never_includes_the_managing_node() {
    use peephole::cluster::owner::{self, cmd, cmd::OwnerCmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    // c vouched for a (its config peer), so a is in c's subtree as b sees it.
    eventually("b knows that c admitted a", || async {
        members::subtree(&nb.store, c.id, b.id)
            .await
            .unwrap()
            .contains(&a.id)
    })
    .await;
    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    let all = OwnerCmd::Block {
        node: c.id,
        subtree: true,
    };
    let e = cmd::run(&na.node, &key, b.id, st.counter, all)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("manages it"), "{e}");
    assert!(!nb.is_blocked(&a.id) && !nb.is_blocked(&c.id));
    // b still answers a.
    cmd::status(&na.node, &key, b.id).await.unwrap();
}

/// A rotation that is cut short (the browser went away, the process was
/// stopped) does not lose the new key: siblings that already took it are
/// not left with an owner nobody holds, and finishing uses the same key.
#[tokio::test]
async fn an_interrupted_rotation_is_finished_with_the_same_key() {
    use peephole::cluster::owner::{self, cmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let old = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &old, false).await.unwrap();
    owner::adopt(&nc.store, c.id, &old, false).await.unwrap();
    eventually("a finds b and c", || async {
        fleet::discover(&na.node).await.unwrap().len() == 2
    })
    .await;
    // Siblings are asked in the order of their ids: the first one moves,
    // the second one does not answer (a drops what a blocked peer says).
    let (first, n_first, last) = if b.id < c.id {
        (b.id, &nb, c.id)
    } else {
        (c.id, &nc, b.id)
    };
    peephole::cluster::block::block(&na.node, last)
        .await
        .unwrap();
    let cut = tokio::time::timeout(Duration::from_secs(5), cmd::rotate(&na.node, &[])).await;
    assert!(cut.is_err(), "still waiting for the silent sibling");
    let moved_to = owner::load(&n_first.store, first)
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_ne!(
        moved_to, old.id,
        "the first sibling already took the new key"
    );
    assert_eq!(
        owner::load(&na.store, a.id).await.unwrap().unwrap().id,
        old.id,
        "this node switches last"
    );

    // Finishing the rotation: the same key, not another new one.
    let rot = cmd::rotate(&na.node, &[]).await.unwrap();
    assert_eq!(rot.key.id, moved_to);
    assert_eq!(
        owner::load(&na.store, a.id).await.unwrap().unwrap().id,
        moved_to
    );
    assert_eq!(cmd::pending(&na.store).await.unwrap(), vec![last]);
    eventually("a counts the moved sibling as its own again", || async {
        fleet::discover(&na.node).await.unwrap().contains(&first)
    })
    .await;
}

/// A node left out of a rotation stays on the old key and is no longer
/// counted: this is how a node that does not cooperate is put out.
#[tokio::test]
async fn a_rotation_leaves_out_the_nodes_named() {
    use peephole::cluster::owner::{self, cmd, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let old = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &old, false).await.unwrap();
    owner::adopt(&nc.store, c.id, &old, false).await.unwrap();
    eventually("a finds b and c", || async {
        fleet::discover(&na.node).await.unwrap().len() == 2
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let page = format!("{base}/admin/cluster/ownership");
    let html = text(&admin, page.clone()).await;
    assert!(
        html.contains(&format!("name=\"skip\" value=\"{}\"", c.id)),
        "the dialog offers to leave c out"
    );
    let r = admin
        .post(format!("{page}/rotate"))
        .form(&[("skip", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(r.text().await.unwrap().contains("peephole-own1:"));

    let new = owner::load(&na.store, a.id).await.unwrap().unwrap().id;
    assert_ne!(new, old.id);
    assert_eq!(owner::load(&nb.store, b.id).await.unwrap().unwrap().id, new);
    assert_eq!(
        owner::load(&nc.store, c.id).await.unwrap().unwrap().id,
        old.id
    );
    assert!(
        cmd::pending(&na.store).await.unwrap().is_empty(),
        "left out, not waited for"
    );
    assert!(
        na.store
            .setting_get("owner.old_seed")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        na.store
            .setting_get("owner.next_seed")
            .await
            .unwrap()
            .is_none()
    );
    // c still greets with its old certificate: it is counted by nobody.
    assert!(fleet::discover(&nc.node).await.unwrap().is_empty());
    assert_eq!(fleet::discover(&na.node).await.unwrap(), vec![b.id]);
}
/// A payment written on one node is in every node's table of credit
/// entries, also when the node that receives it has blocked nobody and
/// knows nothing else about credits yet.
#[tokio::test]
async fn credit_entries_replicate_into_every_nodes_table() {
    use peephole::cluster::record::Seal;
    use peephole::credits::{self, entries};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let today = credits::day_of(na.hlc.now());
    let written = repl::append(
        &na,
        &[Record::CreditTransfer {
            to: b.id,
            parts: vec![(today, 250)],
            seal: Seal::default(),
        }],
    )
    .await
    .unwrap();
    eventually("b holds a's transfer as a row", || async {
        entries::get(&nb.store.pool, &a.id, written[0].seq)
            .await
            .unwrap()
            .is_some()
    })
    .await;
    let row = entries::get(&nb.store.pool, &a.id, written[0].seq)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.kind,
        entries::Kind::Transfer {
            to: b.id,
            parts: vec![(today, 250)]
        }
    );
    assert_eq!(entries::since(&na.store.pool, 0).await.unwrap().len(), 1);
}
/// A node's sealed payments check out where its log is held, and an
/// entry with a made-up seal does not.
#[tokio::test]
async fn sealed_payments_check_out_on_the_other_node() {
    use peephole::cluster::record::Seal;
    use peephole::credits::{self, entries, entries::SealState};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let today = credits::day_of(na.hlc.now());
    let transfer = |seal: Seal| Record::CreditTransfer {
        to: b.id,
        parts: vec![(today, 10)],
        seal,
    };
    let first = repl::append_sealing(&na, transfer).await.unwrap();
    let second = repl::append_sealing(&na, transfer).await.unwrap();
    let made_up = repl::append(
        &na,
        &[transfer(Seal {
            from: second.seq,
            digest: vec![3; 32],
        })],
    )
    .await
    .unwrap();
    eventually("b holds all three", || async {
        entries::get(&nb.store.pool, &a.id, made_up[0].seq)
            .await
            .unwrap()
            .is_some()
    })
    .await;
    for n in [&na, &nb] {
        let state = |seq: u64| async move {
            entries::get(&n.store.pool, &a.id, seq)
                .await
                .unwrap()
                .unwrap()
                .seal
        };
        assert_eq!(state(first.seq).await, SealState::Consistent);
        assert_eq!(state(second.seq).await, SealState::Consistent);
        assert_eq!(state(made_up[0].seq).await, SealState::Inconsistent);
    }
}
/// A node gives two members different entries at one position of its
/// log and then seals one of them. The member holding the other one marks
/// it, fetches the contradicting entry and publishes the proof; a member
/// that saw no contradiction itself marks it from the proof alone.
#[tokio::test]
async fn a_node_that_shows_two_histories_is_proven_and_marked_everywhere() {
    use peephole::cluster::record::Seal;
    use peephole::cluster::seal;
    use sha2::Digest;
    // x never runs: its log is written by hand below.
    let (ix, x) = new_node("x");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let nb = boot(ib, &b, &[&x, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&x, &b], DEFAULT).await;
    let now = nb.hlc.now();
    let sign = |seq: u64, r: &Record| WireEntry::sign(&ix, seq, now + seq, r).unwrap();
    let e1 = sign(
        1,
        &Record::LogSeal {
            seal: Seal {
                from: 1,
                digest: seal::empty().to_vec(),
            },
        },
    );
    let receipt = |charged: u32| Record::CreditReceipt {
        payer: b.id,
        offer_seq: 1,
        charged_mc: charged,
        answered: vec![],
    };
    let (for_b, for_c) = (sign(2, &receipt(1)), sign(2, &receipt(2)));
    repl::apply_batch(&nb, vec![e1.clone(), for_b.clone()])
        .await
        .unwrap();
    repl::apply_batch(&nc, vec![e1.clone(), for_c.clone()])
        .await
        .unwrap();
    // Both hold x up to 2, so a sync round moves nothing: the fork is
    // invisible until x commits to one branch.
    assert!(seal::forked_set(&nb.store.pool).await.unwrap().is_empty());
    let mut h = sha2::Sha256::new();
    h.update(e1.digest().unwrap());
    h.update(for_c.digest().unwrap());
    let e3 = sign(
        3,
        &Record::LogSeal {
            seal: Seal {
                from: 1,
                digest: h.finalize().to_vec(),
            },
        },
    );
    repl::apply_batch(&nc, vec![e3]).await.unwrap();
    assert!(
        seal::forked_set(&nc.store.pool).await.unwrap().is_empty(),
        "c holds the branch that was sealed"
    );
    eventually("b gets the seal and sees it does not match", || async {
        seal::forked_set(&nb.store.pool)
            .await
            .unwrap()
            .contains(&x.id)
    })
    .await;
    assert_eq!(seal::forked(&nb.store.pool).await.unwrap()[0].proof, None);
    eventually("b fetches c's entry and writes the proof", || async {
        seal::investigate(&nb.node).await.unwrap();
        seal::forked(&nb.store.pool).await.unwrap()[0]
            .proof
            .is_some()
    })
    .await;
    eventually("c marks x from b's proof alone", || async {
        seal::forked(&nc.store.pool)
            .await
            .unwrap()
            .iter()
            .any(|f| f.origin == x.id && f.seq == 2 && f.proof.is_some_and(|p| p.0 == b.id))
    })
    .await;
    // Marked for good, and one proof is enough.
    assert_eq!(seal::investigate(&nb.node).await.unwrap(), 0);
}
/// A stand-in nmap that records the command line it was given, as nmap
/// does: its results count as run with the built-in arguments.
fn fake_nmap_args(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-nmap-args");
    std::fs::write(
        &p,
        "#!/bin/sh\nfor a; do t=$a; done\ncat <<EOF\n<?xml version=\"1.0\"?>\n\
         <nmaprun scanner=\"nmap\" args=\"nmap $*\" start=\"1\" version=\"7.94\">\n\
         <host><status state=\"up\"/><address addr=\"$t\" addrtype=\"ipv4\"/>\n\
         <ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/>\
         <service name=\"ssh\"/></port></ports></host>\n</nmaprun>\nEOF\n",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// Judge every payable scan held on `n` now (the node's own loop waits
/// ten minutes for the requests behind a scan).
async fn judge_now(n: &TestNode) -> usize {
    let origins = peephole::scan::guard::Origins::Any;
    let j = peephole::credits::earn::Judge {
        pool: &n.store.pool,
        origins: &origins,
        classifier: peephole::classify::Classifier::builtin(),
    };
    peephole::credits::earn::judge(&j, 0).await.unwrap()
}

/// A scanner completes a scan for another node's trap: both hold their
/// shares in every node's book.
#[tokio::test]
async fn a_completed_scan_pays_scanner_and_trap_in_every_nodes_book() {
    use peephole::credits;
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            scanner: Some(fake_nmap_args(tools.path())),
            ..DEFAULT
        },
    )
    .await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    enqueue(&na, "198.51.100.40", 2).await;
    eventually_for(
        Duration::from_secs(40),
        "scanned, and everyone has it all",
        || async {
            let mut all = true;
            for n in [&na, &nb, &nc] {
                all &= count(n, "SELECT COUNT(*) FROM scans").await == 1
                    && count(n, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
                    && count(n, "SELECT COUNT(*) FROM requests").await == 3;
            }
            all
        },
    )
    .await;
    for n in [&na, &nb, &nc] {
        assert_eq!(judge_now(n).await, 1);
        let book = credits::book_fresh(&n.node).await.unwrap();
        assert_eq!(book.paid.len(), 1);
        assert!(book.paid[0].scan.args_ok && book.paid[0].scan.level == 2);
        assert_eq!(book.balance(&b.id), 1000, "the scanner's share");
        assert_eq!(book.balance(&a.id), 250, "the trap's share");
        assert_eq!(book.balance(&c.id), 0);
        assert_eq!(book.earned_per_day(), 1250 / 7);
        assert!(book.standing(&b.id).earns());
    }
    // A member blocked here earns nothing here; elsewhere it still does.
    peephole::cluster::block::block(&nc.node, b.id)
        .await
        .unwrap();
    let book = credits::book_fresh(&nc.node).await.unwrap();
    assert_eq!(book.balance(&b.id), 0);
    assert!(book.standing(&b.id).blocked);
    assert_eq!(
        credits::book_fresh(&na.node).await.unwrap().balance(&b.id),
        1000
    );
}

/// A stand-in nmap that reports a host with no open port, whatever the
/// target: a scanner that makes its results up.
fn fake_nmap_empty(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("fake-nmap-empty");
    std::fs::write(
        &p,
        "#!/bin/sh\nfor a; do t=$a; done\ncat <<EOF\n<?xml version=\"1.0\"?>\n\
         <nmaprun scanner=\"nmap\" args=\"nmap $*\" start=\"1\" version=\"7.94\">\n\
         <host><status state=\"up\"/><address addr=\"$t\" addrtype=\"ipv4\"/>\
         <ports></ports></host>\n</nmaprun>\nEOF\n",
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A scanner that audits everything finds another scanner's results made
/// up. That scanner then earns no scanner share where those audits count:
/// at the auditor and in its fleet, and at nobody else.
#[tokio::test]
async fn audits_of_made_up_results_stop_a_scanners_shares_where_they_count() {
    use peephole::cluster::owner::{self, fleet};
    use peephole::credits::{self, audit};
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("a");
    let (i_f, f) = new_node("f");
    let (ib, b) = new_node("b");
    let (is, s) = new_node("s");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&f, &b, &s, &c], DEFAULT).await;
    let _nf = boot(
        i_f,
        &f,
        &[&a, &b, &s, &c],
        Opts {
            scanner: Some(fake_nmap_empty(tools.path())),
            ..DEFAULT
        },
    )
    .await;
    let nb = boot(
        ib,
        &b,
        &[&a, &f, &s, &c],
        Opts {
            scanner: Some(fake_nmap_args(tools.path())),
            audit_share: 1.0,
            ..DEFAULT
        },
    )
    .await;
    let ns = boot(is, &s, &[&a, &f, &b, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &f, &b, &s], DEFAULT).await;
    let key = owner::create(&nb.store, b.id).await.unwrap();
    owner::adopt(&ns.store, s.id, &key, false).await.unwrap();
    eventually("s knows b as one of its own", || async {
        fleet::discover(&ns.node).await.unwrap() == vec![b.id]
    })
    .await;

    for i in 0..16 {
        enqueue(&na, &format!("198.51.100.{}", 60 + i), 1).await;
    }
    eventually_for(Duration::from_secs(60), "all sixteen scanned", || async {
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 16
    })
    .await;
    let by_f = scans_by(&na, f.id).await;
    assert!(by_f >= 5, "f ran {by_f} of 16 scans");
    eventually_for(
        Duration::from_secs(60),
        "b ran f's scans again, and everyone holds the audits",
        || async {
            let mut all = true;
            for n in [&nb, &ns, &nc] {
                all &= count(n, "SELECT COUNT(*) FROM scans WHERE audit_of IS NOT NULL").await
                    == by_f
                    && count(n, "SELECT COUNT(*) FROM scans WHERE audit_of IS NULL").await == 16;
            }
            all
        },
    )
    .await;
    for n in [&nb, &ns, &nc] {
        assert_eq!(judge_now(n).await, 16);
        audit::settle(&n.store.pool).await.unwrap();
        assert_eq!(
            count(
                n,
                "SELECT COUNT(*) FROM scans WHERE audit_result = 'differs'"
            )
            .await,
            by_f,
            "nothing reported, a port found"
        );
    }
    let honest = (16 - by_f) as u64 * 1000;
    for n in [&nb, &ns] {
        let book = credits::book_fresh(&n.node).await.unwrap();
        let st = book.standing(&f.id);
        assert_eq!(st.audits, Some((by_f as u32, by_f as u32)));
        assert!(st.earns() && !st.earns_as_scanner());
        assert_eq!(book.balance(&f.id), 0);
        assert_eq!(book.balance(&b.id), honest);
        // The trap is paid for every scan all the same.
        assert_eq!(book.balance(&a.id), 16 * 250);
    }
    // c is not of b's fleet: b's audits are shown there, they do not count.
    let book = credits::book_fresh(&nc.node).await.unwrap();
    assert_eq!(book.standing(&f.id).audits, None);
    assert_eq!(book.balance(&f.id), by_f as u64 * 1000);
    assert_eq!(book.balance(&b.id), honest);
}

/// A provider a test node serves: a name the cluster knows, an optional
/// budget a day, and a count of the addresses it was asked about.
struct TestProvider {
    name: &'static str,
    per_day: Option<f64>,
    asked: Arc<std::sync::atomic::AtomicUsize>,
}

impl peephole::intel::provider::Provider for TestProvider {
    fn name(&self) -> &'static str {
        self.name
    }
    fn ready(&self) -> bool {
        true
    }
    fn per_day(&self) -> Option<f64> {
        self.per_day
    }
    fn lookup<'a>(
        &'a self,
        ips: &'a [String],
    ) -> futures::future::BoxFuture<'a, Vec<peephole::intel::provider::Finding>> {
        Box::pin(async move {
            self.asked
                .fetch_add(ips.len(), std::sync::atomic::Ordering::SeqCst);
            ips.iter()
                .map(|ip| peephole::intel::provider::Finding {
                    ip: ip.clone(),
                    source_version: None,
                    data: serde_json::json!({ "said_by": self.name }),
                })
                .collect()
        })
    }
}

/// Make `n` serve `list` (provider name, budget a day) with the given
/// on-demand share. Returns the counter of addresses its providers were
/// asked about.
fn serves(
    n: &TestNode,
    list: &[(&'static str, Option<f64>)],
    share: f64,
) -> Arc<std::sync::atomic::AtomicUsize> {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let providers: peephole::intel::Providers = list
        .iter()
        .map(|(name, per_day)| {
            Arc::new(TestProvider {
                name,
                per_day: *per_day,
                asked: asked.clone(),
            }) as Arc<dyn peephole::intel::provider::Provider>
        })
        .collect();
    n.node
        .set_providers(list.iter().map(|(n, _)| n.to_string()).collect());
    n.node.set_lookup_providers(providers);
    n.node
        .set_lookup_shares(peephole::credits::share::Shares::new(
            n.store.clone(),
            share,
        ));
    asked
}

/// A member of an earlier version can serve providers, but it does not know
/// offers and receipts: it is not offered as a server of paid lookups.
#[tokio::test]
async fn an_old_version_member_is_not_asked_for_paid_lookups() {
    use peephole::credits::{pay, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-old");
    let (ic, c) = new_node("node-new");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let old = Opts {
        proto: Some((
            peephole::cluster::rpc::proto::PROTO_MIN,
            peephole::cluster::rpc::proto::OWNER_PROTO - 1,
        )),
        ..DEFAULT
    };
    let nb = boot(ib, &b, &[&a, &c], old).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    serves(&nc, &[("abuseipdb", Some(1000.0))], 0.2);
    price::refresh(&nb.node).await.unwrap();
    price::refresh(&nc.node).await.unwrap();
    price_seen(&na, b.id, "abuseipdb").await;
    price_seen(&na, c.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let servers: Vec<_> = pay::quotes(&na.node, &none)
        .remove("abuseipdb")
        .unwrap_or_default()
        .into_iter()
        .map(|q| q.server)
        .collect();
    assert_eq!(servers, vec![c.id], "only the member that speaks credits");
}

/// Give `node` credits in the books of every node in `on`: `scans` judged
/// level-1 scans it ran for its own trap, 1250 mc each.
async fn grant_scans(on: &[&TestNode], node: NodeId, scans: u32) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let first = NEXT.fetch_add(scans as u64, std::sync::atomic::Ordering::SeqCst);
    let now = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64)
        << 16;
    for n in on {
        for i in 0..scans as u64 {
            let k = first + i;
            sqlx::query(
                "INSERT INTO credit_scans
                   (scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok, judged_at)
                 VALUES (?, ?, ?, ?, ?, ?, 1, 1, 1, datetime('now'))",
            )
            .bind(format!("granted-{k}"))
            .bind(format!("granted-job-{k}"))
            .bind(format!("100.64.{}.{}", k / 250, k % 250))
            .bind(&node.0[..])
            .bind(&node.0[..])
            .bind(now + k as i64)
            .execute(&n.store.pool)
            .await
            .unwrap();
        }
    }
}

/// A server's prices follow what the cluster earns, and its heartbeat
/// carries them and the lookups it serves a day.
#[tokio::test]
async fn announced_prices_follow_the_clusters_earnings() {
    use peephole::credits::price;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    // A budget of 1000 a day and a share of a fifth: 200 lookups a day.
    serves(
        &na,
        &[("abuseipdb", Some(1000.0)), ("maxmind-geolite2", None)],
        0.2,
    );
    // 112 scans at 1.25 credits in a week: 20 credits a day.
    grant_scans(&[&na], a.id, 112).await;
    let t = price::refresh(&na.node).await.unwrap();
    assert_eq!((t.earned_per_day, t.lookups_per_day), (20_000, 200.0));
    // No scanner runs: no capacity, which counts as saturated (double).
    assert_eq!(
        (t.capacity.utilization, t.load, t.unit),
        (1.0, 2.0, Some(400))
    );
    assert_eq!(t.price_of("abuseipdb"), Some(400));
    assert_eq!(t.price_of("maxmind-geolite2"), Some(100));
    let seen = |price: u32| {
        nb.status.known(&a.id).is_some_and(|k| {
            k.hb.prices.contains(&("abuseipdb".to_string(), price))
                && k.hb.on_demand == vec![("abuseipdb".to_string(), 200)]
        })
    };
    eventually("b reads a's prices from its heartbeat", || async {
        seen(400)
    })
    .await;
    // Twice the earnings, twice the price.
    grant_scans(&[&na], a.id, 112).await;
    let t = price::refresh(&na.node).await.unwrap();
    assert_eq!(t.price_of("abuseipdb"), Some(800));
    eventually("b sees the new price", || async { seen(800) }).await;
}

/// Until `asker` has heard `server`'s heartbeat with a price for
/// `provider`; returns the price.
async fn price_seen(asker: &TestNode, server: NodeId, provider: &str) -> u32 {
    let find = || {
        asker.status.known(&server).and_then(|k| {
            k.hb.prices
                .iter()
                .find(|(p, _)| p == provider)
                .map(|(_, mc)| *mc)
        })
    };
    eventually("the server's price is heard", || async { find().is_some() }).await;
    // Paid lookups go to members known to speak the credits protocol: the
    // server's own description of itself (its protocol) has to arrive first.
    eventually("the server's protocol is known", || async {
        asker
            .members()
            .get(&server)
            .is_some_and(|m| m.proto_max > 0)
    })
    .await;
    find().unwrap()
}

/// The asker pays the announced price; the server gets half; both nodes
/// hold the offer and the receipt and arrive at the same balances.
#[tokio::test]
async fn a_paid_lookup_moves_credits_from_the_asker_to_the_server() {
    use peephole::credits::{self, entries, price};
    use std::sync::atomic::Ordering;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let asked = serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    let cost = price_seen(&na, b.id, "abuseipdb").await as u64;
    assert!(cost > 0);

    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.77".parse().unwrap();
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    let from_b = answers
        .iter()
        .find(|x| x.node == "node-bravo")
        .expect("b answered");
    assert_eq!(from_b.resp.findings.len(), 1, "{answers:?}");
    assert_eq!(from_b.resp.findings[0].provider, "abuseipdb");
    assert_eq!(from_b.charged_mc as u64, cost);
    assert_eq!(asked.load(Ordering::SeqCst), 1);

    eventually("both hold the offer and the receipt", || async {
        entries::since(&na.store.pool, 0).await.unwrap().len() == 2
            && entries::since(&nb.store.pool, 0).await.unwrap().len() == 2
    })
    .await;
    for n in [&na, &nb] {
        let book = credits::book_fresh(&n.node).await.unwrap();
        assert_eq!(book.balance(&a.id), 10_000 - cost);
        assert_eq!(book.balance(&b.id), cost / 2);
        assert_eq!(book.ledger.held(&a.id), 0);
    }
    // Nothing about the address was stored: nobody recorded it.
    for n in [&na, &nb] {
        assert_eq!(count(n, "SELECT COUNT(*) FROM ip_intel_log").await, 0);
        assert_eq!(count(n, "SELECT COUNT(*) FROM ips").await, 0);
    }
}

/// Without credits the asker refuses on its own and says how much is
/// missing; credits the server does not count are declined there, and the
/// asker gets them back at once; a spent on-demand share declines the API
/// provider and still serves what has no budget.
#[tokio::test]
async fn an_asker_without_credits_is_declined_with_the_reason() {
    use peephole::credits::{self, entries, price};
    use std::sync::atomic::Ordering;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    // A budget of 5 a day and a share of a fifth: one paid lookup a day.
    let asked = serves(
        &nb,
        &[("abuseipdb", Some(5.0)), ("maxmind-geolite2", None)],
        0.2,
    );
    price::refresh(&nb.node).await.unwrap();
    price_seen(&na, b.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.78".parse().unwrap();
    let why = |answers: &[peephole::intel::lookup::NodeAnswer], provider: &str| {
        answers
            .iter()
            .flat_map(|x| x.resp.declined.iter())
            .find(|(p, _)| p == provider)
            .map(|(_, w)| w.clone())
            .unwrap_or_default()
    };

    // 1. No credits: no offer is written, nobody is asked.
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    let reason = why(&answers, "abuseipdb");
    assert!(
        reason.contains("holds 0.00 credits") && reason.contains("missing"),
        "{reason}"
    );
    assert!(entries::since(&na.store.pool, 0).await.unwrap().is_empty());
    assert_eq!(asked.load(Ordering::SeqCst), 0);

    // 2. Credits only this node counts (the server judged no such scans).
    grant_scans(&[&na], a.id, 4).await;
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert!(
        why(&answers, "abuseipdb").contains("not covered here"),
        "{answers:?}"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    eventually(
        "the receipt of nothing frees the credits at once",
        || async {
            let book = credits::book_fresh(&na.node).await.unwrap();
            book.balance(&a.id) == 5000 && book.ledger.held(&a.id) == 0
        },
    )
    .await;

    // 3. The server counts them too: served, and the share of the day is
    // used up by that one lookup.
    grant_scans(&[&nb], a.id, 4).await;
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert_eq!(
        answers.iter().map(|x| x.resp.findings.len()).sum::<usize>(),
        2
    );
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert!(
        why(&answers, "abuseipdb").contains("on-demand share"),
        "{answers:?}"
    );
    let served: Vec<&str> = answers
        .iter()
        .flat_map(|x| x.resp.findings.iter())
        .map(|f| f.provider.as_str())
        .collect();
    assert_eq!(served, ["maxmind-geolite2"]);
    let geo = nb.price_table().price_of("maxmind-geolite2").unwrap();
    assert_eq!(answers.iter().map(|x| x.charged_mc).sum::<u32>(), geo);
}

/// A lookup the node's own provider answers is paid like any other: half
/// of the price comes back, half is destroyed.
#[tokio::test]
async fn a_lookup_answered_by_the_nodes_own_provider_costs_half_net() {
    use peephole::credits::{self, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&na, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na], a.id, 8).await;
    let cost = price::refresh(&na.node)
        .await
        .unwrap()
        .price_of("abuseipdb")
        .unwrap() as u64;
    let own = na.lookup_providers().unwrap().clone();
    let answers =
        peephole::intel::lookup::cluster(&rec(&na), &own, "203.0.113.79".parse().unwrap()).await;
    assert_eq!(answers[0].node, "this node");
    assert_eq!(answers[0].resp.findings.len(), 1, "{answers:?}");
    assert_eq!(answers[0].charged_mc as u64, cost);
    let book = credits::book_fresh(&na.node).await.unwrap();
    assert_eq!(book.balance(&a.id), 10_000 - cost + cost / 2);
    assert_eq!(book.ledger.tally(&a.id).destroyed, cost - cost / 2);
}

/// Review focus: the server's price moved after the asker read it. The
/// server declines, names its price and charges nothing; an offer at that
/// price is served.
#[tokio::test]
async fn a_price_above_the_offer_is_declined_and_named() {
    use peephole::credits::{self, pay, price};
    use std::sync::atomic::Ordering;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let asked = serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    let cost = price::refresh(&nb.node)
        .await
        .unwrap()
        .price_of("abuseipdb")
        .unwrap();
    assert!(cost > 1);
    price_seen(&na, b.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.80".parse().unwrap();
    let wanted = ["abuseipdb".to_string()];
    let low = pay::offer_and_ask(&na.node, &none, ip, b.id, &wanted, cost as u64 - 1).await;
    assert!(low.findings.is_empty());
    assert_eq!((low.price_mc, low.charged_mc), (Some(cost), 0));
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    let enough = pay::offer_and_ask(&na.node, &none, ip, b.id, &wanted, cost as u64).await;
    assert_eq!((enough.findings.len(), enough.charged_mc), (1, cost));
    eventually("a paid once", || async {
        let book = credits::book_fresh(&na.node).await.unwrap();
        book.balance(&a.id) == 10_000 - cost as u64 && book.ledger.held(&a.id) == 0
    })
    .await;
    // An offer is served once: naming it again gets nothing.
    let seq = peephole::credits::entries::since(&na.store.pool, 0)
        .await
        .unwrap()
        .iter()
        .filter(|e| e.origin == a.id)
        .map(|e| e.seq)
        .max()
        .unwrap();
    let again: peephole::intel::lookup::LookupResp = na
        .call(
            b.id,
            &b.address(),
            "/rpc/v1/lookup",
            &peephole::intel::lookup::LookupReq {
                ip: ip.to_string(),
                providers: wanted.to_vec(),
                offer_seq: Some(seq),
            },
        )
        .await
        .unwrap();
    assert!(again.findings.is_empty(), "{again:?}");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    // And without an offer only free providers answer.
    let free: peephole::intel::lookup::LookupResp = na
        .call(
            b.id,
            &b.address(),
            "/rpc/v1/lookup",
            &peephole::intel::lookup::LookupReq {
                ip: ip.to_string(),
                providers: wanted.to_vec(),
                offer_seq: None,
            },
        )
        .await
        .unwrap();
    assert!(free.findings.is_empty());
    assert!(free.declined[0].1.contains("paid with credits"), "{free:?}");
}

/// A member that speaks only the protocol before credits is never asked
/// for a paid lookup, whatever its heartbeat says.
#[tokio::test]
async fn a_member_of_an_earlier_version_is_not_asked() {
    use peephole::credits::{pay, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            proto: Some((2, 2)),
            ..DEFAULT
        },
    )
    .await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    serves(&nc, &[("abuseipdb", Some(1000.0))], 0.2);
    price::refresh(&nb.node).await.unwrap();
    price::refresh(&nc.node).await.unwrap();
    price_seen(&na, b.id, "abuseipdb").await;
    price_seen(&na, c.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let all = pay::quotes(&na.node, &none);
    let servers: Vec<NodeId> = all["abuseipdb"].iter().map(|q| q.server).collect();
    assert_eq!(servers, [c.id], "b announces a price and is left out");
}

/// A paid answer about an address the cluster has recorded is written
/// into the dataset by the node that served it and reaches every member.
/// For 24 hours the next lookup of that provider is answered from the
/// dataset: no offer, nobody asked. "Ask again" pays.
#[tokio::test]
async fn a_paid_lookup_of_a_recorded_address_is_kept_and_then_free_for_everyone() {
    use peephole::credits::{entries, price};
    use peephole::intel::lookup;
    use std::sync::atomic::Ordering;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let asked = serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    price_seen(&na, b.id, "abuseipdb").await;
    // c's trap recorded a request from the address.
    let row = nc
        .store
        .upsert_ip("203.0.113.90".parse().unwrap())
        .await
        .unwrap();
    rec(&nc)
        .insert_request(&new_request(row.id, "/x"))
        .await
        .unwrap();
    eventually("a and b hold the request", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.90".parse().unwrap();
    let findings = |o: &lookup::Outcome| {
        o.answers
            .iter()
            .map(|x| x.resp.findings.len())
            .sum::<usize>()
    };

    let first = lookup::run(&rec(&na), &none, ip, &[]).await;
    assert!(first.stored.is_empty());
    assert_eq!(findings(&first), 1, "{:?}", first.answers);
    assert!(first.kept);
    let kept =
        "SELECT COUNT(*) FROM ip_intel_log WHERE provider = 'abuseipdb' AND ip = '203.0.113.90'";
    eventually("the answer is in everyone's dataset", || async {
        count(&na, kept).await == 1 && count(&nb, kept).await == 1 && count(&nc, kept).await == 1
    })
    .await;
    let by_b: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ip_intel_log WHERE origin = ?")
        .bind(&b.id.0[..])
        .fetch_one(&nc.store.pool)
        .await
        .unwrap();
    assert_eq!(by_b, 1, "written by the node that served it");

    // Another member, without credits, within 24 hours: from the dataset.
    let payments = entries::since(&nc.store.pool, 0).await.unwrap().len();
    let second = lookup::run(&rec(&nc), &none, ip, &[]).await;
    assert_eq!(second.stored.len(), 1);
    assert_eq!(second.stored[0].provider, "abuseipdb");
    assert_eq!(second.stored[0].node.as_deref(), Some("node-bravo"));
    assert_eq!(second.stored[0].data["said_by"], "abuseipdb");
    assert!(second.stored[0].age_secs < 3600);
    assert_eq!(findings(&second), 0);
    assert_eq!(asked.load(Ordering::SeqCst), 1, "nobody was asked");
    assert_eq!(
        entries::since(&nc.store.pool, 0).await.unwrap().len(),
        payments
    );

    // "Ask again" forces a paid lookup of that provider.
    let again = lookup::run(&rec(&na), &none, ip, &["abuseipdb".to_string()]).await;
    assert!(again.stored.is_empty());
    assert_eq!(findings(&again), 1);
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

/// Review focus: an address nobody recorded. The payment is in the log;
/// nothing about the address is written on any node.
#[tokio::test]
async fn a_paid_lookup_of_an_unrecorded_address_writes_nothing() {
    use peephole::credits::{entries, price};
    use peephole::intel::lookup;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    price_seen(&na, b.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.91".parse().unwrap();
    let out = lookup::run(&rec(&na), &none, ip, &[]).await;
    assert_eq!(
        out.answers
            .iter()
            .map(|x| x.resp.findings.len())
            .sum::<usize>(),
        1
    );
    assert!(!out.kept);
    eventually("the payment is on both nodes", || async {
        entries::since(&na.store.pool, 0).await.unwrap().len() == 2
            && entries::since(&nb.store.pool, 0).await.unwrap().len() == 2
    })
    .await;
    for n in [&na, &nb] {
        for table in ["ips", "ip_intel", "ip_intel_log", "requests"] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            assert_eq!(count(n, &sql).await, 0, "{table}");
        }
        // The payment does not name the address either.
        let log: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT payload FROM repl_log WHERE kind IN ('credit_offer', 'credit_receipt')",
        )
        .fetch_all(&n.store.pool)
        .await
        .unwrap();
        assert_eq!(log.len(), 2);
        assert!(
            log.iter()
                .all(|p| !p.windows(12).any(|w| w == b"203.0.113.91"))
        );
    }
    // And a second lookup pays again: nothing was there to answer from.
    let out = lookup::run(&rec(&na), &none, ip, &[]).await;
    assert!(out.stored.is_empty());
}

/// A node forwards what it holds to its collecting node; the credits keep
/// their day and can be spent there. Less than a credit waits, and
/// nothing goes to a node that is no member.
#[tokio::test]
async fn a_fleet_collects_at_one_node_and_any_of_its_nodes_can_spend() {
    use peephole::credits::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    grant_scans(&[&na, &nb], b.id, 4).await;
    let today = credits::day_of(nb.hlc.now());

    let (_, stranger) = new_node("x");
    assert_eq!(
        fleet::collect(&nb.node, stranger.id).await.unwrap(),
        0,
        "no member"
    );
    assert_eq!(fleet::collect(&nb.node, b.id).await.unwrap(), 0, "itself");
    assert_eq!(fleet::collect(&nb.node, a.id).await.unwrap(), 5000);
    eventually("the credits are at a, on both nodes' books", || async {
        let mut all = true;
        for n in [&na, &nb] {
            let book = credits::book_fresh(&n.node).await.unwrap();
            all &= book.balance(&a.id) == 5000
                && book.balance(&b.id) == 0
                && book.ledger.by_day(&a.id) == vec![(today, 5000)];
        }
        all
    })
    .await;
    // Sending back half a credit: any node may send to any member.
    assert_eq!(fleet::send(&na.node, b.id, 500).await.unwrap(), 500);
    assert!(
        fleet::send(&na.node, b.id, 99_000).await.is_err(),
        "more than it holds"
    );
    assert!(fleet::send(&na.node, stranger.id, 1).await.is_err());
    eventually("b holds half a credit", || async {
        credits::book_fresh(&nb.node).await.unwrap().balance(&b.id) == 500
    })
    .await;
    // Less than a credit, none of it expiring today: it waits.
    assert_eq!(fleet::collect(&nb.node, a.id).await.unwrap(), 0);
    // The setting reaches the node that acts on it.
    let set = peephole::settings::Changes {
        collect_to: Some(a.id.to_string()),
        ..Default::default()
    };
    nb.settings.apply(&set, None).await.unwrap().unwrap();
    assert_eq!(nb.settings.snapshot().collect_to, Some(a.id));
}

/// A node whose balance does not cover a lookup draws the missing amount
/// from its collecting node, which answers only its own fleet.
#[tokio::test]
async fn a_node_draws_what_a_lookup_needs_from_its_collecting_node() {
    use peephole::cluster::msg::Msg;
    use peephole::cluster::owner::{self, fleet as owned};
    use peephole::credits::{self, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (is, s) = new_node("node-server");
    let (ix, x) = new_node("node-x");
    let na = boot(ia, &a, &[&b, &s, &x], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &s, &x], DEFAULT).await;
    let ns = boot(is, &s, &[&a, &b, &x], DEFAULT).await;
    let nx = boot(ix, &x, &[&a, &b, &s], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a counts b as its own", || async {
        owned::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    serves(&ns, &[("abuseipdb", Some(1000.0))], 0.2);
    // The fleet's credits sit at a; b holds nothing.
    grant_scans(&[&na, &nb, &ns], a.id, 8).await;
    price::refresh(&ns.node).await.unwrap();
    let cost = price_seen(&nb, s.id, "abuseipdb").await as u64;
    *nb.collect_to.write().unwrap() = Some(a.id);

    // A stranger's draw is not answered, and moves nothing.
    let asked = nx
        .node
        .request(a.id, Msg::CreditDraw { mc: 100 }, Duration::from_secs(3))
        .await;
    assert!(asked.is_err(), "{asked:?}");

    let none: peephole::intel::Providers = vec![];
    let answers =
        peephole::intel::lookup::cluster(&rec(&nb), &none, "203.0.113.95".parse().unwrap()).await;
    let found: usize = answers.iter().map(|x| x.resp.findings.len()).sum();
    assert_eq!(found, 1, "{answers:?}");
    eventually("the fleet paid, from a's balance", || async {
        let book = credits::book_fresh(&ns.node).await.unwrap();
        book.balance(&a.id) == 10_000 - cost && book.balance(&b.id) == 0
    })
    .await;
}

/// The section names of a rendered page, in order.
fn sections(html: &str) -> Vec<String> {
    html.split("data-section=\"")
        .skip(1)
        .filter_map(|s| s.split('"').next().map(str::to_string))
        .collect()
}

/// The lookup result of a recorded address lists what its IP page lists,
/// with the provider answers on top; the page says what a lookup costs
/// and what was charged.
#[tokio::test]
async fn the_lookup_result_of_a_recorded_address_has_the_sections_of_its_ip_page() {
    use peephole::credits::price;
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            scanner: Some(fake_nmap_args(tools.path())),
            ..DEFAULT
        },
    )
    .await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    let cost = price_seen(&na, b.id, "abuseipdb").await;
    // A recorded address with requests and a finished scan.
    enqueue(&na, "198.51.100.77", 1).await;
    eventually_for(Duration::from_secs(30), "scanned", || async {
        count(&na, "SELECT COUNT(*) FROM scans").await == 1
    })
    .await;
    let (admin, base) = admin_on(&na).await;

    let form = text(&admin, format!("{base}/admin/lookup?ip=198.51.100.77")).await;
    assert!(form.contains("Balance") && form.contains("10.00"), "{form}");
    assert!(form.contains("node-bravo"), "who would be asked");
    assert!(
        form.contains(&peephole::credits::show(cost as u64)),
        "and at what price"
    );

    let ip_page = text(&admin, format!("{base}/ip/198.51.100.77")).await;
    let result = admin
        .post(format!("{base}/admin/lookup"))
        .form(&[("ip", "198.51.100.77")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let on_ip_page = sections(&ip_page);
    assert!(
        on_ip_page.contains(&"scans".to_string()) && on_ip_page.contains(&"requests".to_string())
    );
    assert_eq!(sections(&result), on_ip_page, "one source for both pages");
    assert!(result.contains("Asked now") && result.contains("node-bravo"));
    assert!(result.contains(&format!("charged {}", peephole::credits::show(cost as u64))));
    assert!(
        result.contains("kept in the dataset"),
        "the cluster recorded this address"
    );

    // Asked again within 24 hours: from the dataset, with "Ask again".
    eventually("b's kept answer reached this node", || async {
        count(
            &na,
            "SELECT COUNT(*) FROM ip_intel_log WHERE provider = 'abuseipdb'",
        )
        .await
            == 1
    })
    .await;
    let second = admin
        .post(format!("{base}/admin/lookup"))
        .form(&[("ip", "198.51.100.77")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        second.contains("From the dataset") && second.contains("Ask again"),
        "{second}"
    );
    assert!(!second.contains("Asked now"));

    // An address the dataset does not hold: said so, with what is near it,
    // by network and, since an answer names its ASN, by ASN.
    sqlx::query("UPDATE ips SET asn = 64500 WHERE ip = '198.51.100.77'")
        .execute(&na.store.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ip_intel_log (ip, provider, origin, hlc, fetched_at, data_json)
         VALUES ('198.51.100.78', 'shodan', ?, 1, datetime('now'), '{\"asn\":\"AS64500\"}')",
    )
    .bind(&b.id.0[..])
    .execute(&na.store.pool)
    .await
    .unwrap();
    let unknown = admin
        .post(format!("{base}/admin/lookup"))
        .form(&[("ip", "198.51.100.78")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(unknown.contains("not in the dataset"));
    assert!(
        unknown.contains("198.51.100.0/24") && unknown.contains("198.51.100.77"),
        "{unknown}"
    );
    assert!(unknown.contains("not kept"));
    assert!(
        unknown.contains("Same ASN") && unknown.contains("/ips?asn=64500"),
        "{unknown}"
    );
    assert!(sections(&unknown).is_empty());
}

/// The Credits page: what this node holds, what it earned and spent, what
/// everyone holds, and how the price comes about.
#[tokio::test]
async fn the_credits_page_shows_balance_earnings_payments_and_the_price() {
    use peephole::credits::{self, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    price::refresh(&na.node).await.unwrap();
    let cost = price_seen(&na, b.id, "abuseipdb").await as u64;
    let none: peephole::intel::Providers = vec![];
    peephole::intel::lookup::cluster(&rec(&na), &none, "203.0.113.99".parse().unwrap()).await;
    eventually("the receipt is back", || async {
        let book = credits::book_fresh(&na.node).await.unwrap();
        book.balance(&a.id) == 10_000 - cost && book.ledger.held(&a.id) == 0
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let page = format!("{base}/admin/cluster/credits");
    let html = text(&admin, page.clone()).await;
    assert!(html.contains("Credits</a>"), "the tab is there");
    assert!(
        html.contains(&credits::show(10_000 - cost)),
        "the balance: {html}"
    );
    assert!(html.contains("expires in 6 days") || html.contains("in 6 days"));
    // Earned: the granted scans, with what each paid.
    assert!(html.contains("Earned") && html.contains("1.00") && html.contains("0.25"));
    // Spent: one lookup at b, charged, half of it destroyed.
    assert!(html.contains("Spent") && html.contains("node-bravo") && html.contains("charged"));
    assert!(html.contains("abuseipdb"));
    // Everyone: b holds its half.
    assert!(html.contains(&credits::show(cost / 2)));
    // The price, in words and numbers.
    assert!(
        html.contains("earned") && html.contains("credits a day"),
        "{html}"
    );
    assert!(html.contains("lookups a day"));

    // Sending: half a credit to b.
    let r = admin
        .post(format!("{page}/send"))
        .form(&[("to", b.id.to_string()), ("amount", "0.5".into())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    eventually("b received it", || async {
        credits::book_fresh(&nb.node).await.unwrap().balance(&b.id) == cost / 2 + 500
    })
    .await;
    let html = text(&admin, page.clone()).await;
    assert!(html.contains("Sent and received") && html.contains("0.50"));
    // More than it holds, and nonsense: nothing moves.
    for amount in ["500", "abc", "0"] {
        admin
            .post(format!("{page}/send"))
            .form(&[("to", b.id.to_string()), ("amount", amount.into())])
            .send()
            .await
            .unwrap();
    }
    assert_eq!(
        credits::book_fresh(&na.node).await.unwrap().balance(&a.id),
        10_000 - cost - 500
    );
}

/// The Members table and a member's page say whether it earns here, why
/// not, and what audits found.
#[tokio::test]
async fn a_members_page_says_whether_it_earns_here() {
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    grant_scans(&[&na], b.id, 4).await;
    let (admin, base) = admin_on(&na).await;
    let page = format!("{base}/admin/cluster/node/{}", b.id);
    let html = text(&admin, page.clone()).await;
    assert!(html.contains("Credits") && html.contains("5.00"), "{html}");
    assert!(
        html.contains("Earns here") && html.contains(">yes<"),
        "{html}"
    );
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(!members.contains("not earning here"));

    // b showed two histories (marked as the seal check would).
    sqlx::query("INSERT INTO forked (origin, seq, found_at) VALUES (?, 7, datetime('now'))")
        .bind(&b.id.0[..])
        .execute(&na.store.pool)
        .await
        .unwrap();
    // The page reads a book of at most ten seconds ago: compute one now.
    peephole::credits::book_fresh(&na.node).await.unwrap();
    let html = text(&admin, page).await;
    assert!(html.contains("showed two histories"), "{html}");
    assert!(html.contains(">no<") && html.contains("0.00"));
    let members = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(
        members.contains("not earning here: showed two histories"),
        "{members}"
    );
}

/// Overview shows the cluster's figures from this node's view.
#[tokio::test]
async fn the_overview_shows_the_clusters_credit_figures() {
    use peephole::credits::price;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&na, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na], a.id, 112).await;
    price::refresh(&na.node).await.unwrap();
    let (admin, base) = admin_on(&na).await;
    let html = text(&admin, format!("{base}/admin")).await;
    assert!(html.contains("2 of 2 members earn here"), "{html}");
    assert!(html.contains("140.00"), "credits in circulation");
    assert!(html.contains("20.00"), "earned a day");
    assert!(html.contains("200"), "weighted lookups a day");
    assert!(html.contains("0.40"), "the unit price: saturated, double");
    assert!(html.contains("Forks") && html.contains("Audits"));
}

/// A declined offer frees what it held before the asker offers again:
/// the second offer needs credits the first one held.
#[tokio::test]
async fn a_declined_offer_frees_its_credits_for_the_next() {
    use peephole::credits::{pay, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 1).await;
    let cost = price::refresh(&nb.node)
        .await
        .unwrap()
        .price_of("abuseipdb")
        .unwrap() as u64;
    assert!(cost > 1 && cost < 600, "{cost}");
    price_seen(&na, b.id, "abuseipdb").await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.81".parse().unwrap();
    let wanted = ["abuseipdb".to_string()];
    let low = pay::offer_and_ask(&na.node, &none, ip, b.id, &wanted, cost - 1).await;
    assert_eq!(low.price_mc, Some(cost as u32), "{low:?}");
    // 1250 held: cost - 1 by the first offer. This needs some of it back.
    let more = 1250 - cost + 2;
    let second = pay::offer_and_ask(&na.node, &none, ip, b.id, &wanted, more).await;
    assert_eq!(
        (second.findings.len(), second.charged_mc as u64),
        (1, cost),
        "{second:?}"
    );
}

/// An offer the server will not take for the asker's standing there is
/// released at once: what it held is free again on the asker.
#[tokio::test]
async fn an_offer_declined_for_the_askers_standing_is_released() {
    use peephole::credits::{self, pay, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 1).await;
    let cost = price::refresh(&nb.node)
        .await
        .unwrap()
        .price_of("abuseipdb")
        .unwrap() as u64;
    price_seen(&na, b.id, "abuseipdb").await;
    sqlx::query("INSERT INTO forked (origin, seq, found_at) VALUES (?, 7, datetime('now'))")
        .bind(&a.id.0[..])
        .execute(&nb.store.pool)
        .await
        .unwrap();
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.82".parse().unwrap();
    let wanted = ["abuseipdb".to_string()];
    let r = pay::offer_and_ask(&na.node, &none, ip, b.id, &wanted, cost).await;
    assert!(
        r.findings.is_empty() && r.declined[0].1.contains("not accepted here"),
        "{r:?}"
    );
    let book = credits::book_fresh(&na.node).await.unwrap();
    assert_eq!(book.ledger.held(&a.id), 0);
    assert_eq!(book.balance(&a.id), 1250);
}
