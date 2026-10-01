# Federated Cluster, Part 1: Membership and Deletes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make cluster membership and deletes safe among operators who do not trust each other: nobody can remove another node or delete another node's records, and the shared dataset is persistent.

**Architecture:** All rules are enforced by every node when it applies the signed replication log, never by the sender. Membership loses third-party revocation and gains self-leave plus locally computed 30-day staleness. Tombstones become explicit uid lists that only touch entries of the tombstone's own origin; an erased entry is accepted only together with that signed tombstone. A local "delete" of foreign data and a local block both work by taking rows out of the tables while keeping the signed payload in the log, so the node keeps relaying.

**Tech Stack:** Rust (edition 2024), tokio, axum, sqlx/SQLite, askama templates, CBOR over pinned-key mTLS (existing `src/cluster`).

**Spec:** `docs/superpowers/specs/2026-10-01-federated-cluster-design.md`, sections 2, 3, 4, 8, 9, 10. Sections 5 (config key), 6 (enrichment) and 7 (installer) are separate plans, written after this one lands.

## Global Constraints

- No backward compatibility: record kinds, messages and tables change in place. Protocol version and minimum are both raised to `2`.
- Nobody can remove another node. `member_revoke` is honoured only when its origin is the node it names.
- A member with no sign of life for **30 days** is pruned; a running node writes at least one log entry every **24 hours**.
- Staleness is computed locally from the log; no record prunes a member.
- A tombstone erases only entries whose origin equals the tombstone's origin.
- Records of members that left, were pruned or are blocked stay in the log and are relayed.
- In a cluster nothing is erased by age: `scan.retention_days` applies to standalone nodes only.
- `scan.never_scan` applies only to the scanner of the node whose TOML sets it.
- `[roles]` key names stay `listener`, `scanner`, `web`. Docs call the listener role "trap".
- Schema changes go into new numbered files under `src/store/migrations/`; statements must not contain `;` inside themselves (the runner splits on `;`).
- Every task ends green on: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Review Focus

1. A tombstone that lists a parent (request, scan job) but not its children must not fail with a foreign-key error and stall replication from that origin. Expected: children leave the tables, the batch applies. (Test in Task 5.)
2. A member whose clock runs ahead makes its evidence lie in the future. Expected: it counts as active, never as pruned through arithmetic underflow. (Test in Task 3.)
3. `leave` with no peer reachable. Expected: the node still detaches and reports that nobody was told. (Test in Task 2.)
4. An erased stub with no uid, or with a "proof" that is not a tombstone of the same origin. Expected: rejected, the stream does not advance past it. (Test in Task 6.)
5. Deleting the same foreign record twice, blocking oneself, or unblocking a node that is not blocked. Expected: no error for the repeats, a clear error for blocking oneself. (Tests in Task 7.)

## File Structure

| File | Change | Responsibility after this plan |
|---|---|---|
| `src/cluster/rpc/proto.rs` | modify | protocol version 2 |
| `src/cluster/record.rs` | modify | `MemberInfo` without `never_scan`; `TombstoneRec` with explicit uids |
| `src/cluster/members.rs` | modify | membership rules, `Standing`, staleness |
| `src/cluster/mod.rs` | modify | `Detached` state, `leave`, keepalive, blocked set |
| `src/cluster/invite.rs` | modify | reusable invites, list, revoke |
| `src/cluster/block.rs` | create | local block list: block, unblock, list |
| `src/cluster/repl.rs` | modify | acceptance rule, proofs for erased stubs, `rematerialize` |
| `src/cluster/sync.rs`, `src/cluster/rpc/mod.rs` | modify | `Batch` on pull and push; refusal reasons |
| `src/cluster/cli.rs`, `src/main.rs` | modify | `leave`, `invites`, `invite-revoke`, `block`, `unblock` |
| `src/store/data.rs` | modify | scoped tombstones, `unmaterialize`, `hide`, block checks |
| `src/store/recorder.rs`, `src/store/delete.rs` | modify | deletes split into own (tombstone) and foreign (hide) |
| `src/store/migrations/0009…0013` | create | schema for the above |
| `src/scan/mod.rs`, `src/scan/arbiter.rs`, `src/trap/mod.rs` | modify | local `never_scan`, declined jobs |
| `src/admin/cluster.rs`, `src/admin/pages.rs`, `templates/admin_cluster.html`, `assets/js/app.js` | modify | leave, invites, block, delete report |
| `src/lib.rs`, `src/config.rs` | modify | retention only standalone |
| `README.md`, `deploy/config.example.toml` | modify | documentation |
| `tests/cluster.rs` | modify | integration tests |

---

### Task 1: Protocol 2 and local `never_scan`

**Files:**
- Modify: `src/cluster/rpc/proto.rs`, `src/cluster/record.rs`, `src/cluster/members.rs`, `src/cluster/mod.rs`, `src/cluster/repl.rs` (test only), `src/scan/mod.rs`, `src/scan/arbiter.rs`, `src/trap/mod.rs`, `src/store/mod.rs`
- Create: `src/store/migrations/0009_member_info.sql`
- Test: `src/scan/mod.rs` (unit), `tests/cluster.rs`

**Interfaces:**
- Produces: `MemberInfo { id, name, address, roles, proto_min, proto_max }` (no `never_scan`); `MemberRow` without `never_scan`; `NodeParams` and `Node` without `never_scan`; job outcome status `"declined"` in `Msg::Complete`.

- [ ] **Step 1: Write the failing unit test** in the `tests` module of `src/scan/mod.rs`:

```rust
    #[test]
    fn own_never_scan_is_a_refusal_for_this_scanner_only() {
        let never: Vec<ipnet::IpNet> = vec!["203.0.113.0/24".parse().unwrap()];
        assert_eq!(
            locally_refused(&"203.0.113.9".parse().unwrap(), &never),
            Some(Refusal::Mine("never_scan 203.0.113.0/24".into()))
        );
        assert_eq!(
            locally_refused(&"10.0.0.1".parse().unwrap(), &never),
            Some(Refusal::Never("non-global address".into()))
        );
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib own_never_scan_is_a_refusal`
Expected: compile error, `Refusal` not found.

- [ ] **Step 3: Raise the protocol.** In `src/cluster/rpc/proto.rs`:

```rust
/// Highest protocol version this build speaks.
pub const PROTO_VERSION: u32 = 2;
/// Lowest protocol version this build still speaks. Version 1 let any
/// member revoke others and delete their records; it is not spoken.
pub const PROTO_MIN: u32 = 2;
```

- [ ] **Step 4: Remove `never_scan` from membership.**

In `src/cluster/record.rs` delete the `never_scan` field (and its doc comment) from `MemberInfo`, and the `never_scan: vec![],` line from the `info` helper in its tests.

Create `src/store/migrations/0009_member_info.sql`:

```sql
-- never_scan is local to each scanner now; members no longer publish it.
ALTER TABLE members DROP COLUMN never_scan_json
```

Append to `MIGRATIONS` in `src/store/mod.rs`:

```rust
    include_str!("migrations/0009_member_info.sql"),
```

In `src/cluster/members.rs` remove `never_scan` from `MemberRow`, from the `Row` tuple, from `SELECT`, `from_row`, `write_info`, `insert` and the revoke placeholder. The read side becomes:

```rust
type Row = (
    Vec<u8>,
    String,
    Option<String>,
    String,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
);

const SELECT: &str = "SELECT id, name, address, roles_json, proto_min, proto_max,
                             sponsor, info_hlc, admitted_hlc, revoked_hlc FROM members";

fn from_row(r: Row) -> Result<MemberRow> {
    let admitted = r.8;
    Ok(MemberRow {
        id: NodeId::from_slice(&r.0)?,
        name: r.1,
        address: r.2,
        roles: serde_json::from_str(&r.3).unwrap_or_default(),
        proto_min: r.4 as u32,
        proto_max: r.5 as u32,
        sponsor: NodeId::from_slice(&r.6)?,
        info_hlc: r.7 as u64,
        active: admitted > 0 && r.9.is_none_or(|rev| admitted > rev),
    })
}
```

`write_info` and `insert` lose the `never_scan_json` column, its `?` placeholder and its bind (`insert` then has nine columns and nine placeholders).

In `src/cluster/mod.rs` remove the `never_scan` field from `NodeParams` and `Node`, its initialisers in `from_config` and `open`, the field in `self_info`, the `&& m.never_scan == mine.never_scan` comparison and the `never_scan: vec![],` line in `bootstrap`.

- [ ] **Step 5: Make refusals two-valued** in `src/scan/mod.rs`. Replace `locally_refused` and `Safety`:

```rust
/// Why this scanner will not run a job.
#[derive(Debug, PartialEq)]
enum Refusal {
    /// Nobody may scan it (non-global address, a cluster member's address).
    Never(String),
    /// This scanner's own `never_scan` covers it; another scanner may take it.
    Mine(String),
}

impl Refusal {
    fn reason(&self) -> &str {
        match self {
            Refusal::Never(w) | Refusal::Mine(w) => w,
        }
    }
}

/// Config-only refusal applied before nmap runs: never scan a non-global
/// address, and leave anything in this node's `never_scan` to others.
fn locally_refused(ip: &IpAddr, never: &[ipnet::IpNet]) -> Option<Refusal> {
    if !crate::net::is_scannable_target(*ip) {
        return Some(Refusal::Never("non-global address".into()));
    }
    let canon = crate::net::canonical(*ip);
    never
        .iter()
        .find(|n| n.contains(&canon))
        .map(|n| Refusal::Mine(format!("never_scan {n}")))
}
```

```rust
/// Rebuild the member-address set this often (member list, DNS).
const SAFETY_REFRESH: Duration = Duration::from_secs(300);

/// Targets no scanner touches: the addresses of all cluster members.
struct Safety {
    addrs: std::collections::HashSet<IpAddr>,
    built: Option<std::time::Instant>,
}

impl Safety {
    fn new() -> Self {
        Self {
            addrs: Default::default(),
            built: None,
        }
    }

    async fn refresh(&mut self, node: &Node) {
        if self.built.is_some_and(|t| t.elapsed() < SAFETY_REFRESH) {
            return;
        }
        let mut addrs = std::collections::HashSet::new();
        let mut hosts: Vec<String> = node.dial_targets().into_iter().map(|t| t.2).collect();
        if let Ok(rows) = crate::cluster::members::all(&node.store).await {
            hosts.extend(rows.into_iter().filter_map(|m| m.address));
        }
        hosts.extend(node.cfg.advertise.clone());
        for h in hosts {
            if let Ok(Ok(it)) =
                tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host(h)).await
            {
                addrs.extend(it.map(|sa| sa.ip()));
            }
        }
        self.addrs = addrs;
        self.built = Some(std::time::Instant::now());
    }

    fn refuses(&self, ip: &IpAddr) -> Option<String> {
        self.addrs
            .contains(ip)
            .then(|| "cluster member address".to_string())
    }
}
```

In the standalone branch of `Source::acquire` use the reason text:

```rust
            if let Some(r) = locally_refused(&ip, &self.cfg.scan.never_scan) {
                info!(target = %ip, why = r.reason(), "scan refused");
                let _ = self.rec.finish_job(job.id, None, Some(r.reason())).await;
                return Box::pin(self.acquire()).await;
            }
```

In the cluster branch replace the pre-flight block (`let refused = …` through its `if let Some(why) = refused { … }`):

```rust
            // Pre-flight: refused targets and duplicates never reach nmap.
            let refused = match locally_refused(&ip, &self.cfg.scan.never_scan) {
                some @ Some(_) => some,
                None => {
                    let mut s = self.safety.lock().await;
                    s.refresh(node).await;
                    s.refuses(&ip).map(Refusal::Never)
                }
            };
            match refused {
                Some(Refusal::Never(why)) => {
                    info!(target = %ip, %why, "scan refused");
                    self.report(node, arbiter, &g.job_uid, "refused", Some(why))
                        .await;
                    continue;
                }
                // Our own never_scan: hand the job back for another scanner.
                Some(Refusal::Mine(why)) => {
                    info!(target = %ip, %why, "scan declined");
                    self.report(node, arbiter, &g.job_uid, "declined", Some(why))
                        .await;
                    continue;
                }
                None => {}
            }
```

- [ ] **Step 6: Teach the arbiter about declined jobs** in `src/scan/arbiter.rs`.

Add the field to `Arbiter` and initialise it with `declined: Mutex::new(HashMap::new()),` in `start`:

```rust
    /// Scanners that handed a job back because their own never_scan covers it.
    declined: Mutex<HashMap<String, std::collections::HashSet<NodeId>>>,
```

Replace `next_job`'s row lookup so a scanner is not offered a job it declined:

```rust
        let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
            "SELECT j.uid, i.ip, j.level, j.attempts FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
             WHERE j.status = 'queued' AND j.arbiter = ?
             ORDER BY j.level DESC, j.queued_at ASC LIMIT 50",
        )
        .bind(&me.0[..])
        .fetch_all(&self.node.store.pool)
        .await?;
        let row = {
            let declined = self.declined.lock().unwrap();
            rows.into_iter()
                .find(|(uid, ..)| !declined.get(uid).is_some_and(|s| s.contains(&scanner)))
        };
        let Some((uid, ip, level, attempts)) = row else {
            return Ok(None);
        };
```

In `complete`, accept the new status and branch after the lease is removed:

```rust
        if !["done", "failed", "superseded", "refused", "declined"].contains(&status) {
            return false;
        }
```

```rust
        self.leases.lock().unwrap().remove(uid);
        if status == "declined" {
            return self.decline(scanner, uid, error).await;
        }
        self.declined.lock().unwrap().remove(uid);
```

Add the two methods:

```rust
    /// Members currently running the scanner role (this node included).
    fn scanners(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self
            .node
            .members()
            .values()
            .filter(|m| m.roles.iter().any(|r| r == "scanner"))
            .map(|m| m.id)
            .collect();
        if self.node.roles.scanner && !v.contains(&self.node.id()) {
            v.push(self.node.id());
        }
        v
    }

    /// A scanner handed the job back. It returns to the queue for the other
    /// scanners; once every scanner has declined, it is refused for good.
    async fn decline(&self, scanner: NodeId, uid: &str, why: Option<String>) -> bool {
        let everyone = {
            let mut d = self.declined.lock().unwrap();
            let set = d.entry(uid.to_string()).or_default();
            set.insert(scanner);
            let all = self.scanners().iter().all(|s| set.contains(s));
            if all {
                d.remove(uid);
            }
            all
        };
        let r = if everyone {
            let why = format!(
                "declined by every scanner ({})",
                why.unwrap_or_else(|| "never_scan".into())
            );
            self.set_state(uid, "refused", Some(why), Some(now_ts())).await
        } else {
            self.set_state(uid, "queued", None, None).await
        };
        if let Err(e) = r {
            warn!(?e, job = %uid, "recording a declined job failed");
            return false;
        }
        true
    }
```

- [ ] **Step 7: Queue scans regardless of the trap's `never_scan` in a cluster.** In `src/trap/mod.rs` there are two identical lines `let allowlisted = state.cfg.scan.never_scan.iter().any(|n| n.contains(&canon));`. Replace both with:

```rust
    // never_scan is the business of this node's own scanner. Standalone that
    // is the only scanner, so the job is not queued at all; in a cluster
    // another scanner may take it.
    let allowlisted = state.recorder.node().is_none()
        && state.cfg.scan.never_scan.iter().any(|n| n.contains(&canon));
```

- [ ] **Step 8: Fix the remaining compile errors.** Run `cargo build --all-targets`. Every error is a `never_scan` line in a `NodeParams { … }` or `MemberInfo { … }` literal (`src/cluster/repl.rs` tests, `tests/cluster.rs`); delete those lines. In `tests/cluster.rs` keep `Opts::never_scan` and its use in `scan_config(&o.never_scan)`; only the `never_scan: o.never_scan.clone(),` line inside `NodeParams` goes.

- [ ] **Step 9: Replace the cluster test.** In `tests/cluster.rs` delete `never_scan_of_any_member_is_honoured` and add:

```rust
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
    assert!(!tools.path().join("targets.log").exists(), "nmap must not run");
}
```

- [ ] **Step 10: Run the tests**

Run: `cargo test`
Expected: PASS. If `incompatible_protocol_ranges_are_reported` fails, it pins its own ranges and must not be changed; look for a leftover `never_scan`.

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster)!: protocol 2; never_scan is local to its scanner"
```

---

### Task 2: A node can only remove itself

**Files:**
- Modify: `src/cluster/members.rs`, `src/cluster/repl.rs`, `src/cluster/mod.rs`, `src/cluster/invite.rs`, `src/cluster/cli.rs`, `src/main.rs`, `src/admin/cluster.rs`, `templates/admin_cluster.html`
- Test: `tests/cluster.rs`

**Interfaces:**
- Consumes: `MemberInfo` from Task 1.
- Produces:
  - `pub enum cluster::Detached { Left, Pruned }` with `pub fn label(&self) -> &'static str`
  - `pub async fn cluster::set_detached(store: &Store, d: Option<Detached>) -> Result<()>`
  - `pub fn Node::detached(&self) -> Option<Detached>`
  - `pub async fn cluster::leave(node: &Node) -> Result<usize>` (number of peers told)
  - `MemberView::state: &'static str`
  - `repl::trusted` now means "ever admitted".

- [ ] **Step 1: Write the failing tests** in `tests/cluster.rs`. Delete `revocation_spreads_and_locks_the_node_out` and add:

```rust
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
    let token = invite::create(&nb, 1).await.unwrap();
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
    assert!(nc.dial_targets().is_empty(), "a node that left stops dialling");
    eventually("a sees c gone", || knows(&na, c.id, false)).await;
    let e = nc.hello(a.id, &a.address()).await.unwrap_err();
    assert!(format!("{e:#}").contains("not a cluster member"), "{e:#}");

    // Rejoining takes an invite.
    let token = invite::create(&na, 1).await.unwrap();
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
```

In `outbound_only_member_syncs_both_ways` the probe record `Record::MemberRevoke { id: d.id }` would now be ignored. Replace that line with:

```rust
    let rec = Record::MemberAdd(peephole::cluster::record::MemberInfo {
        id: d.id,
        name: "d".into(),
        address: None,
        roles: vec![],
        proto_min: 0,
        proto_max: 0,
    });
```

In `admin_cluster_page_and_private_attribution` replace the block that starts with `// Revoke from the UI.` (through `assert!(knows(&na, c.id, false).await);`) with:

```rust
    // Removing another node is not offered.
    let r = admin
        .post(format!("{base}/admin/cluster/revoke"))
        .form(&[("key", c.id.to_string())])
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success(), "revoke route is gone");
    assert!(knows(&na, c.id, true).await);
    assert!(page.contains("Leave cluster"), "leave button");
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test cluster only_a_node_itself_can_leave`
Expected: compile error, `cluster::leave` not found.

- [ ] **Step 3: Membership rules.** In `src/cluster/members.rs` update the module doc and the revoke arm:

```rust
//! - `member_revoke` is honoured only from the node it names: that is how
//!   a node leaves. Nobody can remove another node. A later add re-admits.
```

```rust
        Record::MemberRevoke { id } => {
            if *id != e.origin {
                warn!(
                    origin = %e.origin.short(),
                    target = %id.short(),
                    "ignored member_revoke for another node: a node can only remove itself"
                );
                return Ok(true);
            }
            sqlx::query(
                "UPDATE members SET revoked_hlc = MAX(COALESCE(revoked_hlc, 0), ?), revoked_by = ?
                 WHERE id = ?",
            )
            .bind(e.hlc as i64)
            .bind(&e.origin.0[..])
            .bind(&id.0[..])
            .execute(&mut *conn)
            .await?;
            info!(id = %id.short(), "member left the cluster");
        }
```

In `src/cluster/repl.rs` replace `trusted`:

```rust
/// Whether records from `origin` are accepted: this node, or any node that
/// was ever admitted. Leaving or being pruned ends a node's access, not the
/// validity of what it recorded.
pub async fn trusted(node: &Node, conn: &mut SqliteConnection, origin: &NodeId) -> Result<bool> {
    if *origin == node.id() {
        return Ok(true);
    }
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE id = ? AND admitted_hlc > 0")
            .bind(&origin.0[..])
            .fetch_one(&mut *conn)
            .await?;
    Ok(n > 0)
}
```

- [ ] **Step 4: The detached state and `leave`.** In `src/cluster/mod.rs` add:

```rust
/// Why this node no longer takes part in its cluster. It keeps its copy of
/// the data and what it contributed stays in the cluster.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Detached {
    /// It left (`peephole cluster leave`).
    Left,
    /// It was offline for longer than the prune window.
    Pruned,
}

const DETACHED_KEY: &str = "cluster.detached";

impl Detached {
    fn as_str(&self) -> &'static str {
        match self {
            Detached::Left => "left",
            Detached::Pruned => "pruned",
        }
    }

    /// What the admin UI and CLI say about it.
    pub fn label(&self) -> &'static str {
        match self {
            Detached::Left => "This node left its cluster and no longer syncs. Rejoin with an invite.",
            Detached::Pruned => {
                "This node was silent for more than 30 days and has been pruned from its cluster. Rejoin with an invite."
            }
        }
    }
}

async fn read_detached(store: &Store) -> Result<Option<Detached>> {
    let v: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(DETACHED_KEY)
        .fetch_optional(&store.pool)
        .await?;
    Ok(match v.as_deref() {
        Some("left") => Some(Detached::Left),
        Some("pruned") => Some(Detached::Pruned),
        _ => None,
    })
}

/// Persist (or clear) the detached state; the daemon picks it up within
/// seconds, also when the CLI wrote it.
pub async fn set_detached(store: &Store, d: Option<Detached>) -> Result<()> {
    match d {
        Some(d) => {
            sqlx::query(
                "INSERT INTO settings (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(DETACHED_KEY)
            .bind(d.as_str())
            .execute(&store.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM settings WHERE key = ?")
                .bind(DETACHED_KEY)
                .execute(&store.pool)
                .await?;
        }
    }
    Ok(())
}

/// Leave the cluster: announce it, hand the announcement to every peer we
/// can reach, then stop syncing. Returns how many peers were told.
pub async fn leave(node: &Node) -> Result<usize> {
    repl::append(node, &[Record::MemberRevoke { id: node.id() }]).await?;
    let mut told = 0;
    for (peer, _, addr) in node.dial_targets() {
        if sync::reconcile(node, peer, &addr, false).await.is_ok() {
            told += 1;
        }
    }
    if told == 0 {
        warn!("left the cluster without reaching a peer; it will prune this node after 30 days");
    }
    set_detached(&node.store, Some(Detached::Left)).await?;
    node.reload_members().await?;
    Ok(told)
}
```

Add the field `detached: RwLock<Option<Detached>>,` to `Node`, initialise it with `detached: RwLock::new(None),` in `open`, and add:

```rust
    pub fn detached(&self) -> Option<Detached> {
        *self.detached.read().unwrap()
    }
```

`reload_members` reads it together with the members, and `dial_targets` honours it:

```rust
    pub async fn reload_members(&self) -> Result<()> {
        let rows = members::all(&self.store).await?;
        let detached = read_detached(&self.store).await?;
        let map: HashMap<_, _> = rows
            .into_iter()
            .filter(|m| m.active || m.id == self.identity.id)
            .map(|m| (m.id, m))
            .collect();
        let before = self.dial_targets();
        *self.members.write().unwrap() = Arc::new(map);
        *self.detached.write().unwrap() = detached;
        if self.dial_targets() != before {
            self.members_changed.notify_one();
        }
        Ok(())
    }
```

```rust
    /// Active members we can dial: `(id, name, address)`. None while this
    /// node is detached from its cluster.
    pub fn dial_targets(&self) -> Vec<(NodeId, String, String)> {
        if self.detached().is_some() {
            return vec![];
        }
```

(the rest of `dial_targets` is unchanged).

- [ ] **Step 5: Rejoining.** In `src/cluster/invite.rs`, `join`: replace the `others` check and clear the state on success.

```rust
    let others = node
        .members()
        .values()
        .filter(|m| m.id != node.id())
        .count();
    // A node in a cluster may only rejoin that same cluster; a detached one
    // may join anywhere, like a standalone node.
    let known = super::members::all(&node.store)
        .await?
        .iter()
        .any(|m| m.id == t.id);
    if others > 0 && !known && node.detached().is_none() {
        bail!("this node already belongs to a cluster ({others} other member(s))");
    }
```

```rust
                repl::append(node, &[Record::MemberAdd(info.clone())]).await?;
                super::set_detached(&node.store, None).await?;
                node.reload_members().await?;
                return Ok(info);
```

- [ ] **Step 6: CLI.** In `src/cluster/cli.rs` change `USAGE` (replace the `revoke` line):

```rust
       peephole cluster leave [CONFIG]";
```

Replace the `Some("revoke") => { … }` arm:

```rust
        Some("leave") => {
            reject_unknown_flags(&flags, &[])?;
            let (_, node) = open(cfg_at(1)).await?;
            let told = super::leave(&node).await?;
            println!(
                "left the cluster ({told} peer(s) told). This node keeps its data and no \
                 longer syncs; rejoin with: peephole cluster join <token>"
            );
        }
```

In the `members`/`status` arm change the state line to `let state = if m.active { "active" } else { "left" };`. Delete the `resolve` function (nothing uses it until Task 7 brings it back) and the imports the compiler then reports as unused (`Record`, possibly `NodeId`). In `src/admin/cluster.rs` the `Record` import goes for the same reason. In `src/main.rs` change the help text `(id|invite|join|members|status|revoke)` to `(id|invite|join|members|status|leave)`.

- [ ] **Step 7: Admin page.** In `src/admin/cluster.rs`:

- Remove the `/admin/cluster/revoke` route, `RevokeForm` and `revoke`. Add `.route("/admin/cluster/leave", post(leave))`.
- Add `pub state: &'static str,` to `MemberView`; set `state: if m.active { "active" } else { "left" },` in `views` and `state: "active",` in the fallback `mine`.
- In `ClusterPage` replace `can_join: bool` with `detached: Option<&'static str>`. In `render_page` set `detached: None` for the standalone page and `detached: node.detached().map(|d| d.label()),` otherwise.
- Add the handler:

```rust
async fn leave(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Redirect> {
    let node = node(&st)?;
    Ok(match crate::cluster::leave(node).await {
        Ok(told) => back(
            Some(format!(
                "This node left the cluster ({told} peer(s) told). Its data stays here; it no longer syncs."
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("Leaving failed: {e:#}"))),
    })
}
```

In `templates/admin_cluster.html`:

- Directly after the `<div class="stack">` line add:

```html
{% if let Some(d) = detached %}<div class="banner banner-warning">{{ d }}</div>{% endif %}
```

- Replace the card head of "This node" with:

```html
  <div class="card-head"><h2>This node · {{ me.name }}</h2><span class="muted mono">{{ me.short }}</span>
    {% if detached.is_none() %}<button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-leave">Leave cluster</button>
    <dialog id="dlg-leave"><h3>Leave the cluster?</h3><p class="muted">This node stops syncing. Its copy of the data stays, and what it contributed stays in the cluster. Nobody else can remove a node; rejoining needs an invite.</p>
      <form method="post" action="/admin/cluster/leave" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Leave</button></form></dialog>{% endif %}</div>
```

- In the members table replace `<span class="badge badge-status" data-status="failed">revoked</span>` with `<span class="badge badge-status" data-status="failed">{{ m.state }}</span>`, and replace the whole last cell (`<td>{% if m.active %} … {% endif %}</td>`, the Revoke button and dialog) with `<td></td>`.
- Replace `{% if can_join %}` … `{% endif %}` around the join card by the card alone, with the heading `Join or rejoin a cluster`.

- [ ] **Step 8: Run the tests**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 9: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster)!: no removal of other nodes; a node leaves by itself"
```

---

### Task 3: Stale members are pruned

**Files:**
- Modify: `src/cluster/hlc.rs`, `src/cluster/members.rs`, `src/cluster/mod.rs`, `src/cluster/rpc/mod.rs`, `src/cluster/cli.rs`, `src/admin/cluster.rs`
- Test: `src/cluster/members.rs` (unit), `tests/cluster.rs`

**Interfaces:**
- Consumes: `Detached`, `set_detached`, `Node::detached` from Task 2.
- Produces:
  - `pub(crate) fn hlc::wall_ms() -> u64`
  - `pub const members::PRUNE_AFTER_MS: u64`, `pub const members::KEEPALIVE_MS: u64`
  - `pub enum members::Standing { Active, Left, Pruned, NotAdmitted }` with `pub fn label(&self) -> &'static str`
  - `pub fn members::standing(admitted_hlc: u64, left_hlc: Option<u64>, last_entry_hlc: u64, now_ms: u64) -> Standing`
  - `MemberRow::standing: Standing`, `MemberRow::last_entry_hlc: u64`; `MemberRow::active` equals `standing == Standing::Active`
  - `pub async fn members::all_at(store: &Store, now_ms: u64) -> Result<Vec<MemberRow>>`
  - `pub fn Node::standing_of(&self, id: &NodeId) -> Option<Standing>`
  - `pub async fn Node::keepalive(&self) -> Result<bool>`

- [ ] **Step 1: Write the failing unit tests** at the end of `src/cluster/members.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600 * 1000;

    fn hlc(ms: u64) -> u64 {
        ms << 16
    }

    #[test]
    fn standing_follows_admission_leave_and_evidence() {
        let now = 1_000 * DAY;
        assert_eq!(standing(0, None, hlc(now), now), Standing::NotAdmitted);
        assert_eq!(standing(hlc(now), None, 0, now), Standing::Active);
        // Left: the leave is newer than the admission; a later add re-admits.
        assert_eq!(
            standing(hlc(now - DAY), Some(hlc(now)), hlc(now), now),
            Standing::Left
        );
        assert_eq!(
            standing(hlc(now), Some(hlc(now - DAY)), 0, now),
            Standing::Active
        );
        // 31 days without an entry: pruned. Either kind of evidence revives.
        let old = hlc(now - 31 * DAY);
        assert_eq!(standing(old, None, old, now), Standing::Pruned);
        assert_eq!(standing(old, None, hlc(now - DAY), now), Standing::Active);
        assert_eq!(standing(hlc(now - DAY), None, old, now), Standing::Active);
        // Exactly at the limit is still active.
        let edge = hlc(now - 30 * DAY);
        assert_eq!(standing(edge, None, edge, now), Standing::Active);
    }

    #[test]
    fn a_clock_running_ahead_never_looks_stale() {
        let now = 1_000 * DAY;
        let future = hlc(now + 400 * DAY);
        assert_eq!(standing(future, None, future, now), Standing::Active);
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib standing_follows`
Expected: compile error, `standing` not found.

- [ ] **Step 3: Implement `Standing`.** In `src/cluster/hlc.rs` change `fn wall_ms()` to `pub(crate) fn wall_ms()`. In `src/cluster/members.rs` add below the imports:

```rust
/// A member without any sign of life for this long is pruned.
pub const PRUNE_AFTER_MS: u64 = 30 * 24 * 3600 * 1000;
/// A running node writes at least one entry this often, so it stays visible.
pub const KEEPALIVE_MS: u64 = 24 * 3600 * 1000;

/// A member's standing as this node computes it from its copy of the log.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub enum Standing {
    Active,
    /// It left by itself.
    Left,
    /// No sign of life for [`PRUNE_AFTER_MS`].
    Pruned,
    /// Known (e.g. it described itself) but never admitted.
    NotAdmitted,
}

impl Standing {
    pub fn label(&self) -> &'static str {
        match self {
            Standing::Active => "active",
            Standing::Left => "left",
            Standing::Pruned => "pruned",
            Standing::NotAdmitted => "not admitted",
        }
    }
}

/// Signs of life are the newest entry the member signed and its latest
/// admission. Entries are signed by their origin, so nobody can make another
/// node look stale, and evidence relayed by any member counts.
pub fn standing(
    admitted_hlc: u64,
    left_hlc: Option<u64>,
    last_entry_hlc: u64,
    now_ms: u64,
) -> Standing {
    if admitted_hlc == 0 {
        return Standing::NotAdmitted;
    }
    if left_hlc.is_some_and(|l| l >= admitted_hlc) {
        return Standing::Left;
    }
    let evidence = super::hlc::physical_ms(admitted_hlc.max(last_entry_hlc));
    if now_ms.saturating_sub(evidence) > PRUNE_AFTER_MS {
        Standing::Pruned
    } else {
        Standing::Active
    }
}
```

Add to `MemberRow`:

```rust
    pub standing: Standing,
    /// HLC of the newest log entry this member signed (0: none held).
    pub last_entry_hlc: u64,
```

Replace `Row`, `SELECT`, `from_row`, `all` and `get`:

```rust
type Row = (
    Vec<u8>,
    String,
    Option<String>,
    String,
    i64,
    i64,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
);

const SELECT: &str = "SELECT id, name, address, roles_json, proto_min, proto_max,
                             sponsor, info_hlc, admitted_hlc, revoked_hlc,
                             (SELECT l.hlc FROM repl_log l WHERE l.origin = members.id
                              ORDER BY l.seq DESC LIMIT 1)
                      FROM members";

fn from_row(r: Row, now_ms: u64) -> Result<MemberRow> {
    let last_entry_hlc = r.10.unwrap_or(0) as u64;
    let standing = standing(r.8 as u64, r.9.map(|v| v as u64), last_entry_hlc, now_ms);
    Ok(MemberRow {
        id: NodeId::from_slice(&r.0)?,
        name: r.1,
        address: r.2,
        roles: serde_json::from_str(&r.3).unwrap_or_default(),
        proto_min: r.4 as u32,
        proto_max: r.5 as u32,
        sponsor: NodeId::from_slice(&r.6)?,
        info_hlc: r.7 as u64,
        active: standing == Standing::Active,
        standing,
        last_entry_hlc,
    })
}

/// Every member row with its standing as of now.
pub async fn all(store: &crate::store::Store) -> Result<Vec<MemberRow>> {
    all_at(store, super::hlc::wall_ms()).await
}

/// Like [`all`], judged at `now_ms` (tests).
pub async fn all_at(store: &crate::store::Store, now_ms: u64) -> Result<Vec<MemberRow>> {
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY name")))
        .fetch_all(&store.pool)
        .await?;
    rows.into_iter().map(|r| from_row(r, now_ms)).collect()
}

async fn get(conn: &mut SqliteConnection, id: &NodeId) -> Result<Option<MemberRow>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id = ?")))
        .bind(&id.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    row.map(|r| from_row(r, super::hlc::wall_ms())).transpose()
}
```

- [ ] **Step 4: Run the unit tests**

Run: `cargo test --lib members::`
Expected: PASS.

- [ ] **Step 5: Write the failing integration tests** in `tests/cluster.rs`:

```rust
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
    };
    // A admitted B 40 days ago; B described itself then and went silent.
    let st = repl::apply_batch(
        &x,
        vec![
            WireEntry::sign(&a_id, 1, hlc_days_ago(40, 1), &Record::MemberAdd(info(&b_id)))
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
    assert_eq!(st.applied, 2, "a pruned member's records are still applied: {st:?}");
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
            WireEntry::sign(&b_id, 2, hlc_days_ago(0, 3), &Record::MemberUpdate(info(&b_id)))
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
    assert!(!x.keepalive().await.unwrap(), "fresh entries: nothing to do");
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
                peers: vec![PeerConfig {
                    name: "a".into(),
                    address: a.address(),
                    public_key: a.id.to_string(),
                }],
            },
            roles: Roles::default(),
            store,
            proto: (2, 2),
            has_maxmind: false,
            data_dir: dir.path().to_path_buf(),
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
```

Other tests sign membership entries with tiny HLCs (`1`, `10`, `20`) and then assert `active`; with staleness those members are pruned. In `forged_entries_are_rejected_and_unknown_origins_parked` replace the HLC arguments `10`, `12` and `20` with `hlc_days_ago(0, 10)`, `hlc_days_ago(0, 12)` and `hlc_days_ago(0, 20)`.

- [ ] **Step 6: Run them to verify they fail**

Run: `cargo test --test cluster members_silent a_running_node a_node_offline`
Expected: compile errors for `standing_of` and `keepalive`.

- [ ] **Step 7: Node side.** In `src/cluster/mod.rs`:

Add the field `standings: RwLock<Arc<HashMap<NodeId, members::Standing>>>,` to `Node` (initialise with `standings: RwLock::new(Arc::new(HashMap::new())),`). In `reload_members`, build it before the rows are consumed:

```rust
        let standings: HashMap<_, _> = rows.iter().map(|m| (m.id, m.standing)).collect();
```

and store it next to the member map:

```rust
        *self.standings.write().unwrap() = Arc::new(standings);
```

Add the methods:

```rust
    /// The standing of any known node, member or not.
    pub fn standing_of(&self, id: &NodeId) -> Option<members::Standing> {
        self.standings.read().unwrap().get(id).copied()
    }

    /// HLC of the newest entry this node wrote, if any.
    async fn own_last_hlc(&self) -> Result<Option<u64>> {
        let h: Option<i64> = sqlx::query_scalar(
            "SELECT hlc FROM repl_log WHERE origin = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.id().0[..])
        .fetch_optional(&self.store.pool)
        .await?;
        Ok(h.map(|h| h as u64))
    }

    /// Write a sign of life when this node has been quiet for a day, so the
    /// cluster does not prune a node that merely has nothing to record.
    /// Returns whether an entry was written.
    pub async fn keepalive(&self) -> Result<bool> {
        if self.detached().is_some() {
            return Ok(false);
        }
        let last = self.own_last_hlc().await?.map_or(0, hlc::physical_ms);
        if hlc::wall_ms().saturating_sub(last) < members::KEEPALIVE_MS {
            return Ok(false);
        }
        repl::append(self, &[Record::MemberUpdate(self.self_info())]).await?;
        Ok(true)
    }
```

In `Node::open`, after `node.reload_members().await?;` add the self-check:

```rust
        // Offline for longer than the prune window: the cluster dropped us,
        // and our log is too old to judge anyone else by.
        if node.detached().is_none()
            && let Some(last) = node.own_last_hlc().await?
            && hlc::wall_ms().saturating_sub(hlc::physical_ms(last)) > members::PRUNE_AFTER_MS
            && node.standings.read().unwrap().len() > 1
        {
            warn!("no entry of our own for over 30 days: pruned from the cluster; rejoin with an invite");
            set_detached(&node.store, Some(Detached::Pruned)).await?;
            node.reload_members().await?;
        }
```

In `heartbeat_loop`, after `node.refresh_heartbeat();`:

```rust
        if let Err(e) = node.keepalive().await {
            warn!(?e, "keepalive failed");
        }
```

- [ ] **Step 8: Tell a pruned node why it is refused.** In `src/cluster/rpc/mod.rs` replace the `else` branch of `require_member`:

```rust
    } else {
        let why = match node.standing_of(&peer) {
            Some(crate::cluster::members::Standing::Pruned) => {
                "pruned: no sign of life for 30 days; rejoin with an invite"
            }
            _ => "not a cluster member",
        };
        tracing::debug!(peer = %peer.short(), why, "rpc refused");
        (StatusCode::FORBIDDEN, why).into_response()
    }
```

- [ ] **Step 9: Show the standing.** In `src/admin/cluster.rs` set `state: m.standing.label(),` in `views`. In `src/cluster/cli.rs`, `members`/`status` arm, replace the state line with `let state = m.standing.label();`, widen its column from `{:<8}` to `{:<12}`, and say why a detached node is on its own, directly before `for m in rows {`:

```rust
            if let Some(d) = crate::cluster::Detached::read(&store).await? {
                println!("{}", d.label());
            }
```

Expose that reader in `src/cluster/mod.rs`:

```rust
impl Detached {
    /// The persisted state (CLI; the daemon caches it in [`Node::detached`]).
    pub async fn read(store: &Store) -> Result<Option<Detached>> {
        read_detached(store).await
    }
}
```

- [ ] **Step 10: Run the tests**

Run: `cargo test`
Expected: PASS. A failing older test that asserts `active` after applying entries with small literal HLCs needs `hlc_days_ago(0, n)` in place of the literal, as in Step 5.

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster): prune members silent for 30 days; daily sign of life"
```

---

### Task 4: Reusable invites

**Files:**
- Create: `src/store/migrations/0010_invites.sql`
- Modify: `src/store/mod.rs`, `src/cluster/invite.rs`, `src/cluster/cli.rs`, `src/main.rs`, `src/admin/cluster.rs`, `templates/admin_cluster.html`
- Test: `tests/cluster.rs`

**Interfaces:**
- Produces:
  - `pub struct invite::InviteOpts { pub label: String, pub ttl_hours: Option<u64>, pub max_uses: Option<u32> }` (`Default`: no expiry, no limit)
  - `pub async fn invite::create(node: &Node, o: &InviteOpts) -> Result<String>`
  - `pub struct invite::InviteRow { pub id: i64, pub label: String, pub created_at: String, pub expires_at: Option<String>, pub max_uses: Option<i64>, pub uses: i64, pub revoked: bool, pub usable: bool, pub joined: Vec<NodeId> }`
  - `pub async fn invite::list(store: &Store) -> Result<Vec<InviteRow>>` (newest first)
  - `pub async fn invite::revoke(store: &Store, id: i64) -> Result<bool>`
  - `invite::DEFAULT_TTL_HOURS` is removed.

- [ ] **Step 1: Write the failing test.** In `tests/cluster.rs` replace `invites_are_single_use_and_expire` with:

```rust
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
```

Every other call `invite::create(&NODE, 1)` in `tests/cluster.rs` becomes `invite::create(&NODE, &Default::default())`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test cluster invites_are_reusable`
Expected: compile error, `InviteOpts` not found.

- [ ] **Step 3: Schema.** Create `src/store/migrations/0010_invites.sql` and append `include_str!("migrations/0010_invites.sql"),` to `MIGRATIONS`:

```sql
-- Invites are reusable: one token can admit a whole peer group over time.
-- Only the secret's hash is stored. Existing one-time invites are dropped.
DROP TABLE IF EXISTS invites;
CREATE TABLE invites (
  id INTEGER PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT
);
CREATE TABLE invite_uses (
  invite_id INTEGER NOT NULL REFERENCES invites(id),
  node BLOB NOT NULL,
  used_at TEXT NOT NULL
);
CREATE INDEX idx_invite_uses_invite ON invite_uses(invite_id)
```

- [ ] **Step 4: Implement.** In `src/cluster/invite.rs` update the module doc (`//! Join invites.` … "An invite can be redeemed any number of times until it expires, reaches its use limit or is revoked."), remove `DEFAULT_TTL_HOURS`, and replace `create` and the invite check in `redeem`:

```rust
/// How an invite is limited. The default has no expiry and no use limit.
#[derive(Debug, Clone, Default)]
pub struct InviteOpts {
    /// Shown in the invite list (who it was given to).
    pub label: String,
    pub ttl_hours: Option<u64>,
    pub max_uses: Option<u32>,
}

/// Create an invite; returns the token (shown once).
pub async fn create(node: &Node, o: &InviteOpts) -> Result<String> {
    let Some(addr) = node.cfg.advertise.clone() else {
        bail!(
            "this node has no cluster.advertise address, so a joiner cannot reach it; \
             create the invite on a reachable node"
        );
    };
    if o.ttl_hours.is_some_and(|h| !(1..=24 * 365).contains(&h)) {
        bail!("invite lifetime must be between 1 hour and 1 year");
    }
    if o.max_uses.is_some_and(|n| !(1..=10_000).contains(&n)) {
        bail!("invite use limit must be between 1 and 10000");
    }
    let label = o.label.trim();
    if label.chars().count() > 64 {
        bail!("invite label must be at most 64 characters");
    }
    let mut secret = vec![0u8; 32];
    aws_lc_rs::rand::fill(&mut secret).map_err(|_| anyhow::anyhow!("rng failure"))?;
    let expires = o.ttl_hours.map(|h| {
        (chrono::Utc::now() + chrono::Duration::hours(h as i64))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    });
    sqlx::query(
        "INSERT INTO invites (secret_hash, label, created_at, expires_at, max_uses)
         VALUES (?, ?, datetime('now'), ?, ?)",
    )
    .bind(hash(&secret))
    .bind(label)
    .bind(expires)
    .bind(o.max_uses.map(i64::from))
    .execute(&node.store.pool)
    .await?;
    let token = Token {
        v: 1,
        addrs: vec![addr],
        id: node.id(),
        secret,
    };
    Ok(format!(
        "{PREFIX}{}",
        data_encoding::BASE64URL_NOPAD.encode(&super::rpc::cbor::encode(&token)?)
    ))
}
```

In `redeem`, replace the `let used = … if used != 1 { … }` block:

```rust
    // One statement, so concurrent joins cannot exceed the use limit.
    let invite: Option<i64> = sqlx::query_scalar(
        "UPDATE invites SET uses = uses + 1
         WHERE secret_hash = ? AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > datetime('now'))
           AND (max_uses IS NULL OR uses < max_uses)
         RETURNING id",
    )
    .bind(hash(&req.secret))
    .fetch_optional(&node.store.pool)
    .await
    .map_err(|e| internal(e.into()))?;
    let Some(invite) = invite else {
        return Err((403, "invalid, revoked, exhausted or expired invite".into()));
    };
    sqlx::query("INSERT INTO invite_uses (invite_id, node, used_at) VALUES (?, ?, datetime('now'))")
        .bind(invite)
        .bind(&peer.0[..])
        .execute(&node.store.pool)
        .await
        .map_err(|e| internal(e.into()))?;
```

Add at the end of the file (before any tests):

```rust
/// An invite as the UI and CLI list it.
#[derive(Debug, Clone)]
pub struct InviteRow {
    pub id: i64,
    pub label: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked: bool,
    /// Still redeemable right now.
    pub usable: bool,
    /// Nodes that joined with it.
    pub joined: Vec<NodeId>,
}

/// All invites created on this node, newest first.
pub async fn list(store: &crate::store::Store) -> Result<Vec<InviteRow>> {
    type Row = (
        i64,
        String,
        String,
        Option<String>,
        Option<i64>,
        i64,
        bool,
        bool,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, label, created_at, expires_at, max_uses, uses, revoked_at IS NOT NULL,
                revoked_at IS NULL AND (expires_at IS NULL OR expires_at > datetime('now'))
                  AND (max_uses IS NULL OR uses < max_uses)
         FROM invites ORDER BY id DESC",
    )
    .fetch_all(&store.pool)
    .await?;
    let mut out = vec![];
    for r in rows {
        let nodes: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT DISTINCT node FROM invite_uses WHERE invite_id = ? ORDER BY used_at",
        )
        .bind(r.0)
        .fetch_all(&store.pool)
        .await?;
        out.push(InviteRow {
            id: r.0,
            label: r.1,
            created_at: r.2,
            expires_at: r.3,
            max_uses: r.4,
            uses: r.5,
            revoked: r.6,
            usable: r.7,
            joined: nodes
                .iter()
                .filter_map(|n| NodeId::from_slice(n).ok())
                .collect(),
        });
    }
    Ok(out)
}

/// Stop an invite from admitting anyone else. Members that already joined
/// with it stay. Returns false if it was unknown or already revoked.
pub async fn revoke(store: &crate::store::Store, id: i64) -> Result<bool> {
    let n = sqlx::query(
        "UPDATE invites SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&store.pool)
    .await?
    .rows_affected();
    Ok(n == 1)
}
```

- [ ] **Step 5: CLI.** In `src/cluster/cli.rs`, `USAGE` gets these lines in place of the old `invite` line:

```rust
       peephole cluster invite [--label TEXT] [--ttl HOURS] [--uses N] [CONFIG]
       peephole cluster invites [CONFIG]
       peephole cluster invite-revoke ID [CONFIG]
```

Replace the `invite` arm and add two arms:

```rust
        Some("invite") => {
            reject_unknown_flags(&flags, &["label", "ttl", "uses"])?;
            let flag = |name: &str| flags.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
            let opts = invite::InviteOpts {
                label: flag("label").unwrap_or_default().to_string(),
                ttl_hours: flag("ttl")
                    .map(|v| v.parse().context("--ttl: hours"))
                    .transpose()?,
                max_uses: flag("uses")
                    .map(|v| v.parse().context("--uses: a number"))
                    .transpose()?,
            };
            let (_, node) = open(cfg_at(1)).await?;
            let token = invite::create(&node, &opts).await?;
            println!("{token}");
            eprintln!(
                "reusable invite. Whoever holds it can join, and a member cannot be removed \
                 afterwards, only blocked node by node. Limit it with --uses or --ttl; \
                 revoke it with: peephole cluster invite-revoke <id> (see: peephole cluster invites)"
            );
        }
        Some("invites") => {
            reject_unknown_flags(&flags, &[])?;
            let cfg = Config::load(Path::new(cfg_at(1)))?;
            let store = Store::connect(&cfg.database_path).await?;
            for i in invite::list(&store).await? {
                println!(
                    "{:<4} {:<8} uses {}{}  expires {}  created {}  {}",
                    i.id,
                    if i.usable { "usable" } else if i.revoked { "revoked" } else { "closed" },
                    i.uses,
                    i.max_uses.map(|m| format!("/{m}")).unwrap_or_default(),
                    i.expires_at.as_deref().unwrap_or("never"),
                    i.created_at,
                    i.label
                );
                for n in i.joined {
                    println!("       joined: {}", n.short());
                }
            }
        }
        Some("invite-revoke") => {
            reject_unknown_flags(&flags, &[])?;
            let id: i64 = pos.get(1).context(USAGE)?.parse().context("invite id")?;
            let cfg = Config::load(Path::new(cfg_at(2)))?;
            let store = Store::connect(&cfg.database_path).await?;
            if invite::revoke(&store, id).await? {
                println!("invite {id} revoked; members that joined with it stay");
            } else {
                bail!("no usable invite {id}");
            }
        }
```

In `src/main.rs` extend the help text to `(id|invite|invites|invite-revoke|join|members|status|leave)`.

- [ ] **Step 6: Admin page.** In `src/admin/cluster.rs`:

```rust
pub struct InviteView {
    pub id: i64,
    pub label: String,
    pub created_at: String,
    pub expires: String,
    pub uses: String,
    pub state: &'static str,
    pub usable: bool,
    pub joined: String,
}

async fn invites(node: &Node) -> AppResult<Vec<InviteView>> {
    let names: std::collections::HashMap<NodeId, String> = members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| (m.id, m.name))
        .collect();
    Ok(invite::list(&node.store)
        .await?
        .into_iter()
        .map(|i| InviteView {
            id: i.id,
            label: i.label,
            created_at: i.created_at,
            expires: i.expires_at.unwrap_or_else(|| "never".into()),
            uses: match i.max_uses {
                Some(m) => format!("{} of {m}", i.uses),
                None => i.uses.to_string(),
            },
            state: if i.usable {
                "usable"
            } else if i.revoked {
                "revoked"
            } else {
                "closed"
            },
            usable: i.usable,
            joined: i
                .joined
                .iter()
                .map(|n| names.get(n).cloned().unwrap_or_else(|| n.short()))
                .collect::<Vec<_>>()
                .join(", "),
        })
        .collect())
}
```

In `ClusterPage` replace `invite_ttl: u64` with `invites: Vec<InviteView>` (`vec![]` on the standalone page, `invites(node).await?` otherwise). Replace `InviteForm` and `create_invite`, and add the revoke handler and its route `.route("/admin/cluster/invite/revoke", post(revoke_invite))`:

```rust
#[derive(serde::Deserialize)]
struct InviteForm {
    label: Option<String>,
    ttl_hours: Option<String>,
    max_uses: Option<String>,
}

/// Create an invite and show it once (never stored in clear).
async fn create_invite(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<InviteForm>,
) -> AppResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let node = node(&st)?;
    // Empty fields mean "no limit"; anything else must be a number.
    let number = |v: &Option<String>| match v.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => s.parse::<u64>().map(Some).map_err(|_| ()),
    };
    let (Ok(ttl), Ok(uses)) = (number(&f.ttl_hours), number(&f.max_uses)) else {
        return Ok(back(None, Some("expiry and use limit must be numbers".into())).into_response());
    };
    let opts = invite::InviteOpts {
        label: f.label.unwrap_or_default(),
        ttl_hours: ttl,
        max_uses: uses.map(|n| n.min(u32::MAX as u64) as u32),
    };
    match invite::create(node, &opts).await {
        Ok(token) => Ok(render_page(&st, Some(token), Flash::default())
            .await?
            .into_response()),
        Err(e) => Ok(back(None, Some(format!("{e:#}"))).into_response()),
    }
}

#[derive(serde::Deserialize)]
struct InviteRevokeForm {
    id: i64,
}

async fn revoke_invite(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<InviteRevokeForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    Ok(if invite::revoke(&node.store, f.id).await? {
        back(
            Some("Invite revoked. Members that joined with it stay.".into()),
            None,
        )
    } else {
        back(None, Some("No usable invite with that id.".into()))
    })
}
```

In `templates/admin_cluster.html`:

- Replace the text of the shown-once invite card with: `Shown once. On a new node run <code>peephole cluster join &lt;token&gt;</code> or paste it on that node's Cluster page. It can be used again until it expires, reaches its use limit or is revoked.`
- Replace the invite `<form>` in the Members card head with nothing (delete it), and add this card after the Members card:

```html
<section class="card">
  <div class="card-head"><h2>Invites</h2><span class="muted">created on this node</span></div>
  <div class="banner banner-warning">Whoever holds a usable invite can join, and nobody can remove a member afterwards: other nodes can only block it for themselves. Set a use limit or an expiry when you hand an invite to more than one person.</div>
  <form method="post" action="/admin/cluster/invite" class="filters">
    <label>For <input name="label" maxlength="64" placeholder="peer group"></label>
    <label>Expires after <input type="number" name="ttl_hours" min="1" max="8760" placeholder="never" size="6"> h</label>
    <label>Use limit <input type="number" name="max_uses" min="1" max="10000" placeholder="none" size="6"></label>
    <button class="btn btn-primary" type="submit">Create invite</button></form>
  {% if !invites.is_empty() %}
  <div class="table-wrap"><table>
    <thead><tr><th>For</th><th>State</th><th>Uses</th><th>Expires (UTC)</th><th>Created (UTC)</th><th>Joined</th><th></th></tr></thead>
    <tbody>{% for i in invites %}<tr{% if !i.usable %} class="muted"{% endif %}>
      <td>{{ i.label }}</td>
      <td><span class="badge badge-status" data-status="{% if i.usable %}done{% else %}failed{% endif %}">{{ i.state }}</span></td>
      <td>{{ i.uses }}</td><td class="ts">{{ i.expires }}</td><td class="ts">{{ i.created_at }}</td><td>{{ i.joined }}</td>
      <td>{% if i.usable %}<form method="post" action="/admin/cluster/invite/revoke"><input type="hidden" name="id" value="{{ i.id }}"><button class="btn btn-sm btn-danger" type="submit">Revoke invite</button></form>{% endif %}</td>
    </tr>{% endfor %}</tbody>
  </table></div>{% endif %}
</section>
```

- [ ] **Step 7: Run the tests**

Run: `cargo test`
Expected: PASS. `tests/cli.rs` (`invite --ttl 2`) and the invite post in `tests/integration.rs` and `tests/cluster.rs` (`ttl_hours=2`) keep working unchanged.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster): reusable invites with label, expiry, use limit and revocation"
```

---

### Task 5: Deletes are scoped to the origin

**Files:**
- Create: `src/store/migrations/0011_scoped_tombstones.sql`
- Modify: `src/store/mod.rs`, `src/cluster/record.rs`, `src/store/data.rs`, `src/store/recorder.rs`, `src/store/delete.rs`, `src/admin/pages.rs`
- Test: `src/store/data.rs` (unit), `tests/cluster.rs`

**Interfaces:**
- Produces:
  - `pub struct record::TombstoneRec { pub uid: String, pub uids: Vec<String> }`; `record::TombTarget` is removed.
  - `pub(crate) async fn data::unmaterialize(conn: &mut SqliteConnection, kind: &str, uid: &str) -> Result<Option<i64>>` (returns the row's `ip_id` if a row was removed)
  - `pub(crate) async fn data::drop_orphan_ip(conn: &mut SqliteConnection, ip_id: i64) -> Result<()>`
  - `pub struct recorder::Deleted { pub deleted: u64, pub hidden: u64 }` (counts of the records asked for; `hidden` stays 0 until Task 7)
  - `Recorder::delete_request(id) -> Result<Deleted>`, `delete_requests(ids) -> Result<Deleted>`, `delete_scan(id) -> Result<Deleted>`, `delete_claim(id) -> Result<Deleted>`, `delete_ips(ids) -> Result<Deleted>`, `delete_ip(id) -> Result<bool>` (whether the IP existed)
  - The `Store::delete_*` wrappers in `src/store/delete.rs` keep their current signatures.

- [ ] **Step 1: Write the failing unit tests** in the `tests` module of `src/store/data.rs`:

```rust
    use crate::cluster::identity::Identity;
    use crate::cluster::record::{RequestRec, ScanJobRec, TombstoneRec};

    fn request(uid: &str, path: &str) -> Record {
        Record::Request(RequestRec {
            uid: uid.into(),
            ts: now_ts(),
            ip: "203.0.113.7".into(),
            method: "GET".into(),
            path: path.into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 1,
            scan_level: 1,
            is_fp_claim: false,
            page_token: None,
        })
    }

    /// A log row as the replication layer would hold it for an applied,
    /// row-backed record (payload dropped).
    async fn log_row(conn: &mut SqliteConnection, origin: &NodeId, seq: i64, kind: &str, uid: &str) {
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, applied, received_at)
             VALUES (?, ?, ?, ?, ?, NULL, x'00', 1, datetime('now'))",
        )
        .bind(&origin.0[..])
        .bind(seq)
        .bind(seq)
        .bind(kind)
        .bind(uid)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    async fn count(conn: &mut SqliteConnection, sql: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(&mut *conn)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_tombstone_only_deletes_its_own_origins_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        for (origin, uid, seq) in [(&a, "req-a", 1), (&b, "req-b", 1)] {
            let ctx = Ctx {
                origin: Some(origin),
                hlc: 10,
            };
            assert_eq!(
                apply(&mut conn, ctx, &request(uid, "/x")).await.unwrap(),
                Effect::Applied
            );
            log_row(&mut conn, origin, seq, "request", uid).await;
        }
        // B lists both; only its own goes.
        let t = Record::Tombstone(TombstoneRec {
            uid: "tomb-1".into(),
            uids: vec!["req-a".into(), "req-b".into()],
        });
        let ctx = Ctx {
            origin: Some(&b),
            hlc: 20,
        };
        apply(&mut conn, ctx, &t).await.unwrap();
        let left: Vec<String> = sqlx::query_scalar("SELECT uid FROM requests")
            .fetch_all(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, ["req-a"]);
        assert_eq!(
            count(&mut conn, "SELECT COUNT(*) FROM tombstoned WHERE uid = 'req-a'").await,
            0
        );
        assert_eq!(
            count(
                &mut conn,
                "SELECT COUNT(*) FROM repl_log WHERE uid = 'req-a' AND erased_by IS NOT NULL"
            )
            .await,
            0
        );
        assert_eq!(
            count(
                &mut conn,
                "SELECT COUNT(*) FROM repl_log WHERE uid = 'req-b' AND erased_by = 'tomb-1'"
            )
            .await,
            1
        );
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ips").await, 1, "a's request keeps the ip");
    }

    /// A tombstone that names a parent but not its children must not trip a
    /// foreign key and stall the origin's stream.
    #[tokio::test]
    async fn children_left_out_of_a_tombstone_leave_the_tables() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let ctx = |hlc| Ctx { origin: None, hlc };
        apply(&mut conn, ctx(1), &request("req", "/x")).await.unwrap();
        apply(
            &mut conn,
            ctx(2),
            &Record::FpClaim(crate::cluster::record::FpClaimRec {
                uid: "claim".into(),
                request_uid: "req".into(),
                ip: "203.0.113.7".into(),
                ts: now_ts(),
                contact_email: None,
                user_agent: None,
            }),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx(3),
            &Record::ScanJob(ScanJobRec {
                uid: "job".into(),
                ip: "203.0.113.7".into(),
                level: 2,
                queued_at: now_ts(),
            }),
        )
        .await
        .unwrap();
        apply(
            &mut conn,
            ctx(4),
            &Record::ScanResult(ScanResultRec {
                uid: "scan".into(),
                job_uid: "job".into(),
                ip: "203.0.113.7".into(),
                level: 2,
                started_at: now_ts(),
                finished_at: Some(now_ts()),
                os_guess: None,
                raw_xml: None,
                ports: vec![],
            }),
        )
        .await
        .unwrap();
        let t = Record::Tombstone(TombstoneRec {
            uid: "tomb".into(),
            uids: vec!["req".into(), "job".into()],
        });
        assert_eq!(apply(&mut conn, ctx(5), &t).await.unwrap(), Effect::Applied);
        for table in ["requests", "fp_claims", "scan_jobs", "scans", "ips"] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            assert_eq!(count(&mut conn, &sql).await, 0, "{table}");
        }
    }
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib a_tombstone_only_deletes children_left_out`
Expected: compile error, `TombstoneRec` has no field `uids`.

- [ ] **Step 3: The record.** In `src/cluster/record.rs` delete `TombTarget` and replace `TombstoneRec`:

```rust
/// A delete by the node that created the listed records. Wherever it is
/// applied, it only affects entries of the tombstone's own origin; uids of
/// other nodes' records in the list are ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TombstoneRec {
    pub uid: String,
    pub uids: Vec<String>,
}
```

- [ ] **Step 4: Schema.** Create `src/store/migrations/0011_scoped_tombstones.sql` and append it to `MIGRATIONS`:

```sql
-- Tombstones list the uids they delete; per-IP cut-offs are gone.
DROP TABLE IF EXISTS ip_tombstones
```

- [ ] **Step 5: Apply side.** In `src/store/data.rs`:

Update the imports (`TombTarget` goes, add `ROW_BACKED`):

```rust
use crate::cluster::record::{
    FingerprintRec, FpClaimRec, IntelManifestRec, IpEnrichRec, JobAdoptRec, JobStatusRec, PortRec,
    ROW_BACKED, Record, RequestRec, ScanJobRec, ScanResultRec, TombstoneRec,
};
```

Replace `erased_by` (uids only):

```rust
/// The tombstone that already deleted this record, if any.
async fn erased_by(conn: &mut SqliteConnection, uid: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT tombstone_uid FROM tombstoned WHERE uid = ?")
            .bind(uid)
            .fetch_optional(&mut *conn)
            .await?,
    )
}
```

and its callers:

- `request`, `scan_job`, `scan_result`: `if let Some(t) = erased_by(conn, &r.uid).await? { return Ok(Effect::Erased(t)); }`
- `ip_enrich`: delete the `erased_by` check at its top.
- `fp_claim`: `erased_by(conn, &r.uid)`; a claim whose request is gone is already `Ignored` by the `request_id` lookup below it and stays in the log.
- `fingerprint`: `erased_by(conn, &r.uid)`; a fingerprint whose request is gone is stored without a request, as before.

Delete `tombstone_ip` and `uids_for_ip`. Replace `tombstone` and add the helpers:

```rust
/// Delete the listed records, as far as the tombstone's origin created
/// them. Records of other nodes that hang off a deleted one (a claim on a
/// deleted request, a scan of a deleted job) are not this origin's to erase:
/// they leave the tables, because their parent is gone, and stay in the log.
async fn tombstone(conn: &mut SqliteConnection, ctx: Ctx<'_>, t: &TombstoneRec) -> Result<Effect> {
    // In a cluster the log says who created what; a standalone node created
    // everything it holds.
    let own: Vec<String> = match ctx.origin {
        Some(o) => {
            let mut v = vec![];
            for chunk in t.uids.chunks(400) {
                let sql = format!(
                    "SELECT uid FROM repl_log WHERE origin = ? AND kind != 'tombstone' AND uid IN ({})",
                    placeholders(chunk.len())
                );
                let mut q =
                    sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql)).bind(&o.0[..]);
                for uid in chunk {
                    q = q.bind(uid);
                }
                v.extend(q.fetch_all(&mut *conn).await?);
            }
            v
        }
        None => t.uids.clone(),
    };
    if own.is_empty() {
        return Ok(Effect::Applied);
    }
    let mine: std::collections::HashSet<&str> = own.iter().map(String::as_str).collect();
    let mut ips = std::collections::BTreeSet::new();
    for table in ["requests", "fp_claims", "fingerprints", "scan_jobs", "scans"] {
        let sql = format!("SELECT DISTINCT ip_id FROM {table} WHERE uid IN ({{}})");
        for chunk in own.chunks(400) {
            let sql = sql.replace("{}", &placeholders(chunk.len()));
            let mut q = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql));
            for uid in chunk {
                q = q.bind(uid);
            }
            ips.extend(q.fetch_all(&mut *conn).await?);
        }
    }
    // Dependents that are not part of this delete.
    let claims = uids_where(
        conn,
        "SELECT uid FROM fp_claims WHERE request_uid IN ({})",
        &own,
    )
    .await?;
    for uid in claims.iter().filter(|u| !mine.contains(u.as_str())) {
        unmaterialize(conn, "fp_claim", uid).await?;
    }
    let scans = uids_where(conn, "SELECT uid FROM scans WHERE job_uid IN ({})", &own).await?;
    for uid in scans.iter().filter(|u| !mine.contains(u.as_str())) {
        unmaterialize(conn, "scan_result", uid).await?;
    }
    for_uids(
        conn,
        "UPDATE fingerprints SET request_id = NULL WHERE request_uid IN ({})",
        &own,
    )
    .await?;
    bury(conn, &own, &t.uid).await?;
    // Children before parents.
    for_uids(
        conn,
        "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid IN ({}))",
        &own,
    )
    .await?;
    for table in ["scans", "fp_claims", "fingerprints", "scan_jobs", "requests"] {
        let sql = format!("DELETE FROM {table} WHERE uid IN ({{}})");
        for_uids(conn, &sql, &own).await?;
    }
    for ip_id in ips {
        drop_orphan_ip(conn, ip_id).await?;
    }
    Ok(Effect::Applied)
}

/// Remove an IP row once nothing refers to it any more.
pub(crate) async fn drop_orphan_ip(conn: &mut SqliteConnection, ip_id: i64) -> Result<()> {
    sqlx::query(
        "DELETE FROM ips WHERE id = ?1
           AND NOT EXISTS (SELECT 1 FROM requests WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM scan_jobs WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM scans WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM fingerprints WHERE ip_id = ?1)
           AND NOT EXISTS (SELECT 1 FROM fp_claims WHERE ip_id = ?1)",
    )
    .bind(ip_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Put a row-backed record's payload back into its log entry, so the entry
/// can be relayed without the row.
async fn keep_payload(conn: &mut SqliteConnection, kind: &str, uid: &str) -> Result<()> {
    if !ROW_BACKED.contains(&kind) {
        return Ok(());
    }
    if let Some(rec) = rebuild(conn, kind, uid).await? {
        sqlx::query(
            "UPDATE repl_log SET payload = ?
             WHERE uid = ? AND kind = ? AND payload IS NULL AND erased_by IS NULL",
        )
        .bind(crate::cluster::rpc::cbor::encode(&rec)?)
        .bind(uid)
        .bind(kind)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Take a record out of the tables but keep it in the log with its payload,
/// so this node still relays it. Children that cannot exist without it leave
/// the tables the same way. Returns the row's IP id if there was a row.
pub(crate) async fn unmaterialize(
    conn: &mut SqliteConnection,
    kind: &str,
    uid: &str,
) -> Result<Option<i64>> {
    let table = match kind {
        "request" => "requests",
        "fp_claim" => "fp_claims",
        "fingerprint" => "fingerprints",
        "scan_job" => "scan_jobs",
        "scan_result" => "scans",
        _ => return Ok(None),
    };
    let sql = format!("SELECT ip_id FROM {table} WHERE uid = ?");
    let ip_id: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await?;
    if ip_id.is_none() {
        return Ok(None);
    }
    keep_payload(conn, kind, uid).await?;
    match kind {
        "request" => {
            sqlx::query("DELETE FROM fp_claims WHERE request_uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
            sqlx::query("UPDATE fingerprints SET request_id = NULL WHERE request_uid = ?")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        "scan_job" => {
            let scans: Vec<String> = sqlx::query_scalar("SELECT uid FROM scans WHERE job_uid = ?")
                .bind(uid)
                .fetch_all(&mut *conn)
                .await?;
            for s in scans {
                keep_payload(conn, "scan_result", &s).await?;
                sqlx::query(
                    "DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid = ?)",
                )
                .bind(&s)
                .execute(&mut *conn)
                .await?;
                sqlx::query("DELETE FROM scans WHERE uid = ?")
                    .bind(&s)
                    .execute(&mut *conn)
                    .await?;
            }
        }
        "scan_result" => {
            sqlx::query("DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE uid = ?)")
                .bind(uid)
                .execute(&mut *conn)
                .await?;
        }
        _ => {}
    }
    let sql = format!("DELETE FROM {table} WHERE uid = ?");
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(uid)
        .execute(&mut *conn)
        .await?;
    Ok(ip_id)
}
```

Update the module doc comment's second paragraph: "Deletes are tombstones: they list the uids to remove, affect only records of the tombstone's own origin, and remember the deleted uids so a record that arrives later is dropped instead of resurrecting."

- [ ] **Step 6: Write side.** In `src/store/recorder.rs` replace the import `TombTarget, TombstoneRec` by `TombstoneRec`, and replace everything from `fn tomb(` through the end of `prune_older_than` with:

```rust
    /// Uids of `table` rows whose `col` is one of `keys`, split into what
    /// this node originated and what other nodes did. Only the former can be
    /// deleted cluster-wide.
    async fn split(
        &self,
        table: &'static str,
        col: &'static str,
        keys: Keys<'_>,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let me = self.node_id().map(|id| id.0.to_vec());
        let n = match keys {
            Keys::Ids(k) => k.len(),
            Keys::Uids(k) => k.len(),
        };
        let (mut own, mut other) = (vec![], vec![]);
        for start in (0..n).step_by(400) {
            let end = (start + 400).min(n);
            let sql = format!(
                "SELECT uid, origin FROM {table} WHERE uid IS NOT NULL AND {col} IN ({})",
                vec!["?"; end - start].join(",")
            );
            let mut q = sqlx::query_as::<_, (String, Option<Vec<u8>>)>(sqlx::AssertSqlSafe(sql));
            match keys {
                Keys::Ids(k) => {
                    for v in &k[start..end] {
                        q = q.bind(*v);
                    }
                }
                Keys::Uids(k) => {
                    for v in &k[start..end] {
                        q = q.bind(v.as_str());
                    }
                }
            }
            for (uid, origin) in q.fetch_all(&self.store().pool).await? {
                if origin == me {
                    own.push(uid);
                } else {
                    other.push(uid);
                }
            }
        }
        Ok((own, other))
    }

    /// Delete records this node originated, everywhere.
    async fn bury(&self, uids: Vec<String>) -> Result<()> {
        let records: Vec<_> = uids
            .chunks(TOMB_CHUNK)
            .map(|c| {
                Record::Tombstone(TombstoneRec {
                    uid: new_uid(),
                    uids: c.to_vec(),
                })
            })
            .collect();
        if !records.is_empty() {
            self.write(records).await?;
        }
        Ok(())
    }

    /// Records other nodes originated cannot be deleted from here.
    async fn hide(&self, _uids: Vec<String>) -> Result<u64> {
        Ok(0)
    }

    pub async fn delete_request(&self, id: i64) -> Result<Deleted> {
        self.delete_requests(&[id]).await
    }

    /// Delete requests. Ours go cluster-wide, together with our claims and
    /// fingerprints on them.
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<Deleted> {
        let (reqs, foreign) = self.split("requests", "id", Keys::Ids(ids)).await?;
        let (claims, _) = self
            .split("fp_claims", "request_uid", Keys::Uids(&reqs))
            .await?;
        let (fps, _) = self
            .split("fingerprints", "request_uid", Keys::Uids(&reqs))
            .await?;
        let deleted = reqs.len() as u64;
        self.bury([reqs, claims, fps].concat()).await?;
        Ok(Deleted {
            deleted,
            hidden: self.hide(foreign).await?,
        })
    }

    /// Whether the IP existed. Everything this node recorded about it is
    /// deleted cluster-wide.
    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        let existed = self.ip_of(ip_id).await.is_ok();
        self.delete_ips(&[ip_id]).await?;
        Ok(existed)
    }

    /// Delete everything about these IPs, as far as this node recorded it.
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<Deleted> {
        let (mut own, mut foreign) = (vec![], vec![]);
        for table in ["requests", "fp_claims", "fingerprints", "scan_jobs", "scans"] {
            let (o, f) = self.split(table, "ip_id", Keys::Ids(ids)).await?;
            own.extend(o);
            foreign.extend(f);
        }
        let deleted = own.len() as u64;
        self.bury(own).await?;
        let hidden = self.hide(foreign).await?;
        // An IP without any record left (or that never had one) goes too.
        let mut conn = self.store().pool.acquire().await?;
        for id in ids {
            data::drop_orphan_ip(&mut conn, *id).await?;
        }
        Ok(Deleted { deleted, hidden })
    }

    pub async fn delete_scan(&self, id: i64) -> Result<Deleted> {
        let (own, foreign) = self.split("scans", "id", Keys::Ids(&[id])).await?;
        let deleted = own.len() as u64;
        self.bury(own).await?;
        Ok(Deleted {
            deleted,
            hidden: self.hide(foreign).await?,
        })
    }

    pub async fn delete_claim(&self, id: i64) -> Result<Deleted> {
        let (own, foreign) = self.split("fp_claims", "id", Keys::Ids(&[id])).await?;
        let deleted = own.len() as u64;
        self.bury(own).await?;
        Ok(Deleted {
            deleted,
            hidden: self.hide(foreign).await?,
        })
    }

    /// Retention (standalone nodes): delete requests, with their claims and
    /// fingerprints, and scan results older than `days`. Bounded per call so
    /// a huge backlog drains over several runs. Returns (requests, scans).
    pub async fn prune_older_than(&self, days: u32) -> Result<(u64, u64)> {
        if days == 0 {
            return Ok((0, 0));
        }
        const BATCH: i64 = 20_000;
        let pool = &self.store().pool;
        let cutoff = format!("-{days} days");
        let req_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT id FROM requests WHERE ts < datetime('now', ?) ORDER BY id LIMIT ?",
        )
        .bind(&cutoff)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let reqs = self.delete_requests(&req_ids).await?.deleted;
        let scan_uids: Vec<String> = sqlx::query_scalar(
            "SELECT uid FROM scans
             WHERE COALESCE(finished_at, started_at) < datetime('now', ?)
             ORDER BY id LIMIT ?",
        )
        .bind(&cutoff)
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        let scans = scan_uids.len() as u64;
        self.bury(scan_uids).await?;
        Ok((reqs, scans))
    }
}

/// Row keys for [`Recorder::split`].
#[derive(Clone, Copy)]
enum Keys<'a> {
    Ids(&'a [i64]),
    Uids(&'a [String]),
}

/// What a delete did, counted in the records that were asked for.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Deleted {
    /// Records this node originated: deleted on every node.
    pub deleted: u64,
    /// Records other nodes originated: hidden on this node only.
    pub hidden: u64,
}
```

(The closing `}` after `prune_older_than` ends `impl Recorder`; make sure the file does not end up with a second one.)

In `src/store/delete.rs` keep the wrappers' signatures:

```rust
impl Store {
    pub async fn delete_request(&self, id: i64) -> Result<bool> {
        Ok(self.local().delete_request(id).await?.deleted > 0)
    }

    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        self.local().delete_ip(ip_id).await
    }

    pub async fn delete_scan(&self, scan_id: i64) -> Result<bool> {
        Ok(self.local().delete_scan(scan_id).await?.deleted > 0)
    }

    pub async fn delete_claim(&self, id: i64) -> Result<bool> {
        Ok(self.local().delete_claim(id).await?.deleted > 0)
    }

    /// Delete many requests (and their claims/fingerprints).
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<u64> {
        Ok(self.local().delete_requests(ids).await?.deleted)
    }

    /// Delete many IPs with everything hanging off them; returns how many
    /// of them existed.
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<u64> {
        let mut n = 0;
        for id in ids {
            n += self.local().delete_ip(*id).await? as u64;
        }
        Ok(n)
    }
}
```

- [ ] **Step 7: Admin handlers** in `src/admin/pages.rs`. Single deletes report "not found" when nothing happened; bulk loops must stop when a round changes nothing (records of other nodes still match the filter until Task 7 hides them):

```rust
    let out = st.recorder.delete_request(id).await?;
    if out.deleted + out.hidden == 0 {
        return Err(AppError::NotFound);
    }
```

(the same shape in `scan_delete` with `delete_scan` and in `claim_delete` with `delete_claim`; `ip_delete` stays as it is.)

In `bulk_delete_requests`:

```rust
    let n = if form.all {
        // Rounds of MATCH_LIMIT until nothing matches, so "all" means all.
        let mut total = 0u64;
        loop {
            let ids = st.store.matching_request_ids(&form.filter).await?;
            if ids.is_empty() {
                break;
            }
            let out = st.recorder.delete_requests(&ids).await?;
            total += out.deleted + out.hidden;
            if out.deleted + out.hidden == 0
                || (ids.len() as i64) < crate::store::browse::MATCH_LIMIT
            {
                break;
            }
        }
        total
    } else {
        let ids: Vec<i64> = form.ids.iter().filter_map(|v| v.parse().ok()).collect();
        let out = st.recorder.delete_requests(&ids).await?;
        out.deleted + out.hidden
    };
```

In `bulk_delete_ips` the same change with `matching_ip_ids` and `delete_ips` (both branches: `let out = st.recorder.delete_ips(&ids).await?;` then `out.deleted + out.hidden`).

- [ ] **Step 8: Run the unit tests**

Run: `cargo test --lib`
Expected: PASS, including the existing tests in `src/store/delete.rs`.

- [ ] **Step 9: Rewrite the cluster test.** In `tests/cluster.rs` replace `deletes_propagate_and_stay_deleted` with:

```rust
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

    // B cannot delete A's request for the cluster.
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    assert_eq!(rec(&nb).delete_request(one_on_b).await.unwrap().deleted, 0);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(count(&na, "SELECT COUNT(*) FROM requests").await, 3);

    // A deletes its own: gone everywhere, with its claim, and erased from
    // the log.
    let out = rec(&na).delete_request(r1).await.unwrap();
    assert_eq!(out.deleted, 1);
    eventually("b dropped /one", || async {
        count(&nb, "SELECT COUNT(*) FROM requests WHERE path = '/one'").await == 0
    })
    .await;
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM fp_claims").await, 0);
    assert_eq!(
        count(
            &nb,
            "SELECT COUNT(*) FROM repl_log WHERE erased_by IS NOT NULL"
        )
        .await,
        2,
        "request and claim payloads are erased from the log"
    );

    // Deleting the IP on A removes what A recorded; B's request stays.
    assert!(rec(&na).delete_ip(ip_a.id).await.unwrap());
    eventually("only b's request is left on b", || async {
        let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM requests")
            .fetch_all(&nb.store.pool)
            .await
            .unwrap();
        paths == ["/three"]
    })
    .await;
    eventually("and on a", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    assert_eq!(count(&na, "SELECT COUNT(*) FROM ips").await, 1);

    // B deletes the IP: now it is gone on both.
    assert!(rec(&nb).delete_ip(ip_b.id).await.unwrap());
    eventually("ip gone everywhere", || async {
        count(&na, "SELECT COUNT(*) FROM ips").await == 0
            && count(&nb, "SELECT COUNT(*) FROM ips").await == 0
    })
    .await;
}
```

- [ ] **Step 10: Run the tests**

Run: `cargo test`
Expected: PASS. Other tests that built `TombTarget` values fail to compile; rewrite them with `TombstoneRec { uid, uids }`.

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(store)!: tombstones list uids and only delete their origin's records"
```

---

### Task 6: Erased entries need the origin's tombstone as proof

Today a relay can send an erased stub (no payload, no signature) for any entry and the receiver accepts it. In a federation that lets one hostile member make other nodes drop somebody's records. From now on a stub is accepted only together with the signed tombstone, by the same origin, that lists its uid.

**Files:**
- Create: `src/store/migrations/0012_tomb_proofs.sql`
- Modify: `src/store/mod.rs`, `src/cluster/sync.rs`, `src/cluster/repl.rs`, `src/cluster/rpc/mod.rs`
- Test: `tests/cluster.rs`

**Interfaces:**
- Consumes: `TombstoneRec { uid, uids }` from Task 5.
- Produces:
  - `pub struct sync::Batch { pub entries: Vec<WireEntry>, pub proofs: Vec<WireEntry> }` with `impl From<Vec<WireEntry>> for Batch`
  - `pub async fn repl::entries_after(store, wants, max_entries, max_bytes) -> Result<Batch>`
  - `pub async fn repl::apply_batch(node: &Node, batch: impl Into<Batch>) -> Result<Applied>`
  - `/rpc/v1/pull` answers with `Batch`; `/rpc/v1/push` takes `Batch`. `sync::PushReq` is removed.

- [ ] **Step 1: Write the failing test** in `tests/cluster.rs`. Change the helper `log_of` and add `batch_of`:

```rust
async fn batch_of(n: &Node, origin: NodeId) -> peephole::cluster::sync::Batch {
    repl::entries_after(&n.store, &[(origin, 0)], 10_000, usize::MAX)
        .await
        .unwrap()
}

async fn log_of(n: &Node, origin: NodeId) -> Vec<WireEntry> {
    batch_of(n, origin).await.entries
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
```

```rust
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
    let (one, two) = (request_uid(&na, "/one").await, request_uid(&na, "/two").await);
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
        entries: before.entries.clone(),
        proofs: after.proofs.clone(),
    };
    strip(&mut forged, &two, Some(tomb.clone()));
    let st = repl::apply_batch(&x, forged).await.unwrap();
    assert!(st.rejected >= 1, "{st:?}");
    assert!(head_of(&x, a.id).await < a_head, "the stream stops at the forgery");
    assert_eq!(
        count(&x, "SELECT COUNT(*) FROM requests WHERE path = '/two'").await,
        0
    );
    // The honest stream still applies afterwards.
    let st = repl::apply_batch(&x, batch_of(&na, a.id).await).await.unwrap();
    assert_eq!(st.rejected, 0, "{st:?}");
    assert_eq!(head_of(&x, a.id).await, a_head);
    assert_eq!(paths(&x).await, ["/two"]);
    // X can pass the erasure on with its proof.
    assert_eq!(batch_of(&x, a.id).await.proofs.len(), 1);

    // No proof, a proof from another origin, a stub without a uid: rejected.
    let stub_only = Batch {
        entries: after.entries.clone(),
        proofs: vec![],
    };
    let other = Identity::generate().unwrap();
    let wrong_origin = Batch {
        entries: after.entries.clone(),
        proofs: vec![
            WireEntry::sign(
                &other,
                1,
                1,
                &Record::Tombstone(peephole::cluster::record::TombstoneRec {
                    uid: tomb.clone(),
                    uids: vec![one.clone()],
                }),
            )
            .unwrap(),
        ],
    };
    let mut no_uid = Batch {
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test cluster erased_stubs_need`
Expected: compile error, `sync::Batch` not found.

- [ ] **Step 3: Schema.** Create `src/store/migrations/0012_tomb_proofs.sql` and append it to `MIGRATIONS`:

```sql
-- Tombstones received as proof for an erased entry before the tombstone
-- itself arrived in its origin's stream; kept so the erasure can be relayed.
CREATE TABLE tomb_proofs (
  origin BLOB NOT NULL, tomb_uid TEXT NOT NULL, entry BLOB NOT NULL,
  PRIMARY KEY (origin, tomb_uid)
) WITHOUT ROWID
```

- [ ] **Step 4: The wire type.** In `src/cluster/sync.rs` remove `PushReq` and add:

```rust
/// Log entries, plus the signed tombstones that justify the erased ones
/// among them. A receiver accepts an erased entry only with such a proof.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Batch {
    pub entries: Vec<WireEntry>,
    pub proofs: Vec<WireEntry>,
}

impl From<Vec<WireEntry>> for Batch {
    fn from(entries: Vec<WireEntry>) -> Self {
        Self {
            entries,
            proofs: vec![],
        }
    }
}
```

In `reconcile`, the pull loop becomes:

```rust
        let batch: Batch = node
            .call(
                peer,
                addr,
                "/rpc/v1/pull",
                &PullReq {
                    wants,
                    max_entries: BATCH_ENTRIES,
                    max_bytes: BATCH_BYTES,
                },
            )
            .await?;
        if batch.entries.is_empty() {
            break;
        }
        let st = repl::apply_batch(node, batch).await?;
```

and the push loop:

```rust
        let batch = repl::entries_after(&node.store, &wants, BATCH_ENTRIES, BATCH_BYTES).await?;
        if batch.entries.is_empty() {
            break;
        }
        let after: Heads = node.call(peer, addr, "/rpc/v1/push", &batch).await?;
```

In `src/cluster/rpc/mod.rs` import `Batch` in place of `PushReq`; `pull` needs no change beyond the type it serialises; `push` takes the batch:

```rust
async fn push(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(batch): Cbor<Batch>,
) -> Response {
    if batch.entries.len() > 5 * BATCH_ENTRIES || batch.proofs.len() > 5 * BATCH_ENTRIES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "too many entries").into_response();
    }
    match repl::apply_batch(&node, batch).await {
```

- [ ] **Step 5: Serve proofs.** In `src/cluster/repl.rs` change `entries_after` to return `Result<Batch>` (`use super::sync::Batch;`). At its end, replace `Ok(out)`:

```rust
    // Erased entries travel with the tombstone that erased them.
    let mut proofs = vec![];
    let mut seen = std::collections::HashSet::new();
    for e in &out {
        if e.payload.is_some() {
            continue;
        }
        let Some(tomb) = &e.erased_by else { continue };
        if seen.insert((e.origin, tomb.clone()))
            && let Some(p) = held_proof(&mut conn, &e.origin, tomb).await?
        {
            proofs.push(p);
        }
    }
    Ok(Batch {
        entries: out,
        proofs,
    })
}

/// The tombstone `tomb_uid` of `origin` as we hold it: in the log, or
/// stored as a proof ahead of its arrival there.
async fn held_proof(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    tomb_uid: &str,
) -> Result<Option<WireEntry>> {
    let row: Option<LogRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE origin = ? AND kind = 'tombstone' AND uid = ? AND payload IS NOT NULL",
    )
    .bind(&origin.0[..])
    .bind(tomb_uid)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(r) = row {
        return Ok(Some(from_row(r)?));
    }
    let blob: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT entry FROM tomb_proofs WHERE origin = ? AND tomb_uid = ?")
            .bind(&origin.0[..])
            .bind(tomb_uid)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(match blob {
        Some(b) => Some(super::rpc::cbor::decode(&b)?),
        None => None,
    })
}

/// Whether `proof` is a tombstone signed by `origin` that lists `uid`.
fn proves(proof: &WireEntry, origin: &NodeId, tomb_uid: &str, uid: &str) -> bool {
    proof.origin == *origin
        && proof.kind == "tombstone"
        && proof.uid.as_deref() == Some(tomb_uid)
        && proof.verify()
        && matches!(proof.record(), Some(Record::Tombstone(t)) if t.uids.iter().any(|u| u == uid))
}

/// Check an erased stub against the batch's proofs and the tombstones we
/// hold. A proof that is new to us is stored so we can relay the erasure.
async fn erasure_proven(
    conn: &mut SqliteConnection,
    proofs: &[WireEntry],
    e: &WireEntry,
) -> Result<bool> {
    let (Some(uid), Some(tomb)) = (&e.uid, &e.erased_by) else {
        return Ok(false);
    };
    if let Some(held) = held_proof(conn, &e.origin, tomb).await? {
        return Ok(proves(&held, &e.origin, tomb, uid));
    }
    let Some(p) = proofs.iter().find(|p| proves(p, &e.origin, tomb, uid)) else {
        return Ok(false);
    };
    sqlx::query("INSERT OR IGNORE INTO tomb_proofs (origin, tomb_uid, entry) VALUES (?, ?, ?)")
        .bind(&e.origin.0[..])
        .bind(tomb)
        .bind(super::rpc::cbor::encode(p)?)
        .execute(&mut *conn)
        .await?;
    Ok(true)
}
```

(`let mut conn` at the top of `entries_after` is already mutable; `held_proof` is called after the loop that used it.)

- [ ] **Step 6: Demand proofs.** Still in `src/cluster/repl.rs`:

```rust
/// Apply entries received from a peer (any origin).
pub async fn apply_batch(node: &Node, batch: impl Into<Batch>) -> Result<Applied> {
    let Batch { entries, proofs } = batch.into();
    let mut st = Applied::default();
    if entries.is_empty() {
        return Ok(st);
    }
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    for e in entries {
        apply_one(node, &mut tx, e, &proofs, &mut st).await?;
    }
```

(the rest of `apply_batch` is unchanged). `apply_one` gains the parameter `proofs: &[WireEntry]` and passes it on: `return apply_stub(node, conn, e, held > have, proofs, st).await;`. Replace `apply_stub` and its doc comment:

```rust
/// An entry its origin deleted (payload erased, `erased_by` naming the
/// tombstone). The tombstone sits *later* in the same origin's in-order
/// stream, so the stub cannot wait for it; instead it must come with that
/// tombstone as proof: signed by the stub's origin and listing its uid. A
/// stub without one is rejected, so a relay cannot make this node drop
/// records their origin never deleted.
async fn apply_stub(
    node: &Node,
    conn: &mut SqliteConnection,
    e: WireEntry,
    blocked: bool,
    proofs: &[WireEntry],
    st: &mut Applied,
) -> Result<()> {
    if !erasure_proven(conn, proofs, &e).await? {
        warn!(origin = %e.origin.short(), seq = e.seq, "erased entry without a valid tombstone dropped");
        st.rejected += 1;
        return Ok(());
    }
    if blocked || !trusted(node, conn, &e.origin).await? {
        park(conn, &e).await?;
        st.parked += 1;
        return Ok(());
    }
    apply_stub_now(node, conn, &e, st).await
}
```

- [ ] **Step 7: Run the tests**

Run: `cargo test`
Expected: PASS. Call sites that passed a `Vec<WireEntry>` to `apply_batch` keep compiling through `From`; call sites that used the result of `entries_after` as a vector need `.entries`.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster)!: erased entries are only accepted with their origin's tombstone"
```

---

### Task 7: Local hide and local block

**Files:**
- Create: `src/store/migrations/0013_hide_block.sql`, `src/cluster/block.rs`
- Modify: `src/store/mod.rs`, `src/store/data.rs`, `src/store/recorder.rs`, `src/cluster/mod.rs`, `src/cluster/repl.rs`, `src/cluster/msg.rs`, `src/cluster/rpc/mod.rs`, `src/cluster/cli.rs`, `src/main.rs`, `src/scan/mod.rs`, `src/admin/cluster.rs`, `src/admin/pages.rs`, `templates/admin_cluster.html`, `assets/js/app.js`
- Test: `tests/cluster.rs`

**Interfaces:**
- Consumes: `data::unmaterialize`, `data::drop_orphan_ip`, `Deleted`, `Recorder::hide` stub from Task 5; `Batch` from Task 6.
- Produces:
  - `pub async fn data::hide(conn: &mut SqliteConnection, uids: &[String]) -> Result<u64>`
  - `pub async fn block::list(store: &Store) -> Result<Vec<NodeId>>`
  - `pub async fn block::block(node: &Node, id: NodeId) -> Result<u64>` (records taken out of the tables)
  - `pub async fn block::unblock(node: &Node, id: NodeId) -> Result<bool>` (false if it was not blocked)
  - `pub fn Node::is_blocked(&self, id: &NodeId) -> bool`
  - `pub async fn repl::rematerialize(node: &Node) -> Result<usize>`
  - `MemberView::blocked: bool`

- [ ] **Step 1: Write the failing tests** in `tests/cluster.rs`. A foreign delete now hides, so in `deletes_reach_only_the_deleters_own_records` (Task 5) replace everything from the comment `// B cannot delete A's request for the cluster.` up to (not including) the comment `// Deleting the IP on A removes what A recorded; B's request stays.` with:

```rust
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

```

Then add:

```rust
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
    for path in ["/one", "/two"] {
        rec(&na)
            .insert_request(&new_request(ip.id, path))
            .await
            .unwrap();
    }
    eventually("b has both", || async {
        count(&nb, "SELECT COUNT(*) FROM requests").await == 2
    })
    .await;
    let one_on_b: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/one'")
        .fetch_one(&nb.store.pool)
        .await
        .unwrap();
    let out = rec(&nb).delete_request(one_on_b).await.unwrap();
    assert_eq!((out.deleted, out.hidden), (0, 1));
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
    eventually("everyone has both", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 2
            && count(&nc, "SELECT COUNT(*) FROM requests").await == 2
    })
    .await;

    assert!(block::block(&nb, nb.id()).await.is_err(), "not oneself");
    assert_eq!(block::block(&nb, a.id).await.unwrap(), 1);
    assert_eq!(block::block(&nb, a.id).await.unwrap(), 0, "repeat is harmless");
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
    assert!(!block::unblock(&nb, a.id).await.unwrap(), "repeat is harmless");
    assert_eq!(paths(&nb).await, ["/a1", "/a2", "/b1"]);
    assert!(!nb.is_blocked(&a.id));
}

/// The admin is told what a delete did: cluster-wide or local only.
#[tokio::test]
async fn admin_delete_reports_hidden_records() {
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
    let r = admin
        .post(format!("{base}/admin/requests/{id}/delete"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM requests").await, 0);
    assert_eq!(count(&nb, "SELECT COUNT(*) FROM hidden").await, 1);
}
```

The last test checks that the delete succeeds and hides; the notice text and its cookie are covered by the unit test in Step 8.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test cluster foreign_delete_hides blocking_a_peer admin_delete_reports`
Expected: compile errors for `cluster::block`, `repl::rematerialize`.

- [ ] **Step 3: Schema.** Create `src/store/migrations/0013_hide_block.sql` and append it to `MIGRATIONS`:

```sql
-- Local decisions of this node; never replicated.
-- hidden: records of other nodes an admin deleted here.
CREATE TABLE hidden (uid TEXT PRIMARY KEY, hidden_at TEXT NOT NULL) WITHOUT ROWID;
-- blocked_peers: nodes this node does not talk to or show records of.
CREATE TABLE blocked_peers (id BLOB PRIMARY KEY, blocked_at TEXT NOT NULL) WITHOUT ROWID
```

- [ ] **Step 4: Keep suppressed records out of the tables.** In `src/store/data.rs` add:

```rust
/// Record kinds a local hide or block keeps out of the tables. Membership,
/// tombstones and scan-job state still apply, so the cluster stays in step.
const CONTENT_KINDS: [&str; 6] = [
    "request",
    "fingerprint",
    "fp_claim",
    "scan_job",
    "scan_result",
    "ip_enrich",
];

async fn origin_blocked(conn: &mut SqliteConnection, origin: Option<&NodeId>) -> Result<bool> {
    let Some(o) = origin else { return Ok(false) };
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_peers WHERE id = ?")
        .bind(&o.0[..])
        .fetch_one(&mut *conn)
        .await?;
    Ok(n > 0)
}

/// Whether `uid` is kept out of the tables locally: hidden by an admin, or
/// created by a blocked node.
async fn suppressed(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM hidden WHERE uid = ?1)
             OR EXISTS(SELECT 1 FROM repl_log l JOIN blocked_peers b ON b.id = l.origin
                       WHERE l.uid = ?1)",
    )
    .bind(uid)
    .fetch_one(&mut *conn)
    .await?;
    Ok(n > 0)
}

/// Whether a parent row that is missing is gone for good (deleted, hidden or
/// blocked) rather than not replicated yet.
async fn gone(conn: &mut SqliteConnection, uid: &str) -> Result<bool> {
    Ok(is_tombstoned(conn, uid).await? || suppressed(conn, uid).await?)
}

/// Local delete of records other nodes created: they leave this node's
/// tables for good and stay in its log. Returns how many were hidden.
pub async fn hide(conn: &mut SqliteConnection, uids: &[String]) -> Result<u64> {
    let mut n = 0;
    for uid in uids {
        let kind: Option<String> = sqlx::query_scalar(
            "SELECT kind FROM repl_log WHERE uid = ? AND kind != 'tombstone' LIMIT 1",
        )
        .bind(uid)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(kind) = kind else { continue };
        sqlx::query("INSERT OR IGNORE INTO hidden (uid, hidden_at) VALUES (?, datetime('now'))")
            .bind(uid)
            .execute(&mut *conn)
            .await?;
        if let Some(ip_id) = unmaterialize(conn, &kind, uid).await? {
            drop_orphan_ip(conn, ip_id).await?;
            n += 1;
        }
    }
    Ok(n)
}
```

At the top of `apply`, before the `match`:

```rust
    // Hides and blocks only exist in a cluster.
    if ctx.origin.is_some() && CONTENT_KINDS.contains(&r.kind()) {
        if origin_blocked(conn, ctx.origin).await? {
            return Ok(Effect::Ignored);
        }
        if let Some(uid) = r.uid()
            && suppressed(conn, &uid).await?
        {
            return Ok(Effect::Ignored);
        }
    }
```

In `job_status` and `scan_result`, replace `is_tombstoned(conn, &r.job_uid).await?` with `gone(conn, &r.job_uid).await?` (the missing-job branches), and adjust the comments: "deleted, hidden or blocked → drop".

- [ ] **Step 5: Re-apply after an unblock.** In `src/cluster/repl.rs` add:

```rust
/// Apply log entries that are held with their payload but have no row:
/// after an unblock, everything the block kept out of the tables. Records an
/// admin hid stay hidden. Returns how many entries were looked at.
pub async fn rematerialize(node: &Node) -> Result<usize> {
    let _g = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    // Parents first; job state after the jobs it refers to.
    let rows: Vec<LogRow> = sqlx::query_as(
        "SELECT origin, seq, hlc, kind, uid, payload, sig, erased_by FROM repl_log
         WHERE payload IS NOT NULL
           AND kind IN ('request','scan_job','job_adopt','job_status','fp_claim',
                        'fingerprint','scan_result','ip_enrich')
         ORDER BY CASE kind WHEN 'request' THEN 0 WHEN 'scan_job' THEN 1
                            WHEN 'job_adopt' THEN 2 WHEN 'job_status' THEN 3 ELSE 4 END, hlc",
    )
    .fetch_all(&mut *tx)
    .await?;
    let n = rows.len();
    for r in rows {
        let e = from_row(r)?;
        if let Some(rec) = e.record() {
            apply_record(node, &mut tx, &e, &rec).await?;
        }
    }
    tx.commit().await?;
    drop(_g);
    node.notify_changed();
    Ok(n)
}
```

- [ ] **Step 6: The block list.** Create `src/cluster/block.rs` and add `pub mod block;` to `src/cluster/mod.rs`:

```rust
//! The local block list. Blocking a peer is this node's own decision and
//! is never replicated: the node stops talking to the peer and keeps its
//! records out of its tables, but still stores and relays them, so nobody
//! else is affected.
use super::Node;
use super::identity::NodeId;
use super::repl;
use crate::store::data;
use anyhow::{Result, bail};

pub async fn list(store: &crate::store::Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT id FROM blocked_peers")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// Block `id`. Returns how many of its records left the tables.
pub async fn block(node: &Node, id: NodeId) -> Result<u64> {
    if id == node.id() {
        bail!("a node cannot block itself");
    }
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("INSERT OR IGNORE INTO blocked_peers (id, blocked_at) VALUES (?, datetime('now'))")
        .bind(&id.0[..])
        .execute(&mut *tx)
        .await?;
    let mut n = 0;
    let mut ips = std::collections::BTreeSet::new();
    // Children before parents, so each row is counted once.
    for (table, kind) in [
        ("scans", "scan_result"),
        ("fp_claims", "fp_claim"),
        ("fingerprints", "fingerprint"),
        ("scan_jobs", "scan_job"),
        ("requests", "request"),
    ] {
        let sql = format!("SELECT uid FROM {table} WHERE origin = ? AND uid IS NOT NULL");
        let uids: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(&id.0[..])
            .fetch_all(&mut *tx)
            .await?;
        for uid in uids {
            if let Some(ip) = data::unmaterialize(&mut tx, kind, &uid).await? {
                ips.insert(ip);
                n += 1;
            }
        }
    }
    for ip in ips {
        data::drop_orphan_ip(&mut tx, ip).await?;
    }
    tx.commit().await?;
    drop(guard);
    node.reload_members().await?;
    tracing::info!(id = %id.short(), records = n, "peer blocked");
    Ok(n)
}

/// Unblock `id` and bring its records back. False if it was not blocked.
pub async fn unblock(node: &Node, id: NodeId) -> Result<bool> {
    let n = sqlx::query("DELETE FROM blocked_peers WHERE id = ?")
        .bind(&id.0[..])
        .execute(&node.store.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Ok(false);
    }
    repl::rematerialize(node).await?;
    node.reload_members().await?;
    tracing::info!(id = %id.short(), "peer unblocked");
    Ok(true)
}
```

In `src/cluster/mod.rs` add the field `blocked: RwLock<Arc<std::collections::HashSet<NodeId>>>,` (initialise with `blocked: RwLock::new(Arc::new(Default::default())),`), load it in `reload_members` before `let before = self.dial_targets();`:

```rust
        let blocked: std::collections::HashSet<NodeId> =
            block::list(&self.store).await?.into_iter().collect();
```

store it with the others (`*self.blocked.write().unwrap() = Arc::new(blocked);`), and add:

```rust
    /// Whether this node blocked `id` (a local decision, see [`block`]).
    pub fn is_blocked(&self, id: &NodeId) -> bool {
        self.blocked.read().unwrap().contains(id)
    }
```

In `dial_targets` extend the first filter: `.filter(|m| m.id != self.id() && !self.is_blocked(&m.id))`.

- [ ] **Step 7: Refuse a blocked peer.**

`src/cluster/rpc/mod.rs`, at the top of `require_member`:

```rust
    if node.is_blocked(&peer) {
        return (StatusCode::FORBIDDEN, "blocked by this node").into_response();
    }
```

`src/cluster/msg.rs`, in `deliver`, before the member check:

```rust
        if self.is_blocked(&b.from) {
            return debug!(from = %b.from.short(), "message from a blocked peer dropped");
        }
```

`src/scan/mod.rs`, in the arbiter loop of `acquire`, right after `let Ok(arbiter) = NodeId::from_slice(&a) else { continue; };`:

```rust
            // No scan work for or from a peer this node blocked.
            if node.is_blocked(&arbiter) {
                continue;
            }
```

- [ ] **Step 8: Hide on delete, and say so.** In `src/store/recorder.rs` replace the `hide` stub:

```rust
    /// Records other nodes originated cannot be deleted from here: they are
    /// hidden on this node only.
    async fn hide(&self, uids: Vec<String>) -> Result<u64> {
        let Recorder::Cluster(n) = self else {
            return Ok(0);
        };
        if uids.is_empty() {
            return Ok(0);
        }
        let _g = n.apply_lock.lock().await;
        let mut tx = n.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let hidden = data::hide(&mut tx, &uids).await?;
        tx.commit().await?;
        Ok(hidden)
    }
```

In `src/admin/pages.rs` add a one-shot message that the next page shows, and a unit test for it:

```rust
/// What a delete did, for the admin.
fn deleted_msg(d: crate::store::recorder::Deleted) -> String {
    match (d.deleted, d.hidden) {
        (n, 0) => format!("Deleted {n} record(s)."),
        (0, h) => format!(
            "Hid {h} record(s) on this node only: other nodes recorded them, so they stay in the cluster."
        ),
        (n, h) => format!(
            "Deleted {n} record(s) cluster-wide; hid {h} record(s) of other nodes on this node only."
        ),
    }
}

/// Redirect with a one-shot notice. It travels in a short-lived cookie the
/// page script shows and clears, so a crafted link cannot plant a message.
fn redirect_with_notice(to: &str, msg: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let enc = serde_urlencoded::to_string([("m", msg)]).unwrap_or_default();
    let cookie = format!(
        "peephole_flash={}; Path=/; Max-Age=30; SameSite=Strict",
        enc.trim_start_matches("m=")
    );
    (
        [(axum::http::header::SET_COOKIE, cookie)],
        Redirect::to(to),
    )
        .into_response()
}

#[cfg(test)]
mod delete_notice_tests {
    use super::*;
    use crate::store::recorder::Deleted;

    #[test]
    fn notice_names_what_happened_and_fits_a_cookie() {
        assert_eq!(
            deleted_msg(Deleted {
                deleted: 2,
                hidden: 0
            }),
            "Deleted 2 record(s)."
        );
        assert!(
            deleted_msg(Deleted {
                deleted: 0,
                hidden: 1
            })
            .starts_with("Hid 1 record(s) on this node only")
        );
        let r = redirect_with_notice(
            "/requests",
            &deleted_msg(Deleted {
                deleted: 1,
                hidden: 3,
            }),
        );
        let c = r.headers()[axum::http::header::SET_COOKIE].to_str().unwrap();
        assert!(c.starts_with("peephole_flash=Deleted+1+record"), "{c}");
        let value = c.split(';').next().unwrap();
        assert!(!value.contains(' '), "cookie value must be encoded: {c}");
        assert!(c.contains("hid+3+record"), "{c}");
    }
}
```

Use it in the delete handlers. Each changes its return type from `AppResult<Redirect>` to `AppResult<axum::response::Response>`:

```rust
async fn request_delete(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Path(id): Path<i64>,
) -> AppResult<axum::response::Response> {
    let out = st.recorder.delete_request(id).await?;
    if out.deleted + out.hidden == 0 {
        return Err(AppError::NotFound);
    }
    Ok(redirect_with_notice("/requests", &deleted_msg(out)))
}
```

`scan_delete` and `claim_delete` take the same shape with their targets (`"/admin/scans"`, `"/admin/inbox"`). `ip_delete` calls `st.recorder.delete_ips(&[ip.id]).await?` and returns `Ok(redirect_with_notice("/ips", &deleted_msg(out)))`. In the two bulk handlers, sum `Deleted` instead of a number (`total.deleted += out.deleted; total.hidden += out.hidden;` with `let mut total = Deleted::default();`), keep the stop condition from Task 5, log both counts, and return `Ok(redirect_with_notice(&format!("/requests?{}", …), &deleted_msg(total)))` (and `/ips?…` for IPs).

In `assets/js/app.js`, after the block `// Confirmation dialogs for destructive forms.` … `});` (the `data-close` handler), add:

```js
  // One-shot notice the server set after an action; shown once, then cleared.
  var fm = document.cookie.match(/(?:^|; )peephole_flash=([^;]*)/);
  if (fm) {
    document.cookie = "peephole_flash=; Path=/; Max-Age=0; SameSite=Strict";
    var main = document.querySelector("main");
    if (main) {
      var note = document.createElement("div");
      note.className = "banner banner-success";
      try { note.textContent = decodeURIComponent(fm[1].replace(/\+/g, " ")); } catch (e) { note.textContent = ""; }
      if (note.textContent) main.insertBefore(note, main.firstChild);
    }
  }
```

- [ ] **Step 9: CLI and Cluster page.**

`src/cluster/cli.rs`: add to `USAGE`

```rust
       peephole cluster block NODE [CONFIG]     (NODE: name, fingerprint or ed25519:… key)
       peephole cluster unblock NODE [CONFIG]
```

and the arms:

```rust
        Some(cmd @ ("block" | "unblock")) => {
            reject_unknown_flags(&flags, &[])?;
            let who = pos.get(1).context(USAGE)?;
            let (_, node) = open(cfg_at(2)).await?;
            let id = resolve(&members::all(&node.store).await?, who)?;
            if cmd == "block" {
                let n = super::block::block(&node, id).await?;
                println!(
                    "blocked {}: this node no longer talks to it and shows none of its records \
                     ({n} taken out of view). Other nodes are unaffected.",
                    id.short()
                );
            } else if super::block::unblock(&node, id).await? {
                println!("unblocked {}; its records are back", id.short());
            } else {
                println!("{} was not blocked", id.short());
            }
        }
```

Bring back the lookup helper those arms use (removed in Task 2), above `run`:

```rust
/// Find a member by name, short fingerprint or full key.
fn resolve(rows: &[members::MemberRow], who: &str) -> Result<NodeId> {
    if let Ok(id) = NodeId::parse(who) {
        return Ok(id);
    }
    let hits: Vec<_> = rows
        .iter()
        .filter(|m| m.name == who || m.id.short() == who)
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.id),
        [] => bail!("no member named `{who}`"),
        _ => bail!("`{who}` is ambiguous; use the full key"),
    }
}
```

In the `members`/`status` arm load the block list once, `let blocked = super::block::list(&store).await?;`, before the loop, and show it after the roles: change the format string's tail from `roles={}{}` to `roles={}{}{}` and add the argument `if blocked.contains(&m.id) { " blocked" } else { "" }` before `me`. In `src/main.rs` extend the help text with `block|unblock`.

`src/admin/cluster.rs`: add `pub blocked: bool,` to `MemberView` (`blocked: node.is_blocked(&m.id),` in `views`, `blocked: false,` in the fallback), the routes `.route("/admin/cluster/block", post(block))` and `.route("/admin/cluster/unblock", post(unblock))`, and:

```rust
#[derive(serde::Deserialize)]
struct KeyForm {
    key: String,
}

async fn block(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    Ok(match crate::cluster::block::block(node, id).await {
        Ok(n) => back(
            Some(format!(
                "Blocked {}. This node no longer talks to it and shows none of its records ({n} taken out of view). Other nodes are unaffected.",
                id.short()
            )),
            None,
        ),
        Err(e) => back(None, Some(format!("{e:#}"))),
    })
}

async fn unblock(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    Ok(if crate::cluster::block::unblock(node, id).await? {
        back(
            Some(format!("Unblocked {}. Its records are back.", id.short())),
            None,
        )
    } else {
        back(None, Some("That node was not blocked.".into()))
    })
}
```

`templates/admin_cluster.html`: next to the state badge add `{% if m.blocked %} <span class="badge badge-status" data-status="failed">blocked</span>{% endif %}`, and replace the empty last cell `<td></td>` of the members table with:

```html
        <td>{% if m.blocked %}
          <form method="post" action="/admin/cluster/unblock"><input type="hidden" name="key" value="{{ m.key }}"><button class="btn btn-sm" type="submit">Unblock</button></form>
        {% else %}
          <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-block-{{ loop.index }}">Block</button>
          <dialog id="dlg-block-{{ loop.index }}"><h3>Block {{ m.name }}?</h3><p class="muted">This node stops talking to it and shows none of its records. Nothing changes for other nodes: nobody can remove a member from the cluster. You can unblock it later.</p>
            <form method="post" action="/admin/cluster/block" class="actions"><input type="hidden" name="key" value="{{ m.key }}">
              <button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Block</button></form></dialog>
        {% endif %}</td>
```

- [ ] **Step 10: Run the tests**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 11: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster): local hide for foreign records and local peer block"
```

---

### Task 8: Persistent dataset and documentation

**Files:**
- Modify: `src/lib.rs`, `README.md`, `deploy/config.example.toml`, `install.sh` (one comment)
- Test: `src/lib.rs` (unit)

**Interfaces:**
- Consumes: everything above (documentation only).
- Produces: `pub fn retention_applies(cfg: &config::Config) -> bool`.

- [ ] **Step 1: Write the failing test** at the end of `src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> config::Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\n[roles]\nlistener = false\nweb = false\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn retention_only_applies_to_standalone_nodes() {
        assert!(retention_applies(&cfg("")));
        assert!(!retention_applies(&cfg("[scan]\nretention_days = 0\n")));
        assert!(!retention_applies(&cfg(
            "[cluster]\nnode_name = \"n\"\nlisten = \"127.0.0.1:7443\"\n"
        )));
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib retention_only_applies`
Expected: compile error, `retention_applies` not found.

- [ ] **Step 3: Implement.** In `src/lib.rs`:

```rust
/// Whether old records are deleted by age. Only on a standalone node: a
/// cluster's dataset is persistent, and nothing in it is erased by age.
pub fn retention_applies(cfg: &config::Config) -> bool {
    cfg.cluster.is_none() && cfg.scan.retention_days > 0
}
```

Replace the retention spawn in `run`:

```rust
    // Retention (standalone only): prune requests and scan results older
    // than the configured window so the database does not grow without bound.
    if retention_applies(&cfg) {
        tokio::spawn(run_retention(
            recorder.clone(),
            cfg.scan.retention_days,
            shutdown_rx.clone(),
        ));
    }
```

In `check_config`, inside `if cfg.cluster.is_some() { … }`, after the node-key lines:

```rust
        if cfg.scan.retention_days > 0 {
            summary.push_str(
                "\nnote: scan.retention_days is ignored in a cluster (the shared dataset is persistent)",
            );
        }
```

- [ ] **Step 4: Run the test**

Run: `cargo test --lib retention_only_applies`
Expected: PASS.

- [ ] **Step 5: README.** Replace the section from `## Distributed mode` up to (not including) `## Configuration` with:

````markdown
## Distributed mode

Several deployments can form a cluster that shares one dataset: every
request, the scan queue, scan results and the Tor intel. The operators do
not need to know or trust each other. Each node runs any combination of
three roles, set in `[roles]`:

| Role | Does | Needs |
|---|---|---|
| `listener` | the trap: records and classifies requests, queues scans | `trap_listen`, `rules_dir` |
| `scanner` | runs nmap for jobs from any trap | nmap |
| `web` | wall of shame and admin area | `admin_listen`, `[webauthn]` |

Every node keeps a full copy of the dataset, so any web node shows the
whole cluster. Scanners take jobs from any trap; jobs go to the scanner
with the fewest recent scans.

Enable it with a `[cluster]` section (see the example config), then add
nodes:

```sh
peephole cluster id                       # this node's key
peephole cluster invite --label friends   # on a member: a reusable invite
peephole cluster invites                  # list them; invite-revoke <id> closes one
peephole cluster join <token>             # on the new node; or Admin → Cluster
peephole cluster members                  # who is in, and their standing
peephole cluster block <node>             # this node ignores a peer (unblock undoes it)
peephole cluster leave                    # this node leaves; it keeps its data
```

Nodes talk HTTP/2 over mutual TLS with pinned Ed25519 keys on
`cluster.listen` (default port 7443). A node without `advertise` is
outbound-only: it dials its peers and still syncs both ways. Peers can also
be listed under `[[cluster.peers]]` with their key.

How trust works:

- **Nobody can remove a node.** A node leaves by itself. A member that
  shows no sign of life for 30 days is pruned by every node on its own and
  rejoins with an invite.
- **An invite is reusable** until it expires, reaches its use limit or is
  revoked. Whoever holds a usable invite can join and cannot be removed
  afterwards, so limit invites you hand to more than one person.
- **Blocking is local.** A node that blocks a peer stops talking to it and
  shows none of its records. It still stores and relays them, so other
  nodes are unaffected.
- **Deletes reach your own records only.** Deleting something your node
  recorded removes it on every node. Deleting something another node
  recorded hides it on your node only.
- **The dataset is persistent.** What a node contributed stays when it
  leaves or is pruned. `scan.retention_days` applies to standalone nodes
  only; a cluster node's database grows with the cluster.

Things to know:

- Counter-scans come from the scanner node's address, not the trap's. Abuse
  reports go to that node's hosting provider.
- `scan.never_scan` protects what you do not want your own scanner to
  touch. It applies only on the node that sets it; other scanners may still
  scan those addresses. Scanners never scan the addresses of cluster
  members.
- Every member sees everything the cluster records, including raw requests
  and false-positive claims with their optional contact address.
- Run NTP on every node: cooldowns and the 30-day prune compare timestamps
  written by different nodes. The Cluster page flags clock differences.
- A standalone node that joins brings its history with it.
- Node names and keys appear only in the admin area, never on public pages.
````

In the `## Install` section nothing changes in this plan.

- [ ] **Step 6: Example config.** In `deploy/config.example.toml` change the two comments:

```toml
retention_days = 90        # standalone only: delete requests and scan results older than this; 0 = keep forever. Ignored in a cluster.
never_scan = ["192.168.0.0/16"] # extra CIDRs this node's scanner never scans (own infra, monitoring); other cluster scanners are not bound by it
```

and replace the sentence in the `[cluster]` comment block `Add nodes with … or list them below.` by: `Add nodes with the reusable invite from "peephole cluster invite" and "peephole cluster join <token>", or list them below. Nobody can remove a member; a node leaves with "peephole cluster leave".`

In `install.sh` the generated `[scan]` block has the same two comments; give them the same wording:

```sh
retention_days = 90        # standalone only: delete older requests and scans; 0 = keep forever (ignored in a cluster)
```

```sh
never_scan = ["192.168.0.0/16"] # extra CIDRs this node's scanner never scans (own infra, monitoring)
```

and in its closing notes replace `Add members with 'peephole cluster invite' here and 'peephole cluster join <token>' there.` with `Add members with the reusable invite from 'peephole cluster invite' here and 'peephole cluster join <token>' there.`

- [ ] **Step 7: Run everything**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && bash -n install.sh`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(cluster): persistent dataset (no retention in a cluster); docs for federation"
```

---

## Not in this plan

These spec items belong to the later plans and are deliberately untouched here:

- §3.3 "ignores its enrichment results": a blocked node's future `ip_enrich` records are already kept out (Task 7), but GeoIP facts it wrote before the block stay in `ips` until the enrichment plan replaces `ip_enrich` with per-origin `ip_intel` rows.
- §5 config key, runtime settings, role toggles. Remote pace (`SetPace`) keeps working as today until then.
- §6 enrichment providers and the end of GeoLite2 file sharing.
- §7 installer wizard and reverse-proxy guidance.
