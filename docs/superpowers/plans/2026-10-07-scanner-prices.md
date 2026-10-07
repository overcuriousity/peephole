# Scanner Prices Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each scanner sells scan jobs at its own price, which follows how busy it is. Arbiters hand each job to the cheapest scanner that asks, at most at a price they compute themselves. A node's own jobs are funded by the same rule as everyone's. The collecting node goes: every node keeps what it earns, and a lookup that needs more draws from its siblings, richest first.

**Architecture:** `credits::price` computes, on every node, a price for every scanner from public inputs (paid scans by `finished_at`, announced capacity). A scanner's own copy is its selling price, announced in the heartbeat. Other nodes' copies are their reference prices. `scan::arbiter::hand_out` orders claimants by the price it would pay, and pushes hoarding or non-delivering scanners to the back. `scan::Source::acquire_granted` asks arbiters that can pay first, in urgency order. `credits::jobs` funds offers at the chosen scanner's price and tallies own jobs in `scan_jobs.self_mc`. `credits::fleet` loses forwarding; its draw asks siblings richest first. Protocol 5.

**Tech Stack:** Rust 2024, tokio, sqlx (SQLite), serde/CBOR heartbeats, askama templates.

**Spec:** `docs/superpowers/specs/2026-10-07-scanner-prices-design.md`

## Global Constraints

- `PAID_TARGET` = 0.9; `PRICE_TOLERANCE` = 1.25; delivery gate: less than half of at least 5 grants in 24 hours.
- The price rule (`step`, `PRICE_STEP` = 0.15, `PRICE_FLOOR` = 1 mc) is unchanged. The scan price is flat per job, whatever the level.
- Protocol 5 (`SCAN_PRICE_PROTO`). An arbiter funds only scanners with `proto_max >= 5`. Lookups keep `MARKET_PROTO` (4).
- A scan of a node's own job still earns no mint (`earn::pay` unchanged).
- Being a sibling has no economic effect except that a lookup may draw from siblings. Scans are paid from the node's own balance only; a sibling's job is paid like anyone's.
- Specs are not amended after implementation. Docs go to `docs/cluster.md`, CHANGELOG (Unreleased) and code comments.
- Match surrounding code: comment density, naming (`mc` suffix for millicredits), British-neutral plain English in user-facing text.
- Every commit ends with:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01TkkewpcFyWjkbJc2oZxG4B
  ```
- Verification per task: `cargo test --lib <module>` for the task's tests, then `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`. Full `cargo test` before the last commit.

## Review Focus

1. **A new scanner appears mid-hour.** No reference price exists until the next hourly refresh. Expected: its grants are unpaid (not refused, not panicking), and it is priced after the next refresh. Pinned in Task 1 (`offer_price(Some(a), None)` is None) and Task 4 (`hand_out` grants unpaid without a reference).
2. **A node that is not a scanner.** It has no selling price. The heartbeat carries `scan_price_mc: None`, the Credits page shows a dash, and `fund` for its own scanner is never called. Pinned in Task 1 (`Table::price_of(SCAN)` is None without a pace) and Task 7 (page renders "not a scanner").
3. **Mixed protocol 4 and 5 nodes during the upgrade.** A protocol 4 heartbeat without `scan_budget_mc` must decode, and a protocol 5 one must decode on protocol 4. Pinned in Task 2.
4. **A job that fails or is requeued after its own budget was reserved.** The reservation must stop counting (otherwise a node's own budget leaks away). Pinned in Task 3 (`self_committed` counts only `running` and done today).
5. **The arbiter's own scanner has no capacity entry yet** (no jobs in 7 days). The capacity gate must not push it last forever. Pinned in Task 4 (`over_capacity` false when `can_do` unknown).

---

### Task 0: Base the branch on master with PR #49

**Files:** none (git only).

- [x] **Step 1:** Wait until PR #49 is merged into `master` (`gh pr view 49 --json state` says `MERGED`).
- [x] **Step 2:** In the worktree `../peephole-scanner-prices` (branch `scanner-prices`):

```bash
git fetch origin && git rebase origin/master
cargo build 2>&1 | tail -3
```

Expected: rebase clean (the branch only holds the spec and this plan), build OK.

- [ ] **Step 3:** Confirm the migration number: `ls src/store/migrations | tail -2` shows `0022_price_history.sql` as the last. This plan uses `0023_scan_self_mc.sql` and `0024_no_collecting_node.sql`. If another migration landed, take the next free number throughout.

---

### Task 1: A price per scanner

**Files:**
- Modify: `src/credits/price.rs` (constants, `Table`, `refresh`, new functions, tests)
- Modify: `src/credits/mod.rs:225-234` (the loop no longer feeds bids into the price)
- Modify: `src/admin/credits.rs`, `src/admin/overview.rs` (only so they compile: `t.scan_mc` → `t.sell_mc.unwrap_or(0)`, `scan_bids` → 0. Task 7 does the page properly.)

**Interfaces:**
- Produces:
  - `pub const PAID_TARGET: f64`
  - `pub const PRICE_TOLERANCE: f64`
  - `pub fn scanner_step(cur: Mc, paid: f64, can_do_per_hour: f64) -> Mc`
  - `pub fn offer_price(announced: Option<u32>, reference: Option<u32>) -> Option<u32>`
  - `pub fn min_take(sell_mc: u32) -> u32`
  - `pub struct ScannerPrice { pub node: NodeId, pub price_mc: u32, pub paid: f64, pub supply: f64 }`
  - `Table { sell_mc: Option<u32>, scanners: Vec<ScannerPrice>, .. }` (fields `scan_bids`, `scan_mc` removed)
  - `Table::reference(&self, node: &NodeId) -> Option<u32>`
  - `Table::can_do(&self, node: &NodeId) -> Option<f64>`
  - `pub fn charged_jobs(l: &super::ledger::Ledger) -> HashSet<(NodeId, String)>`
  - `pub async fn paid_scans(pool: &SqlitePool, charged: &HashSet<(NodeId, String)>) -> Result<HashMap<NodeId, u32>>`
  - `Table::price_of(SCAN)` returns `sell_mc`.

- [ ] **Step 1: Write the failing tests** (in `price.rs`'s `mod tests`):

```rust
#[test]
fn a_scanner_price_follows_its_paid_load() {
    // 10 scans an hour possible: the target is 9 paid.
    let busy = scanner_step(1000, 10.0, 10.0);
    assert!(busy > 1000, "full of paid work: up ({busy})");
    let idle = scanner_step(1000, 0.0, 10.0);
    assert!(idle < 1000, "no paid work: down ({idle})");
    assert_eq!(scanner_step(PRICE_FLOOR, 0.0, 10.0), PRICE_FLOOR, "never under the floor");
    // At the target it holds within a step's rounding.
    let held = scanner_step(1000, 9.0, 10.0);
    assert!((999..=1001).contains(&held), "{held}");
}

#[test]
fn a_saturated_scanner_settles_near_the_target() {
    // Paid demand falls as the price rises: buyers with 900 mc an hour.
    let mut p: Mc = 1;
    for _ in 0..200 {
        let paid = (900.0 / p as f64).min(10.0);
        p = scanner_step(p, paid, 10.0);
    }
    let paid = (900.0 / p as f64).min(10.0);
    assert!((8.0..=10.0).contains(&paid), "settles near 9 paid of 10 ({paid} at {p})");
}

#[test]
fn an_offer_is_the_announced_price_capped_by_the_reference() {
    assert_eq!(offer_price(Some(100), Some(100)), Some(100));
    assert_eq!(offer_price(Some(80), Some(100)), Some(80), "undercutting is fine");
    assert_eq!(offer_price(Some(500), Some(100)), Some(125), "capped at 1.25×");
    assert_eq!(offer_price(None, Some(100)), None, "not a scanner");
    assert_eq!(offer_price(Some(100), None), None, "no reference yet: unpaid");
    assert_eq!(min_take(125), 100);
    assert_eq!(min_take(1), 0);
}

#[tokio::test]
async fn paid_scans_count_charged_jobs_and_own_jobs_by_finish_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
    let pool = &store.pool;
    let (s, a) = (id(1), id(2));
    sqlx::query("INSERT INTO ips (id, ip) VALUES (1, '192.0.2.1')").execute(pool).await.unwrap();
    // (job uid, queued by, finished minutes ago)
    for (n, (uid, origin, ago)) in [
        ("paid", a, 10),     // charged offer: counts
        ("unpaid", a, 10),   // no offer: does not count
        ("own", s, 20),      // the scanner's own job: counts
        ("old", a, 90),      // charged, but finished over an hour ago
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query(
            "INSERT INTO scan_jobs (id, ip_id, level, status, queued_at, uid, origin, arbiter, scanner)
             VALUES (?, 1, 1, 'done', datetime('now','-2 hours'), ?, ?, ?, ?)",
        )
        .bind(n as i64 + 1).bind(uid).bind(&origin.0[..]).bind(&origin.0[..]).bind(&s.0[..])
        .execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
             VALUES (?, 1, 1, datetime('now', ?), datetime('now', ?), ?, ?, ?)",
        )
        .bind(n as i64 + 1)
        .bind(format!("-{} minutes", ago + 5))
        .bind(format!("-{ago} minutes"))
        .bind(format!("scan-{uid}")).bind(&s.0[..]).bind(uid)
        .execute(pool).await.unwrap();
    }
    let charged: HashSet<(NodeId, String)> =
        [(s, "paid".to_string()), (s, "old".to_string())].into_iter().collect();
    let got = paid_scans(pool, &charged).await.unwrap();
    assert_eq!(got.get(&s), Some(&2), "{got:?}");
}

#[test]
fn the_table_answers_for_each_scanner() {
    let t = Table {
        sell_mc: Some(40),
        scanners: vec![ScannerPrice { node: id(7), price_mc: 55, paid: 3.0, supply: 9.0 }],
        ..Default::default()
    };
    assert_eq!(t.price_of(SCAN), Some(40));
    assert_eq!(t.reference(&id(7)), Some(55));
    assert_eq!(t.reference(&id(8)), None);
    assert_eq!(Table::default().price_of(SCAN), None, "not a scanner: no selling price");
}
```

- [ ] **Step 2: Run them, expect compile failure**

Run: `cargo test --lib credits::price 2>&1 | tail -5`
Expected: errors such as `cannot find function scanner_step`.

- [ ] **Step 3: Implement the pure parts** (top of `price.rs`, after `PROBES_PER_SLOT_HOUR`):

```rust
/// Share of a scanner's capacity paid work should fill. A scanner fetches
/// work only when a worker is free, so paid work never exceeds its
/// capacity: with a target of 1 its price could only fall.
pub const PAID_TARGET: f64 = 0.9;
/// An arbiter offers a scanner at most this times its own copy of the
/// scanner's price; a scanner takes no less than its price divided by it.
pub const PRICE_TOLERANCE: f64 = 1.25;

/// One scanner's next price: its paid scans of the past hour against
/// [`PAID_TARGET`] of what it can do in an hour.
pub fn scanner_step(cur: Mc, paid: f64, can_do_per_hour: f64) -> Mc {
    step(cur, paid, PAID_TARGET * can_do_per_hour)
}

/// What an arbiter offers a scanner: what it announces, at most
/// [`PRICE_TOLERANCE`] times this node's own copy. None: not a scanner,
/// or no copy here yet; the job is granted unpaid.
pub fn offer_price(announced: Option<u32>, reference: Option<u32>) -> Option<u32> {
    let cap = (reference? as f64 * PRICE_TOLERANCE).floor() as u32;
    Some(announced?.min(cap))
}

/// The least a scanner selling at `sell_mc` takes for a funded job.
pub fn min_take(sell_mc: u32) -> u32 {
    (sell_mc as f64 / PRICE_TOLERANCE).floor() as u32
}
```

Change `Table` (replace `scan_bids` and `scan_mc`):

```rust
/// One scanner's price as this node computes it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannerPrice {
    pub node: NodeId,
    pub price_mc: u32,
    /// Its paid scans of the past hour, and [`PAID_TARGET`] of its capacity.
    pub paid: f64,
    pub supply: f64,
}

pub struct Table {
    pub at_ms: u64,
    pub capacity: Capacity,
    /// This node's own selling price; None: it does not scan.
    pub sell_mc: Option<u32>,
    /// Every scanner this node counts (itself included), with this node's
    /// copy of its price: the reference an arbiter offers against.
    pub scanners: Vec<ScannerPrice>,
    pub probe_mc: Option<u32>,
    pub resolve_mc: u32,
    pub offers: Vec<Offer>,
}
```

In `impl Table`: `SCAN => self.sell_mc,` in `price_of`, plus:

```rust
    /// This node's copy of `node`'s scan price.
    pub fn reference(&self, node: &NodeId) -> Option<u32> {
        self.scanners.iter().find(|s| s.node == *node).map(|s| s.price_mc)
    }

    /// Scans an hour `node` can do, as this node counts its capacity.
    pub fn can_do(&self, node: &NodeId) -> Option<f64> {
        self.capacity.scanners.iter().find(|s| s.node == *node).map(|s| s.can_do)
    }
```

- [ ] **Step 4: Implement the demand inputs** (below `scanners()`):

```rust
/// The scan jobs a receipt charged, by the scanner that charged them.
pub fn charged_jobs(l: &super::ledger::Ledger) -> HashSet<(NodeId, String)> {
    l.offers
        .iter()
        .filter(|o| matches!(o.state, super::ledger::OfferState::Charged { charged } if charged > 0))
        .filter_map(|o| Some((o.to, o.job.clone()?)))
        .collect()
}

/// Each scanner's paid scans that finished in the past hour, by the
/// scan's own `finished_at` (holding receipts back moves nothing): jobs a
/// receipt of it charged, and jobs it queued itself.
pub async fn paid_scans(
    pool: &sqlx::SqlitePool,
    charged: &HashSet<(NodeId, String)>,
) -> Result<HashMap<NodeId, u32>> {
    let rows: Vec<(Vec<u8>, String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT s.origin, s.job_uid, j.origin FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid
         WHERE s.audit_of IS NULL AND s.origin IS NOT NULL AND s.job_uid IS NOT NULL
           AND s.finished_at > datetime('now', '-1 hour')",
    )
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<NodeId, u32> = HashMap::new();
    for (scanner, job, queued_by) in rows {
        let Ok(scanner) = NodeId::from_slice(&scanner) else { continue };
        let own = queued_by.as_deref() == Some(&scanner.0[..]);
        if own || charged.contains(&(scanner, job)) {
            *out.entry(scanner).or_default() += 1;
        }
    }
    Ok(out)
}

/// Kept across restarts: this node's copy of `scanner`'s price.
fn scanner_key(scanner: &NodeId) -> String {
    format!("price:scan:{scanner}")
}

/// Where a scanner's next step starts: the last copy here, the kept
/// copy, on upgrade the cluster-wide scan price of the market before
/// scanner prices, the lower median of what scanners announce, the floor.
async fn scanner_current(node: &Node, old: &Table, scanner: &NodeId, announced: &[u32]) -> Result<Mc> {
    if let Some(p) = old.reference(scanner).filter(|p| *p > 0) {
        return Ok(p as Mc);
    }
    for key in [scanner_key(scanner), price_key(SCAN)] {
        if let Some(p) = node.store.intel_get(&key).await?.and_then(|v| v.parse::<Mc>().ok()) {
            return Ok(p.max(PRICE_FLOOR));
        }
    }
    Ok(start(announced))
}
```

- [ ] **Step 5: Rewrite the scan part of `refresh`.** Remove `let mut bids ... node.scan_bids ...` and `bids += k.hb.scan_bids` from the member loop; keep collecting `announced` for `SCAN` from `k.hb.scan_price_mc`. Replace the block from `// Funded jobs waiting now` through `let scan_mc = ...` with:

```rust
    // Every scanner's price, from its paid scans of the past hour against
    // what it can do: the same public inputs on every node.
    let paid = paid_scans(&node.store.pool, &charged_jobs(&book.ledger)).await?;
    let mut scanner_prices = vec![];
    for s in &capacity.scanners {
        let cur = scanner_current(node, &old, &s.node, &ann(SCAN)).await?;
        let got = paid.get(&s.node).copied().unwrap_or(0) as f64;
        let price_mc = as_mc(scanner_step(cur, got, s.can_do));
        node.store.intel_set(&scanner_key(&s.node), &price_mc.to_string()).await?;
        scanner_prices.push(ScannerPrice { node: s.node, price_mc, paid: got, supply: PAID_TARGET * s.can_do });
    }
    let sell_mc = scanner_prices.iter().find(|s| s.node == me).map(|s| s.price_mc);
```

In the `for (good, mc) in ...` loop that keeps prices, drop `(SCAN, scan_mc)` from the chain (scanner prices are kept above). In PR #49's history block, replace `goods.push((SCAN, Some(scan_mc), bids as f64, capacity.per_day / 24.0));` with:

```rust
    let mine = scanner_prices.iter().find(|s| s.node == me);
    goods.push((SCAN, sell_mc, mine.map_or(0.0, |s| s.paid), mine.map_or(0.0, |s| s.supply)));
```

Build the `Table` with `sell_mc, scanners: scanner_prices,` instead of `scan_bids, scan_mc`.

- [ ] **Step 6: The credits loop.** In `src/credits/mod.rs`, the comment above `jobs::announce_bids` says the hourly price sees this node's bids; change it to `// Every tick (one count and the cached book), for the heartbeat.` (Task 2 renames the call.)

- [ ] **Step 7: Keep the pages compiling.** In `src/admin/credits.rs` and `src/admin/overview.rs`, replace `show(t.scan_mc as u64)` with `t.sell_mc.map_or_else(|| "–".into(), |m| show(m as u64))`, and `scan_bids: t.scan_bids` with `scan_bids: 0`. In `tests/cluster.rs:6047`, the same replacement for `t.scan_mc`.

- [ ] **Step 8: Run tests**

Run: `cargo test --lib credits::price 2>&1 | tail -5` → all pass.
Run: `cargo clippy --all-targets -- -D warnings 2>&1 | tail -3` → clean.

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -m "Credits: a price per scanner, from its paid load

Every node computes every scanner's price hourly from its paid scans of
the past hour (by finish time) against 90 % of its capacity. A
scanner's own copy is its selling price.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01TkkewpcFyWjkbJc2oZxG4B"
```

---

### Task 2: Heartbeat and protocol 5

**Files:**
- Modify: `src/cluster/rpc/proto.rs` (`PROTO_VERSION = 5`, `SCAN_PRICE_PROTO = 5`)
- Modify: `src/cluster/status.rs:60-90, 410-432, 550-560, 680-686` (fields)
- Modify: `src/cluster/mod.rs:287-290, 355-360` (`scan_bids` atomic → two atomics)
- Modify: `src/cluster/repl.rs:1754, 2005` (test heartbeats)
- Modify: `src/credits/jobs.rs:140-160` (`announce_bids` → `announce_budget`)
- Modify: `src/credits/mod.rs:225-229` (call site)
- Modify: `src/scan/mod.rs:548-555` (temporarily: `k.hb.scan_bids` → `k.hb.scan_queued`, so it compiles until Task 5)
- Modify: `src/credits/pay.rs:715-725` (the test asserting protocol constants)

**Interfaces:**
- Consumes: Task 1's `Table::price_of(SCAN)` (selling price).
- Produces:
  - `Heartbeat { scan_price_mc: Option<u32>, scan_budget_mc: u32, scan_queued: u32, .. }` (`scan_bids` removed)
  - `Node { scan_budget_mc: AtomicU32, scan_queued: AtomicU32 }`
  - `pub const SCAN_PRICE_PROTO: u32 = 5;`
  - `pub fn sells_scans(proto_max: u32) -> bool` in `credits::pay`
  - `pub async fn announce_budget(node: &Arc<Node>) -> Result<()>` in `credits::jobs`

- [ ] **Step 1: Write the failing compatibility test** (in `status.rs` tests; follow the existing heartbeat tests there that build a `Heartbeat` literal):

```rust
#[test]
fn scan_fields_decode_across_protocol_4_and_5() {
    use crate::cluster::rpc::cbor::{decode, encode};
    /// The scan fields of a protocol 4 heartbeat.
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    struct Old {
        #[serde(default)]
        scan_price_mc: Option<u32>,
        #[serde(default)]
        scan_bids: u32,
    }
    #[derive(serde::Serialize, serde::Deserialize, Default, PartialEq, Debug)]
    struct New {
        #[serde(default)]
        scan_price_mc: Option<u32>,
        #[serde(default)]
        scan_budget_mc: u32,
        #[serde(default)]
        scan_queued: u32,
    }
    let new: New = decode(&encode(&Old { scan_price_mc: Some(7), scan_bids: 3 }).unwrap()).unwrap();
    assert_eq!(new, New { scan_price_mc: Some(7), ..Default::default() });
    let old: Old = decode(&encode(&New { scan_price_mc: None, scan_budget_mc: 5, scan_queued: 2 }).unwrap()).unwrap();
    assert_eq!((old.scan_price_mc, old.scan_bids), (None, 0));
}
```

This pins the serde behaviour the real `Heartbeat` relies on (`#[serde(default)]`, unknown fields ignored). Also extend the existing round-trip test of a full `Heartbeat` in `status.rs` (the one that builds a literal at line ~550) to set `scan_budget_mc: 5, scan_queued: 2` and assert they survive `encode`/`decode`.

- [ ] **Step 2: Run, expect failure** on the full-heartbeat test (`no field scan_budget_mc`).

Run: `cargo test --lib cluster::status 2>&1 | tail -5`

- [ ] **Step 3: Implement.**

`proto.rs`:

```rust
pub const PROTO_VERSION: u32 = 5;
/// Scanners sell scan jobs at their own prices (`credits::price`); an
/// arbiter funds only scanners at this protocol or later.
pub const SCAN_PRICE_PROTO: u32 = 5;
```

`status.rs` `Heartbeat`: replace the `scan_price_mc` doc and the `scan_bids` field:

```rust
    /// What this node sells a funded scan job for, in mc; None when it
    /// does not scan.
    #[serde(default)]
    pub scan_price_mc: Option<u32>,
    /// What this node, as arbiter, may still spend on scan jobs now.
    #[serde(default)]
    pub scan_budget_mc: u32,
    /// Its queued scan jobs.
    #[serde(default)]
    pub scan_queued: u32,
```

In `refresh_heartbeat`: `scan_budget_mc: self.scan_budget_mc.load(Relaxed), scan_queued: self.scan_queued.load(Relaxed),`. Test literals: `scan_budget_mc: 0, scan_queued: 0`.

`cluster/mod.rs`: replace `pub scan_bids: AtomicU32` with

```rust
    /// This node's scan budget left and queued jobs, for the heartbeat
    /// (`credits::jobs::announce_budget`).
    pub scan_budget_mc: std::sync::atomic::AtomicU32,
    pub scan_queued: std::sync::atomic::AtomicU32,
```

`pay.rs`, next to `pays_with`:

```rust
/// Whether a member announcing `proto_max` sells scan jobs at its own price.
pub fn sells_scans(proto_max: u32) -> bool {
    proto_max >= crate::cluster::rpc::proto::SCAN_PRICE_PROTO
}
```

`jobs.rs`: delete `bids()` and its test `bids_are_what_the_budget_buys_of_the_queue`; replace `announce_bids` with:

```rust
/// Compute and keep this node's scan budget left and queued jobs, for
/// the heartbeat.
pub async fn announce_budget(node: &Arc<Node>) -> Result<()> {
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued' AND arbiter = ?",
    )
    .bind(&node.id().0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let book = super::book(node).await?;
    let self_mc = self_committed(&node.store.pool, &node.id()).await?;
    let left = budget(&book.ledger, &node.id(), node.scan_share(), self_mc);
    node.scan_budget_mc.store(left.min(u32::MAX as Mc) as u32, std::sync::atomic::Ordering::Relaxed);
    node.scan_queued.store(queued.clamp(0, u32::MAX as i64) as u32, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
```

`credits/mod.rs`: call `jobs::announce_budget(&node)`, log text `"credits: scan budget not computed"`.

`scan/mod.rs:554`: `.map(|k| (k.hb.scan_queued, k.hb.scan_price_mc.unwrap_or(0)))` (replaced in Task 5).

`pay.rs` test at ~720: add `assert_eq!(crate::cluster::rpc::proto::SCAN_PRICE_PROTO, 5);`.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib cluster::status credits 2>&1 | tail -5` → pass. Clippy clean.

- [ ] **Step 5: Commit** — message `Cluster: protocol 5, heartbeats carry a scanner's selling price and an arbiter's scan budget` plus the trailer lines.

---

### Task 3: Funding at the scanner's price, own jobs and the self tally

**Files:**
- Create: `src/store/migrations/0023_scan_self_mc.sql`
- Modify: `src/credits/jobs.rs` (`budget`, `fund`, new `self_committed`, tests)
- Modify: `src/scan/arbiter.rs:213-237` (`next_job_for` passes the price)

**Interfaces:**
- Consumes: `price::offer_price`, `Table::reference`, `pay::sells_scans`.
- Produces:
  - `pub fn budget(l: &Ledger, me: &NodeId, share: f64, self_mc: Mc) -> Mc` where `self_mc` is `self_committed`.
  - `pub async fn self_committed(pool: &SqlitePool, me: &NodeId) -> Result<Mc>`
  - `pub async fn fund(node: &Arc<Node>, funding: &mut Funding, scanner: NodeId, job_uid: &str, min_mc: u32, price: u32) -> Option<(Option<u64>, u32)>`: `Some((Some(seq), price))` for an offer, `Some((None, price))` for an own job funded by the tally, None for unpaid.
  - `pub fn price_for(node: &Node, scanner: &NodeId) -> Option<u32>`: what this arbiter would pay `scanner` (own: its selling price; others: `offer_price(announced, reference)`, None for an older protocol).

- [ ] **Step 1: Migration** `0023_scan_self_mc.sql`:

```sql
-- Scanner prices: what a node's own job, granted to its own scanner,
-- counts against its scan budget. Local: paying oneself moves nothing,
-- so it is not in the ledger and not replicated.
ALTER TABLE scan_jobs ADD COLUMN self_mc INTEGER;
```

- [ ] **Step 2: Write the failing tests** (in `jobs.rs` tests):

```rust
#[test]
fn the_budget_counts_own_jobs() {
    // A balance of 1000 at share 0.5: 500. Own jobs holding 200 count
    // like offers: (1000 + 200) × 0.5 - 200 = 400 left.
    let l = ledger_with_balance(id(1), 1000);
    assert_eq!(budget(&l, &id(1), 0.5, 0), 500);
    assert_eq!(budget(&l, &id(1), 0.5, 200), 400);
}

#[tokio::test]
async fn own_job_reservations_count_while_running_and_when_done_today() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
    let pool = &store.pool;
    let me = id(1);
    sqlx::query("INSERT INTO ips (id, ip) VALUES (1, '192.0.2.1')").execute(pool).await.unwrap();
    for (n, status, finished, mc) in [
        (1, "running", None, 30),
        (2, "done", Some("datetime('now')"), 20),
        (3, "done", Some("datetime('now','-2 days')"), 50),
        (4, "queued", None, 70),  // requeued after its reservation: no longer counts
        (5, "failed", Some("datetime('now')"), 90),
    ] {
        sqlx::query(&format!(
            "INSERT INTO scan_jobs (id, ip_id, level, status, queued_at, finished_at, uid, arbiter, self_mc)
             VALUES (?, 1, 1, ?, datetime('now'), {}, ?, ?, ?)",
            finished.unwrap_or("NULL")
        ))
        .bind(n).bind(status).bind(format!("j{n}")).bind(&me.0[..]).bind(mc)
        .execute(pool).await.unwrap();
    }
    assert_eq!(self_committed(pool, &me).await.unwrap(), 50);
}
```

`ledger_with_balance` is a test helper to add in the same module, built like the existing test `the_budget_is_a_share_of_what_was_there_today` builds its ledger (`ledger::run` with one `Earned` of `mc` for `node` today). Reuse that test's setup code; do not invent a new ledger API.

Also update the existing `budget(...)` calls in that test to pass `0`.

- [ ] **Step 3: Run, expect failure** (`budget` takes 3 arguments; `self_committed` not found).

Run: `cargo test --lib credits::jobs 2>&1 | tail -5`

- [ ] **Step 4: Implement** in `jobs.rs`:

```rust
/// What `me` may still hold in or pay for its scan jobs today: `share` of
/// its balance plus what its scan offers and own jobs (`self_mc`) hold
/// and were charged today, minus those.
pub fn budget(l: &Ledger, me: &NodeId, share: f64, self_mc: Mc) -> Mc {
    let (mut held, mut charged) = (0, 0);
    for o in l.offers.iter().filter(|o| o.payer == *me && o.job.is_some()) {
        match o.state {
            OfferState::Open => held += o.held_now(),
            OfferState::Charged { charged: c } if day_of(o.hlc) == l.today => charged += c,
            _ => {}
        }
    }
    let committed = held + charged + self_mc;
    let cap = ((l.balance(me) + committed) as f64 * share.clamp(0.0, 1.0)).floor() as Mc;
    cap.saturating_sub(committed)
}

/// What this node's own jobs granted to its own scanner hold (running) or
/// were charged today (done): they count against the budget like offers.
/// A job requeued, failed or refused no longer counts.
pub async fn self_committed(pool: &sqlx::SqlitePool, me: &NodeId) -> Result<Mc> {
    let n: Option<i64> = sqlx::query_scalar(
        "SELECT SUM(self_mc) FROM scan_jobs
         WHERE arbiter = ? AND self_mc > 0
           AND (status = 'running' OR (status = 'done' AND finished_at >= date('now')))",
    )
    .bind(&me.0[..])
    .fetch_one(pool)
    .await?;
    Ok(n.unwrap_or(0).max(0) as Mc)
}

/// What this node, as arbiter, would pay `scanner` for a job now: its own
/// scanner its selling price; another scanner what it announces, at most
/// [`price::PRICE_TOLERANCE`] times this node's copy. None: unpaid.
pub fn price_for(node: &Node, scanner: &NodeId) -> Option<u32> {
    let table = node.price_table();
    if *scanner == node.id() {
        return table.price_of(price::SCAN);
    }
    let k = node.status.known(scanner)?;
    if !node.members().get(scanner).is_some_and(|m| super::pay::sells_scans(m.proto_max)) {
        return None;
    }
    price::offer_price(k.hb.scan_price_mc, table.reference(scanner))
}
```

`Funding` gets `self_mc: Option<Mc>` (computed once per round like `book`). Rewrite `fund`:

```rust
pub async fn fund(
    node: &Arc<Node>,
    funding: &mut Funding,
    scanner: NodeId,
    job_uid: &str,
    min_mc: u32,
    price: u32,
) -> Option<(Option<u64>, u32)> {
    let me = node.id();
    if price == 0 || price < min_mc {
        return None;
    }
    let book = match &funding.book {
        Some(b) => b.clone(),
        None => {
            let b = super::book_fresh(node).await.ok()?;
            funding.lots = b.ledger.by_day(&me);
            funding.book = Some(b.clone());
            b
        }
    };
    let self_mc = match funding.self_mc {
        Some(s) => s,
        None => {
            let s = self_committed(&node.store.pool, &me).await.ok()?;
            funding.self_mc = Some(s);
            s
        }
    };
    let left = budget(&book.ledger, &me, node.scan_share(), self_mc)
        .saturating_sub(funding.committed);
    if left < price as Mc {
        return None;
    }
    if scanner == me {
        // Paying oneself moves nothing: the job holds the price against
        // the budget instead of an offer.
        sqlx::query("UPDATE scan_jobs SET self_mc = ? WHERE uid = ?")
            .bind(price as i64)
            .bind(job_uid)
            .execute(&node.store.pool)
            .await
            .ok()?;
        funding.committed += price as Mc;
        return Some((None, price));
    }
    // ... unchanged from here: first_day_for_job, parts_from, append_sealing,
    // on Ok: funding.committed += price; lots reduced; Some((Some(e.seq), price))
}
```

Remove the old `scanner == me` early return and the `pays_with` check (now in `price_for`).

`arbiter.rs` `next_job_for`: compute `let price = crate::credits::jobs::price_for(&self.node, &scanner);` and call `fund(&self.node, funding, scanner, &g.job_uid, min_mc, price.unwrap_or(0))`. On `Some((seq, price))` set `g.offer_seq = seq; g.price_mc = price;` (for an own job `offer_seq` stays None and `price_mc` is informational). Keep the log line.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib credits::jobs scan::arbiter 2>&1 | tail -5` → pass. Clippy clean.

- [ ] **Step 6: Commit** — `Credits: scan jobs are funded at the chosen scanner's price; own jobs count against the budget` plus the trailer.

---

### Task 4: The arbiter hands each job to the cheapest scanner, and guards against hoarding

**Files:**
- Modify: `src/scan/arbiter.rs` (`Lease`, `Arbiter` fields, `hand_out`, `complete`, `sweep`, `scans_last_hour`, new pure functions, tests)

**Interfaces:**
- Consumes: `jobs::price_for`, `Table::can_do`.
- Produces (module-private, tested in place):
  - `fn delivers(outcomes: &VecDeque<(Instant, bool)>, now: Instant) -> bool`
  - `fn over_capacity(granted_last_hour: i64, can_do: Option<f64>) -> bool`
  - `fn claim_order(price: Option<u32>, demoted: bool, load: i64, id: NodeId) -> (bool, u32, i64, NodeId)`

- [ ] **Step 1: Write the failing tests** (in `arbiter.rs` tests):

```rust
#[test]
fn a_scanner_delivers_unless_it_failed_half_of_five_recent_grants() {
    let now = Instant::now();
    let mut o = VecDeque::new();
    for ok in [false, false, false, false] {
        o.push_back((now, ok));
    }
    assert!(delivers(&o, now), "fewer than 5 grants: no judgement");
    o.push_back((now, true));
    assert!(!delivers(&o, now), "1 of 5 delivered");
    for _ in 0..4 {
        o.push_back((now, true));
    }
    assert!(delivers(&o, now), "5 of 9 delivered");
    let old = VecDeque::from(vec![(now - Duration::from_secs(25 * 3600), false); 9]);
    assert!(delivers(&old, now), "only the past 24 hours count");
}

#[test]
fn capacity_gate_needs_a_known_capacity() {
    assert!(!over_capacity(100, None), "unknown capacity never gates");
    assert!(!over_capacity(9, Some(10.0)));
    assert!(over_capacity(10, Some(10.0)));
}

#[test]
fn claimants_go_cheapest_first_and_demoted_ones_last() {
    let (a, b, c, d) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]), NodeId([4; 32]));
    let mut v = vec![
        claim_order(Some(50), false, 0, a),
        claim_order(Some(20), false, 9, b),
        claim_order(Some(5), true, 0, c),   // cheapest but hoarding
        claim_order(None, false, 0, d),     // no price: after the priced ones
    ];
    v.sort();
    let order: Vec<NodeId> = v.into_iter().map(|k| k.3).collect();
    assert_eq!(order, vec![b, a, d, c]);
}
```

- [ ] **Step 2: Run, expect compile failure.**

Run: `cargo test --lib scan::arbiter 2>&1 | tail -5`

- [ ] **Step 3: Implement.**

```rust
/// A claimant that delivered less than this share of at least
/// [`DELIVERY_MIN_GRANTS`] grants of this arbiter in the past 24 hours
/// goes after all others.
const DELIVERY_MIN: f64 = 0.5;
const DELIVERY_MIN_GRANTS: usize = 5;
const DELIVERY_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// Whether a scanner's recent grants of this arbiter came back delivered
/// often enough (`(when, delivered)` outcomes).
fn delivers(outcomes: &VecDeque<(Instant, bool)>, now: Instant) -> bool {
    let recent: Vec<bool> = outcomes
        .iter()
        .filter(|(t, _)| now.saturating_duration_since(*t) < DELIVERY_WINDOW)
        .map(|(_, ok)| *ok)
        .collect();
    if recent.len() < DELIVERY_MIN_GRANTS {
        return true;
    }
    recent.iter().filter(|ok| **ok).count() as f64 >= DELIVERY_MIN * recent.len() as f64
}

/// Whether a scanner already got what it can do in an hour from this
/// arbiter. Unknown capacity never gates.
fn over_capacity(granted_last_hour: i64, can_do: Option<f64>) -> bool {
    can_do.is_some_and(|c| granted_last_hour as f64 >= c.max(1.0))
}

/// Sort key of a claimant: not demoted first, then the price this
/// arbiter would pay (unpaid after every price), fewest recent scans, key.
fn claim_order(price: Option<u32>, demoted: bool, load: i64, id: NodeId) -> (bool, u32, i64, NodeId) {
    (demoted, price.unwrap_or(u32::MAX), load, id)
}
```

`Lease` gains `funded: bool`; set it in `next_job_skipping`'s lease insert to `false` and, in `next_job_for`, after funding, set `self.leases.lock().unwrap().get_mut(&g.job_uid).map(|l| l.funded = g.offer_seq.is_some() || g.price_mc > 0)`. `recover` inserts `funded: false`.

`Arbiter` gains `outcomes: Mutex<HashMap<NodeId, VecDeque<(Instant, bool)>>>` and a method:

```rust
    /// Remember how a grant to `scanner` ended, for [`delivers`].
    fn note_outcome(&self, scanner: NodeId, delivered: bool) {
        let now = Instant::now();
        let mut o = self.outcomes.lock().unwrap();
        let q = o.entry(scanner).or_default();
        q.push_back((now, delivered));
        while q.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) >= DELIVERY_WINDOW) {
            q.pop_front();
        }
    }
```

Record outcomes: in `complete`, capture `let funded = self.leases.lock().unwrap().get(uid).is_some_and(|l| l.funded);` before the lease is removed; then `"done"` → `note_outcome(scanner, true)`; `"failed"` → `false`; `"later" | "declined"` → `false` only when `funded`. In `sweep`, a lease expired without a result → `note_outcome(scanner, false)`; with a result → `true`.

`scans_last_hour` counts only this arbiter's grants: add `AND arbiter = ?` bound to `self.node.id()`.

`hand_out`: replace the load sort:

```rust
        let table = self.node.price_table();
        let now = Instant::now();
        let mut keyed = vec![];
        for w in waiters {
            let s = w.0;
            let price = crate::credits::jobs::price_for(&self.node, &s);
            let demoted = over_capacity(load[&s], table.can_do(&s))
                || !self.outcomes.lock().unwrap().get(&s).is_none_or(|o| delivers(o, now));
            keyed.push((claim_order(price, demoted, load[&s], s), w));
        }
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
        let waiters: Vec<Waiter> = keyed.into_iter().map(|(_, w)| w).collect();
```

The grant loop stays (one round, `funding` carried).

- [ ] **Step 4: Run tests**

Run: `cargo test --lib scan::arbiter 2>&1 | tail -5` → pass. Clippy clean.

- [ ] **Step 5: Commit** — `Scans: an arbiter hands each job to the cheapest scanner; hoarding and non-delivering scanners go last` plus the trailer.

---

### Task 5: The scanner asks arbiters that can pay first, in urgency order

**Files:**
- Modify: `src/scan/mod.rs:140-158` (`funded_first` → `can_pay_first`), `:525-560` (`acquire_granted`), `Source` (new field `demoted`), the grant loop (demotion), tests at `:2158`

**Interfaces:**
- Consumes: `price::min_take`, `jobs::budget`, `jobs::self_committed`, `Heartbeat::{scan_budget_mc, scan_queued}`, `pay::sells_scans`.
- Produces: `fn can_pay_first(arbiters: Vec<NodeId>, can_pay: impl Fn(&NodeId) -> bool) -> Vec<NodeId>`

- [ ] **Step 1: Write the failing test** (replace `funded_arbiters_are_asked_first_best_paying_first`):

```rust
#[test]
fn arbiters_that_can_pay_are_asked_first_in_urgency_order() {
    let (a, b, c, d) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]), NodeId([4; 32]));
    // Urgency order a, b, c, d; b and d can pay.
    let order = can_pay_first(vec![a, b, c, d], |n| *n == b || *n == d);
    assert_eq!(order, vec![b, d, a, c]);
}
```

- [ ] **Step 2: Run, expect failure.**

Run: `cargo test --lib scan::tests::arbiters_that_can_pay 2>&1 | tail -5`

- [ ] **Step 3: Implement.**

```rust
/// `arbiters` (in urgency order) with those that can pay this scanner's
/// price first; each group keeps its order. Price differences between
/// arbiters do not reorder anything: the scanner names the price.
fn can_pay_first(arbiters: Vec<NodeId>, can_pay: impl Fn(&NodeId) -> bool) -> Vec<NodeId> {
    let (mut first, rest): (Vec<_>, Vec<_>) = arbiters.into_iter().partition(|a| can_pay(a));
    first.extend(rest);
    first
}
```

`Source` gets `demoted: std::sync::Mutex<HashMap<NodeId, Instant>>` (default empty), with doc `/// Arbiters asked as able to pay that granted unpaid: asked with the others until then.` and `const DEMOTE_FOR: Duration = Duration::from_secs(3600);`.

In `acquire_granted`, replace the `funded_first(...)` block and `min_mc`:

```rust
        let me = node.id();
        let sell = node.price_table().price_of(crate::credits::price::SCAN);
        let book = crate::credits::book(node).await?;
        let own_left = match sell {
            Some(_) => crate::credits::jobs::budget(
                &book.ledger, &me, node.scan_share(),
                crate::credits::jobs::self_committed(&node.store.pool, &me).await?,
            ),
            None => 0,
        };
        let demoted: HashSet<NodeId> = {
            let mut d = self.demoted.lock().unwrap();
            d.retain(|_, until| *until > Instant::now());
            d.keys().copied().collect()
        };
        let can_pay = |a: &NodeId| -> bool {
            let Some(price) = sell.map(|p| p as u64) else { return false };
            if *a == me {
                return own_left >= price;
            }
            if demoted.contains(a)
                || !node.members().get(a).is_some_and(|m| crate::credits::pay::sells_scans(m.proto_max))
            {
                return false;
            }
            node.status.known(a).is_some_and(|k| {
                k.hb.scan_queued > 0 && (k.hb.scan_budget_mc as u64).min(book.balance(a)) >= price
            })
        };
        let asked_as_paying: HashSet<NodeId> = arbiters.iter().filter(|a| can_pay(a)).copied().collect();
        let arbiters = can_pay_first(arbiters, can_pay);
        let min_mc = sell.map_or(0, crate::credits::price::min_take);
```

After a grant `g` arrives from `arbiter` (right after `let Some(g) = grant else { continue };`):

```rust
            if arbiter != me && g.offer_seq.is_none() && asked_as_paying.contains(&arbiter) {
                // Announced it could pay, then granted unpaid (or offered
                // under our least): asked with the others for an hour.
                self.demoted.lock().unwrap().insert(arbiter, Instant::now() + DEMOTE_FOR);
            }
```

(Use the imports already in the file; add `HashSet` if missing.)

- [ ] **Step 4: Run tests**

Run: `cargo test --lib scan 2>&1 | tail -5` → pass. Clippy clean.

- [ ] **Step 5: Commit** — `Scans: a scanner asks arbiters that can pay its price first, in urgency order` plus the trailer.

---

### Task 6: No collecting node; a lookup draws from the richest siblings

**Files:**
- Modify: `src/credits/fleet.rs` (delete `collect`, `COLLECT_EVERY`, the forwarding loop at ~153-179; `draw` asks siblings richest first)
- Modify: `src/credits/pay.rs:300-315` (`make_offer` calls the new `draw`)
- Modify: `src/cluster/mod.rs:283-286, 357` (delete `collect_to`)
- Modify: `src/cluster/msg.rs:130-135` (doc of `CreditDraw`: "a sibling → a sibling")
- Modify: `src/settings.rs` (delete `KEY_COLLECT_TO`, `collect_to` in `Changes`, `Snapshot`, `Settings`, validation, describe, merge, persistence and the test `the_collecting_node_is_a_runtime_setting`), `src/settings_cli.rs:80-86`
- Modify: `src/cluster/owner/cmd.rs:128, 307` (status no longer reports it)
- Modify: `src/admin/cluster_owner.rs` (delete `collect_here` and its route; `:193-215` where the page reads it), `src/admin/cluster.rs:187-206, 909-936, 1183, 1611` (delete `collect_options` and its test)
- Modify: `templates/admin_cluster_ownership.html:85`, `templates/admin_cluster_node.html:90-92, 130`, `templates/_node_settings.html:7`, `templates/admin_cluster_credits.html:93`
- Create: `src/store/migrations/0024_no_collecting_node.sql`
- Modify: `tests/cluster.rs` (delete `collecting_credits_here_tells_the_siblings_and_shows_where_credits_go` and `a_fleet_collects_at_one_node_and_any_of_its_nodes_can_spend`; rewrite `a_node_draws_what_a_lookup_needs_from_its_collecting_node`)

**Interfaces:**
- Produces:
  - `pub fn draw_order(siblings: &[NodeId], balance: impl Fn(&NodeId) -> Mc) -> Vec<NodeId>`
  - `pub async fn draw(node: &Arc<Node>, mc: Mc) -> bool` (same signature; asks siblings richest first)

- [ ] **Step 1: Write the failing unit test** (in `fleet.rs` tests):

```rust
#[test]
fn a_lookup_draws_from_the_richest_sibling_first() {
    let (a, b, c) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]));
    let bal = |n: &NodeId| match n.0[0] { 1 => 50, 2 => 900, _ => 0 };
    assert_eq!(draw_order(&[a, b, c], bal), vec![b, a], "richest first; nothing to give: not asked");
    assert!(draw_order(&[], bal).is_empty());
}
```

- [ ] **Step 2: Run, expect failure.**

Run: `cargo test --lib credits::fleet 2>&1 | tail -5`

- [ ] **Step 3: Implement** in `fleet.rs`. Module doc:

```rust
//! A fleet (the nodes of one owner) proves ownership. Its one economic
//! effect: a node whose lookup needs more than it holds draws the missing
//! credits from its siblings, the richest first. Every node keeps what it
//! earns; scans are paid from the node's own balance only.
```

```rust
/// Siblings to draw from: those holding anything, the richest first
/// (ties by key, so the order is stable).
pub fn draw_order(siblings: &[NodeId], balance: impl Fn(&NodeId) -> Mc) -> Vec<NodeId> {
    let mut v: Vec<(Mc, NodeId)> = siblings
        .iter()
        .map(|s| (balance(s), *s))
        .filter(|(b, _)| *b > 0)
        .collect();
    v.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    v.into_iter().map(|(_, s)| s).collect()
}

/// Draw `mc` from this node's siblings, the richest first, until it is
/// covered, and wait for the transfers to arrive. False: no sibling gave
/// enough.
pub async fn draw(node: &Arc<Node>, mc: Mc) -> bool {
    let me = node.id();
    let Ok(book) = super::book_fresh(node).await else { return false };
    let start = book.balance(&me);
    let siblings = crate::cluster::owner::fleet::siblings(&node.store).await.unwrap_or_default();
    let siblings: Vec<NodeId> = siblings.into_iter().filter(|s| *s != me && !node.is_blocked(s)).collect();
    let mut missing = mc;
    for from in draw_order(&siblings, |s| book.balance(s)) {
        let ask = missing.min(book.balance(&from)).min(u32::MAX as Mc) as u32;
        let avoid = crate::cluster::owner::cmd::old_relays(node, &from);
        let sent = match node
            .request_avoiding(from, Msg::CreditDraw { mc: ask as Mc }, DRAW_WAIT, avoid)
            .await
        {
            Ok(Msg::CreditDrawReply { sent_mc }) => sent_mc,
            _ => 0,
        };
        if sent == 0 {
            continue;
        }
        // The transfer is an entry of the sibling's log: fetch it.
        if let Some(addr) = node.dial_address(&from) {
            let _ = crate::cluster::sync::reconcile(node, from, &addr, false).await;
        }
        missing = missing.saturating_sub(sent);
        if missing == 0 {
            break;
        }
    }
    // Wait until the book holds what arrived.
    let until = tokio::time::Instant::now() + DRAW_WAIT;
    loop {
        if let Ok(b) = super::book_fresh(node).await
            && b.balance(&me) >= start + mc.saturating_sub(missing)
        {
            return missing == 0;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
```

Check the `CreditDraw { mc }` field type in `msg.rs` and match it (the current code passes `mc` straight through). Keep `serve` unchanged: it already answers siblings only. Delete `collect`, `COLLECT_EVERY`, `receivable` if only `collect` used it (`send` uses it too: keep it then), and the loop that kept `collect_to` in step with settings (`~153-179`) together with its spawn in `main.rs`/`lib.rs` (find it with `grep -rn "fleet::run\|fleet::keep" src`).

`pay.rs:306`: the comment becomes `// Draw what is missing from the siblings, the richest first.`; the call stays `super::fleet::draw(node, missing)`.

Migration `0024_no_collecting_node.sql`:

```sql
-- Fleets: nothing is forwarded to a collecting node any more; every node
-- keeps what it earns and a lookup draws from its siblings.
DELETE FROM settings WHERE key = 'credits.collect_to';
```

Remove the setting everywhere listed under **Files**. `Changes` and `Snapshot` derive `Deserialize`. Check they do not use `deny_unknown_fields` (`grep -n deny_unknown src/settings.rs src/cluster/owner/cmd.rs`). If they don't, an older sibling sending `collect_to` in an owner command is ignored. If they do, keep the field as `#[serde(default, skip_serializing)] collect_to: Option<String>` with a comment `/// Sent by nodes before fleets lost their collecting node; ignored.`

- [ ] **Step 4: Rewrite the integration test** `a_node_draws_what_a_lookup_needs_from_its_collecting_node` → `a_lookup_draws_from_the_richest_sibling`. Same setup with three siblings a, b, c (adopt c like b). Then:
  - `grant_scans(&[&na, &nb, &nc, &ns], a.id, 8)` (a is rich);
  - `grant_scans(&[&na, &nb, &nc, &ns], c.id, 1)` (c is poorer; adjust the expected balances with `minted(8, 9)` and `minted(1, 9)`);
  - delete the `collect_to` line.
  
  Assert the stranger's draw is still unanswered, the lookup on b succeeds, and in `ns`'s book: `book.balance(&a.id) == minted(8, 9) - cost`, `book.balance(&c.id) == minted(1, 9)`, `book.balance(&b.id) == 0`.

- [ ] **Step 5: Run tests**

Run: `cargo test --lib credits::fleet settings 2>&1 | tail -5`, then `cargo test --test cluster a_lookup_draws_from_the_richest_sibling fleet 2>&1 | tail -5` → pass. `grep -rn "collect_to\|collecting node\|Collect credits" src templates tests` → only the migration and, if kept, the ignored serde field. Clippy clean.

- [ ] **Step 6: Commit** — `Fleets: no collecting node; a lookup draws from the richest siblings` plus the trailer.

---

### Task 7: Integration tests, pages and docs

**Files:**
- Modify: `tests/cluster.rs:4960-5040` (`a_funded_scan_job_pays_the_scanner_its_price`), add two tests
- Modify: `src/admin/credits.rs` (PR #49's dashboard: scan tile, per-scanner table), `templates/admin_cluster_credits.html`, `src/admin/overview.rs`
- Modify: `docs/cluster.md` (Credits: "Prices", "Scan jobs", "What this cannot do", "Upgrading"), `CHANGELOG.md` (Unreleased)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Update the existing integration test.** In `a_funded_scan_job_pays_the_scanner_its_price`, the price now comes from the scanner. Replace the block from `// A kept price to start from` through `assert!(cost > 1, "{cost}");` with:

```rust
    // A kept copy of b's price on both nodes, so it is more than the floor
    // and a's reference agrees with b's selling price.
    let key = format!("price:scan:{}", b.id);
    na.store.intel_set(&key, "1000").await.unwrap();
    nb.store.intel_set(&key, "1000").await.unwrap();
    let sell = price::refresh(&nb.node).await.unwrap().price_of(price::SCAN).unwrap();
    price::refresh(&na.node).await.unwrap();
    eventually("a hears b's selling price", || async {
        na.node.status.known(&b.id).and_then(|k| k.hb.scan_price_mc) == Some(sell)
    })
    .await;
    let cost = peephole::credits::jobs::price_for(&na.node, &b.id).unwrap() as u64;
    assert!(cost > 1, "{cost}");
```

The rest of the test stays.

- [ ] **Step 2: Add the inflated-price test** right after it:

```rust
/// A scanner that announces more than the rule gives is paid the
/// arbiter's reference price, capped at PRICE_TOLERANCE.
#[tokio::test]
async fn an_inflated_scanner_price_is_paid_at_the_reference() {
    use peephole::credits::{self, price};
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], Opts { scanner: Some(fake_nmap_args(tools.path())), ..DEFAULT }).await;
    grant_scans(&[&na, &nb], a.id, 8).await;
    market_known(&na, b.id).await;
    market_known(&nb, a.id).await;
    na.node.set_scan_share(0.5);
    let key = format!("price:scan:{}", b.id);
    na.store.intel_set(&key, "1000").await.unwrap();
    nb.store.intel_set(&key, "50000").await.unwrap(); // b claims far more
    let sell = price::refresh(&nb.node).await.unwrap().price_of(price::SCAN).unwrap();
    let reference = price::refresh(&na.node).await.unwrap().reference(&b.id).unwrap();
    eventually("a hears b's selling price", || async {
        na.node.status.known(&b.id).and_then(|k| k.hb.scan_price_mc) == Some(sell)
    })
    .await;
    let paid = credits::jobs::price_for(&na.node, &b.id).unwrap();
    assert_eq!(paid, (reference as f64 * price::PRICE_TOLERANCE).floor() as u32);
    assert!(paid < sell);
}
```

Note: b's `min_take(sell)` is then far above `paid`, so `fund` grants unpaid. That is the intended outcome (the spec's §3) and needs no scan in this test.

- [ ] **Step 3: Add the two-scanner test** (cheaper gets the job):

```rust
/// With two scanners asking, the arbiter grants to the cheaper one.
#[tokio::test]
async fn the_cheaper_scanner_gets_the_job() {
    use peephole::credits::price;
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let scanner = || Opts { scanner: Some(fake_nmap_args(tools.path())), ..DEFAULT };
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], scanner()).await;
    let nc = boot(ic, &c, &[&a, &b], scanner()).await;
    grant_scans(&[&na, &nb, &nc], a.id, 8).await;
    for (n, of) in [(&na, b.id), (&na, c.id), (&nb, a.id), (&nc, a.id)] {
        market_known(n, of).await;
    }
    na.node.set_scan_share(0.5);
    for (who, mc) in [(b.id, "3000"), (c.id, "1000")] {
        let key = format!("price:scan:{who}");
        for n in [&na, &nb, &nc] {
            n.store.intel_set(&key, mc).await.unwrap();
        }
    }
    for n in [&nb, &nc, &na] {
        price::refresh(&n.node).await.unwrap();
    }
    eventually("a hears both prices", || async {
        [b.id, c.id].iter().all(|s| na.node.status.known(s).and_then(|k| k.hb.scan_price_mc).is_some())
    })
    .await;
    enqueue(&na, "198.51.100.42", 1).await;
    eventually_for(Duration::from_secs(40), "scanned", || async {
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
    })
    .await;
    assert_eq!(scans_by(&na, c.id).await, 1, "the cheaper scanner ran it");
}
```

Both scanners must be asking within the same claim window for the price order to decide. If the test is flaky because `b` claims alone first, make `b` slower to claim by giving it `Opts { scan_interval: ... }` if such an option exists in the harness (check `Opts` in `tests/cluster.rs`). Otherwise assert over 4 jobs that `c` ran at least 3, and say so in the test's doc comment.

- [ ] **Step 4: Run integration tests**

Run: `cargo test --test cluster funded_scan inflated cheaper_scanner 2>&1 | tail -8` → pass.
Then `cargo test --test cluster 2>&1 | tail -5`. Fix any other test that read `scan_mc` or `scan_bids` the same way as in Task 1 Step 7.

- [ ] **Step 5: Pages.** In `src/admin/credits.rs` (PR #49 code), replace the price view's `scan: String, scan_bids: u32` with:

```rust
    /// This node's selling price; a dash when it does not scan.
    scan: String,
    /// Its paid scans of the past hour, and its target.
    scan_paid: String,
    scan_target: String,
    /// Every scanner: name, announced price, this node's reference price,
    /// paid scans of the past hour against its target.
    scanners: Vec<(String, String, String, String)>,
```

Fill them from `t.sell_mc`, `t.scanners` (with `node.status.known(&s.node).and_then(|k| k.hb.scan_price_mc)` for the announced price and the member's name from `node.members()`). In `templates/admin_cluster_credits.html`:
- Scan tile hint: `{% if price.scan == "–" %}not a scanner{% else %}its selling price · {{ price.scan_paid }} paid of {{ price.scan_target }} an hour{% endif %}`.
- Line 30's bullet: `This node sells a funded scan job for <b>{{ price.scan }}</b> credits; each scanner prices itself by how busy it is with paid work.`
- A table under "What things cost here": columns Scanner, Announces, Reference here, Paid / target an hour, one row per `price.scanners`.

Update the template-rendering unit test in `credits.rs` (~line 678) to the new fields, and add an assertion that a `scan` of `"–"` renders `not a scanner`. In `overview.rs`, keep Task 1's replacement.

- [ ] **Step 6: Docs.** In `docs/cluster.md`, Credits section:
  - "Prices": scan prices are per scanner. Each scanner's price follows its paid scans of the past hour against 90 % of its capacity. Every node computes every scanner's price from the log and the heartbeats, and pays at most 1.25 times its own figure.
  - "Scan jobs": the arbiter hands each job to the cheapest scanner asking. A scanner asks arbiters that can pay its price first, in urgency order. A node's own jobs are funded from the same budget without moving credits. Hoarding scanners (over their hourly capacity, or delivering less than half of 5 recent grants) go last.
  - "What this cannot do": add understated capacity, a lone dishonest scanner at start, and capacity withdrawal (the spec's §9 items).
  - "Upgrading": `Protocol 5: scan jobs are paid only between nodes on protocol 5; upgrade all nodes together.`
  - Ownership/fleet text in `docs/cluster.md`: remove "Your nodes as one" (collecting node) and the limit about a broken-into sibling spending the collecting node. Instead: "A lookup that needs more than a node holds draws from its siblings, richest first; a sibling broken into can draw from the others."
  - CHANGELOG Unreleased, under "Changed", one bullet per spec section: scanner prices, cheapest scanner, own jobs, fleets without a collecting node, protocol 5. Under "Removed": `credits.collect_to` and "Collect credits here".

- [ ] **Step 7: Full verification**

```bash
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test 2>&1 | tail -15
```

Expected: all pass. Paste the summary lines into the PR description.

- [ ] **Step 8: Commit** — `Credits: scanner prices on the Credits page, docs and changelog` plus the trailer.
