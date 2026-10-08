# Reliability Pricing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An arbiter hands each scan job to the scanner that is cheapest per *delivered* result at the job's level, waits up to 30 min for a cheaper live one, and shows why a job went where.

**Architecture:** Pure ranking and reserve logic in a new `src/scan/rank.rs`; the grant record and its wording in a new `src/scan/handout.rs` over a local table `job_handouts`; `Arbiter::hand_out` becomes a job-major `round` that uses both. Weights come from an hourly snapshot cached on the `Node`. Prices refresh every 10 minutes (one-line change; steps already scale with time).

**Tech Stack:** Rust, tokio, sqlx/SQLite, askama templates.

**Spec:** `docs/superpowers/specs/2026-10-08-reliability-pricing-design.md`

## Global Constraints

- `effective(s, L) = price_for(s) / weight(s, L)`; no price → `u32::MAX`.
- Rank eligible claimants by `(demoted, effective, load, key)`.
- Paid jobs: no sit-out draws. Unpaid jobs: the sit-out draws stay (unless the job waited `OVERRIDE_WAIT_MINS`).
- Reserve: scanners live for this arbiter, not demoted, not over capacity, `>= MIN_SAMPLE` scans at `L` in the snapshot. `OVERRIDE_WAIT_MINS` (30) ends the wait.
- Weight snapshot of hour `H` = scans finished in `[H − 24 h, H)`, taken at `H + 5 min`.
- Price refresh every 10 minutes (`ticks % 10 == 1`); `price_history` keeps one point per hour.
- `job_handouts`: local, not replicated, pruned after 8 days.
- No protocol change.
- Never edit the spec; document in `docs/cluster.md` and `CHANGELOG.md`.
- Text on pages: plain, short sentences, like the existing templates.

## Review Focus

1. **Head-of-queue starvation.** Jobs every claimant already handed back, or held for the reserve, must not hide the jobs behind them: a lone weak scanner still gets an L1 job while L4 jobs wait for the reserve. (Test in Task 5: `held_jobs_do_not_hide_the_ones_behind`.) The spec's bound of `4 × claimants` jobs would starve here; the round reads up to `ROUND_JOBS` (500) jobs, filters the uids and levels every claimant rules out in SQL, and stops once every claimant has a job.
2. **A reserve scanner that would never take the job** (it declined it, or is its last failer within `LAST_FAILER_WAIT`, or is a claimant that excludes the level) must not hold it back. (Test in Task 3: `a_scanner_that_cannot_take_the_job_sets_no_reserve`.)
3. **Two claims from the same scanner in one round** (several idle workers) each get a job; "given a job this round" is per claim, not per scanner. (Test in Task 5: `two_claims_of_one_scanner_get_two_jobs`.)
4. **Huge prices / tiny weights:** `price / 0.1` must not overflow `u32`. (Test in Task 3: `effective_saturates`.)
5. **Snapshot boundary:** a scan finished at 14:59 counts in the snapshot of 15:00, which is taken only from 15:05; the 14:00 snapshot holds until then. (Test in Task 1.)

## Coordination note

`docs/superpowers/plans/2026-10-08-probe-unrestricted-paid-scan.md` (Task 4) also adds migration `0026`, and its Task 6 edits `next_job_for`, which this plan removes. Whichever lands second renumbers its migration to the next free number and, for Task 6, scales the price passed to `fund` in `Arbiter::grant` by `level_factor(level)` for manual jobs (all scanners alike, so ranking and reserve are unchanged).

---

### Task 1: Hourly weight snapshot

**Files:**
- Modify: `src/scan/weight.rs` (tallies over a fixed window, `Snapshot`, `Weights` cache)
- Modify: `src/cluster/mod.rs` (field `weights` on `Node`, next to `market`)
- Modify: `src/admin/cluster.rs:274` (pace row reads the snapshot)

**Interfaces:**
- Produces:
  - `pub async fn weight::tallies_before(pool: &SqlitePool, hour: i64) -> Result<Tallies>` — scans finished in `[hour − 24 h, hour)`, `hour` = Unix seconds / 3600.
  - `pub fn weight::due_hour(unix_secs: u64) -> i64` — `(unix_secs − 300) / 3600`.
  - `pub struct weight::Snapshot { pub hour: i64, pub tallies: Tallies }`
  - `pub struct weight::Weights` (Default) with `pub async fn get(&self, pool: &SqlitePool) -> Result<Arc<Snapshot>>`.
  - `Node.weights: crate::scan::weight::Weights`.
  - `pub fn weight::unix_now() -> u64`.

- [ ] **Step 1: Failing tests** in `weight.rs` tests:

```rust
#[test]
fn the_snapshot_of_an_hour_is_due_five_minutes_after_it() {
    let h = 500_000i64;
    let at = |s: i64| (h * 3600 + s) as u64;
    assert_eq!(due_hour(at(0)), h - 1);
    assert_eq!(due_hour(at(299)), h - 1);
    assert_eq!(due_hour(at(300)), h);
    assert_eq!(due_hour(at(3599)), h);
}

#[tokio::test]
async fn a_snapshot_counts_the_24_hours_before_its_hour() {
    let dir = tempfile::tempdir().unwrap();
    let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
    let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
    let h = 500_000i64;
    // seconds relative to the start of hour h
    for (status, rel) in [("done", -1i64), ("done", 0), ("done", -24 * 3600), ("failed", -24 * 3600 - 1)] {
        s.enqueue_scan(ip.id, 4, 0).await.unwrap();
        sqlx::query(
            "UPDATE scan_jobs SET status = ?, error = 'nmap exited 1', scanner = ?,
                    finished_at = datetime(?, 'unixepoch')
             WHERE id = (SELECT MAX(id) FROM scan_jobs)",
        )
        .bind(status)
        .bind(&id(7).0[..])
        .bind(h * 3600 + rel)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    let t = tallies_before(&s.pool, h).await.unwrap();
    // 14:59:59 and exactly 24 h before count; 15:00:00 and older do not.
    assert_eq!(t[&(id(7), 4)], Tally { ok: 2, failed: 0 });
    // The same rows give the same snapshot on any node.
    assert_eq!(tallies_before(&s.pool, h).await.unwrap(), t);
}
```

- [ ] **Step 2:** `cargo test --lib scan::weight` → fails to compile.

- [ ] **Step 3: Implement.** Replace `tallies` with `tallies_before` (the `finished_at > datetime('now', ...)` filter becomes `finished_at >= datetime(?1, 'unixepoch') AND finished_at < datetime(?2, 'unixepoch')` with `(hour − WINDOW_HOURS) * 3600` and `hour * 3600`). Update the existing `tallies_count_hard_failures_only_within_the_window` test to call `tallies_before(&s.pool, due_hour(unix_now()) + 1)` with ages of `-1 hours`/`-30 hours` (still: 1 ok, 1 failed).

```rust
/// Minutes after the hour its snapshot is taken: scans finished just
/// before it have replicated by then.
const SNAPSHOT_DELAY_SECS: u64 = 300;

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The hour whose snapshot holds at `unix_secs`.
pub fn due_hour(unix_secs: u64) -> i64 {
    (unix_secs.saturating_sub(SNAPSHOT_DELAY_SECS) / 3600) as i64
}

/// The tallies of the 24 hours before `hour` (UTC, Unix hours).
#[derive(Debug, Default)]
pub struct Snapshot {
    pub hour: i64,
    pub tallies: Tallies,
}

/// The snapshot in force, computed again once the next one is due.
#[derive(Default)]
pub struct Weights(tokio::sync::Mutex<Option<Arc<Snapshot>>>);

impl Weights {
    pub async fn get(&self, pool: &SqlitePool) -> Result<Arc<Snapshot>> {
        let hour = due_hour(unix_now());
        let mut g = self.0.lock().await;
        if let Some(s) = g.as_ref().filter(|s| s.hour == hour) {
            return Ok(s.clone());
        }
        let s = Arc::new(Snapshot { hour, tallies: tallies_before(pool, hour).await? });
        *g = Some(s.clone());
        Ok(s)
    }
}
```

Add `pub weights: crate::scan::weight::Weights,` to `Node` and `weights: Default::default(),` in its constructor. Update the module doc: weights are measured once an hour. In `src/admin/cluster.rs` replace `crate::scan::weight::tallies(&node.store.pool).await?` by `node.weights.get(&node.store.pool).await?` and read `.tallies` from it. The arbiter's `skipped_levels` call site is rewritten in Task 5; until then change it to `self.node.weights.get(..).await?.tallies` so the tree builds.

- [ ] **Step 4:** `cargo test --lib scan::weight scan::arbiter admin::cluster` → PASS.
- [ ] **Step 5: Commit** `Scan weights: measured once an hour`.

---

### Task 2: Prices every 10 minutes

**Files:**
- Modify: `src/credits/mod.rs:235-240`
- Test: `src/credits/price.rs` tests, `src/credits/history.rs` tests

- [ ] **Step 1: Failing/pinning tests** in `price.rs` tests:

```rust
#[test]
fn six_ten_minute_steps_move_a_price_like_one_hourly_step() {
    for (paid, can_do) in [(0.0, 10.0), (10.0, 10.0), (4.0, 10.0)] {
        let hourly = scanner_step(1_000_000, paid, can_do, 1.0);
        let mut p = 1_000_000;
        for _ in 0..6 {
            p = scanner_step(p, paid, can_do, 1.0 / 6.0);
        }
        let diff = (p as f64 - hourly as f64).abs() / hourly as f64;
        assert!(diff < 0.002, "paid {paid}: {p} vs {hourly}");
    }
}
```

and in `history.rs` tests (if no such test exists yet) one that two `record` calls with the same `hour` and good leave one row holding the second values.

- [ ] **Step 2:** run `cargo test --lib credits::price credits::history`. If the step test fails, the step rule is not time-consistent and must be looked at before going on (stop and report).
- [ ] **Step 3:** In `src/credits/mod.rs` change the comment and condition:

```rust
        // At the start (once the first heartbeats are in) and every 10
        // minutes: steps scale with the time since the last one.
        if ticks % 10 == 1
```

- [ ] **Step 4:** `cargo test --lib credits` → PASS.
- [ ] **Step 5: Commit** `Prices: refresh every 10 minutes`.

---

### Task 3: Ranking and reserve (pure)

**Files:**
- Create: `src/scan/rank.rs` (add `pub mod rank;` in `src/scan/mod.rs`)

**Interfaces:**
- Produces:
  - `pub fn effective(price: Option<u32>, weight: f64) -> u32`
  - `pub struct Bid { pub id: NodeId, pub price: Option<u32>, pub weight: f64, pub demoted: bool, pub load: i64 }` with `pub fn effective(&self) -> u32`
  - `pub fn rank(bids: &mut [Bid])` — sorts by `(demoted, effective, load, id)`.
  - `pub struct Standby { pub id: NodeId, pub price: Option<u32>, pub weight: f64, pub sample: i64 }` — a live, non-demoted, under-capacity scanner, with its finished scans at the level.
  - `pub fn reserve(standby: &[Standby]) -> Option<u32>` — lowest effective among those with `sample >= MIN_SAMPLE` and a price.
  - `pub fn waits(best: u32, reserve: Option<u32>, waited_secs: i64) -> Wait` with `pub enum Wait { Go, Hold, Override }`.

- [ ] **Step 1: Failing tests** (in `rank.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    fn id(b: u8) -> NodeId { NodeId([b; 32]) }
    fn bid(b: u8, price: u32, weight: f64, demoted: bool, load: i64) -> Bid {
        Bid { id: id(b), price: Some(price), weight, demoted, load }
    }

    #[test]
    fn the_cheapest_per_delivered_result_wins() {
        // Fast asks 30, delivers all; Flaky asks 20, half at L4, all at L1.
        let mut l4 = vec![bid(2, 20, 0.5, false, 0), bid(1, 30, 1.0, false, 9)];
        rank(&mut l4);
        assert_eq!(l4[0].id, id(1));
        let mut l1 = vec![bid(2, 20, 1.0, false, 0), bid(1, 30, 1.0, false, 0)];
        rank(&mut l1);
        assert_eq!(l1[0].id, id(2));
    }

    #[test]
    fn demoted_last_then_load_then_key() {
        let mut v = vec![
            bid(1, 5, 1.0, true, 0),
            bid(2, 40, 1.0, false, 3),
            bid(3, 40, 1.0, false, 1),
            Bid { id: id(4), price: None, weight: 1.0, demoted: false, load: 0 },
        ];
        rank(&mut v);
        let order: Vec<NodeId> = v.iter().map(|b| b.id).collect();
        assert_eq!(order, vec![id(3), id(2), id(4), id(1)]);
    }

    #[test]
    fn effective_saturates() {
        assert_eq!(effective(Some(u32::MAX), 0.1), u32::MAX);
        assert_eq!(effective(None, 1.0), u32::MAX);
        assert_eq!(effective(Some(20), 0.5), 40);
    }

    #[test]
    fn the_reserve_needs_a_record_at_the_level() {
        let s = |b: u8, price: u32, weight: f64, sample: i64| Standby { id: id(b), price: Some(price), weight, sample };
        assert_eq!(reserve(&[s(1, 30, 1.0, 10), s(2, 10, 1.0, 4)]), Some(30));
        assert_eq!(reserve(&[s(2, 10, 1.0, MIN_SAMPLE - 1)]), None);
        assert_eq!(reserve(&[]), None);
    }

    #[test]
    fn a_paid_job_waits_for_a_cheaper_scanner_until_the_override() {
        assert_eq!(waits(40, Some(30), 0), Wait::Hold);
        assert_eq!(waits(40, Some(30), OVERRIDE_WAIT_MINS * 60), Wait::Override);
        assert_eq!(waits(30, Some(30), 0), Wait::Go);
        assert_eq!(waits(40, None, 0), Wait::Go);
    }
}
```

(Review Focus 2 — who may stand by for a job — is decided where `Standby` lists are built, in Task 5, and tested there as `a_scanner_that_cannot_take_the_job_sets_no_reserve`.)

- [ ] **Step 2:** `cargo test --lib scan::rank` → fails to compile.
- [ ] **Step 3: Implement:**

```rust
//! Ranking scanners for a scan job by what one delivered result costs:
//! a failed scan is not paid, so a scanner's price buys a result only as
//! often as it delivers (its `weight` at the job's level). A paid job
//! waits for a cheaper live scanner (the reserve) up to
//! [`OVERRIDE_WAIT_MINS`]: the buyer's patience.
use super::weight::{MIN_SAMPLE, OVERRIDE_WAIT_MINS};
use crate::cluster::identity::NodeId;

/// `price / weight` in millicredits; no price: never cheaper than a priced one.
pub fn effective(price: Option<u32>, weight: f64) -> u32 {
    match price {
        Some(p) => (p as f64 / weight.max(super::weight::MIN_WEIGHT)).round().min(u32::MAX as f64) as u32,
        None => u32::MAX,
    }
}

/// A claimant of a round, as it stands for one job.
#[derive(Debug, Clone)]
pub struct Bid { pub id: NodeId, pub price: Option<u32>, pub weight: f64, pub demoted: bool, pub load: i64 }

impl Bid {
    pub fn effective(&self) -> u32 { effective(self.price, self.weight) }
}

/// Not demoted first, then cheapest per delivered result, fewest recent
/// scans, key.
pub fn rank(bids: &mut [Bid]) {
    bids.sort_by_key(|b| (b.demoted, b.effective(), b.load, b.id));
}

/// A live scanner that could take the job but is not asking right now.
#[derive(Debug, Clone)]
pub struct Standby { pub id: NodeId, pub price: Option<u32>, pub weight: f64, pub sample: i64 }

/// The cheapest per delivered result among scanners with a record at the level.
pub fn reserve(standby: &[Standby]) -> Option<u32> {
    standby.iter().filter(|s| s.sample >= MIN_SAMPLE && s.price.is_some())
        .map(|s| effective(s.price, s.weight)).min()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Wait { Go, Hold, Override }

pub fn waits(best: u32, reserve: Option<u32>, waited_secs: i64) -> Wait {
    match reserve {
        Some(r) if r < best && waited_secs >= OVERRIDE_WAIT_MINS * 60 => Wait::Override,
        Some(r) if r < best => Wait::Hold,
        _ => Wait::Go,
    }
}
```

- [ ] **Step 4:** `cargo test --lib scan::rank` → PASS.
- [ ] **Step 5: Commit** `Scan jobs: rank scanners by price per delivered result`.

---

### Task 4: The hand-out record

**Files:**
- Create: `src/store/migrations/0026_job_handouts.sql`; register in `src/store/mod.rs` `MIGRATIONS`.
- Create: `src/scan/handout.rs` (add `pub mod handout;` in `src/scan/mod.rs`).

**Interfaces:**
- Produces:
  - `pub enum Reason { Cheapest, Override, Unpaid }` (`as_str`/`parse`: `cheapest`, `override`, `unpaid`).
  - `pub struct Handout { pub job_uid: String, pub scanner: NodeId, pub level: i64, pub paid: bool, pub price_mc: Option<u32>, pub rate: f64, pub effective_mc: u32, pub next: Option<(NodeId, u32)>, pub waited_secs: i64, pub reason: Reason, pub sat_out: i64 }`
  - `pub async fn record(pool: &SqlitePool, h: &Handout) -> Result<()>` — insert, then delete rows older than 8 days.
  - `pub async fn latest(pool: &SqlitePool, job_uids: &[String]) -> Result<HashMap<String, Handout>>` — the latest row per job.
  - `pub fn describe(h: &Handout, name: &dyn Fn(&NodeId) -> String) -> String`
  - `pub fn names(node: &Node) -> impl Fn(&NodeId) -> String`

Migration:

```sql
-- Why the arbiter gave each scan job to the scanner it did, for the scan
-- page and the Scans history. Local only (only the arbiter decides);
-- one row per grant, kept for 8 days.
CREATE TABLE job_handouts (
  id INTEGER PRIMARY KEY,
  job_uid TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (datetime('now')),
  scanner BLOB NOT NULL,
  level INTEGER NOT NULL,
  paid INTEGER NOT NULL,
  price_mc INTEGER,             -- NULL: the scanner has no price here
  rate REAL NOT NULL,           -- its weight at the level
  effective_mc INTEGER NOT NULL,
  next_scanner BLOB,            -- the next best claimant, if any
  next_effective_mc INTEGER,
  waited_secs INTEGER NOT NULL, -- held for the reserve (cheapest) or queued (override)
  reason TEXT NOT NULL,         -- cheapest, override, unpaid
  sat_out INTEGER NOT NULL DEFAULT 0  -- unpaid: claimants that sat the level out
);
CREATE INDEX job_handouts_job ON job_handouts(job_uid, id);
CREATE INDEX job_handouts_at ON job_handouts(at);
```

(`sat_out` is beyond the spec's column list: it decides whether the unpaid text names the sit-outs.)

- [ ] **Step 1: Failing tests** in `handout.rs`:

```rust
#[test]
fn each_reason_reads_plainly() {
    let fast = NodeId([1; 32]); let flaky = NodeId([2; 32]);
    let name = |id: &NodeId| if *id == fast { "Fast".to_string() } else { "Flaky".to_string() };
    let mut h = Handout { job_uid: "j".into(), scanner: fast, level: 4, paid: true,
        price_mc: Some(30), rate: 1.0, effective_mc: 30, next: Some((flaky, 40)),
        waited_secs: 720, reason: Reason::Cheapest, sat_out: 0 };
    assert_eq!(describe(&h, &name),
        "Given to Fast for 0.03 per delivered result (price 0.03, 100 % at L4). Next best: Flaky, 0.04. Waited 12 min for Fast.");
    h.waited_secs = 0; h.next = None;
    assert_eq!(describe(&h, &name), "Given to Fast for 0.03 per delivered result (price 0.03, 100 % at L4).");
    let o = Handout { scanner: flaky, price_mc: Some(20), rate: 0.5, effective_mc: 40,
        waited_secs: 1830, reason: Reason::Override, ..h.clone() };
    assert_eq!(describe(&o, &name), "Waited 30 min, then went to whoever asked: Flaky, 0.04 per delivered result.");
    let u = Handout { paid: false, reason: Reason::Unpaid, sat_out: 2, ..o.clone() };
    assert_eq!(describe(&u, &name), "Unpaid: the scan budget did not cover it; went to Flaky (scanners weak at L4 sat out by the old rule).");
    let u = Handout { sat_out: 0, ..u };
    assert_eq!(describe(&u, &name), "Unpaid: the scan budget did not cover it; went to Flaky.");
}

#[tokio::test]
async fn the_latest_grant_is_kept_for_eight_days() {
    let dir = tempfile::tempdir().unwrap();
    let s = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
    let h = |uid: &str, eff: u32| Handout { job_uid: uid.into(), scanner: NodeId([1; 32]), level: 2,
        paid: true, price_mc: Some(eff), rate: 1.0, effective_mc: eff, next: None,
        waited_secs: 0, reason: Reason::Cheapest, sat_out: 0 };
    record(&s.pool, &h("old", 1)).await.unwrap();
    sqlx::query("UPDATE job_handouts SET at = datetime('now', '-9 days')").execute(&s.pool).await.unwrap();
    record(&s.pool, &h("a", 10)).await.unwrap();
    record(&s.pool, &h("a", 20)).await.unwrap(); // a retry grant
    let got = latest(&s.pool, &["a".into(), "old".into()]).await.unwrap();
    assert_eq!(got["a"].effective_mc, 20);
    assert!(!got.contains_key("old"), "pruned after 8 days");
}
```

- [ ] **Step 2:** `cargo test --lib scan::handout` → fails to compile.
- [ ] **Step 3: Implement** (`Handout` derives `Debug, Clone`; `Reason` derives `Debug, Clone, Copy, PartialEq`). Text rules:
  - `show(mc)` is `crate::credits::show(mc as u64)`; percent is `(rate * 100).round()`.
  - Cheapest: `"Given to {s} for {eff} per delivered result (price {p}, {pct} % at L{l})."` + `" Next best: {n}, {neff}."` if `next` + `" Waited {m} min for {s}."` if `waited_secs >= 60` (`m = waited_secs / 60`). Price without a value prints `–`.
  - Override: `"Waited {waited_secs/60} min, then went to whoever asked: {s}, {eff} per delivered result."`
  - Unpaid: `"Unpaid: the scan budget did not cover it; went to {s}"` + `" (scanners weak at L{l} sat out by the old rule)"` if `sat_out > 0` + `"."`.
  - `record` binds all columns, then `DELETE FROM job_handouts WHERE at < datetime('now', '-8 days')`.
  - `latest` uses `SELECT ... FROM job_handouts WHERE id IN (SELECT MAX(id) FROM job_handouts WHERE job_uid IN (SELECT value FROM json_each(?)) GROUP BY job_uid)` with the uids as a JSON array.
  - `names(node)`: clone `node.members()`; `move |id| m.get(id).map_or_else(|| id.short(), |r| r.name.clone())`.
- [ ] **Step 4:** `cargo test --lib scan::handout store` → PASS.
- [ ] **Step 5: Commit** `Scan jobs: record why each job went where`.

---

### Task 5: Job-major hand-out in the arbiter

**Files:**
- Modify: `src/credits/jobs.rs` (split `affordable` out of `fund`)
- Modify: `src/scan/arbiter.rs` (replace `hand_out`, `next_job_for`, `next_job`, `skipped_levels`, `next_job_skipping`, `claim_order`; add `round`, `grant`; field `held`)

**Interfaces:**
- Consumes: Task 1 `node.weights.get`, `weight::weight`, `weight::skipped_levels`; Task 3 `rank::{Bid, rank, Standby, reserve, waits, Wait}`; Task 4 `handout::{Handout, Reason, record}`.
- Produces:
  - `pub async fn credits::jobs::affordable(node: &Arc<Node>, funding: &mut Funding, min_mc: u32, price: u32) -> bool` — reads (and caches in `funding`) the book and self tally; writes nothing.
  - `pub(crate) struct Claimant { pub id: NodeId, pub exclude: Vec<u8>, pub min_mc: u32 }`
  - `async fn Arbiter::round(&self, claims: &[Claimant]) -> Result<Vec<Option<Grant>>>` — one result per claim, in order.
  - Constant `ROUND_JOBS: i64 = 500`.

The round:

1. Per distinct claimant id: `price_for`, `(all, here) = scans_last_hour`, `demoted = over_capacity(here, can_do) || !delivers`.
2. `snap = node.weights.get(pool)`, `scanners = self.scanners()`. Standby pool: every scanner in `scanners`, with its own `scans_last_hour`, not over capacity, `delivers`, with `price_for`.
3. `blocked(uid, s)`: in `declined[uid]` or `later[uid][s] > now`. Uids every claimant is blocked from and levels every claimant excludes go into SQL as `NOT IN (json_each(?))`.
4. Query (same order and arbiter-wide filters as today, plus what the per-job check needs):

```sql
SELECT j.uid, i.ip, j.level, j.attempts, j.failed_by,
       j.retry_at IS NULL OR j.retry_at <= datetime('now', '-{LAST_FAILER_WAIT} minutes') AS failer_may,
       CAST((julianday('now') - julianday(j.queued_at)) * 86400 AS INTEGER) AS waited_secs
FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
WHERE j.status = 'queued' AND j.arbiter = ?
  AND j.uid NOT IN (SELECT value FROM json_each(?))
  AND j.level NOT IN (SELECT value FROM json_each(?))
  AND (j.retry_at IS NULL OR j.retry_at <= datetime('now'))
ORDER BY {est.order_by("j", "j.uid")} LIMIT {ROUND_JOBS}
```

5. For each row, until every claim has a grant:
   - eligible claims: not served, `!blocked(uid, id)`, level not in `exclude`, and not (`failed_by == id && !failer_may`). None → next row.
   - `outranked_by` → mark superseded as today, next row.
   - Bids from eligible claims (weight `weight(&snap.tallies, id, &scanners, level)`), `rank`; keep the claim index alongside.
   - `top`: if `top.price` is `Some(p)` and `affordable(node, &mut funding, claim.min_mc, p)`: paid. Standby list for this job: standby scanners not blocked for the uid, not the job's waiting failer, and (if they are a claimant in this round) not excluding the level; with `sample = ok + failed` from `snap.tallies` at the level. `waits(top.effective(), reserve(&standby), waited_secs)`: `Hold` → note `held.entry(uid).or_insert(now)`, next row; `Go` → reason `Cheapest`, `waited` = time since `held[uid]` (0 if none); `Override` → reason `Override`, `waited = waited_secs`.
   - else unpaid: unless `waited_secs >= OVERRIDE_WAIT_MINS * 60`, drop bids whose id sits the level out (`skipped_levels(&snap.tallies, id, &scanners, unix_now()).contains(&level)`), counting them in `sat_out`; empty → next row; reason `Unpaid`.
   - `grant(...)`: writes `running` as `next_job_skipping` did, inserts the lease, then `fund` when paid (as `next_job_for` did, setting `offer_seq`, `price_mc`, `lease.funded`); `held.remove(uid)`; increments the claimant's `load`; records the `Handout` (`paid` = the grant actually funded; `next` = second bid's id and effective for paid reasons; a record failure is logged at debug, never fails the grant).
6. `hand_out` takes the waiters, builds `Claimant`s, calls `round`, sends each result to its waiter.

`recheck_declined` also drops `held` entries older than 2 × `OVERRIDE_WAIT_MINS` (the job went elsewhere).

- [ ] **Step 1: Rewrite the tests.** Remove `claimants_go_cheapest_first_and_demoted_ones_last` (covered by `rank` tests). Add a test helper and convert every `arbiter.next_job(s, &x)` / `next_job_for(&mut f, s, &x, m)` to it:

```rust
impl Arbiter {
    /// One round with one claim.
    async fn next_job(&self, scanner: NodeId, exclude: &[u8], min_mc: u32) -> Option<Grant> {
        self.round(&[Claimant { id: scanner, exclude: exclude.to_vec(), min_mc }])
            .await.unwrap().pop().flatten()
    }
}
```

(`next_job(x, &[])` callers become `next_job(x, &[], 0)`; `.unwrap().unwrap()` becomes `.unwrap()`, `.unwrap().is_none()` becomes `.is_none()`.) Replace `sat_out_levels_are_skipped_until_the_job_has_waited` by `an_unpaid_job_skips_scanners_sitting_its_level_out` (below). New tests, using `give_credits`/`selling` and these helpers:

```rust
/// Pretend `who` finished `ok` and `failed` scans at `level` in the
/// snapshot's window (2 hours ago).
async fn history(store: &crate::store::Store, who: NodeId, level: i64, ok: usize, failed: usize) {
    let ip = store.upsert_ip("198.51.100.1".parse().unwrap()).await.unwrap();
    for status in std::iter::repeat_n("done", ok).chain(std::iter::repeat_n("failed", failed)) {
        sqlx::query(
            "INSERT INTO scan_jobs (uid, origin, arbiter, hlc, ip_id, level, status, queued_at,
                                    finished_at, scanner, error)
             VALUES (lower(hex(randomblob(16))), ?1, ?1, 1, ?2, ?3, ?4, datetime('now', '-3 hours'),
                     datetime('now', '-2 hours'), ?1, 'nmap exited 1')",
        )
        .bind(&who.0[..]).bind(ip.id).bind(level).bind(status)
        .execute(&store.pool).await.unwrap();
    }
}

/// A member `id` with the scanner role, heard from just now, announcing `price`.
fn live_scanner(node: &Node, id: NodeId, price: u32) { /* see Step 3 note */ }

async fn queue(node: &Arc<Node>, store: &crate::store::Store, last: u8, level: u8) -> String {
    let ip = store.upsert_ip(format!("203.0.113.{last}").parse().unwrap()).await.unwrap();
    Recorder::Cluster(node.clone()).enqueue_scan(ip.id, level, 24).await.unwrap();
    sqlx::query_scalar("SELECT uid FROM scan_jobs WHERE ip_id = ? ORDER BY id DESC LIMIT 1")
        .bind(ip.id).fetch_one(&store.pool).await.unwrap()
}

#[tokio::test]
async fn a_paid_job_goes_to_the_cheapest_per_delivered_result() {
    // This node (Fast, 30 mc) delivers every L4 scan; Flaky (20 mc) half.
    // Both ask in the same round: Fast gets L4, Flaky gets L1.
    ...
    let res = arbiter.round(&[claim(flaky), claim(me)]).await.unwrap();
    // assert the L4 job went to `me`, the L1 job to `flaky`
}

#[tokio::test]
async fn a_paid_job_waits_for_a_cheaper_live_scanner_until_the_override() {
    // Only Flaky asks for the L4 job; Fast (this node) is live, idle, cheaper per result.
    assert!(arbiter.next_job(flaky, &[], 0).await.is_none());
    // An L1 job behind it still goes to Flaky (Review Focus 1).
    // After 31 minutes in the queue, the L4 job goes to Flaky, reason override.
}

#[tokio::test]
async fn a_scanner_that_cannot_take_the_job_sets_no_reserve() {
    // Fast cheaper per result but: (a) declined the job, (b) is its last failer
    // within LAST_FAILER_WAIT, (c) has fewer than MIN_SAMPLE scans at L4,
    // (d) is over capacity — each time Flaky gets the job at once.
}

#[tokio::test]
async fn an_unpaid_job_skips_scanners_sitting_its_level_out() {
    // No credits: the job is unpaid. Flaky (weight 0.1 at L4) and another
    // full-weight claimant ask: with a draw that sits Flaky out, the other
    // gets it; the funding check wrote no offer; the record says unpaid.
}

#[tokio::test]
async fn two_claims_of_one_scanner_get_two_jobs() {
    // two claims from `other`, two jobs queued: both granted, distinct uids.
}

#[tokio::test]
async fn every_grant_is_recorded() {
    // after a grant, handout::latest has the job with the right scanner and reason
}
```

The test bodies must be written out in full during implementation; the skeleton comments above state each one's setup and assertions. For the sit-out case pick, by loop over `weight::draw`, a time where Flaky sits out — `round` takes the time from `weight::unix_now()`, so instead give Flaky weight `MIN_WEIGHT` (0 ok, 500 failed) where `draw >= 0.1` in 90 % of stretches, and assert over the current stretch only if `draw(flaky, 4, unix_now()) >= MIN_WEIGHT` (otherwise assert Flaky may get it): the assertion must hold either way.

- [ ] **Step 2:** `cargo test --lib scan::arbiter` → fails to compile.
- [ ] **Step 3: Implement** `affordable` (moved check from `fund`; `fund` calls it after clearing the old reservation and keeps its own path otherwise), then the arbiter round as described. `live_scanner` in tests: look at how other tests in `src/cluster` or `src/credits/price.rs` (`test_node`) insert a member with roles and a heartbeat (`node.status`), and reuse that helper; `price_for` needs the member's `proto_max` to sell scans and a reference price in `node.price_table()` (`Table.scanners` with that node).
- [ ] **Step 4:** `cargo test --lib` → PASS; `cargo clippy --all-targets -- -D warnings` → clean.
- [ ] **Step 5: Commit** `Scan jobs: hand out by job, cheapest per delivered result`.

---

### Task 6: What is shown

**Files:**
- Modify: `src/admin/credits.rs` (`PriceView.scanners` becomes `Vec<ScannerRow>`, `weights_as_of`), `templates/admin_cluster_credits.html`
- Modify: `src/admin/scans.rs` (`scan_page`: `handed_out: Option<String>`; history titles), `templates/admin_scan.html`, `templates/admin_scans.html`
- Modify: `src/store/inspect.rs` (`HistoryRow` gets `uid: String` and `#[sqlx(skip)] handout: Option<String>`; `job_history` selects `j.uid`)

**Interfaces:**
- Consumes: Task 1 snapshot, Task 3 `rank::effective`, Task 4 `handout::{latest, describe, names}`.

- [ ] **Step 1: Failing tests.**
  - `credits.rs` `the_page_shows_where_credits_come_from`: build `scanners: vec![ScannerRow { name: "node-bravo".into(), announced: "0.06".into(), reference: "0.05".into(), paid: "30 / 36".into(), levels: vec![("0.05".into(), "price 0.05 ÷ success 100 % (0 ok, 0 failed, last 24 h)".into(), true), ("0.10".into(), "…".into(), false), ("0.05".into(), "…".into(), true), ("0.05".into(), "…".into(), true)] }]` and `weights_as_of: "Success rates as of 14:00 UTC, next at 15:00.".into()`; assert the page contains `<b>0.05</b>`, `0.10`, `per delivered result`, and the as-of line.
  - `scans.rs` (or the template test module there): render `ScanPage` with `handed_out: Some("Given to Fast for 0.03 per delivered result (price 0.03, 100 % at L4).".into())` and assert it shows `Handed out` and the text; with `None`, no `Handed out`.
  - `templates/admin_scans.html` note: a page render test asserting `cheapest per delivered result` and `30 min` appear and `1 − weight` no longer does.
- [ ] **Step 2:** run the tests → fail.
- [ ] **Step 3: Implement.**
  - Credits: per scanner in `t.scanners`, `price = credits::jobs::price_for(node, &s.node)`, `w = weight(&snap.tallies, s.node, &arbiter::scanners(node), l)`, cell `rank::effective(price, w)` shown with `show` (`–` for `u32::MAX`), title `"price {show(p)} ÷ success {pct} % ({ok} ok, {failed} failed, last 24 h)"`; the cheapest per level (min over priced cells) is `true`. `weights_as_of = format!("Success rates as of {:02}:00 UTC, next at {:02}:00.", snap.hour % 24, (snap.hour + 1) % 24)`. Template: header adds `<th class="num" title="Credits per delivered result at level N">LN</th>` for N = 1..4 and a caption cell row; under the table `<p class="muted small">{{ price.weights_as_of }} Each level column is the price divided by the scanner's success rate there, relative to the best live scanner: what one delivered result costs.</p>`.
  - Scan page: look up `SELECT j.uid, j.arbiter FROM scan_jobs j JOIN scans s ON s.job_uid = j.uid WHERE s.id = ?`. Arbiter is this node → `handout::latest` → `describe`; arbiter another member → `"Handed out by {name}; the reason is on that node."`; no job or no record → `None`. Template: in `.meta`, `{% if let Some(h) = handed_out %}<span>Handed out: {{ h }}</span>{% endif %}`.
  - History: after `job_history`, `handout::latest(pool, uids)` and fill `handout` with `describe`; template: the scanner cell gets `{% if let Some(h) = r.handout %} title="{{ h }}"{% endif %}` on a `<span>` around the name.
  - Scans note (`admin_scans.html:51`) becomes: "0 pauses a scanner. Paid jobs go to the scanner that is cheapest per delivered result at the job's level: its price divided by its success rate there (last 24 h, timeouts aside, measured hourly). A job waits up to 30 min for a cheaper live scanner, then goes to whoever asks. A scanner that fails a level often wins it only if its price makes up for it. Unpaid jobs keep the old rule: a scanner that fails a level more than the others sits it out for 10-minute stretches, a share of 1 − weight of them." — then adjust the test to assert `1 − weight` *does* still appear (unpaid rule) and `cheapest per delivered result` too.
- [ ] **Step 4:** `cargo test --lib admin store` → PASS.
- [ ] **Step 5: Commit** `Admin: price per delivered result and why a job went where`.

---

### Task 7: Docs

**Files:** `docs/cluster.md` (Prices bullet ~183, Scan jobs bullet ~215, "Every node counts for itself" ~229), `CHANGELOG.md` (Unreleased → Changed).

- [ ] **Step 1:** Prices: "computed every 10 minutes on each node" and keep the per-hour bounds; note `price_history` keeps one point per hour. Scan jobs: replace "hands each job to the cheapest scanner asking" with: the arbiter hands each job to the claimant that is cheapest per delivered result at the job's level (price ÷ success rate, last 24 h, measured hourly at five past); a paid job waits up to 30 minutes for a cheaper live scanner with a record at that level; unpaid jobs keep the sit-out rule; the reasons are on the scan page and as a title in the Scans history (local, 8 days, `job_handouts`). Mention the round reads up to 500 queued jobs.
- [ ] **Step 2:** CHANGELOG `### Changed` entries: buyers rank scanners per delivered result; prices every 10 minutes; weights hourly; Credits L1–L4 columns; scan page "Handed out".
- [ ] **Step 3:** `cargo test --lib` and `cargo clippy --all-targets -- -D warnings` once more; commit `Docs: reliability pricing`.
