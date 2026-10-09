# Scarce Credits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the daily mint with a fixed supply (a 1000-credit daily pool split among verified listeners), move every price by sales with no floor, make zero-priced goods free without an offer, fund every scan job, and add three goods: reverse names (a quorum good), bought audits, and relay leases — cut over at protocol 7.

**Architecture:** Members write an hourly `reach_report`; every node tallies them into up hours and verified listeners, and its ledger credits each closed day's pool to them. The ledger reads only economy-2 payments (`economy: 2`, signed under a new domain), so the old economy is ignored without a recount. Prices step up when a good sold or is at capacity and down otherwise, from wherever they are, down to 0. Quorum goods ask `min(9, ⌊n/2⌋+1)` nodes, the cheapest first. Scanners buy audits of their own scans; outbound-only members lease relays that hold their outbox.

**Tech Stack:** Rust 2024, tokio, axum, sqlx/SQLite, askama, serde/CBOR; tests with `cargo test`.

**Spec:** `docs/superpowers/specs/2026-10-09-scarce-credits-design.md` (approved, final: do not reopen its decisions).

## Global Constraints

- `POOL_PER_DAY = 1000 credits` (1 000 000 mc); the supply is six pools; nothing mints, nothing burns; a lot lives on its day and the 6 after.
- A verified listener of day d: listener role and an advertised address in its member record, up in at least 12 of the day's 24 hours.
- Up in hour h: more than half of the reports for h, from distinct reporters other than the member and not blocked or left out here, name it.
- Reach reports: one per origin per hour (later ones ignored); a report for an hour after the one its entry is written in, or more than 25 hours before it, is ignored.
- Prices: `u32` mc, may be 0, no floor; per hour at most ×e^0.45 up and ×e^-0.15 down, scaled by the hours since the last refresh (at most 1), and at least 1 mc toward the signal; refreshed every 10 minutes.
- Quorum: `q = min(9, ⌊n/2⌋ + 1)`, n = reachable members announcing a price for the good, this node included; standalone q = 1. `IpNameRec.answers` and `RdnsRec.answers` hold at most 9.
- Audits (spec §4, revised): a scan of a job granted by another arbiter, level 1–4, is designated when `SHA-256("peephole-audit\0" || job uid || done-status HLC)` as a fraction is below `AUDIT_RATE = 0.05` (a protocol constant); its auditors are the first 3 active protocol-7 scanners other than the scanner ranked by `SHA-256(seed || key)`; an audit starts within 30 minutes; a scanner fails when ≥ 2 designated scans of 7 days lack a bought audit and it bought < 80 %. `[credits] audit_share` (default 0.05) keeps its meaning: the unpaid auditor-side checks.
- Relays: a lease is one hour; `[cluster] relay_slots` default 16; a lessee holds two, renewing 5 minutes before expiry.
- `PROTO_VERSION = 7`, `ECONOMY_PROTO = 7`; `pays_with` and `sells_scans` require 7. Economy-2 entries carry `economy: 2` and are signed under `peephole-repl-v2\0`.
- No recount, no migration of balances: old `credit_entries` rows stay and are ignored.
- Schema: one new migration, `src/store/migrations/0029_scarce_credits.sql`, created by Task 1; later tasks append to it in DAG order (it is unreleased). Never edit 0001–0028.
- Every field added to an existing wire struct is `#[serde(default)]`, with `skip_serializing_if` when it has an empty value, so older peers decode it.
- `docs/superpowers/plans/*` and older specs are historical; never edit them.
- One PR, branch `scarce-credits`: the protocol bump and every sender-side gate land with the code that emits the new kinds and fields (the rolling `latest` build deploys every master push).
- The live member under `~/peephole-node` must not run protocol-7 code before the field upgrades.
- Commit after every task, messages in the log's style ("Credits: …", "Prices: …"), ending with the `Co-Authored-By` line from the session.
- Minor findings of reviews are fixed, not deferred.

## Decisions this plan makes where the spec is silent

Each is the narrowest reading that keeps the spec's decisions intact; an implementer must not widen them.

1. **"Relayed only to protocol-7 members."** The log cannot skip positions, so the serving side of sync stops an origin's stream for a peer below protocol 7 at that origin's first entry that only protocol 7 knows (a `reach_report`, an `rdns_name`, or an economy-2 credit entry). The peer catches up after it upgrades.
2. **"Seals signed under a new domain string."** The signature of an economy-2 `credit_offer`, `credit_receipt` or `credit_transfer` (and therefore its digest in the seal chain) uses the domain `peephole-repl-v2\0`. The `Seal` digest rule itself is unchanged: a protocol-6 node checking a changed digest rule would mark the protocol-7 node as having shown two histories, permanently. A protocol-6 node that is handed such an entry anyway rejects its signature and retries later; nothing is marked.
3. **Audit offers are at least 1 mc.** The obligation counts only charged audit offers, and an offer of nothing cannot be written; an audit by an auditor priced at 0 is offered 1 mc.
4. **Gates in the new ledger.** A member failing the rules gate gets no pool share here and its receipts move nothing; a scanner failing the audit gates (differing audits or audits owed) has its scan-job receipts move nothing. A receipt that moves nothing leaves its offer open until it lapses back to the payer.
5. **A day's pool is credited 1 hour after UTC midnight**, so the reports for hour 23 have arrived.
6. **A node reports every hour it was running in**, also when it reached nobody; it never reports an hour before its start.
7. **A scanner's "sold"** is a scan of a job granted to it that finished since this node last stepped its price; "at capacity" is its granted scans of the past hour at 90 % of what it can do (the existing target).
8. **Before the first refresh** a good the price table lacks is priced 0 by the seller, as probes already do; an advertised node announces its relay price (0 until its first refresh).
9. **Outboxes** are held only for members with an advertised address or a current relay lease.

## Review Focus

1. **The upgrade sitting.** A protocol-6 peer pulling from a protocol-7 node must get each origin's entries up to its first protocol-7-only entry and nothing after it, never a gap; a protocol-7 node reads every protocol-6 entry. Test in Task 6 (`entries_after` with an old peer).
2. **The day boundary.** At 00:30 UTC yesterday's pool is not credited yet; at 01:00 it is; a report for hour 23 written at 00:01 counts for yesterday. Test in Task 6 (`closed`) and Task 1 (`hour_ok`).
3. **A restart mid-hour.** The node reports only the hours it was running in and never an hour before its start; a restart after an hour ended loses that hour's report rather than writing an empty one. Test in Task 1 (`Tracker`).
4. **A price at 0 that rises between heartbeat and request.** The asker asks without an offer, is declined naming 1 mc, and offers that once; a server naming more than twice `max(offered, 1)` is not offered again. Test in Task 2 (`retry_price`).
5. **An outbound-only member whose first relay refuses.** The sender tries the second listed relay; with no relay listed, `can_call` is false and nothing waits for a timeout. Test in Task 9 (`next_hops`).

## Execution DAG

```
wave 1:  T1 reach reports        T2 zero-priced goods free
wave 2:  T3 sales prices (T2)    T4 quorum + resolution (T2)
wave 3:  T5 every job funded (T3)
wave 4:  T6 protocol 7: the cut and the pool (T1, T4, T5)
wave 5:  T7 reverse names (T3, T4, T6)   T8 paid audits (T5, T6)   T9 relay leases (T3, T6)
wave 6:  T10 pages, CLI, installer, docs (all)
```

Parallel implementers work in worktrees branched from `scarce-credits` (rebase from the feature branch, not master), with one shared `CARGO_TARGET_DIR` (e.g. `export CARGO_TARGET_DIR=$HOME/peephole/target`). Each finished task is merged into `scarce-credits` before the tasks that depend on it start.

## Environment

- Every Bash call: `export PATH=$HOME/.cargo/bin:$PATH`.
- A lib or cluster test build takes about a minute and 1–2 GB. The disk is tight: before a full run, keep only the newest copy of each binary in `target/debug/deps` and clear `target/debug/incremental` (e.g. `ls -t target/debug/deps/peephole-* | tail -n +3 | xargs -r rm`, `rm -rf target/debug/incremental`).
- Focused tests: `cargo test --lib <module path>` and `cargo test --test cluster <name>`. The full suite (`cargo test`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`) runs once, in the final review.

---

### Task 1: Reach reports and up hours

Every member writes one replicated `reach_report` per UTC hour naming the advertised members it completed a sync round with; every node tallies the reports into up hours per member and day, and into each day's verified listeners. Nothing pays from it yet (Task 6 does).

**Files:**
- Create: `src/credits/reach.rs`
- Create: `src/store/migrations/0029_scarce_credits.sql`
- Modify: `src/store/mod.rs:39-68` (append the migration to `MIGRATIONS`)
- Modify: `src/cluster/record.rs` (new `ReachReportRec`, `Record::ReachReport`, kind `reach_report`)
- Modify: `src/store/data.rs:62-110` (dispatch the new kind)
- Modify: `src/cluster/mod.rs` (`Node.reach` field, initialised in `Node::open`)
- Modify: `src/cluster/sync.rs` (`peer_loop`: note a completed round)
- Modify: `src/credits/mod.rs` (`pub mod reach;`, write due reports each tick, prune hourly)
- Modify: `src/credits/cli.rs` (`credits uptime`)
- Test: `src/credits/reach.rs` (`mod tests`), `src/cluster/record.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (Task 6 and Task 10 rely on these exact names):
  - `crate::cluster::record::ReachReportRec { pub hour: u32, pub reached: Vec<NodeId> }`, `Record::ReachReport(ReachReportRec)`, kind `"reach_report"`, no uid.
  - `crate::credits::reach::{HOUR_MS: u64, MIN_UP_HOURS: u32 = 12, MAX_BACK_HOURS: u32 = 25, MAX_REACHED: usize = 1024}`
  - `reach::hour_of(ms: u64) -> u32`, `reach::hour_ok(hour: u32, hlc: u64) -> bool`
  - `reach::apply(conn, ctx: Ctx<'_>, r: &ReachReportRec) -> Result<Effect>`, `reach::record(conn, origin: &NodeId, hour: u32, reached: &[NodeId]) -> Result<()>`
  - `reach::Report { reporter: NodeId, hour: u32, reached: BTreeSet<NodeId> }`, `reach::since(pool, from_hour: u32) -> Result<Vec<Report>>`, `reach::prune(pool, before_hour: u32) -> Result<u64>`
  - `reach::Uptime = BTreeMap<(NodeId, u32 /*day*/), u32 /*hours*/>`, `reach::up(reports: &[&Report], member: &NodeId, ignored: &HashSet<NodeId>) -> bool`, `reach::uptime(reports: &[Report], members: &[NodeId], ignored: &HashSet<NodeId>) -> Uptime`
  - `reach::verified(members: &[MemberRow], uptime: &Uptime, day: u32) -> BTreeSet<NodeId>`
  - `reach::Tracker` with `note_alive(&self, now_ms)`, `note(&self, peer: NodeId, now_ms)`, `take_due(&self, now_ms) -> Vec<(u32, Vec<NodeId>)>`; `Node.reach: reach::Tracker`
  - `reach::report_due(node: &Arc<Node>, now_ms: u64) -> Result<usize>`
  - `reach::uptime_lines(names: &[(NodeId, String)], uptime: &Uptime, verified: &BTreeMap<u32, BTreeSet<NodeId>>, days: &[u32]) -> Vec<String>`

- [ ] **Step 1: Create the migration**

`src/store/migrations/0029_scarce_credits.sql`:

```sql
-- Protocol 7, scarce credits. Hourly reach reports (`credits::reach`):
-- the advertised members each member completed a sync round with in one
-- UTC hour. `reached` is the members' 32-byte keys, concatenated.
CREATE TABLE reach_reports (
  origin BLOB NOT NULL,
  hour INTEGER NOT NULL,
  reached BLOB NOT NULL,
  PRIMARY KEY (origin, hour)
) WITHOUT ROWID;

CREATE INDEX idx_reach_reports_hour ON reach_reports(hour);
```

Append `include_str!("migrations/0029_scarce_credits.sql"),` to `MIGRATIONS` in `src/store/mod.rs`.

- [ ] **Step 2: Add the record kind**

In `src/cluster/record.rs`, next to `IpNameRec`:

```rust
/// The advertised members the origin completed a sync round with during
/// one UTC hour (`credits::reach`). One per origin and hour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReachReportRec {
    /// Hours since the Unix epoch, UTC.
    pub hour: u32,
    pub reached: Vec<NodeId>,
}
```

Add the variant `ReachReport(ReachReportRec),` at the end of `enum Record` and `Record::ReachReport(_) => "reach_report",` in `kind()`. `uid()` returns None for it (the `_ => None` arm covers it).

In `src/store/data.rs` `apply`, add the arm `Record::ReachReport(r) => crate::credits::reach::apply(conn, ctx, r).await,` before the membership/credits arm. It is not a content kind (a block does not hide it; `credits::reach::uptime` leaves out blocked reporters itself).

Add to `record.rs`'s tests:

```rust
    #[test]
    fn a_reach_report_round_trips() {
        let r = Record::ReachReport(ReachReportRec {
            hour: 490_000,
            reached: vec![NodeId([1; 32]), NodeId([2; 32])],
        });
        let bytes = crate::cluster::rpc::cbor::encode(&r).unwrap();
        assert_eq!(crate::cluster::rpc::cbor::decode::<Record>(&bytes).unwrap(), r);
        assert_eq!(r.kind(), "reach_report");
        assert_eq!(r.uid(), None);
    }
```

- [ ] **Step 3: Write the failing tests for the tally**

Create `src/credits/reach.rs` with only the module doc, the `use` lines, the constants, empty `todo!()` bodies for the functions in **Interfaces**, and this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::members::{MemberRow, Standing};

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn report(reporter: u8, hour: u32, reached: &[u8]) -> Report {
        Report {
            reporter: id(reporter),
            hour,
            reached: reached.iter().map(|n| id(*n)).collect(),
        }
    }

    fn member(n: u8, listener: bool, address: bool) -> MemberRow {
        MemberRow {
            id: id(n),
            name: format!("n{n}"),
            address: address.then(|| format!("198.51.100.{n}:7443")),
            roles: if listener { vec!["listener".into()] } else { vec![] },
            proto_min: 2,
            proto_max: 7,
            sponsor: id(n),
            active: true,
            standing: Standing::Active,
            info_hlc: 0,
            last_entry_hlc: 0,
            remote_config: false,
        }
    }

    #[test]
    fn up_needs_more_than_half_of_the_other_reporters() {
        let none = HashSet::new();
        let rs = [report(2, 7, &[1]), report(3, 7, &[1]), report(4, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(up(&refs, &id(1), &none), "2 of 3");
        let rs = [report(2, 7, &[1]), report(3, 7, &[]), report(4, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(!up(&refs, &id(1), &none), "1 of 3");
        let rs = [report(2, 7, &[1]), report(3, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(!up(&refs, &id(1), &none), "half is not more than half");
        assert!(!up(&[], &id(1), &none), "nobody reported");
    }

    #[test]
    fn a_reporter_never_counts_for_itself_and_ignored_ones_not_at_all() {
        let rs = [report(1, 7, &[1]), report(2, 7, &[1]), report(3, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        // Its own report is left out: 1 of 2 others.
        assert!(!up(&refs, &id(1), &HashSet::new()));
        // Reporter 3 is blocked here: 1 of 1.
        assert!(up(&refs, &id(1), &[id(3)].into()));
    }

    #[test]
    fn uptime_counts_up_hours_per_day_and_a_second_report_for_an_hour_is_ignored() {
        let day = 20_000u32;
        let h = day * 24;
        let reports = vec![
            report(2, h, &[1]),
            report(2, h, &[]), // a second report of 2 for that hour
            report(2, h + 1, &[1]),
            report(2, h + 24, &[1]), // the next day
        ];
        let up = uptime(&reports, &[id(1), id(2)], &HashSet::new());
        assert_eq!(up.get(&(id(1), day)), Some(&2));
        assert_eq!(up.get(&(id(1), day + 1)), Some(&1));
        assert_eq!(up.get(&(id(2), day)), None, "nobody reported 2");
    }

    #[test]
    fn a_verified_listener_is_an_advertised_listener_up_twelve_hours() {
        let day = 20_000u32;
        let mut up = Uptime::new();
        for n in [1u8, 2, 3, 4] {
            up.insert((id(n), day), 12);
        }
        up.insert((id(5), day), 11);
        let members = [
            member(1, true, true),
            member(2, false, true),  // not a listener
            member(3, true, false),  // outbound-only
            member(4, true, true),
            member(5, true, true),   // 11 hours
        ];
        assert_eq!(verified(&members, &up, day), [id(1), id(4)].into());
        assert!(verified(&members, &up, day + 1).is_empty());
    }

    #[test]
    fn a_report_is_taken_for_its_hour_and_up_to_25_hours_before() {
        let at = |hour: u64| (hour * HOUR_MS + 60_000) << 16;
        assert!(hour_ok(100, at(101)), "written at the start of the next hour");
        assert!(hour_ok(101, at(101)), "the hour it is written in");
        assert!(!hour_ok(102, at(101)), "an hour still to come");
        assert!(hour_ok(76, at(101)), "25 hours back");
        assert!(!hour_ok(75, at(101)), "26 hours back");
    }

    #[test]
    fn the_tracker_reports_only_hours_it_ran_in_and_each_once() {
        let t = Tracker::default();
        let ms = |hour: u64, min: u64| hour * HOUR_MS + min * 60_000;
        // Started in hour 10: nothing before it is ever reported.
        t.note_alive(ms(10, 30));
        t.note(id(2), ms(10, 31));
        t.note(id(3), ms(10, 59));
        t.note(id(2), ms(10, 59));
        assert!(t.take_due(ms(10, 59)).is_empty(), "the hour is not over");
        t.note_alive(ms(11, 0));
        let due = t.take_due(ms(11, 0));
        assert_eq!(due, vec![(10, vec![id(2), id(3)])]);
        assert!(t.take_due(ms(11, 1)).is_empty(), "taken once");
        // An hour it was alive in but reached nobody is reported empty.
        t.note_alive(ms(12, 5));
        assert_eq!(t.take_due(ms(12, 6)), vec![(11, vec![])]);
    }

    #[tokio::test]
    async fn the_first_report_of_an_origin_for_an_hour_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let origin = id(9);
        let ctx = |hlc| Ctx {
            origin: Some(&origin),
            hlc,
        };
        let at = (101 * HOUR_MS) << 16;
        let mut conn = store.pool.acquire().await.unwrap();
        let first = ReachReportRec {
            hour: 100,
            reached: vec![id(1)],
        };
        let second = ReachReportRec {
            hour: 100,
            reached: vec![id(1), id(2)],
        };
        let late = ReachReportRec {
            hour: 70,
            reached: vec![id(1)],
        };
        assert_eq!(apply(&mut conn, ctx(at), &first).await.unwrap(), Effect::Applied);
        assert_eq!(apply(&mut conn, ctx(at), &second).await.unwrap(), Effect::Applied);
        assert_eq!(apply(&mut conn, ctx(at), &late).await.unwrap(), Effect::Ignored);
        drop(conn);
        let all = since(&store.pool, 0).await.unwrap();
        assert_eq!(all, vec![report(9, 100, &[1])]);
        assert_eq!(prune(&store.pool, 101).await.unwrap(), 1);
        assert!(since(&store.pool, 0).await.unwrap().is_empty());
    }

    #[test]
    fn uptime_lines_mark_the_verified_days() {
        let day = 20_000u32;
        let mut up = Uptime::new();
        up.insert((id(1), day), 24);
        up.insert((id(1), day + 1), 5);
        let verified: BTreeMap<u32, BTreeSet<NodeId>> = [(day, [id(1)].into())].into();
        let lines = uptime_lines(
            &[(id(1), "node-alpha".into()), (id(2), "node-bravo".into())],
            &up,
            &verified,
            &[day, day + 1],
        );
        assert_eq!(lines[0], format!("{:<24}{:>7}{:>7}", "member", "10-04", "10-05"));
        assert_eq!(lines[1], format!("{:<24}{:>7}{:>7}", "node-alpha", "24*", "5"));
        assert_eq!(lines[2], format!("{:<24}{:>7}{:>7}", "node-bravo", "0", "0"));
    }
}
```

(Day 20 000 is 2024-10-04 UTC; the CLI prints `MM-DD`.)

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test --lib credits::reach cluster::record::tests::a_reach_report_round_trips`
Expected: the reach tests panic at `todo!()`; the record test passes once Step 2 is in.

- [ ] **Step 5: Implement `src/credits/reach.rs`**

```rust
//! Who could be reached, hour by hour. Every member writes one
//! `reach_report` per UTC hour naming the advertised members it completed
//! a sync round with in that hour. A member is up in an hour when more
//! than half of that hour's reports, from others not left out here, name
//! it; an advertised listener up for at least [`MIN_UP_HOURS`] of a UTC
//! day is a verified listener of that day and shares its pool
//! (`credits::pool`).
use crate::cluster::Node;
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::members::MemberRow;
use crate::cluster::record::{ReachReportRec, Record};
use crate::store::data::{Ctx, Effect};
use anyhow::Result;
use sqlx::{SqliteConnection, SqlitePool};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex};

pub const HOUR_MS: u64 = 3_600_000;
/// Up hours a listener needs in a UTC day to be verified.
pub const MIN_UP_HOURS: u32 = 12;
/// A report is taken for an hour at most this many hours before the one
/// its entry is written in.
pub const MAX_BACK_HOURS: u32 = 25;
/// Most members one report names.
pub const MAX_REACHED: usize = 1024;

/// The UTC hour of `ms`, in hours since the epoch.
pub fn hour_of(ms: u64) -> u32 {
    (ms / HOUR_MS).min(u32::MAX as u64) as u32
}

/// Whether a report for `hour` written at `hlc` is taken: not for an hour
/// after the one it is written in, nor more than [`MAX_BACK_HOURS`] before.
pub fn hour_ok(hour: u32, hlc: u64) -> bool {
    let at = hour_of(hlc::physical_ms(hlc));
    hour <= at && hour.saturating_add(MAX_BACK_HOURS) >= at
}

/// Keep a report: the first of its origin for its hour.
pub async fn apply(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &ReachReportRec,
) -> Result<Effect> {
    let Some(origin) = ctx.origin else {
        return Ok(Effect::Ignored);
    };
    if r.reached.len() > MAX_REACHED || !hour_ok(r.hour, ctx.hlc) {
        return Ok(Effect::Ignored);
    }
    record(conn, origin, r.hour, &r.reached).await?;
    Ok(Effect::Applied)
}

/// Store a report row; a later one of `origin` for `hour` is ignored.
pub async fn record(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    hour: u32,
    reached: &[NodeId],
) -> Result<()> {
    let blob: Vec<u8> = reached.iter().flat_map(|n| n.0).collect();
    sqlx::query("INSERT OR IGNORE INTO reach_reports (origin, hour, reached) VALUES (?, ?, ?)")
        .bind(&origin.0[..])
        .bind(hour as i64)
        .bind(blob)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// One report as the tally reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub reporter: NodeId,
    pub hour: u32,
    pub reached: BTreeSet<NodeId>,
}

/// Every report for `from_hour` or later.
pub async fn since(pool: &SqlitePool, from_hour: u32) -> Result<Vec<Report>> {
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT origin, hour, reached FROM reach_reports WHERE hour >= ? ORDER BY hour, origin",
    )
    .bind(from_hour as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(origin, hour, reached)| {
            Some(Report {
                reporter: NodeId::from_slice(&origin).ok()?,
                hour: u32::try_from(hour).ok()?,
                reached: reached
                    .chunks_exact(32)
                    .filter_map(|c| NodeId::from_slice(c).ok())
                    .collect(),
            })
        })
        .collect())
}

/// Drop the reports for hours before `before_hour`.
pub async fn prune(pool: &SqlitePool, before_hour: u32) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM reach_reports WHERE hour < ?")
        .bind(before_hour as i64)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Up hours per member and UTC day.
pub type Uptime = BTreeMap<(NodeId, u32), u32>;

/// Whether `member` was up in the hour of `reports`: more than half of
/// those from reporters other than itself and not in `ignored` name it.
pub fn up(reports: &[&Report], member: &NodeId, ignored: &HashSet<NodeId>) -> bool {
    let counted: Vec<&&Report> = reports
        .iter()
        .filter(|r| r.reporter != *member && !ignored.contains(&r.reporter))
        .collect();
    let named = counted.iter().filter(|r| r.reached.contains(member)).count();
    named * 2 > counted.len()
}

/// The up hours of `members` per day, from `reports` (one per reporter
/// and hour counts; `ignored`: reporters blocked or left out here).
pub fn uptime(reports: &[Report], members: &[NodeId], ignored: &HashSet<NodeId>) -> Uptime {
    let mut by_hour: BTreeMap<u32, Vec<&Report>> = BTreeMap::new();
    let mut seen: HashSet<(NodeId, u32)> = HashSet::new();
    for r in reports {
        if seen.insert((r.reporter, r.hour)) {
            by_hour.entry(r.hour).or_default().push(r);
        }
    }
    let mut out = Uptime::new();
    for (hour, rs) in &by_hour {
        for m in members {
            if up(rs, m, ignored) {
                *out.entry((*m, hour / 24)).or_default() += 1;
            }
        }
    }
    out
}

/// The verified listeners of `day`: the listener role and an advertised
/// address in their member record, up at least [`MIN_UP_HOURS`] that day.
pub fn verified(members: &[MemberRow], uptime: &Uptime, day: u32) -> BTreeSet<NodeId> {
    members
        .iter()
        .filter(|m| m.active && m.address.is_some() && m.roles.iter().any(|r| r == "listener"))
        .filter(|m| uptime.get(&(m.id, day)).copied().unwrap_or(0) >= MIN_UP_HOURS)
        .map(|m| m.id)
        .collect()
}

/// The advertised members this node completed a sync round with, per
/// hour this process ran in, until the hour is reported.
#[derive(Default)]
pub struct Tracker {
    hours: Mutex<BTreeMap<u32, BTreeSet<NodeId>>>,
}

impl Tracker {
    /// This node runs in the hour of `now_ms`: it reports that hour, even
    /// naming nobody.
    pub fn note_alive(&self, now_ms: u64) {
        self.hours
            .lock()
            .unwrap()
            .entry(hour_of(now_ms))
            .or_default();
    }

    /// A sync round with `peer` completed at `now_ms`.
    pub fn note(&self, peer: NodeId, now_ms: u64) {
        self.hours
            .lock()
            .unwrap()
            .entry(hour_of(now_ms))
            .or_default()
            .insert(peer);
    }

    /// The hours before the one of `now_ms`, with whom they reached; taken
    /// out, so each is reported once.
    pub fn take_due(&self, now_ms: u64) -> Vec<(u32, Vec<NodeId>)> {
        let mut hours = self.hours.lock().unwrap();
        let current = hours.split_off(&hour_of(now_ms));
        std::mem::replace(&mut *hours, current)
            .into_iter()
            .map(|(h, s)| (h, s.into_iter().collect()))
            .collect()
    }
}

/// Write this node's report of every hour that ended (at most
/// [`MAX_BACK_HOURS`] back). Returns how many were written.
pub async fn report_due(node: &Arc<Node>, now_ms: u64) -> Result<usize> {
    node.reach.note_alive(now_ms);
    let now = hour_of(now_ms);
    let records: Vec<Record> = node
        .reach
        .take_due(now_ms)
        .into_iter()
        .filter(|(h, _)| h.saturating_add(MAX_BACK_HOURS) >= now)
        .map(|(hour, reached)| Record::ReachReport(ReachReportRec { hour, reached }))
        .collect();
    if records.is_empty() {
        return Ok(0);
    }
    crate::cluster::repl::append(node, &records).await?;
    Ok(records.len())
}

/// `credits uptime`: a header of `MM-DD` days, then per member its up
/// hours each day, `*` where it was a verified listener.
pub fn uptime_lines(
    names: &[(NodeId, String)],
    uptime: &Uptime,
    verified: &BTreeMap<u32, BTreeSet<NodeId>>,
    days: &[u32],
) -> Vec<String> {
    let date = |d: u32| {
        chrono::DateTime::from_timestamp(d as i64 * 86_400, 0)
            .map(|t| t.format("%m-%d").to_string())
            .unwrap_or_default()
    };
    let mut out = vec![days.iter().fold(format!("{:<24}", "member"), |mut s, d| {
        s.push_str(&format!("{:>7}", date(*d)));
        s
    })];
    for (id, name) in names {
        let mut line = format!("{name:<24}");
        for d in days {
            let h = uptime.get(&(*id, *d)).copied().unwrap_or(0);
            let star = if verified.get(d).is_some_and(|v| v.contains(id)) { "*" } else { "" };
            line.push_str(&format!("{:>7}", format!("{h}{star}")));
        }
        out.push(line);
    }
    out
}
```

Add `pub mod reach;` to `src/credits/mod.rs`.

- [ ] **Step 6: Track sync rounds and write reports**

In `src/cluster/mod.rs` add the field next to `market`:

```rust
    /// The advertised members this node reached, per hour, until reported
    /// (`credits::reach`).
    pub reach: crate::credits::reach::Tracker,
```

and `reach: Default::default(),` in `Node::open`'s struct literal.

In `src/cluster/sync.rs` `peer_loop`, right after `node.traffic.round(peer, &name, round.is_ok());`:

```rust
        if round.is_ok() {
            node.reach.note(peer, super::hlc::wall_ms());
        }
```

(`peer_loop` runs only for dial targets, i.e. members with an advertised address.)

In `src/credits/mod.rs` `run`, at the top of the loop body:

```rust
        // The hours that ended since the last tick, once each.
        if let Err(e) = reach::report_due(&node, crate::cluster::hlc::wall_ms()).await {
            tracing::debug!(?e, "credits: reach report not written");
        }
```

and inside the hourly `ticks.is_multiple_of(60)` prune block, after `entries::prune`:

```rust
                reach::prune(pool, reach::hour_of(crate::cluster::hlc::wall_ms())
                    .saturating_sub((LOT_DAYS + 1) * 24)).await?;
```

(adjust the `async` block's return so all three prunes are awaited; the block returns `anyhow::Result<u64>`).

- [ ] **Step 7: Add `credits uptime`**

In `src/credits/cli.rs`, add to `USAGE`: `       peephole credits uptime [CONFIG]             each member's reported hours up, 7 days` (drop nothing yet; Task 6 removes `why`). Add the arm:

```rust
        ["uptime"] => {
            let now = crate::cluster::hlc::wall_ms();
            let today = (now / super::DAY_MS) as u32;
            let days: Vec<u32> = (today.saturating_sub(6)..=today).collect();
            let reports = super::reach::since(&node.store.pool, days[0] * 24).await?;
            let mut ignored: std::collections::HashSet<_> =
                crate::cluster::block::list(&node.store).await?.into_iter().collect();
            ignored.extend(crate::cluster::seal::forked_set(&node.store.pool).await?);
            let all: Vec<members::MemberRow> = members::all(&node.store)
                .await?
                .into_iter()
                .filter(|m| m.active)
                .collect();
            let ids: Vec<_> = all.iter().map(|m| m.id).collect();
            let up = super::reach::uptime(&reports, &ids, &ignored);
            let verified = days
                .iter()
                .map(|d| (*d, super::reach::verified(&all, &up, *d)))
                .collect();
            let names: Vec<_> = all.iter().map(|m| (m.id, m.name.clone())).collect();
            for line in super::reach::uptime_lines(&names, &up, &verified, &days) {
                println!("{line}");
            }
            println!("hours up a day (UTC); * a verified listener: advertised, up 12 hours or more");
        }
```

(`members::MemberRow` is `crate::cluster::members::MemberRow`; check `block::list`'s return type and collect accordingly.)

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cargo test --lib credits::reach cluster::record store::tests`
Expected: PASS (the store test checks the schema version against `MIGRATIONS.len()`).

- [ ] **Step 9: Commit**

```bash
git add src/credits/reach.rs src/credits/mod.rs src/credits/cli.rs src/cluster/record.rs \
  src/cluster/mod.rs src/cluster/sync.rs src/store/data.rs src/store/mod.rs \
  src/store/migrations/0029_scarce_credits.sql
git commit -m "Credits: hourly reach reports and up hours"
```

---

### Task 2: Zero-priced goods are free without an offer

A lookup, resolution or probe request may carry no offer: the server answers whatever it prices at zero right now, counts it as demand, and declines the rest naming the price. An asker facing a zero price asks without an offer and, declined with a named price, offers that once. The Lookup page still asks only this node's own providers by itself; a member's zero price is listed under "Ask for more" at "free".

**Files:**
- Modify: `src/credits/pay.rs` (`quotes`, `retry_price`, new `serve_free`, `keep_if_recorded`, `offer_and_ask`)
- Modify: `src/credits/price.rs` (`Table::price_of` and `Table::announced` for `RESOLVE`)
- Modify: `src/intel/lookup.rs` (`serve`, `cheap`)
- Modify: `src/admin/lookup.rs:79-110` (`Offer::from_quotes` takes this node's id)
- Modify: `src/intel/dns.rs` (`ResolveResp.price_mc`, `serve_resolve`, `resolver_price`, `ask`)
- Modify: `src/scan/probe/serve.rs:205-245` (`serve` without an offer)
- Modify: `src/scan/probe/ask.rs:118-180` (`offer_once` at price 0)
- Test: `src/credits/pay.rs`, `src/intel/lookup.rs`, `src/scan/probe/serve.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `pay::serve_free(node: &Arc<Node>, providers: &Providers, peer: NodeId, ip: IpAddr, served: Vec<String>) -> LookupResp`
  - `pay::retry_price(offered: Mc, named: Option<u32>, nothing_answered: bool) -> Option<Mc>`: retries up to `max(offered, 1) × RETRY_AT_MOST`.
  - `pay::offer_and_ask(node, ip, server, providers, total_mc)`: `total_mc == 0` asks without an offer.
  - `lookup::cheap(me: NodeId, quotes: &HashMap<String, Vec<Quote>>) -> Vec<String>`
  - `admin::lookup::Offer::from_quotes(me: NodeId, all: &HashMap<String, Vec<Quote>>) -> Offer`
  - `dns::ResolveResp { addrs, error, charged_mc, price_mc: Option<u32> }` (`price_mc` `#[serde(default, skip_serializing_if = "Option::is_none")]`), `dns::ResolveResp::priced(why: &str, price_mc: u32) -> ResolveResp`
  - `price::Table::price_of(RESOLVE)` is `Some(resolve_mc)`, also at 0; `announced()` always carries `resolve`.

- [ ] **Step 1: Write the failing unit tests**

In `src/credits/pay.rs` tests, add:

```rust
    #[test]
    fn a_zero_offer_is_retried_at_a_small_named_price_only() {
        assert_eq!(retry_price(0, Some(1), true), Some(1));
        assert_eq!(retry_price(0, Some(2), true), Some(2), "twice of one mc");
        assert_eq!(retry_price(0, Some(3), true), None);
        assert_eq!(retry_price(0, None, true), None);
        assert_eq!(retry_price(0, Some(1), false), None, "something was answered");
    }
```

In `src/intel/lookup.rs` tests, replace the body of `cheap_tier_is_what_this_node_answers` after the `q` closure with:

```rust
        let me = NodeId([1; 32]);
        let quotes: HashMap<String, Vec<Quote>> = [
            (super::super::TOR.to_string(), vec![q(super::super::TOR, 1, 0)]),
            (
                super::super::ABUSEIPDB.to_string(),
                vec![q(super::super::ABUSEIPDB, 2, 300)],
            ),
            // A member's zero price: free, but asked only when told to.
            (
                super::super::SHODAN.to_string(),
                vec![q(super::super::SHODAN, 2, 0)],
            ),
            // This node and a member both at zero, the member first.
            (
                super::super::RDAP.to_string(),
                vec![q(super::super::RDAP, 2, 0), q(super::super::RDAP, 1, 0)],
            ),
        ]
        .into();
        assert_eq!(cheap(me, &quotes), [super::super::RDAP, super::super::TOR]);
```

In `src/scan/probe/serve.rs`, at the end of `this_nodes_own_request_needs_no_offer_and_charges_nothing`, replace the last block ("Another node's request without an offer is still declined.") with:

```rust
        // Another node's request without an offer: declined at a price,
        // naming it ...
        let other = NodeId([9; 32]);
        node.set_price_table(Arc::new(price::Table {
            probe_mc: Some(5),
            ..Default::default()
        }));
        let resp = prober.serve(&node, other, &req).await;
        assert_eq!(
            resp,
            ProbeResp::Declined {
                why: "probes are paid with credits: the request carries no offer".into(),
                price_mc: Some(5),
            }
        );
        // ... and served free at zero, with no receipt.
        node.set_price_table(Arc::new(price::Table {
            probe_mc: Some(0),
            ..Default::default()
        }));
        let before = node.own_head.load(std::sync::atomic::Ordering::Relaxed);
        let resp = prober.serve(&node, other, &req).await;
        assert!(matches!(resp, ProbeResp::Accepted { .. }), "{resp:?}");
        for _ in 0..100 {
            if store.probes_for_ip(ip.id).await.unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let probes = store.probes_for_ip(ip.id).await.unwrap();
        assert_eq!((probes.len(), probes[0].charged_mc), (2, 0));
        assert_eq!(
            node.own_head.load(std::sync::atomic::Ordering::Relaxed),
            before + 1,
            "the result alone"
        );
```

- [ ] **Step 2: Write the failing cluster test**

In `tests/cluster.rs`, after `a_price_above_the_offer_is_declined_and_named`:

```rust
/// A provider priced at zero is answered without an offer and costs
/// nothing; one with a price is declined naming it, and the asker's offer
/// of that price is served.
#[tokio::test]
async fn a_zero_priced_lookup_is_served_without_an_offer() {
    use peephole::credits::{pay, price};
    use peephole::intel::lookup::{LookupReq, LookupResp};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0)), ("shodan", Some(1000.0))], 0.5);
    nb.node.set_price_table(std::sync::Arc::new(price::Table {
        offers: vec![
            price::Offer {
                provider: "abuseipdb".into(),
                price_mc: 0,
                on_demand: 500,
            },
            price::Offer {
                provider: "shodan".into(),
                price_mc: 7,
                on_demand: 500,
            },
        ],
        ..Default::default()
    }));
    let ask = |providers: &[&str]| LookupReq {
        ip: "203.0.113.81".into(),
        providers: providers.iter().map(|p| p.to_string()).collect(),
        offer_seq: None,
    };
    let resp: LookupResp = na
        .call(b.id, &b.address(), "/rpc/v1/lookup", &ask(&["abuseipdb", "shodan"]))
        .await
        .unwrap();
    assert_eq!(resp.findings.len(), 1, "{resp:?}");
    assert_eq!(resp.findings[0].provider, "abuseipdb");
    assert_eq!((resp.charged_mc, resp.price_mc), (0, Some(7)));
    assert!(
        resp.declined
            .iter()
            .any(|(p, why)| p == "shodan" && why.contains("the request carries no offer")),
        "{resp:?}"
    );
    // Nothing was written: no offer, no receipt.
    assert!(
        peephole::credits::entries::since(&nb.store.pool, 0)
            .await
            .unwrap()
            .is_empty()
    );
    // The asker's side: a quote of zero is asked without an offer.
    nb.node.refresh_heartbeat();
    price_seen(&na, b.id, "abuseipdb").await;
    let wanted = ["abuseipdb".to_string()];
    let free = pay::offer_and_ask(&na.node, "203.0.113.82".parse().unwrap(), b.id, &wanted, 0).await;
    assert_eq!((free.findings.len(), free.charged_mc), (1, 0));
}
```

(`price_seen` waits until `na` holds `b`'s announced price for the provider; check that it accepts a price of 0 — if it waits for a price above 0, give it a `>= 0` variant for this test.)

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib credits::pay intel::lookup scan::probe::serve` and `cargo test --test cluster a_zero_priced_lookup_is_served_without_an_offer`
Expected: compile errors for `cheap(me, …)`, then failures: `retry_price(0, Some(1))` is None; the probe at zero is declined; the cluster lookup declines `abuseipdb` ("lookups are paid with credits").

- [ ] **Step 4: Implement the server side**

In `src/credits/pay.rs`:

1. `quotes`: push `price_mc: *price_mc` (no clamp); in its doc comment replace "(never less than the floor: what another node answers is paid)" with "(at the price it announces, which may be 0)".

2. Add a constant and use it for both "share is spent" literals in `serve`:

```rust
/// Why a provider whose on-demand share is used up is declined.
const SHARE_SPENT: &str = "this node's on-demand share of that provider is spent for today";
```

3. Move the tail of `serve` that keeps answers of a recorded address (from `if !resp.findings.is_empty() && recorded(...)` to `resp.kept = all;`) into:

```rust
/// Keep `resp`'s answers in the dataset when the cluster recorded `ip`.
async fn keep_if_recorded(node: &Arc<Node>, ip: IpAddr, resp: &mut LookupResp) {
    if resp.findings.is_empty() || !recorded(&node.store.pool, &ip).await {
        return;
    }
    let rec = crate::store::recorder::Recorder::Cluster(node.clone());
    let text = crate::net::canonical(ip).to_string();
    let mut all = true;
    for f in &resp.findings {
        let version = f.source_version.as_deref();
        let written = if provider_info(&f.provider).is_some_and(|i| i.api) {
            rec.record_lookup(&text, &f.provider, version, f.data.clone()).await
        } else {
            rec.record_intel(&text, &f.provider, version, f.data.clone()).await
        };
        if let Err(e) = written {
            tracing::warn!(provider = %f.provider, ?e, "lookup result not kept");
            all = false;
        }
    }
    resp.kept = all;
}
```

and call `keep_if_recorded(node, ip, &mut resp).await;` where the block was.

4. Add:

```rust
/// The serving side of a request without an offer: what this node prices
/// at zero now is answered free (it still takes the on-demand share and
/// counts as demand); the rest is declined naming its price, so the asker
/// may offer it.
pub async fn serve_free(
    node: &Arc<Node>,
    providers: &Providers,
    peer: NodeId,
    ip: IpAddr,
    served: Vec<String>,
) -> LookupResp {
    let table = node.price_table();
    let shares = node.lookup_shares();
    let provider = |name: &str| providers.iter().find(|p| p.name() == name);
    let (mut free, mut declined, mut priced) = (vec![], vec![], 0 as Mc);
    for name in served {
        node.market.note(&name, 1);
        let price = table.price_of(&name).unwrap_or(0);
        if price > 0 {
            priced += price as Mc;
            declined.push((
                name,
                format!(
                    "this costs {} credits here now; the request carries no offer",
                    show(price as Mc)
                ),
            ));
            continue;
        }
        let taken = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.take(p.as_ref()).await.unwrap_or(false),
            _ => true,
        };
        match taken {
            true => free.push(name),
            false => declined.push((name, SHARE_SPENT.to_string())),
        }
    }
    let mut resp = if free.is_empty() {
        LookupResp::default()
    } else {
        crate::intel::lookup::local(providers, &ip, &free).await
    };
    if priced > 0 {
        resp.price_mc = Some(priced.min(u32::MAX as Mc) as u32);
    }
    tracing::info!(asker = %peer.short(), providers = %free.join(","), "free lookup served");
    keep_if_recorded(node, ip, &mut resp).await;
    resp.declined.append(&mut declined);
    resp
}
```

5. `retry_price`:

```rust
pub(crate) fn retry_price(offered: Mc, named: Option<u32>, nothing_answered: bool) -> Option<Mc> {
    let p = named? as Mc;
    let bound = offered.max(1).saturating_mul(RETRY_AT_MOST);
    (nothing_answered && p > offered && p <= bound).then_some(p)
}
```

and update its doc: "… only up to [`RETRY_AT_MOST`] times what it offered (one mc for a request without an offer)".

In `src/intel/lookup.rs` `serve`, replace the `None => LookupResp { declined: … "lookups are paid with credits" … }` arm with `None => crate::credits::pay::serve_free(node, providers, peer, ip, served).await,` and update the function's doc ("without one, what this node prices at zero is answered free and the rest is declined naming its price").

In `src/credits/price.rs`, `Table::price_of`: `RESOLVE => Some(self.resolve_mc),`; `Table::announced`: push `(RESOLVE.to_string(), self.resolve_mc)` unconditionally.

In `src/intel/dns.rs`:

```rust
/// A node's answer: the global addresses its resolver returned, or why
/// there are none.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResp {
    pub addrs: Vec<IpAddr>,
    #[serde(default)]
    pub error: Option<String>,
    /// What the resolver charged, in mc.
    #[serde(default)]
    pub charged_mc: u32,
    /// Its price, when the request offered less (or nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_mc: Option<u32>,
}

impl ResolveResp {
    pub fn refused(why: &str) -> ResolveResp {
        ResolveResp {
            addrs: vec![],
            error: Some(why.to_string()),
            charged_mc: 0,
            price_mc: None,
        }
    }

    /// Declined for its price, which it names.
    pub fn priced(why: &str, price_mc: u32) -> ResolveResp {
        ResolveResp {
            price_mc: Some(price_mc),
            ..ResolveResp::refused(why)
        }
    }
}
```

Rewrite `serve_resolve` after the `valid_name` check:

```rust
    let cost = node.price_table().price_of(price::RESOLVE).unwrap_or(0);
    node.market.note(price::RESOLVE, 1);
    let seq = match req.offer_seq {
        Some(seq) => Some(seq),
        None if cost == 0 => None,
        None => {
            return ResolveResp::priced(
                &format!(
                    "resolving a name costs {} credits here now; the request carries no offer",
                    crate::credits::show(cost as u64)
                ),
                cost,
            );
        }
    };
    if let Some(seq) = seq {
        let accepted =
            pay::accept_offer(node, peer, seq, cost as u64, "resolve", pay::SERVE_MARGIN_MS).await;
        match accepted {
            Ok(_) => {}
            Err(pay::Declined::TooLow { why, price_mc }) => {
                return ResolveResp::priced(&why, price_mc);
            }
            Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => {
                return ResolveResp::refused(&w);
            }
        }
    }
    let taken = match node.lookup_shares() {
        Some(s) => s.take_good(price::RESOLVE).await.unwrap_or(false),
        None => true,
    };
    if !taken {
        if let Some(seq) = seq {
            pay::release(node, peer, seq).await;
        }
        return ResolveResp::refused("this node's resolutions for others are used up for today");
    }
    let answer = resolve_here(&name).await;
    let charged = match seq {
        None => 0,
        Some(seq) => {
            let charged = charge_for(&answer, cost);
            let receipt = Record::CreditReceipt {
                payer: peer,
                offer_seq: seq,
                charged_mc: charged,
                answered: if charged > 0 { vec![price::RESOLVE.into()] } else { vec![] },
            };
            match crate::cluster::repl::append(node, &[receipt]).await {
                Ok(_) => charged,
                Err(e) => {
                    tracing::warn!(?e, "resolve receipt not written");
                    0
                }
            }
        }
    };
    match answer {
        Ok(addrs) => ResolveResp {
            addrs,
            error: None,
            charged_mc: charged,
            price_mc: None,
        },
        Err(e) => ResolveResp::refused(&e),
    }
```

(The old "no resolution price yet" branch goes: the table always prices resolution now, 0 before the first refresh. Demand is counted for every request that names a valid host, as the market counter does for lookups.)

`resolver_price`: drop `.filter(|mc| *mc > 0)` and change its doc to "What `id` announces for resolving a name (0: free); None: no price, or it predates the market."

Replace `ask` with:

```rust
/// One member's answer: asked without an offer at a zero price, with one
/// otherwise; a decline naming a higher price is offered that once.
async fn ask(node: &Arc<Node>, id: NodeId, name: &str) -> (NodeId, Result<Vec<IpAddr>, String>) {
    let Some(price) = resolver_price(node, &id) else {
        return (id, Err("announces no price for resolving".into()));
    };
    let mut resp = ask_once(node, id, name, price as u64).await;
    if let Ok(r) = &resp
        && r.error.is_some()
        && let Some(p) = crate::credits::pay::retry_price(price as u64, r.price_mc, true)
    {
        resp = ask_once(node, id, name, p).await;
    }
    let answer = match resp {
        Err(e) => Err(e),
        Ok(ResolveResp { error: Some(e), .. }) => Err(e),
        Ok(ResolveResp { addrs, .. }) => Ok(addrs),
    };
    (id, answer)
}

/// One request to `id`, with an offer of `price` unless it is 0.
async fn ask_once(
    node: &Arc<Node>,
    id: NodeId,
    name: &str,
    price: u64,
) -> Result<ResolveResp, String> {
    let offer_seq = match price {
        0 => None,
        p => Some(crate::credits::pay::make_offer(node, id, p).await?),
    };
    let req = ResolveReq {
        name: name.to_string(),
        offer_seq,
    };
    let call = node.call_any::<ResolveReq, ResolveResp>(
        id,
        "/rpc/v1/resolve",
        &req,
        crate::intel::lookup::RPC_TIMEOUT,
    );
    match call.await {
        Err(e) if e.downcast_ref::<crate::cluster::msg::NoAnswer>().is_some() => {
            Err("did not answer in time".into())
        }
        Err(e) => Err(format!("could not be asked: {e:#}")),
        Ok(r) => Ok(r),
    }
}
```

In `src/scan/probe/serve.rs` `serve`, replace the `None => { return match parsed {…} }` arm with:

```rust
            None if price_u32 == 0 => {
                node.market.note(price::PROBE, 1);
                None
            }
            None => {
                node.market.note(price::PROBE, 1);
                return match parsed {
                    Err(why) => declined(why, None),
                    Ok(_) => declined(
                        "probes are paid with credits: the request carries no offer",
                        Some(price_u32),
                    ),
                };
            }
```

and update the doc comment of `serve` ("This node's own request, and any request while the probe price is 0, carries no offer: it is free and has no receipt.").

- [ ] **Step 5: Implement the asking side**

`src/credits/pay.rs` `offer_and_ask`: replace the offer with

```rust
    // A zero price is asked without an offer.
    let offer_seq = match total_mc {
        0 => None,
        mc => match make_offer(node, server, mc).await {
            Ok(seq) => Some(seq),
            Err(why) => return decline(why),
        },
    };
    let req = LookupReq {
        ip: ip.to_string(),
        providers: providers.to_vec(),
        offer_seq,
    };
```

and sync after an empty answer only when `offer_seq.is_some()` (there is no receipt to fetch otherwise).

`src/scan/probe/ask.rs` `offer_once`: replace the `make_offer` block with

```rust
    let offer_seq = match price {
        0 => None,
        p => match pay::make_offer(node, server, p).await {
            Ok(seq) => Some(seq),
            Err(why) => return refused(why),
        },
    };
```

use `offer_seq` in the `ProbeReq`, and run the sync after a decline only when `offer_seq.is_some()`.

`src/intel/lookup.rs`:

```rust
/// The providers a lookup asks without being told to: those this node
/// serves itself (free here). A member's zero price is listed under "Ask
/// for more", at "free", and asked only when picked.
pub fn cheap(me: NodeId, quotes: &HashMap<String, Vec<crate::credits::pay::Quote>>) -> Vec<String> {
    let mut v: Vec<String> = quotes
        .iter()
        .filter(|(_, l)| l.iter().any(|q| q.server == me))
        .map(|(p, _)| p.clone())
        .collect();
    v.sort();
    v
}
```

and in `run`: `let cheap = cheap(node.id(), &crate::credits::pay::quotes(node, providers));`.

`src/admin/lookup.rs` `Offer::from_quotes(me: NodeId, all)`: `let cheap = crate::intel::lookup::cheap(me, all);`; for a provider in `cheap`, show this node's own quote (`list.iter().find(|q| q.server == me)`), otherwise the first (cheapest) one; the "free" label for a price of 0 stays. Update every caller (`grep -n from_quotes src`) to pass `node.id()`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib credits::pay intel::lookup intel::dns scan::probe admin::lookup` and `cargo test --test cluster a_zero_priced_lookup a_price_above_the_offer a_resolution`
Expected: PASS. `a_price_above_the_offer_is_declined_and_named` ends by asking without an offer: its provider is priced above 0, so it is still declined, now with "the request carries no offer" — change its last assertion from `why.contains("paid with credits")` to `why.contains("the request carries no offer")`.

- [ ] **Step 7: Commit**

```bash
git add src/credits/pay.rs src/credits/price.rs src/intel/lookup.rs src/intel/dns.rs \
  src/admin/lookup.rs src/scan/probe/serve.rs src/scan/probe/ask.rs tests/cluster.rs
git commit -m "Credits: zero-priced lookups, names and probes are free without an offer"
```

---

### Task 3: Prices move by sales, with no floor

Every price steps up when its good sold in the period (or is at capacity) and down otherwise, by the existing bounded step, from wherever it is, down to 0. Reverse names get a price of their own (`rdns`), announced like resolution.

**Files:**
- Modify: `src/credits/price.rs` (constants, `sales_step`, `start`, `current`, `scanner_current`, `granted_scans`, `scanner_raises`, `Table.rdns_mc`, `refresh`; tests)
- Modify: `src/scan/probe/serve.rs:155-162,425-440` (`Prober::price` falls back to 0)
- Modify: `src/credits/pay.rs:430` (a provider missing from the table costs 0)
- Modify: `src/admin/credits.rs` (`good_label` names `rdns`)
- Modify: `tests/cluster.rs` (`a_paid_probe_is_accepted_served_and_charged`: no floor)
- Test: `src/credits/price.rs`, `src/scan/probe/serve.rs`

**Interfaces:**
- Consumes: Task 2's `Table::price_of(RESOLVE) == Some(resolve_mc)`.
- Produces:
  - `price::RAISE_PER_HOUR: f64 = 0.45`, `price::LOWER_PER_HOUR: f64 = 0.15`, `price::RDNS: &str = "rdns"`
  - `price::sales_step(price: Mc, raise: bool, hours: f64) -> Mc`
  - `price::start(announced: &[u32]) -> Mc` (lower median, zeros included; 0 when nobody announces)
  - `price::granted_scans(pool: &SqlitePool) -> Result<HashMap<NodeId, Vec<u64>>>` (finish times in ms, past hour, one per job)
  - `price::scanner_raises(finished: &[u64], now_ms: u64, period_ms: u64, can_do: f64) -> bool`
  - `price::Table.rdns_mc: u32`; `price_of(RDNS) == Some(rdns_mc)`; `announced()` always carries `rdns`.
  - `ScannerPrice.paid` now means "scans of jobs granted to it that finished in the past hour" (name kept).
  - Removed: `PRICE_FLOOR`, `PRICE_STEP`, `step`, `flow_step`, `scaled_step`, `provider_price`, `scanner_step`, `paid_scans`, `charged_jobs`.

- [ ] **Step 1: Write the failing tests**

In `src/credits/price.rs` tests, delete `a_price_follows_the_imbalance_within_a_bounded_step`, `a_short_period_moves_a_flow_price_by_its_share_of_a_step`, `every_provider_follows_its_supply`, `a_scanner_price_follows_its_paid_load`, `six_ten_minute_steps_move_a_price_like_one_hourly_step`, `a_saturated_scanner_settles_near_the_target` and `paid_scans_count_charged_jobs_and_own_jobs_by_finish_time`, and add:

```rust
    #[test]
    fn a_price_rises_when_it_sold_and_falls_when_it_did_not() {
        let up = |h: f64| (1000.0 * (RAISE_PER_HOUR * h).exp()).round() as Mc;
        let down = |h: f64| (1000.0 * (-LOWER_PER_HOUR * h).exp()).round() as Mc;
        assert_eq!(sales_step(1000, true, 1.0), up(1.0));
        assert_eq!(sales_step(1000, false, 1.0), down(1.0));
        assert_eq!(sales_step(1000, true, 1.0 / 6.0), up(1.0 / 6.0), "ten minutes");
        assert_eq!(sales_step(1000, false, 5.0), down(1.0), "never more than a full step");
    }

    #[test]
    fn a_price_has_no_floor_and_a_used_good_leaves_zero() {
        let mut p: Mc = 1000;
        for _ in 0..1000 {
            p = sales_step(p, false, 1.0 / 6.0);
        }
        assert_eq!(p, 0, "unsold for long enough: free");
        assert_eq!(sales_step(0, false, 1.0), 0, "never below 0");
        assert_eq!(sales_step(0, true, 1.0 / 6.0), 1, "sold at 0: up by at least 1 mc");
        assert_eq!(sales_step(3, false, 1.0 / 6.0), 2, "rounding does not hold it");
        assert_eq!(sales_step(u32::MAX as Mc, true, 1.0), u32::MAX as Mc);
    }

    #[test]
    fn six_ten_minute_steps_move_a_price_like_one_hourly_step() {
        for raise in [true, false] {
            let hourly = sales_step(1_000_000, raise, 1.0);
            let mut p = 1_000_000;
            for _ in 0..6 {
                p = sales_step(p, raise, 1.0 / 6.0);
            }
            let diff = (p as f64 - hourly as f64).abs() / hourly as f64;
            assert!(diff < 0.002, "raise {raise}: {p} vs {hourly}");
        }
    }

    #[test]
    fn a_scanner_rises_when_a_granted_scan_ended_in_the_period_or_at_capacity() {
        let (now, min) = (10 * 3_600_000u64, 60_000u64);
        assert!(scanner_raises(&[now - 5 * min], now, 10 * min, 10.0), "sold in the period");
        assert!(!scanner_raises(&[now - 30 * min], now, 10 * min, 10.0), "sold before it");
        let nine: Vec<u64> = (0..9).map(|i| now - (20 + i) * min).collect();
        assert!(scanner_raises(&nine, now, 10 * min, 10.0), "90 % of capacity in the hour");
        assert!(!scanner_raises(&nine[..8], now, 10 * min, 10.0));
        assert!(!scanner_raises(&[], now, 10 * min, 0.0), "a paused scanner sells nothing");
    }

    #[tokio::test]
    async fn granted_scans_count_each_job_once_by_finish_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let pool = &store.pool;
        let (s, a) = (id(1), id(2));
        sqlx::query(
            "INSERT INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')",
        )
        .execute(pool)
        .await
        .unwrap();
        // (job uid, queued by, its scanner, finished minutes ago)
        for (n, (uid, origin, by, ago)) in [
            ("paid", a, s, 10),     // granted to s: counts
            ("free", a, s, 10),     // granted at zero: counts too
            ("own", s, s, 20),      // the scanner's own job: counts
            ("old", a, s, 90),      // finished over an hour ago
            ("other", s, a, 10),    // granted to a, but s wrote the scan
            ("future", s, s, -600), // dated ahead: never counts
        ]
        .into_iter()
        .enumerate()
        {
            sqlx::query(
                "INSERT INTO scan_jobs (id, ip_id, level, status, queued_at, uid, origin, arbiter, scanner)
                 VALUES (?, 1, 1, 'done', datetime('now','-2 hours'), ?, ?, ?, ?)",
            )
            .bind(n as i64 + 1).bind(uid).bind(&origin.0[..]).bind(&origin.0[..]).bind(&by.0[..])
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
                 VALUES (?, 1, 1, datetime('now', ?), datetime('now', ?), ?, ?, ?)",
            )
            .bind(n as i64 + 1)
            .bind(format!("{} minutes", -(ago + 5)))
            .bind(format!("{} minutes", -ago))
            .bind(format!("scan-{uid}")).bind(&s.0[..]).bind(uid)
            .execute(pool).await.unwrap();
        }
        // More scan records of one job count once.
        for k in 0..3 {
            sqlx::query(
                "INSERT INTO scans (job_id, ip_id, level, started_at, finished_at, uid, origin, job_uid)
                 VALUES (3, 1, 1, datetime('now','-9 minutes'), datetime('now','-8 minutes'), ?, ?, 'own')",
            )
            .bind(format!("again-{k}")).bind(&s.0[..])
            .execute(pool).await.unwrap();
        }
        let got = granted_scans(pool).await.unwrap();
        assert_eq!(got.get(&s).map(Vec::len), Some(3), "{got:?}");
        assert_eq!(got.get(&a), None, "{got:?}");
        let now = crate::cluster::hlc::wall_ms();
        assert!(got[&s].iter().all(|t| *t <= now && *t + 3_600_000 >= now));
    }
```

Change `a_new_good_starts_at_the_median_announced_or_the_floor` to:

```rust
    #[test]
    fn a_new_good_starts_at_the_lower_median_announced_or_zero() {
        assert_eq!(start(&[]), 0);
        assert_eq!(start(&[300, 100, 200]), 200);
        assert_eq!(start(&[100, 400]), 100, "lower median");
        assert_eq!(start(&[0, 0]), 0);
        assert_eq!(start(&[0, 400]), 0, "a free announcement counts");
    }
```

In `a_table_knows_what_it_offers` the announced prices are now the two providers, `resolve` and `rdns`: change `assert_eq!(prices.len(), 2);` to

```rust
        assert_eq!(prices.len(), 4);
        assert!(prices.contains(&(RESOLVE.to_string(), 0)));
        assert!(prices.contains(&(RDNS.to_string(), 0)));
        assert_eq!(t.price_of(RDNS), Some(0));
```

In `src/scan/probe/serve.rs`, rename `the_price_is_the_tables_or_the_floor` to `the_price_is_the_tables_or_zero` and assert `prober.price(&price::Table::default()) == 0`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib credits::price scan::probe::serve`
Expected: compile errors (`sales_step`, `granted_scans`, `scanner_raises`, `RDNS` missing).

- [ ] **Step 3: Implement the step and the start**

In `src/credits/price.rs` replace `PRICE_FLOOR`, `PRICE_STEP`, `scanner_step`, `step`, `flow_step`, `scaled_step` and `provider_price` with:

```rust
/// Per hour a price rises at most by e^0.45 and falls by e^-0.15 (the
/// sizes of the market before the sales rule).
pub const RAISE_PER_HOUR: f64 = 0.45;
pub const LOWER_PER_HOUR: f64 = 0.15;
/// Reverse names of a source looked up for another member (`intel::rdns`).
pub const RDNS: &str = "rdns";

/// One step of a price `hours` after the last: up when the good sold in
/// that period (or is at capacity), down when it sold nothing. A period
/// shorter than an hour takes that share of the hour's step, a longer one
/// a full step. The price moves by at least 1 mc, which is what lifts a
/// used good off zero; it never goes below zero. No floor.
pub fn sales_step(price: Mc, raise: bool, hours: f64) -> Mc {
    let scale = hours.clamp(0.0, 1.0);
    let rate = if raise { RAISE_PER_HOUR } else { -LOWER_PER_HOUR };
    let p = (price as f64 * (rate * scale).exp())
        .round()
        .min(u32::MAX as f64) as Mc;
    match (raise, p == price) {
        (true, true) => price.saturating_add(1).min(u32::MAX as Mc),
        (false, true) => price.saturating_sub(1),
        _ => p,
    }
}
```

Update the module doc: "What a good costs here: one rule for every good. A good that sold in the last period gets dearer, one that sold nothing cheaper, by a bounded step an hour, down to nothing."

`start`:

```rust
/// Where a good's price starts here: the lower median of what members
/// announce for it, free ones included; 0 when nobody does.
pub fn start(announced: &[u32]) -> Mc {
    let mut v = announced.to_vec();
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[(v.len() - 1) / 2] as Mc
}
```

`current`: take `old.price_of(good)` as it is (drop `.filter(|p| *p > 0)`), and the kept value without `.max(PRICE_FLOOR)`. `scanner_current`: drop the `.filter(|p| *p > 0)` and every `.max(PRICE_FLOOR)`.

Replace `charged_jobs` and `paid_scans` with:

```rust
/// The scans of jobs granted to each scanner that finished in the past
/// hour, as wall-clock ms by the scan's own `finished_at`: one per job
/// (its scanner's first record), none dated in the future. Granted at
/// any price, zero included: a sale.
pub async fn granted_scans(pool: &sqlx::SqlitePool) -> Result<HashMap<NodeId, Vec<u64>>> {
    let rows: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT s.origin, MIN(s.finished_at) FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.audit_of IS NULL AND s.origin IS NOT NULL AND s.job_uid IS NOT NULL
           AND s.finished_at > datetime('now', '-1 hour')
           AND s.finished_at <= datetime('now')
         GROUP BY s.origin, s.job_uid",
    )
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<NodeId, Vec<u64>> = HashMap::new();
    for (scanner, finished) in rows {
        let (Ok(scanner), Ok(t)) = (
            NodeId::from_slice(&scanner),
            chrono::NaiveDateTime::parse_from_str(&finished, "%Y-%m-%d %H:%M:%S"),
        ) else {
            continue;
        };
        out.entry(scanner)
            .or_default()
            .push(t.and_utc().timestamp_millis().max(0) as u64);
    }
    Ok(out)
}

/// Whether a scanner's price rises: a scan of a job granted to it ended
/// in the last `period_ms`, or its granted scans of the past hour reach
/// [`PAID_TARGET`] of what it can do (at capacity).
pub fn scanner_raises(finished: &[u64], now_ms: u64, period_ms: u64, can_do: f64) -> bool {
    let sold = finished.iter().any(|t| t.saturating_add(period_ms) >= now_ms);
    let full = can_do > 0.0 && finished.len() as f64 >= PAID_TARGET * can_do;
    sold || full
}
```

Update `PAID_TARGET`'s doc: "Share of a scanner's capacity at which it counts as at capacity: its price rises whatever it sold."

- [ ] **Step 4: Implement the table and the refresh**

`Table`: add after `resolve_mc`:

```rust
    /// What looking up a source's reverse names for another member costs here.
    pub rdns_mc: u32,
```

`price_of`: add `RDNS => Some(self.rdns_mc),`. `announced`: push `(RDNS.to_string(), self.rdns_mc)` after `resolve`.

In `refresh`, replace everything from `let none = vec![];` down to (and including) the loop that writes `scanner_prices` with:

```rust
    let none = vec![];
    let ann = |g: &str| announced.get(g).unwrap_or(&none).clone();
    let got = |g: &str| demand.get(g).copied().unwrap_or(0.0);
    // A good that was asked for sold (a request beyond the supply is a
    // sale too), so it rises; one nobody asked for falls.
    let next = |cur: Mc, good: &str| as_mc(sales_step(cur, got(good) > 0.0, hours));
    let empty = vec![];
    let providers = node.lookup_providers().unwrap_or(&empty);
    let offer_per_day = node
        .lookup_shares()
        .map_or(crate::config::DEFAULT_OFFER_PER_DAY, |s| s.offer_per_day());
    let mut offers = vec![];
    for p in providers.iter().filter(|p| p.ready()) {
        let on_demand = node
            .lookup_shares()
            .map_or(offer_per_day, |s| s.allowance(p.as_ref()));
        let cur = current(node, &old, p.name(), &ann(p.name())).await?;
        offers.push(Offer {
            provider: p.name().to_string(),
            price_mc: next(cur, p.name()),
            on_demand,
        });
    }
    let resolve_mc = next(current(node, &old, RESOLVE, &ann(RESOLVE)).await?, RESOLVE);
    let rdns_mc = next(current(node, &old, RDNS, &ann(RDNS)).await?, RDNS);
    let probe_mc = match node.prober() {
        Some(_) => Some(next(current(node, &old, PROBE, &ann(PROBE)).await?, PROBE)),
        None => None,
    };
    // Every scanner's price, from the scans of jobs granted to it: the
    // same public inputs on every node.
    let granted = granted_scans(&node.store.pool).await?;
```

keep the `legacy_key` block and `let now_ms = …;`, then:

```rust
    let mut scanner_prices = vec![];
    for s in &capacity.scanners {
        let (cur, hours) = scanner_current(node, &old, &s.node, legacy, &ann(SCAN), now_ms).await?;
        let finished = granted.get(&s.node).map(Vec::as_slice).unwrap_or(&[]);
        let period_ms = (hours.clamp(0.0, 1.0) * 3_600_000.0) as u64;
        let raise = scanner_raises(finished, now_ms, period_ms, s.can_do);
        let price_mc = as_mc(sales_step(cur, raise, hours));
        node.store
            .intel_set(&scanner_key(&s.node), &format!("{price_mc}@{now_ms}"))
            .await?;
        scanner_prices.push(ScannerPrice {
            node: s.node,
            price_mc,
            paid: (finished.len() as f64).min(s.can_do),
            supply: PAID_TARGET * s.can_do,
        });
    }
```

Keep the rest, with these changes: the `intel_set(&price_key(good), …)` chain adds `.chain([(RDNS, rdns_mc)])`; the history `goods` gets an `RDNS` row after `RESOLVE` (`(RDNS, Some(rdns_mc), per_hour(got(RDNS)), offer_per_day as f64 / 24.0)`); the final `Table` sets `rdns_mc`. `book` is still read for `left_out`. Remove imports that are now unused.

Fix the old floor references:
- `src/scan/probe/serve.rs` `Prober::price`: `table.probe_mc.unwrap_or(0)`; its doc "…or 0 before the first refresh".
- `src/credits/pay.rs` `serve`: `table.price_of(name).unwrap_or(0) as Mc`.
- `src/admin/credits.rs` `good_label`: `credits::price::RDNS => "Reverse names".into(),`; in the page's `rank` closure give `RDNS` the rank 3 and shift the providers to 4.
- `tests/cluster.rs` `a_paid_probe_is_accepted_served_and_charged`: replace `assert!(cost as u64 >= price::PRICE_FLOOR);` by first raising the scanner's probe price with `priced(&nb, price::PROBE, 1).await` (use the scanner's `TestNode`) and asserting `cost >= 1`.

`grep -rn "PRICE_FLOOR\|flow_step\|scanner_step\|provider_price\|paid_scans\|charged_jobs" src tests` must print nothing.

A restart must not make every good free until the first refresh (a minute later). Add, and call from `src/lib.rs` right after the cluster node is opened (before `cluster::start`):

```rust
/// Seed this node's table from the prices it kept, so a restart serves
/// at them until the first refresh steps them.
pub async fn load_kept(node: &Node) -> Result<()> {
    let kept = |good: &str| {
        let store = node.store.clone();
        let key = price_key(good);
        async move { store.intel_get(&key).await.ok().flatten().and_then(|v| v.parse::<Mc>().ok()) }
    };
    let mut t = Table::default();
    t.resolve_mc = kept(RESOLVE).await.map_or(0, as_mc);
    t.rdns_mc = kept(RDNS).await.map_or(0, as_mc);
    if node.prober().is_some() {
        t.probe_mc = kept(PROBE).await.map(as_mc);
    }
    for p in node.lookup_providers().into_iter().flatten().filter(|p| p.ready()) {
        if let Some(mc) = kept(p.name()).await {
            t.offers.push(Offer {
                provider: p.name().to_string(),
                price_mc: as_mc(mc),
                on_demand: node
                    .lookup_shares()
                    .map_or(crate::config::DEFAULT_OFFER_PER_DAY, |s| s.allowance(p.as_ref())),
            });
        }
    }
    let me = node.id();
    if let Some((mc, _)) = node.store.intel_get(&scanner_key(&me)).await?.and_then(|v| parse_kept(&v)) {
        t.sell_mc = Some(as_mc(mc));
    }
    node.set_price_table(Arc::new(t));
    Ok(())
}
```

(`at_ms` stays 0, so the first refresh takes a full step from the kept prices, as it does today. Call it after the prober and the lookup providers are set on the node; Task 9 adds `relay_mc` here too. Test: in `price.rs`'s tests, keep `price:resolve = 40` on a `test_node`, call `load_kept`, and assert `node.price_table().price_of(RESOLVE) == Some(40)`.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib credits scan::probe admin::credits` and `cargo test --test cluster price a_paid_probe a_funded_scan_job`
Expected: PASS. `priced()` raises from 0 by 1 mc per refresh (its period is tiny), which reaches the small targets the tests ask for; if a test needs more than 50 mc, seed the kept price (`intel_set("price:<good>", …)`) before calling it.

- [ ] **Step 6: Commit**

```bash
git add src/credits/price.rs src/credits/pay.rs src/scan/probe/serve.rs src/admin/credits.rs tests/cluster.rs
git commit -m "Prices: sold rises, unsold falls, no floor; reverse names priced"
```

---

### Task 4: The quorum size, and resolution by the cheapest

A quorum good asks `q = min(9, ⌊n/2⌋ + 1)` nodes: this node and the q−1 cheapest members announcing a price for it, ties broken by the existing diversity order. Resolution uses it now; Task 7's reverse names reuse it.

**Files:**
- Modify: `src/intel/dns.rs` (`MAX_RESOLVERS` → `MAX_QUORUM`, `quorum`, `member_price`, `pick_cheapest`, `choose(…, good)`, `lookup_with`; tests)
- Modify: `src/store/probes.rs:192` (`MAX_QUORUM`)
- Modify: `tests/cluster.rs` (the one `dns::choose` call)
- Test: `src/intel/dns.rs`

**Interfaces:**
- Consumes: Task 2's `resolver_price` without the `> 0` filter.
- Produces:
  - `dns::MAX_QUORUM: usize = 9`, `dns::quorum(n: usize) -> usize`
  - `dns::member_price(node: &Node, id: &NodeId, good: &str) -> Option<u32>` (`resolver_price(node, id)` = `member_price(node, id, price::RESOLVE)`)
  - `dns::pick_cheapest(first: Resolver, rest: &[(Resolver, u32)], n: usize) -> Vec<Resolver>`
  - `dns::choose(node: &Node, siblings: &HashSet<NodeId>, geo: &SharedGeo, good: &str) -> Vec<Resolver>`
  - Removed: `MAX_RESOLVERS`, `pick`, `keep_priced`.

- [ ] **Step 1: Write the failing tests**

In `src/intel/dns.rs` tests, delete `priced_candidate` and `only_priced_market_resolvers_are_chosen`, and replace `resolvers_prefer_non_siblings_and_new_countries` with:

```rust
    fn r(i: u8, sibling: bool, country: Option<&str>) -> Resolver {
        Resolver {
            id: NodeId([i; 32]),
            name: format!("n{i}"),
            sibling,
            country: country.map(str::to_string),
        }
    }

    fn ids(v: Vec<Resolver>) -> Vec<u8> {
        v.iter().map(|r| r.id.0[0]).collect()
    }

    #[test]
    fn the_quorum_is_a_majority_of_the_priced_members_and_at_most_nine() {
        for (n, q) in [(0, 1), (1, 1), (2, 2), (3, 2), (4, 3), (5, 3), (16, 9), (17, 9), (100, 9)] {
            assert_eq!(quorum(n), q, "n = {n}");
        }
    }

    #[test]
    fn at_one_price_resolvers_prefer_non_siblings_and_new_countries() {
        let rest: Vec<(Resolver, u32)> = [
            r(1, true, Some("FR")),
            r(2, false, Some("DE")),
            r(3, false, Some("US")),
            r(4, false, None),
            r(5, true, Some("JP")),
            r(6, false, Some("US")),
            r(7, false, Some("BR")),
        ]
        .into_iter()
        .map(|c| (c, 0))
        .collect();
        let me = || r(0, false, Some("DE"));
        // This node; new countries among non-siblings; then the other non-siblings.
        assert_eq!(ids(pick_cheapest(me(), &rest, 5)), [0, 3, 7, 2, 4]);
        // Siblings only when nothing else is left, a new country first.
        assert_eq!(ids(pick_cheapest(me(), &rest, 8)), [0, 3, 7, 2, 4, 6, 1, 5]);
        assert_eq!(ids(pick_cheapest(me(), &rest[..1], 5)), [0, 1]);
        assert_eq!(ids(pick_cheapest(me(), &[], 3)), [0], "alone");
    }

    #[test]
    fn the_cheapest_are_asked_first_and_diversity_breaks_ties() {
        let rest = [
            (r(7, false, Some("BR")), 9),
            (r(4, false, None), 3),
            (r(2, false, Some("DE")), 1),
            (r(3, false, Some("US")), 1),
        ];
        let me = || r(0, false, Some("DE"));
        assert_eq!(ids(pick_cheapest(me(), &rest, 3)), [0, 3, 2], "at 1: the new country first");
        assert_eq!(ids(pick_cheapest(me(), &rest, 4)), [0, 3, 2, 4]);
        assert_eq!(ids(pick_cheapest(me(), &rest, 9)), [0, 3, 2, 4, 7]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib intel::dns`
Expected: compile errors (`quorum`, `pick_cheapest` missing).

- [ ] **Step 3: Implement**

In `src/intel/dns.rs`, replace `MAX_RESOLVERS` with:

```rust
/// Most nodes asked for a quorum good (a name resolved, a source's
/// reverse names), this node included.
pub const MAX_QUORUM: usize = 9;

/// How many nodes a quorum good asks: a majority of the `n` reachable
/// members announcing a price for it (this node included), at most
/// [`MAX_QUORUM`]; alone, 1.
pub fn quorum(n: usize) -> usize {
    (n / 2 + 1).min(MAX_QUORUM)
}
```

Replace `resolver_price` and `keep_priced` with:

```rust
/// What `id` announces for `good` (0: free); None: no price, or it
/// predates the market.
pub fn member_price(node: &Node, id: &NodeId, good: &str) -> Option<u32> {
    let m = node.members().get(id).cloned()?;
    if !crate::credits::pay::pays_with(m.proto_max) {
        return None;
    }
    node.status
        .known(id)?
        .hb
        .prices
        .iter()
        .find(|(g, _)| g == good)
        .map(|(_, mc)| *mc)
}

/// What `id` announces for resolving a name.
pub fn resolver_price(node: &Node, id: &NodeId) -> Option<u32> {
    member_price(node, id, crate::credits::price::RESOLVE)
}
```

Replace `choose` and `pick` with:

```rust
/// The nodes asked for `good`: this node, then the [`quorum`]'s other
/// members among the live, callable members that announce a price for
/// it, cheapest first (see [`pick_cheapest`]).
pub fn choose(
    node: &Node,
    siblings: &HashSet<NodeId>,
    geo: &SharedGeo,
    good: &str,
) -> Vec<Resolver> {
    use rand::seq::SliceRandom;
    let me = node.id();
    let resolver = |id: NodeId| {
        let (name, country) = describe(node, geo, &id);
        Resolver {
            id,
            name,
            sibling: siblings.contains(&id),
            country,
        }
    };
    let mut others: Vec<NodeId> = node
        .live_members(crate::intel::LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id != me && !node.is_blocked(id) && node.can_call(id))
        .collect();
    // Equal prices in random order, so no member is preferred.
    others.shuffle(&mut rand::rng());
    let priced: Vec<(Resolver, u32)> = others
        .into_iter()
        .filter_map(|id| Some((resolver(id), member_price(node, &id, good)?)))
        .collect();
    let q = quorum(priced.len() + 1);
    pick_cheapest(resolver(me), &priced, q)
}

/// `first` (this node), then up to `n` in all of `rest`, cheapest first;
/// among equal prices non-siblings before siblings, and within each a new
/// country before a seen one, otherwise in `rest`'s order.
pub fn pick_cheapest(first: Resolver, rest: &[(Resolver, u32)], n: usize) -> Vec<Resolver> {
    let mut rest: Vec<&(Resolver, u32)> = rest.iter().collect();
    // Stable: equal prices keep their (shuffled) order.
    rest.sort_by_key(|(_, p)| *p);
    let mut seen: HashSet<String> = first.country.iter().cloned().collect();
    let mut out = vec![first];
    let mut i = 0;
    while i < rest.len() && out.len() < n {
        let price = rest[i].1;
        let tier: Vec<&Resolver> = rest[i..]
            .iter()
            .take_while(|(_, p)| *p == price)
            .map(|(r, _)| r)
            .collect();
        i += tier.len();
        for (sibling, fresh) in [(false, true), (false, false), (true, true), (true, false)] {
            for c in &tier {
                if out.len() >= n {
                    return out;
                }
                if c.sibling != sibling || out.iter().any(|o| o.id == c.id) {
                    continue;
                }
                if fresh && !c.country.as_deref().is_some_and(|x| !seen.contains(x)) {
                    continue;
                }
                if let Some(x) = &c.country {
                    seen.insert(x.clone());
                }
                out.push((*c).clone());
            }
        }
    }
    out.truncate(n.max(1));
    out
}
```

In `lookup_with`: `choose(node, &siblings, geo, crate::credits::price::RESOLVE)`. Update the module doc's "several nodes at once" to "a quorum of nodes (`quorum`), the cheapest first". In `src/store/probes.rs` `apply_ip_name`: `r.answers.len() > dns::MAX_QUORUM`. In `tests/cluster.rs` (`an_old_outbound_only_member_is_not_asked`): `dns::choose(&na.node, &Default::default(), &geo, peephole::credits::price::RESOLVE)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib intel::dns store::probes admin::lookup`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/intel/dns.rs src/store/probes.rs tests/cluster.rs
git commit -m "Lookup: a name is resolved by a quorum of the cheapest members"
```

---

### Task 5: Every scan job is funded, at zero or above

A bid at price 0 is affordable; a grant at 0 writes no offer and the scanner treats it as funded. The idle-work branch (granting the best bid unpaid), the sit-out draws for unpaid jobs, the paid/funded distinction in hand-outs and the scanner-side demotion of arbiters that grant unfunded all go. A job with no affordable bid is not granted this round and waits. The offer is written before the job is marked running, so a failed offer leaves the job queued.

**Files:**
- Modify: `src/credits/jobs.rs` (`affordable`, `fund`, docs; tests)
- Modify: `src/scan/arbiter.rs` (`Lease.funded`, `complete`, `round`, `grant`, module doc; tests)
- Modify: `src/scan/handout.rs` (unpaid reasons, `paid`, `sat_out`)
- Modify: `src/scan/weight.rs` (delete `skipped_levels` and `draw` with their tests)
- Modify: `src/scan/mod.rs:150-200,300-340,600-690` (demotion goes)
- Modify: `src/admin/scans.rs:560-580` (test `Handout` literal)
- Modify: `src/cluster/status.rs:395-440` (`refresh_heartbeat`: a scanner announces 0 before its first refresh)
- Test: `src/credits/jobs.rs`, `src/scan/arbiter.rs`, `src/scan/mod.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: Task 3 (scanner prices can be 0; `start()` is 0 without announcements).
- Produces:
  - `jobs::affordable(node, funding, min_mc, price) -> bool`: true at `price == 0` (when `price >= min_mc`).
  - `jobs::fund(...) -> Option<(Option<u64>, u32)>`: `Some((None, 0))` for a zero price, without an offer or a reservation.
  - `jobs::price_for(node, scanner) -> Option<u32>`: without this node's copy of the scanner's price (before its first refresh), an announced 0 is taken as it is; any other announced price is not (it cannot be capped).
  - A scanner's heartbeat carries `scan_price_mc = Some(0)` until its first refresh (Decision 8).
  - `Arbiter::grant(&self, funding, claim, job, price: u32) -> Result<Option<Grant>>`: None when the offer could not be written (the job stays queued).
  - `scan::handout::Handout` without `paid` and `sat_out`; `Reason` is `Cheapest | Override`.
  - `[credits] scan_share = 0` funds only zero-priced scanners.

- [ ] **Step 1: Write the failing tests**

In `src/credits/jobs.rs` tests (they already build ledgers by hand), add:

```rust
    #[tokio::test]
    async fn a_zero_price_is_affordable_without_credits_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = crate::cluster::Node::open(crate::cluster::NodeParams {
            identity: crate::cluster::identity::Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                peers: vec![],
            },
            roles: Default::default(),
            store: store.clone(),
            proto: (2, 2),
            data_dir: dir.path().to_path_buf(),
            retention_days: 0,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        node.set_scan_share(0.0);
        let mut f = Funding::default();
        assert!(affordable(&node, &mut f, 0, 0).await, "free, even with a share of 0");
        assert!(!affordable(&node, &mut f, 0, 1).await, "no credits");
        assert!(!affordable(&node, &mut f, 5, 0).await, "under the scanner's least");
        let other = crate::cluster::identity::Identity::generate().unwrap().id;
        assert_eq!(fund(&node, &mut f, other, "job-1", 0, 0).await, Some((None, 0)));
        assert_eq!(fund(&node, &mut f, node.id(), "job-2", 0, 0).await, Some((None, 0)));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_entries")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "no offer written");
        assert_eq!(self_committed(&store.pool, &node.id()).await.unwrap(), 0);
    }
```

In `src/scan/arbiter.rs` tests, add the helper and tests:

```rust
    /// A member scanner priced at 0, with this node's copy of its price:
    /// granted at zero, without credits.
    async fn zero_scanner(node: &Node) -> NodeId {
        use crate::credits::price::{Limit, ScannerCapacity, ScannerPrice};
        let id = remote_scanner(node, 0).await;
        let mut t = (*node.price_table()).clone();
        t.scanners.push(ScannerPrice {
            node: id,
            price_mc: 0,
            paid: 0.0,
            supply: 0.0,
        });
        t.capacity.scanners.push(ScannerCapacity {
            node: id,
            can_do: 100.0,
            did: 0.0,
            limited_by: Limit::PerHour,
        });
        node.set_price_table(Arc::new(t));
        id
    }

    #[tokio::test]
    async fn a_zero_priced_scanner_is_granted_without_an_offer() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let free = zero_scanner(&node).await;
        let uid = queue(&node, &store, 2, 2).await;
        let g = arbiter.next_job(free, &[], 0).await.unwrap();
        assert_eq!((g.job_uid.as_str(), g.offer_seq, g.price_mc), (uid.as_str(), None, 0));
        let h = handout_of(&store, &uid).await;
        assert_eq!(h.reason, crate::scan::handout::Reason::Cheapest);
    }

    #[tokio::test]
    async fn a_scanner_announcing_zero_is_granted_before_this_node_has_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        // No `references`: this node has no copy of its price yet.
        let fresh = remote_scanner(&node, 0).await;
        let pricey = remote_scanner(&node, 40).await;
        let uid = queue(&node, &store, 2, 2).await;
        assert!(arbiter.next_job(pricey, &[], 0).await.is_none(), "40 cannot be capped yet");
        let g = arbiter.next_job(fresh, &[], 0).await.unwrap();
        assert_eq!((g.job_uid.as_str(), g.price_mc), (uid.as_str(), 0));
    }

    #[tokio::test]
    async fn a_job_nobody_can_be_paid_for_waits() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        // Priced, but this node holds no credits; and one without a price here.
        let priced = remote_scanner(&node, 30).await;
        references(&node, &[(priced, 30, 100.0)]);
        let unknown = Identity::generate().unwrap().id;
        let uid = queue(&node, &store, 2, 2).await;
        let got = arbiter
            .round(&[claim_of(priced, &[]), claim_of(unknown, &[])])
            .await
            .unwrap();
        assert!(got.iter().all(Option::is_none), "{got:?}");
        assert_eq!(status(&store, &uid).await, "queued");
    }
```

Delete `no_budget_grants_without_an_offer`, `an_unpaid_job_skips_scanners_sitting_its_level_out` and `an_unpaid_grant_says_why`. In `a_scanner_without_a_reference_goes_after_a_priced_one`, rename it to `a_scanner_without_a_reference_is_not_granted`, keep the first half and replace the tail ("Alone, it is granted unpaid.") with `assert!(arbiter.claim(other, vec![], 0).await.is_none());`. In `a_regranted_job_drops_its_old_reservation`, grant the second time to a `zero_scanner` instead of an unpriced id, and assert its reservation is cleared as before. Every other test that claims with a bare `Identity::generate().unwrap().id` (`grep -n "Identity::generate().unwrap().id" src/scan/arbiter.rs`) claims with `zero_scanner(&node).await` instead, so its job can be granted.

In `src/scan/mod.rs` tests, delete the `demotes` assertions (the test that holds them keeps its `can_pay` part) and add:

```rust
    #[test]
    fn an_arbiter_can_pay_a_zero_price_from_nothing() {
        let other = Payer {
            own: false,
            sells_scans: true,
            announced: Some((1, 0)),
            balance: Some(0),
        };
        assert!(can_pay(Some(0), 0, &other));
        let idle = Payer {
            announced: Some((0, 0)),
            ..other
        };
        assert!(!can_pay(Some(0), 0, &idle), "nothing queued");
    }
```

(`Payer` derives nothing today: add `#[derive(Clone, Copy)]` if the struct-update syntax needs it.)

In `tests/cluster.rs`, after `a_funded_scan_job_pays_the_scanner_its_price`:

```rust
/// A scanner priced at 0 is granted the job without an offer; once its
/// price has risen, the next job is funded with one.
#[tokio::test]
async fn a_job_is_granted_at_zero_and_funded_once_the_price_rises() {
    use peephole::credits::{self, entries, ledger::OfferState, price};
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
    grant_scans(&[&na, &nb], a.id, 8).await;
    market_known(&na, b.id).await;
    market_known(&nb, a.id).await;
    na.node.set_scan_share(0.5);
    let key = format!("price:scan:{}", b.id);
    for n in [&na, &nb] {
        n.store.intel_set(&key, "0").await.unwrap();
        price::refresh(&n.node).await.unwrap();
    }
    eventually("a hears b's price of 0", || async {
        na.node.status.known(&b.id).and_then(|k| k.hb.scan_price_mc) == Some(0)
    })
    .await;
    enqueue(&na, "198.51.100.43", 2).await;
    eventually_for(Duration::from_secs(40), "scanned at zero", || async {
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
    })
    .await;
    assert!(entries::since(&na.store.pool, 0).await.unwrap().is_empty(), "no offer");
    // The price rises: the next job is funded.
    for n in [&na, &nb] {
        n.store.intel_set(&key, "1000").await.unwrap();
        price::refresh(&n.node).await.unwrap();
    }
    let sell = nb.node.price_table().price_of(price::SCAN).unwrap();
    eventually("a hears b's new price", || async {
        na.node.status.known(&b.id).and_then(|k| k.hb.scan_price_mc) == Some(sell)
    })
    .await;
    enqueue(&na, "198.51.100.44", 2).await;
    eventually_for(Duration::from_secs(40), "scanned and charged", || async {
        let book = credits::book_fresh(&na.node).await.unwrap();
        book.ledger.offers.iter().any(|o| {
            o.payer == a.id && o.job.is_some() && matches!(o.state, OfferState::Charged { charged } if charged > 0)
        })
    })
    .await;
}
```

(Task 6 replaces `grant_scans` here with the pool helper, like everywhere else.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib credits::jobs scan::arbiter scan::tests` and `cargo test --test cluster a_job_is_granted_at_zero`
Expected: `affordable(…, 0, 0)` is false; the zero scanner's grant goes through the idle branch with `Reason::NoPrice`/`Unpaid`; the unpayable job is granted unpaid.

- [ ] **Step 3: Implement the funding**

`src/credits/jobs.rs`:
- `affordable`: replace `if price == 0 || price < min_mc { return false; }` with `if price < min_mc { return false; }` and, right after, `if price == 0 { return true; }` (a free grant needs no book).
- `fund`: after clearing the old reservation, `if price == 0 { return Some((None, 0)); }` before `affordable`. Doc: "`Some((None, 0))` at a zero price: granted free, without an offer. None: a price under `min_mc`, no budget, or the offer could not be written; the job is not granted."
- `price_for`:

```rust
/// What this node, as arbiter, would pay `scanner` for a job now: its own
/// scanner its selling price (0 before the first refresh); another
/// scanner what it announces, at most [`price::PRICE_TOLERANCE`] times
/// this node's copy, or an announced 0 while there is no copy yet. None:
/// not a scanner of the market, or a price that cannot be capped yet; it
/// cannot be granted the job.
pub fn price_for(node: &Node, scanner: &NodeId) -> Option<u32> {
    let table = node.price_table();
    if *scanner == node.id() {
        return table
            .price_of(price::SCAN)
            .or_else(|| node.roles().scanner.then_some(0));
    }
    let k = node.status.known(scanner)?;
    if !node
        .members()
        .get(scanner)
        .is_some_and(|m| super::pay::sells_scans(m.proto_max))
    {
        return None;
    }
    match table.reference(scanner) {
        Some(_) => price::offer_price(k.hb.scan_price_mc, table.reference(scanner)),
        None => k.hb.scan_price_mc.filter(|p| *p == 0),
    }
}
```

- `src/cluster/status.rs` `refresh_heartbeat`: `scan_price_mc: table.price_of(crate::credits::price::SCAN).or_else(|| (self.roles().scanner && local.pace.is_some()).then_some(0)),` (a scanner sells free until its first refresh, as a prober does).
- Module doc: "Every grant is funded: at the scanner's price, which may be 0 (then without an offer)."

`src/scan/arbiter.rs`:
- Module doc: replace "A paid job waits … ; an unpaid job goes by the old sit-out draws." with "Every grant is funded, at zero or above; a job no claimant can be paid for waits. A job waits for a cheaper live scanner up to `weight::OVERRIDE_WAIT_MINS`."
- `Lease`: delete `funded`; `recover` and `grant` stop setting it; `complete`: `"later" | "declined" if undelivered(status, error.as_deref()) => …` (every grant is funded).
- `round`: replace from `// The best claimant this round's book can pay` to the `let next = …;` with:

```rust
                // The best claimant this round's book can pay; with none,
                // the job waits for the next round.
                let mut payee = None;
                for (k, (ci, b)) in bids.iter().enumerate() {
                    if let Some(p) = b.price
                        && crate::credits::jobs::affordable(
                            &self.node,
                            &mut funding,
                            claims[*ci].min_mc,
                            p.saturating_mul(factor),
                        )
                        .await
                    {
                        payee = Some(k);
                        break;
                    }
                }
                let Some(pick) = payee else { continue };
                let top = bids[pick].1.clone();
                let standby: Vec<Standby> = scanners
                    .iter()
                    .filter(|s| {
                        !stands[*s].demoted
                            && !table.can_do(s).is_some_and(|c| c < 1.0)
                            && takes(s)
                            && !last.get(*s).is_some_and(|(x, min_mc)| {
                                x.contains(&(level as u8))
                                    || stands[*s].price.is_some_and(|p| p < *min_mc)
                            })
                    })
                    .map(|s| {
                        let t = snap.tallies.get(&(*s, level)).copied().unwrap_or_default();
                        Standby {
                            id: *s,
                            price: stands[s].price,
                            weight: weight::weight(&snap.tallies, *s, &scanners, level),
                            sample: t.ok + t.failed,
                        }
                    })
                    .collect();
                let (reason, waited) =
                    match rank::waits(top.effective(), rank::reserve(&standby), job.waited_secs) {
                        Wait::Hold => {
                            self.held
                                .lock()
                                .unwrap()
                                .entry(job.uid.clone())
                                .or_insert_with(Instant::now);
                            continue;
                        }
                        Wait::Go => {
                            let held = self.held.lock().unwrap().get(&job.uid).copied();
                            (Reason::Cheapest, held.map_or(0, |t| t.elapsed().as_secs() as i64))
                        }
                        Wait::Override => (Reason::Override, job.waited_secs),
                    };
```

  keep the `outranked_by` block unchanged, then:

```rust
                let (i, bid) = bids[pick].clone();
                let next = bids
                    .iter()
                    .find(|(_, b)| b.id != bid.id)
                    .map(|(_, b)| (b.id, b.effective()));
                let c = &claims[i];
                let price = bid.price.unwrap_or(0).saturating_mul(factor);
                let g = match self.grant(&mut funding, c, &job, price).await {
                    Ok(Some(g)) => g,
                    // The offer could not be written: the job stays queued.
                    Ok(None) => continue,
                    Err(e) => {
                        warn!(?e, job = %job.uid, "handing out scan jobs stopped");
                        break 'pages;
                    }
                };
```

  and build the `Handout` without `paid` and `sat_out`, with `reason` as is. Delete the `overdue` binding and the `bids_top_claim` binding if they become unused.
- `grant(&self, funding, claim, job, price: u32) -> Result<Option<Grant>>`: fund first, then write the state:

```rust
    /// Fund `job` for `claim`'s scanner at `price` and mark it running
    /// under a lease. None: the offer could not be written; the job stays
    /// queued.
    async fn grant(
        &self,
        funding: &mut crate::credits::jobs::Funding,
        claim: &Claimant,
        job: &Queued,
        price: u32,
    ) -> Result<Option<Grant>> {
        let Some((offer_seq, price)) =
            crate::credits::jobs::fund(&self.node, funding, claim.id, &job.uid, claim.min_mc, price)
                .await
        else {
            return Ok(None);
        };
        self.rec
            .write(vec![Record::JobStatus(JobStatusRec {
                job_uid: job.uid.clone(),
                status: "running".into(),
                started_at: Some(now_ts()),
                finished_at: None,
                error: None,
                attempts: job.attempts + 1,
                scanner: Some(claim.id),
            })])
            .await?;
        self.leases.lock().unwrap().insert(
            job.uid.clone(),
            Lease {
                scanner: claim.id,
                expires: Instant::now() + self.lease,
            },
        );
        if price > 0 {
            info!(job = %job.uid, scanner = %claim.id.short(),
                price = %crate::credits::show(price as u64), "scan job funded");
        }
        Ok(Some(Grant {
            job_uid: job.uid.clone(),
            ip: job.ip.clone(),
            level: job.level,
            lease_secs: self.lease.as_secs().max(1),
            offer_seq,
            price_mc: price,
        }))
    }
```

  (If the state write fails after an offer was written, the offer lapses unanswered: nothing is charged.)

`src/scan/handout.rs`: delete `Reason::{Unpaid, NoPrice, BelowMin, OfferFailed}`, `Reason::unpaid`, and the `paid` and `sat_out` fields; `record` binds `1` for `paid` and `0` for `sat_out` (the columns stay); reading back skips rows whose reason does not parse (hand-outs of the old rules, gone within `KEEP_DAYS`); `describe` loses its unpaid wording. Fix `src/admin/scans.rs`'s test literal.

`src/scan/weight.rs`: delete `skipped_levels`, `draw` and their test `a_decision_holds_for_a_stretch_and_follows_the_weight`; keep `MIN_WEIGHT` (the weight floor).

`src/scan/mod.rs`: delete `DEMOTE_FOR`, the `demoted` field (and its initialiser), `Payer.demoted`, `demotes`, the `asked_as_paying` set and the block that demotes after a grant. `can_pay` keeps ordering arbiters: drop the `a.demoted ||` test. A grant without an offer is a free grant: `offer: g.offer_seq.zip(Some(g.price_mc))` is None and nothing is settled.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib credits::jobs scan admin::scans` and `cargo test --test cluster a_job_is_granted_at_zero a_funded_scan_job the_cheaper_scanner scanners_share expired_lease outbound_only_scanner`
Expected: PASS. Cluster tests never run the price loop, so their scanners announce 0 and their arbiters, holding no copy, grant at 0 without credits: the scan tests that relied on unpaid grants keep working unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/credits/jobs.rs src/scan/arbiter.rs src/scan/handout.rs src/scan/weight.rs \
  src/scan/mod.rs src/admin/scans.rs tests/cluster.rs
git commit -m "Scans: every job is funded, at zero or above; no idle work, no demotion"
```

---

### Task 6: Protocol 7 — the cut and the pool

The mint, the allowance, the judge, the counted-scan weights and `credits why` go. At the end of each UTC day (credited one hour after midnight) `POOL_PER_DAY` is split evenly among the day's verified listeners, the remainder one mc each to the lowest keys; a member that does not earn here is not credited here and its share is not redistributed. Payments of the new economy carry `economy: 2` and are signed under `peephole-repl-v2\0`; the ledger reads only those. `PROTO_VERSION` and `ECONOMY_PROTO` become 7; payments, funded jobs, resolutions and probes run only between protocol-7 members; sync withholds protocol-7-only entries from older members.

**Files:**
- Create: `src/credits/pool.rs`
- Delete: `src/credits/earn.rs`, `src/credits/mint.rs`
- Modify: `src/store/migrations/0029_scarce_credits.sql` (append)
- Modify: `src/cluster/rpc/proto.rs` (versions)
- Modify: `src/cluster/record.rs` (`economy` fields, signing domain, `ECONOMY`, `ECONOMY_KINDS`, `Record::economy`, `WireEntry::needs_economy_proto`)
- Modify: `src/cluster/repl.rs:247-330` (`entries_after(…, old_peer)`), `src/cluster/rpc/mod.rs:90-110`, `src/cluster/sync.rs:395` (callers)
- Modify: `src/credits/entries.rs` (economy column, filter)
- Modify: `src/credits/ledger.rs` (`Gates`, receipt gates, docs)
- Modify: `src/credits/gates.rs` (drop `to_gates`, `earn::Gates`)
- Modify: `src/credits/mod.rs` (`Book`, `compute`, `run`, modules, docs)
- Modify: `src/credits/pay.rs`, `src/credits/jobs.rs`, `src/credits/fleet.rs`, `src/intel/dns.rs`, `src/scan/probe/serve.rs` (every `Record::Credit*` they write carries `economy: ECONOMY`; `pays_with`/`sells_scans`)
- Modify: `src/credits/cli.rs` (`why` goes, `log` shows the pool), `tests/cli.rs` (the `why` test goes)
- Modify: `src/admin/credits.rs`, `templates/admin_cluster_credits.html`, `assets/js/charts.js:392-418`, `assets/css/35-pages.css:141-142` (money from the pool; page details are Task 10's)
- Modify: `src/admin/overview.rs` (+ its template: counted scans go)
- Modify: `src/scan/arbiter.rs` tests (`give_credits`, `remote_scanner`'s protocol)
- Modify: `tests/cluster.rs` (helpers, deleted tests, new tests)
- Test: `src/credits/pool.rs`, `src/credits/ledger.rs`, `src/credits/entries.rs`, `src/cluster/record.rs`, `src/cluster/repl.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: Task 1 (`reach::{since, uptime, verified, record, Uptime}`), Task 5 (funded jobs).
- Produces:
  - `proto::PROTO_VERSION = 7`, `proto::ECONOMY_PROTO = 7` (replaces `MARKET_PROTO` and `SCAN_PRICE_PROTO`); `pay::pays_with(p)` and `pay::sells_scans(p)` are `p >= ECONOMY_PROTO`.
  - `record::ECONOMY: u8 = 2`, `record::ECONOMY_KINDS: &[&str]` (starts as `["reach_report"]`; Task 7 adds `"rdns_name"`).
  - `Record::CreditOffer { to, parts, seal, job, economy: u8 }`, `Record::CreditReceipt { payer, offer_seq, charged_mc, answered, economy: u8 }`, `Record::CreditTransfer { to, parts, seal, economy: u8 }` (`economy` `#[serde(default, skip_serializing_if = "is_zero_u8")]`); `Record::economy(&self) -> u8`.
  - `WireEntry::needs_economy_proto(&self) -> bool`.
  - `repl::entries_after(store, wants, since_hlc, max_entries, max_bytes, old_peer: bool)`.
  - `credits::pool::{POOL_PER_DAY: Mc, REPORT_GRACE_MS: u64, end_of(day) -> u64, closed(day, now_ms) -> bool, split(day, &BTreeSet<NodeId>) -> Vec<Earned>, credited(&BTreeMap<u32, BTreeSet<NodeId>>, now_ms) -> Vec<Earned>}`, `credits::pool::testing::report_all_day(pool, day, listeners: &[NodeId]) -> Result<()>` (`#[doc(hidden)] pub`).
  - `ledger::Gates { left_out, no_sales, no_scan_sales: HashSet<NodeId> }`, `ledger::run(earned: &[Earned], entries: &[Entry], gates: &Gates, now_ms: u64) -> Ledger`.
  - `credits::Book { ledger, pool: Vec<Earned> /* credited here */, listeners: BTreeMap<u32, BTreeSet<NodeId>>, uptime: reach::Uptime, standings, now_ms }` with `balance`, `standing`, `pool_per_day() -> Mc`, `up_hours(&NodeId, day) -> u32`.

- [ ] **Step 1: Write the failing unit tests**

Create `src/credits/pool.rs` with its doc, constants, `todo!()` bodies and:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn the_pool_is_split_evenly_and_the_rest_goes_to_the_lowest_keys() {
        let three: BTreeSet<NodeId> = [id(9), id(1), id(5)].into();
        let shares = split(DAY, &three);
        assert_eq!(
            shares.iter().map(|e| (e.node, e.mc)).collect::<Vec<_>>(),
            [(id(1), 333_334), (id(5), 333_333), (id(9), 333_333)]
        );
        assert_eq!(shares.iter().map(|e| e.mc).sum::<Mc>(), POOL_PER_DAY);
        assert!(shares.iter().all(|e| e.hlc == end_of(DAY)));
        assert!(split(DAY, &BTreeSet::new()).is_empty(), "nobody: nothing");
        assert_eq!(split(DAY, &[id(3)].into())[0].mc, POOL_PER_DAY);
    }

    #[test]
    fn a_day_is_credited_an_hour_after_it_ends() {
        let end = (DAY as u64 + 1) * DAY_MS;
        assert!(!closed(DAY, end - 1));
        assert!(!closed(DAY, end + 30 * 60_000), "00:30: reports of 23:00 may be on their way");
        assert!(closed(DAY, end + REPORT_GRACE_MS));
        let days: BTreeMap<u32, BTreeSet<NodeId>> =
            [(DAY, [id(1)].into()), (DAY + 1, [id(2)].into())].into();
        let got = credited(&days, end + REPORT_GRACE_MS);
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].node, crate::credits::day_of(got[0].hlc)), (id(1), DAY));
    }
}
```

In `src/credits/ledger.rs` tests: change the `ledger` helper to `run(earned, entries, &Gates::default(), now_ms)`, change `entries_and_earnings_of_a_node_left_out_do_not_count` to pass `&Gates { left_out: [id(…)].into(), ..Default::default() }`, and add:

```rust
    #[test]
    fn the_receipts_of_a_member_that_does_not_earn_here_move_nothing() {
        // 1 pays 2 for a lookup; 2 fails the rules gate here.
        let earned = [earn(1, DAY, 0, 1000)];
        let entries = [
            offer(1, 1, at(DAY, 1), 2, &[(DAY, 300)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 300),
        ];
        let gates = Gates {
            no_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 3));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (700, 0), "held, not paid");
        let l = run(&earned, &entries, &gates, now(DAY, 20));
        assert_eq!(l.balance(&id(1)), 1000, "lapsed back to the payer");
        assert_eq!(l.offers[0].state, OfferState::Lapsed);
    }

    #[test]
    fn a_scanner_failing_the_audit_gates_is_not_paid_for_scans_but_for_lookups() {
        let earned = [earn(1, DAY, 0, 1000)];
        let entries = [
            job_offer(1, 1, at(DAY, 1), 2, &[(DAY, 100)]),
            receipt(2, 1, at(DAY, 2), 1, 1, 100),
            offer(1, 2, at(DAY, 3), 2, &[(DAY, 50)]),
            receipt(2, 2, at(DAY, 4), 1, 2, 50),
        ];
        let gates = Gates {
            no_scan_sales: [id(2)].into(),
            ..Default::default()
        };
        let l = run(&earned, &entries, &gates, now(DAY, 5));
        assert_eq!(l.balance(&id(2)), 50, "the lookup only");
        assert_eq!(l.offers[0].state, OfferState::Open, "the scan offer waits to lapse");
    }
```

In `src/credits/entries.rs` tests, every `Record::Credit*` literal gets `economy: crate::cluster::record::ECONOMY`, and add:

```rust
    #[tokio::test]
    async fn only_payments_of_the_new_economy_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let day = 20_000u32;
        let at = |min: u64| ((day as u64 * crate::credits::DAY_MS + min * 60_000) << 16) | 1;
        let offer = |economy: u8| Record::CreditOffer {
            to: b.id,
            parts: vec![(day, 200)],
            seal: Seal::default(),
            job: None,
            economy,
        };
        let mut conn = store.pool.acquire().await.unwrap();
        for (seq, economy) in [(1, 0u8), (2, crate::cluster::record::ECONOMY)] {
            let r = offer(economy);
            let e = WireEntry::sign(&a, seq, at(seq), &r).unwrap();
            assert!(apply(&mut conn, &e, &r, SealState::Consistent).await.unwrap());
        }
        drop(conn);
        let read = since(&store.pool, 0).await.unwrap();
        assert_eq!(read.iter().map(|e| e.seq).collect::<Vec<_>>(), [2], "the old one is kept, not read");
        assert_eq!(get(&store.pool, &a.id, 1).await.unwrap(), None);
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credit_entries")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 2);
    }
```

In `src/cluster/record.rs` tests:

```rust
    #[test]
    fn payments_of_the_new_economy_are_signed_under_their_own_domain() {
        let id = crate::cluster::identity::Identity::generate().unwrap();
        let offer = |economy: u8| Record::CreditOffer {
            to: NodeId([3; 32]),
            parts: vec![(20_000, 5)],
            seal: Seal::default(),
            job: None,
            economy,
        };
        let new = WireEntry::sign(&id, 4, 9 << 16, &offer(ECONOMY)).unwrap();
        let old = WireEntry::sign(&id, 4, 9 << 16, &offer(0)).unwrap();
        assert!(new.verify() && old.verify());
        assert_ne!(new.digest(), old.digest());
        assert!(new.needs_economy_proto() && !old.needs_economy_proto());
        // The same payload under the old domain does not verify: no older
        // node takes it for a payment of the economy it counts.
        let forged = WireEntry {
            sig: old.sig.clone(),
            payload: new.payload.clone(),
            ..new.clone()
        };
        assert!(!forged.verify());
        assert_eq!(offer(ECONOMY).economy(), ECONOMY);
        assert_eq!(Record::LogSeal { seal: Seal::default() }.economy(), 0);
    }
```

In `src/cluster/repl.rs` tests:

```rust
    /// An older member is served each origin up to its first entry only
    /// protocol 7 knows, never past it (no gap); a protocol-7 member gets all.
    #[tokio::test]
    async fn an_older_member_is_not_served_entries_of_protocol_seven() {
        use crate::cluster::record::{ReachReportRec, Record};
        let (_d, node) = test_node(0).await;
        let first = super::append(&node, &[Record::LogSeal { seal: Default::default() }])
            .await
            .unwrap();
        // (A log_seal is any entry older nodes know; use `append_sealing`
        // if a bare seal cannot be appended.)
        super::append(
            &node,
            &[Record::ReachReport(ReachReportRec {
                hour: crate::credits::reach::hour_of(crate::cluster::hlc::wall_ms()),
                reached: vec![],
            })],
        )
        .await
        .unwrap();
        let wants = [(node.id(), first[0].seq - 1)];
        let old = super::entries_after(&node.store, &wants, 0, 100, 1 << 20, true)
            .await
            .unwrap();
        assert_eq!(old.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [first[0].seq]);
        let new = super::entries_after(&node.store, &wants, 0, 100, 1 << 20, false)
            .await
            .unwrap();
        assert_eq!(new.entries.len(), 2);
    }
```

(If `append` refuses a `LogSeal` built by hand, write the first entry with `super::append_sealing(&node, |seal| Record::LogSeal { seal })` instead.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib credits::pool credits::ledger credits::entries cluster::record cluster::repl::tests::an_older_member`
Expected: compile errors (`economy`, `Gates`, `pool`), then `todo!()` panics.

- [ ] **Step 3: The wire: protocol, economy, domain, sync**

`src/cluster/rpc/proto.rs`: `PROTO_VERSION = 7`; delete `MARKET_PROTO` and `SCAN_PRICE_PROTO`; add

```rust
/// Members from this version count the credits of protocol 7 (a fixed
/// supply, `credits::pool`) and sell scans at their own prices: payments,
/// funded jobs and every paid good run only between them, and sync
/// withholds protocol-7-only entries from older members.
pub const ECONOMY_PROTO: u32 = 7;
```

Fix every use (`grep -rn "MARKET_PROTO\|SCAN_PRICE_PROTO" src tests`): `pays_with` and `sells_scans` compare with `ECONOMY_PROTO`; `pay::tests::only_market_nodes_are_paid` asserts `ECONOMY_PROTO == 7`, `!pays_with(6)`, `pays_with(7)`; the arbiter test helper `remote_scanner` and the cluster tests insert `ECONOMY_PROTO`; tests that build an old member use `ECONOMY_PROTO - 1`. In `accept_offer`, the decline for an older asker reads "your node predates the credits of protocol 7: upgrade it to pay here".

`src/cluster/record.rs`: add after `SIG_DOMAIN`:

```rust
/// Payments of the credits of protocol 7 (`economy` [`ECONOMY`]) are
/// signed under their own domain: no older node takes one for a payment
/// of the economy it counts.
const SIG_DOMAIN_V2: &[u8] = b"peephole-repl-v2\0";
/// The economy of protocol 7's credits (`credits::pool`). Payments
/// without it are of the economy before, which nothing reads any more.
pub const ECONOMY: u8 = 2;
/// Kinds only protocol 7 knows. Sync serves an older member an origin's
/// entries up to the first of these (or of a payment of [`ECONOMY`]).
pub const ECONOMY_KINDS: &[&str] = &["reach_report"];
const CREDIT_KINDS: [&str; 3] = ["credit_offer", "credit_receipt", "credit_transfer"];

fn is_zero_u8(n: &u8) -> bool {
    *n == 0
}

/// The signing domain of an entry of `kind` carrying `payload`.
fn domain(kind: &str, payload: &[u8]) -> &'static [u8] {
    let new = CREDIT_KINDS.contains(&kind)
        && super::rpc::cbor::decode::<Record>(payload).is_ok_and(|r| r.economy() == ECONOMY);
    if new { SIG_DOMAIN_V2 } else { SIG_DOMAIN }
}
```

In `signing_bytes`, use `let d = domain(kind, payload);` and `m.extend_from_slice(d)` (capacity: `d.len()`). Add the field to the three credit variants, after their last field:

```rust
        /// [`ECONOMY`] for the credits of protocol 7; absent (0) before.
        #[serde(default, skip_serializing_if = "is_zero_u8")]
        economy: u8,
```

and

```rust
impl Record {
    /// The economy a payment belongs to; 0 for everything else.
    pub fn economy(&self) -> u8 {
        match self {
            Record::CreditOffer { economy, .. }
            | Record::CreditReceipt { economy, .. }
            | Record::CreditTransfer { economy, .. } => *economy,
            _ => 0,
        }
    }
}

impl WireEntry {
    /// Whether only members of protocol 7 may be served this entry.
    pub fn needs_economy_proto(&self) -> bool {
        ECONOMY_KINDS.contains(&self.kind.as_str())
            || (CREDIT_KINDS.contains(&self.kind.as_str())
                && self.record().is_some_and(|r| r.economy() == ECONOMY))
    }
}
```

Every place that writes a payment sets `economy: ECONOMY` (`grep -rn "Record::CreditOffer {\|Record::CreditReceipt {\|Record::CreditTransfer {" src` outside tests: `pay::release`, `pay::make_offer`, `pay::serve`, `jobs::fund`, `jobs::settle`, `fleet` transfers, `dns::serve_resolve`, `probe::serve`). Pattern matches that destructure them add `..` where needed. `an_offer_without_a_job_encodes_like_one_before_jobs` keeps `economy: 0` (its subject is the old encoding).

`src/cluster/repl.rs` `entries_after`: add the parameter `old_peer: bool` (doc: "an older member: each origin stops at its first entry only protocol 7 knows"), and at the top of the `for e in candidates` loop body, after `let mut e = e?;`:

```rust
            if old_peer && e.needs_economy_proto() {
                break;
            }
```

Callers: the pull handler in `src/cluster/rpc/mod.rs` and `sync.rs:395` pass `node.members().get(&peer).is_some_and(|m| m.proto_max < proto::ECONOMY_PROTO)`; the tests in `repl.rs` pass `false`.

- [ ] **Step 4: Entries, ledger, pool, book**

Append to `src/store/migrations/0029_scarce_credits.sql`:

```sql
-- Payments of protocol 7's credits carry `economy` 2; the ledger reads
-- only those. Older rows stay, unread, until they age out.
ALTER TABLE credit_entries ADD COLUMN economy INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_credit_entries_economy_hlc ON credit_entries(economy, hlc);
-- The judge and its counted scans are gone.
DROP TABLE credit_scans;
```

`src/credits/entries.rs`: `apply` binds `r.economy()` into the new `economy` column; `since` and `get` add `AND economy = 2` (bind `ECONOMY`); the module doc says "Only payments of protocol 7's economy are read; older rows are kept and ignored."

`src/credits/ledger.rs`: module doc: "The ledger: every balance, from the pool credited to the verified listeners (`credits::pool`) and what the log says about payments. … A credit belongs to a lot: a node and the UTC day of the pool it came from. It keeps its lot when it changes hands and is gone 7 days after that day." `Earned` doc: "A pool share credited to a node; its HLC dates the lot." Add `Gates` (as in **Interfaces**, each field documented), replace `Walk.left_out` with `gates: &'a Gates`, and in `Walk::receipt`, before the `position` search, `if self.gates.no_sales.contains(&e.origin) { return; }`, and after it

```rust
        // A scanner failing the audit gates here is not paid for scans.
        if self.l.offers[i].job.is_some() && self.gates.no_scan_sales.contains(&e.origin) {
            return;
        }
```

`run(earned, entries, gates: &Gates, now_ms)` uses `gates.left_out` where it used `left_out`. Every other caller of `ledger::run` (`grep -rn "ledger::run\|run(&earned\|run(&\[" src`, e.g. the `credits::jobs` tests) passes `&Gates::default()` or the gates it means. Its doc: "Members in `gates.left_out` hold nothing and their entries move nothing; the receipts of those in `no_sales`, and the scan receipts of those in `no_scan_sales`, move nothing (their offers lapse back)."

`src/credits/pool.rs`:

```rust
//! Where credits come from: a fixed pool a day, split evenly among that
//! day's verified listeners (`credits::reach`). Nothing else mints and
//! nothing burns, so the supply is six pools. The pool of day d is dated
//! the day's last instant, lands in its lot and lives on days d to d+6.
use super::ledger::Earned;
use super::{CREDIT, DAY_MS, Mc};
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, BTreeSet};

/// Split among the verified listeners per UTC day.
pub const POOL_PER_DAY: Mc = 1000 * CREDIT;
/// A day's pool is credited this long after the day ends: the reports of
/// its last hour are written at midnight and need time to arrive.
pub const REPORT_GRACE_MS: u64 = 3_600_000;

/// The last instant of `day` as an HLC.
pub fn end_of(day: u32) -> u64 {
    (((day as u64 + 1) * DAY_MS - 1) << 16) | 0xFFFF
}

/// Whether `day`'s pool is credited at `now_ms`.
pub fn closed(day: u32, now_ms: u64) -> bool {
    now_ms >= (day as u64 + 1) * DAY_MS + REPORT_GRACE_MS
}

/// `day`'s pool, evenly among `listeners`; the remainder one mc each to
/// the lowest keys.
pub fn split(day: u32, listeners: &BTreeSet<NodeId>) -> Vec<Earned> {
    let n = listeners.len() as Mc;
    if n == 0 {
        return vec![];
    }
    let (each, left) = (POOL_PER_DAY / n, POOL_PER_DAY % n);
    listeners
        .iter()
        .enumerate()
        .map(|(i, node)| Earned {
            node: *node,
            hlc: end_of(day),
            mc: each + Mc::from((i as Mc) < left),
        })
        .collect()
}

/// The shares of every day in `listeners` that is closed at `now_ms`.
pub fn credited(listeners: &BTreeMap<u32, BTreeSet<NodeId>>, now_ms: u64) -> Vec<Earned> {
    listeners
        .iter()
        .filter(|(day, _)| closed(**day, now_ms))
        .flat_map(|(day, set)| split(*day, set))
        .collect()
}

/// For tests: whole days of reports naming listeners.
#[doc(hidden)]
pub mod testing {
    use crate::cluster::identity::NodeId;

    /// Make `listeners` up in every hour of `day` on this store: a
    /// reporter that is no member names them in each hour (merged with
    /// what it named before).
    pub async fn report_all_day(
        pool: &sqlx::SqlitePool,
        day: u32,
        listeners: &[NodeId],
    ) -> anyhow::Result<()> {
        let reporter = NodeId([0xEE; 32]);
        let blob: Vec<u8> = listeners.iter().flat_map(|n| n.0).collect();
        for hour in day * 24..(day + 1) * 24 {
            sqlx::query(
                "INSERT INTO reach_reports (origin, hour, reached) VALUES (?, ?, ?)
                 ON CONFLICT(origin, hour) DO UPDATE SET reached = reached || excluded.reached",
            )
            .bind(&reporter.0[..])
            .bind(hour as i64)
            .bind(&blob)
            .execute(pool)
            .await?;
        }
        Ok(())
    }
}
```

`src/credits/mod.rs`: module doc "Lookup credits: a fixed pool a day for the verified listeners, earned by selling goods, spent on goods. Every node computes every balance for itself…"; modules: drop `earn` and `mint`, add `pool` (and `reach` from Task 1). Replace `Book` and `compute`:

```rust
/// Everything this node knows about credits at one moment: who was up
/// when, whose pool shares it credits, and where every credit is.
pub struct Book {
    pub ledger: ledger::Ledger,
    /// The pool shares this node credits (members that earn here).
    pub pool: Vec<ledger::Earned>,
    /// The verified listeners of each day the window reads.
    pub listeners: BTreeMap<u32, BTreeSet<NodeId>>,
    pub uptime: reach::Uptime,
    /// The members that do not earn in full here.
    pub standings: gates::Standings,
    pub now_ms: u64,
}

impl Book {
    pub fn balance(&self, node: &NodeId) -> Mc {
        self.ledger.balance(node)
    }

    pub fn standing(&self, node: &NodeId) -> gates::Standing {
        self.standings.get(node).cloned().unwrap_or_default()
    }

    /// What the pool credited here a day over the last 7 days.
    pub fn pool_per_day(&self) -> Mc {
        let from = self.now_ms.saturating_sub(7 * DAY_MS);
        let week: Mc = self
            .pool
            .iter()
            .filter(|e| crate::cluster::hlc::physical_ms(e.hlc) >= from)
            .map(|e| e.mc)
            .sum();
        week / 7
    }

    /// `node`'s up hours on `day`, as reported.
    pub fn up_hours(&self, node: &NodeId, day: u32) -> u32 {
        self.uptime.get(&(*node, day)).copied().unwrap_or(0)
    }
}

/// Compute this node's book from what it holds now.
pub async fn compute(node: &Node) -> anyhow::Result<Book> {
    let now_ms = crate::cluster::hlc::wall_ms();
    let since = window_start(now_ms);
    let (first, today) = (day_of(since), (now_ms / DAY_MS) as u32);
    let standings = gates::standings(node).await?;
    let set = |f: &dyn Fn(&gates::Standing) -> bool| -> HashSet<NodeId> {
        standings.iter().filter(|(_, s)| f(s)).map(|(id, _)| *id).collect()
    };
    let gates = ledger::Gates {
        left_out: set(&|s| s.left_out()),
        no_sales: set(&|s| !s.earns()),
        no_scan_sales: set(&|s| !s.earns_as_scanner()),
    };
    let members: Vec<crate::cluster::members::MemberRow> =
        crate::cluster::members::all(&node.store)
            .await?
            .into_iter()
            .filter(|m| m.active)
            .collect();
    let ids: Vec<NodeId> = members.iter().map(|m| m.id).collect();
    let reports = reach::since(&node.store.pool, first * 24).await?;
    let uptime = reach::uptime(&reports, &ids, &gates.left_out);
    let listeners: BTreeMap<u32, BTreeSet<NodeId>> = (first..=today)
        .map(|d| (d, reach::verified(&members, &uptime, d)))
        .collect();
    // A member that does not earn here is not credited here, and its
    // share is not given to anyone else.
    let pool: Vec<ledger::Earned> = pool::credited(&listeners, now_ms)
        .into_iter()
        .filter(|e| !gates.no_sales.contains(&e.node))
        .collect();
    let entries = entries::since(&node.store.pool, since).await?;
    let ledger = ledger::run(&pool, &entries, &gates, now_ms);
    Ok(Book {
        ledger,
        pool,
        listeners,
        uptime,
        standings,
        now_ms,
    })
}
```

(`window_start`'s doc: "the 7 days lots live, and one more"; imports `BTreeMap`, `BTreeSet`.) In `run`: delete `origins`, the `rejudge_args` match, the `earn::Judge`/`earn::judge` block and `earn::prune`; keep everything else (audit settling, standings logging, pruning entries and reach reports, weights snapshot, budget, prices, reach reports from Task 1). Delete `src/credits/earn.rs` and `src/credits/mint.rs`.

`src/credits/gates.rs`: delete `to_gates` and the `use super::earn::Gates;` line; its test keeps the `Standing` assertions and drops the `to_gates` part. Module doc: "…a member's requests must classify the same under this build's rules, its scans must stand up to audits…" stays.

- [ ] **Step 5: Money on the pages and the CLI**

These are the minimum the deleted fields force; Task 10 completes the pages.

`src/admin/credits.rs`:
- Delete `EarnedRow`, the `earned` and `waiting` fields and their queries (`credit_scans` is gone), and the `use … mint` import.
- `MemberRow`: replace `minted` and `allowance` with `pool: String` ("its pool shares credited here over the last 7 days"): `show(sum_week(&book.pool, &m.id))`.
- `income`: `Vec<(String, String)>` of `(date, pool share)` from `book.pool` for this node; `accruing` becomes `today_up: (u32, bool)`: this node's up hours today (`book.up_hours(&me, today)`) and whether it is advertised and a listener (`node.cfg.advertise.is_some() && node.roles().listener`).
- `FlowDay`: replace `mint` and `allowance` with `pool: f64` (filled from `book.pool`).
- The test `the_page_shows_where_credits_come_from` builds the new fields; it asserts `"1000 credits a day"` and `"12 of the day's 24 hours"` instead of the mint sentences, and `"5 hours up today"` for `today_up: (5, true)`.

`templates/admin_cluster_credits.html`:
- Page lede: "A fixed pool a day for the members anyone can reach, earned by selling goods, spent on goods. Every figure is this node's own count, from its copy of the log."
- The "Minted today" tile becomes:
  `<div class="tile"><span class="label">Up today</span><div class="value">{{ today_up.0 }}<span class="of"> hours</span></div><div class="hint">{% if today_up.1 %}reported by the members · 12 earn today's pool share{% else %}not an advertised listener: no pool share{% endif %}</div></div>`
- Money flow legend: `<span><i class="swatch k-pool"></i>pool</span><span><i class="swatch k-sales"></i>sales</span><span><i class="swatch k-spent"></i>spent</span>`.
- "Where credits come from": `<p>Every day 1000 credits are split evenly among the members anyone can reach: advertised listeners that at least half of the members reached in at least 12 of the day's 24 hours. Nothing else creates credits and nothing destroys them; a credit is gone 7 days after the day of its pool. Everything else is earned by selling: lookups, names, probes, scans, audits and relays.</p><p>Today: {{ today_up.0 }} hours up so far; the day's pool is credited an hour after it ends (UTC).</p>` and the income table with columns Day / Pool.
- Cluster table: replace the Mint and Allowance columns with "Pool (7 days)".
- Delete the "Earned" ledger part (judged scans); "Nothing to spend" reads "Credits come from the daily pool, above, and from sales."

`assets/js/charts.js` (`data-flow`): stack `pool` and `sales` instead of `mint`, `allowance`, `sales` (the max, the bars, the hover text and the hidden table); `assets/css/35-pages.css`: rename `.k-mint` to `.k-pool` and delete `.k-allowance`.

`src/admin/overview.rs`: delete `paid_scans` and the `book.paid` loop; `earned` becomes `show(book.pool_per_day())`; the `served_today` query adds `AND economy = 2`. Remove the paid-scans figure from the overview template (`grep -n paid_scans templates`).

`src/credits/cli.rs`: delete `why` (from `USAGE` too) and in `log` replace the `book.paid` loop with the pool shares:

```rust
            for e in book.pool.iter().filter(|e| e.node == me && recent(e.hlc)) {
                lines.push((e.hlc, format!("pool     {:>8}  this node's share of the day", show(e.mc))));
            }
```

`tests/cli.rs`: delete the `why` test.

- [ ] **Step 6: Tests move to the pool**

`src/scan/arbiter.rs` tests: replace `give_credits` with

```rust
    /// Credits for `node`: the whole pool of the day two days back.
    async fn give_credits(store: &crate::store::Store, node: NodeId) {
        let day = (crate::cluster::hlc::wall_ms() / crate::credits::DAY_MS) as u32 - 2;
        sqlx::query("UPDATE members SET address = '198.51.100.1:7443', roles_json = '[\"listener\",\"scanner\"]' WHERE id = ?")
            .bind(&node.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        crate::credits::pool::testing::report_all_day(&store.pool, day, &[node])
            .await
            .unwrap();
    }
```

`tests/cluster.rs`: delete `judge_now`, `grant_scans`, `minted`, `mint_of`, `mint_total`, `a_completed_scan_counts_for_the_scanner_in_every_nodes_book` and `audits_of_made_up_results_stop_a_scanners_shares_where_they_count` (the audit gates are Task 8's). Add:

```rust
/// The day two days back: closed, and its lot alive for 4 more days.
fn pool_day() -> u32 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        / peephole::credits::DAY_MS) as u32
        - 2
}

/// Make `listeners` the verified listeners of [`pool_day`] on every node
/// in `on`: each gets its share of that day's pool.
async fn fund_listeners(on: &[&TestNode], listeners: &[NodeId]) {
    for n in on {
        peephole::credits::pool::testing::report_all_day(&n.store.pool, pool_day(), listeners)
            .await
            .unwrap();
    }
}

/// What `id` holds from the pool when `listeners` share it.
fn share(listeners: &[NodeId], id: NodeId) -> u64 {
    peephole::credits::pool::split(pool_day(), &listeners.iter().copied().collect())
        .iter()
        .filter(|e| e.node == id)
        .map(|e| e.mc)
        .sum()
}
```

Then, in every test: `grant_scans(&[&na, &nb], a.id, 8)` → `fund_listeners(&[&na, &nb], &[a.id])`; several `grant_scans` calls of one test become one `fund_listeners` naming all their nodes; `minted(x, y)` → `share(&[…the funded ids…], <id>)`. A test that compared mint shares by scan counts now compares equal shares. Tests that build an outbound-only payer cannot fund it from the pool (no address): fund a reachable sibling, or have a funded member transfer to it with `peephole::credits::fleet::send`.

Add the cluster tests the spec names for this task:

```rust
/// The pool goes to the advertised listeners that were reached, not to
/// an outbound-only member, and every node credits the same shares.
#[tokio::test]
async fn the_pool_reaches_reached_listeners_only() {
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (io, o) = new_node("node-oscar");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let no = boot(io, &o, &[], Opts { advertise: false, ..DEFAULT }).await;
    let token = invite::create(&na, &Default::default()).await.unwrap();
    invite::join(&no, &token).await.unwrap();
    // Real reports for the current hour: rounds run, then each node
    // reports the hour as if it had ended.
    let next_hour = peephole::cluster::hlc::wall_ms() + 3_600_000;
    eventually("everyone synced with a and b", || async {
        [&na, &nb, &no].iter().all(|n| {
            n.node.status.reached_recently(&a.id) || n.node.id() == a.id
        }) && [&na, &no].iter().all(|n| n.node.status.reached_recently(&b.id))
    })
    .await;
    for n in [&na, &nb, &no] {
        peephole::credits::reach::report_due(&n.node, next_hour).await.unwrap();
    }
    let hour = peephole::credits::reach::hour_of(peephole::cluster::hlc::wall_ms());
    let day = hour / 24;
    eventually("every node counts a and b up this hour, o not", || async {
        let mut ok = true;
        for n in [&na, &nb, &no] {
            let book = peephole::credits::book_fresh(&n.node).await.unwrap();
            ok &= book.up_hours(&a.id, day) == 1
                && book.up_hours(&b.id, day) == 1
                && book.up_hours(&o.id, day) == 0;
        }
        ok
    })
    .await;
    // A whole day up: o is up too, but has no address, so no share.
    fund_listeners(&[&na, &nb, &no], &[a.id, b.id, o.id]).await;
    for n in [&na, &nb, &no] {
        let book = peephole::credits::book_fresh(&n.node).await.unwrap();
        assert_eq!(book.balance(&a.id), share(&[a.id, b.id], a.id));
        assert_eq!(book.balance(&b.id), share(&[a.id, b.id], b.id));
        assert_eq!(book.balance(&o.id), 0);
    }
}

/// A member below protocol 7 is neither paid nor charged: it is not
/// quoted, and an offer it makes moves nothing.
#[tokio::test]
async fn a_protocol_six_member_is_neither_paid_nor_charged() {
    use peephole::cluster::rpc::proto;
    use peephole::credits::pay;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            proto: Some((proto::PROTO_MIN, proto::ECONOMY_PROTO - 1)),
            ..DEFAULT
        },
    )
    .await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.5);
    fund_listeners(&[&na, &nb], &[a.id, b.id]).await;
    nb.node.refresh_heartbeat();
    eventually("a knows b's protocol", || async {
        na.members().get(&b.id).is_some_and(|m| m.proto_max == proto::ECONOMY_PROTO - 1)
    })
    .await;
    let none: peephole::intel::Providers = vec![];
    assert!(
        pay::quotes(&na.node, &none).values().flatten().all(|q| q.server != b.id),
        "not paid"
    );
    // b offers a: a declines (and frees it); nothing moves.
    let seq = pay::make_offer(&nb.node, a.id, 100).await.unwrap();
    let declined = pay::accept_offer(&na.node, b.id, seq, 100, "lookup", pay::SERVE_MARGIN_MS).await;
    assert!(matches!(declined, Err(pay::Declined::Why(w)) if w.contains("protocol 7")));
    let book = peephole::credits::book_fresh(&na.node).await.unwrap();
    assert_eq!(book.balance(&a.id), share(&[a.id, b.id], a.id), "not charged to b's benefit");
}

/// Payments of the economy before protocol 7 are kept and move nothing.
#[tokio::test]
async fn old_economy_entries_move_nothing() {
    use peephole::cluster::record::{Record, Seal};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    fund_listeners(&[&na, &nb], &[a.id]).await;
    // An old-economy transfer from a to b, as protocol 6 wrote it.
    peephole::cluster::repl::append_sealing(&na.node, |seal: Seal| Record::CreditTransfer {
        to: b.id,
        parts: vec![(pool_day(), 500_000)],
        seal,
        economy: 0,
    })
    .await
    .unwrap();
    eventually("b holds a's entry", || async {
        count(&nb, "SELECT COUNT(*) FROM credit_entries WHERE economy = 0").await == 1
    })
    .await;
    for n in [&na, &nb] {
        let book = peephole::credits::book_fresh(&n.node).await.unwrap();
        assert_eq!(book.balance(&a.id), share(&[a.id], a.id));
        assert_eq!(book.balance(&b.id), 0);
    }
}
```

(Check `Opts.proto` semantics in `boot_in`: it is the `(min, max)` the node speaks. If a protocol-6 node cannot finish the handshake with a 7 because `PROTO_MIN` exceeds 6, it still does: `PROTO_MIN` is 2.)

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --lib credits cluster::record cluster::repl admin scan::arbiter` and `cargo test --test cluster pool protocol_six old_economy funded lookup resolution probe credits overview` and `cargo test --test cli`
Expected: PASS. Then `grep -rn "mint\|allowance\|earn::\|credit_scans\|judge" src tests templates assets --include=*.rs --include=*.html --include=*.js --include=*.css` prints nothing about credits (words like "minted" in unrelated comments are fine).

- [ ] **Step 8: Commit**

```bash
git add -A src tests templates assets
git commit -m "Credits: protocol 7 — a fixed daily pool for verified listeners; the mint goes"
```

---

### Task 7: Reverse names, a quorum good

Only the node that recorded a source (the origin of the first request held for it) buys its reverse names, on today's schedule (first seen; again when it returns a day after the last lookup). It asks itself free and the q−1 cheapest members announcing `rdns` over `/rpc/v1/rdns` (routable), each with an offer unless priced at zero; each resolver answers only forward-confirmed PTR names, and a failure is unpaid. The buyer writes one replicated `rdns_name` record; every node tallies it: a name stands when more than half of those that answered gave it, and is kept in `ip_names` (source `rdns`) with its `agreed` flag. A standalone node keeps its local loop.

**Files:**
- Modify: `src/cluster/record.rs` (`RdnsRec`, `Record::RdnsName`, kind `rdns_name`, `ECONOMY_KINDS`)
- Modify: `src/store/data.rs` (dispatch; `rdns_name` is a content kind)
- Modify: `src/store/rdns.rs` (`rdns_due_own`, `mark_rdns`, `apply_rdns`, `tally_names`)
- Modify: `src/intel/rdns.rs` (`RdnsReq`, `RdnsResp`, `lookup_here`, `serve_rdns`, `buy_pass`, `run`)
- Modify: `src/cluster/mod.rs` (`Node.rdns_lookup` hook)
- Modify: `src/cluster/rpc/mod.rs` (route `/rpc/v1/rdns`), `src/cluster/rpc/routed.rs` (routable path)
- Modify: `src/lib.rs:195` (the loop gets the node and the geo database)
- Modify: `templates/_names.html` (agreement of reverse names)
- Test: `src/store/rdns.rs`, `src/cluster/rpc/routed.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: Task 3 (`price::RDNS`, `Table.rdns_mc`, announced `rdns`), Task 4 (`dns::{choose, quorum, member_price, MAX_QUORUM}`), Task 6 (`ECONOMY`, `ECONOMY_KINDS`, `economy` on receipts), Task 2's pattern (zero price without an offer, `pay::retry_price`).
- Produces:
  - `record::RdnsRec { uid: String, ip: String, at: String, answers: Vec<(NodeId, Result<Vec<String>, String>)>, build: String }`, `Record::RdnsName(RdnsRec)`, kind `"rdns_name"`.
  - `intel::rdns::{RdnsReq { ip: String, offer_seq: Option<u64> }, RdnsResp { names: Vec<String>, error: Option<String>, charged_mc: u32, price_mc: Option<u32> }}`
  - `intel::rdns::serve_rdns(node: &Arc<Node>, peer: NodeId, req: &RdnsReq) -> RdnsResp`
  - `intel::rdns::buy_pass(node: &Arc<Node>, geo: &SharedGeo) -> Result<usize>`
  - `cluster::Node::set_rdns_lookup(f: RdnsLookup)`; `intel::rdns::RdnsLookup = Arc<dyn Fn(IpAddr) -> BoxFuture<'static, Result<Vec<String>, String>> + Send + Sync>`
  - `store::rdns::tally_names(answers) -> (usize /*answered*/, Vec<(String, usize /*votes*/, bool /*agreed*/)>)`

- [ ] **Step 1: Write the failing tests**

In `src/store/rdns.rs` tests:

```rust
    #[test]
    fn a_reverse_name_stands_with_more_than_half_of_those_that_answered() {
        use crate::cluster::identity::NodeId;
        let id = |n: u8| NodeId([n; 32]);
        let answers = vec![
            (id(1), Ok(vec!["host.example.net".to_string()])),
            (id(2), Ok(vec!["host.example.net".into(), "alias.example.net".into()])),
            (id(3), Err("timed out".to_string())),
            (id(2), Ok(vec!["alias.example.net".into()])), // a second answer counts for nothing
        ];
        let (answered, names) = tally_names(&answers);
        assert_eq!(answered, 2);
        assert_eq!(
            names,
            vec![
                ("host.example.net".to_string(), 2, true),
                ("alias.example.net".to_string(), 1, false),
            ]
        );
    }

    #[tokio::test]
    async fn only_this_nodes_own_sources_are_due_for_buying() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mine = source(&s, "198.51.100.7").await;
        let theirs = source(&s, "198.51.100.8").await;
        let me = crate::cluster::identity::NodeId([1; 32]);
        let other = crate::cluster::identity::NodeId([2; 32]);
        for (ip_id, origin) in [(mine, me), (theirs, other)] {
            sqlx::query("UPDATE requests SET origin = ? WHERE ip_id = ?")
                .bind(&origin.0[..])
                .bind(ip_id)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        let due: Vec<i64> = s.rdns_due_own(10, &me).await.unwrap().into_iter().map(|(id, _)| id).collect();
        assert_eq!(due, [mine]);
        s.mark_rdns(mine).await.unwrap();
        assert!(s.rdns_due_own(10, &me).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_reverse_name_record_keeps_every_name_with_its_flag() {
        use crate::cluster::identity::NodeId;
        use crate::cluster::record::RdnsRec;
        use crate::store::data::{Ctx, Effect};
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let origin = NodeId([1; 32]);
        let r = RdnsRec {
            uid: format!("{}u1", origin.uid_prefix()),
            ip: "198.51.100.9".into(),
            at: "2026-10-09 12:00:00".into(),
            answers: vec![
                (NodeId([1; 32]), Ok(vec!["host.example.net".into()])),
                (NodeId([2; 32]), Ok(vec!["host.example.net".into(), "alias.example.net".into()])),
            ],
            build: String::new(),
        };
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: Some(&origin), hlc: 5 };
        assert_eq!(apply_rdns(&mut conn, ctx, &r).await.unwrap(), Effect::Applied);
        let mut bad = r.clone();
        bad.answers = (0..10).map(|i| (NodeId([i; 32]), Ok(vec![]))).collect();
        assert_eq!(apply_rdns(&mut conn, ctx, &bad).await.unwrap(), Effect::Ignored, "over the quorum");
        drop(conn);
        let ip = s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap();
        let names = s.names_for_ip(ip.id).await.unwrap();
        let got: Vec<(String, bool, i64, i64)> = names
            .iter()
            .map(|n| (n.name.clone(), n.agreed, n.votes, n.answered))
            .collect();
        assert!(got.contains(&("host.example.net".into(), true, 2, 2)), "{got:?}");
        assert!(got.contains(&("alias.example.net".into(), false, 1, 2)), "{got:?}");
        assert!(names.iter().all(|n| n.source == "rdns"));
    }
```

(`source` is the module's existing test helper; if `names_for_ip` orders differently, the `contains` checks do not care.)

In `src/cluster/rpc/routed.rs`'s `only_paid_request_paths_are_routed`: assert `allowed("/rpc/v1/rdns")`.

In `tests/cluster.rs`:

```rust
/// The node that recorded a source buys its reverse names from itself
/// and the cheapest other member (q = 2 of 3); the agreed name and the
/// disputed one replicate with their flags.
#[tokio::test]
async fn reverse_names_are_bought_from_a_quorum_and_replicate_with_their_flag() {
    use peephole::credits::price;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let fake = |names: &'static [&'static str]| -> peephole::intel::rdns::RdnsLookup {
        std::sync::Arc::new(move |_ip| {
            Box::pin(async move { Ok(names.iter().map(|n| n.to_string()).collect()) })
        })
    };
    na.node.set_rdns_lookup(fake(&["host.example.net"]));
    nb.node.set_rdns_lookup(fake(&["host.example.net", "alias.example.net"]));
    nc.node.set_rdns_lookup(fake(&["other.example.net"]));
    // c asks more than b: the quorum of 2 is a and b.
    nc.node.set_price_table(std::sync::Arc::new(price::Table {
        rdns_mc: 5,
        ..Default::default()
    }));
    for n in [&na, &nb, &nc] {
        n.node.refresh_heartbeat();
    }
    eventually("a hears both prices", || async {
        peephole::intel::dns::member_price(&na.node, &b.id, price::RDNS) == Some(0)
            && peephole::intel::dns::member_price(&na.node, &c.id, price::RDNS) == Some(5)
    })
    .await;
    record(&na, "198.51.100.90", "/x").await;
    let geo: peephole::intel::SharedGeo = Default::default();
    assert_eq!(peephole::intel::rdns::buy_pass(&na.node, &geo).await.unwrap(), 1);
    let q = "SELECT COUNT(*) FROM ip_names n JOIN ips i ON i.id = n.ip_id
             WHERE i.ip = '198.51.100.90' AND n.source = 'rdns'";
    for n in [&na, &nb, &nc] {
        eventually("the names replicate", || async {
            count(n, &format!("{q} AND n.name = 'host.example.net' AND n.agreed = 1 AND n.votes = 2")).await == 1
                && count(n, &format!("{q} AND n.name = 'alias.example.net' AND n.agreed = 0")).await == 1
                && count(n, &format!("{q} AND n.name = 'other.example.net'")).await == 0
        })
        .await;
    }
    // Bought once: due again only when the source returns a day later.
    assert_eq!(peephole::intel::rdns::buy_pass(&na.node, &geo).await.unwrap(), 0);
    // b and c do not buy a's source.
    assert_eq!(peephole::intel::rdns::buy_pass(&nb.node, &geo).await.unwrap(), 0);
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib store::rdns cluster::rpc::routed` and `cargo test --test cluster reverse_names_are_bought`
Expected: compile errors (`tally_names`, `rdns_due_own`, `RdnsRec`, `buy_pass`).

- [ ] **Step 3: The record**

`src/cluster/record.rs`, next to `IpNameRec`:

```rust
/// The reverse names of a source, as the quorum the recording node bought
/// them from answered (`intel::rdns`): forward-confirmed PTR names, or why
/// there are none. Every node tallies the answers itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RdnsRec {
    pub uid: String,
    pub ip: String,
    pub at: String,
    pub answers: Vec<(NodeId, Result<Vec<String>, String>)>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}
```

Variant `RdnsName(RdnsRec)`, kind `"rdns_name"`, `uid()` → `Some(r.uid.clone())`. `ECONOMY_KINDS` becomes `&["reach_report", "rdns_name"]`. `src/store/data.rs`: `Record::RdnsName(r) => super::rdns::apply_rdns(conn, ctx, r).await,`, and add `"rdns_name"` to `CONTENT_KINDS` (length 11).

- [ ] **Step 4: Store and tally**

`src/store/rdns.rs` (module doc: "Reverse DNS names of the sources (`intel::rdns`). In a cluster the node that recorded a source buys its names from a quorum and replicates the answers (`rdns_name`); every node tallies them. A standalone node looks up on its own."):

```rust
/// Per name, how many of those that answered gave it, and whether that
/// is more than half; most votes first. A node's second answer counts for
/// nothing; a failure is no answer.
pub fn tally_names(
    answers: &[(NodeId, Result<Vec<String>, String>)],
) -> (usize, Vec<(String, usize, bool)>) {
    let mut seen = std::collections::HashSet::new();
    let mut votes: std::collections::BTreeMap<String, usize> = Default::default();
    let mut answered = 0;
    for (id, a) in answers {
        if !seen.insert(*id) {
            continue;
        }
        let Ok(names) = a else { continue };
        answered += 1;
        let distinct: std::collections::BTreeSet<&String> = names.iter().collect();
        for n in distinct {
            *votes.entry(n.clone()).or_default() += 1;
        }
    }
    let mut out: Vec<(String, usize, bool)> = votes
        .into_iter()
        .map(|(n, v)| (n, v, v * 2 > answered))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    (answered, out)
}

/// Keep a reverse-name record: every name with its votes and flag; the
/// newest record's tally stands.
pub(crate) async fn apply_rdns(
    conn: &mut sqlx::SqliteConnection,
    _ctx: super::data::Ctx<'_>,
    r: &crate::cluster::record::RdnsRec,
) -> Result<super::data::Effect> {
    use super::data::Effect;
    let ok_name = |n: &String| crate::intel::dns::valid_name(n).as_deref() == Some(n.as_str());
    if r.uid.len() > 128
        || r.answers.len() > crate::intel::dns::MAX_QUORUM
        || !r.ip.parse::<std::net::IpAddr>().is_ok_and(crate::net::is_scannable_target)
        || r.answers.iter().any(|(_, a)| match a {
            Ok(v) => v.len() > MAX_NAMES || !v.iter().all(ok_name),
            Err(e) => e.len() > 200,
        })
        || chrono::NaiveDateTime::parse_from_str(&r.at, "%Y-%m-%d %H:%M:%S").is_err()
    {
        return Ok(Effect::Ignored);
    }
    if let Some(t) = super::probes::erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let Some(ip_id) = super::probes::ensure_ip(conn, &r.ip, None).await? else {
        return Ok(Effect::Ignored);
    };
    let (answered, names) = tally_names(&r.answers);
    for (name, votes, agreed) in names {
        sqlx::query(
            "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen)
             VALUES (?1, ?2, 'rdns', ?3, ?3)
             ON CONFLICT(ip_id, name, source) DO UPDATE
               SET first_seen = min(first_seen, excluded.first_seen)",
        )
        .bind(ip_id)
        .bind(&name)
        .bind(&r.at)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "UPDATE ip_names SET last_seen = ?1, agreed = ?2, asked = ?3, answered = ?4,
                    votes = ?5, record_uid = ?6
             WHERE ip_id = ?7 AND name = ?8 AND source = 'rdns'
               AND (last_seen < ?1 OR (last_seen = ?1 AND (record_uid IS NULL OR record_uid <= ?6)))",
        )
        .bind(&r.at)
        .bind(agreed)
        .bind(r.answers.len() as i64)
        .bind(answered as i64)
        .bind(votes as i64)
        .bind(&r.uid)
        .bind(ip_id)
        .bind(&name)
        .execute(&mut *conn)
        .await?;
    }
    Ok(Effect::Applied)
}
```

(`erased_by` and `ensure_ip` are the helpers `apply_ip_name` uses in `store/probes.rs`; make them `pub(super)` if they are private. Check the `ip_names` defaults: a row inserted without `agreed` must not read as agreed before the update — the update always runs right after the insert for the same name, so it does.)

And on `impl Store`:

```rust
    /// This node's own sources due a reverse lookup: the first request held
    /// for them is its own (`origin` is this node, or none: recorded before
    /// it joined), never looked up or seen again a day after the last time.
    pub async fn rdns_due_own(&self, limit: i64, me: &NodeId) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT i.id, i.ip FROM ips i
             WHERE i.request_count > 0
               AND (i.rdns_at IS NULL OR i.last_seen > datetime(i.rdns_at, '+1 day'))
               AND (SELECT r.origin IS NULL OR r.origin = ?1 FROM requests r
                    WHERE r.ip_id = i.id ORDER BY r.id LIMIT 1)
             ORDER BY i.last_seen DESC LIMIT ?2",
        )
        .bind(&me.0[..])
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// The source was looked up now (whatever was found).
    pub async fn mark_rdns(&self, ip_id: i64) -> Result<()> {
        sqlx::query("UPDATE ips SET rdns_at = ? WHERE id = ?")
            .bind(super::data::now_ts())
            .bind(ip_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
```

(The due query reads `self.read`; in the test it runs right after writes on the same database, which WAL makes visible.)

- [ ] **Step 5: Serving and buying**

`src/cluster/mod.rs`: field `rdns_lookup: std::sync::OnceLock<crate::intel::rdns::RdnsLookup>` (initialised `Default::default()`), with

```rust
    /// Tests: answer reverse lookups with `f` instead of the system resolver.
    #[doc(hidden)]
    pub fn set_rdns_lookup(&self, f: crate::intel::rdns::RdnsLookup) {
        let _ = self.rdns_lookup.set(f);
    }

    pub fn rdns_lookup(&self) -> Option<&crate::intel::rdns::RdnsLookup> {
        self.rdns_lookup.get()
    }
```

`src/intel/rdns.rs` — add after the module doc (update it: "…In a cluster the node that recorded a source buys its names from a quorum (`buy_pass`); a standalone node looks up on its own (`pass`)."):

```rust
/// How a node finds a source's forward-confirmed reverse names.
pub type RdnsLookup = std::sync::Arc<
    dyn Fn(IpAddr) -> futures::future::BoxFuture<'static, Result<Vec<String>, String>>
        + Send
        + Sync,
>;

/// What one node asks another.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RdnsReq {
    pub ip: String,
    /// The asker's offer; None at a zero price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
}

/// Its answer: the names, or why there are none.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RdnsResp {
    pub names: Vec<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub charged_mc: u32,
    /// This node's price, when the request offered less (or nothing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_mc: Option<u32>,
}

impl RdnsResp {
    fn refused(why: &str, price_mc: Option<u32>) -> Self {
        RdnsResp {
            error: Some(why.into()),
            price_mc,
            ..Default::default()
        }
    }
}

/// This node's answer for `ip`: the hook in tests, else the system resolver.
pub async fn lookup_here(node: &crate::cluster::Node, ip: IpAddr) -> Result<Vec<String>, String> {
    if let Some(f) = node.rdns_lookup() {
        return f(ip).await;
    }
    let Some(resolver) = system_resolver() else {
        return Err("no nameserver on this node".into());
    };
    confirmed_names(resolver, &system_forward(), ip)
        .await
        .map_err(|e| format!("{e:#}").chars().take(200).collect())
}

/// Look up `req.ip`'s reverse names for `peer`: free at a zero price,
/// against the offer it names otherwise; a failure is not charged.
pub async fn serve_rdns(
    node: &std::sync::Arc<crate::cluster::Node>,
    peer: crate::cluster::identity::NodeId,
    req: &RdnsReq,
) -> RdnsResp {
    use crate::credits::{pay, price};
    let release = async || {
        if let Some(seq) = req.offer_seq {
            pay::release(node, peer, seq).await;
        }
    };
    let Some(ip) = req
        .ip
        .trim()
        .parse::<IpAddr>()
        .ok()
        .filter(|a| req.ip.len() <= 64 && crate::net::is_scannable_target(*a))
    else {
        release().await;
        return RdnsResp::refused("not a public address", None);
    };
    let cost = node.price_table().price_of(price::RDNS).unwrap_or(0);
    node.market.note(price::RDNS, 1);
    if req.offer_seq.is_none() && cost > 0 {
        return RdnsResp::refused(
            &format!(
                "reverse names cost {} credits here now; the request carries no offer",
                crate::credits::show(cost as u64)
            ),
            Some(cost),
        );
    }
    if let Some(seq) = req.offer_seq {
        match pay::accept_offer(node, peer, seq, cost as u64, "rdns", pay::SERVE_MARGIN_MS).await {
            Ok(_) => {}
            Err(pay::Declined::TooLow { why, price_mc }) => {
                return RdnsResp::refused(&why, Some(price_mc));
            }
            Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => {
                return RdnsResp::refused(&w, None);
            }
        }
    }
    let taken = match node.lookup_shares() {
        Some(s) => s.take_good(price::RDNS).await.unwrap_or(false),
        None => true,
    };
    if !taken {
        release().await;
        return RdnsResp::refused("this node's reverse lookups for others are used up for today", None);
    }
    let answer = lookup_here(node, ip).await;
    let charged = match (req.offer_seq, &answer) {
        (Some(seq), _) => {
            let charged = if answer.is_ok() { cost } else { 0 };
            let receipt = crate::cluster::record::Record::CreditReceipt {
                payer: peer,
                offer_seq: seq,
                charged_mc: charged,
                answered: if charged > 0 { vec![price::RDNS.into()] } else { vec![] },
                economy: crate::cluster::record::ECONOMY,
            };
            match crate::cluster::repl::append(node, &[receipt]).await {
                Ok(_) => charged,
                Err(e) => {
                    tracing::warn!(?e, "reverse-name receipt not written");
                    0
                }
            }
        }
        (None, _) => 0,
    };
    match answer {
        Ok(names) => RdnsResp {
            names,
            charged_mc: charged,
            ..Default::default()
        },
        Err(e) => RdnsResp::refused(&e, None),
    }
}

/// One member's answer, with an offer unless its price is 0; a decline
/// naming a higher price is offered that once.
async fn ask_rdns(
    node: &std::sync::Arc<crate::cluster::Node>,
    id: crate::cluster::identity::NodeId,
    ip: IpAddr,
) -> Result<Vec<String>, String> {
    use crate::credits::{pay, price};
    let Some(first) = crate::intel::dns::member_price(node, &id, price::RDNS) else {
        return Err("announces no price for reverse names".into());
    };
    let once = async |price: u64| -> Result<RdnsResp, String> {
        let offer_seq = match price {
            0 => None,
            p => Some(pay::make_offer(node, id, p).await?),
        };
        let req = RdnsReq {
            ip: ip.to_string(),
            offer_seq,
        };
        node.call_any::<RdnsReq, RdnsResp>(id, "/rpc/v1/rdns", &req, crate::intel::lookup::RPC_TIMEOUT)
            .await
            .map_err(|e| match e.downcast_ref::<crate::cluster::msg::NoAnswer>() {
                Some(_) => "did not answer in time".to_string(),
                None => format!("could not be asked: {e:#}"),
            })
    };
    let mut resp = once(first as u64).await;
    if let Ok(r) = &resp
        && r.error.is_some()
        && let Some(p) = pay::retry_price(first as u64, r.price_mc, true)
    {
        resp = once(p).await;
    }
    match resp? {
        RdnsResp { error: Some(e), .. } => Err(e),
        RdnsResp { names, .. } => Ok(names),
    }
}

/// Buy the reverse names of this node's own sources that are due, from
/// itself and the quorum's cheapest other members, and replicate the
/// answers. Returns how many sources were handled.
pub async fn buy_pass(
    node: &std::sync::Arc<crate::cluster::Node>,
    geo: &crate::intel::SharedGeo,
) -> anyhow::Result<usize> {
    let due = node.store.rdns_due_own(BATCH, &node.id()).await?;
    let n = due.len();
    let siblings: std::collections::HashSet<_> =
        crate::cluster::owner::fleet::siblings(&node.store)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    let me = node.id();
    let rec = crate::store::recorder::Recorder::Cluster(node.clone());
    for (ip_id, text) in due {
        let Ok(ip) = text.parse::<IpAddr>() else {
            node.store.mark_rdns(ip_id).await?;
            continue;
        };
        if !crate::net::is_scannable_target(ip) {
            node.store.mark_rdns(ip_id).await?;
            continue;
        }
        let chosen = crate::intel::dns::choose(node, &siblings, geo, crate::credits::price::RDNS);
        let others = futures::future::join_all(
            chosen
                .iter()
                .filter(|r| r.id != me)
                .map(|r| async { (r.id, ask_rdns(node, r.id, ip).await) }),
        );
        let (own, mut answers) = futures::join!(lookup_here(node, ip), others);
        answers.insert(0, (me, own));
        let r = crate::cluster::record::RdnsRec {
            uid: rec.uid(),
            ip: crate::net::canonical(ip).to_string(),
            at: crate::store::data::now_ts(),
            answers,
            build: crate::COMMIT.into(),
        };
        if let Err(e) = rec.write(vec![crate::cluster::record::Record::RdnsName(r)]).await {
            tracing::warn!(%ip, ?e, "reverse names not written");
        }
        node.store.mark_rdns(ip_id).await?;
    }
    Ok(n)
}
```

Clip every answer before it goes into the record: names to `MAX_NAMES` (`crawler::MAX_NAMES`, re-exported for `store::rdns`), errors to 200 characters — otherwise `apply_rdns` ignores the whole record.

`run(store, node: Option<Arc<Node>>, geo: SharedGeo, enabled, shutdown)`: with a node, each pass is `buy_pass(&node, &geo)` (no `system_resolver` check: `lookup_here` reports its absence as this node's answer); without one, the existing `pass`. `src/lib.rs`: pass `node.clone()` and `geo.clone()` (move the spawn below `node`'s creation if needed).

`src/cluster/rpc/mod.rs`: `.route("/rpc/v1/rdns", post(rdns))` with

```rust
/// A source's reverse names for a member, free at zero or paid with the
/// offer it names.
async fn rdns(
    State(node): State<Arc<Node>>,
    Extension(Peer(peer)): Extension<Peer>,
    Cbor(req): Cbor<crate::intel::rdns::RdnsReq>,
) -> Response {
    Cbor(crate::intel::rdns::serve_rdns(&node, peer, &req).await).into_response()
}
```

`src/cluster/rpc/routed.rs`: `ROUTED_PATHS` gains `"/rpc/v1/rdns"` (length 4) and `answer` a matching arm.

`templates/_names.html`: for `source == "rdns"`, when `n.answered > 0` show `reverse DNS, forward-confirmed, {% if n.agreed %}agreed{% else %}disputed{% endif %} {{ n.votes }}/{{ n.answered }}, {{ n.day() }}`; otherwise the old text (a standalone node's own lookups).

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib store::rdns intel::rdns cluster::rpc store::data` and `cargo test --test cluster reverse_names`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/cluster/record.rs src/store/data.rs src/store/rdns.rs src/store/probes.rs src/intel/rdns.rs \
  src/cluster/mod.rs src/cluster/rpc/mod.rs src/cluster/rpc/routed.rs src/lib.rs templates/_names.html tests/cluster.rs
git commit -m "Lookup: reverse names are bought from a quorum and replicated with their agreement"
```

---

### Task 8: Paid audits of designated scans, and the obligation

Neither which scans are audited nor by whom is the scanner's choice (spec §4, revised). A successful scan of a job granted by another arbiter, at level 1–4, is **designated** when `SHA-256("peephole-audit\0" || job uid || HLC of the arbiter's done status)`, read as a fraction, is below `AUDIT_RATE = 0.05`; its auditors are ranked by `SHA-256(seed || key)` over the active protocol-7 scanners other than the scanner. The scanner buys the audit from the first of them that is live and priced (then the second, the third), with a `CreditOffer` whose `audit` names the scan (at least 1 mc, Decision 3) and an `AuditReq`; an auditor accepts only a designated scan it ranks among the first three for, runs it as today, publishes `ScanAuditRec`, then charges (`answered: ["audit"]`). Every node counts per scanner the designated scans of the last 7 days (minus the newest `AUDIT_OFFER_TTL_MS`) and the bought ones; a scanner fails when at least 2 have no bought audit and it bought under 80 %. One that fails is not funded by arbiters, and its scan receipts move nothing in each node's ledger (Task 6's `no_scan_sales`). The unpaid auditor-side `Picker` stays as it is.

**Files:**
- Modify: `src/cluster/record.rs` (`CreditOffer.audit`)
- Modify: `src/store/migrations/0029_scarce_credits.sql` (append `audit_uid`)
- Modify: `src/credits/entries.rs` (`Kind::Offer.audit`, column)
- Modify: `src/credits/ledger.rs` (`Offer.audit`, `ttl_ms`)
- Modify: `src/credits/mod.rs` (`AUDIT_OFFER_TTL_MS`; `run` calls `audit::buy_due` each tick)
- Modify: `src/credits/pay.rs` (`make_offer_for`; `time_left` by the offer's own lifetime)
- Modify: `src/credits/audit.rs` (designation, ranking, `Queue`, `serve`, `buy`, `buy_due`, `owes`, `obligations`; the `Picker` stays; tests)
- Modify: `src/credits/gates.rs` (`Standing.audits_owed`)
- Modify: `src/cluster/msg.rs` (`Msg::AuditReq`, `Msg::AuditReply`)
- Modify: `src/cluster/mod.rs` (`Node.audit_queue`, `Node.audits_tried`)
- Modify: `src/scan/mod.rs` (`next_audit` takes bought audits before unpaid picks; `Job::Audit.offer`; the receipt after a bought audit)
- Modify: `src/scan/arbiter.rs` (`stand`: no price for a scanner that does not earn as one)
- Modify: `src/lib.rs`, `tests/cluster.rs` `boot_in` (`credits::audit::serve(&node)`)
- Test: `src/credits/audit.rs`, `src/credits/gates.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: Task 5 (`Arbiter::stand`, funded grants), Task 6 (`ECONOMY`, `ECONOMY_PROTO`, `ledger::Gates.no_scan_sales`, `Book.standing`, `entries::get` reads economy 2 only).
- Produces:
  - `Record::CreditOffer { …, audit: Option<String> }` (`#[serde(default, skip_serializing_if = "Option::is_none")]`); `entries::Kind::Offer { to, parts, job, audit }`; `ledger::Offer.audit: Option<String>`.
  - `credits::AUDIT_OFFER_TTL_MS: u64 = audit::AUDIT_WINDOW_MS + JOB_OFFER_TTL_MS`.
  - `pay::make_offer_for(node, server, total_mc: Mc, audit: Option<String>) -> Result<u64, String>` (`make_offer` = `make_offer_for(…, None)`).
  - `Msg::AuditReq { scan_uid: String, offer_seq: u64 }`, `Msg::AuditReply { accepted: bool, why: Option<String> }`.
  - `audit::{AUDIT_RATE: f64 = 0.05, AUDITORS: usize = 3}`, `audit::seed(job_uid: &str, done_hlc: u64) -> [u8; 32]`, `audit::designated(seed: &[u8; 32]) -> bool`, `audit::auditors(seed: &[u8; 32], members: &[MemberRow], scanner: &NodeId) -> Vec<NodeId>` (the first [`AUDITORS`], best first).
  - `audit::Task { scan_uid, job_uid, ip, level, deadline_ms, offer: Option<(NodeId, u64, u32)> }` (None: an unpaid pick), `audit::Queue` (`push`, `take`), `Node.audit_queue: Mutex<audit::Queue>`, `Node.audits_tried: Mutex<HashSet<String>>`.
  - `audit::serve(node: &Arc<Node>)`, `audit::buy(node: &Arc<Node>, scan_uid: &str) -> Result<NodeId, String>`, `audit::buy_due(node: &Arc<Node>) -> usize`.
  - `audit::owes(designated: u32, bought: u32) -> Option<(u32, u32)>` (bought, designated), `audit::obligations(pool, members: &[MemberRow], now_ms: u64) -> Result<HashMap<NodeId, (u32 /*designated*/, u32 /*bought*/)>>`.
  - `gates::Standing.audits_owed: Option<(u32, u32)>`; `earns_as_scanner()` is false while it is set.

- [ ] **Step 1: Write the failing tests**

In `src/credits/audit.rs` tests (the `Picker` tests stay):

```rust
    fn scanner_member(n: u8, proto: u32) -> crate::cluster::members::MemberRow {
        crate::cluster::members::MemberRow {
            id: id(n),
            name: format!("n{n}"),
            address: Some(format!("198.51.100.{n}:7443")),
            roles: vec!["scanner".into()],
            proto_min: 2,
            proto_max: proto,
            sponsor: id(n),
            active: true,
            standing: crate::cluster::members::Standing::Active,
            info_hlc: 0,
            last_entry_hlc: 0,
            remote_config: false,
        }
    }

    #[test]
    fn about_one_scan_in_twenty_is_designated_and_nobody_chooses_which() {
        let n = (0..20_000u64)
            .filter(|h| designated(&seed("job-x", *h << 16)))
            .count();
        assert!((800..1200).contains(&n), "{n} of 20000");
        // The same job and done status: the same answer everywhere.
        assert_eq!(seed("job-x", 7), seed("job-x", 7));
        assert_ne!(seed("job-x", 7), seed("job-y", 7));
        assert_ne!(seed("job-x", 7), seed("job-x", 8));
    }

    #[test]
    fn the_auditors_are_ranked_by_the_seed_never_the_scanner() {
        let members = [
            scanner_member(1, 7),
            scanner_member(2, 7),
            scanner_member(3, 7),
            scanner_member(4, 7),
            scanner_member(5, 6), // too old to be paid
        ];
        let s = seed("job-x", 7);
        let got = auditors(&s, &members, &id(1));
        assert_eq!(got.len(), AUDITORS);
        assert!(!got.contains(&id(1)), "never the scanner itself");
        assert!(!got.contains(&id(5)));
        assert_eq!(got, auditors(&s, &members, &id(1)), "deterministic");
        // Another seed, another order (for some seed among a few).
        assert!((8..40u64).any(|h| auditors(&seed("job-x", h), &members, &id(1)) != got));
        let mut listener = scanner_member(6, 7);
        listener.roles = vec!["listener".into()];
        assert!(!auditors(&s, &[listener], &id(1)).contains(&id(6)), "not a scanner");
    }

    #[test]
    fn a_scanner_owes_when_two_designated_scans_lack_an_audit_and_it_bought_under_80_percent() {
        assert_eq!(owes(0, 0), None);
        assert_eq!(owes(1, 0), None, "one miss is forgiven");
        assert_eq!(owes(2, 0), Some((0, 2)));
        assert_eq!(owes(10, 8), None, "80 %");
        assert_eq!(owes(10, 7), Some((7, 10)));
        assert_eq!(owes(20, 17), None, "three misses, but 85 %");
    }

    #[test]
    fn bought_audits_are_handed_out_first_and_late_ones_dropped() {
        let now = hlc::wall_ms();
        let task = |uid: &str, level: u8, deadline_ms: u64| Task {
            scan_uid: uid.into(),
            job_uid: format!("job-{uid}"),
            ip: "203.0.113.5".into(),
            level,
            deadline_ms,
            offer: Some((id(1), 7, 3)),
        };
        let mut q = Queue::default();
        assert!(q.push(task("late", 2, now - 1)));
        assert!(q.push(task("four", 4, now + 60_000)));
        assert!(q.push(task("two", 2, now + 60_000)));
        assert_eq!(q.take(&[4]).map(|t| t.scan_uid), Some("two".into()));
        assert_eq!(q.take(&[4]), None, "level 4 excluded, the late one dropped");
        assert_eq!(q.take(&[]).map(|t| t.scan_uid), Some("four".into()));
    }

    #[tokio::test]
    async fn the_obligation_counts_designated_scans_and_audits_bought_from_their_auditors() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let pool = &store.pool;
        let (s, arbiter, auditor, stranger) = (id(1), id(9), id(2), id(3));
        let members = [scanner_member(1, 7), scanner_member(2, 7)];
        sqlx::query("INSERT INTO ips (id, ip, first_seen, last_seen) VALUES (1, '192.0.2.1', '', '')")
            .execute(pool)
            .await
            .unwrap();
        let now = hlc::wall_ms();
        let day_ago = |extra: u64| ((now - 86_400_000 - extra) << 16) | 1;
        // Three done jobs of another arbiter whose done status designates them.
        let mut hlcs = vec![];
        let mut h = 0u64;
        while hlcs.len() < 3 {
            if designated(&seed(&format!("job-{}", hlcs.len()), day_ago(h))) {
                hlcs.push(day_ago(h));
            }
            h += 1;
        }
        for (n, done) in hlcs.iter().enumerate() {
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid, origin, arbiter, scanner, status_hlc)
                 VALUES (1, 2, 'done', datetime('now'), ?1, ?2, ?2, ?3, ?4)",
            )
            .bind(format!("job-{n}")).bind(&arbiter.0[..]).bind(&s.0[..]).bind(hlc::to_db(*done))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, hlc)
                 VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4)",
            )
            .bind(format!("scan-{n}")).bind(&s.0[..]).bind(format!("job-{n}")).bind(hlc::to_db(*done))
            .execute(pool).await.unwrap();
        }
        // scan-0: audited by its auditor, paid. scan-1: audited by a node
        // that is no auditor of it, paid. scan-2: not audited.
        for (n, by) in [(0i64, auditor), (1, stranger)] {
            sqlx::query(
                "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, audit_of, hlc)
                 VALUES (1, 2, datetime('now'), datetime('now'), ?1, ?2, ?3, ?4, ?5)",
            )
            .bind(format!("audit-{n}")).bind(&by.0[..]).bind(format!("job-{n}")).bind(format!("scan-{n}")).bind(hlc::to_db(day_ago(0)))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, seal, economy, audit_uid)
                 VALUES (?1, ?2, ?3, 'offer', ?4, '[]', 1, 2, ?5)",
            )
            .bind(&s.0[..]).bind(n + 1).bind(hlc::to_db(day_ago(0))).bind(&by.0[..]).bind(format!("scan-{n}"))
            .execute(pool).await.unwrap();
            sqlx::query(
                "INSERT INTO credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, economy)
                 VALUES (?1, 1, ?2, 'receipt', ?3, '[]', ?4, 4, '[\"audit\"]', 0, 2)",
            )
            .bind(&by.0[..]).bind(hlc::to_db(day_ago(0))).bind(&s.0[..]).bind(n + 1)
            .execute(pool).await.unwrap();
        }
        let got = obligations(pool, &members, now).await.unwrap();
        assert_eq!(got.get(&s), Some(&(3, 1)), "{got:?}");
        assert_eq!(owes(3, 1), Some((1, 3)));
    }
```

(Check the `scans` columns the inserts use against the schema and add any `NOT NULL` column it requires. With members 1 and 2 only, scanner 2 is the only possible auditor of scanner 1's scans.)

In `src/credits/gates.rs`'s `standing_says_who_earns_and_why_not`:

```rust
        let owing = Standing {
            audits_owed: Some((1, 3)),
            ..Default::default()
        };
        assert!(owing.earns() && !owing.earns_as_scanner());
        assert_eq!(owing.reasons(), ["audits: bought 1 of 3 designated"]);
```

In `tests/cluster.rs`:

```rust
/// A scan designated for audit is bought from its first auditor, which
/// queues it; a node that is no auditor of it declines.
#[tokio::test]
async fn a_designated_scan_is_audited_by_its_auditor() {
    use peephole::credits::audit;
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("node-alpha");
    let (is, s) = new_node("node-sierra");
    let (ix, x) = new_node("node-xray");
    let scanner = || Opts {
        scanner: Some(fake_nmap_args(tools.path())),
        workers: 0,
        ..DEFAULT
    };
    let na = boot(ia, &a, &[&s, &x], DEFAULT).await;
    let ns = boot(is, &s, &[&a, &x], scanner()).await;
    let nx = boot(ix, &x, &[&a, &s], scanner()).await;
    fund_listeners(&[&na, &ns, &nx], &[s.id]).await;
    market_known(&ns, x.id).await;
    eventually("s hears x's scan price", || async {
        ns.node.status.known(&x.id).is_some_and(|k| k.hb.scan_price_mc.is_some())
    })
    .await;
    // A done job of a, scanned by s, whose done status designates it; on
    // s and x alike (as replication would leave it).
    let now = peephole::cluster::hlc::wall_ms();
    let done = (0u64..)
        .map(|i| ((now - i) << 16) | 1)
        .find(|h| audit::designated(&audit::seed("job-d", *h)))
        .unwrap();
    for n in [&ns, &nx] {
        let ip = n.store.upsert_ip("198.51.100.70".parse().unwrap()).await.unwrap();
        sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid, origin, arbiter, scanner, status_hlc)
             VALUES (?1, 2, 'done', datetime('now'), 'job-d', ?2, ?2, ?3, ?4)",
        )
        .bind(ip.id).bind(&a.id.0[..]).bind(&s.id.0[..]).bind(peephole::cluster::hlc::to_db(done))
        .execute(&n.store.pool).await.unwrap();
        sqlx::query(
            "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, hlc)
             VALUES (?1, 2, datetime('now'), datetime('now'), 'scan-d', ?2, 'job-d', ?3)",
        )
        .bind(ip.id).bind(&s.id.0[..]).bind(peephole::cluster::hlc::to_db(done))
        .execute(&n.store.pool).await.unwrap();
    }
    assert_eq!(audit::buy(&ns.node, "scan-d").await, Ok(x.id));
    assert_eq!(nx.node.audit_queue.lock().unwrap().len(), 1, "x queued it");
    // a is no scanner, so no auditor of it.
    let req = peephole::cluster::msg::Msg::AuditReq {
        scan_uid: "scan-d".into(),
        offer_seq: 1,
    };
    let reply = ns.node.request(a.id, req, Duration::from_secs(10)).await;
    assert!(
        !matches!(reply, Ok(peephole::cluster::msg::Msg::AuditReply { accepted: true, .. })),
        "{reply:?}"
    );
}

/// A scanner that buys no audits of its designated scans owes them:
/// arbiters stop funding it, so it is granted nothing.
#[tokio::test]
async fn a_scanner_that_buys_no_audits_of_its_designated_scans_stops_being_funded() {
    let tools = tempfile::tempdir().unwrap();
    let (ia, a) = new_node("node-alpha");
    let (is, s) = new_node("node-sierra");
    let (ix, x) = new_node("node-xray");
    let na = boot(ia, &a, &[&s, &x], DEFAULT).await;
    let ns = boot(
        is,
        &s,
        &[&a, &x],
        Opts {
            scanner: Some(fake_nmap_args(tools.path())),
            ..DEFAULT
        },
    )
    .await;
    // x is another scanner: the auditor s should have bought from.
    let _nx = boot(ix, &x, &[&a, &s], Opts { scanner: Some(fake_nmap_args(tools.path())), workers: 0, ..DEFAULT }).await;
    market_known(&na, s.id).await;
    // Three designated scans of a's jobs by s, a day old, none audited.
    let now = peephole::cluster::hlc::wall_ms();
    let ip = na.store.upsert_ip("198.51.100.61".parse().unwrap()).await.unwrap();
    let mut found = 0;
    for i in 0u64.. {
        let done = ((now - 86_400_000 - i) << 16) | 1;
        let job = format!("owed-job-{found}");
        if !peephole::credits::audit::designated(&peephole::credits::audit::seed(&job, done)) {
            continue;
        }
        sqlx::query(
            "INSERT INTO scan_jobs (ip_id, level, status, queued_at, uid, origin, arbiter, scanner, status_hlc)
             VALUES (?1, 1, 'done', datetime('now'), ?2, ?3, ?3, ?4, ?5)",
        )
        .bind(ip.id).bind(&job).bind(&a.id.0[..]).bind(&s.id.0[..]).bind(peephole::cluster::hlc::to_db(done))
        .execute(&na.store.pool).await.unwrap();
        sqlx::query(
            "INSERT INTO scans (ip_id, level, started_at, finished_at, uid, origin, job_uid, hlc)
             VALUES (?1, 1, datetime('now'), datetime('now'), ?2, ?3, ?4, ?5)",
        )
        .bind(ip.id).bind(format!("owed-scan-{found}")).bind(&s.id.0[..]).bind(&job).bind(peephole::cluster::hlc::to_db(done))
        .execute(&na.store.pool).await.unwrap();
        found += 1;
        if found == 3 {
            break;
        }
    }
    let book = peephole::credits::book_fresh(&na.node).await.unwrap();
    assert_eq!(book.standing(&s.id).audits_owed, Some((0, 3)));
    enqueue(&na, "198.51.100.62", 1).await;
    tokio::time::sleep(Duration::from_secs(8)).await;
    assert_eq!(
        count(&na, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued'").await,
        1,
        "not funded, not granted"
    );
}
```

(`Opts.workers: 0` keeps a scanner from claiming jobs while it has the scanner role; check that `run_workers` with no workers still announces the role. The book is cached for 10 s; the arbiter reads `credits::book`, which `book_fresh` just refreshed. Add `Queue::len` for the first test.)

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib credits::audit credits::gates` and `cargo test --test cluster designated`
Expected: compile errors (`seed`, `designated`, `auditors`, `owes`, `Queue`, `obligations`, `audits_owed`).

- [ ] **Step 3: The offer of an audit**

`src/store/migrations/0029_scarce_credits.sql`, append:

```sql
-- The scan an audit offer pays for (`credits::audit`).
ALTER TABLE credit_entries ADD COLUMN audit_uid TEXT;
CREATE INDEX idx_credit_entries_audit ON credit_entries(audit_uid) WHERE audit_uid IS NOT NULL;
```

`Record::CreditOffer` gains, before `economy`:

```rust
        /// The scan an audit this offer buys checks (`credits::audit`);
        /// such an offer lives as long as an audit may take.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audit: Option<String>,
```

(every literal adds `audit: None`, every pattern `..`). `entries::apply` keeps `audit` (≤ 128 bytes, else the offer is ignored like a long job) in `audit_uid`; `Kind::Offer` gains `audit: Option<String>`, read back by `from_row` (add `audit_uid` to `COLUMNS` and `Row`). `ledger::Offer` gains `audit: Option<String>` (filled in `Walk::offer`), and

```rust
    pub fn ttl_ms(&self) -> u64 {
        if self.audit.is_some() {
            super::AUDIT_OFFER_TTL_MS
        } else if self.job.is_some() {
            super::JOB_OFFER_TTL_MS
        } else {
            OFFER_TTL_MS
        }
    }
```

`src/credits/mod.rs`:

```rust
/// An audit offer lapses after the time an audit may wait to start, the
/// longest scan and the margin for the receipt.
pub const AUDIT_OFFER_TTL_MS: u64 = audit::AUDIT_WINDOW_MS + JOB_OFFER_TTL_MS;
```

`src/credits/pay.rs`: rename the body of `make_offer` to `make_offer_for(node, server, total_mc, audit: Option<String>)` writing `audit` into the `CreditOffer`, and keep `pub async fn make_offer(node, server, total_mc) -> Result<u64, String> { make_offer_for(node, server, total_mc, None).await }`. In `accept_offer`, check time against the offer's own lifetime: `fn time_left(hlc: u64, ttl_ms: u64, now_ms: u64, margin_ms: u64) -> bool { now_ms + margin_ms <= physical_ms(hlc) + ttl_ms }`, called with `offer.ttl_ms()`; its unit test passes `OFFER_TTL_MS`.

- [ ] **Step 4: Designation, ranking, obligation**

`src/credits/audit.rs`: module doc — "Audits: a second look at a scan. … A share of the scans of granted jobs is designated for audit by a hash of the log the scanner cannot steer (`designated`), and the scanner buys each such audit from auditors ranked by the same hash (`auditors`, `buy`); every node counts whether it did (`obligations`). Each scanner also re-runs a share of others' fresh scans unpaid (`Picker`). A node believes, for the differ gate, the audits it made itself and those of its own fleet."

```rust
/// The share of scans of granted jobs designated for a bought audit; a
/// protocol constant, so every node designates the same scans.
pub const AUDIT_RATE: f64 = 0.05;
/// Auditors that may sell the audit of one designated scan.
pub const AUDITORS: usize = 3;

/// What designates a scan and ranks its auditors: a hash of its job and
/// the HLC of the arbiter's done status, which the arbiter writes after
/// the result is published.
pub fn seed(job_uid: &str, done_hlc: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"peephole-audit\0");
    h.update(job_uid.as_bytes());
    h.update(done_hlc.to_be_bytes());
    h.finalize().into()
}

/// Whether the scan of `seed` is designated for a bought audit.
pub fn designated(seed: &[u8; 32]) -> bool {
    let x = u64::from_be_bytes(seed[..8].try_into().expect("8 bytes"));
    (x as f64) < AUDIT_RATE * (u64::MAX as f64 + 1.0)
}

/// The auditors of a designated scan, best first: the active scanners of
/// protocol 7 other than `scanner`, ranked by `SHA-256(seed || key)`; the
/// first [`AUDITORS`].
pub fn auditors(seed: &[u8; 32], members: &[MemberRow], scanner: &NodeId) -> Vec<NodeId> {
    use sha2::{Digest, Sha256};
    let mut ranked: Vec<([u8; 32], NodeId)> = members
        .iter()
        .filter(|m| {
            m.active
                && m.id != *scanner
                && m.proto_max >= crate::cluster::rpc::proto::ECONOMY_PROTO
                && m.roles.iter().any(|r| r == "scanner")
        })
        .map(|m| {
            let mut h = Sha256::new();
            h.update(seed);
            h.update(m.id.0);
            (h.finalize().into(), m.id)
        })
        .collect();
    ranked.sort();
    ranked.into_iter().take(AUDITORS).map(|(_, id)| id).collect()
}

/// `(bought, designated)` when a scanner's designated scans lack a bought
/// audit twice or more and it bought fewer than 80 % of them.
pub fn owes(designated: u32, bought: u32) -> Option<(u32, u32)> {
    let missing = designated.saturating_sub(bought);
    (missing >= 2 && u64::from(bought) * 5 < u64::from(designated) * 4)
        .then_some((bought, designated))
}

/// Per scanner: its scans designated over the last 7 days (leaving out
/// the newest [`crate::credits::AUDIT_OFFER_TTL_MS`], whose audits may
/// still run), and how many of them it bought: an audit by one of the
/// scan's [`auditors`] (by `members` as held here), with a charged audit
/// offer from the scanner to that auditor naming the scan.
pub async fn obligations(
    pool: &SqlitePool,
    members: &[MemberRow],
    now_ms: u64,
) -> Result<HashMap<NodeId, (u32, u32)>> {
    let from = hlc::to_db(now_ms.saturating_sub(7 * crate::credits::DAY_MS) << 16);
    let to = hlc::to_db(now_ms.saturating_sub(crate::credits::AUDIT_OFFER_TTL_MS) << 16);
    // (scanner, scan uid, job uid, done HLC)
    let scans: Vec<(Vec<u8>, String, String, i64)> = sqlx::query_as(
        "SELECT s.origin, s.uid, j.uid, j.status_hlc FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.audit_of IS NULL AND s.origin IS NOT NULL AND s.uid IS NOT NULL
           AND s.level BETWEEN 1 AND 4 AND j.status = 'done'
           AND j.arbiter IS NOT NULL AND j.arbiter != s.origin
           AND j.status_hlc >= ? AND j.status_hlc < ?",
    )
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    // (scan uid, auditor) of every audit the scanner paid its auditor for.
    let paid: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT o.audit_uid, o.peer FROM credit_entries o
         JOIN credit_entries r ON r.kind = 'receipt' AND r.economy = 2 AND r.charged_mc > 0
              AND r.origin = o.peer AND r.peer = o.origin AND r.offer_seq = o.seq
         JOIN scans a ON a.audit_of = o.audit_uid AND a.origin = o.peer
         WHERE o.kind = 'offer' AND o.economy = 2 AND o.audit_uid IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let paid: std::collections::HashSet<(String, Vec<u8>)> = paid.into_iter().collect();
    let mut out: HashMap<NodeId, (u32, u32)> = HashMap::new();
    for (scanner, scan_uid, job_uid, done) in scans {
        let Ok(scanner) = NodeId::from_slice(&scanner) else { continue };
        let s = seed(&job_uid, hlc::from_db(done));
        if !designated(&s) {
            continue;
        }
        let e = out.entry(scanner).or_default();
        e.0 += 1;
        if auditors(&s, members, &scanner)
            .iter()
            .any(|a| paid.contains(&(scan_uid.clone(), a.0.to_vec())))
        {
            e.1 += 1;
        }
    }
    Ok(out)
}
```

(`MemberRow` is `crate::cluster::members::MemberRow`; `hlc::from_db`/`to_db` are the existing converters.)

`src/credits/gates.rs`: `Standing` gains

```rust
    /// `(bought, designated)` audits of its designated scans over 7 days,
    /// when it bought too few (`credits::audit::owes`).
    pub audits_owed: Option<(u32, u32)>,
```

`earns_as_scanner`: `self.earns() && self.audits.is_none() && self.audits_owed.is_none()`; `reasons` adds `format!("audits: bought {b} of {d} designated")`; `standings` adds, after the differ gate:

```rust
    let all = crate::cluster::members::all(&node.store).await?;
    let now = crate::cluster::hlc::wall_ms();
    for (scanner, (designated, bought)) in super::audit::obligations(&node.store.pool, &all, now).await? {
        if let Some(o) = super::audit::owes(designated, bought) {
            out.entry(scanner).or_default().audits_owed = Some(o);
        }
    }
```

- [ ] **Step 5: Buying and selling**

`src/cluster/msg.rs`, at the end of `Msg`:

```rust
    /// Scanner → its auditor: audit my designated scan `scan_uid`, paid
    /// with my offer `offer_seq` (`credits::audit`). The auditor reads the
    /// scan from its own copy of the log.
    AuditReq {
        scan_uid: String,
        offer_seq: u64,
    },
    AuditReply {
        accepted: bool,
        why: Option<String>,
    },
```

`src/cluster/mod.rs`: `pub audit_queue: Mutex<crate::credits::audit::Queue>,` and `pub audits_tried: Mutex<std::collections::HashSet<String>>,` (both `Default::default()`).

`src/credits/audit.rs`, beside the `Picker`:

```rust
/// A scan to run again: an unpaid pick (`offer` None) or a bought audit.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub scan_uid: String,
    pub job_uid: String,
    pub ip: String,
    pub level: u8,
    /// Wall-clock ms after which it is dropped.
    pub deadline_ms: u64,
    /// Who bought it, its offer and what it offered.
    pub offer: Option<(NodeId, u64, u32)>,
}

/// Bought audits waiting for a free worker; handed out before unpaid picks.
#[derive(Default)]
pub struct Queue(VecDeque<Task>);

impl Queue {
    /// Queue a bought audit; false when [`MAX_WAITING`] wait already.
    pub fn push(&mut self, t: Task) -> bool {
        if self.0.len() >= MAX_WAITING {
            return false;
        }
        self.0.push_back(t);
        true
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The next one still in time and not at a level in `exclude`.
    pub fn take(&mut self, exclude: &[u8]) -> Option<Task> {
        let now = hlc::wall_ms();
        self.0.retain(|t| t.deadline_ms > now);
        let i = self.0.iter().position(|t| !exclude.contains(&t.level))?;
        self.0.remove(i)
    }
}
```

The `Picker`'s own `Task` becomes this `Task` with `offer: None` (its `take` returns it); `started`/`started_last_hour` stay on the `Picker`, which also counts bought audits started (the worker calls `started()` for both).

```rust
/// `(scanner, job uid, ip, level, done HLC)` of the scan `scan_uid` held
/// here, once its job is done; waits up to `SERVE_WAIT` for it to arrive.
async fn scan_of(node: &Node, scan_uid: &str) -> Option<(NodeId, String, String, u8, u64)> {
    let until = tokio::time::Instant::now() + crate::credits::pay::SERVE_WAIT;
    loop {
        let row: Option<(Vec<u8>, String, String, i64, i64)> = sqlx::query_as(
            "SELECT s.origin, j.uid, i.ip, s.level, j.status_hlc FROM scans s
             JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
             JOIN ips i ON i.id = s.ip_id
             WHERE s.uid = ? AND s.audit_of IS NULL AND j.status = 'done'
               AND j.arbiter IS NOT NULL AND j.arbiter != s.origin",
        )
        .bind(scan_uid)
        .fetch_optional(&node.store.pool)
        .await
        .ok()
        .flatten();
        if let Some((s, job, ip, level, done)) = row {
            return Some((NodeId::from_slice(&s).ok()?, job, ip, u8::try_from(level).ok()?, hlc::from_db(done)));
        }
        if tokio::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Answer bought audits: check the scan, the ranking and the offer, then
/// queue the audit.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::AuditReq { scan_uid, offer_seq } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            Some(match sell(&node, from, &scan_uid, offer_seq).await {
                Ok(()) => Msg::AuditReply { accepted: true, why: None },
                Err(why) => Msg::AuditReply { accepted: false, why: Some(why) },
            })
        })
    }));
}

async fn sell(node: &Arc<Node>, peer: NodeId, scan_uid: &str, seq: u64) -> Result<(), String> {
    use crate::credits::{entries, pay, price};
    let refuse = async |why: &str| {
        pay::release(node, peer, seq).await;
        Err(why.to_string())
    };
    if !node.roles().scanner || scan_uid.is_empty() || scan_uid.len() > 128 {
        return refuse("this node audits no such scan").await;
    }
    let Some((scanner, job_uid, ip, level, done)) = scan_of(node, scan_uid).await else {
        return refuse("the scan or its done job is not held here").await;
    };
    let s = seed(&job_uid, done);
    let members = crate::cluster::members::all(&node.store).await.map_err(|e| format!("{e:#}"))?;
    if scanner != peer || !(1..=4).contains(&level) || !designated(&s) {
        return refuse("not a designated scan of the asker").await;
    }
    if !auditors(&s, &members, &scanner).contains(&node.id()) {
        return refuse("this node is not among the scan's auditors").await;
    }
    let least = price::min_take(node.price_table().price_of(price::SCAN).unwrap_or(0)) as u64;
    // Room for the wait, the longest scan and the receipt.
    let margin = AUDIT_WINDOW_MS + crate::scan::pace::MAX_RUN_SECS * 1000 + 60_000;
    if let Err(d) = pay::accept_offer(node, peer, seq, least, "audit", margin).await {
        return Err(match d {
            pay::Declined::Why(w) | pay::Declined::NotCovered(w) => w,
            pay::Declined::TooLow { why, .. } => why,
        });
    }
    let named = entries::get(&node.store.pool, &peer, seq).await.ok().flatten();
    let Some(entries::Entry { kind: entries::Kind::Offer { parts, audit: Some(of), .. }, .. }) = named else {
        return refuse("the offer buys no audit").await;
    };
    if of != scan_uid {
        return refuse("the offer is for another scan").await;
    }
    let task = Task {
        scan_uid: scan_uid.to_string(),
        job_uid,
        ip,
        level,
        deadline_ms: hlc::wall_ms() + AUDIT_WINDOW_MS,
        offer: Some((peer, seq, parts.iter().map(|(_, mc)| *mc).sum())),
    };
    if !node.audit_queue.lock().unwrap().push(task) {
        return refuse("this scanner has too many audits waiting").await;
    }
    Ok(())
}

/// Buy the audit of this node's designated scan `scan_uid` from its
/// auditors in rank order: the first that is live, announces a scan price
/// and accepts, at that price (at least 1 mc). Returns the auditor.
pub async fn buy(node: &Arc<Node>, scan_uid: &str) -> Result<NodeId, String> {
    let me = node.id();
    let Some((scanner, job_uid, _, _, done)) = scan_of(node, scan_uid).await else {
        return Err("the scan or its done job is not held here".into());
    };
    if scanner != me {
        return Err("not this node's scan".into());
    }
    let s = seed(&job_uid, done);
    if !designated(&s) {
        return Err("not designated".into());
    }
    let members = crate::cluster::members::all(&node.store).await.map_err(|e| format!("{e:#}"))?;
    let mut last = "no auditor is reachable".to_string();
    for auditor in auditors(&s, &members, &me) {
        let live = node.live_members(crate::scan::arbiter::LIVE_WINDOW).contains(&auditor);
        let price = node.status.known(&auditor).and_then(|k| k.hb.scan_price_mc);
        let (true, Some(price)) = (live && node.can_call(&auditor), price) else {
            continue;
        };
        let offer_seq = match crate::credits::pay::make_offer_for(
            node,
            auditor,
            price.max(1) as u64,
            Some(scan_uid.to_string()),
        )
        .await
        {
            Ok(seq) => seq,
            Err(why) => return Err(why),
        };
        let req = Msg::AuditReq { scan_uid: scan_uid.to_string(), offer_seq };
        match node.request(auditor, req, std::time::Duration::from_secs(30)).await {
            Ok(Msg::AuditReply { accepted: true, .. }) => return Ok(auditor),
            Ok(Msg::AuditReply { why, .. }) => last = why.unwrap_or_else(|| "declined".into()),
            Ok(_) => last = "unexpected answer".into(),
            Err(e) => last = format!("could not be asked: {e:#}"),
        }
    }
    Err(last)
}

/// Buy the audits of this node's designated scans whose done status
/// arrived within the audit window and that it has not tried yet.
/// Returns how many it bought.
pub async fn buy_due(node: &Arc<Node>) -> usize {
    let me = node.id();
    let since = hlc::to_db(hlc::wall_ms().saturating_sub(AUDIT_WINDOW_MS) << 16);
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT s.uid, j.uid, j.status_hlc FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid AND j.scanner = s.origin
         WHERE s.origin = ?1 AND s.audit_of IS NULL AND s.uid IS NOT NULL
           AND s.level BETWEEN 1 AND 4 AND j.status = 'done'
           AND j.arbiter IS NOT NULL AND j.arbiter != ?1 AND j.status_hlc >= ?2",
    )
    .bind(&me.0[..])
    .bind(since)
    .fetch_all(&node.store.pool)
    .await
    .unwrap_or_default();
    let mut bought = 0;
    for (scan_uid, job_uid, done) in rows {
        if !designated(&seed(&job_uid, hlc::from_db(done)))
            || !node.audits_tried.lock().unwrap().insert(scan_uid.clone())
        {
            continue;
        }
        match buy(node, &scan_uid).await {
            Ok(by) => {
                tracing::info!(scan = %scan_uid, auditor = %by.short(), "audit bought");
                bought += 1;
            }
            Err(why) => tracing::info!(scan = %scan_uid, %why, "designated scan not audited"),
        }
    }
    bought
}
```

`audits_tried` is pruned with the hourly prune in `credits::run` (clear it when it holds more than 10 000 uids: a scan older than the window is never due again). `credits::run` calls `audit::buy_due(&node).await;` every tick.

- [ ] **Step 6: The auditor runs and charges; arbiters stop funding**

`src/scan/mod.rs`:
- `next_audit`: first `let bought = node.audit_queue.lock().unwrap().take(exclude);` (never hold the std lock across an `await`), then the picker as today; the checks after (`active`, `preflight`, evidence) apply to both. `picker.started()` for both.
- `Job::Audit` gains `offer: Option<(NodeId, u64, u32)>` from the task.
- `finish`, `Job::Audit` with `Outcome::Done`: after `record_scan_audit` succeeds and when `offer` is `Some((payer, seq, price))`,

```rust
                        let receipt = Record::CreditReceipt {
                            payer,
                            offer_seq: seq,
                            charged_mc: price,
                            answered: vec![crate::credits::price::AUDIT.into()],
                            economy: crate::cluster::record::ECONOMY,
                        };
                        if let Err(e) = crate::cluster::repl::append(node, &[receipt]).await {
                            warn!(audit_of = %of, ?e, "audit receipt not written");
                        }
```

  (a bought audit that fails, is abandoned or is not run writes nothing: the offer lapses). Add `pub const AUDIT: &str = "audit";` to `credits::price` next to `SCAN`.

`src/scan/arbiter.rs` `round`: read `let book = crate::credits::book(&self.node).await.ok();` once and pass it to `stand`: `price: if book.as_ref().is_some_and(|b| !b.standing(scanner).earns_as_scanner()) { None } else { crate::credits::jobs::price_for(&self.node, scanner) },` (doc: "None: unpaid here, or a scanner that does not earn as one (it owes audits, or its audits differ): it is not funded").

`src/lib.rs`: `credits::audit::serve(&node)` where the other cluster handlers are registered (with `credits::fleet::serve`); `tests/cluster.rs` `boot_in`: `peephole::credits::audit::serve(&node);` after `peephole::credits::fleet::serve(&node);`. `[credits] audit_share` keeps its meaning (the unpaid checks).

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test --lib credits scan cluster::msg` and `cargo test --test cluster designated a_funded_scan_job audits`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add -A src tests
git commit -m "Credits: designated scans are audited by ranked auditors; owed audits stop funding"
```

---

### Task 9: Relay leases

A new good `relay`: one hour of holding an outbox for an outbound-only member and relaying directed messages to it. Any advertised member sells it, with `[cluster] relay_slots` leases at a time (default 16); its price follows the sales rule (sold: a lease accepted; at capacity: every slot taken) and is announced under `relay`. An outbound-only member leases the two cheapest reachable sellers, renewing 5 minutes before expiry, long-polls only their inboxes and lists them in its heartbeat (`relays`). A relay holds an outbox only for members with an address or a current lease from it. A sender routes a message for an outbound-only member through one of its listed relays and tries the other when the first fails or refuses; the neighbour-graph route stays for members that list no relays. Without a lease a member still syncs but cannot be asked for anything paid.

**Files:**
- Create: `src/cluster/relay.rs`
- Modify: `src/cluster/mod.rs` (`pub mod relay;`, `Node.relay_leases`, `Node.leased`, `routed_callable`)
- Modify: `src/config.rs` (`ClusterConfig.relay_slots`), and every `ClusterConfig { … }` literal (`grep -rn "origin_quota_mb: 20 \* 1024" src tests`: add `relay_slots: 16,`)
- Modify: `src/cluster/msg.rs` (`Hop` derives, `relay_hop`, `next_hop`, `route_avoiding`, `inbox_loop`)
- Modify: `src/cluster/status.rs` (`Heartbeat.relays`, `refresh_heartbeat`; the test `Heartbeat` literals in `status.rs`, `repl.rs`, `arbiter.rs` add `relays: vec![]`)
- Modify: `src/credits/price.rs` (`RELAY`, `Table.relay_mc`, refresh)
- Modify: `src/cluster/rpc/mod.rs` (route `/rpc/v1/relay`), `src/cluster/rpc/routed.rs` (routable)
- Modify: `src/lib.rs` (spawn `cluster::relay::run` in cluster mode)
- Modify: `tests/cluster.rs` (`Opts.lease`, `boot_in`, new test)
- Test: `src/cluster/relay.rs`, `src/cluster/msg.rs`, `tests/cluster.rs`

**Interfaces:**
- Consumes: Task 2 (zero price without an offer, `pay::retry_price`), Task 3 (`sales_step`, `current`), Task 4 (`dns::member_price`), Task 6 (`ECONOMY`, `ECONOMY_PROTO`).
- Produces:
  - `price::RELAY: &str = "relay"`, `price::Table.relay_mc: Option<u32>` (None: not advertised).
  - `ClusterConfig.relay_slots: u32` (`#[serde(default = "default_relay_slots")]`, 16).
  - `relay::{LEASE_MS, RENEW_BEFORE_MS, WANTED}`, `relay::RelayReq { hours: u32, offer_seq: Option<u64> }`, `relay::RelayResp::{Accepted { until_ms: u64 }, Declined { why: String, price_mc: Option<u32> }}`
  - `relay::Leases` (as relay: `holds(&NodeId, now_ms) -> bool`, `current(now_ms) -> usize`, `grant(NodeId, now_ms) -> u64`), `relay::Leased` (as lessee: `relays(now_ms) -> Vec<NodeId>`, `keep(now_ms) -> Vec<NodeId>`, `set(NodeId, until_ms)`); `Node.relay_leases: relay::Leases`, `Node.leased: relay::Leased`.
  - `relay::price(node: &Node) -> Option<u32>`, `relay::serve(node: &Arc<Node>, peer: NodeId, req: &RelayReq) -> RelayResp`, `relay::lease_once(node: &Arc<Node>) -> usize`, `relay::run(node: Arc<Node>, shutdown)`.
  - `Heartbeat.relays: Vec<NodeId>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`).
  - `msg::relay_hop(me: &NodeId, to: &NodeId, relays: &[NodeId], dial: &HashMap<NodeId, String>, avoid: &[NodeId], holds: bool) -> Option<Hop>`.

- [ ] **Step 1: Write the failing tests**

`src/cluster/relay.rs` tests (create the file with the types and `todo!()` bodies first):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn a_relay_holds_a_lease_for_an_hour_and_a_renewal_extends_it() {
        let l = Leases::default();
        let t = 1_000_000_000u64;
        let until = l.grant(id(1), t);
        assert_eq!(until, t + LEASE_MS);
        assert!(l.holds(&id(1), t + LEASE_MS - 1));
        assert!(!l.holds(&id(1), t + LEASE_MS));
        assert!(!l.holds(&id(2), t));
        // Renewed 5 minutes before the end: an hour more from the end.
        let renewed = l.grant(id(1), until - RENEW_BEFORE_MS);
        assert_eq!(renewed, until + LEASE_MS);
        assert_eq!(l.current(t), 1);
        // After it ran out, a new lease starts now.
        assert_eq!(l.grant(id(1), renewed + 5), renewed + 5 + LEASE_MS);
        l.grant(id(2), t);
        assert_eq!(l.current(renewed + 6), 1, "the other ran out");
    }

    #[test]
    fn a_lessee_renews_what_ends_within_five_minutes() {
        let l = Leased::default();
        let t = 1_000_000_000u64;
        l.set(id(1), t + LEASE_MS);
        l.set(id(2), t + RENEW_BEFORE_MS - 1);
        assert_eq!(l.relays(t), [id(1), id(2)]);
        assert_eq!(l.keep(t), [id(1)], "2 is due a renewal");
        assert_eq!(l.relays(t + RENEW_BEFORE_MS), [id(1)], "2 ran out");
    }
}
```

`src/cluster/msg.rs` tests:

```rust
    #[test]
    fn an_outbound_only_member_is_reached_through_its_relays_in_turn() {
        let id = |n: u8| NodeId([n; 32]);
        let (me, to) = (id(1), id(9));
        let dial: HashMap<NodeId, String> =
            [(id(2), "a:1".to_string()), (id(3), "b:1".to_string())].into();
        let hop = |relays: &[NodeId], avoid: &[NodeId], holds: bool| {
            relay_hop(&me, &to, relays, &dial, avoid, holds)
        };
        assert_eq!(hop(&[id(2), id(3)], &[], false), Some(Hop::Dial(id(2), "a:1".into())));
        assert_eq!(hop(&[id(2), id(3)], &[id(2)], false), Some(Hop::Dial(id(3), "b:1".into())), "the first refused");
        assert_eq!(hop(&[id(2), id(3)], &[id(2), id(3)], false), None, "both refused: no route");
        assert_eq!(hop(&[id(4)], &[], false), None, "a relay this node cannot dial");
        // This node is one of its relays: its outbox, while the lease holds.
        assert_eq!(hop(&[me, id(2)], &[], true), Some(Hop::Outbox(to)));
        assert_eq!(hop(&[me, id(2)], &[], false), None, "no lease from it: refused");
    }
```

`tests/cluster.rs`: add `lease: bool` to `Opts` (doc: "an outbound-only node leases relays (`cluster::relay::run`)"), `lease: true` in `DEFAULT`; in `boot_in`, after `cluster::start`, `if !o.advertise && o.lease { tokio::spawn(peephole::cluster::relay::run(node.clone(), rx.clone())); }` (clone `rx` before `cluster::start` consumes it). Then:

```rust
/// An outbound-only member with a lease is asked through its relay; one
/// without a lease cannot be asked at all.
#[tokio::test]
async fn only_an_outbound_only_member_with_a_lease_can_be_asked() {
    use peephole::credits::pay;
    let (ia, a) = new_node("node-alpha");
    let (io, o) = new_node("node-oscar");
    let (ip, p) = new_node("node-papa");
    let na = boot(ia, &a, &[], DEFAULT).await;
    let no = boot(io, &o, &[], Opts { advertise: false, ..DEFAULT }).await;
    let np = boot(ip, &p, &[], Opts { advertise: false, lease: false, ..DEFAULT }).await;
    // Admitted by invite, as `outbound_pair` does.
    for n in [&no, &np] {
        let token = invite::create(&na, &Default::default()).await.unwrap();
        invite::join(n, &token).await.unwrap();
    }
    serves(&no, &[("abuseipdb", Some(1000.0))], 0.5);
    serves(&np, &[("abuseipdb", Some(1000.0))], 0.5);
    eventually("o leased a and a knows it", || async {
        na.node
            .status
            .known(&o.id)
            .is_some_and(|k| k.hb.relays == vec![a.id])
    })
    .await;
    assert!(na.node.relay_leases.holds(&o.id, peephole::cluster::hlc::wall_ms()));
    price_seen(&na, o.id, "abuseipdb").await;
    let wanted = ["abuseipdb".to_string()];
    let got = pay::offer_and_ask(&na.node, "203.0.113.83".parse().unwrap(), o.id, &wanted, 0).await;
    assert_eq!(got.findings.len(), 1, "{got:?}");
    // p syncs (a knows its heartbeat) but leased nothing: not callable.
    eventually("a knows p", || async { na.node.status.known(&p.id).is_some() }).await;
    assert!(!na.node.can_call(&p.id));
    let none: peephole::intel::Providers = vec![];
    assert!(pay::quotes(&na.node, &none).values().flatten().all(|q| q.server != p.id));
}
```

Existing outbound-only tests keep `lease: true` and so lease `a` on their own; where a test asks the outbound-only member right after booting, wait first with `eventually(…, k.hb.relays non-empty …)` (put that wait into `outbound_pair`).

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib cluster::relay cluster::msg` and `cargo test --test cluster only_an_outbound_only_member_with_a_lease`
Expected: compile errors, then `todo!()` panics.

- [ ] **Step 3: Implement `src/cluster/relay.rs`**

```rust
//! Relay leases: an outbound-only member (nobody can dial it) rents an
//! hour of outbox hosting from reachable members, two at a time. A relay
//! holds an outbox only for members it holds a lease from; senders route
//! messages for an outbound-only member through the relays it lists in
//! its heartbeat. A lease is a good like any other (`credits::price`).
use super::Node;
use super::identity::NodeId;
use crate::credits::{Mc, pay, price, show};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One lease: an hour.
pub const LEASE_MS: u64 = 3_600_000;
/// A lessee renews this long before a lease ends.
pub const RENEW_BEFORE_MS: u64 = 5 * 60_000;
/// Relays an outbound-only member holds.
pub const WANTED: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReq {
    /// Always 1.
    pub hours: u32,
    /// The lessee's offer; None at a zero price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RelayResp {
    /// Leased until this wall-clock time (ms).
    Accepted { until_ms: u64 },
    Declined {
        why: String,
        #[serde(default)]
        price_mc: Option<u32>,
    },
}

/// The leases this node holds as a relay: lessee → end (ms).
#[derive(Default)]
pub struct Leases(Mutex<HashMap<NodeId, u64>>);

impl Leases {
    pub fn holds(&self, id: &NodeId, now_ms: u64) -> bool {
        self.0.lock().unwrap().get(id).is_some_and(|until| *until > now_ms)
    }

    /// Leases that have not ended.
    pub fn current(&self, now_ms: u64) -> usize {
        let mut l = self.0.lock().unwrap();
        l.retain(|_, until| *until > now_ms);
        l.len()
    }

    /// Lease (or renew) for `id`: an hour from the end of its current
    /// lease, or from now. Returns the new end.
    pub fn grant(&self, id: NodeId, now_ms: u64) -> u64 {
        let mut l = self.0.lock().unwrap();
        let from = l.get(&id).copied().filter(|u| *u > now_ms).unwrap_or(now_ms);
        let until = from + LEASE_MS;
        l.insert(id, until);
        until
    }
}

/// The leases this node took as a lessee: relay → end (ms).
#[derive(Default)]
pub struct Leased(Mutex<BTreeMap<NodeId, u64>>);

impl Leased {
    /// Its relays now.
    pub fn relays(&self, now_ms: u64) -> Vec<NodeId> {
        let mut l = self.0.lock().unwrap();
        l.retain(|_, until| *until > now_ms);
        l.keys().copied().collect()
    }

    /// Relays not due a renewal.
    pub fn keep(&self, now_ms: u64) -> Vec<NodeId> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, until)| **until > now_ms + RENEW_BEFORE_MS)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn set(&self, relay: NodeId, until_ms: u64) {
        self.0.lock().unwrap().insert(relay, until_ms);
    }
}

/// What a lease costs here; None: this node is not advertised (it can
/// relay nothing). 0 before the first price refresh.
pub fn price(node: &Node) -> Option<u32> {
    node.cfg
        .advertise
        .is_some()
        .then(|| node.price_table().relay_mc.unwrap_or(0))
}

/// Lease an hour of outbox hosting to `peer`: free at a zero price, paid
/// with its offer otherwise, charged when accepted.
pub async fn serve(node: &Arc<Node>, peer: NodeId, req: &RelayReq) -> RelayResp {
    let declined = |why: String, price_mc: Option<u32>| RelayResp::Declined { why, price_mc };
    let release = async || {
        if let Some(seq) = req.offer_seq {
            pay::release(node, peer, seq).await;
        }
    };
    let Some(cost) = price(node) else {
        release().await;
        return declined("this node cannot be reached: it relays nothing".into(), None);
    };
    if req.hours != 1 {
        release().await;
        return declined("a lease is one hour".into(), None);
    }
    let now = super::hlc::wall_ms();
    node.market.note(price::RELAY, 1);
    if !node.relay_leases.holds(&peer, now)
        && node.relay_leases.current(now) >= node.cfg.relay_slots as usize
    {
        release().await;
        return declined("every relay slot here is leased".into(), Some(cost));
    }
    match req.offer_seq {
        None if cost > 0 => {
            return declined(
                format!(
                    "a lease costs {} credits here now; the request carries no offer",
                    show(cost as Mc)
                ),
                Some(cost),
            );
        }
        None => {}
        Some(seq) => {
            match pay::accept_offer(node, peer, seq, cost as Mc, "relay", pay::SERVE_MARGIN_MS).await {
                Ok(_) => {}
                Err(pay::Declined::TooLow { why, price_mc }) => return declined(why, Some(price_mc)),
                Err(pay::Declined::Why(w) | pay::Declined::NotCovered(w)) => return declined(w, None),
            }
            let receipt = super::record::Record::CreditReceipt {
                payer: peer,
                offer_seq: seq,
                charged_mc: cost,
                answered: vec![price::RELAY.into()],
                economy: super::record::ECONOMY,
            };
            if let Err(e) = super::repl::append(node, &[receipt]).await {
                tracing::warn!(?e, "relay receipt not written");
                return declined("the receipt could not be written".into(), None);
            }
        }
    }
    let until_ms = node.relay_leases.grant(peer, now);
    tracing::info!(lessee = %peer.short(), charged = %show(cost as Mc), "relay leased");
    RelayResp::Accepted { until_ms }
}

/// One lease request to `relay` at `price`, offered again once at a
/// higher price it names.
async fn ask(node: &Arc<Node>, relay: NodeId, first: u32) -> Option<u64> {
    let once = async |p: Mc| -> Option<RelayResp> {
        let offer_seq = match p {
            0 => None,
            p => Some(pay::make_offer(node, relay, p).await.ok()?),
        };
        let req = RelayReq { hours: 1, offer_seq };
        node.call_any::<RelayReq, RelayResp>(relay, "/rpc/v1/relay", &req, Duration::from_secs(20))
            .await
            .ok()
    };
    let mut resp = once(first as Mc).await?;
    if let RelayResp::Declined { price_mc, .. } = &resp
        && let Some(p) = pay::retry_price(first as Mc, *price_mc, true)
    {
        resp = once(p).await?;
    }
    match resp {
        RelayResp::Accepted { until_ms } => Some(until_ms),
        RelayResp::Declined { why, .. } => {
            tracing::debug!(relay = %relay.short(), %why, "relay lease declined");
            None
        }
    }
}

/// Lease what is missing of [`WANTED`] relays (renewing those that end
/// within [`RENEW_BEFORE_MS`]) from the cheapest reachable sellers. An
/// advertised node leases nothing. Returns how many leases it took.
pub async fn lease_once(node: &Arc<Node>) -> usize {
    if node.cfg.advertise.is_some() {
        return 0;
    }
    let now = super::hlc::wall_ms();
    let keep = node.leased.keep(now);
    let need = WANTED.saturating_sub(keep.len());
    if need == 0 {
        return 0;
    }
    let me = node.id();
    let mut sellers: Vec<(u32, u32, NodeId)> = node
        .live_members(crate::intel::LIVE_WINDOW)
        .into_iter()
        .filter(|id| *id != me && !keep.contains(id) && !node.is_blocked(id))
        .filter(|id| node.dial_address(id).is_some())
        .filter_map(|id| {
            let p = crate::intel::dns::member_price(node, &id, price::RELAY)?;
            let mut r = [0u8; 4];
            let _ = aws_lc_rs::rand::fill(&mut r);
            Some((p, u32::from_le_bytes(r), id))
        })
        .collect();
    sellers.sort();
    let mut took = 0;
    for (p, _, relay) in sellers {
        if took == need {
            break;
        }
        if let Some(until) = ask(node, relay, p).await {
            node.leased.set(relay, until);
            took += 1;
        }
    }
    if took > 0 {
        node.publish_status();
    }
    took
}

/// Keep this outbound-only node's relays leased, until shutdown.
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        lease_once(&node).await;
        let short = node.leased.relays(super::hlc::wall_ms()).len() < WANTED;
        let wait = Duration::from_secs(if short { 5 } else { 60 });
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
    }
}
```

`src/cluster/mod.rs`: `pub mod relay;`; fields `pub relay_leases: relay::Leases,` and `pub leased: relay::Leased,` (`Default::default()`); `routed_callable` adds `&& (m.address.is_some() || self.status.known(id).is_some_and(|k| !k.hb.relays.is_empty()))` to the member check (an outbound-only member without relays cannot be asked).

`src/config.rs`: `ClusterConfig` gains

```rust
    /// Relay leases this node sells at a time to outbound-only members
    /// (only an advertised node relays).
    #[serde(default = "default_relay_slots")]
    pub relay_slots: u32,
```

with `fn default_relay_slots() -> u32 { 16 }`; add `relay_slots: 16,` to every literal.

- [ ] **Step 4: Routing, inboxes, heartbeat, price**

`src/cluster/msg.rs`: `#[derive(Debug, PartialEq)]` on `Hop`; add

```rust
/// The first hop of a message for `to`, an outbound-only member leasing
/// `relays`: this node's outbox when it is one of them and `holds` its
/// lease (else none: it refuses), otherwise the first listed relay this
/// node can dial that is not in `avoid`.
pub(crate) fn relay_hop(
    me: &NodeId,
    to: &NodeId,
    relays: &[NodeId],
    dial: &HashMap<NodeId, String>,
    avoid: &[NodeId],
    holds: bool,
) -> Option<Hop> {
    if relays.contains(me) {
        return holds.then_some(Hop::Outbox(*to));
    }
    relays
        .iter()
        .filter(|r| !avoid.contains(r))
        .find_map(|r| dial.get(r).map(|a| Hop::Dial(*r, a.clone())))
}
```

In `next_hop`, right after building `dial`:

```rust
        // An outbound-only member is reached through the relays it leases.
        let relays = self.status.known(to).map(|k| k.hb.relays).unwrap_or_default();
        if !relays.is_empty() && !dial.contains_key(to) {
            let now = super::hlc::wall_ms();
            let holds = self.relay_leases.holds(to, now) && self.status.polled_recently(to);
            return relay_hop(&self.id(), to, &relays, &dial, avoid, holds);
        }
```

and in `via`, hold an outbox only for a member with an address or a current lease: `(self.status.polled_recently(id) && self.holds_outbox_for(id)).then_some(Hop::Outbox(*id))` with

```rust
    /// Whether this node keeps an outbox for `id`: it has an address
    /// (it collects here when its dial fails), or leased this node.
    fn holds_outbox_for(&self, id: &NodeId) -> bool {
        self.members().get(id).is_some_and(|m| m.address.is_some())
            || self.relay_leases.holds(id, super::hlc::wall_ms())
    }
```

In `route_avoiding`, a relay that fails or refuses is skipped for the next:

```rust
                Some(Hop::Dial(peer, addr)) => {
                    match node.call::<_, bool>(peer, &addr, "/rpc/v1/msg", &env).await {
                        Ok(_) => Ok(Some(peer)),
                        Err(e) if node.status.known(&body.to).is_some_and(|k| k.hb.relays.contains(&peer)) => {
                            debug!(relay = %peer.short(), ?e, "relay failed; trying the next");
                            let mut avoid = avoid;
                            avoid.push(peer);
                            node.route_avoiding(env, avoid).await
                        }
                        Err(e) => Err(e),
                    }
                }
```

`inbox_loop`: at the top of the loop body, an outbound-only node polls only its relays:

```rust
        if node.cfg.advertise.is_none()
            && !node.leased.relays(super::hlc::wall_ms()).contains(&peer)
        {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
```

`src/cluster/status.rs`: `Heartbeat` gains

```rust
    /// The relays this outbound-only node leases (`cluster::relay`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<NodeId>,
```

`refresh_heartbeat` sets `relays: self.leased.relays(super::hlc::wall_ms())` and, after `table.announced()`, `if let Some(p) = super::relay::price(self) && !prices.iter().any(|(g, _)| g == crate::credits::price::RELAY) { prices.push((crate::credits::price::RELAY.to_string(), p)); }` (make `prices` mutable).

`src/credits/price.rs`: `pub const RELAY: &str = "relay";`; `Table.relay_mc: Option<u32>`; `price_of(RELAY) => self.relay_mc`; `announced()` pushes it when `Some`. In `refresh`, after `probe_mc`:

```rust
    // A relay sells leases; it is at capacity when every slot is leased.
    let relay_mc = match node.cfg.advertise {
        Some(_) => {
            let cur = current(node, &old, RELAY, &ann(RELAY)).await?;
            let full = node.relay_leases.current(crate::cluster::hlc::wall_ms())
                >= node.cfg.relay_slots as usize;
            Some(as_mc(sales_step(cur, got(RELAY) > 0.0 || full, hours)))
        }
        None => None,
    };
```

keep it (`price_key(RELAY)`; `load_kept` seeds `relay_mc` from it when advertised), add a history row (`(RELAY, relay_mc, per_hour(got(RELAY)), node.cfg.relay_slots as f64)` when advertised) and set it in the `Table`. `src/admin/credits.rs` `good_label`: `credits::price::RELAY => "Relay lease".into()`.

`src/cluster/rpc/mod.rs`: `.route("/rpc/v1/relay", post(relay))` calling `crate::cluster::relay::serve(&node, peer, &req)`; `src/cluster/rpc/routed.rs`: `ROUTED_PATHS` gains `"/rpc/v1/relay"` with its arm in `answer`, and the routed test asserts it. `src/lib.rs`: in cluster mode, `tokio::spawn(cluster::relay::run(node.clone(), shutdown_rx.clone()));` next to `credits::run`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib cluster credits::price config` and `cargo test --test cluster outbound only_an_outbound_only_member_with_a_lease routed probe_by_an_outbound owner_commands_reach_an_outbound_only`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A src tests
git commit -m "Cluster: outbound-only members lease two relays; relays hold outboxes only for lessees"
```

---

### Task 10: Pages, CLI, installer and docs

The Credits page shows each member's reported hours today and whether it qualifies, the goods table lists reverse names and relay leases, and the price card states the audit share; the installer's advertise prompt says what an unreachable node gives up; the docs, README, example config and changelog describe the new economy.

**Files:**
- Modify: `src/admin/credits.rs`, `templates/admin_cluster_credits.html` (Up column, audit share, relay and reverse-name prices)
- Modify: `install.sh:1188-1190` (advertise prompt)
- Modify: `docs/cluster.md` (outbound-only paragraph ~line 24, "Credits: a market for the cluster's work", "Upgrading")
- Modify: `README.md:105-110` (Lookup paragraph)
- Modify: `deploy/config.example.toml` (`[credits]`, `[cluster] relay_slots`)
- Modify: `CHANGELOG.md` (`## [Unreleased]`: a `### Breaking` section first, plus Added/Changed lines)
- Test: `src/admin/credits.rs`, `tests/cluster.rs` (`the_credits_page_shows_balance_earnings_payments_and_the_price`)

**Interfaces:**
- Consumes: everything before. `Book::up_hours`, `Book.listeners`, `reach::MIN_UP_HOURS`, `pool::POOL_PER_DAY`, `price::{RDNS, RELAY}`, `Table.{rdns_mc, relay_mc}`, `cfg.credits.audit_share`.
- Produces: no code interfaces.

- [ ] **Step 1: Write the failing page test**

In `src/admin/credits.rs`, `MemberRow` gains `up: String` ("hours up today, as reported") and `qualifies: bool` ("an advertised listener up `MIN_UP_HOURS` today"); `PriceView` gains `rdns: String`, `relay: Option<String>` (None: not advertised) and `audit_share: String` ("5"). Extend `the_page_shows_where_credits_come_from`: the member row gets `up: "14".into(), qualifies: true`, the price view `rdns: "0.00".into(), relay: Some("0.01".into()), audit_share: "5".into()`, and assert

```rust
        for want in [
            "14 h",
            "qualifies",
            "Reverse names cost <b>0.00</b>",
            "A relay lease (an hour) costs <b>0.01</b>",
            "checks 5 % of other nodes' fresh scans unpaid",
        ] {
            assert!(html.contains(want), "{want} missing");
        }
        let mut page = page;
        page.members[0].qualifies = false;
        page.price.relay = None;
        let html = page.render().unwrap();
        assert!(html.contains("does not qualify"));
        assert!(!html.contains("A relay lease"));
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib admin::credits`
Expected: compile errors for the new fields.

- [ ] **Step 3: Implement the page**

In `page`, per member: `up: book.up_hours(&m.id, today).to_string()`, `qualifies: m.address.is_some() && m.roles.iter().any(|r| r == "listener") && book.up_hours(&m.id, today) >= credits::reach::MIN_UP_HOURS`. In `PriceView`: `rdns: show(t.rdns_mc as u64)`, `relay: crate::cluster::relay::price(node).map(|m| show(m as u64))`, `audit_share: format!("{:.0}", st.cfg.credits.audit_share * 100.0)` (use the config the admin state holds; `grep -n "cfg" src/admin/mod.rs` for its name).

Template:
- Cluster table: a column `<th class="num" title="Hours up today, as the members report; 12 earn the day's pool share">Up today</th>` with `<td class="num">{{ m.up }} h {% if m.qualifies %}<span class="badge" data-status="done">qualifies</span>{% else %}<span class="muted small">does not qualify</span>{% endif %}</td>`.
- "What things cost here", after the resolution line:
  `<li>Reverse names cost <b>{{ price.rdns }}</b> credits here.</li>`
  `{% if let Some(r) = price.relay %}<li>A relay lease (an hour) costs <b>{{ r }}</b> credits here.</li>{% endif %}`
  `<li>1 in 20 scans of granted jobs is designated for an audit the scanner buys from auditors the log ranks; this node also checks {{ price.audit_share }} % of other nodes' fresh scans unpaid.</li>`
- Its lead paragraph: "Each price follows sales: it rises while the good sells (or every slot is taken) and falls while it does not, down to nothing. What this node answers itself is free, though its own scan jobs use up its scan budget."

- [ ] **Step 4: Installer**

`install.sh` line ~1189, the advertise prompt becomes:

```bash
        say $'\nOther members dial this node at an address you publish. The port must be reachable from the\ninternet; the installer does not change the firewall. A node nobody can reach gets no daily\nallowance of credits, earns only by scanning or by selling lookups and names, and must lease a\nrelay from a reachable member to be asked for anything paid. To change it later: advertise and\nlisten in /etc/peephole/config.toml, then restart peephole.\n'
```

Run `bash -n install.sh` and `tests/install-smoke.sh` if it runs offline (read it first; skip it if it needs a VM, and say so in the report).

- [ ] **Step 5: Docs**

`docs/cluster.md`, outbound-only paragraph (~line 24): replace "…and receives directed messages (it fetches them from its peers' outboxes), so from protocol 6 it also answers paid lookups, DNS resolutions and probes that arrive as such messages: it and the member whose outbox it polls must run protocol 6." with: "From protocol 7 it leases two relays from reachable members (an hour at a time, at their relay price, renewed 5 minutes before the end) and fetches its directed messages from their outboxes only; members reach it through the relays its heartbeat lists. Without a lease it still syncs, but it cannot be asked for anything paid. It gets no share of the daily pool: only members anyone can reach do."

"Credits: a market for the cluster's work" — replace the lede and the first bullets with:

- Lede: "Everything the cluster does for a member is a good that member buys with **credits**: lookups, name resolutions, reverse names, probes, scan jobs, audits and relay leases. The supply is fixed; prices follow sales."
- **Where credits come from.** "One door: the daily pool. At the end of each UTC day 1000 credits are split evenly among that day's verified listeners — members with the listener role and an advertised address that were up in at least 12 of the day's 24 hours — the remainder 0.001 each to the lowest keys, credited an hour after midnight. Up means reported: every member writes one `reach_report` an hour naming the advertised members it completed a sync round with, and a member is up in an hour when more than half of that hour's reports from others (not blocked here) name it. A member that does not earn on your node gets no share there, and its share goes to nobody. `peephole credits uptime` lists each member's hours."
- **Where they go.** "Nowhere: nothing burns. A credit keeps its day when it changes hands and is gone 7 days after it, so at most six pools are in circulation. Sellers keep what they charge."
- **Prices.** "One rule for every good, on each node every 10 minutes: a good that sold since the last refresh (or whose every slot is taken) gets dearer by at most a factor of e^0.45 an hour; one that sold nothing gets cheaper by e^-0.15 an hour; each step is scaled by the time since the last and moves at least 0.001 credits. There is no floor: a good nobody buys becomes free, and a free good that is used costs 0.001 at the next refresh. A request may carry no offer: the server answers what it prices at zero and declines the rest naming the price, which the asker may offer once. Scan prices are per scanner, computed by every node from the scans of jobs granted to it; an arbiter pays at most 1.25 times its own figure."
- **Domains and reverse names.** "Quorum goods: `q = min(9, ⌊n/2⌋+1)` nodes are asked, n being the reachable members announcing a price (this node included): this node and the q−1 cheapest, other operators and new countries first among equals. An answer stands when more than half of those that answered gave it. Only the node that recorded a source buys its reverse names (forward-confirmed PTR names); the answers replicate as `rdns_name` records and every node keeps the names with their agreement."
- **Scan jobs.** Delete the idle-work and unfunded sentences ("A job no claimant can be paid for is idle work: there, … stretches, a share of 1 − weight of them." and "Jobs that are not funded are scanned by idle capacity and earn the mint only."); add "Every grant is funded, at zero or above: a scanner priced at 0 is granted without an offer. A job no claimant can be paid for waits. `scan_share = 0` funds only free scanners."
- **Conformity and audits.** "…its scans stand up to the audits you believe: those of your own nodes. One in 20 scans of jobs granted by another arbiter is designated for a bought audit by a hash of the job and the arbiter's done status, which the scanner cannot steer or know before it has published the result; the same hash ranks the scan's three auditors among the scanners. The scanner buys the audit from the first of them that is reachable and priced; the auditor is paid when it publishes the audit. A scanner with two or more designated scans of 7 days unaudited and under 80 % bought is not funded by arbiters, and its scan receipts count for nothing, until it catches up. Each scanner also re-runs `[credits] audit_share` (5 %) of other nodes' fresh scans unpaid, own jobs and small scanners included."
- **Relays.** "An advertised node sells relay leases (`[cluster] relay_slots`, 16 at a time): an hour of holding an outbox for an outbound-only member. It holds outboxes only for members with an address or a lease."
- "What this cannot do": delete the items about the mint, the allowance, idle scanners and "a sensor with a small allowance"; replace "A member that spent its credits and then stops earning here…" with "A member that stops earning here (rules or audits) is credited no pool share and paid for no sales here until it earns again; offers to it lapse back to their payers."; add "Fleets are private, so a sibling of a scanner can rank among its auditors and approve what it is sent; the unpaid checks of other operators are the guard. An arbiter colluding with its scanner can steer which scans are designated." and "Reach reports are self-asserted: a majority of members colluding can call a listener down, or one up."
- **Upgrading.** Add first: "Protocol 7 is a clean cut: the credits of protocol 7 (payments carrying `economy` 2, signed under their own domain) are the only ones counted; earlier payments are kept and ignored, balances start at zero, and the first money is the first pool after a day with 12 reported hours. Upgrade all members in one sitting: a member below protocol 7 is not paid, funded or charged, and is served no entries of protocol 7 until it upgrades."

The command list near line 55 gains `peephole credits uptime               # members' reported hours up, 7 days` and loses `credits why`.

`README.md` Lookup paragraph: "In a cluster, lookups, names, probes and scan jobs are goods bought with credits: a fixed pool a day goes to the members anyone can reach, and everything else is earned by selling. An answer under 24 hours old comes from the dataset for free…" (the rest unchanged).

`deploy/config.example.toml`:

```toml
# [credits]
# # Cluster only. A scanner runs this share of the other nodes' fresh scans
# # again to check them, unpaid (0 = check nothing). Bought audits of
# # designated scans do not depend on it.
# audit_share = 0.05
# # Cluster only. The share of this node's credits its own scan jobs may hold
# # or pay for in a day: a funded job pays its scanner on delivery
# # (0 = fund only scanners priced at zero).
# scan_share = 0.5
```

and under the `[cluster]` example: `# relay_slots = 16        # relay leases sold at a time to outbound-only members (advertised nodes only)`.

`CHANGELOG.md`, `## [Unreleased]`, a new first section:

```markdown
### Breaking

- Protocol 7: a new economy of credits. The daily mint, the allowance and
  the judging of scans are gone; 1000 credits a day are split among the
  members anyone can reach (advertised listeners up 12 of 24 hours, by
  hourly reach reports). Balances start at zero: payments of earlier
  versions are kept but no longer counted. Upgrade every member in one
  sitting; a member below protocol 7 is neither paid nor charged.
- `peephole credits why` is gone; `peephole credits uptime` lists each
  member's reported hours.
```

and under Changed/Added: prices follow sales with no floor (zero-priced goods free without an offer); every scan job is funded, no idle work; domains and reverse names are quorum goods (`min(9, ⌊n/2⌋+1)` of the cheapest); reverse names of a source are bought by the node that recorded it and replicated with their agreement; scanners buy audits of their designated scans (1 in 20, drawn from the log) from ranked auditors, and are not funded while they owe them; outbound-only members lease relays (`[cluster] relay_slots`). Remove or reword the Unreleased lines this release contradicts ("Unpaid jobs keep the sit-out rule.", "Scans run with the previous list still earn.").

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --lib admin` and `cargo test --test cluster the_credits_page the_overview_shows`
Expected: PASS (adjust the cluster page test's expected strings to the new texts).

- [ ] **Step 7: Commit**

```bash
git add src/admin/credits.rs templates/admin_cluster_credits.html install.sh docs/cluster.md README.md \
  deploy/config.example.toml CHANGELOG.md tests/cluster.rs
git commit -m "Docs and pages: the pool, uptime, quorum goods, audits and relays"
```

---

### Final review

- [ ] Prune `target/` (see **Environment**), then run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` (all targets). Every failure is fixed before review.
- [ ] One thorough whole-branch review against the spec and this plan (`git diff master...scarce-credits`), with the **Review Focus** list in hand. Every finding, minor ones included, is fixed and re-verified.
- [ ] Do not push and do not touch `~/peephole-node`: the field upgrade is the user's, in one sitting.
