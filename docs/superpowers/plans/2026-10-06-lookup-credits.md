# Lookup Credits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lookups are paid with credits that nodes earn by completed counter-scans: every node keeps a ledger computed from its own copy of the log, servers price and serve paid lookups, and a fleet earns and spends as one.

**Architecture:** Six new record kinds travel in the replication log. `cluster::seal` gives every log entry a digest, chains a node's payments to its log with seals and turns a contradiction into a fork proof. A new crate module `credits` judges scans, computes the ledger as a pure function of the log (`credits::ledger`), prices lookups (`credits::price`) and pays for them (`credits::pay`); `intel::lookup` asks and serves through it. Audits are scans run a second time by other scanners (`credits::audit`). The admin area gets Cluster › Credits, and the lookup result shares its sections with the IP page (`admin::target`).

**Tech Stack:** Rust 2024, tokio, axum, askama templates, sqlx/SQLite, aws-lc-rs (Ed25519), ciborium (CBOR), sha2, zstd, quick-xml. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-lookup-credits-design.md`. Read it first; this plan argues from it. It builds on the node-ownership plan (`2026-10-06-node-ownership.md`), which is implemented on this branch: `cluster::owner` (fleet, siblings, owner commands).

## Global Constraints

- Branch `ownership-credits`. No new branch, no PR.
- No new crates in `Cargo.toml`.
- Unit: 1 credit = 1000 mc; integers everywhere (`u64` in sums, `u32` on the wire). Shown with two decimals.
- Record kinds, verbatim: `credit_offer`, `credit_receipt`, `credit_transfer`, `log_seal`, `fork_proof`, `scan_audit`. Only `scan_audit` has a uid.
- Numbers from the spec, verbatim: shares 1000/250 mc (L1, L2) and 2000/500 mc (L3, L4); one paid scan per IP in 24 hours; 500 paid scans per node, role and UTC day; lots live on their day and the 6 after; an offer lapses after 15 minutes; judging waits 10 minutes; rules gate: at least 20 compared and more than 2 % differing; audit gate: at least 5 conclusive counted audits in 7 days and at least half differing; `audit_share` default 0.05, audit window 30 minutes; `on_demand_share` default 0.2; weights 1 / 0.25 / 0.25 / 0 (keyed API / InternetDB / GeoLite2 / Tor); `unit` within 0.01 and 100 credits; surge 1 to 8; a `log_seal` after 500 unsealed entries and once a day; a fork proof of at most 1 MiB.
- `PROTO_VERSION` stays 3: ownership raised it on this branch and both ship in one release. Credit messages and paid lookups go only to members with `proto_max >= 3` (`rpc::proto::OWNER_PROTO`).
- Migrations are append-only: each task that needs schema adds its own file from `0013` on, and never edits an older one. Statements must not contain `;` inside themselves; `--` comments are stripped.
- Every balance, gate and price is this node's own view, computed from its own log. Nothing here asks another node what a balance is.
- A standalone node (no `[cluster]`) is unchanged: its own providers, no credits.
- Plan-time check (spec §12), done: `history::window_hlc(7, now)` is `now − 7 × 24 h`, and `history::prune` drops only entries dated before it. The oldest entry a live lot can depend on is dated at the start of UTC day `today − 6`, which is less than 7 × 24 h ago at every moment of today. So with `retention_days = 7` (the smallest window `Config::load` accepts) every entry of the current UTC day and the 6 before is held, also right after the daily prune. The 24-hour window of an IP can start up to a day earlier: a node with the smallest window may pay a scan that a node with more history counts as inside a window. That is the "views differ at the edges" of spec §13, not a defect.
- The code in this plan was written from reading the codebase, not compiled. Expect small mismatches (a signature, an import, a visibility, an askama pattern). Fix them to match the real code, keep the plan's behaviour and names, and say so in the commit message.
- Run only the tests a task names. No full `cargo test` per task (the disk fills up); the last task runs the wider set once, after checking `df -h .`.
- Before each commit: `cargo fmt --all`.
- Commit messages follow the repo's style (`Credits: …`, `Admin: …`, `Docs: …`) and end with the line `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Admin copy is plain: "credits", "balance", "earned", "spent", "destroyed", "audit", "showed two histories", "not earning here". Never "ledger", "lot", "seal", "fork" or "mc" in the UI; those are code and doc words. Amounts are shown as credits with two decimals ("0.25").

## Review Focus

Inputs the spec implies but that are easy to leave untested. Each has its test in the task named.

1. **Entries arrive in another order on another node** (a receipt before its offer's transfer, a scan judged late): balances are the same on every node that holds the same entries. → Task 5, `the_same_entries_in_any_arrival_order_give_the_same_balances`.
2. **A payment names more than the payer holds here** (this node judged the payer's scans differently, or the payer lies): what is there moves, nothing goes below zero, and a server does not serve what is not covered in its own view. → Task 5, `an_offer_larger_than_the_lot_holds_what_is_there`; Task 13, `an_asker_without_credits_is_declined_with_the_reason`.
3. **A node upgraded later than its peers** (its log holds sealing entries and their ranges from before it knew digests): seals over such ranges are checked from the stored entries, and an entry it only ever saw erased leaves the seal unchecked, not wrong. → Task 2, `a_seal_over_entries_without_stored_digests_is_checked_from_the_entries`, `a_stub_in_the_range_leaves_the_seal_unchecked`.
4. **The server's price moved between the heartbeat the asker saw and the request**: the server declines and names its price, nothing is charged, and a second offer at that price is served. → Task 13, `a_price_above_the_offer_is_declined_and_named`.
5. **A lookup of an address nobody recorded**: nothing about the address is written on any node, while the payment itself is. → Task 14, `a_paid_lookup_of_an_unrecorded_address_writes_nothing`.

## File Structure

| File | Responsibility |
|---|---|
| `src/cluster/record.rs` | The six record kinds, `Seal`, `ScanAuditRec` |
| `src/cluster/seal.rs` (new) | Entry digests, seals (make, check), forks (mark, re-pull, prove), the periodic `log_seal` |
| `src/cluster/repl.rs` | Digest on insert, `append_sealing`, the hook that applies credit entries |
| `src/credits/mod.rs` (new) | Units, days, constants, the cached book of this node (`credits::book`) and its background loop |
| `src/credits/entries.rs` (new) | The `credit_entries` table: what the log says about payments, with the shape rules |
| `src/credits/ledger.rs` (new) | The ledger: a pure function from earnings and credit entries to balances |
| `src/credits/earn.rs` (new) | Payable scans, judging them once (`credit_scans`), paying them (pure walk) |
| `src/credits/gates.rs` (new) | Who earns here: rules agreement, audits, blocks, forks |
| `src/credits/audit.rs` (new) | Choosing scans to audit, comparing two results, counting audits |
| `src/credits/price.rs` (new) | Weights, scan capacity, load factor, unit price, surge, what the heartbeat announces |
| `src/credits/share.rs` (new) | The on-demand share of each provider budget and its counters |
| `src/credits/pay.rs` (new) | Offers and receipts around a lookup: the asking and the serving side |
| `src/credits/fleet.rs` (new) | Collecting to one node, drawing from it, sending |
| `src/credits/cli.rs` (new) | `peephole credits …` |
| `src/scan/profiles.rs` (new) | The built-in nmap argument lists, the accepted earlier ones, normalizing a command line |
| `src/scan/mod.rs` | Audits as jobs of the scan workers |
| `src/intel/lookup.rs`, `src/intel/api.rs`, `src/intel/provider.rs` | Paid lookups, the dataset first, provider budgets per day |
| `src/admin/target.rs` (new), `templates/_target.html` (new) | Everything the dataset holds on one address, for the IP page and the lookup result |
| `src/admin/credits.rs` (new), `templates/admin_cluster_credits.html` (new) | Cluster › Credits |
| `src/admin/lookup.rs`, `src/admin/cluster.rs`, `src/admin/overview.rs`, `src/admin/scans.rs`, templates | Prices and charges on Lookup, the member's credits block, issues, overview figures, audit marks |
| `src/store/migrations/0013_credit_entries.sql` … `0018_…` (new, one per task that needs one) | Tables and columns |
| `tests/cluster.rs`, `tests/cluster_limits.rs`, `tests/cli.rs` | Integration tests |
| `docs/cluster.md`, `docs/dataset.md`, `docs/operations.md`, `deploy/config.example.toml`, `CHANGELOG.md` | Docs |

---

## Part A: the log

### Task 1: Record kinds and what the log says about payments

Five of the six record kinds (the sixth, `scan_audit`, comes with audits in Task 8) and the table that holds offers, receipts and transfers as rows, so the ledger never scans the log.

**Files:**
- Create: `src/credits/mod.rs`, `src/credits/entries.rs`, `src/store/migrations/0013_credit_entries.sql`
- Modify: `src/lib.rs` (module list), `src/cluster/record.rs` (kinds), `src/store/data.rs:75-90` (the `match r` in `apply`), `src/cluster/repl.rs` (`apply_record`), `src/store/mod.rs` (`MIGRATIONS`), `tests/cluster.rs`
- Test: unit tests in `src/credits/entries.rs`, `src/credits/mod.rs`, `src/cluster/record.rs`; `tests/cluster.rs::credit_entries_replicate_into_every_nodes_table`

**Interfaces:**
- Produces:
  - `cluster::record::Seal { pub from: u64, pub digest: Vec<u8> }` (`serde_bytes`), `Debug, Clone, PartialEq, Default`
  - `Record::CreditOffer { to: NodeId, parts: Vec<(u32, u32)>, seal: Seal }`, `Record::CreditReceipt { payer: NodeId, offer_seq: u64, charged_mc: u32, answered: Vec<String> }`, `Record::CreditTransfer { to: NodeId, parts: Vec<(u32, u32)>, seal: Seal }`, `Record::LogSeal { seal: Seal }`, `Record::ForkProof { a: Box<WireEntry>, b: Box<WireEntry> }`; a part is `(day, mc)`
  - `credits::Mc = u64`, `credits::CREDIT: Mc = 1000`, `credits::DAY_MS: u64`, `credits::LOT_DAYS: u32 = 7`, `credits::OFFER_TTL_MS: u64 = 900_000`, `credits::day_of(hlc: u64) -> u32`, `credits::show(mc: Mc) -> String`, `credits::parse_amount(s: &str) -> Option<Mc>`
  - `credits::entries::SealState { None, Consistent, Unchecked, Inconsistent }` (`Debug, Clone, Copy, PartialEq`), stored as 0..=3
  - `credits::entries::Kind { Offer { to: NodeId, parts: Vec<(u32, u32)> }, Receipt { payer: NodeId, offer_seq: u64, charged_mc: u32, answered: Vec<String> }, Transfer { to: NodeId, parts: Vec<(u32, u32)> } }`
  - `credits::entries::Entry { pub origin: NodeId, pub seq: u64, pub hlc: u64, pub kind: Kind, pub seal: SealState }` (`Debug, Clone, PartialEq`)
  - `credits::entries::parts_ok(parts: &[(u32, u32)], day: u32) -> bool`
  - `credits::entries::apply(conn: &mut SqliteConnection, e: &WireEntry, r: &Record, seal: SealState) -> Result<bool>` (false: not a payment, or it breaks a shape rule)
  - `credits::entries::since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Entry>>` (ordered by HLC, origin, sequence), `credits::entries::get(pool, origin: &NodeId, seq: u64) -> Result<Option<Entry>>`, `credits::entries::prune(pool, before_hlc: u64) -> Result<u64>`
  - Table `credit_entries (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal)`

- [ ] **Step 1: The migration**

Create `src/store/migrations/0013_credit_entries.sql`:

```sql
-- Lookup credits: the offers, receipts and transfers of the log as rows.
-- `peer` is the receiver of an offer or transfer and the payer of a
-- receipt; `parts` is a JSON array of [day, mc]; `seal` says how the
-- entry's seal checked out here (0 none, 1 consistent, 2 unchecked,
-- 3 inconsistent).
CREATE TABLE credit_entries (
  origin BLOB NOT NULL, seq INTEGER NOT NULL, hlc INTEGER NOT NULL,
  kind TEXT NOT NULL, peer BLOB NOT NULL, parts TEXT NOT NULL DEFAULT '[]',
  offer_seq INTEGER, charged_mc INTEGER, answered TEXT,
  seal INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (origin, seq)
) WITHOUT ROWID;

CREATE INDEX idx_credit_entries_hlc ON credit_entries(hlc)
```

In `src/store/mod.rs`, append to `MIGRATIONS` after the `0012_owner_log_kinds.sql` line:

```rust
    include_str!("migrations/0013_credit_entries.sql"),
```

- [ ] **Step 2: Write the failing tests**

Create `src/credits/mod.rs`:

```rust
//! Lookup credits: earned by completed counter-scans, spent on lookups.
//! Every node computes every balance for itself, from its own copy of the
//! log; see docs/superpowers/specs/2026-10-06-lookup-credits-design.md.
pub mod entries;

/// Millicredits: 1 credit = 1000 mc. Sums are `u64`, amounts on the wire
/// `u32`.
pub type Mc = u64;
pub const CREDIT: Mc = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_amounts() {
        let hlc = |ms: u64| ms << 16;
        assert_eq!(day_of(hlc(0)), 0);
        assert_eq!(day_of(hlc(DAY_MS - 1)), 0);
        assert_eq!(day_of(hlc(DAY_MS)), 1);
        assert_eq!(day_of(hlc(20_000 * DAY_MS + 5) | 7), 20_000);
        assert_eq!(show(0), "0.00");
        assert_eq!(show(250), "0.25");
        assert_eq!(show(1000), "1.00");
        assert_eq!(show(12_345), "12.35", "rounded to cents");
        assert_eq!(show(4), "0.00");
        assert_eq!(parse_amount("1"), Some(1000));
        assert_eq!(parse_amount("0.25"), Some(250));
        assert_eq!(parse_amount(" 12.5 "), Some(12_500));
        assert_eq!(parse_amount("0.001"), Some(1));
        for bad in ["", "-1", "1.2345", "abc", "1e3", "0", "0.0"] {
            assert_eq!(parse_amount(bad), None, "{bad}");
        }
    }
}
```

Create `src/credits/entries.rs` with the imports and tests only:

```rust
//! What the log says about payments. Offers, receipts and transfers are
//! kept as rows when their log entry is applied, so the ledger reads a
//! week of them without walking the log. A row is the entry as it was
//! signed; whether it moves anything is the ledger's business.
use super::day_of;
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{Record, WireEntry};
use anyhow::Result;
use sqlx::{SqliteConnection, SqlitePool};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::cluster::record::Seal;
    use crate::store::Store;

    #[test]
    fn parts_name_one_to_seven_live_days_once_each() {
        let day = 20_000;
        assert!(parts_ok(&[(day, 1)], day));
        assert!(parts_ok(&[(day - 6, 5), (day, 5)], day));
        assert!(!parts_ok(&[], day), "none");
        assert!(!parts_ok(&[(day, 0)], day), "nothing");
        assert!(!parts_ok(&[(day - 7, 5)], day), "gone");
        assert!(!parts_ok(&[(day + 1, 5)], day), "not earned yet");
        assert!(!parts_ok(&[(day, 5), (day, 5)], day), "twice");
        let all: Vec<(u32, u32)> = (0..7).map(|i| (day - i, 1)).collect();
        assert!(parts_ok(&all, day));
        let mut eight = all.clone();
        eight.push((day - 6, 1));
        assert!(!parts_ok(&eight, day));
        // The first days of the epoch do not underflow.
        assert!(parts_ok(&[(0, 1)], 3));
    }

    #[tokio::test]
    async fn payments_are_kept_as_rows_and_broken_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let day = 20_000u32;
        let at = |min: u64| ((day as u64 * crate::credits::DAY_MS + min * 60_000) << 16) | 1;
        let seal = Seal::default();
        let sign = |id: &Identity, seq: u64, hlc: u64, r: &Record| {
            (WireEntry::sign(id, seq, hlc, r).unwrap(), r.clone())
        };
        let offer = sign(
            &a,
            4,
            at(1),
            &Record::CreditOffer {
                to: b.id,
                parts: vec![(day - 1, 300), (day, 200)],
                seal: seal.clone(),
            },
        );
        let receipt = sign(
            &b,
            9,
            at(2),
            &Record::CreditReceipt {
                payer: a.id,
                offer_seq: 4,
                charged_mc: 400,
                answered: vec!["abuseipdb".into()],
            },
        );
        let transfer = sign(
            &a,
            5,
            at(3),
            &Record::CreditTransfer {
                to: b.id,
                parts: vec![(day, 50)],
                seal: seal.clone(),
            },
        );
        let to_self = sign(
            &a,
            6,
            at(4),
            &Record::CreditTransfer {
                to: a.id,
                parts: vec![(day, 50)],
                seal: seal.clone(),
            },
        );
        let stale = sign(
            &a,
            7,
            at(5),
            &Record::CreditOffer {
                to: b.id,
                parts: vec![(day - 7, 50)],
                seal: seal.clone(),
            },
        );
        let other = sign(&a, 8, at(6), &Record::LogSeal { seal });
        let mut conn = store.pool.acquire().await.unwrap();
        for ((e, r), kept, state) in [
            (&offer, true, SealState::Consistent),
            (&receipt, true, SealState::None),
            (&transfer, true, SealState::Unchecked),
            (&to_self, false, SealState::Consistent),
            (&stale, false, SealState::Consistent),
            (&other, false, SealState::Consistent),
        ] {
            assert_eq!(apply(&mut conn, e, r, state).await.unwrap(), kept, "{r:?}");
        }
        // Applied twice (a replay after an unblock): still one row.
        assert!(apply(&mut conn, &offer.0, &offer.1, SealState::Consistent).await.unwrap());
        drop(conn);

        let all = since(&store.pool, 0).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0],
            Entry {
                origin: a.id,
                seq: 4,
                hlc: at(1),
                kind: Kind::Offer {
                    to: b.id,
                    parts: vec![(day - 1, 300), (day, 200)]
                },
                seal: SealState::Consistent,
            }
        );
        assert_eq!(
            all[1].kind,
            Kind::Receipt {
                payer: a.id,
                offer_seq: 4,
                charged_mc: 400,
                answered: vec!["abuseipdb".into()]
            }
        );
        assert_eq!((all[2].seq, all[2].seal), (5, SealState::Unchecked));
        assert_eq!(since(&store.pool, at(3)).await.unwrap().len(), 1);
        assert_eq!(get(&store.pool, &a.id, 4).await.unwrap(), Some(all[0].clone()));
        assert_eq!(get(&store.pool, &a.id, 99).await.unwrap(), None);
        assert_eq!(prune(&store.pool, at(3)).await.unwrap(), 2);
        assert_eq!(since(&store.pool, 0).await.unwrap().len(), 1);
    }
}
```

In `src/lib.rs` add `pub mod credits;` after `pub mod config;`.

In `src/cluster/record.rs`, add to the test module:

```rust
    /// The credit kinds have no uid (no tombstone can erase a payment) and
    /// survive the wire.
    #[test]
    fn credit_records_round_trip_without_a_uid() {
        let id = Identity::generate().unwrap();
        let seal = Seal {
            from: 3,
            digest: vec![7; 32],
        };
        let inner = WireEntry::sign(&id, 1, 1 << 16, &Record::LogSeal { seal: seal.clone() }).unwrap();
        for (r, kind) in [
            (
                Record::CreditOffer {
                    to: id.id,
                    parts: vec![(20_000, 250), (20_001, 4_000_000_000)],
                    seal: seal.clone(),
                },
                "credit_offer",
            ),
            (
                Record::CreditReceipt {
                    payer: id.id,
                    offer_seq: 12,
                    charged_mc: 200,
                    answered: vec!["shodan".into()],
                },
                "credit_receipt",
            ),
            (
                Record::CreditTransfer {
                    to: id.id,
                    parts: vec![(20_000, 1)],
                    seal: seal.clone(),
                },
                "credit_transfer",
            ),
            (Record::LogSeal { seal: seal.clone() }, "log_seal"),
            (
                Record::ForkProof {
                    a: Box::new(inner.clone()),
                    b: Box::new(inner.clone()),
                },
                "fork_proof",
            ),
        ] {
            assert_eq!(r.kind(), kind);
            assert_eq!(r.uid(), None);
            let e = WireEntry::sign(&id, 2, 2 << 16, &r).unwrap();
            assert!(e.verify());
            assert_eq!(e.record(), Some(r));
        }
    }
```

and `use super::super::identity::Identity;` at the top of that test module if `Identity` is not yet in scope there (the file's `use super::identity::{Identity, NodeId};` is in scope through `use super::*;`).

Append to `tests/cluster.rs`:

```rust
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
```

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib credits::`
Expected: does not compile (`cannot find function day_of`, `no variant named CreditOffer`, …).

- [ ] **Step 4: The record kinds**

`src/cluster/record.rs`, above `#[derive(...)] pub enum Record`:

```rust
/// What a sealing entry (an offer, a transfer, a `log_seal`) says about
/// its origin's log before it: see `cluster::seal`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Seal {
    /// Sequence number of the origin's previous sealing entry; the entry's
    /// own number for the first one.
    pub from: u64,
    /// SHA-256 over the digests of the origin's entries from `from` up to
    /// the one before this entry.
    #[serde(with = "serde_bytes")]
    pub digest: Vec<u8>,
}
```

In `enum Record`, after `SkipBatch(SkipBatchRec),`:

```rust
    /// Credits set aside for a lookup at `to`: `(day, mc)` of the origin's
    /// lots (see `credits`). Identified by its origin and sequence number.
    CreditOffer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        seal: Seal,
    },
    /// The server's word on an offer: what it charged, and for which
    /// providers. The address looked up is not in it.
    CreditReceipt {
        payer: NodeId,
        offer_seq: u64,
        charged_mc: u32,
        answered: Vec<String>,
    },
    /// Credits sent to another node.
    CreditTransfer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        seal: Seal,
    },
    /// A seal with nothing else to say (written when many entries have
    /// none yet).
    LogSeal {
        seal: Seal,
    },
    /// Two entries one origin signed for the same position of its log.
    ForkProof {
        a: Box<WireEntry>,
        b: Box<WireEntry>,
    },
```

In `Record::kind`, after the `SkipBatch` arm:

```rust
            Record::CreditOffer { .. } => "credit_offer",
            Record::CreditReceipt { .. } => "credit_receipt",
            Record::CreditTransfer { .. } => "credit_transfer",
            Record::LogSeal { .. } => "log_seal",
            Record::ForkProof { .. } => "fork_proof",
```

`Record::uid` needs no change (the `_ => None` arm covers them).

`src/store/data.rs`, in `apply`'s `match r`, replace the last arm

```rust
        Record::MemberAdd(_) | Record::MemberUpdate(_) | Record::MemberRevoke { .. } => {
            Ok(Effect::Ignored)
        }
```

by

```rust
        // Membership and credits are the cluster layer's (`members::apply`,
        // `credits::entries`, `cluster::seal`): no row of the dataset.
        Record::MemberAdd(_)
        | Record::MemberUpdate(_)
        | Record::MemberRevoke { .. }
        | Record::CreditOffer { .. }
        | Record::CreditReceipt { .. }
        | Record::CreditTransfer { .. }
        | Record::LogSeal { .. }
        | Record::ForkProof { .. } => Ok(Effect::Ignored),
```

- [ ] **Step 5: Units and the table**

In `src/credits/mod.rs`, between the constants and the test module:

```rust
pub const DAY_MS: u64 = 86_400_000;
/// A credit can be used on the day it was earned and the 6 after.
pub const LOT_DAYS: u32 = 7;
/// An offer without a receipt lapses after this long.
pub const OFFER_TTL_MS: u64 = 15 * 60 * 1000;

/// The UTC day an entry belongs to, from its HLC.
pub fn day_of(hlc: u64) -> u32 {
    (crate::cluster::hlc::physical_ms(hlc) / DAY_MS) as u32
}

/// An amount in credits with two decimals ("0.25").
pub fn show(mc: Mc) -> String {
    let cents = (mc + 5) / 10;
    format!("{}.{:02}", cents / 100, cents % 100)
}

/// An amount typed by an operator ("1", "0.25"): more than nothing, at
/// most three decimals.
pub fn parse_amount(s: &str) -> Option<Mc> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty()
        || frac.len() > 3
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: Mc = whole.parse().ok()?;
    let frac: Mc = format!("{frac:0<3}").parse().ok()?;
    let mc = whole.checked_mul(CREDIT)?.checked_add(frac)?;
    (mc > 0).then_some(mc)
}
```

In `src/credits/entries.rs`, between the imports and the test module:

```rust
/// How an entry's seal checked out here (`cluster::seal`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SealState {
    /// The entry carries no seal (a receipt).
    None,
    Consistent,
    /// Part of the range is not held here, or only as an erased stub.
    Unchecked,
    Inconsistent,
}

impl SealState {
    fn to_db(self) -> i64 {
        match self {
            SealState::None => 0,
            SealState::Consistent => 1,
            SealState::Unchecked => 2,
            SealState::Inconsistent => 3,
        }
    }

    fn from_db(v: i64) -> Self {
        match v {
            1 => SealState::Consistent,
            2 => SealState::Unchecked,
            3 => SealState::Inconsistent,
            _ => SealState::None,
        }
    }
}

/// A payment as its origin signed it.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Offer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
    },
    Receipt {
        payer: NodeId,
        offer_seq: u64,
        charged_mc: u32,
        answered: Vec<String>,
    },
    Transfer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub origin: NodeId,
    pub seq: u64,
    pub hlc: u64,
    pub kind: Kind,
    pub seal: SealState,
}

/// Providers one receipt may name, and how long a name may be.
const MAX_ANSWERED: usize = 16;
const MAX_PROVIDER_LEN: usize = 64;

/// Whether `parts` (of an offer or transfer written on `day`) name 1 to 7
/// lots, each once, each of that day or the 6 before, each with more than
/// nothing.
pub fn parts_ok(parts: &[(u32, u32)], day: u32) -> bool {
    let first = day.saturating_sub(super::LOT_DAYS - 1);
    (1..=super::LOT_DAYS as usize).contains(&parts.len())
        && parts
            .iter()
            .all(|(d, mc)| (first..=day).contains(d) && *mc > 0)
        && parts
            .iter()
            .enumerate()
            .all(|(i, (d, _))| parts[..i].iter().all(|(x, _)| x != d))
}

/// Keep `r` (the record of `e`) as a row. False: `r` is no payment, or it
/// breaks a shape rule and the ledger ignores it.
pub async fn apply(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
    seal: SealState,
) -> Result<bool> {
    let day = day_of(e.hlc);
    type Cols<'a> = (
        &'static str,
        &'a NodeId,
        &'a [(u32, u32)],
        Option<u64>,
        Option<u32>,
        Option<&'a [String]>,
    );
    let (kind, peer, parts, offer_seq, charged, answered): Cols = match r {
        Record::CreditOffer { to, parts, .. } if parts_ok(parts, day) => {
            ("offer", to, parts, None, None, None)
        }
        Record::CreditTransfer { to, parts, .. } if *to != e.origin && parts_ok(parts, day) => {
            ("transfer", to, parts, None, None, None)
        }
        Record::CreditReceipt {
            payer,
            offer_seq,
            charged_mc,
            answered,
        } if answered.len() <= MAX_ANSWERED
            && answered.iter().all(|a| a.len() <= MAX_PROVIDER_LEN) =>
        {
            (
                "receipt",
                payer,
                &[],
                Some(*offer_seq),
                Some(*charged_mc),
                Some(answered),
            )
        }
        _ => return Ok(false),
    };
    sqlx::query(
        "INSERT OR IGNORE INTO credit_entries
           (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal)
         VALUES (?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq.min(i64::MAX as u64) as i64)
    .bind(hlc::to_db(e.hlc))
    .bind(kind)
    .bind(&peer.0[..])
    .bind(serde_json::to_string(parts)?)
    .bind(offer_seq.map(|s| s.min(i64::MAX as u64) as i64))
    .bind(charged.map(i64::from))
    .bind(answered.map(serde_json::to_string).transpose()?)
    .bind(seal.to_db())
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

type Row = (
    Vec<u8>,
    i64,
    i64,
    String,
    Vec<u8>,
    String,
    Option<i64>,
    Option<i64>,
    Option<String>,
    i64,
);

const COLUMNS: &str =
    "origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal";

fn from_row(r: Row) -> Result<Entry> {
    let peer = NodeId::from_slice(&r.4)?;
    let kind = match r.3.as_str() {
        "offer" => Kind::Offer {
            to: peer,
            parts: serde_json::from_str(&r.5)?,
        },
        "transfer" => Kind::Transfer {
            to: peer,
            parts: serde_json::from_str(&r.5)?,
        },
        "receipt" => Kind::Receipt {
            payer: peer,
            offer_seq: r.6.unwrap_or(0).max(0) as u64,
            charged_mc: r.7.unwrap_or(0).clamp(0, u32::MAX as i64) as u32,
            answered: serde_json::from_str(r.8.as_deref().unwrap_or("[]"))?,
        },
        other => anyhow::bail!("credit entry of unknown kind `{other}`"),
    };
    Ok(Entry {
        origin: NodeId::from_slice(&r.0)?,
        seq: r.1.max(0) as u64,
        hlc: hlc::from_db(r.2),
        kind,
        seal: SealState::from_db(r.9),
    })
}

/// The payments dated `from_hlc` or later, in the order the ledger walks
/// them: by HLC, then origin, then sequence number.
pub async fn since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Entry>> {
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM credit_entries WHERE hlc >= ? ORDER BY hlc, origin, seq"
    )))
    .bind(hlc::to_db(from_hlc))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(from_row).collect()
}

pub async fn get(pool: &SqlitePool, origin: &NodeId, seq: u64) -> Result<Option<Entry>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM credit_entries WHERE origin = ? AND seq = ?"
    )))
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .fetch_optional(pool)
    .await?;
    row.map(from_row).transpose()
}

/// Drop the rows dated before `before_hlc` (their lots are long gone).
pub async fn prune(pool: &SqlitePool, before_hlc: u64) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM credit_entries WHERE hlc < ?")
        .bind(hlc::to_db(before_hlc))
        .execute(pool)
        .await?
        .rows_affected())
}
```

- [ ] **Step 6: Apply them from the log**

`src/cluster/repl.rs`, in `apply_record`, directly after the `if let Record::JobAdopt(a) = r { … }` block:

```rust
    // Payments become rows; Task 2 replaces the state by the seal's check.
    if matches!(
        r,
        Record::CreditOffer { .. } | Record::CreditReceipt { .. } | Record::CreditTransfer { .. }
    ) {
        let state = match r {
            Record::CreditReceipt { .. } => crate::credits::entries::SealState::None,
            _ => crate::credits::entries::SealState::Unchecked,
        };
        crate::credits::entries::apply(conn, e, r, state).await?;
        return Ok(Settled::default());
    }
```

- [ ] **Step 7: Run the tests**

Run: `cargo test --lib credits:: && cargo test --lib cluster::record && cargo test --lib store:: && cargo test --test cluster credit_entries_replicate`
Expected: PASS (3 credits tests, the record tests, the store tests for the migration, 1 integration test).

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add src/credits src/lib.rs src/cluster/record.rs src/cluster/repl.rs src/store/data.rs src/store/mod.rs src/store/migrations/0013_credit_entries.sql tests/cluster.rs
git commit -m "Credits: record kinds and the table of payments

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Digests and seals

Every log entry gets a digest. An offer, a transfer and a `log_seal` commit to their origin's log before them, and every node that holds that stretch of the log checks the commitment when the entry is applied.

**Files:**
- Create: `src/cluster/seal.rs`, `src/store/migrations/0014_seals.sql`
- Modify: `src/cluster/mod.rs` (module list), `src/cluster/record.rs` (`WireEntry::digest`), `src/cluster/repl.rs` (`insert_log`, `apply_record`, `append_sealing`), `src/store/mod.rs` (`MIGRATIONS`), `tests/cluster.rs`
- Test: unit tests in `src/cluster/seal.rs`; `tests/cluster.rs::sealed_payments_check_out_on_the_other_node`

**Interfaces:**
- Consumes: `Record::{CreditOffer, CreditTransfer, LogSeal}`, `Seal`, `credits::entries::{apply, SealState}` (Task 1); `history::floor_of`; `store::data::rebuild`.
- Produces:
  - `WireEntry::digest(&self) -> Option<[u8; 32]>`
  - `cluster::seal::SEALING: [&str; 3]` = `["credit_offer", "credit_transfer", "log_seal"]`
  - `seal::empty() -> [u8; 32]`
  - `seal::digest_of(conn, origin: &NodeId, seq: u64) -> Result<Option<[u8; 32]>>` (`pub(crate)`)
  - `seal::range_digest(conn, origin: &NodeId, from: u64, to: u64) -> Result<Option<[u8; 32]>>` (`to` exclusive, `pub(crate)`)
  - `seal::head(conn, origin: &NodeId) -> Result<Option<u64>>` (the origin's last sealing entry applied here)
  - `seal::next(conn, origin: &NodeId, seq: u64) -> Result<Seal>` (`pub(crate)`)
  - `seal::check(conn, e: &WireEntry, seal: &Seal) -> Result<SealState>` (`pub(crate)`)
  - `seal::on_apply(node: &Node, conn, e: &WireEntry, r: &Record) -> Result<()>` (`pub(crate)`)
  - `repl::append_sealing(node: &Node, make: impl FnOnce(Seal) -> Record) -> Result<WireEntry>`
  - Column `repl_log.digest`, table `seal_heads (origin, seq)`

- [ ] **Step 1: The migration**

Create `src/store/migrations/0014_seals.sql`:

```sql
-- Seals: a digest per log entry (SHA-256 of what its origin signed; kept
-- when the entry is erased later), and where each origin's last sealing
-- entry sits.
ALTER TABLE repl_log ADD COLUMN digest BLOB;

CREATE TABLE seal_heads (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL) WITHOUT ROWID
```

Append to `MIGRATIONS` in `src/store/mod.rs`:

```rust
    include_str!("migrations/0014_seals.sql"),
```

- [ ] **Step 2: Write the failing tests**

Create `src/cluster/seal.rs` with imports and tests:

```rust
//! Seals: how a node's payments commit to the rest of its log.
//!
//! Every log entry has a digest, the SHA-256 of what its origin signed. A
//! sealing entry (an offer, a transfer, a `log_seal`) names the origin's
//! previous sealing entry and carries the SHA-256 over the digests of the
//! entries from there up to itself. The ranges overlap in one entry, so
//! the seals of a node chain over its whole log. A node that showed two
//! members different entries at one position must, with its next payment,
//! commit to one of them, and every member holding the other then holds
//! two signed statements that contradict each other.
use super::Node;
use super::identity::NodeId;
use super::record::{Record, Seal, WireEntry};
use crate::credits::entries::SealState;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::store::Store;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (store, dir)
    }

    fn filler(id: &Identity, seq: u64) -> WireEntry {
        let r = Record::CreditReceipt {
            payer: id.id,
            offer_seq: seq,
            charged_mc: 0,
            answered: vec![],
        };
        WireEntry::sign(id, seq, (1_000 + seq) << 16, &r).unwrap()
    }

    fn sealing(id: &Identity, seq: u64, seal: Seal) -> WireEntry {
        WireEntry::sign(id, seq, (1_000 + seq) << 16, &Record::LogSeal { seal }).unwrap()
    }

    /// Store an entry as the log holds it. `digest`: as this build stores
    /// it; without, as a build before seals did.
    async fn put(conn: &mut SqliteConnection, e: &WireEntry, digest: bool) {
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, erased_by, applied,
                                   received_at, digest)
             VALUES (?,?,?,?,?,?,?,?,1,datetime('now'),?)",
        )
        .bind(&e.origin.0[..])
        .bind(e.seq as i64)
        .bind(e.hlc as i64)
        .bind(&e.kind)
        .bind(&e.uid)
        .bind(&e.payload)
        .bind(&e.sig)
        .bind(&e.erased_by)
        .bind(digest.then(|| e.digest().unwrap().to_vec()))
        .execute(&mut *conn)
        .await
        .unwrap();
    }

    /// Store `e` and, like `on_apply`, note it as its origin's newest
    /// sealing entry.
    async fn put_sealing(conn: &mut SqliteConnection, e: &WireEntry) {
        put(conn, e, true).await;
        note(conn, &e.origin, e.seq).await.unwrap();
    }

    fn seal_of(e: &WireEntry) -> Seal {
        match e.record() {
            Some(Record::LogSeal { seal }) => seal,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_seal_covers_the_entries_since_the_previous_one() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        for seq in 1..=3 {
            put(&mut conn, &filler(&id, seq), true).await;
        }
        // The first sealing entry names itself and covers nothing.
        let first = next(&mut conn, &id.id, 4).await.unwrap();
        assert_eq!((first.from, first.digest.as_slice()), (4, &empty()[..]));
        let e4 = sealing(&id, 4, first.clone());
        assert_eq!(check(&mut conn, &e4, &first).await.unwrap(), SealState::Consistent);
        put_sealing(&mut conn, &e4).await;
        assert_eq!(head(&mut conn, &id.id).await.unwrap(), Some(4));
        for seq in 5..=6 {
            put(&mut conn, &filler(&id, seq), true).await;
        }
        // The next one starts at the previous sealing entry.
        let second = next(&mut conn, &id.id, 7).await.unwrap();
        assert_eq!(second.from, 4);
        let mut h = Sha256::new();
        for e in [e4.clone(), filler(&id, 5), filler(&id, 6)] {
            h.update(e.digest().unwrap());
        }
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(second.digest, want);
        let e7 = sealing(&id, 7, second.clone());
        assert_eq!(check(&mut conn, &e7, &second).await.unwrap(), SealState::Consistent);

        // Another digest, another start, or "the first" after a first one:
        // the origin signed two histories.
        let wrong = |from: u64, digest: Vec<u8>| Seal { from, digest };
        for bad in [
            wrong(4, vec![9; 32]),
            wrong(5, second.digest.clone()),
            wrong(7, empty().to_vec()),
            wrong(8, second.digest.clone()),
            wrong(4, vec![1, 2, 3]),
        ] {
            let e = sealing(&id, 7, bad.clone());
            assert_eq!(
                check(&mut conn, &e, &bad).await.unwrap(),
                SealState::Inconsistent,
                "{bad:?}"
            );
        }
    }

    /// A node that upgraded later holds entries without stored digests:
    /// the seal is checked from the entries themselves.
    #[tokio::test]
    async fn a_seal_over_entries_without_stored_digests_is_checked_from_the_entries() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        let e1 = sealing(
            &id,
            1,
            Seal {
                from: 1,
                digest: empty().to_vec(),
            },
        );
        put(&mut conn, &e1, false).await;
        note(&mut conn, &id.id, 1).await.unwrap();
        put(&mut conn, &filler(&id, 2), false).await;
        let seal = next(&mut conn, &id.id, 3).await.unwrap();
        let e3 = sealing(&id, 3, seal.clone());
        assert_eq!(check(&mut conn, &e3, &seal).await.unwrap(), SealState::Consistent);
        // Computed once, then kept.
        let kept: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT digest FROM repl_log WHERE origin = ? AND seq = 2")
                .bind(&id.id.0[..])
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(kept, Some(filler(&id, 2).digest().unwrap().to_vec()));
    }

    /// An entry this node only ever saw erased has no digest here: the
    /// seal says nothing. One erased after it arrived keeps its digest.
    #[tokio::test]
    async fn a_stub_in_the_range_leaves_the_seal_unchecked() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        let e1 = sealing(
            &id,
            1,
            Seal {
                from: 1,
                digest: empty().to_vec(),
            },
        );
        put_sealing(&mut conn, &e1).await;
        let e2 = filler(&id, 2);
        // What the origin sealed: its real entry 2.
        let mut h = Sha256::new();
        h.update(e1.digest().unwrap());
        h.update(e2.digest().unwrap());
        let seal = Seal {
            from: 1,
            digest: h.finalize().to_vec(),
        };
        let e3 = sealing(&id, 3, seal.clone());

        // Held as a stub that arrived erased: no payload, no signature.
        let stub = WireEntry {
            payload: None,
            sig: None,
            erased_by: Some("t".into()),
            ..e2.clone()
        };
        put(&mut conn, &stub, false).await;
        assert_eq!(check(&mut conn, &e3, &seal).await.unwrap(), SealState::Unchecked);

        // Erased after it arrived: the digest stayed.
        sqlx::query("UPDATE repl_log SET digest = ? WHERE origin = ? AND seq = 2")
            .bind(e2.digest().unwrap().to_vec())
            .bind(&id.id.0[..])
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(check(&mut conn, &e3, &seal).await.unwrap(), SealState::Consistent);
    }

    /// A node that keeps only a window: a range that starts below what it
    /// holds, and a "first" seal it cannot know to be the first.
    #[tokio::test]
    async fn a_range_below_the_floor_leaves_the_seal_unchecked() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let id = Identity::generate().unwrap();
        crate::cluster::history::raise_floor(&mut conn, &id.id, 10)
            .await
            .unwrap();
        put(&mut conn, &filler(&id, 10), true).await;
        let from_below = Seal {
            from: 7,
            digest: vec![5; 32],
        };
        let e = sealing(&id, 11, from_below.clone());
        assert_eq!(check(&mut conn, &e, &from_below).await.unwrap(), SealState::Unchecked);
        let first = Seal {
            from: 11,
            digest: empty().to_vec(),
        };
        let e = sealing(&id, 11, first.clone());
        assert_eq!(check(&mut conn, &e, &first).await.unwrap(), SealState::Unchecked);
    }
}
```

In `src/cluster/mod.rs` add `pub mod seal;` after `pub mod rpc;`.

Append to `tests/cluster.rs`:

```rust
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
```

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib cluster::seal`
Expected: does not compile (`cannot find function next`, `no method named digest`, …).

- [ ] **Step 4: The digest of an entry**

`src/cluster/record.rs`, in `impl WireEntry` after `verify`:

```rust
    /// SHA-256 of what the origin signed: the entry's digest in its
    /// origin's seals. None for an erased entry (nothing signed is left).
    pub fn digest(&self) -> Option<[u8; 32]> {
        use sha2::Digest;
        let p = self.payload.as_ref()?;
        Some(
            sha2::Sha256::digest(signing_bytes(
                &self.origin,
                self.seq,
                self.hlc,
                &self.kind,
                self.uid.as_deref(),
                p,
            ))
            .into(),
        )
    }
```

`src/cluster/repl.rs`, `insert_log`: the `INSERT` gains the column and its bind.

```rust
    sqlx::query(
        "INSERT INTO repl_log (origin, seq, hlc, kind, uid, payload, sig, erased_by, applied,
                               received_at, accounted, digest)
         VALUES (?,?,?,?,?,?,?,?,?,datetime('now'),?,?)",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq as i64)
    .bind(e.hlc as i64)
    .bind(&e.kind)
    .bind(&e.uid)
    .bind(&e.payload)
    .bind(&e.sig)
    .bind(&e.erased_by)
    .bind(state)
    .bind(accounted)
    // While the payload is here: a row-backed entry gives it up below.
    .bind(e.digest().map(|d| d.to_vec()))
    .execute(&mut *conn)
    .await?;
```

- [ ] **Step 5: Implement `seal.rs`**

Insert between the imports and the test module:

```rust
/// The kinds of entry that carry a seal.
pub const SEALING: [&str; 3] = ["credit_offer", "credit_transfer", "log_seal"];
/// Longest range one seal is checked over here; a longer one stays
/// unchecked (an honest node seals at least every 500 entries).
const MAX_RANGE: u64 = 50_000;

/// The digest of an empty range: what a node's first sealing entry carries.
pub fn empty() -> [u8; 32] {
    Sha256::digest([]).into()
}

/// The seal a record carries, if it is of a sealing kind.
pub fn seal_in(r: &Record) -> Option<&Seal> {
    match r {
        Record::CreditOffer { seal, .. }
        | Record::CreditTransfer { seal, .. }
        | Record::LogSeal { seal } => Some(seal),
        _ => None,
    }
}

/// `origin`'s last sealing entry applied here.
pub async fn head(conn: &mut SqliteConnection, origin: &NodeId) -> Result<Option<u64>> {
    let s: Option<i64> = sqlx::query_scalar("SELECT seq FROM seal_heads WHERE origin = ?")
        .bind(&origin.0[..])
        .fetch_optional(&mut *conn)
        .await?;
    Ok(s.map(|s| s.max(0) as u64))
}

async fn note(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO seal_heads (origin, seq) VALUES (?, ?)
         ON CONFLICT(origin) DO UPDATE SET seq = MAX(seq, excluded.seq)",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The digest of `origin`'s entry `seq` as held here: the stored one, or
/// (for an entry a build before seals stored) computed from the entry and
/// kept. None: not held, or only ever seen erased.
pub(crate) async fn digest_of(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
) -> Result<Option<[u8; 32]>> {
    type Row = (
        i64,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT hlc, kind, uid, payload, sig, digest FROM repl_log WHERE origin = ? AND seq = ?",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((hlc, kind, uid, payload, sig, digest)) = row else {
        return Ok(None);
    };
    if let Some(d) = digest.and_then(|d| <[u8; 32]>::try_from(d).ok()) {
        return Ok(Some(d));
    }
    // Erased before it had a digest: nothing signed is left to hash.
    if sig.is_none() {
        return Ok(None);
    }
    let payload = match (payload, &uid) {
        (Some(p), _) => p,
        // Row-backed: the row reproduces the signed payload.
        (None, Some(uid)) => match crate::store::data::rebuild(conn, &kind, uid).await? {
            Some(r) => super::rpc::cbor::encode(&r)?,
            None => return Ok(None),
        },
        (None, None) => return Ok(None),
    };
    let e = WireEntry {
        origin: *origin,
        seq,
        hlc: super::hlc::from_db(hlc),
        kind,
        uid,
        payload: Some(payload),
        sig,
        erased_by: None,
    };
    // Only what the origin really signed counts.
    if !e.verify() {
        return Ok(None);
    }
    let d = e.digest();
    if let Some(d) = d {
        sqlx::query("UPDATE repl_log SET digest = ? WHERE origin = ? AND seq = ?")
            .bind(&d[..])
            .bind(&origin.0[..])
            .bind(seq as i64)
            .execute(&mut *conn)
            .await?;
    }
    Ok(d)
}

/// SHA-256 over the digests of `origin`'s entries `from .. to` (`to`
/// excluded). None: one of them is not held with a digest, or the range
/// is longer than this node checks.
pub(crate) async fn range_digest(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    from: u64,
    to: u64,
) -> Result<Option<[u8; 32]>> {
    if to < from || to - from > MAX_RANGE {
        return Ok(None);
    }
    let mut h = Sha256::new();
    for seq in from..to {
        match digest_of(conn, origin, seq).await? {
            Some(d) => h.update(d),
            None => return Ok(None),
        }
    }
    Ok(Some(h.finalize().into()))
}

/// The seal for the entry `origin` (this node) is about to write at `seq`.
pub(crate) async fn next(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<Seal> {
    let Some(prev) = head(conn, origin).await?.filter(|p| *p < seq) else {
        return Ok(Seal {
            from: seq,
            digest: empty().to_vec(),
        });
    };
    match range_digest(conn, origin, prev, seq).await? {
        Some(d) => Ok(Seal {
            from: prev,
            digest: d.to_vec(),
        }),
        // A wrong seal would mark this node as having shown two histories.
        None => bail!(
            "this node's log entries {prev}..{seq} cannot be sealed (one of them has no digest)"
        ),
    }
}

async fn kind_of(conn: &mut SqliteConnection, origin: &NodeId, seq: u64) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT kind FROM repl_log WHERE origin = ? AND seq = ?")
            .bind(&origin.0[..])
            .bind(seq.min(i64::MAX as u64) as i64)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// How the seal of `e` (a sealing entry that is being applied; its row is
/// in the log) checks out against what this node holds of its origin.
pub(crate) async fn check(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    seal: &Seal,
) -> Result<SealState> {
    if seal.digest.len() != 32 || seal.from > e.seq {
        return Ok(SealState::Inconsistent);
    }
    let prev = head(conn, &e.origin).await?.filter(|p| *p < e.seq);
    if seal.from == e.seq {
        // "My first sealing entry."
        if prev.is_some() {
            return Ok(SealState::Inconsistent);
        }
        // An earlier one may lie below what this node holds.
        if super::history::floor_of(conn, &e.origin).await? > 1 {
            return Ok(SealState::Unchecked);
        }
        return Ok(if seal.digest == empty() {
            SealState::Consistent
        } else {
            SealState::Inconsistent
        });
    }
    match prev {
        Some(p) if p != seal.from => return Ok(SealState::Inconsistent),
        Some(_) => {}
        // No sealing entry of this origin was applied here: the one it
        // names is below this node's floor, or is no sealing entry.
        None => match kind_of(conn, &e.origin, seal.from).await? {
            None => return Ok(SealState::Unchecked),
            Some(k) if !SEALING.contains(&k.as_str()) => return Ok(SealState::Inconsistent),
            Some(_) => {}
        },
    }
    Ok(
        match range_digest(conn, &e.origin, seal.from, e.seq).await? {
            None => SealState::Unchecked,
            Some(d) if d[..] == seal.digest[..] => SealState::Consistent,
            Some(_) => SealState::Inconsistent,
        },
    )
}

/// A credit entry is being applied: check its seal, remember where the
/// origin's seals stand, and keep a payment as a row.
pub(crate) async fn on_apply(
    _node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<()> {
    let state = match seal_in(r) {
        None => SealState::None,
        Some(seal) => {
            let state = check(conn, e, seal).await?;
            note(conn, &e.origin, e.seq).await?;
            if state == SealState::Inconsistent {
                tracing::warn!(origin = %e.origin.short(), seq = e.seq,
                    "a seal does not match the log held here: its origin showed two histories");
            }
            state
        }
    };
    crate::credits::entries::apply(conn, e, r, state).await?;
    Ok(())
}
```

- [ ] **Step 6: Seal on append, check on apply**

`src/cluster/repl.rs`: replace the block Task 1 added to `apply_record` by

```rust
    if matches!(
        r,
        Record::CreditOffer { .. }
            | Record::CreditReceipt { .. }
            | Record::CreditTransfer { .. }
            | Record::LogSeal { .. }
            | Record::ForkProof { .. }
    ) {
        super::seal::on_apply(node, conn, e, r).await?;
        return Ok(Settled::default());
    }
```

and add below `append`:

```rust
/// Append one sealing record created by this node (an offer, a transfer,
/// a `log_seal`). `make` gets the seal for the position the entry takes,
/// computed in the same transaction that writes it.
pub async fn append_sealing(node: &Node, make: impl FnOnce(Seal) -> Record) -> Result<WireEntry> {
    let guard = node.apply_lock.lock().await;
    let mut tx = node.store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let me = node.id();
    let seq = log_head(&mut tx, &me)
        .await?
        .max(pending_head(&mut tx, &me).await?)
        + 1;
    let seal = super::seal::next(&mut tx, &me, seq).await?;
    let record = make(seal);
    let (e, _) = append_in_tx(node, &mut tx, &record).await?;
    tx.commit().await?;
    drop(guard);
    node.own_head
        .fetch_max(e.seq, std::sync::atomic::Ordering::Relaxed);
    node.notify_changed();
    Ok(e)
}
```

with `Seal` added to the `use super::record::{…}` line of `repl.rs`.

- [ ] **Step 7: Run the tests**

Run: `cargo test --lib cluster::seal && cargo test --lib cluster::repl && cargo test --lib store:: && cargo test --test cluster sealed_payments_check_out && cargo test --test cluster credit_entries_replicate`
Expected: PASS (4 seal tests, the existing repl tests, the store tests, 2 integration tests).

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add src/cluster/seal.rs src/cluster/mod.rs src/cluster/record.rs src/cluster/repl.rs src/store/mod.rs src/store/migrations/0014_seals.sql tests/cluster.rs
git commit -m "Credits: log digests and seals

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Forks: two histories become a proof

**Files:**
- Create: `src/store/migrations/0015_forks.sql`
- Modify: `src/cluster/seal.rs`, `src/cluster/repl.rs` (`signed_entry` becomes `pub(crate)`), `src/store/mod.rs` (`MIGRATIONS`), `src/lib.rs` (start the loop), `tests/cluster.rs`
- Test: unit tests in `src/cluster/seal.rs`; `tests/cluster.rs::a_node_that_shows_two_histories_is_proven_and_marked_everywhere`

**Interfaces:**
- Consumes: Task 2's `seal` items; `repl::{signed_entry, append, append_sealing}`; `sync::{PullReq, Batch}`; `Node::{dial_targets, call, detached}`.
- Produces:
  - `seal::proof_valid(a: &WireEntry, b: &WireEntry) -> bool`
  - `seal::Forked { pub origin: NodeId, pub seq: u64, pub found_at: String, pub proof: Option<(NodeId, u64)> }` (`Debug, Clone, PartialEq`)
  - `seal::forked(pool: &SqlitePool) -> Result<Vec<Forked>>`, `seal::forked_set(pool: &SqlitePool) -> Result<HashSet<NodeId>>`
  - `seal::investigate(node: &Arc<Node>) -> Result<usize>` (fork proofs written)
  - `seal::seal_if_due(node: &Node) -> Result<bool>`
  - `seal::run(node: Arc<Node>, shutdown: tokio::sync::watch::Receiver<bool>)`
  - `seal::MAX_PROOF_BYTES: usize = 1 << 20`, `seal::SEAL_EVERY: u64 = 500`
  - Tables `forked (origin, seq, found_at, proof_origin, proof_seq)`, `fork_suspects (origin, from_seq, to_seq, found_at)`

- [ ] **Step 1: The migration**

Create `src/store/migrations/0015_forks.sql`:

```sql
-- Origins that showed two histories (permanent for that node key), with
-- the fork proof once one is known, and the ranges still to be compared
-- with the peers' copies.
CREATE TABLE forked (
  origin BLOB PRIMARY KEY, seq INTEGER NOT NULL, found_at TEXT NOT NULL,
  proof_origin BLOB, proof_seq INTEGER
) WITHOUT ROWID;

CREATE TABLE fork_suspects (
  origin BLOB NOT NULL, from_seq INTEGER NOT NULL, to_seq INTEGER NOT NULL,
  found_at TEXT NOT NULL,
  PRIMARY KEY (origin, from_seq, to_seq)
) WITHOUT ROWID
```

Append to `MIGRATIONS`:

```rust
    include_str!("migrations/0015_forks.sql"),
```

- [ ] **Step 2: Write the failing tests**

Add to the test module of `src/cluster/seal.rs`:

```rust
    #[test]
    fn a_fork_proof_is_two_signed_entries_for_one_position() {
        let (id, other) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let entry = |id: &Identity, seq: u64, charged: u32| {
            let r = Record::CreditReceipt {
                payer: id.id,
                offer_seq: 1,
                charged_mc: charged,
                answered: vec![],
            };
            WireEntry::sign(id, seq, 5 << 16, &r).unwrap()
        };
        let (a, b) = (entry(&id, 2, 1), entry(&id, 2, 2));
        assert!(proof_valid(&a, &b));
        assert!(proof_valid(&b, &a));
        assert!(!proof_valid(&a, &a.clone()), "the same bytes");
        assert!(!proof_valid(&a, &entry(&other, 2, 2)), "different origins");
        assert!(!proof_valid(&a, &entry(&id, 3, 2)), "different positions");
        let mut forged = b.clone();
        forged.sig = a.sig.clone();
        assert!(!proof_valid(&a, &forged), "a bad signature");
        let mut erased = b.clone();
        erased.payload = None;
        assert!(!proof_valid(&a, &erased), "nothing signed");
        // The same record dated differently is two statements as well.
        let r = a.record().unwrap();
        let later = WireEntry::sign(&id, 2, 6 << 16, &r).unwrap();
        assert!(proof_valid(&a, &later));
    }

    #[tokio::test]
    async fn forked_origins_are_marked_once_and_keep_their_proof() {
        let (store, _dir) = store().await;
        let mut conn = store.pool.acquire().await.unwrap();
        let (o, p) = (Identity::generate().unwrap().id, Identity::generate().unwrap().id);
        assert!(forked_set(&store.pool).await.unwrap().is_empty());
        assert!(mark(&mut conn, &o, 7, None).await.unwrap(), "new");
        assert!(!mark(&mut conn, &o, 9, None).await.unwrap());
        assert!(!mark(&mut conn, &o, 7, Some((&p, 3))).await.unwrap());
        // A later proof does not replace the first.
        mark(&mut conn, &o, 7, Some((&o, 99))).await.unwrap();
        drop(conn);
        let all = forked(&store.pool).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!((all[0].origin, all[0].seq, all[0].proof), (o, 7, Some((p, 3))));
        assert!(forked_set(&store.pool).await.unwrap().contains(&o));
    }
```

Append to `tests/cluster.rs`:

```rust
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
        seal::forked(&nb.store.pool).await.unwrap()[0].proof.is_some()
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
```

`tests/cluster.rs` needs `use peephole::cluster::record::WireEntry;`: the file's first `use` line already imports `Record` and `WireEntry`.

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib cluster::seal`
Expected: does not compile (`cannot find function proof_valid`, `mark`, `forked`).

- [ ] **Step 4: Implement**

`src/cluster/repl.rs`: make `signed_entry` reachable: `pub(crate) async fn signed_entry(`.

`src/cluster/seal.rs`: extend the imports

```rust
use sqlx::{SqliteConnection, SqlitePool};
use std::collections::HashSet;
use std::sync::Arc;
```

and add after `check`:

```rust
/// A fork proof larger than this (both entries together) is not written.
pub const MAX_PROOF_BYTES: usize = 1 << 20;
/// A node seals its log when this many of its entries have no seal yet.
pub const SEAL_EVERY: u64 = 500;
/// A range that could not be compared with any peer's copy is given up
/// after this long; the origin stays marked.
const SUSPECT_TTL: &str = "-7 days";

/// Whether `a` and `b` prove that their origin signed two entries for one
/// position of its log. Needs nothing but the two entries.
pub fn proof_valid(a: &WireEntry, b: &WireEntry) -> bool {
    a.origin == b.origin
        && a.seq == b.seq
        && a.verify()
        && b.verify()
        && a.digest().is_some()
        && a.digest() != b.digest()
}

/// An origin that showed two histories, as this node knows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Forked {
    pub origin: NodeId,
    /// Where it was noticed: the position of the two entries, or of the
    /// seal that did not match.
    pub seq: u64,
    pub found_at: String,
    /// The `fork_proof` entry (its origin and sequence number), once known.
    pub proof: Option<(NodeId, u64)>,
}

/// Mark `origin` as having shown two histories. True: newly marked. The
/// mark is permanent; a proof is added to a mark that had none, and takes
/// its position.
async fn mark(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    seq: u64,
    proof: Option<(&NodeId, u64)>,
) -> Result<bool> {
    let new = sqlx::query(
        "INSERT OR IGNORE INTO forked (origin, seq, found_at, proof_origin, proof_seq)
         VALUES (?, ?, datetime('now'), ?, ?)",
    )
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .bind(proof.map(|p| p.0.0.to_vec()))
    .bind(proof.map(|p| p.1.min(i64::MAX as u64) as i64))
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if let (false, Some((by, at))) = (new, proof) {
        sqlx::query(
            "UPDATE forked SET seq = ?, proof_origin = ?, proof_seq = ?
             WHERE origin = ? AND proof_origin IS NULL",
        )
        .bind(seq.min(i64::MAX as u64) as i64)
        .bind(&by.0[..])
        .bind(at.min(i64::MAX as u64) as i64)
        .bind(&origin.0[..])
        .execute(&mut *conn)
        .await?;
    }
    Ok(new)
}

/// Every origin marked here, oldest mark first.
pub async fn forked(pool: &SqlitePool) -> Result<Vec<Forked>> {
    type Row = (Vec<u8>, i64, String, Option<Vec<u8>>, Option<i64>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT origin, seq, found_at, proof_origin, proof_seq FROM forked ORDER BY found_at, origin",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(origin, seq, found_at, by, at)| {
            Ok(Forked {
                origin: NodeId::from_slice(&origin)?,
                seq: seq.max(0) as u64,
                found_at,
                proof: match (by, at) {
                    (Some(by), Some(at)) => Some((NodeId::from_slice(&by)?, at.max(0) as u64)),
                    _ => None,
                },
            })
        })
        .collect()
}

pub async fn forked_set(pool: &SqlitePool) -> Result<HashSet<NodeId>> {
    Ok(forked(pool).await?.into_iter().map(|f| f.origin).collect())
}

/// Compare the ranges whose seal did not match with the peers' copies of
/// them. Two entries for one position, both signed, are published as a
/// `fork_proof`. Returns how many proofs were written.
pub async fn investigate(node: &Arc<Node>) -> Result<usize> {
    sqlx::query("DELETE FROM fork_suspects WHERE found_at < datetime('now', ?)")
        .bind(SUSPECT_TTL)
        .execute(&node.store.pool)
        .await?;
    // A proof for the origin (ours or anyone's) ends the search.
    sqlx::query(
        "DELETE FROM fork_suspects WHERE origin IN
           (SELECT origin FROM forked WHERE proof_origin IS NOT NULL)",
    )
    .execute(&node.store.pool)
    .await?;
    let suspects: Vec<(Vec<u8>, i64, i64)> =
        sqlx::query_as("SELECT origin, from_seq, to_seq FROM fork_suspects ORDER BY found_at")
            .fetch_all(&node.store.pool)
            .await?;
    let mut written = 0;
    'suspect: for (origin, from, to) in suspects {
        let origin = NodeId::from_slice(&origin)?;
        let (from, to) = (from.max(1) as u64, to.max(1) as u64);
        for (peer, _, addr) in node.dial_targets() {
            if peer == origin {
                continue;
            }
            let req = super::sync::PullReq {
                wants: vec![(origin, from - 1)],
                since_hlc: 0,
                max_entries: (to - from + 1).min(5000) as usize,
                max_bytes: 4 * super::sync::BATCH_BYTES,
            };
            let theirs: super::sync::Batch = match node.call(peer, &addr, "/rpc/v1/pull", &req).await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(peer = %peer.short(), ?e, "fork check: peer not asked");
                    continue;
                }
            };
            for b in theirs.entries {
                if b.origin != origin || b.seq < from || b.seq > to || b.payload.is_none() {
                    continue;
                }
                let held = {
                    let mut conn = node.store.pool.acquire().await?;
                    super::repl::signed_entry(&mut conn, &origin, b.seq).await?
                };
                let Some(a) = held else { continue };
                if !proof_valid(&a, &b) {
                    continue;
                }
                let size = a.payload.as_ref().map_or(0, Vec::len)
                    + b.payload.as_ref().map_or(0, Vec::len);
                if size > MAX_PROOF_BYTES {
                    tracing::warn!(origin = %origin.short(), seq = b.seq,
                        "two histories found, too large to publish as a proof");
                    continue;
                }
                let seq = b.seq;
                super::repl::append(
                    node,
                    &[Record::ForkProof {
                        a: Box::new(a),
                        b: Box::new(b),
                    }],
                )
                .await?;
                tracing::warn!(origin = %origin.short(), seq,
                    "a member showed two histories: proof published");
                written += 1;
                continue 'suspect;
            }
        }
    }
    Ok(written)
}

/// Write a `log_seal` when [`SEAL_EVERY`] of this node's entries have no
/// seal yet, and once a day if its log grew (and at once when it has
/// never sealed: the chain has to start somewhere). True: one was written.
pub async fn seal_if_due(node: &Node) -> Result<bool> {
    if node.detached().is_some() {
        return Ok(false);
    }
    let me = node.id();
    let (own, sealed, at): (i64, Option<i64>, Option<i64>) = sqlx::query_as(
        "SELECT (SELECT COALESCE(MAX(seq), 0) FROM repl_log WHERE origin = ?1),
                (SELECT seq FROM seal_heads WHERE origin = ?1),
                (SELECT l.hlc FROM repl_log l JOIN seal_heads s
                   ON s.origin = l.origin AND s.seq = l.seq WHERE l.origin = ?1)",
    )
    .bind(&me.0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let own = own.max(0) as u64;
    let due = match sealed {
        None => own > 0,
        Some(s) => {
            let unsealed = own.saturating_sub(s.max(0) as u64);
            let age_ms = super::hlc::wall_ms()
                .saturating_sub(super::hlc::physical_ms(super::hlc::from_db(at.unwrap_or(0))));
            unsealed >= SEAL_EVERY || (unsealed > 0 && age_ms >= crate::credits::DAY_MS)
        }
    };
    if !due {
        return Ok(false);
    }
    super::repl::append_sealing(node, |seal| Record::LogSeal { seal }).await?;
    Ok(true)
}

/// How often the loop looks.
const TICK: std::time::Duration = std::time::Duration::from_secs(30);

/// Keep this node's log sealed, and turn seals that did not match into
/// fork proofs.
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    loop {
        if let Err(e) = seal_if_due(&node).await {
            tracing::warn!(?e, "sealing the log failed");
        }
        if let Err(e) = investigate(&node).await {
            tracing::debug!(?e, "fork check failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}
```

Replace `on_apply` by:

```rust
/// A credit entry is being applied: check its seal, remember where the
/// origin's seals stand, keep a payment as a row, and take a fork proof.
pub(crate) async fn on_apply(
    _node: &Node,
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
) -> Result<()> {
    if let Record::ForkProof { a, b } = r {
        if proof_valid(a, b) && mark(conn, &a.origin, a.seq, Some((&e.origin, e.seq))).await? {
            tracing::warn!(origin = %a.origin.short(), seq = a.seq, by = %e.origin.short(),
                "a member showed two histories (proof received): its credits are void here");
        }
        return Ok(());
    }
    let state = match seal_in(r) {
        None => SealState::None,
        Some(seal) => {
            let state = check(conn, e, seal).await?;
            note(conn, &e.origin, e.seq).await?;
            if state == SealState::Inconsistent {
                // Its origin signed this seal and the entries held here.
                if mark(conn, &e.origin, e.seq, None).await? {
                    tracing::warn!(origin = %e.origin.short(), seq = e.seq,
                        "a member showed two histories (its seal does not match the log held \
                         here): its credits are void here");
                }
                sqlx::query(
                    "INSERT OR IGNORE INTO fork_suspects (origin, from_seq, to_seq, found_at)
                     VALUES (?, ?, ?, datetime('now'))",
                )
                .bind(&e.origin.0[..])
                .bind(seal.from.min(e.seq).min(i64::MAX as u64) as i64)
                .bind(e.seq.min(i64::MAX as u64) as i64)
                .execute(&mut *conn)
                .await?;
            }
            state
        }
    };
    crate::credits::entries::apply(conn, e, r, state).await?;
    Ok(())
}
```

`src/lib.rs`, below the `tokio::spawn(cluster::owner::fleet::run(…));` statement:

```rust
        tokio::spawn(cluster::seal::run(node.clone(), shutdown_rx.clone()));
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib cluster::seal && cargo test --lib store:: && cargo test --test cluster a_node_that_shows_two_histories && cargo test --test cluster sealed_payments_check_out`
Expected: PASS (6 seal tests, the store tests, 2 integration tests). In `sealed_payments_check_out_on_the_other_node` node a is now marked on both nodes for its made-up seal; the test's assertions do not change.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/cluster/seal.rs src/cluster/repl.rs src/store/mod.rs src/store/migrations/0015_forks.sql src/lib.rs tests/cluster.rs
git commit -m "Credits: a node that shows two histories is proven and marked

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Part B: earning and the ledger

### Task 4: The built-in scan arguments, and telling them from others

A scan earns its scanner share only when it ran with the built-in arguments of its level. The lists move out of `Config` into one place that also knows how to recognize them in the command line nmap writes into its XML.

Plan-time check (spec §3): the stored XML is nmap's output unchanged (`nmap_xml::parse_nmap_xml` keeps `xml.to_vec()`, `Recorder::record_scan_result` compresses exactly that). `scan::nmap_argv` adds, outside the level's list: `--host-timeout <t>s`, `--script-timeout <t>s` (lists with scripts), `--min-rate <n>` (level 4), `-6` (IPv6), `-oX -` and the target. Those and the level-4 UDP block are what normalizing removes; nothing else.

**Files:**
- Create: `src/scan/profiles.rs`
- Modify: `src/scan/mod.rs` (module list), `src/config.rs` (`default_level_argv`, the two constants)
- Test: unit tests in `src/scan/profiles.rs`; existing `cargo test --lib config::`

**Interfaces:**
- Produces:
  - `scan::profiles::builtin(level: u8, udp: bool) -> Option<Vec<String>>` (what `Config::default_level_argv` returned without `scan.level_argv`)
  - `scan::profiles::ACCEPTED: &[(u8, &[&str])]` (earlier built-in lists, normalized; empty in this release)
  - `scan::profiles::normalize(tokens: &[String], level: u8) -> Vec<String>`
  - `scan::profiles::args_ok(command_line: &str, level: u8) -> bool`
  - `scan::profiles::xml_args(xml: &[u8]) -> Option<String>` (the `args` attribute of `<nmaprun>`)

- [ ] **Step 1: Write the failing tests**

Create `src/scan/profiles.rs`:

```rust
//! The nmap arguments of each scan level as this build runs them, and how
//! to recognize them in a finished scan. A scan earns its scanner share
//! (see `credits::earn`) only when the command line in its XML is one of
//! the built-in lists, apart from what legitimately differs per node and
//! target.
use quick_xml::Reader;
use quick_xml::events::Event;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg(scan: &str) -> Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n[scan]\n{scan}"
        ))
        .unwrap()
    }

    /// What nmap writes into `args`: its argv joined by spaces.
    fn command_line(cfg: &Config, level: u8, target: &str) -> String {
        let argv = crate::scan::nmap_argv(level, &target.parse().unwrap(), cfg, 900).unwrap();
        format!("/usr/bin/nmap {}", argv.join(" "))
    }

    #[test]
    fn every_built_in_level_is_recognized_with_every_tunable_set() {
        let plain = cfg("");
        let tuned = cfg("min_rate = 1000\nlevel4_udp = true");
        for level in 1..=4u8 {
            for (c, target) in [
                (&plain, "203.0.113.7"),
                (&tuned, "203.0.113.7"),
                (&plain, "2001:db8::7"),
                (&tuned, "2001:db8::7"),
            ] {
                let line = command_line(c, level, target);
                assert!(args_ok(&line, level), "level {level}: {line}");
            }
        }
        // A list of one level is not that of another.
        let l1 = command_line(&plain, 1, "203.0.113.7");
        assert!(!args_ok(&l1, 2) && !args_ok(&l1, 4));
        assert!(!args_ok(&command_line(&plain, 3, "203.0.113.7"), 2));
        assert!(!args_ok("", 1) && !args_ok("nmap", 1));
        assert!(!args_ok(&l1, 0) && !args_ok(&l1, 9));
    }

    #[test]
    fn an_operators_own_list_is_not_a_built_in_one() {
        let custom = cfg("[scan.level_argv]\n2 = [\"-Pn\", \"-sS\", \"-T4\", \"--top-ports\", \"10\"]");
        assert!(!args_ok(&command_line(&custom, 2, "203.0.113.7"), 2));
        // One argument more or less, or another value, is another list.
        let line = command_line(&cfg(""), 2, "203.0.113.7");
        assert!(!args_ok(&line.replace("-T3", "-T5"), 2));
        assert!(!args_ok(&line.replace(" -O", ""), 2));
        assert!(!args_ok(&format!("{line} --script vuln"), 2));
        // What may differ: timeouts, the rate floor, the target.
        let ip = "203.0.113.7".parse().unwrap();
        let short = crate::scan::nmap_argv(2, &ip, &cfg(""), 60).unwrap().join(" ");
        assert!(!line.ends_with(&short), "another timeout");
        assert!(args_ok(&format!("nmap {short}"), 2));
        // nmap versions that quote an argument with spaces still match.
        let l3 = command_line(&cfg(""), 3, "203.0.113.7");
        let quoted = l3.replace(SCRIPTS, &format!("\"{SCRIPTS}\""));
        assert_ne!(quoted, l3);
        assert!(args_ok(&quoted, 3));
    }

    #[test]
    fn an_earlier_built_in_list_stays_accepted() {
        let old: &[&str] = &["-Pn", "-sS", "--top-ports", "50"];
        let line = "nmap -Pn -sS --top-ports 50 --host-timeout 60s -oX - 203.0.113.7";
        assert!(!args_ok(line, 1));
        assert!(args_ok_among(line, 1, &[(1, old)]));
        assert!(!args_ok_among(line, 2, &[(1, old)]), "accepted for its level only");
    }

    #[test]
    fn the_command_line_is_read_from_the_xml() {
        let xml = br#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn --script &quot;a or b&quot; -oX - 203.0.113.7" start="1">
<host/></nmaprun>"#;
        assert_eq!(
            xml_args(xml).as_deref(),
            Some("nmap -Pn --script \"a or b\" -oX - 203.0.113.7")
        );
        assert_eq!(xml_args(b"<nmaprun start=\"1\"/>"), None);
        assert_eq!(xml_args(b"not xml"), None);
        let fixture = std::fs::read("tests/fixtures/nmap-basic.xml").unwrap();
        assert_eq!(
            xml_args(&fixture).as_deref(),
            Some("nmap -sS -sV -oX - 198.51.100.23")
        );
    }
}
```

Add `pub mod profiles;` after `pub mod pace;` in `src/scan/mod.rs`.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib scan::profiles`
Expected: does not compile (`cannot find function args_ok`, `SCRIPTS`, …).

- [ ] **Step 3: Implement**

Insert between the imports and the test module of `src/scan/profiles.rs`:

```rust
/// One NSE argument; it contains spaces, so lists are built element by
/// element. `discovery` and `safe` also hold scripts that would leak the
/// target to third parties (`external`: whois, ASN and geolocation
/// lookups), broadcast on the scanner's own network (`broadcast`
/// prerules), or flood (`dos`); those categories are excluded.
pub const SCRIPTS: &str = "(discovery or safe) and not (intrusive or broadcast or external or dos)";
/// Level 2 names its scripts: the source's own identifiers (SSH host keys
/// and algorithm lists, the TLS certificate), each one handshake with a
/// port nmap already found open, all in `safe`.
pub const IDENTITY_SCRIPTS: &str = "ssh-hostkey,ssh2-enum-algos,ssl-cert";

/// The built-in arguments of a level, without the target. `udp`: level 4
/// also scans the top UDP ports (`scan.level4_udp`). None for a level
/// outside 1..=4.
pub fn builtin(level: u8, udp: bool) -> Option<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<String>>();
    Some(match level {
        1 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "--version-light",
            "-T3",
            "--top-ports",
            "100",
        ]),
        2 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--script",
            IDENTITY_SCRIPTS,
        ]),
        3 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            SCRIPTS,
        ]),
        4 => {
            let mut v = s(&["-Pn", "-sS"]);
            if udp {
                v.push("-sU".into());
                v.push("-p".into());
                v.push(format!("T:1-65535,U:{}", crate::config::UDP_TOP50));
            } else {
                v.push("-p-".into());
            }
            v.extend(s(&[
                "-sV",
                "-O",
                "-T3",
                "--max-retries",
                "1",
                "--traceroute",
                "--script",
                SCRIPTS,
            ]));
            v
        }
        _ => return None,
    })
}

/// Built-in lists of earlier releases that still earn, normalized, with
/// their level. A release that changes a list appends the old one here
/// and removes it two releases later, so a rolling upgrade costs nobody
/// their earnings.
pub const ACCEPTED: &[(u8, &[&str])] = &[];

/// A command line as words: split at whitespace, quotes dropped (nmap
/// versions differ in whether they quote an argument with spaces; the
/// words are the same either way).
fn words(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|w| w.replace(['"', '\''], ""))
        .filter(|w| !w.is_empty())
        .collect()
}

/// `tokens` (an nmap command line as words, without the program) with
/// everything removed that legitimately differs per node or target: the
/// target, `-oX -`, `-6`, the two timeouts, the rate floor and, at level
/// 4, the choice between all TCP ports and TCP plus the top UDP ports.
pub fn normalize(tokens: &[String], level: u8) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        let next = tokens.get(i + 1).map(String::as_str);
        match t {
            "-6" => i += 1,
            "-oX" | "--host-timeout" | "--script-timeout" | "--min-rate" => i += 2,
            "-sU" | "-p-" if level == 4 => i += 1,
            "-p" if level == 4 && next.is_some_and(|n| n.starts_with("T:1-65535,U:")) => i += 2,
            _ => {
                out.push(tokens[i].clone());
                i += 1;
            }
        }
    }
    // The target is the last argument.
    if out
        .last()
        .is_some_and(|t| t.parse::<std::net::IpAddr>().is_ok())
    {
        out.pop();
    }
    out
}

fn args_ok_among(command_line: &str, level: u8, accepted: &[(u8, &[&str])]) -> bool {
    let all = words(command_line);
    // The first word is the program as it was called.
    let Some((_, args)) = all.split_first() else {
        return false;
    };
    let got = normalize(args, level);
    if got.is_empty() {
        return false;
    }
    let built_in = builtin(level, false).map(|b| normalize(&words(&b.join(" ")), level));
    built_in.is_some_and(|b| b == got)
        || accepted
            .iter()
            .any(|(l, list)| *l == level && list.iter().copied().eq(got.iter().map(String::as_str)))
}

/// Whether `command_line` (the `args` nmap wrote into its XML) is a
/// built-in argument list of `level`: this build's, or an accepted
/// earlier one.
pub fn args_ok(command_line: &str, level: u8) -> bool {
    args_ok_among(command_line, level, ACCEPTED)
}

/// The command line nmap recorded in its XML output (`<nmaprun args=…>`).
pub fn xml_args(xml: &[u8]) -> Option<String> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) | Event::Empty(e) => {
                if e.name().as_ref() != b"nmaprun" {
                    return None;
                }
                return e.attributes().flatten().find_map(|a| {
                    (a.key.as_ref() == b"args").then(|| {
                        #[allow(deprecated)]
                        a.unescape_value()
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned())
                    })
                });
            }
            Event::Eof => return None,
            _ => {}
        }
        buf.clear();
    }
}
```

`src/config.rs`: in `default_level_argv`, replace everything from the comment `// One NSE argument; it contains spaces, …` through the final `Some(argv)` by

```rust
        crate::scan::profiles::builtin(level, self.scan.level4_udp)
```

(the range check and the `scan.level_argv` lookup above it stay). Make the constant public where it is not: `pub const UDP_TOP50`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib scan::profiles && cargo test --lib config:: && cargo test --lib scan::tests`
Expected: PASS (4 new tests; the config and scan tests show that every level's arguments are what they were).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/scan/profiles.rs src/scan/mod.rs src/config.rs
git commit -m "Scan: the built-in argument lists in one place, recognizable in a result

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: The ledger

A pure function: from what scans earned and what the log says about payments to every balance. No database, no clock but the one passed in.

**Files:**
- Create: `src/credits/ledger.rs`
- Modify: `src/credits/mod.rs` (`pub mod ledger;`)
- Test: unit tests in `src/credits/ledger.rs`

**Interfaces:**
- Consumes: `credits::entries::{Entry, Kind, parts_ok}`, `credits::{Mc, DAY_MS, LOT_DAYS, OFFER_TTL_MS, day_of}` (Task 1).
- Produces (in `credits::ledger`):
  - `Earned { pub node: NodeId, pub hlc: u64, pub mc: Mc }` (`Debug, Clone, PartialEq`)
  - `OfferState { Open, Charged { charged: Mc, to_server: Mc, destroyed: Mc }, Lapsed }`
  - `Offer { pub payer: NodeId, pub seq: u64, pub hlc: u64, pub to: NodeId, pub offered: Mc, pub covered: Mc, pub held: Vec<(u32, Mc)>, pub state: OfferState, pub answered: Vec<String> }`
  - `Moved { pub hlc: u64, pub from: NodeId, pub to: NodeId, pub named: Mc, pub moved: Mc }`
  - `Tally { pub earned: Mc, pub spent: Mc, pub served: Mc, pub destroyed: Mc, pub sent: Mc, pub received: Mc }` (`Default`)
  - `Ledger { pub lots: BTreeMap<(NodeId, u32), Mc>, pub offers: Vec<Offer>, pub transfers: Vec<Moved>, pub tallies: HashMap<NodeId, Tally>, pub today: u32 }` with `balance(&self, node: &NodeId) -> Mc`, `by_day(&self, node: &NodeId) -> Vec<(u32, Mc)>`, `held(&self, node: &NodeId) -> Mc`, `spendable_parts(&self, node: &NodeId, mc: Mc) -> Option<Vec<(u32, u32)>>`, `offer(&self, payer: &NodeId, seq: u64) -> Option<&Offer>`, `circulating(&self) -> Mc`, `expiring_today(&self, node: &NodeId) -> Mc`, `tally(&self, node: &NodeId) -> Tally`
  - `run(earned: &[Earned], entries: &[Entry], left_out: &HashSet<NodeId>, now_ms: u64) -> Ledger`

- [ ] **Step 1: Write the failing tests**

Create `src/credits/ledger.rs`:

```rust
//! The ledger: every balance, from what scans earned and what the log
//! says about payments. A pure function of its input, so every node that
//! holds the same entries and judges the same scans arrives at the same
//! balances, in whatever order the entries reached it.
//!
//! A credit belongs to a lot: a node and the UTC day it was earned. It
//! keeps its lot when it changes hands and is gone 7 days after the scan
//! that created it.
use super::entries::{Entry, Kind, parts_ok};
use super::{DAY_MS, LOT_DAYS, Mc, OFFER_TTL_MS, day_of};
use crate::cluster::hlc::physical_ms;
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, HashMap, HashSet};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::entries::SealState;

    const DAY: u32 = 20_000;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    /// An HLC `min` minutes into day `day`.
    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }

    fn earn(node: u8, day: u32, min: u64, mc: Mc) -> Earned {
        Earned {
            node: id(node),
            hlc: at(day, min),
            mc,
        }
    }

    fn entry(origin: u8, seq: u64, hlc: u64, kind: Kind) -> Entry {
        Entry {
            origin: id(origin),
            seq,
            hlc,
            kind,
            seal: SealState::Consistent,
        }
    }

    fn offer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Offer {
                to: id(to),
                parts: parts.to_vec(),
            },
        )
    }

    fn receipt(origin: u8, seq: u64, hlc: u64, payer: u8, offer_seq: u64, charged: u32) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Receipt {
                payer: id(payer),
                offer_seq,
                charged_mc: charged,
                answered: vec!["abuseipdb".into()],
            },
        )
    }

    fn transfer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Transfer {
                to: id(to),
                parts: parts.to_vec(),
            },
        )
    }

    fn now(day: u32, min: u64) -> u64 {
        day as u64 * DAY_MS + min * 60_000
    }

    fn ledger(earned: &[Earned], entries: &[Entry], now_ms: u64) -> Ledger {
        run(earned, entries, &HashSet::new(), now_ms)
    }

    #[test]
    fn earn_then_spend() {
        let l = ledger(
            &[earn(1, DAY, 0, 1000)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 400)]),
                receipt(2, 9, at(DAY, 11), 1, 5, 400),
            ],
            now(DAY, 60),
        );
        assert_eq!(l.balance(&id(1)), 600);
        assert_eq!(l.balance(&id(2)), 200, "half goes to the server");
        assert_eq!(l.held(&id(1)), 0);
        let o = l.offer(&id(1), 5).unwrap();
        assert_eq!(
            o.state,
            OfferState::Charged {
                charged: 400,
                to_server: 200,
                destroyed: 200
            }
        );
        assert_eq!(o.answered, vec!["abuseipdb".to_string()]);
        let (t1, t2) = (l.tally(&id(1)), l.tally(&id(2)));
        assert_eq!((t1.earned, t1.spent, t1.destroyed), (1000, 400, 200));
        assert_eq!(t2.served, 200);
        assert_eq!(l.circulating(), 800);
        // The server's half is of the same day's lot as what was paid.
        assert_eq!(l.by_day(&id(2)), vec![(DAY, 200)]);
    }

    #[test]
    fn an_offer_larger_than_the_lot_holds_what_is_there() {
        let l = ledger(
            &[earn(1, DAY, 0, 300)],
            &[offer(1, 5, at(DAY, 10), 2, &[(DAY, 1000)])],
            now(DAY, 12),
        );
        let o = l.offer(&id(1), 5).unwrap();
        assert_eq!((o.offered, o.covered), (1000, 300));
        assert_eq!((l.balance(&id(1)), l.held(&id(1))), (0, 300));
        // A receipt takes at most what was held.
        let l = ledger(
            &[earn(1, DAY, 0, 300)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 1000)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 1000),
            ],
            now(DAY, 12),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (0, 150));
        // An offer on nothing holds nothing, and nothing goes below zero.
        let l = ledger(&[], &[offer(1, 5, at(DAY, 10), 2, &[(DAY, 50)])], now(DAY, 12));
        assert_eq!(l.offer(&id(1), 5).unwrap().covered, 0);
        assert_eq!(l.balance(&id(1)), 0);
    }

    #[test]
    fn a_receipt_lower_than_the_offer_returns_the_rest() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 100), earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 100), (DAY, 300)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 150),
            ],
            now(DAY, 12),
        );
        // Oldest lot first: all 100 of yesterday, 50 of today.
        assert_eq!(l.by_day(&id(1)), vec![(DAY, 450)]);
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 50), (DAY, 25)]);
        // A receipt of nothing frees everything at once.
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 0),
            ],
            now(DAY, 12),
        );
        assert_eq!((l.balance(&id(1)), l.held(&id(1)), l.balance(&id(2))), (500, 0, 0));
    }

    #[test]
    fn an_offer_lapses_after_fifteen_minutes_and_a_late_receipt_is_ignored() {
        let es = [
            offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
            receipt(2, 1, at(DAY, 26), 1, 5, 300),
        ];
        let earned = [earn(1, DAY, 0, 500)];
        // Still open a minute before the limit.
        let open = ledger(&earned, &es[..1], now(DAY, 24));
        assert_eq!((open.balance(&id(1)), open.held(&id(1))), (200, 300));
        assert_eq!(open.offer(&id(1), 5).unwrap().state, OfferState::Open);
        let late = ledger(&earned, &es, now(DAY, 30));
        assert_eq!((late.balance(&id(1)), late.balance(&id(2))), (500, 0));
        assert_eq!(late.offer(&id(1), 5).unwrap().state, OfferState::Lapsed);
        // Exactly at the limit it still counts.
        let on_time = ledger(
            &earned,
            &[es[0].clone(), receipt(2, 1, at(DAY, 25), 1, 5, 300)],
            now(DAY, 30),
        );
        assert_eq!(on_time.balance(&id(2)), 150);
        // A receipt dated before its offer does not.
        let early = ledger(
            &earned,
            &[es[0].clone(), receipt(2, 1, at(DAY, 9), 1, 5, 300)],
            now(DAY, 12),
        );
        assert_eq!(early.balance(&id(2)), 0);
        // What lapsed can be offered again.
        let again = ledger(
            &earned,
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 500)]),
                offer(1, 6, at(DAY, 40), 3, &[(DAY, 500)]),
            ],
            now(DAY, 41),
        );
        assert_eq!(again.offer(&id(1), 6).unwrap().covered, 500);
    }

    #[test]
    fn only_the_first_receipt_from_the_node_offered_to_counts() {
        let earned = [earn(1, DAY, 0, 500)];
        let o = offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]);
        let l = ledger(
            &earned,
            &[
                o.clone(),
                receipt(3, 1, at(DAY, 11), 1, 5, 300),
                receipt(2, 1, at(DAY, 12), 1, 5, 100),
                receipt(2, 2, at(DAY, 13), 1, 5, 300),
            ],
            now(DAY, 14),
        );
        assert_eq!(l.balance(&id(3)), 0, "not the node the offer was made to");
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (400, 50));
        // A receipt that names no offer does nothing.
        let l = ledger(&earned, &[receipt(2, 1, at(DAY, 12), 1, 99, 100)], now(DAY, 14));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (500, 0));
    }

    #[test]
    fn an_offer_to_oneself_costs_half() {
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 1, &[(DAY, 200)]),
                receipt(1, 6, at(DAY, 11), 1, 5, 200),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(1)), 400);
    }

    #[test]
    fn a_transfer_moves_what_is_there_and_keeps_the_day() {
        let l = ledger(
            &[earn(1, DAY - 2, 0, 100), earn(1, DAY, 0, 50)],
            &[transfer(1, 5, at(DAY, 10), 2, &[(DAY - 2, 500), (DAY, 20)])],
            now(DAY, 12),
        );
        assert_eq!(l.by_day(&id(1)), vec![(DAY, 30)]);
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 2, 100), (DAY, 20)]);
        assert_eq!(
            l.transfers,
            vec![Moved {
                hlc: at(DAY, 10),
                from: id(1),
                to: id(2),
                named: 520,
                moved: 120
            }]
        );
        let (t1, t2) = (l.tally(&id(1)), l.tally(&id(2)));
        assert_eq!((t1.sent, t2.received), (120, 120));
        // What is held for an offer cannot be sent meanwhile.
        let l = ledger(
            &[earn(1, DAY, 0, 100)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY, 80)]),
                transfer(1, 6, at(DAY, 11), 3, &[(DAY, 100)]),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(3)), 20);
    }

    #[test]
    fn a_credit_is_gone_seven_days_after_its_scan_however_often_it_moved() {
        let earned = [earn(1, DAY, 0, 1000)];
        let moved = [transfer(1, 5, at(DAY + 3, 0), 2, &[(DAY, 1000)])];
        let l = ledger(&earned, &moved, now(DAY + 6, 0));
        assert_eq!(l.balance(&id(2)), 1000);
        assert_eq!(l.expiring_today(&id(2)), 1000);
        assert_eq!(l.expiring_today(&id(1)), 0);
        let l = ledger(&earned, &moved, now(DAY + 7, 0));
        assert_eq!(l.balance(&id(2)), 0);
        assert_eq!(l.circulating(), 0);
        // An entry that names a lot on its eighth day is ignored whole.
        let stale = [transfer(1, 5, at(DAY + 7, 0), 2, &[(DAY, 500), (DAY + 7, 1)])];
        let l = ledger(&[earn(1, DAY, 0, 1000), earn(1, DAY + 7, 0, 10)], &stale, now(DAY + 7, 1));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (10, 0));
        // So is a transfer to oneself.
        let own = [transfer(1, 5, at(DAY, 5), 1, &[(DAY, 500)])];
        assert!(ledger(&earned, &own, now(DAY, 6)).transfers.is_empty());
    }

    #[test]
    fn halves_round_down_and_the_remainder_is_destroyed() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 3), earn(1, DAY, 0, 10)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 3), (DAY, 4)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 7),
            ],
            now(DAY, 12),
        );
        // 3 → 1 to the server, 2 destroyed; 4 → 2 and 2.
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 1), (DAY, 2)]);
        assert_eq!(
            l.offer(&id(1), 5).unwrap().state,
            OfferState::Charged {
                charged: 7,
                to_server: 3,
                destroyed: 4
            }
        );
    }

    #[test]
    fn entries_and_earnings_of_a_node_left_out_do_not_count() {
        let earned = [earn(1, DAY, 0, 1000), earn(2, DAY, 0, 1000)];
        let entries = [
            transfer(2, 1, at(DAY, 5), 3, &[(DAY, 400)]),
            offer(1, 5, at(DAY, 10), 2, &[(DAY, 300)]),
            receipt(2, 2, at(DAY, 11), 1, 5, 300),
        ];
        let out: HashSet<NodeId> = [id(2)].into();
        let l = run(&earned, &entries, &out, now(DAY, 30));
        assert_eq!(l.balance(&id(2)), 0, "blocked or forked: nothing");
        assert_eq!(l.balance(&id(3)), 0, "its transfers move nothing");
        // Its receipt does not count either: the offer lapses.
        assert_eq!(l.balance(&id(1)), 1000);
        assert_eq!(l.offer(&id(1), 5).unwrap().state, OfferState::Lapsed);
        // Credits sent to it are lost to everyone.
        let sent = [transfer(1, 6, at(DAY, 12), 2, &[(DAY, 100)])];
        let l = run(&earned, &sent, &out, now(DAY, 30));
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (900, 0));
    }

    /// Review focus: entries reach nodes in different orders.
    #[test]
    fn the_same_entries_in_any_arrival_order_give_the_same_balances() {
        let earned = vec![
            earn(1, DAY - 1, 30, 1000),
            earn(2, DAY, 1, 250),
            earn(1, DAY, 2, 2000),
            earn(3, DAY, 2, 500),
        ];
        let entries = vec![
            offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 800), (DAY, 300)]),
            transfer(3, 1, at(DAY, 10), 1, &[(DAY, 500)]),
            receipt(2, 4, at(DAY, 11), 1, 5, 900),
            transfer(1, 6, at(DAY, 12), 3, &[(DAY - 1, 1000), (DAY, 100)]),
            offer(2, 5, at(DAY, 13), 3, &[(DAY, 600), (DAY - 1, 600)]),
            receipt(3, 2, at(DAY, 40), 2, 5, 600),
            transfer(2, 6, at(DAY, 41), 1, &[(DAY - 1, 5000), (DAY, 5000)]),
        ];
        let want = ledger(&earned, &entries, now(DAY, 50));
        let mut e2 = entries.clone();
        let mut g2 = earned.clone();
        for round in 0..6 {
            e2.rotate_left(round % entries.len() + 1);
            if round % 2 == 0 {
                e2.reverse();
                g2.reverse();
            }
            let got = ledger(&g2, &e2, now(DAY, 50));
            assert_eq!(got.lots, want.lots, "round {round}");
            assert_eq!(got.offers, want.offers, "round {round}");
        }
        // And it is what the entries say: nothing appears from nowhere.
        let total: Mc = earned.iter().map(|e| e.mc).sum();
        let destroyed: Mc = want.tallies.values().map(|t| t.destroyed).sum();
        let all: Mc = want.lots.values().sum::<Mc>() + want.offers.iter().map(Offer::held_now).sum::<Mc>();
        assert_eq!(all + destroyed, total);
    }

    #[test]
    fn what_can_be_spent_is_drawn_from_the_oldest_lots() {
        let l = ledger(
            &[earn(1, DAY - 6, 0, 100), earn(1, DAY - 1, 0, 50), earn(1, DAY, 0, 500)],
            &[],
            now(DAY, 10),
        );
        assert_eq!(
            l.spendable_parts(&id(1), 180),
            Some(vec![(DAY - 6, 100), (DAY - 1, 50), (DAY, 30)])
        );
        assert_eq!(l.spendable_parts(&id(1), 650), Some(vec![(DAY - 6, 100), (DAY - 1, 50), (DAY, 500)]));
        assert_eq!(l.spendable_parts(&id(1), 651), None);
        assert_eq!(l.spendable_parts(&id(1), 0), None);
        assert_eq!(l.spendable_parts(&id(2), 1), None);
    }
}
```

Add `pub mod ledger;` below `pub mod entries;` in `src/credits/mod.rs`.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::ledger`
Expected: does not compile (`cannot find type Ledger`, `cannot find function run`, …).

- [ ] **Step 3: Implement**

Insert between the imports and the test module:

```rust
/// Credits a completed scan gave a node (`earn::pay` decides how many).
#[derive(Debug, Clone, PartialEq)]
pub struct Earned {
    pub node: NodeId,
    /// The HLC of the scan result: it dates the lot.
    pub hlc: u64,
    pub mc: Mc,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OfferState {
    /// Written, no receipt yet, not 15 minutes old.
    Open,
    Charged {
        charged: Mc,
        to_server: Mc,
        destroyed: Mc,
    },
    /// 15 minutes passed without a receipt: everything went back.
    Lapsed,
}

/// An offer as the ledger sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub payer: NodeId,
    pub seq: u64,
    pub hlc: u64,
    pub to: NodeId,
    /// What the offer names.
    pub offered: Mc,
    /// What the payer's lots held of that when it was written: the most a
    /// receipt can take.
    pub covered: Mc,
    /// Still set aside, by lot day; empty once charged or lapsed.
    pub held: Vec<(u32, Mc)>,
    pub state: OfferState,
    /// The providers its receipt names.
    pub answered: Vec<String>,
}

impl Offer {
    pub fn held_now(&self) -> Mc {
        self.held.iter().map(|(_, mc)| mc).sum()
    }
}

/// A transfer and what it really moved.
#[derive(Debug, Clone, PartialEq)]
pub struct Moved {
    pub hlc: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub named: Mc,
    pub moved: Mc,
}

/// What a node earned and paid over the entries walked.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Tally {
    pub earned: Mc,
    /// Charged to it for lookups.
    pub spent: Mc,
    /// Its half of what it charged others.
    pub served: Mc,
    /// The half of its payments that went to nobody.
    pub destroyed: Mc,
    pub sent: Mc,
    pub received: Mc,
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// Balance per lot `(node, day)`.
    pub lots: BTreeMap<(NodeId, u32), Mc>,
    /// Every offer walked, in the order of the walk.
    pub offers: Vec<Offer>,
    pub transfers: Vec<Moved>,
    pub tallies: HashMap<NodeId, Tally>,
    /// The UTC day balances are read for.
    pub today: u32,
}

impl Ledger {
    fn first_live_day(&self) -> u32 {
        self.today.saturating_sub(LOT_DAYS - 1)
    }

    /// What `node` can spend now: its lots that are still alive.
    pub fn balance(&self, node: &NodeId) -> Mc {
        self.by_day(node).iter().map(|(_, mc)| mc).sum()
    }

    /// `node`'s live lots that hold something, oldest first.
    pub fn by_day(&self, node: &NodeId) -> Vec<(u32, Mc)> {
        self.lots
            .range((*node, self.first_live_day())..=(*node, self.today))
            .filter(|(_, mc)| **mc > 0)
            .map(|((_, day), mc)| (*day, *mc))
            .collect()
    }

    /// What `node` has set aside in open offers.
    pub fn held(&self, node: &NodeId) -> Mc {
        self.offers
            .iter()
            .filter(|o| o.payer == *node && o.state == OfferState::Open)
            .map(Offer::held_now)
            .sum()
    }

    /// The parts of an offer or transfer of `mc` by `node`, oldest lots
    /// first; None when it does not hold that much (or `mc` is nothing).
    pub fn spendable_parts(&self, node: &NodeId, mc: Mc) -> Option<Vec<(u32, u32)>> {
        if mc == 0 {
            return None;
        }
        let mut left = mc;
        let mut parts = vec![];
        for (day, have) in self.by_day(node) {
            let take = have.min(left).min(u32::MAX as Mc);
            parts.push((day, take as u32));
            left -= take;
            if left == 0 {
                return Some(parts);
            }
        }
        None
    }

    pub fn offer(&self, payer: &NodeId, seq: u64) -> Option<&Offer> {
        self.offers
            .iter()
            .find(|o| o.payer == *payer && o.seq == seq)
    }

    /// Every live credit, held ones included.
    pub fn circulating(&self) -> Mc {
        let first = self.first_live_day();
        let in_lots: Mc = self
            .lots
            .iter()
            .filter(|((_, day), _)| (first..=self.today).contains(day))
            .map(|(_, mc)| mc)
            .sum();
        let held: Mc = self
            .offers
            .iter()
            .filter(|o| o.state == OfferState::Open)
            .flat_map(|o| o.held.iter())
            .filter(|(day, _)| (first..=self.today).contains(day))
            .map(|(_, mc)| mc)
            .sum();
        in_lots + held
    }

    /// What `node` holds in the lot that is on its last day.
    pub fn expiring_today(&self, node: &NodeId) -> Mc {
        if self.today < LOT_DAYS - 1 {
            return 0;
        }
        self.lots
            .get(&(*node, self.first_live_day()))
            .copied()
            .unwrap_or(0)
    }

    pub fn tally(&self, node: &NodeId) -> Tally {
        self.tallies.get(node).copied().unwrap_or_default()
    }
}

enum Step<'a> {
    Earn(&'a Earned),
    Entry(&'a Entry),
}

impl Step<'_> {
    /// The order of the walk: by HLC, then origin, then sequence number;
    /// what a scan earned comes before an entry of the same instant.
    fn key(&self) -> (u64, NodeId, u8, u64) {
        match self {
            Step::Earn(e) => (e.hlc, e.node, 0, 0),
            Step::Entry(e) => (e.hlc, e.origin, 1, e.seq),
        }
    }
}

struct Walk<'a> {
    l: Ledger,
    left_out: &'a HashSet<NodeId>,
}

impl Walk<'_> {
    fn lot(&mut self, node: NodeId, day: u32) -> &mut Mc {
        self.l.lots.entry((node, day)).or_insert(0)
    }

    fn tally(&mut self, node: NodeId) -> &mut Tally {
        self.l.tallies.entry(node).or_default()
    }

    /// Give back what offers older than 15 minutes still hold.
    fn lapse(&mut self, now_ms: u64) {
        for i in 0..self.l.offers.len() {
            let o = &self.l.offers[i];
            if o.state != OfferState::Open || now_ms <= physical_ms(o.hlc) + OFFER_TTL_MS {
                continue;
            }
            let (payer, held) = (o.payer, std::mem::take(&mut self.l.offers[i].held));
            self.l.offers[i].state = OfferState::Lapsed;
            for (day, mc) in held {
                *self.lot(payer, day) += mc;
            }
        }
    }

    fn offer(&mut self, e: &Entry, to: NodeId, parts: &[(u32, u32)]) {
        let mut held = vec![];
        for (day, mc) in parts {
            let lot = self.lot(e.origin, *day);
            let take = (*lot).min(*mc as Mc);
            *lot -= take;
            if take > 0 {
                held.push((*day, take));
            }
        }
        held.sort();
        self.l.offers.push(Offer {
            payer: e.origin,
            seq: e.seq,
            hlc: e.hlc,
            to,
            offered: parts.iter().map(|(_, mc)| *mc as Mc).sum(),
            covered: held.iter().map(|(_, mc)| mc).sum(),
            held,
            state: OfferState::Open,
            answered: vec![],
        });
    }

    fn receipt(&mut self, e: &Entry, payer: NodeId, offer_seq: u64, charged: Mc, answered: &[String]) {
        let Some(i) = self.l.offers.iter().position(|o| {
            o.payer == payer
                && o.seq == offer_seq
                && o.to == e.origin
                && o.state == OfferState::Open
                && e.hlc > o.hlc
                && physical_ms(e.hlc) <= physical_ms(o.hlc) + OFFER_TTL_MS
        }) else {
            return;
        };
        let held = std::mem::take(&mut self.l.offers[i].held);
        let mut left = charged.min(held.iter().map(|(_, mc)| mc).sum());
        let (paid, mut to_server) = (left, 0);
        for (day, mc) in held {
            let take = mc.min(left);
            left -= take;
            let half = take / 2;
            to_server += half;
            *self.lot(e.origin, day) += half;
            *self.lot(payer, day) += mc - take;
        }
        let destroyed = paid - to_server;
        let o = &mut self.l.offers[i];
        o.answered = answered.to_vec();
        o.state = OfferState::Charged {
            charged: paid,
            to_server,
            destroyed,
        };
        let t = self.tally(payer);
        t.spent += paid;
        t.destroyed += destroyed;
        self.tally(e.origin).served += to_server;
    }

    fn transfer(&mut self, e: &Entry, to: NodeId, parts: &[(u32, u32)]) {
        let mut moved = 0;
        for (day, mc) in parts {
            let lot = self.lot(e.origin, *day);
            let take = (*lot).min(*mc as Mc);
            *lot -= take;
            *self.lot(to, *day) += take;
            moved += take;
        }
        self.l.transfers.push(Moved {
            hlc: e.hlc,
            from: e.origin,
            to,
            named: parts.iter().map(|(_, mc)| *mc as Mc).sum(),
            moved,
        });
        self.tally(e.origin).sent += moved;
        self.tally(to).received += moved;
    }
}

/// Walk what was earned and every payment in order, and return where
/// every credit is at `now_ms`. Nodes in `left_out` (blocked here, or
/// shown to have two histories) earn nothing and their entries move
/// nothing; what others sent them is lost.
pub fn run(
    earned: &[Earned],
    entries: &[Entry],
    left_out: &HashSet<NodeId>,
    now_ms: u64,
) -> Ledger {
    let mut steps: Vec<Step> = earned
        .iter()
        .map(Step::Earn)
        .chain(entries.iter().map(Step::Entry))
        .collect();
    steps.sort_by_key(Step::key);
    let mut w = Walk {
        l: Ledger {
            today: (now_ms / DAY_MS) as u32,
            ..Default::default()
        },
        left_out,
    };
    for step in steps {
        match step {
            Step::Earn(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.left_out.contains(&e.node) {
                    continue;
                }
                *w.lot(e.node, day_of(e.hlc)) += e.mc;
                w.tally(e.node).earned += e.mc;
            }
            Step::Entry(e) => {
                w.lapse(physical_ms(e.hlc));
                if w.left_out.contains(&e.origin) {
                    continue;
                }
                match &e.kind {
                    Kind::Offer { to, parts } if parts_ok(parts, day_of(e.hlc)) => {
                        w.offer(e, *to, parts)
                    }
                    Kind::Transfer { to, parts }
                        if *to != e.origin && parts_ok(parts, day_of(e.hlc)) =>
                    {
                        w.transfer(e, *to, parts)
                    }
                    Kind::Receipt {
                        payer,
                        offer_seq,
                        charged_mc,
                        answered,
                    } => w.receipt(e, *payer, *offer_seq, *charged_mc as Mc, answered),
                    // Breaks a shape rule: ignored whole.
                    _ => {}
                }
            }
        }
    }
    w.lapse(now_ms);
    // A node left out shows no balance, whatever was sent to it.
    w.l.lots.retain(|(node, _), _| !left_out.contains(node));
    w.l
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib credits::ledger`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/credits/ledger.rs src/credits/mod.rs
git commit -m "Credits: the ledger as a function of the log

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Payable scans: judging them once, paying them at every recomputation

**Files:**
- Create: `src/credits/earn.rs`, `src/store/migrations/0016_credit_scans.sql`
- Modify: `src/credits/mod.rs` (`pub mod earn;`), `src/store/mod.rs` (`MIGRATIONS`)
- Test: unit tests in `src/credits/earn.rs`

**Interfaces:**
- Consumes: `credits::ledger::Earned`, `credits::{Mc, DAY_MS}` (Tasks 1, 5); `scan::profiles::{args_ok, xml_args}` (Task 4); `scan::guard::{evidence, Origins}`; `classify::Classifier`.
- Produces (in `credits::earn`):
  - `Judged { pub scan_uid: String, pub job_uid: String, pub ip: String, pub scanner: NodeId, pub trap: NodeId, pub hlc: u64, pub level: u8, pub job_level: u8, pub args_ok: bool }` (`Debug, Clone, PartialEq`)
  - `Judge<'a> { pub pool: &'a SqlitePool, pub origins: &'a guard::Origins, pub classifier: &'a Classifier }`
  - `judge(j: &Judge<'_>, min_age_secs: i64) -> Result<usize>`; `JUDGE_AFTER_SECS: i64 = 600`
  - `judged_since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Judged>>` (HLC order), `judged_one(pool, scan_uid: &str) -> Result<Option<Judged>>`, `prune(pool, before_hlc: u64) -> Result<u64>`
  - `Gates { pub no_shares: HashMap<NodeId, String>, pub no_scanner_share: HashMap<NodeId, String> }` (`Default`; the value is the reason in words)
  - `Paid { pub scan: Judged, pub scanner_mc: Mc, pub trap_mc: Mc, pub scanner_note: String, pub trap_note: String }` (a note is empty when the share was paid in full)
  - `pay(scans: &[Judged], gates: &Gates) -> Vec<Paid>`, `earned(paid: &[Paid]) -> Vec<Earned>`
  - `PER_NODE_PER_DAY: u32 = 500`, `IP_WINDOW_MS: u64 = 86_400_000`
  - Table `credit_scans`

- [ ] **Step 1: The migration**

Create `src/store/migrations/0016_credit_scans.sql`:

```sql
-- How this node judged each payable scan, once: the level its own rules
-- and requests back, and whether the scan ran with built-in arguments.
CREATE TABLE credit_scans (
  scan_uid TEXT PRIMARY KEY, job_uid TEXT NOT NULL, ip TEXT NOT NULL,
  scanner BLOB NOT NULL, trap BLOB NOT NULL, hlc INTEGER NOT NULL,
  level INTEGER NOT NULL, job_level INTEGER NOT NULL,
  args_ok INTEGER NOT NULL, judged_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE UNIQUE INDEX idx_credit_scans_job ON credit_scans(job_uid);

CREATE INDEX idx_credit_scans_hlc ON credit_scans(hlc)
```

Append to `MIGRATIONS`:

```rust
    include_str!("migrations/0016_credit_scans.sql"),
```

- [ ] **Step 2: Write the failing tests**

Create `src/credits/earn.rs`:

```rust
//! Earning: a completed counter-scan pays its scanner and the trap that
//! queued the job. A node judges each payable scan once, when the requests
//! behind it have had time to arrive (`judge`, stored in `credit_scans`),
//! and decides what it pays at every recomputation of the ledger (`pay`),
//! because that depends on the other scans and on who earns here now.
use super::ledger::Earned;
use super::{DAY_MS, Mc};
use crate::classify::Classifier;
use crate::cluster::hlc::{self, physical_ms};
use crate::cluster::identity::NodeId;
use crate::scan::guard;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    const DAY: u32 = 20_000;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }

    /// A judged scan of `ip` by scanner 1 for trap 2.
    fn scan(n: u32, ip: &str, hlc: u64, level: u8) -> Judged {
        Judged {
            scan_uid: format!("s{n}"),
            job_uid: format!("j{n}"),
            ip: ip.into(),
            scanner: id(1),
            trap: id(2),
            hlc,
            level,
            job_level: level,
            args_ok: true,
        }
    }

    fn shares(p: &Paid) -> (Mc, Mc) {
        (p.scanner_mc, p.trap_mc)
    }

    #[test]
    fn shares_by_level() {
        let scans: Vec<Judged> = (1..=4u8)
            .map(|l| scan(l as u32, &format!("203.0.113.{l}"), at(DAY, l as u64), l))
            .collect();
        let paid = pay(&scans, &Gates::default());
        let got: Vec<(Mc, Mc)> = paid.iter().map(shares).collect();
        assert_eq!(got, [(1000, 250), (1000, 250), (2000, 500), (2000, 500)]);
        assert!(paid.iter().all(|p| p.scanner_note.is_empty() && p.trap_note.is_empty()));
        let e = earned(&paid);
        assert_eq!(e.len(), 8);
        assert_eq!(e.iter().filter(|x| x.node == id(1)).map(|x| x.mc).sum::<Mc>(), 6000);
        assert_eq!(e.iter().filter(|x| x.node == id(2)).map(|x| x.mc).sum::<Mc>(), 1500);
        assert_eq!(e[0].hlc, at(DAY, 1), "dated like the scan");
    }

    #[test]
    fn one_paid_scan_per_ip_in_24_hours() {
        let ip = "203.0.113.9";
        let scans = [
            scan(1, ip, at(DAY, 0), 2),
            // Within the window: nothing.
            scan(2, ip, at(DAY, 600), 1),
            // A higher tier pays the difference, once.
            scan(3, ip, at(DAY, 700), 3),
            scan(4, ip, at(DAY, 800), 4),
            // 24 hours after the first: paid again (the window did not
            // move with the scans in between).
            scan(5, ip, at(DAY + 1, 0), 1),
            // Another address is not affected.
            scan(6, "203.0.113.10", at(DAY, 5), 1),
        ];
        let paid = pay(&scans, &Gates::default());
        let by_uid = |u: &str| paid.iter().find(|p| p.scan.scan_uid == u).unwrap();
        assert_eq!(shares(by_uid("s1")), (1000, 250));
        assert_eq!(shares(by_uid("s2")), (0, 0));
        assert!(by_uid("s2").scanner_note.contains("already paid within 24 hours"));
        assert!(by_uid("s2").trap_note.contains("already paid within 24 hours"));
        assert_eq!(shares(by_uid("s3")), (1000, 250));
        assert!(by_uid("s3").scanner_note.contains("difference"));
        assert_eq!(shares(by_uid("s4")), (0, 0));
        assert_eq!(shares(by_uid("s5")), (1000, 250));
        assert_eq!(shares(by_uid("s6")), (1000, 250));
        // The result does not depend on the order the scans are given in.
        let mut rev = scans.to_vec();
        rev.reverse();
        assert_eq!(pay(&rev, &Gates::default()), paid);
    }

    #[test]
    fn the_five_hundred_and_first_scan_of_a_day_pays_nothing_in_that_role() {
        let mut scans: Vec<Judged> = (0..501u32)
            .map(|n| scan(n, &format!("198.51.{}.{}", n / 250, n % 250), at(DAY, n as u64), 1))
            .collect();
        // The last one was queued by another trap, which is not at its limit.
        scans[500].trap = id(3);
        let paid = pay(&scans, &Gates::default());
        assert_eq!(shares(&paid[499]), (1000, 250));
        assert_eq!(shares(&paid[500]), (0, 250));
        assert!(paid[500].scanner_note.contains("daily limit"));
        // The next UTC day starts a new count.
        let next = pay(&[scan(600, "192.0.2.1", at(DAY + 1, 0), 1)], &Gates::default());
        assert_eq!(shares(&next[0]), (1000, 250));
    }

    #[test]
    fn arguments_evidence_and_gates_take_shares_away() {
        let mut other_args = scan(1, "203.0.113.1", at(DAY, 1), 2);
        other_args.args_ok = false;
        // Asked for level 4; the requests held here back level 2.
        let mut capped = scan(2, "203.0.113.2", at(DAY, 2), 2);
        capped.job_level = 4;
        let mut none = scan(3, "203.0.113.3", at(DAY, 3), 0);
        none.job_level = 2;
        let paid = pay(&[other_args, capped, none], &Gates::default());
        assert_eq!(shares(&paid[0]), (0, 250), "the trap is paid, the scanner is not");
        assert!(paid[0].scanner_note.contains("arguments differ"));
        assert!(paid[0].trap_note.is_empty());
        assert_eq!(shares(&paid[1]), (1000, 250), "paid as the level it is backed for");
        assert!(paid[1].scanner_note.contains("backs level 4"), "{}", paid[1].scanner_note);
        assert_eq!(shares(&paid[2]), (0, 0));
        assert!(paid[2].scanner_note.contains("no request held here backs"));
        // A scan that pays nothing opens no window: a real one later does.
        let later = [
            scan(3, "203.0.113.3", at(DAY, 3), 0),
            scan(4, "203.0.113.3", at(DAY, 9), 1),
        ];
        assert_eq!(shares(&pay(&later, &Gates::default())[1]), (1000, 250));

        // A node that does not earn here, and one whose audits fail.
        let scans = [scan(1, "203.0.113.1", at(DAY, 1), 3)];
        let mut gates = Gates::default();
        gates.no_shares.insert(id(2), "rules: disagree on 12% of 500".into());
        let p = pay(&scans, &gates);
        assert_eq!(shares(&p[0]), (2000, 0));
        assert!(p[0].trap_note.contains("not earning here: rules: disagree on 12% of 500"));
        let mut gates = Gates::default();
        gates.no_scanner_share.insert(id(1), "audits: 3 of 5 differ".into());
        let p = pay(&scans, &gates);
        assert_eq!(shares(&p[0]), (0, 500));
        assert!(p[0].scanner_note.contains("audits: 3 of 5 differ"));
        // A gated scan does not use up the daily limit of its node.
        let mut many: Vec<Judged> = (0..500u32)
            .map(|n| scan(n, &format!("198.51.{}.{}", n / 250, n % 250), at(DAY, n as u64), 1))
            .collect();
        for s in many.iter_mut().take(10) {
            s.args_ok = false;
        }
        many.push(scan(900, "192.0.2.9", at(DAY, 900), 1));
        assert_eq!(shares(pay(&many, &Gates::default()).last().unwrap()), (1000, 0));
    }

    /// Rows as replication leaves them for one finished job.
    async fn finished_scan(store: &Store, ip: &str, job_level: i64, args: &str, n: u8) -> String {
        let row = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let (scanner, trap) = (id(1), id(2));
        let (job, uid) = (format!("job-{n}"), format!("scan-{n}"));
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<nmaprun scanner=\"nmap\" args=\"{args}\" start=\"1\"><host/></nmaprun>"
        );
        sqlx::query(
            "INSERT INTO scan_jobs (uid, ip_id, level, status, queued_at, origin, hlc, arbiter, scanner)
             VALUES (?, ?, ?, 'done', datetime('now'), ?, 1, ?, ?)",
        )
        .bind(&job)
        .bind(row.id)
        .bind(job_level)
        .bind(&trap.0[..])
        .bind(&trap.0[..])
        .bind(&scanner.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        let hlc = (hlc::wall_ms() << 16) as i64 + n as i64;
        sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, raw_xml)
             VALUES (?, ?, ?, (SELECT id FROM scan_jobs WHERE uid = ?), ?, ?, ?, datetime('now'), ?)",
        )
        .bind(&uid)
        .bind(&scanner.0[..])
        .bind(hlc)
        .bind(&job)
        .bind(&job)
        .bind(row.id)
        .bind(job_level)
        .bind(zstd::encode_all(xml.as_bytes(), 3).unwrap())
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, applied, received_at)
             VALUES (?, ?, ?, 'scan_result', ?, 1, datetime('now', '-5 minutes'))",
        )
        .bind(&scanner.0[..])
        .bind(n as i64)
        .bind(hlc)
        .bind(&uid)
        .execute(&store.pool)
        .await
        .unwrap();
        uid
    }

    #[tokio::test]
    async fn a_scan_is_judged_once_when_it_has_been_here_long_enough() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let cfg: crate::config::Config =
            toml::from_str("database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n")
                .unwrap();
        let line = |level: u8| {
            let argv =
                crate::scan::nmap_argv(level, &"203.0.113.7".parse().unwrap(), &cfg, 600).unwrap();
            format!("nmap {}", argv.join(" "))
        };
        // No request from this address is held here.
        let unbacked = finished_scan(&store, "203.0.113.7", 2, &line(2), 1).await;
        // Requests are held; the scanner used its own arguments.
        let rec = store.local();
        let ip = store.upsert_ip("203.0.113.8".parse().unwrap()).await.unwrap();
        for i in 0..3 {
            rec.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: format!("/.env?{i}"),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                scan_level: 4,
                severity: 4,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let own_args = finished_scan(&store, "203.0.113.8", 2, "nmap -A -T5 -oX - 203.0.113.8", 2).await;
        let built_in = finished_scan(&store, "203.0.113.8", 1, &line(1), 3).await;

        let origins = guard::Origins::Any;
        let j = Judge {
            pool: &store.pool,
            origins: &origins,
            classifier: Classifier::builtin(),
        };
        // Arrived five minutes ago: not yet.
        assert_eq!(judge(&j, 600).await.unwrap(), 0);
        assert_eq!(judge(&j, 60).await.unwrap(), 3);
        assert_eq!(judge(&j, 60).await.unwrap(), 0, "once");

        let all = judged_since(&store.pool, 0).await.unwrap();
        assert_eq!(all.len(), 3);
        let one = |uid: &str| judged_one(&store.pool, uid);
        let a = one(&unbacked).await.unwrap().unwrap();
        assert_eq!((a.level, a.job_level, a.args_ok), (0, 2, true));
        assert_eq!((a.scanner, a.trap, a.ip.as_str()), (id(1), id(2), "203.0.113.7"));
        // What the requests held here back, as a scanner would judge them.
        let backed = guard::evidence(&store.pool, "203.0.113.8", &origins, Some(Classifier::builtin()))
            .await
            .unwrap()
            .max_level;
        assert!(backed >= 1, "the test's requests ask for a scan");
        let b = one(&own_args).await.unwrap().unwrap();
        assert_eq!((b.level, b.args_ok), (backed.min(2), false));
        let c = one(&built_in).await.unwrap().unwrap();
        assert_eq!((c.level, c.args_ok), (1, true));
        assert_eq!(one("nope").await.unwrap(), None);

        assert_eq!(prune(&store.pool, u64::MAX >> 1).await.unwrap(), 3);
    }
}
```

Add `pub mod earn;` to `src/credits/mod.rs`.

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib credits::earn`
Expected: does not compile (`cannot find type Judged`, `cannot find function pay`, …).

- [ ] **Step 4: Implement**

Insert between the imports and the test module:

```rust
/// A scan is judged this long after its result arrived here, so the
/// requests behind it have had time to replicate.
pub const JUDGE_AFTER_SECS: i64 = 600;
/// Paid scans per node, role and UTC day.
pub const PER_NODE_PER_DAY: u32 = 500;
/// One paid scan per IP in this window, cluster-wide. Fixed here, not a
/// node's rescan cooldown: that is each node's own setting and can be 0.
pub const IP_WINDOW_MS: u64 = DAY_MS;
/// Scans judged per pass.
const JUDGE_BATCH: i64 = 200;
/// Bytes of a scan's XML read to find its command line.
const XML_HEAD: u64 = 64 * 1024;

/// A payable scan as this node judged it.
#[derive(Debug, Clone, PartialEq)]
pub struct Judged {
    pub scan_uid: String,
    pub job_uid: String,
    pub ip: String,
    pub scanner: NodeId,
    /// The node that queued the job (also after another arbiter adopted it).
    pub trap: NodeId,
    /// The HLC of the scan result: its time, and its lot's day.
    pub hlc: u64,
    /// The level it is paid for: the job's, capped by what the requests
    /// held here back under this build's rules. 0: nothing backs it.
    pub level: u8,
    pub job_level: u8,
    /// It ran with the built-in arguments of the job's level.
    pub args_ok: bool,
}

/// What judging a scan needs from the node.
pub struct Judge<'a> {
    pub pool: &'a SqlitePool,
    /// Whose requests count as evidence (`scan.trusted_origins`).
    pub origins: &'a guard::Origins,
    pub classifier: &'a Classifier,
}

/// The command line in a stored (zstd-compressed) nmap XML.
fn command_line(raw_xml: Option<&[u8]>) -> Option<String> {
    use std::io::Read;
    let mut head = Vec::new();
    zstd::stream::read::Decoder::new(raw_xml?)
        .ok()?
        .take(XML_HEAD)
        .read_to_end(&mut head)
        .ok()?;
    crate::scan::profiles::xml_args(&head)
}

/// Judge the payable scans that arrived at least `min_age_secs` ago and
/// have no judgment yet. A scan is payable when its job is done by a
/// scanner as its arbiter recorded it, and a result of that scanner for
/// the job's address and level is held; the earliest one of a job counts.
/// Returns how many were judged.
pub async fn judge(j: &Judge<'_>, min_age_secs: i64) -> Result<usize> {
    type Row = (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Option<Vec<u8>>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.uid, j.uid, i.ip, j.scanner, j.origin, s.hlc, j.level, s.raw_xml
         FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid
         JOIN ips i ON i.id = s.ip_id
         JOIN repl_log l ON l.uid = s.uid AND l.origin = s.origin
         WHERE j.status = 'done' AND j.scanner IS NOT NULL AND j.origin IS NOT NULL
           AND s.origin = j.scanner AND s.ip_id = j.ip_id AND s.level = j.level
           AND l.received_at <= datetime('now', ?)
           AND NOT EXISTS (SELECT 1 FROM credit_scans c WHERE c.job_uid = j.uid)
         ORDER BY s.hlc, s.uid LIMIT ?",
    )
    .bind(format!("-{} seconds", min_age_secs.max(0)))
    .bind(JUDGE_BATCH)
    .fetch_all(j.pool)
    .await?;
    let mut n = 0;
    for (scan_uid, job_uid, ip, scanner, trap, at, job_level, raw_xml) in rows {
        let job_level = job_level.clamp(0, 4) as u8;
        let backed = guard::evidence(j.pool, &ip, j.origins, Some(j.classifier))
            .await?
            .max_level;
        let args_ok = command_line(raw_xml.as_deref())
            .is_some_and(|line| crate::scan::profiles::args_ok(&line, job_level));
        // The unique index on the job keeps the earliest scan of a job.
        n += sqlx::query(
            "INSERT OR IGNORE INTO credit_scans
               (scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok, judged_at)
             VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))",
        )
        .bind(&scan_uid)
        .bind(&job_uid)
        .bind(&ip)
        .bind(&scanner)
        .bind(&trap)
        .bind(at)
        .bind(job_level.min(backed) as i64)
        .bind(job_level as i64)
        .bind(args_ok)
        .execute(j.pool)
        .await?
        .rows_affected() as usize;
    }
    Ok(n)
}

type JudgedRow = (String, String, String, Vec<u8>, Vec<u8>, i64, i64, i64, bool);

const JUDGED_COLUMNS: &str =
    "scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok";

fn from_row(r: JudgedRow) -> Result<Judged> {
    Ok(Judged {
        scan_uid: r.0,
        job_uid: r.1,
        ip: r.2,
        scanner: NodeId::from_slice(&r.3)?,
        trap: NodeId::from_slice(&r.4)?,
        hlc: hlc::from_db(r.5),
        level: r.6.clamp(0, 4) as u8,
        job_level: r.7.clamp(0, 4) as u8,
        args_ok: r.8,
    })
}

/// The judged scans dated `from_hlc` or later, in the order they are paid.
pub async fn judged_since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Judged>> {
    let rows: Vec<JudgedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {JUDGED_COLUMNS} FROM credit_scans WHERE hlc >= ? ORDER BY hlc, scan_uid"
    )))
    .bind(hlc::to_db(from_hlc))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(from_row).collect()
}

/// How this node judged one scan.
pub async fn judged_one(pool: &SqlitePool, scan_uid: &str) -> Result<Option<Judged>> {
    let row: Option<JudgedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {JUDGED_COLUMNS} FROM credit_scans WHERE scan_uid = ?"
    )))
    .bind(scan_uid)
    .fetch_optional(pool)
    .await?;
    row.map(from_row).transpose()
}

pub async fn prune(pool: &SqlitePool, before_hlc: u64) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM credit_scans WHERE hlc < ?")
        .bind(hlc::to_db(before_hlc))
        .execute(pool)
        .await?
        .rows_affected())
}

/// Who does not earn here right now, and why (in words, for the pages).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Gates {
    /// None of the node's shares count, as scanner or as trap.
    pub no_shares: HashMap<NodeId, String>,
    /// Its scanner shares do not count.
    pub no_scanner_share: HashMap<NodeId, String>,
}

/// What one judged scan pays.
#[derive(Debug, Clone, PartialEq)]
pub struct Paid {
    pub scan: Judged,
    pub scanner_mc: Mc,
    pub trap_mc: Mc,
    /// Why the share is not the full one of the scan's level; empty when
    /// it is.
    pub scanner_note: String,
    pub trap_note: String,
}

/// `(scanner, trap)` shares of a tier: 1 for levels 1 and 2, 2 for 3 and 4.
fn tier_shares(tier: u8) -> (Mc, Mc) {
    match tier {
        2 => (2000, 500),
        _ => (1000, 250),
    }
}

/// Decide what every judged scan pays. A pure function of its input: the
/// scans are walked in the order of their HLCs (then uids), whatever
/// order they are given in.
pub fn pay(scans: &[Judged], gates: &Gates) -> Vec<Paid> {
    let mut order: Vec<&Judged> = scans.iter().collect();
    order.sort_by(|a, b| (a.hlc, &a.scan_uid).cmp(&(b.hlc, &b.scan_uid)));
    // Per IP: when its 24-hour window opened, and the tier paid in it.
    let mut windows: HashMap<&str, (u64, u8)> = HashMap::new();
    // Paid scans per node, UTC day and role (0 scanner, 1 trap).
    let mut counts: HashMap<(NodeId, u32, u8), u32> = HashMap::new();
    let mut out = Vec::with_capacity(order.len());
    for s in order {
        let mut p = Paid {
            scan: s.clone(),
            scanner_mc: 0,
            trap_mc: 0,
            scanner_note: String::new(),
            trap_note: String::new(),
        };
        if s.level == 0 {
            let why = format!("no request held here backs a scan of {}", s.ip);
            p.scanner_note = why.clone();
            p.trap_note = why;
            out.push(p);
            continue;
        }
        let tier = if s.level >= 3 { 2 } else { 1 };
        let ms = physical_ms(s.hlc);
        let mut note = String::new();
        let (scanner, trap) = match windows.get_mut(s.ip.as_str()) {
            Some((start, paid_tier)) if ms < *start + IP_WINDOW_MS => {
                if tier > *paid_tier {
                    let (hi, lo) = (tier_shares(tier), tier_shares(*paid_tier));
                    *paid_tier = tier;
                    note = "the difference to the scan this IP was already paid for".into();
                    (hi.0 - lo.0, hi.1 - lo.1)
                } else {
                    note = "this IP was already paid within 24 hours".into();
                    (0, 0)
                }
            }
            _ => {
                windows.insert(s.ip.as_str(), (ms, tier));
                tier_shares(tier)
            }
        };
        if note.is_empty() && s.level < s.job_level {
            note = format!(
                "paid as level {}: no request held here backs level {}",
                s.level, s.job_level
            );
        }
        (p.scanner_mc, p.trap_mc) = (scanner, trap);
        p.scanner_note = note.clone();
        p.trap_note = note;
        if !s.args_ok {
            p.scanner_mc = 0;
            p.scanner_note = "arguments differ from the built-in ones".into();
        }
        if let Some(why) = gates
            .no_shares
            .get(&s.scanner)
            .or_else(|| gates.no_scanner_share.get(&s.scanner))
        {
            p.scanner_mc = 0;
            p.scanner_note = format!("not earning here: {why}");
        }
        if let Some(why) = gates.no_shares.get(&s.trap) {
            p.trap_mc = 0;
            p.trap_note = format!("not earning here: {why}");
        }
        let day = super::day_of(s.hlc);
        for (node, role, mc, why) in [
            (s.scanner, 0u8, &mut p.scanner_mc, &mut p.scanner_note),
            (s.trap, 1u8, &mut p.trap_mc, &mut p.trap_note),
        ] {
            if *mc == 0 {
                continue;
            }
            let n = counts.entry((node, day, role)).or_insert(0);
            if *n >= PER_NODE_PER_DAY {
                *mc = 0;
                *why = "daily limit reached".into();
            } else {
                *n += 1;
            }
        }
        out.push(p);
    }
    out
}

/// What `paid` gives the ledger: one earning per share that is not nothing.
pub fn earned(paid: &[Paid]) -> Vec<Earned> {
    paid.iter()
        .flat_map(|p| {
            [(p.scan.scanner, p.scanner_mc), (p.scan.trap, p.trap_mc)]
                .into_iter()
                .filter(|(_, mc)| *mc > 0)
                .map(|(node, mc)| Earned {
                    node,
                    hlc: p.scan.hlc,
                    mc,
                })
        })
        .collect()
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib credits::earn && cargo test --lib store::`
Expected: PASS (5 earn tests; the store tests confirm the migration applies).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/credits/earn.rs src/credits/mod.rs src/store/mod.rs src/store/migrations/0016_credit_scans.sql
git commit -m "Credits: scans are judged once and paid by the rules of the spec

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Who earns here, and this node's book

The gates that do not need audits (rules agreement, blocks, forks), the book that puts judged scans, gates and the ledger together, and the loop that judges scans in the background. The rules comparison moves from the admin state to the node, so the ledger and the pages share one cached result.

**Files:**
- Create: `src/credits/gates.rs`
- Modify: `src/credits/mod.rs` (the book, its cache, the loop), `src/cluster/mod.rs` (two `Node` fields), `src/admin/cluster.rs` (the rules comparison moves out), `src/admin/mod.rs` (`AdminState.rules_check` goes), `src/admin/system.rs:179` (`SHORT_HASH` path), `src/lib.rs` (start the loop), `tests/cluster.rs`
- Test: unit tests in `src/credits/gates.rs`; `tests/cluster.rs::a_completed_scan_pays_scanner_and_trap_in_every_nodes_book`; existing `cargo test --lib admin::cluster`

**Interfaces:**
- Consumes: `earn::{judge, Judge, judged_since, pay, earned, Gates, Paid, JUDGE_AFTER_SECS}` (Task 6); `ledger::{run, Ledger}` (Task 5); `entries::{since, prune}` (Task 1); `seal::forked` (Task 3); `cluster::block::list`; `classify::stored::{agreement, Agreement}`; `store::stats::SwrCache`.
- Produces:
  - `credits::gates::{RulesCheck, Carried, carried, RULES_SAMPLE, SHORT_HASH}` (moved from `admin::cluster`, unchanged), `gates::rules_check(node: &Node) -> Result<Arc<RulesCheck>>`
  - `gates::rules_fail(a: &Agreement) -> bool`
  - `gates::Standing { pub blocked: bool, pub forked: Option<u64>, pub rules: Option<Agreement>, pub audits: Option<(u32, u32)> }` (`Debug, Clone, Default, PartialEq`) with `earns(&self) -> bool`, `earns_as_scanner(&self) -> bool`, `left_out(&self) -> bool`, `reasons(&self) -> Vec<String>`
  - `gates::Standings = HashMap<NodeId, Standing>`, `gates::standings(node: &Node) -> Result<Standings>`, `gates::to_gates(s: &Standings) -> earn::Gates`
  - `credits::Book { pub ledger: Ledger, pub paid: Vec<earn::Paid>, pub standings: gates::Standings, pub now_ms: u64 }` with `balance(&self, node: &NodeId) -> Mc`, `standing(&self, node: &NodeId) -> gates::Standing`, `earned_per_day(&self) -> Mc`
  - `credits::compute(node: &Node) -> Result<Book>`, `credits::book(node: &Node) -> Result<Arc<Book>>` (at most 10 s old), `credits::book_fresh(node: &Node) -> Result<Arc<Book>>`
  - `credits::window_start(now_ms: u64) -> u64` (the HLC from which entries and scans are read: 8 days back)
  - `credits::run(node: Arc<Node>, cfg: Config, shutdown: tokio::sync::watch::Receiver<bool>)`
  - `Node.rules_check: SwrCache<(), gates::RulesCheck>`, `Node.credits_book: Mutex<Option<(Instant, Arc<Book>)>>`

- [ ] **Step 1: Write the failing tests**

Create `src/credits/gates.rs` with the imports and tests:

```rust
//! Who earns here. Each node decides for itself, from what it holds:
//! a member's requests must classify the same under this build's rules,
//! its scans must stand up to audits, and a member that is blocked here or
//! showed two histories earns nothing at all. The gates are evaluated at
//! each recomputation, not stored: a member that agrees again (after an
//! upgrade, typically) earns again.
use super::earn::Gates;
use crate::classify::stored::{Agreement, agreement};
use crate::cluster::identity::NodeId;
use crate::cluster::{Node, members};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    fn a(sampled: u32, differing: u32) -> Agreement {
        Agreement { sampled, differing }
    }

    #[test]
    fn the_rules_gate_needs_twenty_requests_and_more_than_two_percent() {
        assert!(!rules_fail(&a(19, 19)), "too few to judge");
        assert!(rules_fail(&a(20, 1)), "5 %");
        assert!(!rules_fail(&a(500, 10)), "2 % passes");
        assert!(rules_fail(&a(500, 11)));
        assert!(!rules_fail(&a(500, 0)));
        assert!(!rules_fail(&a(0, 0)));
    }

    #[test]
    fn standing_says_who_earns_and_why_not() {
        let fine = Standing::default();
        assert!(fine.earns() && fine.earns_as_scanner() && !fine.left_out());
        assert!(fine.reasons().is_empty());
        let rules = Standing {
            rules: Some(a(500, 60)),
            ..Default::default()
        };
        assert!(!rules.earns() && !rules.left_out());
        assert_eq!(rules.reasons(), ["rules: disagree on 12% of 500"]);
        let audits = Standing {
            audits: Some((5, 3)),
            ..Default::default()
        };
        assert!(audits.earns() && !audits.earns_as_scanner());
        assert_eq!(audits.reasons(), ["audits: 3 of 5 differ"]);
        let gone = Standing {
            blocked: true,
            forked: Some(7),
            ..Default::default()
        };
        assert!(gone.left_out() && !gone.earns());
        assert_eq!(
            gone.reasons(),
            ["blocked on this node", "showed two histories (at entry 7 of its log)"]
        );

        let (x, y, z) = (NodeId([1; 32]), NodeId([2; 32]), NodeId([3; 32]));
        let all: Standings = [(x, rules), (y, audits), (z, fine)].into();
        let g = to_gates(&all);
        assert_eq!(g.no_shares.get(&x).map(String::as_str), Some("rules: disagree on 12% of 500"));
        assert_eq!(g.no_scanner_share.get(&y).map(String::as_str), Some("audits: 3 of 5 differ"));
        assert!(!g.no_shares.contains_key(&z) && !g.no_scanner_share.contains_key(&z));
    }
}
```

Append to `tests/cluster.rs`:

```rust
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
    eventually_for(Duration::from_secs(40), "scanned, and everyone has it all", || async {
        let mut all = true;
        for n in [&na, &nb, &nc] {
            all &= count(n, "SELECT COUNT(*) FROM scans").await == 1
                && count(n, "SELECT COUNT(*) FROM scan_jobs WHERE status = 'done'").await == 1
                && count(n, "SELECT COUNT(*) FROM requests").await == 3;
        }
        all
    })
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
    peephole::cluster::block::block(&nc.node, b.id).await.unwrap();
    let book = credits::book_fresh(&nc.node).await.unwrap();
    assert_eq!(book.balance(&b.id), 0);
    assert!(book.standing(&b.id).blocked);
    assert_eq!(
        credits::book_fresh(&na.node).await.unwrap().balance(&b.id),
        1000
    );
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::gates`
Expected: does not compile (`cannot find function rules_fail`, `cannot find type Standing`).

- [ ] **Step 3: Move the rules comparison**

From `src/admin/cluster.rs` to `src/credits/gates.rs` (below the imports), unchanged apart from what is said here:

- `SHORT_HASH` (make it `pub const`), `struct Carried` with its `impl` (make `view` `pub(crate)`), `pub async fn carried`, `pub struct RulesCheck`, `RULES_CHECK_TTL`, `pub const RULES_SAMPLE`, and `async fn compare_rules`.
- In their place in `src/admin/cluster.rs` put

```rust
use crate::credits::gates::{Carried, RULES_SAMPLE, RulesCheck, carried};
pub(crate) use crate::credits::gates::SHORT_HASH;

/// The comparison of members' requests with this node's rules, made at
/// most every ten minutes (see [`crate::credits::gates::rules_check`]).
pub(crate) async fn rules_check(_st: &AdminState, node: &Node) -> AppResult<Arc<RulesCheck>> {
    Ok(crate::credits::gates::rules_check(node).await?)
}
```

  Drop an import of these names that the compiler then reports as unused (the test module of `admin/cluster.rs` reaches `Carried` and `carried` through `use super::*;`).
- `src/admin/mod.rs`: remove the field `rules_check` from `AdminState` and its initializer `rules_check: crate::store::stats::SwrCache::new(1),`.

Add to `src/credits/gates.rs`, below the moved items:

```rust
/// The comparison, made at most every [`RULES_CHECK_TTL`] (an older one is
/// used while it is made again), shared by the ledger and the pages.
pub async fn rules_check(node: &Node) -> Result<Arc<RulesCheck>> {
    let store = node.store.clone();
    node.rules_check
        .get((), RULES_CHECK_TTL, move || {
            let store = store.clone();
            Box::pin(async move { compare_rules(&store).await })
        })
        .await
}
```

`src/cluster/mod.rs`, in `struct Node` after `pub owner_locks: owner::Locks,`:

```rust
    /// How members' requests compare with this node's rules (the credits
    /// gate and the cluster pages).
    pub rules_check: crate::store::stats::SwrCache<(), crate::credits::gates::RulesCheck>,
    /// This node's book of credits, as last computed.
    pub credits_book: Mutex<Option<(std::time::Instant, Arc<crate::credits::Book>)>>,
```

and in `Node::open`'s struct literal after `owner_locks: Default::default(),`:

```rust
            rules_check: crate::store::stats::SwrCache::new(1),
            credits_book: Mutex::new(None),
```

- [ ] **Step 4: The gates**

Append to `src/credits/gates.rs` (before the test module):

```rust
/// A member is judged by its rules only when at least this many of its
/// newest requests could be compared.
pub const RULES_MIN_SAMPLE: u32 = 20;

/// Whether a member fails the rules gate: at least 20 requests compared
/// and more than 2 % of them classified differently here.
pub fn rules_fail(a: &Agreement) -> bool {
    a.sampled >= RULES_MIN_SAMPLE && u64::from(a.differing) * 50 > u64::from(a.sampled)
}

/// What stands between a member and its earnings on this node.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Standing {
    pub blocked: bool,
    /// It showed two histories, noticed at this position of its log.
    pub forked: Option<u64>,
    /// Its rules agreement, when that fails the gate.
    pub rules: Option<Agreement>,
    /// Counted audits of the last 7 days as `(conclusive, differing)`,
    /// when they fail the gate (`credits::audit`).
    pub audits: Option<(u32, u32)>,
}

impl Standing {
    /// Its shares count here (as trap; as scanner see `earns_as_scanner`).
    pub fn earns(&self) -> bool {
        !self.left_out() && self.rules.is_none()
    }

    pub fn earns_as_scanner(&self) -> bool {
        self.earns() && self.audits.is_none()
    }

    /// Out of the ledger altogether: no balance, and its payments move
    /// nothing.
    pub fn left_out(&self) -> bool {
        self.blocked || self.forked.is_some()
    }

    /// Every reason that applies, in words.
    pub fn reasons(&self) -> Vec<String> {
        let mut v = vec![];
        if self.blocked {
            v.push("blocked on this node".to_string());
        }
        if let Some(seq) = self.forked {
            v.push(format!("showed two histories (at entry {seq} of its log)"));
        }
        if let Some(a) = &self.rules {
            v.push(format!("rules: {}", a.summary()));
        }
        if let Some((conclusive, differing)) = self.audits {
            v.push(format!("audits: {differing} of {conclusive} differ"));
        }
        v
    }
}

/// The members that do not earn in full here; everyone else does.
pub type Standings = HashMap<NodeId, Standing>;

/// Evaluate the gates now.
pub async fn standings(node: &Node) -> Result<Standings> {
    let mut out = Standings::new();
    for id in crate::cluster::block::list(&node.store).await? {
        out.entry(id).or_default().blocked = true;
    }
    for f in crate::cluster::seal::forked(&node.store.pool).await? {
        out.entry(f.origin).or_default().forked = Some(f.seq);
    }
    let check = rules_check(node).await?;
    for (id, a) in &check.by_member {
        // This node's own requests are what its rules made of them.
        if *id != node.id() && rules_fail(a) {
            out.entry(*id).or_default().rules = Some(*a);
        }
    }
    Ok(out)
}

/// The gates as the paying walk takes them.
pub fn to_gates(s: &Standings) -> Gates {
    let mut g = Gates::default();
    for (id, st) in s {
        if !st.earns() {
            g.no_shares.insert(*id, st.reasons().join("; "));
        } else if !st.earns_as_scanner() {
            g.no_scanner_share.insert(*id, st.reasons().join("; "));
        }
    }
    g
}
```

The imports `members` and `agreement` at the top of the file are used by the moved `compare_rules`; if the compiler reports one unused, drop it.

- [ ] **Step 5: The book and the loop**

`src/credits/mod.rs`: add `pub mod gates;` to the module list, and below `parse_amount`:

```rust
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use std::collections::HashSet;
use std::sync::Arc;

/// Everything this node knows about credits at one moment: who earns
/// here, what every judged scan paid, and where every credit is.
pub struct Book {
    pub ledger: ledger::Ledger,
    pub paid: Vec<earn::Paid>,
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

    /// What all members earned a day over the last 168 hours (the `E` of
    /// the price formula).
    pub fn earned_per_day(&self) -> Mc {
        let from = self.now_ms.saturating_sub(7 * DAY_MS);
        let week: Mc = self
            .paid
            .iter()
            .filter(|p| crate::cluster::hlc::physical_ms(p.scan.hlc) >= from)
            .map(|p| p.scanner_mc + p.trap_mc)
            .sum();
        week / 7
    }
}

/// The HLC from which scans and payments are read at `now_ms`: the 7 days
/// lots live, and one more for the 24-hour window of each IP.
pub fn window_start(now_ms: u64) -> u64 {
    now_ms.saturating_sub((LOT_DAYS as u64 + 1) * DAY_MS) << 16
}

/// Compute this node's book from what it holds now.
pub async fn compute(node: &Node) -> anyhow::Result<Book> {
    let now_ms = crate::cluster::hlc::wall_ms();
    let since = window_start(now_ms);
    let standings = gates::standings(node).await?;
    let judged = earn::judged_since(&node.store.pool, since).await?;
    let paid = earn::pay(&judged, &gates::to_gates(&standings));
    let entries = entries::since(&node.store.pool, since).await?;
    let left_out: HashSet<NodeId> = standings
        .iter()
        .filter(|(_, s)| s.left_out())
        .map(|(id, _)| *id)
        .collect();
    let ledger = ledger::run(&earn::earned(&paid), &entries, &left_out, now_ms);
    Ok(Book {
        ledger,
        paid,
        standings,
        now_ms,
    })
}

/// How old a book the pages and the heartbeat may use.
const BOOK_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// This node's book, at most [`BOOK_TTL`] old.
pub async fn book(node: &Node) -> anyhow::Result<Arc<Book>> {
    if let Some((at, b)) = node.credits_book.lock().unwrap().as_ref()
        && at.elapsed() < BOOK_TTL
    {
        return Ok(b.clone());
    }
    book_fresh(node).await
}

/// This node's book, computed now (before money moves: an offer is made,
/// or served).
pub async fn book_fresh(node: &Node) -> anyhow::Result<Arc<Book>> {
    let b = Arc::new(compute(node).await?);
    *node.credits_book.lock().unwrap() = Some((std::time::Instant::now(), b.clone()));
    Ok(b)
}

/// How often the loop judges scans.
const TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// Judge scans as they become due, say in the journal when a member's
/// standing changes, and drop what is older than the ledger reads.
pub async fn run(
    node: Arc<Node>,
    cfg: crate::config::Config,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let origins = crate::scan::guard::Origins::from_config(&cfg.scan.safety, Some(node.id()));
    let mut known: gates::Standings = Default::default();
    let mut ticks = 0u64;
    loop {
        let judge = earn::Judge {
            pool: &node.store.pool,
            origins: &origins,
            classifier: crate::classify::Classifier::builtin(),
        };
        match earn::judge(&judge, earn::JUDGE_AFTER_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(scans = n, "credits: scans judged"),
            Err(e) => tracing::warn!(?e, "credits: judging scans failed"),
        }
        match gates::standings(&node).await {
            Ok(now) => {
                let names = node.members();
                let name = |id: &NodeId| names.get(id).map_or_else(|| id.short(), |m| m.name.clone());
                for (id, s) in &now {
                    if known.get(id) != Some(s) {
                        tracing::info!(member = %name(id), reasons = %s.reasons().join("; "),
                            "credits: member does not earn in full here");
                    }
                }
                for id in known.keys().filter(|id| !now.contains_key(*id)) {
                    tracing::info!(member = %name(id), "credits: member earns here again");
                }
                known = now;
            }
            Err(e) => tracing::debug!(?e, "credits: standings not evaluated"),
        }
        if ticks % 60 == 0 {
            let before = window_start(crate::cluster::hlc::wall_ms());
            let pool = &node.store.pool;
            if let Err(e) = async {
                entries::prune(pool, before).await?;
                earn::prune(pool, before).await
            }
            .await
            {
                tracing::debug!(?e, "credits: pruning failed");
            }
        }
        ticks += 1;
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}
```

`src/lib.rs`, below the `tokio::spawn(cluster::seal::run(…));` line:

```rust
        tokio::spawn(credits::run(
            node.clone(),
            cfg.clone(),
            shutdown_rx.clone(),
        ));
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib credits:: && cargo test --lib admin::cluster && cargo test --test cluster a_completed_scan_pays && cargo test --test cluster admin_cluster_page_and_private_attribution`
Expected: PASS. The admin tests show the moved comparison still feeds the cluster pages.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add src/credits src/cluster/mod.rs src/admin/cluster.rs src/admin/mod.rs src/admin/system.rs src/lib.rs tests/cluster.rs
git commit -m "Credits: who earns here, and each node's book of balances

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Part C: audits

### Task 8: The `scan_audit` record

An audit is a scan run again by another scanner. It is published as its own record kind (old nodes relay it untouched), stored in `scans` with `audit_of` set, and never mistaken for the result of its job.

**Files:**
- Create: `src/store/migrations/0017_scan_audits.sql`
- Modify: `src/cluster/record.rs`, `src/store/data.rs` (`apply`, `CONTENT_KINDS`, `scan_result`, `remove_row`), `src/cluster/repl.rs` (`waits_for`, `rematerialize`), `src/store/recorder.rs` (`record_scan_audit`), `src/store/inspect.rs` (`ScanSummary`, `SCAN_SELECT`, the queue row's scan), `src/scan/arbiter.rs:522`, `src/credits/earn.rs` (`judge`), `src/store/export.rs` and `src/export/mod.rs` (`uid`, `audit_of`), `src/store/mod.rs` (`MIGRATIONS`)
- Test: unit tests in `src/store/data.rs`, `src/cluster/record.rs`, `src/credits/earn.rs`; existing `cargo test --lib export::`

**Interfaces:**
- Produces:
  - `cluster::record::ScanAuditRec { pub audit_of: String, pub scan: ScanResultRec }`; `Record::ScanAudit(Box<ScanAuditRec>)`, kind `scan_audit`, uid = the audit's own scan uid; `scan.job_uid` is the audited scan's job
  - Columns `scans.audit_of` (uid of the audited scan) and `scans.audit_result` (`agrees`, `differs`, `inconclusive`; filled by Task 9)
  - `Recorder::record_scan_audit(&self, audit_of: &str, job_uid: &str, ip: &str, level: i64, started_at: &str, res: &ScanResult) -> Result<()>`
  - `ScanSummary.audit_of: Option<String>`, `ScanSummary.audit_result: Option<String>`

- [ ] **Step 1: The migration**

Create `src/store/migrations/0017_scan_audits.sql`:

```sql
-- Audits: a scan run again by another scanner. `audit_of` is the uid of
-- the scan it checks, `audit_result` how the two compare here.
ALTER TABLE scans ADD COLUMN audit_of TEXT;

ALTER TABLE scans ADD COLUMN audit_result TEXT;

CREATE INDEX idx_scans_audit_of ON scans(audit_of) WHERE audit_of IS NOT NULL
```

Append to `MIGRATIONS`:

```rust
    include_str!("migrations/0017_scan_audits.sql"),
```

- [ ] **Step 2: Write the failing tests**

Add to the test module of `src/store/data.rs`:

```rust
    /// An audit is stored as a scan of the same job, marked as an audit,
    /// and leaves the tables without taking the audited scan along.
    #[tokio::test]
    async fn an_audit_is_a_scan_of_the_same_job_marked_as_such() {
        use crate::cluster::record::{PortRec, ScanAuditRec, ScanJobRec};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut conn = store.pool.acquire().await.unwrap();
        let (scanner, auditor) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let ctx = |origin, hlc| Ctx {
            origin: Some(origin),
            hlc,
        };
        let job = Record::ScanJob(ScanJobRec {
            uid: "job".into(),
            ip: "203.0.113.9".into(),
            level: 2,
            queued_at: now_ts(),
        });
        assert_eq!(apply(&mut conn, ctx(&scanner, 1), &job).await.unwrap(), Effect::Applied);
        let scan = |uid: &str, job: &str| ScanResultRec {
            build: String::new(),
            uid: uid.into(),
            job_uid: job.into(),
            ip: "203.0.113.9".into(),
            level: 2,
            started_at: now_ts(),
            finished_at: Some(now_ts()),
            os_guess: None,
            raw_xml: None,
            ports: vec![PortRec {
                port: 22,
                proto: "tcp".into(),
                state: "open".into(),
                service: None,
                product: None,
                version: None,
            }],
        };
        let original = Record::ScanResult(scan("orig", "job"));
        assert_eq!(apply(&mut conn, ctx(&scanner, 2), &original).await.unwrap(), Effect::Applied);
        let audit = Record::ScanAudit(Box::new(ScanAuditRec {
            audit_of: "orig".into(),
            scan: scan("audit", "job"),
        }));
        assert_eq!((audit.kind(), audit.uid().as_deref()), ("scan_audit", Some("audit")));
        for _ in 0..2 {
            assert_eq!(apply(&mut conn, ctx(&auditor, 3), &audit).await.unwrap(), Effect::Applied);
        }
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM scans").await, 2);
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ports").await, 2);
        let of: Option<String> = sqlx::query_scalar("SELECT audit_of FROM scans WHERE uid = 'audit'")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(of.as_deref(), Some("orig"));
        assert_eq!(
            count(&mut conn, "SELECT COUNT(*) FROM scans WHERE audit_of IS NULL").await,
            1
        );
        // Its job has not arrived: it waits, like a scan result.
        let early = Record::ScanAudit(Box::new(ScanAuditRec {
            audit_of: "x".into(),
            scan: scan("audit-2", "job-not-here"),
        }));
        assert_eq!(apply(&mut conn, ctx(&auditor, 4), &early).await.unwrap(), Effect::Deferred);
        // A blocked auditor's audits stay out of the tables.
        sqlx::query("INSERT INTO blocked_peers (id, blocked_at) VALUES (?, datetime('now'))")
            .bind(&auditor.0[..])
            .execute(&mut *conn)
            .await
            .unwrap();
        let more = Record::ScanAudit(Box::new(ScanAuditRec {
            audit_of: "orig".into(),
            scan: scan("audit-3", "job"),
        }));
        assert_eq!(apply(&mut conn, ctx(&auditor, 5), &more).await.unwrap(), Effect::Ignored);
        // Taken out of the tables alone.
        assert!(unmaterialize(&mut conn, "scan_audit", "audit").await.unwrap().is_some());
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM scans").await, 1);
        assert_eq!(count(&mut conn, "SELECT COUNT(*) FROM ports").await, 1);
    }
```

(`count`, `Identity`, `Store`, `now_ts` and `ScanResultRec` are in scope in that test module already; add a `use` for one the compiler misses.)

In `src/credits/earn.rs`, extend `a_scan_is_judged_once_when_it_has_been_here_long_enough`: directly before `let origins = guard::Origins::Any;` add

```rust
        // An audit of the last scan, by another node: not a payable scan.
        sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, audit_of)
             SELECT 'audit-1', ?, hlc - 1, job_id, job_uid, ip_id, level, started_at, uid
             FROM scans WHERE uid = ?",
        )
        .bind(&id(1).0[..])
        .bind(&built_in)
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, applied, received_at)
             VALUES (?, 99, 99, 'scan_audit', 'audit-1', 1, datetime('now', '-5 minutes'))",
        )
        .bind(&id(1).0[..])
        .execute(&store.pool)
        .await
        .unwrap();
```

(The audit is written as if by the scanner itself and dated just before the scan, the case in which it would be judged in the scan's place: `judged_one(&built_in)` further down then finds nothing.)

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib store::data::tests::an_audit_is_a_scan`
Expected: does not compile (`cannot find struct ScanAuditRec`).

- [ ] **Step 4: Implement**

`src/cluster/record.rs`, below `ScanResultRec`:

```rust
/// A finished audit: a scan run again by another scanner to check a
/// result (see `credits::audit`). Audits earn nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanAuditRec {
    /// The uid of the audited scan.
    pub audit_of: String,
    /// The audit's own result; its `job_uid` is the audited scan's job.
    pub scan: ScanResultRec,
}
```

`enum Record`, after `ForkProof { … },`:

```rust
    ScanAudit(Box<ScanAuditRec>),
```

`Record::kind`: `Record::ScanAudit(_) => "scan_audit",`. `Record::uid`, before the `_ => None` arm: `Record::ScanAudit(r) => Some(r.scan.uid.clone()),`.

`src/store/data.rs`:

- `CONTENT_KINDS` becomes `[&str; 8]` with `"scan_audit",` after `"scan_result",`.
- In `apply`'s `match r`: `Record::ScanResult(r) => scan_result(conn, ctx, r, None).await,` and, below it,

```rust
        Record::ScanAudit(a) => {
            // The uid of another node's scan: a plain identifier, bounded.
            if a.audit_of.is_empty() || a.audit_of.len() > 128 {
                return Ok(Effect::Ignored);
            }
            scan_result(conn, ctx, &a.scan, Some(&a.audit_of)).await
        }
```

- `scan_result` gains the parameter `audit_of: Option<&str>` (last), its doc comment the sentence `/// With \`audit_of\`: an audit of that scan, stored the same way.`, and its `INSERT` the column:

```rust
    let res = sqlx::query(
        "INSERT OR IGNORE INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at,
           finished_at, os_guess, raw_xml, build, audit_of)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
```

  with `.bind(audit_of)` after `.bind(&r.build)`.
- `remove_row`: the table map gets `"scan_result" | "scan_audit" => "scans",` and the `match kind` below it `"scan_result" | "scan_audit" => { … }` (the arm that deletes the scan's ports).

`src/cluster/repl.rs`:

- `waits_for`: add `Record::ScanAudit(a) => Some(a.scan.job_uid.clone()),`.
- `rematerialize`: add `'scan_audit'` to the `kind IN (…)` list (after `'scan_result'`).

`src/store/recorder.rs`, below `record_scan_result`:

```rust
    /// Publish an audit: this node's own scan of `ip`, run to check the
    /// scan `audit_of` of another node (whose job is `job_uid`).
    pub async fn record_scan_audit(
        &self,
        audit_of: &str,
        job_uid: &str,
        ip: &str,
        level: i64,
        started_at: &str,
        res: &ScanResult,
    ) -> Result<()> {
        self.write(vec![Record::ScanAudit(Box::new(
            crate::cluster::record::ScanAuditRec {
                audit_of: audit_of.to_string(),
                scan: ScanResultRec {
                    build: crate::COMMIT.into(),
                    uid: self.uid(),
                    job_uid: job_uid.to_string(),
                    ip: ip.to_string(),
                    level,
                    started_at: started_at.to_string(),
                    finished_at: Some(now_ts()),
                    os_guess: res.os_guess.clone(),
                    raw_xml: Some(zstd::encode_all(res.raw_xml.as_slice(), 3)?),
                    ports: res
                        .ports
                        .iter()
                        .map(|p| PortRec {
                            port: p.port as i64,
                            proto: p.proto.clone(),
                            state: p.state.clone(),
                            service: p.service.clone(),
                            product: p.product.clone(),
                            version: p.version.clone(),
                        })
                        .collect(),
                },
            },
        ))])
        .await
    }
```

Readers of `scans` that mean "the result of the job":

- `src/store/inspect.rs`: `ScanSummary` gains

```rust
    /// The uid of the scan this one audits; None for an ordinary scan.
    pub audit_of: Option<String>,
    /// How the audit compares with the scan it checks, once compared here.
    pub audit_result: Option<String>,
```

  `SCAN_SELECT` selects them: add `s.audit_of, s.audit_result,` after `s.os_guess,`. In the queue query (the `LEFT JOIN scans s ON s.id = (SELECT MAX(x.id) FROM scans x WHERE x.job_id = j.id)` line) the subquery becomes `(SELECT MAX(x.id) FROM scans x WHERE x.job_id = j.id AND x.audit_of IS NULL)`. If another place builds a `ScanSummary` by hand (`grep -n 'ScanSummary {' src tests`), give it `audit_of: None, audit_result: None`.
- `src/scan/arbiter.rs:522`: `"SELECT COUNT(*) FROM scans WHERE job_uid = ? AND audit_of IS NULL"`.
- `src/credits/earn.rs`, `judge`: add `AND s.audit_of IS NULL` after `AND s.origin = j.scanner`.

Export: `src/store/export.rs`, `ScanOut` gains `pub uid: Option<String>,` and `pub audit_of: Option<String>,`; its query selects `s.uid, s.audit_of` after `s.build`. `src/export/mod.rs`, `scan_json`: add after `"level": s.level,`

```rust
        "uid": s.uid,
        "audit_of": s.audit_of,
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib store::data && cargo test --lib cluster::record && cargo test --lib credits::earn && cargo test --lib export:: && cargo test --lib store::inspect && cargo test --lib scan::`
Expected: PASS. If an export test compares a whole scan object, add the two keys to what it expects and say so in the commit message.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add -A src
git commit -m "Credits: the scan_audit record, stored as a marked scan of the same job

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Comparing an audit with the scan, and the audit gate

**Files:**
- Create: `src/credits/audit.rs`
- Modify: `src/credits/mod.rs` (`pub mod audit;`, the loop settles audits), `src/credits/gates.rs` (`standings`), `src/store/hostkeys.rs` (`is_identity` becomes `pub(crate)`)
- Test: unit tests in `src/credits/audit.rs`

**Interfaces:**
- Consumes: `scans.audit_of`, `scans.audit_result` (Task 8); `gates::Standing.audits` (Task 7); `owner::fleet::siblings`; `store::hostkeys::is_identity`.
- Produces (in `credits::audit`):
  - `Outcome { Agrees, Differs, Inconclusive }` (`Debug, Clone, Copy, PartialEq, Eq, Hash`) with `as_str(self) -> &'static str` (`agrees`, `differs`, `inconclusive`) and `parse(s: &str) -> Option<Self>`
  - `Found { pub open_tcp: BTreeSet<u16>, pub keys: BTreeSet<(u16, String, String)> }` (`Default`; a key is `(port, kind, fingerprint)` of an SSH host key or TLS certificate)
  - `compare(original: &Found, audit: &Found) -> Outcome`
  - `found(pool: &SqlitePool, scan_id: i64) -> Result<Found>`
  - `settle(pool: &SqlitePool) -> Result<usize>` (audits compared now)
  - `audits_fail(conclusive: u32, differing: u32) -> bool`
  - `Count { pub scanner: NodeId, pub auditor: NodeId, pub outcome: Outcome, pub n: u32 }`, `counts(pool: &SqlitePool, since_hlc: u64) -> Result<Vec<Count>>`
  - `counted(counts: &[Count], auditors: &[NodeId]) -> HashMap<NodeId, (u32, u32)>` (per audited scanner: conclusive, differing)

- [ ] **Step 1: Write the failing tests**

Create `src/credits/audit.rs`:

```rust
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
use std::collections::{BTreeSet, HashMap};

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
    async fn scan(store: &Store, uid: &str, origin: u8, audit_of: Option<&str>, ports: &[u16]) -> i64 {
        let ip = store.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
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
            sqlx::query("INSERT INTO ports (scan_id, port, proto, state) VALUES (?, ?, 'tcp', 'open')")
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
        assert_eq!(found(&store.pool, orig).await.unwrap(), Found::default());
        assert_eq!(
            found(&store.pool, honest).await.unwrap().open_tcp,
            [22u16, 80].into_iter().collect()
        );

        assert_eq!(settle(&store.pool).await.unwrap(), 4);
        assert_eq!(settle(&store.pool).await.unwrap(), 0, "once");
        let result = |uid: &'static str| async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT audit_result FROM scans WHERE uid = ?")
                .bind(uid)
                .fetch_one(&store.pool)
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
}
```

Add `pub mod audit;` to `src/credits/mod.rs`.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::audit`
Expected: does not compile (`cannot find type Found`, …).

- [ ] **Step 3: Implement**

`src/store/hostkeys.rs`: `pub(crate) fn is_identity(` (it tells SSH host keys and TLS certificates from JA4X and HASSH).

Insert between the imports and the test module of `src/credits/audit.rs`:

```rust
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
        original.keys.contains(k) && original.open_tcp.contains(&k.0) && audit.open_tcp.contains(&k.0)
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
```

`src/credits/gates.rs`, in `standings` before `Ok(out)`:

```rust
    // Audits this node made itself, and those of its own fleet.
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let week = crate::cluster::hlc::wall_ms().saturating_sub(7 * super::DAY_MS) << 16;
    let counts = super::audit::counts(&node.store.pool, week).await?;
    for (scanner, (conclusive, differing)) in super::audit::counted(&counts, &auditors) {
        if super::audit::audits_fail(conclusive, differing) {
            out.entry(scanner).or_default().audits = Some((conclusive, differing));
        }
    }
```

`src/credits/mod.rs`, in `run`, after the `match earn::judge(…) { … }` statement:

```rust
        if let Err(e) = audit::settle(&node.store.pool).await {
            tracing::debug!(?e, "credits: comparing audits failed");
        }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib credits::audit && cargo test --lib credits::gates && cargo test --lib store::hostkeys`
Expected: PASS (3 audit tests, the gate tests, the host-key tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/credits src/store/hostkeys.rs
git commit -m "Credits: audits are compared with the scan they check, and counted

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Scanners run audits

**Files:**
- Modify: `src/credits/audit.rs` (`Picker`), `src/config.rs` (`[credits] audit_share`), `src/scan/mod.rs` (audit jobs), `tests/cluster.rs` (`Opts`, `scan_config`, the test), `deploy/config.example.toml`
- Test: unit tests in `src/credits/audit.rs`, `src/config.rs`; `tests/cluster.rs::audits_of_made_up_results_stop_a_scanners_shares_where_they_count`

**Interfaces:**
- Consumes: `Recorder::record_scan_audit` (Task 8); `audit::{settle, counts}`, the audit gate in `gates::standings` (Task 9); `scan::profiles::builtin` (Task 4); `Source::{preflight, active}`, `guard::evidence`.
- Produces:
  - `config::CreditsConfig { pub audit_share: f64 }` (default 0.05, 0..=1), `Config.credits`
  - `audit::AUDIT_WINDOW_MS: u64 = 1_800_000`
  - `audit::Task { pub scan_uid: String, pub job_uid: String, pub ip: String, pub level: u8, pub deadline_ms: u64 }`
  - `audit::Picker` with `new(share: f64) -> Self`, `poll(&mut self, pool: &SqlitePool, me: &NodeId) -> Result<()>`, `take(&mut self, exclude: &[u8]) -> Option<Task>`, `started(&mut self)`, `started_last_hour(&mut self) -> i64`
  - `scan::audit_argv(level: u8, target: &IpAddr, cfg: &Config, timeout_secs: u64) -> Option<Vec<String>>`

- [ ] **Step 1: Write the failing tests**

Add to the test module of `src/credits/audit.rs`:

```rust
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
        assert_eq!((t.scan_uid.as_str(), t.job_uid.as_str(), t.level), ("fresh", "job", 1));
        assert_eq!(t.ip, "203.0.113.9");
        assert!(all.take(&[4]).is_none());
        assert_eq!(all.take(&[]).unwrap().scan_uid, "big");
        assert!(all.take(&[]).is_none(), "not its own, not an old one, not an audit");
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
```

Add to the test module of `src/config.rs`:

```rust
    #[test]
    fn the_audit_share_defaults_to_five_percent_and_is_a_share() {
        let base = "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n";
        let cfg: Config = toml::from_str(base).unwrap();
        assert_eq!(cfg.credits.audit_share, 0.05);
        let cfg: Config = toml::from_str(&format!("{base}[credits]\naudit_share = 0\n")).unwrap();
        assert_eq!(cfg.credits.audit_share, 0.0);
        for bad in ["-0.1", "1.5"] {
            let cfg: Config =
                toml::from_str(&format!("{base}[credits]\naudit_share = {bad}\n")).unwrap();
            assert!(cfg.credits.check().is_err(), "{bad}");
        }
    }
```

In `tests/cluster.rs`:

- `struct Opts` gains `/// Share of other nodes' fresh scans this scanner audits.\n    audit_share: f64,`; `DEFAULT` gains `audit_share: 0.0,`.
- `fn scan_config(never_scan: &[String], audit_share: f64)`: the TOML gains `\n[credits]\naudit_share = {audit_share}\n` at its end; both callers in `boot_in` pass `o.audit_share`.

Append to `tests/cluster.rs`:

```rust
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
                all &= count(n, "SELECT COUNT(*) FROM scans WHERE audit_of IS NOT NULL").await == by_f
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
            count(n, "SELECT COUNT(*) FROM scans WHERE audit_result = 'differs'").await,
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
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::audit`
Expected: does not compile (`cannot find type Picker`).

- [ ] **Step 3: Config**

`src/config.rs`: add to `struct Config`, after the `enrichment` field:

```rust
    /// Lookup credits (cluster only).
    #[serde(default)]
    pub credits: CreditsConfig,
```

and below `EnrichmentConfig`'s `impl Default`:

```rust
/// `[credits]`: this node's part in the cluster's credit system.
#[derive(Debug, Clone, Deserialize)]
pub struct CreditsConfig {
    /// Share of the other nodes' fresh scans a scanner runs again to check
    /// them (0 to 1; 0: this node audits nothing).
    #[serde(default = "default_audit_share")]
    pub audit_share: f64,
}

fn default_audit_share() -> f64 {
    0.05
}

impl Default for CreditsConfig {
    fn default() -> Self {
        Self {
            audit_share: default_audit_share(),
        }
    }
}

impl CreditsConfig {
    pub fn check(&self) -> anyhow::Result<()> {
        if !(0.0..=1.0).contains(&self.audit_share) {
            anyhow::bail!("credits.audit_share must be between 0 and 1");
        }
        Ok(())
    }
}
```

In `Config::load`'s validation, next to the `enrichment.refresh_after_days` check: `self.credits.check()?;`. In `OPTIONAL_KEYS` add `("credits", "audit_share", "0.05"),`.

`deploy/config.example.toml`, after the `[enrichment]` block:

```toml
# [credits]
# # Cluster only. A scanner runs this share of the other nodes' fresh scans
# # again to check them (audits earn nothing; 0 = audit nothing).
# audit_share = 0.05
```

- [ ] **Step 4: The picker**

Append to `src/credits/audit.rs` (before the test module), and add `use std::collections::VecDeque;` and `use std::time::Instant;` to the imports:

```rust
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
        let rows: Vec<(i64, String, String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT s.id, s.uid, s.job_uid, i.ip, s.level, s.finished_at
             FROM scans s JOIN ips i ON i.id = s.ip_id
             WHERE s.id > ? AND s.audit_of IS NULL AND s.uid IS NOT NULL
               AND s.job_uid IS NOT NULL AND s.origin IS NOT NULL AND s.origin != ?
             ORDER BY s.id LIMIT 500",
        )
        .bind(last)
        .bind(&me.0[..])
        .fetch_all(pool)
        .await?;
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
        // Rows of this node's own scans and of audits move the mark too.
        let max: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM scans")
            .fetch_one(pool)
            .await?;
        self.last_id = Some(max.unwrap_or(0).max(self.last_id.unwrap_or(0)));
        Ok(())
    }

    /// The next audit to start now: still in time, and not of a level in
    /// `exclude` (the scanner is at its share of that level).
    pub fn take(&mut self, exclude: &[u8]) -> Option<Task> {
        let now = hlc::wall_ms();
        self.queue.retain(|t| t.deadline_ms > now);
        let i = self.queue.iter().position(|t| !exclude.contains(&t.level))?;
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
```

- [ ] **Step 5: Audits as jobs of the scan workers**

`src/scan/mod.rs`:

1. Split `nmap_argv`. Its body from `let host_timeout = host_timeout_secs(timeout_secs);` through `Some(argv)` moves into

```rust
/// `argv` (a level's list) with what every run adds: the timeouts, the
/// rate floor of level 4, `-6`, XML on standard output and the target.
fn complete(
    mut argv: Vec<String>,
    level: u8,
    target: IpAddr,
    cfg: &Config,
    timeout_secs: u64,
) -> Vec<String> {
    // … the moved lines, ending in `argv` instead of `Some(argv)` …
}
```

   and `nmap_argv` becomes

```rust
    let target = crate::net::canonical(*target);
    let argv = cfg.default_level_argv(level)?;
    Some(complete(argv, level, target, cfg, timeout_secs))
```

   (keep its comment about IPv4-mapped addresses). Below it:

```rust
/// The arguments of an audit: the built-in list of the level, whatever
/// `scan.level_argv` says, so the audit is comparable.
pub fn audit_argv(
    level: u8,
    target: &IpAddr,
    cfg: &Config,
    timeout_secs: u64,
) -> Option<Vec<String>> {
    let target = crate::net::canonical(*target);
    let argv = profiles::builtin(level, cfg.scan.level4_udp)?;
    Some(complete(argv, level, target, cfg, timeout_secs))
}
```

2. `enum Job` gains

```rust
    /// Another node's scan, run again here to check it (`credits::audit`).
    /// No arbiter and no lease: nobody waits for it.
    Audit {
        /// The uid of the audited scan, and its job's.
        of: String,
        job_uid: String,
        ip: IpAddr,
        level: u8,
        started_at: String,
    },
```

   and both `match self` in `impl Job` take it in: `Job::Local { ip, .. } | Job::Granted { ip, .. } | Job::Audit { ip, .. } => *ip` and the same for `level`.

3. `struct Source` gains `/// The scans of other nodes this scanner audits.\n    audits: tokio::sync::Mutex<crate::credits::audit::Picker>,`; `Source::new` initializes it with `audits: tokio::sync::Mutex::new(crate::credits::audit::Picker::new(cfg.credits.audit_share)),` (before `rec,`).

4. In `impl Source`, below `acquire`:

```rust
    /// The next audit this scanner can start: an audit obeys everything a
    /// scan does (never_scan, members' addresses, Tor exits, crawlers, the
    /// evidence held here) except the rescan cooldown.
    async fn next_audit(&self, exclude: &[u8]) -> anyhow::Result<Option<Job>> {
        let Some(node) = self.node() else {
            return Ok(None);
        };
        let pool = &node.store.pool;
        let mut picker = self.audits.lock().await;
        picker.poll(pool, &node.id()).await?;
        while let Some(t) = picker.take(exclude) {
            let Ok(ip) = t.ip.parse::<IpAddr>() else {
                continue;
            };
            let key = crate::net::canonical(ip);
            if self.active.lock().unwrap().contains_key(&key) {
                continue;
            }
            let now = crate::store::data::now_ts();
            if let Some(r) = self.preflight(&ip, &t.ip, &now).await? {
                debug!(target = %ip, why = r.reason(), "audit not run");
                continue;
            }
            let ev = guard::evidence(pool, &t.ip, &self.origins, Some(self.classifier)).await?;
            if ev.allowed_level(&self.cfg.scan.safety) < t.level {
                debug!(target = %ip, level = t.level, "audit not run: the requests held here do not back it");
                continue;
            }
            picker.started();
            self.active.lock().unwrap().insert(key, t.level);
            return Ok(Some(Job::Audit {
                of: t.scan_uid,
                job_uid: t.job_uid,
                ip,
                level: t.level,
                started_at: now,
            }));
        }
        Ok(None)
    }
```

5. `finish`: the first statement becomes

```rust
        if let Job::Granted { ip, .. } | Job::Audit { ip, .. } = job {
```

   and the `match (job, self.node())` gets, after the `(Job::Local { id, .. }, _)` arm:

```rust
            (
                Job::Audit {
                    of,
                    job_uid,
                    ip,
                    level,
                    started_at,
                },
                _,
            ) => match outcome {
                Outcome::Done(res) => {
                    if let Err(e) = self
                        .rec
                        .record_scan_audit(of, job_uid, &ip.to_string(), *level as i64, started_at, &res)
                        .await
                    {
                        warn!(audit_of = %of, ?e, "could not record audit");
                    }
                }
                // A failed audit says nothing: it is not published.
                Outcome::Failed(e) => debug!(audit_of = %of, error = %e, "audit scan failed"),
                Outcome::Abandoned => {}
            },
```

6. `queue_row`: the `let id = match job { … }` gets the arm `Job::Audit { .. } => return None,`.

7. `run_workers`:

   - the rate cap counts audits: replace `Ok(n) if n >= p.max_scans_per_hour => break,` by

```rust
                Ok(n)
                    if n + source.audits.lock().await.started_last_hour()
                        >= p.max_scans_per_hour =>
                {
                    break;
                }
```

   - audits run before queued jobs: replace the `let job = match source.acquire(&exclude).await { … };` statement by

```rust
            let audit = match source.next_audit(&exclude).await {
                Ok(a) => a,
                Err(e) => {
                    warn!(?e, "audit poll failed");
                    None
                }
            };
            let job = match audit {
                Some(job) => job,
                None => match source.acquire(&exclude).await {
                    Ok(Some(job)) => job,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(?e, "queue poll failed");
                        break;
                    }
                },
            };
```

   - the arguments: replace `let argv = nmap_argv(job.level(), &job.ip(), &cfg, limit);` by

```rust
            let argv = match &job {
                Job::Audit { .. } => audit_argv(job.level(), &job.ip(), &cfg, limit),
                _ => nmap_argv(job.level(), &job.ip(), &cfg, limit),
            };
```

`run_scan` needs no change: only a granted job renews a lease.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib credits::audit && cargo test --lib config:: && cargo test --lib scan:: && cargo test --test cluster audits_of_made_up_results && cargo test --test cluster scanners_share_a_listeners_queue`
Expected: PASS. The audit test takes about 30 s (sixteen scans and their audits, one start a second per scanner).

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add src/credits/audit.rs src/config.rs src/scan/mod.rs tests/cluster.rs deploy/config.example.toml
git commit -m "Credits: scanners run a share of the other nodes' scans again

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Part D: paying for lookups

### Task 11: The on-demand share of each provider budget

The limit that holds whatever happens to the credit system: paid lookups take at most `on_demand_share` of each API provider's budget. Its counter, and the surge that follows a day on which it ran out, live with the budget counters in `intel_meta`.

**Files:**
- Create: `src/credits/share.rs`
- Modify: `src/credits/mod.rs` (`pub mod share;`), `src/config.rs` (`enrichment.on_demand_share`), `src/intel/provider.rs` (`Provider::per_day`), `src/intel/api.rs` (its implementation), `src/cluster/mod.rs` (`Node` keeps the shares), `src/lib.rs` (set them), `deploy/config.example.toml`
- Test: unit tests in `src/credits/share.rs`, `src/intel/api.rs`, `src/config.rs`

**Interfaces:**
- Produces:
  - `EnrichmentConfig.on_demand_share: f64` (default 0.2, 0..=1)
  - `Provider::per_day(&self) -> Option<f64>` (the provider's budget in requests a day; None: no budget)
  - `credits::share::Shares` (`Clone`) with `new(store: Store, share: f64) -> Self`, `allowance(&self, p: &dyn Provider) -> Option<u32>`, `used(&self, provider: &str) -> Result<u32>`, `spent(&self, p: &dyn Provider) -> Result<bool>`, `take(&self, p: &dyn Provider) -> Result<bool>`, `surge(&self, p: &dyn Provider) -> Result<u32>`, and for tests the same with the day passed in: `used_on`, `take_on`, `surge_on(&self, p, day: NaiveDate)`
  - `share::SURGE_MAX: u32 = 8`
  - `Node::set_lookup_shares(&self, s: Shares)`, `Node::lookup_shares(&self) -> Option<&Shares>`

- [ ] **Step 1: Write the failing tests**

Create `src/credits/share.rs`:

```rust
//! The on-demand share: the part of each API provider's budget that paid
//! lookups may use. An operator who mints credits out of nothing can
//! still take no more than this from any server. Counted per provider and
//! UTC day; a day on which the share ran out makes the provider cost
//! double the next day (the surge), a day on which it did not halves that
//! again.
use crate::intel::provider::Provider;
use crate::store::Store;
use anyhow::Result;
use chrono::{Duration, NaiveDate, Utc};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::provider::Finding;
    use futures::future::BoxFuture;

    /// A provider with a budget of `per_day` requests a day.
    struct Budget(&'static str, Option<f64>);

    impl Provider for Budget {
        fn name(&self) -> &'static str {
            self.0
        }
        fn ready(&self) -> bool {
            true
        }
        fn per_day(&self) -> Option<f64> {
            self.1
        }
        fn lookup<'a>(&'a self, _ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
            Box::pin(async { vec![] })
        }
    }

    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, d).unwrap()
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn the_share_is_counted_per_provider_and_day_and_survives_a_restart() {
        let (store, _dir) = store().await;
        let s = Shares::new(store.clone(), 0.2);
        // A daily budget of 12: two on-demand lookups (2.4, rounded down).
        let daily = Budget("abuseipdb", Some(12.0));
        // A weekly budget of 50 is about 7.14 a day: one.
        let weekly = Budget("greynoise-community", Some(50.0 / 7.0));
        let none = Budget("maxmind-geolite2", None);
        assert_eq!(s.allowance(&daily), Some(2));
        assert_eq!(s.allowance(&weekly), Some(1));
        assert_eq!(s.allowance(&none), None, "no budget, no limit");

        assert!(s.take_on(&daily, day(6)).await.unwrap());
        assert!(!s.spent_on(&daily, day(6)).await.unwrap());
        assert!(s.take_on(&daily, day(6)).await.unwrap());
        assert!(s.spent_on(&daily, day(6)).await.unwrap());
        assert!(!s.take_on(&daily, day(6)).await.unwrap(), "spent");
        assert_eq!(s.used_on("abuseipdb", day(6)).await.unwrap(), 2);
        // Another provider, another day: their own counts.
        assert!(s.take_on(&weekly, day(6)).await.unwrap());
        assert!(!s.take_on(&weekly, day(6)).await.unwrap());
        assert!(s.take_on(&daily, day(7)).await.unwrap());
        // A provider without a budget is never spent and not counted.
        for _ in 0..5 {
            assert!(s.take_on(&none, day(6)).await.unwrap());
        }
        assert_eq!(s.used_on("maxmind-geolite2", day(6)).await.unwrap(), 0);
        // A restart does not hand the share out again.
        let again = Shares::new(store.clone(), 0.2);
        assert!(!again.take_on(&daily, day(6)).await.unwrap());
        // No share at all: nothing is served on demand.
        let closed = Shares::new(store, 0.0);
        assert_eq!(closed.allowance(&daily), Some(0));
        assert!(closed.spent_on(&daily, day(9)).await.unwrap());
        assert!(!closed.take_on(&daily, day(9)).await.unwrap());
    }

    #[tokio::test]
    async fn the_surge_doubles_after_a_day_the_share_ran_out_and_halves_after_one_it_did_not() {
        let (store, _dir) = store().await;
        let s = Shares::new(store.clone(), 0.5);
        let p = Budget("shodan", Some(2.0));
        let spend = |d: u32| {
            let (s, p) = (&s, &p);
            async move {
                assert!(s.take_on(p, day(d)).await.unwrap());
            }
        };
        assert_eq!(s.surge_on(&p, day(1)).await.unwrap(), 1);
        spend(1).await;
        assert_eq!(s.surge_on(&p, day(1)).await.unwrap(), 1, "the same day");
        assert_eq!(s.surge_on(&p, day(2)).await.unwrap(), 2);
        spend(2).await;
        spend(3).await;
        // Read only on day 4: both days are taken into account.
        assert_eq!(s.surge_on(&p, day(4)).await.unwrap(), 8);
        spend(4).await;
        assert_eq!(s.surge_on(&p, day(5)).await.unwrap(), 8, "at most 8");
        // A restart keeps it.
        let again = Shares::new(store, 0.5);
        assert_eq!(again.surge_on(&p, day(5)).await.unwrap(), 8);
        // Two days on which it did not run out.
        assert_eq!(again.surge_on(&p, day(7)).await.unwrap(), 2);
        assert_eq!(again.surge_on(&p, day(20)).await.unwrap(), 1, "at least 1");
        // No budget, no surge.
        let free = Budget("maxmind-geolite2", None);
        assert_eq!(again.surge_on(&free, day(20)).await.unwrap(), 1);
    }
}
```

Add `pub mod share;` to `src/credits/mod.rs`.

Add to the test module of `src/intel/api.rs`:

```rust
    #[tokio::test]
    async fn the_budget_per_day_is_the_tightest_limit() {
        struct Svc;
        impl Service for Svc {
            fn name(&self) -> &'static str {
                "abuseipdb"
            }
            fn request(&self, client: &reqwest::Client, _ip: &str) -> reqwest::RequestBuilder {
                client.get("http://127.0.0.1:9/")
            }
            fn parse(&self, _status: StatusCode, _body: &[u8]) -> Option<serde_json::Value> {
                None
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let day = |max| Limit {
            period: Period::Day,
            max,
        };
        let week = |max| Limit {
            period: Period::Week,
            max,
        };
        let p = |limits| ApiProvider::new(Svc, store.clone(), limits, 30.0);
        assert_eq!(p(vec![]).per_day(), None, "no local limit");
        assert_eq!(p(vec![day(1000)]).per_day(), Some(1000.0));
        assert_eq!(p(vec![week(70)]).per_day(), Some(10.0));
        assert_eq!(p(vec![day(25), week(70)]).per_day(), Some(10.0));
    }
```

Add to the test module of `src/config.rs`:

```rust
    #[test]
    fn the_on_demand_share_defaults_to_a_fifth() {
        let base = "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n";
        let cfg: Config = toml::from_str(base).unwrap();
        assert_eq!(cfg.enrichment.on_demand_share, 0.2);
        assert_eq!(cfg.enrichment.refresh_after_days, 30.0);
        let cfg: Config =
            toml::from_str(&format!("{base}[enrichment]\non_demand_share = 1.5\n")).unwrap();
        assert!(cfg.enrichment.check().is_err());
    }
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::share`
Expected: does not compile (`cannot find type Shares`, `no method named per_day`).

- [ ] **Step 3: Implement**

`src/intel/provider.rs`, in `trait Provider` after `status`:

```rust
    /// The provider's budget in requests a day (a weekly budget divided by
    /// 7; the tightest when it has several). None: no budget here, as for
    /// a local database.
    fn per_day(&self) -> Option<f64> {
        None
    }
```

`src/intel/api.rs`, in `impl<S: Service> Provider for ApiProvider<S>`:

```rust
    fn per_day(&self) -> Option<f64> {
        self.limits
            .iter()
            .map(|l| match l.period {
                Period::Day => l.max as f64,
                Period::Week => l.max as f64 / 7.0,
            })
            .reduce(f64::min)
    }
```

`src/config.rs`: `EnrichmentConfig` gains

```rust
    /// The part of each API provider's budget that paid on-demand lookups
    /// may use (0 to 1). Whatever happens to credits, no more than this is
    /// taken from this node's budgets.
    #[serde(default = "default_on_demand_share")]
    pub on_demand_share: f64,
```

with `fn default_on_demand_share() -> f64 { 0.2 }`, the field in its `impl Default` (`on_demand_share: default_on_demand_share(),`), and

```rust
impl EnrichmentConfig {
    pub fn check(&self) -> anyhow::Result<()> {
        if !(0.0..=1.0).contains(&self.on_demand_share) {
            anyhow::bail!("enrichment.on_demand_share must be between 0 and 1");
        }
        Ok(())
    }
}
```

called from `Config::load` next to `self.credits.check()?;`. `OPTIONAL_KEYS`: `("enrichment", "on_demand_share", "0.2"),`.

`deploy/config.example.toml`, in the `[enrichment]` block after `refresh_after_days = 30`:

```toml
# Cluster only: the part of each API provider's budget that paid lookups of
# other members (and your own on-demand lookups) may use. 0.2 = a fifth.
# on_demand_share = 0.2
```

Insert between the imports and the test module of `src/credits/share.rs`:

```rust
/// The surge of a provider is at most this.
pub const SURGE_MAX: u32 = 8;
/// Counters of days older than this are deleted.
const KEEP_DAYS: i64 = 8;

/// This node's on-demand shares.
#[derive(Clone)]
pub struct Shares {
    store: Store,
    share: f64,
}

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

fn used_key(provider: &str, day: NaiveDate) -> String {
    format!("ondemand:{provider}:{day}")
}

impl Shares {
    pub fn new(store: Store, share: f64) -> Self {
        Self {
            store,
            share: share.clamp(0.0, 1.0),
        }
    }

    /// On-demand lookups of `p` this node serves per UTC day: its budget
    /// times the share, rounded down. None: `p` has no budget, so no limit.
    pub fn allowance(&self, p: &dyn Provider) -> Option<u32> {
        p.per_day()
            .map(|d| (d * self.share).floor().clamp(0.0, u32::MAX as f64) as u32)
    }

    pub async fn used_on(&self, provider: &str, day: NaiveDate) -> Result<u32> {
        Ok(self
            .store
            .intel_get(&used_key(provider, day))
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    pub async fn used(&self, provider: &str) -> Result<u32> {
        self.used_on(provider, today()).await
    }

    pub async fn spent_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<bool> {
        Ok(match self.allowance(p) {
            None => false,
            Some(a) => self.used_on(p.name(), day).await? >= a,
        })
    }

    /// Whether today's share of `p` is used up.
    pub async fn spent(&self, p: &dyn Provider) -> Result<bool> {
        self.spent_on(p, today()).await
    }

    /// Count one on-demand lookup of `p`, unless its share of the day is
    /// spent (false). Written through, so a restart does not hand the
    /// share out twice.
    pub async fn take_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<bool> {
        let Some(allowance) = self.allowance(p) else {
            return Ok(true);
        };
        if allowance == 0 {
            return Ok(false);
        }
        let taken = sqlx::query(
            "INSERT INTO intel_meta (key, value) VALUES (?1, '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
             WHERE CAST(value AS INTEGER) < ?2",
        )
        .bind(used_key(p.name(), day))
        .bind(allowance as i64)
        .execute(&self.store.pool)
        .await?
        .rows_affected();
        Ok(taken == 1)
    }

    pub async fn take(&self, p: &dyn Provider) -> Result<bool> {
        self.take_on(p, today()).await
    }

    /// The surge of `p` on `day`: 1 at first; doubled (up to
    /// [`SURGE_MAX`]) for every day since it was last looked at on which
    /// the share ran out, halved (down to 1) for every day on which it did
    /// not. Kept with the budget counters.
    pub async fn surge_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<u32> {
        let Some(allowance) = self.allowance(p) else {
            return Ok(1);
        };
        let key = format!("surge:{}", p.name());
        let stored = self.store.intel_get(&key).await?;
        let (mut factor, mut seen) = stored
            .as_deref()
            .and_then(|v| v.split_once('|'))
            .and_then(|(f, d)| Some((f.parse::<u32>().ok()?, d.parse::<NaiveDate>().ok()?)))
            .unwrap_or((1, day));
        factor = factor.clamp(1, SURGE_MAX);
        // Days long past all count as "did not run out": start from 1.
        if (day - seen).num_days() > 30 {
            (factor, seen) = (1, day);
        }
        while seen < day {
            let ran_out = allowance > 0 && self.used_on(p.name(), seen).await? >= allowance;
            factor = if ran_out {
                (factor * 2).min(SURGE_MAX)
            } else {
                (factor / 2).max(1)
            };
            seen += Duration::days(1);
        }
        let now = format!("{factor}|{day}");
        if stored.as_deref() != Some(now.as_str()) {
            self.store.intel_set(&key, &now).await?;
            // The counters of days no surge looks at any more.
            sqlx::query("DELETE FROM intel_meta WHERE key LIKE ? AND key < ?")
                .bind(format!("ondemand:{}:%", p.name()))
                .bind(used_key(p.name(), day - Duration::days(KEEP_DAYS)))
                .execute(&self.store.pool)
                .await?;
        }
        Ok(factor)
    }

    pub async fn surge(&self, p: &dyn Provider) -> Result<u32> {
        self.surge_on(p, today()).await
    }
}
```

`src/cluster/mod.rs`: in `struct Node`, after the `lookup_providers` field:

```rust
    /// The on-demand share of each provider budget (see `credits::share`).
    lookup_shares: std::sync::OnceLock<crate::credits::share::Shares>,
```

initialized with `lookup_shares: Default::default(),`, and below `lookup_providers()`:

```rust
    pub fn set_lookup_shares(&self, s: crate::credits::share::Shares) {
        let _ = self.lookup_shares.set(s);
    }

    pub fn lookup_shares(&self) -> Option<&crate::credits::share::Shares> {
        self.lookup_shares.get()
    }
```

`src/lib.rs`: where `node.set_lookup_providers(…)` is called, add directly below it

```rust
        node.set_lookup_shares(credits::share::Shares::new(
            store.clone(),
            cfg.enrichment.on_demand_share,
        ));
```

(use the names of the store and the node in scope at that place: `grep -n set_lookup_providers src/lib.rs`).

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib credits::share && cargo test --lib intel::api && cargo test --lib config::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/credits/share.rs src/credits/mod.rs src/config.rs src/intel/provider.rs src/intel/api.rs src/cluster/mod.rs src/lib.rs deploy/config.example.toml
git commit -m "Credits: the on-demand share of each provider budget, and its surge

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: Scan capacity and the price of a lookup

**Files:**
- Create: `src/credits/price.rs`
- Modify: `src/credits/mod.rs` (`pub mod price;`, the loop refreshes the table hourly), `src/cluster/status.rs` (`Heartbeat.on_demand`, `Heartbeat.prices`, every `Heartbeat { … }` literal), `src/cluster/repl.rs` (two `Heartbeat { … }` literals in tests), `src/cluster/mod.rs` (`Node` keeps the table), `tests/cluster.rs`
- Test: unit tests in `src/credits/price.rs`; `tests/cluster.rs::announced_prices_follow_the_clusters_earnings`

**Interfaces:**
- Consumes: `credits::book_fresh`, `Book::earned_per_day`, `gates::Standing::left_out` (Task 7); `share::Shares::{allowance, surge}` (Task 11); `Node::{lookup_providers, lookup_shares, live_members, dial_address}`; `scan::pace::DEFAULT_SCAN_SECS`; `scan::arbiter::LIVE_WINDOW`.
- Produces (in `credits::price`):
  - `UNIT_MIN: Mc = 10`, `UNIT_MAX: Mc = 100_000`
  - `weight_milli(provider: &str) -> u32`
  - `Scanner { pub node: NodeId, pub max_workers: u32, pub max_scans_per_hour: i64, pub mean_secs: Option<f64>, pub jobs_7d: u32, pub ended_24h: u32 }`
  - `Limit { Workers, PerHour }`, `ScannerCapacity { pub node: NodeId, pub can_do: f64, pub did: f64, pub limited_by: Limit }`, `Capacity { pub scanners: Vec<ScannerCapacity>, pub per_day: f64, pub used_per_day: f64, pub utilization: f64 }`
  - `capacity(scanners: &[Scanner]) -> Capacity`, `load(utilization: f64) -> f64`, `unit(earned_per_day: Mc, lookups_per_day: f64, utilization: f64) -> Option<Mc>`, `price(provider: &str, unit: Option<Mc>, surge: u32) -> u32`
  - `Offer { pub provider: String, pub price_mc: u32, pub surge: u32, pub on_demand: Option<u32> }`
  - `Table { pub at_ms: u64, pub earned_per_day: Mc, pub lookups_per_day: f64, pub capacity: Capacity, pub load: f64, pub unit: Option<Mc>, pub offers: Vec<Offer> }` (`Default`) with `price_of(&self, provider: &str) -> Option<u32>`
  - `scanners(node: &Node, left_out: &HashSet<NodeId>) -> Result<Vec<Scanner>>`, `refresh(node: &Node) -> Result<Arc<Table>>`
  - `Heartbeat.on_demand: Vec<(String, u32)>`, `Heartbeat.prices: Vec<(String, u32)>`
  - `Node::price_table(&self) -> Arc<price::Table>`, `Node::set_price_table(&self, t: Arc<price::Table>)`

- [ ] **Step 1: Write the failing tests**

Create `src/credits/price.rs`:

```rust
//! What a lookup costs. A fixed price fits one cluster size only, so the
//! price follows the two things that set the balance: what the cluster
//! earns (credits a day, read from the log) and what it can serve
//! (on-demand lookups a day, announced in heartbeats). The scanners' load
//! moves it by at most a factor of 2 either way, and each server corrects
//! for what the formula cannot know with its own surge.
use super::Mc;
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::intel;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn scanner(n: u8, workers: u32, per_hour: i64, mean: Option<f64>, jobs: u32, day: u32) -> Scanner {
        Scanner {
            node: id(n),
            max_workers: workers,
            max_scans_per_hour: per_hour,
            mean_secs: mean,
            jobs_7d: jobs,
            ended_24h: day,
        }
    }

    #[test]
    fn the_load_factor_runs_from_a_half_to_double() {
        assert_eq!(load(0.0), 0.5);
        assert_eq!(load(0.5), 1.0);
        assert_eq!(load(1.0), 2.0);
        assert_eq!(load(7.0), 2.0, "bounded");
        assert_eq!(load(-1.0), 0.5);
    }

    #[test]
    fn scan_capacity_is_bound_by_workers_or_by_the_hourly_limit() {
        // 2 workers at 360 s a scan do 20 an hour; the limit is 30.
        let by_workers = scanner(1, 2, 30, Some(360.0), 10, 48);
        // 4 workers at 60 s could do 240 an hour; the limit is 30.
        let by_limit = scanner(2, 4, 30, Some(60.0), 50, 240);
        let c = capacity(&[by_workers.clone(), by_limit.clone()]);
        assert_eq!((c.scanners[0].can_do, c.scanners[0].limited_by), (20.0, Limit::Workers));
        assert_eq!((c.scanners[1].can_do, c.scanners[1].limited_by), (30.0, Limit::PerHour));
        assert_eq!((c.scanners[0].did, c.scanners[1].did), (2.0, 10.0));
        assert_eq!((c.per_day, c.used_per_day), (1200.0, 288.0));
        assert_eq!(c.utilization, 0.24);

        // Fewer than 5 jobs: the cluster's mean scan time (here 120 s over
        // 2 + 58 jobs: 2×600 + 58×(6000/58)).
        let new = scanner(3, 1, 3600, Some(600.0), 2, 0);
        let old = scanner(4, 1, 3600, Some(6000.0 / 58.0), 58, 0);
        let c = capacity(&[new, old]);
        assert_eq!(c.scanners[0].can_do, 30.0);
        // No job anywhere: the default scan time.
        let c = capacity(&[scanner(5, 1, 3600, None, 0, 0)]);
        assert_eq!(c.scanners[0].can_do, 3600.0 / crate::scan::pace::DEFAULT_SCAN_SECS);
        // A paused scanner can do nothing; with no capacity at all the
        // cluster counts as saturated.
        let c = capacity(&[scanner(6, 0, 30, Some(60.0), 9, 3), scanner(7, 2, 0, None, 0, 0)]);
        assert_eq!((c.per_day, c.utilization), (0.0, 1.0));
        assert_eq!(capacity(&[]).utilization, 1.0);
        // More done than the current pace allows: at most 1.
        let c = capacity(&[scanner(8, 1, 1, Some(60.0), 99, 99)]);
        assert_eq!(c.utilization, 1.0);
    }

    #[test]
    fn the_unit_price_is_what_the_days_earnings_buy_of_the_days_capacity() {
        // The spec's example: 20 credits a day, 200 weighted lookups a day.
        assert_eq!(unit(20_000, 200.0, 0.5), Some(200));
        assert_eq!(unit(20_000, 200.0, 0.0), Some(100), "idle scanners: half");
        assert_eq!(unit(20_000, 200.0, 1.0), Some(400), "saturated: double");
        assert_eq!(price(intel::ABUSEIPDB, Some(200), 1), 200);
        assert_eq!(price(intel::SHODAN, Some(200), 1), 200);
        assert_eq!(price(intel::GREYNOISE, Some(200), 1), 200);
        assert_eq!(price(intel::INTERNETDB, Some(200), 1), 50);
        assert_eq!(price(intel::MAXMIND, Some(200), 1), 50);
        assert_eq!(price(intel::TOR, Some(200), 8), 0, "free");
        assert_eq!(price(intel::ABUSEIPDB, Some(200), 4), 800, "surge");
        // Doubling the earnings doubles the price; doubling the capacity
        // halves it.
        assert_eq!(unit(40_000, 200.0, 0.5), Some(400));
        assert_eq!(unit(20_000, 400.0, 0.5), Some(100));
        // No earnings yet: the floor. Far too many: the ceiling.
        assert_eq!(unit(0, 200.0, 0.5), Some(UNIT_MIN));
        assert_eq!(unit(u64::MAX / 4, 1.0, 1.0), Some(UNIT_MAX));
        // Nobody announces capacity: no unit; what has no budget is priced
        // from the floor, and a price is never less than 1 mc.
        assert_eq!(unit(20_000, 0.0, 0.5), None);
        assert_eq!(price(intel::MAXMIND, None, 1), 2);
        assert_eq!(price(intel::MAXMIND, Some(1), 1), 1);
    }

    #[test]
    fn a_table_knows_what_it_offers() {
        let t = Table {
            offers: vec![
                Offer {
                    provider: intel::ABUSEIPDB.into(),
                    price_mc: 200,
                    surge: 1,
                    on_demand: Some(200),
                },
                Offer {
                    provider: intel::MAXMIND.into(),
                    price_mc: 50,
                    surge: 1,
                    on_demand: None,
                },
            ],
            ..Default::default()
        };
        assert_eq!(t.price_of(intel::ABUSEIPDB), Some(200));
        assert_eq!(t.price_of(intel::SHODAN), None);
        let (on_demand, prices) = t.announced();
        assert_eq!(on_demand, [(intel::ABUSEIPDB.to_string(), 200)]);
        assert_eq!(prices.len(), 2);
    }
}
```

Add `pub mod price;` to `src/credits/mod.rs`.

Append to `tests/cluster.rs`:

```rust
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
    n.node.set_providers(list.iter().map(|(n, _)| n.to_string()).collect());
    n.node.set_lookup_providers(providers);
    n.node
        .set_lookup_shares(peephole::credits::share::Shares::new(n.store.clone(), share));
    asked
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
    serves(&na, &[("abuseipdb", Some(1000.0)), ("maxmind-geolite2", None)], 0.2);
    // 112 scans at 1.25 credits in a week: 20 credits a day.
    grant_scans(&[&na], a.id, 112).await;
    let t = price::refresh(&na.node).await.unwrap();
    assert_eq!((t.earned_per_day, t.lookups_per_day), (20_000, 200.0));
    // No scanner runs: no capacity, which counts as saturated (double).
    assert_eq!((t.capacity.utilization, t.load, t.unit), (1.0, 2.0, Some(400)));
    assert_eq!(t.price_of("abuseipdb"), Some(400));
    assert_eq!(t.price_of("maxmind-geolite2"), Some(100));
    let seen = |price: u32| {
        nb.status.known(&a.id).is_some_and(|k| {
            k.hb.prices.contains(&("abuseipdb".to_string(), price))
                && k.hb.on_demand == vec![("abuseipdb".to_string(), 200)]
        })
    };
    eventually("b reads a's prices from its heartbeat", || async { seen(400) }).await;
    // Twice the earnings, twice the price.
    grant_scans(&[&na], a.id, 112).await;
    let t = price::refresh(&na.node).await.unwrap();
    assert_eq!(t.price_of("abuseipdb"), Some(800));
    eventually("b sees the new price", || async { seen(800) }).await;
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::price`
Expected: does not compile (`cannot find function load`, `cannot find type Scanner`, …).

- [ ] **Step 3: Implement the pure part**

Insert between the imports and the test module of `src/credits/price.rs`:

```rust
/// The unit price stays within 0.01 and 100 credits.
pub const UNIT_MIN: Mc = 10;
pub const UNIT_MAX: Mc = 100_000;

/// The weight of a provider in thousandths: a keyed API 1, Shodan
/// InternetDB and GeoLite2 a quarter, the Tor exit list nothing (free).
pub fn weight_milli(provider: &str) -> u32 {
    match provider {
        intel::TOR => 0,
        intel::MAXMIND | intel::INTERNETDB => 250,
        _ => 1000,
    }
}

/// What is known of one scanner: its pace as its heartbeat announces it,
/// and its finished jobs as the replicated queue holds them.
#[derive(Debug, Clone, PartialEq)]
pub struct Scanner {
    pub node: NodeId,
    pub max_workers: u32,
    pub max_scans_per_hour: i64,
    /// Mean worker time of the jobs it ended (done or failed) in the last
    /// 7 days; None without one.
    pub mean_secs: Option<f64>,
    pub jobs_7d: u32,
    /// Jobs and audits it ended in the last 24 hours.
    pub ended_24h: u32,
}

/// Which of its two settings binds a scanner.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Limit {
    Workers,
    PerHour,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScannerCapacity {
    pub node: NodeId,
    /// Scans an hour it can do, and did over the last 24 hours.
    pub can_do: f64,
    pub did: f64,
    pub limited_by: Limit,
}

/// The cluster's scan capacity, in scans a day.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Capacity {
    pub scanners: Vec<ScannerCapacity>,
    pub per_day: f64,
    pub used_per_day: f64,
    /// Used over capacity, at most 1; 1 with no capacity at all.
    pub utilization: f64,
}

pub fn capacity(scanners: &[Scanner]) -> Capacity {
    let (secs, jobs) = scanners
        .iter()
        .filter_map(|s| Some((s.mean_secs? * s.jobs_7d as f64, s.jobs_7d)))
        .fold((0.0, 0u32), |a, b| (a.0 + b.0, a.1 + b.1));
    let cluster_mean = if jobs > 0 {
        secs / jobs as f64
    } else {
        crate::scan::pace::DEFAULT_SCAN_SECS
    };
    let per_scanner: Vec<ScannerCapacity> = scanners
        .iter()
        .map(|s| {
            let d = match s.mean_secs {
                Some(m) if s.jobs_7d >= 5 => m,
                _ => cluster_mean,
            }
            .max(1.0);
            let by_workers = s.max_workers as f64 * 3600.0 / d;
            let per_hour = s.max_scans_per_hour.max(0) as f64;
            let (can_do, limited_by) = if by_workers <= per_hour {
                (by_workers, Limit::Workers)
            } else {
                (per_hour, Limit::PerHour)
            };
            ScannerCapacity {
                node: s.node,
                can_do,
                did: s.ended_24h as f64 / 24.0,
                limited_by,
            }
        })
        .collect();
    let per_day: f64 = per_scanner.iter().map(|s| s.can_do).sum::<f64>() * 24.0;
    let used_per_day: f64 = per_scanner.iter().map(|s| s.did).sum::<f64>() * 24.0;
    Capacity {
        utilization: if per_day <= 0.0 {
            1.0
        } else {
            (used_per_day / per_day).min(1.0)
        },
        scanners: per_scanner,
        per_day,
        used_per_day,
    }
}

/// Half price while the scanners idle, double when they are saturated.
pub fn load(utilization: f64) -> f64 {
    2f64.powf(2.0 * utilization.clamp(0.0, 1.0) - 1.0)
}

/// The unit price in mc: the price at which what the cluster earns in a
/// day buys what it can serve in a day (half of every payment survives,
/// so an earned credit is spent twice on average), moved by the scanners'
/// load. None: nobody announces lookup capacity.
pub fn unit(earned_per_day: Mc, lookups_per_day: f64, utilization: f64) -> Option<Mc> {
    if lookups_per_day <= 0.0 {
        return None;
    }
    let u = earned_per_day as f64 / (0.5 * lookups_per_day) * load(utilization);
    Some((u.round().clamp(0.0, UNIT_MAX as f64) as Mc).clamp(UNIT_MIN, UNIT_MAX))
}

/// What one lookup of `provider` costs here, in mc: its weight times the
/// unit times this node's surge for it, at least 1 mc; nothing for a free
/// provider. Without a unit, what is served is priced from the floor.
pub fn price(provider: &str, unit: Option<Mc>, surge: u32) -> u32 {
    let w = weight_milli(provider) as u64;
    if w == 0 {
        return 0;
    }
    let p = w * unit.unwrap_or(UNIT_MIN) * surge.max(1) as u64 / 1000;
    p.clamp(1, u32::MAX as u64) as u32
}

/// One provider as this node serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub provider: String,
    pub price_mc: u32,
    pub surge: u32,
    /// On-demand lookups a day; None: no budget, no limit.
    pub on_demand: Option<u32>,
}

/// This node's prices and what they were computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub at_ms: u64,
    /// What all members earned a day over the last 7 days (E).
    pub earned_per_day: Mc,
    /// Weighted on-demand lookups a day the cluster announces (C).
    pub lookups_per_day: f64,
    pub capacity: Capacity,
    pub load: f64,
    pub unit: Option<Mc>,
    pub offers: Vec<Offer>,
}

impl Table {
    pub fn price_of(&self, provider: &str) -> Option<u32> {
        self.offers
            .iter()
            .find(|o| o.provider == provider)
            .map(|o| o.price_mc)
    }

    /// What the heartbeat carries: `(on_demand, prices)`.
    pub fn announced(&self) -> (Vec<(String, u32)>, Vec<(String, u32)>) {
        (
            self.offers
                .iter()
                .filter_map(|o| Some((o.provider.clone(), o.on_demand?)))
                .collect(),
            self.offers
                .iter()
                .map(|o| (o.provider.clone(), o.price_mc))
                .collect(),
        )
    }
}
```

- [ ] **Step 4: Announce, measure, refresh**

`src/cluster/status.rs`: `struct Heartbeat` gains, after `floors`:

```rust
    /// Per provider with a budget: paid on-demand lookups this node
    /// serves a day (see `credits::price`).
    #[serde(default)]
    pub on_demand: Vec<(String, u32)>,
    /// Per provider this node serves: its current price in mc.
    #[serde(default)]
    pub prices: Vec<(String, u32)>,
```

In `Node::refresh_heartbeat`, before the `let hb = Heartbeat {` line: `let (on_demand, prices) = self.price_table().announced();`, and the literal gets `on_demand,` and `prices,` at its end. Every other `Heartbeat { … }` literal (two more in `status.rs`'s tests, two in `repl.rs`'s tests) gets `on_demand: vec![], prices: vec![],`.

`src/cluster/mod.rs`: in `struct Node`, after `lookup_shares`:

```rust
    /// This node's lookup prices, as last computed (`credits::price`).
    price_table: RwLock<Arc<crate::credits::price::Table>>,
```

initialized with `price_table: Default::default(),`, and below `lookup_shares()`:

```rust
    pub fn price_table(&self) -> Arc<crate::credits::price::Table> {
        self.price_table.read().unwrap().clone()
    }

    /// Adopt new prices and announce them with the next heartbeat.
    pub fn set_price_table(&self, t: Arc<crate::credits::price::Table>) {
        *self.price_table.write().unwrap() = t;
        self.publish_status();
    }
```

Append to `src/credits/price.rs` (before the test module):

```rust
/// The scanners this node counts: live members with the scanner role
/// (this node included) that are not in `left_out` (blocked or forked
/// here), with their announced pace and their finished jobs.
pub async fn scanners(node: &Node, left_out: &HashSet<NodeId>) -> Result<Vec<Scanner>> {
    let stats: Vec<(Vec<u8>, Option<f64>, i64, i64)> = sqlx::query_as(
        "SELECT scanner,
                AVG((julianday(finished_at) - julianday(started_at)) * 86400.0),
                COUNT(*),
                COALESCE(SUM(finished_at > datetime('now', '-1 day')), 0)
         FROM scan_jobs
         WHERE scanner IS NOT NULL AND status IN ('done', 'failed')
           AND started_at IS NOT NULL AND finished_at IS NOT NULL
           AND finished_at > datetime('now', '-7 days')
         GROUP BY scanner",
    )
    .fetch_all(&node.store.pool)
    .await?;
    let audits: Vec<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT origin, COUNT(*) FROM scans
         WHERE audit_of IS NOT NULL AND origin IS NOT NULL
           AND finished_at > datetime('now', '-1 day')
         GROUP BY origin",
    )
    .fetch_all(&node.store.pool)
    .await?;
    let mut jobs: HashMap<NodeId, (Option<f64>, u32, u32)> = HashMap::new();
    for (id, mean, n, day) in stats {
        if let Ok(id) = NodeId::from_slice(&id) {
            jobs.insert(id, (mean.map(|m| m.max(0.0)), n.max(0) as u32, day.max(0) as u32));
        }
    }
    for (id, n) in audits {
        if let Ok(id) = NodeId::from_slice(&id) {
            jobs.entry(id).or_default().2 += n.max(0) as u32;
        }
    }
    let me = node.id();
    let mut out = vec![];
    for id in node.live_members(crate::scan::arbiter::LIVE_WINDOW) {
        if left_out.contains(&id) {
            continue;
        }
        let pace = if id == me {
            node.roles()
                .scanner
                .then(|| node.status.local.lock().unwrap().pace)
                .flatten()
        } else {
            node.status
                .known(&id)
                .filter(|k| k.hb.roles.iter().any(|r| r == "scanner"))
                .and_then(|k| k.hb.pace)
        };
        let Some(pace) = pace else { continue };
        let (mean_secs, jobs_7d, ended_24h) = jobs.get(&id).copied().unwrap_or_default();
        out.push(Scanner {
            node: id,
            max_workers: pace.max_workers,
            max_scans_per_hour: pace.max_scans_per_hour,
            mean_secs,
            jobs_7d,
            ended_24h,
        });
    }
    Ok(out)
}

/// Compute this node's prices from what it holds and hears now, keep
/// them, and announce them with the next heartbeat.
pub async fn refresh(node: &Node) -> Result<Arc<Table>> {
    let book = super::book_fresh(node).await?;
    let left_out: HashSet<NodeId> = book
        .standings
        .iter()
        .filter(|(_, s)| s.left_out())
        .map(|(id, _)| *id)
        .collect();
    let capacity = capacity(&scanners(node, &left_out).await?);
    let empty = vec![];
    let providers = node.lookup_providers().unwrap_or(&empty);
    let shares = node.lookup_shares();
    // What this node serves, and what it adds to the cluster's capacity.
    let mut own: Vec<(String, u32, Option<u32>)> = vec![];
    let mut weighted: u64 = 0;
    for p in providers.iter().filter(|p| p.ready()) {
        let (on_demand, surge) = match shares {
            Some(s) => (s.allowance(p.as_ref()), s.surge(p.as_ref()).await?),
            None => (None, 1),
        };
        weighted += weight_milli(p.name()) as u64 * on_demand.unwrap_or(0) as u64;
        own.push((p.name().to_string(), surge, on_demand));
    }
    // And every live member that can be asked and is not left out here.
    let me = node.id();
    let members = node.members();
    for id in node.live_members(intel::LIVE_WINDOW) {
        let askable = id != me
            && !left_out.contains(&id)
            && !node.is_blocked(&id)
            && node.dial_address(&id).is_some()
            && members
                .get(&id)
                .is_some_and(|m| m.proto_max >= crate::cluster::rpc::proto::OWNER_PROTO);
        if !askable {
            continue;
        }
        if let Some(k) = node.status.known(&id) {
            for (provider, n) in &k.hb.on_demand {
                if intel::provider_info(provider).is_some() {
                    weighted += weight_milli(provider) as u64 * *n as u64;
                }
            }
        }
    }
    let lookups_per_day = weighted as f64 / 1000.0;
    let earned_per_day = book.earned_per_day();
    let unit = unit(earned_per_day, lookups_per_day, capacity.utilization);
    let table = Arc::new(Table {
        at_ms: crate::cluster::hlc::wall_ms(),
        earned_per_day,
        lookups_per_day,
        load: load(capacity.utilization),
        capacity,
        unit,
        offers: own
            .into_iter()
            .map(|(provider, surge, on_demand)| Offer {
                price_mc: price(&provider, unit, surge),
                provider,
                surge,
                on_demand,
            })
            .collect(),
    });
    node.set_price_table(table.clone());
    Ok(table)
}
```

`src/intel/mod.rs`: `LIVE_WINDOW` is private and now read from another module: `pub(crate) const LIVE_WINDOW`.

`src/credits/mod.rs`, in `run`: the prices are computed at the start and every hour. Inside the loop, after the pruning block:

```rust
        // At the start (once the first heartbeats are in) and every hour.
        if ticks % 60 == 1 {
            if let Err(e) = price::refresh(&node).await {
                tracing::debug!(?e, "credits: prices not computed");
            }
        }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib credits::price && cargo test --lib cluster::status && cargo test --lib cluster::repl && cargo test --test cluster announced_prices_follow`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/credits src/cluster/status.rs src/cluster/repl.rs src/cluster/mod.rs src/intel/mod.rs tests/cluster.rs
git commit -m "Credits: scan capacity, and prices that follow earnings and lookup capacity

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 13: A lookup is paid for

The asking node picks the cheapest server per provider, sets credits aside with an offer, and asks; the serving node checks the offer in its own book, asks its providers, and writes the receipt. A node's own providers cost the same: an offer to itself and its own receipt. The per-peer allowance of 50 a day goes.

**Files:**
- Create: `src/credits/pay.rs`
- Modify: `src/credits/mod.rs` (`pub mod pay;`), `src/intel/lookup.rs` (request, answer, `serve`, `cluster`), `src/intel/mod.rs` (`LIVE_WINDOW` visibility), `src/cluster/mod.rs` (the per-peer budget goes; free-lookup limit and offers being served), `src/cluster/rpc/mod.rs` (doc comment), `src/admin/lookup.rs` and `templates/admin_lookup.html` (the `per_peer` text goes), `tests/cluster.rs`
- Test: unit tests in `src/credits/pay.rs`, `src/intel/lookup.rs`; `tests/cluster.rs::a_paid_lookup_moves_credits_from_the_asker_to_the_server`, `::an_asker_without_credits_is_declined_with_the_reason`, `::a_lookup_answered_by_the_nodes_own_provider_costs_half_net`, `::a_price_above_the_offer_is_declined_and_named`, `::a_member_of_an_earlier_version_is_not_asked`

**Interfaces:**
- Consumes: `repl::append_sealing` (Task 2); `entries::{get, Kind, SealState}` (Task 1); `credits::{book_fresh, show}`, `Book`, `ledger::{Ledger::spendable_parts, OfferState}` (Tasks 5, 7); `share::Shares::{spent, take}` (Task 11); `price::{weight_milli, price, Table::price_of}`, `Node::price_table`, `Heartbeat.prices` (Task 12); `sync::reconcile`; `Node::call`.
- Produces:
  - `LookupReq.offer_seq: Option<u64>`; `LookupResp.charged_mc: u32`, `LookupResp.price_mc: Option<u32>`
  - `lookup::NodeAnswer.charged_mc: u32`
  - `lookup::serve(node: &Arc<Node>, peer: NodeId, req: &LookupReq) -> LookupResp` (signature unchanged; `peer` may be this node)
  - `lookup::cluster(rec: &Recorder, providers: &Providers, ip: IpAddr) -> Vec<NodeAnswer>` (signature unchanged)
  - `credits::pay::Quote { pub provider: String, pub server: NodeId, pub server_name: String, pub price_mc: u32 }`
  - `pay::quotes(node: &Node, own: &Providers) -> HashMap<String, Vec<Quote>>` (cheapest first)
  - `pay::serve(node: &Arc<Node>, providers: &Providers, peer: NodeId, ip: IpAddr, served: Vec<String>, offer_seq: u64) -> LookupResp`
  - `pay::offer_and_ask(node: &Arc<Node>, own: &Providers, ip: IpAddr, server: NodeId, providers: &[String], total_mc: Mc) -> LookupResp`
  - `pay::ask(node: &Arc<Node>, own: &Providers, ip: IpAddr, wanted: &[String]) -> Vec<NodeAnswer>`
  - `pay::SERVE_WAIT: Duration` (10 s), `pay::FREE_PER_HOUR: usize = 60`
  - `Node::take_free_lookup(&self, peer: NodeId) -> bool`; `Node::take_lookup_budget` and `lookup::PER_PEER_PER_DAY` are removed

- [ ] **Step 1: Write the failing tests**

Create `src/credits/pay.rs` with imports and the unit test:

```rust
//! Paying for a lookup. The asking node sets credits aside with a
//! `credit_offer` to the server it chose and names that entry in its
//! request; the server checks the offer against its own book, asks its
//! providers and writes a `credit_receipt` for what it answered. Half of
//! what is charged goes to the server, half is destroyed. A node's own
//! providers cost the same as anyone else's.
use super::entries::{self, Kind, SealState};
use super::ledger::OfferState;
use super::{Mc, price, show};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use crate::intel::lookup::{LookupReq, LookupResp, NodeAnswer};
use crate::intel::{Providers, provider_info};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    fn q(provider: &str, server: u8, price_mc: u32) -> Quote {
        Quote {
            provider: provider.into(),
            server: NodeId([server; 32]),
            server_name: format!("n{server}"),
            price_mc,
        }
    }

    #[test]
    fn the_cheapest_server_is_asked_first_and_no_node_is_preferred() {
        let mut list = vec![q("abuseipdb", 3, 300), q("abuseipdb", 1, 200), q("abuseipdb", 2, 250)];
        cheapest_first(&mut list);
        let order: Vec<u32> = list.iter().map(|x| x.price_mc).collect();
        assert_eq!(order, [200, 250, 300]);
        // Equal prices: one of them at random, not always the same one.
        let mut first = HashSet::new();
        for _ in 0..200 {
            let mut same = vec![q("abuseipdb", 1, 200), q("abuseipdb", 2, 200)];
            cheapest_first(&mut same);
            first.insert(same[0].server);
        }
        assert_eq!(first.len(), 2);
    }
}
```

Add `pub mod pay;` to `src/credits/mod.rs`.

In `src/intel/lookup.rs`'s test module add:

```rust
    /// A request of a node of an earlier version carries no offer and
    /// still decodes; an answer of one carries no charge.
    #[test]
    fn requests_and_answers_of_an_earlier_version_decode() {
        #[derive(Serialize)]
        struct OldReq {
            ip: String,
            providers: Vec<String>,
        }
        #[derive(Serialize)]
        struct OldResp {
            findings: Vec<Found>,
            declined: Vec<(String, String)>,
        }
        let raw = crate::cluster::rpc::cbor::encode(&OldReq {
            ip: "203.0.113.7".into(),
            providers: vec![],
        })
        .unwrap();
        let req: LookupReq = crate::cluster::rpc::cbor::decode(&raw).unwrap();
        assert_eq!(req.offer_seq, None);
        let raw = crate::cluster::rpc::cbor::encode(&OldResp {
            findings: vec![],
            declined: vec![],
        })
        .unwrap();
        let resp: LookupResp = crate::cluster::rpc::cbor::decode(&raw).unwrap();
        assert_eq!((resp.charged_mc, resp.price_mc), (0, None));
    }
```

Append to `tests/cluster.rs`:

```rust
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
    let asked = serves(&nb, &[("abuseipdb", Some(5.0)), ("maxmind-geolite2", None)], 0.2);
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
    assert!(reason.contains("holds 0.00 credits") && reason.contains("missing"), "{reason}");
    assert!(entries::since(&na.store.pool, 0).await.unwrap().is_empty());
    assert_eq!(asked.load(Ordering::SeqCst), 0);

    // 2. Credits only this node counts (the server judged no such scans).
    grant_scans(&[&na], a.id, 4).await;
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert!(why(&answers, "abuseipdb").contains("not covered here"), "{answers:?}");
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    eventually("the receipt of nothing frees the credits at once", || async {
        let book = credits::book_fresh(&na.node).await.unwrap();
        book.balance(&a.id) == 5000 && book.ledger.held(&a.id) == 0
    })
    .await;

    // 3. The server counts them too: served, and the share of the day is
    // used up by that one lookup.
    grant_scans(&[&nb], a.id, 4).await;
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert_eq!(answers.iter().map(|x| x.resp.findings.len()).sum::<usize>(), 2);
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, ip).await;
    assert!(why(&answers, "abuseipdb").contains("on-demand share"), "{answers:?}");
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
    let cost = price::refresh(&na.node).await.unwrap().price_of("abuseipdb").unwrap() as u64;
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
    let cost = price::refresh(&nb.node).await.unwrap().price_of("abuseipdb").unwrap();
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
```

```rust
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
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib credits::pay`
Expected: does not compile (`cannot find type Quote`, `no field offer_seq`, …).

- [ ] **Step 3: Request, answer and the serving entry point**

`src/intel/mod.rs`: `LIVE_WINDOW` is `pub(crate)` since Task 12; nothing to change.

`src/intel/lookup.rs`:

- The module comment's two paragraphs become:

```rust
//! On-demand enrichment: an admin asks what the providers say about one
//! address, now. On a standalone node its own databases and keys answer.
//! In a cluster a lookup is paid with credits (`crate::credits::pay`): per
//! provider the node with the lowest announced price answers, this node's
//! own providers included, and what was paid for is kept in the dataset
//! when the cluster has recorded the address. The automatic enrichment
//! ([`super::enrich_loop`]) keeps recording on its own schedule.
```

- Delete `PER_PEER_PER_DAY`.
- `LookupReq` gains

```rust
    /// The asker's `credit_offer` (its sequence number in the asker's log)
    /// that pays for this request. None: free providers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
```

- `LookupResp` gains

```rust
    /// What the receipt charges, in mc.
    #[serde(default)]
    pub charged_mc: u32,
    /// Set when the offer was below this node's price for what was asked:
    /// that price, so the asker may offer again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_mc: Option<u32>,
```

- `NodeAnswer` gains `/// What that node charged for this answer, in mc.\n    pub charged_mc: u32,`.
- Replace `serve` by:

```rust
/// Serve a member's request (or this node's own, `peer` being itself)
/// with this node's providers. With an offer the request is paid
/// (`credits::pay::serve`); without one only free providers answer, at
/// most [`crate::credits::pay::FREE_PER_HOUR`] times an hour per asker.
pub async fn serve(node: &Arc<Node>, peer: NodeId, req: &LookupReq) -> LookupResp {
    let all = |why: &str| LookupResp {
        declined: vec![("*".into(), why.into())],
        ..Default::default()
    };
    let Some(providers) = node.lookup_providers() else {
        return all("this node runs no enrichment providers");
    };
    if req.ip.len() > MAX_IP_LEN {
        return all("address too long");
    }
    let Ok(ip) = req.ip.trim().parse::<IpAddr>() else {
        return all("not an IP address");
    };
    // Only what this node serves is asked; the rest is declined at once.
    let served: Vec<String> = providers
        .iter()
        .map(|p| p.name().to_string())
        .filter(|n| req.providers.is_empty() || req.providers.contains(n))
        .collect();
    let mut declined: Vec<(String, String)> = req
        .providers
        .iter()
        .filter(|n| !served.contains(n))
        .map(|n| (n.clone(), "not served by this node".into()))
        .collect();
    let mut resp = match req.offer_seq {
        Some(seq) => crate::credits::pay::serve(node, providers, peer, ip, served, seq).await,
        None => {
            let (free, paid): (Vec<String>, Vec<String>) = served
                .into_iter()
                .partition(|n| crate::credits::price::weight_milli(n) == 0);
            declined.extend(paid.into_iter().map(|n| {
                (
                    n,
                    "lookups of this provider are paid with credits: the request carries no offer"
                        .into(),
                )
            }));
            if free.is_empty() {
                LookupResp::default()
            } else if !node.take_free_lookup(peer) {
                LookupResp {
                    declined: free
                        .into_iter()
                        .map(|n| (n, "too many free lookups from your node this hour".into()))
                        .collect(),
                    ..Default::default()
                }
            } else {
                local(providers, &ip, &free).await
            }
        }
    };
    resp.declined.append(&mut declined);
    resp
}
```

  (`use std::sync::Arc;` joins the imports of the file.)
- Replace `cluster` and `ask_members` by:

```rust
/// What every reachable node says about `ip`. Standalone: this node's
/// providers. In a cluster: per provider the cheapest node, paid with
/// this node's credits (`credits::pay::ask`).
pub async fn cluster(rec: &Recorder, providers: &Providers, ip: IpAddr) -> Vec<NodeAnswer> {
    let known: Vec<String> = KNOWN_PROVIDERS.iter().map(|p| p.name.to_string()).collect();
    let Recorder::Cluster(node) = rec else {
        let mine = local(providers, &ip, &[]).await;
        let mut out = vec![NodeAnswer {
            node: "this node".into(),
            resp: mine,
            charged_mc: 0,
        }];
        note_unserved(&mut out, &known);
        return out;
    };
    let mut out = crate::credits::pay::ask(node, providers, ip, &known).await;
    if out.is_empty() {
        out.push(NodeAnswer {
            node: "this node".into(),
            resp: LookupResp::default(),
            charged_mc: 0,
        });
    }
    note_unserved(&mut out, &known);
    out
}

/// Every provider in `wanted` that nobody answered or declined gets a
/// note on the first answer.
fn note_unserved(out: &mut [NodeAnswer], wanted: &[String]) {
    let missing: Vec<String> = wanted
        .iter()
        .filter(|p| {
            !out.iter().any(|a| {
                a.resp.findings.iter().any(|f| &f.provider == *p)
                    || a.resp.declined.iter().any(|(n, _)| n == *p)
            })
        })
        .cloned()
        .collect();
    for p in missing {
        out[0]
            .resp
            .declined
            .push((p, "no reachable node serves this provider".into()));
    }
}
```

  The unused imports the compiler then reports (`provider_info`, `Duration` if `RPC_TIMEOUT` is its only user: it stays, `pay` uses it) are dropped.
- The existing test `standalone_cluster_lookup_is_the_local_answer_plus_unserved_notes` keeps passing unchanged; `NodeAnswer` literals in tests get `charged_mc: 0`.

`src/cluster/mod.rs`:

- Replace the field `lookup_budget` (with its doc comment) by

```rust
    /// Free lookups served per asking member in the last hour.
    free_lookups: Mutex<HashMap<NodeId, std::collections::VecDeque<std::time::Instant>>>,
    /// Offers a paid lookup is being served for right now: `(payer,
    /// sequence number)`. An offer is served once.
    pub(crate) serving_offers: Mutex<std::collections::HashSet<(NodeId, u64)>>,
```

  and its initializer by `free_lookups: Mutex::new(HashMap::new()),` and `serving_offers: Mutex::new(Default::default()),`.
- Replace `take_lookup_budget` by

```rust
    /// Count one free lookup for `peer`; false when it had
    /// [`crate::credits::pay::FREE_PER_HOUR`] in the last hour.
    pub fn take_free_lookup(&self, peer: NodeId) -> bool {
        let hour = Duration::from_secs(3600);
        let mut all = self.free_lookups.lock().unwrap();
        all.retain(|_, q| q.back().is_some_and(|t| t.elapsed() < hour));
        let q = all.entry(peer).or_default();
        while q.front().is_some_and(|t| t.elapsed() >= hour) {
            q.pop_front();
        }
        if q.len() >= crate::credits::pay::FREE_PER_HOUR {
            return false;
        }
        q.push_back(std::time::Instant::now());
        true
    }
```

`src/cluster/rpc/mod.rs`: the doc comment of `lookup` becomes `/// On-demand enrichment for a member: paid with the offer it names, or free providers only.`

`src/admin/lookup.rs`: remove the field `per_peer` from `LookupPage` and from its four initializers. `templates/admin_lookup.html` line 5: the subtitle becomes `<p class="muted">Every reachable provider, now.{% if cluster %} Paid with credits; kept in the dataset when the cluster has recorded the address.{% else %} Not stored; spends API budget.{% endif %}</p>`. (Task 16 rebuilds this page.)

- [ ] **Step 4: Implement `pay.rs`**

Insert between the imports and the test module:

```rust
/// How long a server waits for the asker's offer to arrive.
pub const SERVE_WAIT: Duration = Duration::from_secs(10);
/// Free lookups (no offer) a member gets an hour.
pub const FREE_PER_HOUR: usize = 60;
/// Servers tried for one provider before giving up.
const MAX_ROUNDS: usize = 3;

/// A node that could answer for a provider, and what it asks.
#[derive(Debug, Clone, PartialEq)]
pub struct Quote {
    pub provider: String,
    pub server: NodeId,
    pub server_name: String,
    pub price_mc: u32,
}

/// Sort by price; equal prices in random order, so no node is preferred.
fn cheapest_first(list: &mut [Quote]) {
    let mut keyed: Vec<(u32, u32, Quote)> = list
        .iter()
        .map(|q| {
            let mut r = [0u8; 4];
            let _ = aws_lc_rs::rand::fill(&mut r);
            (q.price_mc, u32::from_le_bytes(r), q.clone())
        })
        .collect();
    keyed.sort_by_key(|(price, r, _)| (*price, *r));
    for (slot, (_, _, q)) in list.iter_mut().zip(keyed) {
        *slot = q;
    }
}

/// Who could be asked for each provider, cheapest first: this node, if it
/// serves the provider, and every live member that announces a price for
/// it and can be asked. Neither this node nor its fleet is preferred.
pub fn quotes(node: &Node, own: &Providers) -> HashMap<String, Vec<Quote>> {
    let me = node.id();
    let mut out: HashMap<String, Vec<Quote>> = HashMap::new();
    let table = node.price_table();
    for p in own.iter().filter(|p| p.ready()) {
        let name = p.name();
        out.entry(name.to_string()).or_default().push(Quote {
            provider: name.to_string(),
            server: me,
            server_name: "this node".into(),
            price_mc: table
                .price_of(name)
                .unwrap_or_else(|| price::price(name, table.unit, 1)),
        });
    }
    let members = node.members();
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        let Some(m) = members.get(&id) else { continue };
        if id == me
            || node.is_blocked(&id)
            || m.proto_max < crate::cluster::rpc::proto::OWNER_PROTO
            || node.dial_address(&id).is_none()
        {
            continue;
        }
        let Some(k) = node.status.known(&id) else {
            continue;
        };
        for (provider, price_mc) in &k.hb.prices {
            if provider_info(provider).is_none() {
                continue;
            }
            out.entry(provider.clone()).or_default().push(Quote {
                provider: provider.clone(),
                server: id,
                server_name: m.name.clone(),
                price_mc: *price_mc,
            });
        }
    }
    for list in out.values_mut() {
        cheapest_first(list);
    }
    out
}

/// The asker's entry `seq`, once it is held here (as a payment row).
async fn wait_for(node: &Node, peer: &NodeId, seq: u64) -> Option<entries::Entry> {
    let until = tokio::time::Instant::now() + SERVE_WAIT;
    loop {
        if let Ok(Some(e)) = entries::get(&node.store.pool, peer, seq).await {
            return Some(e);
        }
        if tokio::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Removes an offer from the ones being served when the request ends.
struct Serving<'a>(&'a Node, (NodeId, u64));

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        self.0.serving_offers.lock().unwrap().remove(&self.1);
    }
}

/// The serving side: check the offer `offer_seq` of `peer` in this node's
/// own book, ask the providers in `served`, write the receipt. Whatever is
/// declined says why.
pub async fn serve(
    node: &Arc<Node>,
    providers: &Providers,
    peer: NodeId,
    ip: IpAddr,
    served: Vec<String>,
    offer_seq: u64,
) -> LookupResp {
    let decline = |names: &[String], why: String| LookupResp {
        declined: names.iter().map(|n| (n.clone(), why.clone())).collect(),
        ..Default::default()
    };
    let Some(entry) = wait_for(node, &peer, offer_seq).await else {
        return decline(
            &served,
            format!("the offer (entry {offer_seq} of your node's log) did not arrive here"),
        );
    };
    match &entry.kind {
        Kind::Offer { to, .. } if *to == node.id() => {}
        Kind::Offer { .. } => return decline(&served, "the offer is made to another node".into()),
        _ => return decline(&served, format!("entry {offer_seq} of your node's log is no offer")),
    }
    // Unchecked is not enough: the asker's next offer seals a range that
    // starts at this one, so one declined offer is the cost.
    match entry.seal {
        SealState::Consistent => {}
        SealState::Inconsistent => {
            return decline(&served, "the offer's seal does not match your node's log here".into());
        }
        _ => {
            return decline(
                &served,
                "the offer's seal could not be checked here yet; offer again".into(),
            );
        }
    }
    if !node.serving_offers.lock().unwrap().insert((peer, offer_seq)) {
        return decline(&served, "this offer is being served already".into());
    }
    let _serving = Serving(node, (peer, offer_seq));
    let book = match super::book_fresh(node).await {
        Ok(b) => b,
        Err(e) => return decline(&served, format!("this node could not read its books: {e:#}")),
    };
    let standing = book.standing(&peer);
    if standing.left_out() {
        return decline(
            &served,
            format!(
                "your node's credits are not accepted here: {}",
                standing.reasons().join("; ")
            ),
        );
    }
    let Some(offer) = book.ledger.offer(&peer, offer_seq) else {
        return decline(&served, "the offer does not count here".into());
    };
    if offer.state != OfferState::Open {
        return decline(
            &served,
            "the offer is used up, or older than 15 minutes".into(),
        );
    }
    let (offered, covered) = (offer.offered, offer.covered);

    let table = node.price_table();
    let price_of = |name: &str| -> Mc {
        table
            .price_of(name)
            .unwrap_or_else(|| price::price(name, table.unit, 1)) as Mc
    };
    let shares = node.lookup_shares();
    let provider = |name: &str| providers.iter().find(|p| p.name() == name);
    // Providers whose on-demand share is spent are declined one by one;
    // the rest is served.
    let (mut asking, mut declined) = (vec![], vec![]);
    for name in served {
        let spent = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.spent(p.as_ref()).await.unwrap_or(true),
            _ => false,
        };
        if spent {
            declined.push((
                name,
                "this node's on-demand share of that provider is spent for today".to_string(),
            ));
        } else {
            asking.push(name);
        }
    }
    let total: Mc = asking.iter().map(|n| price_of(n)).sum();
    let refuse = |why: String, price_mc: Option<u32>| async move {
        // A receipt of nothing frees the asker's credits at once.
        let receipt = Record::CreditReceipt {
            payer: peer,
            offer_seq,
            charged_mc: 0,
            answered: vec![],
        };
        if let Err(e) = repl::append(node, &[receipt]).await {
            tracing::debug!(?e, "receipt not written");
        }
        tracing::info!(asker = %peer.short(), %why, "paid lookup declined");
        (why, price_mc)
    };
    let refused = if total > offered {
        Some(
            refuse(
                format!(
                    "this costs {} credits here now; the offer is {}",
                    show(total),
                    show(offered)
                ),
                Some(total.min(u32::MAX as Mc) as u32),
            )
            .await,
        )
    } else if covered < total {
        Some(
            refuse(
                format!(
                    "not covered here: this node counts {} of the {} credits offered",
                    show(covered),
                    show(offered)
                ),
                None,
            )
            .await,
        )
    } else {
        None
    };
    if let Some((why, price_mc)) = refused {
        let mut resp = decline(&asking, why);
        resp.price_mc = price_mc;
        resp.declined.append(&mut declined);
        return resp;
    }
    // Count the share before asking: a failed request used the budget too.
    let mut ask_now = vec![];
    for name in asking {
        let taken = match (shares, provider(&name)) {
            (Some(s), Some(p)) => s.take(p.as_ref()).await.unwrap_or(false),
            _ => true,
        };
        if taken {
            ask_now.push(name);
        } else {
            declined.push((
                name,
                "this node's on-demand share of that provider is spent for today".to_string(),
            ));
        }
    }
    let mut resp = if ask_now.is_empty() {
        LookupResp::default()
    } else {
        crate::intel::lookup::local(providers, &ip, &ask_now).await
    };
    let answered: Vec<String> = resp.findings.iter().map(|f| f.provider.clone()).collect();
    let charged = answered.iter().map(|n| price_of(n)).sum::<Mc>().min(covered);
    let receipt = Record::CreditReceipt {
        payer: peer,
        offer_seq,
        charged_mc: charged.min(u32::MAX as Mc) as u32,
        answered: answered.clone(),
    };
    match repl::append(node, &[receipt]).await {
        Ok(_) => resp.charged_mc = charged.min(u32::MAX as Mc) as u32,
        // Answered all the same: this node goes unpaid, the asker's
        // credits return after 15 minutes.
        Err(e) => tracing::warn!(?e, "credit receipt not written"),
    }
    tracing::info!(asker = %peer.short(), providers = %answered.join(","),
        charged = %show(charged), "paid lookup served");
    resp.declined.append(&mut declined);
    resp
}

/// Offer `total_mc` to `server` for `providers` and ask it once. The
/// answer carries what it charged; a refusal says why.
pub async fn offer_and_ask(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    server: NodeId,
    providers: &[String],
    total_mc: Mc,
) -> LookupResp {
    let decline = |why: String| LookupResp {
        declined: providers.iter().map(|p| (p.clone(), why.clone())).collect(),
        ..Default::default()
    };
    let me = node.id();
    let book = match super::book_fresh(node).await {
        Ok(b) => b,
        Err(e) => return decline(format!("this node could not read its books: {e:#}")),
    };
    let Some(parts) = book.ledger.spendable_parts(&me, total_mc) else {
        let have = book.balance(&me);
        return decline(format!(
            "this node holds {} credits; the lookup costs {} ({} missing)",
            show(have),
            show(total_mc),
            show(total_mc.saturating_sub(have))
        ));
    };
    let offer = match repl::append_sealing(node, |seal| Record::CreditOffer {
        to: server,
        parts,
        seal,
    })
    .await
    {
        Ok(e) => e,
        Err(e) => return decline(format!("the offer could not be written: {e:#}")),
    };
    let req = LookupReq {
        ip: ip.to_string(),
        providers: providers.to_vec(),
        offer_seq: Some(offer.seq),
    };
    let mut resp = if server == me {
        let _ = own;
        crate::intel::lookup::serve(node, me, &req).await
    } else {
        let Some(addr) = node.dial_address(&server) else {
            return decline("the node cannot be dialled from here".into());
        };
        // So the offer is there before the request.
        if let Err(e) = crate::cluster::sync::reconcile(node, server, &addr, false).await {
            tracing::debug!(?e, "sync before a paid lookup failed; the server waits for the offer");
        }
        let call = node.call::<LookupReq, LookupResp>(server, &addr, "/rpc/v1/lookup", &req);
        match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT + SERVE_WAIT, call).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return decline(format!("could not be asked: {e:#}")),
            Err(_) => return decline("did not answer in time".into()),
        }
    };
    // Only what was asked for, and only from providers this build knows.
    resp.findings
        .retain(|f| providers.contains(&f.provider) && provider_info(&f.provider).is_some());
    resp
}

/// Ask the cheapest server of each quote group once more at its named
/// price when it turned the first offer down for being too low.
async fn ask_server(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    server: NodeId,
    quotes: &[Quote],
) -> LookupResp {
    let names: Vec<String> = quotes.iter().map(|q| q.provider.clone()).collect();
    let total: Mc = quotes.iter().map(|q| q.price_mc as Mc).sum();
    let me = node.id();
    if total == 0 {
        // Free providers need no offer.
        let req = LookupReq {
            ip: ip.to_string(),
            providers: names.clone(),
            offer_seq: None,
        };
        if server == me {
            return crate::intel::lookup::local(own, &ip, &names).await;
        }
        let Some(addr) = node.dial_address(&server) else {
            return LookupResp::default();
        };
        let call = node.call::<LookupReq, LookupResp>(server, &addr, "/rpc/v1/lookup", &req);
        return match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT, call).await {
            Ok(Ok(mut r)) => {
                r.findings
                    .retain(|f| names.contains(&f.provider) && provider_info(&f.provider).is_some());
                r
            }
            _ => LookupResp {
                declined: names
                    .iter()
                    .map(|n| (n.clone(), "could not be asked".into()))
                    .collect(),
                ..Default::default()
            },
        };
    }
    let first = offer_and_ask(node, own, ip, server, &names, total).await;
    match first.price_mc {
        // Its price moved since its heartbeat: offer that, once.
        Some(p) if first.findings.is_empty() && p as Mc > total => {
            offer_and_ask(node, own, ip, server, &names, p as Mc).await
        }
        _ => first,
    }
}

/// The asking side: for each provider in `wanted` that somebody serves,
/// ask the cheapest server (and the next cheapest when it declines), and
/// pay what each asks. One answer per server asked.
pub async fn ask(
    node: &Arc<Node>,
    own: &Providers,
    ip: IpAddr,
    wanted: &[String],
) -> Vec<NodeAnswer> {
    let me = node.id();
    let mut remaining: Vec<String> = wanted.to_vec();
    let mut tried: HashMap<String, HashSet<NodeId>> = HashMap::new();
    let mut out: Vec<NodeAnswer> = vec![];
    for _ in 0..MAX_ROUNDS {
        let all = quotes(node, own);
        // The cheapest server not yet tried, per provider still open.
        let mut by_server: Vec<(NodeId, String, Vec<Quote>)> = vec![];
        for p in &remaining {
            let seen = tried.entry(p.clone()).or_default();
            let Some(q) = all
                .get(p)
                .and_then(|list| list.iter().find(|q| !seen.contains(&q.server)))
            else {
                continue;
            };
            seen.insert(q.server);
            match by_server.iter_mut().find(|(s, _, _)| *s == q.server) {
                Some((_, _, list)) => list.push(q.clone()),
                None => by_server.push((q.server, q.server_name.clone(), vec![q.clone()])),
            }
        }
        if by_server.is_empty() {
            break;
        }
        // This node first, then by name: a stable order on the page.
        by_server.sort_by_key(|(s, name, _)| (*s != me, name.clone()));
        for (server, name, quotes) in by_server {
            let resp = ask_server(node, own, ip, server, &quotes).await;
            remaining.retain(|p| !resp.findings.iter().any(|f| &f.provider == p));
            out.push(NodeAnswer {
                node: name,
                charged_mc: resp.charged_mc,
                resp,
            });
        }
        if remaining.is_empty() {
            break;
        }
    }
    out
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib credits::pay && cargo test --lib intel::lookup && cargo test --lib admin::lookup && cargo test --test cluster a_paid_lookup_moves_credits && cargo test --test cluster an_asker_without_credits && cargo test --test cluster a_lookup_answered_by_the_nodes_own_provider && cargo test --test cluster a_price_above_the_offer && cargo test --test cluster a_member_of_an_earlier_version`
Expected: PASS. If an existing test in `tests/cluster.rs` exercised the per-peer allowance of 50 (`grep -n 'on-demand budget\|PER_PEER' tests`), delete it and say so in the commit message: the allowance is gone.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add -A src templates tests
git commit -m "Credits: lookups are paid with an offer and a receipt

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 14: The dataset first, and keeping what was paid for

**Files:**
- Modify: `src/credits/pay.rs` (`Stored`, `stored`, keeping in `serve`), `src/intel/lookup.rs` (`LookupResp.kept`, `Outcome`, `run`; `cluster` goes through `run`), `tests/cluster.rs`
- Test: `tests/cluster.rs::a_paid_lookup_of_a_recorded_address_is_kept_and_then_free_for_everyone`, `::a_paid_lookup_of_an_unrecorded_address_writes_nothing`

**Interfaces:**
- Consumes: Task 13's `pay::{ask, serve}`; `Recorder::{record_lookup, record_intel}`; table `ip_intel_log`.
- Produces:
  - `LookupResp.kept: bool` (the serving node wrote the answers into the dataset)
  - `pay::Stored { pub provider: String, pub fetched_at: String, pub age_secs: i64, pub node: Option<String>, pub source_version: Option<String>, pub data: serde_json::Value }` (`Debug, Clone, PartialEq`)
  - `pay::stored(pool: &SqlitePool, ip: &IpAddr) -> Result<Vec<Stored>>` (per provider the newest result under 24 hours old)
  - `pay::recorded(pool: &SqlitePool, ip: &IpAddr) -> bool`
  - `lookup::Outcome { pub stored: Vec<pay::Stored>, pub answers: Vec<NodeAnswer>, pub kept: bool }`
  - `lookup::run(rec: &Recorder, providers: &Providers, ip: IpAddr, again: &[String]) -> Outcome` (`again`: providers to ask although the dataset has a fresh result)

- [ ] **Step 1: Write the failing tests**

Append to `tests/cluster.rs`:

```rust
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
    let row = nc.store.upsert_ip("203.0.113.90".parse().unwrap()).await.unwrap();
    rec(&nc).insert_request(&new_request(row.id, "/x")).await.unwrap();
    eventually("a and b hold the request", || async {
        count(&na, "SELECT COUNT(*) FROM requests").await == 1
            && count(&nb, "SELECT COUNT(*) FROM requests").await == 1
    })
    .await;
    let none: peephole::intel::Providers = vec![];
    let ip = "203.0.113.90".parse().unwrap();
    let findings = |o: &lookup::Outcome| o.answers.iter().map(|x| x.resp.findings.len()).sum::<usize>();

    let first = lookup::run(&rec(&na), &none, ip, &[]).await;
    assert!(first.stored.is_empty());
    assert_eq!(findings(&first), 1, "{:?}", first.answers);
    assert!(first.kept);
    let kept = "SELECT COUNT(*) FROM ip_intel_log WHERE provider = 'abuseipdb' AND ip = '203.0.113.90'";
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
    assert_eq!(entries::since(&nc.store.pool, 0).await.unwrap().len(), payments);

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
    assert_eq!(out.answers.iter().map(|x| x.resp.findings.len()).sum::<usize>(), 1);
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
        assert!(log.iter().all(|p| !p.windows(12).any(|w| w == b"203.0.113.91")));
    }
    // And a second lookup pays again: nothing was there to answer from.
    let out = lookup::run(&rec(&na), &none, ip, &[]).await;
    assert!(out.stored.is_empty());
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --test cluster a_paid_lookup_of_a_recorded_address`
Expected: does not compile (`cannot find function run in module lookup`).

- [ ] **Step 3: Implement**

`src/intel/lookup.rs`:

- `LookupResp` gains

```rust
    /// The answering node wrote these answers into the dataset (the
    /// cluster has recorded the address).
    #[serde(default)]
    pub kept: bool,
```

- Below `cluster`:

```rust
/// A lookup as the admin page shows it.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    /// Provider results the dataset already holds, under 24 hours old:
    /// shown instead of asking (and paying) again.
    pub stored: Vec<crate::credits::pay::Stored>,
    /// What the nodes asked now answered.
    pub answers: Vec<NodeAnswer>,
    /// An answering node kept the answers in the dataset.
    pub kept: bool,
}

/// Look `ip` up: first in the dataset, then at the providers. `again`
/// names the providers to ask although the dataset has a fresh result.
pub async fn run(rec: &Recorder, providers: &Providers, ip: IpAddr, again: &[String]) -> Outcome {
    let known: Vec<String> = KNOWN_PROVIDERS.iter().map(|p| p.name.to_string()).collect();
    let Recorder::Cluster(node) = rec else {
        // Standalone: this node's providers, no credits, nothing stored.
        let mut answers = vec![NodeAnswer {
            node: "this node".into(),
            resp: local(providers, &ip, &[]).await,
            charged_mc: 0,
        }];
        note_unserved(&mut answers, &known);
        return Outcome {
            answers,
            ..Default::default()
        };
    };
    let stored: Vec<_> = match crate::credits::pay::stored(&node.store.pool, &ip).await {
        Ok(s) => s
            .into_iter()
            .filter(|s| !again.contains(&s.provider))
            .collect(),
        Err(e) => {
            tracing::debug!(?e, "lookup: stored results not read");
            vec![]
        }
    };
    let wanted: Vec<String> = known
        .into_iter()
        .filter(|p| !stored.iter().any(|s| &s.provider == p))
        .collect();
    let mut answers = crate::credits::pay::ask(node, providers, ip, &wanted).await;
    if answers.is_empty() {
        answers.push(NodeAnswer {
            node: "this node".into(),
            resp: LookupResp::default(),
            charged_mc: 0,
        });
    }
    note_unserved(&mut answers, &wanted);
    Outcome {
        kept: answers.iter().any(|a| a.resp.kept),
        stored,
        answers,
    }
}
```

- `cluster` becomes a thin wrapper that always asks:

```rust
/// What every reachable node says about `ip` now, whatever the dataset
/// holds (see [`run`]).
pub async fn cluster(rec: &Recorder, providers: &Providers, ip: IpAddr) -> Vec<NodeAnswer> {
    let all: Vec<String> = KNOWN_PROVIDERS.iter().map(|p| p.name.to_string()).collect();
    run(rec, providers, ip, &all).await.answers
}
```

`src/credits/pay.rs`: add `use sqlx::SqlitePool;` and, before `serve`:

```rust
/// A provider result the dataset holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub provider: String,
    pub fetched_at: String,
    pub age_secs: i64,
    /// The node that fetched it.
    pub node: Option<String>,
    pub source_version: Option<String>,
    pub data: serde_json::Value,
}

/// Per provider, the newest result for `ip` any node fetched less than 24
/// hours ago. Shown instead of asking again: it costs nothing.
pub async fn stored(pool: &SqlitePool, ip: &IpAddr) -> anyhow::Result<Vec<Stored>> {
    type Row = (String, String, Option<String>, String, Option<String>, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.provider, t.fetched_at, t.source_version, t.data_json,
                (SELECT name FROM members m WHERE m.id = t.origin),
                CAST((julianday('now') - julianday(t.fetched_at)) * 86400 AS INTEGER)
         FROM ip_intel_log t
         WHERE t.ip = ? AND t.fetched_at > datetime('now', '-1 day')
         ORDER BY t.hlc DESC, t.origin DESC",
    )
    .bind(crate::net::canonical(*ip).to_string())
    .fetch_all(pool)
    .await?;
    let mut out: Vec<Stored> = vec![];
    for (provider, fetched_at, source_version, data_json, node, age_secs) in rows {
        if provider_info(&provider).is_none() || out.iter().any(|s| s.provider == provider) {
            continue;
        }
        out.push(Stored {
            provider,
            fetched_at,
            age_secs: age_secs.max(0),
            node,
            source_version,
            data: serde_json::from_str(&data_json).unwrap_or(serde_json::Value::Null),
        });
    }
    Ok(out)
}

/// Whether the dataset here holds a recorded request from `ip` (a
/// false-positive claim alone does not count).
pub async fn recorded(pool: &SqlitePool, ip: &IpAddr) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM requests r JOIN ips i ON i.id = r.ip_id
                       WHERE i.ip = ? AND r.is_fp_claim = 0)",
    )
    .bind(crate::net::canonical(*ip).to_string())
    .fetch_one(pool)
    .await
    .is_ok_and(|n| n > 0)
}
```

In `serve`, directly before the final `resp.declined.append(&mut declined);`:

```rust
    // What was paid for is kept for everyone when the cluster has
    // recorded the address, exactly as the automatic enrichment would
    // write it; for an address nobody recorded nothing is written.
    if !resp.findings.is_empty() && recorded(&node.store.pool, &ip).await {
        let rec = crate::store::recorder::Recorder::Cluster(node.clone());
        let text = crate::net::canonical(ip).to_string();
        let mut all = true;
        for f in &resp.findings {
            let version = f.source_version.as_deref();
            let written = if provider_info(&f.provider).is_some_and(|i| i.api) {
                rec.record_lookup(&text, &f.provider, version, f.data.clone())
                    .await
            } else {
                rec.record_intel(&text, &f.provider, version, f.data.clone())
                    .await
            };
            if let Err(e) = written {
                tracing::warn!(provider = %f.provider, ?e, "paid lookup result not kept");
                all = false;
            }
        }
        resp.kept = all;
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --test cluster a_paid_lookup_of && cargo test --test cluster a_paid_lookup_moves_credits && cargo test --lib intel::lookup`
Expected: PASS (three integration tests, the lookup unit tests).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/credits/pay.rs src/intel/lookup.rs tests/cluster.rs
git commit -m "Credits: the dataset answers first, and paid answers are kept for recorded addresses

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 15: A fleet's one balance: collecting, drawing, sending

**Files:**
- Create: `src/credits/fleet.rs`
- Modify: `src/credits/mod.rs` (`pub mod fleet;`), `src/settings.rs` (`credits.collect_to`), `src/settings_cli.rs` (`show`), `src/cluster/msg.rs` (two `Msg` variants), `src/cluster/mod.rs` (`Node.collect_to`), `src/cluster/owner/cmd.rs` (`OwnerCmd::SendCredits`), `src/credits/pay.rs` (draw before refusing), `src/admin/cluster_owner.rs` and `templates/admin_cluster_ownership.html` ("Collect credits here"), `src/lib.rs` (wiring), `tests/cluster.rs` (`boot_in`, tests)
- Test: unit tests in `src/settings.rs`, `src/cluster/owner/cmd.rs`; `tests/cluster.rs::a_fleet_collects_at_one_node_and_any_of_its_nodes_can_spend`, `::a_node_draws_what_a_lookup_needs_from_its_collecting_node`

**Interfaces:**
- Consumes: `repl::append_sealing`; `credits::{book_fresh, show, CREDIT}`; `Ledger::{spendable_parts, expiring_today}`; `owner::fleet::siblings`; `owner::cmd::{status, run, kept_key, OwnerCmd}`; `pay::offer_and_ask`.
- Produces:
  - Setting `credits.collect_to` (`settings::KEY_COLLECT_TO`): `Changes.collect_to: Option<String>` (a node key; the empty string clears it), `Snapshot.collect_to: Option<NodeId>`
  - `Msg::CreditDraw { mc: u64 }`, `Msg::CreditDrawReply { sent_mc: u64 }`
  - `Node.collect_to: RwLock<Option<NodeId>>`
  - `credits::fleet::send(node: &Node, to: NodeId, mc: Mc) -> Result<Mc>` (what was sent)
  - `fleet::collect(node: &Node, to: NodeId) -> Result<Mc>`
  - `fleet::serve(node: &Arc<Node>)` (answers `CreditDraw`)
  - `fleet::draw(node: &Arc<Node>, mc: Mc) -> bool` (credits arrived)
  - `fleet::run(node: Arc<Node>, settings: Settings, shutdown: tokio::sync::watch::Receiver<bool>)`
  - `fleet::COLLECT_EVERY: Duration` (600 s), `fleet::DRAW_WAIT: Duration` (10 s)
  - `OwnerCmd::SendCredits { to: NodeId, mc: u64 }`
  - Route `POST /admin/cluster/ownership/collect-here`

- [ ] **Step 1: Write the failing tests**

Add to the test module of `src/settings.rs`:

```rust
    #[test]
    fn the_collecting_node_is_a_runtime_setting() {
        let id = crate::cluster::identity::Identity::generate().unwrap().id;
        let set = Changes::from_key_value(KEY_COLLECT_TO, &id.to_string()).unwrap();
        assert_eq!(set.collect_to.as_deref(), Some(id.to_string().as_str()));
        assert_eq!(set.describe(), format!("collect_to={}", id.short()));
        let s = validate(snap((true, true, true)), &set, &Prereqs::default()).unwrap();
        assert_eq!(s.collect_to, Some(id));
        // Cleared with an empty value; untouched by a change that does not name it.
        let off = Changes::from_key_value(KEY_COLLECT_TO, "").unwrap();
        assert_eq!(off.describe(), "collect_to=off");
        assert_eq!(validate(s, &off, &Prereqs::default()).unwrap().collect_to, None);
        assert_eq!(
            validate(s, &Changes::default(), &Prereqs::default())
                .unwrap()
                .collect_to,
            Some(id)
        );
        assert!(Changes::from_key_value(KEY_COLLECT_TO, "not a key").is_err());
        assert!(KEYS.contains(&KEY_COLLECT_TO));
        // A change without it encodes as before: an older node reads it.
        let enc = crate::cluster::rpc::cbor::encode(&Changes::default()).unwrap();
        assert!(!enc.windows(10).any(|w| w == b"collect_to"));
    }
```

(`snap` is the helper of that test module; it gains `collect_to: None`.)

In `src/cluster/owner/cmd.rs`, extend `commands_describe_themselves_for_the_log`:

```rust
        assert_eq!(
            OwnerCmd::SendCredits { to: n, mc: 1250 }.describe(),
            format!("send 1.25 credits to {}", n.short())
        );
```

In `tests/cluster.rs`, `boot_in`: below `cluster::owner::cmd::serve(&node, settings.clone());` add `peephole::credits::fleet::serve(&node);`.

Append to `tests/cluster.rs`:

```rust
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
    assert_eq!(fleet::collect(&nb.node, stranger.id).await.unwrap(), 0, "no member");
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
    assert!(fleet::send(&na.node, b.id, 99_000).await.is_err(), "more than it holds");
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
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib settings::`
Expected: does not compile (`cannot find value KEY_COLLECT_TO`, `no field collect_to`).

- [ ] **Step 3: The setting**

`src/settings.rs`:

- `pub const KEY_COLLECT_TO: &str = "credits.collect_to";` below `KEY_ROLE_WEB`; `KEYS` becomes `[&str; 8]` with `KEY_COLLECT_TO,` at its end.
- `struct Changes` gains

```rust
    /// The fleet node this node forwards its credits to: a node key
    /// (`ed25519:…`); the empty string forwards to nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_to: Option<String>,
```

- `describe`: after the `web` block

```rust
        if let Some(x) = &self.collect_to {
            v.push(match NodeId::parse(x) {
                Ok(id) => format!("collect_to={}", id.short()),
                Err(_) => "collect_to=off".into(),
            });
        }
```

- `merge`: `self.collect_to = other.collect_to.or(self.collect_to.take());`
- `from_key_value`: the arm

```rust
            KEY_COLLECT_TO => {
                let v = value.trim();
                if !v.is_empty() {
                    NodeId::parse(v).map_err(|_| {
                        format!("{key}: `{value}` is not a node key (see `peephole cluster members`)")
                    })?;
                }
                c.collect_to = Some(v.to_string());
            }
```

- `struct Snapshot` gains `/// Where this node forwards its credits (`credits::fleet`).\n    pub collect_to: Option<NodeId>,`; `defaults()` and `Settings::snapshot` set it (`collect_to: None,` and `collect_to: *self.collect_to.read().unwrap(),`).
- `validate`, before the role loop:

```rust
    if let Some(x) = &c.collect_to {
        s.collect_to = match x.trim() {
            "" => None,
            key => Some(
                NodeId::parse(key).map_err(|_| "collect_to must be a node key".to_string())?,
            ),
        };
    }
```

- `struct Settings` gains `collect_to: Arc<RwLock<Option<NodeId>>>,` (initialized with `Default::default()` in `with_pace`); `adopt` sets it: `*self.collect_to.write().unwrap() = s.collect_to;`.
- `write`: the list of `(key, value)` pairs gains `(KEY_COLLECT_TO, c.collect_to.clone()),`.
- `stored`: it merges every row whose key is in `KEYS` through `Changes::from_key_value`, which now covers the new key; nothing to change.

`src/settings_cli.rs`, `show`: the array of rows gains

```rust
                (
                    KEYS[7],
                    now.collect_to.map(|id| id.to_string()).unwrap_or_default(),
                    now.collect_to.is_some(),
                ),
```

- [ ] **Step 4: Messages and the fleet module**

`src/cluster/msg.rs`, in `enum Msg` after `OwnerReply { … }`:

```rust
    /// Fleet node → its collecting node: send me this much (`credits::fleet`).
    CreditDraw {
        mc: u64,
    },
    /// What the collecting node sent.
    CreditDrawReply {
        sent_mc: u64,
    },
```

`src/cluster/mod.rs`: `struct Node` gains, after `price_table`:

```rust
    /// The fleet node this node forwards its credits to and draws from
    /// (the runtime setting `credits.collect_to`).
    pub collect_to: RwLock<Option<NodeId>>,
```

initialized with `collect_to: RwLock::new(None),`.

Create `src/credits/fleet.rs`:

```rust
//! A fleet's one balance. The ledger has node accounts only; a fleet
//! becomes one entity through two movements between its nodes, both
//! ordinary transfers: every node forwards what it earns to the fleet's
//! collecting node, and a node that needs credits draws them from there.
//! To the rest of the cluster these are transfers like any other.
use super::{CREDIT, Mc, show};
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use crate::settings::Settings;
use anyhow::{Result, bail};
use std::sync::Arc;
use std::time::Duration;

/// How often a node forwards what it holds.
pub const COLLECT_EVERY: Duration = Duration::from_secs(600);
/// How long a node waits for its collecting node, and then for the
/// transfer to arrive.
pub const DRAW_WAIT: Duration = Duration::from_secs(10);

/// Whether credits can be sent to `to` from here: an active member that
/// is neither blocked nor shown to have two histories.
async fn receivable(node: &Node, to: &NodeId) -> Result<bool> {
    if *to == node.id() || node.is_blocked(to) {
        return Ok(false);
    }
    if !node.members().get(to).is_some_and(|m| m.active) {
        return Ok(false);
    }
    Ok(!crate::cluster::seal::forked_set(&node.store.pool)
        .await?
        .contains(to))
}

async fn transfer(node: &Node, to: NodeId, parts: Vec<(u32, u32)>) -> Result<()> {
    repl::append_sealing(node, |seal| Record::CreditTransfer { to, parts, seal }).await?;
    Ok(())
}

/// Send `mc` to `to`, oldest lots first. No fee. Refused when this node
/// does not hold that much, or `to` cannot receive.
pub async fn send(node: &Node, to: NodeId, mc: Mc) -> Result<Mc> {
    if !receivable(node, &to).await? {
        bail!(
            "{} is not a member credits can be sent to from here",
            to.short()
        );
    }
    let book = super::book_fresh(node).await?;
    let Some(parts) = book.ledger.spendable_parts(&node.id(), mc) else {
        bail!(
            "this node holds {} credits, not {}",
            show(book.balance(&node.id())),
            show(mc)
        );
    };
    transfer(node, to, parts).await?;
    tracing::info!(to = %to.short(), credits = %show(mc), "credits sent");
    Ok(mc)
}

/// Forward everything this node holds to `to`, when it holds at least a
/// credit or a lot is on its last day. Returns what was sent.
pub async fn collect(node: &Node, to: NodeId) -> Result<Mc> {
    if !receivable(node, &to).await? {
        return Ok(0);
    }
    let me = node.id();
    let book = super::book_fresh(node).await?;
    let have = book.balance(&me);
    if have == 0 || (have < CREDIT && book.ledger.expiring_today(&me) == 0) {
        return Ok(0);
    }
    let Some(parts) = book.ledger.spendable_parts(&me, have) else {
        return Ok(0);
    };
    transfer(node, to, parts).await?;
    tracing::info!(to = %to.short(), credits = %show(have), "credits forwarded to the collecting node");
    Ok(have)
}

/// Answer draws: a sibling gets what it asks for, as far as this node's
/// balance goes. Anyone else gets no answer.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::CreditDraw { mc } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            let siblings = crate::cluster::owner::fleet::siblings(&node.store)
                .await
                .ok()?;
            if !siblings.contains(&from) {
                tracing::debug!(by = %from.short(), "credit draw by a node that is not ours: not answered");
                return None;
            }
            let have = super::book_fresh(&node).await.ok()?.balance(&node.id());
            let give = mc.min(have);
            let sent_mc = match give {
                0 => 0,
                _ => send(&node, from, give).await.unwrap_or(0),
            };
            Some(Msg::CreditDrawReply { sent_mc })
        })
    }));
}

/// Draw `mc` from this node's collecting node and wait for the transfer
/// to arrive. False: no collecting node, it did not answer, or it sent
/// nothing.
pub async fn draw(node: &Arc<Node>, mc: Mc) -> bool {
    let me = node.id();
    let Some(from) = (*node.collect_to.read().unwrap()).filter(|c| *c != me) else {
        return false;
    };
    let before = match super::book_fresh(node).await {
        Ok(b) => b.balance(&me),
        Err(_) => return false,
    };
    let avoid = crate::cluster::owner::cmd::old_relays(node, &from);
    let sent = match node
        .request_avoiding(from, Msg::CreditDraw { mc }, DRAW_WAIT, avoid)
        .await
    {
        Ok(Msg::CreditDrawReply { sent_mc }) => sent_mc,
        _ => 0,
    };
    if sent == 0 {
        return false;
    }
    // The transfer is an entry of the collecting node's log: fetch it.
    if let Some(addr) = node.dial_address(&from) {
        let _ = crate::cluster::sync::reconcile(node, from, &addr, false).await;
    }
    let until = tokio::time::Instant::now() + DRAW_WAIT;
    loop {
        if let Ok(b) = super::book_fresh(node).await
            && b.balance(&me) > before
        {
            return true;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Keep the node's collecting node in step with its settings, and forward
/// what it holds every [`COLLECT_EVERY`].
pub async fn run(
    node: Arc<Node>,
    settings: Settings,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut changed = settings.subscribe();
    let mut next = tokio::time::Instant::now() + COLLECT_EVERY;
    loop {
        let to = settings.snapshot().collect_to;
        *node.collect_to.write().unwrap() = to;
        if tokio::time::Instant::now() >= next {
            next = tokio::time::Instant::now() + COLLECT_EVERY;
            if let Some(to) = to
                && let Err(e) = collect(&node, to).await
            {
                tracing::debug!(?e, "credits not forwarded");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep_until(next) => {}
            _ = changed.changed() => {}
            _ = shutdown.changed() => break,
        }
    }
}
```

Add `pub mod fleet;` to `src/credits/mod.rs`. `src/lib.rs`, below the `tokio::spawn(credits::run(…));` statement:

```rust
        credits::fleet::serve(node);
        tokio::spawn(credits::fleet::run(
            node.clone(),
            settings.clone(),
            shutdown_rx.clone(),
        ));
```

`src/credits/pay.rs`, in `offer_and_ask`: replace the `let Some(parts) = book.ledger.spendable_parts(&me, total_mc) else { … };` statement by

```rust
    let mut book = book;
    if book.ledger.spendable_parts(&me, total_mc).is_none() {
        // The fleet's balance sits at its collecting node: draw what is
        // missing, then look again.
        let missing = total_mc.saturating_sub(book.balance(&me));
        if super::fleet::draw(node, missing).await
            && let Ok(b) = super::book_fresh(node).await
        {
            book = b;
        }
    }
    let Some(parts) = book.ledger.spendable_parts(&me, total_mc) else {
        let have = book.balance(&me);
        return decline(format!(
            "this node holds {} credits; the lookup costs {} ({} missing)",
            show(have),
            show(total_mc),
            show(total_mc.saturating_sub(have))
        ));
    };
```

- [ ] **Step 5: The owner's command and the button**

`src/cluster/owner/cmd.rs`:

- `enum OwnerCmd` gains `/// The node sends credits to a member (\`credits::fleet\`).\n    SendCredits { to: NodeId, mc: u64 },`.
- `describe`: `OwnerCmd::SendCredits { to, mc } => format!("send {} credits to {}", crate::credits::show(*mc), to.short()),`.
- `execute`:

```rust
        OwnerCmd::SendCredits { to, mc } => {
            let sent = crate::credits::fleet::send(node, *to, *mc)
                .await
                .map_err(err)?;
            Ok(format!(
                "sent {} credits to {}",
                crate::credits::show(sent),
                to.short()
            ))
        }
```

`src/admin/cluster_owner.rs`: the route `.route("/admin/cluster/ownership/collect-here", post(collect_here))` and

```rust
/// Make this node the fleet's collecting node: every sibling that answers
/// is told to forward its credits here.
async fn collect_here(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    let key = match cmd::kept_key(node).await {
        Ok(k) => k,
        Err(e) => return Ok(back_to(PAGE, None, Some(format!("{e:#}")))),
    };
    let me = node.id().to_string();
    let (mut told, mut failed) = (0, vec![]);
    for sib in fleet::siblings(&node.store).await? {
        let done = async {
            let st = cmd::status(node, &key, sib).await?;
            let set = cmd::OwnerCmd::Settings {
                base_version: st.state.version,
                changes: crate::settings::Changes {
                    collect_to: Some(me.clone()),
                    ..Default::default()
                },
            };
            match cmd::run(node, &key, sib, st.counter, set).await? {
                Ok(_) => anyhow::Ok(()),
                Err(e) => anyhow::bail!("{e}"),
            }
        };
        match done.await {
            Ok(()) => told += 1,
            Err(e) => failed.push(format!("{}: {e:#}", sib.short())),
        }
    }
    // This node keeps what it earns.
    let own = crate::settings::Changes {
        collect_to: Some(String::new()),
        ..Default::default()
    };
    st.settings.apply(&own, None).await?.map_err(anyhow::Error::msg)?;
    Ok(if failed.is_empty() {
        back_to(
            PAGE,
            Some(format!("{told} of your nodes now forward their credits to this node.")),
            None,
        )
    } else {
        back_to(
            PAGE,
            None,
            Some(format!("{told} told; not reached: {}", failed.join("; "))),
        )
    })
}
```

`templates/admin_cluster_ownership.html`: in the "My nodes" card, after the table's closing `</div>`:

```html
  {% if managing && nodes.len() > 1 %}
  <form method="post" action="/admin/cluster/ownership/collect-here"><button class="btn btn-sm" type="submit">Collect credits here</button> <span class="muted small">your other nodes forward what they earn to this one; any of them can still spend it</span></form>
  {% endif %}
```

What the ownership plan left for this one (its "Not in this plan"): balances in a sibling's status and on the Ownership page, and sending from a sibling's page.

- `src/cluster/owner/cmd.rs`: `struct Status` gains

```rust
    /// The node's credits as it counts them itself, in mc.
    #[serde(default)]
    pub balance_mc: u64,
    /// Where it forwards its credits (a node key), if anywhere.
    #[serde(default)]
    pub collect_to: Option<String>,
```

  filled in `status_of`: `balance_mc: crate::credits::book(node).await.map(|b| b.balance(&node.id())).unwrap_or(0),` and `collect_to: settings.snapshot().collect_to.map(|id| id.to_string()),`.
- `src/admin/cluster.rs`, `node_owner`: the `match (f.action.as_str(), peer, f.invite)` gains, before the `_` arm,

```rust
        ("send-credits", Some(n), _) => match f
            .amount
            .as_deref()
            .and_then(crate::credits::parse_amount)
        {
            Some(mc) => OwnerCmd::SendCredits { to: n, mc },
            None => return Ok(back_to(&to, None, Some("an amount like 0.5 is needed".into()))),
        },
```

  and `OwnerForm` the field `/// Credits to send, as typed ("0.5").\n    amount: Option<String>,`.
- `templates/admin_cluster_node.html`, in the `Remote::Settings` arm before `<h3>Leave or release</h3>`:

```html
  <h3>Credits there</h3>
  <p>{{ crate::credits::show(status.balance_mc) }} credits as {{ m.name }} counts them{% if let Some(c) = status.collect_to %} · forwards what it earns to <span class="mono">{{ c|truncate(24) }}</span>{% endif %}</p>
  {% if !peers.is_empty() %}
  <form method="post" action="/admin/cluster/node/{{ m.key }}/owner" class="filters">
    <input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="action" value="send-credits">
    <label>Send from there to <select name="target">{% for p in peers %}<option value="{{ p.0 }}">{{ p.1 }}</option>{% endfor %}</select></label>
    <label>Credits <input name="amount" size="8" inputmode="decimal" placeholder="0.5" required></label>
    <button class="btn btn-sm" type="submit">Send</button>
  </form>{% endif %}
```

- `src/admin/cluster_owner.rs`: `NodeRow` gains `credits: String,` (from `crate::credits::book(node).await?`: `crate::credits::show(book.balance(&id))` for the row's node; parse the row's key with `NodeId::parse`), and `templates/admin_cluster_ownership.html`'s "My nodes" table the column `<th class="num">Credits</th>` / `<td class="num">{{ n.credits }}</td>` after Version.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib settings:: && cargo test --lib cluster::owner::cmd && cargo test --lib credits:: && cargo test --test cli && cargo test --test cluster a_fleet_collects && cargo test --test cluster a_node_draws_what_a_lookup_needs && cargo test --test cluster admin_takes_and_gives_up_ownership`
Expected: PASS. The draw test takes about 5 s (the stranger's unanswered draw runs into its timeout).

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add -A src templates tests
git commit -m "Credits: a fleet collects at one node, draws from it, and anyone can send

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Part E: admin area, CLI, docs

### Task 16: One view of an address for the IP page and the lookup result

A lookup shows everything the cluster knows about the address. The IP page's sections move into one partial that both pages render from one loader, so an aggregation added later appears in both. The Lookup page shows the balance, the prices, what a lookup costs, and the result in three parts.

**Files:**
- Create: `src/admin/target.rs`, `templates/_target.html`
- Modify: `src/admin/mod.rs` (module), `src/admin/public.rs` (`IpPage`, `ip_page`), `templates/ip.html`, `src/admin/lookup.rs`, `templates/admin_lookup.html`, `tests/cluster.rs`
- Test: unit tests in `src/admin/lookup.rs` (existing, adjusted) and `src/admin/public.rs` (existing); `tests/cluster.rs::the_lookup_result_of_a_recorded_address_has_the_sections_of_its_ip_page`

**Interfaces:**
- Consumes: `lookup::{run, Outcome}`, `pay::{Stored, quotes, Quote}` (Tasks 13, 14); `credits::{book, show}`; `owner::fleet::siblings`; `Node::retention_days`; the store readers `ip_page` uses today.
- Produces:
  - `admin::target::Target { pub ov: Arc<IpOverview>, pub week_json: String, pub calendar_json: String, pub family_max: i64, pub page: Page<RequestListRow>, pub intel: Vec<IntelCard>, pub admin: Option<IpAdminData>, pub labels: bool, pub paged: bool, pub window_days: u32 }`
  - `admin::target::load(state: &AdminState, ip: &IpRow, authed: bool, page: i64, paged: bool) -> AppResult<Option<Target>>`
  - `admin::target::neighbourhood(state: &AdminState, ip: IpAddr) -> AppResult<Neighbourhood>` with `Neighbourhood { pub net: String, pub net_count: i64, pub neighbours: Vec<…> }` for an address the dataset does not hold
  - In `_target.html` every section carries `data-section="<name>"`: `intel`, `scans`, `host-keys`, `canaries`, `decoys`, `activity`, `families`, `neighbourhood`, `fingerprints`, `claims`, `requests`

- [ ] **Step 1: Write the failing test**

Append to `tests/cluster.rs`:

```rust
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
    assert!(on_ip_page.contains(&"scans".to_string()) && on_ip_page.contains(&"requests".to_string()));
    assert_eq!(sections(&result), on_ip_page, "one source for both pages");
    assert!(result.contains("Asked now") && result.contains("node-bravo"));
    assert!(result.contains(&format!("charged {}", peephole::credits::show(cost as u64))));
    assert!(result.contains("kept in the dataset"), "the cluster recorded this address");

    // Asked again within 24 hours: from the dataset, with "Ask again".
    let second = admin
        .post(format!("{base}/admin/lookup"))
        .form(&[("ip", "198.51.100.77")])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(second.contains("From the dataset") && second.contains("Ask again"), "{second}");
    assert!(!second.contains("Asked now"));

    // An address the dataset does not hold: said so, with what is near it.
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
    assert!(unknown.contains("198.51.100.0/24") && unknown.contains("198.51.100.77"), "{unknown}");
    assert!(unknown.contains("not kept"));
    assert!(sections(&unknown).is_empty());
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test --test cluster the_lookup_result_of_a_recorded_address`
Expected: FAIL (the form shows no balance; later: the result has no sections).

- [ ] **Step 3: The loader and the partial**

Create `src/admin/target.rs`:

```rust
//! Everything the dataset holds on one address. The IP page and the
//! lookup result both render this, from `templates/_target.html`: an
//! aggregation added here appears in both.
use crate::admin::AdminState;
use crate::admin::error::AppResult;
use crate::admin::public::{IntelCard, IpAdminData, ScanWithPorts, intel_cards};
use crate::store::browse::{Audience, IpOverview, Page, RequestListRow};
use crate::store::requests::IpRow;
use std::sync::Arc;

/// One address as the dataset knows it.
pub struct Target {
    pub ov: Arc<IpOverview>,
    /// `ov.week` and `ov.calendar` for the charts.
    pub week_json: String,
    pub calendar_json: String,
    /// Largest family count, for the bar widths.
    pub family_max: i64,
    pub page: Page<RequestListRow>,
    pub intel: Vec<IntelCard>,
    /// Admin-only sections; loaded only with a session.
    pub admin: Option<IpAdminData>,
    pub labels: bool,
    /// The requests list links to further pages (the IP page; the lookup
    /// result links to the IP page instead).
    pub paged: bool,
    /// Days of history this node keeps; 0: all of it.
    pub window_days: u32,
}

/// Load `ip`'s view. None: the address is in the table but has no
/// overview (nothing recorded about it).
pub async fn load(
    state: &AdminState,
    ip: &IpRow,
    authed: bool,
    page: i64,
    paged: bool,
) -> AppResult<Option<Target>> {
    // Anonymous views go through the cache; an admin always reads fresh.
    let ov = if authed {
        state.store.ip_overview(ip.id).await?.map(Arc::new)
    } else {
        state.stats_cache.ip(&state.store, ip.id).await?
    };
    let Some(ov) = ov else {
        return Ok(None);
    };
    // Per-request rows are admin-only: not even queried for the public.
    let requests = if authed {
        state
            .store
            .requests_for_ip(ip.id, page, Audience::Admin)
            .await?
    } else {
        Page {
            items: vec![],
            page: 1,
            has_next: false,
        }
    };
    let admin = if authed {
        let found = state.store.scans_for_ip(ip.id).await?;
        let ids: Vec<i64> = found.iter().map(|s| s.id).collect();
        let mut ports = state.store.ports_for_scans(&ids).await?;
        let scans = found
            .into_iter()
            .map(|s| ScanWithPorts {
                ports: ports.remove(&s.id).unwrap_or_default(),
                s,
            })
            .collect();
        Some(IpAdminData {
            jobs: state.store.jobs_for_ip(ip.id, 20).await?,
            scans,
            fingerprints: state.store.fingerprints_for_ip(ip.id).await?,
            claims: state.store.claims_for_ip(ip.id).await?,
            skipped: state.store.skipped_for_ip(ip.id).await?,
            host_keys: state.store.host_keys_for_ip(ip.id).await?,
            canary_links: state.store.canary_links_for_ip(ip.id).await?,
            decoys: state.store.decoy_counts_for_ip(ip.id).await?,
        })
    } else {
        None
    };
    Ok(Some(Target {
        week_json: serde_json::to_string(&ov.week).unwrap_or_else(|_| "[]".into()),
        calendar_json: serde_json::to_string(&ov.calendar).unwrap_or_else(|_| "[]".into()),
        family_max: ov.families.iter().map(|f| f.count).max().unwrap_or(0),
        intel: intel_cards(state.store.intel_for_ip(&ip.ip).await?, authed),
        page: requests,
        admin,
        labels: crate::admin::public::labels_shown(state, authed),
        paged,
        window_days: state.recorder.node().map_or(0, |n| n.retention_days),
        ov,
    }))
}

/// What is near an address the dataset does not hold: the recorded
/// addresses in its network.
pub struct Neighbourhood {
    pub net: String,
    pub rows: Vec<crate::store::browse::IpSummary>,
}

pub async fn neighbourhood(state: &AdminState, ip: std::net::IpAddr) -> AppResult<Neighbourhood> {
    let prefix = if ip.is_ipv4() { 24 } else { 48 };
    let net = ipnet::IpNet::new(ip, prefix)
        .map(|n| n.trunc())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let rows = state.store.ips_matching(&[], &[net], 20).await?;
    Ok(Neighbourhood {
        net: net.to_string(),
        rows,
    })
}
```

Make what it uses reachable: in `src/admin/public.rs`, `labels_shown` becomes `pub(crate) fn labels_shown`. Add `pub mod target;` to `src/admin/mod.rs` (after `pub mod system;`).

Create `templates/_target.html` by moving, from `templates/ip.html`, everything from the line `  <section class="card" id="intel">` through the closing `</section>` of the Requests card (the block that starts `{% if chrome.authed %}` and holds the requests table), unchanged apart from this:

- Every use of the page's variables goes through `t`: `ov` → `t.ov`, `intel` → `t.intel`, `admin` → `t.admin`, `week_json` → `t.week_json`, `calendar_json` → `t.calendar_json`, `family_max` → `t.family_max`, `labels` → `t.labels`, `page.items` → `t.page.items` (`{% for c in intel %}` becomes `{% for c in t.intel %}`, `{% if let Some(adm) = admin %}` becomes `{% if let Some(adm) = t.admin %}`, and so on).
- Each `<section …>` gets its name: `data-section="intel"` (Intelligence), `"scans"` (Counter-scans), `"host-keys"`, `"canaries"`, `"decoys"`, `"activity"`, `"families"` (What it was after), `"neighbourhood"`, `"fingerprints"`, `"claims"` (False-positive claims), `"requests"`.
- In the Activity card's head, after `<span class="muted">UTC</span>`: `{% if t.window_days > 0 %}<span class="muted">this node keeps {{ t.window_days }} days</span>{% endif %}`.
- The pagination line at the end of the Requests card becomes

```html
    {% if t.paged %}{% let page = t.page %}{% let qs = "" %}{% include "_pagination.html" %}{% else if t.page.has_next %}<p class="muted"><a href="/ip/{{ t.ov.ip.ip }}">All requests on its page →</a></p>{% endif %}
```

`templates/ip.html` then is: its head and tiles as they are (with `ov` → `t.ov`, `admin` → `t.admin`), then

```html
<div class="stack">
  {% include "_target.html" %}
  {% if can_delete %}
  … the danger zone card, unchanged, with `ov` → `t.ov` …
  {% endif %}
</div>
{% endblock %}
```

`src/admin/public.rs`: `IpPage` becomes

```rust
#[derive(Template)]
#[template(path = "ip.html")]
struct IpPage {
    chrome: Chrome,
    /// Everything the dataset holds on the address (also what the lookup
    /// result shows).
    t: crate::admin::target::Target,
    /// Admin on a standalone node: the IP can be deleted.
    can_delete: bool,
}
```

and `ip_page`'s body, after the `ip_by_addr` lookup:

```rust
    let Some(t) =
        crate::admin::target::load(&state, &ip, authed, page_num(q.page), true).await?
    else {
        return Err(AppError::NotFound);
    };
    render(&IpPage {
        chrome: Chrome::new(authed, "ips"),
        t,
        can_delete: authed && state.can_delete(),
    })
```

- [ ] **Step 4: The Lookup page**

`src/admin/lookup.rs`: replace `LookupResult`, `LookupPage`, `IpForm`, `page`, `lookup` and `run` by the following (the bulk form and its handler stay; every `LookupPage { … }` literal in `bulk` gets the new fields from `offer(&state).await?`):

```rust
/// One provider as it would be asked: by whom, and at what price.
pub struct QuoteView {
    pub label: String,
    pub node: String,
    pub price: String,
}

/// What the form shows before a lookup: what this node can spend and what
/// the cluster asks.
#[derive(Default)]
pub struct Offer {
    /// The balance in credits (the fleet's, when this node has an owner).
    pub balance: Option<String>,
    pub fleet: bool,
    pub quotes: Vec<QuoteView>,
    /// What a lookup of every provider costs at most.
    pub total: String,
}

async fn offer(state: &AdminState) -> anyhow::Result<Offer> {
    let Some(node) = state.recorder.node() else {
        return Ok(Offer::default());
    };
    let book = crate::credits::book(node).await?;
    let siblings = crate::cluster::owner::fleet::siblings(&node.store).await?;
    let balance: u64 = std::iter::once(node.id())
        .chain(siblings.iter().copied())
        .map(|id| book.balance(&id))
        .sum();
    let all = crate::credits::pay::quotes(node, &state.providers);
    let mut quotes = vec![];
    let mut total = 0u64;
    for info in crate::intel::KNOWN_PROVIDERS {
        let Some(q) = all.get(info.name).and_then(|l| l.first()) else {
            continue;
        };
        total += q.price_mc as u64;
        quotes.push(QuoteView {
            label: info.label.to_string(),
            node: q.server_name.clone(),
            price: if q.price_mc == 0 {
                "free".into()
            } else {
                crate::credits::show(q.price_mc as u64)
            },
        });
    }
    Ok(Offer {
        balance: Some(crate::credits::show(balance)),
        fleet: !siblings.is_empty(),
        quotes,
        total: crate::credits::show(total),
    })
}

/// A provider answer the dataset already held.
pub struct StoredView {
    pub card: IntelCard,
    pub provider: String,
    pub age: String,
}

/// The result for one address.
pub struct LookupResult {
    pub ip: String,
    /// What the dataset holds on the address; None: it is not in it.
    pub target: Option<crate::admin::target::Target>,
    /// For an address the dataset does not hold: what is near it.
    pub near: Option<crate::admin::target::Neighbourhood>,
    /// Provider answers from the dataset (under 24 hours old).
    pub stored: Vec<StoredView>,
    /// Answers asked for now, with the node that served and its charge.
    pub cards: Vec<IntelCard>,
    /// `(node, charged)` for every node that charged something.
    pub charges: Vec<(String, String)>,
    /// `(provider label, node, why)` for every provider without an answer.
    pub declined: Vec<(String, String, String)>,
    /// A serving node kept the answers in the dataset.
    pub kept: bool,
}

#[derive(Template)]
#[template(path = "admin_lookup.html")]
struct LookupPage {
    chrome: Chrome,
    ip: String,
    error: Option<String>,
    result: Option<LookupResult>,
    cluster: bool,
    offer: Offer,
    bulk: Option<Bulk>,
}

#[derive(serde::Deserialize, Default)]
pub struct IpForm {
    pub ip: Option<String>,
    /// A provider to ask although the dataset has a fresh answer.
    pub again: Option<String>,
}

async fn page(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Query(q): Query<IpForm>,
) -> AppResult<Html<String>> {
    render(&LookupPage {
        chrome: chrome(),
        ip: q.ip.unwrap_or_default().trim().to_string(),
        error: None,
        result: None,
        cluster: state.recorder.node().is_some(),
        offer: offer(&state).await?,
        bulk: None,
    })
}

async fn lookup(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
    Form(f): Form<IpForm>,
) -> AppResult<Html<String>> {
    let text = f.ip.unwrap_or_default().trim().to_string();
    let cluster = state.recorder.node().is_some();
    let Ok(ip) = text.parse::<IpAddr>() else {
        return render(&LookupPage {
            chrome: chrome(),
            ip: text,
            error: Some("Not an IP address.".into()),
            result: None,
            cluster,
            offer: offer(&state).await?,
            bulk: None,
        });
    };
    let ip = crate::net::canonical(ip);
    let again: Vec<String> = f.again.into_iter().filter(|a| !a.is_empty()).collect();
    let result = run(&state, ip, &again).await?;
    render(&LookupPage {
        chrome: chrome(),
        ip: ip.to_string(),
        error: None,
        result: Some(result),
        cluster,
        // After the lookup: the balance it left.
        offer: offer(&state).await?,
        bulk: None,
    })
}

fn age(secs: i64) -> String {
    match secs {
        s if s < 120 => "just now".into(),
        s if s < 7200 => format!("{} min old", s / 60),
        s => format!("{} h old", s / 3600),
    }
}

/// Look the address up and arrange the three parts of the page: what the
/// dataset knows, provider answers from the dataset, and live answers.
pub async fn run(state: &AdminState, ip: IpAddr, again: &[String]) -> AppResult<LookupResult> {
    let out = crate::intel::lookup::run(&state.recorder, &state.providers, ip, again).await;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let label = |p: &str| {
        crate::intel::provider_info(p)
            .map(|i| i.label.to_string())
            .unwrap_or_else(|| p.to_string())
    };
    let (mut rows, mut declined, mut charges) = (vec![], vec![], vec![]);
    for a in &out.answers {
        for f in &a.resp.findings {
            rows.push(IpIntelRow {
                provider: f.provider.clone(),
                fetched_at: now.clone(),
                source_version: f.source_version.clone(),
                data_json: f.data.to_string(),
                node: Some(a.node.clone()),
            });
        }
        for (p, why) in &a.resp.declined {
            declined.push((label(p), a.node.clone(), why.clone()));
        }
        if a.charged_mc > 0 {
            charges.push((a.node.clone(), crate::credits::show(a.charged_mc as u64)));
        }
    }
    // Cards only for providers that answered; the rest is listed below.
    let cards = intel_cards(rows, true)
        .into_iter()
        .filter(|c| c.newest.is_some())
        .collect();
    let stored = out
        .stored
        .iter()
        .flat_map(|s| {
            let row = IpIntelRow {
                provider: s.provider.clone(),
                fetched_at: s.fetched_at.clone(),
                source_version: s.source_version.clone(),
                data_json: s.data.to_string(),
                node: s.node.clone(),
            };
            intel_cards(vec![row], true)
                .into_iter()
                .filter(|c| c.newest.is_some())
                .map(|card| StoredView {
                    card,
                    provider: s.provider.clone(),
                    age: age(s.age_secs),
                })
        })
        .collect();
    let row = state.store.ip_by_addr(&ip.to_string()).await?;
    let target = match &row {
        Some(r) => crate::admin::target::load(state, r, true, 1, false).await?,
        None => None,
    };
    let near = match target {
        Some(_) => None,
        None => Some(crate::admin::target::neighbourhood(state, ip).await?),
    };
    Ok(LookupResult {
        ip: ip.to_string(),
        target,
        near,
        stored,
        cards,
        charges,
        declined,
        kept: out.kept,
    })
}
```

`templates/admin_lookup.html`: add `{% block head %}<script src="/assets/js/charts.js?v={{ chrome.stamp }}" defer></script>{% endblock %}` after the title block (the Activity section draws charts), and replace the single-address form and everything from `{% if let Some(e) = error %}` to the end by:

```html
<form class="filters card" method="post" action="/admin/lookup">
  <label>IP address <input name="ip" value="{{ ip }}" placeholder="203.0.113.7 or 2001:db8::1" required autofocus></label>
  <button class="btn btn-primary" type="submit">Look up</button>
  {% if let Some(b) = offer.balance %}
  <span class="muted">Balance{% if offer.fleet %} of your nodes{% endif %}: <b>{{ b }}</b> credits · this lookup costs up to {{ offer.total }} · <a href="/admin/cluster/credits">credits →</a></span>
  {% endif %}
</form>
{% if !offer.quotes.is_empty() %}
<details class="card"><summary>Who would be asked, and at what price</summary>
  <div class="table-wrap"><table>
    <thead><tr><th>Provider</th><th>Node</th><th class="num">Price (credits)</th></tr></thead>
    <tbody>{% for q in offer.quotes %}<tr><td>{{ q.label }}</td><td>{{ q.node }}</td><td class="num">{{ q.price }}</td></tr>{% endfor %}</tbody>
  </table></div>
  <p class="muted small">Per provider the node with the lowest price answers, your own included. An answer of the last 24 hours in the dataset is shown instead and costs nothing.</p>
</details>
{% endif %}
```

(the bulk form and the stored-data card stay between this and what follows)

```html
{% if let Some(e) = error %}<p class="muted">{{ e }}</p>{% endif %}
{% if let Some(r) = result %}
<div class="stack">
<section class="card" id="answers">
  <div class="card-head"><h2>{{ r.ip }}{% let value = r.ip.as_str() %}{% let what = "IP address" %}{% let subtle = false %}{% include "_copy.html" %}</h2><span class="muted">{% if r.target.is_some() %}<a href="/ip/{{ r.ip }}">in the dataset →</a>{% else %}not in the dataset{% endif %}</span></div>
  {% if !r.stored.is_empty() %}
  <h3>From the dataset</h3>
  <div class="intel-grid">
  {% for s in r.stored %}
    <div class="intel">
      <h3>{{ s.card.label }} <span class="mono muted small">{{ s.card.name }}</span></h3>
      {% if let Some(x) = s.card.newest %}
        <dl class="kv">{% for f in x.facts %}<dt>{{ f.label }}</dt><dd{% if !f.mono %} class="plain"{% endif %}>{{ f.value }}</dd>{% endfor %}</dl>
        <p class="muted small intel-src">from the dataset, {{ s.age }}{% if let Some(n) = x.node %}, fetched by {{ n }}{% endif %} · free</p>
      {% endif %}
      <form method="post" action="/admin/lookup"><input type="hidden" name="ip" value="{{ r.ip }}"><input type="hidden" name="again" value="{{ s.provider }}"><button class="btn btn-sm" type="submit">Ask again</button> <span class="muted small">a paid lookup</span></form>
    </div>
  {% endfor %}
  </div>
  {% endif %}
  {% if !r.cards.is_empty() %}
  <h3>Asked now</h3>
  <div class="intel-grid">
  {% for c in r.cards %}
    <div class="intel">
      <h3>{{ c.label }} <span class="mono muted small">{{ c.name }}</span></h3>
      {% if let Some(x) = c.newest %}
        <dl class="kv">{% for f in x.facts %}<dt>{{ f.label }}</dt><dd{% if !f.mono %} class="plain"{% endif %}>{{ f.value }}</dd>{% endfor %}</dl>
        <p class="muted small intel-src">looked up <span class="mono">{{ x.fetched_at }}</span>{% if let Some(v) = x.source_version %} · data <span class="mono">{{ v }}</span>{% endif %}{% if let Some(n) = x.node %} · by {{ n }}{% endif %}</p>
      {% endif %}
    </div>
  {% endfor %}
  </div>
  {% for (node, amount) in r.charges %}<p class="small">{{ node }} charged {{ amount }} credits.</p>{% endfor %}
  {% if cluster %}<p class="muted small">{% if r.kept %}The answers are kept in the dataset: the cluster has recorded this address.{% else %}The answers are not kept: the cluster has not recorded this address.{% endif %}</p>{% endif %}
  {% else if r.stored.is_empty() %}
  <p class="muted">No provider answered.</p>
  {% endif %}
  {% if !r.declined.is_empty() %}
  <h3>Not answered</h3>
  <ul class="small">
    {% for (label, node, why) in r.declined %}<li><strong>{{ label }}</strong> <span class="muted">({{ node }})</span>: {{ why }}</li>{% endfor %}
  </ul>
  {% endif %}
</section>
{% if let Some(t) = r.target %}
{% include "_target.html" %}
{% endif %}
{% if let Some(n) = r.near %}
<section class="card"><div class="card-head"><h2>Near it</h2><span class="muted">recorded addresses in <a class="mono" href="/ips?q={{ n.net }}">{{ n.net }}</a></span></div>
  {% if n.rows.is_empty() %}<p class="muted">None recorded.</p>{% else %}
  <div class="table-wrap"><table><thead><tr><th>IP</th><th>Country</th><th>ASN</th><th class="num">Requests</th><th>Max sev.</th></tr></thead><tbody>
  {% for x in n.rows %}<tr><td><a class="mono" href="/ip/{{ x.ip }}">{{ x.ip }}</a></td><td>{{ x.country.as_deref().unwrap_or("—") }}</td><td>{% if let Some(a) = x.asn %}AS{{ a }}{% else %}—{% endif %}</td><td class="num">{{ x.request_count }}</td><td>{{ x.max_severity }}</td></tr>{% endfor %}
  </tbody></table></div>{% endif %}
</section>
{% endif %}
</div>
{% endif %}
{% endblock %}
```

The page's subtitle (line 5) becomes `<p class="muted">What the cluster knows about an address, and what every reachable provider says now.{% if cluster %} Provider answers are paid with credits.{% endif %}</p>`.

The existing unit test of `admin/lookup.rs` (`the_page_needs_a_session_and_answers_from_local_providers`, a standalone node) keeps its assertions except two texts: `"in the dataset"` stays; where it expects `"not in the dataset"` for `2001:db8::1` that still holds. Run it and adjust only what the new markup renamed.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib admin::lookup && cargo test --lib admin::public && cargo test --test cluster the_lookup_result_of_a_recorded_address && cargo test --test integration ip_page`
Expected: PASS. (`tests/integration.rs` holds the IP page's rendering tests; if no test name contains `ip_page`, run the ones that fetch `/ip/` : `grep -n '"/ip/' tests/integration.rs`.)

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add -A src templates tests
git commit -m "Admin: a lookup shows what the cluster knows, its prices and its charges

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 17: Cluster › Credits

**Files:**
- Create: `src/admin/credits.rs`, `templates/admin_cluster_credits.html`
- Modify: `src/admin/mod.rs` (module, router), `src/admin/views.rs` (`CLUSTER_TABS`), `tests/cluster.rs`
- Test: unit test in `src/admin/credits.rs`; `tests/cluster.rs::the_credits_page_shows_balance_earnings_payments_and_the_price`

**Interfaces:**
- Consumes: `credits::{book_fresh, show, parse_amount, day_of, Book}`, `earn::Paid`, `ledger::{Offer, OfferState, Moved, Tally}`, `price::Table`, `fleet::send`, `owner::fleet::siblings`, `admin::cluster::{node, back_to}`.
- Produces: `admin::credits::routes()`; routes `GET /admin/cluster/credits`, `POST /admin/cluster/credits/send`; tab key `"credits"`; `admin::credits::when(hlc: u64) -> String`, `admin::credits::date_of(day: u32) -> String`

- [ ] **Step 1: Write the failing tests**

Create `src/admin/credits.rs` with its imports and this test module at the end (the rest follows in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_times_read_as_utc() {
        // 2026-10-06 is day 20_732 of the epoch.
        assert_eq!(date_of(20_732), "2026-10-06");
        let noon = (20_732u64 * 86_400_000 + 12 * 3_600_000 + 34 * 60_000) << 16;
        assert_eq!(when(noon), "2026-10-06 12:34");
        assert_eq!(expires_in(20_732, 20_732), "in 6 days");
        assert_eq!(expires_in(20_727, 20_732), "in 1 day");
        assert_eq!(expires_in(20_726, 20_732), "today");
    }
}
```

Append to `tests/cluster.rs`:

```rust
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
        credits::book_fresh(&na.node).await.unwrap().balance(&a.id) == 10_000 - cost
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let page = format!("{base}/admin/cluster/credits");
    let html = text(&admin, page.clone()).await;
    assert!(html.contains("Credits</a>"), "the tab is there");
    assert!(html.contains(&credits::show(10_000 - cost)), "the balance: {html}");
    assert!(html.contains("expires in 6 days") || html.contains("in 6 days"));
    // Earned: the granted scans, with what each paid.
    assert!(html.contains("Earned") && html.contains("1.00") && html.contains("0.25"));
    // Spent: one lookup at b, charged, half of it destroyed.
    assert!(html.contains("Spent") && html.contains("node-bravo") && html.contains("charged"));
    assert!(html.contains("abuseipdb"));
    // Everyone: b holds its half.
    assert!(html.contains(&credits::show(cost / 2)));
    // The price, in words and numbers.
    assert!(html.contains("earned") && html.contains("credits a day"), "{html}");
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
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib admin::credits`
Expected: does not compile (`cannot find function date_of`).

- [ ] **Step 3: The handlers**

`src/admin/credits.rs`, above the test module:

```rust
//! Cluster › Credits: what this node holds, earned and spent, what every
//! member holds in this node's view, and how the price comes about.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::cluster::{back_to, node};
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::identity::NodeId;
use crate::credits::ledger::OfferState;
use crate::credits::{self, show};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

const PAGE: &str = "/admin/cluster/credits";
/// Rows shown per list.
const ROWS: usize = 100;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route(PAGE, get(page))
        .route("/admin/cluster/credits/send", post(send))
}

/// The date of a lot's day.
pub fn date_of(day: u32) -> String {
    chrono::DateTime::from_timestamp(day as i64 * 86_400, 0)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// The minute an entry is dated (UTC).
pub fn when(hlc: u64) -> String {
    chrono::DateTime::from_timestamp_millis(crate::cluster::hlc::physical_ms(hlc) as i64)
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}

/// When a lot of `day` is gone, seen from `today`.
fn expires_in(day: u32, today: u32) -> String {
    match (day + credits::LOT_DAYS - 1).saturating_sub(today) {
        0 => "today".into(),
        1 => "in 1 day".into(),
        n => format!("in {n} days"),
    }
}

struct DayRow {
    date: String,
    amount: String,
    expires: String,
}

struct NodeRow {
    name: String,
    balance: String,
    /// Where it forwards its credits, as its transfers of the week show.
    collects: String,
    is_self: bool,
}

struct EarnedRow {
    at: String,
    /// The scan's page, when the scan is held here.
    scan: Option<i64>,
    ip: String,
    level: u8,
    role: &'static str,
    amount: String,
    note: String,
}

struct SpentRow {
    at: String,
    server: String,
    providers: String,
    offered: String,
    charged: String,
    destroyed: String,
    state: &'static str,
}

struct MovedRow {
    at: String,
    from: String,
    to: String,
    amount: String,
    /// It named more than was there.
    short: bool,
}

struct MemberRow {
    key: String,
    name: String,
    balance: String,
    earned: String,
    spent: String,
    /// Why it does not earn in full here; empty: it does.
    standing: String,
}

struct PriceView {
    earned_per_day: String,
    lookups_per_day: String,
    utilization: String,
    load: String,
    unit: Option<String>,
    /// `(provider label, price, surge, on-demand a day)`.
    offers: Vec<(String, String, u32, String)>,
}

#[derive(Template)]
#[template(path = "admin_cluster_credits.html")]
struct CreditsPage {
    chrome: Chrome,
    balance: String,
    held: String,
    days: Vec<DayRow>,
    /// This node has an owner: its nodes and their total.
    fleet: Option<(String, Vec<NodeRow>)>,
    earned: Vec<EarnedRow>,
    /// Scans that wait to be judged.
    waiting: i64,
    spent: Vec<SpentRow>,
    moved: Vec<MovedRow>,
    members: Vec<MemberRow>,
    /// Earned and destroyed over the entries read, and what is in
    /// circulation now.
    totals: (String, String, String),
    price: PriceView,
    /// `(key, name)` of the members credits can be sent to.
    receivers: Vec<(String, String)>,
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let node = node(&st)?;
    let me = node.id();
    let book = credits::book_fresh(node).await?;
    let l = &book.ledger;
    let members = node.members();
    let name = |id: &NodeId| {
        if *id == me {
            "this node".to_string()
        } else {
            members.get(id).map_or_else(|| id.short(), |m| m.name.clone())
        }
    };
    let siblings = crate::cluster::owner::fleet::siblings(&node.store).await?;

    let days = l
        .by_day(&me)
        .into_iter()
        .map(|(day, mc)| DayRow {
            date: date_of(day),
            amount: show(mc),
            expires: expires_in(day, l.today),
        })
        .collect();
    // Where each of this operator's nodes sent credits last.
    let last_to: HashMap<NodeId, NodeId> = l.transfers.iter().map(|t| (t.from, t.to)).collect();
    let fleet = (!siblings.is_empty()).then(|| {
        let all: Vec<NodeId> = std::iter::once(me).chain(siblings.iter().copied()).collect();
        let total: u64 = all.iter().map(|id| book.balance(id)).sum();
        let rows = all
            .iter()
            .map(|id| NodeRow {
                name: name(id),
                balance: show(book.balance(id)),
                collects: match last_to.get(id).filter(|to| all.contains(to)) {
                    Some(to) => format!("forwards to {}", name(to)),
                    None => "keeps what it earns".into(),
                },
                is_self: *id == me,
            })
            .collect();
        (show(total), rows)
    });

    let mut earned = vec![];
    for p in book.paid.iter().rev() {
        for (who, role, mc, note) in [
            (p.scan.scanner, "scanner", p.scanner_mc, &p.scanner_note),
            (p.scan.trap, "trap", p.trap_mc, &p.trap_note),
        ] {
            if who != me || earned.len() >= ROWS {
                continue;
            }
            let scan: Option<i64> = sqlx::query_scalar("SELECT id FROM scans WHERE uid = ?")
                .bind(&p.scan.scan_uid)
                .fetch_optional(&st.store.read)
                .await?;
            earned.push(EarnedRow {
                at: when(p.scan.hlc),
                scan,
                ip: p.scan.ip.clone(),
                level: p.scan.job_level,
                role,
                amount: show(mc),
                note: note.clone(),
            });
        }
    }
    let waiting: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scans s JOIN scan_jobs j ON j.uid = s.job_uid
         WHERE j.status = 'done' AND s.origin = j.scanner AND s.audit_of IS NULL
           AND (j.scanner = ?1 OR j.origin = ?1) AND s.hlc >= ?2
           AND NOT EXISTS (SELECT 1 FROM credit_scans c WHERE c.job_uid = j.uid)",
    )
    .bind(&me.0[..])
    .bind(crate::cluster::hlc::to_db(credits::window_start(book.now_ms)))
    .fetch_one(&st.store.read)
    .await?;

    let spent = l
        .offers
        .iter()
        .rev()
        .filter(|o| o.payer == me)
        .take(ROWS)
        .map(|o| {
            let (charged, destroyed, state) = match &o.state {
                OfferState::Open => (0, 0, "open"),
                OfferState::Lapsed => (0, 0, "lapsed"),
                OfferState::Charged {
                    charged, destroyed, ..
                } => (
                    *charged,
                    *destroyed,
                    if o.covered < o.offered {
                        "charged (not fully covered at the server)"
                    } else {
                        "charged"
                    },
                ),
            };
            SpentRow {
                at: when(o.hlc),
                server: name(&o.to),
                providers: o.answered.join(", "),
                offered: show(o.offered),
                charged: show(charged),
                destroyed: show(destroyed),
                state,
            }
        })
        .collect();
    let moved = l
        .transfers
        .iter()
        .rev()
        .filter(|t| t.from == me || t.to == me)
        .take(ROWS)
        .map(|t| MovedRow {
            at: when(t.hlc),
            from: name(&t.from),
            to: name(&t.to),
            amount: show(t.moved),
            short: t.moved < t.named,
        })
        .collect();

    let mut rows: Vec<MemberRow> = members
        .values()
        .filter(|m| m.active)
        .map(|m| {
            let t = l.tally(&m.id);
            MemberRow {
                key: m.id.to_string(),
                name: name(&m.id),
                balance: show(book.balance(&m.id)),
                earned: show(t.earned),
                spent: show(t.spent),
                standing: book.standing(&m.id).reasons().join("; "),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let totals = (
        show(l.tallies.values().map(|t| t.earned).sum()),
        show(l.tallies.values().map(|t| t.destroyed).sum()),
        show(l.circulating()),
    );

    let t = node.price_table();
    let label = |p: &str| {
        crate::intel::provider_info(p)
            .map(|i| i.label.to_string())
            .unwrap_or_else(|| p.to_string())
    };
    let price = PriceView {
        earned_per_day: show(t.earned_per_day),
        lookups_per_day: format!("{:.0}", t.lookups_per_day),
        utilization: format!("{:.0}", t.capacity.utilization * 100.0),
        load: format!("{:.2}", t.load),
        unit: t.unit.map(show),
        offers: t
            .offers
            .iter()
            .map(|o| {
                (
                    label(&o.provider),
                    if o.price_mc == 0 {
                        "free".into()
                    } else {
                        show(o.price_mc as u64)
                    },
                    o.surge,
                    o.on_demand
                        .map_or_else(|| "no limit".to_string(), |n| n.to_string()),
                )
            })
            .collect(),
    };
    let receivers = members
        .values()
        .filter(|m| m.active && m.id != me && !node.is_blocked(&m.id))
        .map(|m| (m.id.to_string(), m.name.clone()))
        .collect();
    render(&CreditsPage {
        chrome: Chrome::new(true, "admin"),
        balance: show(book.balance(&me)),
        held: show(l.held(&me)),
        days,
        fleet,
        earned,
        waiting,
        spent,
        moved,
        members: rows,
        totals,
        price,
        receivers,
    })
}

#[derive(serde::Deserialize)]
struct SendForm {
    to: String,
    amount: String,
}

async fn send(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<SendForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let (Ok(to), Some(mc)) = (NodeId::parse(&f.to), credits::parse_amount(&f.amount)) else {
        return Ok(back_to(
            PAGE,
            None,
            Some("Choose a member and an amount like 0.5.".into()),
        ));
    };
    Ok(match crate::credits::fleet::send(node, to, mc).await {
        Ok(sent) => back_to(
            PAGE,
            Some(format!("Sent {} credits to {}.", show(sent), to.short())),
            None,
        ),
        Err(e) => back_to(PAGE, None, Some(format!("Not sent: {e:#}"))),
    })
}
```

`src/admin/mod.rs`: `pub mod credits;` after `pub mod countries;`, and `.merge(credits::routes())` below `.merge(cluster_owner::routes())`. `src/admin/views.rs`, `CLUSTER_TABS`: add `("credits", "/admin/cluster/credits", "Credits"),` after the ownership entry.

- [ ] **Step 4: The template**

Create `templates/admin_cluster_credits.html`:

```html
{% extends "layout.html" %}
{% block title %}peephole — cluster credits{% endblock %}
{% block content %}
{% let sub = "cluster" %}{% include "_admin_nav.html" %}
{% let subtab = "credits" %}{% let tabs = crate::admin::views::CLUSTER_TABS %}{% let tabs_label = "Cluster pages" %}{% include "_subtabs.html" %}
<div class="page-head"><div><h1>Credits</h1><p class="muted">Earned by completed counter-scans, spent on lookups. Every figure is this node's own count, from its copy of the log.</p></div></div>
<div class="stack">
<section class="card"><h2>Balance</h2>
  <div class="tiles">
    <div class="tile"><span class="label">This node</span><div class="value">{{ balance }}</div><div class="hint">credits</div></div>
    <div class="tile"><span class="label">Set aside</span><div class="value">{{ held }}</div><div class="hint">in open lookups</div></div>
    {% if let Some((total, _)) = fleet %}<div class="tile"><span class="label">All your nodes</span><div class="value">{{ total }}</div><div class="hint">credits</div></div>{% endif %}
  </div>
  {% if days.is_empty() %}<p class="muted">Nothing to spend. Credits come from completed counter-scans: the scanner earns 1 (levels 1, 2) or 2 (levels 3, 4), the trap that queued the job a quarter of that.</p>{% else %}
  <div class="table-wrap"><table>
    <thead><tr><th>Earned on (UTC)</th><th class="num">Credits</th><th>Expires</th></tr></thead>
    <tbody>{% for d in days %}<tr><td class="mono">{{ d.date }}</td><td class="num">{{ d.amount }}</td><td>{{ d.expires }}</td></tr>{% endfor %}</tbody>
  </table></div>
  <p class="muted small">A credit can be used on the day it was earned and the 6 days after, whoever holds it by then.</p>{% endif %}
</section>
{% if let Some((_, nodes)) = fleet %}
<section class="card"><h2>My nodes</h2>
  <div class="table-wrap"><table>
    <thead><tr><th>Node</th><th class="num">Credits</th><th>Collects</th></tr></thead>
    <tbody>{% for n in nodes %}<tr><td><b>{{ n.name }}</b></td><td class="num">{{ n.balance }}</td><td>{{ n.collects }}</td></tr>{% endfor %}</tbody>
  </table></div>
  <p class="muted small">One node can collect what the others earn (<a href="/admin/cluster/ownership">Ownership</a> › Collect credits here); each of them draws from it when a lookup needs more than it holds.</p>
</section>
{% endif %}
<section class="card"><div class="card-head"><h2>Earned</h2><span class="muted">last 7 days, newest first (UTC)</span></div>
  {% if waiting > 0 %}<p class="muted">{{ waiting }} scan{% if waiting != 1 %}s{% endif %} not judged yet: a scan is judged ten minutes after it arrives.</p>{% endif %}
  {% if earned.is_empty() %}<p class="muted">Nothing yet.</p>{% else %}
  <div class="table-wrap wide"><table>
    <thead><tr><th>When</th><th>Scan</th><th>IP</th><th>Level</th><th>As</th><th class="num">Credits</th><th></th></tr></thead>
    <tbody>{% for e in earned %}<tr>
      <td class="ts">{{ e.at }}</td>
      <td>{% if let Some(id) = e.scan %}<a class="mono" href="/admin/scans/{{ id }}">scan #{{ id }}</a>{% else %}<span class="muted">not held here</span>{% endif %}</td>
      <td><a class="mono" href="/ip/{{ e.ip }}">{{ e.ip }}</a></td><td>{{ e.level }}</td><td>{{ e.role }}</td>
      <td class="num">{{ e.amount }}</td><td class="muted">{{ e.note }}</td>
    </tr>{% endfor %}</tbody>
  </table></div>{% endif %}
</section>
<section class="card"><div class="card-head"><h2>Spent</h2><span class="muted">lookups this node paid for</span></div>
  {% if spent.is_empty() %}<p class="muted">Nothing yet.</p>{% else %}
  <div class="table-wrap wide"><table>
    <thead><tr><th>When</th><th>Answered by</th><th>Providers</th><th class="num">Offered</th><th class="num">Charged</th><th class="num">Of which destroyed</th><th>State</th></tr></thead>
    <tbody>{% for s in spent %}<tr>
      <td class="ts">{{ s.at }}</td><td>{{ s.server }}</td><td class="mono">{{ s.providers }}</td>
      <td class="num">{{ s.offered }}</td><td class="num">{{ s.charged }}</td><td class="num">{{ s.destroyed }}</td><td>{{ s.state }}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
  <p class="muted small">Half of what is charged goes to the node that answered; the other half is destroyed. An offer without an answer lapses after 15 minutes and costs nothing.</p>{% endif %}
</section>
<section class="card"><div class="card-head"><h2>Sent and received</h2></div>
  {% if moved.is_empty() %}<p class="muted">No transfers.</p>{% else %}
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>From</th><th>To</th><th class="num">Credits</th></tr></thead>
    <tbody>{% for m in moved %}<tr><td class="ts">{{ m.at }}</td><td>{{ m.from }}</td><td>{{ m.to }}</td><td class="num">{{ m.amount }}{% if m.short %} <span class="muted small">(less than named)</span>{% endif %}</td></tr>{% endfor %}</tbody>
  </table></div>{% endif %}
  {% if !receivers.is_empty() %}
  <form method="post" action="/admin/cluster/credits/send" class="filters">
    <label>Send to <select name="to">{% for r in receivers %}<option value="{{ r.0 }}">{{ r.1 }}</option>{% endfor %}</select></label>
    <label>Credits <input name="amount" size="8" inputmode="decimal" placeholder="0.5" required></label>
    <button class="btn" type="submit">Send</button>
    <span class="muted small">any member, no fee; it cannot be taken back</span>
  </form>{% endif %}
</section>
<section class="card"><div class="card-head"><h2>Cluster</h2><span class="muted">as this node counts it</span></div>
  <div class="table-wrap"><table>
    <thead><tr><th>Member</th><th class="num">Credits</th><th class="num">Earned</th><th class="num">Spent</th><th></th></tr></thead>
    <tbody>{% for m in members %}<tr>
      <td><a href="/admin/cluster/node/{{ m.key }}"><b>{{ m.name }}</b></a></td>
      <td class="num">{{ m.balance }}</td><td class="num">{{ m.earned }}</td><td class="num">{{ m.spent }}</td>
      <td>{% if !m.standing.is_empty() %}<span class="badge badge-status" data-status="running">not earning here: {{ m.standing }}</span>{% endif %}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
  <p class="muted">Earned {{ totals.0 }} · destroyed {{ totals.1 }} · in circulation {{ totals.2 }} credits. Another node may count differently: it holds other entries, blocks other members, or runs other rules.</p>
</section>
<section class="card"><div class="card-head"><h2>What a lookup costs here</h2></div>
  <ul>
    <li>The cluster earned <b>{{ price.earned_per_day }}</b> credits a day over the last 7 days.</li>
    <li>Its members announce <b>{{ price.lookups_per_day }}</b> paid lookups a day (weighted: a keyed API counts 1, Shodan InternetDB and GeoLite2 a quarter).</li>
    <li>The scanners ran at <b>{{ price.utilization }}%</b> of what they can do: lookups cost <b>{{ price.load }}</b> of the plain price (half when they idle, double when they are saturated).</li>
    <li>{% if let Some(u) = price.unit %}One weighted lookup costs <b>{{ u }}</b> credits: the price at which a day's earnings buy a day's lookups.{% else %}No member announces lookup capacity: what has no budget is priced at the lowest price.{% endif %}</li>
  </ul>
  {% if !price.offers.is_empty() %}
  <div class="table-wrap"><table>
    <thead><tr><th>Provider served here</th><th class="num">Price (credits)</th><th class="num" title="Doubles after a day on which the on-demand share ran out, halves after a day on which it did not">Surge</th><th class="num">Paid lookups a day</th></tr></thead>
    <tbody>{% for o in price.offers %}<tr><td>{{ o.0 }}</td><td class="num">{{ o.1 }}</td><td class="num">×{{ o.2 }}</td><td class="num">{{ o.3 }}</td></tr>{% endfor %}</tbody>
  </table></div>{% endif %}
</section>
</div>
{% endblock %}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib admin::credits && cargo test --test cluster the_credits_page_shows`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/admin/credits.rs src/admin/mod.rs src/admin/views.rs templates/admin_cluster_credits.html tests/cluster.rs
git commit -m "Admin: Cluster › Credits

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 18: Members: who earns here, and the rules display

**Files:**
- Modify: `src/admin/cluster.rs` (`MemberView`, `issues`, `views`, `node_view`, `NodePage`), `src/admin/cluster_owner.rs` and `src/admin/overview.rs` (callers of `views`), `templates/admin_cluster_node.html`, `tests/cluster.rs`
- Test: unit tests in `src/admin/cluster.rs`; `tests/cluster.rs::a_members_page_says_whether_it_earns_here`

**Interfaces:**
- Consumes: `credits::{book, Book, show}`, `gates::Standing`, `audit::{counts, Count, Outcome}`, `seal::{forked, Forked}`, `owner::fleet::siblings`.
- Produces:
  - `MemberView.balance: String`, `MemberView.not_earning: Vec<String>`
  - `admin::cluster::views(node: &Node, check: &RulesCheck, book: Option<&credits::Book>) -> AppResult<(MemberView, Vec<MemberView>)>` (third parameter new; None: the credit fields stay empty)
  - `admin::cluster::CreditsBlock { pub balance: String, pub earns: bool, pub reasons: Vec<String>, pub counted: (u32, u32, u32), pub others: (u32, u32, u32), pub fork: Option<String> }` on `NodePage.credits`

- [ ] **Step 1: Write the failing tests**

In `src/admin/cluster.rs`'s test module, replace the assertions about `"records with other rules"` and `rules_differ` in the test that builds `MemberView`s with `ruleset_same` (the one near the end of the file; it asserts on `issues()`) by:

```rust
    /// A member is flagged for its rules only when it does not earn here;
    /// another fingerprint or a few differing requests are information.
    #[test]
    fn issues_name_what_stops_a_member_from_earning() {
        let other_build = MemberView {
            ruleset_same: Some(false),
            rules_differ: true,
            rules: "disagree on <1% of 500".into(),
            ..Default::default()
        };
        assert!(other_build.issues().is_empty(), "{:?}", other_build.issues());
        let gated = MemberView {
            not_earning: vec![
                "rules: disagree on 12% of 500".into(),
                "showed two histories (at entry 7 of its log)".into(),
            ],
            ..Default::default()
        };
        assert_eq!(
            gated.issues(),
            ["not earning here: rules: disagree on 12% of 500; showed two histories (at entry 7 of its log)"]
        );
    }
```

Append to `tests/cluster.rs`:

```rust
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
    assert!(html.contains("Earns here") && html.contains(">yes<"), "{html}");
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
    assert!(members.contains("not earning here: showed two histories"), "{members}");
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib admin::cluster`
Expected: does not compile (`no field not_earning`).

- [ ] **Step 3: Implement**

`src/admin/cluster.rs`:

1. `MemberView` gains, after `managed`:

```rust
    /// Its credits in this node's count ("5.00"); empty when not loaded.
    pub balance: String,
    /// Why its shares do not count in full here; empty: it earns.
    pub not_earning: Vec<String>,
```

2. `issues()`: remove the two blocks that push `rules: …` (on `rules_differ`) and `"records with other rules"` (on `ruleset_same`), and add in their place:

```rust
        if !self.not_earning.is_empty() {
            v.push(format!("not earning here: {}", self.not_earning.join("; ")));
        }
```

   `rules_differ` and `ruleset_same` stay as fields: the member page shows them as information.

3. `views` gains the parameter `book: Option<&crate::credits::Book>` (last). In the per-member literal: `balance: book.map(|b| crate::credits::show(b.balance(&m.id))).unwrap_or_default(), not_earning: book.map(|b| b.standing(&m.id).reasons()).unwrap_or_default(),`; in the literal for this node the same with `me`. Callers:
   - `scanner_rows`: `views(node, &none, None)` (the pace table reads no credit fields and must not wait for the rules comparison).
   - the Members page handler and `node_view`: load `let book = crate::credits::book(node).await?;` next to `rules_check` and pass `Some(&book)`.
   - `src/admin/cluster_owner.rs` (`render_page`) and `src/admin/overview.rs` (`members`): the same.

4. The member page. Add above `struct NodePage`:

```rust
/// A member's credits as this node counts them.
pub struct CreditsBlock {
    pub balance: String,
    pub earns: bool,
    /// Every reason it does not earn in full here.
    pub reasons: Vec<String>,
    /// Audits of its scans over 7 days as `(agrees, differs,
    /// inconclusive)`: by this node and its fleet (they count), and by
    /// other members (shown only).
    pub counted: (u32, u32, u32),
    pub others: (u32, u32, u32),
    /// Where it showed two histories, and the proof if one is known.
    pub fork: Option<String>,
}

async fn credits_block(node: &Node, id: NodeId) -> AppResult<CreditsBlock> {
    use crate::credits::audit::Outcome;
    let book = crate::credits::book(node).await?;
    let standing = book.standing(&id);
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let week = crate::cluster::hlc::wall_ms().saturating_sub(7 * crate::credits::DAY_MS) << 16;
    let (mut counted, mut others) = ((0, 0, 0), (0, 0, 0));
    for c in crate::credits::audit::counts(&node.store.pool, week).await? {
        if c.scanner != id {
            continue;
        }
        let t = if auditors.contains(&c.auditor) {
            &mut counted
        } else {
            &mut others
        };
        match c.outcome {
            Outcome::Agrees => t.0 += c.n,
            Outcome::Differs => t.1 += c.n,
            Outcome::Inconclusive => t.2 += c.n,
        }
    }
    let members = node.members();
    let fork = crate::cluster::seal::forked(&node.store.pool)
        .await?
        .into_iter()
        .find(|f| f.origin == id)
        .map(|f| match f.proof {
            Some((by, seq)) => format!(
                "two entries at position {} of its log; proof published by {} (entry {seq} of its log)",
                f.seq,
                members.get(&by).map_or_else(|| by.short(), |m| m.name.clone())
            ),
            None => format!(
                "its seal at entry {} does not match its log as held here; no proof yet",
                f.seq
            ),
        });
    Ok(CreditsBlock {
        balance: crate::credits::show(book.balance(&id)),
        earns: standing.earns_as_scanner(),
        reasons: standing.reasons(),
        counted,
        others,
        fork,
    })
}
```

   `NodePage` gains `credits: CreditsBlock,`; `node_view` fills it with `credits: credits_block(node, id).await?,`.

`templates/admin_cluster_node.html`:

- In the Rules card: the `Some(false)` badge of "Carried" becomes plain text, ` <span class="muted small">differs from ours</span>`, and "Classified again here" shows the failed badge only when the gate fails:

```html
    {% if !m.is_self %}<dt>Classified again here</dt><dd>{{ m.rules }} <span class="muted small">details: <code>peephole cluster agreement {{ m.short }}</code></span></dd>{% endif %}
```

- After the Rules card:

```html
<section class="card"><h2>Credits</h2>
  <dl class="kv">
    <dt>Balance</dt><dd>{{ credits.balance }} <span class="muted small">credits, as this node counts them</span></dd>
    <dt>Earns here</dt><dd>{% if credits.earns %}<span class="badge badge-status" data-status="done">yes</span>{% else %}<span class="badge badge-status" data-status="failed">no</span>{% endif %}{% for r in credits.reasons %} <span class="small">{{ r }}{% if !loop.last %};{% endif %}</span>{% endfor %}</dd>
    {% if let Some(f) = credits.fork %}<dt>Showed two histories</dt><dd>{{ f }}. <span class="muted small">Its credits are void here, for good.</span></dd>{% endif %}
    <dt>Audits, 7 days</dt><dd>{{ credits.counted.0 }} agree · {{ credits.counted.1 }} differ · {{ credits.counted.2 }} inconclusive <span class="muted small">by this node and your other nodes: these count</span>{% if credits.others.0 + credits.others.1 + credits.others.2 > 0 %}<br>{{ credits.others.0 }} agree · {{ credits.others.1 }} differ · {{ credits.others.2 }} inconclusive <span class="muted small">by other members: shown, not counted</span>{% endif %}</dd>
  </dl>
</section>
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib admin:: && cargo test --test cluster a_members_page_says && cargo test --test cluster admin_cluster_page_and_private_attribution && cargo test --test cluster admin_manages_a_sibling`
Expected: PASS. If an existing test asserted the text `records with other rules`, it asserted the behaviour §11 of the spec removes: delete that assertion and say so in the commit message.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A src templates tests
git commit -m "Admin: members show whether they earn here; another rules fingerprint is no issue

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 19: Overview figures, what needs attention, audits on the scan pages

**Files:**
- Modify: `src/admin/overview.rs`, `templates/admin_home.html`, `src/admin/scans.rs`, `templates/admin_scan.html`, `templates/admin_scans.html`, `templates/_cluster_pace_row.html`, `templates/_target.html`, `src/admin/cluster.rs` (`MemberView` capacity fields, `scanner_rows`), `tests/cluster.rs`
- Test: unit tests in `src/admin/overview.rs`; `tests/cluster.rs::the_overview_shows_the_clusters_credit_figures`

**Interfaces:**
- Consumes: `credits::{book, Book, show}`, `price::{Table, scanners, capacity, Limit}`, `audit::{counts, counted, Outcome}`, `seal::forked`, `gates::RulesCheck`, `Node::price_table`.
- Produces:
  - `overview::ClusterFigures` (fields below) and `HomePage.cluster: Option<ClusterFigures>`
  - `Signals.forked: Vec<(String, String)>` (name, key), `Signals.custom_argv: Vec<u8>`, `Signals.expiring: Option<String>`
  - `MemberView.can_do: String`, `MemberView.did: String`, `MemberView.limited_by: &'static str`
  - `ScanPage.audits: Vec<(String, String)>` (auditor, result) and `ScanPage.audit_of: Option<i64>` (the audited scan's page)

- [ ] **Step 1: Write the failing tests**

Add to `src/admin/overview.rs`'s test module:

```rust
    #[test]
    fn credit_matters_that_need_a_look() {
        let s = Signals {
            forked: vec![("node-x".into(), "key-x".into())],
            custom_argv: vec![2, 4],
            expiring: Some("3.25".into()),
            ..Default::default()
        };
        let v = attention(&s);
        let texts: Vec<&str> = v.iter().map(|a| a.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "node-x showed two histories: its credits are void here.",
                "This node sets scan.level_argv for level 2, 4: its scans there earn no scanner share.",
                "3.25 credits expire today.",
            ]
        );
        assert_eq!(v[0].href, "/admin/cluster/node/key-x");
        assert_eq!(v[2].href, "/admin/cluster/credits");
    }
```

Append to `tests/cluster.rs`:

```rust
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
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib admin::overview`
Expected: does not compile (`no field forked`).

- [ ] **Step 3: What needs attention**

`src/admin/overview.rs`: `Signals` gains

```rust
    /// Members that showed two histories: `(name, key)`.
    pub forked: Vec<(String, String)>,
    /// Levels this node scans with its own arguments (`scan.level_argv`):
    /// those scans earn no scanner share.
    pub custom_argv: Vec<u8>,
    /// Credits of this node in the lot that expires today, when at least 1.
    pub expiring: Option<String>,
```

`attention`, before `v` is returned:

```rust
    for (name, key) in &s.forked {
        v.push(warn(
            format!("{name} showed two histories: its credits are void here."),
            &format!("/admin/cluster/node/{key}"),
        ));
    }
    if !s.custom_argv.is_empty() {
        let levels: Vec<String> = s.custom_argv.iter().map(u8::to_string).collect();
        v.push(warn(
            format!(
                "This node sets scan.level_argv for level {}: its scans there earn no scanner share.",
                levels.join(", ")
            ),
            "/admin/cluster/credits",
        ));
    }
    if let Some(c) = &s.expiring {
        v.push(warn(
            format!("{c} credits expire today."),
            "/admin/cluster/credits",
        ));
    }
```

`signals`, inside `if let Some(node) = st.recorder.node() { … }`:

```rust
        if let Ok(forked) = crate::cluster::seal::forked(&node.store.pool).await {
            let members = node.members();
            s.forked = forked
                .iter()
                .map(|f| {
                    (
                        members
                            .get(&f.origin)
                            .map_or_else(|| f.origin.short(), |m| m.name.clone()),
                        f.origin.to_string(),
                    )
                })
                .collect();
        }
        if node.roles().scanner {
            let mut levels: Vec<u8> = st.cfg.scan.level_argv.keys().copied().collect();
            levels.sort();
            s.custom_argv = levels;
        }
        if let Ok(book) = crate::credits::book(node).await {
            let expiring = book.ledger.expiring_today(&node.id());
            s.expiring = (expiring >= crate::credits::CREDIT).then(|| crate::credits::show(expiring));
        }
```

- [ ] **Step 4: The cluster's figures**

`src/admin/overview.rs`:

```rust
/// The "Cluster" row: every figure from this node's view, each linked to
/// the page that breaks it down.
pub struct ClusterFigures {
    /// "11 of 12 members earn here".
    pub conformity: String,
    /// The lowest rules agreement among members ("disagree on 3% of 500").
    pub lowest_agreement: String,
    /// Different rules fingerprints the members' newest requests carry.
    pub rule_sets: usize,
    pub circulating: String,
    /// Per day, 7-day averages.
    pub earned: String,
    pub spent: String,
    pub destroyed: String,
    pub expiring_today: String,
    /// Paid scans a day, low and high tier.
    pub paid_scans: (String, String),
    /// Scans a day the scanners can do, did, and the utilization in %.
    pub capacity: (String, String, String),
    /// Counted audits of 7 days: agrees, differs, inconclusive.
    pub audits: (u32, u32, u32),
    /// The unit price with its load factor.
    pub unit: String,
    pub load: String,
    /// Lowest and highest announced price of a keyed provider.
    pub price_range: Option<(String, String)>,
    /// Weighted paid lookups a day announced, and lookups served today.
    pub lookups: (String, i64),
    pub forks: usize,
}

async fn cluster_figures(
    st: &AdminState,
    node: &crate::cluster::Node,
) -> AppResult<ClusterFigures> {
    use crate::credits::audit::Outcome;
    use crate::credits::show;
    let book = crate::credits::book(node).await?;
    let check = crate::admin::cluster::rules_check(st, node).await?;
    let members = node.members();
    let active: Vec<_> = members.values().filter(|m| m.active).collect();
    let earning = active
        .iter()
        .filter(|m| book.standing(&m.id).earns_as_scanner())
        .count();
    let lowest = check
        .by_member
        .values()
        .filter(|a| a.sampled > 0)
        .max_by(|a, b| {
            (u64::from(a.differing) * u64::from(b.sampled))
                .cmp(&(u64::from(b.differing) * u64::from(a.sampled)))
        })
        .map(|a| a.summary())
        .unwrap_or_else(|| "no requests to compare".into());
    let rule_sets: std::collections::HashSet<&String> = check
        .carried
        .values()
        .filter_map(|c| c.newest.as_ref())
        .collect();
    let l = &book.ledger;
    let per_day = |total: u64| show(total / 7);
    let week = book.now_ms.saturating_sub(7 * crate::credits::DAY_MS);
    let in_week = |hlc: u64| crate::cluster::hlc::physical_ms(hlc) >= week;
    let (mut low, mut high) = (0u64, 0u64);
    for p in book.paid.iter().filter(|p| in_week(p.scan.hlc)) {
        if p.scanner_mc + p.trap_mc == 0 {
            continue;
        }
        if p.scan.level >= 3 {
            high += 1;
        } else {
            low += 1;
        }
    }
    let tenth = |n: u64| format!("{:.1}", n as f64 / 7.0);
    let mut auditors = crate::cluster::owner::fleet::siblings(&node.store).await?;
    auditors.push(node.id());
    let mut audits = (0, 0, 0);
    for c in crate::credits::audit::counts(&node.store.pool, week << 16).await? {
        if !auditors.contains(&c.auditor) {
            continue;
        }
        match c.outcome {
            Outcome::Agrees => audits.0 += c.n,
            Outcome::Differs => audits.1 += c.n,
            Outcome::Inconclusive => audits.2 += c.n,
        }
    }
    let t = node.price_table();
    // What live members ask for a keyed provider.
    let mut keyed: Vec<u32> = t
        .offers
        .iter()
        .filter(|o| crate::credits::price::weight_milli(&o.provider) == 1000)
        .map(|o| o.price_mc)
        .collect();
    for id in node.live_members(crate::intel::LIVE_WINDOW) {
        if let Some(k) = node.status.known(&id) {
            keyed.extend(
                k.hb.prices
                    .iter()
                    .filter(|(p, _)| crate::credits::price::weight_milli(p) == 1000)
                    .map(|(_, mc)| *mc),
            );
        }
    }
    let served_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM credit_entries
         WHERE kind = 'receipt' AND charged_mc > 0 AND hlc >= ?",
    )
    .bind(crate::cluster::hlc::to_db(
        (book.now_ms / crate::credits::DAY_MS * crate::credits::DAY_MS) << 16,
    ))
    .fetch_one(&st.store.read)
    .await?;
    Ok(ClusterFigures {
        conformity: format!("{earning} of {} members earn here", active.len()),
        lowest_agreement: lowest,
        rule_sets: rule_sets.len(),
        circulating: show(l.circulating()),
        earned: show(book.earned_per_day()),
        spent: per_day(l.tallies.values().map(|t| t.spent).sum()),
        destroyed: per_day(l.tallies.values().map(|t| t.destroyed).sum()),
        expiring_today: show(
            active
                .iter()
                .map(|m| l.expiring_today(&m.id))
                .sum::<u64>(),
        ),
        paid_scans: (tenth(low), tenth(high)),
        capacity: (
            format!("{:.0}", t.capacity.per_day),
            format!("{:.0}", t.capacity.used_per_day),
            format!("{:.0}", t.capacity.utilization * 100.0),
        ),
        audits,
        unit: t.unit.map_or_else(|| "—".into(), show),
        load: format!("{:.2}", t.load),
        price_range: keyed
            .iter()
            .min()
            .zip(keyed.iter().max())
            .map(|(lo, hi)| (show(*lo as u64), show(*hi as u64))),
        lookups: (format!("{:.0}", t.lookups_per_day), served_today),
        forks: crate::cluster::seal::forked(&node.store.pool).await?.len(),
    })
}
```

`HomePage` gains `cluster: Option<ClusterFigures>,`, filled in `home`:

```rust
        cluster: match st.recorder.node() {
            // The landing page must not fail with the cluster's figures.
            Some(node) => cluster_figures(&st, node)
                .await
                .inspect_err(|e| tracing::warn!(error = ?e, "overview: cluster figures unavailable"))
                .ok(),
            None => None,
        },
```

`templates/admin_home.html`, after the closing `</div>` of the first `<div class="tiles">`:

```html
{% if let Some(c) = cluster %}
<section class="card" aria-label="Cluster">
  <div class="card-head"><h2>Cluster</h2><span class="muted">as this node counts it</span></div>
  <div class="tiles">
    <a class="tile" href="/admin/cluster"><span class="label">Conformity</span><div class="value small">{{ c.conformity }}</div><div class="hint">lowest: {{ c.lowest_agreement }}</div></a>
    <a class="tile" href="/admin/cluster"><span class="label">Rule sets</span><div class="value">{{ c.rule_sets }}</div><div class="hint">fingerprints carried</div></a>
    <a class="tile" href="/admin/cluster/credits"><span class="label">Credits in circulation</span><div class="value">{{ c.circulating }}</div><div class="hint">{{ c.expiring_today }} expire today</div></a>
    <a class="tile" href="/admin/cluster/credits"><span class="label">Earned / spent / destroyed</span><div class="value small">{{ c.earned }} / {{ c.spent }} / {{ c.destroyed }}</div><div class="hint">credits a day, 7-day average</div></a>
    <a class="tile" href="/admin/scans?status=done#history"><span class="label">Paid scans</span><div class="value small">{{ c.paid_scans.0 }} / {{ c.paid_scans.1 }}</div><div class="hint">a day: levels 1–2 / 3–4</div></a>
    <a class="tile" href="/admin/scans#scanners"><span class="label">Scan capacity</span><div class="value small">{{ c.capacity.1 }} of {{ c.capacity.0 }}</div><div class="hint">scans a day done of possible · {{ c.capacity.2 }}%</div></a>
    <a class="tile" href="/admin/cluster"><span class="label">Audits</span><div class="value small">{{ c.audits.0 }} / {{ c.audits.1 }} / {{ c.audits.2 }}</div><div class="hint">agree / differ / inconclusive, 7 days</div></a>
    <a class="tile" href="/admin/cluster/credits"><span class="label">Lookup price</span><div class="value">{{ c.unit }}</div><div class="hint">per weighted lookup · load ×{{ c.load }}{% if let Some((lo, hi)) = c.price_range %} · keyed {{ lo }}–{{ hi }}{% endif %}</div></a>
    <a class="tile" href="/admin/lookup"><span class="label">Lookup capacity</span><div class="value">{{ c.lookups.0 }}</div><div class="hint">paid lookups a day · {{ c.lookups.1 }} served today</div></a>
    <a class="tile" href="/admin/cluster"><span class="label">Forks</span><div class="value">{{ c.forks }}</div><div class="hint">members that showed two histories</div></a>
  </div>
</section>
{% endif %}
```

- [ ] **Step 5: Capacity per scanner, and audits on the scan pages**

`src/admin/cluster.rs`: `MemberView` gains `/// Scans an hour it can do and did ("20.0"), and which setting binds it.\n    pub can_do: String,\n    pub did: String,\n    pub limited_by: &'static str,`. In `scanner_rows`, after the rows are collected:

```rust
    let left_out = std::collections::HashSet::new();
    let cap = crate::credits::price::capacity(
        &crate::credits::price::scanners(node, &left_out).await?,
    );
    let mut rows = rows;
    for m in rows.iter_mut() {
        if let Some(c) = cap.scanners.iter().find(|c| c.node.to_string() == m.key) {
            m.can_do = format!("{:.1}", c.can_do);
            m.did = format!("{:.1}", c.did);
            m.limited_by = match c.limited_by {
                crate::credits::price::Limit::Workers => "workers",
                crate::credits::price::Limit::PerHour => "scans per hour",
            };
        }
    }
    Ok(rows)
```

(`rows` being the collected `Vec<MemberView>` the function returned so far.) `templates/admin_scans.html`: the Scanners table head gains `<th class="num" title="From its measured scan times and its pace">Can do / h</th><th class="num" title="Jobs and audits it ended in the last 24 hours">Did / h</th><th>Limited by</th>` before `<th>Level weights</th>`; `templates/_cluster_pace_row.html` gains, before the level-weights cell, `<td class="num">{{ m.can_do }}</td><td class="num">{{ m.did }}</td><td>{{ m.limited_by }}</td>`.

`src/admin/scans.rs`: `ScanPage` gains

```rust
    /// When this scan is an audit: the page of the scan it checks.
    audit_of: Option<i64>,
    /// Audits of this scan: `(auditor, result)`.
    audits: Vec<(String, String)>,
```

filled in `scan_page`:

```rust
    let audit_of: Option<i64> = match &s.audit_of {
        Some(uid) => sqlx::query_scalar("SELECT id FROM scans WHERE uid = ?")
            .bind(uid)
            .fetch_optional(&st.store.read)
            .await?,
        None => None,
    };
    let audits: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT (SELECT name FROM members m WHERE m.id = a.origin), a.audit_result
         FROM scans a WHERE a.audit_of = (SELECT uid FROM scans WHERE id = ?) ORDER BY a.id",
    )
    .bind(id)
    .fetch_all(&st.store.read)
    .await?;
```

with `audit_of,` and `audits: audits.into_iter().map(|(n, r)| (n.unwrap_or_else(|| "another node".into()), r.unwrap_or_else(|| "not compared yet".into()))).collect(),` in the literal.

`templates/admin_scan.html`, at the end of the `<div class="meta">` line (inside it):

```html
{% if s.audit_of.is_some() %}<span class="badge badge-status" data-status="queued">audit{% if let Some(o) = audit_of %} of <a href="/admin/scans/{{ o }}">scan #{{ o }}</a>{% endif %}{% if let Some(r) = s.audit_result %}: {{ r }}{% endif %}</span>{% endif %}{% for (who, result) in audits %}<span>audited by {{ who }}: {{ result }}</span>{% endfor %}
```

`templates/_target.html`, in the Counter-scans heading of each scan (`<h3>Level {{ sc.s.level }} · …`), directly after `Level {{ sc.s.level }}`: `{% if sc.s.audit_of.is_some() %} <span class="badge badge-status" data-status="queued">audit{% if let Some(r) = sc.s.audit_result %}: {{ r }}{% endif %}</span>{% endif %}`.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib admin:: && cargo test --test cluster the_overview_shows_the_clusters && cargo test --test cluster audits_of_made_up_results`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add -A src templates tests
git commit -m "Admin: cluster figures on Overview, scan capacity per scanner, audits marked

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 20: `peephole credits` on the command line

**Files:**
- Create: `src/credits/cli.rs`
- Modify: `src/credits/mod.rs` (`pub mod cli;`), `src/cluster/cli.rs` (`open` and `resolve` become `pub(crate)`), `src/main.rs` (usage, `Cmd`, `parse`, dispatch, parse test), `tests/cli.rs`
- Test: `tests/cli.rs::credits_from_the_shell`

**Interfaces:**
- Consumes: `credits::{compute, show, parse_amount, Book}`, `earn::judged_one`, `fleet::send`, `cluster::cli::{open, resolve}`, `admin::credits::{when, date_of}`.
- Produces: `credits::cli::run(args: &[String], default_config: &str) -> anyhow::Result<()>`, `credits::cli::USAGE`

- [ ] **Step 1: Write the failing test**

Append to `tests/cli.rs`:

```rust
/// The credits subcommands on a fresh cluster node: nothing held, nothing
/// earned, and the errors say what is wrong.
#[test]
fn credits_from_the_shell() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "database_path = \"{d}/t.db\"\ndata_dir = \"{d}\"\n[roles]\nlistener = false\nweb = false\n\
             [cluster]\nnode_name = \"n1\"\nlisten = \"127.0.0.1:0\"\n",
            d = dir.path().display()
        ),
    )
    .unwrap();
    let run = |args: &[&str]| {
        let out = bin()
            .arg("credits")
            .args(args)
            .arg(cfg.to_str().unwrap())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    };
    let (ok, out, err) = run(&[]);
    assert!(ok, "{err}");
    assert!(out.contains("balance 0.00 credits"), "{out}");
    let (ok, out, _) = run(&["log"]);
    assert!(ok && out.contains("nothing earned, spent or sent"), "{out}");
    let (ok, out, _) = run(&["members"]);
    assert!(ok && out.contains("n1") && out.contains("0.00"), "{out}");
    let (ok, _, err) = run(&["why", "no-such-scan"]);
    assert!(!ok && err.contains("not judged"), "{err}");
    let (ok, _, err) = run(&["send", "n1", "1"]);
    assert!(!ok && err.contains("not a member credits can be sent to"), "{err}");
    let (ok, _, err) = run(&["send", "n1", "abc"]);
    assert!(!ok && err.contains("amount"), "{err}");
    let (ok, _, err) = run(&["bogus"]);
    assert!(!ok && err.contains("usage: peephole credits"), "{err}");
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test --test cli credits_from_the_shell`
Expected: FAIL (`unknown command 'credits'`).

- [ ] **Step 3: Implement**

`src/cluster/cli.rs`: `pub(crate) async fn open(` and `pub(crate) fn resolve(`.

Create `src/credits/cli.rs`:

```rust
//! `peephole credits …`: this node's credits from the shell. Like
//! `peephole cluster`, it works on the node's database, also while the
//! daemon runs; every figure is this node's own count.
use super::{Book, show};
use crate::admin::credits::{date_of, when};
use crate::cluster::cli::{open, resolve};
use crate::cluster::members;
use crate::credits::ledger::OfferState;
use anyhow::{Context, Result, bail};

pub const USAGE: &str = "usage: peephole credits [CONFIG]                     balance, by day
       peephole credits log [--days N] [CONFIG]     earned, spent, sent, received
       peephole credits members [CONFIG]            every member's balance and standing
       peephole credits why SCAN [CONFIG]           how this node judged one scan (its uid)
       peephole credits send NODE AMOUNT [CONFIG]   NODE: name, fingerprint or key";

fn config_path(arg: &str) -> bool {
    arg.contains('/') || arg.ends_with(".toml") || std::path::Path::new(arg).is_file()
}

pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let mut days = 7u64;
    let mut pos: Vec<&str> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--days" => {
                days = it
                    .next()
                    .and_then(|d| d.parse().ok())
                    .filter(|d| (1..=7).contains(d))
                    .context("--days takes a number from 1 to 7")?;
            }
            f if f.starts_with("--") => bail!("unknown flag {f}\n\n{USAGE}"),
            p => pos.push(p),
        }
    }
    // A trailing path is the config file.
    let config = match pos.last() {
        Some(p) if config_path(p) => pos.pop().unwrap_or(default_config),
        _ => default_config,
    };
    let (_, node) = open(config).await?;
    let me = node.id();
    let names = node.members();
    let name = |id: &crate::cluster::identity::NodeId| {
        names
            .get(id)
            .map_or_else(|| id.short(), |m| m.name.clone())
    };
    match pos.as_slice() {
        [] => {
            let book: Book = super::compute(&node).await?;
            println!(
                "balance {} credits ({} set aside in open lookups)",
                show(book.balance(&me)),
                show(book.ledger.held(&me))
            );
            for (day, mc) in book.ledger.by_day(&me) {
                let left = (day + super::LOT_DAYS - 1).saturating_sub(book.ledger.today);
                println!("  {}  {:>10}  expires in {left} day(s)", date_of(day), show(mc));
            }
        }
        ["log"] => {
            let book = super::compute(&node).await?;
            let from = book.now_ms.saturating_sub(days * super::DAY_MS);
            let recent = |hlc: u64| crate::cluster::hlc::physical_ms(hlc) >= from;
            let mut lines: Vec<(u64, String)> = vec![];
            for p in book.paid.iter().filter(|p| recent(p.scan.hlc)) {
                for (who, role, mc, note) in [
                    (p.scan.scanner, "scanner", p.scanner_mc, &p.scanner_note),
                    (p.scan.trap, "trap", p.trap_mc, &p.trap_note),
                ] {
                    if who == me {
                        lines.push((
                            p.scan.hlc,
                            format!(
                                "earned   {:>8}  {} level {} as {role}{}",
                                show(mc),
                                p.scan.ip,
                                p.scan.job_level,
                                if note.is_empty() {
                                    String::new()
                                } else {
                                    format!("  ({note})")
                                }
                            ),
                        ));
                    }
                }
            }
            for o in book.ledger.offers.iter().filter(|o| o.payer == me && recent(o.hlc)) {
                let what = match &o.state {
                    OfferState::Open => "open".to_string(),
                    OfferState::Lapsed => "lapsed, nothing charged".to_string(),
                    OfferState::Charged { charged, .. } => format!(
                        "charged {} for {}",
                        show(*charged),
                        o.answered.join(", ")
                    ),
                };
                lines.push((
                    o.hlc,
                    format!("offered  {:>8}  to {}: {what}", show(o.offered), name(&o.to)),
                ));
            }
            for t in book.ledger.transfers.iter().filter(|t| recent(t.hlc)) {
                if t.from == me {
                    lines.push((t.hlc, format!("sent     {:>8}  to {}", show(t.moved), name(&t.to))));
                } else if t.to == me {
                    lines.push((
                        t.hlc,
                        format!("received {:>8}  from {}", show(t.moved), name(&t.from)),
                    ));
                }
            }
            if lines.is_empty() {
                println!("nothing earned, spent or sent in the last {days} day(s)");
            }
            lines.sort_by_key(|(hlc, _)| *hlc);
            for (hlc, line) in lines {
                println!("{}  {line}", when(hlc));
            }
        }
        ["members"] => {
            let book = super::compute(&node).await?;
            for m in members::all(&node.store).await?.iter().filter(|m| m.active) {
                let reasons = book.standing(&m.id).reasons();
                println!(
                    "{:<24} {:>10}  {}",
                    m.name,
                    show(book.balance(&m.id)),
                    if reasons.is_empty() {
                        "earns here".to_string()
                    } else {
                        format!("not earning here: {}", reasons.join("; "))
                    }
                );
            }
        }
        ["why", scan] => {
            let Some(j) = super::earn::judged_one(&node.store.pool, scan).await? else {
                bail!(
                    "scan `{scan}` is not judged here (unknown, not payable, or it arrived less \
                     than ten minutes ago)"
                );
            };
            println!(
                "scan {} of {} by {} for the trap {}",
                j.scan_uid,
                j.ip,
                name(&j.scanner),
                name(&j.trap)
            );
            println!(
                "  job level {}, paid as level {} (what the requests held here back)",
                j.job_level, j.level
            );
            println!(
                "  arguments: {}",
                if j.args_ok {
                    "the built-in ones"
                } else {
                    "not the built-in ones (no scanner share)"
                }
            );
            let book = super::compute(&node).await?;
            if let Some(p) = book.paid.iter().find(|p| p.scan.scan_uid == j.scan_uid) {
                for (role, mc, note) in [
                    ("scanner", p.scanner_mc, &p.scanner_note),
                    ("trap", p.trap_mc, &p.trap_note),
                ] {
                    println!(
                        "  {role}: {} credits{}",
                        show(mc),
                        if note.is_empty() {
                            String::new()
                        } else {
                            format!(" ({note})")
                        }
                    );
                }
            }
        }
        ["send", who, amount] => {
            let mc = super::parse_amount(amount)
                .with_context(|| format!("`{amount}` is not an amount (like 1 or 0.25)"))?;
            let to = resolve(&members::all(&node.store).await?, who)?;
            let sent = super::fleet::send(&node, to, mc).await?;
            println!("sent {} credits to {}", show(sent), name(&to));
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
```

Add `pub mod cli;` to `src/credits/mod.rs`.

`src/main.rs`:

- Usage: after the `peephole owner …` line add `       peephole credits [log|members|why|send] …             this node's credits (--help)`.
- `enum Cmd`: `Credits,` after `Owner,`; `parse`: `Some("credits") => Ok(Cmd::Credits),`; dispatch:

```rust
        Cmd::Credits => {
            if let Err(e) = peephole::credits::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
```

- Parse test: `assert_eq!(p(&["credits", "log"]), Ok(Cmd::Credits));`

- [ ] **Step 4: Run the tests**

Run: `cargo test --test cli credits_from_the_shell && cargo test --bin peephole`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/credits/cli.rs src/credits/mod.rs src/cluster/cli.rs src/main.rs tests/cli.rs
git commit -m "Credits: peephole credits, log, members, why, send

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 21: Docs, changelog, and the wider check

**Files:**
- Modify: `docs/cluster.md`, `docs/dataset.md`, `docs/operations.md`, `deploy/config.example.toml`, `CHANGELOG.md`
- Test: formatting, clippy and the test targets this plan touched

- [ ] **Step 1: `docs/cluster.md`**

In the command list at the top, after the `peephole owner show` line:

```sh
peephole credits                          # this node's credits, by day
peephole credits log                      # earned, spent, sent, received (7 days)
peephole credits members                  # every member's balance and whether it earns here
peephole credits send <node> <amount>     # send credits to a member
```

Add a section before `## Things to know`:

```markdown
## Credits: lookups are paid with scans

A lookup (Admin → Lookup) asks every provider the cluster reaches about one
address. It is paid with **credits**, and credits are earned by the work
the cluster asked for: completed counter-scans.

- **Earning.** A completed scan pays its scanner 1 credit (levels 1, 2) or
  2 (levels 3, 4) and the trap that queued the job a quarter of that. One
  paid scan per address in 24 hours, 500 a day per node and role. A credit
  can be used on the day it was earned and the 6 days after.
- **What does not earn.** A scan run with your own `scan.level_argv`
  (no scanner share at that level), a scan no request held on the judging
  node backs, uptime, recorded requests, audits.
- **Every node counts for itself**, from its own copy of the log. There is
  no vote and no shared chain; `Cluster › Credits` shows this node's count
  and says why a scan was not paid in full.
- **Conformity.** A member earns on your node only while at least 98 % of
  its newest 500 requests classify the same with your rules, and its scans
  stand up to the audits you believe: those of your own nodes. A scanner
  runs 5 % of the other nodes' fresh scans again (`[credits] audit_share`);
  audits earn nothing.
- **Prices** follow what the cluster earns and what it can serve: each
  serving node computes one unit price an hour (a day's earnings buy a
  day's lookups), halved while the scanners idle and doubled when they are
  saturated. A keyed API costs 1 unit, Shodan InternetDB and GeoLite2 a
  quarter, the Tor exit list nothing. Half of what you pay goes to the
  node that answered, half is destroyed. Your own providers cost the same.
- **Your budgets are safe.** Paid lookups take at most
  `[enrichment] on_demand_share` (a fifth by default) of each API budget,
  whatever happens to credits. A provider whose share ran out costs double
  the next day.
- **Known addresses.** A lookup shows everything the dataset holds on the
  address. A provider answer under 24 hours old is shown instead of asking
  again, free. An answer that was paid for is kept in the dataset when the
  cluster has recorded the address (members can then infer who looked it
  up); for an address nobody recorded nothing is written anywhere.
- **Your nodes as one.** `Cluster › Ownership › Collect credits here`
  makes one node of yours the collecting node: the others forward what
  they earn and draw from it when a lookup needs more than they hold.
- **Two histories.** A node that gives two members different entries at
  one position of its log is found out with its next payment: its entries
  carry seals over its log. Members that hold the proof show "showed two
  histories"; that node's credits are void there for good.
- **What this cannot do.** It cannot tell a recorded request nobody sent
  from a real one, and it cannot stop one double spend per node key. See
  the limits in `docs/superpowers/specs/2026-10-06-lookup-credits-design.md`.
```

- [ ] **Step 2: The other docs**

`docs/dataset.md`, in the description of **`scans`**: add the two fields `uid` (the scan's identifier in the cluster) and `audit_of` (set when the scan is an audit: the `uid` of the scan it checks; an audit is a scan run again by another scanner and is not a counter-scan of its own). Add the six record kinds to the list of record kinds if the file has one (`grep -n 'skip_batch' docs/dataset.md`).

`docs/operations.md`: where enrichment budgets are described (`grep -n 'daily_limit\|budget' docs/operations.md`), add one paragraph: in a cluster, `on_demand_share` of each API budget serves paid lookups of members and this node's own on-demand lookups; the automatic enrichment uses the rest.

`deploy/config.example.toml`: next to `# [scan.level_argv]` add the comment line `# A scanner that sets its own arguments for a level earns no scanner share for scans at that level (lookup credits).`

- [ ] **Step 3: `CHANGELOG.md`**

Under `## [Unreleased]`, in `### Added` after the Ownership entry:

```markdown
- Lookup credits. Lookups are paid with credits earned by completed
  counter-scans (scanner 1 or 2, the trap a quarter); every node computes
  every balance from its own copy of the log. Prices follow the cluster's
  earnings, lookup capacity and scanner load; half of a payment goes to
  the node that answered, half is destroyed. A lookup shows everything the
  dataset holds on the address, answers under 24 hours old come from the
  dataset for free, and paid answers are kept for recorded addresses.
  Scanners audit a share of each other's scans; a node that shows two
  histories of its log is proven and marked. `Cluster › Credits`,
  `peephole credits`, `[credits] audit_share`,
  `[enrichment] on_demand_share`. See docs/cluster.md.
```

and in `### Changed`:

```markdown
- **Breaking:** a member no longer serves 50 free API lookups a day to
  every other member. Lookups in a cluster cost credits, your own
  providers included; a standalone node is unchanged.
- The Members table flags a member for its rules only when it does not
  earn here (less than 98 % agreement); another rules fingerprint alone is
  no issue.
- Export: scans carry `uid` and `audit_of`.
```

- [ ] **Step 4: The wider check**

Run `df -h .` first. If less than 8 GB are free, delete stale copies of this project's own test binaries in `target/debug/deps` (keep the newest per name) and old directories in `target/debug/incremental` before going on.

Run, in this order:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --lib
cargo test --test cli
cargo test --test cluster
cargo test --test cluster_limits
cargo test --test integration
bash -n install.sh && bash -n tests/install-smoke.sh
```

Expected: no formatting diff, no clippy warning, all tests PASS. Fix what fails and re-run the failing command only. `cluster_limits` and `integration` are in the set because this plan changed what they exercise: per-origin storage, the lookup allowance, the IP page.

- [ ] **Step 5: Commit**

```bash
git add docs/cluster.md docs/dataset.md docs/operations.md deploy/config.example.toml CHANGELOG.md
git commit -m "Docs: lookup credits

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

## Not in this plan

Spec items left out on purpose, each small and separable; say so in the hand-over:

- The spec's `§10` "Lookup › this lookup costs up to …" is shown as the sum of the cheapest price per provider before the lookup; a per-provider choice of what to ask is not offered.
- `Cluster › a member` and the Members table link a fork's proof by naming the publishing node and entry; there is no page that shows the two entries.
- The journal line "per offer served or declined" names asker, providers and charge; the reason for a decline is in the same line. No separate audit table for declines.
- Spec §14 lists "an old-version peer relays the new kinds unchanged". Storing and relaying a kind a build does not know is the log's existing behaviour (`UNKNOWN_KIND` in `repl.rs`) and has its tests there; a test with a real older binary is not part of this plan. That such a peer is not asked for lookups is tested (Task 13).
- Where a sibling forwards its credits is read from its transfers of the last 7 days on the Credits page, and from its own status on its member page; the Credits page does not ask every sibling.
