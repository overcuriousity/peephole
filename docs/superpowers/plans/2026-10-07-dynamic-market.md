# Dynamic Market Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-scan mint, the trap share, the fixed provider weights, the surge and the 50 % burn with a fixed daily mint for scanners, a daily allowance per member, market prices for every good with limited supply, and paid scan jobs.

**Architecture:** Balances stay a pure function of the log (`credits::ledger::run`). What enters it changes: instead of one `Earned` per paid scan, `credits::mint` produces one `Earned` per scanner and closed day (its share of `MINT_PER_DAY`) and one per active member and closed day (`ALLOWANCE_PER_DAY`). Receipts move the full amount. Prices are computed hourly per node by one rule (`price::step`) from demand counted at the node and supply it can measure, and announced in the heartbeat. Arbiters fund grants with an offer that carries the job uid; scanners charge it on delivery.

**Tech Stack:** Rust 2024, tokio, sqlx (SQLite), serde/CBOR records, askama templates.

**Spec:** `docs/superpowers/specs/2026-10-07-dynamic-market-design.md`

## Global Constraints

- Ledger constants (must be identical on every node, build constants): `MINT_PER_DAY` = 1000 credits, `ALLOWANCE_PER_DAY` = 5 credits, `PER_NODE_PER_DAY` = 500 (existing), `LOT_DAYS` = 7 (existing), level weights 1 (levels 1, 2) and 2 (levels 3, 4).
- Price parameters (build defaults, may differ per node): `PRICE_FLOOR` = 1 mc, `PRICE_STEP` = 0.15, step bounded by `clamp((D − S) / max(S, 1), −3, 3)`.
- Every provider is paid (Tor, RDAP, InternetDB and GeoLite2 included); a request without an offer is declined. `pay::FREE_PER_HOUR`, `take_free_lookup`, `take_free_resolve` and `take_free` go: there is no free hourly quota of anything.
- `[enrichment] offer_per_day` (default 1000): the daily supply of a provider without an API budget and of name resolutions on that node; a provider with a budget offers its on-demand share as now.
- The Lookup page asks no provider by itself: only those the admin picks ("all" = every one). A node's own background enrichment is unchanged.
- Nothing is burned: a receipt moves the full charged amount to the server.
- A scan of the scanner's own job (scanner == trap) never counts for the mint.
- `[credits] scan_share` in the config file, default 0.5, between 0 and 1.
- A scan offer carries the job uid and lapses after `pace::MAX_RUN_SECS` × 1000 + `pay::SERVE_MARGIN_MS` ms; other offers after `OFFER_TTL_MS` (15 min) as now.
- `PROTO_VERSION` becomes 4; `MARKET_PROTO` = 4 gates every payment (lookups, probes, scan offers) and scan bids counted in prices.
- Ledger rule changes take effect on upgrade (no activation days).
- Build environment: prefix every cargo command with `export PATH=$HOME/.cargo/bin:$PATH;`. Run only the focused tests named in a step; check `df -h .` before a build and delete stale copies of this project's own test binaries in `target/debug/deps` (keep the newest per name) when space is low.
- Wording in code comments, pages and docs follows the project's style: plain sentences, no marketing words; credits shown with `credits::show`.

## Review Focus

1. **A day's mint with very uneven counts** (one scanner with 1 scan, another with 499): shares must sum to exactly `MINT_PER_DAY`, no node gets a negative or overflowing amount. Test in Task 2 (`split_sums_exactly_with_remainders`).
2. **A scan that reaches a node after its day closed**: the share moves; a lot that shrank must make later offers cover less, never produce a negative lot. Test in Task 2 (`a_late_scan_shifts_a_closed_day`).
3. **A scanner that never reports back** (crash mid-scan): the scan offer must hold credits until it lapses after `MAX_RUN_SECS` + margin and then return them; a receipt after that is ignored. Test in Task 1 (`a_job_offer_lapses_after_the_longest_run`).
4. **A node with zero balance arbitrating jobs**: it must grant unfunded (no offer, no error) and announce 0 bids. Test in Task 4 (`no_budget_grants_without_an_offer`).
5. **A resolver that fails or times out after the offer was written**: the asker must not be charged; the offer is released by a receipt of nothing (or lapses). Test in Task 5 (`a_failed_resolution_charges_nothing`).

---

### Task 1: Ledger — full transfers and job offers

**Files:**
- Create: `src/store/migrations/0021_market.sql`
- Modify: `src/store/mod.rs` (migration list near line 50)
- Modify: `src/cluster/record.rs:464-468` (`CreditOffer`), its test near line 855
- Modify: `src/credits/entries.rs` (`Kind::Offer`, `apply`, `COLUMNS`, `from_row`, tests near lines 269, 310)
- Modify: `src/credits/mod.rs` (new constant)
- Modify: `src/credits/ledger.rs` (`OfferState`, `Offer`, `Tally`, `lapse`, `offer`, `receipt`, tests)
- Modify: `src/credits/pay.rs:318` (`make_offer` record), module doc
- Modify: `src/admin/credits.rs`, `src/admin/overview.rs`, `templates/admin_cluster_credits.html`, `templates/admin_home.html` (drop "destroyed")

**Interfaces:**
- Produces: `Record::CreditOffer { to, parts, seal, job: Option<String> }`; `entries::Kind::Offer { to, parts, job: Option<String> }`; `ledger::Offer.job: Option<String>`; `ledger::OfferState::Charged { charged: Mc }`; `credits::JOB_OFFER_TTL_MS: u64`; `Tally` without `destroyed`.

- [ ] **Step 1: Write the failing ledger tests**

In `src/credits/ledger.rs` tests, add a helper and three tests; replace `an_offer_to_oneself_costs_half` and `halves_round_down_and_the_remainder_is_destroyed`:

```rust
    fn job_offer(origin: u8, seq: u64, hlc: u64, to: u8, parts: &[(u32, u32)]) -> Entry {
        entry(
            origin,
            seq,
            hlc,
            Kind::Offer {
                to: id(to),
                parts: parts.to_vec(),
                job: Some(format!("job{seq}")),
            },
        )
    }

    #[test]
    fn a_receipt_moves_the_full_amount() {
        let l = ledger(
            &[earn(1, DAY - 1, 0, 3), earn(1, DAY, 0, 10)],
            &[
                offer(1, 5, at(DAY, 10), 2, &[(DAY - 1, 3), (DAY, 4)]),
                receipt(2, 1, at(DAY, 11), 1, 5, 7),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.by_day(&id(2)), vec![(DAY - 1, 3), (DAY, 4)]);
        assert_eq!(l.offer(&id(1), 5).unwrap().state, OfferState::Charged { charged: 7 });
        assert_eq!((l.tally(&id(1)).spent, l.tally(&id(2)).served), (7, 7));
    }

    #[test]
    fn an_offer_to_oneself_costs_nothing() {
        let l = ledger(
            &[earn(1, DAY, 0, 500)],
            &[
                offer(1, 5, at(DAY, 10), 1, &[(DAY, 200)]),
                receipt(1, 6, at(DAY, 11), 1, 5, 200),
            ],
            now(DAY, 12),
        );
        assert_eq!(l.balance(&id(1)), 500);
    }

    #[test]
    fn a_job_offer_lapses_after_the_longest_run() {
        let earned = [earn(1, DAY, 0, 500)];
        // Charged four hours later: still open, so it counts.
        let l = ledger(
            &earned,
            &[
                job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)]),
                receipt(2, 1, at(DAY, 250), 1, 5, 200),
            ],
            now(DAY, 260),
        );
        assert_eq!((l.balance(&id(1)), l.balance(&id(2))), (300, 200));
        assert_eq!(l.offer(&id(1), 5).unwrap().job.as_deref(), Some("job5"));
        // Never charged: held until MAX_RUN_SECS + margin, then returned.
        let lapse_min = 10 + crate::credits::JOB_OFFER_TTL_MS / 60_000;
        let open = ledger(&earned, &[job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)])], now(DAY, lapse_min));
        assert_eq!(open.balance(&id(1)), 300);
        assert_eq!(open.offer(&id(1), 5).unwrap().state, OfferState::Open);
        let gone = ledger(&earned, &[job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)])], now(DAY, lapse_min + 1));
        assert_eq!(gone.balance(&id(1)), 500);
        // A receipt after the lapse is ignored.
        let late = ledger(
            &earned,
            &[
                job_offer(1, 5, at(DAY, 10), 2, &[(DAY, 200)]),
                receipt(2, 1, at(DAY, lapse_min + 2), 1, 5, 200),
            ],
            now(DAY, lapse_min + 3),
        );
        assert_eq!((late.balance(&id(1)), late.balance(&id(2))), (500, 0));
    }
```

Update the existing `offer(...)` test helper to build `Kind::Offer { to: id(to), parts: parts.to_vec(), job: None }`.

- [ ] **Step 2: Run them to see them fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::ledger`
Expected: compile errors (`job` field, `Charged { charged }`, `JOB_OFFER_TTL_MS`).

- [ ] **Step 3: Migration, record and entries**

`src/store/migrations/0021_market.sql`:

```sql
-- Dynamic market: a scan offer names the job it funds (it lapses later
-- than a lookup offer), and the allowance asks whether a member recorded
-- a request on a day.
ALTER TABLE credit_entries ADD COLUMN job_uid TEXT;
CREATE INDEX idx_requests_origin_hlc ON requests(origin, hlc) WHERE origin IS NOT NULL;
```

Add `include_str!("migrations/0021_market.sql"),` after the 0020 line in `src/store/mod.rs`.

In `src/cluster/record.rs`, extend the variant (absent field encodes like before):

```rust
    CreditOffer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        seal: Seal,
        /// The scan job this offer funds (`credits::jobs`); such an offer
        /// lapses after the longest scan, not after 15 minutes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job: Option<String>,
    },
```

Add `job: None` to every construction (`record.rs` test, `entries.rs` tests, `pay.rs::make_offer`).

In `src/credits/entries.rs`: `Kind::Offer { to: NodeId, parts: Vec<(u32, u32)>, job: Option<String> }`; in `apply` match `Record::CreditOffer { to, parts, job, .. } if parts_ok(parts, day) && job.as_ref().is_none_or(|j| j.len() <= 64)` and bind `job.as_deref()` into a new `job_uid` column (the other kinds bind `None`); append `, job_uid` to `COLUMNS`, extend `Row` with `Option<String>` and set `job: r.10` in `from_row` for `"offer"`.

In `src/credits/mod.rs`:

```rust
/// A scan offer (`credits::jobs`) lapses after the longest scan and the
/// margin a server keeps for writing its receipt.
pub const JOB_OFFER_TTL_MS: u64 =
    crate::scan::pace::MAX_RUN_SECS * 1000 + pay::SERVE_MARGIN_MS;
```

- [ ] **Step 4: Ledger: per-offer lifetime, full transfer**

In `src/credits/ledger.rs`:

```rust
pub enum OfferState {
    Open,
    Charged { charged: Mc },
    Lapsed,
}

pub struct Offer {
    // ... existing fields ...
    /// The scan job it funds; None: a lookup or probe.
    pub job: Option<String>,
}

impl Offer {
    /// How long it may wait for its receipt.
    pub fn ttl_ms(&self) -> u64 {
        if self.job.is_some() { super::JOB_OFFER_TTL_MS } else { OFFER_TTL_MS }
    }
}
```

Remove `destroyed` from `Tally` and update its doc of `served` to "What it charged others". In `lapse` use `o.ttl_ms()` instead of `OFFER_TTL_MS`; in `offer` store `job: job.clone()` (pass `job: &Option<String>` from the `Kind::Offer` arm in `run`); in `receipt` use `physical_ms(e.hlc) <= physical_ms(o.hlc) + o.ttl_ms()` and replace the halving loop:

```rust
        let held = std::mem::take(&mut self.l.offers[i].held);
        let mut left = charged.min(held.iter().map(|(_, mc)| mc).sum());
        let paid = left;
        for (day, mc) in held {
            let take = mc.min(left);
            left -= take;
            *self.lot(e.origin, day) += take;
            *self.lot(payer, day) += mc - take;
        }
        let o = &mut self.l.offers[i];
        o.answered = answered.to_vec();
        o.state = OfferState::Charged { charged: paid };
        self.tally(payer, e.hlc, |t| t.spent += paid);
        self.tally(e.origin, e.hlc, |t| t.served += paid);
```

Update the module doc ("Half of what is charged ... destroyed" goes) and `pay.rs`'s module doc ("the server keeps what it charges").

- [ ] **Step 5: Fix the remaining expectations and pages**

Run `cargo test --lib credits::` and correct every failing expectation that assumed the half: recompute each by "the server gets the full charged amount, the payer keeps the rest of what the offer held"; remove assertions on `destroyed`. In `src/admin/credits.rs` drop `SpentRow.destroyed`, the "Of which destroyed" column in `templates/admin_cluster_credits.html`, the sentence about the destroyed half (replace with "What is charged goes to the node that answered. An offer without an answer lapses after 15 minutes (a scan offer after the longest scan) and costs nothing."), and the destroyed total (`totals` becomes `(earned, circulating)`; template line 77: "In 7 days earned {{ totals.0 }} · in circulation now {{ totals.1 }} credits. …"). In `src/admin/overview.rs` `spending` returns only the charged sum; drop `ClusterFigures.destroyed` and its test value (line ~603); the home tile becomes "Earned / spent" with `{{ c.earned }} / {{ c.spent }}`.

- [ ] **Step 6: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits:: && cargo test --lib cluster::record && cargo test --lib admin::overview`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A src/store src/cluster/record.rs src/credits src/admin templates
git commit -m "Credits: receipts move the full amount; scan offers name their job and lapse after the longest scan"
```

---

### Task 2: The daily mint and the allowance

**Files:**
- Create: `src/credits/mint.rs`
- Modify: `src/credits/earn.rs` (`Paid`, `pay`, remove `tier_shares`/`earned`, tests)
- Modify: `src/credits/mod.rs` (`pub mod mint;`, `Book`, `compute`, `earned_per_day`)
- Modify: `src/admin/credits.rs`, `templates/admin_cluster_credits.html` (earned rows), `src/admin/overview.rs:333`

**Interfaces:**
- Consumes: `ledger::Earned { node, hlc, mc }`, `gates::Standings`, `earn::Judged`.
- Produces:
  - `earn::Paid { scan: Judged, weight: u8, note: String }`; `earn::pay(scans: &[Judged], gates: &Gates) -> Vec<Paid>`.
  - `mint::MINT_PER_DAY: Mc`, `mint::ALLOWANCE_PER_DAY: Mc`, `mint::end_of(day: u32) -> u64`, `mint::closed(day: u32, now_ms: u64) -> bool`, `mint::split(paid: &[Paid], now_ms: u64) -> Vec<Earned>`, `mint::allowances(active: &BTreeSet<(NodeId, u32)>, standings: &Standings, now_ms: u64) -> Vec<Earned>`, `mint::active_days(pool: &SqlitePool, members: &[NodeId], from_day: u32, to_day: u32) -> Result<BTreeSet<(NodeId, u32)>>`.
  - `Book { ledger, paid, minted: Vec<Earned>, allowances: Vec<Earned>, standings, now_ms }`; `Book::earned_per_day()` = mint + allowances of the last 7 days / 7.

- [ ] **Step 1: Write the failing `earn` tests**

Replace `shares_by_level` and adjust `one_paid_scan_per_ip_in_24_hours` (weights instead of millicredits: tiers 1 and 2, an upgrade within the window counts 1, a repeat 0). Add:

```rust
    #[test]
    fn weights_by_level_and_no_trap_share() {
        let scans: Vec<Judged> = (1..=4u8)
            .map(|l| scan(l as u32, &format!("203.0.113.{l}"), at(DAY, l as u64), l))
            .collect();
        let w: Vec<u8> = pay(&scans, &Gates::default()).iter().map(|p| p.weight).collect();
        assert_eq!(w, [1, 1, 2, 2]);
    }

    #[test]
    fn a_scan_of_its_own_job_does_not_count() {
        let mut s = scan(1, "203.0.113.5", at(DAY, 1), 2);
        s.trap = s.scanner;
        let p = &pay(&[s], &Gates::default())[0];
        assert_eq!(p.weight, 0);
        assert_eq!(p.note, "a scan of its own job");
    }
```

- [ ] **Step 2: Write the failing `mint` tests** (in `src/credits/mint.rs`, `#[cfg(test)] mod tests`)

```rust
    use super::*;
    use crate::credits::earn::{Judged, Paid};

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId { NodeId([n; 32]) }
    fn at(day: u32, min: u64) -> u64 { (day as u64 * DAY_MS + min * 60_000) << 16 }
    fn paid(n: u32, scanner: u8, day: u32, weight: u8) -> Paid {
        Paid {
            scan: Judged {
                scan_uid: format!("s{n}"), job_uid: format!("j{n}"), ip: format!("203.0.113.{}", n % 250),
                scanner: id(scanner), trap: id(9), hlc: at(day, n as u64 % 1000), level: 2, job_level: 2, args_ok: true,
            },
            weight,
            note: String::new(),
        }
    }
    fn after(day: u32) -> u64 { (day as u64 + 1) * DAY_MS + JUDGE_AFTER_SECS as u64 * 1000 }

    #[test]
    fn a_closed_day_is_split_by_weight_and_dated_in_its_lot() {
        let p = [paid(1, 1, DAY, 1), paid(2, 1, DAY, 2), paid(3, 2, DAY, 1)];
        let e = split(&p, after(DAY));
        let get = |n| e.iter().find(|x| x.node == id(n)).unwrap();
        assert_eq!((get(1).mc, get(2).mc), (750 * CREDIT, 250 * CREDIT));
        assert_eq!(crate::credits::day_of(get(1).hlc), DAY);
        // Not closed yet: nothing.
        assert!(split(&p, after(DAY) - 1).is_empty());
        // Weight 0 does not count; an empty day mints nothing.
        assert!(split(&[paid(4, 3, DAY, 0)], after(DAY)).is_empty());
    }

    #[test]
    fn split_sums_exactly_with_remainders() {
        let mut p = vec![paid(1, 1, DAY, 1)];
        p.extend((2..=500).map(|n| paid(n, 2, DAY, 1)));
        p.push(paid(501, 3, DAY, 2));
        let e = split(&p, after(DAY));
        assert_eq!(e.iter().map(|x| x.mc).sum::<Mc>(), MINT_PER_DAY);
        assert!(e.iter().all(|x| x.mc > 0));
        assert_eq!(split(&p, after(DAY)), e, "deterministic");
    }

    #[test]
    fn a_late_scan_shifts_a_closed_day() {
        let before = split(&[paid(1, 1, DAY, 1)], after(DAY));
        assert_eq!(before[0].mc, MINT_PER_DAY);
        let later = split(&[paid(1, 1, DAY, 1), paid(2, 2, DAY, 1)], after(DAY) + 3_600_000);
        assert_eq!(later.iter().find(|x| x.node == id(1)).unwrap().mc, MINT_PER_DAY / 2);
        // The ledger lets a shrunk lot cover only what is there.
        let entries = [crate::credits::entries::Entry {
            origin: id(1), seq: 1, hlc: at(DAY + 1, 10),
            kind: crate::credits::entries::Kind::Offer { to: id(3), parts: vec![(DAY, (MINT_PER_DAY * 3 / 4) as u32)], job: None },
            seal: crate::credits::entries::SealState::Consistent,
        }];
        let l = crate::credits::ledger::run(&later, &entries, &Default::default(), (DAY as u64 + 1) * DAY_MS + 11 * 60_000);
        assert_eq!(l.offer(&id(1), 1).unwrap().covered, MINT_PER_DAY / 2);
        assert_eq!(l.balance(&id(1)), 0);
    }

    #[test]
    fn the_allowance_goes_to_active_members_that_earn_here() {
        let active: BTreeSet<(NodeId, u32)> = [(id(1), DAY), (id(2), DAY), (id(3), DAY), (id(1), DAY + 1)].into();
        let mut st = Standings::new();
        st.entry(id(2)).or_default().blocked = true;
        st.entry(id(3)).or_default().rules = Some(crate::classify::agreement::Agreement { sampled: 100, differing: 50 });
        let e = allowances(&active, &st, after(DAY));
        assert_eq!(e.iter().map(|x| (x.node, x.mc)).collect::<Vec<_>>(), [(id(1), ALLOWANCE_PER_DAY)]);
        assert_eq!(crate::credits::day_of(e[0].hlc), DAY);
    }

    #[tokio::test]
    async fn active_days_come_from_recorded_requests() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store.upsert_ip("203.0.113.7".parse().unwrap()).await.unwrap();
        for (who, day) in [(1u8, DAY), (1, DAY), (2, DAY + 1)] {
            sqlx::query("INSERT INTO requests (ts, ip_id, method, path, origin, hlc) VALUES ('2026-01-01T00:00:00Z', ?, 'GET', '/', ?, ?)")
                .bind(ip.id).bind(&id(who).0[..]).bind(crate::cluster::hlc::to_db(at(day, 5)))
                .execute(&store.pool).await.unwrap();
        }
        let got = active_days(&store.pool, &[id(1), id(2), id(3)], DAY, DAY + 1).await.unwrap();
        assert_eq!(got, [(id(1), DAY), (id(2), DAY + 1)].into());
    }
```

Check the `requests` NOT NULL columns in `src/store/migrations/0001_initial.sql` (line 16 on) and add any the insert lacks; check the `Agreement` path and field names in `src/credits/gates.rs` (`rules_fail`) and use them.

- [ ] **Step 3: Run to see them fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::earn credits::mint`
Expected: compile errors.

- [ ] **Step 4: Rewrite `earn::pay`**

`Paid` becomes `{ scan, weight: u8, note: String }`. Replace `tier_shares` with `fn tier_weight(tier: u8) -> u8 { if tier == 2 { 2 } else { 1 } }`. Keep the walk order, the 24-hour window and the upgrade rule (an upgrade counts `2 − 1 = 1`), the `level == 0`, `args_ok` and gate checks (scanner side only: `gates.no_shares` or `gates.no_scanner_share` of `s.scanner`). Before the window check add:

```rust
        if s.scanner == s.trap {
            p.note = "a scan of its own job".into();
            out.push(p);
            continue;
        }
```

so an own-job scan neither counts nor opens the IP's window. The daily cap counts `(scanner, day)` only. Delete `earned()`; update the module doc ("a completed counter-scan counts for its scanner's share of the day's mint (`credits::mint`)").

- [ ] **Step 5: Write `src/credits/mint.rs`**

```rust
//! Where credits come from: a fixed amount a day, split among the
//! scanners by the scans that counted that day, and a small allowance for
//! every member that earns here and recorded a request that day. Both are
//! dated the day's last instant, so they land in its lot, and are final
//! once the day is closed.
use super::earn::{JUDGE_AFTER_SECS, Paid};
use super::gates::Standings;
use super::ledger::Earned;
use super::{CREDIT, DAY_MS, Mc, day_of};
use crate::cluster::identity::NodeId;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::{BTreeMap, BTreeSet};

/// Split among the scanners per UTC day.
pub const MINT_PER_DAY: Mc = 1000 * CREDIT;
/// Per member that earns here and recorded a request, per UTC day.
pub const ALLOWANCE_PER_DAY: Mc = 5 * CREDIT;

/// The last instant of `day` as an HLC.
pub fn end_of(day: u32) -> u64 {
    (((day as u64 + 1) * DAY_MS - 1) << 16) | 0xFFFF
}

/// `day` has ended and its scans have had time to be judged.
pub fn closed(day: u32, now_ms: u64) -> bool {
    now_ms >= (day as u64 + 1) * DAY_MS + JUDGE_AFTER_SECS.max(0) as u64 * 1000
}

/// Each closed day's mint, split by the weights of its counted scans
/// (largest remainder, ties by node key, so the shares sum exactly).
pub fn split(paid: &[Paid], now_ms: u64) -> Vec<Earned> {
    let mut days: BTreeMap<u32, BTreeMap<NodeId, u64>> = BTreeMap::new();
    for p in paid.iter().filter(|p| p.weight > 0) {
        *days
            .entry(day_of(p.scan.hlc))
            .or_default()
            .entry(p.scan.scanner)
            .or_default() += p.weight as u64;
    }
    let mut out = vec![];
    for (day, weights) in days.into_iter().filter(|(d, _)| closed(*d, now_ms)) {
        let total: u64 = weights.values().sum();
        let mut shares: Vec<(NodeId, Mc, u64)> = weights
            .iter()
            .map(|(n, w)| {
                let x = MINT_PER_DAY as u128 * *w as u128;
                (*n, (x / total as u128) as Mc, (x % total as u128) as u64)
            })
            .collect();
        let mut left = MINT_PER_DAY - shares.iter().map(|s| s.1).sum::<Mc>();
        shares.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        for s in shares.iter_mut() {
            if left == 0 {
                break;
            }
            s.1 += 1;
            left -= 1;
        }
        shares.sort_by_key(|s| s.0);
        out.extend(shares.into_iter().filter(|s| s.1 > 0).map(|(node, mc, _)| Earned {
            node,
            hlc: end_of(day),
            mc,
        }));
    }
    out
}

/// The allowance of every closed day for the members active that day
/// that earn here.
pub fn allowances(active: &BTreeSet<(NodeId, u32)>, standings: &Standings, now_ms: u64) -> Vec<Earned> {
    active
        .iter()
        .filter(|(n, d)| closed(*d, now_ms) && standings.get(n).is_none_or(|s| s.earns()))
        .map(|(node, day)| Earned { node: *node, hlc: end_of(*day), mc: ALLOWANCE_PER_DAY })
        .collect()
}

/// `(member, day)` for every day from `from_day` to `to_day` on which this
/// node holds a request the member recorded.
pub async fn active_days(
    pool: &SqlitePool,
    members: &[NodeId],
    from_day: u32,
    to_day: u32,
) -> Result<BTreeSet<(NodeId, u32)>> {
    let mut out = BTreeSet::new();
    for m in members {
        for day in from_day..=to_day {
            let lo = (day as u64 * DAY_MS) << 16;
            let hi = end_of(day);
            let any: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM requests WHERE origin = ? AND hlc BETWEEN ? AND ?)",
            )
            .bind(&m.0[..])
            .bind(crate::cluster::hlc::to_db(lo))
            .bind(crate::cluster::hlc::to_db(hi))
            .fetch_one(pool)
            .await?;
            if any {
                out.insert((*m, day));
            }
        }
    }
    Ok(out)
}
```

Add `pub mod mint;` in `src/credits/mod.rs`.

- [ ] **Step 6: The book uses the mint**

In `src/credits/mod.rs`:

```rust
pub struct Book {
    pub ledger: ledger::Ledger,
    pub paid: Vec<earn::Paid>,
    /// Each scanner's share of each closed day's mint.
    pub minted: Vec<ledger::Earned>,
    pub allowances: Vec<ledger::Earned>,
    pub standings: gates::Standings,
    pub now_ms: u64,
}

    /// What was minted and allowed a day over the last 7 days.
    pub fn earned_per_day(&self) -> Mc {
        let from = self.now_ms.saturating_sub(7 * DAY_MS);
        let week: Mc = self
            .minted
            .iter()
            .chain(&self.allowances)
            .filter(|e| crate::cluster::hlc::physical_ms(e.hlc) >= from)
            .map(|e| e.mc)
            .sum();
        week / 7
    }
```

In `compute`: after `paid`, build

```rust
    let minted = mint::split(&paid, now_ms);
    let members: Vec<NodeId> = crate::cluster::members::all(&node.store)
        .await?
        .into_iter()
        .map(|m| m.id)
        .collect();
    let today = (now_ms / DAY_MS) as u32;
    let first = day_of(since);
    let active = mint::active_days(&node.store.pool, &members, first, today).await?;
    let allowances = mint::allowances(&active, &standings, now_ms);
    let earned: Vec<ledger::Earned> = minted.iter().chain(&allowances).cloned().collect();
    let ledger = ledger::run(&earned, &entries, &left_out, now_ms);
```

- [ ] **Step 7: Pages follow**

`src/admin/credits.rs`: earned rows list this node's paid scans with `counts: String` (`"1"`, `"2"`, or `"—"` with the note) instead of `role` and `amount`; template columns "When, Scan, Level, Counts, Note". `src/admin/overview.rs:333`: `if p.weight == 0 { continue; }`.

- [ ] **Step 8: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits:: && cargo test --lib admin::`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add -A src/credits src/admin templates
git commit -m "Credits: a fixed daily mint split among scanners, an allowance for active members; no trap share, no pay for one's own jobs"
```

---

### Task 3: Market prices

**Files:**
- Modify: `src/credits/price.rs` (rewrite of weights/unit/load/price/Table/refresh; keep `Scanner`, `capacity`, `scanners`)
- Modify: `src/credits/share.rs` (remove surge and its test)
- Modify: `src/cluster/rpc/proto.rs` (`MARKET_PROTO`), `src/credits/pay.rs` (`pays_with`)
- Modify: `src/cluster/mod.rs` (`Node.market: price::Demand`, `scan_bids: AtomicU32`, `scan_share: OnceLock<f64>` with `set_scan_share`/`scan_share`)
- Modify: `src/cluster/status.rs` (`Heartbeat.scan_price_mc`, `Heartbeat.scan_bids`, `refresh_heartbeat`, test constructions)
- Modify: `src/credits/pay.rs` (`quotes`, `serve`: price fallback, demand counting)
- Modify: `src/intel/lookup.rs` (offer-less path, `cheap` removed, `run`), `src/admin/lookup.rs` (no cheap tier), `src/cluster/mod.rs` (remove `take_free_lookup`, `free_lookups`, `take_free`)
- Modify: `src/config.rs` (`EnrichmentConfig.offer_per_day`), `src/lib.rs:176` (`Shares::new`)
- Modify: `src/scan/probe/serve.rs` (price, slots, demand), `src/admin/credits.rs`, `src/admin/overview.rs`, `templates/admin_cluster_credits.html`, `templates/admin_home.html`

**Interfaces:**
- Consumes: `price::capacity`, `price::scanners`, `share::Shares::allowance`, `owner::fleet::siblings`.
- Produces:
  - `price::PRICE_FLOOR: Mc = 1`, `price::PRICE_STEP: f64 = 0.15`, `price::SCAN: &str = "scan"`, `price::PROBE` (kept), `price::PROBES_PER_SLOT_HOUR: f64 = 30.0`.
  - `price::step(price: Mc, demand: f64, supply: f64) -> Mc`; `price::start(announced: &[u32]) -> Mc`.
  - `price::Demand` with `note(&self, good: &str, n: u32)` and `take(&self) -> (HashMap<String, f64>, f64 /*hours*/)`.
  - `price::Offer { provider, price_mc: u32, on_demand: Option<u32> }`; `price::Table { at_ms, capacity, scan_bids: u32, scan_mc: u32, probe_mc: Option<u32>, offers }` with `price_of`, `announced` as now.
  - `Heartbeat { ..., #[serde(default)] scan_price_mc: Option<u32>, #[serde(default)] scan_bids: u32 }`.
  - `Shares::new(store, share: f64, offer_per_day: u32)`; `Shares::allowance(p) -> u32`: the budget share with a budget, `offer_per_day` without; `Shares::offer_per_day() -> u32`; `Shares::take_good(good: &str) -> Result<bool>` (counts against `offer_per_day`).
  - `price::Offer.on_demand: u32`.
  - `price::provider_price(per_day: u32, current: Option<Mc>, demand: f64, hours: f64) -> Mc`.
  - `price::RESOLVE: &str = "resolve"`; `Table.resolve_mc: u32`, announced in `prices` as `("resolve", mc)`.
  - `proto::MARKET_PROTO: u32 = 4`; `pay::pays_with(proto_max: u32) -> bool`.

- [ ] **Step 1: Write the failing price tests** (replace the tests of `price.rs` that use `unit`, `load`, `price`, `weight_milli`; keep `scan_capacity_is_bound_by_workers_or_by_the_hourly_limit` and `a_table_knows_what_it_offers` adapted to the new `Offer`)

```rust
    #[test]
    fn a_price_follows_the_imbalance_within_a_bounded_step() {
        assert_eq!(step(1000, 10.0, 10.0), 1000, "balanced");
        assert!(step(1000, 20.0, 10.0) > 1000);
        assert!(step(1000, 5.0, 10.0) < 1000);
        // At most e^(0.15 × 3) either way.
        assert_eq!(step(1000, 1e9, 10.0), (1000.0 * (0.45f64).exp()).round() as Mc);
        assert_eq!(step(1000, 0.0, 1e9), (1000.0 * (-0.45f64).exp()).round() as Mc);
        // Excess supply ends at the floor, never below; no supply counts as 1.
        let mut p = 1000;
        for _ in 0..200 { p = step(p, 0.0, 50.0); }
        assert_eq!(p, PRICE_FLOOR);
        assert!(step(PRICE_FLOOR, 5.0, 0.0) > PRICE_FLOOR);
    }

    #[test]
    fn a_new_good_starts_at_the_median_announced_or_the_floor() {
        assert_eq!(start(&[]), PRICE_FLOOR);
        assert_eq!(start(&[300, 100, 200]), 200);
        assert_eq!(start(&[100, 400]), 100, "lower median");
        assert_eq!(start(&[0, 0]), PRICE_FLOOR);
    }

    #[test]
    fn demand_is_counted_and_taken() {
        let d = Demand::default();
        d.note("abuseipdb", 2);
        d.note("abuseipdb", 1);
        d.note(PROBE, 1);
        let (got, hours) = d.take();
        assert_eq!(got.get("abuseipdb"), Some(&3.0));
        assert_eq!(got.get(PROBE), Some(&1.0));
        assert!(hours > 0.0 && hours < 0.01);
        assert!(d.take().0.is_empty(), "taken");
    }

    #[test]
    fn every_provider_follows_its_supply() {
        assert_eq!(provider_price(240, None, 3.0, 1.0), step(PRICE_FLOOR, 3.0, 10.0));
        assert_eq!(provider_price(240, Some(500), 10.0, 1.0), 500);
        assert_eq!(provider_price(0, Some(500), 1.0, 1.0), step(500, 1.0, 0.0));
        assert!(provider_price(240, Some(1), 0.0, 1.0) >= PRICE_FLOOR, "never free");
        // A generous node (high offer_per_day) gets cheaper under the same demand.
        assert!(provider_price(24_000, Some(500), 50.0, 1.0) < provider_price(240, Some(500), 50.0, 1.0));
    }
```

- [ ] **Step 2: Run to see them fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::price`
Expected: compile errors.

- [ ] **Step 3: Implement the rule, the demand counter and the provider price**

In `src/credits/price.rs` (remove `UNIT_MIN`, `UNIT_MAX`, `weight_milli`, `load`, `unit`, `price`; rewrite the module doc: "What a good costs here: one rule for every good with limited supply. Excess demand raises the price, excess supply lowers it, by a bounded step an hour. A good without a supply limit costs nothing."):

```rust
pub const PRICE_FLOOR: Mc = 1;
pub const PRICE_STEP: f64 = 0.15;
pub const SCAN: &str = "scan";
pub const PROBE: &str = "probe";
/// A name resolved for another member (`intel::dns`).
pub const RESOLVE: &str = "resolve";
/// A probe slot serves this many probes an hour (`PROBE_TIMEOUT` is 2 minutes).
pub const PROBES_PER_SLOT_HOUR: f64 = 30.0;

/// One step of a price from the demand and the supply of a period.
pub fn step(price: Mc, demand: f64, supply: f64) -> Mc {
    let x = ((demand - supply) / supply.max(1.0)).clamp(-3.0, 3.0);
    let p = (price.max(PRICE_FLOOR) as f64 * (PRICE_STEP * x).exp()).round();
    (p.min(u32::MAX as f64) as Mc).max(PRICE_FLOOR)
}

/// Where a good's price starts here: the lower median of what members
/// announce for it, or the floor.
pub fn start(announced: &[u32]) -> Mc {
    let mut v: Vec<u32> = announced.iter().copied().filter(|p| *p > 0).collect();
    if v.is_empty() {
        return PRICE_FLOOR;
    }
    v.sort_unstable();
    v[(v.len() - 1) / 2] as Mc
}

/// A provider's next price here: a step from `current` (or the floor)
/// with `per_day` spread over `hours` as supply.
pub fn provider_price(per_day: u32, current: Option<Mc>, demand: f64, hours: f64) -> Mc {
    step(current.unwrap_or(PRICE_FLOOR), demand, per_day as f64 / 24.0 * hours)
}

/// Paid requests this node received since the last refresh, per good.
pub struct Demand {
    inner: std::sync::Mutex<(std::time::Instant, HashMap<String, f64>)>,
}

impl Default for Demand {
    fn default() -> Self {
        Self { inner: std::sync::Mutex::new((std::time::Instant::now(), HashMap::new())) }
    }
}

impl Demand {
    pub fn note(&self, good: &str, n: u32) {
        *self.inner.lock().unwrap().1.entry(good.to_string()).or_default() += n as f64;
    }

    /// The counts and the hours they cover; starts a new period.
    pub fn take(&self) -> (HashMap<String, f64>, f64) {
        let mut g = self.inner.lock().unwrap();
        let hours = (g.0.elapsed().as_secs_f64() / 3600.0).max(1e-6);
        g.0 = std::time::Instant::now();
        (std::mem::take(&mut g.1), hours)
    }
}
```

`Offer` loses `surge`; `Table` becomes:

```rust
pub struct Table {
    pub at_ms: u64,
    pub capacity: Capacity,
    /// Funded scan jobs waiting in the cluster, as arbiters announce them.
    pub scan_bids: u32,
    pub scan_mc: u32,
    /// None: this node does not probe.
    pub probe_mc: Option<u32>,
    /// What resolving a name for another member costs here.
    pub resolve_mc: u32,
    pub offers: Vec<Offer>,
}
```

`announced()` appends `(RESOLVE.to_string(), self.resolve_mc)` to the prices when `resolve_mc > 0` (`pay::quotes` ignores it: it keeps only known providers).

Delete `surge_on`, `surge`, `SURGE_MAX` and the surge test from `src/credits/share.rs` and its module-doc sentence about the surge.

- [ ] **Step 4: Rewrite `refresh`**

```rust
/// Kept across restarts.
fn price_key(good: &str) -> String {
    format!("price:{good}")
}

async fn current(node: &Node, old: &Table, good: &str, announced: &[u32]) -> Result<Mc> {
    if let Some(p) = old.price_of(good).filter(|p| *p > 0) {
        return Ok(p as Mc);
    }
    if let Some(p) = node.store.intel_get(&price_key(good)).await?.and_then(|v| v.parse::<Mc>().ok()) {
        return Ok(p.max(PRICE_FLOOR));
    }
    Ok(start(announced))
}

pub async fn refresh(node: &Node) -> Result<Arc<Table>> {
    let book = super::book_fresh(node).await?;
    let left_out: HashSet<NodeId> = book.standings.iter().filter(|(_, s)| s.left_out()).map(|(id, _)| *id).collect();
    let capacity = capacity(&scanners(node, &left_out).await?);
    let (demand, hours) = node.market.take();
    let old = node.price_table();
    // What live members announce, per good (for the start price) and their scan bids.
    let me = node.id();
    let members = node.members();
    let mut announced: HashMap<String, Vec<u32>> = HashMap::new();
    let mut bids: u64 = node.scan_bids.load(std::sync::atomic::Ordering::Relaxed) as u64;
    for id in node.live_members(intel::LIVE_WINDOW) {
        if id == me || left_out.contains(&id) || node.is_blocked(&id)
            || !members.get(&id).is_some_and(|m| super::pay::pays_with(m.proto_max))
        {
            continue;
        }
        let Some(k) = node.status.known(&id) else { continue };
        for (p, mc) in &k.hb.prices {
            announced.entry(p.clone()).or_default().push(*mc);
        }
        if let Some(mc) = k.hb.scan_price_mc {
            announced.entry(SCAN.into()).or_default().push(mc);
        }
        if let Some(mc) = k.hb.probe_price_mc {
            announced.entry(PROBE.into()).or_default().push(mc);
        }
        bids += k.hb.scan_bids as u64;
    }
    let none = vec![];
    let ann = |g: &str| announced.get(g).unwrap_or(&none).clone();
    let got = |g: &str| demand.get(g).copied().unwrap_or(0.0);
    let mut offers = vec![];
    let empty = vec![];
    let providers = node.lookup_providers().unwrap_or(&empty);
    let offer_per_day = node.lookup_shares().map_or(crate::config::DEFAULT_OFFER_PER_DAY, |s| s.offer_per_day());
    for p in providers.iter().filter(|p| p.ready()) {
        let on_demand = node.lookup_shares().map_or(offer_per_day, |s| s.allowance(p.as_ref()));
        let cur = current(node, &old, p.name(), &ann(p.name())).await?;
        offers.push(Offer {
            provider: p.name().to_string(),
            price_mc: provider_price(on_demand, Some(cur), got(p.name()), hours).min(u32::MAX as Mc) as u32,
            on_demand,
        });
    }
    let resolve_cur = current(node, &old, RESOLVE, &ann(RESOLVE)).await?;
    let resolve_mc = step(resolve_cur, got(RESOLVE), offer_per_day as f64 / 24.0 * hours).min(u32::MAX as Mc) as u32;
    let probe_mc = match node.prober() {
        Some(pr) => {
            let cur = current(node, &old, PROBE, &ann(PROBE)).await?;
            Some(step(cur, got(PROBE), pr.slots() as f64 * PROBES_PER_SLOT_HOUR * hours).min(u32::MAX as Mc) as u32)
        }
        None => None,
    };
    // Funded jobs waiting now against what the scanners do in an hour.
    let scan_cur = current(node, &old, SCAN, &ann(SCAN)).await?;
    let scan_mc = step(scan_cur, bids as f64, capacity.per_day / 24.0).min(u32::MAX as Mc) as u32;
    for (good, mc) in offers
        .iter()
        .map(|o| (o.provider.as_str(), o.price_mc))
        .chain(probe_mc.map(|m| (PROBE, m)))
        .chain([(SCAN, scan_mc), (RESOLVE, resolve_mc)])
    {
        node.store.intel_set(&price_key(good), &mc.to_string()).await?;
    }
    let table = Arc::new(Table {
        at_ms: crate::cluster::hlc::wall_ms(),
        capacity,
        scan_bids: bids.min(u32::MAX as u64) as u32,
        scan_mc,
        probe_mc,
        resolve_mc,
        offers,
    });
    node.set_price_table(table.clone());
    Ok(table)
}
```

`Table::price_of` also answers `SCAN` (from `scan_mc`) and `PROBE` (from `probe_mc`):

```rust
    pub fn price_of(&self, good: &str) -> Option<u32> {
        match good {
            SCAN => Some(self.scan_mc).filter(|p| *p > 0),
            PROBE => self.probe_mc,
            RESOLVE => Some(self.resolve_mc).filter(|p| *p > 0),
            _ => self.offers.iter().find(|o| o.provider == good).map(|o| o.price_mc),
        }
    }
```

- [ ] **Step 5: Protocol constant, node fields and heartbeat**

`src/cluster/rpc/proto.rs` (`PROTO_VERSION` stays 3 until Task 6):

```rust
/// Members from this version count balances with the market's rules
/// (`credits::mint`): payments go only between them.
pub const MARKET_PROTO: u32 = 4;
```

`src/credits/pay.rs`:

```rust
/// Whether a member announcing `proto_max` counts balances as this node does.
pub fn pays_with(proto_max: u32) -> bool {
    proto_max >= crate::cluster::rpc::proto::MARKET_PROTO
}
```


In `src/cluster/mod.rs` add to `Node` (and its constructor):

```rust
    /// Paid requests counted for this node's prices (`credits::price`).
    pub market: crate::credits::price::Demand,
    /// Funded scan jobs this node would grant now (`credits::jobs`).
    pub scan_bids: std::sync::atomic::AtomicU32,
    scan_share: std::sync::OnceLock<f64>,
```

with

```rust
    /// `[credits] scan_share`: set once at start.
    pub fn set_scan_share(&self, share: f64) {
        let _ = self.scan_share.set(share.clamp(0.0, 1.0));
    }

    pub fn scan_share(&self) -> f64 {
        self.scan_share.get().copied().unwrap_or(0.0)
    }
```

In `src/cluster/status.rs` add to `Heartbeat`:

```rust
    /// What a funded scan job costs at this node now, in mc.
    #[serde(default)]
    pub scan_price_mc: Option<u32>,
    /// Funded scan jobs this node, as arbiter, would grant now.
    #[serde(default)]
    pub scan_bids: u32,
```

and fill them in `refresh_heartbeat`: `scan_price_mc: table.price_of(crate::credits::price::SCAN)`, `scan_bids: self.scan_bids.load(Ordering::Relaxed)`; `probe_price_mc: self.prober().map(|p| p.price(&table))`. Add `scan_price_mc: None, scan_bids: 0` to the two test constructions.

- [ ] **Step 6: Callers**

- `src/credits/pay.rs::quotes`: own price `table.price_of(name).unwrap_or(price::PRICE_FLOOR as u32)`. `serve`: `price_of` falls back the same way. In `serve`, before `accept_offer`, count demand unless the asker is a sibling:

```rust
    let sibling = crate::cluster::owner::fleet::siblings(&node.store)
        .await
        .is_ok_and(|s| s.contains(&peer));
    if !sibling {
        for name in &all {
            node.market.note(name, 1);
        }
    }
```

- `src/config.rs`: `EnrichmentConfig.offer_per_day: u32` with `#[serde(default = "default_offer_per_day")]`, `pub const DEFAULT_OFFER_PER_DAY: u32 = 1000;`, doc: "Paid lookups a day this node serves of each provider without an API budget (Tor exit list, RDAP, GeoLite2, …), and names it resolves a day for other members." Add `("enrichment", "offer_per_day", "1000")` next to the `on_demand_share` entry near line 609 and a test that the default is 1000. `src/lib.rs:176`: pass `cfg.enrichment.offer_per_day` to `Shares::new`.

- `src/credits/share.rs`: `Shares { store, share, offer_per_day }`;

```rust
    /// Paid lookups of `p` this node serves a UTC day: its API budget times
    /// the share, or `offer_per_day` without a budget.
    pub fn allowance(&self, p: &dyn Provider) -> u32 {
        match p.per_day() {
            Some(d) => (d * self.share).floor().clamp(0.0, u32::MAX as f64) as u32,
            None => self.offer_per_day,
        }
    }

    pub fn offer_per_day(&self) -> u32 {
        self.offer_per_day
    }

    /// Count one paid unit of `good` (a resolution) against
    /// `offer_per_day`; false when today's are used up.
    pub async fn take_good(&self, good: &str) -> Result<bool> {
        self.take_named(good, self.offer_per_day, today()).await
    }
```

Move the body of `take_on` into `async fn take_named(&self, name: &str, allowance: u32, day: NaiveDate) -> Result<bool>` (no `None` branch any more) and let `take_on` call it with `p.name()` and `self.allowance(p)`; `spent_on` compares with `self.allowance(p)` directly. `price::Table::announced` maps every offer's `on_demand` (no `filter_map`). Update the share tests' `Shares::new(.., 0.2)` calls to pass `1000` and add: a fake provider without a budget gets `1000`.

- `src/intel/lookup.rs::serve`: the offer-less path declines every provider with "lookups are paid with credits: the request carries no offer" (no partition, no `take_free_lookup`). Delete `cheap`, `CHEAP_MILLI` and the test `cheap_tier_is_tor_rdap_geolite_and_internetdb`; in `run`, `wanted` is the providers in `ask` or `again` without a fresh stored answer (no cheap tier). Update the doc comment above `serve` (line ~112) accordingly.

- `src/cluster/mod.rs`: remove `take_free_lookup`, `take_free_resolve`, `take_free`, the `free_lookups`/`free_resolves` fields and their initialisation; `src/credits/pay.rs`: remove `FREE_PER_HOUR`. (`src/cluster/rpc/mod.rs::resolve` uses `take_free_resolve` until Task 5: in this task make it refuse every request with "resolving a name is paid with credits: upgrade this node", Task 5 replaces it.)

- `src/admin/lookup.rs`: `Offer::from_quotes` puts every provider into the paid list (no cheap tier; drop the cheap-tier total and its template text "What a lookup costs at most"); `asked` with `*` returns every known provider. The tests `a_lookup_asks_the_cheap_tier_and_offers_the_rest` (rename to `a_lookup_asks_only_what_was_picked`) and the two that expect "Tor exit list" after a lookup (lines ~664 and ~722) change: nothing is asked unless picked, so they pick `tor` explicitly or expect the provider to be offered with its price instead of answered.

- `src/scan/probe/serve.rs`: `pub fn slots(&self) -> u32 { self.max }`; `price` returns `table.probe_mc.unwrap_or(price::PRICE_FLOOR as u32)`; remove `surging`; where a paid probe request arrives (before its offer is accepted), `node.market.note(price::PROBE, 1)` unless the asker is a sibling (same check as above).

- Pages: `src/admin/credits.rs` `PriceView` becomes `{ scan: String, scan_bids: u32, capacity_per_hour: String, utilization: String, probe: Option<String>, offers: Vec<(String, String, String)> }` (provider label, price, paid lookups it serves a day); template list: "A funded scan job costs **{{ price.scan }}** credits here ({{ price.scan_bids }} funded jobs waiting; the scanners do {{ price.capacity_per_hour }} an hour, {{ price.utilization }} % used)." plus the provider table without the surge column. `src/admin/overview.rs`: the keyed range filters `provider_info(p).is_some_and(|i| i.api)` and price > 0; `unit` becomes `scan` (`show(t.scan_mc as u64)`), the home tile "Scan price" with hint "a funded job · keyed lookups {{ lo }}–{{ hi }}".

- [ ] **Step 7: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits:: && cargo test --lib intel:: && cargo test --lib cluster::status && cargo test --lib config && cargo test --lib admin::`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add -A src templates
git commit -m "Credits: market prices per good from demand and supply; no weights, unit, surge or free tier; offer_per_day for providers without a budget"
```

---

### Task 4: Paid scan jobs

**Files:**
- Create: `src/credits/jobs.rs`
- Modify: `src/credits/mod.rs` (`pub mod jobs;`, hourly bids in `run`)
- Modify: `src/config.rs` (`CreditsConfig.scan_share`, check, test), `src/lib.rs` (`node.set_scan_share`)
- Modify: `src/cluster/msg.rs` (`Claim.min_mc`, `Grant.offer_seq`, `Grant.price_mc`, tests)
- Modify: `src/scan/arbiter.rs` (`handle`, `claim`, `hand_out`, `next_job_skipping`)
- Modify: `src/scan/mod.rs` (`acquire_granted` order and claim, `Job::Granted.offer`, settle on finish and turndowns)

**Interfaces:**
- Consumes: `ledger::Ledger`, `Offer.job`, `OfferState`, `repl::append_sealing`, `repl::append`, `Table::price_of(price::SCAN)`, `Node::scan_share`, `Node::scan_bids`.
- Produces:
  - `jobs::budget(l: &Ledger, me: &NodeId, share: f64) -> Mc`
  - `jobs::bids(queued: u32, budget: Mc, price: Mc) -> u32`
  - `jobs::fund(node: &Arc<Node>, scanner: NodeId, job_uid: &str, min_mc: u32) -> Option<(u64, u32)>`
  - `jobs::settle(node: &Arc<Node>, arbiter: NodeId, offer_seq: u64, charged_mc: u32)`
  - `jobs::announce_bids(node: &Arc<Node>) -> Result<u32>`
  - `Msg::Claim { exclude_levels, min_mc: u32 }`, `Grant { job_uid, ip, level, lease_secs, offer_seq: Option<u64>, price_mc: u32 }`

- [ ] **Step 1: Write the failing `jobs` tests** (in `src/credits/jobs.rs`)

```rust
    use super::*;
    use crate::credits::entries::{Entry, Kind, SealState};
    use crate::credits::ledger::{Earned, run};

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId { NodeId([n; 32]) }
    fn at(day: u32, min: u64) -> u64 { (day as u64 * DAY_MS + min * 60_000) << 16 }
    fn e(origin: u8, seq: u64, hlc: u64, kind: Kind) -> Entry {
        Entry { origin: id(origin), seq, hlc, kind, seal: SealState::Consistent }
    }

    #[test]
    fn the_budget_is_a_share_of_what_was_there_today() {
        let earned = [Earned { node: id(1), hlc: at(DAY, 0), mc: 1000 }];
        let entries = [
            e(1, 1, at(DAY, 1), Kind::Offer { to: id(2), parts: vec![(DAY, 200)], job: Some("a".into()) }),
            e(2, 1, at(DAY, 2), Kind::Receipt { payer: id(1), offer_seq: 1, charged_mc: 200, answered: vec!["scan".into()] }),
            e(1, 2, at(DAY, 3), Kind::Offer { to: id(2), parts: vec![(DAY, 100)], job: Some("b".into()) }),
            // A lookup offer is not a scan offer.
            e(1, 3, at(DAY, 4), Kind::Offer { to: id(3), parts: vec![(DAY, 50)], job: None }),
        ];
        let l = run(&earned, &entries, &Default::default(), (DAY as u64 * DAY_MS) + 5 * 60_000);
        // balance 650, committed 300: half of 950 is 475, 175 left.
        assert_eq!(budget(&l, &id(1), 0.5), 175);
        assert_eq!(budget(&l, &id(1), 0.0), 0);
        assert_eq!(budget(&l, &id(1), 1.0), 650);
    }

    #[test]
    fn bids_are_what_the_budget_buys_of_the_queue() {
        assert_eq!(bids(10, 175, 50), 3);
        assert_eq!(bids(2, 175, 50), 2);
        assert_eq!(bids(10, 0, 50), 0);
        assert_eq!(bids(10, 175, 0), 0, "no price, no bid");
    }
```

and in `src/scan/arbiter.rs` tests (using the existing `setup`):

```rust
    #[tokio::test]
    async fn no_budget_grants_without_an_offer() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        node.set_scan_share(1.0);
        let rec = Recorder::Cluster(node.clone());
        let ip = store.upsert_ip("203.0.113.94".parse().unwrap()).await.unwrap();
        rec.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let scanner = Identity::generate().unwrap().id;
        let g = arbiter.next_job_for(scanner, &[], 0).await.unwrap().unwrap();
        assert_eq!((g.offer_seq, g.price_mc), (None, 0));
    }
```

and in `src/cluster/msg.rs` extend the compatibility test: `Msg::Claim { exclude_levels: vec![], min_mc: 0 }` still encodes like `OldMsg::Claim`, and a `Grant` with `offer_seq: None, price_mc: 0` encodes like the old grant (add an `OldGrant` struct mirroring the four old fields if the test file has none).

- [ ] **Step 2: Run to see them fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::jobs scan::arbiter cluster::msg`
Expected: compile errors.

- [ ] **Step 3: Write `src/credits/jobs.rs`**

```rust
//! Paying for scan jobs. An arbiter funds a job it grants with an offer to
//! the scanner that names the job; the scanner charges the offered price
//! when it delivers the result, and nothing otherwise. What an arbiter
//! commits to its own jobs is bounded by `[credits] scan_share`.
use super::entries::Kind;
use super::ledger::{Ledger, OfferState};
use super::{DAY_MS, Mc, day_of, price};
use crate::cluster::identity::NodeId;
use crate::cluster::record::Record;
use crate::cluster::{Node, repl};
use anyhow::Result;
use std::sync::Arc;

/// What `me` may still hold in or pay for its scan jobs today: `share` of
/// its balance plus what its scan offers hold and were charged today,
/// minus those two.
pub fn budget(l: &Ledger, me: &NodeId, share: f64) -> Mc {
    let (mut held, mut charged) = (0, 0);
    for o in l.offers.iter().filter(|o| o.payer == *me && o.job.is_some()) {
        match o.state {
            OfferState::Open => held += o.held_now(),
            OfferState::Charged { charged: c } if day_of(o.hlc) == l.today => charged += c,
            _ => {}
        }
    }
    let committed = held + charged;
    let cap = ((l.balance(me) + committed) as f64 * share.clamp(0.0, 1.0)).floor() as Mc;
    cap.saturating_sub(committed)
}

/// Queued jobs `budget` funds at `price`.
pub fn bids(queued: u32, budget: Mc, price: Mc) -> u32 {
    if price == 0 {
        return 0;
    }
    (budget / price).min(queued as Mc) as u32
}

/// Fund the grant of `job_uid` to `scanner` at this node's scan price:
/// `(offer_seq, price)` once the offer is written. None: its own scanner,
/// a scanner that predates the market, a price under `min_mc`, or no
/// budget; the job is granted unfunded.
pub async fn fund(node: &Arc<Node>, scanner: NodeId, job_uid: &str, min_mc: u32) -> Option<(u64, u32)> {
    let me = node.id();
    if scanner == me
        || !node.members().get(&scanner).is_some_and(|m| super::pay::pays_with(m.proto_max))
    {
        return None;
    }
    let price = node.price_table().price_of(price::SCAN)?;
    if price < min_mc {
        return None;
    }
    let book = super::book_fresh(node).await.ok()?;
    if budget(&book.ledger, &me, node.scan_share()) < price as Mc {
        return None;
    }
    let parts = book.ledger.spendable_parts(&me, price as Mc)?;
    let job = Some(job_uid.to_string());
    match repl::append_sealing(node, |seal| Record::CreditOffer { to: scanner, parts, seal, job }).await {
        Ok(e) => Some((e.seq, price)),
        Err(e) => {
            tracing::debug!(?e, job = %job_uid, "scan offer not written; granted unfunded");
            None
        }
    }
}

/// The scanner's receipt for a funded job: the price for a delivered
/// result, nothing for anything else (it frees the offer at once).
pub async fn settle(node: &Arc<Node>, arbiter: NodeId, offer_seq: u64, charged_mc: u32) {
    let receipt = Record::CreditReceipt {
        payer: arbiter,
        offer_seq,
        charged_mc,
        answered: vec![price::SCAN.into()],
    };
    if let Err(e) = repl::append(node, &[receipt]).await {
        tracing::warn!(?e, "scan receipt not written");
    }
}

/// Compute and keep the funded jobs this node would grant now, for the
/// heartbeat and the scan price.
pub async fn announce_bids(node: &Arc<Node>) -> Result<u32> {
    let queued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scan_jobs WHERE status = 'queued' AND arbiter = ?",
    )
    .bind(&node.id().0[..])
    .fetch_one(&node.store.pool)
    .await?;
    let book = super::book(node).await?;
    let price = node.price_table().price_of(price::SCAN).unwrap_or(0) as Mc;
    let n = bids(
        queued.clamp(0, u32::MAX as i64) as u32,
        budget(&book.ledger, &node.id(), node.scan_share()),
        price,
    );
    node.scan_bids.store(n, std::sync::atomic::Ordering::Relaxed);
    Ok(n)
}
```

(`Kind` and `DAY_MS` imports are for the tests; move them into the test module if the compiler warns.) Add `pub mod jobs;` to `src/credits/mod.rs`. In `credits::run`, before the hourly `price::refresh`, call `jobs::announce_bids(&node)` (log failures at debug) and also call it every tick (`announce_bids` is cheap: one count and the cached book).

- [ ] **Step 4: Config**

`src/config.rs`: `CreditsConfig { audit_share, #[serde(default = "default_scan_share")] scan_share: f64 }`, `fn default_scan_share() -> f64 { 0.5 }`, `check` rejects values outside 0..=1 with "credits.scan_share must be between 0 and 1"; extend the existing `[credits]` test with `scan_share = 0` and the bad values. `src/lib.rs` near line 273: `node.set_scan_share(cfg.credits.scan_share);` before the arbiter starts. Document it in the example config if the repository has one (`grep -rn audit_share deploy docs`), next to `audit_share`.

- [ ] **Step 5: Messages**

`src/cluster/msg.rs`:

```rust
pub struct Grant {
    pub job_uid: String,
    pub ip: String,
    pub level: i64,
    pub lease_secs: u64,
    /// The arbiter's offer that funds this job (`credits::jobs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub price_mc: u32,
}

    Claim {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude_levels: Vec<u8>,
        /// The least a funded job may pay: half the scanner's own scan price.
        #[serde(default, skip_serializing_if = "is_zero")]
        min_mc: u32,
    },
```

with `fn is_zero(n: &u32) -> bool { *n == 0 }`. Fix every `Msg::Claim { exclude_levels }` pattern and construction (`arbiter.rs:131`, `scan/mod.rs:540`, msg tests).

- [ ] **Step 6: Arbiter**

Carry `min_mc` through `handle` → `claim` → the waiter tuple (`type Waiter = (NodeId, Vec<u8>, u32, oneshot::Sender<Option<Grant>>)`) → `hand_out` → a new `next_job_for(scanner, exclude, min_mc)`, which calls the existing `next_job` and then:

```rust
    async fn next_job_for(&self, scanner: NodeId, exclude: &[u8], min_mc: u32) -> Result<Option<Grant>> {
        let Some(mut g) = self.next_job(scanner, exclude).await? else {
            return Ok(None);
        };
        if let Some((seq, price)) = crate::credits::jobs::fund(&self.node, scanner, &g.job_uid, min_mc).await {
            g.offer_seq = Some(seq);
            g.price_mc = price;
            info!(job = %g.job_uid, scanner = %scanner.short(), price = %crate::credits::show(price as u64), "scan job funded");
        }
        Ok(Some(g))
    }
```

`next_job_skipping` builds the `Grant` with `offer_seq: None, price_mc: 0`. Existing tests keep calling `next_job`.

- [ ] **Step 7: Scanner**

In `src/scan/mod.rs`:
- `Job::Granted` gains `offer: Option<(u64, u32)>`; set it from `g.offer_seq.zip(Some(g.price_mc))` in `check_grant` where the `Job::Granted` is built.
- `acquire_granted`: claim with `min_mc: node.price_table().price_of(crate::credits::price::SCAN).unwrap_or(0) / 2`; before the loop, order the arbiters: those whose heartbeat (or, for this node, `node.scan_bids`) announces `scan_bids > 0` first, by announced `scan_price_mc` descending, then the rest in the existing order (a stable sort by `(funded rank, original index)`).
- Every path that reports a granted job's end calls `crate::credits::jobs::settle(&node, arbiter, seq, if status == "done" { price } else { 0 })` when `offer` is `Some((seq, price))`: the finish path near line 760 and the two turn-down spawns in `acquire_granted` (`over_share`, `check_grant` errors; there the grant's `offer_seq` is used directly with 0).

- [ ] **Step 8: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::jobs && cargo test --lib scan:: && cargo test --lib cluster::msg && cargo test --lib config`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add -A src
git commit -m "Scan jobs are paid: arbiters fund grants within scan_share, scanners charge on delivery and ask funding arbiters first"
```

---

### Task 5: Paid domain resolution

**Files:**
- Modify: `src/intel/dns.rs` (`ResolveReq`, `choose`, `lookup_with`, `ask`, tests)
- Modify: `src/cluster/rpc/mod.rs:219-240` (`resolve` handler)

**Interfaces:**
- Consumes: `pay::make_offer(node, server, total_mc) -> Result<u64, String>`, `pay::accept_offer(node, peer, offer_seq, price, what, margin_ms) -> Result<Accepted, Declined>`, `pay::release(node, peer, offer_seq)`, `pay::SERVE_MARGIN_MS`, `price::RESOLVE`, `Table::price_of`, `Shares::take_good`, `Node::market`.
- Produces: `ResolveReq { name, #[serde(default)] offer_seq: Option<u64> }`; `ResolveResp { addrs, error, #[serde(default)] charged_mc: u32 }`; `dns::resolver_price(node: &Node, id: &NodeId) -> Option<u32>`; `dns::serve_resolve(node: &Arc<Node>, peer: NodeId, req: &ResolveReq) -> ResolveResp`.

- [ ] **Step 1: Write the failing tests** (in `src/intel/dns.rs` tests)

```rust
    #[test]
    fn only_priced_market_resolvers_are_chosen() {
        let c = |n: u8, priced: bool| (Resolver { id: NodeId([n; 32]), name: format!("n{n}"), sibling: false, country: None }, priced);
        let kept = keep_priced(vec![c(1, true), c(2, false), c(3, true)]);
        assert_eq!(kept.iter().map(|r| r.id).collect::<Vec<_>>(), [NodeId([1; 32]), NodeId([3; 32])]);
    }

    #[test]
    fn a_failed_resolution_charges_nothing() {
        assert_eq!(charge_for(&Ok(vec!["203.0.113.9".parse().unwrap()]), 40), 40);
        assert_eq!(charge_for(&Ok(vec![]), 40), 40, "an empty answer is an answer");
        assert_eq!(charge_for(&Err("SERVFAIL".into()), 40), 0);
    }

    #[test]
    fn a_resolve_request_without_an_offer_encodes_like_before() {
        #[derive(serde::Serialize)]
        struct Old { name: String }
        let new = ResolveReq { name: "example.com".into(), offer_seq: None };
        assert_eq!(
            crate::cluster::rpc::cbor::encode(&new).unwrap(),
            crate::cluster::rpc::cbor::encode(&Old { name: "example.com".into() }).unwrap()
        );
    }
```

- [ ] **Step 2: Run to see them fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib intel::dns`
Expected: compile errors.

- [ ] **Step 3: Request and response**

```rust
pub struct ResolveReq {
    pub name: String,
    /// The asker's offer for this resolution (`credits::pay`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_seq: Option<u64>,
}

pub struct ResolveResp {
    pub addrs: Vec<IpAddr>,
    #[serde(default)]
    pub error: Option<String>,
    /// What the resolver charged, in mc.
    #[serde(default)]
    pub charged_mc: u32,
}
```

`ResolveResp::refused` sets `charged_mc: 0`.

- [ ] **Step 4: The resolver's side**

```rust
/// What a resolver charges for `answer` at `price`: an answer (even an
/// empty one) costs the price, a failure nothing.
pub fn charge_for(answer: &Result<Vec<IpAddr>, String>, price: u32) -> u32 {
    if answer.is_ok() { price } else { 0 }
}

/// Resolve `req.name` for `peer`, paid with the offer it names.
pub async fn serve_resolve(node: &Arc<Node>, peer: NodeId, req: &ResolveReq) -> ResolveResp {
    use crate::credits::{pay, price};
    let Some(name) = valid_name(&req.name) else {
        return ResolveResp::refused("not a host name");
    };
    let Some(seq) = req.offer_seq else {
        return ResolveResp::refused("resolving a name is paid with credits: the request carries no offer");
    };
    let sibling = crate::cluster::owner::fleet::siblings(&node.store).await.is_ok_and(|s| s.contains(&peer));
    if !sibling {
        node.market.note(price::RESOLVE, 1);
    }
    let Some(cost) = node.price_table().price_of(price::RESOLVE) else {
        pay::release(node, peer, seq).await;
        return ResolveResp::refused("this node has no resolution price yet; ask again later");
    };
    if let Err(d) = pay::accept_offer(node, peer, seq, cost as u64, "resolve", pay::SERVE_MARGIN_MS).await {
        let why = match d {
            pay::Declined::Why(w) | pay::Declined::NotCovered(w) => w,
            pay::Declined::TooLow { why, .. } => why,
        };
        return ResolveResp::refused(&why);
    }
    let taken = match node.lookup_shares() {
        Some(s) => s.take_good(price::RESOLVE).await.unwrap_or(false),
        None => true,
    };
    if !taken {
        pay::release(node, peer, seq).await;
        return ResolveResp::refused("this node's resolutions for others are used up for today");
    }
    let answer = resolve_here(&name).await;
    let charged = charge_for(&answer, cost);
    let receipt = crate::cluster::record::Record::CreditReceipt {
        payer: peer,
        offer_seq: seq,
        charged_mc: charged,
        answered: if charged > 0 { vec![price::RESOLVE.into()] } else { vec![] },
    };
    let charged = match crate::cluster::repl::append(node, &[receipt]).await {
        Ok(_) => charged,
        Err(e) => {
            tracing::warn!(?e, "resolve receipt not written");
            0
        }
    };
    match answer {
        Ok(addrs) => ResolveResp { addrs, error: None, charged_mc: charged },
        Err(e) => ResolveResp::refused(&e),
    }
}
```

`src/cluster/rpc/mod.rs::resolve` becomes `Cbor(crate::intel::dns::serve_resolve(&node, peer, &req).await).into_response()` with the doc "A host name resolved for a member, paid with the offer it names; it never scans, probes or stores anything." (`take_free_resolve` was removed in Task 3.)

- [ ] **Step 5: The asker's side**

```rust
/// What `id` announces for resolving a name; None: no price, or it
/// predates the market.
pub fn resolver_price(node: &Node, id: &NodeId) -> Option<u32> {
    let m = node.members().get(id).cloned()?;
    if !crate::credits::pay::pays_with(m.proto_max) {
        return None;
    }
    node.status
        .known(id)?
        .hb
        .prices
        .iter()
        .find(|(g, _)| g == crate::credits::price::RESOLVE)
        .map(|(_, mc)| *mc)
        .filter(|mc| *mc > 0)
}

/// The candidates that can be paid, in their order.
fn keep_priced(candidates: Vec<(Resolver, bool)>) -> Vec<Resolver> {
    candidates.into_iter().filter(|(_, priced)| *priced).map(|(r, _)| r).collect()
}
```

In `choose`, keep this node and filter the others before `pick`: build `others` as `(resolver(id), resolver_price(node, &id).is_some())` and pass `keep_priced(...)` on. In `ask`, take the price, write the offer, and name it:

```rust
async fn ask(node: &Arc<Node>, id: NodeId, name: &str) -> (NodeId, Result<Vec<IpAddr>, String>) {
    let Some(addr) = node.dial_address(&id) else {
        return (id, Err("cannot be dialled from here".into()));
    };
    let Some(price) = resolver_price(node, &id) else {
        return (id, Err("announces no price for resolving".into()));
    };
    let seq = match crate::credits::pay::make_offer(node, id, price as u64).await {
        Ok(seq) => seq,
        Err(why) => return (id, Err(why)),
    };
    let req = ResolveReq { name: name.to_string(), offer_seq: Some(seq) };
    let call = node.call::<ResolveReq, ResolveResp>(id, &addr, "/rpc/v1/resolve", &req);
    let answer = match tokio::time::timeout(crate::intel::lookup::RPC_TIMEOUT, call).await {
        Err(_) => Err("did not answer in time".into()),
        Ok(Err(e)) => Err(format!("could not be asked: {e:#}")),
        Ok(Ok(ResolveResp { error: Some(e), .. })) => Err(e),
        Ok(Ok(ResolveResp { addrs, .. })) => Ok(addrs),
    };
    (id, answer)
}
```

A resolver that times out never writes a receipt; the asker's offer lapses after 15 minutes and costs nothing.

- [ ] **Step 6: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib intel::dns && cargo test --lib admin::lookup`
Expected: PASS. (The `admin::lookup` resolve test runs standalone or with no priced members, so only this node answers.)

- [ ] **Step 7: Commit**

```bash
git add -A src
git commit -m "Domain resolution is paid to each other resolver: offer per resolver, charged only for an answer"
```

---

### Task 6: Protocol gate and the cluster tests

**Files:**
- Modify: `src/cluster/rpc/proto.rs`, `src/credits/pay.rs` (`quotes`, `accept_offer`, `pays_with`), every payment check on `OWNER_PROTO` in `src/scan/probe/`
- Modify: `tests/cluster.rs` (`grant_scans` at line ~4877 and the credit tests from line ~4844 to ~5500)

**Interfaces:**
- Consumes: `proto::MARKET_PROTO`, `pay::pays_with` (Task 3).
- Produces: `proto::PROTO_VERSION = 4`.

- [ ] **Step 1: Write the failing unit test** (in `src/credits/pay.rs` tests)

```rust
    #[test]
    fn only_market_nodes_are_paid() {
        assert_eq!(crate::cluster::rpc::proto::MARKET_PROTO, 4);
        assert!(crate::cluster::rpc::proto::PROTO_VERSION >= crate::cluster::rpc::proto::MARKET_PROTO);
        assert!(!pays_with(3));
        assert!(pays_with(4));
    }
```

- [ ] **Step 2: Run to see it fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::pay`
Expected: FAIL on the `PROTO_VERSION` assertion.

- [ ] **Step 3: Implement the gate**

`src/cluster/rpc/proto.rs`: `pub const PROTO_VERSION: u32 = 4;`.

Use `pays_with` in `pay::quotes` instead of `>= OWNER_PROTO`, and at the top of `accept_offer`:

```rust
    if !node.members().get(&peer).is_some_and(|m| pays_with(m.proto_max)) {
        release(node, peer, offer_seq).await;
        return why("your node predates the market (protocol 4): upgrade it to pay here".into());
    }
```

Run `grep -rn "OWNER_PROTO" src/scan src/credits src/intel` and replace each check that guards a payment or a price with `pays_with(m.proto_max)`.

- [ ] **Step 4: Seed balances with the mint in the cluster tests**

Replace `grant_scans` in `tests/cluster.rs`:

```rust
/// Counted scans of `node` two days ago (a closed day), for a trap that
/// is no test node: `node` gets that day's mint, shared with every other
/// node granted scans in the same test by their numbers of scans.
async fn grant_scans(on: &[&TestNode], node: NodeId, scans: u32) {
    use peephole::credits::DAY_MS;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let first = NEXT.fetch_add(scans as u64, std::sync::atomic::Ordering::SeqCst);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let day = now_ms / DAY_MS - 2;
    let trap = NodeId([0xEE; 32]);
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
            .bind(&trap.0[..])
            .bind((((day * DAY_MS + 3_600_000 + k) << 16) as i64))
            .execute(&n.store.pool)
            .await
            .unwrap();
        }
    }
}

/// What a node granted `scans` of `total` scans in a test holds from the mint.
fn minted(scans: u64, total: u64) -> u64 {
    peephole::credits::mint::MINT_PER_DAY * scans / total
}
```

Then run `cargo test --test cluster credit` (and the other names below) and update each expectation:
- A balance seeded as `10_000` (8 scans) becomes `minted(8, 8)`; where two nodes were granted scans in one test, use `minted(theirs, all)`.
- A server's gain `cost / 2` becomes `cost`; `a_lookup_answered_by_the_nodes_own_provider_costs_half_net` becomes `..._costs_nothing_net` with `book.balance(&a.id) == minted(8, 8)` and no `destroyed`.
- `announced_prices_follow_the_clusters_earnings` becomes `announced_prices_follow_demand_and_supply`: after `price::refresh`, the heartbeat of `a` carries a positive price for `abuseipdb` and `maxmind-geolite2`; after noting demand far above supply (`na.node.market.note("abuseipdb", 10_000)`) and refreshing again, the `abuseipdb` price rose.
- The assertion near line 5185 ("without an offer only free providers answer") becomes: without an offer nothing is answered and every provider is declined with "paid with credits".
- `a_paid_lookup_moves_credits_from_the_asker_to_the_server`: `book.balance(&b.id) == cost` (b was granted no scans).
- `an_old_version_member_is_not_asked_for_paid_lookups`: the old member announces protocol 3.

Add one test:

```rust
/// A paid lookup moves exactly the price: what the asker loses, the
/// server gains.
#[tokio::test]
async fn a_payment_destroys_nothing() {
    use peephole::credits::{self, price};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    serves(&nb, &[("abuseipdb", Some(1000.0))], 0.2);
    grant_scans(&[&na, &nb], a.id, 8).await;
    price::refresh(&nb.node).await.unwrap();
    let none: peephole::intel::Providers = vec![];
    let answers = peephole::intel::lookup::cluster(&rec(&na), &none, "203.0.113.78".parse().unwrap()).await;
    let cost = answers.iter().find(|x| x.node == "node-bravo").unwrap().charged_mc as u64;
    assert!(cost > 0);
    eventually("the receipt arrived", || async {
        credits::book_fresh(&na.node).await.unwrap().balance(&b.id) == cost
    })
    .await;
    let book = credits::book_fresh(&na.node).await.unwrap();
    assert_eq!(book.balance(&a.id) + book.balance(&b.id), minted(8, 8));
}
```

- [ ] **Step 5: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib credits::pay && cargo test --test cluster credit && cargo test --test cluster lookup && cargo test --test cluster price && cargo test --test cluster resolve`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A src tests
git commit -m "Protocol 4: payments only between nodes that count with the market's rules; cluster tests seed balances with the mint"
```

---

### Task 7: The Credits page shows the market

**Files:**
- Modify: `src/admin/credits.rs`, `templates/admin_cluster_credits.html`

**Interfaces:**
- Consumes: `Book.minted`, `Book.allowances`, `mint::closed`, `price::Table` (`scan_mc`, `scan_bids`, `capacity`, `probe_mc`, `resolve_mc`, `offers`), `ledger::Tally.served`.

- [ ] **Step 1: Write the failing render test** (in `src/admin/credits.rs` tests)

```rust
    #[test]
    fn the_page_shows_where_credits_come_from() {
        use askama::Template;
        let page = CreditsPage {
            chrome: crate::admin::views::Chrome::new(true, "admin"),
            balance: "1250.00".into(),
            held: "0.00".into(),
            days: vec![],
            fleet: None,
            earned: vec![],
            waiting: 0,
            spent: vec![],
            moved: vec![],
            members: vec![MemberRow {
                key: "k".into(),
                name: "node-alpha".into(),
                balance: "1250.00".into(),
                earned: "255.00".into(),
                spent: "0.00".into(),
                standing: String::new(),
                minted: "250.00".into(),
                allowance: "5.00".into(),
                sales: "1.20".into(),
            }],
            totals: ("255.00".into(), "812.00".into()),
            price: PriceView {
                scan: "0.05".into(),
                scan_bids: 3,
                capacity_per_hour: "40".into(),
                utilization: "12".into(),
                probe: None,
                resolve: "0.01".into(),
                offers: vec![("MaxMind GeoLite2".into(), "0.02".into(), "1000".into())],
            },
            receivers: vec![],
            income: vec![("2026-10-06".into(), "250.00".into(), "5.00".into())],
            accruing: (12, true),
        };
        let html = page.render().unwrap();
        for want in ["2026-10-06", "250.00", "5.00", "1.20", "812.00", "0.05", "12 scans counted so far", "1000 credits are split among the scanners"] {
            assert!(html.contains(want), "{want} missing");
        }
        assert!(!html.contains("destroyed"));
    }
```

Adjust the field list to the struct's actual fields after Tasks 1–3 (they are the ones named here).

- [ ] **Step 2: Run to see it fail**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib admin::credits`
Expected: compile errors (`income`, `accruing`, `minted`, `resolve`).

- [ ] **Step 3: Implement**

`CreditsPage` gains `income: Vec<(String, String, String)>` (this node's closed days, newest first: date, its mint share, its allowance, from `book.minted`/`book.allowances` grouped by `day_of(hlc)`) and `accruing: (u32, bool)` (today's counted scans of this node: `book.paid` with `weight > 0`, `scanner == me` and today's day; whether this node recorded a request today, from `mint::active_days(pool, &[me], today, today)`). `MemberRow` gains `minted`, `allowance` (sums over the last 7 days per node) and `sales` (`week_tally(..).served`). `PriceView` gains `resolve` (`show(t.resolve_mc)`).

Template: a section "Where credits come from" before the balance tables:

```html
<p>Every day 1000 credits are split among the scanners by the scans that counted. Every member that earns here and recorded a request gets 5 credits a day. A credit is gone 7 days after the day it was minted; nothing else destroys it.</p>
<p>Today: {{ accruing.0 }} scans counted so far{% if accruing.1 %}, and the allowance{% endif %}; credited when the day ends (UTC).</p>
<table>
  <thead><tr><th>Day</th><th class="num">Mint</th><th class="num">Allowance</th></tr></thead>
  {% for (d, m, a) in income %}<tr><td>{{ d }}</td><td class="num">{{ m }}</td><td class="num">{{ a }}</td></tr>{% endfor %}
</table>
```

The members table gets the columns "Mint", "Allowance", "Sales" (7 days). The price list adds "Resolving a name costs **{{ price.resolve }}** credits here."

- [ ] **Step 4: Run the focused tests**

Run: `export PATH=$HOME/.cargo/bin:$PATH; cargo test --lib admin::credits`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/admin/credits.rs templates/admin_cluster_credits.html
git commit -m "Credits page: mint, allowance, income by source and the market's prices"
```

---

### Task 8: Docs and changelog

**Files:**
- Modify: `docs/cluster.md` (section "Credits: lookups are paid with scans", lines 149–239), `README.md` (line ~105), `CHANGELOG.md` (Unreleased), `docs/superpowers/specs/2026-10-07-dynamic-market-design.md` (status line)

- [ ] **Step 1: Rewrite the Credits section**

Title "Credits: a market for the cluster's work". Bullets in the section's existing style, each a bold lead and plain sentences:
- **Where credits come from.** The daily mint (1000 credits split among scanners by counted scans of the day; levels 3 and 4 count twice; a scan of a node's own job never counts; one counted scan per address in 24 hours, 500 a day per scanner) and the allowance (5 credits a day for every member that earns here and recorded a request that day). Both are credited when the UTC day ends.
- **Where they go.** A credit is gone 7 days after its day. Payments move the full price.
- **Prices.** One rule per good, hourly, per node: excess demand raises a price by at most a factor of e^0.45 an hour, excess supply lowers it, never under 0.001 credits. Every provider is paid, the Tor exit list, RDAP, InternetDB and GeoLite2 included; there is no free quota. A provider with an API budget offers its on-demand share; one without, and name resolution, offer `[enrichment] offer_per_day` (default 1000) a day. The Lookup page asks only the providers picked.
- **Domains.** Each other resolver is paid its announced price; a failed resolution costs nothing; this node's own resolver is free.
- **Scan jobs.** The arbiter funds its jobs up to `[credits] scan_share` (default half) of its balance; funded jobs are offered to scanners first; the scanner charges on delivery; a scan offer lapses after 12 hours.
- Keep, updated: conformity and audits, budgets, known addresses, collecting node, two histories.
- **What this cannot do**: replace the trap-share and price-claim items with the spec's §8 items (manufactured requests, two keys of one operator, many keys, free riders, small allowances, no outside value, constants from a simulation); keep the others that still hold.
- **Upgrading.** Protocol 4: payments only between upgraded nodes; upgrade all nodes together; balances are recounted at start.

- [ ] **Step 2: README and CHANGELOG**

README line on credits: "lookups, probes and scan jobs are paid with credits; scanners earn most of them, every member a little." CHANGELOG under Unreleased, "Changed": the dynamic market in six bullets (mint, allowance, market prices with `offer_per_day`, paid scan jobs, every provider and resolution paid with no free quota, no burn) and "Upgrade all nodes together: protocol 4 pays only between upgraded nodes."

- [ ] **Step 3: Spec status**

Set `Status: implemented.` in the spec.

- [ ] **Step 4: Full verification**

Run: `df -h . && export PATH=$HOME/.cargo/bin:$PATH; cargo clippy --all-targets -- -D warnings && cargo test --lib && cargo test --test cluster`
Expected: no warnings; all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add docs README.md CHANGELOG.md
git commit -m "Docs: the dynamic market"
```
