# Scanner prices: each scanner sells at its own price

Date: 2026-10-07 · Status: proposed.

Changes §3 (scan jobs) and the scan part of §5 (prices) of
`2026-10-07-dynamic-market-design.md` as implemented on master. Builds on
PR #49 (the Credits market dashboard and `price_history`); implementation
starts once #49 is merged. Everything else of the market (mint, allowance,
lookups, probes, resolution, expiry) stays as it is.

## Goal

A scan job goes to the cheapest scanner, and a scanner's price follows how
busy it is:

- **A scanner prices itself.** Paid work above a target share of its
  capacity raises its price; less lowers it. An idle scanner gets cheap
  and attracts work, a busy one gets expensive and sheds it, so work
  spreads across the scanners by price.
- **The arbiter picks the cheapest scanner** that asks, whether it is
  another node or its own.
- **A node's own jobs follow the same rule as anyone's**: paid when its
  scan budget covers its own scanner's price, unpaid otherwise.
- **Nodes that collect credits elsewhere can fund scans.**
- **No node can raise a price by announcing one**: buyers compute every
  scanner's price themselves from public inputs.

Why: today one scan price is computed on every node from all paid jobs
waiting against all scan capacity. It ignores how busy any one scanner
is, so an idle scanner cannot get cheaper; it ignores unpaid jobs; and
each node's copy drifts, so "best paying first" ranks arbiters by drift.
Paid jobs always go before unpaid ones, so a scanner's own jobs (never
paid) and those of nodes that forward their credits (no balance) come
last and starve under load. Scan funding draws only on the node's own
balance, so a node whose credits sit at its collecting node funds
nothing.

## Constants

Price parameters, defaults of the build (they shape offers only):

| Parameter | Value | Meaning |
|---|---|---|
| `PAID_TARGET` | 0.9 | Share of a scanner's capacity paid work should fill |
| `PRICE_TOLERANCE` | 1.25 | An arbiter offers at most this times its own copy of a scanner's price; a scanner takes no less than its price divided by it |
| `DELIVERY_MIN` | 0.5 of at least 5 | Share of an arbiter's recent grants a scanner must deliver to be ordered by price (§8) |

The price rule itself (`step`, `PRICE_STEP`, `PRICE_FLOOR`) is unchanged.
The scan price stays flat per job, whatever the level.

## 1. A scanner's price

Every node keeps a price for **every scanner** it counts (live members
with the scanner role, not blocked or forked here; `price::scanners`),
and steps each once an hour with the existing rule:

- **Demand**: the scanner's paid scans whose result says they finished
  in the past hour (the scan's own `finished_at`, not when its receipt
  arrived), as the log holds them: the scans its receipts name, plus the
  scans it ran of jobs it queued itself (the node that queued the job,
  as the mint's own-job rule identifies it, `earn::Judged::trap`).
- **Supply**: `PAID_TARGET` × the scans it can do in an hour, as
  `price::capacity` computes them today from its announced pace and the
  durations of its jobs in the replicated queue.
- `scan_mc = step(current, demand, supply)`.

Every input is public: the receipts and scans are in every node's log, the
pace is in the heartbeat. So every node arrives at nearly the same price
for each scanner; they differ only by log lag.

The scanner's own copy of its price is its **selling price**, announced in
its heartbeat. Other nodes' copies are their **reference prices** (§3).

Why `PAID_TARGET` < 1: a scanner fetches work only when a worker is free,
so paid work can never exceed its capacity. With a target of 1 the price
could only fall. With 0.9, sustained overload raises the price until paid
demand settles near 90 %; the rest goes to unpaid jobs, so they are not
starved entirely.

All own jobs count as demand, whether or not the node's budget covered
them (§4): other nodes cannot tell the two apart. They do occupy the
scanner.

**Start.** A node starts a scanner's price from, in order: its last
copy (kept across restarts, `price:scan:<node>`); on upgrade, the node's
kept cluster-wide scan price (`price:scan`); otherwise the lower median
of the scan prices scanners announce; otherwise the floor.

Non-scanners compute no price of their own. The cluster-wide scan price
and its `bids` go.

## 2. Who gets a job

**Scanner side** (`acquire_granted`). A scanner asks arbiters in two
groups:

1. Arbiters that can pay its selling price: `scan_budget_mc` ≥ its price
   and `scan_queued` > 0, as they announce (§5). Its own node counts when
   its own budget covers the price.
2. All other arbiters with queued jobs.

Within each group the order is the urgency order of the market before
this change (highest response ratio first, `order::ratio_sql`), not price.
`min_mc` in the claim becomes the scanner's selling price divided by
`PRICE_TOLERANCE` (was: half of it).

**Arbiter side** (`hand_out`). The scanners that claim within the claim
window are sorted by the price this arbiter would pay each (§3), cheapest
first; equal prices by fewest scans in the last hour, then by key. Each
gets the arbiter's next job (`next_job`, unchanged). The job is funded at
that scanner's price when the budget left in the round covers it, and
granted unpaid otherwise.

## 3. The price check

An arbiter offers a scanner `min(announced, own copy × PRICE_TOLERANCE)`,
rounded down. A scanner that announces less is paid less. A scanner that
announces more than the tolerance allows is paid the arbiter's figure.
If that is under the claim's `min_mc` (the announced price divided by
`PRICE_TOLERANCE`), `fund` grants unpaid.

So a scanner can always undercut its price, and can never raise it beyond
what the rule gives from public inputs. A scanner whose price only
drifted from the arbiter's copy is paid at most a little less.

## 4. A node's own jobs

- The node's own scanner takes part in §2 like any other, at its selling
  price.
- A grant of an own job to its own scanner is **funded** when the round's
  budget left covers that price. No offer is written: paying oneself
  moves nothing. The amount is kept with the job (`scan_jobs.self_mc`,
  new column) and counts in `jobs::budget` like an offer's charge of the
  day: held while the job runs, charged when it ends done, released when
  it fails or is refused.
- Otherwise the own job is granted unpaid, like a poor arbiter's.
- So a node's own jobs use up the same `scan_share` as jobs it buys
  elsewhere. Its balance is untouched.
- Unchanged: a scan of a node's own job earns no mint.

## 5. The collecting node

A node with `collect_to` set (another node of its fleet):

- **Budget**: `scan_share` × (its own balance + its collecting node's
  balance divided by the number of its siblings, `owner::fleet::siblings`;
  whether a sibling forwards is its own setting and not known here),
  less what its scan offers and own jobs hold and were charged
  today. Every node computes any member's balance from its log.
- **Scan float**: once an hour, after the price step, it draws from its
  collecting node what its queued jobs need at the cheapest scanner's
  price, up to that budget, less what it holds (`fleet::draw`).
  `fleet::collect` forwards only what exceeds the float.
- A draw that fails leaves the node's jobs unpaid until the next hour.

The collecting node itself funds from its own balance as now.

## 6. Protocol and heartbeat

Protocol 5 (`SCAN_PRICE_PROTO`). Heartbeat:

- `scan_price_mc`: the scanner's selling price; None on a node that does
  not scan.
- `scan_budget_mc` (new): the arbiter's scan budget left now.
- `scan_queued` (new): its queued jobs.
- `scan_bids` is no longer sent and is ignored when received.

An arbiter funds only scanners on protocol 5 or later. A scanner on an
older protocol gets unpaid grants. A scanner on protocol 5 treats an arbiter
on an older protocol as unable to pay. Upgrade all nodes together, as with
protocol 4.

## 7. Pages and docs

- **Credits page** (PR #49's dashboard): the `scan` row shows this node's
  selling price as its own price (none on a non-scanner), and the lowest,
  median and highest announced selling prices. Its demand and supply are
  this scanner's paid scans and `PAID_TARGET` × its capacity per hour. A
  table lists every scanner: announced price, this node's reference
  price, paid scans in the last hour against its capacity.
- **`price_history`**: the `scan` good records this node's selling price,
  as above.
- **`docs/cluster.md`**: the "Prices" and "Scan jobs" bullets and the
  limits list.
- **CHANGELOG**: Unreleased.

This spec is not amended after implementation.

## 8. Attack vectors

Each is mitigated where the design can; what remains is in §9.

- **A cheap scanner that hoards jobs.** A scanner announces the floor,
  wins every claim round by price, and delivers nothing or hands the jobs
  back: sensors' scans stall. Today's ordering by load limited this; price
  ordering alone would not. Mitigation in `hand_out`:
  - a claimant that already got its announced capacity of jobs from this
    arbiter in the past hour is ordered after all others;
  - a claimant that delivered less than half of at least 5 grants of this
    arbiter in the past 24 hours (failed, lease expired, handed back) is
    ordered after all others, by load.
  Leases still return undelivered jobs, as now.
- **Cherry-picking under a flat price.** A scanner hands back long
  (level 3, 4) grants and keeps short ones. A handed-back funded grant
  counts as undelivered for the rule above. `exclude_levels` stays the
  only honest way to refuse a level, as now.
- **An arbiter that underpays.** A modified arbiter computes a low
  reference price. The scanner's `min_mc` is its price divided by
  `PRICE_TOLERANCE` (not half), so an offer more than that below is
  granted unpaid, and the scanner orders that arbiter as one that cannot
  pay for the next hour.
- **An arbiter that overstates its budget.** It announces a large
  `scan_budget_mc` to be asked first, then grants unpaid. A scanner counts
  an arbiter as able to pay only when the arbiter's balance in its own
  book covers the price. An arbiter whose grant came unpaid although it
  was asked as able to pay is ordered with those that cannot for the next
  hour.
- **Receipt timing.** A scanner holds receipts back and writes them in
  one hour to make that hour's demand spike. Demand counts scans by when
  they finished, not when the receipt was written, so holding receipts
  back moves nothing.
- **A fleet that counts its balance several times.** Each sibling would
  see the whole collecting node's balance and fund from it, overspending
  `scan_share` many times. Each counts its share of it (§5).
- **Undercutting.** A scanner sells below its rule price to win jobs.
  This is allowed: buyers gain, and its price then rises by the rule as it
  fills. It cannot later raise its price faster than the rule allows.

## 9. What this cannot do

- **Understated capacity.** A scanner can announce a lower pace to look
  busier and raise its price. It then runs fewer scans than it could, and
  scans beyond its announced pace show in the log.
- **A lone dishonest scanner at start.** A node that joins a cluster
  whose only scanner announces an inflated price starts its reference
  price there. From then on that price moves only by the rule.
- **Overload still rations by money.** When every scanner is busy, an
  arbiter that cannot pay waits. The rest of capacity left by
  `PAID_TARGET` goes to unpaid jobs.
- **Log lag.** Arbiters and scanners compute from their own logs. Prices
  differ by what arrived where, within `PRICE_TOLERANCE` in normal
  operation.
- **Own jobs count as load.** A node's own jobs raise its scanner's price
  even when its budget did not cover them.
- **Capacity withdrawal raises the price.** A scanner that fills itself
  with its own jobs (invented requests at its own trap), or with paid jobs
  of a second key of its operator, looks busy and its price rises. This
  is the same as announcing a lower pace, which an operator can always do:
  a scanner that sells less of its capacity is scarcer. Others are
  protected by choosing the cheapest scanner, by `scan_share` bounding
  what they spend, by the rule bounding how fast a price rises, and by
  the mint drawing new scanners in. With one scanner it is a monopoly,
  and that cannot be priced away.

## 10. Testing

- Unit: the price step of one scanner from demand and capacity, including
  a busy scanner rising, an idle one falling to the floor, and a saturated
  scanner settling near `PAID_TARGET`.
- Unit: the offer price as `min(announced, copy × PRICE_TOLERANCE)`, and
  unpaid below `min_mc`.
- Unit: the scanner's claim order (can-pay group first, urgency within,
  own node by its own budget); the arbiter's order (cheapest first, then
  load).
- Unit: own-job funding against the budget, held, charged and released
  with `self_mc`; no offer written.
- Unit: the fleet budget (the collecting node's balance shared among
  its forwarding nodes) and scan float; `collect` keeps the float.
- Unit: the attack mitigations: a claimant over its hourly capacity or
  under `DELIVERY_MIN` goes last; demand by `finished_at`; an underpaying
  or unpaid-granting arbiter drops out of the can-pay group for an hour;
  an arbiter whose book balance is under the price is not asked first.
- Unit: heartbeat compatibility: a protocol 4 heartbeat decodes, a
  protocol 5 one decodes on protocol 4.
- Integration (`tests/cluster.rs`): two scanners at different prices, one
  arbiter. The cheaper gets the jobs until its price rises past the other.
  A scanner that announces an inflated price is paid the reference price.
