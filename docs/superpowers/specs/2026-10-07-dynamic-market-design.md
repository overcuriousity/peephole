# Dynamic market: a fixed mint, an allowance, prices from supply and demand

Date: 2026-10-07 · Status: draft.

Replaces the credit rules of "Credits: lookups are paid with scans" in
`docs/cluster.md` and rewrites that section when implemented. Builds on the
ledger, offers and receipts, gates, audits and ownership as they are on
master (PR #47).

## Goal

Credits become a market. Every service the cluster renders has a price
set by supply and demand, no price is a constant, and the people who do
the work that can be checked earn the new money:

- **Every scan job, lookup, probe and domain resolution costs credits.**
  What a node already holds (its dataset, replicated answers) stays free.
- **Scanners earn most**: a share of a fixed daily mint for checked work,
  plus the full price of every funded job.
- **Every conforming member earns a little**: a small daily allowance, so
  a sensor-only node can spend.
- **Growth is self-correcting**: more sensors means more money chasing
  scans, a higher scan price, and a reason to run another scanner.

Why: today a scan pays a constant 1 or 2 credits (and the trap a quarter
of that, which invented requests farm), provider weights are constants,
scan jobs are free, and half of every payment is destroyed. Requests can
never be verified, so they must not mint; scans can, by audit.

## The four laws

1. **Money enters by two doors only.**
   - The **daily mint** `MINT_PER_DAY`, split among scanners by their
     counted scans of that UTC day (§1).
   - The **allowance** `ALLOWANCE_PER_DAY` to every member that conforms
     here and recorded a request that day (§2).
2. **Money leaves by one door only: expiry.** A credit keeps its lot (the
   day it was minted) when it changes hands and is gone 7 days later, as
   now. Nothing is burned: a payment moves its full amount.
3. **Everything else is a transfer at a market price**: the buyer pays
   the node that rendered the service (§3, §4).
4. **Prices move with supply and demand**: excess demand raises a price,
   excess supply lowers it, each good on its own (§5).

Money in circulation is therefore bounded: at most 7 days of mint plus 7
days of allowances.

## Protocol constants and price parameters

**Ledger constants** decide balances, so every node must use the same
ones or balances diverge. They are constants of the build:

| Constant | Value | Meaning |
|---|---|---|
| `MINT_PER_DAY` | 1000 credits | Split among scanners per UTC day |
| `ALLOWANCE_PER_DAY` | 5 credits | Per conforming, active member per UTC day |
| `PER_NODE_PER_DAY` | 500 (existing) | Counted scans per scanner per day |
| `LOT_DAYS` | 7 (existing) | Lifetime of a credit |
| Level weights | 1 (levels 1, 2), 2 (levels 3, 4) | A scan's weight in the mint split |

**Price parameters** only shape the offers a node makes; a receipt never
charges more than was offered, so nodes may differ in them without
harm. They are defaults of the build:

| Parameter | Value | Meaning |
|---|---|---|
| `PRICE_FLOOR` | 1 mc | No price goes below (the ledger's smallest unit) |
| `PRICE_STEP` | 0.15 | How fast a price follows the imbalance (§5) |

Ratio, not level, matters: the allowance is about 1/50 of what a scanner
earns from the mint in a cluster of four scanners. Prices find their
level against the money supply.

## 1. The daily mint

- **Counted scans.** A scan counts for its scanner under today's rules of
  `earn::pay` (backed by a request held here, one per IP and 24 hours,
  built-in arguments, the scanner's standing, `PER_NODE_PER_DAY`) **and**
  the new **cross-owner rule**: the scanner and the trap that queued the
  job are not the same node and not siblings of one owner
  (`cluster::owner`). Levels 3 and 4 count 2, levels 1 and 2 count 1
  (the work ratio of today's tiers). Funded and unfunded jobs count alike.
- **The split.** Each scanner gets `MINT_PER_DAY × its count / all
  counts` of day D, dated D (so it lives D … D+6). Every node computes it
  from the scans it holds, like every balance today.
- **When.** Day D's split is final for display once D has ended (UTC) and
  `JUDGE_AFTER_SECS` has passed; until then the Credits page shows it as
  accruing and it cannot be spent. A scan of day D that reaches a node
  later still counts there and shifts the shares slightly; a lot that
  shrinks makes later offers cover less, as with a member that stops
  earning today (`ledger`).
- **No scans that day**: nothing is minted for it.
- **Audits** earn nothing and cost nothing, as now. A scanner whose scans
  fail the audits of your own nodes stops counting here (existing gate).
- **The trap share goes.** Recording requests earns nothing directly.

## 2. The allowance

- Every member gets `ALLOWANCE_PER_DAY` for day D, dated D, when on this
  node it (a) has no gate (`gates::Standing` neither blocked, forked nor
  below the rules agreement), and (b) recorded at least one request dated
  D that is held here. Scanners and API nodes get it too.
- It is credited when day D ends, like the mint.
- A new node earns it once the rules agreement is measurable
  (`RULES_MIN_SAMPLE`, existing).

## 3. Scan jobs

- **Funding.** The arbiter (the node that queued or adopted the job)
  funds its jobs from its own balance: by default
  `[credits] scan_share = 0.5`, i.e. up to half of what it can spend may
  be held in or paid for its own scan jobs; 0 funds nothing, 1 all. The
  operator sets it on System › Settings (`credits.scan_share`).
- **Order.** Funded jobs go first (by response ratio among them, as now),
  then unfunded ones; a scanner takes unfunded jobs only when it has no
  funded one. Fairness among claimants stays as it is.
- **Offer and receipt.** On a grant of a funded job the arbiter writes an
  **offer** to the scanner at its scan price (§5); the `Grant` carries the
  price. The scanner writes the **receipt** when it delivers the result,
  charging at most the offered price; the receipt names `scan`. A scan
  offer lapses after the job's level timeout (`pace::level_timeout_secs`)
  plus `SERVE_MARGIN_MS`, not after 15 minutes.
- **Declining.** A `Claim` carries the scanner's own scan price; the
  arbiter grants a funded job only at a price of at least half of it, and
  otherwise an unfunded one or nothing. So a scanner is never handed work
  at a price far below what it sees.
- **A job that was not funded** is scanned by idle capacity, for the mint
  only.

## 4. Lookups, probes, domain resolution

- **Lookups.** Every provider costs its market price on the serving node,
  your own providers too (you pay yourself; the amount comes back). The
  50 % destruction goes: the server keeps the full charged amount.
- **Probes.** Priced like a provider named `probe` on each scanner, with
  its probe slots as supply.
- **Domain resolution** costs each resolver's `resolve` price; the free
  per-hour allowance (`take_free_resolve`) and the free-lookup limit
  (`pay::FREE_PER_HOUR`) go, since nothing is free; prices limit use.
- **Providers without a daily budget** (Tor exit list, RDAP, GeoLite2,
  resolution) have unlimited supply, so their price sits at the floor.
  The Lookup page keeps running the cheap tier by itself: every provider
  whose price is at the floor.
- **Budgets stay safe.** `[enrichment] on_demand_share` still caps what
  paid lookups take of each API budget; the share is the supply.
- **Answers already held** (fresh under 24 h, replicated) are shown free.

## 5. Prices

Each node computes its prices hourly and announces them in the heartbeat
(the existing `prices` field). The rule for every good is one:

    price ← max(PRICE_FLOOR, price × exp(PRICE_STEP × clamp((D − S) / max(S, 1), −3, 3)))

with D and S over the last hour:

| Good | Demand D | Supply S |
|---|---|---|
| Scan (one price per node, cluster-wide inputs) | Funded jobs waiting: the sum of the `scan_bids` arbiters announce (new heartbeat field: jobs they would fund at their price now) | Scans an hour the live, counted scanners can do (`price::capacity`, existing) |
| Provider p on this node | Paid requests for p offered to this node | Its on-demand allowance per hour; unlimited without a budget |
| Probe on this scanner | Probe offers to it | Its probe slots an hour |
| Resolution on this node | Resolve requests to it | Unlimited |

- **Payments within one owner** (siblings) are not counted as demand, so
  an owner cannot pump its own price.
- **A new good** starts at the median price other members announce for
  it, or at the floor.
- **The weights go**: `weight_milli`, the unit price, the load factor,
  the probe's 4 units and the surge (`share::surge`, `SURGE_MAX`) are
  replaced by this rule. The existing re-offer once up to twice the
  announced price stays.
- Prices are kept across restarts (`intel_kv`, like the share counters).

## 6. Compatibility and later changes

Balances are a pure function of the log, so an upgraded node recomputes
the whole 8-day window under the new rules at start. Ledger constants
can change later only by a release that every node takes. Old and new nodes
count different balances: a new protocol version `MARKET_PROTO`
(`rpc::proto`, `PROTO_VERSION` 4) gates payments. New nodes neither offer
to nor serve nodes below it; scans by old scanners still count for the
mint on new nodes. The changelog tells operators to upgrade all their
nodes together.

**Later changes** to a ledger constant take effect on upgrade: the
release changes the rules at once, the node recounts the 8-day window,
and nodes disagree on balances until every node has upgraded. Such a
release bumps `PROTO_VERSION`, so payments run only between nodes with
the same rules; its changelog says so.

## 7. Pages and docs

- **Cluster › Credits** shows: this node's balance by lot day, today's
  accruing mint share and allowance, money in circulation, the prices it
  sees for scans and each provider over 7 days, and income by source
  (mint, allowance, sales) for each member. Why a scan did not count
  (existing notes) stays, plus "same owner as the trap".
- **System › Settings**: `credits.scan_share`.
- `docs/cluster.md` Credits section rewritten to the four laws; README
  line on credits; CHANGELOG.

## 8. What this cannot do

- **Invented or manufactured requests** cannot be told from real ones.
  They no longer mint anything, but they create jobs that idle scanners
  scan for the mint.
- **Two unlinked keys of one operator** (a trap and a scanner) pass the
  cross-owner rule and take a larger share of the fixed mint, at the
  expense of honest scanners, up to `PER_NODE_PER_DAY`. Blocking (with
  the admission subtree) is the answer.
- **Many keys** each draw the allowance. Joining needs an invite, a member
  admits at most 20 nodes a day, and each key must pass the rules
  agreement first.
- **A free-riding operator** (`scan_share = 0`) gets its attackers scanned
  only by idle capacity; with many of them the scan price understates
  demand.
- **A sensor with a small allowance** can be priced out of goods that cost
  more than 7 days of it; operators place sensors where traffic is.
- **Credits have no outside value**: an API node is paid in services of
  the cluster, as today.
- The constants were chosen with an abstract simulation, not with data
  from a real cluster; the Credits page shows what is needed to adjust
  them.

## 9. Testing

- `earn`: cross-owner rule (same node, siblings, unlinked), level weights,
  the mint split of a day (shares sum to `MINT_PER_DAY`, empty day mints
  nothing), late scans shifting shares.
- Allowance: gates, the active-that-day condition, day dating.
- `ledger`: receipts move the full amount; scan offers lapse after the
  level timeout; a shrinking lot makes later offers cover less.
- Price rule: rises with excess demand, falls to the floor with excess
  supply, bounded step, same-owner demand ignored, start from announced
  median.
- Arbiter: funded before unfunded, the `scan_share` budget, declining a
  grant priced below half the scanner's price.
- Protocol: no offers to or from nodes below `MARKET_PROTO`.
- Render tests for the Credits page and the setting.
