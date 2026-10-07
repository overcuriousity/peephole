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
| `PRICE_FLOOR` | 1 mc | No price of a good with limited supply goes below (the ledger's smallest unit) |
| `PRICE_STEP` | 0.15 | How fast a price follows the imbalance (§5) |

Ratio, not level, matters: the allowance is about 1/50 of what a scanner
earns from the mint in a cluster of four scanners. Prices find their
level against the money supply.

## 1. The daily mint

- **Counted scans.** A scan counts for its scanner under today's rules of
  `earn::pay` (backed by a request held here, one per IP and 24 hours,
  built-in arguments, the scanner's standing, `PER_NODE_PER_DAY`) **and**
  the new **own-job rule**: the scanner is not the trap that queued the
  job. (Ownership is not replicated: a node knows only its own siblings,
  so no node can tell that two other members share an owner; the rule
  can only be the node key.) Levels 3 and 4 count 2, levels 1 and 2 count 1
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
  `[credits] scan_share = 0.5` in the config file. What its scan offers
  hold plus what they were charged today may reach that share of its
  balance plus those two; 0 funds nothing, 1 everything.
- **Order.** A scanner asks the arbiters that announce funded jobs
  (`scan_bids` > 0) first, highest scan price first, then the others as
  now. An arbiter that can fund grants with an offer, otherwise without.
  Fairness among claimants stays as it is.
- **Offer and receipt.** On a grant of a funded job the arbiter writes an
  **offer** to the scanner at its scan price (§5); the `Grant` carries the
  price. The scanner writes the **receipt** when it delivers the result,
  charging the offered price for `done` and nothing otherwise; the
  receipt names `scan`. A scan offer carries the job's uid and lapses
  after `pace::MAX_RUN_SECS` plus `SERVE_MARGIN_MS`, not after 15
  minutes.
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
- **Free: what needs no setup.** The Tor exit list, RDAP and Shodan
  InternetDB need no account or key; they stay free, served without
  offers under the existing hourly limit (`pay::FREE_PER_HOUR`), and the
  Lookup page runs them by itself. A provider is marked free in
  `intel::KNOWN_PROVIDERS` (`free: bool`). InternetDB's on-demand share
  still protects its budget.
- **Everything else is paid**, GeoLite2 included: its operator set up an
  account and a key.
- **Supply without an API budget.** A paid provider without a daily API
  budget (GeoLite2) and domain resolution use the operator's
  `[enrichment] offer_per_day` (default 1000) as their daily supply on
  that node. A node that offers more is cheaper; askers go to the
  cheapest server first, so many generous nodes lower the price.
- **Domain resolution** is paid to each other resolver: the asker offers
  each its announced `resolve` price, the resolver charges it when it
  answers and nothing when it fails. This node's own resolver costs
  nothing. Resolvers that announce no price, or predate the market, are
  not chosen. The free hourly resolution allowance (`take_free_resolve`)
  goes.
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
| Paid provider p on this node | Paid requests for p offered to this node | Its on-demand share of the API budget per hour, or `offer_per_day` / 24 without a budget |
| Resolution on this node | Paid resolve requests to it | `offer_per_day` / 24 |
| Probe on this scanner | Probe offers to it | Its probe slots × 30 an hour (`PROBE_TIMEOUT` is 2 minutes) |

- **Requests from this node's own siblings** are not counted as demand,
  so an owner cannot pump the price of its own nodes.
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
- **Config file**: `[credits] scan_share`, `[enrichment] offer_per_day`.
- `docs/cluster.md` Credits section rewritten to the four laws; README
  line on credits; CHANGELOG.

## 8. What this cannot do

- **Invented or manufactured requests** cannot be told from real ones.
  They no longer mint anything, but they create jobs that idle scanners
  scan for the mint.
- **Two keys of one operator** (a trap and a scanner) pass the own-job
  rule and take a larger share of the fixed mint, at the
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

- Providers: free ones need no offer; GeoLite2 and resolution use `offer_per_day`; a paid resolution is charged only when answered.
- `earn`: own-job rule, level weights,
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
