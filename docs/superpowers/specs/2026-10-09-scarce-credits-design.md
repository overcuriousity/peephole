# Scarce credits: a fixed money supply, sales-driven prices, and new goods

Date: 2026-10-09. Status: approved design, awaiting the implementation plan.

## Why

Measured on the live 5-node cluster on 2026-10-09: every good was priced at
the floor of 1 millicredit at every node, demand per hour was 0.0 for every
good, and the only purchases of the week were 300 scan jobs and 4 name
resolutions at 1 millicredit each. The fixed daily mint of 1000 credits was
helicopter money with nothing to buy; prices could not leave the floor
because they moved only on capacity, and a 5-node cluster never runs out of
capacity. Credits regulated nothing.

The user's intent, in their words: no mint; sales only; nothing burned; the
allowance is the only money that flows in; the total supply is fixed; there
are no unfunded jobs; no price floor; prices fall when money is scarce and
rise when money is spread evenly; everything the cluster does for a member is
a good that member buys; non-scanner nodes get real ways to earn.

## What the user decided

| Question | Decision |
|---|---|
| Money model | No mint. Sellers keep what they charge. The daily pool is the only inflow. |
| Pool size | 1000 credits a day, so the supply is 6000 credits. |
| Cutover | Protocol 7. A node joins the new economy and leaves the old one; nothing is recounted. |
| Price rule | Sold: raise. Sold nothing: lower. At capacity: raise. No floor. |
| Allowance | Only verified listeners: advertised, listener role, reachable in at least 12 of 24 hours by hourly peer reports. Outbound-only members get none. |
| Quorum | Reverse DNS and resolution ask min(9, ⌊n/2⌋+1) nodes; majority of answers stands. Anything not from an external provider needs a quorum. |
| Probes | Stay scanner-gated: a scanner defines itself by exposing itself. |
| Audits | A scanner buys peer review of its scans from other scanners; which scans and which auditors are drawn from the log, not chosen by the scanner (revised). Unpaid random checks stay. |
| Relays | Outbound-only members lease outbox hosting from reachable members, two at a time. |
| Not in this round | Automatic enrichment stays free. Reachability checks, history service, Tor fetching, more providers, claim verification: later specs. |

## 1. Money supply

Nothing mints and nothing burns. A credit keeps its lot day when it changes
hands and is gone 7 days after that day, as today. The only inflow is the
daily pool.

- `POOL_PER_DAY = 1000 credits`. At the end of each UTC day the pool is
  split evenly among that day's verified listeners, in millicredits, the
  remainder going one millicredit each to the lowest node keys. The share
  of a member that does not earn on a node (its standing there) is not
  credited there and not redistributed.
- A **verified listener** of day d is a member that, on day d, has the
  listener role and an advertised address in its member record, and was
  **up** in at least 12 of the day's 24 hours.
- **Reach reports.** Every member writes one replicated record per UTC
  hour, `ReachReport { hour: u32, reached: Vec<NodeId> }`, listing the
  advertised members it completed at least one sync round with during that
  hour. No new traffic: sync rounds already run every minute. Reports are
  written at the start of the next hour, carry the hour they describe, and
  a node writes at most one per hour (later ones for the same hour are
  ignored, as are reports for hours more than 25 hours back or in the
  future). A member is up in hour h when more than half of the reports for
  h, from distinct reporters that are not blocked or left out here, name
  it. A reporter never counts for itself, and only members with an
  advertised address in their member record count as reporters
  (revised: outbound-only keys cost nothing to run, so they could
  otherwise outvote the reachable members).
- The supply during any day is six pools: the lots of the six previous
  days. The pool of day d is dated `end_of(d)` and lives on days d..d+6.
- The old mint, the judge, the counted-scan weights, `credit_scans`,
  `credits why` and the per-member allowance go.

## 2. Prices

### No floor

`PRICE_FLOOR` goes. A price is a `u32` of millicredits that may be 0. The
step rule keeps its sizes (at most e^0.45 up and e^-0.15 down per hour,
scaled by the time since the last refresh) and its "at least one millicredit
toward the imbalance" clause, which is what lifts a price off zero.

### The sales rule

Every seller refreshes each good it sells every 10 minutes, as today. The
signal per good is:

- **Sold** anything in the period: it served a request for the good, paid
  or free (the existing demand counter, `market.note`), ran a scan job it
  was granted by another arbiter, or accepted a lease. A scanner's own jobs
  count neither as sales nor toward its capacity (revised: otherwise it
  could raise its own price by queuing work for itself). Raise by the full step.
- Sold nothing: lower by the full step.
- At capacity (the existing demand-over-supply signal: scans against 90 % of
  what it can do, lookups against the on-demand share, probes against slots,
  leases against slots): raise, whatever it sold.

A good priced at zero that is used therefore leaves zero at the next
refresh. Prices track the money: buyers
pick the cheapest per delivered result and can spend only their budgets, so
a price above what the cluster can pay stops selling and falls. In
equilibrium the cluster's spending matches its inflow.

### Zero-priced goods are free, without an offer

- A lookup, resolution, reverse-name or probe request may carry no offer.
  The server answers whatever it prices at zero right now and declines the
  rest naming the price (the existing too-low path), so the asker may offer
  again.
- Scan jobs: a bid at price 0 is affordable. The grant is funded at 0 and
  writes no offer. `Grant.offer_seq` stays None and `price_mc` 0; the
  scanner treats it as funded.
- The Lookup page still asks only this node's own providers by itself; a
  member pricing a provider at zero is listed under "Ask for more" at
  "free".

### No unfunded jobs

Every grant is funded, at zero or above. The arbiter's idle-work branch
(granting the best bid unpaid when no bid is affordable), the sit-out rule
for unpaid jobs, the `paid`/`funded` distinction in hand-outs, and the
scanner-side demotion of arbiters that grant unfunded all go. A job with no
affordable bid is not granted this round and waits. `[credits] scan_share =
0` now means the node funds only zero-priced scanners.

## 3. Quorum goods

### Quorum size

`q = min(9, ⌊n/2⌋ + 1)` where n is the number of reachable members that
announce a price for the good, this node included (live within the intel
window, not blocked, callable). Standalone: q = 1.

### Resolution

Unchanged in flow and tally; `MAX_RESOLVERS = 5` becomes q. The resolvers
asked are this node and the q-1 cheapest, ties broken by the existing
diversity order (other operators before siblings, new countries before seen
ones). `IpNameRec.answers` may hold up to 9 answers.

### Reverse DNS

A new good `rdns`, priced per node like `resolve` (supply: `offer_per_day`
a day). Only the node that recorded a source (the origin of the first
request held for it) buys its reverse names, on today's schedule (first
seen; again when it returns a day after the last lookup). It asks itself
free and the q-1 cheapest members over `/rpc/v1/rdns` (routable), each
with an offer unless priced at zero. Each resolver answers only
forward-confirmed PTR names; a failure is unpaid. The buyer writes one
replicated `RdnsRec { uid, ip, at, answers: Vec<(NodeId, Result<Vec<String>,
String>)>, build }`. Every node tallies it: a name stands when more than
half of those that answered gave it, and is kept in `ip_names` with source
`rdns` and an `agreed` flag; a disputed name is kept with the flag off. The
local reverse-DNS loop no longer looks up other members' sources. A
standalone node keeps its own loop as today.

## 4. Paid audits

Revised 2026-10-09: in the first version the scanner chose which of its
scans were audited and by whom, so it could fake most results and buy
audits only of the honest ones, from a friend. Now neither choice is the
scanner's.

**Which scans.** A successful scan of a job granted by another arbiter
(own jobs are left out: they pay nobody), at level 1 to 4, is
**designated** for audit when `SHA-256("peephole-audit\0" || job uid ||
the HLC of the arbiter's done status)` read as a fraction is below
`AUDIT_RATE = 0.05`, a protocol constant. The arbiter writes the done
status only after the scan result is published, so the scanner has
committed to every result before it can know which one is checked, and it
cannot redraw. Every node computes the same designation from the log.

**By whom.** The auditors of a designated scan are ranked by
`SHA-256(seed || auditor key)`, seed as above, over the active members with
the scanner role at protocol 7 other than the scanner. The scanner offers
the first of them that is live and announces a scan price, at that price (at
least 1 mc), with a `CreditOffer` whose new `audit: Option<String>` field
names the scan uid, and sends `AuditReq { scan_uid, job_uid, ip, level,
offer_seq }` as a directed message; when it declines or cannot be reached,
the second, then the third. An auditor accepts only a scan for which it is
among the first three. It runs the audit as today (same arguments, within
30 minutes of the scan), publishes `ScanAuditRec`, and writes the receipt
(`answered: ["audit"]`) when the result is published. A failed or late
audit charges nothing and the offer lapses.

**Obligation.** From the log, every node counts per scanner the scans
designated in the last 7 days (leaving out the most recent
`AUDIT_OFFER_TTL`, whose audits may still be running) and how many of them
it bought: a `ScanAuditRec` by one of the scan's first three auditors, with
a charged audit offer from the scanner to it. A scanner fails when at least
2 designated scans have no bought audit and it bought fewer than 80 % of
them. `Standing` gains `audits_owed: Option<(u32, u32)>` (bought,
designated). A scanner that fails it is not funded by arbiters, and in each
node's ledger its scan receipts move nothing while it fails, as with the
rules gate, so it earns nothing from scans until it catches up. The differ
gate is unchanged: a node believes only the audits made by itself and its
fleet.

**Unpaid checks stay.** The auditor-side picker of today stays: each
scanner re-runs `[credits] audit_share` (default 0.05) of other nodes' fresh
scans on its own, unpaid. It covers own jobs and small scanners, and feeds
the differ gate of the auditor's fleet.

Known limits: a member's fleet is private, so a sibling of the scanner can
rank among its first three auditors (with n scanners and k siblings, about
3k/n of the designated scans) and approve whatever it is sent; the unpaid
checks of the other operators are the guard. An arbiter colluding with its
scanner can choose its done-status HLC and steer the designation.

## 5. Relay leases

A new good `relay`: one hour of holding an outbox for an outbound-only
member and relaying directed messages to it. Any advertised member sells it;
capacity is `[cluster] relay_slots` leases an hour (default 16); its price
follows the sales rule and is announced in the heartbeat's `prices` under
`relay`.

- An outbound-only member leases two relays every hour: the two cheapest
  reachable members announcing a price. One offer each, `RelayReq { hours:
  1, offer_seq }` over `/rpc/v1/relay`, accepted with a receipt charged at
  acceptance (`answered: ["relay"]`). It renews 5 minutes before expiry.
  With fewer than two sellers it leases what there is.
- The relay records the lease in memory until it expires. It holds an
  outbox and accepts outbox hops only for members it has a current lease
  from; messages for anyone else are refused.
- The lessee long-polls only its leased relays' inboxes and lists them in
  its heartbeat (`relays: Vec<NodeId>`). A sender routes a directed message
  to an outbound-only member through one of the listed relays and tries
  the other when the first fails or refuses. The neighbour-graph route
  stays as the fallback for members that list no relays.
- Without a lease the member still syncs (sync is free) but cannot be asked
  for anything paid.

## 6. Protocol 7 and the cut

- `PROTO_VERSION = 7`, `ECONOMY_PROTO = 7`; `pays_with` and `sells_scans`
  require it. Payments, funded jobs, resolutions, probes, audits and leases
  run only between protocol-7 members.
- **A clean cut, nothing recounted.** Entries of the new economy are
  distinguishable from the old: `CreditOffer`, `CreditReceipt` and
  `CreditTransfer` carry `economy: u8 = 2`, and their seals are signed
  under a new domain string. The ledger reads only economy-2 entries and
  the pool; every entry of the old economy is ignored for good. Balances
  start at zero on upgrade; the first money is the first pool credited
  after a day with 12 reported hours. Old lots, old sales and the old
  mint are neither carried over nor reconstructed.
- New record kinds (`ReachReport`, `RdnsRec`, the `audit` and `economy`
  fields) are relayed only to protocol-7 members. New RPC paths
  `/rpc/v1/rdns` and `/rpc/v1/relay` are routable.
- Each node's kept prices carry over; the sales rule moves them from there.
- Upgrade all members in one sitting. A member below protocol 7 is not
  paid, not funded and not charged until it upgrades.

## 7. Installer, pages, CLI and docs

- Installer: the advertise prompt says that a node nobody can reach gets no
  daily allowance, earns only by scanning or selling lookups and names, and
  must lease a relay to be asked for anything paid.
- Credits page: the "Minted today" tile and the mint column go; an "Up"
  column shows the member's reported hours today and whether it qualifies;
  the goods table gains reverse names, relay and the audit share; "Where
  credits come from" describes the pool and the 12-hour rule.
- Overview: counted scans go.
- CLI: `credits why` goes; `credits uptime` lists each member's reported
  hours per day for the last 7 days.
- docs/cluster.md (Credits section, outbound-only paragraph, Upgrading),
  README (Lookup paragraph), `deploy/config.example.toml` (`[credits]`,
  `[cluster] relay_slots`), CHANGELOG (Breaking).

## 8. Testing

Unit tests: pool split with remainder; hourly reach tally, the majority
rule and the 12-hour rule; quorum size; the sales step at zero, when sold,
when idle and at capacity; affordability at zero; the audit designation
and auditor ranking, the obligation and its 2-missing / 80 % rule; the economy filter in the ledger.

Cluster tests, one per behaviour: the pool reaches reached listeners only
and not an outbound-only member; a zero-priced lookup is served without an
offer and a priced one is declined naming the price; a job is granted at
zero and funded once the price rises; reverse names are bought from q nodes
and agreed names replicate with their flag; a scanner that buys no audits
of its designated scans stops being funded; an outbound-only member with a lease is asked through
its relay and one without is not; a protocol-6 member is neither paid nor
charged; old-economy entries move nothing.

The existing mint, allowance and idle-work tests are deleted, not adapted.
