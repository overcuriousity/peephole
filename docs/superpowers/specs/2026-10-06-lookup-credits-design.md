# Lookup credits: earned by scanning, spent on lookups

Date: 2026-10-06 · Status: draft for review.

Companion spec: [node ownership](2026-10-06-node-ownership-design.md),
which defines the fleet (an operator's own nodes), siblings and owner
commands.

## Problem

An admin can ask every provider the cluster reaches about one address
(Admin → Lookup). A member serves at most 50 API lookups a day per asking
node (`intel::lookup::PER_PEER_PER_DAY`), whatever that node contributes.
A node that only consumes gets the same as one that runs a capable
scanner.

## Goal

- The base allowance is 0. Lookups are paid with **credits**, and credits
  are earned by work the cluster asked for: completed counter-scans.
- A fleet earns and spends as one entity: what any of its nodes earns is
  one balance, and any of its nodes can spend it.
- A lookup shows everything the cluster knows about the address, and what
  was paid for is kept for everyone.
- A node that serves lookups is paid for it.
- The price of a lookup follows what the cluster scans and what it can
  serve, so a node's share of the earnings buys the same share of the
  lookups in a cluster of 4 nodes and in one of 400.
- Nodes whose rules or scan arguments are not the common ones do not earn.
- No single operator can drain the cluster's provider budgets, whatever
  they do to the credit system.
- Everything is judged by each node for itself, from its own copy of the
  log. No voting, no global chain.
- Every step is visible in the admin area.

Not a goal: stopping a member from recording requests nobody sent. Nothing
in this architecture can tell such a request from a real one
(docs/cluster.md says so already). §12 states what that costs.

## Terms

| Term | Meaning |
|---|---|
| **Cluster** | All member nodes. Their operators need not know or trust each other. Every node judges every other for itself |
| **Fleet** | The nodes of one operator: those that hold a certificate of the same ownership key. A subset of a cluster. Its nodes prove membership to each other, not to the rest of the cluster |
| **Sibling** | Another node of this node's fleet |
| **Managing node** | A fleet node that keeps the ownership key and can therefore command its siblings |
| **Collecting node** | The fleet node that receives what the others earn; the fleet's one balance sits there |

## Decisions

| Topic | Decision |
|---|---|
| Unit | 1 credit = 1000 mc (millicredits), integers throughout. Shown with two decimals |
| Earning | Per completed scan: scanner 1.0 (L1, L2) or 2.0 (L3, L4); the trap that queued the job 0.25 or 0.5 |
| Not earning | Uptime, recorded requests, audit scans, failed or refused scans |
| Per IP | One paid scan per IP in 24 hours, cluster-wide; a higher level later in the window pays the difference |
| Per node | At most 500 paid scans per UTC day as scanner and 500 as trap |
| Lifetime | A credit can be used on the day it was earned and the 6 days after |
| Accounts | Per node in the ledger. Only a node's own log can debit it |
| Fleet balance | Fleet nodes forward what they earn to the fleet's collecting node; a sibling that needs credits draws them from there |
| Sending | Any node may send credits to any node |
| Lookup price | Dynamic, set by each serving node from one formula: what the cluster earned per day, divided by what it can serve per day, times a load factor (§7). Weights: keyed API provider 1, Shodan InternetDB 0.25, GeoLite2 0.25, Tor exit list free |
| Load factor | Half price while the cluster's scanners idle, double when they are saturated, from measured scan times against configured workers and scans per hour |
| Where the price goes | Half to the node that answered, half is destroyed |
| Own providers | Cost the same as anyone else's |
| Which node answers | Per provider, the one with the lowest announced price. No preference for the asking node or its fleet |
| Known addresses | A lookup shows everything the dataset holds on the address, free. A stored provider result under 24 hours old is shown instead of asking again |
| Paid results | Kept in the dataset when the cluster has recorded the address; never kept otherwise |
| Scan capacity | Measured from the log and the scanners' pace; shown, and the source of the load factor (§7) |
| Server protection | On-demand lookups take at most `on_demand_share` (default 0.2) of each provider budget; a provider whose share ran out costs double the next day |
| Rules conformity | A node earns only while at least 98% of its newest 500 requests classify the same here |
| Scan conformity | A scan earns its scanner share only when run with the built-in arguments of its level |
| Audits | Every scanner re-runs 5% of every other node's fresh scans; a node believes its own audits and its siblings' |
| Double spending | Cannot be prevented without consensus. Made provable (§6); a node caught loses all credit standing |
| Standalone node | Unchanged: its own providers, no credits |

## What is enforced, and how

| Claim | Enforced by | How strong |
|---|---|---|
| Who offered, sent or received what | The Ed25519 signature every log entry already carries | Cannot be forged or denied |
| A node has no payments it hides from some members | Seals: each payment commits to a hash of the node's log before it (§6) | Two shown histories leave two signed, contradicting entries: proof for everyone |
| Nobody spends more than they hold | Every node recomputes every balance from the log (§8) | Exact in each node's view |
| Nobody spends the same credit twice | Not preventable here; detected and proven after the fact | The node's credits become void everywhere |
| A request was classified with the common rules | Classifying it again: the classifier is deterministic and every member holds the request | Exact, for the request as recorded |
| A scan used the common arguments | The command line in the scan's nmap XML | A declaration. A modified binary can declare one thing and run another |
| A scan actually ran | Audits (§4) | Statistical |
| A request actually arrived | Nothing | — |

Signatures and hashes settle everything nodes say **to each other**.
Re-running settles everything that is a **computation over shared data**.
Neither can settle a statement about the outside world; only a second
look (an audit) can.

Considered and left out:

- **Zero-knowledge proofs** of correct classification: re-running gives
  the same assurance, and every member has the inputs.
- **Attested hardware** to prove which binary ran: operators own their
  machines, and most nodes are plain virtual servers.
- **Homomorphic encryption**: it computes on data the computing party may
  not read. Members share the whole dataset on purpose, and the API
  providers need the plain address anyway.
- **Hash puzzles** as a way to earn: they reward hardware, not
  contribution.
- **A global chain or voting**: invites are open, so a set of throwaway
  nodes outvotes the honest ones.

## 1. Lots

- A credit belongs to a **lot**: a node and the UTC day it was earned,
  `day = floor(physical_ms(hlc) / 86 400 000)` of the entry that created
  it.
- A lot of day `d` can be named by entries dated on days `d ..= d + 6`.
  Afterwards it is gone.
- Offers and transfers name the lots they draw on. A credit keeps its lot
  when it changes hands, so it expires 7 days after the scan that created
  it, however often it moved.
- Each day's lots form a ledger of their own. A node needs the entries of
  the last 7 days to know every live balance. The smallest history window
  is 7 days (`retention_days`), so every node has them.

## 2. Earning

### A payable scan

A scan is **payable** when this node holds all of:

- the job (`scan_jobs` row, from `scan_job`), with status `done` and a
  scanner `X` as its arbiter recorded them;
- a scan row for that job whose origin is `X`, with the job's IP and
  level, that is not an audit.

Its time is the HLC of the scan result entry (`scans.hlc`); its lot day
follows from that. The earliest such scan of a job counts.

### Judging it (once)

At least 10 minutes after the scan row arrived, so the requests behind it
have had time to replicate, the node judges the scan and stores the result
in `credit_scans (scan_uid, job_uid, ip, scanner, trap, hlc, level,
args_ok, judged_at)`:

- **Level.** `guard::evidence` for the IP with this build's classifier
  and this node's `scan.trusted_origins`, as a scanner does before it
  runs a job. `level = min(job level, evidence.max_level)`. Level 0 (no
  request here backs any scan): the scan pays nothing.
- **Arguments.** `args_ok` when the `args` attribute of the nmap XML,
  normalized, equals the normalized built-in command line for that level
  (§3).

`trap` is the origin of the `scan_job` entry (the node that queued it),
also after another arbiter adopted the job.

### Paying it (at every recomputation)

Payable, judged scans are walked in HLC order:

- **Per IP.** The first paid scan of an IP opens a 24-hour window with its
  tier (low: L1, L2; high: L3, L4). A scan of that IP inside the window
  pays the difference when its tier is higher, and nothing otherwise. The
  window does not move.
- **Shares.** Low tier: scanner 1000 mc, trap 250 mc. High tier: 2000 and
  500. Without `args_ok` the scanner share is not paid; the trap share is.
- **Per node and day.** A node's 501st paid scan of a UTC day in one role
  pays nothing in that role.
- **Gates** (§3, §4, §6) remove the shares of nodes that currently do not
  qualify.

The 24-hour window is fixed here, not taken from a node's
`rescan_cooldown_hours`: that setting is the node's own and can be 0.

## 3. Conformity

Both checks are judged by each node against its own build.

### Rules

- The comparison is the one a member's page already shows
  (`classify::stored::agreement`): the member's newest 500 requests,
  classified again with this build's rules.
- A member fails when at least 20 requests were compared and more than 2%
  differ.
- While it fails, none of its shares count here, as scanner or as trap.
  When it agrees again (after an upgrade, typically), they count again:
  the gate is evaluated at each recomputation, not stored.
- The comparison is made at most every 10 minutes; its cache moves out of
  the admin state so the ledger can use it.

The fingerprint on a request (`rules`) is not part of the gate. Nodes on
different builds whose rules give the same verdicts all pass.

### Scan arguments

- **Normalizing** removes what legitimately differs per node or target:
  the target, `-oX -`, `-6`, `--host-timeout <t>`, `--script-timeout <t>`,
  `--min-rate <n>` (any value `scan.min_rate` accepts) and, at level 4,
  the optional UDP block of `scan.level4_udp`.
- What remains must equal a built-in argument list of that level: this
  build's, or one of the earlier ones in `scan::profiles::ACCEPTED`. A
  release that changes a built-in list appends the old one there; a list
  stays accepted for two releases, so a rolling upgrade costs nobody their
  earnings.
- A scanner with its own `scan.level_argv` for a level earns no scanner
  share at that level. `deploy/config.example.toml` says so next to the
  key.

Plan-time check: confirm that the stored XML is nmap's output unchanged
(the `args` attribute intact) and list every argument `scan::nmap_argv`
adds outside `default_level_argv`; the list above is from reading that
function once.

## 4. Audits

### Running them

A node with the scanner role and `credits.audit_share > 0` (default 0.05):

- When a scan result of **another node** arrives that finished at most 30
  minutes ago, it picks it for an audit with probability `audit_share`,
  from its own random source. Nobody can predict or verify the choice,
  and nobody needs to.
- It runs the same level with its own built-in arguments, through its
  normal workers. An audit counts against `max_scans_per_hour`, obeys
  `never_scan`, member addresses, the L4 share and the node's own evidence
  check, and runs before queued jobs. It ignores the rescan cooldown.
- An audit that has not started within 30 minutes of the original's end
  is dropped: the source may be gone, and a late audit proves little.
- The result is published as a `scan_audit` entry: the fields of a scan
  result plus `audit_of`, the audited scan's uid. It is stored in `scans`
  with `audit_of` set, appears on the scan pages marked as an audit, and
  is exported with an `audit_of` column.
- Audits earn nothing. Otherwise "auditing" one's own second node would
  be a way to mint.

Siblings are audited like everyone else.

### Comparing

`audit::compare(original, audit)`, a pure function of the two stored
results:

- **Inconclusive**: the audit failed, or found no open TCP port. A source
  that vanished cannot be told from one that was never scanned.
- **Agrees**: a port open in both carries the same SSH host key or TLS
  certificate; or at least half of the ports the audit found open were
  reported open by the original.
- **Differs**: otherwise.

### Believing them

- A node counts audits made by itself and by its siblings. Audits by
  other operators are shown but do not count: a few throwaway nodes could
  otherwise publish false audits and strip an honest scanner of its
  earnings.
- A scanner fails when, over the last 7 days, at least 5 counted audits of
  it were conclusive and at least half of those differ. While it fails,
  its scanner shares do not count here.
- A node without the scanner role and without scanner siblings has no
  counted audits and applies no audit gate.

The thresholds (5%, 30 minutes, 5 audits, half) are first values. The
member page shows the counts, so they can be set from what the live
cluster produces before anyone depends on them.

## 5. Records

Six new record kinds. None has a uid, except `scan_audit`, so no tombstone
can erase a payment.

```
credit_offer    { to: NodeId, parts: [(day: u32, mc: u32)], seal: Seal }
credit_receipt  { payer: NodeId, offer_seq: u64, charged_mc: u32, answered: [String] }
credit_transfer { to: NodeId, parts: [(day: u32, mc: u32)], seal: Seal }
log_seal        { seal: Seal }
fork_proof      { a: WireEntry, b: WireEntry }
scan_audit      { audit_of: String, ..fields of ScanResultRec }

Seal            { from: u64, digest: [u8; 32] }
```

An offer is identified by its origin and sequence number. A receipt names
the providers that answered, so everyone can see what was charged for
what. The address looked up is in none of them. Whether a lookup leaves a
trace is decided in § Keeping what was paid for.

Shape rules (an entry that breaks one is ignored by the ledger):

- `parts`: 1 to 7, distinct days, each within the entry's own day and the
  6 before, each `mc > 0`.
- `credit_transfer.to` is not the origin. `credit_offer.to` may be.
- A receipt comes from the offer's `to`, is dated after the offer and at
  most 15 minutes after it (by the two HLCs), and charges at most the sum
  of the offer's parts. The first receipt for an offer counts.

## 6. Seals and forks

### The gap today

`repl::apply_one` treats an entry at a sequence number it already holds as
a duplicate without comparing it. A modified node can therefore give one
member entry *n* = "offer to A" and another member entry *n* = "offer to
B", and nothing notices. Each server would see a covered offer.

### Seals

- Every node stores a **digest** per log entry: SHA-256 of the bytes the
  entry's signature covers. It is computed when the entry is appended or
  applied with its payload, kept in `repl_log.digest`, and kept when the
  entry is later erased. An entry applied by an older build has none; it
  is computed from the stored entry the first time a seal needs it.
- A **sealing entry** is a `credit_offer`, a `credit_transfer` or a
  `log_seal`. Its `seal.from` is the sequence number of the origin's
  previous sealing entry (or the entry's own number for the first one),
  and `seal.digest` is SHA-256 over the digests of the origin's entries
  `from ..` up to the one before the sealing entry.
- Ranges overlap in one entry (the previous sealing entry), so the seals
  of a node form a chain over its whole log.
- A node writes a `log_seal` when 500 of its entries have no seal yet, and
  once a day if its log grew. A range is therefore never older than any
  member's history window.

### Checking

A node that holds every entry of a seal's range with a digest recomputes
it when the sealing entry is applied.

- **Consistent**: nothing happens.
- **Unchecked**: part of the range is below this node's floor, or it only
  ever saw an erased stub of an entry. The seal says nothing here.
- **Inconsistent**: the digest differs, or `from` does not name the
  origin's previous sealing entry. The origin signed two histories. This
  node marks the origin **forked** at once (`forked (origin, seq,
  found_at)`), then pulls that range of the origin's log again from its
  peers and compares entry by entry.

When the re-pull finds a peer's entry with the same origin and sequence
number as one held here, both with valid signatures and different bytes,
the node appends a `fork_proof` with the pair (unless one is already
known for that origin, or the two together exceed 1 MiB).

A node that applies a `fork_proof` checks it (same origin, same sequence
number, both signatures valid, different signed bytes) and marks the
origin forked. The check needs nothing but the proof.

### What forked means

For a forked origin, at every node that knows:

- none of its shares count, and its balance is 0;
- its offers are not served, and transfers from it move nothing;
- credits sent to it are lost;
- the Members table and its page say "showed two histories" with the
  sequence number, and link the proof.

The mark is permanent for that node key. Membership, replication and the
node's records are not touched; blocking stays the operator's decision.

### What this achieves

A node that double-spends must fork its log. Its next offer or transfer
commits to one of the two branches, and every member holding the other
branch then has the contradiction. It can avoid that only by never paying
again. So a node key can double-spend once, for at most its balance at
each server it reaches before they compare, and is worthless afterwards.

## 7. Paying for a lookup

### Prices

A fixed price fits one cluster size only. With about 15 scans a day
(roadmap, 2026-10-04) a price of 1 credit would leave the whole cluster 15
to 40 lookups a day, where every node had 50 before; in a cluster a
hundred times larger the same price would make lookups nearly free. So
the price follows the two things that set the balance: how much the
cluster earns, and how much it can serve.

**Weights** `intel::lookup::weight(provider)`: AbuseIPDB, Shodan and
GreyNoise Community 1; Shodan InternetDB 0.25; GeoLite2 0.25; Tor exit
list 0 (free).

**What a node announces.** The heartbeat gains two fields:

- `on_demand`: per provider with a budget, the on-demand lookups this
  node serves per day (§ On-demand share);
- `prices`: per provider this node serves, its current price in mc.

**The formula.** Every serving node computes, once an hour:

```
E     = credits earned by all members in the last 168 hours, in this
        node's ledger, divided by 7                       (credits a day)
C     = sum over providers p with a budget of
        weight(p) × on-demand lookups a day announced for p
        by this node and by every live member that can be asked
        and is neither blocked nor forked here            (lookups a day)
u     = the cluster's scan utilization over the last 24 hours, 0 to 1
        (§ Scan capacity)
load  = 2 ^ (2u − 1)                  (0.5 idle, 1 at half load, 2 saturated)
unit  = E / (0.5 × C) × load, kept within 0.01 and 100 credits
price(p) = weight(p) × unit × surge(p), at least 1 mc
```

Two things move the price, on purpose:

- **`E / (0.5 × C)` sets the level.** It is the price at which the
  cluster's daily earnings buy what the cluster can serve in a day,
  whatever the cluster's size.
- **`load` moves it with the scanners' load.** With much idle scan
  capacity the cluster does not need more scanners, and lookups cost
  half. With the scanners saturated it does, and lookups cost double: a
  lookup is then worth more scanning, and earning by adding scan capacity
  pays most exactly when capacity is short.

- `E` is what the cluster's scanners actually completed and were paid
  for, read from the log. Credits exist only for completed scans, so only
  completed scans can balance against lookups.
- `E` already falls in a quiet week and rises in a busy one. `load` adds
  what `E` cannot see: whether that output was a small part of what the
  scanners could do, or all of it.
- The 0.5 is the part of every payment that survives (it goes to the
  serving node). An earned credit is therefore spent twice on average
  before it is gone, and `unit` is the price at which the cluster's daily
  earnings buy exactly what the cluster can serve in a day.
- Example: the cluster earns 20 credits a day and can serve 200 weighted
  lookups a day, so the level is 20 / 100 = 0.2 credits. With the
  scanners at half load an AbuseIPDB lookup costs 0.20 and a GeoLite2
  lookup 0.05; with them idle 0.10 and 0.025; saturated 0.40 and 0.10.
- At half load a node that earns half of the cluster's credits can buy
  half of what the cluster serves. Below that the cluster's credits buy
  more than the servers hold ready, and the on-demand share and the surge
  decide; above it, less.
- GeoLite2 has no budget and adds nothing to `C`; it is priced by its
  weight like the others.
- With no earnings yet, `unit` is at its floor of 0.01. In a cluster's
  first week `E` still fills up and prices start low.

**Surge.** `surge(p)` starts at 1. When this node's on-demand share for a
provider ran out before a UTC day ended, the provider's surge doubles for
the next day (at most 8); after a day in which it did not run out, it
halves (at least 1). It is stored with the budget counters. This is the
correction for everything the formula cannot know: capacity that members
announce but do not serve, and demand that is higher than the earnings
suggest.

**Consequences.**

- Inventing scans no longer creates lookups out of nothing. More earned
  credits raise `E` and with it every price; the inventor gains a larger
  share of a fixed capacity, at the cost of every honest earner, and the
  servers hand out no more than before.
- Prices differ slightly between servers: each uses its own ledger and
  its own surge. The asking node sees every server's price before it
  pays.

A server charges for each provider it **answered**. A provider that
declined or failed costs nothing.

### The asking node

1. Chooses a server per provider by one rule: the lowest announced
   price. Candidates are this node, if it serves the provider, and every
   live member that announces it and can be asked. This node and its
   fleet get no preference. Equal prices: one of them at random. A server
   that declines is followed by the next cheapest.
2. Refuses on its own when its balance, less its open offers, is below the
   announced price. The page says how much is missing.
3. Appends one `credit_offer` per server for the announced price of what
   it asks there, drawing on its oldest lots first.
4. Runs a sync round with the server (so the offer is there), then calls
   `/rpc/v1/lookup` with `LookupReq { ip, providers, offer_seq }`.
5. Shows the answer and what was charged.

For its own providers the node does the same without the RPC: an offer to
itself and its own receipt. Half the price comes back, half is destroyed.
A lookup is never free in a cluster, whoever answers it.

### The serving node

1. Waits up to 10 seconds until it holds the asker's entry `offer_seq`.
2. Declines when any of this fails; the reason goes into the answer:
   - the entry is a `credit_offer` to this node, at most 15 minutes old,
     without a receipt;
   - the asker is not blocked and not forked;
   - the offer's seal is **consistent**. Unchecked is not enough (the
     asker's next offer seals a range that starts at this one, so one
     declined offer is the cost);
   - its current price for the providers it is about to serve is not
     above the offer (the answer then names the price, and the asker may
     offer again);
   - in this node's own ledger the offer is covered for that price;
   - for each API provider, its on-demand share is not spent (those
     providers are declined individually; the rest is served).
3. Asks the providers.
4. Appends a `credit_receipt` with the price of what it answered. A
   receipt of 0 is written too: it frees the asker's credits at once
   instead of after 15 minutes.
5. Answers; `LookupResp` gains `charged_mc`.

A request without `offer_seq` gets free providers only, at most 60 times
an hour per asking node.

### On-demand share

`[enrichment] on_demand_share` (default 0.2, range 0–1): the part of each
API provider's budget (`intel/api.rs`) that paid lookups may use. It is
counted per provider and UTC day: a daily budget times the share, a
weekly budget times the share divided by 7, rounded down. That number is
what the node announces as `on_demand`. The counter is stored with the
budget counters so a restart does not reset it, and it covers this node's
own on-demand lookups too. `PER_PEER_PER_DAY` and
`Node::take_lookup_budget` are removed.

This is the limit that holds whatever happens to the credit system: an
operator who mints credits out of nothing can still take no more than this
share from any server.

### What the cluster knows

Every node holds the whole dataset, so this part costs nothing and asks
nobody.

- For an address the dataset holds, the lookup result shows everything
  the IP page shows: severity and activity, what it was after, stored
  provider results with their history, counter-scans with ports, host
  keys and certificates, canaries, decoys, fingerprints, the addresses
  linked to it (shared key, certificate, fingerprint or canary), its
  neighbourhood (same network, same ASN), false-positive claims, and the
  requests.
- For an address the dataset does not hold, it says so and shows the
  neighbourhood: recorded addresses in the same network, and in the same
  ASN as soon as an answer names one.
- **One source for both pages.** A new module `admin::target` returns the
  ordered list of sections for an address; the IP page and the lookup
  result both render that list. An aggregation added later (campaigns,
  new paths) is added there once and appears in both.
- A node that keeps only a window shows what it holds and says "this node
  keeps N days".

### The dataset first

Before a provider is asked about a known address, the node checks its
dataset: a result of that provider for that address fetched less than 24
hours ago, by any node, is shown instead. It is marked "from the dataset,
3 h old, fetched by <node>", costs nothing and writes no offer. "Ask
again" next to it forces a paid lookup of that provider.

### Keeping what was paid for

- When the serving node's dataset holds at least one recorded request
  from the address (a false-positive claim alone does not count), it
  writes each provider's answer into the dataset exactly as its automatic
  enrichment would: the same `ip_intel` record, the same history, and the
  provider's refresh schedule for that address starts anew.
- The asking node does the same for answers from its own providers.
- For an address the cluster has not recorded, nothing is written: not on
  the asking node, not on the serving node, not in the dataset. That part
  of today's rule stays.

What this buys: every member has the result, the automatic enrichment
does not spend its budget on that address again, and for 24 hours the
next lookup of it is free for everyone.

What it costs: for a known address, members see that a provider was asked
at that time by the serving node, next to a receipt of the same moment
that names the payer. Who looked up which recorded address can therefore
be inferred. Addresses the cluster never recorded stay private.

### Scan capacity

Shown on Cluster › Overview and per scanner on the cluster's pace table,
and the source of `u` in the price.

For each live member with the scanner role that is neither blocked nor
forked here:

```
d        = mean worker time (finished − started) of the jobs it ended,
           done or failed, in the last 7 days; with fewer than 5 such
           jobs, the cluster's mean; with none, pace::DEFAULT_SCAN_SECS
by_workers = max_workers × 3600 / d
can_do   = min(by_workers, max_scans_per_hour)        (scans an hour)
did      = jobs it ended in the last 24 hours / 24    (scans an hour)
```

`max_workers` and `max_scans_per_hour` are the node's current pace from
its heartbeat; the durations come from the replicated `scan_jobs` rows,
so every node computes them from the same data. Audits count in `did`. A
paused scanner (0 workers or 0 scans an hour) can do 0.

Cluster figures: capacity = sum of `can_do` × 24, used = sum of `did` ×
24, idle = the difference, utilization `u` = used / capacity, at most 1;
with no capacity at all, `u` = 1. Per scanner the table adds "can do" and
"did", and which of the two limits binds ("limited by workers" or
"limited by scans per hour").

What is measured and what is announced: the scan times and the number of
scans come from the log. The workers and the hourly limit are each
scanner's own setting, as its heartbeat announces them. `load` is bounded
to a factor of 2 either way, so a wrong announcement can at most halve or
double a price.

### Bulk lookups

The bulk form of Admin → Lookup reads stored data only and asks no
provider. It stays free.

## 8. The ledger

A pure function of the log and the node's own judgments, recomputed when
the log grew (cached otherwise). Input: the judged scans of §2 and the
credit entries of the last 7 days, in HLC order (ties: origin, then
sequence number). Entries of blocked and forked origins are left out.

Per lot `(node, day)` it keeps a balance; per open offer an amount held
back.

| Event | Effect |
|---|---|
| Scan paid (§2) | Adds the shares to the scanner's and the trap's lot of that day |
| `credit_offer` | For each part: `held = min(part, balance of that lot)`; moves `held` out of the lot into the offer |
| `credit_receipt` | `paid = min(charged, held in the offer)`, taken oldest lot first. Half of each lot's part (rounded down) goes to the server's lot of the same day; the rest is destroyed. What is still held returns to the payer's lots |
| Offer 15 minutes old, no receipt | What is held returns to the payer's lots |
| `credit_transfer` | For each part: moves `min(part, balance of that lot)` to the receiver's lot of the same day |

A balance never goes below 0: an entry that names more than a lot holds
moves what is there. With an honest node that never happens, since it
knows its own log. It happens when this node judges the payer's earnings
differently than the payer does, and then the difference is simply not
recognized here.

**Balances are per view.** Nodes on the same build, holding the same
entries, with the same blocks and the same siblings compute the same
balances. A node that blocks a member, or runs older rules, may count
less. A serving node is paid, in its own view, exactly for what it judged
covered before it served. Whether a third node honours those credits
later depends on that node's view of the original earnings. Common rules
keep the views together; that is what §3 is for.

## 9. The fleet's balance, and sending

The ledger has node accounts only. A fleet becomes one entity through two
movements between its nodes, both ordinary transfers.

**Collecting.**

- Runtime setting `credits.collect_to`: a node id, or nothing. Settable
  locally (System › Settings, `peephole settings set`) and by the owner
  (`Changes` gains the field).
- Every 10 minutes a node with `collect_to` set writes one
  `credit_transfer` of everything it holds to that node, when it holds at
  least 1 credit or a lot is on its last day. Nothing is sent to a node
  that is not an active member, or is blocked or forked here.
- Cluster › Ownership offers "Collect credits here": it sets `collect_to`
  to this node on every sibling.

**Drawing.**

- A node with `collect_to` set whose own balance does not cover a lookup
  sends `Msg::CreditDraw { mc }` to its collecting node, for the missing
  amount.
- The collecting node answers only a sibling (it knows them, ownership
  spec §3). It writes a `credit_transfer` of that amount, oldest lots
  first, as far as its balance goes, and says how much it sent.
- The asking node waits up to 10 seconds for the transfer to arrive, then
  makes its offer.

So every node of a fleet can look things up with what the fleet earned,
and the operator sees one balance: the Credits page shows the fleet's
total, which is the sum of the siblings' balances in this node's ledger.

**To the rest of the cluster** a fleet is not an entity. It sees nodes,
their accounts and the transfers between them, and judges each node for
itself: one sibling that fails the rules gate or is blocked loses its own
shares, not the fleet's.

**Sending.** `peephole credits send NODE AMOUNT` and a form on the Credits
page send to any member of the cluster, inside the fleet or not. No fee.

## 10. Admin interface and CLI

**Cluster › Credits** (new sub-tab):

- **Balance**: credits now; by day with "expires in N days"; held in open
  offers.
- **My nodes** (when owned): the fleet's total; each sibling's balance and
  where it collects.
- **Earned**, last 7 days: time, scan (linked), IP, level, role (scanner
  or trap), amount, and for anything not paid in full the reason in
  words: "arguments differ from the built-in ones", "no request held
  here backs this level", "this IP was already paid within 24 hours",
  "daily limit reached", "not judged yet".
- **Spent**: time, server, providers, offered, charged, of which
  destroyed, state (open, charged, lapsed, not covered at the server).
- **Sent and received**: transfers.
- **Cluster**: every member's balance, earned and spent in 7 days; totals
  earned, destroyed and in circulation.

**Admin → Lookup**: balance (the fleet's, when owned) and current prices
above the form (per provider, the server that would be asked and its
price); "this lookup costs up to 0.65 credits" before sending. The result
has three parts: what the cluster knows (§7), provider answers from the
dataset with their age and "Ask again", and live answers with the node
that served and what it charged. Decline reasons as the server gave
them. A note says whether the result was kept ("kept in the dataset: the
cluster has recorded this address") or not.

**Cluster › Credits** also explains the price: this node's `E`, `C`, the
utilization and `load`, `unit` and each provider's surge, as numbers with
one line of text each ("the cluster earned 20.4 credits a day over the
last 7 days", "the scanners ran at 31% of what they can do: lookups cost
0.77 of the plain price").

**Cluster › a member**: a "Credits" block: balance; "earns here: yes", or
"no" with every reason that applies (rules agreement below 98%, audits,
blocked, showed two histories); audits of the last 7 days as agrees /
differs / inconclusive, counted ones and others apart.

**Members table, Issues column**: "not earning here: <reason>" and
"showed two histories". "records with other rules" is no longer an issue
(§11).

**Cluster › Overview** gains a "Cluster" row of figures, all from this
node's view and each linked to the page that breaks it down:

| Figure | Meaning |
|---|---|
| Conformity | "11 of 12 members earn here", and the lowest rules agreement among members |
| Rule sets | How many different rules fingerprints the members' newest requests carry |
| Credits in circulation | Sum of all live balances |
| Earned / spent / destroyed | Per day, 7-day average |
| Expiring today | Credits in lots on their last day |
| Paid scans | Per day, 7-day average, low and high tier |
| Scan capacity | Scans a day the scanners can do, did, and idle; utilization (§7) |
| Audits | Last 7 days: agrees / differs / inconclusive (counted ones) |
| Lookup price | `unit` now with its load factor, and the range of announced prices for a keyed provider |
| Lookup capacity | Weighted on-demand lookups a day announced, and lookups served today (receipts) |
| Forks | Members that showed two histories |

**Cluster › Overview**, needs-attention strip: a member showed two
histories; this node sets `scan.level_argv` for a level (its scans there
earn no scanner share); a lot of at least 1 credit expires today.

**Scans**: an audit is marked "audit of <scan>" with the comparison
result; the audited scan shows "audited by <node>: agrees / differs /
inconclusive".

**CLI**:

```
peephole credits                      balance, by day
peephole credits log [--days N]       earned, spent, sent, received
peephole credits members              every member's balance and standing
peephole credits why SCAN             how this node judged one scan
peephole credits send NODE AMOUNT
```

**Journal**: one line per offer served or declined (asker, providers,
charged, reason), per transfer written, per member whose standing
changes, and a warning with the sequence number when a fork is found.

## 11. Rules display

Reported from the live cluster on 2026-10-06: three members flagged
"records with other rules" while "classified again here" said "rules
agree 100%". The fingerprint differed because the nodes ran different
builds; no verdict in the sample did.

- `MemberView::issues` drops the fingerprint comparison. A member is
  flagged for its rules only when the rules gate of §3 fails, with the
  agreement summary as the text.
- The member page keeps both lines ("Carried", "Classified again here")
  as information. "differs" next to the fingerprint is no longer styled
  as a failure.

## 12. Mixed versions and rollout

- Old nodes store and relay the new record kinds without applying them
  (`UNKNOWN_KIND`) and apply them after their upgrade.
- `PROTO_VERSION` goes up. A new node asks only members of the new
  version for lookups; an old node's request has no `offer_seq` and gets
  free providers only.
- Old scanners earn (new nodes judge their scans like any other) but
  cannot spend until upgraded.
- No starting grant. The ledger is a function of the log, so the scans of
  the 7 days before a node's upgrade are judged like any other, and every
  upgraded node arrives at the same balances whenever it upgraded.
- `scan_audit` is a new kind, not a new field of `scan_result`, so no old
  node has to rebuild a signed entry it does not fully understand.

Plan-time check: the smallest window keeps entries by HLC age
(`history::window_hlc`); confirm that with `retention_days = 7` every
entry dated within the current UTC day and the 6 before is held at every
moment, including right after the daily prune.

## 13. Limits

- **Invented requests.** A member can record requests nobody sent. Honest
  scanners then scan those addresses, earn for it, and the inventor earns
  the trap share: at most 0.5 per address and day, 500 addresses a day
  per node. The scanned addresses are bystanders, which is the real harm,
  and it exists today without credits. `scan.trusted_origins` and blocking
  are the answer; a blocked member's shares count for nothing at the node
  that blocked it.
- **Throwaway nodes.** Per-node limits do not bound an operator with many
  node keys. The on-demand share does: it caps what all askers together
  can take from a server.
- **Invented scans** are caught only where audits are counted, and only
  for sources still reachable 30 minutes later.
- **One double spend per node key** (§6).
- **A server can take the price and not answer.** The asker sees it
  (charged, no finding) and loses at most one lookup's price per try; the
  receipt is public.
- **Views differ at the edges** (§8). A node that just joined judges
  scans by the requests inside its window; a scan whose requests are
  older counts for nothing there.
- **Announced pace is a claim.** A member that announces more workers
  than it has makes the cluster look idle and halves the price at most; a
  blocked member's pace is not counted.
- **Announced capacity is a claim.** A member that announces on-demand
  lookups it does not serve lowers everyone's price. The surge corrects
  each honest server within a day or two, the on-demand share caps what
  can be taken meanwhile, and a blocked member's announcement is not
  counted.
- **A fleet node can spend the fleet's credits.** A sibling that was
  broken into can draw what the collecting node holds. The loss is
  credits of at most 7 days; releasing the node (ownership spec) ends it.
- **Lookups of recorded addresses are visible** to members, with a good
  guess at who asked (§7).
- **A cluster without scans has no lookups.** Prices scale with earnings,
  but someone has to earn: with nothing scanned in 7 days, nobody holds a
  credit.

## 14. Testing

Unit:

- Ledger, table-driven: earn then spend; offer larger than the lot;
  receipt lower than the offer returns the rest; receipt after 15 minutes
  ignored; lapse returns everything; second receipt ignored; transfer of
  more than held; lot named on day `d + 7` ignored; halves round down and
  the remainder is destroyed; entries of a blocked or forked origin left
  out; same input in any arrival order gives the same balances.
- Paying scans: second scan of an IP within 24 hours pays nothing, a
  higher tier pays the difference, after 24 hours pays again; the 501st
  scan of a day; `args_ok = false` pays the trap only; level capped by
  evidence; level 0 pays nothing.
- Argument normalizing: each built-in level with every tunable set
  normalizes to its list; a custom `level_argv` does not; an earlier list
  in `ACCEPTED` passes.
- Rules gate: 19 requests never fail; 2% passes, more fails.
- `audit::compare`: every branch, including the host-key shortcut and the
  empty audit.
- Audit gate: 4 differing audits do nothing; 5 with 3 differing fail;
  audits by a non-sibling do not count.
- Seals: digest over a range; consistent, unchecked (a stub in the range,
  a range below the floor) and inconsistent; a wrong `from`.
- `fork_proof`: valid pair accepted; same bytes, different origins,
  different sequence numbers or a bad signature rejected.
- Load factor: 0.5 at utilization 0, 1 at 0.5, 2 at 1; no capacity counts
  as saturated; blocked scanners left out.
- Price formula: the example above; no earnings gives the floor; no
  announced capacity gives no `unit` (what is served, e.g. GeoLite2
  alone, is then priced from the floor); blocked and forked members'
  announcements left out; the weights; the clamp at both ends.
- Scan capacity: limited by workers, limited by scans per hour, fewer
  than 5 jobs falls back to the cluster's mean, none to the default.
- Surge: doubles after a day the share ran out, halves after a day it did
  not, stays within 1 and 8, survives a restart.
- The on-demand share counter per UTC day, for a daily and a weekly
  budget, across a restart.

Integration (`tests/cluster.rs`, `tests/cluster_limits.rs`):

- A scanner completes a scan for another node's trap; after the judging
  delay both hold the shares in every node's ledger.
- A paid lookup between two nodes: offer, answer, receipt; the payer is
  down by the price, the server up by half.
- An asker without credits is declined with the reason; with credits but
  a spent on-demand share, the API provider is declined and GeoLite2
  served.
- A lookup answered by the node's own provider costs half the price net.
- A node with `collect_to` set and no credits looks up: it draws from the
  collecting node and is served; a non-sibling's draw is not answered.
- A paid lookup of a recorded address writes `ip_intel` on the serving
  node and reaches every member; the next lookup within 24 hours is
  answered from the dataset without an offer; "Ask again" pays.
- A paid lookup of an address nobody recorded writes nothing anywhere.
- The lookup result of a recorded address lists the same sections as its
  IP page.
- A server whose price rose above the offer declines and names the price;
  the second offer is served.
- Doubling the cluster's earnings doubles the announced prices within the
  hour.
- A node that writes two different entries at one sequence number and
  then an offer: the member holding the other branch marks it forked,
  publishes the proof, and a third member that saw neither branch's
  conflict marks it from the proof alone.
- Collecting: a scanner with `collect_to` set forwards within one round;
  the receiving node can spend it; the lot day is unchanged.
- An audit of a fabricated result (no open ports reported, audit finds
  some) differs; five of them stop the scanner's shares at the auditor
  and its sibling, and at nobody else.
- An old-version peer relays the new kinds unchanged and is not asked for
  lookups.
- The Members table no longer flags a member whose fingerprint differs
  while its requests agree.
