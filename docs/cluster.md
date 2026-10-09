# Distributed mode

Several deployments can form a cluster that shares one dataset: every
request, the scan queue, scan results and what is known about each IP. The
operators do not need to know or trust each other. Each node runs any
combination of three roles, set in `[roles]`:

| Role | Does | Needs |
|---|---|---|
| `listener` | the trap: records and classifies requests, queues scans | `trap_listen` |
| `scanner` | runs nmap for jobs from any trap | nmap |
| `web` | wall of shame and admin area | `admin_listen`, `[webauthn]` |

Every node keeps a full copy of the dataset, so any web node shows the
whole cluster. Scanners take jobs from any trap; jobs go to the scanner
with the fewest recent scans.

The installer writes a `[cluster]` section on every node (see
[`deploy/config.example.toml`](../deploy/config.example.toml)): a name, the
listener and the `advertise` address other members dial, whose port must be
reachable from the internet. A node without an invite runs alone until it
joins; a running node picks a join up without a restart.

Outbound-only is the fallback for a node nobody can reach (no public
address, no port forwarding), set by hand: delete `advertise` and set
`listen` to loopback (`127.0.0.1:7443`), then restart peephole. Such a node
dials its peers and still syncs both ways, and receives directed messages
(it fetches them from its peers' outboxes), so from protocol 6 it also
answers paid lookups, DNS resolutions and probes that arrive as such
messages: it and the member whose outbox it polls must run protocol 6. It
cannot issue invites: a joiner could not reach it.

Then add nodes:

```sh
peephole cluster id                       # this node's key
peephole cluster invite --label friends   # on a member: a reusable invite (a week, 10 uses)
peephole cluster invites                  # list them; invite-revoke <id> closes one
peephole cluster join <token>             # on the new node; or Admin → Cluster
peephole cluster members                  # who is in, and their standing
peephole cluster agreement <node>         # its requests our rules classify differently
peephole cluster block <node>             # this node ignores a peer (unblock undoes it)
peephole cluster block --subtree <node>   # ... and every node it admitted, transitively
peephole cluster purge <node>             # delete a blocked peer's data here, stop relaying it
peephole cluster leave                    # this node leaves; it keeps its data
peephole owner new                        # an ownership key for your nodes; this node keeps it
peephole owner claim                      # on each other node of yours: reads the key from standard input (alias: adopt)
peephole owner show                       # this node's owner and the nodes that share it
peephole owner forget-key [--force]       # this node no longer keeps the key; it stays owned
peephole owner release                    # this node has no owner afterwards
peephole credits                          # this node's credits, by day
peephole credits log [--days N]           # earned, spent, sent, received (up to 7 days)
peephole credits members                  # every member's balance and whether it earns here
peephole credits why <scan>               # how this node judged one scan, and what it paid
peephole credits send <node> <amount>     # send credits to a member
```

Nodes talk HTTP/2 over mutual TLS with pinned Ed25519 keys on
`cluster.listen` (default port 7443). A node without `advertise` is
outbound-only: it dials its peers and still syncs both ways. Peers can
also be listed under `[[cluster.peers]]` with their key.

A joining node learns the members first: the inviter's reply carries
every member's signed admission and description, and every sync batch
sends the membership entries ahead of the data. Each is checked against
its signer, who must be trusted already, so an inviter can leave members
out but cannot add anyone; whatever it leaves out arrives from the other
members.

## How trust works

- **Nobody can remove a node.** A node leaves by itself. A member that
  shows no sign of life for 30 days is pruned by every node on its own and
  rejoins with an invite.
- **An invite is reusable** until it expires, reaches its use limit or is
  revoked: by default after a week or 10 uses (`--ttl 0` / `--uses 0`
  lift a limit). Whoever holds a usable invite can join and cannot be
  removed afterwards. A member admits at most 20 new nodes a day; a node
  that left admits nobody.
- **Blocking is local.** A node that blocks a peer stops talking to it and
  shows none of its records. It still stores and relays them, so other
  nodes are unaffected. `--subtree` (or "Block with all it admitted" on
  the member's page under Cluster) also blocks every node it admitted. Purging a blocked
  peer deletes what this node holds of it and stops relaying it.
- **Each node judges for itself.** Timestamps from the future count as of
  receipt; scan jobs must name a public address and a known level, at most
  2000 per member and hour; a member's jobs move to another arbiter only
  once this node, too, sees the arbiter silent (or the job untouched) for
  `takeover_hours`. Entries of a node nobody admitted are parked only up to
  100 per node and dropped after a week. `cluster.origin_quota_mb`
  (default 20 GiB) caps what one member's entries may take on this node.
- **No deletes from the admin.** On a cluster node the admin pages offer
  no delete: the records belong to the cluster. Retention (`retention_days`)
  still prunes, and `peephole cluster purge` removes a blocked peer's data.
- **The dataset is persistent.** What a node contributed stays when it
  leaves or is pruned. By default every node keeps the whole history. Each
  member's page (Cluster › the member) counts the requests, fingerprints, scans and
  lookups this node holds from it; the dataset export has the records.
- **A node may keep only a window.** With `retention_days = N` (top level,
  at least 7) a node keeps the last N days, like a pruned Bitcoin node: daily
  it drops older records *and* their log entries on this node only (no
  deletes reach other nodes), keeps the newest entry of every member and all
  membership entries, and serves only what it holds. Its heartbeat tells the
  others where its history starts ("keeps N days" on its page under Cluster), so
  nobody asks it for more. A node joining with a window fetches only that
  window, from any member; a node keeping everything fetches the old history
  from members that keep everything, and waits ("History incomplete: waiting
  for a full member") while none is reachable. Switching a window off later
  does not bring the dropped history back.

## Your own nodes: ownership

Operators in a cluster need not know each other. The nodes of one operator
can still belong together: they share an **ownership key**.

- **Create it once** on your first node (`peephole owner new`, or Cluster ›
  Ownership › "Your first node?") and **claim each of your other nodes**
  with it, on that node (`peephole owner claim`, or Cluster › Ownership ›
  "Already have a key?" there). A node cannot be claimed from another one:
  whoever claims it needs its admin site or shell. The key is shown once;
  `claim` reads it from standard input so it does not end up in the shell
  history. The Ownership page of a claimed node lists the members not
  claimed with its key.
- A node stores the owner's public half and a certificate for itself. The
  key itself stays only where you choose to keep it (`--keep`, or "Also
  manage my other nodes from here"): those are your **managing nodes**. A
  scanner that gets broken into cannot take over your other nodes if it
  does not keep the key.
- Your nodes find each other on their own and are marked "yours" on the
  cluster pages. Nothing about ownership is replicated: other operators'
  nodes cannot verify who owns what, though a member that relays the
  messages can see which nodes answered each other.
- From a managing node you can change a sibling's scan workers and
  roles, block, unblock and purge peers there, revoke its
  invites, have it leave the cluster, and release it. Each of your nodes
  lists the commands it received (Cluster › Ownership).
- **Not possible from outside**, also for the owner: creating an invite
  (the invite is a secret and would pass through other members), and
  everything in the config file (addresses, paths, WebAuthn, API keys,
  `never_scan`, nmap arguments).
- **A leaked key**: rotate it on a managing node (Cluster › Ownership).
  Every node of yours that answers takes the new key; for the rest the page
  offers to retry. On a node you cannot reach that way, run
  `peephole owner claim` locally. The new key is stored before the first
  node is told, so a rotation that was cut short is finished from the same
  page with the same key. A rotation also removes the kept key from your
  other managing nodes: enter the new one there again if they should keep
  managing. Until a rotation is finished, forgetting the key on that node
  is refused (on the CLI: unless `--force`): the keys it keeps are the
  only way to the nodes it has moved or not moved yet. A release, adoption
  or forgotten key on the node itself while the rotation waits for the
  others is not undone by it; the rotation then stops with an error.
- **Putting a node out**: `Release` asks the node to drop its owner. A node
  that does not cooperate (it was broken into, or its certificate was
  copied) is put out by rotating the key and leaving it out in the rotate
  dialog: it stays on the old key and is counted by nobody afterwards.
- A member that relays your commands cannot change, redirect or replay
  them, but it sees them: the settings you send, a node's block list and
  invite labels in its status, and the new owner's public half during a
  rotation.
- A key that is forgotten, replaced or released is blanked in the node's
  database. Copies of the database made while the node kept the key (the
  installer's backups, your own) still contain it: delete them, or rotate.
- Whoever can log in to a node, or run the CLI on it, can always release it
  or give it another owner. Ownership adds a remote door; it does not lock
  the local one. Protecting the key and the nodes is the operator's job.
- A node's own admin (System › Settings and Scans, or
  `peephole settings set|reset|show`) can always change its runtime
  settings, and roles switch without a restart.

Config keys (`cluster.remote_config`, `peephole cluster config-key`) are
gone. `remote_config` in a config file is ignored.

## Credits: a market for the cluster's work

Services between nodes (lookups, probes, domain resolutions, scan jobs) are
paid with **credits**. Every price is set by supply and demand; scanners
earn most of the new money, every member a little.

- **Where credits come from.** Two doors only. The daily mint: 1000
  credits split among scanners by their counted scans of the UTC day;
  levels 3 and 4 count twice, levels 1 and 2 once. A scan counts when a
  request held on the judging node backs it, once per address in 24 hours,
  500 a day per scanner, with the built-in arguments, and never when the
  scanner is the trap that queued the job. The allowance: 5 credits a day
  for every member that earns here and recorded a request that day.
  Both are credited when the UTC day ends.
- **Where they go.** A credit is gone 7 days after its day. Nothing else
  destroys credits: a payment moves the full price.
- **Prices.** One rule per good, computed every 10 minutes on each node: excess
  demand raises a price by at most a factor of e^0.45 an hour, excess
  supply lowers it by at most a factor of e^-0.15 an hour (each step is
  scaled by the time since the last one, so a 10-minute refresh takes a
  sixth of an hourly step), a price moves at least 0.001 credits toward the
  imbalance, and it never goes under 0.001 credits. What a node answers
  itself is free (its own providers, prober, resolver, scanner), though
  its own scan jobs use up its scan budget like jobs it buys. Scan
  prices are per scanner: each scanner's price follows its paid scans of
  the past hour (each job once, by the scanner that ran it, at most its
  capacity) against 90 % of its capacity, by a step scaled to the time
  since its last one. Every node computes every
  scanner's price from the log and the heartbeats, and pays at most 1.25
  times its own figure. What
  another node answers is paid, whoever owns it, the Tor exit list,
  RDAP, InternetDB and GeoLite2 included; there is no free quota. A
  provider with an API budget offers its on-demand share (`[enrichment]
  on_demand_share`); one without, and name resolution, offer
  `[enrichment] offer_per_day` (default 1000) a day. Askers go to the cheapest server first. The Lookup page runs this
  node's own providers by itself and asks other nodes only for the
  providers picked; an automatic lookup never buys from another node.
- **Domains.** A lookup of a domain asks 5 resolvers (nodes of the
  cluster) and lists each address with its votes; an address stands when
  most of the resolvers that answered returned it. Each other resolver is
  paid its announced price when it answers; a failed resolution costs
  nothing; this node's own resolver is free. Agreed names are replicated
  as `ip_name` records and appear in the dataset's `names` column.
- **Probes.** An observational probe of the ports a scan found open is
  priced on each scanner like a provider, with its probe slots as supply,
  and paid per vantage. The offer is accepted first, the result arrives
  when the scanner has finished; an accepted probe with no result lapses
  after 15 minutes.
  The Actions card sells counter-scans the same way: the arbiter funds a
  bought (manual) job at the scanner's price times 4^(level−1), and the
  scanners skip their evidence re-check for it — the safety preflight
  (protected addresses, Tor exits, verified crawlers) still applies.
- **Scan jobs.** The arbiter (the node that queued the job) funds its jobs
  from its own balance, up to `[credits] scan_share` (default 0.5) of it,
  and hands each job to the scanner asking that is cheapest **per
  delivered result** at the job's level: its price divided by its success
  rate there, relative to the best live scanner with at least 5 scans at
  that level (the level weight, at least 0.1). A failed scan is not paid,
  so a scanner that fails a level often wins it only if its price makes
  up for it. The success rates are measured once an hour: the snapshot of
  hour H counts the scans finished in the 24 hours before H and is taken
  at H + 5 min, so arbiters with the same log agree. A job is paid to the
  best claimant the scan budget can pay (one that takes no less than more
  than its price here is passed over). A paid job waits for a cheaper live
  scanner (not hoarding, not paused, under its capacity, with a record at
  that level, and able to take the job: it did not hand it back, and its
  last claim here neither excluded the level nor asked more than its
  price) for up to 30 minutes, then goes to whoever asks. A job no
  claimant can be paid for is idle work: there,
  a scanner that fails a level more than the others still sits it out
  for 10-minute stretches, a share of 1 − weight of them. A round reads
  the queue 200 jobs at a time, up to 5000, past those every claimant
  handed back; an error ends the round but keeps its grants. Why a
  job went where is kept by its arbiter in `job_handouts` (local, 8 days)
  and shown on the scan page and as a title in the Scans history; other
  nodes say which node handed it out. A scanner asks
  arbiters that can pay its price first, in urgency order. A node's own
  jobs are funded from the same budget without moving credits. Scanners
  that hoard (over their hourly capacity, or delivering less than half of
  5 recent grants) go last. The scanner charges the offered price when it
  delivers the result, and nothing when it does not. A scan offer lapses
  after the longest scan (12 hours plus 2 minutes). Jobs that are not
  funded are scanned by idle capacity and earn the mint only.
- **Every node counts for itself**, from its own copy of the log. There is
  no vote and no shared chain; `Cluster › Credits` shows the market as
  this node sees it: each good's price over 7 days beside the spread
  members announce, its demand and supply, this node's daily income by
  source and spending, every member's holdings, and why a scan was not
  counted. Prices are kept hourly in `price_history` (local, 8 days; the
  last refresh of an hour stands for it). The scanner table shows, per
  level, what one delivered result costs with each scanner, the cheapest
  in bold.
  The balance itself is on the Overview and the Lookup page.
- **Conformity and audits.** A member earns on your node only while at
  least 98 % of its newest 500 requests classify the same with your
  rules, and its scans stand up to the audits you believe: those of your
  own nodes. A scanner runs 5 % of the other nodes' fresh scans again
  (`[credits] audit_share`); audits earn nothing.
- **Your budgets are safe.** Paid lookups take at most
  `[enrichment] on_demand_share` (a fifth by default) of each API budget,
  whatever happens to credits.
- **Known addresses.** A lookup shows everything the dataset holds on the
  address. A provider answer under 24 hours old is shown instead of asking
  again, free. An answer that was paid for is kept in the dataset when the
  cluster has recorded the address (members can then infer who looked it
  up); for an address nobody recorded nothing is written anywhere.
- **Your nodes as one.** Every node keeps what it earns. A paid lookup,
  probe or name resolution that needs more than a node holds draws from
  its siblings, richest first. Scans are funded from the node's own
  balance only.
- **Two histories.** A node that gives two members different entries at
  one position of its log is found out with its next payment: its entries
  carry seals over its log. Members that hold the proof show "showed two
  histories"; that node's credits are void there for good.
- **What this cannot do.**
  - It cannot tell a recorded request nobody sent from a real one. Such
    requests mint nothing, but they create jobs that idle scanners scan
    for the mint. `scan.trusted_origins` and blocking are the answer.
  - Two keys of one operator (a trap and a scanner) pass the own-job rule
    and take a larger share of the fixed mint from honest scanners, up to
    500 scans a day. Blocking is the answer.
  - Many node keys each draw the allowance. Joining needs an invite, a
    member admits at most 20 nodes a day, and each key must first pass the
    rules agreement.
  - A free rider (`scan_share = 0`) gets its attackers scanned only by
    idle capacity; with many of them the scan price understates demand.
  - A scanner can announce a lower pace to look busier and raise its
    price; it then runs fewer scans than it could, and scans beyond its
    announced pace show in the log.
  - A node that joins a cluster whose only scanner announces an inflated
    price starts its reference price there; from then on it moves only by
    the rule.
  - A scanner that fills itself with its own jobs, or with paid jobs of a
    second key of its operator, looks busy and its price rises: the same
    as selling less of its capacity. Cheapest-scanner choice, `scan_share`
    and the bounded rise protect others; with one scanner it is a
    monopoly.
  - A sensor with a small allowance can be priced out of goods that cost
    more than 7 days of it.
  - Credits have no outside value: an API node is paid in services of the
    cluster.
  - The constants come from an abstract simulation, not from a real
    cluster; the Credits page shows what is needed to adjust them.
  - A majority of colluding resolvers can agree on a wrong address; the
    per-address votes are shown so a single odd answer stands out.
  - Invented scan results are caught only by audits, and only for sources
    still reachable 30 minutes after the scan arrived.
  - It cannot stop one double spend per node key: the second branch is
    proven and the node's credits are void everywhere afterwards.
  - A server can take the price and not answer; you lose that lookup's
    price, and the receipt is public. A server that declines and names a
    higher price is offered it once, up to twice its announced price;
    beyond that the next server is asked.
  - A member that spent its credits and then stops earning here (its
    rules agreement drops below 98 %) loses its earnings of the last 8
    days in every node's count, and the servers it paid lose those
    receipts with them, until it earns again.
  - A receipt counts when it arrives late; if the lapsed offer was spent
    again elsewhere, the second server is paid less (at most the first
    server's price).
  - A sibling that was broken into can draw from the others (credits of
    at most 7 days); release it.
  - Lookups of recorded addresses are visible to members, with a good
    guess at who asked.
- **Upgrading.** Protocol 4: payments run only between upgraded nodes, so
  upgrade all nodes together. Protocol 5: scan jobs are paid only between
  nodes on protocol 5; upgrade all nodes together. The cluster-wide scan
  price of protocol 4 seeds the scanners known at the first refresh after
  the upgrade; scanners that join later start at the median price
  scanners announce. Balances are recounted at start under the
  new rules. Protocol 6: outbound-only members are asked paid lookups,
  resolutions and probes through their outbox only when they and the
  member whose outbox they poll run protocol 6; older outbound-only
  members are not asked until they upgrade.

## Things to know

- Counter-scans come from the scanner node's address, not the trap's. Abuse
  reports go to that node's hosting provider.
- `scan.never_scan` protects what you do not want your own scanner to
  touch. It applies only on the node that sets it; other scanners may still
  scan those addresses. Scanners never scan the addresses of cluster
  members (published ones, and the ones members connect from).
- A scanner checks each job an arbiter grants against its own copy of the
  job and runs it only when requests it holds back the level;
  `scan.trusted_origins` limits whose requests count. It does not take a
  request's stored scan level on trust: it classifies the request again
  with the rules built into its own binary and counts the lower of the two
  levels, and the labels its own rules give. A node with doctored rules
  cannot make other scanners scan harder than their rules allow. The IP's
  history in the hour before (which turns many requests into a path
  scanner) is rebuilt from every row the scanner holds that the recording
  trap can have counted (see below), so the level can come out lower when
  rows are missing here, never above the stored level.
- Each member's page under Cluster shows how its newest
  500 requests compare with this node's rules ("rules agree 100%",
  "disagree on 12% of 500"): the share whose labels or severity come out
  differently when classified again here. Only the IP's history (requests
  in the hour, which make a path scanner) cannot be read back exactly:
  the trap counted the rows its database held at that moment, with no
  upper bound in time. So it is bracketed, and a request agrees when
  either bound reproduces it:
  - *seen*, an upper bound: every node's rows of the IP dated from an
    hour (plus a minute) before the request up to 5 minutes after it (the
    clock drift cap: another node's row can be dated ahead of the
    member's clock, and the trap counted it);
  - *own*, a lower bound: only the member's own rows it recorded before
    this one (by its clock, not by arrival here), dated at least a minute
    earlier, within the hour. Requests of one IP are classified
    concurrently, so a row dated in the same moment may not have been
    written yet when the trap counted.

  Requests of other nodes the member had not seen yet, or saw although
  they were dated later, do not count as disagreement. Made at most every
  10 minutes, with the rules built into this binary. Differences come from
  members running another build (older or newer rules) as much as from
  doctored ones. `peephole cluster agreement NODE [--sample N]` makes the
  same comparison on the command line and lists each request that differs
  (id, time, method, path; the stored labels and severity, ours under
  both bounds, and the two history counts); the badge's tooltip names it.
- **Rules fingerprints.** The signature rules are built into the binary, so
  nodes of one build classify alike. Every request carries the fingerprint
  of the rules that classified it (`rules`, a SHA-256 over the rules files)
  and the build that recorded it (`build`). System › Status shows our own
  fingerprint and each member's page the one its newest requests carry ("same as
  ours" or "differs", with a count when they carry more than one, as after
  an upgrade); a request's page shows its fingerprint. What is checked and
  what is only declared:
  - The build and the rules fingerprint on a row are the recording node's
    word. A modified binary can claim any build and any fingerprint, and
    classify with whatever rules it likes.
  - The actual check is classifying again: scanners do it for every grant,
    and the Rules column for each member's recent requests.
  - Neither can tell a fabricated request from a real one: a node can
    record requests nobody sent. `scan.trusted_origins` and blocking are
    the answer to a member you do not trust.
  - Older nodes keep the signed form of requests with a fingerprint (their
    rows have no column for it), so a mixed cluster keeps syncing.
- When two nodes queue the same IP before either job has reached the
  other, only one of them is scanned: the higher level, else the one
  queued first. Arbiters and scanners both apply this, and the other job
  ends as "superseded".
- A failed scan is retried on its own. The job stays "failed" (the
  scanner weights and the failure counts read it); its arbiter queues a new
  job for the same IP and level, marked "retry" on the Scans page. Nobody
  gets a retry for 10 minutes, doubling per failure up to 2 hours, and the
  scanner that failed last waits 30 minutes longer, so another scanner
  gets the first try. Retries stop 24 hours after the first failure, once
  a scan of the IP at that level or higher succeeds anywhere in the
  cluster, and never start for an invalid target. A standalone node
  retries the same way.
- Every member sees everything the cluster records, including raw requests
  and false-positive claims with their optional contact address. Every
  member can export the whole dataset (`peephole export`, or Admin →
  Export); see [docs/dataset.md](dataset.md).
- **On-demand lookups.** Admin → Lookup shows first what the dataset
  holds on the address (the same sections as its IP page; for an unknown
  address, what is near it by network and ASN) and any provider answer
  under 24 hours old, for free. The other providers are asked at the
  member that offers each one cheapest, this node included, and paid in
  credits (see Credits above). A member serves paid lookups only from
  its on-demand share of each provider's budget (`[enrichment]
  on_demand_share`), so curiosity cannot spend what the automatic
  enrichment runs on. Paid answers for an address the cluster has
  recorded are kept in the dataset; for any other address nothing is
  stored. A member of an earlier version cannot be asked; from protocol
  6 an outbound-only member is asked through the outbox it long-polls.
- **The blocklist feed** of a web node (`/api/blocklist`) is drawn from
  the whole cluster's requests and never lists a member's addresses
  (published ones, and the ones members connect from).
- Run NTP on every node: cooldowns and the 30-day prune compare timestamps
  written by different nodes. The Members table's Issues column flags clock differences.
  Entries dated more than 5 minutes ahead of a node's clock wait there
  until it catches up, and a node's entries must be dated later than its
  previous one; older ones are kept in the log but take no effect.
- **In the journal** (`journalctl -u peephole`), each peer that exchanged
  anything gets one `cluster traffic in the last minute` line: sync rounds
  (and how many failed), entries received and applied, entries sent, each
  by kind (`12 (request 10, scan_job 2)`). Peers becoming reachable or
  unreachable are logged as they happen. `RUST_LOG=peephole=debug` (in a
  drop-in, `systemctl edit peephole`) adds a line per sync round.
- **Known limitation:** the admission limit (20 new members a day per
  sponsor) is judged by the sponsor's own timestamps. A member key that
  dates all of its entries in the past from its very first one can spread
  admissions over past days and so admit more. Only members can do this;
  block a member you do not trust.
- A standalone node that joins brings its history with it.
- Node names and keys appear only in the admin area, never on public pages.
- GeoIP: a node with MaxMind credentials downloads the GeoLite2 databases
  for itself. The databases are never passed on. That node looks up the IPs
  the other nodes recorded and shares the results, so one member with
  credentials is enough; without any, the dataset has no GeoIP data. The Tor
  exit list is public and is fetched by one node for all. Every result
  records which provider and which node it came from (Admin → Export).
- Threat-intel APIs (AbuseIPDB, Shodan, Shodan InternetDB)
  work the same way. Every node with a key announces it. One of
  them looks each IP up, newest IPs first, within its own daily or weekly
  budget. The result, with its UTC time, is shared with every member. A node
  whose budget is spent, or whose key is rejected, stops announcing the
  provider, and another node with a key takes over. An IP is looked up again
  only when it comes back, after 30 days, then 45, 67.5, …
  (`[enrichment] refresh_after_days`). Every lookup is kept in a history
  (Admin → Export → full lookup history). The results are admin-only: the
  IP page shows them, and the IP list filters by abuse score, provider tag
  and "looked up / not yet".
