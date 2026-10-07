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

Enable it with a `[cluster]` section (see
[`deploy/config.example.toml`](../deploy/config.example.toml)), then add
nodes:

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
peephole owner adopt                      # on each other node of yours: reads the key from standard input
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
outbound-only: it dials its peers and still syncs both ways. Peers can also
be listed under `[[cluster.peers]]` with their key.

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

- **Create it once** (`peephole owner new`, or Cluster › Ownership) and
  **enter it on each of your other nodes** (`peephole owner adopt`, or the
  same page there). The key is shown once; `adopt` reads it from standard
  input so it does not end up in the shell history.
- A node stores the owner's public half and a certificate for itself. The
  key itself stays only where you choose to keep it (`--keep`, or the
  checkbox): those are your **managing nodes**. A scanner that gets broken
  into cannot take over your other nodes if it does not keep the key.
- Your nodes find each other on their own and are marked "yours" on the
  cluster pages. Nothing about ownership is replicated: other operators'
  nodes cannot verify who owns what, though a member that relays the
  messages can see which nodes answered each other.
- From a managing node you can change a sibling's scan pace, rescan
  cooldown and roles, block, unblock and purge peers there, revoke its
  invites, have it leave the cluster, and release it. Each of your nodes
  lists the commands it received (Cluster › Ownership).
- **Not possible from outside**, also for the owner: creating an invite
  (the invite is a secret and would pass through other members), and
  everything in the config file (addresses, paths, WebAuthn, API keys,
  `never_scan`, nmap arguments).
- **A leaked key**: rotate it on a managing node (Cluster › Ownership).
  Every node of yours that answers takes the new key; for the rest the page
  offers to retry. On a node you cannot reach that way, run
  `peephole owner adopt` locally. The new key is stored before the first
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
- **Probes.** An observational probe of the ports a scan found open
  (headers, certificates, JARM, SSH host keys) costs 4 units times the
  surge, announced per scanner and paid per vantage; half of each payment
  is destroyed. The answer comes in two phases: the offer is accepted
  first, the result arrives when the scanner has finished. An accepted
  probe with no result lapses after 15 minutes. Nothing is minted.
- **Your budgets are safe.** Paid lookups take at most
  `[enrichment] on_demand_share` (a fifth by default) of each API budget,
  whatever happens to credits. A provider whose share ran out costs double
  the next day.
- **Known addresses.** A lookup shows everything the dataset holds on the
  address. A provider answer under 24 hours old is shown instead of asking
  again, free. An answer that was paid for is kept in the dataset when the
  cluster has recorded the address (members can then infer who looked it
  up); for an address nobody recorded nothing is written anywhere. The
  cheap tier (the dataset, fresh answers, free providers) runs by itself;
  paid providers are offered with their prices.
- **Domains.** A lookup of a domain asks 5 resolvers (nodes of the
  cluster) and lists each address with its votes; an address stands when
  most of the resolvers that answered returned it. Disputed names are
  shown with their votes. Agreed names are replicated as `ip_name`
  records and appear in the dataset's `names` column.
- **Your nodes as one.** `Cluster › Ownership › Collect credits here`
  makes one node of yours the collecting node: the others forward what
  they earn and draw from it when a lookup needs more than they hold.
  Each node can also be pointed there itself: `System › Settings › Collect credits at`
  or `peephole settings set credits.collect_to <key>`.
- **Two histories.** A node that gives two members different entries at
  one position of its log is found out with its next payment: its entries
  carry seals over its log. Members that hold the proof show "showed two
  histories"; that node's credits are void there for good.
- **What this cannot do.**
  - It cannot tell a recorded request nobody sent from a real one. Honest
    scanners then scan the address and the inventor earns the trap share
    (at most 0.5 per address and day). `scan.trusted_origins` and blocking
    are the answer.
  - A majority of colluding resolvers can agree on a wrong address; the
    per-address votes are shown so a single odd answer stands out.
  - Invented scan results are caught only by audits, and only for sources
    still reachable 30 minutes after the scan arrived.
  - It cannot stop one double spend per node key: the second branch is
    proven and the node's credits are void everywhere afterwards.
  - Many node keys of one operator are bounded only by each server's
    on-demand share, not per node.
  - A server can take the price and not answer; you lose that lookup's
    price, and the receipt is public. A server that declines and names a
    higher price is offered it once, up to twice its announced price;
    beyond that the next server is asked.
  - Announced pace and lookup capacity are claims. Inflated ones lower
    the price until the surge corrects it; blocked members are not
    counted.
  - A member that spent its credits and then stops earning here (its
    rules agreement drops below 98 %) loses its earnings of the last 8
    days in every node's count, and the servers it paid lose those
    receipts with them, until it earns again.
  - A receipt counts when it arrives late; if the lapsed offer was spent
    again elsewhere, the second server is paid less (at most the first
    server's price).
  - A node that is trap and scanner and whose log lags the clock can date
    a few days of scans at once, one time per node key.
  - A sibling that was broken into can spend what your collecting node
    holds (credits of at most 7 days); release it.
  - Lookups of recorded addresses are visible to members, with a good
    guess at who asked.

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
  stored. An outbound-only member, and one of an earlier version, cannot
  be asked.
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
- Threat-intel APIs (AbuseIPDB, Shodan, Shodan InternetDB, GreyNoise
  Community) work the same way. Every node with a key announces it. One of
  them looks each IP up, newest IPs first, within its own daily or weekly
  budget. The result, with its UTC time, is shared with every member. A node
  whose budget is spent, or whose key is rejected, stops announcing the
  provider, and another node with a key takes over. An IP is looked up again
  only when it comes back, after 30 days, then 45, 67.5, …
  (`[enrichment] refresh_after_days`). Every lookup is kept in a history
  (Admin → Export → full lookup history). The results are admin-only: the
  IP page shows them, and the IP list filters by abuse score, provider tag
  and "looked up / not yet".
