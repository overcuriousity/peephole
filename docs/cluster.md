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

## Changing another node's settings

- A node's scan pace, rescan cooldown and roles are runtime settings. Its
  own admin (System › Settings and Scans for the pace, or
  `peephole settings set|reset|show`) can always
  change them, and roles switch without a restart.
- With `remote_config = true` under `[cluster]`, the node has a **config
  key** (`peephole cluster config-key show`). Whoever holds it can change
  those settings from their own node: paste the key on their Cluster › Access page,
  or `peephole cluster config-key add <key>`.
- `peephole cluster config-key rotate` replaces the key and withdraws the
  permission from everyone at once. The node lists who changed what.
- Nothing else is changeable from outside: addresses, paths, WebAuthn, API
  keys, `never_scan`, nmap arguments and `remote_config` itself stay in the
  config file.

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
- Every member sees everything the cluster records, including raw requests
  and false-positive claims with their optional contact address. Every
  member can export the whole dataset (`peephole export`, or Admin →
  Export); see [docs/dataset.md](dataset.md).
- **On-demand lookups.** Admin → Lookup asks every provider the cluster can
  reach about one address: this node's own databases and keys first, then
  one live member per provider nobody here serves, over the cluster RPC.
  Nothing is stored anywhere. A member serves at most 50 API lookups a day
  per asking node (GeoLite2 and the Tor list are free), so curiosity cannot
  spend the budget the automatic enrichment runs on. An outbound-only
  member cannot be asked.
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
