# Distributed mode

Several deployments can form a cluster that shares one dataset: every
request, the scan queue, scan results and what is known about each IP. The
operators do not need to know or trust each other. Each node runs any
combination of three roles, set in `[roles]`:

| Role | Does | Needs |
|---|---|---|
| `listener` | the trap: records and classifies requests, queues scans | `trap_listen`, `rules_dir` |
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
  the Cluster page) also blocks every node it admitted. Purging a blocked
  peer deletes what this node holds of it and stops relaying it.
- **Each node judges for itself.** Timestamps from the future count as of
  receipt; scan jobs must name a public address and a known level, at most
  2000 per member and hour; a member's jobs move to another arbiter only
  once this node, too, sees the arbiter silent (or the job untouched) for
  `takeover_hours`. Entries of a node nobody admitted are parked only up to
  100 per node and dropped after a week. `cluster.origin_quota_mb`
  (default 20 GiB) caps what one member's entries may take on this node.
- **Deletes reach your own records only.** Deleting something your node
  recorded removes it on every node. Deleting something another node
  recorded hides it on your node only.
- **The dataset is persistent.** What a node contributed stays when it
  leaves or is pruned. By default every node keeps the whole history. The
  Cluster page counts, per member, the requests, fingerprints, scans and
  lookups this node holds from it; the dataset export has the records.
- **A node may keep only a window.** With `retention_days = N` (top level,
  at least 7) a node keeps the last N days, like a pruned Bitcoin node: daily
  it drops older records *and* their log entries on this node only (no
  deletes reach other nodes), keeps the newest entry of every member and all
  membership entries, and serves only what it holds. Its heartbeat tells the
  others where its history starts ("keeps N days" on the Cluster page), so
  nobody asks it for more. A node joining with a window fetches only that
  window, from any member; a node keeping everything fetches the old history
  from members that keep everything, and waits ("History incomplete: waiting
  for a full member") while none is reachable. Switching a window off later
  does not bring the dropped history back.

## Changing another node's settings

- A node's scan pace, rescan cooldown and roles are runtime settings. Its
  own admin (Cluster page, or `peephole settings set|reset|show`) can always
  change them, and roles switch without a restart.
- With `remote_config = true` under `[cluster]`, the node has a **config
  key** (`peephole cluster config-key show`). Whoever holds it can change
  those settings from their own node: paste the key on their Cluster page,
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
  `scan.trusted_origins` limits whose requests count.
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
  written by different nodes. The Cluster page flags clock differences.
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
