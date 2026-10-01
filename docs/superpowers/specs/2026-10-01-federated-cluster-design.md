# peephole — federated cluster

Date: 2026-10-01
Status: design agreed in brainstorming; awaiting user review of this document
Builds on: the distributed mode in `src/cluster` (signed replicated log,
pinned-key mTLS RPC, invites, shared scan queue, intel sharing). Where this
document conflicts with the "Distributed mode" section of the README or with
current behaviour, this document wins.

## 1. Goal

A peephole cluster becomes a federation of operators who do not need to know
or trust each other. Every node keeps contributing to and reading one shared
dataset, which is ultimately meant for research and machine learning, while
no operator can damage another operator's node, data or membership.

Each deployer decides for their own node:

1. whether it runs the scanner,
2. whether it runs a trap (detector),
3. whether it has the web interface (wall of shame and admin area),
4. whether it joins a cluster, and if so whether holders of its config key
   may adjust its runtime settings.

Success means:

- A hostile or careless member cannot delete other nodes' records, remove
  other nodes, or reconfigure nodes it holds no key for.
- A peer group can enroll one by one, over weeks, from one invite.
- No GeoLite2 database file leaves the node that downloaded it.
- Adding Shodan or AbuseIPDB later needs a new provider, not new plumbing or
  a schema change.
- A first install is one interactive run that ends with a working config
  and a ready reverse-proxy example.

## 2. Decisions locked during brainstorming

- **No removal.** Nobody can remove another node from the cluster. A node
  can only remove itself. Members not seen by anybody for 30 days are
  pruned.
- **Deletes are scoped.** A delete propagates only for records the deleting
  node originated. Deleting a foreign record hides it locally.
- **Reads and the scan queue stay shared.** Every member sees the whole
  dataset; scanners take jobs from any trap.
- **Config key.** Each node has one key. Holding it grants the right to
  change that node's allow-listed runtime settings. The grant is persistent
  until the owner rotates the key, which cuts off all holders.
- **Reusable invites**, no expiry by default.
- **API keys are strictly local** and never replicated.
- **GeoLite2 files are not shared;** lookup results are. The Tor exit list,
  a public list, is still shared as a file.
- **Role names stay** (`listener`, `scanner`, `web` in `[roles]`). Docs and
  the installer call the listener role "trap" consistently.
- **Installer wizard on first install only.** A re-run updates the binary.
- **Shodan and AbuseIPDB are out of scope**, but the dataset and the
  enrichment mechanism are built so they slot in.

## 3. Membership

### 3.1 Records

- `member_add` (any member vouches for a node): unchanged. It admits or
  re-admits.
- `member_update` (a node describes itself): unchanged.
- `member_revoke` is honoured **only when its origin is the node it names**.
  This is how a node leaves. A `member_revoke` naming another node is ignored
  on apply and logged. Every node enforces this itself, so a modified peer
  cannot bypass it.

`peephole cluster revoke` and the Revoke button are removed. New:
`peephole cluster leave` and a Leave button on the node's own Cluster page.
A node that left keeps its local copy of the dataset and stops syncing. It
can rejoin with an invite.

### 3.2 Stale pruning

Liveness evidence for a member is the newest wall-clock time among:

- the HLC of any log entry signed by that member, and
- the HLC of its latest `member_add`.

A member with no evidence newer than 30 days is **pruned**: every node
computes this locally from its own copy of the log, and no record is written,
so nobody holds the power to prune. Because entries are signed by their
origin, nobody can make another node look stale; evidence relayed by any
member counts, which is what "not seen by anybody" means.

To make an idle node visible, every running node appends a `member_update`
for itself whenever its newest own entry is older than 24 hours.

A pruned member is inactive: not dialled, refused on RPC with a distinct
"pruned" error, shown as pruned in the UI and CLI. Its records stay in the
dataset. It rejoins with an invite (`member_add` renews the evidence).

A node that starts and finds its own newest entry older than 30 days treats
itself as pruned: it does not judge other members by its outdated log, shows
"pruned, rejoin with an invite", and stays in that state until a join
succeeds.

### 3.3 Local block

Any node can block a peer for itself: `peephole cluster block NODE`,
`unblock`, and buttons on the Cluster page. The block list is a local table
and is never replicated. While a peer is blocked, this node:

- refuses its connections and does not dial it,
- still stores and relays its log entries, so other nodes are unaffected,
- hides every record it originated from views, statistics and exports,
- ignores its enrichment results,
- does not claim its scan jobs and refuses its claims,
- still honours its `never_scan` list.

Unblocking reverses all of it.

### 3.4 Invites

Invites become reusable. The token format (`peephole1:…`) is unchanged; reuse
is a property of the issuing node's `invites` table, which gains a label, an
optional expiry, an optional use limit, a use count and a revoked-at time.
Each redemption is recorded (which node, when).

- `peephole cluster invite [--label L] [--ttl HOURS] [--uses N]`: no expiry
  and no use limit unless given.
- `peephole cluster invites` lists them with their uses.
- `peephole cluster invite-revoke ID` invalidates one.
- The Cluster page offers the same.

A token works only against the node that issued it. The existing rate limit
on join attempts stays.

**Consequence the operator must understand:** whoever obtains a valid invite
can join, and cannot be removed afterwards, only blocked node by node. The
invite UI says so, and suggests a use limit or expiry.

## 4. Deletes

### 4.1 Cluster-wide effect

A tombstone erases only entries whose origin equals the tombstone's origin.
This is checked when a tombstone is applied and when a later entry is tested
against earlier tombstones. For the `Ip` target ("everything about this IP up
to now") it means: everything this origin recorded about the IP.

### 4.2 Local hide

When an admin deletes records that other nodes originated, they are marked
hidden locally. Hidden rows stay in the database and in the log, so the node
keeps relaying them, but they are excluded from every view, statistic and
export. The hide list is local and never replicated.

One admin delete can do both: the confirmation reports how many records were
deleted cluster-wide and how many were hidden locally.

### 4.3 Retention

`scan.retention_days` keeps working through tombstones, so under 4.1 it
erases the node's **own** old records, cluster-wide. Foreign records live as
long as their originating node keeps them.

Two consequences, accepted for now:

- A node's disk use is bounded by every member's retention, not only its
  own. The remedy against a flooding peer is the local block.
- A short retention removes that node's contributions from everybody's copy
  of the research dataset.

Dropping foreign history locally would need log compaction (a node could no
longer serve the entries it dropped). That is a separate future project.

## 5. Config key and remote settings

### 5.1 Opt-in

`cluster.remote_config = true|false` in the TOML, default `false`. The value
is published in the node's member info, so other nodes show it as open or
locked. With `false`, every remote change is refused.

### 5.2 The key

- 32 random bytes, generated on first start with `remote_config = true`,
  stored in the node's local database, never replicated.
- Shown as one string, `peephole-cfg1:<base64url>`, which also carries the
  node's identity so the holder's node knows which member it belongs to.
- `peephole cluster config-key show` and `… rotate`; the same on the node's
  own Cluster page. Rotation replaces the key and invalidates every holder
  at once.

### 5.3 Using it

A holder pastes the key into their own node's Cluster page (or
`peephole cluster config-key add KEY`). It is stored in a local table on the
holder's node.

Directed messages are relayed hop by hop through other members, so the key
never travels. Two new message types replace `SetPace`:

- `ConfigGet` → current settings, their version, and the recommended pace.
  Open to any member; nothing in it is secret.
- `ConfigSet { base_version, changes, mac }` → new version, or an error.
  `mac` is HMAC-SHA256 under the key over a domain tag, the message id,
  sender, recipient, creation time, `base_version` and the changes.

The target accepts a `ConfigSet` only if `remote_config` is on, the MAC
verifies, `base_version` equals its current settings version and every value
passes the same validation as the local admin UI. The version check also
defeats replays and resolves concurrent editors: the later one is refused
and reloads. A `ConfigSet` with no changes is how the holder's node verifies
a freshly pasted key.

Every accepted change is written to a local audit list on the target (when,
which node, what changed), shown on its Cluster page.

**Behaviour change:** remote pace changes work today without any permission.
They will require the key.

### 5.4 The settings

| Setting | Remote change |
|---|---|
| Scan pace: workers, scans per hour, timeout | yes, within the existing limits |
| Rescan cooldown | yes |
| Extra `never_scan` entries | add and remove extras; TOML entries cannot be removed |
| Roles `listener`, `scanner`, `web` | yes, see 5.5 |

Not remotely changeable: listen and advertise addresses, paths, `[webauthn]`,
API keys, `scan.level_argv` (control over nmap arguments on a root scanner is
remote code execution), `trusted_proxies`, `remote_config` itself, and
**`retention_days`**. Retention was on the list agreed in brainstorming; it
is excluded here because under section 4.3 lowering it irreversibly erases
the node's contributions for everyone. The owner changes it locally.

Remote and local-UI changes are overrides in the existing `settings` table on
top of the TOML defaults, as scan pace is today. `peephole settings show`
lists effective values and their source; `peephole settings reset [KEY]`
drops overrides.

### 5.5 Role toggles

Roles become switchable at runtime, locally and remotely. `run` in
`src/lib.rs` starts each role's tasks under its own stop signal, and a role
supervisor starts or stops them when the effective roles change:

- `listener`: bind or release the trap listener.
- `scanner`: start or stop claiming jobs. Running nmap processes finish.
- `web`: bind or release the admin listener.

Rules:

- A role can be switched on only if its local prerequisites exist:
  `trap_listen` and `rules_dir`; a working nmap; `admin_listen` and
  `[webauthn]`. The reply names the missing prerequisite otherwise.
- At least one role stays on.
- Switching off `web` remotely is allowed. The owner restores it with
  `peephole settings reset`.
- After a change the node republishes its `member_update`.

## 6. Enrichment

### 6.1 Results only

GeoLite2 files leave file sharing: the kinds `geolite2-city` and
`geolite2-asn` are no longer announced, served or copied, and old manifests
for them are ignored. Every node with `[maxmind]` credentials downloads for
itself, daily, as a standalone node does. On upgrade, a node without
credentials deletes GeoLite2 files it copied from peers earlier.

The Tor exit list stays as it is: one elected node fetches, the others copy.

### 6.2 Providers

An enrichment provider is something a node may or may not be able to query:
it needs a local database or API key. Heartbeats replace `has_maxmind` with
a list of provider names the node can serve.

Results replicate as a new record kind, `ip_intel`:

| Field | Meaning |
|---|---|
| `ip` | the address |
| `provider` | e.g. `maxmind-geolite2`, `tor-exits`; later `shodan`, `abuseipdb` |
| `fetched_at` | when the lookup was made |
| `source_version` | provider data version if known (database build date) |
| `data` | provider-specific fields as a map |

They are stored in a new `ip_intel` table keyed by (ip, provider, origin),
keeping provenance for the research dataset and letting a local block drop
one node's results without losing the others'. The existing `ips` columns
(country, ASN, organisation, Tor flag) remain as the current view, taken from
the newest result of a non-blocked origin. Exports gain the `ip_intel` rows.
Existing `ip_enrich` records keep applying and are read as results of the
node that wrote them.

### 6.3 Who looks up

- A trap that can serve a provider itself enriches at record time, as today.
- Otherwise the IP stays without that provider's result, and the live nodes
  that can serve the provider rank themselves by node key. Rank 0 fills
  missing results on its next pass; rank *r* steps in only for IPs still
  missing after *r* × 10 minutes. This generalises the current
  `backfill_missing_geo`.
- If no member can serve a provider, the dataset simply has no data from it.

This loop is written once, against a small provider interface (name, "can I
serve", "look up these IPs"). MaxMind is its first implementation. An API
provider later adds its own quota handling inside "look up these IPs" and
nothing else.

## 7. Installer

### 7.1 Wizard (first install only)

Asked in this order; every answer can be preset by an environment variable,
which skips its prompt, and unattended installs behave as today.

1. Run a trap? Run the scanner? Have the web interface? (`PEEPHOLE_ROLES`)
2. With the trap: is a reverse proxy on this machine in front of it?
   (`PEEPHOLE_LOCAL_PROXY`) Yes: `trap_listen = 127.0.0.1:8080` and loopback
   as the trusted proxy. No: listen on all interfaces and ask for the
   trusted proxy CIDRs, as today.
3. With the web interface: the public domain.
4. Join or start a cluster? Then node name, RPC listen address, advertise
   address (empty for outbound-only), and an invite token (empty to start a
   new cluster or join later).
5. In a cluster: may holders of this node's config key change its settings?
   (`PEEPHOLE_REMOTE_CONFIG`)
6. Optional MaxMind credentials, with the note that without them geo data
   comes from other members' lookups, if any member has a key.

The closing summary prints the node key, the config key when remote config
is on, and the next steps for the chosen roles.

### 7.2 Reverse-proxy guidance

The installer writes `/etc/peephole/nginx.example.conf` with the operator's
values filled in and prints the steps to enable it (copy, certificate,
reload). It does not install or modify nginx. The file has:

- the TLS server block for the admin domain, as today, plus the HTTP
  redirect,
- a catch-all trap block: `default_server` on port 80 proxying everything to
  the trap listener, passing the client address in `X-Forwarded-For` from
  `$remote_addr` so a client-supplied header cannot spoof it,
- a commented catch-all for port 443 with a self-signed certificate, for
  operators who also want to trap HTTPS probes.

Blocks for roles that are off are left out. The HAProxy fallback setup in
the README remains as the alternative.

## 8. Compatibility

- The cluster protocol version is raised and the minimum with it: scoped
  deletes and self-only revocation must be enforced by every node, so nodes
  on the old protocol are refused at `hello` until upgraded.
- Membership already materialised stays as it is. A node that replays the
  log from scratch ignores old third-party revocations.
- `invites` rows from before stay valid as single-use invites.
- Configs without `cluster.remote_config` load with it off; `check-config`
  notes the new key.

## 9. Known consequences

- The trust model is open by design. A member can flood the dataset with
  junk; the remedies are per-node blocks, not removal.
- False-positive claims, including an optional contact e-mail, replicate to
  every member as they do today. In a federation that means to operators the
  claimant never dealt with. Unchanged here; worth a later decision.
- `RequeueFailed` (any admin asks every arbiter to requeue failed jobs) stays
  open to all members, consistent with the shared scan queue.

## 10. Testing

- Unit: revocation by a third party is ignored, self-revocation applies;
  staleness from log evidence, including re-admission and the self-pruned
  start; tombstone scoping per origin for each target type; MAC and version
  checks of `ConfigSet`; settings validation and TOML-floor rules; provider
  ranking and the delayed step-in.
- Cluster integration (`tests/cluster.rs`, `tests/cluster_e2e.rs`): three
  nodes; a foreign delete hides locally and leaves the other nodes intact;
  an own delete propagates; block and unblock; one invite redeemed by two
  nodes, then revoked; config change with a valid key, a rotated key, a
  locked node and a stale version; role toggle taking effect without a
  restart; a node without MaxMind getting geo results from a key holder and
  never receiving the file.
- Installer (`tests/install-smoke.sh`): preset-variable runs for a trap-only
  node behind a local proxy and for a cluster node with remote config on;
  the generated nginx example contains exactly the blocks for the chosen
  roles.

## 11. Implementation order

Four plans, each shippable on its own:

1. Membership and deletes (sections 3 and 4), with the protocol bump.
2. Config key, runtime settings and role toggles (section 5).
3. Enrichment (section 6).
4. Installer (section 7), last because it surfaces the options from 1–3.
