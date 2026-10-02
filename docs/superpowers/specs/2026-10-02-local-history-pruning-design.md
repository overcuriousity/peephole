# peephole — local history pruning

Date: 2026-10-02
Status: decisions taken with the user; written spec awaiting review
Replaces: `cluster.retention_days` (cooperative, cluster-wide deletes of a
node's own records) and `scan.retention_days` (standalone, default 90).

## 1. Goal

The cluster keeps the whole history. A single node may keep less, like a
pruned Bitcoin node: it drops its old records *and* their log entries to
save disk, keeps everything newer, keeps taking part in sync, and cannot
serve what it dropped. Full members serve old history to whoever needs it.
Nothing a node prunes is deleted anywhere else.

Decisions taken:

- **Pruning is local and real.** Old table rows and their replication-log
  entries go; disk use shrinks. No tombstones are written.
- **Default: keep everything, on every node.** Standalone too (today 90
  days). Pruning is opt-in per node.
- **Membership is unchanged.** No removal of other nodes; blocks stay per
  node.

Success means: a pruned node stays in sync for everything inside its
window, never makes peers busy-loop or stall, and a node joining a cluster
gets the full history as long as one full member is reachable.

## 2. Configuration

- New top-level key `retention_days` (u32, default 0 = keep forever): this
  node keeps records and history from the last N days; older ones are
  deleted on this node only. Minimum 7 when set (shorter windows would cut
  into replication lag and the 7-day parking window).
- `cluster.retention_days` and `scan.retention_days` are removed (code,
  `OPTIONAL_KEYS`, docs, tests). No compatibility: existing installs are
  removed and reinstalled, so nothing reads or warns about the old keys.
- The installer writes `retention_days = 0` with a comment; the config
  example, README, docs/operations.md and docs/cluster.md describe it.

## 3. Standalone nodes

Unchanged mechanism, new key: `Recorder::prune_older_than` (requests, scans
with ports, finished orphan jobs, light-row batches; local tombstones as
today, which the standalone tombstone pruning already clears). Runs daily
when `retention_days > 0`.

## 4. Cluster nodes: the history floor

### 4.1 Invariant

Today every node holds, per origin, exactly the entries `1..=head`. A
pruning node holds `floor..=head` instead, with `floor >= 1`. `floor = 1`
means the full history. Every rule that assumed `1..=head` uses
`floor..=head`. New table `repl_floors(origin BLOB PRIMARY KEY, seq INTEGER)`
(absent row = 1).

### 4.2 What is pruned

Daily (and once at start), per origin:

1. `cut` = the lowest seq whose entry's HLC time is within the window
   (`now − retention_days`). Entries below `cut` are the prefix to drop.
2. Never the newest entry of an origin: `cut <= head`. Several parts of
   the code read the latest log row (this node's next own seq, gap and
   duplicate checks, HLC seeding, member standing), so it always stays.
3. Parked entries (`repl_pending`) are not touched (they sit above head).
4. Per prefix entry, in one transaction per batch:
   - row-backed and table kinds: take the materialized row out (the
     existing `unmaterialize` path, *without* putting the payload back into
     the log) and drop orphan IPs as usual;
   - `ip_intel` entries: delete the matching `ip_intel_log` rows of that
     origin up to the cut HLC; `ip_intel` (newest result per IP, provider
     and origin) keeps a row only if its own entry is above the cut;
   - membership, job state, adoption, intel-manifest and tombstone
     entries: only the log entry goes; their effects live in their tables
     (`members`, `scan_jobs`, `tombstoned`, …), which are kept;
   - delete the log rows, any `tomb_proofs` for them, and set
     `repl_floors.seq = cut`.
5. The `tombstoned` table is kept whole (a deleted record that arrives
   again must stay deleted).
6. `origin_usage` is reduced by what the dropped entries were counted
   with. To know it, `repl_log` gains `accounted INTEGER` (bytes counted at
   arrival; old rows: `length(payload)` + 128, or 128 without payload), so a
   pruning node's quota measures what it holds, not all it ever received.

Records that are older than the window but whose entries lie above `cut`
(an entry's HLC is when it was signed; a record's own time is earlier at
most by replication delay) stay until their entry falls out of the window.

### 4.3 Serving and asking

- `Heads` stay as they are. Floors travel in heartbeats: new
  `floors: Vec<(NodeId, u64)>` (only origins with a floor above 1) and
  `retention_days: u32`. Every node runs this version (no mixed-version
  clusters to support).
- A node never asks a peer for `(origin, after)` when the peer's floor is
  above `after + 1`; those wants are skipped for that peer only.
- `/wait` answers early only for origins it can actually serve the caller
  (its floor ≤ caller's head + 1, origin not purged). The same rule is
  applied to purged and refused origins, which today can make two peers
  re-sync without pause (an existing busy loop found while mapping the
  code; fixed here).
- An empty pull for an origin the peer advertised but cannot serve is
  treated as `stuck` (backoff), as a safety net (e.g. a floor not yet
  gossiped).

### 4.4 Receiving

- A full node (retention off) only accepts an origin's entries from seq 1
  upward, as today. If every reachable member is pruned for that origin,
  it waits until a full member is reachable (the admin Cluster page shows
  "history incomplete: waiting for a full member").
- A pruned node that holds nothing of an origin yet may start it at a
  peer's floor: it accepts the first entry it is offered at that seq and
  records it as its own floor. It never needs entries outside its window.
- Erased stubs and their tombstones keep working: a tombstone always has a
  higher seq than the entries it erases, so a stub above the floor has its
  tombstone above it too.

### 4.5 Joining

A node joining with retention off backfills everything from full members
(each peer loop already pulls independently; pruned peers are skipped per
origin by the floor rule). A node joining with retention on fetches only
its window, from any member.

## 5. Admin and CLI

- Cluster page, per member: "full history" or "keeps N days (history from
  <date>)", from the heartbeat. This node's own line shows its floor date.
- `peephole cluster status` prints the same.
- Warning on the Cluster page when this node is full but some origin's
  history start is held by no reachable full member.

## 6. Removed

`src/cluster/retention.rs`, its daily call in `cluster::maintenance_loop`,
`ClusterConfig.retention_days`, the startup note that `scan.retention_days`
is ignored in a cluster, `retention_applies`, and the tests and fixtures of
both old settings (rewritten for `retention_days`).

## 7. Testing

- Unit: cut computation (never the head, HLC window, empty origin);
  floor-aware contiguity (accept at floor for pruned, refuse for full);
  `/wait` and wants honour floors, purged and refused origins (no early
  answer); usage decrement; config: old keys load with the notice,
  `retention_days` 1–6 rejected.
- Cluster (tests/cluster.rs): three nodes, one pruned. Old records vanish
  on the pruned node only; it keeps syncing new ones; a full node joining
  later backfills everything from the full members while the pruned one is
  up; a pruned node joining later fetches only its window; no peer loop
  re-syncs without pause (count reconcile rounds over a few seconds).
- Standalone: `retention_days` prunes as `scan.retention_days` did; 0
  keeps everything.

## 8. Out of scope

- Pruning other nodes' data by any remote action.
- A minimum number of full members per cluster (shown as a warning only).

## 9. Implementation notes (code map, 2026-10-02)

From a read-only survey of the replication code; line numbers as of the
commit this spec was written on.

- **Heads and contiguity.** `Heads = Vec<(NodeId, u64)>` (repl.rs:28-31),
  stored in `repl_heads` (migration 0006), read at repl.rs:66-73. Invariant
  comment at repl.rs:4-16 ("no prefix can be dropped" — to be rewritten for
  floors). Receive path `apply_one` (repl.rs:544-625): purged → reject;
  `held = max(log_head, pending_head)`; `seq <= held` duplicate;
  `seq != held+1` gap → reject (repl.rs:590-593); quota (594-600); stubs need
  a proof (686-704); signature/prefix checks (606-619); parking
  (`park_or_refuse`, 629-678). `bump_head` 408-418, `reset_head` 973-990.
  Test `heads_table_matches_held_entries` (repl.rs:1201-1260) asserts heads
  = MAX(seq) of log ∪ pending.
- **Readers of the newest log row (why the head entry must stay).** Own next
  seq: repl.rs:474-477, 502-505. Member standing / last sign of life:
  members.rs:122-128, 310-313. HLC seed: mod.rs:307. Keepalive
  `own_last_hlc`: mod.rs:450-458.
- **Serving.** `entries_after` (repl.rs:231-331): skips purged (250); reads
  `seq > after ORDER BY seq`; rebuilds row-backed payloads via
  `data::rebuild` (288-300) and stops with a warn when a row is gone
  (294-298 — deleting a row while keeping its log entry causes this);
  enforces contiguity (304); stubs travel with proofs (313-326,
  `held_proof` 335-361, `proves` 366-379).
- **Sync round.** `reconcile` (sync.rs:201-281): hello, heads, gossip
  (heartbeats, 213-216), pull loop (220-255; empty batch ends it, `stuck`
  only when nothing applied or parked, 245-253), push loop (257-278).
  Backoff 139-147. `peer_loop` re-runs reconcile after `/wait`
  (175-187). `/wait` server (rpc/mod.rs:161-179) answers at once when any
  head is above the caller's — the busy loop with purged/refused origins.
  `refused_origins` (repl.rs:195-225): purged, over quota, full parking.
  RPC handlers: pull rpc/mod.rs:64-76, push 78-98.
- **Existing "stop holding" mechanisms.** Purge: block.rs:127-180
  (`purged_origins`, migration 0018; head deliberately not reset);
  unblock: block.rs:184-207. Tombstones: data.rs:820-841, 878-983;
  `tombstoned` must stay forever in a cluster. Parked expiry
  `expire_parked` repl.rs:942-970 (hourly, mod.rs:779-782) — the only place
  heads shrink today. Quota: `origin_usage` (migration 0018), incremented in
  `insert_log` (repl.rs:438-447), checked by `over_quota` (179-189), never
  decremented except by purge (block.rs:159).
- **Old retention, to remove.** `cluster.retention_days`: config.rs:182-186,
  src/cluster/retention.rs, scheduled in `maintenance_loop`
  (mod.rs:768-795), startup note lib.rs:79-88, docs/cluster.md:64-69,
  deploy/config.example.toml:172, test tests/cluster_limits.rs:660-714,
  fixtures tests/cluster.rs:125, 684, 899, 1116; tests/cluster_limits.rs:92;
  repl.rs:1218; scan/arbiter.rs:593; scan/mod.rs:1387.
  `scan.retention_days`: config.rs:284-287, 430-432, 442, OPTIONAL_KEYS 464;
  gate `retention_applies` lib.rs:97-101 (test 692-699); spawn lib.rs:175-182;
  `run_retention` lib.rs:603-639; `Recorder::prune_older_than`
  recorder.rs:1037-1095 (keep, under the new key); docs
  deploy/config.example.toml:102, install.sh:787, docs/operations.md:195,
  docs/cluster.md:65-66; tests src/store/delete.rs:261, 282-338.
- **Heartbeat.** status.rs:37-53; signed over raw CBOR body and relayed
  unchanged (55-75, 209-216). Not stored in the DB. Precedent for added
  fields: `providers`, `own_seq`. Admin lag view admin/cluster.rs:178-201;
  CLI cluster/cli.rs:204-236.
- **Naming.** "Prune"/"pruned" already means a member silent for 30 days
  (`Standing::Pruned`, members.rs:16-70; RPC error "pruned: no sign of
  life", rpc/mod.rs:221-223, sync.rs:153). In code and UI, call the new
  concept "history floor" / "keeps N days", not "pruned node".
- **Joining.** invite.rs:163-209 (join), 263 (inviter adds joiner);
  `sync::supervise` sync.rs:66-110 runs one peer loop per dial target
  (mod.rs:523-542), so backfill already comes from all members in parallel.
