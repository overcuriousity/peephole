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
- `cluster.retention_days` is removed (code, docs, tests).
- `scan.retention_days` is no longer read. A config that still sets it
  loads, and `check-config` and the startup summary say: "scan.retention_days
  is no longer used; this node keeps everything unless retention_days is
  set" (so upgraded installs that carry the installer's old `= 90` keep
  everything from now on, as decided).
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
  `#[serde(default)] floors: Vec<(NodeId, u64)>` (only origins with a
  floor above 1) and `#[serde(default)] retention_days: u32`. Old nodes
  ignore both (signed bytes are relayed unchanged; precedent: `own_seq`).
- A node never asks a peer for `(origin, after)` when the peer's floor is
  above `after + 1`; those wants are skipped for that peer only.
- `/wait` answers early only for origins it can actually serve the caller
  (its floor ≤ caller's head + 1, origin not purged). The same rule is
  applied to purged and refused origins, which today can make two peers
  re-sync without pause (an existing busy loop found while mapping the
  code; fixed here).
- An empty pull for an origin the peer advertised but cannot serve is
  treated as `stuck` (backoff), as a safety net for peers on older
  versions that do not send floors.

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
