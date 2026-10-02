# Local history pruning + data provenance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A node may keep only the last N days of records and replication history (a "history floor" per origin, like a pruned Bitcoin node) while full members keep and serve everything; every replicated data row records the node and the binary build that created it.

**Architecture:** A new module `src/cluster/history.rs` owns floors (`repl_floors`), the daily prune pass and the "can this peer serve that" rules. `repl.rs` becomes floor-aware on the serving (`entries_after`) and receiving (`apply_one`, `drain_pending`) side; `sync.rs`/`rpc` use the rules for wants, pushes and `/wait`; heartbeats carry floors and `retention_days`. Provenance is a `build` field (the commit baked in by `build.rs`) on every data record, stored in a column next to the existing `origin`, and exported with the full node id.

**Tech Stack:** Rust 2024, tokio, axum, sqlx/SQLite, serde/CBOR, askama.

**Spec:** `docs/superpowers/specs/2026-10-02-local-history-pruning-design.md` (plus the user's addition in the session: provenance per row; and the membership amendment below).

## Global Constraints

- One top-level `retention_days` (u32), default 0 = keep forever, on every node incl. standalone; values 1–6 are rejected at load ("minimum 7").
- `cluster.retention_days` and `scan.retention_days` are removed outright: no compatibility, no notes, no mixed-version clusters.
- Pruning is local: nothing is deleted on other nodes; no tombstones are written by a cluster prune; membership and block lists are unchanged.
- In code and UI the concept is "history floor" / "keeps N days" — never "pruned node" ("pruned" means a member silent for 30 days).
- The newest log entry of each origin is never pruned.
- Tests must not depend on machine speed (CI runners are slower): no tight wall-clock budgets, use `eventually` loops with generous limits; busy-loop assertions use counts far apart (≤ 20 vs. hundreds).
- Local checks before the PR: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `tests/deploy-check.sh`, installer smoke test via podman.
- Provenance: `build` = `crate::COMMIT` of the binary that created the record (12 hex or "unknown"); node id = the record's origin (empty on a standalone node, which has no node key).

## Spec amendment (decided during planning)

Membership entries (`member_add`, `member_update`, `member_revoke`) are **kept** below the floor instead of deleted. Reason: a node joining with retention on fetches only its window; without the admissions below the window it could never trust (and so never apply) the other members' entries. They are few and small. Consequences:
- The floor means "everything from here on is held"; below it a node holds only membership entries.
- When a server answers a want from above `after + 1` (its floor, or the receiver's window), it also sends the membership entries in between ("sparse" entries) and declares the start in `Batch.floors`. Only a windowed receiver (retention on) accepts the jump; a full receiver rejects it as a gap.
- `may_sponsor` cannot judge "was the sponsor silent for 30 days before this admission" across a gap in the sponsor's history; with a gap right before the entry it skips that one check (the rest — revoked, daily limit — stays).

## Review Focus

1. A node switches `retention_days` from N back to 0: it must not try to backfill below its floors (it keeps them, shows its history start) and must not loop. → Task 6 test `full_node_with_old_floor_rejects_jumps`.
2. A full node whose only reachable peers keep a window for some origin: no busy loop, and the admin page says "history incomplete: waiting for a full member". → Task 9/10 tests.
3. A purged origin on one side: `/wait` must not answer at once forever. → Task 7 unit test + Task 10 round-count test.
4. A windowed node offline longer than its window (all peers windowed): it jumps to the peers' floor instead of stalling. → Task 6 test `windowed_node_jumps_to_a_peer_floor`.
5. Pruning a request whose claim (another origin, newer entry) remains: the claim's entry must still be servable (payload kept). → Task 4 test.

---

### Task 1: Configuration — one top-level `retention_days`

**Files:**
- Modify: `src/config.rs` (Config field, validate, remove `ClusterConfig.retention_days`, `ScanConfig.retention_days`, `default_retention_days`, OPTIONAL_KEYS)
- Modify: `src/lib.rs` (check_config notes, remove `retention_applies` + test, spawn `run_retention` on standalone with `cfg.retention_days`)
- Delete: `src/cluster/retention.rs`; Modify `src/cluster/mod.rs` (module, maintenance call), `src/store/recorder.rs` (`delete_own`)
- Modify fixtures: `src/cluster/repl.rs:1218`, `src/scan/arbiter.rs:593`, `src/scan/mod.rs:1387`, `tests/cluster.rs` (4×), `tests/cluster_limits.rs:92` and remove its test at :660-714
- Test: `src/config.rs` tests

**Interfaces:** Produces `Config.retention_days: u32`.

- [ ] Step 1: failing tests in `src/config.rs`: `retention_days` defaults to 0; `retention_days = 3` fails `validate` with "at least 7"; `retention_days = 7` loads; `optional_key_notes` mentions `retention_days` (default 0) when absent.
- [ ] Step 2: run `cargo test --lib config::` → compile failure / FAIL.
- [ ] Step 3: implement:
```rust
/// Keep records and replication history of the last this many days on this
/// node only (0: keep everything). At least 7 when set.
#[serde(default)]
pub retention_days: u32,
```
in `validate`: `if (1..7).contains(&self.retention_days) { bail!("retention_days must be 0 (keep everything) or at least 7"); }`. OPTIONAL_KEYS: replace `("scan","retention_days","90")` with `("", "retention_days", "0")`. Remove the other two fields and all their uses (compiler-guided). `check_config`: drop the two cluster notes; add `if cfg.retention_days > 0 { summary += "\nretention: this node keeps the last {d} days (records and history; other nodes keep theirs)" }`. `run`: `if cfg.cluster.is_none() && cfg.retention_days > 0 { spawn run_retention(recorder, cfg.retention_days, ...) }`.
- [ ] Step 4: `cargo test --lib` passes; `cargo build --tests` compiles.
- [ ] Step 5: rewrite `src/store/delete.rs::retention_prunes_old_requests_and_scans` comments to the new key (mechanism unchanged). Commit `feat(config): one top-level retention_days, default keep forever`.

### Task 2: Provenance — `build` on every data record, node id + build in the export

**Files:**
- Create: `src/store/migrations/0024_history_floor.sql` (shared with Task 3; this task adds the `build` columns)
- Modify: `src/store/mod.rs` (migration list), `src/cluster/record.rs` (field on `RequestRec`, `SkipBatchRec`, `IpIntelRec`, `FpClaimRec`, `FingerprintRec`, `ScanResultRec`), `src/store/data.rs` (insert + rebuild), `src/store/recorder.rs` (set `crate::COMMIT`), `src/cluster/adopt.rs`, `src/store/export.rs`, `src/export/mod.rs`, `src/export/parquet.rs`, tests constructing those records.
- Test: `src/store/data.rs` rebuild round-trip; `tests/cluster.rs::enrichment_results_are_exported_with_provenance`.

**Interfaces:** Produces `pub build: String` (`#[serde(default)]`) on those records; columns `build TEXT NOT NULL DEFAULT ''` on `requests, skipped_batches, ip_intel, ip_intel_log, fp_claims, fingerprints, scans`; export columns `node_id`, `build`; JSON keys `node_id`, `build` in `intel`, `scans`, `fingerprints` items.

- [ ] Step 1: failing tests: (a) data.rs: apply a `RequestRec` with `build: "abc123def456"` and `rebuild` returns it equal; same for scan result and skip batch; (b) export test asserts `row["node_id"] == b.id.to_string()` (full hex), `row["build"] == peephole::COMMIT`, `geo["node_id"]`, `geo["build"]`.
- [ ] Step 2: run → FAIL (field missing).
- [ ] Step 3: implement migration columns, record fields, insert binds, rebuild selects, recorder sets `build: crate::COMMIT.into()`, adopt carries row build, export: `ExportRow.node_id`, `ExportRow.build` after `node` in `COLUMNS`, parquet fields `node_id`, `build` (Utf8, non-null), intel/scan/fingerprint JSON keys. Node id is the full hex of the origin (`NodeId::from_slice(..).to_string()`), "" for a standalone row.
- [ ] Step 4: tests pass (`cargo test --lib store::data`, `cargo test --test cluster enrichment_results_are_exported`).
- [ ] Step 5: commit `feat(dataset): record the node and build that created each row`.

### Task 3: History floor storage and the prune pass

**Files:**
- Modify: `src/store/migrations/0024_history_floor.sql` (`repl_floors`, `repl_log.accounted`)
- Create: `src/cluster/history.rs`; Modify `src/cluster/mod.rs` (`pub mod history`), `src/cluster/repl.rs` (`insert_log` writes `accounted`)
- Test: `tests/history.rs` (new, offline nodes like `tests/cluster_limits.rs`)

**Interfaces:**
- `pub const MEMBERSHIP: [&str; 3] = ["member_add","member_update","member_revoke"]`
- `pub async fn floors(conn) -> Result<HashMap<NodeId,u64>>` (absent = 1), `pub async fn floor_of(conn, &NodeId) -> Result<u64>`, `pub(crate) async fn set_floor(conn, &NodeId, u64)`
- `pub fn window_hlc(days: u32, now_ms: u64) -> u64` = `(now_ms - days*86_400_000) << 16`
- `pub async fn cut(conn, origin, floor, window_hlc) -> Result<u64>`: lowest seq ≥ floor with `hlc >= window_hlc`, else the log head; never above the log head; 0 when the origin has no log.
- `pub async fn prune(node: &Node) -> Result<u64>`: for every origin in `repl_heads` (not purged), `new = max(floor, cut)`; in batches of 500 entries (`seq < new`, `kind NOT IN MEMBERSHIP`, ordered by seq), one `BEGIN IMMEDIATE` tx each under `apply_lock`: drop rows (`data::drop_row`, Task 4), collect IP ids → `drop_orphan_ip`; delete `ip_intel_log` / `ip_intel` rows of that origin with `hlc < cut_hlc` (+ `refresh_ip_view`); delete `tomb_proofs` of pruned tombstones; `origin_usage -= SUM(accounted), entries -= n`; delete log rows; `set_floor(new)`. Returns entries deleted. No-op when `node.retention_days == 0`.

- [ ] Step 1: failing tests in `tests/history.rs` (offline node `x` trusting origin `a`, `retention_days = 7`): a's entries 1..=6 (member_update@40d, request@40d, ip_intel@40d, request@30d, request@1d, request@0d) applied; `history::prune(&x)` → requests of 40d/30d gone, ip_intel row gone, member_update entry kept, floor = 5, head unchanged, usage decreased by the dropped `accounted`; cut never passes the head (all entries old → floor = head); `retention_days = 0` → nothing pruned; usage counts what is held.
- [ ] Step 2: `cargo test --test history` → FAIL.
- [ ] Step 3: implement (migration: `CREATE TABLE repl_floors (origin BLOB PRIMARY KEY, seq INTEGER NOT NULL); ALTER TABLE repl_log ADD COLUMN accounted INTEGER NOT NULL DEFAULT 128; UPDATE repl_log SET accounted = COALESCE(length(payload),0) + 128;`). `Node` gets `retention_days: u32` from a new `NodeParams.retention_days` (fixtures updated).
- [ ] Step 4: tests pass.
- [ ] Step 5: commit `feat(cluster): history floors and the local prune pass`.

### Task 4: Row removal that keeps dependents servable

**Files:** Modify `src/store/data.rs` (`unmaterialize` → shared helper with `keep_own: bool`; claims of a request keep their payload); Test: `src/store/data.rs` tests or `tests/history.rs`.

**Interfaces:** `pub(crate) async fn drop_row(conn, kind, uid) -> Result<Option<i64>>` (like `unmaterialize`, without putting the row's own payload back).

- [ ] Step 1: failing test: origin a's request, origin b's claim on it (applied on x); `hide` (or prune) of the request → b's claim entry still has a payload and `entries_after(b, 0)` returns it.
- [ ] Step 2: FAIL (claim deleted without `keep_payload`).
- [ ] Step 3: in the `"request"` branch, `keep_payload(conn, "fp_claim", claim_uid)` for each claim before deleting; split `unmaterialize(conn, kind, uid)` = `remove_row(conn, kind, uid, true)`, `drop_row` = `remove_row(.., false)`.
- [ ] Step 4: pass. Step 5: commit `fix(store): a removed request keeps its claims relayable`.

### Task 5: Serving from a floor (entries_after)

**Files:** Modify `src/cluster/repl.rs::entries_after`, `src/cluster/sync.rs` (`Batch.floors`, `PullReq.since_hlc`), `src/cluster/rpc/mod.rs::pull`; Test `tests/history.rs`.

**Interfaces:** `entries_after(store, wants, since_hlc: u64, max_entries, max_bytes) -> Batch`; `Batch { entries, proofs, #[serde(default)] floors: Vec<(NodeId,u64)> }`; `PullReq { wants, #[serde(default)] since_hlc: u64, max_entries, max_bytes }`.

Per want `(o, after)`: `start = max(after+1, floor(o))`; if `since_hlc > 0`, `start = max(start, cut(o, start, since_hlc))` (never above the log head). Rows: `seq > after AND (seq >= start OR kind IN MEMBERSHIP)`; entries below `start` are sent as they are (sparse), contiguity is enforced from `start`; parked entries only from `start`. If `start > after+1`, push `(o, start)` to `floors`.

- [ ] Step 1: failing tests: pruned x (floor 5 for a) answers want `(a,0)` with the kept member_update + 5,6 and `floors = [(a,5)]`; want `(a,4)` → 5,6, no floors entry; full node with `since_hlc` = window answers from the first entry in the window plus membership below.
- [ ] Step 2: FAIL. Step 3: implement. Step 4: pass. Step 5: commit `feat(cluster): serve history from the floor, with membership below it`.

### Task 6: Receiving with floors (apply_one, drain_pending, may_sponsor)

**Files:** Modify `src/cluster/repl.rs` (`apply_batch` passes `floors`, `apply_one`, `drain_pending`, `entries`), `src/cluster/members.rs::may_sponsor`; Test `tests/history.rs`.

Rules in `apply_one` (after the purged check):
- `have = max(log_head, floor-1)`, `held = max(have, pending_head)`.
- If the batch declares `pf` for the origin and `pf > held+1`: only when `node.retention_days > 0` and the origin is trusted: an entry with `seq < pf`, membership kind, `seq > log_head`, valid signature → stored and applied (`apply_verified`), counted applied; the entry at `seq == pf` → `set_floor(pf)` then the normal path. Everything else of that origin → rejected.
- `drain_pending`: expected next = `max(log_head, floor-1) + 1`.
- `may_sponsor`: if the sponsor's previous signed entry is not `e.seq - 1` (a gap: history below a floor), skip the "silent for 30 days before" check.

- [ ] Step 1: failing tests: windowed node w (retention 7) applies `entries_after(x,(a,0))` → holds member_update + 5,6, floor 5; full node f rejects the same batch (heads 0, nothing stored); `windowed_node_jumps_to_a_peer_floor` (w holds a:1..2, peer floor 5 → floor 5, holds 5,6); `full_node_with_old_floor_rejects_jumps` (retention 0, floor 3, offered floor 5 → rejected).
- [ ] Step 2: FAIL. Step 3: implement. Step 4: pass. Step 5: commit `feat(cluster): accept history from a peer's floor on a windowed node`.

### Task 7: Peers' floors — heartbeats, wants, pushes, /wait

**Files:** Modify `src/cluster/status.rs` (`Heartbeat.floors`, `retention_days`), `src/cluster/mod.rs` (`Node.own_floors` cache filled by `heartbeat_loop`, `sync_rounds` counter), `src/cluster/sync.rs` (`reconcile`, `WaitReq`), `src/cluster/rpc/mod.rs::wait`, `src/cluster/history.rs` (rules); Test: unit tests in `history.rs`.

**Interfaces:**
- `Heartbeat { .., #[serde(default)] floors: Vec<(NodeId,u64)>, #[serde(default)] retention_days: u32 }`
- `WaitReq { heads, #[serde(default)] refused: Vec<NodeId>, #[serde(default)] windowed: bool }`
- `pub fn servable(peer_floor: u64, receiver_head: u64, receiver_windowed: bool) -> bool` = `receiver_windowed || peer_floor <= receiver_head + 1`
- `pub fn wait_ready(ours: &Heads, floors: &HashMap<NodeId,u64>, skip: &HashSet<NodeId>, req: &WaitReq) -> bool`: some origin not in `skip` (our purged) nor `req.refused`, our head > theirs, and `servable(floor, theirs, req.windowed)`.
- `Node::peer_floor(peer, origin) -> u64`, `Node::peer_windowed(peer) -> bool` from heartbeats; `Node::since_hlc() -> u64` (0 when full).
- `reconcile`: wants skip `!servable(peer_floor, mine, self windowed)`; PullReq carries `since_hlc`; an empty batch for non-empty wants → `stuck = true`; push wants skip `!servable(own floor, theirs, peer_windowed)` and pass the peer's window as `since_hlc`; `node.sync_rounds += 1` per round.
- `peer_loop` sends `WaitReq { heads, refused, windowed }`; `/wait` uses `wait_ready`.

- [ ] Step 1: failing unit tests for `servable` and `wait_ready` (purged origin ahead → not ready; refused by caller → not ready; floor above caller head+1 for a full caller → not ready, for a windowed caller → ready).
- [ ] Step 2: FAIL. Step 3: implement. Step 4: pass (`cargo test --lib cluster::history`). Step 5: commit `fix(cluster): /wait and wants skip what cannot be served`.

### Task 8: Scheduling

**Files:** Modify `src/cluster/mod.rs::maintenance_loop` (prune once ~5 min after start, then daily, when `node.retention_days > 0`); `src/lib.rs::run_retention` stays for standalone.

- [ ] Step 1: no new test (timer wiring; `history::prune` is tested). Step 2: implement: `if node.retention_days > 0 && tick % (24*60) == 5 { history::prune(&node) }` and refresh `own_floors`. Step 3: commit together with Task 7 or alone `feat(cluster): prune daily`.

### Task 9: Admin Cluster page and CLI status

**Files:** Modify `src/admin/cluster.rs` (MemberView `history: String`, page warning), `templates/…cluster…html`, `src/cluster/cli.rs` (status lines); Test: `tests/cluster.rs::admin_cluster_page_and_private_attribution` extension / new test.

- Per member: "full history" (heartbeat retention 0), "keeps N days" (N>0), "?" (no heartbeat). This node: "full history" or "keeps N days (history from <date>)" with the date of the oldest entry at a floor (`MIN(hlc)` of entries at their origin's floor).
- Warning when this node is full and for some member origin we lag (`hb.own_seq > held`) while no live member with retention 0 exists: "history incomplete: waiting for a full member".
- CLI `cluster status`: per member `history   from seq F` when this node's floor for it is > 1; first line `retention: keeps N days` / `full history` from config.

- [ ] Step 1: failing test (admin page contains "full history"/"keeps 7 days"). Step 2: FAIL. Step 3: implement. Step 4: pass. Step 5: commit `feat(admin): show who keeps the full history`.

### Task 10: Cluster integration tests

**Files:** `tests/cluster.rs` (`Opts.retention_days`, `boot_in` passes it).

- [ ] `history_floor_is_local`: a, b full, p windowed (7); origin o (offline identity, admitted via a's config peer… or appended `MemberAdd`) entries old (40 d) and new fed to a; all three get them; `history::prune(&p)` → old rows gone on p only; new record on a still reaches p.
- [ ] `full_joiner_backfills_from_full_members`: after the above, f (full) joins via p's invite → eventually holds o's whole log from seq 1.
- [ ] `windowed_joiner_fetches_its_window`: w (7) joins → holds o's new entries, membership entries, none of the old data; o's member name known.
- [ ] `no_busy_loop_with_purged_or_floored_origins`: purge on one node / full node next to a windowed one only; `sync_rounds` over 3 s ≤ 20.
- [ ] Run `cargo test --test cluster` (full suite), commit `test(cluster): history floors end to end`.

### Task 11: Docs, installer, example config, spec

**Files:** `install.sh:787`, `deploy/config.example.toml:102,172`, `README.md`, `docs/operations.md:195`, `docs/cluster.md:64-69`, spec (amendment section).

- [ ] Write `retention_days = 0` at top level (before any table) with a comment; remove the old keys; describe floors in docs/cluster.md; run `tests/deploy-check.sh`, installer smoke (podman ubuntu:26.04), shellcheck (ubuntu:24.04). Commit `docs: retention_days and history floors`.

### Finish

- [ ] fmt, clippy, full `cargo test`; one fresh-context review of the whole branch; fix findings; release ritual (PR → green CI → merge → check `latest` assets).
