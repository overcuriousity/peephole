# Handoff: federated cluster

Written 2026-10-01, when the session that did the work below was ended on request.

## Where things stand

Branch `federated-cluster` (local only, never pushed), 20 commits ahead of `master`. Working tree clean after the commit that adds this file.

| Part | Spec | Plan | State |
|---|---|---|---|
| 1 Membership and deletes | §3, §4, §8 | `plans/2026-10-01-federated-cluster-1-membership-deletes.md` | Implemented, reviewed, review findings fixed (`f4c1730`) |
| 2 Config key, runtime settings, live roles | §5 | `plans/2026-10-01-federated-cluster-2-config-key.md` | Implemented (`139847f`..`5b0e754`). **Not reviewed**: the reviewer was stopped before it reported |
| 3 Enrichment as results | §6 | `plans/2026-10-01-federated-cluster-3-enrichment.md` | Plan written, nothing implemented |
| 4 Installer wizard | §7 | `plans/2026-10-01-federated-cluster-4-installer.md` | Plan written, nothing implemented |

Spec: `specs/2026-10-01-federated-cluster-design.md` (kept in step with the code up to part 2).

At `5b0e754`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` all passed (136 lib, 6 CLI, 36 cluster, 1 cluster e2e, 26 integration, 1 roles e2e). The two commits after it only add plan documents.

## What to do next, in order

1. **Review part 2** before building on it. Range `f4c1730..5b0e754`. The plan's "Review Focus" lists five cases to check. Points worth a hard look:
   - the MAC over a `ConfigSet` (`src/cluster/confkey.rs`: `mac_input`, the verify in `serve`), replay and the version compare-and-set;
   - `Settings::write` / `stored` / `reset` / `reload` with the daemon and the CLI as two processes on one SQLite file (`write` opens `BEGIN IMMEDIATE` and reads through the pool on another connection);
   - the role supervisor in `src/lib.rs` (`RoleRunner`): strict first pass, retries, shutdown, switching `web` off from the web UI;
   - where the config key is stored and shown.
2. **Implement part 3**, then **part 4**, from their plans. Both plans were written before part 2 was reviewed; adjust them if the review changes interfaces.
3. Each part ends with a whole-branch review and one fix pass (the workflow used so far: superpowers `executing-plans`, test first, one commit per task).
4. Only then decide about merging. Nothing has been pushed and no PR exists.

## Things the plans do not say

- **Migrations** are numbered up to `0016`. Part 3's plan uses `0017_ip_intel.sql`; check the number is still free.
- **Test flakiness**: `tests/cluster.rs` used to fail randomly on "Address already in use"; `free_port` now never hands out a port twice (`f0ee254`). `tests/cluster_e2e.rs` and `tests/roles_e2e.rs` have their own `free_port` without that guard.
- **README**: part 1 accidentally replaced the "Distributed mode" section with a fragment; it was restored in `5b0e754`. No test reads the README, so read it by eye after editing it.
- **Uid binding** (from the part 1 review): every record uid in a cluster must start with `NodeId::uid_prefix()` of its origin. `Recorder` does this; any new code that writes records with a uid must go through `Recorder` or add the prefix, or peers reject the entry and everything after it in that node's log. Tests that sign records by hand need prefixed uids.
- **Tombstones** carry `uids` and parallel `seqs` (log positions); an erased stub is only accepted at a named position. `TombstoneRec` literals in tests need `seqs`.
- **Part 3 removes `has_maxmind`** from `NodeParams`; several test literals carry it (`src/cluster/repl.rs`, `src/scan/arbiter.rs`, `tests/cluster.rs`).
- **Part 4's smoke test** runs in a container. The host is Fedora (glibc 2.43), newer than CI's `ubuntu:24.04`, so a locally built binary does not run in that image. `podman` and `docker` are installed; the plan suggests `ubuntu:26.04`, untested. `shellcheck` is not installed locally.
- The executing-plans ledger for part 2 is in `.superpowers/sdd/2026-10-01-federated-cluster-2-config-key/progress.md` (git-ignored). Its content is reproduced below; the directory can be deleted.

## Decisions taken on the user's behalf

### Part 1

- Baseline tests were flaky on port reuse; fixed the test helper in its own commit.
- Invite listing uses `GROUP BY node ORDER BY MIN(used_at)` in place of the plan's `SELECT DISTINCT … ORDER BY used_at`.
- A foreign delete of an IP hides the other node's records on the deleting node (spec §4.2); a plan test that expected otherwise was corrected.
- Reviewer's "declined to judge" items stand as they are: `job_adopt` and job outcome reports are accepted from any member, a scan result is not checked against the assigned scanner, parked entries are unlimited. These pre-date this work or are accepted by spec §9. Cost: a hostile member can disturb the shared scan queue.
- **I1 residual**: an admission dated into the future is clamped to the time it is applied. A node that joins later replays it at its own "now" and sees a node that left as active until it is pruned 30 days later. A full fix needs re-admission to reference the leave it supersedes (record format change). No data is affected.
- **I5** (block/unblock as one long transaction) was fixed by batching without a test that failed first; the existing block/unblock tests cover the results, not the lock duration.
- Local appends now refuse a uid that is not bound to the node, so a bug cannot poison the node's own log.

### Part 2

- `Settings::stored` merges all override rows before validating (the plan validated key by key, which misjudges role overrides that are only valid together).
- The role supervisor is strict at startup (a role that cannot start is fatal, as before) and retries only later changes.
- `tests/cli.rs::settings_are_shown_set_and_reset_from_the_shell` was written after the implementation and never failed first.
- The runtime settings form is also shown on a standalone node's Cluster page.
- Rotating the config key from the UI is refused while remote configuration is off.

## Deferred minor findings (part 1 review, not fixed)

- Unblock is not atomic: a crash between deleting the block row and the replay leaves the peer's records out of the tables until a block/unblock cycle.
- Leave has a crash window between the revoke entry and the detached flag; peers are told one after another inside the request.
- A detached node still redeems invites; a failed append after the invite `UPDATE` burns a use.
- A replayed `job_adopt` cycle can show a running job as queued until the next status arrives.
- `ips.fp_claimed` is not reset after a hide or tombstone; a dependent scan with another IP can leave an orphan `ips` row.
- A fingerprint from another origin linked to a blocked node's request keeps `request_id = NULL` after unblock.
- The delete-notice cookie lacks `Secure` and a `__Host-` prefix.
- Bulk "delete all IPs" stops early if a whole page of matches had no records.
- `bootstrap` still warns "configured peer is revoked" for peers that left or were pruned.

## Spec items still open after part 2

- §3.3: a blocked peer's GeoIP facts written before the block stay in `ips` until part 3 replaces `ip_enrich` with per-origin `ip_intel` rows (part 3, task 1 handles it).
- §6 and §7 entirely.
- §9: false-positive claims with the optional contact e-mail replicate to every member; left for a later decision.
