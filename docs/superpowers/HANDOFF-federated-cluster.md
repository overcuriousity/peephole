# Handoff: federated cluster

Written 2026-10-01, when the session that did the work below was ended on request.

## Where things stand

Updated 2026-10-01 after parts 2–4 were reviewed and finished. All four parts
are implemented, each task reviewed, each part closed by a whole-part review
and one fix pass.

| Part | Spec | Plan | State |
|---|---|---|---|
| 1 Membership and deletes | §3, §4, §8 | `plans/2026-10-01-federated-cluster-1-membership-deletes.md` | Done, reviewed (`f4c1730`) |
| 2 Config key, runtime settings, live roles | §5 | `plans/2026-10-01-federated-cluster-2-config-key.md` | Done, reviewed; fixes in `636e3be` |
| 3 Enrichment as results | §6 | `plans/2026-10-01-federated-cluster-3-enrichment.md` | Done, reviewed (`5ff5e1b`..`fab9b6f`) |
| 4 Installer wizard | §7 | `plans/2026-10-01-federated-cluster-4-installer.md` | Done, reviewed (`483b53d`..`cf784b4`) |

Checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`; the installer smoke test runs locally in
`docker.io/library/ubuntu:26.04` (same glibc as a Fedora 44 host) and
shellcheck via `docker.io/koalaman/shellcheck:stable` (see part 4's plan).

## Decisions taken after the first handoff

### Part 2 review
- The role supervisor never waits for a stopping role: it signals it and
  reaps it later; the web role gets 5 s for open requests and the live queue
  stream ends on the stop signal; a role is not restarted while its previous
  instance still runs (a fresh scanner would requeue the old one's jobs);
  shutdown waits at most 10 s. Failed starts back off up to 5 min. At
  startup only roles the config file enables are fatal, so a remote override
  cannot crash-loop a node.
- The own-node settings form carries its version; the pace row only changes
  this node; `reload` holds the writers' lock.
- Deferred (minor): a pasted config key is not verified until first use;
  `settings show` labels an override equal to the file value as "config
  file"; invalid stored overrides fall back to defaults in memory only.

### Part 3
- R1: deleting an IP removes its `ip_intel` rows and the intel export lists
  only IPs that still exist. The `ip_intel` log entries stay (they have no
  uid, so no tombstone names them). Cost: an IP's country/ASN/Tor facts stay
  in the replicated log after a delete; fixing it means giving `IpIntelRec`
  a uid.
- R2: every code path records only the provider it consulted; nothing
  republishes the displayed (possibly foreign) facts under its own origin.
- R3: the trap records `{"exit": true|false}` for every IP once a Tor list
  is loaded.
- R5 (from the whole-part review): fixed trap-created IPs not showing early
  results, junk IPs starving fill-in, credential-less cluster nodes loading
  copied GeoLite2 files, null-key dedupe, unknown providers (ignored on
  apply), blocked peers in the ranking, the export cap (100 000), and a
  migration-0017 test. Deferred: a member can pin "newest" with a
  future-dated entry (remedy: block); able nodes all rank 0 until heartbeats
  carry providers, and backlogs make every rank step in (duplicate MaxMind
  lookups; must be solved before any quota-bound provider); adopted
  standalone results get a fresh HLC and outrank newer ones;
  `ips_missing_intel` scans `ips` each minute; results from providers a node
  does not know are dropped, so a later version only sees them after a
  rematerialize.

### Part 4
- The MaxMind question is asked last (spec §7.1 order).
- The smoke test's `cluster members` assertion was replaced (it failed on
  master CI too): the command is read-only and empty before the daemon runs.
- From the whole-part review: the config is generated into a temporary
  file and validated before it is installed, so a bad answer leaves no
  config behind and a re-run asks again; the printed nginx steps are in an
  order that works on stock Debian/Ubuntu nginx (certificate first, default
  site removed, then enable); `listen 443 ssl http2` for nginx < 1.25.1.
- Deferred: a typo at a yes/no prompt aborts instead of re-asking (nothing
  is written); the generated nginx example has no `default_server` on 443
  unless the commented HTTPS catch-all is enabled; upgraded nodes keep their
  old nginx example (the README shows the new catch-all); the catch-all
  proxies to 127.0.0.1 even when the trap listens on all interfaces behind
  a remote proxy (the example's trailing note says so).

## Things the plans do not say

- **Migrations** are numbered up to `0016`. Part 3's plan uses `0017_ip_intel.sql`; check the number is still free.
- **Test flakiness**: `tests/cluster.rs` used to fail randomly on "Address already in use"; `free_port` now never hands out a port twice (`f0ee254`). `tests/cluster_e2e.rs` and `tests/roles_e2e.rs` have their own `free_port` without that guard.
- **README**: part 1 accidentally replaced the "Distributed mode" section with a fragment; it was restored in `5b0e754`. No test reads the README, so read it by eye after editing it.
- **Uid binding** (from the part 1 review): every record uid in a cluster must start with `NodeId::uid_prefix()` of its origin. `Recorder` does this; any new code that writes records with a uid must go through `Recorder` or add the prefix, or peers reject the entry and everything after it in that node's log. Tests that sign records by hand need prefixed uids.
- **Tombstones** carry `uids` and parallel `seqs` (log positions); an erased stub is only accepted at a named position. `TombstoneRec` literals in tests need `seqs`.
- **Part 3 removes `has_maxmind`** from `NodeParams`; several test literals carry it (`src/cluster/repl.rs`, `src/scan/arbiter.rs`, `tests/cluster.rs`).
- **Part 4's smoke test** runs in a container. The host is Fedora (glibc 2.43), newer than CI's `ubuntu:24.04`, so a locally built binary does not run in that image. `podman` and `docker` are installed; the plan suggests `ubuntu:26.04`, untested. `shellcheck` is not installed locally.

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
