# Attack chains: handoff

Written 2026-11-01 when the machine had to be switched off. Work stopped mid-plan. Nothing is merged to master, no PR is open and nothing is released.

Read these first, in this order:

1. This file.
2. `docs/superpowers/specs/2026-11-01-attack-chains-design.md`: the design, approved by the user.
3. `docs/superpowers/plans/2026-11-01-attack-chains.md`: the plan.
4. `docs/superpowers/plans/2026-11-01-attack-chains-ledger.md`: every ruling and completed task, in order.

The spec and plan predate some rulings. Where they differ, the ledger and this file win. In particular, Task 11's merge algorithm in the plan is unsafe: use `2026-11-01-attack-chains-task-11-findings.md`. `chains::rebuild` no longer exists: it is `chains::plan` plus `chains::store_plan`.

## Where things stand

| Task | What | State | Branch |
|---|---|---|---|
| 1-9 | Parser, X-ray, pieces, Links kinds, chains, strip, Chains list | Complete, reviewed | `feat/attack-chains` |
| 11 | Campaign joiner edges | Rewrite committed; its re-review was stopped before reporting | `ac/t11` at b6fbaff |
| 10 | Dossier and API | Partial, uncommitted when stopped | `ac/t10`, WIP commit |
| 13 | Trap fix, dead ends | Partial, stopped just before the change to `take` | `ac/t13`, WIP commit |
| 14 | Sandbox results | Partial, uncommitted when stopped | `ac/t14`, WIP commit |
| 12 | Flow map | Not started; needs 9 and 11 | none |
| 15 | Acceptance on real data | Not started | none |
| 16 | Interface audit | Not started; **stop for user approval** | none |
| 17-19 | Interface clean-up | Not started | none |
| 20 | PR, merge, release | Not started | none |

The WIP commits are snapshots. They were not compiled, tested or reviewed: treat them as a starting point, and check each against its plan task.

`ac/t11` was cut from `feat/attack-chains` before Task 9 landed, so merging it will touch `src/admin/campaigns.rs` and `templates/campaign.html`. It fixed one stale test line that Task 9 also fixed.

## What to do next

Order, as a DAG. Tasks at one level can run in parallel:

1. Re-review `ac/t11` (see below), fix findings, merge into `feat/attack-chains`.
2. Finish 10, 13 and 14, each with a targeted review, and merge.
3. Task 12.
4. Task 15.
5. Task 16, then **stop**. The user approves the list, including any removals, before 17-19.
6. Tasks 17 and 18, then 19.
7. Task 20.

Use `superpowers:subagent-driven-development` on `feat/attack-chains`, in worktrees. The ledger is the recovery map. To reuse the helper scripts, copy the ledger to the path `sdd-workspace` prints.

### Task 11 re-review

Try to break it with a forgery search. The required algorithm and its reasons are in `2026-11-01-attack-chains-task-11-findings.md`. Accepted departures: size ties break by the clouds' members, not a value key; in step 3 an address assigned to a cloud counts only for that cloud's values.

Check, with `k = 2`: can one forged address, or one per group, merge two groups or clouds, or make the result depend on value names or row order? Does the real case still work (163 addresses on a stager, 37 of them also on a key)? Does it stay near linear on 5,000 values?

Also open from the implementer: an unmerged edge can have both ends in no campaign, stored but shown nowhere; `Store::campaign` still loads every edge, with the 500 limit on the table only.

### Decisions already made for the unfinished tasks

**Task 10:**
- `Chain` has a `more` count and holds at most 200 pieces. Include `more`, so a consumer knows the list is partial.
- A piece appears with `value` and `defanged`. A stager also lists its URLs raw and defanged.
- The `xray` summary holds layer kinds, pieces and opaque reasons, with no layer text.
- Upload text never appears. Key values are fingerprints only.
- `/api/v1/chains` uses the same scope as `/api/v1/campaigns/{key}/dossier`.
- `ac/t11` also touches `src/admin/dossier.rs` (`joiner_edges`, defanged edge values).

**Task 12:** load the `dataviz` skill first. `Chain` holds at most 200 pieces, so the 600-piece test needs several chains. Stage rows are uncapped in the store for this task; the strip template folds after 8.

**Task 13:**
- Skip the plan's Step 1. Confirmed on the observer: all four `pr3d4t0r.php` uploads came through `POST /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php`, kind `script`. The trap's list holds `/wp-file-manager/lib/php/connector.minimal.php`, so match on `path.ends_with`.
- An upload has one answered path, so a connector upload answers only at `/wp-content/plugins/wp-file-manager/lib/files/{name}`.
- `chains::dead_ends(conn, chain)` exists per chain. The new cluster-wide function is `dead_ends_all`, reusing its condition: same address, path ending in `/<filename>`, status 404, within 60 seconds after the upload.
- The tab is `/admin/evidence/chains?tab=dead-ends`, grouped by path, newest first, defanged where a value is attacker text.
- `decoy::answers_itself` stops a file taking over a path the trap answers.

**Task 14:**
- The form appears only on `stager` and `file` pages, for joiner pieces.
- `refresh_counts` already spares pieces with `piece_results`. Show such a piece plainly when it has no sightings.
- `source_url` is defanged text, never a link. Length limits: family 64, note 2,000, source_url 2,000.
- `sha256` is 64 lowercase hex, normalised from upper case.
- Results are node-local: nothing goes in the replicated log.
- Payload with results: one row per result, `Mark::External`, naming the family or hash, with the word "external".

### Open items for the final pass

The user does not defer findings, so fix these before the PR:

- `decode.rs` `B64` wrapped-line tail can swallow a following line holding a real token.
- zlib output is labelled `LayerKind::Gzip`.
- Padding collapse folds short noise-looking fragments of a split payload.
- `text_boundary` reads only the first line, so a preamble leaves boundary noise.
- `cat "$(curl …)" | sh` marks a fetch whose output is a file name.
- A substitution found by text can miss a layer already open as non-Shell.
- A key with no `END` masks to end of text, dropping later fetches in that layer.
- `copy()` of a function parameter and URLs in arrays stay `queried`.
- A literal passed to a custom function promotes in a fetching and writing layer. It is needed for real droppers such as `adminer('http://…','x.php')`, so weigh before changing.
- A chain's shell inputs are the union across its profiles, so two shells can cross-match.
- Dead-code warnings for clippy: `RAW` in `src/admin/links.rs`, `PHP_CURL_URL` in `src/model/xray/pieces.rs`.
- The strip has never been seen in a browser: check light, dark and narrow. Measure query cost on a large chain.

Then Task 15's real-data acceptance, the full `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`, and a whole-branch review on the most capable model.

## Standing rules from the user

- **One PR, one release** for all of this, including the interface clean-up.
- **Member expiry stays at 30 days.** The user considered 7 days and dropped it.
- **Quick, targeted reviews and unit tests per stage.** The full review and full test suite run once, at the end.
- **No deferred findings.** Minors get fixed too.
- **Never fetch, contact or resolve anything from a payload.** The operator uses an external sandbox.
- **Defang payload addresses in all output**, and never make them links. The repo is public: use `192.0.2.0/24`, `example.org` and generated keys in tests, and put no captured material in commits.
- **Merging:** master has no branch protection. Run `gh pr checks <n> --watch`, then `gh pr merge <n> --merge`. Never `--auto`.
- **Release:** bump `version` in `Cargo.toml` and `Cargo.lock`, turn `## [Unreleased]` into `## [X.Y.Z] - date` with a compare link, commit `Release X.Y.Z` on master, tag annotated `peephole vX.Y.Z`, push master then the tag. CI publishes. No manual builds.
- **Specs are not edited after implementation.** Record behaviour in user docs, CHANGELOG or comments.
- **Other agents** may commit in the main checkout, so work in worktrees.
- Commit messages end with the attribution the harness gives. Plain language in user-facing text.

## Build limits

A build froze the original machine on 2026-11-01: a kernel soft lockup, `kswapd0` stuck over 22 minutes in `btrfs_drop_extent_map_range`. The disk was not full. The likely trigger was parallel builds with big reflinked target dirs and incremental caches, on btrfs with 30 GB RAM.

If the new machine is small or on btrfs, give each worktree this untracked `.cargo/config.toml`, and never copy a target dir. It cut a build from 34 GB to about 1.5 GB:

```toml
[build]
target-dir = "/path/to/one/shared/target"
jobs = 4
incremental = false

[profile.dev]
debug = 0

[profile.test]
debug = 0
```

Add `.cargo/config.toml` to `.git/info/exclude`. Do not commit it.

## What does not travel

- **Observer data.** Task 15 needs real data. The observer lives at `~/.local/share/peephole-observer` on the original machine and is not in git. Another machine needs a fresh observer join, with an invite from the user: web role only, no trap, no scanner, reverse DNS off. Run the new build only on a copy of its database. Figures from the original observer are in the spec.
- **Mockups.** The browser mockups were in tmpfs and are gone. The chosen design is in the spec: chain strip everywhere, flow map as the main view on campaign pages, no Story view.
- **Implementer reports and briefs.** They stayed in the git-ignored workspace. `task-brief` regenerates briefs from the plan.
- **Claude's memory.** The rules above are copied here for that reason.
