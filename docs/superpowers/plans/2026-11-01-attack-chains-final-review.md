# Final review: f82e42f..3e916eb (attack chains)

## Verdict

**Not ready to ship.** There is 1 Critical, 5 Important and 18 Minor findings.

- **Critical:** one source address on the public trap can run the node out of memory in the hourly pass, and the pass repeats after every restart.
- **Certain test failure:** `only_the_upload_store_names_the_content_table` fails on this head (I1).
- **Task 19:** the diff is sound. It adds two Minors: M11 and the stale names in M18.
- **Clean areas:**
  - Replication and mixed clusters: nothing changed under `src/cluster`, and no record kind changed.
  - Migration order.
  - Escaping: no new `|safe`.
  - Key masking in the X-ray panes and in the chain and X-ray JSON.
  - Defanging.
  - `CAMPAIGN_V` handling.
  - Delete triggers.
  - Chain and API routes.

**How this was checked:** by reading the code, plus SQLite query plans on an in-memory copy of the schema. Nothing was built or run, so every memory and time figure below is an estimate from the code, not a measurement. `shell.rs` and `container.rs` were read at their entry points and risk points, not line by line. See "Declined to judge".

## Critical

### C1. Chain building has no bound on joiners, so one address can exhaust memory
**`src/store/chains.rs:226-245`, `:130-171`, `:174-217`, `:256-285`, `:294-327`; also `src/store/campaigns.rs:919-930`**

**What's wrong.** `joiner_sightings` loads every joiner sighting, and `connect` builds a `Group` per joiner. `unions` keeps a `HashMap<(i64,i64), HashSet<i64>>` entry per joiner pair and never removes one. `MAX_JOINERS_PER_IP` protects only `compute()`. `PAIRED_JOINERS_MAX` limits one source, not the total.

**Why it matters.** Two attacks work, using the default `record_rate` of 10 per second per address:
- **One address.** A roughly 5 KB PHP body with 256 `copy('http://aN.example/','x');` calls gives 256 fresh joiners. That is about 9 million joiners an hour. At about 0.5 KB per group, plus the sighting vectors and `ChainOut`, memory grows by roughly 6 GB per hour of attack.
- **Two addresses.** Both send the same 64-stager bodies, each body with fresh hosts. Each distinct body adds 2,016 pair entries, so 36,000 bodies an hour gives about 72 million entries, or more than 10 GB.

Other effects:
- The derived rows have no retention unless `retention_days` is set, so the pass grows with all history.
- `recompute_campaigns` also runs at startup, so an OOM kill repeats after each restart and takes the trap down with it.
- The same flood makes `store_plan` rewrite millions of `chains` and `chain_pieces` rows in one write transaction. That can exceed the 10-second `busy_timeout` the trap's writes wait under.

This is the spec's "exhaust memory" anti-goal, reached through the hourly pass rather than the parser.

**How to fix.** Apply the campaign rule to chains, and do it in SQL so the data never reaches memory:
- Read only each address's newest `MAX_JOINERS_PER_IP` distinct joiners, using a window function, in both `joiner_sightings` and `Input::read`.
- That bounds pairs to 120 per address and chains to 16 per address.
- List the capped addresses as excluded.
- Add a test with one address and thousands of fresh joiners that asserts the row counts of the plan.

## Important

### I1. `tests/never_served.rs` fails on this head, and the "only `store/uploads.rs` names `upload_blobs`" constraint is broken
**`src/store/chains.rs:2653`, `tests/never_served.rs:251-272`**

**What's wrong.** A unit test in `chains.rs` runs `DELETE FROM upload_blobs`. The guard test scans all of `src/` as text and expects exactly `0034_uploads.sql` and `src/store/uploads.rs`. `grep -rl upload_blobs src templates` also returns `src/store/chains.rs`.

**Why it matters.** The running full suite will fail here. The final-pass report notes that `tests/never_served.rs` was not run. The constraint also weakens.

**How to fix.** Add a `#[cfg(test)]` helper in `src/store/uploads.rs` that removes the blobs, and call it from `chains.rs`.

### I2. One body can make a parse take seconds, because a regex is compiled per PHP literal
**`src/model/xray/pieces.rs:875-884`, `:824-838`, `:688-716`, `:988-1035`**

**What's wrong.** `php_literals` has no cap. For each URL literal assigned to a variable, `php_saved` calls `fetched_by_name`, which compiles a new regex and scans the whole layer. `php_fetches` does the same per `fopen($v`.

A 64 KiB `<?php copy('a','b');file_put_contents('x','y');$v='http://a.b/x';...` holds about 3,000 literals. A new regex has no shared DFA cache, so I estimate 1 to 5 seconds per parse. The cost is quadratic in layer size. `pathological_input_is_fast` does not cover this shape.

**Why it matters.** Extraction parses a 200-row batch on one thread, so a batch can take minutes. An attacker's 10 rows per second then outruns extraction. The request, upload and dossier pages pay the same cost on an async worker (M2). See I3 for the effect on maintenance.

**How to fix.**
- Memoize `fetched_by_name` per name.
- Stop after `MAX_PARTS` literals or calls, and record `OverLimit`.
- Replace the per-call regexes with a byte search or one prebuilt regex.
- Add this shape to `pathological_input_is_fast`.

### I3. The whole backfill runs inline in the maintenance loop
**`src/store/maintenance.rs:56-61`, `src/store/pieces.rs:379-405`, `:555`, `:560-562`, `src/lib.rs:305-313`**

**What's wrong.** `extract` runs until no row is left, and its cursor follows new rows, so it returns only once the inflow stops outrunning it. `maintenance::run` awaits it inline, and `EXTRACTING` makes the hourly tick queue behind the startup backfill.

**Why it matters.**
- The spec accepts a slower backfill, but not stalling everything else. While extraction runs, `prune_expired_auth`, `daily_maintenance` (tombstones, `gc_blobs`, vacuum) and the campaign, chain and evidence passes all wait.
- Upper limit on drain is 800 rows per second, so a node with more than about 3 million heavy rows stalls past the first hour.
- With I2 an attacker can hold this state for as long as the backlog lasts.
- Startup is not blocked, because this is a background task.

**How to fix.** Run extraction as its own background task. Give the hourly call a cap on rows or time, and let the campaign pass run on what has been read so far.

### I4. Strip queries scale with global piece popularity and chain size, not with what the page shows
**`src/store/chains.rs:1347-1359`, `:1380-1410`, `:1646-1671`**

**What's wrong.** Query plans confirm `SEARCH g USING PRIMARY KEY (piece=?)` for every piece in `chain_pieces`, describers included, with `role` filtered afterwards. A recipe shared by a million requests is scanned in each of the `found`, `tags` and `counts` queries. `GROUP BY ... ORDER BY MAX(g.ts) DESC LIMIT 2000` also reads and sorts every source of the chain before the limit applies. `of_piece` has the same shape.

**Why it matters.** The 22 ms measured on the observer was for 866 sources. At that rate a chain with a million sources costs about 25 seconds per query, per strip. A request page builds up to 6 strips and a campaign page up to 33, each holding a read connection. Chains get this large from a single botnet stager.

**How to fix.**
- Add `p.kind IN ('stager','key','file')` to the `src` CTEs. The `JOIN pieces` is already there.
- Read the newest 2,000 sources from an index on `(piece, ts)`, per joiner, then merge.
- Compute `seen` with `EXISTS`, or store it.
- Check the plans on the observer copy.

### I5. The accepted key limit is not stated, and nearby text reads as the opposite
**`docs/api-v1.md:493-496`, `CHANGELOG.md` entry "Dossiers carry attack chains", `docs/api-v1.md` "Never here" list**

**What's wrong.** The spec records as a known limit that the stored body keeps key bytes, and that a key written line by line has no marker and is not masked. No user-facing doc says either. The CHANGELOG says "upload text and key material never do", and the API docs say "Never here: ... key material". A request dossier's `body_text` and `body_b64` do carry a raw key, now up to 64 KiB.

**Why it matters.** Dossiers are made to leave the node. An operator will read the docs as saying a dossier is safe to share with a captured key in it.

**How to fix.** State both limits in `docs/api-v1.md`, in `docs/operations.md` and in the CHANGELOG. Scope "never" to the chain and `xray` objects.

## Minor

**M1. `src/admin/xray.rs:483,509,553`, `src/model/xray/key.rs:112-114,149-161`.** `mask_ranges` recomputes `all_masks` for every layer, so one view does it up to 130 times, each with regex scans plus `with_repeats` window compares. Many key-bearing layers can make a request page take seconds (estimate). Fix: compute `all_masks` once in `xray_view`.

**M2. `src/admin/pages.rs:227`, `src/admin/uploads.rs:123`, `src/admin/dossier.rs:1025`.** `parse` runs on an async worker, although extraction and `gather_follow_ups` move it to `spawn_blocking`. With I2 this blocks a worker for seconds. Fix: use `spawn_blocking` in all three.

**M3. `src/store/pieces.rs:241-249`.** Each URL write counts all `piece_url_sources` of that URL inside the write transaction, so a URL in many requests costs quadratic time while holding the write lock. Fix: add 1 when the `INSERT OR IGNORE` inserted a row.

**M4. `src/store/pieces.rs:312-320`.** A future `XRAY_V` bump deletes all sightings and URLs in one `BEGIN IMMEDIATE`, unlike the chunked work around it. Fix: delete in id or hash ranges.

**M5. `src/store/pieces.rs:357-377`.** The hourly `stamp_light` walks from id 0 to `MAX(id)`, with a 25 ms sleep every 5,000 ids, even with nothing pending. Ten million rows cost about 50 seconds per hour. Fix: start at `SELECT MIN(id)` of the pending rows.

**M6. `src/store/pieces.rs:750`.** `add_piece_result` uses a deferred transaction that reads and then writes. On a node with constant trap writes it can fail with a snapshot `database is locked`, which the busy timeout does not retry, and the admin sees it as "Not saved". Fix: `begin_with("BEGIN IMMEDIATE")`.

**M7. `src/store/chains.rs:1903`, `docs/api-v1.md:569`.** The Chains list and API `payload` are only `seen` or `gap`. After Task 14, a chain with a sandbox result shows `external` on its strip and `gap` in the list. Fix: add `external`, then update the docs and OpenAPI.

**M8. `src/store/chains.rs:1414`.** A piece seen only before a chain's newest 2,000 sources gets 0 requests, so it shows "0 req". `docs/detection.md` says what is past a cap is counted. Fix: fall back to the piece's count, or say so.

**M9. `templates/_chain_flow.html:4`.** The ledger item said to scope the band to the campaign or say so in the lane note. Item 11 scoped it to the chain, and the page does not say so, so a chain spanning campaigns shows other campaigns' requests. Fix: change the note to "band width is the chain's requests, across campaigns".

**M10. `src/store/campaigns.rs:1131-1140`, `templates/admin_campaigns.html:33-35`.** The joiner cap adds one `Excluded` row per address. Those rows go into the report JSON and are all rendered, so many addresses mean an unbounded page. Fix: store a count and the top few.

**M11. `templates/_target.html:117`.** Task 19 restyles an empty state on the public IP page, which the spec and the audit keep out of scope. Fix: keep the old markup on this line.

**M12. `src/store/stats.rs:713-758`, `docs/overview.md:159`.** Joiner-formed campaigns now feed the public "Campaigns this period" tile, including a forged loose campaign. The spec says the public dashboard does not change. Fix: filter on `joiner_edges = 0`, or say so in "What is public".

**M13. `src/store/uploads.rs:737`, `src/admin/xray.rs:540`.** Upload text is read to 256 KiB, while the spec says 1 MiB. Nothing says the text was cut, and the X-ray head shows 262,144 bytes for a larger file. Fix: pass the real size and record `OverLimit`.

**M14. `src/admin/dossier.rs:1023`.** `other_chains` is cut at 31 by `CHAINS_MAX`, although a body can name 256 stagers and the docs say it counts the rest. Fix: count separately, or state the cap.

**M15. `templates/admin_chains.html:7`, `src/admin/flow.rs:245`.**
- `.tabs` has no CSS, so the Chains and Dead ends tabs have no current state. Fix: use `class="seg"` with `aria-current="true"`.
- An empty stage has height 0, so its band has thickness 0, despite the comment on `BAND_MIN`. Fix: draw it at `BAND_MIN`.

**M16. `docs/roadmap.md`, `docs/dataset.md`, `CHANGELOG.md`.**
- Roadmap: unchanged, though plan Task 15 Step 4 and the spec list it. Fix: add what shipped.
- Dataset: the spec's addition that the `campaign` column can shift is missing. Under v3, addresses with no campaign can gain one. Fix: add it.
- CHANGELOG: it names 0053 but not 0052. It does not mention the first-start backfill, that the first campaign pass and all chains wait for it, that a `#N` can change, or that a node with `retention_days` shows only what it still holds. Fix: add a release note.

**M17. `docs/detection.md:435-438,449`, `docs/operations.md:538`, `CHANGELOG.md:92`.**
- Accepted limit: the text names the bridge but not its result. Fix: say plainly that as few as two forged addresses can show two unrelated loose groups as one false campaign, and put this in the CHANGELOG too. `src/admin/glossary.rs:79` needs the same change.
- Line 449 gives "at least two addresses" without the tenth rule, the 64-joiner rule or the 50-address file rule.
- "Metadata only" is no longer exact, because dossiers carry pieces from upload text, which the spec allows. Fix: say "metadata and the pieces found".

**M18. Stale names and pointers.**
- `src/store/migrations/0052_chains.sql:1` cites `docs/cluster.md` "Attack chains", which does not exist. Fix before release, since a shipped migration is frozen.
- Comments still use the old page names: `src/admin/views.rs:16`, `src/trap/mod.rs:86`, `src/cluster/repl.rs:1487`, `src/admin/cluster.rs:104`.
- A test comment in `src/store/links.rs`, "The campaigns do not read them yet", is out of date.

## Declined to judge

- **Raw `value` and `urls[].url` in the API and dossiers.** Global constraint 5 says only "Copy for sandbox" gives a raw URL. Plan Task 10 and the CHANGELOG specify raw plus defanged, and the ledger is silent. The two documents conflict, so this is yours to rule on.
- **Request headers are not parsed.** The spec's `Source` comment lists headers, but the plan's `Source` has none and the ledger is silent. Payloads in `User-Agent` give no pieces. I treated the plan as the later word; it may be worth a roadmap line.
- **A key in the path or query still shows in the request line, `/requests` and the copy button.** This surface predates the branch, and the spec scopes masking to the X-ray panes.
- **Migration time on a big database.** `ADD COLUMN` is constant time, and `campaign_edges` has no `CHECK` on `kind`. The partial index needs a table scan at startup, as 0007 and 0042 did. No big database was available to time it.
- **`shell.rs` and `container.rs` logic line by line.** Earlier reviews covered these. I checked their limits, indexing and entry points, and traced `decode.rs` and `key.rs` where they touch masks. Absence of findings there is weaker evidence than elsewhere.
- **`docs/openapi.json` field by field.** I relied on `openapi_lists_chains` and the schema checks in the dossier tests, which I read but did not run.
- **Visual results, including the `.empty-card` change.** There was no browser check, which is accepted.
- **Ledger rulings and the five clippy lints.** Accepted, so not reported.
