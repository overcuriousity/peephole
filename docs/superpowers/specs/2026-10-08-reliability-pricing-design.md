# Reliability pricing: buyers pay per delivered scan

Date: 2026-10-08 · Status: proposed.

Changes how an arbiter hands out scan jobs (`src/scan/arbiter.rs`), how
often prices refresh (`src/credits/mod.rs`, `src/credits/price.rs`) and how
often the per-level scanner weights are measured (`src/scan/weight.rs`).
The mint, the allowance, pay on delivery, the price rule itself and the
wire protocol stay as they are.

## Goal

Some scanners fail scans of one level far more often than others. A buyer
should then buy less of that level from them, the way a market does it:
by comparing what one **delivered** result costs, not by a rationing rule.

Example: Fast asks 3 credits and delivers every L4 scan. Flaky asks 2 and
fails half its L4 scans, but is fine at L1 and L2. A failed scan is not
paid, so a delivered L4 result costs 2 / 0.5 = 4 with Flaky and 3 with
Fast. Fast should win L4 jobs, Flaky should keep winning L1 jobs.

Why: today the buyer ranks scanners by asking price alone, which is the
same for every level. A scanner's failed scans are unpaid, so its paid
work drops below target and **its price falls**, which ranks it first and
pulls more of the work it fails toward it; its good levels are underpriced
with it. A separate rule (sit-outs: the scanner skips the level for a share
`1 − weight` of 10-minute stretches, decided by a shared random draw)
limits the damage. That is rationing, and the buyer has no say in it.

## 1. Price per delivered result

For a scanner `s` and a job of level `L`:

    effective(s, L) = price_for(s) / weight(s, L)

- `price_for` is today's offer price (`credits::jobs::price_for`): what
  `s` announces, at most `PRICE_TOLERANCE` × this node's copy; this node's
  own table price for itself. No price (not a scanner, does not sell
  scans, no copy here): effective is `u32::MAX`.
- `weight` is today's `weight::weight`: the scanner's success rate at `L`
  over the best rate among the other live scanners with at least
  `MIN_SAMPLE` scans there, floored at `MIN_WEIGHT` (0.1). Ranking by
  this relative weight gives the same order as ranking by absolute
  success rate, since the best rate divides every scanner alike.
- A job whose price is scaled by level (the manual scans of
  `2026-10-08-probe-unrestricted-paid-scan-design.md`, `× 4^(L−1)`)
  scales every scanner's effective price at that level alike; the ranking
  and the reserve below are unchanged by it.

## 2. Handing out by job, not by scanner

Today `hand_out` sorts the scanners asking in a round (the 2-second
`CLAIM_WINDOW`) by price and gives each the next job it may take. The job's
level is known only after the scanner is picked, so the level cannot enter
the choice.

New: a round walks the **jobs** and picks a scanner for each.

1. Collect the claimants of the round, as today, with their load (scans
   in the last hour) and their demotion (over hourly capacity, or
   delivered less than half of 5 recent grants of this arbiter).
2. Take the queued jobs of this arbiter in today's order (highest
   response ratio first, `order`), at most `4 × claimants` of them, with
   today's arbiter-wide filters (status `queued`, `retry_at` passed).
3. For each job, the **eligible** claimants: not yet given a job this
   round, not having handed this job back (declined, or "later" within
   `LATER_BACKOFF`), not excluding its level, and not its last failer
   within `LAST_FAILER_WAIT`. None: next job. The superseded check
   (`outranked_by`) runs before, as today.
4. Rank the eligible claimants for the job's level by
   `(demoted, effective, load, key)`. Demoted scanners go last; equal
   effective prices go to fewer recent scans; the key breaks the rest.
5. **Paid or unpaid.** Check, without writing anything, whether this
   round's book can fund the top-ranked claimant at its price and its
   `min_mc` (the check `fund` makes today, split out so it can run
   first).
   - **Paid:** apply the reserve (§3). If the job goes now, `fund` writes
     the offer and the job is granted funded. The sit-outs do not apply.
   - **Unpaid:** the claimants sitting the level out by today's draw
     (`skipped_levels`, unless the job has waited `OVERRIDE_WAIT_MINS`)
     are dropped, and the job goes unpaid to the best of the rest, ranked
     as in step 4. Idle work has no price to compare, so the sit-outs stay
     for it.
6. Claimants left without a job when the jobs run out get none, as today.

This replaces the scanner-major loop in `hand_out` / `next_job_for` /
`next_job_skipping`; the per-scanner filters move from SQL into the
per-job check of step 3.

## 3. The reserve: waiting for a better offer

A paid job goes to its best claimant only if no live scanner that is not
asking right now would be cheaper per delivered result. The **reserve** of
level `L` is the lowest `effective(s, L)` over the scanners that:

- are live for this arbiter (`arbiter::scanners`),
- are not demoted here and not over their hourly capacity,
- have at least `MIN_SAMPLE` finished scans at `L` in the current weight
  snapshot (§4), so a scanner that never runs `L` does not hold `L` jobs
  back.

If the best claimant's effective price is above the reserve, the job stays
queued for a later round. A job that has waited `OVERRIDE_WAIT_MINS` (30)
goes to its best claimant whatever the reserve: that is the buyer's
patience. If the cheaper scanner stays busy, its price rises by the price
rule until the weaker one wins again; the split settles by price.

## 4. Weights measured hourly

The weights are measured **once an hour** instead of at every hand-out,
over the same 24 hours:

- The snapshot of hour `H` counts the scans finished in `[H − 24 h, H)`
  (UTC hours), with today's rules (only hard failures; timeouts, invalid
  targets, declines and lapsed leases count for nothing).
- It is taken at `H + 5 min`, so scans finished just before `H` have
  replicated; until then the snapshot of the previous hour holds. Every
  node that has the same log computes the same snapshot, so arbiters
  agree.
- The arbiter (ranking, reserve, sit-out draws) and the admin pages read
  the snapshot; the Cluster pace row's "Level weights" shows it too.
- At start, the snapshot of the latest full hour is taken at once.

## 5. Prices every 10 minutes

The price refresh (`price::refresh`) runs every 10 minutes instead of
every hour (`src/credits/mod.rs`: `ticks % 60 == 1` → `ticks % 10 == 1`).

- **The rule's speed per hour stays.** Each step is already scaled by the
  hours since the last one (`hours_since`, `flow_step`), so a 10-minute
  refresh takes 1/6 of an hourly step: at most e^0.45 up and e^−0.15 down
  an hour, as before. Prices move in smaller steps and react sooner.
- A scanner's price still compares its paid scans of the **past hour**
  against `PAID_TARGET` × its hourly capacity; the hour now slides every
  10 minutes. Flow goods (lookups, probes, resolutions) count their demand
  since the last refresh, as today.
- The least move of 1 mc per refresh stays, so a price off its target
  moves at least 6 mc an hour. That matters only near the floor; no
  special case.
- `price_history` keeps one point per hour (the last refresh of the hour
  replaces the earlier ones, `INSERT OR REPLACE` on the hour); demand and
  supply stay per hour.
- No live load surcharge: a scanner that is full right now does not ask
  for work, so it is already out of the round; price follows lasting
  demand.

## 6. What is shown

**Cluster › Credits, scanner table** ("What things cost here"): four new
columns L1–L4 beside Announces, Reference here and Paid / target an hour,
each the scanner's effective price at that level as this node sees it,
the cheapest per level in bold. A cell's title gives the basis: "price
0.020 ÷ success 50 % (6 ok, 6 failed, last 24 h)". A line under the table:
"Success rates as of 14:00 UTC, next at 15:00."

**Scan page** (`/admin/scans/<id>`): a "Handed out" line from the arbiter's
record of the grant:

- Paid: "Given to Fast for 0.030 per delivered result (price 0.030, 100 %
  at L4). Next best: Flaky, 0.040 (price 0.020, 50 %). Waited 12 min for
  Fast." (The wait part only when the job waited for the reserve.)
- Override: "Waited 30 min, then went to whoever asked: Flaky, 0.040 per
  delivered result."
- Unpaid: "Unpaid: the scan budget did not cover it; went to Flaky
  (scanners weak at L4 sat out by the old rule)."
- On a node that was not the arbiter: "Handed out by <arbiter>; the
  reason is on that node."

**Record:** a local table `job_handouts` (new migration):
`job_uid, at, scanner, level, paid, price_mc, rate, effective_mc,
next_scanner, next_effective_mc, waited_secs, reason`
(`reason`: `cheapest`, `override`, `unpaid`), one row per grant (a retry
adds one; the page shows the latest), pruned after 8 days like
`price_history`. Not replicated: nothing new goes between nodes.

**Scans history** (`/admin/scans`): for a finished job of this arbiter, the
same text as a title on the scanner's name, so failed jobs (no scan page)
show it too.

**Scans › Scanners note** (`templates/admin_scans.html`): the paragraph on
sit-outs becomes: paid jobs go to the scanner that is cheapest per
delivered result, waiting up to 30 min for a cheaper live one; a scanner
that fails a level often is cheaper only if its price makes up for it;
unpaid jobs keep the sit-out rule.

## 7. Compatibility

- No protocol change: every input (prices in heartbeats, the replicated
  `scan_jobs`) is already there, and each arbiter decides alone.
- Mixed versions: an old arbiter keeps ranking by price with sit-outs; a
  new one ranks per delivered result. Scanners see only grants and do not
  care. Old nodes keep refreshing hourly; since steps scale with time,
  prices on old and new nodes follow the same path, the new ones in finer
  steps, well within `PRICE_TOLERANCE`.

## 8. What this cannot do

- The weights cover 24 hours: a scanner that just got fixed stays
  expensive per result until its failures age out (the `PRIOR_OK` prior
  and the `MIN_WEIGHT` floor keep it taking the odd job).
- A job that waits for the reserve waits for a scanner that may not come
  back soon; the 30-minute override bounds the wait.
- The reserve uses this arbiter's view of liveness and capacity; a
  scanner that looks live but is stuck holds jobs back up to 30 minutes.
- The record of why a job went where is on the arbiter only.

## 9. Testing

- Ranking: Fast and Flaky as above: Fast gets the L4 job, Flaky the L1
  job; a demoted scanner goes last whatever its price; equal effective
  prices go to the fewer recent scans.
- Reserve: an L4 job waits while only Flaky asks and Fast is live and
  cheaper per result; after `OVERRIDE_WAIT_MINS` it goes to Flaky; a
  scanner with fewer than `MIN_SAMPLE` scans at L4, a demoted one and one
  over capacity set no reserve.
- Unpaid: a job the budget cannot fund is granted unpaid, and a scanner
  sitting the level out by the draw does not get it; the funding check
  writes nothing.
- One job per claimant per round; jobs past the bound are left for later;
  a superseded job is marked as today.
- Snapshot: two nodes with the same rows compute the same snapshot for
  hour `H`; a scan finished after `H` counts only from `H + 1`; until
  `H + 5 min` the previous snapshot holds.
- Prices: six 10-minute steps move a price as far as one hourly step with
  the same demand and supply; `price_history` holds one point per hour.
- Shown: `job_handouts` is written at each grant and pruned after 8 days;
  the scan page renders each reason; the history title appears on the
  arbiter's rows; the Credits table shows L1–L4 with the cheapest in bold.
- Docs: `docs/cluster.md` (Credits: scan jobs and prices; the sit-out
  paragraph) and `CHANGELOG.md`.
