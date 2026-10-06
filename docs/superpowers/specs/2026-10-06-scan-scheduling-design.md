# Scan scheduling: L4 share, minimum rate, response-ratio queue, presets

Date: 2026-10-06 · Status: implemented (branch `ai-decoys`, PR #41).

## Problem

On the 4-node cluster (2 workers each) the queue stalled: backlog 83 and
growing, oldest job 35 h, throughput 24/h against a pace allowance of 107/h,
"0 finished last hour".

Cause, measured on the nodes:

- All 8 workers ran L4 scans at once, each for 1:30–1:45 h, close to nmap's
  `--host-timeout` (6840 s for L4).
- The queue hands out `level DESC, queued_at ASC`, so a free worker always
  takes a waiting L4 job. While ≥ 8 L4 jobs wait, nothing else starts.
- L4 is slow because `-p-` at `-T3` against hosts that drop probes lets
  nmap's adaptive timing crawl. 7 days of L4: 10 done (avg 13 min, max 51),
  9 failed (avg 28 min, max 114). The long failures are nmap host-timeouts
  (`nmap_xml.rs` reports them as `timeout (nmap host-timeout)`), recorded as
  failed, not as the UI's timeouts.

Duration per level, 7 days (done):

| Level | Done | Avg min | Max min |
|---|---|---|---|
| 1 | 686 | 2.1 | 9.0 |
| 2 | 474 | 1.8 | 25.1 |
| 3 | 179 | 2.6 | 12.0 |
| 4 | 10 | 13.0 | 51.3 |

L1 (`-T2`, no detection) is slower than L2 and returns less. L1–L3 cost the
same; only L4 differs.

Volume by level (all time): L1 1.4k, L2 14k, L3 670, L4 445.

## Goal

- L1–L3 never wait behind L4: a node never runs more than half its workers
  on L4.
- L4 finishes in minutes, not hours, and rarely hits its timeout.
- Short jobs go first, but a waiting job's priority grows until it runs; no
  level starves.
- Each level returns as much as it can in the least time. Scans stay
  non-intrusive: no `-A`, no `intrusive`/`brute`/`auth`/`vuln`/`exploit`/
  `dos`/`external`/`broadcast` scripts, no `-T4`/`-T5`.
- Works in a mixed-version cluster during a rolling upgrade.

Not in scope: the old L4 jobs (from 2026-10-04) that arbiters skip while
newer L4 jobs run. Residential, their arbiter, was not reachable for logs;
the queue order below replaces the code path in question. Re-check after
rollout.

## Decisions

| Topic | Decision |
|---|---|
| L4 cap | `floor(max_workers × scan.level4_max_share)` concurrent L4 scans per scanner; default share 0.5 |
| Minimum workers | 2. Saving 1 is rejected; 0 still pauses. The recommender never suggests fewer than 2 |
| Where the cap applies | At the arbiter's pick: the scanner's claim names the levels it cannot take now |
| Mixed versions | An old arbiter ignores the claim field; the scanner hands an L4 grant over its cap back as "later" |
| L4 speed | `--min-rate <scan.min_rate>` (default 300 pps, per node) and `--max-retries 1` |
| L4 timeout | `level4_timeout_factor` default 4 → 2 |
| Queue order | Highest response ratio next: `(waited + est) / est` |
| Duration estimate | Per level, mean worker time of done + failed jobs over 7 days, clamped to [5 min, level timeout]; defaults until there is data |
| Level-ordered things that stay | Same-IP tie-break (`outranked_by`), full-queue eviction, cooldown |
| UDP at L4 | `-sU --top-ports 50`, behind `scan.level4_udp` (default off) |

## 1. L4 share

### Scanner

The worker loop (`scan::run_workers`) tracks the level of each running job
(it already keeps `Job` per task; count L4 entries). Before acquiring:

```
l4_cap   = floor(p.max_workers as f64 * share) as usize   // ≥ 1 for workers ≥ 2
at_cap   = running_l4 >= l4_cap
exclude  = if at_cap { [4] } else { [] }
```

`exclude` is passed into `Source::acquire`:

- Standalone (`acquire_local`): `AND j.level NOT IN (exclude)` in the
  queue query.
- Cluster (`acquire_granted`): sent in the claim (below). If a grant still
  comes back at an excluded level (old arbiter), `check_grant` turns it
  down as `"later"` with why `"at the level-4 share"`. No nmap runs, and
  nothing counts against the hourly rate.

The share is re-read every pass, like the pace.

### Protocol

`Msg::Claim` becomes `Claim { #[serde(default, skip_serializing_if =
"Vec::is_empty")] exclude_levels: Vec<u8> }`. An empty list serializes the
same as today's unit `Claim`, so an old arbiter decodes a claim from a
scanner below its cap unchanged.

Plan-time check: confirm with a test that (a) the old unit encoding decodes
into the new variant, and (b) the decoder of the old unit variant accepts
the new encoding with a non-empty `exclude_levels`, or else answers in a way
the scanner treats like "no grant". If (b) fails, an old arbiter must not
receive a claim with the field set: gate the field on the peer's protocol
version (`proto_max`) and bump `PROTO_VERSION`.

### Arbiter

`next_job` takes the claim's `exclude_levels` and adds `AND j.level NOT IN
(exclude)` to `next_job_skipping`. Unlike the weight skips, this filter is
**not** lifted after `OVERRIDE_WAIT_MINS`: the scanner cannot take the job
now, whatever its age.

`hand_out` keeps its per-claimant fairness. Each waiter carries its own
exclusions.

### Config and pace

- `scan.level4_max_share`: float, `0.0 < share ≤ 1.0`, default 0.5.
  Validated by `Config::load`, settable through `settings` like the other
  `[scan]` keys (`DEFAULT_KEYS` in `config.rs`).
- `Pace::validate`: `max_workers` must be 0 or within `2..=MAX_WORKERS`.
  The error message says so.
- `pace::recommend`: never recommends fewer than 2 workers.
- Startup with `scan.max_workers = 1` in the config file: `Config::load`
  fails with a clear message (no silent change).

The Scans page shows each scanner's L4 share next to its workers, for
example "2 workers · ≤ 1 on L4".

## 2. L4 speed

L4 preset gets `--min-rate <n>` and `--max-retries 1`. `n` comes from
`scan.min_rate` (default 300, range 50–5000), added to the argv in
`nmap_argv` only for level 4, and only if the preset or the operator's
`level_argv` has no `--min-rate` already (same rule as `--host-timeout`).

300 pps covers 65535 TCP ports in about 4 minutes. `-sV`, `-O` and the
scripts then run only on what is open.

Per node: residential sits behind a home router whose NAT table gets an
entry for every SYN. It sets a lower `scan.min_rate` in its own config. The
setting is per node; nothing replicates it.

`level4_timeout_factor` default 4 → 2 (60 min with the 30-min base). An
operator's explicit value is kept.

The doc comment on `default_level_argv` changes from "timing capped at
`-T3`" to "timing template capped at `-T3`; L4 sets a minimum send rate so
filtered hosts cannot stretch a full-range scan".

## 3. Queue order: highest response ratio next

### Formula

For each queued job:

```
waited_min = minutes since queued_at
est_min    = estimate[level]
ratio      = (waited_min + est_min) / est_min
```

Highest ratio first; ties by `queued_at`, then `uid` (or `id` standalone),
so all nodes agree.

With today's numbers (est 5 for L1–L3 after the floor, about 20 for L4):
two fresh jobs tie at 1 and `queued_at` decides. An L4 job ranks equal to
an L1–L3 job that has waited a quarter as long, e.g. an L4 waiting 40 min
equals an L2 waiting 10 min. L1–L3 behave as first in, first out among
themselves.

### Estimates

`scan::order::Estimates` (new module), refreshed at most once a minute from
the local, replicated `scan_jobs`:

```
SELECT level, AVG((julianday(finished_at) - julianday(started_at)) * 1440)
FROM scan_jobs
WHERE status IN ('done', 'failed') AND finished_at > datetime('now', '-7 days')
  AND started_at IS NOT NULL
GROUP BY level
```

Each level's value is clamped to `[5, level timeout in minutes]`. A level
with fewer than 5 finished jobs uses the default: L1 5, L2 5, L3 5,
L4 20 minutes.

Every node computes its own estimates from the same replicated rows, so
arbiters and scanners agree closely but not exactly. That is fine: order is
a preference, not a correctness property.

### Where it applies

The `ORDER BY` is built from the estimates as a SQL `CASE` on level (four
bound floats), in:

1. `arbiter::next_job_skipping`: the arbiter's pick.
2. `Source::acquire_local`: the standalone pick.
3. `Source::acquire_granted`: the order in which a scanner asks arbiters.
   Today `ORDER BY MAX(level) DESC, MIN(queued_at)`; becomes the highest
   ratio of any of that arbiter's queued jobs (excluding the scanner's
   `exclude_levels`).

A shared helper builds the expression so the three stay identical.

Unchanged: `outranked_by` (which of two jobs for the same IP runs: higher
level covers lower), full-queue eviction (drops the lowest level), the
cooldown, and the `max_queued` cap.

## 4. Presets

`default_level_argv`, targets appended as today.

| Level | Argv |
|---|---|
| 1 | `-Pn -sS -sV --version-light -T3 --top-ports 100` |
| 2 | unchanged: `-Pn -sS -sV -O -T3 --top-ports 1000 --script ssh-hostkey,ssh2-enum-algos,ssl-cert` |
| 3 | `-Pn -sS -sV -O -T3 --top-ports 1000 --traceroute --script <SCRIPTS>` |
| 4 | `-Pn -sS -sV -O -T3 -p- --max-retries 1 --traceroute --script <SCRIPTS>` (+ `--min-rate`, see 2) |

With `scan.level4_udp = true`, L4 also scans the top 50 UDP ports. `-p-`
and `--top-ports` cannot be combined in one run, so the argv form is
`-sS -sU -p T:1-65535,U:<list>` with the 50 UDP ports listed explicitly
(taken from nmap's `nmap-services` frequency order at plan time and kept as
a constant). Plan-time check: confirm nmap accepts this form with `-sV -O`
and the scripts. If it does not, UDP stays out of this change.

Why:

- L1 drops `-T2`: the 0.4 s pause between probes made L1 slower than L2
  while finding less. `--version-light` names services at small cost.
- L2 is 85 % of all jobs and already the fastest level; any addition costs
  ×30 what it costs at L4.
- L3 and L4 add `--traceroute`: the network path costs a few probes and
  helps attribution.
- `--version-all` is not added: it costs time on every open port.

UDP stays off by default until L4 durations after rollout show room for it.

## Testing

Unit (focused, as the existing ones in `config.rs`, `pace.rs`,
`arbiter.rs`, `scan/mod.rs`):

- Presets: L1 has no `-T2`; L3/L4 have `--traceroute`; L4 has
  `--max-retries 1`; the existing non-intrusive tests (no `-A`, timing
  ≤ `-T3`, script safelist) still pass.
- `nmap_argv`: `--min-rate` added at L4 only, value from config, an
  operator's own `--min-rate` kept.
- Config: `level4_max_share` and `min_rate` ranges; `max_workers = 1`
  rejected; new `level4_timeout_factor` default.
- Pace: `validate` rejects 1 worker; `recommend` never below 2.
- L4 cap: with 2 workers and 1 L4 running, the claim excludes 4; with 0 L4
  running, it does not.
- Arbiter: `exclude_levels` is honoured and not lifted after
  `OVERRIDE_WAIT_MINS`.
- Scanner: an L4 grant over the cap is handed back `"later"`.
- Protocol: unit `Claim` and `Claim { exclude_levels: [] }` encode the same
  and decode both ways.
- Order: estimates clamp and fall back to defaults; a fresh L4 ranks behind
  a fresh L2; an L4 that has waited long enough ranks ahead; ties by
  `queued_at`.

The cluster e2e test (`tests/cluster_e2e.rs`) gets one case: two scanners
with 2 workers, a queue of 4 L4 and 4 L2 jobs, a fake nmap that sleeps; at
no time does a scanner run 2 L4 at once, and L2 jobs start while L4 runs.

## Rollout

1. Deploy to all nodes. Old and new nodes interoperate (see Protocol).
2. Residential sets its own `scan.min_rate` before or with the deploy.
3. After a day, check per-level durations and L4 failures with the query
   used for this spec. Then decide on `scan.level4_udp`, and look again at
   whether any old L4 jobs are still being skipped.

Until every arbiter runs the new version, a capped scanner takes and hands
back one L4 grant per claim from old arbiters (backoff 180 s), and old
arbiters offer it no lower levels until their L4s are in backoff. Upgrade all
nodes promptly.

The UDP argv form (`-p T:1-65535,U:<list>`) is still unverified on a real
nmap; check it before enabling `level4_udp`.

The changelog gets one entry under the next release.
