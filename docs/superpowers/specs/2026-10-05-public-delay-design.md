# Public surface: delayed, non-live views

Date: 2026-10-05 · Status: approved design, awaiting spec review
Part A of the UI rework (B: admin information architecture, C: linking
hub, D: analytics drill-down, E: lookup/global search follow separately).

## Goal

The public pages (wall `/`, `/ips`, `/ip/{addr}`, `/api/stats`,
`/api/map`, `/api/blocklist`) show the last N requests of the last 24 h,
but nothing on them is live: every change becomes visible only minutes
after it happened, with per-row jitter. This keeps a **casual live
watcher** from correlating their own probes with what the wall shows and
so learning which addresses are our nodes.

### Threat model (decided)

In scope: someone who sends a probe and watches the public pages for a
reaction within seconds or a few minutes.

Out of scope (accepted, by decision): an attacker who correlates exact
timestamps offline, encodes unique markers in paths, or uses a fresh
source IP per target. Public rows keep exact (minute) timestamps and
paths; every IP is still published once its delay has passed.

## Current state

- Anonymous public reads go through `StatsCache` / `SwrCache`
  (`src/store/stats.rs`), which serve the newest computed value (TTL
  15 s for the 24 h wall, 30 s for IP pages, 60 s blocklist).
- The wall soft-refreshes itself (`assets/js/charts.js`, "Soft
  refresh"), shows "last hit *n* s ago" from an unfiltered `MAX(ts)`,
  and `data-ago` times tick every 5 s (`assets/js/app.js`).
- `/ip/{addr}` and `/ips` show `first_seen` / `last_seen` as ticking
  relative times; a just-seen IP is reachable within the cache TTL.
- Denormalised counters (`ips.request_count`, `max_severity`,
  `first_seen`, `last_seen`, `ip_labels`) update on insert, so a plain
  "rows older than X" filter cannot delay them.
- The wall's admin-only "Recent activity" card is a live SSE feed
  (`/admin/api/recent`).

## Design

### 1. Held-back cache

`SwrCache` keeps, per key, a short queue of `(computed_at, value)`
versions instead of one value, and gains a `hold: Duration`:

- **Serve** the newest version with `now − computed_at ≥ hold`.
- **Recompute** (in the background, single-flight as today) when the
  newest version, served or still aging, is older than the refresh
  interval R = 60 s. The new version joins the queue and ages.
- **Cold key** (no version old enough): compute now and serve it. This is
  safe only together with the IP-visibility condition in §2.
- **Prune** versions older than the one being served. A hot key holds
  about (hold + R) / R versions (6 at the defaults); the existing
  bounds on the number of keys stay.
- `hold = 0` reproduces today's behaviour exactly.

The decision logic is a pure function so it can be tested without real
time:

```rust
fn pick(versions: &[Instant], now: Instant, hold: Duration, refresh: Duration)
    -> (Option<usize> /* serve */, bool /* recompute */)
```

Anonymous public pages, `/api/stats`, `/api/map` and `/api/blocklist`
use `hold = delay`. Admin reads keep bypassing the cache.

Effect: a change shows up publicly between D and D + R after it
happened. Wall aggregates move in steps of R (accepted). Caches are in
memory, so the first view after a restart is computed fresh (accepted).

### 2. IP visibility condition (anonymous only)

Every public query that can reveal an address gets:

```sql
i.first_seen <= datetime(:now, '-' || (:delay_s + jitter(i.id)) || ' seconds')
```

It is applied in `public_ip_filter` / the directory search, the public
`ip_by_addr` path of `/ip/{addr}` (a hidden IP is a 404), the map and
country counts, and the blocklist query. Admin queries do not get it.

Because of this, a cold key computed "now" cannot show an IP that
appeared within the last D + jitter. Later changes to a known IP reach
the public only through held-back versions.

Accepted gap: for an IP that arrives by cluster replication,
`first_seen` is when the source node first saw it, so on this node the
IP can become public as soon as the record arrives.

### 3. Jitter

```text
jitter(id) = (id * 2654435761) % (J * 60 + 1)   seconds, 0 ≤ jitter ≤ J min
```

This is computed in SQL and is deterministic: the same on every node
and across restarts, so a row never flickers in and out of view. It is
not secret, but row and IP ids are never shown publicly.

### 4. Wall: "Recent requests" (public)

- The newest `recent_rows` requests within the last 24 h, regardless of
  the selected range, taken when the cached version is computed, keeping
  only rows with `ts ≤ computed_at − jitter(r.id)`. Each row's effective
  delay is therefore D + aging + its own jitter, and rows near the edge
  appear one at a time.
- Columns: time (UTC, minute precision, static), IP with flag (links to
  `/ip/X`), method, path, severity, labels (only when
  `public.show_labels`).
- The path is shown without the query string, cut to 80 characters
  (ending in "…"), and not linked. Askama escapes it. Cutting limits
  graffiti that scanners write into paths.
- It replaces the admin-only live "Recent activity" card on the wall for
  everyone.

### 5. Live elements removed from public pages

| Where | Today | After |
|---|---|---|
| Wall | soft refresh, "updated HH:MM:SS" | removed; static page |
| Wall | "last hit *n* s ago" pulse (`MAX(ts)`) | removed; muted line "Data delayed by about D–D+J min" |
| Wall, `/ip`, `/ips` | ticking `data-ago` relative times | static absolute UTC times, minute precision |

The `data-ago` ticker stays in `app.js` for admin pages. Signed-in
admins see the same static public templates (fresh data); their delay
line reads "Live view (signed in); the public sees this D–D+J min
later."

### 6. Admin side

- `/admin` (Overview) gets the live "Recent activity" card with the
  unchanged SSE feed `/admin/api/recent` and its markup and JS.
- No replication changes; each node's cache is local.

### 7. Settings

`[public]` in `config.toml`:

| key | default | allowed |
|---|---|---|
| `delay_minutes` | 5 | 0–60; 0 turns the hold-back and the IP condition off and logs a warning at startup |
| `jitter_minutes` | 5 | 0–60 |
| `recent_rows` | 50 | 1–200 |

Validated in `Config::validate`. Documented in
`deploy/config.example.toml`, `docs/operations.md`, and `CHANGELOG.md`.

## Testing

- `pick`: serves the newest version at least `hold` old; a cold key
  computes and serves; recomputes after R; the version queue stays
  bounded; `hold = 0` matches today.
- Store:
  - an IP within D + jitter is missing from directory search,
    public `ip_by_addr`, map and country counts, and the blocklist, and
    present for admins;
  - the recent list leaves out rows newer than `computed_at − jitter`;
  - `jitter` stays within `[0, J·60]`.
- Pages:
  - the anonymous wall has no `data-refresh`, `data-ago`, pulse or
    `data-recent` SSE;
  - "Recent requests" drops the query string, cuts paths at 80
    characters, and hides labels when `show_labels = false`;
  - anonymous `/ip/{fresh}` is 404;
  - `/admin` has the live feed.
- Config: bounds are enforced.
- Existing tests that read public pages anonymously set
  `delay_minutes = 0`.
- `cargo test`, `cargo clippy`, `cargo fmt --check` stay clean.

## Out of scope

- Admin information architecture (part B) and the rest of the rework
  (C–E).
- Content k-anonymity, coarse public timestamps, an IP publication
  threshold (excluded by the threat-model decision).
- Persisting held-back versions across restarts.
