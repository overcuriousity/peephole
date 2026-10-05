# Public surface: delayed, non-live views

Date: 2026-10-05 · Status: design revised (publisher), awaiting spec review
Part A of the UI rework (B: admin information architecture, C: linking
hub, D: analytics drill-down, E: lookup/global search follow separately).

## Goal

The public pages (wall `/`, `/ips`, `/ip/{addr}`, `/api/stats`,
`/api/map`, `/api/blocklist`) show the last N requests of the last 24 h,
but nothing on them is live. A request becomes visible publicly only
after a delay plus per-row random jitter, and that holds for every
public number, list and page, including pages computed on demand.

### Threat model (decided)

In scope: someone who sends a probe and watches the public pages for a
reaction within seconds or a few minutes, including by opening a page
nobody has viewed before (`/ip/<their address>`, a new `/ips` filter, a
new blocklist parameter set).

Out of scope (accepted, by decision): an attacker who correlates exact
timestamps offline, encodes unique markers in paths, or uses a fresh
source IP per target. Public rows keep exact (minute) timestamps and
paths; every IP is published once its first request is released.

### Why a publisher (decided)

An earlier revision delayed only the response cache. A page nobody had
viewed yet was then computed from live data, so `/ip/<known address>`
right after a probe showed it. Delaying the data itself closes that gap
without making first views wait.

## Current state

- `requests` rows are inserted in one place, `store::data::request`
  (`src/store/data.rs`), for local and replicated records alike.
  Replication is record-based (`Recorder`), so a plain local `UPDATE`
  is never replicated.
- Per-IP read models are kept by triggers (`requests_agg_ai`,
  `requests_agg_ad`, `requests_agg_au`, migration 0001):
  `ips.request_count`, `ips.max_severity`, and `ip_labels.count`.
  `ips.first_seen` / `last_seen` are written by `ensure_ip` and
  `upsert_ip`.
- Public pages read these read models and `requests` directly (about 25
  queries in `src/store/stats.rs`, `src/store/browse.rs`, and
  `src/store/blocklist.rs`). `browse::Audience { Public, Admin }`
  already exists.
- The wall soft-refreshes, shows "last hit *n* s ago" from an unfiltered
  `MAX(ts)`, and `data-ago` times tick every 5 s. `/ip` and `/ips` show
  ticking relative times. The wall's admin-only "Recent activity" card
  is a live SSE feed.

## Design

### 1. Data: pending rows and public read models (migration 0005)

```sql
ALTER TABLE requests ADD COLUMN public_at TEXT;      -- NULL = released
CREATE INDEX idx_requests_pending ON requests(public_at) WHERE public_at IS NOT NULL;

ALTER TABLE ips ADD COLUMN pub_request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_max_severity  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ips ADD COLUMN pub_first_seen TEXT;
ALTER TABLE ips ADD COLUMN pub_last_seen  TEXT;
CREATE INDEX idx_ips_pub_request_count ON ips(pub_request_count, pub_last_seen);
CREATE INDEX idx_ips_pub_last_seen ON ips(pub_last_seen);

ALTER TABLE ip_labels ADD COLUMN pub_count INTEGER NOT NULL DEFAULT 0;

CREATE TABLE publish_cfg (id INTEGER PRIMARY KEY CHECK (id = 1),
                          delay_s INTEGER NOT NULL, jitter_s INTEGER NOT NULL);
```

- **Backfill:** every existing request is already released
  (`public_at` NULL). The migration copies `request_count`,
  `max_severity`, `first_seen`, `last_seen` and `ip_labels.count` into
  the `pub_*` columns for IPs with `request_count > 0`.
- **Public read-model triggers.** The migration drops and recreates the
  three `requests_agg_*` triggers so they keep their current statements
  and also maintain the `pub_*` columns for released rows:
  - insert with `public_at IS NULL` (delay 0, raw test inserts): bump
    both sets of counters;
  - new `requests_pub_release`, `AFTER UPDATE OF public_at` from non-NULL
    to NULL: `pub_request_count + 1`, `pub_max_severity = MAX(…)`,
    `pub_first_seen = MIN(COALESCE(pub_first_seen, ts), ts)`,
    `pub_last_seen = MAX(COALESCE(pub_last_seen, ts), ts)`, and
    `ip_labels.pub_count + 1` for the row's labels;
  - delete of a released row: decrement the `pub_*` counts and recompute
    `pub_max_severity` over released rows. As today for
    `first_seen`/`last_seen`, the seen-times are not recomputed on
    delete;
  - update of `ip_id`/`severity`/`labels_json` on a released row: the
    same move as today, applied to the `pub_*` side.
- `public_at` and the `pub_*` columns are local to each node: never in a
  record, never replicated.

### 2. Insert: setting `public_at`

The delay lives in a one-row local table, `publish_cfg(delay_s, jitter_s)`,
which the migration creates with `(0, 0)`. `Store` writes it once at
startup from config:

```rust
pub async fn set_publish_delay(&self, delay: Duration, jitter: Duration) -> Result<()>
```

The insert trigger `requests_agg_ai` sets
`public_at = datetime('now', '+' || (delay_s + abs(random() % (jitter_s + 1))) || ' seconds')`
(local insert time + delay + random 0..=jitter), or leaves it NULL when
`delay_s + jitter_s = 0`. Tests and tools that never set a delay release
rows at once. The delay starts at this node's insert time, so replicated
or clock-skewed rows can't become public earlier than they arrived here.
No insert code path changes.

### 3. The publisher task

A `tokio` task started in `lib.rs` beside the maintenance task, ending on
shutdown. Every 15 s it releases due rows in chunks of 2000:

```sql
UPDATE requests SET public_at = NULL
 WHERE id IN (SELECT id FROM requests
              WHERE public_at IS NOT NULL AND public_at <= :now
              ORDER BY public_at LIMIT 2000)
```

It repeats until fewer than 2000 rows change, pausing briefly between
chunks like retention does. Errors are logged and the next tick
retries. It writes through `store.pool` directly; `public_at` is not a
replicated column.

### 4. Public reads use only released state

Every query reached by an anonymous request uses the public side
(`Audience::Public`). Admin reads stay unchanged.

| Admin reads | Public reads |
|---|---|
| `requests r` rows | `… AND r.public_at IS NULL` |
| `ips.request_count`, `max_severity`, `first_seen`, `last_seen` | `ips.pub_request_count`, `pub_max_severity`, `pub_first_seen`, `pub_last_seen` (aliased to the old names, so row structs don't change) |
| `ip_labels.count` | `ip_labels.pub_count` (rows with `pub_count > 0`) |
| scans and ports of an IP | only scans with `finished_at ≤ now − delay`, and only of IPs with `pub_request_count > 0` |
| canary tile | only reuses whose using request is released |

In scope:
- `Store::stats(range)` becomes `stats(range, Audience)`.
- `map_counts`; `list_ips` (already takes `IpFilter`, gains the
  audience); `ip_overview` (count, severity, labels, week, calendar,
  rank, neighbours); the public `ip_by_addr` path (an IP with
  `pub_request_count = 0` is a 404 for anonymous visitors); and the
  blocklist queries.
- The admin wall, `/ip`, and `/ips` keep reading fresh admin-side data
  as today.
- `StatsCache` stays: TTL caching for load only, no longer for privacy.

### 5. Wall: "Recent requests" (public)

- The newest `recent_rows` released requests with `ts` in the last 24 h,
  regardless of the selected range.
- Columns: time (UTC, minute precision, static), IP with flag (links to
  `/ip/X`), method, path, severity, labels (only when
  `public.show_labels`).
- The path is shown without the query string, cut to 80 characters
  (ending in "…"), and not linked. Askama escapes it. Cutting limits
  graffiti that scanners write into paths.
- Signed-in admins see the same card with admin-side data, which
  includes pending rows.

### 6. Live elements removed from public pages

| Where | Today | After |
|---|---|---|
| Wall | soft refresh, "updated HH:MM:SS" | removed; static page |
| Wall | "last hit *n* s ago" pulse | removed; muted line "Data delayed by about D–D+J min" (signed in: "Live view (signed in); the public sees this D–D+J min later") |
| Wall, `/ip`, `/ips` | ticking `data-ago` relative times | static absolute UTC times, minute precision |

The `data-ago` ticker stays in `app.js` for admin pages.

### 7. Admin side

- `/admin` (Overview) gets the live "Recent activity" card that moved off
  the wall, with the unchanged SSE feed `/admin/api/recent` and its JS.
- Admin views of requests, IPs and analytics include pending rows.

### 8. Settings

`[public]` in `config.toml`:

| key | default | allowed |
|---|---|---|
| `delay_minutes` | 5 | 0–60; 0 with `jitter_minutes = 0` releases immediately and logs a warning at startup |
| `jitter_minutes` | 5 | 0–60 |
| `recent_rows` | 50 | 1–200 |

Validated in `Config::validate`. Documented in
`deploy/config.example.toml`, `docs/operations.md`, and `CHANGELOG.md`.
A changed delay applies to rows inserted after the restart.

## Testing

- **Migration:** an existing database keeps every row released, and the
  `pub_*` columns equal their admin-side counterparts after migrating.
- **Triggers:**
  - insert pending → admin counters move, `pub_*` don't;
  - release → `pub_*` catch up (count, max severity, first/last seen,
    label counts);
  - deleting a released or a pending row adjusts the right side;
  - reclassification (`UPDATE severity/labels_json`) of a released row
    moves `pub_*`.
- **Insert:** with delay D and jitter J, `public_at` lies in
  `[now + D, now + D + J]`; with zero it is NULL.
- **Publisher:** releases only due rows, in chunks; is idempotent; stops
  on shutdown.
- **Public queries** (one test per surface): a pending request from a
  new IP is invisible on the wall, `/api/stats`, `/api/map`, `/ips`,
  `/ip/{addr}` (404), the blocklist, and "Recent requests". A pending
  request from a known IP changes nothing public (count, last seen,
  labels, week chart). After release all of them show it. Admin views
  show it at once.
- **Pages:**
  - the anonymous wall has no `data-refresh`, `data-ago`, pulse or SSE;
  - "Recent requests" drops the query string, cuts paths at 80
    characters, and hides labels when `show_labels = false`;
  - `/admin` has the live feed.
- **Config:** bounds are enforced.
- `cargo test`, `cargo clippy`, `cargo fmt --check` stay clean.

## Out of scope

- Admin information architecture (part B) and the rest of the rework
  (C–E).
- Content k-anonymity, coarse public timestamps, an IP publication
  threshold (excluded by the threat-model decision).
- Recomputing seen-times on delete (the admin side doesn't either).
