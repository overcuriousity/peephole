# Admin information architecture (UI rework, piece B)

Date: 2026-10-05 · Status: design approved, spec for review.
Roadmap: `2026-10-05-ui-rework-roadmap.md` (piece B). Constraints from piece A:
`2026-10-05-public-delay-design.md`.

## Goal

Make the admin area easy to find one's way in: every fact lives on one page,
Overview / Queue / Scans stop overlapping, and the Cluster page stops being
overwhelming. B fixes the structure (nav, pages, where each card lives); it
does not restyle anything and does not build pieces C (Links), D (drill-down)
or E (global search), but leaves their places ready.

Success:

- The admin subnav has 7 tabs, each page has one job, and no card appears on
  two pages.
- Every feature that exists today is still reachable; no link is dead; old
  GET URLs redirect.
- No public page becomes live or reads unreleased data.

## Decisions

| Topic | Decision |
|---|---|
| Fingerprints, Canaries, Lookup until C/E | Final nav now. "Links" tab over today's Fingerprints and Canaries pages (sub-tabs); Lookup as an IP box in the top bar |
| Requests / IPs | Stay in the top bar only, not in the admin subnav |
| Queue model | Live card holds only queued + running jobs; finished jobs in a server-side, paginated, filterable history |
| Overview "needs attention" | Seven items, computed at page load, reusing existing checks |
| Settings home | A "System" tab with sub-tabs Status · Settings · Keys · Export |
| Code layout | Modules follow the new sections (`overview.rs`, `scans.rs`, `system.rs`, `cluster_access.rs`) |

## 1. Navigation, System, Lookup box, redirects

**Top bar** (`layout.html`): unchanged links (Wall · IPs · Requests · Admin).
For signed-in users, `topbar-actions` gains a small
`<form method="get" action="/admin/lookup">` with one `ip` input. E replaces it
with global search. Nothing renders for anonymous visitors.

**Admin subnav** (`_admin_nav.html`):
Overview · Analytics · Scans · Links · Inbox · Cluster · System.

The highlighted tab comes from the `sub` key each page sets:

| Page | `sub` |
|---|---|
| `/admin` | `home` |
| `/admin/analytics` | `analytics` |
| `/admin/scans`, `/admin/scans/{id}` | `scans` |
| `/admin/fingerprints`, `/admin/canaries` | `links` (tab href: `/admin/fingerprints`) |
| `/admin/inbox` | `inbox` |
| `/admin/cluster`, `/admin/cluster/access`, `/admin/cluster/node/{key}` | `cluster` |
| `/admin/system`, `/admin/system/settings`, `/admin/system/keys`, `/admin/system/export` | `system` |
| `/admin/lookup` | none |

**Sub-tab bar** (`_subtabs.html`): a second, smaller `seg` row, drawn like the
subnav from a list of `(key, href, label)` and the current key (`subtab`).

- Links: Fingerprints (`/admin/fingerprints`) · Canaries (`/admin/canaries`)
- Cluster: Members (`/admin/cluster`) · Access (`/admin/cluster/access`;
  only in a cluster)
- System: Status · Settings · Keys · Export

**System** (new `src/admin/system.rs`):

- `/admin/system` (Status):
  - Intel feeds: Tor exit list, MaxMind (including "via a cluster member"),
    and each API provider's state (`api_provider_states`, moved from
    `pages.rs`). The "older than 48 h" banner moves here with the card.
  - Shared intel (moved from Cluster; shown only in a cluster), with its
    "GeoIP databases stay local" note.
  - This binary's version and built-in rules fingerprint.
- `/admin/system/settings`: the `_node_settings.html` form (cooldown, roles)
  and the settings audit table (both moved from Cluster's "this node" card).
  The form still posts to `/admin/cluster/settings`, which now redirects
  here.
- `/admin/system/keys`, `/admin/system/export`: today's Keys and Export pages,
  unchanged apart from the sub-tab bar. `/admin/keys/delete` and
  `/admin/export/download` keep their paths; key removal redirects to
  `/admin/system/keys`; `app.js` goes to `/admin/system/keys` after
  enrollment.

**Redirects** (308, GET only): `/admin/keys` → `/admin/system/keys`,
`/admin/export` → `/admin/system/export`, `/admin/queue` → `/admin/scans`
(section 2). Every POST keeps its path.

Templates linking to moved pages are updated: `admin_cluster.html` and
`admin_queue.html` links to `/admin/queue` and `/admin/cluster` for pace now
go to `/admin/scans`; `ip.html` and `request.html` keep their
`/admin/fingerprints#…` and `/admin/canaries?…` links (those URLs stay).

## 2. Scans (`src/admin/scans.rs`, `/admin/scans`)

One page, three cards, top to bottom.

**Pace** (`#pace`): the current Queue page's pace card, moved unchanged:
tiles, the two sparklines, the pace form, the recommendation, and the
timeout / growing / not-scanning banners. In a cluster a "Scanners" part
(`#scanners`) follows: the scanner pace table and its level-weights note,
moved from Cluster (`_cluster_pace_row.html`). `/admin/cluster/pace` keeps
its path and redirects to `/admin/scans#scanners`. The not-scanning banner
links to `#scanners`.

**Live queue**: queued and running jobs only; the live indicator sits in this
card's head.

- Store: `active_jobs(limit)`: `QUEUE_JOB_SQL` with
  `WHERE j.status IN ('queued','running') ORDER BY j.id DESC LIMIT ?`.
  The page and the SSE snapshot (`sse.rs::snapshot_or_comment`) both use it,
  so a backlog larger than the limit no longer hides the oldest queued jobs.
  `SNAPSHOT_ROWS` stays 500.
- JS (`app.js`, live queue): the status/level filter attributes go; a row
  matches when its status is `queued` or `running`. A `job` event that moves
  a job to any other status removes its row.
- `queue_snapshot` stays only if something else still uses it; otherwise it
  is removed.

**History**: finished jobs, server-side, paginated (`_pagination.html`).

- GET filters: `status` (done · failed · superseded · refused · empty = any
  finished) and `level`: `/admin/scans?status=failed&level=3&page=2`.
- Store: `job_history(filter, page) -> Page<HistoryRow>` over `scan_jobs`
  with `status NOT IN ('queued','running')`, `ORDER BY j.id DESC`,
  `LEFT JOIN scans s ON s.job_id = j.id` for scan id, OS guess and open-port
  count. Replicated scans already carry the local `job_id` (resolved through
  `job_uid` in `store/data.rs`), and `idx_scans_job` /
  `idx_scan_jobs_status` cover the join and the filter: no migration.
- Columns: Job · Target · Level · Status · Finished · Result · Node.
  Result: for a job with a scan, a link to `/admin/scans/{id}` with open
  ports and OS guess; for a failed job, the error text; otherwise empty.
- This replaces today's completed-scans list (`list_scans` is removed if
  nothing else uses it).
- With `status=failed`, the card shows "Retry failed (last 7 days, one per
  IP)", posting to `/admin/queue/retry-failed` as today. It redirects to
  `/admin/scans?status=failed&retried=N`. The label names the 7-day scope
  because the list can show older failures.

**Notices**: `?saved=1` and `?retried=N` render as today's success banners.

**Routes**: `/admin/scans/{id}`, `/xml`, `/delete` stay (delete redirects to
`/admin/scans`). `GET /admin/queue` → 308 `/admin/scans`, carrying `status`
when it is a finished status. `/admin/queue/pace` and
`/admin/queue/retry-failed` keep their paths and redirect to `/admin/scans`.

## 3. Overview (`src/admin/overview.rs`, `/admin`)

"What is happening, and what needs me". Top to bottom:

**Needs attention**: `attention(st) -> Vec<Attention>` with
`Attention { level: Warn | Info, text: String, href: String }`, computed on
page load. The strip renders only the items that apply and is absent when
none do.

| Item | From | Links to |
|---|---|---|
| N inbox claims | `inbox_count` | `/admin/inbox` |
| N scans failed in 24 h | `queue_summary().failed_24h` | `/admin/scans?status=failed` |
| Queue growing; timeouts high | `queue_metrics` + `recommend` (the same checks as the pace banners, without sparklines) | `/admin/scans#pace` |
| Intel stale | `intel_stale` | `/admin/system` |
| Node X not seen for … | `cluster::views` | node page |
| Node X: issues (see `MemberView::issues`) | `cluster::views` with the cached rules check | node page |
| Detached; history incomplete | `node.detached()`, `cluster::unserved` | `/admin/cluster` |

The builder calls existing functions. Where they are private today
(`pages.rs::pace_view` internals, `cluster::views`, `cluster::unserved`,
`intel_stale`) they are made `pub(crate)` or split so the cheap part can be
called without the rest; no check is copied.

**Headline tiles**, each a link:

| Tile | Value | Links to |
|---|---|---|
| Requests · 24 h | `total_requests` | `/requests` |
| New IPs · 24 h | `new_ips` | `/ips` |
| Queued / running | `queue_summary` | `/admin/scans` |
| Done · 24 h | `queue_summary().done_24h` | `/admin/scans?status=done` |

Request and IP numbers come from a new `StatsCache::admin_stats(store, r)`:
`stats_as(r, Audience::Admin)` behind the same SWR cache and TTL as the
public `stats`. Admin numbers are therefore current, not delayed.

**Recent activity**: unchanged (SSE `/admin/api/recent`, its own live
indicator).

**Removed**: the scan queue card, Recent failures, the Intel card, the stale
banner, and the Started-this-hour / Failed tiles. All now live on Scans,
System or in the strip.

## 4. Cluster (`src/admin/cluster.rs`, new `src/admin/cluster_access.rs`)

**Members** (`/admin/cluster`):

- The detached and history-incomplete banners stay on top.
- One table, this node first and marked "this node":

| Node | Status | Seen | Lag | Issues |
|---|---|---|---|---|
| name + short key, links to the node page | live / inactive state / blocked / purged | last seen | replication lag | one badge ("2 issues") with the list as tooltip; empty when none |

- `MemberView::issues() -> Vec<String>`: incompatible version, clock skew,
  rules differ (agreement), ruleset differs (carried fingerprint), last
  error. Overview uses the same function.
- Moved away: roles, address, version, history, Configure, block/purge
  dialogs and contributions (node page); scanner pace (Scans); shared intel
  and own settings (System); invites, config key, join and leave (Access).

**Node page** (`/admin/cluster/node/{key}`, this node included):

- Renders from local data (`views()`, the matching `MemberView`) first, so it
  works without a config key and when the node does not answer.
- Head: name, short key, status badge; Block / Unblock / Purge with today's
  dialogs (not for this node).
- Details: key (copy button), roles and lookup providers, address, version,
  last seen, lag, history, running scans, clock skew, last error.
- Rules: carried fingerprint, agreement, and the
  `peephole cluster agreement <short>` hint.
- Contributions: this node's row of today's contributions table.
- Pace (scanners): read-only, linking to `/admin/scans#scanners`.
- Remote settings: today's form, only when this node holds its config key.
  Only this card asks the node live; when it does not answer, the card shows
  "did not answer: …" and the rest of the page renders. For this node the
  card is replaced by a link to `/admin/system/settings`.
- `/admin/cluster/block`, `/unblock`, `/purge`, and the node settings POST
  keep their paths and redirect to the node page.

**Access** (`/admin/cluster/access`, only in a cluster):

- Invites: create form, the one-time token (shown after `create_invite`),
  table with revoke.
- This node's config key: show / rotate, or the "locked" notice.
- Configure another node: add key.
- Join or rejoin.
- Leave cluster, last, as a danger zone.

The POSTs keep their paths; `back()` takes a target so these return to
`/admin/cluster/access`.

**Standalone**: `/admin/cluster` shows only the "add `[cluster]` to
config.toml" card; the Access sub-tab is not shown and
`/admin/cluster/access` returns 404.

## 5. Rollout, compatibility, docs, risks

**Steps**, each leaving the app working and tests green:

1. Nav, `_subtabs.html`, System, Lookup box, keys/export redirects. Intel
   and settings are copied to System; the old cards stay until steps 3-4.
2. Scans: `scans.rs`, `active_jobs`, `job_history`, SSE snapshot, JS filter,
   scanner pace moved, `/admin/queue` redirect.
3. Overview: `overview.rs`, `attention`, `admin_stats`, new tiles; old cards
   removed.
4. Cluster: members table, node page, Access; shared intel and settings
   removed from the Cluster page.

**Compatibility**: every POST keeps its path (CLI, scripts and cluster
remote configuration are unaffected); old GET pages redirect. No schema
change.

**Constraints from A**: no public template or handler changes except the
Lookup box, which renders only when `chrome.authed`. Live indicators stay in
their own cards (Scans' live queue, Overview's Recent activity).

**Docs**: README admin section and any docs naming Queue, Keys, Export or the
Cluster page's cards; the roadmap marks B done and links this spec.

**Tests**:

- Step 1: the auth-required page list (`tests/integration.rs`) gets the new
  URLs; each old URL redirects to its new one; the right subnav and sub-tab
  are current.
- Step 2: a backlog above the limit still lists the oldest queued job;
  `job_history` with `status=failed` returns only failed jobs; a done job
  links to its scan; retry redirects to the failed filter; existing pace and
  retry tests move to `/admin/scans`; `tests/cluster.rs` checks of
  `/admin/queue` and `/admin/scans` follow.
- Step 3: one unit test per attention item (condition on → item; off →
  none); Overview has no queue or intel card, tiles link through, and a
  seeded failed job shows in the strip.
- Step 4: members table has the five headers; a node with skew shows the
  issues badge; the node page renders without a held key; an invite token
  appears on Access; block redirects to the node page; standalone hides
  Access.

**Risks**:

- The first Overview load after a restart waits for the rules comparison
  (then cached for 10 min), as the Cluster page does today.
- Moving code out of `pages.rs` is mostly cut and paste; each step runs
  `cargo test` and `cargo clippy`.

## Out of scope

The merged Links page (C), chart drill-downs and filter extensions (D),
global search (E), and any visual restyling.
