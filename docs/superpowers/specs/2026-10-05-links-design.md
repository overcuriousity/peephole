# Links: what ties IPs together (UI rework, piece C)

Date: 2026-10-05 · Status: implemented (branch `links`).
Roadmap: `2026-10-05-ui-rework-roadmap.md` (piece C). Constraints from piece A
(`2026-10-05-public-delay-design.md`) and piece B
(`2026-10-05-admin-ia-design.md`).

## Goal

Clicking a fingerprint, host key, certificate, JA4/JA4H/HASSH/JA4X or canary
anywhere in the admin area lands on a graph that actually helps: centred on
that item, showing the IPs it was seen on and what else links those IPs.
Fingerprints and Canaries become one "Links" area. This is not a core
feature: keep it simple.

Success:

- Every such value in the admin UI links to its item page.
- The item page's graph stays legible: one value on thousands of IPs never
  floods it.
- The index lists every value of every kind, not only shared ones, and can be
  filtered and sorted.
- Old URLs and deep links keep working.
- Admin-only; no public page changes.

## Decisions

| Topic | Decision |
|---|---|
| What a click lands on | One page per item, `/admin/links/<kind>/<value>`, centred on it (not a filtered list) |
| Identity vs software | Identity links (browser fingerprint, SSH host key, TLS certificate, canary reuse) tie sources to one operator; software links (JA4, JA4H, HASSH, JA4X) only say "same tool". The graph walks identity links by default; software kinds are opt-in checkboxes |
| Flooding | A value on more than K = 25 IPs is drawn as one collapsed "N IPs" node, expanded on demand (hard cap 500); a graph stops at 400 nodes and says so |
| Graph engine | Server computes the neighbourhood as JSON; a small vanilla-JS renderer (`linkgraph.js`) lays it out (seeded radial + short force relax). No ELK, no dependencies. Ideas taken from effractor: pointer-anchored clamped zoom, fit that never upscales, highlight by class with fading, wide edge hit paths, collapsed super-node, glide on expand |
| Index | List only, no "all clusters" graph and no top-N slider: sorting by IPs is the overview |
| Canaries page | Moves under Links unchanged, plus a link per reuse to the canary's item page |
| JS tests | None: the repo has no JS test setup and this is not worth adding one for. Everything testable sits in the Rust store and routes |

## Pages and URLs

- `/admin/links` (sub-tab "Fingerprints"): the index. One table with a `kind`
  select grouped into *Identity* (`fp`, `ssh`, `tls`) and *Software* (`ja4`,
  `ja4h`, `hassh`, `ja4x`); default `fp`. Filters below. Each row: value
  (shortened, copy button), IPs, sightings, first seen, last seen; the value
  links to the item page.
- `/admin/links/canaries` (sub-tab "Canaries"): today's canary page
  (KPIs, per-kind table, reuse filters and table), same query parameters.
  The reuse table gains a column linking to `/admin/links/canary/<value_hash>`.
- `/admin/links/<kind>/<value>`: the item page. Kinds: `fp`, `ssh`, `tls`,
  `ja4`, `ja4h`, `hassh`, `ja4x`, `canary` (value: the canary's
  `value_hash`), `ip` (value: an address; "what links this IP"). Unknown kind:
  404. Known kind, value never seen: the page with "not seen" and no graph.
  - Left: the graph card. Right: the facts panel. For an item: kind, full
    value with copy button, first/last seen, sightings, IP count, countries,
    nodes (request-based kinds), nmap `detail` (`ssh`, `tls`), and
    "Requests with this value" → `/requests?ja4=…` / `?ja4h=…` for those
    kinds. Below: the full IP list (IP → `/ip/<addr>`, country, ASN,
    sightings, last seen). For `ip`: a short summary and a link to
    `/ip/<addr>`.
  - Clicking a graph node replaces the panel's top part with that node's
    facts (from the graph JSON; no extra request).
- `LINKS_TABS` → `("fingerprints", "/admin/links", "Fingerprints")`,
  `("canaries", "/admin/links/canaries", "Canaries")`. The admin nav's
  "Links" points at `/admin/links`.

### Old URLs and deep links

| Old | New |
|---|---|
| `GET /admin/fingerprints` | 308 → `/admin/links` |
| `GET /admin/canaries?…` | 308 → `/admin/links/canaries?…`, query string kept (`?ip=` from `ip.html`, `?range=` from Analytics) |
| `/admin/fingerprints#<x>` | The fragment never reaches the server; browsers keep it across the 308. A few lines of JS on the index (in `app.js`) read `location.hash` and `location.replace` it with `/admin/links?anchor=<x>`. The server resolves `anchor`: a browser fingerprint hash → its item page; `ssh-…` / `tls-…` (the shortened anchors of `hostkeys::anchor`, which drop non-alphanumerics, so no prefix match on the stored value works) → the host key whose `anchor()` equals it, found by computing `anchor()` over that kind's distinct fingerprints → its item page (302). No match: the index with a "not found" note |

Values in item URLs are percent-encoded (`|urlencode`); SSH fingerprints are
base64 and contain `/` and `+`.

Neither page has POST routes. Templates link to the new URLs directly; the
redirects only serve bookmarks and open tabs.

## Data (`src/store/links.rs`)

Nothing new replicates: every source is already replicated or derived on each
node.

| kind | IPs come from | identity |
|---|---|---|
| `fp` | `fingerprints(fp_hash, ip_id, ts)` | yes |
| `ssh`, `tls` | `host_keys` with kind `ssh-hostkey` / `tls-cert` | yes |
| `canary` | `canaries.ip_id` (served) ∪ the `ip_id` of requests in `request_tokens` with that `value_hash` (used), only canaries used again (as `REUSE_SELECT` defines reuse) | yes |
| `ja4`, `ja4h` | `requests` | no |
| `hassh`, `ja4x` | `host_keys` | no |

A `LinkKind` enum holds the URL name, display name, identity flag and the
SQL for "IPs of a value" and "values of an IP". `host_keys` sightings count
rows (one per scan and port), as `host_key_clusters` does today; their time is
the scan's `finished_at`.

### `links_list(&LinkFilter) -> Page<LinkRow>`

`LinkFilter` (serde, names and formats as `RequestFilter`, `lenient_i64` for
numbers):

- `kind` (default `fp`), `q` (prefix of the value, case-insensitive for hex),
  `shared` (`1` default: more than one IP; `0`: all), `from`, `to`
  (`ts_bound` as `RequestFilter`), `country`, `node`, `sort` = `ips`
  (default) | `sightings` | `recent`, `page` (`browse::PAGE_SIZE` rows, the
  shared pager; no total count).
- Every filter narrows the sightings, and counts are over the matching
  sightings: with `country=DE`, a value is listed if it was seen on an IP in
  Germany, and its IP count is its German IPs.
- `node` applies to request-based kinds (`fp` via the fingerprint row's
  `origin`, `ja4`, `ja4h`, `canary` via either side); for `ssh`, `tls`, `hassh`,
  `ja4x` the field is shown disabled and ignored.
- `LinkRow`: value, ips, sightings, first_seen, last_seen.

### `link_item(kind, value) -> Option<LinkItem>`

Facts and the full IP list (ip, country, asn, sightings, last_seen), most
sightings first, capped at 1000 rows with a "+N more" note.

### `link_graph(focus, depth, types, all) -> LinkGraph`

Breadth-first from `focus` (`<kind>:<value>` or `ip:<addr>`), `depth` 1–3
(default 2) hops where one hop is item→IPs or IP→items; `types` the kinds to
walk (default the identity kinds; the focus' own kind is always walked).

- item → IPs: more than K = 25 IPs and not `all`: one group node
  `group:<kind>:<value>` labelled with the count, not walked further. With
  `all=1` (expanding a group): up to 500 IPs.
- IP → items: values of the walked kinds on that IP.
- Stop at 400 nodes; `truncated: true` in the answer.
- Node: `{id, kind, label, ips?, sightings?, first_seen?, last_seen?,
  country?}` (enough for the panel). Edge: `{a, b, identity}`.
- Ids are `ip:<addr>`, `<kind>:<value>`, `group:<kind>:<value>`; merging an
  expansion is a union by id.

API: `GET /admin/api/links/graph?focus=…&depth=…&types=…&all=…` (session
required, JSON). Bad `focus` or kind: 400. `depth` clamped to 1–3; unknown
`types` ignored.

### Migration `0006_links.sql`

`CREATE INDEX idx_requests_ja4 ON requests(ja4, ip_id) WHERE ja4 IS NOT NULL;`
(as `idx_requests_ja4h`). Analytics' windowed `ranked_fp` already keeps such
an index out of its plan with `+`.

## Graph UI (`assets/js/linkgraph.js`)

Replaces `fpGraph` in `charts.js` (deleted, with its legend CSS and the
`data-fp-graph` boot code). Loaded only on the item page. Vanilla JS, no
dependencies, CSS in `assets/css/` (never `assets/app.css`).

- Layout: focus fixed at the centre; one ring per hop; nodes on a ring
  ordered by their parent's angle; then about 150 seeded force steps (springs
  along edges, repulsion, pull to the ring's radius). Deterministic for the
  same data. On an expansion, nodes already drawn keep their positions; new
  ones start at their parent and glide out (about 250 ms; none with
  `prefers-reduced-motion`).
- SVG: `svg > g.viewport > g.edges, g.nodes`, styled by class only. Items:
  rounded squares coloured by kind; IPs: circles; groups: larger circles with
  the count. Software edges dashed. Labels: the IP, or kind plus 8 characters
  of the value; the full value in `<title>`. Each edge has a wide invisible
  hit path.
- Pan by dragging the background; wheel zooms about the pointer, pinch on
  touch, clamped 0.2–4×. "Fit" frames the graph and never zooms in past 1×;
  it runs on first draw.
- Hover or keyboard focus (nodes are focusable): the node and its neighbours
  light up, the rest fades (`has-hl` on the svg).
- Click selects a node: the panel shows its facts with two buttons, *Open*
  (`/ip/<addr>` or the item page) and *Expand* (depth 1 from that node, or
  `all=1` for a group, merged in). No node dragging.
- Toolbar: one checkbox per kind (identity on, software off), depth 1–3,
  Fit, and a "truncated at 400 nodes" note when it applies. Changing a
  checkbox or the depth refetches the graph. `types` and `depth` live in the
  query string (`replaceState`), so a view can be shared; the server reads
  them too, for the first fetch.
- A failed fetch shows a one-line error in the graph card and keeps the
  current graph. Without JS the item page still has the facts panel and IP
  list; the graph card says it needs JavaScript.

## Entry points

Every value links to its item page:

| Where | Links |
|---|---|
| `ip.html` admin section | browser fingerprints → `/admin/links/fp/<h>`; new "Link graph" → `/admin/links/ip/<addr>`; canary line → `/admin/links/canaries?ip=…` |
| `request.html` | fingerprint, JA4 (today unlinked), JA4H → item pages |
| `_host_keys.html` | every row's value → its item page (SSH and TLS as today; HASSH and JA4X new). The "N linked" badge keeps its identity-only meaning |
| `admin_analytics.html` | JA4, JA4H, HASSH, JA4X tables → item pages; the canary link → `/admin/links/canaries?range=…` |
| Canary reuse table | new column → `/admin/links/canary/<value_hash>` (`Reuse` gains `value_hash`) |

`RequestFilter` gains `ja4` (admin only, like `ja4h`), so the item page's
"Requests with this value" works for JA4.

## Drill-down gaps (piece D)

- Closed by C: `RequestFilter.ja4`; the JA4, JA4H, HASSH and JA4X tables on
  Analytics link somewhere.
- Made unnecessary: HASSH / JA4X on `IpFilter` (the item page lists those
  IPs).
- Left to D: method, transport, answer, user agent on `RequestFilter`; port,
  product, OS on `IpFilter`.

## Docs

README's admin pages list and `docs/dataset.md` where they name the
Fingerprints / Canaries pages; the roadmap's C row → done, with this file.

## Testing

- Store: `links_list` per kind, `shared`, `q` prefix, `from`/`to`, `country`,
  `node` (and ignored for scan kinds), each sort, paging; `link_item` for
  each kind and for an unknown value; `link_graph` walks identity kinds only
  by default, walks software kinds when asked, collapses above K, expands a
  group with `all`, truncates at 400, respects depth; canary IPs include
  served and used side.
- Query plans: JA4 lookups by value use `idx_requests_ja4`; Analytics'
  windowed JA4 ranking does not (extends the existing plan test).
- Routes: both 308s keep the query string; unknown kind → 404; unseen value
  → 200 with "not seen"; an SSH fingerprint with `/` and `+` round-trips
  through its item URL; `?anchor=` resolves a fingerprint hash and an
  `ssh-`/`tls-` anchor, and falls back to the index; the graph API clamps `depth`, rejects a bad
  `focus`, requires a session.
- Templates: the entry points above render links to item pages (existing
  page tests extended).
- The graph itself: checked by hand in the browser (layout, zoom, expand,
  truncation note, light and dark theme).
