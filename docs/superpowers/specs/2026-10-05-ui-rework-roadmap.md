# UI rework: roadmap

Date: 2026-10-05 · Status: brainstormed, not designed. Each piece gets its own
spec → plan → implementation cycle.

The rework splits into five mostly independent pieces. A and B are done; this file
keeps what was found and decided for the rest, so a new session can start
from here.

| # | Piece | Depends on | Status |
|---|---|---|---|
| A | Public privacy: delayed, jittered public surface, no live elements | — | done: `2026-10-05-public-delay-design.md` |
| B | Admin information architecture: nav, Overview/Queue/Scans merge, Cluster cleanup | — | done: `2026-10-05-admin-ia-design.md` |
| C | Fingerprints + Canaries → one page about what links IPs | B (nav); shares filters with D | done: `2026-10-05-links-design.md` |
| D | Clickable analytics with filtered drill-downs | partly C | done (in-chat design, branch `drilldown-search`) |
| E | Lookup → global search | B | done (in-chat design, branch `drilldown-search`) |

Agreed order: A → B → C → D → E.

## Goals (from the user)

- Public surface (wall, IPs): last N requests of the last 24 h, nothing
  live, delayed with jitter. Done in A.
- Admin: in-depth analytics, real time where it makes sense, and a clearer
  structure:
  1. Overview overlaps with Queue and Scans: merge them, keeping the best
     version of each.
  2. Lookup: expand it, make it more prominent, add features where they make
     sense.
  3. Analytics: every chart element should be clickable and open a filtered
     view (today only "Top paths" is).
  4. Fingerprints and Canaries: merge them. The fingerprint cluster view
     can't be filtered and shows only a few fingerprints.
  5. Cluster page: chaotic and overwhelming.

## What the code showed (as of 0.4.0 + A)

- Admin nav (`templates/_admin_nav.html`) has 11 tabs: Overview, Analytics,
  Queue, Scans, Fingerprints, Canaries, Inbox, Lookup, Export, Keys,
  Cluster.
- **Overview** (`admin_home.html`, `pages.rs::home`) has six tiles (queued,
  running, done/failed 24 h, started this hour / cap, inbox), a live queue
  (25 rows, SSE `/admin/api/queue`), recent failures with "Retry failed",
  and intel feed status. Since A it also has the live "Recent activity"
  feed (SSE `/admin/api/recent`).
- **Queue** (`admin_queue.html`) has a pace card with richer tiles (backlog,
  arrivals/h, throughput/h, net growth, scan duration, failed 24 h),
  sparklines, the pace form and recommendation, retry, status/level filters,
  and a live queue (500 rows). Its tiles cover everything Overview's tiles
  show.
- **Scans** (`admin_scans.html`) is a plain paginated list of completed scans.
- **Fingerprints** (`admin_fingerprints.html`) shows only clusters:
  `Store::fingerprint_clusters` (`src/store/inspect.rs`) returns browser
  fingerprints seen on **more than one IP** (`HAVING COUNT(DISTINCT ip_id) > 1`,
  LIMIT 200), and `host_key_clusters` does the same for SSH host keys and TLS
  certificates. That's why only a few appear. JA4, JA4H, HASSH and JA4X are
  not on this page at all; they are tables on Analytics. There's no filter or
  search.
- **Canaries** (`admin_canaries.html`) has range, kind/node/source/IP
  filters, KPI tiles and a reuse table. Canary reuse also links actors
  across IPs.
- **Analytics** (`admin_analytics.html`, `store/analytics.rs`): only Top
  paths (`/requests?path=`) and JA4H (`/requests?ja4h=`) link anywhere.
- **Drill-down gaps** (block D): `RequestFilter` (`store/browse.rs`)
  supports ip, path, label, severity/min_severity, country, asn, from/to,
  node, ja4h. It has **no** method, transport, answer, user-agent or JA4
  filter. `IpFilter` supports q, country, asn, label, min_severity, tor,
  sort, min_abuse, tag, intel/nointel. It has **no** port, product, HASSH,
  JA4X or OS filter.
- **Lookup** (`admin_lookup.html`, `admin/lookup.rs`) asks every reachable
  provider live, for one IP. Results aren't stored and spend API budget. It
  links to `/ip/X` when the IP is in the dataset.
- **Cluster** (`admin_cluster.html`, about 150 lines): this-node card
  (key, roles, address, version, rules, history, runtime settings, config
  key and audit), invite output, an 11-column members table with inline
  block/purge dialogs, contributions table, invites form and table, "configure
  another node", scanner pace table for all scanners, shared intel table, and
  join. A per-node page exists (`/admin/cluster/node/{key}`,
  `admin_cluster_node.html`) but holds only the remote settings form.

## Ideas per piece (to refine in each brainstorm)

### B: Admin information architecture

- **Nav**, from 11 tabs to about 7: Overview · Requests · Analytics · Scans ·
  Links · Inbox · Cluster, with Keys and Export under a ⚙ menu and global
  search (E) in the header.
- **Overview** becomes the live dashboard, with nothing repeated elsewhere:
  - a "needs attention" strip: unread inbox, failed scans, stale intel, a
    node down, rules that differ between nodes;
  - headline numbers that link through;
  - the live Recent activity feed (already there).
- **Scans** becomes one page with three parts:
  - Pace: the Queue page's tiles, sparklines, form and recommendation;
  - Queue: live and filterable; a `failed` filter with retry replaces
    Overview's "Recent failures";
  - History: today's Scans list.
- **System card:** intel feed status (Overview today) and shared intel
  (Cluster today).
- **Cluster:**
  - Members table cut to about 5 columns: node, status, seen, lag, and one
    "issues" badge for version, clock skew, rules or errors.
  - Each row links to the node page, which grows to hold rules details,
    history, contributions, settings, and block/purge.
  - Scanner pace for all nodes moves to Scans.
  - Invites, config keys, join and leave move to an "Access" sub-tab.

### C: Linking IPs (Fingerprints + Canaries)

- One page with tabs: Browser · TLS (JA4) · HTTP (JA4H) · SSH (HASSH) ·
  Certificates (JA4X / certs) · Canaries.
- Each tab lists all fingerprints, not only shared ones, with a
  "shared only" toggle, hash search, date range, country and node filters,
  and sorting by IPs, sightings or recency.
- The graph shows the top N clusters for the current filter, with a slider
  for N.
- Analytics keeps its top-N summaries and links into this page.

### D: Analytics drill-down

- Every bar, slice or map country links to `/requests?…` or `/ips?…` with
  that filter set. Timeline buckets link with `from`/`to`.
- The applied filters show as removable chips, so narrowing works step by
  step.
- Requires the filter extensions listed under "Drill-down gaps".

### E: Lookup → global search

- A search box on every admin page that recognises what was typed: IP,
  CIDR, `AS123`, a JA4/JA4H/HASSH hash, a request id, a path.
- An IP result combines:
  - live providers (as today);
  - our own data on it: requests, first/last seen, labels, fingerprints,
    and IPs sharing them;
  - actions: queue a scan at a chosen level, block.
- Bulk lookup by pasting a list of IPs.
- Lookups stay unstored (as today).

## Constraints carried over from A

- Public pages must stay non-live and read only released data
  (`Audience::Public`, see the A spec). Any new public view goes through the
  same fragments.
- Admin views read everything (`Audience::Admin`), live where useful (SSE
  patterns in `src/admin/sse.rs`, `assets/js/app.js`; scope live
  indicators to their own card, as done in A).
