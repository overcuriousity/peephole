# Interface audit (Phase 2, Task 16)

Written 2026-11-02 for approval before Tasks 17 to 19. Method: every template
(82, including partials) read against the checklist: page header, back
navigation, admin nav, facts layout, empty state, table density, section order,
repeated markup. The CSS in `assets/css/` was read for the matching rules.
**No browser was available.** Nothing here was judged from a screenshot; the
rendered sample pages in `~/.cache/peephole-ac-accept/pages/` were used only as
data. Visual claims (spacing, narrow screens, dark mode) are inferred from the
CSS and must be checked after each task.

## 1. What is wrong, most valuable first

1. **The request page opens with the least useful things.** Below the chain strip
   come a facts card (11 rows: severity, scan level, answered, transport, JA4,
   JA4H, fingerprint, unrecorded, rules, body), then drops, labels, canaries and
   the full header list, and only then the X-ray, the one view that explains the
   payload. On a page about one request, the evidence is the 8th card.
2. **The campaign page opens with a table.** The flow map and strip come first
   already, but the page header carries seven meta items (strength, size, key,
   first, last, computed) in one line, and "Members" is a full table before
   anything says why these IPs belong together.
3. **Detail pages have no common frame.** Request and IP pages have no admin nav
   (they sit under the top bar's "Requests" and "IPs"); upload, link, campaign,
   scan and canary pages have the admin nav. Back navigation is a muted
   `← All campaigns` under the h1 on two pages (upload, campaign), `← newest` as a
   pager on one, and absent on request, IP, link, scan, canary-decoy and member
   pages. Page actions sit in a header `row` on request and campaign, in a
   "Danger zone" card at the page bottom on the IP page, and in a button row on
   the member page.
4. **Facts are laid out four ways.** `dl.kv` (14 uses, label column),
   `dl.req-facts` (request only, grid), `dl.stat-row` (home only), and `.meta`
   (5 pages, a run of `<span>`s). The same fact (an IP, a time, a node) is
   written differently on each. The copy button is wired by three `let`s per use
   (about 20 uses in 11 files).
5. **The admin nav is the biggest block on every admin page and its labels
   disagree with the pages.** Two rows (6 groups, then 2 to 6 children) before the
   h1. Page titles differ from the tab you clicked: Now / "Overview", Status /
   "System", Members / "Cluster", Credits / "Market", Security keys / the Devices
   page, which is titled "Devices and API keys". `admin_cluster.html` has the h1
   twice (two branches).
6. **Two table styles.** 17 templates use `<table class="table">`, 20 use bare
   `<table>`. Empty states are inconsistent: 57 `td.empty`, 2 `card empty`, 1
   `chain-empty`, and several `<p class="muted">`. Wording varies ("Nothing yet.",
   "none", "No request there since.").
7. **Near-duplicate markup.** `_queue_row` / `_live_queue_row`; `_lookup_body`
   largely repeats what `_target` shows (they share `t`); the "Recent activity"
   row in `admin_home` is the same shape as `_ip_row` / `_related` rows; the
   labels/OWASP chip loop is written in `request.html`, `admin_home.html`,
   `_related` and others. Header rows of `.page-head` are repeated by hand in 35
   templates.
8. **Long single-line template rows.** `request.html` facts, `_target.html` and
   `_xray.html` carry 600+ character lines mixing logic and markup; hard to edit
   safely. Split where touched only.

## 2. Planned changes

Size: S under an hour, M a few hours, L most of a day.

### Task 17: one detail-page frame

| Page or partial | Problem | Proposed change | Size |
|---|---|---|---|
| New `_detail_head.html` | Header hand-built 35 times; back link, meta and actions differ | One partial: crumb row (`← parent list`), h1, meta line, actions slot. One rule: a detail page always has a crumb to its list | M |
| `request.html`, `ip.html` | No admin nav, no crumb; sits under top bar only | Crumb `← Requests` / `← IPs`; top bar keeps "Requests"/"IPs" highlighted. They do not get the admin nav (see decisions) | S |
| `admin_upload`, `campaign`, `admin_link`, `admin_scan`, `admin_canary_decoy`, `admin_cluster_node` | Back link missing or hand-written, inconsistent place | Switch to the frame; crumb to the owning list; keep the admin nav | M |
| `ip.html` | Delete is a "Danger zone" card at the bottom; request page has it in the header | Same place as request: header action, same confirm dialog | S |
| `.meta` / `dl.kv` | Facts rendered four ways | One facts component (`dl.facts`: label/value rows) used by upload, link, scan, member; `.meta` stays only as the header line | M |
| `_copy.html` call sites | 3 `let`s per use | A helper macro/partial with `value`, `what` defaulted; no behaviour change | S |

### Task 18: lead with evidence

| Page or partial | Problem | Proposed change | Size |
|---|---|---|---|
| `request.html` order | Evidence is the 8th card | Order: chain strip, X-ray ("Body"), facts, drops/labels, canaries, headers, related | M |
| `request.html` headers | 20-odd header rows open by default, long | `<details>` closed, summary shows count and the first few names; opens by `#headers` anchor | S |
| `request.html` facts | 11 rows, mostly dashes for non-TLS requests | Facts grid shows only the set rows plus Severity and Answered; empty ones listed in one muted line ("not recorded: JA4, JA4H") | S |
| `request.html` Labels card | A whole card for chips | Move chips into the header meta line (when none: nothing) | S |
| `campaign.html` | Header meta is seven items; Members table precedes any reason | Keep flow map first; collapse header meta to size, first/last seen, strength; key and "computed" into a muted second line; Members stays directly after strip | S |
| `admin_upload.html` | Facts card before the X-ray; timeline after | Strip, X-ray, facts, timeline (same rule as request) | S |

### Task 19: partials and navigation

| Page or partial | Problem | Proposed change | Size |
|---|---|---|---|
| `_admin_nav` / `_subtabs` | Two stacked rows before every h1 | Tighten the two rows (less padding, group row smaller); no entries change. Narrow-screen scrolling stays | S |
| Page titles vs nav labels | Now/Overview, Status/System, Members/Cluster, Credits/Market | Titles follow the nav label (see decisions) | S |
| `admin_cluster.html` | h1 written twice | One h1 outside the branch | S |
| Tables | `table` vs `table.table` | Style both identically in CSS (selector `.table, .table-wrap table`), then drop the class from templates only where touched | S |
| Empty states | 4 shapes, varying wording | One `_empty.html` (`msg`, optional action) for card-level, keep `td.empty` for rows with the same wording style | M |
| `_queue_row` / `_live_queue_row`; chips loop | Duplicated | Merge into one row partial with a flag; one `_labels.html` chips partial | M |
| `_lookup_body` vs `_target` | Overlap | Check which blocks differ; share the rest. Do not start without a diff review | M |
| Long one-line templates | Unreviewable | Split `request.html` facts and `_target` rows into partials as touched by 17 and 18 only | S |

Count: Task 17 has 6 changes, Task 18 has 6, Task 19 has 8.

## 3. Needs your decision

Each of these moves or hides something. Nothing is removed outright; every old
URL stays through `admin::moved` or in place.

1. **Request page: headers collapsed by default.** Lost: seeing headers without a
   click. Gained: the X-ray and facts fit on a screen.
2. **Request page: Labels card becomes chips in the header.** Lost: the "Labels"
   heading and its "none" text. Titles (family, OWASP name) stay as tooltips.
3. **Request page: unset facts (JA4, JA4H, Transport, Unrecorded) fold into one
   "not recorded" line.** Lost: a visible row with a dash for each.
4. **IP page: Delete moves from the bottom "Danger zone" card to the header.**
   Lost: the explanation text "Cannot be undone" outside the dialog (it moves into
   the dialog).
5. **Request and IP pages stay without the admin nav**, with a crumb instead (the
   alternative is adding it, which costs two rows on the page you read most and on
   a page shared with the public site). Your pick.
6. **Page titles renamed to match nav labels** (Overview to Now, System to Status,
   Cluster to Members, Market to Credits). Lost: the old words in titles. The
   docs and CHANGELOG use "Market" and "Cluster" for concepts and stay as they are.
7. **System: fold "Security keys" into "Devices"** (the Devices page is already
   titled "Devices and API keys"). Lost: one nav entry; the page content and URL
   `/admin/system/keys` stay (the URL redirects to the merged page's anchor via
   `moved`). Skip if you want it separate.

## 4. What I'd leave alone

- **Brand, tokens, light/dark, the topbar.** Not a rebrand; the tokens file is
  consistent and both schemes are defined together.
- **Six nav groups and their order.** Chains fit under Evidence, nothing is
  orphaned except the member and scan detail pages, which already resolve to
  their group. Only the Security keys merge is worth asking about.
- **`_chain_strip`, `_chain_flow`, `_xray`.** New, already consistent with
  each other; only their position on the page changes.
- **IP page section nav and card order** (`[data-section-nav]`, intel, actions,
  probes, evidence): it works as an index for a long page.
- **Home page tiles and Cluster card.** Dense, but every tile is a link into the
  page that holds the detail; they are the daily starting point.
- **Public pages, dashboard (`wall`), API and about pages.** Out of scope.
- **Filters and tables on `requests`, `ips`, `scans`.** Density is right for
  scanning; changing column sets would remove function.
- **Per-page `td.empty` rows.** Fine as they are; only wording is touched.
