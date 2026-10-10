# peephole-android v1 — screen designs

Status: draft for review (CTO). Issue: MIK-21, child of MIK-3 (plan rev 2,
`21042643`, owner-confirmed 2026-10-10).

**Staging note:** the `overcuriousity/peephole-android` repo does not exist
yet, so this doc lives here until it does. Move it to
`docs/design/android-v1.md` in that repo once created, unchanged.

Design only — no code. Kotlin + Jetpack Compose, Material 3, dark theme
only (the product is read by forensics/security staff, often at night next
to a running scan; a light theme is out of scope for v1). Low-fi: ASCII
layout blocks plus prose, per the issue's constraints.

## 0. What this is built against

The web admin (`overcuriousity/peephole`, this repo) is the parity
reference named in the brief: `templates/admin_lookup.html`,
`templates/_actions.html`, `templates/_target.html`, `templates/ip.html`,
`templates/_probes.html`, `templates/admin_scans.html`, `templates/_severity.html`,
and the token sheet `assets/css/00-tokens.css`. Where a choice below departs
from the web admin's current behaviour, it's called out explicitly with why.

`docs/api-v1.md` (MIK-3/A) hasn't landed. Every field list below is a
best-effort read of the MIK-3 plan and the web admin's own data model;
items that are guesses, not confirmed fields, are marked **(TBD — api-v1)**.
None of this blocks the visual/interaction design; it does mean the
Engineer should treat field names as placeholders, not a contract.

## 1. Principles carried over from the web admin

- **Never hide why a control is disabled.** The web admin's Actions card
  puts the reason in a `title`/inline string on every disabled button
  instead of hiding it (`_actions.html`). Android does the same: a disabled
  button always has a one-line reason visible under it, not just in a
  long-press tooltip (long-press discovery fails Nielsen's heuristic of
  visibility of system status, and touch has no hover).
- **No one-tap spend.** The web admin's per-level scan buttons submit on a
  single tap today (`_actions.html`'s `level-grid` — tap one button, start
  spending). MIK-3's owner decision is explicit that the phone build must
  not carry this forward: a quote, its expiry, and an explicit confirm step
  are mandatory before any credit-spending action fires. This is a
  deliberate divergence from current web behaviour, not an oversight — call
  it out to the Engineer and to CTO so the web admin isn't cited as the
  counter-example.
- **Severity and cost are never colour-only.** `_severity.html` always pairs
  the colour with the numeral (`sev-0`…`sev-4`); credits are always a
  labelled number, never an icon alone. Android keeps both the colour chip
  and the text/number in every instance (WCAG 1.4.1, data-honesty rule: a
  number always carries its source).
- **Every timestamp is ISO 8601 UTC**, same as the web admin's `ts`/`mono`
  columns, with the local-time equivalent available on tap/long-press, not
  as the primary label — a reviewer comparing a phone screen to the web
  admin or to a report must see the same instant written the same way.

## 2. Navigation map

```
Instance List  ──(tap instance)──▶  IP List + Search ──(tap row)──▶ IP Detail
     │                                     │                           │
     ├─(FAB / +)──▶ Pair (QR scan ▸ confirm) ◀──(from Settings "pair another")
     │                                                                 │
     └─(overflow)──▶ Settings (per instance)                           │
                                                                        │
IP Detail ──(Lookup tab / deep link)──▶ Lookup (single + bulk)         │
IP Detail ──(Probe action)───────────▶ Probe (start) ──▶ Probe (result)│
IP Detail ──(Scan action, per level)──▶ Scan cost-confirm ──▶ Job status (polling) ─┘
                                                                  │
                                                     (on finish) ─▶ back to IP Detail,
                                                                    scan result expanded
```

Bottom navigation (3 destinations, within one paired instance's context):
**IPs** · **Lookup** · **Jobs** (probe/scan job status, including history —
out-of-scope item "live SSE feeds" means this is poll-refresh, pull-to-refresh
plus a fixed interval, not a push stream).

Instance List sits *above* the bottom nav — it's the entry point and the
switcher, reached via a persistent "instance" chip in the top app bar that
opens a bottom sheet listing paired instances (so switching instances never
requires leaving the current screen's back-stack). Settings/unpair is
per-instance, reached from that same bottom sheet or from IP Detail's
overflow menu.

Scan cost-confirm and Pair-confirm are modal destinations (full screen,
own back-stack entry, not a dialog) because both commit the user to
something consequential (money, trust) and deserve a dedicated moment of
attention — a `BasicAlertDialog` is too easy to tap through blind two-stage.

## 3. Material 3 colour roles (dark scheme, mapped from peephole's tokens)

Source: `assets/css/00-tokens.css`, the `:root[data-theme="dark"]` block
(peephole's dark theme is the default; light is opt-in there, and doesn't
exist here at all). Values copied verbatim so a side-by-side screenshot of
the web admin and the app reads as one product.

| M3 role | Hex | peephole token | Used for |
|---|---|---|---|
| `background` | `#0a0b10` | `--color-bg-base` | Screen background |
| `surface` | `#10121a` | `--color-bg-surface` | List rows, sheets |
| `surfaceContainer` / `surfaceContainerHigh` | `#171a24` | `--color-bg-elevated` | Cards, app bar, dialogs |
| `surfaceContainerHighest` (pressed/hover equivalent) | `#1f2330` | `--color-bg-hover` | Pressed row state |
| `onBackground` / `onSurface` | `#e4e6ee` | `--color-fg-primary` | Primary text |
| `onSurfaceVariant` | `#a0a4b8` | `--color-fg-secondary` | Secondary text, labels |
| (muted, no direct M3 role — use `onSurfaceVariant` at 70% or a dedicated `textMuted` custom token) | `#8a8ea6` | `--color-fg-muted` | Hints, timestamps |
| `outline` | `#262b40` | `--color-border` | Dividers, card borders |
| `outlineVariant` | `#212536` | `--color-border-subtle` | Subtle separators |
| `primary` | `#4fd1e0` | `--color-accent` | Primary buttons, links, selected states |
| `onPrimary` | `#0a0b10` | `--color-accent-fg` | Text/icon on primary fill |
| `primaryContainer` (approx.) | `rgba(79,209,224,.14)` | `--color-accent-dim` | Selected chip fill, info banners |
| `tertiary` ("brand") | `#ff3b3b` | `--color-brand` | Tor badge, the one spot that should read as alarm-adjacent but isn't severity |
| `error` | `#ff6b6b` | `--color-danger` | Destructive actions, 401/403/error states |
| `errorContainer` | `rgba(255,107,107,.15)` | `--color-danger-dim` | Error banners |
| custom `warning` / `warningContainer` | `#f0b344` / `rgba(240,179,68,.15)` | `--color-warning(-dim)` | Degraded/queued states, pace warnings |
| custom `success` / `successContainer` | `#5fd39a` / `rgba(95,211,154,.15)` | `--color-success(-dim)` | Done states, confirmations |

Severity (extended custom colour group, not a baseline M3 role — Compose
supports this as a custom `SeverityColors` holder alongside `ColorScheme`):

| sev | Hex (text) | Hex (dim fill) | Meaning |
|---|---|---|---|
| 0 | `#9a9eb2` | `rgba(154,158,178,.16)` | informational |
| 1 | `#f0c34a` | `rgba(240,195,74,.16)` | low |
| 2 | `#ff9440` | `rgba(255,148,64,.16)` | medium |
| 3 | `#ff5c5c` | `rgba(255,92,92,.16)` | high |
| 4 | `#d17dff` | `rgba(209,125,255,.16)` | critical |

Category colours (request/label families, `--cat-*` in the token sheet) —
reused on IP Detail's "what it was after" chips, identical hex to the web
admin: recon `#7aa2ff`, exposure `#4ade80`, inject `#ff5c5c`, impact
`#d17dff`, interact `#ff9440`, bot `#9a9eb2`.

Typography: `Inter` (400/500/600) for UI text, `JetBrains Mono` (400/500)
for addresses, hashes, ports, timestamps — same two families as the web
admin, mapped onto M3's `Typography` slots (`bodyLarge`/`labelLarge` → Inter
500/600, `bodyMedium` → Inter 400, a custom `monoSmall`/`monoMedium` text
style → JetBrains Mono, used anywhere the web admin uses `.mono`). Two
weights per family, three sizes, per the visual-quality bar — more than
that isn't needed here.

Shape: `radius-md` (6dp) for cards and buttons, `radius-lg` (10dp) for
sheets/dialogs — matches `--radius-md`/`--radius-lg`. Elevation stays flat
(peephole's `--shadow-card` is a 1px inset line, not a drop shadow); Compose
`Card` with `tonalElevation` only, no `shadowElevation`, keeps the same flat,
dense, data-forward look instead of a default Material "paper" feel.

## 4. Components used (Material 3, reuse before invention)

- `TopAppBar` (instance switcher chip as the title slot's trailing element)
- `NavigationBar` (3 items: IPs / Lookup / Jobs)
- `Scaffold` + `FloatingActionButton` (Instance List → Pair)
- `Card` / `OutlinedCard` (every content block — direct analogue of the web
  admin's `.card`)
- `AssistChip` / `FilterChip` (severity, status, category — analogue of
  `.badge`/`.badge-status`/`.chip`)
- `SearchBar` (IP List search, replaces a `TextField` for that one case)
- `ListItem` (IP rows, job rows)
- `LinearProgressIndicator` / `CircularProgressIndicator` (job status polling)
- `AlertDialog` reserved for *reversible, cheap* confirmations only (unpair,
  delete-local-pairing) — never for the cost-confirm, see §2.
- `Snackbar` (toasts: "charged 40 credits", "copied", transient errors)
- `PullToRefreshBox` (every list/detail screen)
- `Badge` (instance list unread/new-finding count, if MIK-3 exposes one —
  **(TBD — api-v1)**)
- Camera: CameraX + ML Kit barcode scanning (QR) for Pair — standard,
  no custom scan UI beyond a viewfinder overlay and a manual-entry fallback
  link (code-only entry) for a camera that won't focus or isn't permitted.

## 5. Shared pattern: states

Every screen below names which of these apply; the pattern itself is
defined once so it reads identically everywhere (recognition over recall).

| State | Pattern |
|---|---|
| **loading** | Skeleton rows (shimmer, `surfaceContainerHigh` on `surface`) shaped like the real content, not a spinner-only screen, except Job status which is inherently a progress view. |
| **empty** | Centered icon (outline style, `onSurfaceVariant`) + one sentence + a primary action when one exists ("Pair an instance", "Look up an address"). Never just blank. |
| **error** | Inline banner, `errorContainer`/`error`, the *actual* message from the instance (never a generic "something went wrong") + a **Retry** button. Matches the web admin's `<p class="muted">{{ e }}</p>` pattern but promoted to a visible banner, since mobile has no persistent surrounding chrome to carry a muted aside. |
| **offline** | A persistent top banner ("No connection to this instance — showing the last sync, {time} ago") on top of the last cached screen, not a full-screen takeover, so a technical reader can keep reading what they already pulled. Actions that need the network (lookup, probe, scan, pair) disable with "offline" as the reason string, per §1. |
| **401 — revoked** | Full-screen interstitial, not a banner: the pairing itself is gone. "This device's pairing with {instance name} was revoked. Pair again to continue." + **Pair again** button + **Remove instance** button. Returns to Instance List if dismissed. This is deliberately heavier than a banner because every other action on this instance is now meaningless until re-paired. |
| **403 — no act-scope** | Inline, local to the control, not full-screen: the device *is* paired and can read, just can't spend/act. "Your pairing is read-only on this instance." next to the disabled Lookup-paid/Probe/Scan controls, same place a price or disabled-reason normally sits. Browsing (IP list, IP detail, free lookups) stays fully usable. **(TBD — api-v1: exact scope name and whether it's binary read/act or finer-grained; designed here as a single `act` boolean gate per MIK-3's "any authenticated peephole admin" framing.)** |

## 6. Screens

### 6.1 Instance List

Entry point; lists every peephole instance this device has paired with.

```
┌──────────────────────────────┐
│ peephole                  ⋮  │ ← overflow: about/help
├──────────────────────────────┤
│ ● sentry.example.org         │  ← live dot = reachable now
│   admin · paired 14 Sep      │
│   142 IPs tracked            │
├──────────────────────────────┤
│ ○ lab-node.internal          │  ← hollow dot = unreachable now
│   read-only · paired 2 Oct   │
│   last synced 3h ago         │
├──────────────────────────────┤
│              ...             │
└──────────────────────────────┘
                          (FAB) ⊕ Pair
```

Each row: instance display name, origin host (muted, mono, truncated
middle so both scheme-end and TLD stay visible), reachability dot (colour
only *plus* the word "read-only"/blank — never dot-only, since dot colour
alone fails colour-independence), paired-since date, a one-line freshness
or count stat.

**States**
- loading: 3 skeleton rows.
- empty: "No instances paired yet." + primary button **Pair an instance**
  (same action as the FAB — don't make empty-state the only way in, but
  don't make it a second idiom either).
- error: n/a at this screen's level (it's local data); a per-row banner can
  show if the last sync attempt for that row failed — folds into "offline"
  per-row, not a screen-level error.
- offline: each unreachable instance shows "last synced {time}" instead of
  a live count; no screen-level takeover, since this screen is fundamentally
  "my local list," most of which still means something offline.
- 401/403: shown as a row-level badge ("revoked" / "read-only") rather than
  blocking the list — a revoked instance should still be visible so the
  user can re-pair or remove it (Nielsen: visibility of status, not
  disappearance of the thing that needs attention).

### 6.2 Pair

Two steps in one destination (a 2-step `HorizontalPager` or sequential
Composable state, not two separate back-stack screens, so "back" from
confirm returns to the scanner, not out of pairing entirely).

**Step 1 — scan**
```
┌──────────────────────────────┐
│ ←  Pair an instance          │
├──────────────────────────────┤
│                               │
│     ┌──────────────┐         │
│     │              │         │
│     │   viewfinder  │        │
│     │              │         │
│     └──────────────┘         │
│                               │
│   Point the camera at the    │
│   QR code in your peephole   │
│   admin's pairing page.      │
│                               │
│   Can't scan it? Enter code  │
│   manually →                 │
└──────────────────────────────┘
```
- loading: n/a (camera is live immediately); a brief "starting camera…"
  skeleton only if permission is still resolving.
- empty: n/a.
- error: camera permission denied → inline explanation + **Open settings**
  button + the manual-entry fallback promoted to primary, so a denied
  permission never becomes a dead end.
- offline: scanning itself needs no network; the *confirm* step does, so
  offline is surfaced at step 2, not here.
- 401/403: n/a (nothing is authenticated yet).

**Step 2 — confirm** (shown immediately after a successful scan, before
anything is stored)
```
┌──────────────────────────────┐
│ ←  Confirm pairing            │
├──────────────────────────────┤
│  You're about to pair with:  │
│                               │
│  sentry.example.org          │ ← origin, exactly as the admin reports it
│  Device name shown there:    │
│  "Alice's Pixel"              │ ← editable before confirm
│                               │
│  This grants this app read   │
│  access to this instance's   │
│  data. Paid actions need a   │
│  separate act permission     │
│  granted by its admin.       │
│                               │
│  [ Cancel ]      [ Confirm ] │
└──────────────────────────────┘
```
This is the forgiveness/trust moment: showing the bare **origin** (scheme +
host, not a path, not a pretty display name the QR payload could spoof) is
the one honesty-critical element here — a QR code is an untrusted input,
so the confirm screen's whole job is to let a human catch a wrong or
unexpected host before any credential is stored. Device name is prefilled
from the phone's own name but editable (this is what the *instance's* admin
page will show for this pairing, per the brief — "confirm showing origin
and device name").
- error here: "This QR code isn't a peephole pairing code" (malformed/wrong
  payload) → back to scan, no silent retry.
- offline: "Can't reach {origin} to complete pairing" + **Retry**; the scan
  result is held, not discarded, so retry doesn't mean re-scanning.

### 6.3 IP list + search

```
┌──────────────────────────────┐
│ ≡ sentry.example.org     ⋮   │
├──────────────────────────────┤
│ 🔍 Search IP, ASN, country…  │
├──────────────────────────────┤
│ Filters: [Sev ≥ 3] [Tor] [+] │ ← FilterChips, multi-select
├──────────────────────────────┤
│ 203.0.113.7         ● sev 3  │
│ 🇩🇪 DE · AS64500 · 1.2k reqs  │
├──────────────────────────────┤
│ 198.51.100.4  🧅     ● sev 1  │  ← 🧅/tor badge, text "tor exit" on tap
│ 🇳🇱 NL · AS64501 · 340 reqs   │
├──────────────────────────────┤
│              ...             │
└──────────────────────────────┘
```
Row = IP (mono), severity chip (colour + number, per §1), country flag +
name, ASN, request count, Tor badge when applicable — same fields as
`_bar.html`/`ips.html`'s table columns, reflowed from a table into a
2-line list row for touch. Tapping a row opens IP Detail; long-press (with
a visible overflow `⋮` equivalent for accessibility, since long-press alone
isn't discoverable) offers "Copy IP" / "Open in browser".

**States**
- loading: 6 skeleton rows.
- empty: zero matches for the current search/filter → "Nothing matches
  {query}." + **Clear filters** button if any filter is active; zero IPs in
  the dataset at all (new instance) → "No addresses recorded yet.".
- error: banner + Retry, list keeps last good page below it if one exists.
- offline: top banner per §5; list shows last cached page, each row
  unaffected (this is read-only data, fine to show stale with its
  "last synced" timestamp in the offline banner).
- 401: full interstitial per §5 (replaces this whole screen).
- 403: n/a — browsing is a read action, assumed always inside the base
  pairing scope; only paid/act controls gate on `act`.

### 6.4 IP detail

Highest-risk screen along with cost-confirm — this is the one a lawyer or
non-technical reader may also see over someone's shoulder, so the ordering
is strict inverted-pyramid: identity and verdict first, raw evidence last.

```
┌──────────────────────────────┐
│ ←  203.0.113.7          ⋮    │
├──────────────────────────────┤
│ 203.0.113.7  [copy]          │
│ 🇩🇪 Germany · AS64500 Example │
│ first seen 2026-09-02 UTC    │
│ last seen 2026-10-10 UTC     │
├──────────────────────────────┤
│  Requests   Rank   Max sev.  │ ← stat tiles, 3-up, analogue of
│   1,284     #41      [●3]    │   ip.html's `.tiles`
├──────────────────────────────┤
│ ▸ Enrichment                 │  ← collapsible section, per-source cards
│   GeoIP · MaxMind            │
│   checked 2h ago             │
│   Tor · torproject.org       │
│   not a Tor exit             │
│   AbuseIPDB                  │
│   [Ask again · 25 credits]   │  ← act-scope gated; shows price always
├──────────────────────────────┤
│ ▸ Request history (summary)  │  ← sparkline/calendar, not a raw table
│   [ 7-day hourly bars ]      │
│   [ 26-week severity map ]   │
├──────────────────────────────┤
│ ▸ Scans                      │
│   L3 · finished · 4 ports    │
│   open · 2h ago         [›]  │
│   [ Run a counter-scan ▾ ]   │  → opens level picker → cost-confirm (§6.7)
├──────────────────────────────┤
│ ▸ Probes                     │
│   03:14 UTC · by admin · free│
│   2 vantages agreed          │
│   [ Probe this address ]     │  → Probe (§6.6)
├──────────────────────────────┤
│ ▸ Links                      │
│   AbuseIPDB · Shodan · …     │ ← outbound link chips, opens Custom Tab
└──────────────────────────────┘
```

Section order and content mirror `templates/ip.html` + `_target.html`'s
card order (identity → tiles → intelligence → activity → scans → probes →
links), collapsed into expandable sections on mobile instead of one long
scroll, since a phone screen can't show the web admin's section-nav rail —
each section header is sticky while expanded so "where am I" stays
answered while scrolling (orientation, Nielsen #1).

Request-history is explicitly a **summary**, per the brief (full request
list is out of scope for v1 — no per-request inspector screen). The
sparkline/calendar pairing is the one from `_target.html`'s `.ip-activity`
block, redrawn as a native Compose canvas rather than embedding the web
admin's JS chart.

**States**
- loading: identity block skeleton + 3 tile skeletons + collapsed-looking
  section placeholders (shimmer), expandable sections load their content
  lazily on first expand (keeps the initial screen fast and matches "no
  live SSE" — polling is opt-in per section, not constant).
- empty: n/a for an address that exists; an address with zero stored
  requests (fresh from a lookup, not yet "recorded") shows the identity
  block plus "Not recorded here: not in the dataset." (verbatim parity with
  `admin_lookup.html`'s `r.target.is_none()` branch) and suppresses the
  tiles/scans/probes sections entirely rather than showing them empty.
- error: per-section inline error + Retry (a failed enrichment fetch
  shouldn't block the identity block or other sections — partial failure,
  partial success, exactly like the web admin's per-provider grid where one
  dead provider doesn't blank the page).
- offline: offline banner; every action control (ask again, probe, scan)
  disables with "offline" as the reason.
- 401: full interstitial, replaces the screen.
- 403: enrichment "Ask again", Probe, and counter-scan controls disable
  with "read-only pairing" as the reason; everything else on this screen
  (identity, stored enrichment, history, stored scan/probe results) stays
  fully visible, since those are reads.

### 6.5 Lookup (single + bulk)

```
┌──────────────────────────────┐
│ ←  Lookup                 ⋮  │
├──────────────────────────────┤
│ ┌───────────────────────────┐│
│ │ IP, host, or pasted list  ││  ← multiline TextField, same affordance
│ └───────────────────────────┘│     as the web admin's textarea
│ [ Look up · up to 85 each ]  │  ← price shown pre-submit when known, same
│                               │     string shape as admin_lookup.html
├──────────────────────────────┤
│ Stored (bulk, no cost)       │ ← shown first for a multi-line paste,
│ 203.0.113.7  sev 2  12 reqs  │   exactly like the web's "from stored
│ 198.51.100.9 — not stored    │   data, no provider is asked" table
├──────────────────────────────┤
│ Results                      │
│ 203.0.113.7                  │
│  GeoIP ✓  Tor ✓  AbuseIPDB — │ ← provider chips: answered / pending /
│  not asked                   │   not asked, tap → intel card (§6.4 style)
│  [ Ask for more ▾ ]          │
└──────────────────────────────┘
```
Single input (IP/host) and bulk (newline-separated paste) share one
textfield and one submit path, same as `admin_lookup.html` — no separate
"bulk mode" toggle to choose up front, consistent with "Enter looks up ·
Shift+Enter adds a line" on web (mapped to a multiline field plus an
explicit submit button on mobile, since there's no keyboard modifier to
rely on).

**States**
- loading: submit button shows a determinate-ish busy state ("Looking
  up…", matches `data-busy` on web) per in-flight result, since different
  providers can answer at different times.
- empty: no input yet → placeholder text only, no results section
  rendered (not even empty); a submitted query with zero results for every
  address → "No provider answered." (verbatim parity) per address block.
- error: inline per-address ("No public address." / an unreadable line
  echoed back, same as `n.rows.is_empty()`/`unreadable` handling).
- offline: whole screen's primary action disables; stored-only results
  (bulk "from stored data") remain usable since they need no network call
  — same distinction the web admin already draws.
- 401: interstitial.
- 403: paid "Ask for more"/"Ask again" rows disable with "read-only
  pairing"; free/stored lookups keep working if MIK-3 defines any lookup as
  always-free **(TBD — api-v1: which providers, if any, are zero-cost on
  this instance — on web this is a per-node `quotes()` result, not a fixed
  list)**.

### 6.6 Probe (start + result)

Two states of one screen (not two destinations) — start, then the same
screen re-renders with results as they arrive, matching `_probes.html`'s
"requests made before a restart show once their result arrives" model.

```
Start:                          Result:
┌───────────────────────┐       ┌───────────────────────┐
│ ←  Probe 203.0.113.7  │       │ ←  Probe 203.0.113.7  │
├───────────────────────┤       ├───────────────────────┤
│ Vantage points:        │       │ 03:14 UTC · by you     │
│ ☑ node-eu   €0.10      │       │ ┌───────────────────┐ │
│ ☑ node-us   €0.10      │       │ │Vantage  RTT  Verdict│
│ ☐ node-asia €0.15      │       │ │node-eu  12ms open   │ │
│                        │       │ │node-us  140ms open  │ │
│ [ Probe · 20 credits ] │       │ └───────────────────┘ │
└───────────────────────┘       │ ⚠ Location claim        │
                                 │ contradicted by 1 of 2 │
                                 │ vantages                │
                                 └───────────────────────┘
```
Vantage checkboxes + per-vantage price + running total on the button —
direct parity with `_actions.html`'s `vantage-chips`. A probe has no
cost-confirm step by design distinction from scan: the brief's explicit
"no one-tap buy" requirement names **scan** specifically (credit cost there
is much higher and irreversible resource use on a scanner); probe pricing
here is small and the total is visible on the submit button itself before
commit, same as today's web pattern — flagged as a judgement call, not a
MIK-3-confirmed decision; worth CTO sign-off if probes get priced higher
in practice.

**States**
- loading (post-submit, pre-result): button → busy spinner state
  ("Probing · 0 of 2 in", parity with `_actions.html`'s busy label);
  screen doesn't block, user can navigate away and the result reappears via
  Jobs/IP Detail when ready (no live-SSE, so this is poll-driven while the
  screen is open, and reconciled next time it's opened otherwise).
- empty: n/a.
- error: a vantage that errors shows its row with the error text inline
  (parity with `m.why`), doesn't fail the whole probe.
- offline: submit disables, "offline" reason; an in-flight probe's partial
  results (already fetched before going offline) stay visible.
- 401: interstitial.
- 403: submit disables, "read-only pairing"; a probe's already-stored
  results remain viewable.

### 6.7 Scan cost-confirm

The screen named as highest-risk in the brief. Reached from IP Detail's
level picker (§6.4); one level chosen there, this screen confirms that one
level only — never a combined multi-level purchase in one confirm, so the
number on screen always matches the number the user just tapped.

```
┌──────────────────────────────┐
│ ←  Confirm counter-scan        │
├──────────────────────────────┤
│ Target      203.0.113.7       │
│ Level       L4 — deep service │
│             fingerprint        │
│                                │
│ ┌────────────────────────────┐│
│ │  Cost        45 credits    ││ ← large, unambiguous, own block
│ │  Your balance   210 credits││
│ │  Quote expires  in 0:47    ││ ← live countdown, re-quotes at 0
│ └────────────────────────────┘│
│                                │
│ A scan probes the live host.  │
│ It can take several minutes   │
│ and the result is kept in the │
│ dataset. This charges your    │
│ balance now.                  │
│                                │
│ [ Cancel ]   [ Confirm · 45 ] │ ← price repeated on the commit
│                                │   button itself (recognition over
└────────────────────────────┘   recall at the exact moment of commit)
```
This is a dedicated full screen, not an `AlertDialog` (§2) — the brief's
"explicit confirm" plus "no one-tap buy" is read here as: the confirm
control must not be reachable by the same reflexive tap gesture a user
just used to request the quote (different screen, forces a context switch,
double-checks the Fitts's-Law-easy "just tap confirm" habit).

**Quote expiry is load-bearing, not decorative.** On expiry:
- the Confirm button disables immediately,
- the cost block is replaced by "Quote expired — get a new one," with a
  single **Re-quote** button (which re-enters this same screen with a
  fresh number, not a silent auto-refresh — a changed price must be seen,
  never swapped in under a static-looking button, which would be exactly
  the kind of silent-cost-change dark pattern this product's own ethics
  section forbids).

If the balance shown is lower than the cost, the Confirm button is still
shown (never hidden, §1) but disabled, with "Not enough credits" as the
reason and a link to the instance's credit/top-up surface **(TBD —
api-v1/MIK-3 plan: whether credits can be bought in-app at all; the brief's
out-of-scope list only excludes "one-tap buy" for the scan action itself,
not a credits top-up flow in general, so this is left as a question for
CTO rather than assumed either way)**.

**States**
- loading: cost block shows a skeleton while the quote is being fetched
  (this screen is only ever entered already *requesting* a quote — there's
  no "idle" version of this screen).
- empty: n/a.
- error: quote request failed → cost block replaced with the error message
  + **Retry**; Confirm stays disabled throughout.
- offline: same as error, framed as "Can't reach {instance} for a quote."
  — a stale quote is never shown as if current, since a cost-confirm is
  exactly the one surface where honesty about data freshness is the entire
  point of the screen.
- 401: interstitial (replaces screen — a revoked pairing can't be trusted
  to charge the right account).
- 403: this screen should not be reachable at all from a read-only pairing
  (the level-picker action that launches it is itself disabled per §6.4);
  if reached anyway (e.g. a scope revoked mid-flow), show the 403 message
  in place of the cost block and disable Confirm — belt-and-suspenders,
  never trust only the entry point's gating.

### 6.8 Job status (polling)

One shared screen for both probe and scan jobs in flight or finished,
reached from Jobs (bottom nav) or directly after confirming a scan/probe.

```
┌──────────────────────────────┐
│ ←  Jobs                    ⋮ │
├──────────────────────────────┤
│ Running                      │
│ Scan L4 · 203.0.113.7        │
│ [██████░░░░] queued 2m       │
├──────────────────────────────┤
│ Finished today                │
│ ✓ Scan L3 · 198.51.100.4     │
│   4 open ports · 6m ago   [›]│
│ ✕ Scan L4 · 203.0.113.9      │
│   timed out · 1h ago      [›]│
│ ✓ Probe · 203.0.113.7        │
│   2 of 2 agreed · 2h ago  [›]│
└──────────────────────────────┘
```
Status badges reuse the web admin's `badge-status` tones exactly: queued
(neutral), running (`warning`), done (`success`), failed/refused
(`error`), parity table in §3. Pull-to-refresh plus poll at a fixed
interval while the screen is foregrounded (no SSE, per out-of-scope);
polling stops when backgrounded.

**States**
- loading: skeleton rows under both headers.
- empty: no jobs at all → "No scans or probes yet." (no primary action
  here — starting one happens from IP Detail, not from this list, so no
  duplicate entry point is invented).
- error: banner + Retry; already-known job rows stay visible (don't blank
  a list because the latest poll failed).
- offline: offline banner; rows freeze at last-known status with their
  timestamp, no spinner animates while offline (an animating progress bar
  with no network to back it is a false affordance).
- 401: interstitial.
- 403: list itself is read-only and stays fully visible; nothing on this
  screen needs the act scope, since starting a job happens elsewhere.

### 6.9 Settings / unpair (per instance)

```
┌──────────────────────────────┐
│ ←  sentry.example.org         │
├──────────────────────────────┤
│ Device name                   │
│ Alice's Pixel            [✎]  │
│                                │
│ Paired                        │
│ 2026-09-14 · read + act       │
│                                │
│ Permissions granted here are  │
│ set by this instance's admin, │
│ not by this app.              │
│                                │
│ Notifications          [off ▾]│  (TBD — out of scope: push is excluded
│                                │   for v1; this row may not exist yet —
│                                │   left here only as a placeholder the
│                                │   Engineer should drop, not build)
├──────────────────────────────┤
│        [ Unpair device ]      │ ← btn-danger equivalent
└──────────────────────────────┘
```
Unpair uses the reversible-vs-destructive pattern from `ip.html`'s delete
dialog (`data-confirm` + a dialog restating the consequence) since it's
local and cheap to undo (re-pair), unlike a scan spend — an `AlertDialog`
is the right weight here, consistently with §2's distinction.

**States**
- loading: skeleton for the two info rows.
- empty: n/a (always has at least the pairing info).
- error: unpair request failed → inline error in the dialog, dialog stays
  open, no silent failure.
- offline: unpair disables ("offline" — unpairing is itself a call to the
  instance to invalidate the credential, per MIK-3's pairing model
  **(TBD — api-v1: confirm unpair is server-invalidated, not purely
  local; designed here assuming it is, since a purely local "forget" would
  leave a stale credential valid against the instance)**).
- 401: still reachable (this is the one screen a revoked pairing *should*
  open to, from the interstitial's "Remove instance" button) — shows
  "Already revoked by {instance}" instead of the normal paired-info block,
  and Unpair becomes "Remove from this device" (local-only now, since the
  server side is already gone).
- 403: full settings remain visible; nothing here is act-gated (unpairing
  a read-only pairing is still allowed — it's the user's own device
  record, not a privileged action).

## 7. Accessibility checklist (applies to every screen above)

- All touch targets ≥ 48dp, including chip/badge tap areas that look
  smaller — padding, not visual size, satisfies this (matches the brief's
  explicit minimum).
- Every icon-only control (back, overflow `⋮`, copy, FAB, filter-chip `+`,
  countdown's implicit "time running out") carries a `contentDescription`;
  none rely on an adjacent label alone.
- Colour is never the only carrier of meaning: severity, status, and
  reachability all pair colour with text/number (§1, §3, repeated per
  screen above) — verified against WCAG's use-of-colour criterion the same
  way the web admin's own token comment already frames its severity ramp
  ("text-safe on base").
- Minimum contrast: the peephole dark palette was already chosen against
  `--color-bg-base`/`--color-bg-surface`; reuse verbatim rather than
  reshading for "mobile vibrancy," which is how contrast regressions get
  introduced silently.
- Dynamic type: all `sp`-based text scales with system font size; mono
  fields (addresses, hashes) allow horizontal scroll rather than truncating
  further under larger type.
- Reduced motion: the countdown in §6.7 and any shimmer/skeleton
  animations respect `Settings.Global.ANIMATOR_DURATION_SCALE` /
  Compose's motion-reduction signal — the countdown still updates its
  number, just without an animated sweep.

## 8. Open questions for CTO / Engineer (not blocking, tracked here)

1. Exact shape of the `act` scope (§5, §6.4, §6.9) — binary or
   per-capability (lookup vs probe vs scan priced differently)? Affects
   whether §6 needs three disabled-reason strings or one.
2. Whether credits can be topped up in-app at all (§6.7) — out of scope
   only excludes one-tap *scan* purchase, not a top-up surface broadly.
3. Server-side invalidation on unpair (§6.9) — confirm before Engineer
   builds the local-only fallback path as anything but a true fallback.
4. Notification settings row (§6.9) sketched then flagged as probably
   premature, since push is explicitly out of scope for v1 — recommend
   dropping it from v1 entirely rather than shipping a dead toggle; left
   in the wireframe only so the removal is a visible decision, not a
   silent omission.

## 9. Still outstanding

No visual-truth check has been done on this doc — there is no running
Android build to screenshot, and this delegate's gate requires a live
render for UI-visible work before a "grounded in direct inspection"
verdict. This doc is low-fi ASCII/prose per the issue's own constraint
("no code," "low-fi wireframes… are enough"); the real visual check
belongs to the Engineer's first implementation pass, reviewed against this
spec with actual screenshots at build time.
