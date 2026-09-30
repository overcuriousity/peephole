# peephole — UI rework and public/admin split

Date: 2026-09-30
Status: approved by user (brainstorming complete)
Supersedes: §8.1, §8.3 and §8.4 of `2026-09-29-peephole-design.md` where they
conflict. Everything else in the original spec stands.

## 1. Goals

1. Both web surfaces — the trap page and the admin listener — look deliberate
   and polished, in the visual family of the operator's `engram` and `Vestigo`
   projects, with a darker, more cyberpunk tint. Automatic light/dark theme.
2. The admin listener splits into a **public wall of shame** (no login) and an
   **authenticated admin area** (FIDO2 session):
   - Public: all aggregate statistics, a choropleth map, search across IPs and
     requests, and a per-IP page showing what that IP requested.
   - Admin only: the live scan queue, counter-scan results, raw headers and
     bodies, fingerprints, false-positive claims, exports, key management, and
     deletion of records.
3. Replace the string-`replace` templating with askama, move HTML generation
   out of the store layer, and fix the structural problems found on the way
   (polling SSE, missing indexes, no pagination, swallowed errors).

## 2. Decisions locked during brainstorming

- Public per-IP depth: **requests only**. Request rows (time, method, path,
  query, severity, labels), GeoIP/ASN/Tor, first/last seen. Counter-scan
  results are admin-only. The aggregate "counter-scans completed" number on the
  wall of shame stays public.
- Never public: raw headers, request bodies, fingerprint attributes, scan
  results (ports, services, OS), false-positive claims and contact emails.
- Look and feel: style reference is `../engram` (tokenized CSS, Inter +
  JetBrains Mono self-hosted, `layout.html` with askama blocks). Retinted
  toward cyberpunk. Auto light/dark with a manual toggle. **All fonts are
  declared in the stylesheet and served from the binary**; no external
  requests of any kind.
- Trap bait form: looks like a genuine "Staff sign-in" card; a muted footnote
  under it states it is a decoy for automated tools.
- Admin data operations: **delete records** (requests, IPs with cascade,
  scans, false-positive claims). No notes editing (the `ips.notes` column is
  unused and stays untouched), no scan control, no claim triage.
- Frontend approach: askama templates, one layered CSS file, vanilla JS, all
  embedded via `include_bytes!`. No Node build step in the release pipeline.
  The world map SVG is generated once by a dev-time script and committed.
- Trap page uses the system font stack (one response per scanner hit, no
  asset fetches on the trap listener beyond `/collect.js`). Operator may flip
  this later.
- `askama = "0.14"` as already declared in `Cargo.toml` is used as-is;
  `askama.toml` sets `dirs = ["templates"]`. `rust-embed` is not added:
  assets are embedded with `include_bytes!` through a small static table.

## 3. Module changes

```
src/
├── admin/
│   ├── mod.rs        # AppState, router assembly, security-header middleware
│   ├── auth.rs       # unchanged ceremony; SessionUser; enroll also accepts a session
│   ├── public.rs     # wall of shame, /ips, /ip/{addr}, /requests, /api/*
│   ├── admin.rs      # /admin/* pages, deletes, exports, keys
│   ├── sse.rs        # broadcast-fed queue stream (gated)
│   ├── assets.rs     # embedded css/js/fonts/map, cache headers, stamp
│   ├── error.rs      # AppError -> styled 404/500
│   └── views.rs      # askama template structs (one per page) + filters
├── store/
│   ├── stats.rs      # ranged aggregates, timeline buckets, map counts, cache
│   ├── browse.rs     # IP directory, paginated request search, IP detail rows
│   ├── delete.rs     # the four deletes, transactional
│   └── ...           # existing files; ip_detail() HTML builder removed
├── scan/mod.rs       # publishes QueueEvent on every job transition
├── trap/mod.rs       # publishes QueueEvent on enqueue
├── events.rs         # QueueEvent + broadcast::Sender wrapper (Notifier)
└── main.rs           # `--version`, `check-config <path>`, default: run
templates/            # askama: layout.html, partials, one file per page, trap.html
assets/
├── css/00-tokens.css … 40-charts.css   # concatenated by build.rs → assets/app.css
├── js/app.js, theme.js, charts.js
├── fonts/*.woff2
└── world.svg         # generated, see §8
tools/build-world-map.mjs
```

Module boundaries as before: `store` returns typed rows and never HTML.
`admin` renders. Only `scan` spawns processes.

## 4. Routes

Listener: admin port (behind nginx TLS), unchanged. Trap listener unchanged.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | public | wall of shame dashboard |
| GET | `/ips` | public | IP directory with search/filter, paginated |
| GET | `/ip/{addr}` | public (+admin sections with session) | IP detail |
| GET | `/requests` | public (+detail links with session) | request search, paginated |
| GET | `/api/stats?range=` | public | JSON aggregates for charts (cached) |
| GET | `/api/map?range=` | public | JSON `{ "DE": 123, … }` unique IPs per country |
| GET | `/healthz` | public | `200 ok` when DB answers `SELECT 1` |
| GET/POST | `/login`, `/login/start`, `/login/finish`, `/logout` | public | unchanged |
| GET/POST | `/enroll`, `/enroll/start`, `/enroll/finish` | setup token **or** session | first key or additional key |
| GET | `/assets/*` | public | embedded assets, `max-age=31536000`, stamped URLs |
| GET | `/admin` | session | live queue, workers, rate cap, intel freshness, inbox count, recent failures |
| GET | `/admin/queue` | session | full job list, filter by status/level, live |
| GET | `/admin/api/queue` | session | SSE stream |
| GET | `/admin/requests/{id}` | session | headers, body, rules, fingerprint |
| POST | `/admin/requests/{id}/delete` | session | delete request |
| POST | `/admin/ips/{addr}/delete` | session | delete IP, cascading |
| GET | `/admin/scans` | session | scan list |
| GET | `/admin/scans/{id}` | session | ports table, OS guess |
| GET | `/admin/scans/{id}/xml` | session | raw nmap XML download |
| POST | `/admin/scans/{id}/delete` | session | delete scan + ports |
| GET | `/admin/fingerprints` | session | fp_hash / visitor_id clusters spanning >1 IP |
| GET | `/admin/inbox` | session | false-positive claims |
| POST | `/admin/claims/{id}/delete` | session | delete claim |
| GET | `/admin/export`, `/admin/export/download` | session | as today |
| GET | `/admin/keys`, POST `/admin/keys/delete` | session | as today, plus "enroll another key" link |

Old paths `/requests/{id}`, `/ips/{id}`, `/inbox`, `/keys`, `/export`,
`/api/queue` are removed (no redirects; nothing external links to them).

`range` accepts `24h`, `7d`, `30d`, `all`; default `24h`. Unknown → `24h`.
`page` is 1-based; page size 100; `LIMIT 101` detects "has next".

## 5. Public/admin rendering rule

One template per page. Each template receives `authed: bool` from the
handler (session cookie validated, no redirect on failure). Admin-only
sections and controls are wrapped in `{% if authed %}`. Data that is admin-only
is **not queried** unless `authed` — the public handler never loads headers,
bodies, scans, fingerprints or claims, so a template mistake cannot leak them.

## 6. Data layer

### 6.1 New queries (`store/stats.rs`, `store/browse.rs`, `store/delete.rs`)

- `stats(range) -> Stats`: totals (requests, unique IPs, countries, tor IPs,
  scans done), top IPs (20), top countries (20), top ASNs (20), top labels
  (20), severity distribution, recent 50.
- `timeline(range) -> Vec<(bucket_ts, count)>`: hourly buckets for 24h/7d,
  daily for 30d/all. SQLite `strftime` grouping over `idx_requests_ts`.
- `map_counts(range) -> Vec<(country, unique_ips)>`.
- `list_ips(filter, page) -> Page<IpSummary>`: filter by exact IP, prefix
  (`LIKE 'a.b.%'`), CIDR (parsed in Rust with `ipnet`; the query fetches
  candidates by first octet(s) then filters in Rust — sufficient at this
  scale), country, ASN, label, min severity, tor. Sort by request count or
  last seen. Each row: ip, country, asn_org, is_tor, first/last seen,
  request count, max severity.
- `ip_by_addr(addr) -> Option<IpRow>`.
- `ip_overview(ip_id) -> IpOverview`: counts, max severity, label breakdown,
  24×hour sparkline buckets.
- `requests_for_ip(ip_id, page) -> Page<RequestListRow>`.
- `search_requests(filter, page) -> Page<RequestListRow>` (replaces the
  unpaginated LIMIT 500 version).
- Admin-only: `scans_for_ip`, `ports_for_scan`, `scan_by_id`, `list_scans(page)`,
  `fingerprints_for_ip`, `fingerprint_clusters()`, `claims_for_ip`,
  `queue_snapshot()`, `queue_summary()` (counts by status, scans in last hour
  vs cap, worker count from config).
- Deletes, each in one transaction: `delete_request(id)` (also its
  fingerprints and claims rows), `delete_ip(id)` (requests, fingerprints,
  claims, scan_jobs, scans, ports), `delete_scan(id)` (ports), `delete_claim(id)`.

### 6.2 Schema additions (append to `schema.sql`; all `IF NOT EXISTS`)

```
CREATE INDEX IF NOT EXISTS idx_requests_severity ON requests(severity);
CREATE INDEX IF NOT EXISTS idx_requests_ip_id_id ON requests(ip_id, id);
CREATE INDEX IF NOT EXISTS idx_ips_country ON ips(country);
CREATE INDEX IF NOT EXISTS idx_ips_asn ON ips(asn);
CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip_id);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_ip ON fingerprints(ip_id);
CREATE INDEX IF NOT EXISTS idx_fp_claims_ip ON fp_claims(ip_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_ip ON scan_jobs(ip_id);
```

### 6.3 Stats cache

`AppState` holds `RwLock<HashMap<Range, (Instant, Arc<Stats>)>>` and the same
for map counts. TTL 15 s. `/`, `/api/stats`, `/api/map` read through it.
Admin pages do not use the cache.

### 6.4 Country names

A static `country_name(alpha2) -> &str` table (ISO 3166-1, ~250 entries) in
`admin/countries.rs`, used by templates, the map tooltip, and the top-countries
list. Unknown codes render as the code itself.

## 7. Live queue

`events.rs`:

```rust
#[derive(Clone, serde::Serialize)]
pub enum QueueEvent { Queued{job}, Started{job}, Finished{job}, Failed{job} }
pub struct Notifier(tokio::sync::broadcast::Sender<QueueEvent>); // capacity 256
```

Held in `TrapState`, passed to `scan::run_workers`, held in `AppState`.
`store.enqueue_scan` stays pure; callers publish after a `Queued` outcome.
Workers publish on every status write.

`sse::queue_stream` (gated by `SessionUser`): sends `event: snapshot` with
`queue_snapshot()` on connect, then one `event: job` per broadcast message,
plus `event: snapshot` every 30 s as a self-heal, plus a 15 s keep-alive
comment. On `RecvError::Lagged` it re-sends a snapshot. The 500 ms DB poll is
gone.

`assets/js/app.js` applies events to the queue table in place (row keyed by
job id), shows a pulsing "live" dot while the EventSource is open and a
"reconnecting" state otherwise.

## 8. Assets

- `build.rs` concatenates `assets/css/*.css` in filename order into
  `assets/app.css` (gitignored, exactly as engram) and exports an
  `ASSET_STAMP` env var from an FNV hash of `app.css`, `app.js`, `charts.js`,
  `theme.js`, `world.svg`. Templates reference `/assets/app.css?v={{ stamp }}`.
- `admin/assets.rs` serves the embedded files with correct MIME types and
  `Cache-Control: public, max-age=31536000, immutable`; `/logo.svg` stays as a
  convenience alias for the favicon.
- Fonts: `inter-400/500/600.woff2`, `jetbrains-mono-400/500.woff2` (Latin
  subsets, OFL). Copied from `../engram/assets/fonts` and Vestigo's dist
  (`jetbrains-mono-latin-500`). ~120 KB total.
- `assets/world.svg`: generated by `tools/build-world-map.mjs` from
  `world-atlas` `countries-110m.json` (Natural Earth, public domain) with
  `d3-geo` (Natural Earth 1 projection) and a numeric→alpha-2 table. Output:
  `<svg viewBox="0 0 960 500">` with `<path id="XX" d="…">` per country,
  Antarctica dropped. Committed; the script is documented but not part of
  `cargo build`. If the tool chain is unavailable at implementation time, the
  fallback is a hand-obtained public-domain SVG with alpha-2 ids, provenance
  noted in `assets/README.md`.

## 9. Visual system

### 9.1 Tokens (`00-tokens.css`)

Same structure as engram: `--font-sans`, `--font-mono`, text scale
`--text-xs … --text-2xl`, `--radius-sm/md`, surfaces `--color-bg-base /
surface / elevated / hover / active`, text `--color-fg-primary / secondary /
muted`, borders `--color-border / strong / subtle`, `--color-accent(-dim,
-muted, -fg)`, `--color-danger / warning / success (-dim)`.

peephole additions:

- `--color-brand: #d00000` (from the logo), `--color-brand-dim`.
- Severity scale `--sev-0 … --sev-4`: grey → amber → orange → red → violet,
  each with a `-dim` tint. Used by badges, bars, sparklines and the map legend
  (map uses a 5-step sequential ramp from `--color-accent-dim` to
  `--color-accent`, not the severity scale).
- Dark (default when the system is dark): base `#0a0b10`, surface `#10121a`,
  elevated `#171a24`; accent cyan `#4fd1e0`; faint grid texture on `body`
  via two `repeating-linear-gradient`s at ~3 % alpha.
- Light: base `#f6f5f0`, surface `#efede6`, elevated `#ffffff`; accent
  `#1f6f8b`; no grid texture.
- Every foreground/background pair must clear WCAG AA 4.5:1; check with a
  contrast script during implementation (engram's comments document its
  values; peephole's tints will differ).
- Theme switch: `:root` = light; `@media (prefers-color-scheme: dark)
  :root:not([data-theme="light"])` and `:root[data-theme="dark"]` = dark.
  `theme.js` (blocking, tiny, first in `<head>`) applies
  `localStorage["peephole.theme"]` before first paint. Toggle in the topbar.

### 9.2 Layers

`10-base.css` reset, typography, focus, selection, scrollbars, `.label`,
`.mono`, tabular numerals. `20-layout.css` topbar, `.shell` (max-width 80rem),
stat-tile grid, two-column card grid, phone breakpoint at 48rem.
`30-components.css` cards, tables (sticky header, hover row, dense variant),
badges (severity, label, tor, status), buttons (primary/ghost/danger),
inputs, pagination, empty states, `<dialog>`, live dot. `40-charts.css`
SVG chart colours, axes, tooltip, map fills and legend.

### 9.3 Pages

- **Topbar**: logo mark + "peephole", nav (Wall · IPs · Requests · Admin when
  authed), range switch on stat pages, theme toggle, Login/Logout.
- **Wall of shame**: five stat tiles; timeline chart full width; row of three
  cards (severity distribution, top labels, top countries as horizontal bars);
  map card full width with legend and tooltip; two-column tables (top IPs,
  top ASNs); recent activity table. Stale-intel banner kept, restyled.
- **IP directory**: filter bar (search input accepting IP/prefix/CIDR, country,
  ASN, label, min severity, tor toggle, sort), result table, pagination.
- **IP page**: header block (IP in mono display size, country + name, ASN org,
  Tor badge, first/last seen, request count, max severity badge), 24 h
  sparkline, label chips with counts, request table with pagination. Admin
  sections below: Counter-scans (one card per scan with ports table and XML
  link), Fingerprints (hash, count, "seen from N other IPs" linking to
  `/admin/fingerprints#hash`), Claims, and a danger zone with Delete IP.
- **Requests**: filter bar, table; with a session each row links to the
  detail page and has a delete control.
- **Admin home**: queue card (live), status tiles (queued / running / done 24h
  / failed 24h, scans this hour vs cap, workers), intel freshness, inbox
  count, recent failures with error text.
- **Request detail**: meta grid, labels, headers as a two-column mono table,
  body panel with text/hex toggle (client-side), fingerprint summary if any,
  delete.
- **Login / Enroll**: centred card, logo, one primary button, status line.
- **Errors**: `404.html`, `500.html` on the layout.
- **Trap** (`templates/trap.html`, inline CSS, system fonts): narrow column
  (40rem). Notice card with a small eye mark and the two disclaimer sentences.
  "Staff sign-in" card: username, password, primary button; footnote in
  `--color-fg-muted` at `--text-xs`: "This form is a decoy for automated
  tools. Real staff do not sign in here." Below: quiet text button "I landed
  here by accident" revealing the optional email form. Then the "What we see
  about you" panel as a definition list card (scrambled markup unchanged).
  Light/dark auto via the same media query, tokens inlined. Still
  `noindex,nofollow`, no admin links.

## 10. Security

- Middleware on the admin router: `Content-Security-Policy: default-src
  'self'; img-src 'self' data:; style-src 'self'; script-src 'self';
  connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri
  'self'; form-action 'self'`, `Referrer-Policy: no-referrer`,
  `X-Content-Type-Options: nosniff`. No inline scripts or styles anywhere
  on the admin listener (the login/enroll JS moves to `app.js`).
- Session cookie gains `Secure` when `webauthn.origin` starts with `https://`
  (always, given config validation). `SameSite=Strict` retained → cross-site
  POSTs carry no session; no CSRF token needed.
- `/enroll/start` accepts a valid session as an alternative to the setup
  token, so additional keys can be enrolled without wiping credentials.
- Public handlers never query admin-only tables (§5).
- Every store error surfaces as `AppError` → `tracing::error!` + styled 500.
  No `unwrap_or_default()` on fallible store calls in handlers.

## 11. Testing

Unit:
- `store/stats`: ranges, timeline bucketing, map counts on a seeded DB.
- `store/browse`: CIDR/prefix/exact search, pagination `has_next`.
- `store/delete`: each delete removes dependents and nothing else.
- `admin/countries`: known and unknown codes.
- askama templates compile (implicit in `cargo test`).

Integration (`tests/integration.rs`, adapted and extended):
- Public `/ip/{addr}` contains request paths and labels, does **not** contain
  a header value, body string, port number/service, or fp_hash seeded for
  that IP. The same URL with a session contains all of them.
- `/admin`, `/admin/api/queue`, `/admin/requests/{id}`, deletes → `303` to
  `/login` without a session.
- Delete IP with a session removes requests/scans/ports/fingerprints/claims
  for that IP and leaves another IP's rows intact.
- SSE with a session: first event is `snapshot`; after `enqueue_scan` +
  notifier publish, a `job` event arrives.
- `/api/stats?range=7d` and `/api/map` JSON shapes; second call within 15 s
  served from cache (same `generated_at` field).
- `/requests?page=2` pagination; `/ips?q=203.0.113.0/24` matches seeded IPs.
- Admin response carries the CSP and referrer headers; `/assets/app.css`
  carries the long `Cache-Control`.
- Enroll with a session and no setup token succeeds.
- Trap page contains "Staff sign-in", the decoy footnote, and no `/admin`
  or `/login` link to the admin host.
- Existing WebAuthn, export and full-stack smoke tests continue to pass.

## 12. Installer and deployment

`install.sh` stays the single entry point (`curl … | sudo bash`) and becomes an
idempotent install-or-upgrade tool. Every run detects whether peephole is
already installed and takes the matching path.

### 12.1 Robustness

- The whole script body lives in `main()` and the last line is `main "$@"`,
  so a truncated download executes nothing rather than half a script.
- Preconditions checked up front with clear messages: root, `apt-get`,
  `systemctl` present and systemd running as PID 1, `uname -m` is `x86_64`
  (the only published asset; other architectures get an explicit "build from
  source" error instead of a 404).
- Prerequisites are installed only when missing (`command -v` / `dpkg -s`);
  `apt-get update` runs only in that case.
- Downloads use `curl --fail --retry 5 --retry-delay 3 --retry-all-errors`
  and fail cleanly if the rolling release is mid-recreation (the release
  workflow deletes and recreates the `latest` tag, leaving a window of 404s).
- The release tarball gains a `VERSION` file (`<git sha> <utc build time>`);
  the binary reports the same via `peephole --version`, compiled in from a
  `PEEPHOLE_VERSION` env var set by the release workflow (`option_env!`,
  fallback `dev`). The installer compares the two and skips download and
  restart when they match unless `PEEPHOLE_FORCE=1` is set.
- The binary is installed to `${INSTALL_BIN}.new` and moved into place
  atomically; the previous binary is kept as `${INSTALL_BIN}.prev`.
- `peephole check-config <path>` is a new subcommand: loads and validates the
  config, parses the rule directory, checks `nmap --version`. Exit code
  non-zero with a readable message on failure. The installer runs it against
  the existing config **before** restarting; a failure aborts the upgrade
  with the message and leaves the old binary running.
- After (re)start the installer waits up to 20 s for
  `http://<admin_listen>/healthz` (address read from `config.toml`) to answer
  `200`. On timeout it restores `${INSTALL_BIN}.prev`, restarts, prints the
  last 30 journal lines, and exits non-zero.
- `shellcheck` and `bash -n` run on `install.sh` in CI.

### 12.2 Upgrade path (config present)

- Config is never rewritten. The installer only reports missing keys that the
  new version knows about (via `check-config`, which warns on absent optional
  sections) so the operator can add them.
- Shipped rule files are treated like conffiles: the installer records the
  checksum of every rule file it installs in `${DATA_DIR}/.installed-rules.sha256`.
  On upgrade, a rule file whose current checksum still matches the recorded
  one is replaced by the new shipped version; a file the operator edited is
  kept and a warning names it and the path of the new version left beside it
  as `<name>.toml.new`.
- The systemd unit is reinstalled (operator customisations belong in a
  `peephole.service.d/` drop-in, which survives). `daemon-reload`, then
  `restart`.
- Deployment snippets: `deploy/nginx.example.conf` is added to the tarball
  and installed to `${CONFIG_DIR}/nginx.example.conf` (never enabled
  automatically). It terminates TLS, proxies to `admin_listen`, and for
  `/admin/api/queue` sets `proxy_buffering off`, `proxy_cache off`,
  `proxy_read_timeout 1h` and `X-Accel-Buffering: no` so Server-Sent Events
  stream through nginx. Without this the live queue stalls behind nginx.

### 12.3 First install (no config)

Unchanged prompts and env overrides. After the health check succeeds the
installer reads the setup token from the journal (`journalctl -u peephole
--since -2min`) and prints it together with the enrollment URL
`https://<domain>/enroll`, so the operator does not have to find it in the
logs. If the token line is absent (already consumed) the message says so.

### 12.4 Release workflow changes

- Writes `VERSION` into the tarball and passes `PEEPHOLE_VERSION=<sha>` to
  `cargo build`.
- Packages `deploy/nginx.example.conf`.
- Runs `shellcheck install.sh` as part of CI.

### 12.5 Tests

- `install.sh` is exercised in CI on `ubuntu-latest` inside a Debian
  container with a stubbed download (local tarball served by `python3 -m
  http.server`, `BASE_URL` override honoured by the script): fresh install
  with env-provided settings, then a second run that must report "already
  up to date", then a forced run with an edited rule file that must keep the
  edit and drop a `.new` beside it.
- Unit test for `check-config` on the example config and on a broken one.
- Integration test: `peephole --version` prints the compiled version.

## 13. Out of scope (recommended follow-ups)

Retention/prune + vacuum; per-IP rate limits on `/collect` and `/claim`;
manual scan control (enqueue/cancel/retry/runtime never-scan); scans/ports
export; `peephole reset-admin` subcommand to reissue the setup token;
rule-hit statistics; SQLite online backup command; per-IP public redaction
flag; dropping or implementing `ips.notes`.
