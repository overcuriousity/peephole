# peephole — design spec

Date: 2026-09-29
Status: approved by user (brainstorming complete)

## 1. Purpose

peephole replaces a SANS honeypot in the operator's network. Premise: any request
routed to a nonexistent route is treated as potentially malicious (that is what
the operator observes in their network). peephole receives that traffic, logs it
in a structured database, classifies its severity, and counter-scans the source
IP with nmap at an intensity proportional to the inbound attack. All results are
stored in a structured way for later research ("scan the scanners").

Deployment target: a single Rust binary on a Debian LXC, running as root.

## 2. Decisions locked during brainstorming

- Stack: Rust, tokio + axum, sqlx with embedded SQLite (bundled), webauthn-rs for
  FIDO2, nmap as managed subprocess with `-oX` XML output parsing.
- Database: embedded SQLite (WAL mode). Exports on demand: CSV, Parquet,
  Timesketch JSONL; filterable by timeframe (and other filters) from the admin UI.
- Listeners: two plain-HTTP ports on one binary.
  - Trap port (default 8080): HAProxy perimeter routes fallback traffic here
    directly (HAProxy → trap, no nginx in between).
  - Admin port (default 8443): nginx terminates TLS in front of it.
- No notifications module: all "notification" happens inside the web UI (inbox
  view / badges). No SMTP.
- False-positive claims ("I landed here by accident"): recorded with optional
  contact email, surfaced in the admin inbox — but the scan still proceeds
  (maximum research data).
- Privileges: runs as root (user decision), so nmap can do `-sS`/`-O`. nmap is
  still invoked with fixed argv, no shell.
- Counter-scan ceiling: includes nmap `intrusive` NSE category and `-A` at the
  top level; non-silent timing profiles allowed. Nothing designed to disrupt the
  target. (Legal note: even this is a grey zone in some jurisdictions; the
  operator accepted this. Nothing in the app performs denial-of-service or
  exploit execution.)
- Classification: behavioral ladder + curated TOML signature rules (hybrid).
  Every request is labeled with *why* it was classified — labels are stored per
  request row.
- The app does not need the operator's public IP. The only identity-ish config
  is the WebAuthn RP ID (the dashboard's public domain name).
- Trap page visual direction: "clean official notice" (light, professional,
  security-appliance look) — option A from the mockup session
  (`.superpowers/brainstorm/`).
- Trap page does deep browser fingerprinting + behavioral biometrics
  (amiunique-style superset + typing/mouse behavior), and transparently displays
  the detected metrics to visitors in a human-friendly, bot-unfriendly way.

## 3. Architecture

Single binary, internal modules with one job each:

```
peephole/
├── main.rs            # wiring: load config, open DB, spawn tasks, bind listeners
├── config.rs          # config.toml parsing + validation
├── trap/              # listener 1 (:8080) — trap page, bait login form, FP button,
│                      #   /collect fingerprint endpoint, display panel
├── admin/             # listener 2 (:8443) — public stats, WebAuthn login, per-request
│                      #   detail, inbox, live queue view, exports, key management
├── classify/          # behavioral ladder + TOML signature rules → severity + labels
├── fingerprint/       # JS collector asset, attribute store, fp_hash, correlation
├── scan/              # scan queue, dedup/cooldown, level→nmap argv mapping, XML parsing
├── intel/             # daily jobs: Tor exit-node list, MaxMind GeoLite2 (City + ASN)
├── store/             # SQLite (sqlx, WAL), migrations, all queries
└── export/            # CSV / Parquet / Timesketch-JSONL export with filters
```

(The previously considered `notify/` module is deliberately absent.)

Runtime model (tokio):
- Two axum listeners (trap, admin).
- Scan worker pool draining a persistent queue table in SQLite (survives
  restarts). Default 2 concurrent nmap subprocesses (configurable).
- Scheduler task for daily intel downloads (Tor exit list, MaxMind DBs), with
  jitter; also runs on startup when data is missing.

Module boundaries: `trap` and `admin` never touch the filesystem or spawn
processes; they go through `store`. `classify` is a pure function over a
captured request (unit-testable). `scan` is the only module that spawns
processes. `fingerprint` owns the collector JS asset and all attribute
processing/correlation.

## 4. Data flow

Inbound (trap listener):
1. Any request, any method/path, hits the trap port → capture: source IP
   (from `X-Forwarded-For`, only trusting the configured proxy), method, path,
   query, headers (full set, in received order), body, timestamp.
2. `classify` scores severity → level + rule labels.
3. Row written to `requests`; IP upserted into `ips`, enriched from local
   MaxMind DBs (country, ASN/org); Tor exit-node check against cached set.
4. Tor exit node → marked `is_tor_exit`, no scan queued. IP within rescan
   cooldown → logged, no new scan (unless a higher level than the last scan
   applies — one upgrade allowed). Otherwise a scan job is enqueued.
5. Response: the trap page (disclaimer, FP button, bait login form, fingerprint
   collector, "What we see about you" panel). Submissions to the bait form and
   the FP button are themselves captured requests; bait input escalates
   severity; FP claims create an `fp_claims` row (scan still proceeds).

Fingerprinting (trap listener, `/collect`):
1. Collector JS runs on page load, gathers static attributes, streams behavioral
   summaries; posts asynchronously (sendBeacon/fetch). Never blocks rendering,
   fails silently. Tied to the request by a per-page token.
2. Server stores attributes verbatim, computes `fp_hash` (stable-attribute
   hash), behavioral summary; links to the request and IP.
3. Bot-tell signals (e.g. `navigator.webdriver`, instant form fill) feed back
   into `classify` as escalation signals.

Scan (worker pool):
1. Worker takes the highest-severity queued job → spawns `nmap` with the level's
   argv (fixed array, no shell) → parses `-oX` XML → writes open ports,
   services/versions, OS guess, and the raw XML (compressed) to the DB.
2. Job status: `queued → running → done|failed`, visible live in the admin UI.

## 5. Scan levels & self-protection

| Level | Name        | Trigger example                                   | nmap profile (indicative)                        |
|-------|-------------|---------------------------------------------------|--------------------------------------------------|
| 0     | none        | Tor exit node, allowlisted CIDR                   | —                                                |
| 1     | superficial | single plain 4xx probe                            | `-sS -T2 --top-ports 100`                        |
| 2     | standard    | repeated distinct path scanning, scanner UA       | `-sS -sV -T3 --top-ports 1000`                   |
| 3     | deep        | trap-form interaction, generic injection patterns | `-sS -sV -O -T3 -p- --script=default`            |
| 4     | intensive   | clear exploit payload (SQLi/RCE/traversal sig)    | `-sS -sV -O -A -T4 -p- --script=default,intrusive` |

Exact argv per level lives in `config.toml` (sensible defaults above, operator
editable; non-silent/faster timing allowed at higher levels).

Self-protection (so we don't overload ourselves):
- Persistent queue; max N concurrent nmap workers (default 2).
- Per-scan wall-clock timeout; retries with capped attempts.
- Per-IP rescan cooldown (default 24h); one-time level upgrade within window.
- Global rate cap: max scans/hour (config); excess jobs stay queued, not dropped.
- `never_scan` CIDR allowlist in config.toml (own infra, monitoring, …).

## 6. Classification

Hybrid of a behavioral ladder and signature labels:

- Behavioral ladder (no maintenance): first 4xx from an IP = probe; repeated
  distinct 4xx paths within a window = scanner; interaction with page elements
  (bait form POST) = active attacker.
- Signature rules: small curated TOML rule set (~30 rules; SQLi, XSS, path
  traversal, RCE, sensitive paths like `/.env` or `/wp-login`, scanner user
  agents). Each rule has a weight and a label. Rules are editable without
  recompiling; the app is fully functional with the shipped defaults.
- Fingerprint bot-tells escalate (e.g. `webdriver=true`, inhuman fill speed).
- Final score = ladder position + highest signature weight (+ bot-tell
  escalation) → mapped to scan level. All matched labels are stored on the
  request row (research value: "all SQLi campaigns from AS12345").

## 7. Data model (SQLite, WAL)

- `requests` — id, ts, ip_id, method, path, query, headers_json (ordered), body,
  labels_json, severity, scan_level, is_fp_claim, page_token.
- `ips` — id, ip (unique), first_seen, last_seen, country, asn, asn_org,
  is_tor_exit, fp_claimed, notes.
- `fp_claims` — id, ip_id, request_id, ts, contact_email (nullable), user_agent.
- `scan_jobs` — id, ip_id, level, status, queued_at, started_at, finished_at,
  attempts, error.
- `scans` — id, job_id, ip_id, level, started_at, finished_at, os_guess,
  raw_xml_compressed.
- `ports` — id, scan_id, port, proto, state, service, product, version.
- `fingerprints` — id, request_id, ip_id, ts, fp_hash, visitor_id,
  attributes_json, behavior_summary_json, event_blob_compressed.
- `credentials` — WebAuthn credentials for the single admin (multiple FIDO2
  keys).
- `sessions` — admin session state (short-lived, post-WebAuthn).
- `intel_meta` — last fetch timestamps/status for Tor list and MaxMind DBs.

## 8. Interfaces

### 8.1 Trap interface (port 8080)

- Serves the notice page for any method/path. Visual direction A: clean, light,
  official security-notice look.
- Page contents:
  - Disclaimer: "This request was directed to a route which does not exist.
    Your IP address was classified as potentially malicious and will be
    scanned." plus one neutral line: "Browser characteristics are recorded for
    security research."
  - "I landed here by accident" button → reveals optional email field and, on
    submit, the confirmation "the admin was notified; if you want to be
    contacted for clarification, fill in your email address" (email optional,
    storable alongside the claim).
  - Bait login form with label: "this login form is for malicious bots. if you
    want to ensure to get flagged, fill this form." Accepts arbitrary input
    (SQLi payloads stored as plain text; sqlx bound parameters everywhere).
  - Fingerprint collector (invisible) + "What we see about you" panel (below).
- `noindex,nofollow`; no links to the admin interface.

### 8.2 Fingerprinting (detail)

Static attributes (amiunique superset): navigator (UA, languages, platform,
hardwareConcurrency, deviceMemory, webdriver, plugins/mimeTypes, maxTouchPoints,
PDF viewer), screen (resolution, color depth, pixel ratio, orientation,
window/screen delta), locale (timezone, Intl), rendering (canvas fingerprint,
WebGL vendor/renderer + parameter dump, font enumeration via text measurement,
emoji rendering, CSS media queries: color-gamut/HDR/contrast/prefers-*), audio
(AudioContext fingerprint), storage availability, JS-engine quirks (math
constants, error stack formatting, function toString tampering/proxy detect),
automation markers (CDP artifacts, window.chrome shape, __nightmare,
callPhantom, selenium/playwright/puppeteer tells), WebRTC local candidates where
obtainable, adblock probe. Long-lived visitor ID (cookie + localStorage) to
recognize return visits across IPs.

Server side: full header set in received order (a fingerprint itself); consumes
an optional `X-JA4` header if HAProxy is ever configured to pass one (not
required).

Behavioral biometrics: mouse trajectory (velocity, curvature, pauses,
teleports), click/touch patterns, scroll behavior, focus/blur timing,
time-to-first-interaction, typing cadence on the bait form (dwell/flight time,
paste events, fill order, corrections). Stored as compressed event stream +
precomputed summary features.

Correlation: `fp_hash` and visitor ID are correlated across different source
IPs in the dashboard (same operator hopping proxies = core research question).

### 8.3 "What we see about you" panel

- Human-readable, style-A panel on the trap page listing detected metrics:
  browser/OS, screen, timezone, languages, fingerprint highlights (fonts count,
  canvas/WebGL/audio), visitor-ID status ("seen before from N other IPs"), and
  plain-language behavioral verdicts ("form filled in 0.6s with zero mouse
  movement — inhuman", "typing cadence consistent with automation").
- Bot-unfriendly rendering: built client-side with deliberately unstable
  structure — randomized element ids/classes/nesting, shuffled section order per
  page load, values split across nodes and reassembled by JS, decoy markup; no
  machine-readable endpoint (the `/collect` response is an opaque ack). A
  determined scraper can still extract it; a dumb bot gets nothing for free.
- Panel updates live as more behavior is observed (after meaningful interaction
  or a short idle window).

### 8.4 Admin interface (port 8443, behind nginx TLS)

Unauthenticated (public wall of shame):
- Aggregate stats only: top attacking IPs, countries, ASNs, severity
  distribution, recent activity charts, live scan-queue view. No per-request
  detail, no raw headers/payloads, no fingerprint PII.

Authenticated (FIDO2/WebAuthn only — no password fallback, ever):
- Everything above, plus: per-request inspection, per-IP detail pages (all
  requests + scans + ports + fingerprints), inbox (FP claims with contact
  emails), exports, FIDO2 key management.
- Login: single admin account, multiple resident keys via webauthn-rs. First
  start prints a one-time setup token to the console, which gates the initial
  key enrollment. WebAuthn RP ID and origin are set in config.toml (the public
  domain the dashboard is reached at through nginx).
- Live scan-queue view uses Server-Sent Events (no polling).

## 9. External integrations

- Tor exit nodes: daily fetch of the official Tor Project bulk exit list;
  cached in memory + timestamp in `intel_meta`. On fetch failure keep
  yesterday's list; dashboard badge if older than 48h.
- MaxMind GeoLite2: account ID + license key in config.toml; daily download of
  GeoLite2-City and GeoLite2-ASN into the data dir; queried locally via the
  `maxminddb` crate (no per-request API calls). Same stale-data fallback.
- Both jobs run at startup if data is missing, then every 24h with jitter.

## 10. Exports

From the authenticated admin UI, with timeframe and other filters (IP, label,
severity, country, ASN):
- CSV
- Parquet
- Timesketch JSONL: `datetime`, `timestamp_desc`, `message`, plus fields such
  as source_ip, port, service, severity — directly ingestible by Timesketch.

## 11. Configuration (config.toml)

- listen addresses for trap and admin ports
- database path, data dir
- WebAuthn: rp_id, origin, rp_name
- MaxMind: account_id, license_key
- scan: max_workers, per-scan timeout, rescan cooldown, max scans/hour,
  never_scan CIDRs, per-level nmap argv overrides
- classify: path to TOML rule directory (ships with defaults)
- trusted proxy addresses (for X-Forwarded-For)

## 12. Deployment & operations

- `cargo build --release` → single binary. systemd unit, runs as root.
- Config at `/etc/peephole/config.toml`; data dir `/var/lib/peephole` (SQLite
  DB, MaxMind files, Tor list snapshot).
- Startup validation: nmap present and supports required flags; config sane;
  DB migrations applied; MaxMind/Tor data present or fetch scheduled.
- Backups: copy the SQLite file (+ data dir) — WAL mode allows online copies
  via the SQLite backup API.

## 13. Testing

- Unit: `classify` (rule corpus: request → expected labels/level), nmap XML
  parsing (recorded fixtures), fingerprint hashing/correlation, behavioral
  summary computation.
- Integration: app on ephemeral ports with temp SQLite — trap flow (request →
  classification → queue), FP claim flow, /collect flow, WebAuthn ceremony
  against a soft token, auth split (public vs authenticated endpoints).
- Scan worker pool tested against a fake nmap stub (queue ordering, cooldown,
  rate cap, timeouts).
- `cargo test` must pass before any release build.

## 14. Explicitly out of scope

- SMTP/any external notification channel (inbox is web UI only).
- Disruptive counter-measures (DoS, exploit execution) — hard no.
- Multi-user admin, password login of any kind.
- Public per-request data (public side is aggregates only).
- Knowing/using the operator's public IP (not needed anywhere).
