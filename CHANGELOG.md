# Changelog

Notable changes per release. Versions follow [Semantic Versioning](https://semver.org/);
release builds are on the [releases page](https://github.com/overcuriousity/peephole/releases).

## [0.22.0] - 2026-10-20

Admin UI polish (MIK-686): the wall, the navigation, the IP pages and
the campaign and credits pages say more in plain words. No database
migration, no new setting, no protocol version bump. Two admin URLs
moved and answer with a redirect (see Changed).

### Added
- One IP property strip (shared reading by its named state, Tor exit,
  network kind, scanner or fleet, agent traces) on every admin IP
  surface: the IP page, the lookup result, the `/ips`, ASN and network
  lists, campaign members and request rows. An address with too little
  evidence and no finished counter-scan reads "not scanned", with a link
  to the scan action. `/ips` gets an "Address sharing" select. Public
  pages keep the bare Tor badge (MIK-697).
- The ASN page shows registrant, country, registry, AS kind, abuse
  contact and ranges, from data the node already holds; a missing value
  reads "not known" (MIK-710).
- A glossary line per fingerprint kind and the path shape, as hover
  titles on the request, analytics, links, IP and campaign pages and as
  a visible glossary block; a hard/soft edge legend on the campaign list,
  the campaign page and its graph (MIK-710).
- `/requests?persona=` filters requests by persona; the analytics
  persona rows link to it (MIK-696).

### Changed
- URL change: `/admin/inbox` answers 301 to `/admin/system/inbox`, and
  `/admin/cluster/credits` answers 301 to `/admin/market` (query string
  kept). Inbox now sits under System; Credits is a top-level Market tab,
  shown only when the node runs a cluster (the page is 404 otherwise).
  The send form posts to `/admin/market/send`; the old
  `/admin/cluster/credits/send` is gone, with no redirect (MIK-696).
- Wall: the fake-AI card ranks MCP methods, names a foreign tool under
  the models' rule and replaces the bare "other" with what the folded
  row holds; campaigns and personas share one full-width card; recent
  requests stack below 600 px (MIK-696).
- Analytics: the agent-traces empty state says what counts as a trace
  and that rows from before v0.20.0 were never checked (MIK-696).
- Credits: "Reference here" becomes "Our price per scan", with a note on
  what it is computed from and when the 1.25 cap applies; credits tables
  label their times UTC (MIK-696, MIK-710).
- Campaign page: the header says what ties the group ("soft link only:
  path similarity 0.64"), small groups get a shorter graph, the Timeline
  folds intel-lookup rows behind a toggle and stacks below 600 px
  (MIK-689).
- Device evidence card: the caveat sits under the finding, the sentence
  names the port, the AS note is its own line, and device rows and
  counter-scan headings carry "job # · scan #" (MIK-689).
- Docs: `net.eyeball` needs a written ASdb grant (MIK-694).

### Fixed
- Scan capacity used no longer reads 100 % at zero capacity: the
  overview and credits tiles show a dash with no meter. A price move is
  shown as this node's only when it has a price now; beside a dash there
  is no move badge (MIK-688).

## [0.21.0] - 2026-10-19

Device evidence (MIK-586, MIK-587) and shared-address reading
(MIK-596). Each node derives typed evidence about a source address from
rows it already holds and shows a device verdict on the admin IP page.
On top of it the admin names, for each source address, whether the
evidence says it is likely shared (a carrier-grade NAT, a mobile carrier,
a pooled dynamic line) or one subscriber's own network, with the rule and
the rows it rests on, never a score. The export and the blocklist carry
the same reading so a consumer can see when an entry stands for many
households. One database migration (0047, additive), applied on start.
No new setting, no protocol version bump. The reading is a cost warning,
not a verdict: a pool or mobile address changes hands within hours, so
read it as "blocking this may hit others", not as "this was not the
scanner".

### Added
- Device evidence: a node-local `ip_evidence` table (migration 0047)
  holds typed observations about an address, derived from the node's own
  scans, names, host keys and canaries (`device.cpe`, `device.proxy`,
  `name.*`, `fleet.*`, `net.hosting`). The hourly campaign pass recomputes
  it in one transaction; it is never replicated, never exported and never
  written by a person (MIK-586).
- Admin IP page: a device/evidence verdict with the rows it rests on, and
  the IP directory filters on it with `/ips?evidence=<kind>`. The evidence
  recompute report counts verdicts by rule (MIK-586).
- `net.hosting` from the X4BNet `lists_vpn` datacenter ASN list. A
  snapshot is built into the binary (`rules/evidence/x4bnet/`, MIT notice
  in `NOTICE`); `rules/evidence/as-supplement.toml` adds scanner ASNs the
  list misses, each with a reason and a date. Each node now fetches the
  list from GitHub at startup and then daily, on the Tor exit list's
  cadence and backoff, into `<data_dir>/x4b-datacenter-asn.txt`: a new
  outbound request. A failed or implausible fetch keeps the loaded list.
  The admin system page shows the last fetch, or the snapshot's date
  (MIK-587, MIK-608).
- Operator-naming catalogue: `rules/evidence/names.toml` gains `cgn`,
  `mobile` and `pool` classes (tokens such as `cgnat`, `lsn`, `lte`,
  `mobil`, `dynamic`, `ppp`), split out of the consumer entries so the
  reading can tell a pooled line from a consumer one. New evidence kinds
  `name.cgn`, `name.mobile` and `name.pool`; evidence version 3
  (MIK-647).
- Admin IP page: an "Address sharing" card under the device verdict
  applies the eight rules of [Shared addresses](docs/shared-addresses.md)
  as one first-match table and shows the state, the rule, the direction
  and every matched row, linked to its scan or name. Name rows are exempt
  from the 24-hour device staleness; a name seen more than 30 days
  before the address's `last_seen` no longer counts. The IP directory filters on it with `/ips?reading=<state>`,
  and the evidence recompute report counts addresses per rule (MIK-647).
- Export: a `shared` column `{state, rule, v, source, name}`, derived at
  publish time by the exporting node from its own rows, never stored or
  replicated. It is set only for rules 2, 4, 5 and 6 and only where the
  name it rests on is one the `names` column lists, so a consumer can
  recompute every value from the export and the bundled catalogue; rules
  1, 3, 7 and 8 give null. Parquet `format_version` 2; the column is last
  in CSV (MIK-646).
- Blocklist: a `# shared <ip> rule=N v=N: …` comment line before an entry
  with such a reading. Entry lines and membership are byte-identical to
  a feed without the comments; the operator's name stays out of the feed
  (MIK-646).
- Blocklist `networks=1`: a /24 or /64 holding a shared address is never
  collapsed into a network entry. The skip only narrows a feed, it never
  adds an entry (MIK-646).

### Changed
- Scan levels 1 to 3 also probe the relay/proxy ports 1080, 4145, 8118
  and 9050 and the consumer-device ports 7547, 8291, 8089, 5555 and
  37777. Operators see these probes on the wire (MIK-586).
- The sharing card follows the UX review: the caveat and direction text
  come before the sentence, a neutral badge without a rule number in its
  tooltip, a separate link to `/ips?reading=`, the `/ips` chip shows the
  state's label, `Kind` and `Seen (UTC)` columns with first and last day,
  the name's real lookup source (PTR / rDNS / DNS), and the Names line
  jump clears the sticky header with a visible outline (MIK-652, MIK-662,
  MIK-665).

## [0.20.0] - 2026-10-19

Personas and AI agent detection (roadmap #2 and #3). Each node presents
as a product, its AI decoys answer with an identity of their own, and
requests an LLM agent drove are labelled. One database migration (0046,
additive), applied on start. No new setting, no protocol version bump.

### Added
- Personas: the trap presents as one of five products, `wordpress`,
  `fortinet`, `gpu-box`, `gitlab` or `exchange-owa`. Nothing to configure:
  the node key picks one for the bare IP and for every Host that is not a
  public DNS name, and each public DNS name gets its own, fixed per key
  and name. A persona changes the banner only: `GET /` answers with that
  product's front or sign-in page (carrying the page token), every trap
  response carries its `Server` header, and every decoy still answers
  under every persona (MIK-562, MIK-563).
- The persona is recorded on every request and light row, shown on the
  request and the node in the admin, and exported as a `persona` column.
  In replication it is an optional record field, left out when absent;
  an older member stores the row without it (MIK-562).
- Per-node AI decoy identity (decoy version 5): the MCP decoy's server
  name and version, tool names, extra tools and resources, and the LLM
  gateway's model lists and Ollama version are drawn from the node key,
  so one fingerprint no longer names every member. A persona biases them
  (an `exchange-owa` MCP server gets a mail-ops name, a `gpu-box` gateway
  lists more and larger local models). Older rows render with the
  identity they were served (MIK-561, MIK-563).
- AI agent labels: `ai-agent-artifact` (chat-template tokens, tool-call
  tags and JSON, refusal or self-description text in the target, body or
  a header) and `ai-agent-tooling` (SDK and agent-framework User-Agents,
  `X-Stainless-*` headers, an MCP `initialize` naming a known agent
  client). Both are weak tells capped at a level-1 scan; rules gain an
  `unless_target_regex` veto that keeps `ai-agent-artifact` off the LLM
  decoy endpoints. Checked for precision over the live dataset before
  release (MIK-564, MIK-565).
- Admin: an agent filter on the live feed and `/requests`, an agent badge
  on the IP page and an "agent-driven" mark on campaigns (MIK-566);
  Analytics per persona (counts, follow-up rate, family mix) and the
  share of agent-driven sources and campaigns over time (MIK-567).
- Public dashboard: attack mix per persona (cluster-wide only, from three
  distinct IPs up) and the share of sources with agent traces;
  `/api/stats` gains `agent_ips` (MIK-567).

### Compatibility
- Labels are derived by each node from its own rules. Until every peer
  runs 0.20.0, old and new builds disagree on agent rows: an older build
  does not label `ai-agent-artifact` / `ai-agent-tooling`, so its counts,
  levels and campaign marks for those requests differ from a 0.20.0
  node's. Rows from older members carry no persona.

### Database
- Migration 0046: `requests` and `skipped_requests` gain a nullable
  `persona` column with partial indexes (additive).

## [0.19.0] - 2026-10-18

New paths and exploit waves (roadmap #1): early warning when a path no rule
knows starts spreading. One database migration (0045, additive), applied on
start; `rule_hits` is backfilled in the background. Two new optional
settings sections, `[waves]` and `[notify]`. No protocol change.

### Added
- `/admin/paths` ("New paths"): every path shape with first and last seen,
  distinct IPs, whether a rule matched, its wave and the campaigns that asked
  for it; `?since=` and `?unknown=1` filters (MIK-534).
- Exploit waves: a shape no rule knows that `[waves] min_ips` (default 10)
  distinct IPs ask for within `[waves] window_minutes` (default 60) is
  recorded once as a wave; checked every 5 minutes (MIK-539).
- The live feed badges new shapes and waves; a campaign's page names the
  waves its members started.
- `[notify]`: an optional webhook (JSON) or ntfy push per detection pass,
  at most 10 waves, three attempts, no redirects, 10 s timeout; https or a
  loopback/private http address only. Off by default.
- The public dashboard and `/api/stats` count the new path shapes of the
  period (`new_shapes`); paths themselves stay admin-only (MIK-542).

### Database
- Migration 0045: `shapes` gains `rule_hits` (backfilled in the background),
  new table `waves` (additive).

## [0.18.2] - 2026-10-18

Credits visibility (#75): the Credits page says whose figures it shows
and adds the cluster's. One database migration (0044, additive), applied
on start. No protocol change, no new setting; prices are unchanged.

### Added
- The Credits price table gains *Cluster sold / h* (charged receipts in
  the replicated ledger) and *Cluster offered / h* (live scanners'
  capacity for scans, members' announced `on_demand` for providers; "—"
  where members announce nothing) (MIK-528, MIK-531).
- Relays leased (MIK-529): a node that cannot be dialled lists the relay
  leases it holds, with their end and price, on the Credits page and in
  `peephole credits`.
- `peephole credits log` lists this node's sales: one `sold` line per day
  and good, with total, count and payers (MIK-530).

### Changed
- The price table's *Demand / h* and *Supply / h* read *Sold here / h* and
  *Offered here / h*; the chart tooltip says the same (MIK-531).
- *Sold here* counts the charged receipts of the hour in the ledger
  instead of the last refresh's rate, and the previous hour is recounted
  for late receipts (MIK-528).

### Database
- Migration 0044: `price_history` gains `cluster_demand` and
  `cluster_supply` (additive).

## [0.18.1] - 2026-10-18

### Fixed
- Elements with the `hidden` attribute stay hidden: the firm-price dialog shows "Get a new price" only once the quote has expired or failed.

## [0.18.0] - 2026-10-18

Observations: the admin pages correlate what peephole saw by address,
network, campaign and artifact. Two database migrations (0042, 0043),
applied on start; their backfills run in the background. No new setting,
no protocol change; the cluster's intel share gains the kind `tor-relays`,
and exports and `/api/v1` gain `is_tor_relay`.

### Added

- The command sent to a dropped webshell is stored in a column of its own
  (MIK-493; migration 0042, `requests.cmd`), set at insert and backfilled
  in the background for older rows. Admins filter the requests search by
  it with `/requests?cmd=` (chip "Webshell command").
- Tor relay enrichment from Onionoo (MIK-507, #138): a new `tor-relays`
  provider says for any IPv4 or IPv6 address whether it is a Tor relay, in
  which roles and which relay. The admin intel card shows nickname,
  fingerprint (linked to Tor Metrics), ORPort, first seen, family size and
  version, and says when a Shodan `tor` tag or an open port matches the
  ORPort; the public IP page shows only "Tor exit" or "Tor relay (roles)".
  The relay index is fetched conditionally, sanity-checked like the exit
  list and shared in the cluster (`tor-relays.json`). Exports and
  `/api/v1` gain `is_tor_relay`.
- IP page Timeline (MIK-497): every observation of an address (requests,
  webshell commands, uploads, canaries, probes, scans, fingerprints,
  intel), newest first and paged, replaces the Requests table. The public
  IP page shows only released requests, published scans and probes,
  without older pages.
- Network pages (MIK-496, MIK-503): `/admin/asn/{n}` rolls up an AS (tiles,
  label, port and campaign pivots, its 50 busiest IPs) and every admin AS
  badge links to it. `/admin/net/{handle}` does the same for an RDAP
  network: migration 0043 adds `ips.rdap_handle` and `ips.rdap_name`,
  backfilled for stored IPs; the RDAP handle on the intel card links to it,
  and `/ips` filters by `net=` and `net_name=`.
- Pivot links (MIK-498): a user agent, path, webshell command, open port,
  product, OS, upload sha256 and campaign link to the list filtered to that
  value, on the request, IP, scan, upload and link pages, the requests list
  and the Timeline. `/admin/uploads?sha256=` takes 64 hex digits.
- Campaign artifacts (MIK-500): the campaign page lists its members'
  uploads and webshell commands and a merged Timeline with an IP column.
- Search (MIK-495) finds an upload sha256, a campaign by `#N` or `C12`, and
  a label. An RDAP handle or network name opens its network (MIK-503).
- User agent as a link kind (MIK-504): a user agent opens its Links page,
  which leads on to its requests. It is not campaign evidence.
- Firm-price quotes in the admin area (MIK-505): in a cluster, the scan
  level and the Lookup's Ask and Ask again buttons show a price dialog and
  buy only with a quote, through the same quote store and pricing as
  `/api/v1`, audited the same way. The Lookup page answers from the
  dataset at once and fills each provider's card as it answers. Standalone
  nodes stay free and immediate.

### Changed

- IP and request pages consolidated (MIK-499): Canaries and Decoys fold into
  one Lures card; the same-ASN count moves into the AS link; empty
  Fingerprints and False-positive claims cards are gone and the link graph
  is a head chip. On the request page the fingerprint is a row under JA4H
  and the Query string card is gone.
- Shorter page text (MIK-494, MIK-501): the analyst pages (probe, intel,
  campaign, links, uploads, canaries, decoys, search, lookup, analytics,
  scans, export, dashboard, about) and the operator pages (credits, scans,
  node, cluster, ownership, devices, settings) are cut to the essentials;
  an operator page keeps one line under its heading and its rules in one
  collapsed section. The
  edge rules are on `/admin/links` only. The node page shows a member's
  credit balance as the member itself counts it.
- Dependency updates (MIK-518, #148): zstd, uuid, toml, hyper, serde_json
  and the CI actions (#96–#99, #101–#104).

### Fixed

- IPv6 Tor exits are refused for counter-scans like IPv4 ones (#138). The
  bulk exit list holds IPv4 addresses only; Onionoo exit addresses and the
  ORPorts of exiting relays now count too. See `docs/detection.md` for what
  the rule covers.

## [0.17.0] - 2026-10-18

Campaign clustering v2 and upload lures. One database migration (0041),
applied on start; every node recomputes its campaigns on the first start of
this version. No protocol change, no new setting.

### Added

- Upload lures (MIK-486): file POSTs to the upload scripts bots use
  (UEditor `action_upload.php`, `UploadFile.php`, `api.ali.php`,
  `metadatauploader`, the wp-file-manager and laravel-filemanager
  connectors) are taken as script uploads; `admin-ajax.php` is not. A
  file-manager decoy (`wp_filemanager.php`, elFinder's landing pages,
  wp-file-manager's admin page) answers its landing probes with an upload
  form posting to a taken script, so the probe goes on to the upload
  (`DECOY_V` 4).
- Admin IP and request pages (MIK-480): the IP page gets an admin-only
  "Uploads and webshell commands" section (newest ten of each, with their
  upload kind), linking on to `/admin/uploads?ip=` and
  `/requests?ip=&answer=webshell`; the request page links the uploads it
  carried, shows the command it sent a webshell, and the campaign chip of
  its IP.
- `peephole store campaigns-eval [CONFIG]` (MIK-484) compares the campaign
  parameters on the stored rows and prints the result. It derives path
  shapes into the database it is given: run it on a copy.

### Changed

- Campaign clustering v2 (MIK-483, MIK-485; `CAMPAIGN_V` 2): a soft edge
  also weighs request order. Two IPs that first asked for their shared rare
  path shapes in the same order (agreement at or above 0.5) count like a
  JA4 and JA4H match, and the edge's reason ends in "order agrees" on the
  campaign page and in the link graph. A chaining guard merges two groups
  of two or more IPs over soft edges only when at least two soft edges join
  them, so one look-alike pair no longer chains two campaigns into one;
  soft edges between groups that stay apart are withheld. The
  `recompute-campaigns` report gains one line counting withheld soft
  edges, vetoed pairs and the candidate pairs with a known order.
  Migration 0041 adds `campaign_edges.agreement`. A new version can split a
  campaign and give the split-off parts new keys: join dataset exports
  made by the same version.
- A tarpitted source's upload is taken, not held (MIK-486): the upload
  skips the tarpit before a hold is taken, so the source's next request is
  still held. The per-source, daily and store gates are unchanged.

### Security

- `zip` 8 → 9.0.5 (MIK-488) clears the read-side advisories
  RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369. The export
  writer is unchanged.

## [0.16.0] - 2026-10-16

Campaign clustering (roadmap item 2): source IPs tied together by shared
evidence are grouped into campaigns, recomputed on each node from the
replicated rows. Two database migrations (0039, 0040), applied on start. No
protocol change, no new setting.

### Added

- Path shapes (MIK-433): each request path gets a normalized, versioned
  shape (query dropped, lowercased, UUID, digit, hex and random-token
  segments replaced by placeholders; `SHAPE_V` 1). Shapes are derived on
  insert, local and replicated, for full requests and light rows, and a
  startup backfill derives them for stored rows. Shapes are never
  replicated. Migration 0039 adds `requests.shape`/`shape_v`,
  `skipped_requests.shape`, `skipped_batches.shape_v`, their indexes and
  the `shapes` table.
- Campaign recompute (MIK-434): a deterministic pass groups IPs by hard
  edges (a shared SSH host key, TLS certificate, browser fingerprint or
  reused canary) and soft edges (rarity-weighted Jaccard over path shapes;
  a shared JA4 and JA4H only lowers the threshold). A hard value on more
  than 50 IPs is excluded as shared infrastructure and reported. Every
  order and tie-break goes by IP text, so the campaign key (the IP text of
  the member active first) is the same on every node. The pass runs once
  after the shape backfill, then hourly, and skips when its input is
  unchanged; a failed pass logs a warning. Migration 0040 adds
  `campaigns`, `campaign_members` and `campaign_edges`.
- `peephole store recompute-campaigns [CONFIG]` runs a pass at once and
  prints the report. `store` is an alias of `db`.
- Admin Campaigns area (MIK-435): a read-only list at `/admin/campaigns`
  filtered by country, ASN, minimum size and period, with the excluded
  values and the last pass's time; a campaign page with members, every
  evidence edge and its reason, requests per day and the shared path
  shapes; and a "member of campaign #N" chip on IP pages.
- Campaign graph (MIK-436): the campaign page draws its members and
  evidence edges (focus `campaign:<key>`), paths edges dashed, the edge
  reason on hover. The graph stops at 2000 edges, identity edges first,
  and is then marked truncated.
- Public wall (MIK-437): a "Campaigns this period" tile with counts and
  family labels only, no addresses.
- Dataset export (MIK-437): a `campaign` column in CSV, JSON Lines and
  Parquet, the campaign key of the row's address when the export ran
  (null when none). Documented in `docs/dataset.md`, with the Campaigns
  area in `docs/operations.md` and `docs/overview.md`.

## [0.15.3] - 2026-10-16

Code structure, tests and dependencies from the full review (MIK-370,
batch 3). No behaviour change, no database migration, no protocol change,
no new setting.

### Changed

- The store no longer depends on the admin, scan or trap modules (C7).
  Pure code both sides use moves into a new `model` module and into the
  store; the old paths re-export it.
- `cluster::Node` groups its credits, peer and lookup state into
  `Node::credits`, `Node::peers` and `Node::lookups` (C7). Fields, locks
  and initial values are unchanged.
- `arrow` and `sqlx` build without unused default features: no
  arrow-csv/arrow-json, no sqlx `any` driver, `migrate` or query macros.
  Remaining duplicate crates are documented.

### Tests

- Racing pairing-code redemptions pair exactly one device (T4).
- A replayed owner envelope runs once over the wire; a stale or
  future-dated one is refused (T5).
- A misconfigured proxy keeps the shared sign-in limit (T6).
- The RPC receiver refuses oversized bodies before a handler (T7).
- Two timing tests wait for an event instead of sleeping.

## [0.15.2] - 2026-10-16

Hardening from the full review (MIK-370, batch 2). No database migration,
no protocol change. One new setting: `[credits] device_daily_cap`.

### Security

- A signed-in state-changing request must carry `Origin` or
  `Sec-Fetch-Site`; one with neither is refused (S2). Requests without a
  session (sign-in ceremony, bearer API calls) are unchanged.
- Only a live admin session skips the shared sign-in rate limit; a
  sign-in ceremony cookie no longer does, so one cookie replayed from many
  sources cannot lift the global cap on password guessing (S3).
- The process sets umask 077 at start, and warns with path and mode when
  the node key or the database is readable by group or others (S5).
  Existing files are not chmodded.
- AbuseIPDB and Shodan API keys and the MaxMind licence key print as
  `[redacted]` in logs and debug output (S6). Config files parse unchanged.
- A paired device's spend through `/api/v1` (probes, scan buys, lookup
  buys) is capped per rolling 24 hours (S7). A call that would exceed the
  cap answers `429 spend_cap` before anything is spent; free calls always
  pass. New setting `[credits] device_daily_cap` (credits, default 100,
  `0` turns the cap off, 0 to 1000000).

### Fixed

- One panic while a lock is held no longer panics every later user of
  that lock (C3): every lock recovers from poisoning with a warning naming
  the call site. CI refuses new unchecked lock sites.
- Errors that were silently discarded (setup token, fingerprint and claim
  inserts, owner command log, logout, passkey counter, session prune,
  intel fetch timestamps, peer contact save, role reconcile, member
  reload, fleet sync, bot counter-scan enqueue) are now logged (C4).
- Blocking work (upload zip, export encoding, nmap XML parsing, RDAP
  bootstrap reload and write) runs off the async workers (C5).
- The `/api/v1/ips` cursor is clamped to the last page the store reaches,
  so a crafted cursor cannot overflow the offset or repeat rows, and small
  page sizes no longer stop early (C6).
- Credit ledger arithmetic is checked: a step that would overflow is
  logged and ignored, leaving balances unchanged; release builds panic on
  integer overflow instead of wrapping (C9).

## [0.15.1] - 2026-10-14

Fixes from the full review (MIK-370). No database migration, no protocol
change.

### Security

- The automatic setup token no longer bypasses the password (S1). A node
  signed in by password minted and printed a fresh 24 h setup token on
  every start, and that token enrolled a key and opened an admin session
  without the password. The token is now issued only while neither a
  password nor a key exists, and checked when used: once either exists it
  authorises nothing, so a token issued before the password was set stops
  working. A token from `peephole admin reset-token` is still accepted.

### Fixed

- A panic in a long-lived cluster task (replication and its per-peer
  loops, heartbeat, maintenance, the cluster RPC server, the arbiter's
  lease sweep and job hand-out) is logged at `error` with the task's name
  and stops the node, which systemd restarts, instead of the task dying
  silently (C1). Every panic is logged through tracing with its message,
  location and thread.
- A panicking audit purchase no longer disables audits until restart (C2).

### Tests

- CSRF/Origin refusal of cross-site writes on the admin forms and the
  JSON buy (T1); `no_price` and `no_budget` refusals on a cluster node,
  with nothing queued or charged (T2); upgrades from older databases keep
  their rows, and a database newer than the build is left untouched (T3).

## [0.15.0] - 2026-10-14

Counter-scans of addresses no listener recorded (MIK-329). Database
migration 0038; no protocol change.

### Added

- The lookup page offers a counter-scan of an address that is not in the
  dataset, and `POST /admin/lookup/scan` and the device API's
  `/api/v1/ips/{addr}/scan` sell one. The buy adds the address to the
  dataset, marked unseen (no traffic recorded, no country or ASN made up),
  in the same write as the job; a refused buy adds nothing. The scan
  prices and quote of the device API answer for such an address without
  adding it.
- Unseen addresses are labelled wherever an address is shown: the lookup
  result, the IP page and the IP lists carry an "unseen" badge, and
  `/api/v1/ips` and `/api/v1/ips/{addr}` an `"unseen"` field (docs/api-v1.md).
  The first request from the address makes it seen, first seen then.
- Unseen addresses feed no attacker data: never on `/api/blocklist`, not
  counted in the dashboard and stats.

### Changed

- An address not in the dataset gets a scan only past the checks a probe
  obeys first: never a non-global address, `never_scan`, this node's or a
  member's address, or one on the operator's lists (`422 refused` on the
  device API, before `404`). Recorded addresses keep their checks.
- A peer stores the row of a scan job for an address it has no request
  from as unseen too, until a request comes.
- RDAP, Shodan's InternetDB and the Tor exit list are free goods, not a
  market: no node prices, keeps, records or announces a price for them, and
  `peephole credits market`, the Credits page and the lookup page no longer
  list them. Their results show as before, a request for one (also from a
  0.14.0 member) is served at 0, and their on-demand share still applies.

### Security

- rustls 0.23.45 → 0.23.46 for RUSTSEC-2026-0346, -0347, -0348 and -0349.

## [0.14.0] - 2026-10-13

Protocol 9: a free market. Every node must upgrade to 0.14.0 to trade on
it. A node of protocol 8 stays in the cluster and is still paid and
charged under the protocol 8 rules, but only nodes of 9 set their own asks
and bids.

### Added

- Each node sets its own asks and bids (docs/protocol.md). The default ask
  starts at the lower median of the members' announced prices and follows
  sales on every node every 10 minutes: dearer after a sale, cheaper
  without one, with no floor. The bid spreads the node's credit lots over
  the hours they have left and splits each hour over the goods its
  automatic buyers want. Two members of 9 trade only when the bid is at
  least the ask; a retry never goes above the bid. Lookups and scans an
  operator asks for by hand are not bound by the bid.
- `peephole credits market` and the Credits page list, per good, this
  node's ask, bid, what it sold and bought over 7 days, and how many asks
  above its bid it refused.
- RDAP spot-checks: each node asks the registry again for 10 % of the IPs
  whose RDAP row another member wrote in the last 7 days (picked by a keyed
  hash), records its own row when the answer differs twice, and counts a
  dispute against the writer, shown on the member's cluster page.
- Resolve refresh: a node re-resolves the names on its own sources once
  their last confirmation is 7 days old, within its resolve bid.

### Changed

- A node's scan jobs may hold or pay for its whole balance; the daily
  share is gone. `[credits] scan_share` still loads, does nothing, and is
  reported as an obsolete key.
- Scan jobs, reverse names and keyed providers' answers (MaxMind included)
  are bought at the seller's ask within the buyer's bid between members of
  protocol 9. An arbiter of 9 grants an automatic scan job only when the
  scanner's ask is at most its scan bid; a scanner of 9 claims jobs only
  from arbiters of 9. A key holder gives away only its own sources and
  those of protocol 8 members; other members buy them.

## [0.13.0] - 2026-10-13

### Added

- Fresh provider lookups from a paired device:
  `GET /api/v1/ips/{addr}/lookup/quote` prices the providers it would ask
  (per provider and total, like the admin lookup page's offer) and
  `POST /api/v1/ips/{addr}/lookup` spends the quote once. A stale quote
  (a provider gone, a price moved) asks and charges nothing. Needs the
  `act` scope.

## [0.12.0] - 2026-10-12

### Added

- `GET /api/v1/ips/{addr}/scan/prices` lists every scan level's price
  range at once, so the app's level picker shows prices before a quote.
  It spends nothing and creates no quote.
- Stateful web decoys (roadmap #1): a file dropped on the trap answers at
  its path as the webshell the attacker expects. A later request there,
  from any source, gets a canned reply to `id`, `whoami`, `uname -a`,
  `pwd`, `hostname` or an `echo` of a plain marker, and an empty 200 for
  anything else; replies are `text/plain` with `nosniff` and never come
  from stored content. The node keeps at most 50,000 answered paths in
  memory, loaded from its own uploads at start.
- Admin → Uploads lists dropped files by hash, size, sniffed type and
  client name; an upload's page shows the later requests at its path.
  Held content leaves only as `<sha256>.zip` (ZipCrypto, password
  `infected`), and each download is logged with who took which hash.
  System → Status shows the content held against its ceiling.
- A public "Webshells dropped" tile with the verbs sent to them, after the
  public delay; the `uploads` table in the Parquet export (metadata and
  hash only); `GET /api/v1/uploads` and `GET /api/v1/uploads/{sha256}`
  (metadata only, see docs/api-v1.md).

### Changed

- The Actions card's scan level buttons show the full price range,
  `{floor}–{max} credits` (one amount when both are equal), instead of
  "from {floor} credits": the same text the app shows.
- `POST /api/v1/lookup` answers every host name it is sent. The cap of 10
  names per request and its per-entry `capped` error are gone; names are
  resolved four at a time instead.

## [0.11.0] - 2026-10-12

### Added

- `POST /api/v1/lookup` takes host names and URLs in a new `names` field
  (up to 10 per request): each is reduced to its host (userinfo dropped),
  resolved as on the admin lookup page, and answered per entry with the
  resolver votes and the stored data on the agreed addresses; a bad or
  unresolvable name is a per-entry error. `{"ips": [...]}` is unchanged.
  The admin lookup page accepts the same URL forms.
- Scan level 5, sold on the Actions card at 256 times the level-1 price:
  nmap's `vuln` scripts (minus `external`) on the top 1000 ports. Only an
  admin's bought scan reaches it; the automatic queue stays within levels
  1–4. Level 5 shares level 4's worker budget and two-hour timeout, and is
  granted only to cluster members of protocol 8 and up.
- The machine API `/api/v1` for the companion app (docs/api-v1.md): devices
  pair from Admin → Devices with a single-use code in a QR (5-minute TTL,
  SHA-256 at rest) and then talk bearer-token JSON — paged IP search, one
  address's full record, and bulk stored-data lookup. Device tokens are
  256-bit, hashed at rest, revocable per device. The new optional config
  key `api_tls_spki_sha256` pins the admin origin's TLS key in the pairing
  QR.
- `/api/v1` act endpoints for devices paired with the `act` scope: start a
  probe, quote and buy a counter-scan (a quote is bound to the device,
  address, level and price, lives 2 minutes and is spent once; a refused
  buy queues and charges nothing), and poll the job. They run the Actions
  card's own checks. Every queued job is audited and listed under Recent
  actions on Admin → Devices.
- `GET /api/v1/ips/{addr}/probe/vantages` lists the probe vantages the
  Actions card offers for an address, with their prices and the default
  pick (standalone: this node, free). Same gates as starting a probe; it
  spends nothing.
- The trap keeps files dropped on it: PUTs, WordPress plugin, theme and
  media uploads and multipart POSTs to common upload scripts keep up to
  1 MiB of the first file (name sanitised, type sniffed), stored once per
  SHA-256 and replicated beside the entry to members. The client is told
  the upload landed. Runtime settings `uploads.enabled`,
  `uploads.per_source` (per hour, IPv6 by /64; past it only the hash is
  kept), `uploads.daily_mb`, `uploads.store_max_mb` and
  `uploads.min_free_mb` bound it; `uploads.enabled = false` restores the
  old handling. Older builds skip the content.

### Changed

- The Probes card on an address is easier to read: the location and
  fingerprint checks each open with a one-line verdict, the verdict column
  shows "impossible" or "not contradicted" as a pill, fields that differ
  get their own table with the odd vantage out highlighted, fields that
  agree fold into one value-and-count table, and each vantage's ports sit
  in a card grid.
- The public page is called "Public dashboard" (nav: "Dashboard") instead of
  "Wall of shame". Its address and the `[public]` settings are unchanged.
- New logo: a door peephole whose ring carries three cluster members. It
  follows the system's light or dark theme.
- A config key peephole does not know (misspelled, or from a newer version)
  is no longer ignored silently: the startup log and `check-config` warn
  about it by its full path, e.g. `scan.never_scan_directory`. It still
  loads. `check-config` also points out the optional `scan.own_addresses`,
  `scan.never_scan_dir` and `scan.trusted_origins` when they are not set.
- `trusted_proxies` refuses a `/0` prefix, which believed every client about
  its own address (and let it have this node scan whom it named); the
  installer refuses it too instead of warning. A range wider than an IPv4
  `/8` or an IPv6 `/32` loads with a warning.
- `cluster.takeover_hours` must be between 1 and 720: a window of minutes
  handed jobs of arbiters that were merely slow to others, which scanned
  them twice.
- Protocol 8: an admission dated before its sponsor's own admission counts
  as made at it, for the 20-a-day limit and the date it is kept with. A
  new member could otherwise date admissions back over weeks it was not in
  the cluster, 20 for each day. A node's own admission of its inviter or
  a configured peer does not date them: they were members before.
- An audit agrees with a scan only when at least half of the ports each
  of them found open are open in both: a scan reporting every port (or
  the top 1000) open no longer agrees with whatever the audit finds. The
  same host key still settles it, unless the scan claims more than twice
  as many open ports as the audit found.
- Protocol 8: a scanner writes its scan receipt before it reports the
  job done, and a scan receipt dated at or after the job's done status
  (as the log holds it) moves no credits: the offer lapses back to the
  arbiter. The done status designates the scan for an audit, so a
  scanner charging after it could charge nothing for exactly the scans
  that were designated, or skip designation altogether. A receipt counts
  while no done status is held; once one dated earlier arrives, the
  count says unpaid. Scanners below protocol 8 charge after the done
  status, so they are not paid for scans until they upgrade.
- A member that does not earn on a node (rules or audit gates) is
  credited its sales and pool shares there as before the gate, so the
  members it paid keep what they received; what it still holds of that
  income goes back to its buyers by what each paid, and the pool's part
  is burned. Before, its receipts were dropped over the whole 8-day
  window, so its own payments came out uncovered and third parties lost
  credits they had already been paid. Every node must count alike:
  protocol 8.
- A scanner owes audits (and is not funded) only once four of its
  designated scans of 7 days lack a bought audit and it bought fewer than
  60 % of them (was two and 80 %): an honest scanner whose ranked auditors
  are all offline or decline now and then is not cut off.

### Fixed

- Scans: two buys of the same address and level at once (Actions card or
  `/api/v1`) queue one job, not two. An API scan whose audit entry cannot
  be written is withdrawn and reports `failed`.
- Scans: a standalone node ran a failed scan's retry at once instead of
  after its delay (10 minutes, doubling to 2 hours), so a broken nmap
  failed the same addresses several times a second for as long as it
  stayed broken. Retries now wait; a cluster scanner also no longer asks
  an arbiter whose queued jobs are all retries not yet due.
- Admin: a security key deleted while a sign-in with it was under way
  (up to ten minutes) could still finish that sign-in and get a full
  session. Deleting a key now ends every open sign-in, a session starts
  only while its key is enrolled, and a session whose key is gone is
  no longer honoured.
- Admin: a password sign-in whose check overlapped a password change or
  a switch to security keys only could still get a session. The session
  now starts only if the password checked is still the stored one and
  password sign-in is still on.
- Admin: changing the password was neither rate-limited nor counted
  against the cap on concurrent password checks, so a stolen session
  could guess the current password in parallel and start any number of
  Argon2 jobs. It now has the sign-in endpoints' per-client limit and
  takes one of their check slots.
- Admin: deleting a key said nothing when it did not happen; a database
  error left the key working while the page looked as if it was gone.
  The keys page now says whether the key was deleted, was the last way
  in, was not found, or could not be deleted.
- Cluster: membership entries sent ahead of the log must keep their
  signer's order (past its log held, dated after its latest entry and
  its earlier admissions). Before, a member could sign admissions at
  made-up sequences dated back over weeks and push them, admitting far
  more than 20 nodes a day on every node it reached.
- Cluster: the membership sent ahead in a push, a pull reply or a join
  reply is taken up to 2000 entries, as many as an honest one carries (a
  longer push is refused), and each is looked at twice at most. Before, a
  peer could send any number and hold the database's write lock for a
  time growing with its square.
- Cluster: a push to a peer goes on only while the peer takes entries of
  the origins pushed, for 64 batches at most per round. Before, a member
  answering each push with a head for a made-up origin kept the push
  going forever and held one of the 8 sync slots.
- Cluster: directed messages are told apart by sender and id, ids longer
  than 64 bytes are refused, a sender's ids are remembered up to 16384,
  and at most 256 requests are handled at once. Before, a member could
  fill a node's memory with made-up ids or handlers left waiting.
- Cluster: an outbound-only node counts a relay lease for an hour at
  most, whatever end the relay answers, so a relay claiming a lease
  without end is still renewed or replaced in time.
- Cluster: a sync long-poll listing more than 10000 origins is refused,
  and the rest are looked up in constant time on each change while it is
  held open, instead of searched through.
- A failed upgrade no longer restores the database of a node with a
  `[cluster]` section: the backup rewound the node's signed log, and the
  entries it signed next forked from its peers' copies, which marked it
  forked for good. The installer keeps the migrated database (the older
  version reads it) and says where the backup is.
- A runtime settings change read the stored settings on a second database
  connection while it held the write lock; with the pool busy it waited for
  one while blocking every writer, the trap's included. It reads within its
  own transaction now.
- One unusable saved runtime setting no longer discards all the others
  (e.g. after `peephole settings reset roles.scanner` left
  `roles.listener = false` with no role on, the saved `scan.max_workers`
  was dropped too, without a word): only that setting is ignored, with a
  warning. `peephole settings reset` refuses a reset that would leave
  another saved setting unusable, and a change that would bring back one
  ignored so far.
- A background task that panicked (the public-page publisher, the intel
  scheduler, enrichment, the cluster's loops, …) stopped silently while the
  node went on reporting healthy. Such a panic now stops peephole with an
  error, and systemd starts it again.
- The installer warns when it cannot verify the build provenance because
  the GitHub CLI is missing, instead of relying on the checksum (from the
  same server) without a word, and says how to require or skip the check.
- Bulk deletes (requests or IPs, "all matching") wrote every tombstone in
  one transaction and held the database for as long as that took; the
  trap's writes waiting behind it timed out and requests were lost. They
  now commit 500 records at a time, with a pause in between, like
  retention.
- Cluster: a member's lookup result dated in the future (or not dated at
  all) put off every node's next lookup of that address with that
  provider for good. Its fetch time is now held to the time of its log
  entry, as for shared intel files.
- Cluster: a member's light row dated 1970 (or before year 1) moved the
  address's first sighting there for good, and its canaries with it.
  Times before 2000 are now held to 2000-01-01, as times from the future
  are held to the present.
- A deleted IP's public page was served from the cache for up to ten
  minutes, each view logging "cache refresh failed". It now answers
  "not found" from the first refresh after the delete.
- Cluster: deleting an IP left the names this node had looked up for it
  (domain and reverse lookups) on the other nodes, and they kept the IP
  and its lookups there. The lookups are now deleted with it, everywhere;
  a domain lookup goes as a whole, with the names it gave other addresses.
- Searching for an IPv4 address written as mapped IPv6
  (`::ffff:203.0.113.7`), in the IP search, the request filter, Links, the
  bulk lookup or an IP's page, found nothing; it now finds the IPv4
  address it maps.
- Requests of one source arriving at once could each queue a scan job; the
  duplicates took queue places and /24 and ASN budget until superseded.
  Automatic enqueues now check and write one at a time.
- The dashboard's timeline and its families and OWASP tags read every
  request row in full for the 30-day and all-time ranges, every five
  minutes. A new index covers both (migration 0031; it is built once, at
  the first start after the upgrade).
- A domain looked up again kept the addresses an earlier lookup agreed on
  as agreed, though the newer lookup no longer returned them; they stayed
  in the "agreed name" search and the dataset's `names`. The newest lookup
  of a name now stands alone, whichever order the lookups arrive in.
- Re-reading stored scans after an upgrade (host keys, scan facts)
  decompressed and parsed each batch's nmap XML while holding the database
  write lock. The XML is now read before the lock is taken.
- Dataset export: the scans of every address on a page were held with
  their whole nmap XML (up to 64 MiB each), so an address scanned often
  could take any amount of memory. An address's scans now carry at most
  16 MiB of XML, newest first, and a page at most 64 MiB; a scan left out
  says `"xml_omitted": true` (a new field, see the dataset docs).
- The Decoys page fetched a row per LLM decoy request of the range (the
  whole history for "all time") on every view, only to count them. The
  database counts them now.
- Level-5 scans could not be audited: auditors applied the evidence
  re-check, which never backs level 5, and protocol-7 scanners were
  ranked among their auditors. An audit of a bought job now skips the
  evidence re-check as the scan did, and only protocol-8 scanners audit
  level 5 (protocol 8).
- A request without an offer for a priced good (a lookup, a name or
  reverse-name resolution, a probe) counted as demand, so anyone could
  raise a server's prices for free; only goods answered free or paid for
  count now.
- Offers written together (a domain asked of up to nine resolvers, a
  round of scan jobs while a lookup is paid) named the same oldest
  credits, so most came out under-covered and were declined although the
  node held enough, and each could draw from the fleet on its own. A
  node now writes its offers and transfers one at a time, each from what
  the ones before left, and draws from its siblings once at a time. A
  scanner runs a funded job only when its offer is covered in full.
- A lookup, probe, relay or audit offer could draw from a lot that died
  before the offer was charged, so the server received credits already
  gone. Every offer now leaves out the lots that die within its lifetime,
  as scan offers did.
- An audit counted as bought on the strength of a receipt the ledger
  ignores (dated before its offer, or after the offer lapsed); it now
  takes the receipt the ledger counts, as paid scan jobs already did.

## [0.10.0] - 2026-10-09

### Breaking

- Protocol 7: a new economy of credits. The daily mint, the allowance and
  the judging of scans are gone; 1000 credits a day are split among the
  members anyone can reach (advertised listeners up 12 of 24 hours, by
  hourly reach reports). Balances start at zero: payments of earlier
  versions are kept but no longer counted. Upgrade every member in one
  sitting; a member below protocol 7 is neither paid nor charged, and is
  served no entries of protocol 7 until it upgrades.
- `peephole credits why` is gone; `peephole credits uptime` lists each
  member's reported hours.

### Changed

- Prices follow sales and have no floor: a good nobody buys becomes free,
  and a good priced at zero is served without an offer.
- Every scan job is funded; there is no idle work. A job no claimant can
  be paid for waits.
- Domains and reverse names are quorum goods: `min(9, ⌊n/2⌋+1)` of the
  cheapest nodes are asked. The reverse names of a source are bought by
  the node that recorded it and replicated with their agreement.
- Scanners buy audits of their designated scans (1 in 20 scans of paid
  jobs, drawn from the log) from ranked auditors, and are not funded while
  they owe them. Each scanner still re-checks `[credits] audit_share` of
  other nodes' fresh scans unpaid.
- An outbound-only member gets no share of the daily pool and, without a
  relay lease, cannot be asked anything (remote config and owner commands
  included); answers to its own requests still reach it.
- The Actions card is laid out anew: probe vantages as chips, the four
  scan levels side by side. Every button shows its cost ("Probe · 0.04
  credits", "L4 · from 0.06 credits", "Look up · up to 0.12 credits", "Ask
  again · 0.10 credits") or why it does nothing now: a probe on its way
  says how many vantages answered, a level with a job says queued or
  running, a level with a result less than a day old links to it. A
  clicked button spins and cannot be sent twice, and the notice after a
  probe or a scan shows on the card.
- Only the number of scan workers paces scanning; it stays configurable
  (`scan.max_workers`, the Scans page). The hourly start cap is gone, a
  scan times out after 30 minutes (level 4 after 2 hours), and the rescan
  cooldown is 24 hours. `scan.timeout_secs`, `scan.level4_timeout_factor`,
  `scan.rescan_cooldown_hours` and `scan.max_scans_per_hour` are ignored
  (`check-config` says so), as are runtime overrides of them saved
  earlier. The pace recommendation is gone. Nodes of earlier versions in
  the same cluster are told the fixed values.
- Probes are no longer capped at 16 ports, need neither level-2 evidence
  nor a finished counter-scan (without one they read the well-known ports
  22, 80, 443, 8080 and 8443), and the same address can be probed again
  right away. The safety rules are unchanged.
- Scan jobs go to the scanner that is cheapest per delivered result at
  the job's level: its price divided by its success rate there. A failed
  scan is not paid, so a cheap scanner that fails a level often no longer
  wins it. A job waits up to 30 minutes for a cheaper live scanner, then
  goes to whoever asks.
- Scanner success rates (level weights) are measured once an hour, five
  minutes after the hour, over the 24 hours before it.
- Prices are refreshed every 10 minutes instead of every hour, in steps
  scaled to the time, so they move as fast per hour as before.
- Cluster › Credits shows, per scanner, what one delivered result costs
  at each level (L1–L4), the cheapest in bold.
- The scan page says why its job went to its scanner ("Handed out"), and
  the Scans history shows the same as a title on the scanner's name.
- Levels 3 and 4 no longer run nmap's `http-comments-displayer`: it
  copied every HTML comment it found, binary files included, and was most
  of some scans' XML. Scans run with the previous list are still accepted.
- During a rolling upgrade, a scan scrubbed by a current scanner relays
  only through current members: an older member rebuilds the record
  without the count, and the signature no longer matches. The gap heals
  once every member has upgraded.

### Added

- Outbound-only members lease two relays an hour from reachable members,
  which sell them (`[cluster] relay_slots`, 16 at a time); members reach
  an outbound-only member through the relays its heartbeat lists.
- The Actions card sells a counter-scan of level 1–4: level 1 at the
  cluster's cheapest scanner offer, four times that per level above. The
  job runs through the normal queue and appears live on the IP page; a
  result of the same level less than 24 hours old stands instead of a new
  purchase.
- What a scanned source serves and calls itself. Each port of a scan
  shows what `-sV` added (extra info, OS and device type, the announced
  host name, CPEs) and the fixed fields of a few scripts: page title and
  redirect, `Server` header, login realm, Windows computer and domain
  names from RDP and SMB, SOCKS methods, DNS server id. The scan page has
  a Host card, each scan's heading on the IP page a one-line summary, and
  the export carries the port fields and a `facts` list per scan. Nothing
  is parsed from prose. Stored scans are read once at startup.
- The scanner's own address stays out of its scans. A scanned mail server
  greets the client by address and name, and nmap kept that in the XML
  that is signed, replicated and exported. Before signing, a scanner now
  replaces its own global addresses (interfaces, listeners, `advertise`,
  `scan.own_addresses`, the addresses peers saw it from) and their
  forward-confirmed names with `[scanner]`; the scan page says how often.
  Scans signed before this release cannot be changed; each node removes
  its own addresses and names from them when it serves the XML or the
  export, so a node's own old scans leave it clean. Other members'
  addresses in old scans stay (a purge removes a record everywhere).
- Host keys in the export: each scan in the `scans` column lists its
  `host_keys` (kind, port, fingerprint, detail), so nobody has to parse
  the XML for them.
- ETags of scanned sources. Level 2 also runs nmap's `http-headers`; each
  HTTP port's `ETag` is a new soft link kind (`http-etag`, "same file",
  never "same operator"), and nginx's form is dated. Stored scans are read
  again once at startup. The previous level-2 list is still accepted.
- ETags as a return marker. Decoy version 3 answers the web decoys that
  return 200 with an ETag derived from the request, a canary of kind
  `etag`: a client that sends it back in `If-None-Match`, from any
  address, is a canary reuse.
- Reverse DNS of every source: the PTR names of the addresses that sent
  requests that resolve back (`ip_names` source `rdns`), looked up when
  first seen and when the source returns a day later. A standalone node
  looks them up itself; in a cluster the node that recorded the source
  buys them from a quorum and every node keeps them with their agreement
  (agreed or disputed, votes of answers). Shown on the IP page, in the `names` export column, and as
  the IP directory's new Name filter. `[enrichment] reverse_dns = false`
  turns it off.

### Fixed

- A node whose own rows were deleted by hand in the database stopped
  serving its log at the first of them, and every member that joined
  later stalled there and saw only that node. Such entries are now
  written off as deleted (hourly, warning "own log entries had lost their
  rows"), and new members sync past them.
- A new member knows the whole cluster at once. Before, it learned of the
  other members only from its inviter's log, after all of the inviter's
  history in front of each admission had arrived; until then it saw only
  the inviter, and the others' entries were parked or refused. The join
  reply now carries every member's signed admission, and each sync batch
  sends the membership entries ahead of the data.

## [0.9.0] - 2026-10-08

### Changed

- Ownership is about claiming nodes: an unclaimed node's Ownership page
  offers "Your first node?" (create the key) and "Already have a key?"
  (claim this node, choosing between being managed only and also managing
  the others), the key is shown with the next steps, and a claimed node
  lists the members not claimed with its key. `peephole owner claim`
  replaces `peephole owner adopt`, which stays as an alias.

### Fixed

- Cluster: a member whose dial keeps failing (behind NAT, port closed) is
  asked paid lookups, probes and resolutions through its outbox instead of
  timing out on the dial while the offer holds credits.
- Installer: nginx no longer buffers the trap's streamed answers (the MCP
  decoy's event stream, the tarpit's drip).
- Installer: without nginx in front (`direct`, `remote`) the trap listens
  on `[::]` where the host has IPv6, so IPv6 clients are recorded.
- Installer: an admin listener moved off a busy 8443 no longer lands on
  nginx's own TLS port for the admin domain (8444).
- Cluster CLI commands no longer re-announce the config file's roles over
  the ones the daemon runs.
- `check-config` refuses a `cluster.advertise` or peer address that is
  not `host:port` and a `node_name` members would rewrite; the name is
  taken trimmed.
- A stored `roles.web` or `roles.listener` override no longer switches on
  a role whose config sections are gone (the web role panicked on every
  session request without `[webauthn]`).
- Scanner: a failed lease renewal is retried several times before the
  lease runs out, instead of once at expiry (a duplicate scan).
- A join that fails after the invite was checked gives its use back.
- A credit draw asks only siblings on the market rules (protocol 4+).
- A failed hourly price refresh keeps the hour's demand.
- `check-config` names an obsolete `[greynoise]` section; obsolete-key
  notes are logged once at start.
- `deploy/config.example.toml` documents `[probe]` and
  `[enrichment] offer_per_day`.

## [0.8.0] - 2026-10-08

### Added

- RDAP. A free provider (`rdap`) asks the registries who holds the block an
  address is in: range, handle, holder, abuse contact, registration and
  last-change dates; tags `rdap:country:XX` and `rdap:fresh`. Runs in the
  enrichment loop and in every lookup; one query a second per registry,
  the IANA bootstrap is built in and refreshed weekly.
- Observational probes. From the Lookup page or the IP page an admin asks
  a scanner to read what the ports a counter-scan found open volunteer:
  HTTP status, headers, title, cookie names, page and 404 hashes, favicon
  hash; TLS certificate chain, version, ALPN and JARM; SSH banner, HASSH
  and host key (also from OpenSSH 10); otherwise the banner. Redirects
  are followed for at most 5 hops, each hop checked against the safety
  lists and private space. Only ports already found open are touched,
  never more than 16, 10 s per connection, 120 s per probe, one probe per
  address and scanner a day. In a cluster a probe is paid with credits
  at the scanner's market price for probes; the result and the receipt
  replicate together. `[probe] enabled`, `max_parallel`. Admin-only.
- Vantages. The same probe from up to four scanners at once, spread over
  countries, with a field-by-field diff of what each one saw and a
  light-speed check of each vantage's RTT against the address's GeoLite2
  location: a claim the RTT makes impossible is flagged.
- Peer-observed public address. Peers report the address they see a node
  connect from (`hello`); once a sibling or two members agree it is this
  node's public address: never scanned, announced in heartbeats, used as
  the probe's vantage, shown on System › Status.
- Domains in Lookup. A name is resolved by up to five nodes; an address
  counts when more than half of those that answered returned it, the
  rest is shown as disputed. Agreed names are attached to the address
  (IP page, `names` export column) and replicated. nmap's PTR names from
  stored scans are shown there too.
- Lookup is a tab. It runs the providers this node answers itself (free)
  by itself and offers the others with their price; one
  field takes an address, a name or a pasted list. The top-bar search
  routes names to it.
- Links: favicon, JARM, page-body and 404-page hashes from probes, as
  soft kinds (same product, not the same operator).
- A page per decoy's served canaries; request rows are marked where
  canaries were served or used.
- Failed counter-scans are retried for 24 hours with a growing wait
  (10 min doubling to 2 h; the scanner that failed waits longer); a retry
  stops when a newer scan or a pending job covers the address.
- Admin: sign in with a password (optional, per node; `peephole admin
  password`, `peephole admin login-method`). Passkeys stay the default.
- Cluster: outbound-only members answer paid lookups, resolutions and
  probes, routed through the outbox (protocol 6, see Upgrading).
- Trap: a PROXY header from a peer outside `trusted_proxies` is named in
  the log.
- Installer: asks whether to also allow a password sign-in on the admin
  site (`PEEPHOLE_ADMIN_PASSWORD`, at least 12 characters; only its hash is
  stored).
- Installer: before offering to set up nginx it checks what the setup would
  stop at (an existing peephole site, other sites on port 443, a default
  site that is not the stock link, the packages, the admin domain's DNS)
  and lists what it will change; the default is yes only when every check
  passes.

### Changed

- Installer: the scanner is off by default (opt-in, also without a
  terminal). Unattended installs add `scanner` to `PEEPHOLE_ROLES`.
- Installer: a preset `PEEPHOLE_TRUSTED_PROXIES` no longer means a proxy
  elsewhere; unattended installs behind one set `PEEPHOLE_FRONT=remote`.
- Installer: every node gets a `[cluster]` section; the cluster question is
  gone and `PEEPHOLE_CLUSTER` is ignored. The node name defaults to the
  short host name, the address other members dial is required
  (`PEEPHOLE_CLUSTER_ADVERTISE`, `host:port`; default the admin domain or
  the public address with port 7443), and the listener follows its port.
  The invite question names `peephole cluster join <token>` for later.
- Installer: the Let's Encrypt certificate is requested without a contact
  email; `PEEPHOLE_ACME_EMAIL` is ignored.
- Installer: the admin domain is normalised (a scheme, a path and a
  trailing dot are stripped, upper case is lowered); an IP address is
  refused.
- The dynamic market replaces the fixed credit rules. A daily mint of 1000
  credits is split among scanners by counted scans (levels 3 and 4 count
  twice; a scan of a node's own job never counts); the trap share is gone.
- Every member that earns here and recorded a request that day gets an
  allowance of 5 credits.
- Prices follow supply and demand, hourly, per good: no weights, unit,
  surge or free tier. Providers without an API budget and name
  resolution offer `[enrichment] offer_per_day` (default 1000) a day.
- Scan jobs are paid: the arbiter funds them up to `[credits] scan_share`
  (default 0.5) of its balance, scanners ask funded arbiters first and
  charge on delivery.
- What a node answers itself is free; what another node answers is paid,
  every provider (Tor exit list, RDAP, InternetDB, GeoLite2) and domain
  resolution included. There is no free quota; the Lookup page asks other
  nodes only for the providers picked.
- Nothing is burned any more: a payment moves its full price. Credits
  expire 7 days after their day.
- Scan prices are per scanner. Each scanner's price follows its paid scans
  of the past hour against 90 % of its capacity; every node computes every
  scanner's price from the log and pays at most 1.25 times its own figure.
- The arbiter hands each scan job to the cheapest scanner asking. Scanners
  ask arbiters that can pay first; a scanner over its hourly capacity or
  delivering under half of its recent grants goes last.
- A node's own scan jobs are funded from the same `scan_share` budget as
  jobs it buys elsewhere, without moving credits.
- Fleets have no collecting node: every node keeps what it earns, and a
  lookup that needs more draws from the node's siblings, richest first.
- Heartbeats carry `scan_budget_mc` and `scan_queued`.
- Credits page: the scan tile shows this node's selling price, and a table
  lists every scanner's announced and reference price.
- Host keys and certificates may come from a probe as well as a scan;
  `host_keys` is rebuilt with a nullable `scan_id` (migration 0018).
- The README's "escalate by scope, never by speed" rule now says it
  governs the automatic counter-scans.
- Lookup and the IP page: a signals strip (Tor exit, abuse score with a
  meter, registry holder, Shodan, CVEs) above the provider cards; the
  cards pack in columns, say how old each answer is, and list providers
  without a result on one line. Lookup shows one card per provider: asked
  now, from the dataset, or what the dataset holds, instead of the same
  provider twice. An "On this page" bar jumps between sections.
- Cluster › Credits is a market dashboard: each good's price over 7 days
  (this node's, and the lowest, median and highest that members announce),
  its demand and supply, a price table with 24-hour change and sparklines,
  and this node's daily income (mint, allowance, sales) against spending.
  Prices are snapshotted hourly into `price_history` (migration 0022,
  local, kept 8 days). The balance moved to an Overview tile (with what
  expires by tomorrow) and the Lookup page; earned, spent and transfers
  fold away under "Your credits".
- The Overview's Cluster card: four headline figures (earning members,
  scan capacity with a meter, credits in circulation, audits) and the
  rest in one row.
- Dark mode: card and panel borders are visible; nested panels are inset.
- Times on admin pages read `YYYY-MM-DD HH:MM` in summaries, provider
  timestamps included; Lookup and Links tables show countries with flag
  and name and severity as a badge.

### Fixed

- "Delete all N matching" on Requests left out the MCP session filter
  and could delete far more than N; every filter field now travels with
  the bulk forms (on IPs the sort too), and the filter form keeps the
  session and exact-severity filters.
- Switching the time range on Canaries kept no other filter; the IP
  page's "Show the reuses" link now covers all time.
- The Lookup field (a textarea) was unstyled; Filter buttons on Links,
  Decoys and Canaries were too.
- A claim's contact address is no longer a `mailto:` link (it is
  attacker-supplied); it is shown as text with a copy button.
- Charts: the "all" range shows quiet days as gaps; a failed data load
  says so; chart cells no longer take hundreds of tab stops inside an
  image; the tooltip is no longer announced on every mouse move.
- Contrast: the danger button's hover in dark mode and the OWASP grid's
  third step in light mode; stronger focus rings on fields.

### Removed

- `credits.collect_to`, the setting and the "Collect credits here" action
  on the Ownership page.
- GreyNoise Community enrichment. An existing `[greynoise]` section is ignored.
- The manual "Retry failed" action on the Scans page; retries are
  automatic.

### Upgrading

- The cluster protocol goes from 3 to 6. Upgrade all members soon after
  each other: credits move only between nodes on protocol 4 or later, scan
  jobs are paid only between nodes on protocol 5 or later, and an
  outbound-only member answers paid lookups, resolutions and probes only
  once it, the node whose outbox it polls and every member relaying to it
  run protocol 6.
- Migrations 0018–0024 run on the first start, and balances are recounted
  from the log under the market rules: balances from 0.7 change at once
  (no trap share, burn or scanner-1/2 earnings; mint and allowance
  instead).
- Existing installs keep their config; the installer's new questions apply
  to first installs only. Scripts that install unattended: add `scanner`
  to `PEEPHOLE_ROLES` to keep the scanner, set `PEEPHOLE_FRONT=remote` where
  a preset `PEEPHOLE_TRUSTED_PROXIES` meant a proxy elsewhere, and set
  `PEEPHOLE_CLUSTER_ADVERTISE` unless a default applies (the admin domain
  with the web role and nginx or the trap on this machine; otherwise a
  detected public address). An install that was standalone with
  `PEEPHOLE_CLUSTER=0` or without a terminal is now a cluster node: its
  RPC listener takes port 7443 (or the advertise port) on all interfaces,
  so firewall it if other members should not reach it.

## [0.7.0] - 2026-10-06

### Added

- Ownership. One key for all nodes of an operator (`peephole owner new`,
  `peephole owner adopt`, Cluster › Ownership). Your nodes find each other
  and are marked "yours"; from a node that keeps the key you change a
  sibling's pace, cooldown and roles, block and purge peers there, revoke
  its invites, have it leave, release it, and rotate the key (a node left
  out of a rotation is no longer yours). Each node lists the commands it
  received. See docs/cluster.md.
- Lookup credits. Lookups are paid with credits earned by completed
  counter-scans (scanner 1 or 2, the trap a quarter); every node computes
  every balance from its own copy of the log. Prices follow the cluster's
  earnings, lookup capacity and scanner load; half of a payment goes to
  the node that answered, half is destroyed. A lookup shows everything the
  dataset holds on the address, answers under 24 hours old come from the
  dataset for free, and paid answers are kept for recorded addresses.
  Scanners audit a share of each other's scans; a node that shows two
  histories of its log is proven and marked. `Cluster › Credits`,
  `peephole credits`, `[credits] audit_share`,
  `[enrichment] on_demand_share`. See docs/cluster.md.
- Verified research scanners (Censys, LeakIX, Shodan) are recognised by
  forward-confirmed reverse DNS and never counter-scanned, like
  search-engine crawlers; the Scans page links the day's refused jobs with
  their reasons. See docs/scanners.md.

### Changed

- A source whose requests only look — probe, path-scanner, php-probe and
  nothing else — now earns at most a level-1 counter-scan, however often it
  looked; severity is unchanged. Level 2 and up needs a specific rule hit.
- webshell-probe knows the shell names the current spray waves use
  (chosen, simple, adminfuns, dex, go, ccc, sm, ebkid,
  this_is_a_new_hello_world).

- **Breaking:** a member no longer serves 50 free API lookups a day to
  every other member. Lookups in a cluster cost credits, your own
  providers included; a standalone node is unchanged.
- The Members table flags a member for its rules only when it does not
  earn here (less than 98 % agreement); another rules fingerprint alone is
  no issue.
- Export: scans carry `uid` and `audit_of`.
- **Breaking:** config keys are gone. `cluster.remote_config`,
  `peephole cluster config-key` and the config-key cards on Cluster ›
  Access no longer exist; `remote_config` in a config file is ignored with
  a warning. After the upgrade no node can be changed from another node
  until you run `peephole owner new` on one node and `peephole owner adopt`
  on the others.
- Cluster protocol version 3. Ownership works between nodes of this
  version; older members keep syncing as before.

### Upgrading

- Upgrade all members soon after each other. Until a member is upgraded,
  upgraded members answer its lookups with free providers only, and it
  cannot spend credits.
- Balances start from the counter-scans of the last 8 days; there is no
  starting grant. A member whose recent requests were classified by older
  rules may earn nothing until enough new requests are recorded.
- Remove `remote_config` from config files, and replace scripts that call
  `peephole cluster config-key` with `peephole owner …`.
- Do not go back to 0.6.0 and then upgrade again: entries erased under
  0.6.0 can keep the node from sealing its log, and it can then no longer
  pay for lookups. Do not restore a database backup from before the
  upgrade on a cluster node.

## [0.6.0] - 2026-10-06

### Added

- AI decoys. The trap answers MCP and LLM-API probes instead of a 404, so
  the next steps are recorded.
  - MCP over Streamable HTTP (`/mcp`, `/messages`) and the legacy HTTP+SSE
    transport (`/sse`, held streams in a pool of their own), with five fake
    tools (`read_file`, `list_directory`, `run_command`, `query_db`,
    `fetch_url`). Reads and queries return canary content; nothing is run.
    The session ID is a canary (`mcp-session`) that links later requests,
    from any address and node, to the one that started the session.
  - An LLM gateway decoy: Ollama's native API, OpenAI's (Chat Completions,
    legacy completions, Responses, models; also under Azure, OpenRouter,
    LiteLLM-style prefixes) and Anthropic's (messages, count_tokens,
    complete, models). One fixed reply, framed per API and streamed when
    asked; unlisted models get the API's own 404.
  - `decoy_in` (migration 0009): the parsed decoy input stored with each
    request so answers re-render byte for byte. Replicated between nodes
    and exported beside `answer` and `decoy_v`.
  - The rule `llm-key-use` (weight 3), header-only: LLM-provider key shapes
    (`Authorization: Bearer sk-...`, `x-api-key: sk-ant-...`, Azure OpenAI
    `api-key` of 32 hex characters) on any path. `ai-infra-probe` also matches the new gateway
    paths.
  - Admin › Decoys (MCP funnel, sessions, tool calls, LLM models and
    prompts, web decoys), the quick filters "MCP decoy" and "LLM decoy", the
    request and IP pages' decoy details, and the wall card "What they
    asked our fake AI" (tool names ours, model names filtered, from 2 IPs).
  - A legacy SSE message whose stream queue is full is answered `503` and
    recorded as `decoy:mcp:busy`.
  - `[trap]` settings `mcp_sse_pool` (64), `mcp_sse_per_source` (2),
    `mcp_sse_hold_secs` (300).

### Changed

- At most half of a node's workers run level-4 scans (`scan.level4_max_share`,
  default 0.5); the rest keep shorter scans moving. Workers are now 0 (paused)
  or at least 2; a saved 1 is raised to 2, but a config file with
  `scan.max_workers = 1` now fails to start (set 2 or more).
- Level 4 sends at least `scan.min_rate` probes per second (default 300; lower
  it behind a home router) with `--max-retries 1`, and `level4_timeout_factor`
  defaults to 2. Configs copied from the old example set
  `level4_timeout_factor = 4` explicitly; remove the key or set 2 to get the
  new default.
- The queue runs the job with the highest response ratio (time waited relative
  to how long its level takes) instead of the highest level first.
- Presets: level 1 runs at `-T3` with `--version-light`; levels 3 and 4 add
  `--traceroute`; `scan.level4_udp` adds the top 50 UDP ports to level 4 (off
  by default).
- Cluster: claims name the levels a scanner cannot take; older nodes ignore
  the field and interoperate.
- Decoy version 2: renders every version 1 name unchanged plus the new
  ones. The Answer filter now matches any prefix. AI decoys skip the
  tarpit. An AI decoy that cannot be rendered falls back to the version 1
  pick instead of the 404.
- Cluster › Members shows how many requests and scans each node
  contributed, with its share, again; the full breakdown stays on the
  node page.

## [0.5.1] - 2026-10-06

### Changed

- The wall's "When they knock" card is now "Heatmap" and always covers the
  last 7 days, whatever range is picked, so every weekday is filled in
  (`heatmap` in `/api/stats` likewise).
- "What they were after" no longer files most traffic under "Other". A new
  family, Exposure (green), takes `sensitive-path`; `path-scanner`,
  `api-recon` and `graphql-introspection` are reconnaissance. `path-scanner`
  and the new `php-probe` count only when a request has no more specific
  family, and "Other" only when nothing else applies. The regrouping
  applies to stored requests at once; the new rules below only to new ones.

### Added

- Quick filters on the Requests page, one click to apply and again to
  remove, keeping the other filters: last hour, last 24 h, severity 4,
  severity 3+, tarpitted, decoy served, webshell use, credential attacks,
  POST, no user agent. The Answer filter `decoy` now matches every
  `decoy:…` answer.
- Admin › Links picks the kind from a pill bar (identity kinds, then
  software kinds) instead of a dropdown; switching keeps the other filters.
- Rules from a week of real traffic that matched none: `.env` variants and
  browser-side runtime configs (`/env.js`, `/aws-exports.js`), credential
  stores (git, Docker, gcloud, s3cmd, boto, gem, Maven, NuGet, Composer,
  service-account keys, shell histories), app and deployment config
  (`secrets.yml`, `*.tfvars`, `appsettings*.json`, `docker-compose*.yml`,
  `config.php.bak`), CI pipelines, git clone endpoints and SQL dumps, all
  as `sensitive-path`; and `php-probe` (weight 1) for any PHP script, the
  long filename lists sprayed to find shells left by others.

## [0.5.0] - 2026-10-05

### Added

- Tarpit: for an hour after a source's request reaches severity 4, its
  requests get a `200` that drips a byte every 10 s until the client gives
  up or 10 minutes pass (`[trap] tarpit_*`). It has a pool of its own (256
  connections, 8 per source); a held connection gives its listener slots
  back, and with the pool full the normal answer is sent. Addresses that
  are not global and those in `scan.never_scan` or `never_scan_dir` are
  never held; a request carrying a known canary keeps its decoy answer.
  Recorded as `answer = tarpit` with the time held (`held_ms`, new column,
  replicated and exported); shown on the request page, as a "Scanner time
  wasted" tile on the wall (released rows only), and how full it is on
  System › Status.
- The wall lists the newest requests of the last 24 hours ("Recent
  requests", `[public] recent_rows`, default 50): time, IP, method, path
  (no query string, cut at 80 characters), severity and, when shown,
  labels.
- Admin "Links": every browser fingerprint, SSH host key, TLS certificate,
  JA4, JA4H, HASSH and JA4X, not only shared ones, filterable by value,
  date, country and node and sortable by IPs, sightings or last seen. Each
  value (and each IP) has a page with a graph of the IPs it was seen on and
  what else links them: identity links by default, software fingerprints on
  request, crowded values collapsed. Every such value in the admin pages
  links there. The requests search filters by JA4.
- Admin Analytics: every row opens what is behind it: paths, user agents,
  methods, transports and answers the matching requests (from the range's
  start), open ports, products and OS guesses the IPs with them in any
  stored scan, abuse bands, scan levels and job statuses their lists.
  New admin filters: requests by user agent, method, transport and answer;
  IPs by open port, product and OS guess. Applied filters show as chips
  that remove one filter each.
- Requests keep their User-Agent in a column of their own (derived from
  the stored headers on each node; rows stored before are filled in the
  background on start).
- Admin search: the top bar box takes an IP (its page, or a prefilled
  live lookup when not stored), a network, `AS123`, `#<request id>`, a
  path, or a fingerprint, host key, certificate or JA4/JA4H/HASSH/JA4X
  value (its Links page).
- Lookup checks many addresses or networks at once against stored data
  (no provider is asked).
- Every page's footer links the public API specification (`/api`: the
  blocklist feed, `/api/stats`, `/api/map`, `/api/countries`, `/healthz`
  with their parameters and defaults), an About page (`/about`: what
  peephole does, and the legitimate interest it relies on), the source
  repository and the running build. The blocklist names `/api` in its
  comment lines.

### Changed

- Public pages and feeds (wall, IP directory, IP pages, `/api/stats`,
  `/api/map`, `/api/blocklist`) show a request only after
  `[public] delay_minutes` plus a random 0–`jitter_minutes` (default
  5 + 0–5 min). Nothing on them updates live any more: no auto-refresh, no
  "last hit … ago", static UTC times.
- The live "Recent activity" feed moved from the wall to the admin
  Overview.
- The Fingerprints and Canaries pages moved to `/admin/links` and
  `/admin/links/canaries`; the old addresses redirect.

## [0.4.0] - 2026-10-05

### Added

- JA4H, the HTTP client fingerprint (FoxIO), of every HTTP/1 request,
  derived from its raw head on each node (rows stored before are derived
  in the background at start). Shown on the request page, as "top JA4H" in
  Analytics and as a request search filter, and exported as `ja4h`. Never
  public. HTTP/2 requests have none (no raw head is kept for them), nor
  does plain HTTP through a trusted proxy (nginx on port 80): its head is
  the proxy's request, not the client's.

- Cluster: per-level scanner weights. A scanner that fails a scan level
  (hard failures, timeouts aside) more often than the best live scanner
  over the last 24 h (among scanners with at least 5 scans there) sits
  that level out for 10-minute stretches, a share of 1 − its relative
  success rate (weight at least 0.1), so better scanners get those jobs.
  It recovers as failures age out; jobs waiting over 30 min go to any
  scanner. The Cluster page's scanner table shows the weights.

### Changed

- Scan queue: throughput, net growth and the drain estimate are measured
  from the queue (jobs queued vs. jobs that left it over the last 6 h)
  instead of derived from the scanners' paces. The recommended pace is
  sized as before.

### Fixed

- Tables were cut off on narrow screens instead of scrolling sideways.

## [0.3.0] - 2026-10-04

### Added

- Canaries that come back. Decoys serve realistic credentials derived from
  the request (`.env`: AWS keys, app key, database, Redis, mail and admin
  passwords; `.git/config`: a deploy token), with links to the address the
  scanner used. A harvested password opens a fake admin page (Basic auth)
  or WordPress dashboard, and the git token a ref listing, so the follow-up
  lands in the trap. Every node finds requests carrying a served canary,
  cluster-wide and in either arrival order, and names the request that
  harvested it.
- Admin: a Canaries page (served, used again, time to first use, a reuse
  table with filters); request and IP pages show canaries served and
  reuses. Wall: median time from harvest to first use and the share used
  again, from 5 reuses up. Export: `decoy_v`, `canary_used_from`.
  `peephole decoy render UID` prints a stored decoy again.

- Counter-scans: level 2 runs nmap's `ssh-hostkey`, `ssh2-enum-algos` and
  `ssl-cert` scripts (all `safe`: one handshake with a port already found
  open). From their output, and from every stored scan's XML on upgrade,
  each node derives the source's SSH host keys (`SHA256:` as OpenSSH
  prints them), TLS certificates (SHA-256, subject, issuer, validity),
  JA4X and HASSH-server into a new `host_keys` table. Derived locally from
  the replicated XML, so nothing new is replicated.
- Admin: IP and scan pages list the host keys and certificates, marked
  where another source shares one; the fingerprints page shows shared SSH
  host keys and TLS certificates beside browser fingerprints, in the same
  graph; Analytics ranks HASSH and JA4X values.

### Changed

- Decoy answers to sources over their recording rate keep their page
  token, host and answer in the light row, so their canaries are
  traceable.

- Trap: decoys are always on. `/.env`, `/.git/config`, `/wp-login.php` and
  phpinfo probes get plausible fake content with canary credentials and
  status 200, so the follow-up request lands in the trap too. The
  `trap.decoys` setting is gone; an old `decoys = …` line is ignored.

### Fixed

- Fingerprint graph: nodes never moved vertically during layout (the
  update sat behind a comment).
- Analytics: OS guesses need level 2 since 0.2.1, not level 3.

## [0.2.1] - 2026-10-04

### Changed

- Counter-scans: level 2 now adds OS detection (`-O`), so OS guesses cover
  far more sources. Level 2 is also the most a single request earns by
  default (`scan.single_request_max_level`), so those sources are now
  OS-fingerprinted too; `-O` sends a few extra TCP/ICMP probes and stays
  non-intrusive. Override with `scan.level_argv` to keep the old preset.

## [0.2.0] - 2026-10-04

### Added

- Public wall: tiles with change against the previous window, new IPs, a
  request sparkline and time since the last hit; requests over time stacked
  by severity; a weekday × hour heatmap; requests per attack family; an
  OWASP Top 10 / Automated Threats grid; a ranked country list beside the
  map; data bars on top IPs and networks.
- Public wall: "What the scanners run", ports found open on scanned sources,
  counted as distinct IPs and shown only once open on at least 3 IPs. The
  README's privacy section says so.
- Public wall: soft auto-refresh once per cache lifetime while the tab is
  visible. No new public endpoint.
- Public IP pages: rank among all sources, a 7-day hourly chart by severity,
  a 26-week activity calendar, label families, and neighbours in the same
  /24 (/48) and ASN. The IP directory gets data bars, relative "last seen"
  and severity accents.
- Admin: an Analytics page (top paths, user agents, JA4, methods, transport,
  answers, open ports, products, OS guesses, AbuseIPDB bands, scans per
  level and status).
- Admin: a live feed of new requests on the wall (SSE, `/admin/api/recent`),
  which includes rows replicated from other nodes.
- Admin: request page shows the same IP's and the same JA4's other requests;
  fingerprints page has a draggable graph of fingerprints shared across IPs.
- Copy buttons on IPs and identifiers across the admin pages.

### Changed

- Attack families and OWASP tags follow `[public] show_labels`, on the wall
  and in `/api/stats`.
- Descriptive text on all pages cut to one short line or removed. The decoy
  trap page is unchanged.
- Severity chart fills use their own heat ramp, readable when stacked in
  both themes.
- A failed nmap scan that was killed by a signal now names the signal (for
  example `killed by SIGKILL (forced kill, often out of memory)`) instead of
  `exit None`. Normal exits read `exit <code>` instead of `exit Some(<code>)`.
  Failures already stored keep their old text.

### Fixed

- Phone-width layout: the top bar wraps instead of clipping links, stat tiles
  fit two per row, charts draw at their real width so labels keep their size,
  data tables scroll sideways instead of squeezing columns, and long IPv6
  addresses and paths wrap.
- Scan queue sparklines were always empty (charts.js was not loaded).
- Settings checkboxes, pace inputs and the standalone cluster page at phone
  width.

### Notes

- On the "all" range, the timeline/heatmap and the family/OWASP aggregates
  each scan the `requests` table once per cache refresh (5 minutes).

## [0.1.1] - 2026-10-04

### Added

- `cluster agreement` command.
- Installer: checks what sits in front of the trap, checks the port, and
  detects cloud addresses.

### Fixed

- False disagreement in the cluster rules check.

## [0.1.0] - 2026-10-03

First release.

[0.13.0]: https://github.com/overcuriousity/peephole/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/overcuriousity/peephole/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/overcuriousity/peephole/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/overcuriousity/peephole/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/overcuriousity/peephole/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/overcuriousity/peephole/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/overcuriousity/peephole/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/overcuriousity/peephole/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/overcuriousity/peephole/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/overcuriousity/peephole/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/overcuriousity/peephole/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/overcuriousity/peephole/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/overcuriousity/peephole/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/overcuriousity/peephole/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/overcuriousity/peephole/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/overcuriousity/peephole/releases/tag/v0.1.0
