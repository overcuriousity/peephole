# Changelog

Notable changes per release. Versions follow [Semantic Versioning](https://semver.org/);
release builds are on the [releases page](https://github.com/overcuriousity/peephole/releases).

## [Unreleased]

### Added

- Scan level 5, sold on the Actions card at 256 times the level-1 price:
  nmap's `vuln` scripts (minus `external`) on the top 1000 ports. Only an
  admin's bought scan reaches it; the automatic queue stays within levels
  1–4. Level 5 shares level 4's worker budget and two-hour timeout, and is
  granted only to cluster members of protocol 8 and up.

### Fixed

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
