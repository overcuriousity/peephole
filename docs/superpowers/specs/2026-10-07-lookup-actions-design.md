# Lookup actions: RDAP, observational probes, vantages, DNS by consensus

Date: 2026-10-07 · Status: draft.

Takes "Actions on an IP in Lookup" and the OpenSSH-10 host-key note from
`docs/roadmap.md` and rewords them there when it is implemented. Builds on
`2026-10-06-scan-details-design.md` §1 (peer-observed public address),
which is implemented first.

## Goal

The cluster's paid Lookup answers with what providers hold. It does not look
at the address itself, cannot compare what different parts of the Internet
see of it, and has to be found through the top-bar field. This spec makes
Lookup an analyst's page:

- **RDAP** for every address, free: who holds the block, the abuse contact,
  how old the allocation is.
- An **observational probe** of the ports a counter-scan already found open:
  what the services volunteer (headers, titles, certificates, JARM, SSH host
  keys, HASSH), on demand, paid with credits, run by a scanner of the
  admin's choice.
- A **vantage view**: the same probe from several scanners at once, with a
  field-by-field diff, and a light-speed check of each vantage's RTT against
  the address's claimed location.
- A **Lookup page** that runs the cheap lookups by itself and offers the
  expensive ones with their price; it also takes a **domain**, resolved by
  several nodes with a majority rule, and attaches the name to the dataset.

Priority: depth for the analyst first, a credit sink second.

## The boundary: observation only

The probe reads what a service says to anyone who connects. It touches
**only ports the latest counter-scan found open**, sends one plain request
per protocol, follows nothing but the service's own answer, and never
enumerates paths, versions or weaknesses. Automatic scans keep their rule
("escalate by scope, never by speed or aggressiveness"); the README rewords
it so it clearly governs scans. Probes are admin-only; nothing from them is
on the public wall.

## Approach

A paid probe is a request over RPC; its result is a replicated record, so
it arrives asynchronously through replication like every scan result. A
vantage request is N offers pinned to N scanners. A domain lookup asks
several nodes to resolve and replicates the votes.

## 1. RDAP provider

A new `Provider` named `rdap` ("RDAP registry"), free (`weight_milli` 0),
on every node, no key, IPv6 yes. Both the enrichment loop and lookups use
it; being free, it runs in every lookup.

- **Bootstrap.** IANA `ipv4.json` and `ipv6.json` are built in and refreshed
  weekly into `data_dir`, like the Tor exit list. At most 2 referrals are
  followed.
- **Pace.** One query a second per RIR; one per 10 s for LACNIC and AFRINIC.
  On 429: `Retry-After` when given, else a backoff of 10 s doubling to at
  most 5 min, reset after a success.
- **No block cache.** RDAP returns the most specific object for the address
  asked; sub-assignments inside a range have other holders and abuse
  contacts, so an answer is never reused for a neighbour. Every address is
  asked for itself; the range is stored as information.
- **Stored** (`ip_intel`, provider `rdap`): range, CIDRs, handle, name,
  type, country, registrant organisation, abuse contact, registration and
  last-change dates. Tags `rdap:country:XX` and `rdap:fresh` (block
  registered or changed less than 90 days ago).
- `refresh_after_days` 30. Not redistributable; nothing on the public wall.

## 2. The observational probe

### What it touches

The ports the address's **latest counter-scan** found open, at most 16 of
them (the lowest-numbered first). No port discovery. For each port, by what
the scan called it, else by trying TLS then plain:

- **HTTP(S):** `GET /` and `GET /<random path>` (to record the 404 shape),
  with a current browser `User-Agent`. Recorded: status, `Server`,
  `X-Powered-By`, `<title>`, cookie **names**, body sha256 and size of the
  first 4 KiB, favicon (`/favicon.ico` or the page's `<link rel=icon>`)
  mmh3 and sha256.
- **Redirects:** `Location` is followed, also off-host, at most 5 hops, one
  `GET` per hop; each hop records status, Location, Server, X-Powered-By,
  title, body hash and size, and the TLS certificate and JARM when HTTPS.
  The redirect target is never promoted to a full probe. Every hop target
  is checked against the safety lists and private, loopback and link-local
  space; a hit is recorded as "skipped (protected)" and the chain stops.
- **TLS** (any port that speaks it): certificate chain, protocol version,
  ALPN, **JARM** (the ten ClientHellos sent as raw bytes, built from
  aws-lc-rs primitives; no new dependency).
- **SSH:** banner, KEXINIT (HASSH), host key through a minimal curve25519
  key exchange (one connection per key type the server offers). This also
  covers OpenSSH ≥ 10, which nmap 7.9x cannot complete a key exchange with.
- **Anything else:** a passive banner read (what the service sends within
  5 s).

**Caps:** 10 s per connection, 120 s per probe, 256 KiB per response,
100 KiB per favicon, at most `[probe] max_parallel` (default 2) probes at a
time per scanner.

**RTT:** three TCP connects to the first open port; the minimum is kept
(`rtt_min_ms`).

### Gating

A scanner runs a probe only when:

- the evidence guard allows at least level 2 for the address
  (`Evidence::allowed_level`);
- the address is on no safety list (`never_scan`, members, own and
  peer-observed addresses, Tor exits, verified crawlers);
- the latest scan found at least one open port;
- it has not probed this address in the last 24 hours;
- a probe slot is free.

Probes mint nothing, count toward no pace or earnings, and are not audited.

### Output

A replicated **`Record::ProbeResult(ProbeResultRec)`**: `uid`, `group`
(the vantage request's uid, also set for a single probe), `ip`, `asker`,
`vantage_ip` (section 3), `started_at`, `finished_at`, `rtt_min_ms`,
`ports: Vec<ProbePortRec>` (port, protocol as probed, outcome, and the
fields above), `build`. Fields added later are `#[serde(default)]`, as in
`ScanResultRec`.

Local tables: `probes` (one row per record) and `probe_ports` (one per
port, JSON detail). `host_keys` gains a nullable `probe_id` beside
`scan_id`; a key from a probe shows "from probe (date)" where a scan key
shows its scan link.

New **soft** link kinds in `LinkKind`: `favicon` (mmh3), `jarm`,
`http_body` (sha256 of `/`), `http_404` (sha256 of the random path). They
appear in Links with "seen on k other addresses" and are **not** identity:
a shared favicon is a shared product, not a shared operator. SSH keys and
leaf certificates stay identity kinds.

## 3. Vantages and the RTT check

### Prerequisite: peer-observed public address

Scan-details spec §1: `hello.seen_from`, an address taken as public when a
sibling reports it or two members of different owners do, 7-day expiry,
safety-list integration, listed on System › Status. This spec adds:

- Heartbeat gains `public_addrs: Vec<IpAddr>` (`#[serde(default)]`; older
  peers ignore it): the node's taken public addresses.
- `geo.rs` decodes `location { latitude, longitude, accuracy_radius }`
  from GeoLite2-City into `Geo`.

### A vantage request

The probe of section 2 asked of N scanners at once: N offers (section 4),
N calls, N `ProbeResult` records sharing one `group`. Each scanner probes
independently under its own gating; the 24-hour limit is per scanner, so N
vantages on one address do not collide.

**Choosing vantages.** Default: up to 4 live scanners that announce a
probe price, spread over distinct countries of their `public_addrs`
(padded with the cheapest when fewer countries exist). The admin can tick
any set. The asking node may be one of them. A node without a dial address
is not offered.

**`vantage_ip`.** The scanner's single taken public address at probe time.
With several or none, the address the asker dialled (it sends it as
`ProbeReq.dialled`), marked `vantage_ip_source: dialled`. A node probing
for itself takes its first public address (`public`), or none (`local`).
Coordinates are never stored or sent: whoever
renders resolves `vantage_ip` and the target through its own City mmdb, so
a database update corrects old results too.

### The diff

Rows are `(port, field)`, columns are vantages. Fields: HTTP status,
Server, X-Powered-By, title, body hash, 404 hash, favicon hashes, final
redirect URL; TLS leaf fingerprint, chain length, version, ALPN, JARM; SSH
host-key fingerprint, HASSH; banner. Rows equal across all vantages are
collapsed under "k fields consistent across all vantages"; differing rows
are expanded and marked. A port that timed out or refused from one vantage
is shown as that, not as a difference in every field.

### The light-speed check

For each vantage: `bound_km = rtt_min_ms / 2 × 200` (200 km/ms, about ⅔ c
in fibre: the optimistic bound, so only impossible claims are flagged).
`distance_km` is the haversine distance from the vantage's coordinates to
the target's, minus the target's `accuracy_radius`. When
`distance_km > bound_km`: **"impossible: claimed X km away, light-speed
bound Y km"**. The group header sums it up: "location claim contradicted
by k of N vantages". The check runs with one vantage too. RTT never makes
a positive claim about where the address is.

Not in scope: traceroute, RTT over time, anything that touches ports the
scan did not find open.

## 4. Paying for a probe

**Price.** `4 × unit × surge` mc (weight 4000: four keyed-API lookups —
a probe costs a scanner up to two minutes of a worker and outbound
traffic), floor 1 mc, through `price::price`. Probes do not feed the unit
formula's capacity side and mint nothing. Pricing is expected to become
fully dynamic later; this section only fixes the hooks.

**Announcement.** Heartbeat gains `probe_price_mc: Option<u32>`, its own
field — `probe` is not a provider name and `quotes` keeps filtering unknown
providers. Scanner-role nodes with probing enabled set it; `None` means no
probes here. Surge doubles while at least one of the node's probe slots
is busy. A too-low offer is declined naming the price; the asker offers once more up to
`RETRY_AT_MOST` times, as `ask_server` does.

**Offer and ask.** Per vantage one `CreditOffer` pinned to the scanner,
written and reconciled as `offer_and_ask` does today, then
`POST /rpc/v1/probe` with `ProbeReq { ip, offer_seq, group }`. The server
side of `pay::serve` — wait for the entry, is an offer, for me, seal
consistent, not already serving, standing, offer counts, amount covers the
price — is extracted into `pay::accept_offer(...) -> Result<Accepted,
Declined>` and shared by lookup and probe.

**Two-phase answer.** The RPC reply is immediate: `Accepted { probe_uid }`
or `Declined { why }`. A decline (gating, safety, 24-hour limit, no slot,
bad offer) writes a receipt of nothing at once. On accept, the scanner runs
the probe and then appends **in one batch** the `ProbeResult` and
`CreditReceipt { charged_mc: price, answered: ["probe"] }`. Both replicate;
the asker's page shows the probe as running until the record arrives.
`OFFER_TTL` (15 min) minus `SERVE_MARGIN` (2 min) leaves ample room for a
120 s probe. A scanner that dies mid-probe leaves the offer to lapse, which
frees it; the asker then shows "no result, nothing charged".

**What is charged.** The full price once the probe ran (connections were
attempted), even when every port timed out: the scanner did the work, and
"nothing answered from here" is a finding. Nothing when declined before
any work. Half to the scanner, half destroyed, as for lookups. The own node
costs the same as any other. No free probe quota. Standalone probes
locally without credits, as standalone lookups do.

## 5. The Lookup page

### Entry

`/admin/lookup` becomes a nav entry ("Lookup"). The top-bar field sends an
IP or a hostname there; everything else goes to Search as today, and the
Lookup page links to Search for other identifiers. The form takes an IP,
a domain, or a pasted list (today's bulk form) in one field.

### Cheap first

A lookup runs by itself what the dataset holds plus the **cheap tier**:
every provider with `weight_milli` ≤ 250 (Tor, RDAP, GeoLite2, InternetDB).
The form shows "this lookup costs up to X" from the current quotes before
submitting, so the price is known in advance whatever the pricing becomes.
`intel::lookup::run` takes the set to ask instead of asking everything
missing.

The result page then offers the rest, each with its price and node:
"AbuseIPDB · node X · 0.12 credits [Ask]", … and "Ask all (Y credits)".
Stored results keep "Ask again". `again` becomes the general "ask these
paid providers" parameter, so the handlers barely change.

### Actions card

In `_target.html`, under Intelligence, rendered only with a session (so it
is on the IP page and the lookup result alike):

- Guard line: "Counter-scan found N open ports (date) · evidence allows
  level L", or why a probe is unavailable (no scan, no open port, guard
  below 2, on a safety list, probed by X 3 h ago). Buttons are disabled
  with the reason, never hidden.
- **Probe:** a vantage picker — one row per live scanner announcing a
  price, with name, country, price; the default set pre-ticked; the total
  live; the balance line of today's form. One node or N nodes is the same
  form. Standalone: one button, no prices.
- Submit: `POST /admin/lookup/probe` writes the offers, calls each scanner,
  and redirects to the IP page `#probes`. Nothing waits for the probe.

The roadmap item's "queue a counter-scan" and "block" halves are not in
this spec: there is no manual scan path to hook into, and blocking is its
own flow. The roadmap line is reworded to what remains.

### Probes section

A new admin-only section in `_target.html` (`data-section="probes"`),
newest group first. A group shows when it was asked, by whom, its vantages
and cost, and per vantage a state: queued · running · done · declined
(why) · lapsed (nothing after 15 min). The page updates through the
existing SSE notifier (a `probes` event with the group uid); without SSE it
reloads.

- One vantage: per-port cards (HTTP, TLS, SSH or banner, as in section 2;
  the redirect chain as a hop list with its protected skips). Hashes link
  into Links.
- Several: the diff table of section 3, the RTT row and verdicts at the
  top, per-vantage detail one click away.

## 6. Domains

### Resolving by consensus

A hostname is resolved by several nodes, because one node's resolver may
be tampered with or censored and the result enters the shared dataset.

- New free RPC `POST /rpc/v1/resolve { name }` → `{ addrs, error }`. The
  server resolves with its own system resolver (`tokio::net::lookup_host`,
  5 s timeout) and returns the global-unicast A/AAAA set; it stores
  nothing. The name is validated (≤ 253 chars, hostname syntax, punycode,
  lower case) and the asker is limited as for free lookups (60 an hour).
  Resolving never starts a scan or a probe.
- The asker picks up to **5 resolvers**: itself and random live members,
  preferring distinct owners (siblings share a network and usually a
  resolver) and distinct countries. Fewer available: all of them. A
  standalone or one-member node resolves alone.
- **Agreement is per address:** an address is *agreed* when more than half
  of the resolvers that answered returned it. Two responders: both; one:
  "unverified — single resolver". A minority's NXDOMAIN or different set is
  recorded as that resolver's answer.
- Private, loopback and link-local answers are dropped. At most 16 agreed
  addresses are followed with lookups; the rest are listed as "also
  resolves to".

### Record and storage

`Record::IpName(IpNameRec { name, at, answers: Vec<(NodeId,
Result<Vec<IpAddr>, String>)> })`, written by the asker, so every node
re-derives the votes rather than trusting a tally. It is applied to
`ip_names (ip_id, name, source, first_seen, last_seen, agreed, asked)`,
unique on `(ip_id, name, source)`, `source = 'dns'`. A later record for the
same name updates `last_seen` and the vote. Names are never deleted. Only
agreed addresses carry the name into the dataset and the export's `names`
column; minority addresses are kept with `agreed = 0` and shown as
disputed. The scan-details spec's `ips.ptr` stays separate: `ip_names`
holds names an admin asked about.

Schema: the next `user_version` step in `store/mod.rs`.

### Transparency

Result page: one row per address — "agreed by 4 of 5" or "only from node X
(DE) — disputed" — the resolvers with their countries, errors per
resolver. IP page: "Names: example.com (DNS, agreed 4/5, 2026-10-07)" or
"(DNS, disputed 1/5)". Standalone: "resolved locally, unverified".

### Caveats accepted

- Geo-DNS makes honest resolvers disagree; the per-address rule shows that
  as a minority rather than a failure.
- A majority of distinct owners bounds one dishonest member, not colluding
  ones — the cluster's trust model everywhere.
- CNAME chains are invisible to `lookup_host`; only final addresses are
  stored.
- Wildcard DNS resolves typos; the name is stored as "looked up by admin",
  never presented as the host's own claim.
- The resolver panel is random per lookup, so repeating one can change it.

## Tests

- **RDAP:** bootstrap file picks the RIR by prefix; a referral is followed
  at most twice; pacing per RIR; 429 with and without `Retry-After`; the
  stored fields and the two tags; no reuse of an answer for a neighbour.
- **Probe:** only open ports of the latest scan are touched (a scan with
  none → declined); the 16-port cap; HTTP fields, random-path 404, favicon
  hashes against a local test server; a redirect chain of 6 is cut at 5; a
  hop to a protected or private address is skipped and recorded; TLS
  fields and a JARM against a local rustls server; SSH banner, HASSH and
  host key against a local test server; per-connection and per-probe
  timeouts; the parallel cap; the 24-hour limit per scanner; gating by
  guard and safety lists; `host_keys.probe_id`; the four soft link kinds
  count shared addresses and are not identity.
- **Vantages:** default choice spreads countries; `vantage_ip` and its
  source; the diff collapses equal rows and marks differing ones; a
  timed-out port is not a diff; the light-speed check flags an impossible
  claim and passes a possible one, with and without `accuracy_radius`;
  `Geo` decodes coordinates and survives their absence.
- **Credits:** `probe_price_mc` announced only with probing enabled;
  `accept_offer` serves lookup and probe alike (existing `serve` tests
  pass unchanged); a decline writes a receipt of nothing; accept answers
  at once and the result and receipt land in one batch; a too-low offer
  names the price and the retry rule holds; a lapsed offer charges
  nothing; standalone probes without credits.
- **Lookup page:** cheap tier runs by itself and the price shown before
  matches the quotes; paid providers appear as offers with prices; "Ask"
  and "Ask all" pay as `again` does; the top-bar field routes an IP and a
  hostname to Lookup; the actions card shows the guard line and the
  disabled reason; the probe form writes N offers and redirects; the
  probes section shows every state; the public IP page renders neither
  card.
- **Domains:** validation; resolver choice prefers distinct owners; the
  per-address majority with 5, 2 and 1 responders; a minority NXDOMAIN is
  recorded; private answers are dropped; the 16-address cap; the record
  replicates and every node derives the same votes; `agreed = 0` rows are
  not exported; the disputed and unverified displays.

## Not in this spec

- Queueing a counter-scan or blocking from the Lookup page.
- Resolving a domain from several vantages for comparison (section 3's
  cousin); traceroute; RTT over time.
- Moving `ips.ptr` into `ip_names`.
- Dynamic pricing of probes and providers (a separate change; this spec
  only adds the hooks).
- The canary return host and `reached` of the scan-details spec.
