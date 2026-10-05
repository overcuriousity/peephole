# Roadmap

What is planned, in order, with what each item costs and what it brings.
Shipped items move to the [changelog](../CHANGELOG.md).

**Cost**: S = about a day, M = a few days, L = a week or more, including
tests and docs. **Benefit**: what it adds for an operator, for the dataset,
or both.

Every item names where it shows up. The public wall only ever shows
aggregates: no request contents, no fingerprints, no single scan results
(see the README's privacy rules). Everything else goes to the admin area.

## Evidence from the running cluster

Measured on the real cluster, 30 days, before this roadmap (2026-10-04):

- **About 465 source IPs.** 453 were seen on a single day, 12 on 2–3 days,
  none on more. Scanners almost never come back from the same address, so
  linking work across addresses (campaigns, canary reuse) is what is
  missing.
- **Exact path-set matches.** Groups of 2–5 IPs sent the identical 132-path
  `.env`/cloud-credentials sweep, the identical 189-path webshell list and
  the identical 44-path phpunit sweep. Near-copies (132/131, 81/80, 44/42
  paths) are the same tool and should be grouped too. Benign crawler paths
  (`robots.txt`, `security.txt`, `favicon.ico`, `sitemap.xml`) also match
  exactly, so paths need weighting by rarity.
- **JA4 alone links too much.** The top value covered 27 IPs; it is a TLS
  library default, not an operator.
- **Decoy reach.** 307 requests from 55 IPs (about 12 % of sources) would
  have hit a decoy. Decoys were off then and are always on now.

## Next

### 1. Tarpit

- **Cost:** S–M
- **Benefit:** medium. It costs scanners time for almost nothing, and the
  tarpitted connections are themselves a measurement (how long they wait).

A slow-drip answer for severity-4 sources, with its own bounded pool of
connections (separate from the per-source cap and the global slots), and a
normal answer when the pool is full. Recorded as `answer = tarpit` with the
time held, so the dataset can separate the reduced follow-up traffic.

**Shown:**

- **Admin:** Analytics answer shares (already there, under `tarpit`); time
  held on the request page.
- **Public wall:** a "scanner time wasted" tile (hours held this period).

### 2. Stateful decoys, MCP and AI first

- **Cost:** M for the state machine and the MCP/Ollama decoys
- **Benefit:** high. This is the newest attack surface, there is little
  public data on it, and the rules already detect `mcp-probe` and
  `ai-infra-probe` while the trap answers them with a 404.

A small decoy state machine, keyed by canary or session, with each step
recorded in `answer` (`decoy:mcp:initialize`, `decoy:mcp:tools/call`, …):

- **MCP:** answer `initialize` and `tools/list` with enticing tools
  (`read_file`, `run_command`, `query_db`), and record every `tools/call`
  with its arguments. Reply with plausible errors or canary content.
  Nothing is ever executed.
- **Ollama/OpenAI-compatible:** `/api/tags` and `/v1/models` list fake
  models; `/api/pull`, `/api/chat` and `/v1/chat/completions` are recorded.

**Shown:**

- **Admin:** a Decoys page with a funnel per decoy (served → follow-up →
  next stage) and a log of tool calls with their arguments.
- **Public wall:** "What they asked our fake AI": counts per tool name (our
  own fake names, so safe to show) and per model requested.

### 3. Stateful web decoys: wp-admin, upload sink, webshell commands

- **Cost:** M–L
- **Benefit:** high. It captures the second stage (the dropped webshell and
  the commands sent to it) without emulating a shell.

- **Upload sink.** wp-admin plugin upload, `PUT` and the common upload
  endpoints store the file, hashed and size-capped, and answer with a
  plausible path. Every later request to that path is recorded and linked
  to the upload; the commands are in its parameters.
- **Canned replies.** A short fixed list (`id`, `uname -a`, `whoami`) to
  draw out the next step. No further emulation.
- **Hard rule:** an uploaded file is never served back, so peephole cannot
  be used to host malware. It is exported by hash; the content is exported
  only on request.

**Shown:**

- **Admin:** an Uploads page (hash, size, type, source IP) and per upload a
  timeline of the requests sent to it.
- **Public wall:** a "webshells dropped" tile and counts per command verb.

### 4. Campaign clustering

- **Cost:** L
- **Benefit:** very high. It answers "who is this" across addresses and is
  the main analysis gain for operators and for the dataset.

A typed evidence graph, recomputed deterministically from replicated data,
so every node arrives at the same campaigns. Every edge says why it exists.

- **Hard edges:**
  - a shared SSH host key or TLS certificate (shipped: `host_keys`);
  - a shared browser fingerprint;
  - canary reuse (shipped: `canaries`).
- **Soft edges:**
  - rarity-weighted Jaccard similarity of each IP's normalized path set,
    above a threshold. About 500 IPs a month allows plain pairwise
    comparison; MinHash only if that grows by orders of magnitude;
  - JA4 together with JA4H (shipped: `requests.ja4h`) as supporting evidence, never alone.
- **Path normalization** (IDs, random filenames, query values) is most of
  the work and is shared with item 5.

**Shown:**

- **Admin:** a Campaigns page (size, first and last seen, ASNs, countries)
  and a campaign page with its member IPs, its evidence edges with their
  reasons, a timeline, and the graph (the fingerprints graph, generalized).
  The IP page shows "member of campaign #N".
- **Public wall:** "Campaigns this period": size, ASN and country spread,
  and paths per campaign, as aggregates without fingerprints.
- **Dataset:** a `campaign` column.

### 5. New paths and exploit waves

- **Cost:** M (once item 4's path normalization exists)
- **Benefit:** high. It gives early warning when a new exploit starts
  spreading, often before CVE write-ups.

- A cluster-wide `first_seen` per normalized path, plus the number of
  distinct IPs that sent it.
- A path with no matching rule that reaches N distinct IPs within an hour
  is an exploit wave.
- It lives inside the campaign view ("campaign #N started probing a path no
  rule knows"), not as a separate inbox, which would only be noise.

**Shown:**

- **Admin:** a "New paths" view (first seen, distinct IPs, campaigns), a
  badge on the live feed, and an optional webhook or ntfy push.
- **Public wall:** a count of new path shapes this period (paths themselves
  are request contents, so not public).

### 6. Personas per node or hostname (opt-in)

- **Cost:** M (after items 2 and 3)
- **Benefit:** medium–high. A controlled comparison of targeted versus spray
  traffic across the cluster.

A node, or an SNI/Host name, consistently presents as one product
(WordPress, a Fortinet appliance, a GPU box). Three conditions keep the
dataset clean:

1. The persona is recorded on every request, like `answer`.
2. It stays stable over time.
3. It is opt-in.

Per-IP version roulette is ruled out: scanners that use many source IPs
would see the banner change from visit to visit, and that gives away the
honeypot.

**Shown:**

- **Admin:** Analytics follow-up rate and family mix per persona.
- **Public wall:** attack mix per persona.
- **Dataset:** a `persona` column.

## Small follow-ups

- **Peer-observed public address.** S–M, medium. A NAT'd node cannot see
  its public IP; peers report the source address they see on its RPC
  connections. That replaces `cluster.own_addresses` for NAT'd nodes,
  records which of our addresses a request reached, and lets the canary
  return host cover `localhost` and missing Hosts (a new `decoy_v`).
- **Host keys in the export.** S, medium. Each scan's XML is already
  exported. A parsed `host_keys` list per scan (kind, port, fingerprint,
  detail) saves every dataset user the parsing.
- **SSH host keys from OpenSSH ≥ 10.** M, medium. nmap 7.92's `ssh-hostkey`
  cannot complete a key exchange with OpenSSH 10.2 ("No shared KEX
  methods"), because OpenSSH 10 dropped finite-field Diffie-Hellman from
  its defaults. `ssh2-enum-algos`, and so HASSH, still works. First check
  the nmap version the scanner nodes run (Debian 12 ships 7.93). If the
  limit holds there too, fetch the host key with a minimal key exchange of
  our own (curve25519; the `russh` client hands over the server key before
  authentication), one connection per key type. `host_keys` is derived from
  the stored XML and not replicated, so keys fetched outside nmap need a
  record of their own on the scan.
- **ETags of scanned sources.** S, medium. nmap's `http-headers` (in
  `discovery` and `safe`) already runs at levels 3–4, so the `ETag` of each
  HTTP port is in the stored XML; parse it into `host_keys` as a new kind,
  reparsing old scans via `keys_parsed`. Optionally add `http-headers` to
  level 2's named scripts. A shared ETag means the same file with the same
  mtime and size (one image, one kit), but distro default pages share it
  across thousands of hosts: a soft, rarity-weighted edge for item 4, never
  a hard one. nginx ETags also date the file, roughly when the box was set
  up. Shown on the IP page beside the host keys.
- **ETags as a return marker.** S, low. Decoys answer with an ETag derived
  from the request, like a canary; an `If-None-Match` carrying it from
  another IP links the two. Only caching clients (browsers, headless
  Chrome) send it back, so first count how many recorded requests carry
  `If-None-Match` at all.
- **Reverse DNS of every source.** S, medium. Store the forward-confirmed
  PTR name per IP (the lookup `scan/crawler.rs` already does), refreshed
  when the IP returns. It often names the hoster or a research scanner.
  Shown on the IP page and in the IP directory filter (admin); a `ptr`
  column in the dataset.
- **VPN and relay exits.** M, high. Scanning a VPN exit scans the VPN
  company, a bystander, as with Tor exits. Load X4BNet's `lists_vpn` (MIT,
  ASN-derived) the way the Tor list is loaded. Listed IPs are never
  scanned, flagged like `is_tor_exit`, and kept off the blocklist. Shown
  on the IP page, as an IP directory filter, and as a public "via VPN"
  share beside the Tor share.
- **Proxy signals from our own data.** S, medium. A `Via`, `Forwarded` or
  `X-Forwarded-For` header in the probe itself means a forwarding proxy
  (a rule label); a counter-scan finding `socks5`, `http-proxy` or OpenVPN
  means the source likely is one. Both are admin-only flags on the IP page.
- **JA4T on directly listening traps.** S–M, medium. `TCP_SAVE_SYN` and
  `TCP_SAVED_SYN` give the client's SYN without pcap. This works only where
  the trap listens on 80/443 itself; behind nginx the SYN goes to nginx.
  Shown on the request page and in Analytics. A lowered MSS (around 1380
  for WireGuard, 1360 for OpenVPN) also hints at a tunnel.

## Not planned

- **Passive DNS.** The useful sources (DNSDB, SecurityTrails, VirusTotal,
  OTX, CIRCL) need an API key or vetting and are proprietary data; and
  sources seen once from a throwaway VPS rarely have domains. Reverse DNS
  covers the free part.
- **Per-vendor VPN exit lists** (Mullvad, Proton VPN, NordVPN, iCloud
  Private Relay, …). Which vendors to include would be our own arbitrary
  choice, and every list is one more source to keep working as vendors
  change their endpoints.
- **Paid anonymizer detection** (ip-api, proxycheck.io, IPinfo privacy and
  the like). Residential proxy exits are ordinary home addresses and cannot
  be told apart without such a service, so they stay undetected.

## After 1.0

- **Feeds in other formats.** STIX/TAXII or a MISP feed beside
  `/api/blocklist`, and a CrowdSec-compatible endpoint. Cost M.
- **Weekly digest page.** A generated, permalinked public summary: new
  families, the largest campaign, new path shapes, top movers. Cost M; worth
  it once items 4 and 5 exist.
- **Hall of fame.** Oldest CVE still probed, strangest User-Agent, longest
  payload, as aggregates. Cost S–M.
