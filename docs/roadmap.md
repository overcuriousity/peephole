# Roadmap

What is planned, in order, with what each item costs and what it brings.
Shipped items move to the [changelog](../CHANGELOG.md).

**Cost**: S = about a day, M = a few days, L = a week or more, including
tests and docs. **Benefit**: what it adds for an operator, for the dataset,
or both.

Every item names where it shows up. The public dashboard only ever shows
aggregates: no request contents, no fingerprints, no single scan results
(see [What is public](overview.md#what-is-public)). Everything else goes to the admin area.

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

### 1. Stateful web decoys: wp-admin, upload sink, webshell commands

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
- **Public dashboard:** a "webshells dropped" tile and counts per command verb.

### 2. Campaign clustering

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
  the work and is shared with item 3.

**Shown:**

- **Admin:** a Campaigns page (size, first and last seen, ASNs, countries)
  and a campaign page with its member IPs, its evidence edges with their
  reasons, a timeline, and the graph (the fingerprints graph, generalized).
  The IP page shows "member of campaign #N".
- **Public dashboard:** "Campaigns this period": size, ASN and country spread,
  and paths per campaign, as aggregates without fingerprints.
- **Dataset:** a `campaign` column.

### 3. New paths and exploit waves

- **Cost:** M (once item 2's path normalization exists)
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
- **Public dashboard:** a count of new path shapes this period (paths themselves
  are request contents, so not public).

### 4. Personas per node or hostname (opt-in)

- **Cost:** M (after item 1)
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
- **Public dashboard:** attack mix per persona.
- **Dataset:** a `persona` column.

## Small follow-ups

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
- **Dashboard timeline drill-down.** S, low. For admins, each bucket of the
  dashboard timeline links to `/requests` filtered by that bucket's `from`/`to`,
  as the Analytics charts already do.
- **Queue a counter-scan or block from the Lookup page.** S–M, low. The
  probe and vantage actions exist; the manual scan queue and the block
  action do not yet.

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
  it once items 3 and 4 exist.
- **Hall of fame.** Oldest CVE still probed, strangest User-Agent, longest
  payload, as aggregates. Cost S–M.
