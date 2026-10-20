# Compromised sources: can peephole tell a hijacked endpoint from rented infrastructure?

This is an assessment of an unbuilt proposal, not a description of shipped
behaviour, which is why it is its own file and not a section of
[Detection](detection.md); if a part of it is built, that part moves into
`detection.md` and this file shrinks to the reasoning. Scope: the owner's
question on MIK-574, "can we detect if the scanner is a compromised device
or residential hijacked device without querying some commercial API, just
from our own technical metrics?". Numbers come from the data-reality check
on the hermes node (MIK-577, 2026-10-19, read-only, 11 days of data:
184,159 requests from 6,543 sources) and from the schema under
`src/store/migrations/`. Signal 8 was measured for this assessment a few
hours after MIK-577 on the same node, at 185,035 requests; the gap is live
traffic. Full addresses are not written here; prefixes are
/24.

## Answer

**Rented infrastructure: yes, with confidence, from signals we already
hold.** Cloned SSH host keys, shared TLS certificates, canary hand-offs
between addresses, dense /24s and self-named scanner PTRs each mark one
operator's fleet, and the campaign recompute already ties the hard ones
together.

**Hijacked endpoints: only a thin slice, and only as "a consumer device
answered on this address", never as "compromised".** The one own signal
that points at an end-user box is the counter-scan seeing one: TR-069 on a
router, MikroTik's bandwidth-test port, FRITZ!Box or HikVision services,
Dropbear with LuCI, an Android TV. On current data that is 41 sources, about
0.6% of all and roughly a tenth of the plausibly residential ones. It
fails silently for the largest class the owner asked about, residential-
proxy SDKs on phones and TVs behind NAT, which open nothing on the WAN
address. And it is forgeable towards "victim" by a renter who answers our
scan with CPE banners, which is cheap and worth doing for anyone who wants
a softer label.

**Recommendation: build one narrow, local-only slice (consumer-device
evidence on the IP page), do not build a score, and do not put any
"compromised" verdict into the shared dataset or the blocklist.** The
slice is named in [Recommendation](#recommendation). The roadmap's "Not
planned" line, "residential proxy exits are ordinary home addresses and
cannot be told apart without such a service", stays true for proxy exits
as a class; what we can add is the device evidence for the minority that
exposes a box.

## What the population looks like

- At most 7 to 10% of sources are residential. The only residential-vs-
  hosting label we hold is AbuseIPDB's cached `usage_type` in `ip_intel`
  (third-party, used in MIK-577 as a reference split only): Data Center/
  Hosting/Transit 5,312, Fixed Line ISP 671, Mobile ISP 15. The label is
  noisy: 186 of 193 Hurricane Electric sources (Shadowserver's scanners)
  and 27 Hydra Communications hosts are labelled "Fixed Line ISP", so of
  686 "residential" sources about 470 are plausibly eyeball lines.
- 70% of sources (4,595) dwell under one minute; 3,433 send a single
  request. Residential sources are no different: 512 of 671 "Fixed Line"
  sources stay under a minute.
- Twenty ASNs hold 69% of the sources (4,519); all twenty are clouds or
  scanner operators.

So a hijacked-endpoint detector works on a small minority of the data,
and the hosted majority supplies most of the false positives. Every
signal below is judged against that.

## Verdict per signal

Each signal: where it lives, what it is worth for the two directions
(rented, hijacked), what we have versus what we would need, and the
adversarial read: what an operator pays to evade it, and what they gain
by making us mislabel. "Usable", "weak" and "not worth it" are for the
hijacked direction unless stated.

### 1. ASN, organisation, country

**Where.** `ips.asn`, `ips.asn_org`, `ips.country` (GeoLite2, newest
lookup; `src/store/migrations/0001_initial.sql`), history in `ip_intel`
(`provider='maxmind-geolite2'`), the RDAP network as `ips.rdap_handle` /
`ips.rdap_name` (`0043_rdap_net.sql`, derived per node). Coverage 99.6%
(6,516 of 6,543 with `asn`), 539 distinct ASNs.

**Verdict: usable as the base axis, but we hold no eyeball-vs-hosting
classification of our own.** `asn_org` is free text ("Google LLC",
"3xK Tech GmbH"); nothing in the schema says whether an AS sells to
households. On its own the ASN gets us the hosting majority: an address in
a known cloud is rented, full stop. It does not get us the other way: an
eyeball ASN says "an ISP customer line", which covers a home router, a
phone behind CGNAT, a small business, and a rented "ISP proxy" alike.

**Have / need.** Have: the ASN. Need: an AS-type list we keep ourselves.
Three ways, none bought: (a) a curated seed list of the clouds and scanner
operators we see most (the top 20 ASNs cover 69% of sources and are all
rented; a few hundred entries cover the bulk), (b) a published offline
classification dataset bundled like the Tor list (PeeringDB's
network-type field and the Stanford ASdb; coverage and accuracy under
Prior art, licence and freshness are MIK-582's question), (c) self-labelling from
our own data (an AS whose sources carry consumer PTR names or CPE
devices), which is circular and is not proposed. Cost of (a) or (b): one
text file of well under 2 MiB, refreshed on the Tor list's cadence,
no new columns; a `net.type` evidence row per address (see
[Scoring](#scoring-evidence-not-points)).

**Adversarial read.** A residential-proxy network's whole product is exits
in eyeball ASNs, so AS type is the signal it is built to pass; a botnet gets
it for free. Faking a hosting ASN is never in the attacker's interest. The
other direction is cheap: "ISP proxies" (datacenter space announced under
or registered to an ISP) cost a few dollars per address per month and put
rented infrastructure behind a residential label; Hydra's 27 "Fixed Line"
addresses and Hurricane Electric's 186 are live examples of the label
being wrong, whatever the cause. **Gain from mislabelling:** if AS type
alone fed a "compromised" verdict, everything sent through rented ISP
proxies would land on a shared list as "compromised residential", and the
list would name ISP customers, some innocent holders of recycled
addresses. Therefore AS type is context for other evidence and never a
verdict by itself.

### 2. Reverse DNS and PTR names

**Where.** `ip_names(ip_id, name, source, …)` (`0018_probes.sql`);
`source='rdns'` is this node's forward-confirmed PTR, `source='ptr'` the
name nmap reported in a counter-scan. 2,799 sources (42.8%) have either.
`ips.rdns_at` is set on 1 row although 2,178 sources have an `rdns` name,
so it is not a "was looked up" flag.

**Verdict: usable for rented (self-named scanners), weak for hijacked.**
822 sources (12.6%) carry a scanner name (`scan`, `crawler`, `research`,
`measurement`, `probe`, `stretchoid`, `internetdata`). Only 48 (0.7%)
match consumer-line patterns (`dyn`, `pool`, `dsl`, `cable`, `dhcp`,
`customer`, `broadband`, `fttx`, `ftth`), and those are clean: 34 of 48
are "Fixed Line ISP" by the reference label, 2 are hosting. Five of the
largest rented fleets (3xK, Tencent, GSL, F.n.s., Clouvider) carry no name
at all, so absence of a name says nothing.

**Have / need.** Have: names for 42.8%, a refresh path for names on own
sources (`name_refreshes`, `0037_name_refreshes.sql`, 7-day cadence).
Need: a consumer-naming pattern list (a regex file in the style of
`rules/*.toml`, a few dozen entries, per-ISP where the generic words do not
fire). No new collection; a name is one lookup per source, which already
happens.

**Adversarial read.** In the hijacked direction the PTR belongs to the
ISP, not the operator, so it cannot be forged on a victim; a scanner-
looking name cannot be planted on a home line. In the rented direction it
is free to forge: any hosting reseller lets the renter set the PTR, and
forward confirmation passes because the renter controls both zones, so
`dynamic-N.pool.example-isp.net` on a rented /24 costs nothing. **Gain
from mislabelling:** a name pattern alone must never produce a consumer
verdict; with a CPE device answering (signal 3) it corroborates, since
faking both the name and the device on a rented box is still cheap but
now deliberate.

### 3. Counter-scan results

**Where.** `scans(ip_id, level, os_guess, raw_xml, finished_at)`,
`ports(scan_id, port, proto, state, service, product, version, ostype,
devicetype, cpe)`, `scan_facts(scan_id, port, kind, value)`
(`0027_scan_facts.sql`). 5,374 sources (82.1%) have a finished scan;
2,280 (34.8%) a level-2 scan or higher; 299 (4.6%) a level 4; 2,301
(35.2%) at least one open port. `os_guess` on 1,485 (22.7%).
`devicetype` on **15** sources (0.2%: load balancer 4, broadband router 4,
router 3, PBX 2, webcam 1, VoIP adapter 1). `scan_facts`: `http.server`
275, `http.title` 156, `ntlm.*` 69, **`socks.method` 0, `smb.*` 0**, and
all 9,382 scans have `facts_parsed=1`, so the zeros are real.

**Verdict: the strongest own signal for a hijacked endpoint, and thin.**
A consumer CPE or IoT stack answering on the source address is direct
evidence that the address is an end-user line with an exposed box: TR-069
(`7547`, TP-Link, Huawei; FRITZ!Box on `8089`), MikroTik bandwidth-test on
`2000` and RouterOS services, HikVision camera control, AVM SIP on `5060`,
Dropbear + LuCI, `os_guess` "Android TV OS 11" (38 sources), 3Com or other
home-router OS guesses. Proxy software on the address (3Proxy on 91
sources, Socks4A 82, `http-proxy` on `9999` for the 3xK fleet; 507
sources in all with proxy software, **6** of them in the residential
reference split) is direct evidence of a proxy node but not of whose. On
current data 41 residential sources carry a consumer-device or proxy
fingerprint (MIK-577 query `q11`); eight of them have two or more
agreeing signals (residential ASN, consumer PTR, CPE product, attack
labels), for example a Viettel line with HikVision on 8001/8002 and
MikroTik btest on 2000 under `dynamic-adsl.viettel.vn`, or a Telefonica
Germany line with FRITZ!OS SIP and TR-069 under
`dynamic-N.pool.telefonica.de`. The other 33 are thinner, typically
MikroTik btest alone plus one `probe` request. Published work supports
the signal: Yang et al. (CCS'22) found 3,232,698 China residential-proxy
IPs with at least one TCP/UDP port open for relaying requests, seen by an
outside scanner (see Prior art).

Two limits are structural. `devicetype` is nearly empty, so classification
has to come from `product`, `os_guess` and port sets, which means a
catalogue we write. And the scan sees the gateway: behind NAT the CPE that
answers is the router, not necessarily the host that sent the traffic.
Timing is acceptable: 4,731 of 5,374 scanned sources were scanned within
an hour of their last request and the rest within 24 hours, so the box we
see is usually the one that sent the traffic, but on a dynamic line a 1
to 24 hour lag can hit the next subscriber.

**Have / need.** Have: the scans, at no new cost. Need: a consumer-device
catalogue (port, `product` / `os_guess` / `service` patterns, a vendor
label), a TOML file in the style of `rules/`, applied when a scan result
is stored and on a one-off backfill. Coverage question for the engineer:
both TR-069-on-7547 examples in MIK-577 came from level-4 scans, which
suggests 7547 sits outside nmap's top 1000 (`--top-ports 1000` at levels
2 and 3, `src/scan/profiles.rs`); if so, levels 1 to 3 never see the
clearest CPE tell. The engineer checks `nmap-services` for 7547 and 8291. Adding a handful
of CPE ports (`7547`, `8291`, `2000`, `8089`, `5555`, `37777`) to the
level-1, level-2 and level-3 argument lists in `src/scan/profiles.rs`
(level 1 is `--top-ports 100`, levels 2 and 3 `--top-ports 1000`; level 4
already scans every port) costs a few probes per scan and no retention. Scan budget otherwise unchanged;
storage: one derived row per matched (address, signature), thousands of
rows at most.

**Adversarial read.** We assume that a residential-proxy SDK inside an app
on a phone or TV behind NAT opens nothing on the WAN address, so the scan
sees the ISP's CPE or nothing. That is our assumption and unquantified
(the MIK-576 memo marks it as inference); Yang et al. (CCS'22) saw
3,232,698 China residential-proxy IPs with a relay port open to an outside
scanner, so at least part of the pool is visible. A "clean" scan is therefore the default for the biggest
residential-proxy networks and costs the operator nothing. A botnet that
owns a router can close its WAN listeners after infection, as Mirai
variants do, also for free. In the rented direction the forgery is cheap
and deliberate: a VPS that answers on 7547 with a TR-069 banner and on
2000 with a MikroTik greeting is a few lines of configuration, and our
scanner arrives within the hour, so an operator who watches for it can
switch banners. **Gain from mislabelling:** with the scan feeding
"compromised", a renter gets their addresses listed as victims instead of
attackers, a softer category for addresses they want to keep using.
Pointing our scanner at a third party is limited, because we scan the
address that completed a TCP handshake with us. Consequence for the
design: device evidence is shown with the scan it came from and the exact
port and product, it never lowers severity, never changes blocklist
membership, and never leaves the node.

### 4. Host keys: SSH host key, TLS certificate, ETag, HASSH, JA4X

**Where.** `host_keys(ip_id, port, kind, fingerprint, detail, scan_id |
probe_id)` (`0002_host_keys.sql`, reshaped in `0018_probes.sql`). Instance
keys (`ssh-hostkey`, `tls-cert`, `http-etag`) exist for 839 sources
(12.8%).

**Verdict: usable for rented fleets; not usable for hijacked.** Keys that
repeat do so inside one provider: six SSH host keys on 10 to 22 addresses
each, all AS200373 3xK Tech (one cloned image); one TLS certificate on
port 9999 on 40 DigitalOcean addresses in 40 different /24s; one ETag on
15 Shadowserver hosts. **Not one instance key spans three or more
ASNs** (ssh-hostkey 0, tls-cert 0, http-etag 0 of the keys on two or more
addresses), which is the pattern a cross-network pool or botnet would
leave. HASSH and JA4X span many ASNs (top HASSH: 264 addresses in 43
ASNs) because they name software builds, not machines. The campaign
recompute already turns shared SSH keys and certificates into hard edges
(`campaign_edges.kind IN ('ssh','tls')`, `0040_campaigns.sql`), with a
cap that treats a value on more than 50 addresses as shared
infrastructure rather than one operator.

**Have / need.** Have everything; nothing to add. A weak extra: an
embedded-device HASSH (Dropbear) on a residential address corroborates
signal 3 at no cost.

**Adversarial read.** Bots are distinct devices with distinct keys, and an
SDK opens no listener, so the signal never fires on hijacked endpoints and
evasion is free. For rented fleets evasion is one `ssh-keygen -A` per
instance at boot, cheap but deliberate (3xK has not bothered). **Gain from
mislabelling:** an nmap fingerprint is the public key, and does not prove
possession of the private one. Copying a competitor's host key or
certificate onto one's own boxes merges one's scanning into their fleet;
copying a victim's key onto a scanner merges a residential victim into a
rented fleet. The existing campaign cap of 50 addresses per value limits
the blast radius; the consumer-device verdict below additionally requires
that the address is in no fleet, so a planted key cannot promote a rented
box to "consumer".

### 5. Request fingerprints: JA4, JA4H, User-Agent, browser

**Where.** `requests.ja4` (HTTPS only, 2,602 sources, 39.8%),
`requests.ja4h` (3,770, 57.6%), `requests.user_agent`,
`requests.tls_client_hello`, `requests.raw_head`; browser fingerprints in
`fingerprints` (17 sources in the window).

**Verdict: weak.** JA4 and JA4H name the client tool (Go `net/http`,
zgrab, curl, python-requests), and the same tool runs everywhere: the
biggest JA4 sits on 421 sources in 23 ASNs, the biggest JA4H on 1,084 in
35. A fingerprint across twenty ASNs means "popular tool", not "botnet".
The inverse is the only useful reading: an embedded or old TLS stack (no
ALPN, TLS 1.2 only, odd cipher list) from a residential address suggests
the device itself is sending, a bot rather than a forwarding proxy; we
hold no reference list of CPE client stacks to make that call, and 60% of
sources use plain HTTP and have no JA4 at all. Browser fingerprints are
absent in practice (scanners do not run the trap's JavaScript).

**Have / need.** Have the columns. A reference list of IoT/CPE ClientHello
shapes would be new curation with no data to validate it against here;
not proposed. JA4 (TLS client) is BSD-3; JA4H, JA4X and the rest of
JA4+ are under the FoxIO License 1.1, which MIK-581 settles.

**Adversarial read.** A residential proxy forwards the operator's TCP
stream, so the JA4 we see is the operator's client, the same from every
exit; that is detectable only when the operator is careless and is fixed
for free with uTLS or curl-impersonate. A botnet's JA4 is the device's
own stack, which the operator cannot easily change but which we cannot
recognise either. **Gain from mislabelling:** scoring "browser JA4 +
residential ASN" as "hijacked browser" hands every curl-impersonate user
the victim label; impersonating a competitor's scanner JA4 attributes
one's traffic to their fleet. Hence JA4 contributes nothing to any
verdict here; it stays the campaign recompute's tie-breaker for soft
edges (`campaign_edges.fp_support`).

### 6. Time: dwell, /24 density, diurnal profile

**Where.** `ips.first_seen`, `ips.last_seen`, `requests.ts` (stored to the
second; `docs/dataset.md` says milliseconds, which is wrong for this
column), `skipped_requests.ts_ms`, `skipped_batches.first_ms/last_ms`.

**Verdict: dwell and /24 density usable for rented; diurnal not worth it
on current data.** Dense /24s are scanner operators (49 /24s with 16 or
more sources hold 1,594 sources; the densest five are all scanner
fleets); long-lived addresses too (1,094 hosting sources with a dwell of
a day or more against 80 residential). A diurnal profile needs enough
requests over enough days: 190 sources have 20 or more requests over three
or more days, and **6** of those are residential. A hijacked residential
source typically sends one to five requests and leaves, which no timing
model can read. Eleven days from one vantage point is also too short for
a weekly pattern.

**Have / need.** Have the timestamps. Diurnal would need 30 or more days
of multi-node data on sources that mostly do not stay long enough to
profile; no retention change would fix the latter. Not proposed.

**Adversarial read.** Residential-proxy networks rotate the exit per
request or per session by design, so short dwell is their default and
also the default of every one-shot scanner; it separates nothing. Diurnal
follows the device owner's hours only while the device is on, and a rented
fleet fakes a human curve with one cron line. **Gain from mislabelling:**
a /24-density rule turned on a target: an operator with an ISP-proxy plan
pushes traffic through many exits inside one eyeball /24 and gets that /24
classed as a rented fleet. Density therefore only ever supports a rented
reading when combined with a hosting-type AS, never alone.

### 7. Canary credential reuse

**Where.** `canaries(value_hash, kind, request_id | batch_id, ts, ip_id)`
and `request_tokens(request_id, value_hash, place)`, joined as in
`src/store/canaries.rs` (`REUSE_SELECT`). 103,252 values served to 972
sources; 64 values link two or more source addresses (174 sources).

**Verdict: usable and strong for coordinated rented fleets; says nothing
about hijacked sources yet.** Every cross-source reuse in the window is
one operator (AS25369 Hydra Communications, `infrawat.ch`) passing an MCP
session id between its own hosts within 0 to 2 seconds (242 of 252
cross-source rows). Harvested credentials proper (`git-token` 130 rows,
`db-password` 1) have only ever come back from the address that harvested
them: 0 cross-source. We have no case of a credential taken by one address
and used from a residential exit, which would be the textbook proxy-pool
pattern. If it appears, it is the one piece of evidence that ties a
residential address to a rented operator with no scan involved.

**Have / need.** Have everything; the campaign recompute already makes
canary reuse a hard edge (`kind='canary'`). Needed change: a verdict that
relies on it counts only header and body placements
(`request_tokens.place = 'body'` or `LIKE 'header:%'`; the column holds
`body`, `path`, `query` and `header:<name>`), not path or query.

**Adversarial read.** The derivation is public (`docs/dataset.md`), so an
operator can recognise generated values or test them from a throwaway
exit, cheaply. **Gain from mislabelling:** canary reuse is the one signal
an outsider can steer. To frame address B, the attacker needs B to send
the value; for the `mcp-session` path and query placements a link or an
embedded image is enough to make a victim's browser "reuse" it. A token in
an `Authorization` header or a request body is much harder to plant.
Hence the placement restriction above.

### 8. Forwarding headers sent by the source (measured for this assessment)

**Where.** `requests.headers_json`; `requests.via_proxy` says the row came
through our own trusted reverse proxy. The roadmap lists "a `Via`,
`Forwarded` or `X-Forwarded-For` header in the probe itself means a
forwarding proxy" as a small item.

**Verdict: not worth it as a proxy signal; it is a bypass probe.** On
hermes every request has `via_proxy=1` (185,035 of 185,035), and nginx
stamps `x-forwarded-for` with the source address on all of them: 2,947
sources carry an `x-forwarded-for` equal to themselves. Headers the
source itself sent: `x-forwarded-for` with another value on 72 sources,
`forwarded` on 16, `via` on 2, 73 sources in all, 68 of them hosting and
2 residential. The values are `0.0.0.0`, `localhost` and the like: access-
control bypass attempts, not proxy chains. A rule for them is a
reconnaissance label (`header-spoof`, weight 2), not evidence about the
source's nature, and must ignore the trusted proxy's own header. The
roadmap line should be reworded when this lands.

## Scoring: evidence, not points

The owner asked for a scheme precise enough to implement that never ships
an unexplained number. The adversarial reads above share one lesson: every
signal that points at "hijacked" is cheap to forge in exactly that
direction, and the rented signals are strong because they are expensive
to fake towards "rented". An additive score lets two forgeable weak tells
add up to a strong claim, which is the attacker's lever. So the proposal
is a small set of typed **evidence rows** plus a **first-match verdict
table**, both derived on each node, never replicated and never written by
a person, in the same shape as campaigns (`0040_campaigns.sql`) and the
derived RDAP columns (`0043_rdap_net.sql`).

### Evidence rows

One derived table, `ip_evidence(ip_id, kind, value, ref_kind, ref_id,
first_ts, last_ts, v)`, where `ref_kind`/`ref_id` point at the row that
produced it (`scans.id`, `ip_names.id`, `host_keys.id`, `campaign_edges`
key) and `v` is the derivation version, so a catalogue change recomputes
cleanly. Kinds and their exact conditions:

| kind | condition (tables as named above) | direction | forgeable towards |
|---|---|---|---|
| `net.hosting` | `ips.asn` in the bundled AS-type list as hosting/cloud/scanner, or the address is a verified crawler | rented | not in attacker's interest |
| `net.eyeball` | `ips.asn` in the list as consumer ISP (fixed or mobile); `value` = `fixed` / `mobile` | context only | "residential" via ISP proxies |
| `name.scanner` | `ip_names.source IN ('rdns','ptr')` and name matches the scanner-pattern list | rented | nothing to gain |
| `name.consumer` | same sources, name matches the consumer-pattern list; `value` = the pattern id | context only | "residential" via custom PTR |
| `device.cpe` | an open `ports` row of a finished scan matches a catalogue entry on (port, `product` / `service` / `os_guess` regex); `value` = catalogue id, e.g. `tr069`, `mikrotik-btest`, `fritzbox`, `hikvision`, `openwrt-luci`, `android-tv` | hijacked (device, not line) | "victim" via fake banners |
| `device.proxy` | open port with `product` matching 3Proxy / Socks / `service IN ('socks4','socks5','http-proxy')`, or `scan_facts.kind='socks.method'` | proxy node | "victim" via fake banners |
| `fleet.key` | an instance key (`host_keys.kind IN ('ssh-hostkey','tls-cert','http-etag')`) shared with 2 to 50 other addresses; `value` = fingerprint | rented | "fleet member" via copied public key |
| `fleet.canary` | a canary served to another address came back from this one with `request_tokens.place = 'body'` or `LIKE 'header:%'` | rented | hard (needs the victim to send a header) |
| `fleet.dense` | 16 or more sources in this address's /24 in the window (IPv4) or /48 (IPv6) | rented, only with `net.hosting` | "fleet" by flooding an eyeball /24 |

Nothing in the table is a new collection: every condition reads rows the
node already stores. The two inputs that do not exist yet are the AS-type
list and the two pattern catalogues (consumer names, CPE devices), all
bundled text files.

### Verdict table

Per address, first matching row wins; the verdict carries every evidence
row that matched, with its reference. Wording is deliberately about what
was observed.

| # | rule | verdict | shown as |
|---|---|---|---|
| 1 | verified crawler or research scanner (existing FCrDNS check), or Tor exit | `declared` | existing badges; unchanged |
| 2 | `fleet.key` or `fleet.canary`; or `fleet.dense` with `net.hosting`; or `net.hosting` with `name.scanner` | `rented fleet` | "one of N addresses sharing SSH key …" / "canary served to … came back from here" |
| 3 | `net.hosting` alone | `rented` | "hosting AS" |
| 4 | `device.cpe` and `net.eyeball`, and no `fleet.key` / `fleet.canary`, and no `name.scanner` | `consumer device answered` | "a TP-Link TR-069 service answered on 7547 in scan #… (level 4, <date>); the line is in a consumer ISP AS" |
| 5 | `device.proxy` and `net.eyeball`, and no `fleet.key` / `fleet.canary` | `proxy software on a consumer line` | "3Proxy answered on 3128 in scan #…" |
| 6 | `device.cpe` or `device.proxy`, and no `net.*` row, and no `fleet.key` / `fleet.canary` | `device evidence only` | the device or proxy sentence of rule 4 or 5, then "AS type not classified" |
| 7 | otherwise | `unknown` | nothing |

`fleet.dense` on its own decides nothing: it only confirms a hosting AS
(rule 2), never a consumer one, and it does not block rules 4 to 6, because
a /24 of infected routers in one ISP is dense too. Rule 6 is where every
`device.*` row lands when the address has no `net.*` row, which is every
address outside a listed hosting AS: the bundled list classifies hosting
only (MIK-587), so no address has `net.eyeball`. It stays that way until we hold a written ASdb grant
(see [Before sharing](dataset.md#before-sharing)). Rule 3 catches `net.hosting` before rule 6,
so rule 6 never describes a hosting address.

Rules 4 to 6 never say "compromised", "hijacked" or "botnet". The data
supports "a consumer device answered our scan on this address at this
time"; whether it was hijacked, misconfigured, or a renter's imitation is
not observable from here, and the text says so. `net.eyeball` with
`value='mobile'` adds the fixed caveat "mobile ISP address: usually many
subscribers (CGNAT)".

Order matters against forgery: a planted public key (signal 4) can only
move an address *towards* rented (rule 2), which is the direction nobody
wants to be moved, and a flooded eyeball /24 (signal 6) moves nothing,
because `fleet.dense` counts only next to `net.hosting`; a fake CPE banner (signal
3) can reach rule 4 only on an address that is in no fleet and in an
eyeball AS, so the renter must also buy ISP-proxy space, and even then
earns a sentence on an admin page of the node that scanned them, not a
list entry.

## Confidence and failure modes

**Confidence.** Rented verdicts (rules 2 and 3): high. The evidence is
expensive to fake in that direction and the hosted majority makes it the
common case. Consumer-device verdicts (rules 4 to 6): low to medium per
address, and the population is small: 41 candidates on 6,543 sources
today, 8 with two or more agreeing signals. Treat it as a lead for an
analyst, not a classification.

**Recall is the honest problem, not precision.** The classes the owner
named split as follows. Exposed home routers and IoT boxes: partly
visible (signal 3), and only at the scan level that reaches their ports.
Infected desktops behind a router: the scan sees the router, so visible
only if the router itself is exposed. Residential-proxy SDK exits on
phones, TVs and PCs: mostly invisible, on our assumption that an SDK exit
opens no WAN listener (unquantified; the MIK-576 memo marks it as
inference), plus operator-side JA4 and rotating exits. Exits that do
expose a relay port are visible to signal 3: Yang et al. (CCS'22) found
3,232,698 such China residential-proxy IPs. The roadmap's "cannot be told
apart" line remains correct for SDK exits without a listener.

**CGNAT and shared addresses.** A mobile or CGNAT address is many
households. CGN runs in 17-18% of eyeball ASes and over 90% of cellular
ASes, with subscriber-to-IPv4 ratios up to 20:1 reported (Richter et al.,
*A Multi-perspective Analysis of Carrier-Grade NAT Deployment*, IMC 2016,
https://arxiv.org/abs/1605.05606). 15 sources are "Mobile ISP" by the reference label and the
true number is unknown because CGNAT is not visible from outside. A
per-address verdict there is a claim about a crowd. Mitigations in the
scheme: the `mobile` caveat on every such verdict; a counter-scan of a
CGNAT address scans the carrier's gateway, so `device.cpe` will rarely
fire; and nothing here feeds the blocklist or leaves the node, because a shared
verdict on a CGN address would be copied to every member as a claim about
everyone behind it. A pre-existing hazard worth
noting separately: the blocklist's `networks=1` option collapses busy /24s
to a prefix, and an eyeball /24 collapsed that way blocks many
households. An AS-type list would let `networks=1` skip eyeball /24s; that
is a follow-up, not part of this slice.

**Address churn: the dominant failure mode.** A per-address label goes
stale faster than anything else in this scheme breaks. ISPs renumber IPv4
every 1 day (DTAG) to 2 weeks (BT) (Padmanabhan et al., *DynamIPs*,
CoNEXT 2020, https://www.caida.org/catalog/papers/2020_dynamips/dynamips.pdf),
and 91% of China residential-proxy IPs lived under 10 days (Yang et al.,
CCS'22). A "compromised" label therefore lands on an uninvolved subscriber
within days. Scans land within 1 hour for 88% of scanned sources and
within 24 hours for the rest; on a dynamic line the later ones can hit the
next subscriber. The verdict text therefore names the scan time, and
evidence older than the address's `last_seen` by more than 24 hours is
not used.

**Where a verdict is surfaced.** Local analysis only. Concretely: a derived
table on each node, recomputed with the hourly campaign pass; shown on the
admin IP page and as an IP-list filter; absent from the public dashboard,
absent from `/api/blocklist` (which stays severity-driven: an address that
sent severity-3 requests is listed whether or not a router answered the
scan, and never *un*listed for it), absent from the export as a column.
The export already carries the raw material (`scans`, `names`, `intel`),
so another node or a researcher can recompute the same verdicts with the
same bundled catalogues, which is the same contract campaigns have: derived
on each node, not a replicated claim. Reason: a replicated "consumer
device" row is a statement about a third party's equipment, signed by a
member and copied to every other member's dataset and exports, and the
one strong signal behind it is forgeable by the party with the most to
gain. A derived row can be withdrawn by changing a catalogue; a replicated
row cannot. A second reason is legal: a dynamic IP address can be personal
data for a party with legal means to identify the subscriber (CJEU,
*Breyer*, C-582/14, 19 October 2016,
https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A62014CJ0582),
so a "compromised device" label on it is plausibly processing personal
data, and with churn and CGN often about the wrong person (the memo's
inference).

**Failure modes of the slice itself.** A catalogue regex that is too wide
(for example matching "router" in any `os_guess`) mislabels load
balancers and VPN appliances; the fix is per-entry tests like the rules
have. A too-narrow one misses vendors; the report of the recompute should
list unmatched `devicetype`/`os_guess` values so the catalogue grows from
data. The AS-type list goes stale; refresh it on the Tor list's cadence and
show its date on the status page.

## Prior art

Source: the MIK-576 findings memo (passive identification of residential
proxies, proxyware and botnet endpoints without commercial feeds).
Citations are given as the memo gives them; figures it quotes second-hand
are marked "via". Two paragraphs below are our decisions, not the memo's,
and are labelled as such.

### Offline AS-type sources

ASdb (Ziv, Izhikevich, Ruth, Izhikevich, Durumeric, *ASdb: A System for
Classifying Owners of Autonomous Systems*, IMC 2021,
https://dl.acm.org/doi/10.1145/3487552.3487853) covers 96% of ASes and is
93% accurate on 17 categories (75% on 95 sub-categories), 2.5 to 6 times
more accurate than IPinfo or PeeringDB on hosting providers. PeeringDB
`info_type` covers only about 15% of ASes (95% recall where present, per
ASdb). CAIDA's AS classification was discontinued for declining accuracy:
72% coverage and 58%, 75% and 0% accuracy per class in the December 2020
release, per ASdb's re-measurement. Whether ASdb or PeeringDB can be
bundled, and how often it would need refreshing, is MIK-582's question,
not this document's.

The negative is the important part. AS type separates a hoster from an
eyeball; it cannot separate a hijacked eyeball from an ordinary one.
Residential-proxy exits sit on genuine residential addresses by
construction: Mi et al. (*Resident Evil*, IEEE S&P 2019, via Chiapponi,
*Detecting and Mitigating the New Generation of Scraping Bots*, PhD
thesis, Sorbonne/EURECOM 2023,
https://theses.hal.science/tel-04443915v1/file/CHIAPPONI_Elisa_these_2023.pdf)
found 95.22% of 6M+ collected residential-proxy IPs genuinely residential.
That is why `net.eyeball` is context, never evidence.

### Botnet scanner fingerprints (Mirai)

The memo cites no port or banner catalogue to seed `device.cpe`; what it
found is a packet fingerprint. Mirai's scanner sets the TCP sequence
number to the destination IP (`tcph->seq = iph->daddr;`, `scanner.c`
lines 117-120 and 225,
https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c).
Descendants diverge: Hajime and Mozi "have virtually no overlapping IP
addresses", and the authors conclude "there is no longer one canonical
IoT botnet" (*The End of the Canonical IoT Botnet*, arXiv 2309.01130,
2023, https://arxiv.org/abs/2309.01130).

**Our decision: peephole cannot see this fingerprint, and it is not a
`devices.toml` entry.** Traps terminate TCP in userspace (tokio
`TcpListener`) and nothing stores packet headers. The roadmap's JA4T item
(`TCP_SAVE_SYN` / `TCP_SAVED_SYN`) would not help: the fingerprinted
packet is the scanner's raw half-open SYN, which is answered by RST and
never becomes an accepted socket, so `getsockopt(TCP_SAVED_SYN)` never
runs on it. Mirai's follow-up brute-force connection uses an ordinary
`connect()` (`setup_connection` in `scanner.c`) and gets a kernel-random
ISN. Seeing the scanner SYN would take raw packet capture (pcap or
AF_PACKET plus capabilities), which is outside peephole's design.

### Proxy SDKs and listeners

The memo finds no peer-reviewed receiving-end study of proxyware or
bandwidth-sharing SDKs, only vendor blogs, which it does not draw on. That
an SDK exit opens no listener is marked in the memo as inference, not
measurement. What is measured points the other way for part of the pool:
Yang, Yu, Mi, Tang, Guo, Li, Zheng, Duan (*An Extensive Study of
Residential Proxies in China*, CCS 2022,
https://dl.acm.org/doi/10.1145/3548606.3559377) found 3,232,698 China
residential-proxy IPs that "opened at least one TCP/UDP port for accepting
relaying requests". An open SOCKS port also fits a deliberately run proxy.

**Our decision: this does not change the build.** It raises the value of
signal 3, which the slice already builds on. "Invisible by construction"
is restated in signal 3's adversarial read and in Confidence and failure
modes as our unquantified assumption, with the CCS'22 figure beside it.

### False-positive rates for residential classification

None published, for any of the context signals. For PTR patterns the
closest data point is UDmap's motivating case (Xie, Yu, Achan, Gillum,
Goldszmidt, Wobber, *How Dynamic are IP Addresses?*, SIGCOMM 2007,
http://ccr.sigcomm.org/online/files/fp179-xie.pdf): of 136 spam-sending
addresses in one block, 93 had no rDNS at all, and 30 of the 33 with
records "could not be classified due to the lack of any meaningful
information". No accuracy figure exists for ASN-only residential
classification as a proxy test, and none for "same JA4 from many eyeball
ASNs means a pool". The "context only" rating of signals 1, 2 and 5
stands; it rests on no published calibration.

### Rejected techniques

| Technique | Reported numbers | Why rejected | Source |
|---|---|---|---|
| CAIDA AS classification | 72% coverage; 58% / 75% / 0% accuracy per class (Dec 2020) | Discontinued by CAIDA for declining accuracy | ASdb, IMC 2021 (above) |
| PeeringDB `info_type` alone | ~15% of ASes; 95% recall where present | Too little coverage to stand alone | ASdb, IMC 2021 (above) |
| "Residential ASN means genuine user", or the reverse | 95.22% of 6M+ residential-proxy IPs genuinely residential (Mi et al., S&P 2019, via Chiapponi) | Defeated by design: residential-proxy providers sell exactly this property | Chiapponi thesis 2023 (above) |
| JA3 | none | Broken by Chromium's 2023 extension-order randomisation and cipher stunting; use JA4 and expect yearly drift | FoxIO JA4 README, https://github.com/FoxIO-LLC/ja4 |
| rDNS keywords alone | 93 of 136 addresses with no rDNS; 30 of the remaining 33 unclassifiable | Records often missing or meaningless | Xie et al., SIGCOMM 2007 (above) |
| Long-lived per-IP "compromised" labels | IPv4 renumbering 1 day to 2 weeks; CGN in 17-18% of eyeball ASes | Churn plus CGNAT puts the label on the wrong subscriber | Padmanabhan et al., CoNEXT 2020; Richter et al., IMC 2016 (above) |
| RTT gap: TCP-handshake RTT vs TLS/app-layer RTT | Lab (Δ = 50 ms): FPR 0.04%, FNR 1.93%, accuracy 99.01%. Production: daily FPR upper bound averaged 17.66% (sd 7.53%), 7.24-29.27% across airlines, driven by mobile clients | Decisive: the production FPR. A 7-29% false-positive rate concentrated on mobile clients lands on exactly the CGNAT population this document already flags. It also needs a session we terminate; peephole does terminate TLS and HTTP on its traps, so that is a scope limit (useless on bare SYNs and behind nginx), not a blocker | Chiapponi, Dacier, Thonnard, *Towards Detecting and Geolocalizing Web Scrapers with Round Trip Time Measurements*, TMA 2023, https://www.elisachiapponi.com/publication/tma_2023/; figures from the Chiapponi thesis ch. 4, Table 4.7 |
| One fingerprint for "IoT botnet" | Hajime and Mozi with "virtually no overlapping IP addresses" | Mirai descendants diverge; a fingerprint covers a family | arXiv 2309.01130 (above) |

### Gaps

- No peer-reviewed receiving-end study of proxyware or bandwidth-sharing
  SDKs.
- No numbers on SSH host-key or certificate reuse across ASNs (pool vs
  cloned image). Absent, not disproven.
- No published false-positive rate for the same JA4 across eyeball ASNs.
- Khan, Chiapponi, Verkleij, Sperotto et al., *A First Look at
  User-Installed Residential Proxies From a Network Operator's
  Perspective*, CNSM 2024 (UTwente): not read; the PDF sits behind a
  Cloudflare challenge. Its perspective is in-path.
- Mi et al. (IEEE S&P 2019) and Antonakakis et al. (*Understanding the
  Mirai Botnet*, USENIX Security 2017) were not read in the primary;
  figures from Mi are second-hand.

The memo moved one verdict (signal 3, toward counter-scan, on the CCS'22
figure) and did not change the evidence-row scheme or the recommendation.

## Recommendation

**Build a narrow slice: consumer-device evidence on the IP page. Do not
build a score, a shared verdict, or diurnal analysis.**

The slice, in order, each step with its check:

1. **Catalogues.** `rules/devices.toml` (CPE and IoT signatures: port,
   product/service/`os_guess` regex, id, vendor label; seeded from the
   eight MIK-577 examples plus the MikroTik, TR-069, FRITZ, HikVision,
   Dropbear/LuCI and Android TV families) and a consumer-name pattern list.
   Check: a test that each signature matches its own sample and none of
   the top-20 rented fleets' banners from MIK-577.
2. **Derived table and recompute.** Migration adds `ip_evidence` (local,
   never replicated, `v` column); the campaign pass (`store::campaigns`)
   or a sibling pass computes `device.*`, `name.*`, `fleet.*` rows, with
   the 24-hour staleness rule. Check: `peephole store recompute-campaigns`
   reports evidence rows by kind; on the hermes DB `device.cpe` lands on
   about 40 addresses and none in AS200373, AS14061, AS6939.
3. **Verdict and IP page.** Rules 2 to 6 as a function over an address's
   evidence rows; the IP page shows the verdict sentence with each evidence
   row linked to its scan or name; an IP-list filter `evidence=device.cpe`.
   Check, on the hermes DB without an AS-type list: the eight MIK-577
   CPE examples read as rule 6 with the device, port, scan id and date in
   the sentence and "AS type not classified" after it; the 507 sources
   with proxy software read as rule 6 with the proxy sentence (today they
   would show nothing); the 3xK cloned-key hosts read as rule 2 through
   `fleet.key` and the Hydra canary hosts through `fleet.canary`; no
   address reads as rule 3, 4 or 5, and no address reaches rule 2 through
   `fleet.dense`.
4. **Scan profile.** Add the CPE ports to levels 1 to 3 in
   `src/scan/profiles.rs` after checking nmap's top-100 and top-1000
   membership (the host has no `nmap-services` copy to check against; the
   engineer does). Check: the profile test asserts the ports at each level;
   one level-1 scan of a lab box answering on 7547 yields a `device.cpe`
   row.
5. **Docs.** The shipped part moves into `detection.md`; the roadmap's
   forwarding-header line is reworded as a `header-spoof` label.

Not in the slice: the AS-type list (`net.hosting` / `net.eyeball`). It
has since landed for hosting only (MIK-587): the X4BNet datacenter ASN
list plus a small supplement give `net.hosting`, which switches on rule 3
and the `fleet.dense` and `name.scanner` branches of rule 2. No source we
can bundle classifies eyeball networks, so `net.eyeball` is never set and
rules 4 and 5 cannot fire. What the slice shipped was rules 1, 2 (through
`fleet.key` and `fleet.canary` only), 6 and 7. Rule 6 is
still useful on the IP page and never leaves the node. When a list lands,
it is one more bundled file, the `net.*` rows appear on the next recompute,
and rules 3 to 5 and the rest of rule 2 switch on without a code change.

Rough cost: about two engineer-days (catalogues and tests half a day,
table and recompute one day, page and filter half a day), one additive
migration, no protocol change, no new setting beyond the catalogue files
built into the binary like `rules/`. Storage: a few thousand rows on a
node of this size. Scan budget: a few extra probes per level-1 and level-2
scan if step 4 is taken.

What this buys the owner: on an IP page, "a Huawei TR-069 service answered
on 7547 in the level-4 scan of <date>; AS type not classified" (the last
clause becomes "the AS is a consumer ISP" once the list lands), with
the scan one click away, for the few dozen addresses per 6,500 where that
is true. What it does not buy: a list of compromised devices, or any
detection of residential-proxy exits that expose nothing, which remain
indistinguishable from a careful human on a home line using only what we
hold.
