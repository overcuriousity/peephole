# Shared addresses: can peephole tell that a source address is shared, carrier-NATed, mobile or pooled?

This is the assessment behind the shared reading, in the same register as
[Compromised sources](compromised-sources.md). The narrow slice it
recommends is built (MIK-647, MIK-646): what ships, the rules, the export
column and the blocklist lines, is described in
[Detection](detection.md#shared-addresses) and
[the dataset](dataset.md#shared); this file keeps the reasoning. Scope: the owner's follow-up on
MIK-574, "can we confidently detect wether the ip is a shared one, a
mobile one, cgNAT or similar pooled ones? i am not strictly against a
score, as ling as it is transparent". The no-score rule of the compromised
assessment is lifted for this axis only; it still stands for anything in
the compromised or suspicion family.

Inputs, all 2026-10-19:

- **Data** (MIK-600): read-only pass on the hermes node, 11 days
  (2026-10-08 to 10-19), 186,771 requests from 6,328 sources with a stored
  request. The node holds rows replicated from 5 peers and recorded only 10
  requests itself, so the dataset is multi-node, which supersedes the
  "one node collected all of it" note in the compromised assessment. The
  node runs v0.15.3: `ip_evidence` does not exist there, and no
  `header-spoof` label exists anywhere. Every `device.cpe` and `net.hosting`
  figure below is therefore the MIK-577 approximation over `ports`, `scans`
  and the cached AbuseIPDB `usage_type`, marked "approx." in the tables,
  and no claim resting on one is rated above weak until a recompute on a
  node that has migration 0047. The class split used throughout is the
  cached AbuseIPDB `usage_type` (a third-party reference, not ground
  truth): hosting 5,255, fixed line 603, mobile 15, other 198, none 244,
  Tor 13. "Eyeball" means fixed plus mobile without AS6939 and AS25369
  (Shadowserver and Hydra, mislabelled fixed): 432 sources, 7 % of the
  population.
- **Evasion** (MIK-601, SecFxEngineer): how cheaply each signal can be
  manufactured by an operator who wants the gentler "pooled" label.
- **Literature** (MIK-598, Researcher): six topic notes, each with the side
  a method runs on and its reported error figure or "none reported".
- **Sourcing** (MIK-599, Researcher): no list we may redistribute carries a
  mobile or CGNAT label. That is a finding, not a pending item.

Source addresses are written as /24 (IPv4) or /48 (IPv6).

## Answer

The question is four claims, and the honest answer differs for each. No
blended verdict is given anywhere in this document, and the design in
"A transparent reading" never produces one.

**(a) Several end hosts are behind the address. Good, on a few dozen
addresses; medium confidence per address.** Two own signals say it: a
consumer router or CPE answering our counter-scan on the public address
(approx. 36 sources, 31 of them fixed line), and the counter-scan seeing
two different operating-system stacks behind one address on different
ports (5 eyeball addresses, 391 overall, most of them middleboxes on
hosting). Both are observations of the box on the address, not of the
sender, and both are inflatable only in the direction nobody wants
(signal 7 in the evasion read: faking a CPE banner argues *against* the
label an operator wants). What they cannot say is how many hosts: the
counting methods for that (signal 9) are closed out below.

**(b) Several unrelated subscribers are behind the address (carrier-grade
NAT). Weak, and not establishable from our own behaviour at all.** What
separates (b) from (a): (a) is one subscriber's NAT, one router, one
household's devices, one party who could be asked; (b) is a carrier box
in front of many subscribers who have nothing to do with each other, each
holding a port block, each reassigned within hours. The observations that
would separate them are the source-port block structure (not recorded),
many unrelated identities arriving concurrently (never seen on an eyeball
address: the maximum is 5 User-Agents in an hour, always one tool rotating
them), leaked 100.64/10 addresses (zero from eyeball sources, and carrier
NAT adds no HTTP header by construction), and the absence of a reachable
CPE (absence, which is free to arrange). The only evidence of (b) in
186,771 requests is three ISP-assigned names that say `cgn` or `nat`
(Neomedia, AIS Fibre, Vodacom), and all three answered nothing on the
counter-scan, which is consistent with a carrier gateway and proves
nothing. The literature agrees: no receiver-only method reports a per-IP
false-positive rate on traffic like ours; the validated ones (Cloudflare
0.98 accuracy, Cell Spotting precision 0.97 or better) use HTTP-layer or
on-device signals we do not see, and both label /24s, not hosts. (b) can
be *stated by the carrier's own naming* and never *detected* here, and the
reading below is worded that way.

**(c) The address is mobile. Weak per address from our own signals; a
prior, not a finding.** The brief expected this to be the most answerable
claim, and it would be with a list, but no list qualifies (MIK-599), and
our own signals are thin: 2 PTR hits (`umts`, `digimobil`) on 6,328
sources; an `asn_org` name heuristic that catches 1 of the 12 ASNs behind
the 15 reference-mobile sources and whose 20 "true carrier" hits are 18
times fixed line by the reference label, because China Mobile and SFR run
fixed and data-centre space under the same ASNs. 58.6 % of cellular ASes
are mixed (Cell Spotting), so ASN to "mobile" is structurally a prior.
The reference label itself (the cached AbuseIPDB `usage_type`) is of the
MaxMind kind the literature rates 99.5 % right on one carrier list and
11 % wrong inside one /21 of the same carrier. Of the 3,301 sources whose
User-Agent claims an operating system, the ones claiming Android or iOS
on an eyeball address sat beside `python-requests` in the same burst; the
other 3,027 sources claim none, and "no OS claimed" is insufficient
evidence, not a signal.

**(d) The address is reassigned over time (pooled). Usable where the ISP
says so, weak otherwise.** 18 to 20 non-hosting sources carry a
`dynamic`, `pool` or `ppp` name (the data pass gives 18 in its §4 and 20
in its closing table; both are quoted until a recount on a node with
`ip_evidence`). That is the operator stating its address plan, which is
the one thing a PTR can state. Our own longitudinal data adds nothing
strong: zero canary hops and zero JA4-plus-User-Agent hops between eyeball
addresses in 11 days across 5 nodes; the four UA-only hops (Telkom SA,
SFR, China Unicom, 3BB) are as consistent with several infected devices in
one ISP as with one device re-addressed, and a UA with one request per
address cannot tell them apart. Dwell separates nothing: 68 to 74 % of
every class is gone within a minute. The literature supplies the prior the
data cannot: 75 % of mobile associations last a day or less; fixed lines
with periodic renumbering change daily (DTAG), every 1.5 days (Proximus),
weekly (Orange) or fortnightly (BT); 21 % of CGNs move one subscriber
across public addresses within a session. So a pooled reading is "the ISP
names it pooled, and such lines renumber on these timescales", never
"we watched it move".

In one line: good on (a) for a few dozen addresses, (d) where the ISP
names it, (c) only as a prior, and (b) only as the carrier's own word.
That is the opposite of the brief's hope for (c) and matches its fear for
(b).

## What the population looks like

The data decides what can be measured, and the population is the wrong
one for behavioural CGN detection. 93 % of sources are hosting; the 432
eyeball sources send 1 to 5 requests each, 74 % of them inside a minute;
only 17 fixed-line and 0 mobile sources sent 20 or more requests. Every
receiver-side method in the literature infers sharing from many distinct
*clients* behind one address over time (Livadariu's telescope needs a
per-client identifier in the payload and scores per /24; Hsu's diurnal
fit needs 75 or more browsing subscribers per address; Cloudflare's
classifier takes a day of HTTP logs per /24). A honeypot sees one scanner
per eyeball address, once. Even with every packet-level field recorded,
this population would show multi-subscriber behaviour on almost no
address, which is why the ratings below do not improve much when a
signal is "not recorded" rather than "recorded and empty".

## Verdict per signal

Each of the eleven signals from the brief, with where it lives, what the
data pass counted, what the evasion read says it costs, what the
literature reports, and a rating of usable / weak / not worth it per
claim. "Not recorded" signals are rated on what capturing them would take.

### 1. Identity multiplicity in a short window

**Where:** `requests.ja4` (https only, 41 % of sources), `requests.user_agent`,
`requests.ts`. SSH client identity and client HASSH are not recorded:
there is no SSH trap, and `host_keys.kind='hassh'` is the *server* HASSH of
our counter-scan. A client OS stack profile is not recorded (signal 2).

**Data.** Per source, the maximum distinct count in any one window, all
6,328 sources: JA4 per minute p50/p90/p99 1/1/2, max 4; User-Agents per
hour p50/p90/p99 1/2/21, max 226. Eyeball only: JA4 per minute is 1 on 149
of 151 sources and 2 on 2; User-Agents per hour is 1 on 418 of 432, 2 on 7,
3 to 5 on 7, never more. Of the 92 sources with 11 or more UAs in an hour,
90 are hosting. Every non-hosting source with 3 or more UAs in an hour
(53, read one by one) is one tool rotating UAs inside one burst: same
paths, same labels, one JA4 or none, 6 to 90 requests in 10 to 120 s.

**Evasion.** Free to inflate (one client library varies the ClientHello
and headers per connection); hard to deflate. The signal is lopsided:
high multiplicity is worthless *for* (b), only low multiplicity is weak
evidence against it. Zero weight toward pooled.

**Literature.** Cloudflare's 2021 note counts distinct browser UAs per
address with no accuracy figure; the 2026 classifier uses client
diversity as one feature among many and reports no per-feature figure.

**Rating.** (a) weak: two eyeball sources with two JA4s in a minute. (b)
not worth it. (c) weak: a mobile UA is a claim, and the one Android UA on
a mobile address sat beside `python-requests`. (d) not applicable.

### 2. Mutually inconsistent OS or stack signatures within seconds

**Where:** not recorded. The accept path keeps only the peer address
(`src/trap/listen.rs:287` takes `(stream, peer)`; `src/trap/mod.rs:910`
keeps `peer.ip()`). No raw socket, no SYN capture, no p0f. The counter-scan
records the *answering* host's stack (nmap `-O`, `osmatch` in 2,415
scans), minutes to hours later, which describes the box on the address,
not the sender.

**Capturing it:** `TCP_SAVE_SYN` on the direct listeners gives the
client's SYN without pcap (the roadmap's "JA4T on directly listening
traps" line). It works only where the trap listens on 80/443 itself, which
is the `CA59`, `8058` and `A1E3` peers (27,569 rows, 15 %); behind nginx
the SYN goes to nginx. One small-to-medium slice, no migration beyond a
request column, and it would see one SYN per eyeball source.

**Evasion.** Low cost: two cheap VMs give two genuine kernels. Not
detectable, zero weight.

**Literature.** Maier et al. (PAM 2011) count distinct TTL-and-OS pairs
per DSL line *from inside the ISP* and report that "most accuracy is lost
when relying on IP TTL only", with no number.

**Rating.** (a) weak through the counter-scan stand-in in signal 10. (b),
(c), (d) not recorded.

### 3. Source-port allocation structure

**Where:** not recorded, confirmed: `requests` has no port column;
`raw_head` starts at the request line in all 181,076 rows that have one;
no row carries a PROXY-protocol line; the trusted proxies stamp
`x-real-ip` and `x-forwarded-for` with the address and no port. The port is
in memory at `listener.accept()` (`src/trap/listen.rs:287`) and dropped at
`src/trap/mod.rs:910`; for TLS through a trusted proxy `meta.proxied_src`
(`src/trap/listen.rs:384`) already carries it.

**Capturing it:** one nullable `INTEGER` on `requests` (about 3 to 4 bytes
per row, 0.7 MB for today's table, the same again in the replication log),
filled on the direct listeners and on the TLS-through-proxy path; plain
HTTP through the operator's proxy (the `E201` and `B4BD` peers, 85 % of
rows) would need the operator's nginx to pass `$remote_port` or speak
PROXY protocol on the HTTP listener too. The column would have to join
the replicated record (`src/cluster/record.rs`): a protocol addition. Then
block analysis needs many connections per address, and sources with 20 or
more requests are 17 fixed line and 0 mobile.

**Evasion.** Near zero: unprivileged binding covers the whole ephemeral
range, so one VPS can present per-identity port ranges. The most
CGNAT-specific signal of the eleven is also the cheapest to imitate and
invisible to us. Zero weight.

**Literature.** No published work infers CGNAT from source ports observed
at a receiver and reports an error rate (search log on MIK-598 4/6).
Richter et al. (IMC 2016) suggest the cue from their own server and show
why it is weak: port-preserving CGNs are 41 % of non-cellular and 28 % of
cellular CGN ASes and give no range signal; chunk allocation was found in
17 ASes and needs 20 or more sessions per AS; MAP-E port sets are
non-contiguous. Scanners choose their own ports (ZMap 32768 to 61000,
masscan pinned), so "outside the ephemeral range" means translation *or* a
raw-socket scanner.

**Rating.** Not recorded for (a) to (d). On this population, not worth
capturing for this axis; the JA4T slice above is the better reason to
touch the accept path, and the port could ride along.

### 4. rDNS and PTR naming

**Where:** `ip_names(ip_id, name, source)`, `source IN ('rdns','ptr')`.

**Data.** 2,820 of 6,328 sources (44.6 %) have a name; 271 of 603 fixed
line, 5 of 15 mobile. Token hits (a name split on `[.\-_0-9]+`):

| class | sources | fixed / mobile / hosting / other | sample |
|---|---|---|---|
| `cgn` | 2 | 2 / 0 / 0 / 0 | `N-N-N-N.cgn-wdsl.neomedia.it`, `N-N-N-N.N.nat.nkyN-cgnN.myaisfibre.com` |
| `nat` | 2 | 1 / 1 / 0 / 0 | `vc-nat-gp-s-N-N-N-N.umts.vodacom.co.za`, the AIS one |
| `cgnat`, `lsn`, `dip`, `lte` | 0 | | |
| `pool` | 9 | 8 / 0 / 1 / 0 | one false hit, `expresspools.us` |
| `dyn` | 10 | 10 / 0 / 0 / 0 | `N.N.N.N.dynamic.ttnet.com.tr` |
| `ppp` | 1 | 1 / 0 / 0 / 0 | |
| `dsl` / `cable` / `res` / `fiber` | 15 / 6 / 2 / 3 | all fixed but one | |
| `umts` (+3g/4g/5g/gprs) | 1 | 0 / 1 / 0 / 0 | the Vodacom one |
| `mobile` (`mobil*`, `mob`, `wap`) | 1 | 0 / 1 / 0 / 0 | `N-N-N-N.digimobil.es` |
| `static` | 65 | 12 / 0 / 51 / 1 | |
| any token | 107 | | |

The top 20 ASNs by source count are all clouds and scanner operators and
none has a consumer naming convention.

**Evasion.** Free on rented space (the renter controls the PTR zone and
forward confirmation passes); impossible to plant on a real consumer line,
where the subscriber does not control the PTR. A pool-style name in a
hosting AS is the tell, and the hits today are clean (34 of 48 consumer
names are on fixed-line ISPs). A name must never produce a pooled reading
on an address that has a `net.hosting` or `name.scanner` row.

**Literature.** Cloudflare uses `cgnat`, `cgn` and `lsn` PTR keywords as
*training labels* over the whole IPv4 PTR space and warns they may be
stale. No published accuracy for PTR-based mobile or fixed classification
was found.

**Rating.** (a) weak: a consumer-line name usually sits behind a
household router, but a name does not count hosts. (b) usable but tiny:
the only own evidence of carrier NAT in the dataset is three ISP-assigned
names, and it is the ISP speaking. (c) weak: 2 hits; most carriers
publish no PTR. (d) usable where present: `dynamic`, `pool`, `ppp` is the
ISP stating its address plan, 18 to 20 non-hosting sources. Coverage on
eyeball sources is 45 %, so absence means nothing.

### 5. ASN and organisation name

**Where:** `ips.asn`, `ips.asn_org` (GeoLite2), 6,301 of 6,328 with an ASN.
No curated list exists (MIK-599: X4BNet and its 40 sibling repos, ipverse,
IPinfo Lite, DB-IP Lite, Wikidata MNO-to-ASN, sg-mobile-asn-ranges,
IP2Location LITE and the paid databases all fail on licence, on having no
mobile class, or on labelling whole companies).

**Data.** A `mobil|wireless|cellular|gsm|lte|radiotelephon|selular|movil|
celular|telcel|3g|4g|5g` heuristic on `asn_org`: 13 ASNs, 26 sources; 9 true
carriers (20 sources), 4 false positives from `lte` inside a word
(Beltelecom, PALTEL, RailTel, Globaltech). The reference label calls 18
of the 20 carrier hits fixed line. Recall against the carriers we see is
about 25 %: of the 12 ASNs behind the 15 reference-mobile sources it
catches one (SFR); CMPak, Orange Maroc, TIM, Jio, Vodacom, Pelephone,
Digi, Maxis and Docomo are missed.

**Evasion.** Bought, not faked: a residential or mobile proxy exit at
roughly $1 to 15 per GB residential, $5 to 40 per GB mobile, or $50 to 300
a month for a dedicated modem port. A source sends tens of kilobytes per
node, so the label costs fractions of a cent per node plus the plan's
monthly minimum. Once bought, the ASN really is a carrier's, so (c) and
(b) are then *true*, not forged. This bounds the price of the label, not
its truth.

**Literature.** 58.6 % of cellular ASes are mixed (Cell Spotting, IMC
2017), which is why that work labels /24s and not ASNs. The MaxMind
connection-type database applied to honeypot sources (Huang et al. 2022)
was 99.5 % right on one Japanese carrier's list and 11 % wrong inside one
/21 of the same carrier: a usable prior with a stated error, not a
classifier.

**Rating.** (a) not worth it. (b) weak, prior only. (c) weak: a prior that
needs a list we cannot ship. (d) weak, same prior.

### 6. Longitudinal churn

**Where:** `requests` (`ip_id`, `ts`, `ja4`, `user_agent`, `origin`),
`canaries` with `request_tokens`, `ips.first_seen` and `last_seen`.
Identity is JA4 plus User-Agent on https rows; a canary is a stronger
identity.

**Data.** 1,675 JA4-plus-UA identities; addresses per identity p50 1, p90
4, p99 32, max 195. Identity-and-ASN pairs with 3 or more addresses first
seen inside a 6-hour window in a non-hosting ASN: 20, every one a scanner
(16 Shadowserver, 3 AGOTOZ, 1 Shadowserver AS22168), zero in a genuine
eyeball ASN. Canary reuse across sources: 252 rows, 242 of them Hydra to
Hydra, zero between eyeball addresses. Identities per eyeball address over
11 days: at most 6 after removing Shadowserver and Hydra. The UA-only hops
(Telkom SA `Hello, world` on three `dsl.telkomsa.net` addresses in three
/16s on three days; the SFR mobile pair 12 h apart with the same 5-UA set
and 13 paths; two China Unicom `adsl` addresses; two 3BB `dynamic`
addresses sharing no UA) are the only "same client, new address" patterns.

**Evasion.** Free with the proxy plan of signal 5 (rotation is its default
behaviour). Short dwell is also the signature of a one-shot scanner, so
churn separates nothing on its own. Zero weight toward pooled.

**Literature.** DynamIPs (CoNEXT 2020): 35 networks renumber periodically,
IPv4 modes 1 day (DTAG), 1.5 days (Proximus), 1 week (Orange), 2 weeks
(BT); mobile associations last a day or less in 75 % of cases; fixed
median 61 days. Ebb and Flow (PAM 2024): 33.9 % of 12,855 Atlas vantage
points changed address inside one quarter. Richter (IMC 2016): 21 % of
CGNs pool arbitrarily within a session. A per-prefix pool label moves by
0.2 % a month (Hsu 2026), so it is re-derived monthly; a per-address
"this device" claim behind a pool is stale within a day.

**Rating.** (a) not worth it. (b) weak: many unrelated identities on one
eyeball address over days would be the CGN signature, and the maximum is 6,
all attack tools. (c) not worth it. (d) weak: no strong-identity hop in
11 days; UA-level hops are ambiguous between re-addressing and several
infected devices in one ISP.

### 7. Counter-scan as negative evidence for (b)

**Where:** `ip_evidence` kind `device.cpe` (`rules/evidence/devices.toml`,
scan-profile ports 7547, 8291, 2000, 8089, 5555, 37777 in
`src/scan/profiles.rs`). Approximated on hermes over `ports` and `scans`.

**Data (approx.).** 36 sources with a CPE answering (fixed 31, hosting 5);
their identity multiplicity is 1 UA per minute on 35 and 2 per hour on
one, 9 have a JA4 and all exactly one; none has high multiplicity. Three
of the five (a) examples carry a FRITZ!Box or MikroTik answering while the
requests claim an iPhone UA: the router is not the client. Nothing
contradicts the inversion, but only because every CPE source sends 1 to 14
requests with one identity, not because the data tested it hard. The CGN
gateway case never shows up, because nmap does not identify carrier CGN
gear.

**Evasion.** Faking a banner is self-defeating; the adversarial move is
suppression, which is free and the default state. Presence is solid
evidence against (b); absence is zero weight. A panel may lower a
carrier-pool reading, never raise one, and it says nothing against a
reassigned line.

**Literature.** Richter (IMC 2016): CGN-negative ASes have the NAT one hop
from the client in 92 % of cases, so a reachable CPE on the public address
is the ordinary single-subscriber case. Cloudflare's label set uses Atlas
traceroutes with a private or 100.64/10 hop as CGN ground truth, the same
inversion from the other side.

**Rating.** (a) usable: a household router fronts the address. (b) usable
as negative evidence, thin (36 sources). (c) weak: argues against mobile.
(d) not worth it.

### 8. Leaked RFC 1918 and RFC 6598 addresses in forwarding headers

**Where:** `requests.headers_json`, `requests.raw_head`, `requests.via_proxy`.
A value equal to the source address is the trusted proxy's own stamp and
is ignored; everything else was sent by the client.

**Data.** Sources sending any RFC 1918 value: 35 (34 hosting, 1 our own
QA). RFC 6598: 1 source, hosting (AS48090), spraying random 100.64/10
values across four header names. Eyeball sources leaking either: 0. Of the
35, 14 put the value into 5 to 9 header names at once, cycling 10.0.x,
172.16.x and 192.168.x: an access-control bypass sweep. The one genuine
forwarding chain is a `Go-http-client/1.1` scanner behind a container
network (10.42/16, the k3s default) on 12 hosting addresses across three
VPN ASNs. No source sends a `Via` and a private value together, so
"a proxy adds `Via`" cannot be tested. The `header-spoof` label does not
exist in `origin/master` or on the node; the "also carries the label"
count is 0 by construction.

**Telling genuine from spoofed:** on the proxied peers the proxy appends
its own stamp at the end of the head, so client-sent copies sit earlier
and stay distinguishable by order; on the direct peers everything is
client-sent. Beyond order, nothing separates them, and the evasion read
settles it: a source-supplied header is attacker input and can only ever
earn a reconnaissance label, never evidence about the address. A carrier
could only inject such a header into cleartext HTTP; on TLS the source set
it.

**Rating.** (a) weak: one real forwarding chain, on hosting. (b) not worth
it: carrier NAT adds no HTTP header, so this channel cannot see CGN by
construction, and zero eyeball sources leak anything. (c), (d) not worth
it. Zero weight.

### 9. IP-ID and TCP-timestamp host counting, closed out

**Where:** not recorded for the source's own traffic (no packet capture).
The counter-scan records, for the *answering* host, nmap's `ipidsequence`
class (2,279 scans: all zeros 1,893, incremental 376, randomised 4, busy
6), `tcptssequence` class and an `uptime` guess. That is one host's clock
per scan, not a count of hosts sending traffic. Implied boot time across
repeat scans differs by more than a day on 304 of 501 addresses, which is
nmap's unreliable uptime guess on randomised timestamps, not
reassignment.

**Why it stays closed, with the stack evidence (MIK-598 3/6):**

- **IP-ID (Bellovin 2002).** Linux 6.9 uses a per-connection counter with
  a random start on established sockets and 0 on atomic packets; macOS
  and FreeBSD send 0 on all DF packets, which is all normal TCP; Windows
  Server 1903 and later use per-destination sequential counters. Alive
  for Windows senders only. Bellovin's own validation on 26 hosts was
  "plausible, though not absolutely correct", with no error rate.
- **TCP-timestamp offsets (Bursztein 2005, Wicherski 2013).** Linux
  randomised the offset per connection in 4.10 (commit 95a22caee396,
  motivation verbatim: "jiffies based timestamps allow for easy inference
  of number of devices behind NAT translators"), downgraded to per-host
  offsets in 4.11 (28ee1b746f49) because of `tcp_tw_recycle`, and
  restored per-connection offsets in March 2026 as CVE-2026-23247,
  backported to stable. macOS and iOS randomise per connection by default
  (`tcp_randomize_timestamps=1` in XNU); Windows workstation clients send
  no timestamps. Alive only for unpatched or pre-4.10 Linux and embedded
  kernels, which is a real share of compromised scanners, and positive
  evidence only.
- **Clock skew (Kohno 2005).** Needs about 2,000 packets over 50 minutes
  per source; eyeball sources here send 1 to 5 requests. Dead for this
  traffic.
- **Evasion.** Low cost on an owned host (randomise IP-ID, disable
  timestamps). Zero weight.

Even if the trap captured SYNs tomorrow, these methods would count
Windows and unpatched-Linux senders only, on a population that sends a
handful of packets, and would say nothing about macOS, iOS, patched
Android or Windows clients. The method is not re-proposed; capturing the
SYN is justified by JA4T, not by host counting.

**Rating.** Not recorded for (a) to (d); the counter-scan clock is not
worth it.

### 10. TTL and hop count

**Where:** of the source's packets, not recorded. Of the counter-scan's
replies, recorded: `reason_ttl` per port in all 9,466 scans (zstd-compressed
nmap XML in `scans.raw_xml`), `distance` in 1,832 scans at levels 2 to 4.

**Data.** 1,930 scans have 2 or more open `syn-ack` ports; 513 scans on
391 addresses mix initial-TTL classes (64, 128, 255) across ports, 386 of
those addresses hosting and mostly a middlebox (port 179 answering at
TTL 245 beside the host at 54 on 3xK). Fixed or other: 5 addresses, for
example TM Malaysia with Apache and OpenSSH at TTL 47 on six ports and IIS
at TTL 111 on three: a Linux box and a Windows box behind port forwards.
Hop distance changes across scans on 357 of 1,124 addresses: routing.

**Evasion.** The initial TTL of outbound packets is a host setting; the
traceroute measures the path to the gateway and is shaped freely. Zero
weight for inbound; the counter-scan mix is observation of the box, not of
the sender, and an operator gains nothing by faking it toward (a).

**Literature.** Scheitle et al. (2016): 69 % of passively observed
multi-packet hosts show one stable TTL, with "a difficult false
positive/false negative trade-off". Richter: CGNs sit 2 to 5 hops from the
client in 64 to 73 % of ASes, measured from the client side; at a remote
receiver only the total path is visible.

**Rating.** (a) weak but real: a per-port stack mix on an eyeball address
means port forwards to at least two hosts; 5 hits, with middlebox false
hits to filter (tcpwrapped ports, SYN proxies). (b) not worth it: under
CGN no inbound port is forwarded. (c), (d) not worth it.

### 11. Cross-node correlation

**Where:** replicated `requests` and `canaries` with their `origin` (5
peers).

**Data.** 954 sources seen at 2 or more nodes, 261 at 3 or more, 22 at 5;
fixed line 78 / 22 / 3, mobile 1 / 0 / 0. One identity on 3 or more
addresses of one non-hosting ASN at 2 or more nodes: 41 pairs, all single
scanning tools (Shadowserver 27, AGOTOZ 4, Chinanet 3, Censys 3, one each
for LG POWERCOMM, China Mobile, Driftnet). Canary values reused at a node
other than the serving one: 0 of 515. Eyeball sources at 3 or more nodes
behave like single scanners.

**Evasion.** The signal points one way: one identity from rotating exits
in one carrier ASN across many nodes exposes one *operator* behind a proxy
network. The pattern that would seem to support (b), many identities per
address per node, is signal 1 repeated and free. Suppressing the exposing
pattern is one library setting. It can lower a pooled reading (it is the
compromised family's `fleet.*` evidence), never raise it; absence is zero.

**Rating.** (a) not worth it. (b) weak and untested: the structure exists
and no eyeball ASN shows it. (c) not worth it. (d) weak: it widens the
view for re-addressing and has found none beyond scanners.

### Closing table: signal by claim

| # | signal | holds today | (a) hosts | (b) CGN | (c) mobile | (d) pooled | weight toward pooled (evasion) |
|---|---|---|---|---|---|---|---|
| 1 | identity multiplicity | JA4 41 %, UA 100 % of sources | weak | not worth it | weak | — | zero |
| 2 | client stack inconsistency | not recorded; SYN capture is a small slice on 15 % of rows | weak via 10 | not recorded | not recorded | not recorded | zero |
| 3 | source-port blocks | not recorded; column plus protocol addition, 17 fixed sources with 20+ requests | not recorded | not recorded | not recorded | not recorded | zero |
| 4 | PTR tokens | 44.6 % named; 3 `cgn`/`nat`, 18 to 20 pool, 2 mobile | weak | usable but tiny | weak | usable where present | ceiling, gated by hosting |
| 5 | ASN / org name | 25 % carrier recall; no list ships | not worth it | weak prior | weak prior | weak prior | inert until a list |
| 6 | churn | full; zero strong hops on eyeball | not worth it | weak | not worth it | weak | zero |
| 7 | CPE answering (approx. `device.cpe`) | 36 sources | usable | usable, negative, thin | weak | not worth it | lower only |
| 8 | private address in forwarding headers | 35 RFC 1918, 1 RFC 6598, 0 eyeball | weak | not worth it | not worth it | not worth it | zero |
| 9 | IP-ID / TCP-TS counting | not recorded; closed | not recorded | not recorded | not recorded | not recorded | zero |
| 10 | counter-scan TTL mix | per-port TTL in all scans | weak, 5 hits | not worth it | not worth it | not worth it | raise to (a) only |
| 11 | cross-node correlation | 5 peers; 954 sources at 2+ nodes | not worth it | weak, untested | not worth it | weak | lower only |

## A transparent reading, not a sum

The owner allowed a score if it is transparent. The evasion read adds the
constraint that decides its shape: seven signals carry zero weight toward
pooled, two may only lower, and the two that remain (4 and 5) plus 6 all
arrive together with one proxy subscription. An additive score lets two
forgeable weak tells add up to a strong claim, which is the lever an
operator would pull, and it blends the four claims the brief asked to keep
apart. So the proposal is an **ordinal reading** chosen by a first-match
rule table over typed evidence rows, in the shape `detection.md` already
uses for device evidence: never a sum, never a number, one rule per
reading, every rule published here and in the catalogue, every row linked
to the raw row that produced it. It is called a reading rather than a
score so that nobody renders it as one.

### Evidence rows

All rows live in the existing `ip_evidence(ip_id, kind, value, ref_kind,
ref_id, first_ts, last_ts, v)` from migration 0047, derived by the same
recompute pass, node-local, replaced in one transaction, versioned by
`EVIDENCE_V`. Three new kinds, all read from `ip_names` through
`rules/evidence/names.toml`, where `name.consumer` already matches
`dynamic`, `pool`, `dsl`, `cable`, `dhcp`, `customer`, `broadband` and
`fibre` with token-boundary patterns and per-entry samples:

| kind | condition | value | ref | claim | may |
|---|---|---|---|---|---|
| `name.cgn` | a `[[cgn]]` pattern matches: `cgn`, `cgnat`, `lsn`, `nat` as a token (never inside a word; `nat` only at a label or dash boundary) | pattern id | `name` → `ip_names.id` | (b) | raise to *shared pool* |
| `name.mobile` | a `[[mobile]]` pattern matches: `umts`, `lte`, `gprs`, `3g`, `4g`, `5g`, `mobil`, `mob`, `wap` as tokens | pattern id | `name` | (c) | raise to *shared pool* |
| `name.pool` | the existing `name.consumer` entries `dynamic`, `pool` plus a new `ppp` entry, split out so the reading can tell "pooled" from "consumer" | pattern id | `name` | (d) | raise to *pooled line* |
| `net.eyeball` = `mobile` | exists in `KINDS`, never set; fires when a licensable list or our own prefix labels land | `mobile` | `ip` | (c) | raise to *shared pool* |
| `device.cpe` | exists | catalogue id | `scan` | (a), against (b) and (c); says nothing about (d) | lower a *shared pool* reading to *one subscriber's network*; with `name.pool`, to *one subscriber's network, on a pooled line* |
| `scan.multistack` (optional, not in the slice) | two open `syn-ack` ports of one finished scan answer in different initial-TTL classes, neither port `tcpwrapped` | `64+128` | `scan` | (a), against (b) and (c); says nothing about (d) | as `device.cpe` |

Every `cgn`, `mobile` and `pool` entry carries a `sample` it must match and
is tested against the top-20 rented-fleet names
(`tests/fixtures/rented-fleet-names.txt`) like the consumer entries. The
false hit from the data pass (`expresspools.us`) is excluded by the
existing token-boundary rule. Name rows are not subject to the 24-hour
device staleness (`STALE_SECS`): a pool or CGN name is a property of the
operator's address plan and holds for weeks to months; the reading quotes
the lookup time and the row is re-derived with every recompute, and a
name looked up more than 30 days before the address's `last_seen` is not
used, which
is the monthly re-derivation the literature supports.

### Reading table

Per address, the first matching rule wins. The reading carries every
evidence row that matched, each with its kind, value, the raw row it
points to, and `first_ts`/`last_ts`. Wording is about what was observed and
who observed it.

The table of rules 1 to 8, with what each reading shows, is in
[Detection](detection.md#shared-addresses); the sentences are in the code
(`src/store/evidence.rs`, `sharing_view`). In short: rule 1 strips hosting,
scanner, fleet and Tor addresses; rules 2 and 3 are a consumer router
answering (with and without a pooled name); rules 4, 5 and 6 are a
carrier-NAT, mobile and pooled-line name; 7 another consumer name; 8 the
default, insufficient evidence.

Rule order is the forgery argument. Rule 1 removes every address a renter
controls the PTR of, so a planted `cgn` name on rented space reads nothing
(the data pass found none, and the hosting list is the gate). Rules 2 and
3 sit before the carrier-pool rules because a CPE answering is the one
observation that contradicts a carrier pool, cannot be planted to the
operator's benefit, and is the only behavioural evidence on this axis; it
overrides a stale or wrong `cgn` or `mobile` name. It contradicts nothing
about reassignment: a FRITZ!Box on a `dynamic-….pool.telefonica.de` line
is one subscriber's network *and* a reassigned line, both at once, and a
block on it still hits the next holder. That is why rule 2 exists: when a
CPE answers and the operator names the line pooled, the reading keeps the
pooled claim instead of dropping it. Rules 4 to 6 are the operator
speaking, in the order of the strength of what the name claims. Nothing
adds up: an address with a `cgn` name *and* a `pool` name reads rule 4
with both rows shown, not a higher level, and rule 2 reads two rows
because both are true at once, not because two rows are worth more than
one. Rule 8 is the default, and absence of any row never moves an address
off it.

What each signal may do is the whole weight table, and it is bounded by
the evasion read: signals 1, 2, 3, 6, 8, 9, 10 appear in no rule; 7 and 11
only reach rules 1 to 3, the readings that lower a carrier-pool claim, and
neither can remove a pooled-line claim; 4 reaches rules 4 to 7 only past
the rule-1 gate, and rule 2 only alongside a CPE row; 5 reaches rule 5
only through `net.eyeball`, which stays inert. Changing a weight means
reordering or adding a rule in this table and bumping `EVIDENCE_V`, which
recomputes every node's rows and readings.

### The transparency constraints, one by one

- **Every point traces to a named observation with a timestamp and a link.**
  A reading is a function over `ip_evidence` rows and shows each row with
  `kind`, `value`, `first_ts`, `last_ts` and a link to `ip_names.id` or
  `scans.id`. Nothing in the reading comes from anything the page cannot
  show, because there is no other input.
- **Rules and weights published and versioned.** This table, the
  `names.toml` entries and `EVIDENCE_V`. The reading carries `v`. There is
  no tuning outside the catalogue and no learned component.
- **Never a bare number.** The reading is one of eight named states with
  its sentences. The API (`/api/v1`, if it ever exposes it) returns the
  state name, the rule number as `rule`, and the rows, never an integer
  score; the states carry no numerals in their names so that none is read
  as one.
- **An explicit "insufficient evidence".** Rule 8, the default. Absence of
  a name, of a scan result or of a `net.*` row is not evidence, and the
  text says so where it is shown.
- **Recomputable and withdrawable.** Rows are derived state the recompute
  pass replaces; the reading is computed from them at render time and is
  never stored. A catalogue change or `EVIDENCE_V` bump withdraws every
  reading on every node at the next pass; nothing signed, nothing
  replicated, nothing to recall.
- **Direction stated.** Fixed text beside every reading above rule 1:
  "This reading says how many parties may share this address. It is not a
  threat or suspicion score. A shared pool means a block on this address
  hits other people; it does not change what the address sent." The
  blocklist and severity are untouched (next section).
- **Rules needing the mobile list ship inert.** Rule 5's `net.eyeball`
  branch is in the table and in the code and fires on no address until a
  source sets `net.eyeball`, as MIK-585 and MIK-587 shipped rules 3 to 5 of
  the device verdict.

### Does a true (b) soften a verdict?

The evasion read leaves this call here: a bought carrier exit makes (b)
true, the address really is shared, and blocking it really does hit other
subscribers. The decision is **no automatic softening**: neither severity
nor blocklist membership changes on any reading. Three reasons. The
blocklist is driven by what the address sent, and the requests were sent
whoever else shares the exit. A softening would be the proxy plan paying
for itself: the price of the gentler label is pennies per node plus a
monthly minimum, and the operator who bought the exit is exactly the party
behind the address. And the reading's rows are either the operator's
naming or a scan, both of which rule 1 already strips off rented space but
neither of which we can verify on carrier space. What a true (b) changes is
the *cost* of blocking, not the evidence of abuse, so the reading is shown
as a cost caveat wherever a block or a blocklist entry is shown, and the
one place it may act is additive-safe: the blocklist's `networks=1` option,
which collapses a busy /24 into a prefix and thereby lists addresses that
sent nothing. A /24 holding a rule-2, 4, 5 or 6 reading, the four readings
that say the address is, or sits on, a pool, should not be collapsed. That removes no observed address from the list and stops the
hazard the compromised assessment flagged (an eyeball /24 collapsed into a
prefix blocks many households). It is a follow-up with its own check, not
part of the slice below.

## Shared dataset, exports and blocklist, or local only

The compromised assessment kept its verdicts local because a replicated
"consumer device" row is a statement about a third party's equipment,
forgeable by the party with the most to gain, signed by one member and
copied into every other member's dataset. This axis differs on each
point, and the recommendation differs with it.

- The claim is about the network's address plan, not about a person's
  conduct or equipment. "This address is a carrier pool, by the carrier's
  own naming" is not defamatory and is the kind of fact RIR databases and
  the carriers themselves publish.
- The direction of forgery is protective, and the forgery is purchase. On
  rented space a planted name is gated off by `net.hosting`. On carrier
  space the only way to get the reading is to use the carrier, at which
  point the reading is true. The operator gains a caveat the address
  deserves anyway, and nothing is unblocked by it.
- The cost of omission is the larger one. An export consumer or a blocklist
  consumer who cannot see that an entry is a pool blocks thousands of
  households for one scanner's hour; 75 % of mobile associations are gone
  within a day, so the entry is also stale almost at once.

**Recommendation.** Keep the per-address rows node-local and unsigned, as
every derived row is, and let the inputs do the sharing: `ip_names`, `ips`
and `scans` already replicate, so every node derives the same reading from
the same raw rows with the same bundled catalogue, which is the contract
campaigns and device evidence have. Then surface the reading at the two
boundaries where the collateral is paid, computed by the publishing node
at publish time, never replicated as a claim:

1. **Export:** one derived column, `shared` (the reading's state name,
   rule number and `v`), set by rules 2, 4, 5 and 6 only, the four readings
   that say the address is, or sits on, a pool; null for rules 1, 3, 7 and
   8, which say nothing about sharing or argue against it. Recomputable by
   the consumer from the `names` column, so it adds no authority, only
   convenience.
2. **Blocklist feed:** one additive per-entry field with the same content,
   and the `networks=1` skip above. Membership never changes.

The MIK-575 contrast, stated plainly: there the thing shared would have
been a suspicion about a third party resting on a forgeable banner; here
it is the operator's own naming of its address plan, stripped of rented
space, carrying a cost caveat. Head decides; if the decision is local
only, the build recommendation below changes.

## How we would know we are right

- **(a)** The counter-scan is its own check: an engineer reads the 36 CPE
  and 5 multi-stack addresses by hand once, and a lab line (one household
  router forwarding two ports to a Linux and a Windows box) must produce
  the rows. Medium confidence per address; the population is small and
  the hard part is suppression, which costs nothing and only hides.
- **(b)** Ground truth that exists: carrier statements (RIR and operator
  mailing-list posts, the manual validation Richter used), RIPE Atlas
  probes whose first hop is in 100.64/10 or RFC 1918 and whose public
  address is known (the Cloudflare label method; Atlas data is public and
  these are not our sources, so looking is within the constraint), the
  CAIDA /24 list from Livadariu (2015, stale) and whatever Giotsas et al.
  publish with their paper. All of it validates the *prefix* label the
  carrier's naming already gives, never a per-address, per-time claim.
  Our own canaries are the one per-address check (a canary served to one
  address returning from another inside the same /24 within an hour is
  pool rotation seen directly), and they have shown it zero times in 11
  days. **So (b) cannot be validated here beyond the face plausibility of
  the carrier's own naming**, and that limits how loudly the reading may
  speak: rule 4 says "by the operator's naming" and "not verified by
  behaviour" in its own sentence, and the reading never says "detected".
  Face plausibility is at least consistent: all three named candidates
  answered nothing on the counter-scan, as a carrier gateway would.
- **(c)** The only ground truth is a carrier list, and none can be shipped;
  the cached reference label is a prior with an 11 %-in-one-/21 error
  class. Validation on 15 sources is meaningless. The reading therefore
  names the source of the claim (the PTR, or later the list) in its own
  sentence and claims nothing more.
- **(d)** Our own history is the ground truth, and it needs months, not
  days: watch addresses with a rule-2 or rule-6 reading for a change of identity
  class across days (a canary or JA4-plus-UA hop within one /24 or one
  ISP, or an address whose scan results change vendor between weeks). That
  is a measurement to run on the cluster before anyone claims the
  literature's timescales apply to our sources; the reading quotes the
  timescales as the literature's, not ours.

## Recommendation

*Built as recommended, after Head took the shared-surface recommendation
with conditions (MIK-645): steps 1 and 2 in MIK-647, steps 3 and 4 in
MIK-646. One difference from step 3: the export value also carries
`source` and the `name` the claim rests on, and is set only where that
name is one the export's `names` column lists, so that every value can be
checked from the export itself; the blocklist line leaves the name out,
since a PTR name is the operator's text and a feed line is read by
firewall scripts.*

**Build the narrow slice only if Head takes the shared-surface
recommendation; if the reading stays local only, do not build it.** Local
only, the slice puts about 60 sentences on the admin IP pages of one node
(3 carrier-named pools, 18 to 20 pooled lines, 36 one-subscriber
networks, on 6,328 sources) for the honest answer this document already
gives. Its value is the caveat at the export and blocklist boundaries,
where someone else pays for a block on a pool, and the `networks=1` skip,
which is the only automated use that is safe by construction.

The slice, in order, each step with its check:

1. **Catalogue.** `rules/evidence/names.toml` gains `[[cgn]]`, `[[mobile]]`
   and a `[[pool]]` class (moving `dynamic` and `pool` out of `consumer`,
   adding `ppp`), token-boundary patterns, one sample each; `KINDS` and the
   0047 comment list the three kinds; `EVIDENCE_V` bumps. Check: the
   catalogue test matches every sample and none of the rented-fleet names;
   on a node with migration 0047, `peephole store recompute-campaigns`
   reports `name.cgn` on 3 addresses, `name.pool` on 18 to 20 and
   `name.mobile` on 2 of the hermes data, and `expresspools.us` on none.
   Half a day.
2. **Reading.** A function over an address's rows implementing rules 1 to
   8, with the sentences of the reading table and the fixed direction text; shown on the
   admin IP page under the device verdict, with each row linked to its
   name or scan; `/ips?reading=<state>` as a list filter. Check: the three
   `cgn` candidates read rule 4, the Vodacom address reads rule 4 and
   shows both its `cgn`-class and `mobile` rows, the FRITZ!Box address
   (`dynamic-….pool.telefonica.de`, a CPE answering) reads rule 2, *one
   subscriber's network, on a pooled line*, showing both its scan row and
   its `name.pool` row, every `net.hosting` address reads rule 1, and an
   address with no rows reads rule 8 with the insufficient-evidence
   sentence. One day.
3. **Boundaries (if Head says yes).** The export column and the blocklist
   field, computed at publish time from the publishing node's rows; the
   `networks=1` skip for /24s holding a rule-2, 4, 5 or 6 reading. Check:
   an export of the hermes data has `shared` null on every hosting row and
   on every rule-3, 7 and 8 row, and set on the 22 to 24 rows that carry a
   `cgn`, `mobile` or `pool` name (3 + 18–20 + 2, less the one Vodacom
   address that has both a `cgn` and a `mobile` name, less any address the
   step-1 recompute shows named both `cgn` and `pool`; the step-1 count is
   the exact figure, and the FRITZ!Box address counts once, under rule 2);
   the blocklist feed with `networks=1` lists the Telkom SA `dsl` /24s as
   single addresses, not prefixes. Half a day to
   one day; `docs/dataset.md` and the feed documentation gain the field.
4. **Docs.** The shipped part moves into `detection.md`; this file keeps
   the reasoning.

Rough cost: two to three engineer-days, no migration (the kinds are free
text in `ip_evidence` and the catalogue is a bundled file), no protocol
change (nothing new replicates; the export and feed fields are additive
and derived at publish time), no new setting. Storage: a few dozen rows
on a node of this size.

Not in the slice, each with its reason:

- `scan.multistack` (signal 10): 5 eyeball hits in 11 days, and a clean
  version needs `reason_ttl` stored per port at scan ingest (one additive
  column on `ports`) rather than decompressing 9,466 XML blobs in the
  hourly pass on a two-core host. Add when the column is wanted for
  something else.
- Source-port capture (signal 3): a column plus a protocol addition to see
  a signal that is free to fake, invisible on 85 % of rows, and would have
  17 fixed-line sources with enough connections to analyse. Not for this
  axis. If the SYN is ever captured for JA4T, the port rides along at no
  cost.
- IP-ID and TCP-timestamp counting (signal 9): closed above.
- A mobile list or our own prefix labels (signal 5): nothing qualifies
  today (MIK-599). What would have to change for rule 5's inert branch to
  fire: a licensable list the operator supplies per node under `data_dir`
  on their own licence (never bundled, loaded like the X4BNet fetch), or
  our own prefix labels derived from the cluster's replicated names, "N or
  more addresses in this /24 named `cgn` or `pool` by the operator", re-derived
  monthly as the literature's stability figures support. The second is
  the honest own-data path, carries the same ceiling as the names it is
  made from, and is worth a ticket once the cluster's name coverage on
  eyeball /24s is known.

What this buys the owner, in the owner's words: not a confident detector
of shared, mobile or CGNAT addresses, which the data, the evasion read and
the literature agree does not exist from a receiver's view of a honeypot;
but an honest reading that says, per address and with the operator's own
words and timestamps, "a pool, by the ISP's naming", "a line that is
reassigned", "one subscriber's router", or "insufficient evidence", shown
where a block would cost someone else, and never a number.
