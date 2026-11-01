# Detection

What happens to a request once it reaches the trap: it is classified against rules built into the binary, its source address is
enriched from public and optional commercial sources, and a source that did
enough gets counter-scanned, held in the tarpit, or fed canary credentials
that give it away when it comes back.

## Classification

The trap records every request that reaches no real site: headers and body,
the raw request head as received, how it was answered and, over HTTPS, the
raw TLS ClientHello and its JA4 fingerprint. Floods are sampled, but every
request still leaves at least a light row (time, method, path) or a count;
see [Rows](dataset.md#rows).

Each request is matched against the signature rules. Every rule has a
weight, a label and an `owasp` tag. The weight (1–4) is the request's
severity (0 when nothing matched) and drives the counter-scan level:

| Weight | Meaning | Labels |
|---|---|---|
| 1 | single weak tell | `probe` (behavioural floor), `php-probe`, `ai-agent-tooling` |
| 2 | automated reconnaissance | `ai-agent-artifact`, `scanner-ua`, `research-scanner`, `sensitive-path`, `path-scanner`, `ai-infra-probe`, `api-recon`, `proxy-probe`, `unusual-method`, `automation` |
| 3 | exploit-adjacent | `form-interaction`, `write-method`, `xss`, `crlf-injection`, `webshell-probe`, `app-probe`, `cloud-infra-probe`, `credential-attack`, `mcp-probe`, `graphql-introspection`, `appliance-probe`, `iot-probe`, `inhuman-behavior` |
| 4 | unambiguous exploit / post-exploitation | `sqli`, `rce`, `path-traversal`, `ssrf`, `ssti`, `nosqli`, `xxe`, `deserialization`, `webshell`, `mcp-abuse` |

The counter-scan level is the weight, with one cap: a request whose labels
only say someone looked (`probe`, `path-scanner`, `php-probe`) or who
looked (`ai-agent-artifact`, `ai-agent-tooling`) earns at most a level-1
scan, whatever its severity — a lone drive-by probe does
not warrant a top-1000-port scan. Anything more specific scans at the
weight, capped at 4. `severity` itself is not capped: it records what was
seen.

The `owasp` tag is a Top-10 2021 class (`A03:2021`) for payload families or
an Automated Threat (`OAT-014`) for scanning behaviour. Tags are stored on
the request row (`owasp_json`), shown as badges next to the labels in the
web UI, and included in exports. A typo'd tag fails the build's tests.
Behavioural labels (`probe`, `path-scanner`, `form-interaction`, …) come
from code, not rule files, and carry no tag.

Label badge colours follow the family: blue = reconnaissance (any
`*-probe` label, plus `scanner-ua`/`research-scanner`/`path-scanner`/
`api-recon`/`graphql-introspection`), green = exposure (`sensitive-path`:
secrets, config, repos, dumps, admin and debug pages), red = injection,
violet = execution/impact, orange = interaction, solid = post-exploitation,
grey = automation tells (including `proxy-probe` and the `ai-agent-*`
labels), neutral accent =
everything else. New labels need no UI work: a `something-probe` label is
blue automatically, everything unknown is neutral.

The public dashboard's "What they were after" counts each request once per
family it touched. `path-scanner` and `php-probe` say how a request came,
not what it was after, so they count (as reconnaissance) only when no other
label names a family; "other" likewise only when nothing else applies.

`ai-agent-artifact` and `ai-agent-tooling` say who sent a request: an LLM
agent. The first is the model's own output inside the request (chat-template
tokens such as `<|im_start|>` or `[INST]`, tool-call tags and JSON, refusal
or self-description text) in the target, the body or a header; the second
is its tooling (SDK and agent-framework User-Agents, the OpenAI and
Anthropic SDK headers, an MCP `initialize` whose `clientInfo` names a known
agent client). Like the weak tells they count (as automation) only when no
other label names a family, keep the level-1 scan cap, and do not suppress
the `probe` floor: an agent request that did nothing else reads `probe`
plus the agent label, and counts as hitting no rule. AI crawlers (GPTBot,
ClaudeBot, …) are not agents here; they belong to the verified crawlers.

## Rules

The rules live in [`rules/`](../rules/), one TOML file per family: sixteen
families, from `sqli`, `rce` and path traversal to SSRF, webshells,
deserialization and AI-infrastructure probes. They are built into the
binary, so there is nothing to install or edit on a node, and every node of
one build classifies alike. Changing a rule means changing `rules/*.toml`
and building; CI checks that every rule loads.

Every classified request stores the fingerprint of the rules that
classified it (`rules`, a SHA-256 over the rules files) and the build that
recorded it. `peephole check-config` and the startup log show the number of
rules and the start of their fingerprint. In a cluster, nodes check each
other's classification by classifying again; see
[Things to know](protocol.md#things-to-know).

A rule fires when any of its matchers matches (`target_regex`,
`body_regex`, `ua_regex`, `header_regex`, `path_exact`, optionally limited
to `methods`). `unless_target_regex` is a veto, not a matcher: when it
matches the target (raw or decoded) the rule does not fire, whatever else
matched. `ai-agent-artifact` uses it to stay off the LLM chat and
completion endpoints, where a chat-template token is a prompt aimed at the
decoy rather than an agent's trace. A rule needs at least one matcher; a
veto alone does not count.

Weight rationale when adding rules: would you counter-scan a source that
did *only* this? Recon gets 2, anything that touches an exploit gets 4
only when the payload itself is unambiguous.

## Enrichment

Each source address is looked up, each source within its own rate budget,
and looked up again when the address returns:

- **MaxMind GeoLite2**: country and ASN. A node with MaxMind credentials
  downloads the databases for itself; they are never passed on. That node
  looks up the addresses the other nodes recorded and shares the results,
  so one member with credentials is enough; without any, the dataset has no
  GeoIP data.
- **Tor**: the bulk exit list (IPv4 exits measured by TorDNSEL) and the
  Onionoo relay index (every running relay: its IPv4 and IPv6 addresses,
  roles, nickname and fingerprint). Both are public and fetched by one node
  for all. The IP page says whether an address is an exit or a guard or
  middle relay, and an admin sees which relay it is.
- **RDAP**: registration data from the registries (network, holder, abuse
  contact).
- **Reverse DNS**: forward-confirmed PTR names.
- **AbuseIPDB, Shodan and Shodan InternetDB**, optional. Every node with a
  key announces it. One of them looks each address up, newest first, within
  its own daily or weekly budget, and the result, with its UTC time, is
  shared with every member. A node whose budget is spent, or whose key is
  rejected, stops announcing the provider, and another node with a key
  takes over.

An address is looked up again only when it comes back, after 30 days, then
45, 67.5, … (`[enrichment] refresh_after_days`). Every result records which
provider and which node it came from, and every lookup is kept in a history
(Admin → System → Export → full lookup history). The results of AbuseIPDB, Shodan
and Shodan InternetDB are admin-only: the IP page shows them, and the IP list filters by
abuse score, provider tag and "looked up / not yet".

An admin can also look any address up on demand, through every provider
the cluster can reach. In a cluster those lookups are paid in credits; see
[Credits](overview.md#credits).

## Counter-scans

A node with the scanner role answers reconnaissance with an nmap scan of
the source. The scanner role is opt-in: counter-scans draw abuse reports,
and most hosting providers forbid them (see [Risks](overview.md#risks)).

The automatic levels (1–4) escalate by scope, never by speed or
aggressiveness; every built-in level runs `-T3` (an operator can override a
level's arguments with `[scan.level_argv]`). Level 5 is deliberately
intrusive and only ever bought:

| Level | Scans |
|---|---|
| 1 | the top 100 TCP ports and the device and proxy ports below, with light service detection (`-sV --version-light`) |
| 2 | the top 1000 TCP ports and the device and proxy ports below, service and OS detection (`-O`), and the source's own identifiers: SSH host keys and algorithm lists, TLS certificates, HTTP headers with their ETag |
| 3 | as level 2, plus traceroute and nmap's safe discovery scripts (never those that are intrusive, broadcast, ask third parties or flood) |
| 4 | as level 3 on every TCP port (with `scan.level4_udp`, also the top 50 UDP ports) |
| 5 | the top 1000 ports with nmap's `vuln` scripts, minus those that ask third parties; only bought, never queued automatically |

From level 2 the scan reads the source's SSH host keys, TLS certificates and
HTTP ETags, so sources that share one show up as linked (Admin → Evidence → Links).

The top lists are nmap 7.95's (`--top-ports 100` and `1000`), written out
as port lists, because nmap's `-p` can only narrow a top list. Levels 1 to
3 add the ports where proxies and consumer devices answer and nmap's lists
do not reach: 1080 (SOCKS), 4145 (SOCKS4), 8118 (Privoxy) and 9050 (Tor
SOCKS); 7547 (TR-069), 8291 (MikroTik WinBox), 8089 (FRITZ!Box TR-069),
5555 (Android ADB) and 37777 (Dahua). Level 1 gains nine ports, levels 2
and 3 four. The level lists of 0.20.0 and earlier still earn.

### Device evidence

For an admin, the IP page says what a counter-scan saw answering on the
address, if anything. The page never gives a score, and it never says
whose box answered. The page draws on typed evidence rows. Each row points
at the row that produced it:

| Row | When |
|---|---|
| `device.proxy` | an open port with 3Proxy or SOCKS software, or nmap's service `socks4`, `socks5` or `http-proxy`, or a `socks.method` scan fact |
| `device.cpe` | an open port, or the scan's OS guess, matching a consumer-device signature: TR-069, MikroTik, FRITZ!Box, HikVision, Dahua, OpenWrt/LuCI, Android ADB |
| `fleet.key` | an SSH host key, TLS certificate or HTTP ETag shared with 2 to 50 other addresses |
| `fleet.canary` | a canary served to another address came back from this one in a header or the request body (never the path or query, which a link can plant on anyone) |
| `fleet.dense` | 16 or more sources in the address's /24 (IPv4) or /48 (IPv6) |
| `name.consumer`, `name.scanner` | the reverse or PTR name matches a consumer-line or a scanner pattern |
| `name.pool`, `name.cgn`, `name.mobile` | the reverse or PTR name matches a pooled-line (`dynamic`, `pool`, `ppp`), carrier-NAT (`cgn`, `cgnat`, `lsn`, `nat` as a label) or mobile (`umts`, `lte`, `gprs`, `3g`/`4g`/`5g`, `mobil`, `mob`, `wap`) pattern; read by the [shared reading](#shared-addresses), not the verdict |
| `net.hosting` | the ASN is in the X4BNet datacenter ASN list or in our supplement (see [AS type](#as-type)) |
| `net.eyeball` | never set: no bundled source classifies consumer ISPs |

The signatures and name patterns are built into the binary
(`rules/evidence/`). Each has a sample it must match. No consumer-device
signature or consumer-name pattern may match the banners or names of the
20 largest rented fleets seen on a node. Two nmap OS guesses are left out
for that reason: "Android TV OS 11" and "3Com OfficeConnect wireless
broadband router" turn up on rented hosting addresses.

A scan more than 24 hours older than the address's last request is not
used: on a dynamic line the address may have passed to the next
subscriber. A name is used for 30 days: a pool or carrier-NAT name is a
property of the operator's address plan, not of the subscriber, and holds
for weeks to months.

The verdict is the first rule that matches:

| # | When | Shown |
|---|---|---|
| 1 | a Tor exit | nothing new (the existing badge) |
| 2 | `fleet.key` or `fleet.canary`; or `fleet.dense` or `name.scanner` with `net.hosting` | rented fleet: "one of N addresses sharing SSH host key …" |
| 3 | `net.hosting` | rented: "hosting AS" |
| 4 | `device.cpe` with `net.eyeball`, no scanner name | consumer device answered: "… answered on 7547 in scan #…; the line is in a consumer ISP AS" |
| 5 | `device.proxy` with `net.eyeball` | proxy software on a consumer line |
| 6 | `device.cpe` or `device.proxy`, and no `net.*` row | device evidence only: "TP-LINK TR-069 remote access answered on 7547 in scan #12 (level 4, 2026-10-18); AS type not classified" |
| 7 | anything else | nothing |

Rule 7 shows nothing. An address without evidence is not cleared of
anything; the scan just saw nothing to name. A device verdict
also carries the caveat that what answered is the box on the address at
scan time, not necessarily the sender. Each row on the page carries the
device or proxy, the port, the scan with a link to it, and the date.
`/ips?evidence=device.cpe` (or any other row kind) lists the addresses
with such a row.

#### AS type

`net.hosting` comes from the datacenter ASN list of X4BNet `lists_vpn`
(`input/datacenter/ASN.txt`, MIT licence, notice in
`rules/evidence/x4bnet/LICENSE` and [NOTICE](../NOTICE)).
A snapshot is built into the binary unmodified. Each node fetches the list
from GitHub at startup and then daily, with the Tor exit list's cadence
and backoff, into `<data_dir>/x4b-datacenter-asn.txt`. A fetched copy
replaces the snapshot. A failed fetch, or a fetched file that does not
parse or has fewer than 300 ASNs, keeps the list already loaded. The
system page shows the last fetch next to the Tor exit list's, or the
snapshot's date when there was none.

A small supplement, `rules/evidence/as-supplement.toml`, holds scanner
ASNs the list misses and our own data shows (3xK, Censys, Driftnet). Each
entry must carry the evidence for it (`reason`) and the day it was added
(`added`), and may only say hosting, cloud or scanner. A test fails past
20 entries: beyond that we would be keeping an AS-type feed by hand. An
entry the loaded list covers is dropped on load and logged, so the
supplement shrinks as the list catches up. On the IP page a row from the
supplement is attributed to "our own classification", a row from the list
to the X4BNet list.

Nothing sets `net.eyeball`: no redistributable source classifies consumer
ISPs, and an ASN missing from the hosting list is not thereby one. So
rules 4 and 5 do not fire, and a device in an unlisted AS stays rule 6,
"AS type not classified". `peephole store recompute-campaigns` reports the
ASNs loaded per source.

The rows are derived on each node with the hourly campaign pass. They are
never replicated, never exported and never in the blocklist: a dynamic
address can be personal data, and a device banner is cheap to fake for
whoever wants an address to look like a victim. A forged banner earns at
most a sentence on the admin page of the node it was shown to. (The one
reading that leaves the node is the [shared field](#shared-addresses),
never a row.)
`peephole store recompute-campaigns` recomputes them too. It prints the
rows by kind, the verdicts by rule, and the device types and OS guesses
no signature matched, so the catalogue can grow from data.

#### Shared addresses

A second reading over the same rows says how many parties may share an
address: a carrier-NAT pool, a mobile pool, a line that is reassigned, one
subscriber's router. It is not a threat or suspicion score and never a
number; it changes no severity and no blocklist membership. The reasoning
behind it, signal by signal, is in
[Shared addresses](shared-addresses.md). The first rule that matches wins:

| # | When | Reading |
|---|---|---|
| 1 | `net.hosting`, `name.scanner`, `fleet.key`, `fleet.canary`, or a Tor exit | one operator's address |
| 2 | `device.cpe` and `name.pool` | one subscriber's network, on a pooled line |
| 3 | `device.cpe` | one subscriber's network |
| 4 | `name.cgn` | shared pool, by the operator's naming |
| 5 | `name.mobile`, or `net.eyeball` = `mobile` (never set) | shared pool, mobile |
| 6 | `name.pool` | pooled line |
| 7 | `name.consumer` | consumer line, sharing not read |
| 8 | anything else | insufficient evidence |

Rule 1 comes first so that a name planted on rented space reads nothing.
A consumer router answering (rules 2 and 3) is the one observation that
contradicts a carrier pool, so it overrides a `cgn` or mobile name; it
says nothing against reassignment, which is why rule 2 keeps the pooled
line. Nothing adds up: an address with a `cgn` and a `pool` name reads
rule 4 with both rows shown. Rule 8 is the default, and an address
without a name or a scan is not thereby single-user, nor shared.

The admin IP page shows the reading under the device verdict, with each
row linked to its name or scan and the sentence of what was observed and
who says so; rule 1 shows nothing. Every reading above rule 1 carries the
text: "This reading says how many parties may share this address. It is
not a threat or suspicion score. A shared pool means a block on this
address hits other people; it does not change what the address sent."
`/ips?reading=<state>` lists the addresses of one reading.

**At the boundaries.** Rules 2, 4, 5 and 6, the readings that say the
address is or sits on a pool, also go out with the data, computed by the
publishing node at publish time from its own rows, never stored and never
replicated:

- the export's `shared` column (see [the dataset](dataset.md#shared));
- the blocklist feed: a `#` comment line just before the entry, such as
  `# shared 192.0.2.1 rule=4 v=3: shared pool, by the operator's naming;
  not verified by behaviour`, and with `networks=1` a /24 (IPv6: /64)
  holding such an address anywhere is never collapsed into a prefix; its
  addresses are listed one by one. Entry lines and membership do not
  change.

Each value names who makes the claim: the operator's naming, plus a scan
for rule 2. A value is set only on an agreed name the export lists, so a
rule-5 reading from a mobile `net.eyeball` row alone stays on the IP page
and goes out with neither. None says "detected": a carrier-NAT name is the carrier's own
statement about its address plan, and nothing a honeypot receives can
verify it. The reading is a cost warning about blocking, not a verdict:
an address in a mobile pool usually holds a subscriber for a day or less,
so by the time a block lands the address may belong to someone else.

**Bystanders are spared.**

- One request earns at most a light scan.
- Verified crawlers and research scanners, Tor exits, the node's own
  addresses and `never_scan` networks are never scanned; neither are the
  addresses of cluster members. `never_scan` applies on the node that sets
  it only: other members' scanners may still scan those addresses.
- Per-network, per-ASN and queue budgets stop floods.

**What "Tor exits are never scanned" covers.** An address counts as an exit
when it is on the bulk exit list, is an exit address Onionoo observed, or is
an ORPort address of a relay that has the `Exit` flag or an IPv4 or IPv6
exit policy other than `reject *:*`. That last rule is how IPv6 exits are
recognised. It is a heuristic: a relay can exit from another IPv6 address
than its ORPort, which neither source lists, and the rule fails toward
"exit" (every address of such a relay is refused, IPv4 and IPv6). Guard and
middle relays are not refused: they never carry Tor users' traffic to the
internet, so what comes from them comes from the host. Bridges are not
public, so a bridge address is not known as Tor at all. A relay index that
is too small, has no publish time, or is older than 72 hours is not used.
The bulk list then decides alone, as before, and without either the Tor
status is unknown (`scan.tor_unknown`).

**On request**, an admin can also:

- run an *observational probe* of the ports a scan found open (headers,
  certificates, JARM, SSH host keys), from one scanner or several at once;
- buy a full counter-scan of level 1–4 from the cluster's cheapest scanner,
  each level four times the price of the one below, or a level-5 scan.

How to use both is in [Day to day](operations.md#day-to-day). What they cost
is in [Credits](protocol.md#credits).

### Tarpit

For an hour after a source's request reaches severity 4, its requests get a
slow-drip `200` that holds them up to 10 minutes, from a bounded pool of its
own; the time held is recorded (`held_ms`). Bystander and `never_scan`
networks are never held. The settings are in
[Tarpit and decoy streams](operations.md#tarpit-and-decoy-streams).

### Canaries

Decoys for the probes scanners send first (`.env`, `.git/config`,
wp-login, phpinfo) serve realistic credentials derived from the request,
with links back to the trap. When a harvested credential comes back, from
any address to any node, the admin names the request that harvested it and
the time in between. How the values are derived is in
[Canaries](dataset.md#canaries).

### AI decoys: one identity per node

The MCP server (`/mcp`, `/messages`, `/sse`) and the LLM gateway (Ollama,
OpenAI, Anthropic and Azure paths) answer with an identity of their own on
each node, so one fingerprint does not name every cluster member. It is
drawn from the node key, stays the same for as long as the key does, and
never varies per source address. Per node, the MCP server has its own
name and version, lists the five tools (read a file, list a directory,
run a command, query the database, fetch a URL) under its own names, adds
0-2 canned extra tools, and lists 2 of 4 file resources; the gateway
lists 3-4 of 10 local models, its own Ollama version, and 4-6 of the 6
upstream models. A model the node does not list answers "not found" and
counts as unlisted in the admin's LLM tallies. A tool call is classed and
stored under the tool's canonical name (`read_file`, `list_directory`,
`run_command`, `query_db`, `fetch_url`), whichever name it was sent with;
the canonical names are answered on every node. The derivation is in
[Canaries](dataset.md#canaries) (version 5).

The persona a request is answered under (see Operations, "What your node
presents as") biases that identity and nothing else of the decoys: the
MCP server takes its name from a pool that fits the product (`ml-ops`,
`gpu-tools` for `gpu-box`; `mail-ops`, `exch-admin` for `exchange-owa`),
and a `gpu-box` gateway lists 7-9 local models, 2-3 of them 27B-70B ones.
Tool names, extra tools, resources and upstream models stay the node's.

## Campaigns: what ties two addresses

The hourly campaign pass (`store::campaigns`) joins two addresses only on
evidence of one operator:

- **Hard edges**, one shared value: a browser fingerprint, an SSH host
  key, a TLS certificate, or a canary served to one address and used by
  the other. A value on more than 50 addresses is a shared image or a
  default and ties nothing.
- **Soft edges**, path similarity: the two asked for the same rare path
  shapes (weighted Jaccard of 0.60 or more, at least 3 shapes on at most
  50 addresses each, active within 30 days of each other). A shared JA4
  and JA4H pair, or the shapes asked for in the same order, lowers the
  score needed to 0.45. JA4 and JA4H never tie two addresses on their own.

User agent, JA4 alone, JA4H alone, HASSH, JA4X, JARM, favicon and the
HTTP body, 404 and ETag hashes do not feed campaigns: they identify the
software or the product, which many unrelated operators share, not the
operator. They stay pivots on the Links page.

The Links page also lists what the body X-ray finds, read from this node's
own sightings and not replicated: stagers (only those a command fetches from,
not addresses it merely queries), SSH key fingerprints and uploaded files (by
SHA-256) as identity kinds, and shell recipes and exploit tags as software
kinds. They do not feed campaigns yet. Values from payloads are shown and
copied defanged and are never links. A stager's page lists its URLs, each
with a "Copy for sandbox" button that puts the raw URL on the clipboard for
an external sandbox; the node never fetches it.

An attack chain is a group of stagers, SSH keys and uploaded files that
appear together in sources from at least two addresses, with what those
sources describe. The strip reads it in five stages, built from sightings on
this node:

| Stage | Holds |
|---|---|
| Exploit | Exploit shapes, grouped by attacker's tag up to its first dot, so `x` and `x.selfrep` are one row listing both paths. An exploit with no tag has its own row. |
| Command | Shell recipes and webshell profiles. |
| Delivery | Stagers, SSH keys and uploaded files. A URL a command only queried never appears. |
| Payload | Uploaded text, held here and text by its first bytes, as seen. Otherwise a gap: the node never fetches a stager. |
| Follow-up | What was sent to an uploaded file, tied through the file and never through the address, read through the X-ray: the command that reached the shell's own input when its profile names one, else the recipe. A request holding a private key shows only its recipe, and a request that carried an upload is read without its body. Also dead ends: a 404 for the file's name from the uploader within 60 seconds. With no upload, a gap: the commands never ran here. |

Every row says in words how far it is confirmed, as well as by its border:
solid for seen, dashed for claimed (attacker's text; a tag is a hint, never a
verified CVE), double for external, hatched for a gap, the danger colour for
a dead end. An accent edge marks a joiner, a piece that ties the chain
together. A request or upload with no joiner in a chain gets a chain of its
own pieces, without a key, and links to the chains its address is in. A
source with nothing a strip shows has no strip. A chain reads its newest 64
uploads, the timelines of the newest 8, and the first 32 follow-ups through
the X-ray, and shows 200 pieces, joiners first; what is past a cap is counted.
A page draws at most 5 strips (32 on a campaign's) with a link to the rest.

A campaign's page lists every edge. A soft edge's row opens to the score
and the threshold it met, the order agreement (−1 to 1), the shared
(JA4, JA4H) pairs and the shared shapes with how many addresses asked for
each, the rarest 100 of them, as the pass that made the edge saw them.

## Scanners we do not counter-scan

peephole answers reconnaissance with a counter-scan of the source — except
when the source is verified to be someone who scans the open internet as a
service, not an attacker. Counter-scanning them would hit the operator of a
documented service and buy nothing.

Verification is forward-confirmed reverse DNS (FCrDNS), the same mechanism
Google recommends for Googlebot: the address's PTR record must name a host
under the operator's domain, and that host must resolve back to the
address. A user-agent header alone proves nothing — anyone can send
`CensysInspect/1.1` or `zgrab` — so it is never accepted.

| Operator | Reverse zone | Reference |
|---|---|---|
| Censys | `*.censys-scanner.com` | <https://support.censys.io> (scanner IPs and UA) |
| LeakIX | `*.scan.leakix.org` | <https://leakix.net> (l9scan/l9explore) |
| Shodan | `*.shodan.io` | <https://www.shodan.io> (census hosts) |

Search engines and link-preview fetchers (Google, Bing, Apple, Yandex,
Baidu, Petal, Amazon) are exempt through the same check; their zones are
listed next to these in `src/scan/crawler.rs` (`DOMAINS`).

An operator whose reverse zone lapses becomes scannable again automatically
— verification runs per scan job, not once.

### Are you a scanner operator?

Publish your scanner addresses under a dedicated reverse zone that
forward-confirms, send a PR adding the zone to `DOMAINS` in
`src/scan/crawler.rs` and a row here, and peephole will leave your
addresses alone. Ranges without FCrDNS (a plain IP list) are not accepted:
a list file cannot prove who holds an address tomorrow.

### Seeing who was refused

Admin → Investigate → Scans lists every refused scan job with its reason
(`status=refused`), e.g. `verified crawler (177.186.132.66.censys-scanner.com)`;
the pace card links the last 24 hours' refusals.
