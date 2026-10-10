# Detection

What happens to a request between arriving at the trap and being stored:
it is classified against rules built into the binary, its source address is
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
| 1 | single weak tell | `probe` (behavioural floor), `php-probe` |
| 2 | automated reconnaissance | `scanner-ua`, `research-scanner`, `sensitive-path`, `path-scanner`, `ai-infra-probe`, `api-recon`, `proxy-probe`, `unusual-method`, `automation` |
| 3 | exploit-adjacent | `form-interaction`, `write-method`, `xss`, `crlf-injection`, `webshell-probe`, `app-probe`, `cloud-infra-probe`, `credential-attack`, `mcp-probe`, `graphql-introspection`, `appliance-probe`, `iot-probe`, `inhuman-behavior` |
| 4 | unambiguous exploit / post-exploitation | `sqli`, `rce`, `path-traversal`, `ssrf`, `ssti`, `nosqli`, `xxe`, `deserialization`, `webshell`, `mcp-abuse` |

The counter-scan level is the weight, with one cap: a request whose labels
only say someone looked (`probe`, `path-scanner`, `php-probe`) earns at
most a level-1 scan, whatever its severity — a lone drive-by probe does
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
grey = automation tells (including `proxy-probe`), neutral accent =
everything else. New labels need no UI work: a `something-probe` label is
blue automatically, everything unknown is neutral.

The public dashboard's "What they were after" counts each request once per
family it touched. `path-scanner` and `php-probe` say how a request came,
not what it was after, so they count (as reconnaissance) only when no other
label names a family; "other" likewise only when nothing else applies.

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
- **The Tor exit list**: public, fetched by one node for all.
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
(Admin → Export → full lookup history). The results of the commercial
providers are admin-only: the IP page shows them, and the IP list filters by
abuse score, provider tag and "looked up / not yet".

An admin can also look any address up on demand, through every provider
the cluster can reach. In a cluster those lookups are paid in credits; see
[Credits](overview.md#credits).

## Counter-scans

A node with the scanner role answers reconnaissance with an nmap scan of
the source. The scanner role is opt-in: counter-scans draw abuse reports,
and most hosting providers forbid them (see [Risks](overview.md#risks)).

Levels escalate by scope, never by speed or aggressiveness (every level
runs `-T3`):

| Level | Scans |
|---|---|
| 1 | the top 100 TCP ports, with light service detection (`-sV --version-light`) |
| 2 | the top 1000 TCP ports, service and OS detection (`-O`), and the source's own identifiers: SSH host keys and algorithm lists, TLS certificates, HTTP headers with their ETag |
| 3 | as level 2, plus traceroute and nmap's safe discovery scripts (never those that are intrusive, broadcast, ask third parties or flood) |
| 4 | as level 3 on every TCP port (with `scan.level4_udp`, also the top 50 UDP ports) |
| 5 | the top 1000 ports with nmap's `vuln` scripts, minus those that ask third parties; only bought, never queued automatically |

From level 2 the scan reads the source's SSH host keys, TLS certificates and
HTTP ETags, so sources that share one show up as linked (Admin → Links).

**Bystanders are spared.**

- One request earns at most a light scan.
- Verified crawlers and research scanners, Tor exits, the node's own
  addresses and `never_scan` networks are never scanned; neither are the
  addresses of cluster members.
- Per-network, per-ASN and queue budgets stop floods.

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
[Day to day](operations.md#day-to-day).

### Canaries

Decoys for the probes scanners send first (`.env`, `.git/config`,
wp-login, phpinfo) serve realistic credentials derived from the request,
with links back to the trap. When a harvested credential comes back, from
any address to any node, the admin names the request that harvested it and
the time in between. How the values are derived is in
[Canaries](dataset.md#canaries).

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

Admin → Scans lists every refused scan job with its reason
(`status=refused`), e.g. `verified crawler (177.186.132.66.censys-scanner.com)`;
the pace card links the last 24 hours' refusals.
