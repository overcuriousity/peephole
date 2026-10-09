# The dataset

Every request a trap recorded, with everything peephole knows about it and
its source, as one table. In a cluster every node holds the whole dataset
(or its last `retention_days`), so any operator can export it:

```sh
peephole export -o peephole.parquet                      # everything, typed Parquet
peephole export --format csv --from 2026-09-01 -o sep.csv
peephole export --redistributable --min-severity 2 | zstd > severe.parquet.zst
peephole export --help
```

The same export, with the same filters, is **Admin → Export** on a web node.
Both stream: a file of any size needs little memory. Parquet is the format
for analysis (typed columns, compressed, read by pandas, polars, DuckDB,
Spark and Arrow in every language); CSV and JSON Lines carry the Timesketch
fields for timeline tools.

```python
import polars as pl
df = pl.read_parquet("peephole.parquet")
df.filter(pl.col("severity") >= 3).group_by("ip").len().sort("len", descending=True)
```

```python
import duckdb
duckdb.sql("SELECT country, COUNT(*) FROM 'peephole.parquet' GROUP BY 1 ORDER BY 2 DESC")
```

## Rows

| `kind` | One row per | Columns filled |
|---|---|---|
| `request` | request recorded in full | all |
| `skipped` | request the flood gate answered but recorded only lightly (time, method, path) | `uid`, `node*`, `build`, `ts`, `ip`, `method`, `path`, `unrecorded`, `weight`, the per-IP columns; for a decoy or tarpit answer also `answer` (and `decoy_v`, `host`, or `held_ms`) |

A trap records every request from an address up to a rate; above it, the
request is still answered and classified but kept as a light row, and
beyond a second rate only counted. **Weights make the counts right:**
`weight` is the number of answered requests a row stands for, and the
weights of any export add up to the requests answered in its window. Use
`SUM(weight)` for volumes, `COUNT(*)` for recorded requests.

A filter on `label` or `min_severity` leaves light rows out (they have
neither); a recorded row then also stands for its unrecorded predecessors.

## Columns

Types are the Parquet types. In CSV and JSON Lines every value is text:
lists and objects as JSON, binary columns as base64, times as RFC 3339.
Column order is as listed.

### Provenance

| Column | Type | Meaning |
|---|---|---|
| `kind` | string | `request` or `skipped` (see above) |
| `uid` | string | Stable id of the row across the cluster (light rows: `<batch uid>#<n>`) |
| `node` | string | Name of the node whose trap recorded it (`this node` standalone, or when the name is unknown here) |
| `node_id` | string | That node's public key, hex (empty standalone) |
| `build` | string | Source commit of the peephole build that recorded it (empty for rows older than this column) |
| `ts` | timestamp (ms, UTC) | When the request arrived, by the recording node's clock |

### The request

| Column | Type | Meaning |
|---|---|---|
| `ip` | string | Source address, canonical text (`203.0.113.7`, `2001:db8::1`); IPv4-mapped IPv6 addresses are written as IPv4 |
| `method` | string | HTTP method as sent |
| `path` | string | Request path as sent, not normalised |
| `query` | string? | Query string without `?`, as sent (null when none) |
| `http_version` | string? | `HTTP/1.0`, `HTTP/1.1`, `HTTP/2.0` |
| `host` | string? | `Host` header (HTTP/2: `:authority`) |
| `user_agent` | string? | `User-Agent` header |
| `headers` | list of struct {`name`, `value`} | Every header in order, names as received. Pseudo-headers beginning with `:` are the trap's own observations: `:authority` (HTTP/2), `:version`, `:body-truncated` (the stored body is cut at this many bytes) |
| `body` | binary? | Request body, as received, up to the configured cap |
| `body_size` | int? | Body size as received, before truncation |
| `body_truncated_at` | int? | Bytes kept, when the body was cut |
| `transport` | string? | `http` or `https` |
| `via_proxy` | bool? | The connection came from a trusted reverse proxy (so `ip` is the proxied client, not the proxy) |
| `raw_head` | binary? | The request head exactly as it came off the wire (HTTP/1 only), for parser-level features |
| `tls_client_hello` | binary? | The raw TLS ClientHello (HTTPS only) |
| `ja4` | string? | JA4 fingerprint of that ClientHello |
| `ja4h` | string? | JA4H fingerprint of `raw_head` (HTTP/1 only; null for plain HTTP from a trusted proxy, whose head is the proxy's request, not the client's): method, version, cookie and referer flags, header count, first `Accept-Language`, then hashes of the header names in order and of the sorted cookie names and pairs. An unknown method gives its first two letters |
| `answer` | string? | What the trap sent: `not-found` (a 404), `decoy:<name>` (a believable fake: `decoy:dotenv`, `decoy:git-config`, `decoy:git-head`, `decoy:wp-login`, `decoy:wp-login-failed`, `decoy:phpinfo`; answers to a harvested canary: `decoy:wp-login-ok`, `decoy:wp-admin`, `decoy:admin`, `decoy:git-auth`, `decoy:git-refs`, `decoy:git-pack`), `claim` (the false-positive claim page), `tarpit` (a slow `200` that drips a few bytes at a time, for sources whose requests reached severity 4 in the hour before; see `held_ms`) |
| `decoy_v` | int? | Template version of a decoy answer (see Canaries); empty for other answers, and empty on a decoy row means version 0 |
| `decoy_in` | string? | What an MCP or LLM decoy was rendered from (JSON); empty otherwise |
| `canary_used_from` | list of string | The `uid`s of the rows whose served canaries this row carried (light rows as `<batch uid>#<n>`, `n` the row's position in its batch from 1); empty when none |
| `status` | int? | HTTP status sent |
| `held_ms` | int? | How long a `tarpit` answer held the client, in milliseconds: up to the last chunk the connection took, so a client that gave up counts until then; the configured hold (`trap.tarpit_hold_secs`, default 600 s) when it waited to the end. Null for other answers |
| `unrecorded` | int | Requests from this address answered since the previous row but not recorded (light rows: the drops of the batch, on its last row) |
| `weight` | int | Answered requests this row stands for (see Rows) |

### Classification

These are **rule output, not ground truth**. The trap matches each
request against the TOML signature rules in `rules/`, built into the
recording binary; a model trained on `labels` or `severity` learns those
rules back.
Treat them as weak labels, or re-label from `method`, `path`, `query`,
`headers` and `body`. The `rules` column says which rules classified a row
(`build` says which build recorded it).

| Column | Type | Meaning |
|---|---|---|
| `labels` | list of string | Labels that matched: rule labels (`sqli`, `rce`, `path-traversal`, `ssrf`, `webshell`, `scanner-ua`, `ai-infra-probe`, … one family per file in `rules/`) and behavioural labels from code (`probe`, `path-scanner`, `form-interaction`, …); see the taxonomy in [operations.md](operations.md#classification-taxonomy) |
| `owasp` | list of string | OWASP tags of the matching rules: a Top 10 2021 class (`A03:2021`) for payload families, an Automated Threat (`OAT-014`) for scanning behaviour. Behavioural labels carry none |
| `severity` | int? | 0 (noise) to 4 (exploit attempt); the highest of the matching rules. Null on light rows |
| `scan_level` | int? | Counter-scan level this request earned (0: none, 1 to 4); weak tells alone (`probe`, `path-scanner`, `php-probe`) cap it at 1 whatever the severity |
| `rules` | string? | Fingerprint of the rules that classified it, those built into the recording binary: SHA-256 (hex) over the `rules/*.toml` files, sorted by name, each as its name's and text's 8-byte big-endian length followed by the bytes. Rows with the same value were classified by the same rules, whatever the build; to see the rules, check out a commit whose `rules/` has that fingerprint (`peephole check-config` prints the start of a binary's). Null for claims, light rows and rows recorded before the column existed. It is what the recording node says it used, not a proof |
| `fp_claim` | bool | The address filed a false-positive claim at some point (claim texts and e-mail addresses are never exported) |

### The source address, at the time of the request

| Column | Type | Meaning |
|---|---|---|
| `country` | string? | ISO 3166-1 alpha-2 from GeoLite2: the newest lookup at or before `ts`, or the earliest one when none precedes it |
| `asn` | int? | Autonomous system number, same rule |
| `asn_org` | string? | AS organisation, same rule |
| `is_tor` | bool? | Listed as a Tor exit, same rule (the exit list is IPv4-only); null when never checked |

### Everything else known about the address

Four JSON text columns: `intel`, `scans` and `names` are identical on every
row of the same address, `fingerprints` belongs to the row's request. They
can be large (an nmap XML per scan), so for per-address work take one row
per `ip` first (`DISTINCT ON`, `group_by(...).first()`).

**`intel`**: every enrichment lookup ever recorded, oldest first.

```json
[{"provider": "maxmind-geolite2", "fetched_at": "2026-09-30T12:00:00+00:00",
  "source_version": "2026-09-26", "node": "alice", "node_id": "…", "build": "…",
  "data": {"country": "DE", "asn": 64500, "asn_org": "Example"}},
 {"provider": "abuseipdb", "fetched_at": "…", "source_version": null, "node": "bob", "node_id": "…", "build": "…",
  "data": {"abuseConfidenceScore": 100, "totalReports": 42, "...": "the provider's answer, trimmed to 16 KiB"}}]
```

Providers: `tor-exits` (`{"exit": true|false}`), `maxmind-geolite2`,
`abuseipdb`, `shodan`, `shodan-internetdb`. `data`
for an API provider is the service's own JSON, so its fields follow that
service's documentation; an empty object means the service knew nothing.

**`scans`**: every counter-scan of the address, oldest first.

```json
[{"uid": "…", "audit_of": null, "level": 2, "status": "done", "started_at": "…", "finished_at": "…",
  "node": "alice", "node_id": "…", "build": "…", "scanner": "carol", "os_guess": "Linux 5.x",
  "ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6",
             "extrainfo": "Ubuntu Linux; protocol 2.0", "ostype": "Linux", "devicetype": null,
             "hostname": "host-7.example.net", "cpe": ["cpe:/a:openbsd:openssh:9.6p1"]}],
  "host_keys": [{"kind": "ssh-hostkey", "port": 22, "fingerprint": "SHA256:…", "detail": "ed25519 256"}],
  "facts": [{"port": 80, "proto": "tcp", "kind": "http.title", "value": "PentAGI"},
            {"port": null, "proto": null, "kind": "smb.server", "value": "WIN-344VU98D3RU"}],
  "xml": "<?xml …>  the full nmap output"}]
```

`level` 1 to 4 (more ports, service versions, OS detection, safe scripts);
`node` queued it, `scanner` ran it. From level 2 the XML carries the
source's SSH host keys, SSH algorithm lists, TLS certificates and HTTP
headers (`ssh-hostkey`, `ssh2-enum-algos`, `ssl-cert`, `http-headers`).
`host_keys`: what peephole read from the XML: `ssh-hostkey` (OpenSSH's
`SHA256:` fingerprint), `tls-cert` (SHA-256 of the DER), `ja4x`, `hassh`
(HASSH-server) and `http-etag` (the ETag as sent; for nginx's form the
detail gives the file's modification date and size).
`ports[].extrainfo`, `ostype`, `devicetype`, `hostname` and `cpe` are what
nmap's `-sV` wrote beyond product and version. `facts`: what the source
serves and calls itself, read from the fixed fields of a few scripts, never
from their prose: `http.title`, `http.redirect`, `http.server`, `http.auth`
(`Basic realm="…"`), `ntlm.netbios_computer`, `ntlm.netbios_domain`,
`ntlm.dns_computer`, `ntlm.dns_domain`, `ntlm.dns_tree`,
`ntlm.product_version` (RDP), `socks.method`, `dns.nsid`, and from the SMB
host script `smb.server`, `smb.domain`, `smb.fqdn`, `smb.domain_dns`,
`smb.forest_dns`, `smb.workgroup`, `smb.os`, `smb.lanmanager` (`port`
null). Values are cut at 512 bytes; at most 64 per scan.
`uid` is the scan's identifier in the cluster. `audit_of` is set when the
scan is an audit: the `uid` of the scan it checks. An audit is a scan run
again by another scanner, not a counter-scan of its own; its `node` and
`scanner` are the auditing node, and its `status` is its own (`done` once
it finished), not that of the job it checks.
`scrubbed`: how many times the scanner replaced its own address or name
with `[scanner]` in `xml` before signing the scan (0 for scans from before
0.10.0). The exporting node also removes its own addresses and names from
every scan's `xml` as it writes the file. `peephole export` removes the
configured and interface addresses only, not the address peers saw the
node connect from, so a node behind NAT should set `scan.own_addresses`
(the installer offers it); the admin download and admin export remove the
peer-observed addresses too.

**`names`**: host names known to point at the address, by name.

```json
[{"name": "example.com", "source": "dns", "first_seen": "…", "last_seen": "…", "votes": 4, "answered": 5},
 {"name": "host-7.example.net", "source": "ptr", "first_seen": "…", "last_seen": "…", "votes": 0, "answered": 0},
 {"name": "scanner-3.hoster.example", "source": "rdns", "first_seen": "…", "last_seen": "…", "votes": 0, "answered": 0}]
```

`dns`: an admin looked the name up and up to five nodes resolved it; the
address is listed when more than half of the resolvers that answered
returned it (`votes` of `answered`; `1` of `1` is a single, unverified
resolver). Disputed addresses are not exported. `ptr`: the reverse name
nmap reported in a scan of the address, as the address's own DNS claims it
(`votes` and `answered` are 0). `rdns`: this node's reverse lookup of the
address: a PTR name that resolves back to it (forward-confirmed; names in
special-use zones such as `.local`, `.internal` or `.test` are not looked
up). Each node looks up on its own, so two nodes' exports can differ
here; `votes` and `answered` are 0. Names are in ASCII form (`xn--` for
international ones).

**`fingerprints`**: browser fingerprints the trap page collected from this
request (`request` rows only, usually empty: scanners rarely run
JavaScript).

```json
[{"ts": "…", "node": "…", "node_id": "…", "build": "…", "fp_hash": "…", "visitor_id": "…",
  "attributes": {"...": "collector output: screen, fonts, WebGL, …"},
  "behavior_summary": {"...": "mouse and keyboard summary"},
  "events": [{"...": "raw event log"}]}]
```

### Timeline fields (CSV and JSON Lines only)

| Column | Meaning |
|---|---|
| `message` | One-line summary (`<ip> <method> <path>?<query> (<answer>, severity N, labels: …)`) |
| `datetime` | Same as `ts`, RFC 3339 |
| `timestamp_desc` | `HTTP request logged` or `HTTP request skipped` |

The Parquet file carries `peephole.format_version` (`1`) and the export
filter in its metadata.

## Canaries

Decoys serve credentials (canaries) that name the request they were
served to. They are derived with a public formula and no secret, from
the request's page token. The page token is not exported (it also links
a browser fingerprint or a false-positive claim to its request), so
canary values are recomputed where the data lives: `peephole decoy render
<uid>` prints the decoy a row was answered with, byte for byte, on any
node. In the export, `canary_used_from` already names the reuses.

**Version 1** (`decoy_v` = 1). Each value is

    SHA-256("peephole-canary-v1\0" || page_token || "\0" || kind)

with further blocks `SHA-256(… || "\0" || n)` (`n` = 1, 2, … in decimal)
appended when more bytes are needed, and each byte mapped to
`alphabet[byte mod alphabet length]`:

| kind | format |
|---|---|
| `aws-key` | `AKIA` + 16 characters of `A–Z2–7` |
| `aws-secret` | 40 characters of the base64 alphabet |
| `app-key` | base64 of 32 bytes (served as `base64:…`) |
| `db-password`, `redis-password`, `mail-password`, `admin-password` | 20 characters of `A–Za–z0–9` |
| `git-token` | 40 lowercase hex characters |
| `wp-session` | 43 characters of `A–Za–z0–9` (the token part of the WordPress login cookie) |
| `etag` | hex of 16 bytes: 32 lowercase hex characters (decoy version 3: the `ETag` header of the web decoys answering 200; found again in `If-None-Match`) |

`.env` carries `app-key`, the three passwords, `aws-key`, `aws-secret` and
`admin-password`; `.git/config` carries `git-token`; `decoy:wp-login-ok`
sets a cookie with `wp-session`. From version 3, the decoys `dotenv`,
`git-config`, `git-head`, `wp-login`, `wp-login-failed`, `wp-admin`,
`admin`, `phpinfo` and `git-refs` also carry an `etag`.

The node's site is `<word>.internal`, where `word` is
`WORDS[SHA-256("peephole-site-v1\0" || node_id)[0] mod 32]` (`node_id`
is the serving node's 32-byte key; a standalone node hashes nothing; the
word served is stored with the row, so it survives a standalone node
joining a cluster),
with `WORDS` = shop, portal, crm, billing, intranet, booking, support,
store, app, dashboard, members, orders, invoice, payments, tickets,
inventory, customers, partners, reports, hr, wiki, forms, events, media,
docs, api, account, checkout, catalog, newsletter, jobs, status. Links a
scanner can follow back (`ADMIN_URL`, the git remote) use the request's
`Host` header (HTTP/2: `:authority`; never a proxy-form target) when it
is a public IP or DNS name, an IPv6 literal in brackets, else the site.

**Version 0** (empty `decoy_v` on a decoy row) served `canary-<ref>`,
`AKIACANARY<REF>` (first 10 characters upper-cased) and
`canary/<ref>/not+a+real+secret`, where `ref` is the first 12 hex
characters of the page token without dashes.

A later row that carries a served canary (in a header, the path, the
query or the body) lists the serving row in `canary_used_from`.

## Two exports

**Everything** (the default) includes GeoLite2 results and the API
providers' answers. Their terms do not allow passing these on: MaxMind's
GeoLite2 licence and the AbuseIPDB and Shodan terms bind the
account holder. Cluster members hold them as users of the shared dataset;
a file leaving the cluster should not.

**Redistributable** (`--redistributable`, or "Redistributable" in the web
form) leaves out every result whose terms forbid redistribution: `intel`
keeps only the Tor exit list, and `country`, `asn` and `asn_org` are null.
Use it for anything published, handed to a course, or shared outside the
cluster.

## Before sharing

- **Bodies and headers carry what attackers send**: credentials they try,
  tokens, webhooks, e-mail addresses, and sometimes real users' data from a
  mistyped domain. Review before publishing; the redistributable mode does
  not redact them.
- **Provenance names operators.** `node`, `node_id` and the cluster's
  member names are in every row. Drop them (or hash `node_id`) if the
  operators should not be identifiable from the file.
- **Claim e-mails are never exported**, only `fp_claim`.
- **Counts need `weight`.** See Rows.
- **JA4H is FoxIO's method under the FoxIO License 1.1** (JA4 is BSD
  3-Clause). Check its terms before building a commercial product on the
  `ja4h` column.
