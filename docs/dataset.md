# The dataset

Real scanner traffic, labelled: every request a trap recorded, with
everything peephole knows about it and its source, as one table. In a
cluster it is drawn from every member's trap, and every node holds all of
it (or its last `retention_days`), so any operator can export it.

It is meant for research and machine learning on what scanners actually
send, and for an operator's own analysis. Every row says which node
recorded it, by name and key, and which build it ran, so provenance
survives the file leaving the node.

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
| `skipped` | request the flood gate answered but recorded only lightly (time, method, path) | `uid`, `node*`, `build`, `ts`, `ip`, `method`, `path`, `unrecorded`, `weight`, `persona`, the per-IP columns; for a decoy or tarpit answer also `answer` (and `decoy_v`, `host`, or `held_ms`) |

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
| `answer` | string? | What the trap sent: `not-found` (a 404), `landing` (a `GET` or `HEAD` of `/`: the persona's front or sign-in page, a 200, carrying the page token as the 404 page does), `decoy:<name>` (a believable fake: `decoy:dotenv`, `decoy:git-config`, `decoy:git-head`, `decoy:wp-login`, `decoy:wp-login-failed`, `decoy:phpinfo`; answers to a harvested canary: `decoy:wp-login-ok`, `decoy:wp-admin`, `decoy:admin`, `decoy:git-auth`, `decoy:git-refs`, `decoy:git-pack`), `claim` (the false-positive claim page), `webshell` (a request to a path an upload on this node was told it landed at: a canned reply to a few commands, else an empty `200`), `tarpit` (a slow `200` that drips a few bytes at a time, for sources whose requests reached severity 4 in the hour before; see `held_ms`) |
| `decoy_v` | int? | Template version of a decoy answer (see Canaries); empty for other answers, and empty on a decoy row means version 0 |
| `decoy_in` | string? | What an MCP or LLM decoy was rendered from (JSON), and for `decoy:phpinfo` from decoy version 5 `{"p": …}`; empty otherwise. From decoy version 5 it carries the serving node's AI identity as `"i"` and the persona it answered under as `"p"` (see Canaries); `"tool"` is the canonical tool name |
| `canary_used_from` | list of string | The `uid`s of the rows whose served canaries this row carried (light rows as `<batch uid>#<n>`, `n` the row's position in its batch from 1); empty when none |
| `status` | int? | HTTP status sent |
| `held_ms` | int? | How long a `tarpit` answer held the client, in milliseconds: up to the last chunk the connection took, so a client that gave up counts until then; the configured hold (`trap.tarpit_hold_secs`, default 600 s) when it waited to the end. Null for other answers |
| `persona` | string? | What the trap presented as when it answered: `wordpress`, `fortinet`, `gpu-box`, `gitlab` or `exchange-owa`. Fixed per node key for its bare IP and every Host that is not a public DNS name, and per (node key, name) for each public DNS name it was reached by. Null for rows from before v0.20.0 or from an older member |
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
| `labels` | list of string | Labels that matched: rule labels (`sqli`, `rce`, `path-traversal`, `ssrf`, `webshell`, `scanner-ua`, `ai-infra-probe`, `ai-agent-artifact`, `ai-agent-tooling`, … one family per file in `rules/`) and behavioural labels from code (`probe`, `path-scanner`, `form-interaction`, …); see the taxonomy in [detection.md](detection.md#classification) |
| `owasp` | list of string | OWASP tags of the matching rules: a Top 10 2021 class (`A03:2021`) for payload families, an Automated Threat (`OAT-014`) for scanning behaviour. Behavioural labels carry none |
| `severity` | int? | 0 (noise) to 4 (exploit attempt); the highest of the matching rules. Null on light rows |
| `scan_level` | int? | Counter-scan level this request earned (0: none, 1 to 4); weak tells alone (`probe`, `path-scanner`, `php-probe`, `ai-agent-artifact`, `ai-agent-tooling`) cap it at 1 whatever the severity |
| `rules` | string? | Fingerprint of the rules that classified it, those built into the recording binary: SHA-256 (hex) over the `rules/*.toml` files, sorted by name, each as its name's and text's 8-byte big-endian length followed by the bytes. Rows with the same value were classified by the same rules, whatever the build; to see the rules, check out a commit whose `rules/` has that fingerprint (`peephole check-config` prints the start of a binary's). Null for claims, light rows and rows recorded before the column existed. It is what the recording node says it used, not a proof |
| `fp_claim` | bool | The address filed a false-positive claim at some point (claim texts and e-mail addresses are never exported) |

### The source address, at the time of the request

| Column | Type | Meaning |
|---|---|---|
| `country` | string? | ISO 3166-1 alpha-2 from GeoLite2: the newest lookup at or before `ts`, or the earliest one when none precedes it |
| `asn` | int? | Autonomous system number, same rule |
| `asn_org` | string? | AS organisation, same rule |
| `is_tor` | bool? | A Tor exit, same rule: on the bulk exit list, or an exit by the Onionoo relay index (which covers IPv6); null when never checked |
| `is_tor_relay` | bool? | A running Tor relay of any role (guard, middle, exit) by the Onionoo index (`tor-relays`), same rule; null when never checked |

### Everything else known about the address

Four JSON text columns: `intel`, `scans` and `names` are identical on every
row of the same address, `fingerprints` belongs to the row's request. They
can be large (an nmap XML per scan), so for per-address work take one row
per `ip` first (`DISTINCT ON`, `group_by(...).first()`).

### Campaign

| Column | Type | Meaning |
|---|---|---|
| `campaign` | string? | The campaign `key` of the address when the export ran; null when the address is in no campaign |

A campaign is a group of addresses tied by evidence: a shared SSH host key,
TLS certificate, browser fingerprint or canary, or a similar set of
normalized paths. The column is derived, not recorded: every node
recomputes campaigns from the replicated rows about once an hour, so it is
node-local in timing (a node that has not caught up yet, or not recomputed
yet, can still miss a new member). It is stable in identity: the key is the
IP text of the campaign's oldest member, the same on every node, and
survives recomputes as long as that member stays in it. The key is not a
row of the export; join on it, not on the `#N` the admin pages show, which
is a display rank. A new clustering version can split a campaign, and the
split-off parts get new keys: join across exports made by the same version.

Path shapes are not exported either: `shapes` (with its `rule_hits`) and
`waves` are derived on each node from the rows it holds, so they are
node-local, like the campaigns.

**`intel`**: every enrichment lookup ever recorded, oldest first.

```json
[{"provider": "maxmind-geolite2", "fetched_at": "2026-09-30T12:00:00+00:00",
  "source_version": "2026-09-26", "node": "alice", "node_id": "…", "build": "…",
  "data": {"country": "DE", "asn": 64500, "asn_org": "Example"}},
 {"provider": "abuseipdb", "fetched_at": "…", "source_version": null, "node": "bob", "node_id": "…", "build": "…",
  "data": {"abuseConfidenceScore": 100, "totalReports": 42, "...": "the provider's answer, trimmed to 16 KiB"}}]
```

Providers: `tor-exits` (`{"exit": true|false}`), `tor-relays`
(`{"relay": bool, "exit": bool, "exit_sources": ["bulk list", "Onionoo"],
"family": "IPv4|IPv6", "relays": [{"nickname", "fingerprint", "roles",
"or_ports", "exit", "family_size", "first_seen", "version"}]}`, from
Onionoo; no contact information), `maxmind-geolite2`,
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
  "xml": "<?xml …>  the full nmap output", "xml_omitted": false}]
```

`level` 1 to 4 for queued scans (more ports, service versions, OS detection, safe scripts);
a bought scan may be level 5 (vulnerability scripts);
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
`xml_omitted`: the XML was left out to bound the export's memory. An
address's scans carry at most 16 MiB of XML, newest first, and the
addresses on one page of 5000 rows at most 64 MiB together; past that,
`xml` is null. A scan with no stored or no readable XML has `xml` null and
`xml_omitted` false.

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

### Shared

| Column | Type | Meaning |
|---|---|---|
| `shared` | object? | The address's shared reading where it is a pool or sits on one; null otherwise. Last column in CSV |

```json
{"state": "shared-pool", "rule": 4, "v": 3, "source": "operator naming", "name": "0-0-0-0.cgn-wdsl.example.it"}
```

Set by four readings of the [shared reading](detection.md#shared-addresses)
only: `subscriber-pooled` (rule 2: a consumer router answered in a scan and
the operator names the line pooled), `shared-pool` (rule 4: a carrier-NAT
name), `shared-mobile` (rule 5: a mobile name) and `pooled-line` (rule 6:
a pooled-line name such as `dynamic` or `pool`). `v` is the evidence
version the reading rests on. `source` names who makes the claim:
`operator naming`, or `operator naming and scan` for rule 2. `name` is the
reverse or PTR name the claim rests on, one of the address's `names`. Null
for every other reading, among them hosting, scanner, fleet and Tor exit
addresses (rule 1) and an address where a consumer router answered without
a pooled name (rule 3).

The column is derived by the exporting node when the export runs, from its
own rows; it is never stored and never replicated, and it adds no claim of
its own. A consumer can check each value with the bundled name patterns
(`rules/evidence/names.toml`, classes `cgn`, `mobile`, `pool`) against the
`names` column. On an address with no hosting, scanner, fleet, Tor or
router evidence that recompute gives the same value; the other gates only
ever withhold a value (rules 1 and 3) or add the scan beside the same
name (rule 2, whose router is in `scans`).

**A cost warning, not a verdict.** A value means a block on the address
hits other people. It is not verified by behaviour, and it goes stale
quickly: 75 % of mobile associations are gone within a day. Use it to weigh the cost of a block, not to clear or convict an
address.

The Parquet file carries `peephole.format_version` (`2`; `1` had no
`shared` column) and the export filter in its metadata.

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

**Version 5** adds the node's own AI decoy identity. The node's `ident`
is the first 4 bytes of `SHA-256("peephole-ai-id-v1\0" || node_id)` as 8
lowercase hex characters (a standalone node hashes nothing, as for the
site word), stored in `decoy_in` as `"i"`, so the row renders with the
identity it was served even after the node's key changes. From its bytes
`r[0..4]` and `sel = SHA-256("peephole-ai-sel-v1\0" || r)`: the MCP
server name is `SERVERS[r[0] mod 24]`, its version `r[1] mod 3`.`r[2] mod
16`.`r[3] mod 32`; tool `t` is listed under its name number `sel[t] mod 3`;
`sel[5] mod 3` extra tools from `sel[6]` on; tools in an order drawn from
`sel[8..14]`, resources 2 of 4 drawn from `sel[15..18]`; the gateway lists
`3 + sel[18] mod 2` local models drawn from `sel[20..29]`, Ollama version
`VERSIONS[sel[29] mod 6]`, and drops the OpenAI (Anthropic) model
`sel[30] mod 4` (`sel[31] mod 4`) unless that is 3. The pools are in
`src/trap/decoy/mcp.rs` and `src/model/llm.rs`. A row without `"i"`
(versions 2-4) renders the identity every node served before:
`internal-ops 0.3.1`, the five canonical tools, the first two resources,
the first four local models, all six upstream models, Ollama 0.6.5. Under a persona, `decoy_in` also carries `"p"`: the MCP
server name is then drawn from that persona's own pool of eight
(`mcp_servers` in `src/trap/persona/<name>.rs`) instead of `SERVERS`, the
`gpu-box` gateway lists two more local models (`5 + sel[18] mod 2`) and
`2 + (sel[18] >> 4) mod 2` large ones (`LARGE` in `src/model/llm.rs`,
consecutive from `(sel[18] >> 1) mod 6`), and the phpinfo decoy's
`SERVER_SOFTWARE` is the persona's `Server` header (`Apache` for
`fortinet`, which sends none). A version-5 row without `"p"` renders the
node-neutral identity above, and phpinfo's `Apache/2.4.57 (Debian)`. The
web decoys render as in version 4.

**Version 0** (empty `decoy_v` on a decoy row) served `canary-<ref>`,
`AKIACANARY<REF>` (first 10 characters upper-cased) and
`canary/<ref>/not+a+real+secret`, where `ref` is the first 12 hex
characters of the page token without dashes.

A later row that carries a served canary (in a header, the path, the
query or the body) lists the serving row in `canary_used_from`.

## Uploads

Files dropped on the trap have their own table, in Parquet only: "Table:
Uploads" in the web form (`/admin/export/download?table=uploads&format=parquet`).
One row per upload, oldest first. The time and IP filters apply; label
and severity filters do not. **The file's content is never in it**: the
table has no content column. Content leaves a node only through the
admin's per-file zip.

| Column | Meaning |
|---|---|
| `uid` | The upload's id. |
| `request_uid` | The request that carried the file (`uid` in the main export). |
| `node_id` | Hex id of the node that collected it; null on a standalone node. |
| `ts` | When it was received (UTC). |
| `ip` | The source address. |
| `kind` | `put`, `wp_plugin`, `wp_theme`, `wp_media` or `script`. |
| `filename` | The file name the client sent, as sent. Attacker text. |
| `sniffed_type` | From the first bytes: `zip`, `gzip`, `elf`, `php`, `script`, `html`, `text` or `binary`. |
| `size` | Full size as received. |
| `truncated` | Only the first 1 MiB was kept. |
| `sha256` | Lowercase hex SHA-256 of the kept bytes. |
| `answered_path` | Where the trap told the uploader the file landed. |
| `path_is_prefix` | `answered_path` is a folder (a plugin or theme). |
| `content_state` | Whether this node holds the content: `held`, or why not (`dropped_rate`, `dropped_budget`, `dropped_ceiling`, `dropped_disk`, `dropped_mismatch`, `too_big`, `not_received`). |

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
- **Fingerprint methods have their own licences.** Two are FoxIO
  License 1.1, which allows non-commercial use only (§2). Check before
  building a commercial product on them. Below: (a) implementing it in a
  binary we distribute, (b) publishing its values in exports, (c) selling
  peephole or a service built on it. This is a reading of the terms, not
  legal advice.

  | Column / kind | Method, owner | Licence | (a) binary | (b) values | (c) selling |
  |---|---|---|---|---|---|
  | `ja4` | JA4, FoxIO | BSD 3-Clause (`LICENSE-JA4`) | Allowed; notice in [`NOTICE`](../NOTICE) | Licence is silent | Allowed |
  | `ja4h` | JA4H, FoxIO (patent pending) | FoxIO License 1.1 | Non-commercial only, with the licence terms or URL attached (§2) | Licence is silent; FoxIO's FAQ counts indirect monetisation without exposing the values as commercial | Not allowed without a FoxIO OEM licence (§2, FAQ) |
  | `host_keys` `ja4x` | JA4X, FoxIO (patent pending) | FoxIO License 1.1 | As `ja4h` | As `ja4h` | As `ja4h` |
  | `host_keys` `hassh` | HASSH-server, Salesforce (not FoxIO's JA4SSH) | BSD 3-Clause | Allowed; notice in [`NOTICE`](../NOTICE) | Licence is silent | Allowed |
  | `jarm` (probes; not exported) | JARM, Salesforce | BSD 3-Clause | Allowed; notice in [`NOTICE`](../NOTICE) | Licence is silent | Allowed |
  | `host_keys` `ssh-hostkey`, `tls-cert`, `http-etag`; `favicon`, `http-body`, `http-404` (probes; not exported); `fingerprints` | SHA-256 of standard data; Shodan's favicon convention over MurmurHash3 (public domain); in-tree browser collector | None beyond the crates' MIT / Apache-2.0 | No restriction found | No restriction found | No restriction found |

  **Commercial gate.** We sell nothing today: credits are earned by work
  for other members and buy nothing outside the cluster
  ([Credits](overview.md#credits)). Before any of the following ships, the
  FoxIO columns (`ja4h` and `ja4x`, together) must be resolved, by dropping
  both or by obtaining a FoxIO OEM licence, and counsel reviews this
  reading of the licences:

  1. selling credits, scans or capacity for money;
  2. hosted or managed scanning we charge for;
  3. any paid product that distributes the binary or the fingerprint
     values.

  Teaching or writing about peephole, without distributing the binary or
  its outputs, is outside the gate. If you read the terms differently,
  open an issue.
