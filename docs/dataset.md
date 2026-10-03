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
| `skipped` | request the flood gate answered but recorded only lightly (time, method, path) | `uid`, `node*`, `build`, `ts`, `ip`, `method`, `path`, `unrecorded`, `weight`, the per-IP columns |

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
| `answer` | string? | What the trap sent: `not-found` (a 404), `decoy:<name>` (a believable fake, e.g. `decoy:dotenv`, `decoy:git-config`), `claim` (the false-positive claim page) |
| `status` | int? | HTTP status sent |
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
| `scan_level` | int? | Counter-scan level this request earned (0: none, 1 to 4) |
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

Three JSON text columns, identical on every row of the same address. They
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
`abuseipdb`, `shodan`, `shodan-internetdb`, `greynoise-community`. `data`
for an API provider is the service's own JSON, so its fields follow that
service's documentation; an empty object means the service knew nothing.

**`scans`**: every counter-scan of the address, oldest first.

```json
[{"level": 2, "status": "done", "started_at": "…", "finished_at": "…",
  "node": "alice", "node_id": "…", "build": "…", "scanner": "carol", "os_guess": "Linux 5.x",
  "ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6"}],
  "xml": "<?xml …>  the full nmap output"}]
```

`level` 1 to 4 (more ports, service versions, OS detection, safe scripts);
`node` queued it, `scanner` ran it.

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

## Two exports

**Everything** (the default) includes GeoLite2 results and the API
providers' answers. Their terms do not allow passing these on: MaxMind's
GeoLite2 licence and the AbuseIPDB, Shodan and GreyNoise terms bind the
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
