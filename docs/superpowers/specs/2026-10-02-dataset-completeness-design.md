# peephole — dataset completeness

Date: 2026-10-02
Status: approved in conversation; written spec awaiting review

## 1. Goal

peephole collects and enriches unsolicited traffic into a large, hard
dataset for later research (machine learning among it). Labelling is not its
job: the rule labels stay operational (scan decisions, display). This spec
closes the gaps between what peephole sees and what ends up in the dataset:

1. **How each request was answered** is stored per request.
2. **Flood sampling** no longer loses the skipped requests: each one leaves a
   light row (time, method, path), so rates and timing stay true.
3. **Connection-level signals** are captured: the raw TLS ClientHello and its
   JA4 fingerprint, and the raw HTTP/1 request head (header case and order as
   sent). Behind nginx, TLS is passed through, not terminated.
4. **The request export carries everything** the node knows about each
   request, in CSV (Timesketch-compatible), JSONL (Timesketch) and Parquet.
   The separate enrichment export goes away. A *redistributable* mode leaves
   out every enrichment whose terms forbid passing it on.

Success means: a single export of a time range contains every request
(recorded or skipped), with every field peephole stored about it and its IP,
and the dataset can be rebuilt from raw bytes where features are derived
(JA4, header order).

Out of scope: TCP/IP (SYN) fingerprints, which need packet capture on the
host; HTTP/2 frame fingerprints (hyper does not expose SETTINGS/priority);
any labelling workflow.

## 2. Per-request answer

New `requests` columns:

| Column | Type | Meaning |
|---|---|---|
| `answer` | TEXT NOT NULL DEFAULT '' | `not-found` (trap page), `decoy:<name>` (`dotenv`, `git-config`, `wp-login`, `wp-login-failed`, `phpinfo`), `claim` (FP claim form post). `''` on rows older than this change. |
| `status` | INTEGER | HTTP status sent (404, 200, …). NULL on old rows. |

The trap decides the decoy *before* recording, so the row says what was
sent. The canary inside a decoy is derived from `page_token`, which is
already stored; it is not duplicated.

## 3. Sampling: weights and light rows

- New column `requests.unrecorded INTEGER NOT NULL DEFAULT 0`: requests from
  this IP that were answered but not recorded in full since its previous
  recorded one. The `:unrecorded` pseudo-header is no longer written; the
  migration backfills the column from old rows' `headers_json`.
- Every skipped request leaves a light row: `ts` (millisecond UTC), `ip`,
  `method`, `path` (cut at 1 KiB). The trap buffers them per IP in memory and
  flushes a batch when the IP's next request is recorded, after 10 seconds,
  or at 1000 rows, whichever comes first.
- Bound: at most `trap.skip_log_rate` light rows per IP per second (default
  100, 0 = unlimited). Past that, requests are only counted; the batch
  carries the count (`dropped`). So a flood costs at most ~100 small rows per
  second per IP, and nothing is silently lost: every answered request is a
  full row, a light row, or a counted drop.
- Storage: table `skipped_batches (id, uid, origin, hlc, ip, first_ts,
  last_ts, dropped)` and `skipped_requests (batch_id, ts, method, path)`.
  Replicated as one new record kind `SkipBatch { uid, ip, dropped, rows:
  [(ts, method, path)] }`. Nodes of an older version forward it without
  applying it (unknown kinds already relay). Retention and delete include
  batches like requests.
- The admin IP page shows the light-row count next to the request count.

## 4. Connection-level capture

### 4.1 TLS trap listener

- New config: `trap_tls_listen` (optional), `trap_tls_cert` and
  `trap_tls_key` (optional PEM paths). Without cert and key, peephole makes
  a self-signed certificate for `localhost` at start (rcgen; scanners do not
  check it). Requires the listener role, like `trap_listen`.
- The listener reads the first TLS record(s) up to the end of the
  ClientHello (bounded at 16 KiB, 10 s), keeps the raw bytes, computes JA4
  (FoxIO spec, `t` prefix; TLS 1.3 from `supported_versions`, GREASE
  ignored), then hands the buffered bytes plus the stream to rustls. ALPN
  offered: `h2`, `http/1.1`. A connection that is not TLS or fails the
  handshake is dropped; it is not recorded (no HTTP request exists).
- Same HTTP service, timeouts and connection cap as the plain trap.

### 4.2 PROXY protocol

On the TLS trap listener, a connection from an address in `trusted_proxies`
must start with a PROXY protocol header (v1 or v2); its source address is
the client. From any other address, no header is expected and the peer is
the client. A trusted peer that sends no valid header is dropped. This makes
the listener work both directly on port 443 and behind any proxy that speaks
the PROXY protocol, without naming one.

### 4.3 Raw request head

- Both trap listeners serve HTTP/1 without keep-alive: one request per
  connection. The connection's reader keeps a copy of the first bytes read
  (up to 64 KiB, the existing head limit); the request's raw head is those
  bytes up to and including the first `\r\n\r\n`. On the TLS listener this is
  after decryption.
- New `requests` columns: `transport TEXT` (`http`, `https`; NULL on old
  rows), `raw_head BLOB` (HTTP/1 only), `tls_client_hello BLOB`, `ja4 TEXT`.
- Behind an HTTP proxy (port 80 via nginx) the raw head is the proxy's
  rewrite, not the client's; the export says so through `transport = http`
  and the peer being a trusted proxy (`via_proxy` column in the export).

### 4.4 nginx layout (installer, example, docs)

nginx's `stream` module takes port 443 and routes by SNI without
terminating TLS (`ssl_preread`):

- the admin domain → nginx's own TLS server for the admin site, moved to
  `127.0.0.1:8444 ssl proxy_protocol` (client address restored with
  `set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`);
- every other name, and no SNI → `trap_tls_listen` (default
  `127.0.0.1:8081`) with `proxy_protocol on`.

A listener-only node sends all of 443 to the trap. Port 80 stays an HTTP
proxy as today. The installer installs the stream module where the
distribution packages it separately (`libnginx-mod-stream`), writes the
stream config to `/etc/nginx/peephole-stream.conf` and includes it at the
top level of `nginx.conf` once (an `include` line, added only if absent).
The `ssl_reject_handshake` default server and the commented "self-signed
trap on 443" alternative are removed: unknown names now reach the trap.

Docs (README, `docs/operations.md`, `deploy/config.example.toml`, code
comments) describe nginx or "a reverse proxy"; HAProxy is mentioned nowhere.

## 5. Export

### 5.1 One request export, every field

One row per request, plus one row per light row (§3) with `kind =
skipped`. Recorded requests come first, then light rows, each oldest first;
the same filters (time range, IP, label, min severity) apply, and light rows
are left out when a label or severity filter is set. Columns:

| Column | Content |
|---|---|
| `kind` | `request` or `skipped` |
| `uid`, `node` | record uid; origin node name (or short key; `this node` standalone) |
| `ts` | UTC; Parquet `timestamp(ms, UTC)`, text formats RFC 3339 |
| `ip`, `method`, `path`, `query` | as recorded |
| `http_version`, `host`, `user_agent` | convenience, from the headers |
| `headers` | every header in order, names as received (JSON list of `[name, value]`; Parquet `list<struct<name,value>>`) |
| `body` | Parquet binary; text formats base64 |
| `body_size`, `body_truncated_at` | bytes kept; total received when cut |
| `transport`, `via_proxy`, `raw_head`, `tls_client_hello`, `ja4` | §4; blobs base64 in text formats |
| `answer`, `status` | §2 |
| `unrecorded`, `weight` | §3; `weight = unrecorded + 1` (`1` for light rows) |
| `labels`, `severity`, `scan_level` | list (Parquet `list<string>`; JSON list in text) |
| `fp_claim` | whether the IP filed a false-positive claim (never the email or claim text) |
| `country`, `asn`, `asn_org`, `is_tor` | GeoLite2 and Tor results as of the request time (newest at or before `ts`, else the first after) |
| `intel` | JSON list of every lookup in the IP's history (`ip_intel_log`): provider, fetched_at, source_version, node, data |
| `scans` | JSON list of the IP's counter-scans: level, status times, scanner node, os_guess, ports, nmap XML |
| `fingerprints` | JSON list of browser fingerprints tied to this request: hash, visitor id, attributes, behaviour summary, events (decompressed) |
| `message`, `datetime`, `timestamp_desc` | Timesketch fields (also in CSV now; `timestamp_desc` is `HTTP request logged` or `HTTP request skipped`) |

The per-IP JSON (`intel`, `scans`) repeats on each of the IP's rows; Parquet
dictionary encoding and compression absorb that, the text formats do not.
Point-in-time joins are left to the consumer: `intel` has every lookup with
its time.

Parquet footer metadata: `peephole.format_version = 1`,
`peephole.exported_at`, `peephole.mode` (`full` / `redistributable`),
`peephole.filter` (JSON), `peephole.version`. Parquet is typed for analysis;
it is not Vestigo's interchange format (that one wants per-row provenance of
a source file, which this dataset does not have).

### 5.2 Redistributable mode

`ProviderInfo` gains `redistributable: bool`. Only the Tor exit list is
redistributable; GeoLite2, AbuseIPDB, Shodan, InternetDB and GreyNoise are
not. In redistributable mode the export leaves out `intel` entries of the
others, and `country`, `asn`, `asn_org` (GeoLite2-derived). Everything
peephole observed itself stays, IPs included.

### 5.3 Removed

The enrichment export (`/admin/export/intel`, its store queries and the
template section) is removed. The export page drops the stale "up to
100 000 rows" text and gains the mode choice.

## 6. Replication

`RequestRec` gains the new columns as `#[serde(default)]` fields, so old
records still decode. `request` is row-backed: `store::data::rebuild` must
rebuild exactly the fields that were signed, including the new ones, or
signatures break. Mixed-version clusters: an older node ignores fields it
does not know when applying, so its copy lacks them; acceptable until it is
upgraded (rows are not re-sent).

## 7. Testing

- Unit: JA4 against the FoxIO reference vectors; ClientHello parsing with
  split records and garbage; PROXY v1/v2 parsing; raw-head cut; light-row
  buffer (flush triggers, rate bound, drop count); decoy-to-`answer`
  mapping; redistributable filtering.
- Integration: a TLS client (rustls) through the TLS listener records
  `transport = https`, `ja4`, `tls_client_hello`; a PROXY-headed connection
  from a trusted peer records the header's source; a flood records full rows,
  light rows and drops whose total equals the requests sent; export of each
  format contains every column and round-trips (Parquet read back with the
  `parquet` crate); replication of a request with the new fields verifies.
- Installer: `--nginx-example` output passes `nginx -t` in the existing
  podman smoke test, with the stream module.
