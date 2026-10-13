# peephole API v1

The machine API of a peephole node, built for the Android companion app.
It sits on the same listener as `/admin` — no new exposure: if you can reach
the admin UI you can reach `/api/v1`.

All endpoints are JSON. All times are RFC 3339 UTC. Base URL: the node's
admin origin, e.g. `https://ph.example.net` (the same origin WebAuthn uses).

## Authentication

Two separate credential kinds live on this listener, and they never mix:

- **Admin session** (WebAuthn passkey or password, `__Host-peephole_session`
  cookie) — gates the HTML pages under `/admin`. It is **not** valid on
  `/api/v1/*`; a request that carries only a cookie gets `401`.
- **Device token** (`Authorization: Bearer <token>`) — gates `/api/v1/*`
  only. A bearer token on an HTML admin route is not treated as
  authenticated.

Device tokens are issued by pairing, are 256-bit random (base64url, 43
chars), and only their SHA-256 is stored. Each token carries scopes:

| scope  | meaning                                          |
| ------ | ------------------------------------------------ |
| `read` | every `GET` under `/api/v1`, `POST /api/v1/lookup` |
| `act`  | start probes, buy counter-scans and fresh provider lookups, read their jobs (spends credits) |

`read` is always granted at pairing; `act` is optional (a checkbox on the
pairing form). A missing or wrong scope is `403`.

### Pairing

Pairing starts on the admin UI (**Admin → Devices → Pair a device**, admin
session required). The admin picks the scopes, the server mints a single-use
pairing code (192-bit random, base64url) and renders a QR. The code's SHA-256
is stored with a TTL of 5 minutes; the code itself is never stored and never
logged. The QR holds:

```json
{
  "v": 1,
  "origin": "https://ph.example.net",
  "code": "uJ0c…",
  "tls_spki_sha256": "5LxK…"
}
```

- `origin` — the configured admin origin the app should talk to.
- `code` — the pairing code, redeemed once within 5 minutes.
- `tls_spki_sha256` — base64 of the SHA-256 of the TLS certificate's
  SubjectPublicKeyInfo the admin origin serves. Present only when the
  operator configured it (`api_tls_spki_sha256` in the config; peephole
  terminates no TLS itself, it sits behind a proxy). When present the app
  should pin it; when absent the app falls back to ordinary PKI validation.

The app redeems the code:

`POST /api/v1/pair`

```json
{ "code": "uJ0c…", "device_name": "Pixel 8" }
```

`200`:

```json
{
  "token": "Zv9…",
  "device_id": "8f3c2f0e-…",
  "scopes": ["read"],
  "instance_name": "ph.example.net"
}
```

- `token` is shown once, in this response only. The server stores its hash.
- `instance_name` is the node's display name (its WebAuthn RP name), so the
  app can label the account.

A reused, expired, or unknown code is `401` and the code is dead afterwards
either way (consumed on first use attempt that matches). This endpoint is
rate-limited per client IP (10/min); on excess it answers `429` with
`Retry-After`. `device_name` is required, 1–80 chars, and is stored as given.

### Revocation

Admin → Devices lists every device: name, scopes, who paired it, created,
last seen. **Revoke** marks the device revoked; its token gets `401` on the
next request. Revocation is final (pair again for a new token).

## Errors

Every non-2xx response is JSON:

```json
{ "error": { "code": "not_found", "message": "no such address in the dataset" } }
```

| status | code           | when                                              |
| ------ | -------------- | ------------------------------------------------- |
| 400    | `invalid`      | malformed body, bad address, bad cursor, bad limit |
| 401    | `unauthorized` | no/expired/revoked token, dead pairing code       |
| 403    | `forbidden`    | token lacks the required scope                    |
| 404    | `not_found`    | address not in the dataset, unknown `/api/v1` path, a job not this device's |
| 409    | see below      | a scan is not sold, or a quote cannot be spent    |
| 422    | `refused`      | the probe gate refuses the address (reason in `message`) |
| 429    | `rate_limited` | per-IP limit hit (`Retry-After` header is set)    |
| 500    | `internal`     | storage failure; message is generic, never a leak |

Secrets (tokens, codes) never appear in error bodies or logs.

## Endpoints

All require `Authorization: Bearer <token>` with scope `read`; the
[act endpoints](#act-endpoints) need `act` too.

### `GET /api/v1/ips?q=&cursor=&limit=`

Paged list/search over the IPs in the dataset — the same data the admin
IPs page shows.

- `q` — free text: an exact IP, a network (`203.0.113.0/24`), or a string
  prefix. Empty lists everything.
- `cursor` — opaque continuation token from the previous page's
  `next_cursor`. A cursor is bound to the `q` it was issued with.
- `limit` — page size, default 50; above 100 it clamps to 100, and 0 or a
  non-number is a `400`.

`200`:

```json
{
  "items": [
    {
      "ip": "203.0.113.9",
      "country": "DE",
      "asn": 6805,
      "asn_org": "Telefonica Germany",
      "is_tor": false,
      "first_seen": "2026-10-03T14:02:11Z",
      "last_seen": "2026-10-10T08:41:57Z",
      "request_count": 1284,
      "max_severity": 4,
      "abuse_score": 87
    }
  ],
  "next_cursor": "eyJ…"
}
```

`next_cursor` is `null` on the last page. `abuse_score` is the newest stored
AbuseIPDB score, `null` when none.

### `GET /api/v1/ips/{addr}`

Everything the dataset holds on one address. `404` when the address is not
in the dataset (a lookup that asks providers is an
[act endpoint](#get-apiv1ipsaddrlookupquoteproviders): quote, then spend).

`200`:

```json
{
  "ip": "203.0.113.9",
  "geo": { "country": "DE", "asn": 6805, "asn_org": "Telefonica Germany" },
  "is_tor": false,
  "severity": 4,
  "first_seen": "2026-10-03T14:02:11Z",
  "last_seen": "2026-10-10T08:41:57Z",
  "request_count": 1284,
  "labels": ["scanner", "credential-stuffing"],
  "families": [{ "name": "web-scan", "count": 41 }],
  "intel": {
    "abuseipdb": { "fetched_at": "…", "data": { } },
    "shodan": null,
    "shodan-internetdb": { "fetched_at": "…", "data": { } },
    "rdap": { "fetched_at": "…", "data": { } }
  },
  "scans": [
    {
      "scanned_at": "…",
      "ports": [{ "port": 22, "service": "ssh", "product": "OpenSSH" }]
    }
  ],
  "names": [{ "name": "host9.example.net", "source": "rdns", "agreed": true }],
  "rank": 17,
  "neighbours": {
    "net": "203.0.113.0/24",
    "other_ips": 12,
    "same_asn": 55
  }
}
```

- `intel` — newest stored answer per provider, keyed by the provider's
  stored name (`abuseipdb`, `maxmind-geolite2`, `shodan`,
  `shodan-internetdb`, `rdap`; a known provider that never answered is
  `null`). `data` is the provider's parsed JSON as stored. Tor is not an
  entry here: `is_tor` comes from the exit list the node loads.
- `scans` — newest first: ports found open by nmap scans of the address.
- `names` — names for the address (rDNS, resolved lookups, scan banners),
  each with its source and whether several resolvers agreed.
- `labels` / `families` — the classifier's verdicts; `severity` is the
  highest severity of any request from the address.

### `POST /api/v1/lookup`

Stored-data lookup for several addresses at once — the same semantics and
the same 500-address cap as the admin bulk lookup. No provider is asked; no
credits are spent on `ips`. Host names and URLs go in `names` (below).

```json
{ "ips": ["203.0.113.9", "2001:db8::1", "198.51.100.0/24"] }
```

`200`:

```json
{
  "results": [
    { "ip": "203.0.113.9", "country": "DE", "asn": 6805, "asn_org": "…",
      "is_tor": false, "first_seen": "…", "last_seen": "…",
      "request_count": 1284, "max_severity": 4, "abuse_score": 87 }
  ],
  "missing": ["2001:db8::1"],
  "unreadable": [],
  "capped": false
}
```

- Entries that are networks expand to the matching stored addresses;
  `results` carries the same per-IP summary shape as `GET /api/v1/ips`.
- `missing` — exact addresses not in the dataset; `unreadable` — entries
  that are neither an address nor a network; `capped` — more than 500
  stored rows matched, the list is truncated.
- `names` — one entry per item of the optional `names` field, below
  (`[]` when it is absent).

#### Host names and URLs

`names` takes host names and URLs, up to **10 per request** (each is a
DNS resolution, on several nodes in a cluster); `ips` may then be left out.

```json
{ "names": ["example.com", "https://example.com:8443/login?x=1", "http://[2001:db8::1]/"] }
```

Each entry is reduced to its host: a URL
(`scheme://[user@]host[:port][/path][?query][#fragment]`, or the same
without the scheme, e.g. `example.com/path`) loses everything but the host;
userinfo is dropped and neither echoed nor logged. An IP-literal host
(`203.0.113.9`, `[2001:db8::1]`) is read like an `ips` entry. A host name is
resolved exactly as the admin lookup page resolves it — by this node, and in
a cluster by member resolvers that vote (a member may charge its `resolve`
price, as on the admin page) — and the record is stored; its agreed
addresses (the first 16) are then read from stored data like `ips`. No
intelligence provider is asked.

`names` in the answer is in request order; the input is not repeated:

```json
"names": [
  { "host": "example.com",
    "resolve": {
      "note": null,
      "votes": [ { "ip": "203.0.113.9", "agreed": true, "verdict": "agreed by 3 of 3" } ],
      "resolvers": ["alice (DE)", "bob (NL)", "carol (FR)"],
      "errors": [],
      "also": []
    },
    "results": [ { "ip": "203.0.113.9", "…": "the per-IP summary" } ],
    "missing": [] },
  { "host": "2001:db8::1", "results": [], "missing": ["2001:db8::1"] },
  { "host": "gone.example", "resolve": { "…": "…" },
    "error": { "code": "unresolved", "message": "No resolver answered; nothing was stored." } },
  { "error": { "code": "invalid", "message": "not an IP address, host name or URL" } }
]
```

- `resolve` (host names only) — `votes`: every address answered, whether
  it is agreed and by how many; `note`: how far the answer can be trusted
  when not by a majority of several (`"resolved locally, unverified"`
  standalone, `"unverified — single resolver"`), else `null`;
  `resolvers`: the nodes asked; `errors`: `{node, why}` per node that did
  not answer; `also`: agreed addresses past the first 16, not read.
- A failed entry carries `error` with `code` `invalid` (no host can be
  read) or `unresolved` (no agreed address). A failed entry never fails
  the request.
- Every name is answered: there is no count limit (0.11.0 and older
  answered names past the 10th with `capped`). A few names are resolved at
  a time; the request body limit and the per-client rate limit bound the
  rest.

### `GET /api/v1/uploads?cursor=&limit=`

Files dropped on the trap, newest first: **metadata and hash only**. No
field carries the file's content; content leaves a node only through the
admin's per-file zip.

- `cursor` — opaque continuation token from the previous page's
  `next_cursor`.
- `limit` — page size, default 50; above 100 it clamps to 100, and 0 or a
  non-number is a `400`.

`200`:

```json
{
  "items": [
    {
      "uid": "01J…",
      "request_uid": "01J…",
      "node_id": "6f1c…",
      "ts": "2026-10-12T07:14:03Z",
      "ip": "203.0.113.9",
      "kind": "put",
      "filename": "s.php",
      "sniffed_type": "php",
      "size": 31,
      "truncated": false,
      "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "answered_path": "/s.php",
      "path_is_prefix": false,
      "content_state": "held"
    }
  ],
  "next_cursor": null
}
```

- `kind`: `put`, `wp_plugin`, `wp_theme`, `wp_media` or `script`.
- `filename`: as the client sent it — attacker text; escape it.
- `sniffed_type`: from the first bytes, never the client's `Content-Type`.
- `size`: full size as received; `truncated`: only the first 1 MiB kept.
- `sha256`: lowercase hex, of the kept bytes.
- `node_id`: hex id of the node that collected it; `null` standalone.
- `content_state`: whether this node holds the content (`held`), or why
  not (`dropped_rate`, `dropped_budget`, `dropped_ceiling`,
  `dropped_disk`, `dropped_mismatch`, `too_big`, `not_received`).

### `GET /api/v1/uploads/{sha256}`

Every upload of one file (up to 100, newest first), by its SHA-256 in
hex. `400` (`invalid`) when it is not 64 hex digits, `404` when no upload
has it.

```json
{ "sha256": "9f86d0…0a08", "uploads": [ { "uid": "01J…", "…": "as above" } ] }
```

## Act endpoints

Probes, paid counter-scans and fresh provider lookups, the same actions as
the Actions card on the admin IP page and the admin lookup page, and with the same checks (target rules, probes off, live
scanners, scan budget, a fresh or queued scan of the level): both run the
shared code in `admin::probes::start` and `admin::scan_buy::sale`. Every
endpoint here needs scope `act`; a `read`-only token is `403`. They sit
under the per-client rate limit of all `/api/*` paths (`429` past it).

Credits are given twice: as a decimal string in credits, as the admin UI
prints them (`"1.28"`, `"0.00"` standalone, where nothing costs anything),
and as integer millicredits (`*_mc`).

Every call that queues something writes an audit entry: when, the device
(id and name), who paired it, the action, the target, the credits and the
job id. Admins see the newest 50 under **Recent actions** on
Admin → Devices.

### `GET /api/v1/ips/{addr}/probe/vantages`

What a probe of the address would ask and cost, so the app can show the
total before it commits: the live scanners and default pick of the
Actions card. Spends nothing and writes no audit entry.

`200`:

```json
{
  "vantages": [
    { "id": "…", "name": "fra-1", "country": "DE", "credits": "0.10", "credits_mc": 100, "default": true }
  ]
}
```

Cheapest first. `default` marks the card's default pick; send the ticked
ids as `vantages` to the probe. Standalone it is one free entry, the node
itself (`"name": "this node"`). `404` when the address is not in the
dataset; `422 refused` when the probe would be refused (the gate, no live
scanner announcing a price, or a node that does not probe).

### `POST /api/v1/ips/{addr}/probe`

Body (optional): `{ "vantages": ["<node id>", …] }`. Without it, the
default pick of the Actions card. Ids that are not live scanners are
ignored; none left is `422`. Standalone the node probes itself and
`vantages` is ignored.

`202`:

```json
{
  "job_id": "p_…",
  "credits": "0.30",
  "credits_mc": 300,
  "vantages": [{ "id": "…", "name": "fra-1", "country": "DE", "credits_mc": 100 }]
}
```

`credits` is the sum of the asked scanners' probe prices (what the card
offers); a vantage that declines or lapses is not charged. `404` when the
address is not in the dataset; `422 refused` when the gate refuses it.

### `GET /api/v1/ips/{addr}/scan/prices`

Every level's price range, as the Actions card's level buttons show it,
so the app's level picker can show them before a quote. Spends nothing,
creates no quote and writes no audit entry.

`200`:

```json
{
  "levels": [
    { "level": 1, "about": "top 100 ports, light version detection",
      "credits": "0.08", "credits_mc": 80, "credits_max": "0.32", "credits_max_mc": 320 }
  ]
}
```

- `credits` and `credits_max` are those of the quote (below) at this
  moment; the quote stays the binding price.
- Show `{credits}–{credits_max} credits`, or `{credits} credits` when
  both strings are equal; the web shows the same.
- Standalone every level is free (`"0.00"`). `levels` is empty when no
  live scanner announces a price. `404` when the address is not in the
  dataset.

### `GET /api/v1/ips/{addr}/scan/quote?level=1..5`

`200`:

```json
{
  "quote_id": "q_…",
  "credits": "1.28",
  "credits_mc": 1280,
  "credits_max": "2.56",
  "credits_max_mc": 2560,
  "expires_at": "2026-10-10T16:05:00Z",
  "offer": { "level": 3, "about": "top 1000 ports, versions, OS, traceroute, safe scripts" }
}
```

- The quote is bound to the device, the address, the level and
  `credits_mc`. It lives 2 minutes and is spent once.
- `credits` is the floor: the cheapest live scanner's price × 4^(level-1),
  the low end of the Actions card's range and what the scan budget must
  cover. The arbiter pays whichever scanner wins the job, so the charge
  lies between `credits` and `credits_max` (the dearest live scanner's
  price × the same factor). Show the range.
- A bad `level` is `400`.

When there is nothing to buy, `409` and no quote, with one of these codes:

| code         | when                                                      |
| ------------ | --------------------------------------------------------- |
| `fresh`      | a scan of this level under 24 h old; the error carries `scan_id` and `scanned_at` |
| `on_its_way` | a job of this level is queued or running (`status`)       |
| `no_price`   | no live scanner announces a price                         |
| `no_budget`  | the scan budget does not cover the floor                  |

### `POST /api/v1/ips/{addr}/scan`

Body: `{ "quote_id": "q_…" }`. The quote is spent first (atomically,
once), then the checks of the quote run again.

`202`: `{ "job_id": "s_…", "credits": "1.28", "credits_mc": 1280 }`

Each of these is `409` and **queues nothing and charges nothing** (a scan
is charged when a scanner runs its job):

| code             | when                                                     |
| ---------------- | -------------------------------------------------------- |
| `quote_invalid`  | unknown, another device's, expired or already spent      |
| `quote_mismatch` | the quote is for another address                         |
| `price_changed`  | the floor moved since the quote: get a new one           |
| `fresh`, `on_its_way`, `no_price`, `no_budget` | as for the quote, now  |
| `not_queued`     | the scan queue did not take the job (a queue budget)     |

### `GET /api/v1/ips/{addr}/lookup/quote?providers=…`

What a fresh provider lookup costs now, the offer of the admin lookup
page: the providers it asks, by which node, at what price, and the total.
The address need not be in the dataset. `providers` (optional) is a
comma-separated list of provider names to buy; without it, every provider
offered ("ask all"). This node's own providers are always asked and free.

`200`:

```json
{
  "quote_id": "q_…",
  "credits": "0.35",
  "credits_mc": 350,
  "expires_at": "2026-10-10T16:05:00Z",
  "providers": [
    { "provider": "maxmind", "label": "MaxMind", "node": "this node", "credits": "0.00", "credits_mc": 0, "own": true },
    { "provider": "abuseipdb", "label": "AbuseIPDB", "node": "bob", "credits": "0.10", "credits_mc": 100, "own": false }
  ]
}
```

- The quote is bound to the device, the address, the bought providers and
  `credits_mc`. It lives 2 minutes and is spent once. Show `providers` and
  the total before asking the user to confirm.
- `credits` is the most the lookup charges: a provider that declines or
  already has a fresh answer is not charged. Standalone everything is
  `"0.00"`.
- An unknown provider name is `400 invalid`; a known one nobody offers now
  is `409 not_offered`; nothing to ask at all is `409 no_provider`.

### `POST /api/v1/ips/{addr}/lookup`

Body: `{ "quote_id": "q_…" }`. The quote is spent first (atomically,
once), then the offer is priced again; the audit entry (with the quoted
credits) is written before any provider is asked. The lookup answers at
once, there is no job to poll.

`200`:

```json
{
  "ip": "203.0.113.9",
  "credits": "0.10",
  "credits_mc": 100,
  "charges": [{ "node": "bob", "credits": "0.10", "credits_mc": 100 }],
  "intel": { "abuseipdb": { "source": "fresh", "node": "bob", "fetched_at": "…", "data": { … } } },
  "declined": [{ "provider": "shodan", "node": "bob", "why": "…" }],
  "kept": true
}
```

- `credits` is what was charged; `charges` splits it by node.
- `intel` has one entry per provider, `source` `fresh` (asked now) or
  `stored` (a fresh-enough stored answer the provider was not asked for).
- `kept` is whether the answers were stored in the dataset.

Each of these is `409` and **asks and charges nothing**:

| code             | when                                                     |
| ---------------- | -------------------------------------------------------- |
| `quote_invalid`  | unknown, another device's, expired, already spent, or a scan quote |
| `quote_mismatch` | the quote is for another address                         |
| `price_changed`  | a quoted provider is gone or its price moved: get a new quote |

A server older than this endpoint answers `404 not_found`: the app shows
"server too old" and keeps the stored-data lookup.

### `GET /api/v1/jobs/{job_id}`

A job this device queued. Any other id, another device's included, is
`404`. Poll with backoff (2 s or more); there is no push in v1.

`200`:

```json
{
  "job_id": "s_42",
  "kind": "scan",
  "ip": "203.0.113.9",
  "status": "done",
  "created_at": "2026-10-10T16:03:12Z",
  "result": { "scanned_at": "…", "ports": [{ "port": 22, "service": "ssh", "product": "OpenSSH" }] }
}
```

- `scan`: `status` is `queued`, `running`, `done` or `failed`. A job the
  queue gave up on (`superseded` by another, `refused`, or withdrawn because
  its audit entry could not be written) reports `failed`. `result` is
  `null` until the scan lands, then the shape of
  `scans[]` in `GET /api/v1/ips/{addr}`.
- `lookup`: always `done` with `result` `null`; the `POST` already
  answered (the job id is the quote id).
- `probe`: `status` is `running` while a vantage is queued or running,
  then `done`. `result` is `{ "vantages": [{ "node", "name", "state",
  "why", "rtt_ms", "ports": [{ "port", "protocol", "outcome", "detail" }] }] }`;
  `state` is `queued`, `running`, `done`, `declined` (with `why`) or
  `lapsed` (no result in 15 minutes, nothing charged). `node` is the
  scanner's id, empty standalone. Requests the node has not heard back on
  are kept in memory: after a restart, a vantage shows once its result
  arrives.

## Security notes (for reviewers)

- Pairing codes: 192-bit random, SHA-256 at rest, 5-minute TTL, single-use
  (consumed in the transaction that redeems them), never logged.
- Device tokens: 256-bit random, SHA-256 at rest, constant-time comparison
  via indexed hash lookup (the hash is the lookup key — no row scanning),
  revocable, `last_seen_at` updated at most once a minute.
- The bearer extractor is mounted on `/api/v1/*` only and never reads
  cookies; `SessionUser` never reads `Authorization`. Both directions have
  tests.
- `/api/v1/pair` is anonymous by design (the code is the credential) and is
  rate-limited per client IP like the login endpoints.
- Act endpoints: the `act` scope is checked in the extractor before any
  handler runs. A scan is bought only with a quote of the same device,
  spent by one `DELETE … RETURNING`, so a quote cannot be replayed or
  used by a second device. The audit log copies the device's name and
  pairing admin, so entries stay as they were after a revocation.
- Uploads (MIK-121): the endpoints read `uploads` only, never
  `upload_blobs`; their JSON has no content field (tested).
- CSP is unchanged: the QR is rendered server-side as inline SVG in the
  pairing page (`img-src 'self' data:` already permits it), no new JS.
