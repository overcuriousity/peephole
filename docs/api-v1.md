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
| `act`  | start probes, buy counter-scans, read their jobs (spends credits) |

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
in the dataset (a lookup that would ask providers stays an admin-UI action;
the API serves stored data only).

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
credits are spent.

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

## Act endpoints

Probes and paid counter-scans, the same actions as the Actions card on the
admin IP page, and with the same checks (target rules, probes off, live
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
  the "from X credits" of the Actions card and what the scan budget must
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
- CSP is unchanged: the QR is rendered server-side as inline SVG in the
  pairing page (`img-src 'self' data:` already permits it), no new JS.
