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
| `act`  | reserved for act endpoints (not in v1)           |

`read` is always granted at pairing; `act` is optional and has no effect in
v1 (no endpoint requires it yet). A missing or wrong scope is `403`.

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
| 400    | `invalid`      | malformed body, bad address, bad cursor           |
| 401    | `unauthorized` | no/expired/revoked token, dead pairing code       |
| 403    | `forbidden`    | token lacks the required scope                    |
| 404    | `not_found`    | address not in the dataset                        |
| 429    | `rate_limited` | per-IP limit hit (`Retry-After` header is set)    |
| 500    | `internal`     | storage failure; message is generic, never a leak |

Secrets (tokens, codes) never appear in error bodies or logs.

## Endpoints

All require `Authorization: Bearer <token>` with scope `read`.

### `GET /api/v1/ips?q=&cursor=&limit=`

Paged list/search over the IPs in the dataset — the same data the admin
IPs page shows.

- `q` — free text: an exact IP, a network (`203.0.113.0/24`), or a string
  prefix. Empty lists everything.
- `cursor` — opaque continuation token from the previous page's
  `next_cursor`. A cursor is bound to the `q` it was issued with.
- `limit` — page size, default 50, max 100.

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
    "internetdb": { "fetched_at": "…", "data": { } },
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

- `intel` — newest stored answer per provider (`data` is the provider's
  parsed JSON as stored; `null` when the provider never answered). Tor is not
  an entry here: `is_tor` comes from the exit list the node loads.
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
- CSP is unchanged: the QR is rendered server-side as inline SVG in the
  pairing page (`img-src 'self' data:` already permits it), no new JS.
