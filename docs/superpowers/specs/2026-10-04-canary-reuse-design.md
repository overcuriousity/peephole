# Canary redesign and reuse detection

Roadmap item 1. One spec, one plan, one PR.

## Goal

When a credential served in a decoy comes back, from any IP to any node,
peephole names the request that harvested it and the time from harvest to
use. This links source addresses that the cluster cannot link today: in
the export of 2026-10-04 (19 hours, 4 nodes, 507 IPs), 28 of the 80 IPs
that fetched `.env` or `.git/config` sent that one request and nothing
else.

## Problems today

1. Every secret reads `canary-<ref>`; harvesters filter those out.
2. The decoys point nowhere: `APP_URL=http://localhost`, a git remote on
   `git.example.invalid`. A thief who tried them would never reach us.
3. A decoy served to a source over its recording rate leaves a light row
   without `page_token`, so its canaries cannot be traced (74 of 594
   decoy-eligible requests in the export, all from one IP).
4. Nothing looks for served canaries in later requests.

## Principle: determinism

Every decoy body is a pure function of

    (decoy_v, page_token, host, node_id, ts, method, path, answer)

all of which are stored with the row. No clock, no RNG, no secret, no
setting read at serve time. Consequences:

- Canary values come from a public derivation; any node and any dataset
  user can recompute the canaries of any row.
- Templates are versioned (`decoy_v`); a template change bumps it, old
  rows keep their meaning.
- The one decision that depends on cluster state (whether a login with a
  canary is accepted, which needs the serving row on this node) is
  recorded in `answer`.
- The tokenizer is versioned too (`tokens_v`), so a rule change re-runs
  the backfill instead of mixing rules.

No new setting. Deployers configure nothing for this feature.

## Data

### Request rows (replicated)

- New optional field `decoy_v INTEGER` in `requests` and in `RequestRec`
  (left out of the encoding when unset, like every later field). Null for
  non-decoys and for decoy rows recorded before this change; those are
  version 0 (`canary-<ref>` with `ref` the first 12 hex characters of the
  page token without dashes, as in `src/trap/decoy.rs` today). This PR
  writes version 1.

### Light rows (replicated)

- `skipped_requests` and `SkipRow` gain `page_token`, `host`, `answer`
  and `decoy_v`, set only when the request was answered with a decoy. An
  over-rate decoy is then rendered and traced like a full one.
- Requests past the light-row cap (`dropped`) stay counted only; their
  canaries cannot be traced. The hard cap stays.

### Derived tables (local, never replicated)

Built on each node from replicated rows, like `host_keys`.

- `canaries(value_hash BLOB, request_id, skipped_id, kind TEXT)`: one
  row per canary value served. Exactly one of `request_id` (full row) or
  `skipped_id` (light row, the `skipped_requests` rowid) is set. Index on `value_hash`.
- `request_tokens(value_hash BLOB, request_id, place TEXT)`: tokens from
  each full request (see Detection). Index on `value_hash`; unique on
  `(request_id, value_hash, place)`.
- `value_hash` is the first 8 bytes of SHA-256 of the value; neither
  table stores a credential in readable form.
- A reuse is the join `canaries ⋈ request_tokens` on `value_hash` where
  the using request is not the serving one. Δt is the using row's `ts`
  minus the serving row's. No stored link table: the join is always
  consistent with the rows present, in whatever order replication
  delivered them.
- Backfill: `canary_parsed INTEGER` on `requests` and on
  `skipped_batches`, holding the `tokens_v` the row was parsed with (0:
  not yet). One pass per row writes both its served canaries and its
  tokens, in the background like `keys_parsed`. Rows parsed with an older
  `tokens_v` are parsed again. History before this change gets `request_tokens` too,
  and version-0 decoy rows get their `canary-<ref>` values in `canaries`,
  so an old canary that turns up is still found.

## Decoy content, version 1

### Canary values

    raw = SHA-256("peephole-canary-v1\0" || page_token || "\0" || kind)

formatted per kind:

| kind | format |
|---|---|
| `aws-key` | `AKIA` + 16 characters of `A–Z2–7` |
| `aws-secret` | 40 characters of the base64 alphabet |
| `app-key` | `base64:` + base64 of the 32 bytes; the stored canary value is the base64 part |
| `db-password`, `redis-password`, `mail-password`, `admin-password` | 20 characters of `A–Za–z0–9` |
| `git-token` | 40 lowercase hex characters |
| `wp-session` | 43 characters of `A–Za–z0–9` (the token part of a WordPress `logged_in` cookie) |

Where `raw` has too few bytes for a format, the input is extended with a
counter (`… || "\0" || kind || "\0" || n`). No value contains the word
"canary".

### Names

- **Site**: `<word>.internal`, the word picked from a fixed list of 32
  (`shop`, `portal`, `crm`, `billing`, …, listed in the code and
  documented) by the first byte of `SHA-256("peephole-site-v1\0" ||
  node_id)` mod 32. Fixed per node, never resolves anywhere (`.internal`
  is reserved for private use).
- **Return host**: the request's Host (port included) if it is a public
  IP literal or a DNS name; otherwise (loopback, private, link-local,
  `localhost`, missing) the site. Public names and IPs demonstrably reach
  us: the scanner just used them.
- **Repo**: the site's word.

### Decoys

- **`.env`**: the current Laravel layout with every secret derived;
  `APP_NAME` from the site word; `APP_URL=https://<site>`; `DB_HOST` and
  `REDIS_HOST` stay `127.0.0.1` (real leaks look like that); new
  `ADMIN_URL=http://<return host>/admin/`, `ADMIN_USER=admin`,
  `ADMIN_PASSWORD=<admin-password>`.
- **`.git/config`**: `url = http://deploy:<git-token>@<return
  host>/git/<repo>.git`.
- **`.git/HEAD`**: unchanged.
- **phpinfo**: unchanged except the hostname in `System`, which becomes
  the site's word, matching the `.env`.
- **wp-login (GET)**: unchanged.

## Serving

Only a request that carries a canary is answered differently. Everything
else is answered exactly as before, so old and new rows stay comparable.

**Accepting a canary**: the trap hashes the submitted credential and
looks it up in `canaries` (one indexed read). Any served canary of any
kind is accepted. Requests without a credential in the places below skip
the lookup.

| Request | With a canary | Without |
|---|---|---|
| `POST …/wp-login.php`, password in `pwd` | `302` to `/wp-admin/`, `Set-Cookie: wordpress_logged_in_<hash>=<log>%7C<exp>%7C<wp-session>%7C<hmac>` as WordPress builds it (`<hash>` = 32 hex from SHA-256 of `https://<site>`; `<exp>` = the row's `ts` + 172800 s; `<hmac>` = 64 hex from SHA-256 of the other parts); the `wp-session` part is a canary of this request; `decoy:wp-login-ok` | unchanged: failed page, `decoy:wp-login-failed` |
| `GET /wp-admin/…` with a `wordpress_logged_in_*` canary cookie | static dashboard naming the site; `decoy:wp-admin` | unchanged: trap 404 |
| any path, `Authorization: Basic` whose password is a canary | static admin page naming the site; `decoy:admin` | unchanged (no `401` on common paths) |
| `GET /git/<repo>.git/info/refs?service=git-upload-pack`, Basic with a canary | ref advertisement (`main` and one tag, object IDs = 40 hex from SHA-256 of site and ref name); `decoy:git-refs` | `401`, `WWW-Authenticate: Basic realm="Git"` (git always asks without credentials first; only this exact path, which only a canary holder knows); `decoy:git-auth` |
| `POST /git/<repo>.git/git-upload-pack`, Basic with a canary | `500`, empty body; `decoy:git-pack` | trap 404 |

The git routes match the node's own repo word only.

**Precedence**, first match wins: the wp-login POST, wp-admin and git
routes; then a canary in Basic (admin page); then the existing decoys
(`.env`, `.git/config`, `.git/HEAD`, wp-login, phpinfo); then the trap
404.

**Known race**: recording runs after the answer, so a canary reused on
the same node within moments of being served, or before replication
brought its row, is answered as "without". That outcome is in `answer`;
detection still finds the reuse later through the join.

**Out of scope**: sessions beyond "this cookie is a canary", file
browsing, packfiles (roadmap item 5).

## Detection

One tokenizer, version `tokens_v = 1`, applied to each full request row.

### Places (`place`)

- **Headers, as thoroughly as possible**: every header name and value,
  from the parsed list and, for HTTP/1, from `raw_head` (catches
  duplicates, odd casing, lines the parser dropped). HTTP/2 rows use the
  parsed list including `:authority`. `place` is `header:<name>`
  (lowercase).
  - `Authorization`, `Proxy-Authorization`: Basic decoded and split into
    user and password; Bearer, Token and AWS SigV4 (`Credential=AKIA…/…`)
    values as they are.
  - `Cookie`: each value, percent-decoded.
  - `Referer`, `Origin`, `X-Forwarded-*`, `Forwarded`, and any value that
    parses as an absolute URL: userinfo, path and query split as for the
    request target.
  - Any value, or piece of one, that is valid base64 of printable text is
    decoded once and tokenized too.
- **`path`, `query`**: percent-decoded; `user:pass@` from absolute-form
  targets.
- **`body`**: the stored body; percent-decoded for form bodies, every
  string value for JSON, text parts for multipart, the raw text
  otherwise.

### Tokens

- Maximal runs of `[A-Za-z0-9+/=]`, plus their pieces split at `/`, `+`
  and `=`, of 16 to 128 characters.
- Each run taken raw and decoded (form bodies with a literal `+`).
- Deduplicated per request, at most 256 per request.
- Light rows are not tokenized (no headers or body).

### Matching

- 64-bit hashes; false matches negligible at this volume. The admin view
  shows the place so a human can check.
- A reuse from the serving request's own IP counts, marked "same
  source".

## Display

### Admin

- **Request page**: on a serving request, "Canaries served: N" with kind,
  value and return host; on a using request, "Used canary from request #N
  (node X, served Δt earlier), in `<place>`", linked; "same source" where
  it applies.
- **IP page**: "Credentials harvested here were used by N other IPs" and
  "Used credentials harvested by N other IPs", linked.
- **Canaries page** (nav, beside Fingerprints): for the period, served,
  reused, share reused, median and maximum Δt, per decoy kind; a reuse
  table, newest first (harvesting request: IP, node, decoy, time →
  using request: IP, node, place, time; kind; Δt), each side linked;
  filters for kind, node, same or different source, period. No graph
  (roadmap item 6 generalizes the fingerprints graph).
- **Analytics**: a link to the Canaries page.

### Public wall

One tile: median time from harvest to first use, and the share of
harvested credentials used again, for the selected period. Shown only
from 5 reuses up, so no single event can be read off the wall.

### Export

New columns `decoy_v` and `canary_used_from` (uids of the serving
requests, on rows that used a canary). Canary values are not exported;
the dataset docs give the formula to recompute them from `page_token`.

## Render command

`peephole decoy render <uid>` prints the decoy body a row was answered
with, recomputed from the row. The trap's live path and this command call
the same function.

## Testing

- **Determinism**: golden fixtures, byte-exact, for each decoy and
  answer from fixed inputs; a template change fails them until `decoy_v`
  is bumped. Live path and render command agree. Version 0 reproduced
  from an old row.
- **Derivation**: per kind, length, alphabet, prefix; no value contains
  "canary".
- **Return host**: public IPv4, IPv6 literal, name, with and without
  port, `localhost`, loopback, private, link-local, missing.
- **Tokenizer**: table of cases (Basic, Proxy Basic, Bearer, SigV4,
  cookies, base64 in a custom header, userinfo in Referer, duplicate
  headers in `raw_head`, form body with literal `+`, JSON, multipart)
  each finding its canary; a request without one yields no match; the
  cap holds on a large body.
- **Logins**: wp-login, wp-admin cookie, Basic and git, each with a
  canary and with a wrong value; requests without a canary answered
  exactly as before.
- **Cluster**: serve on node A, use on node B; both report the same
  reuse after replication, in either arrival order. A light-row decoy is
  traceable.
- **Backfill**: a store with existing rows gets `canaries` and
  `request_tokens` on upgrade; a `tokens_v` bump re-parses.

## Docs

- `docs/dataset.md`: `decoy_v`, `canary_used_from`, the derivation
  formula, the site word list, versions 0 and 1.
- `CHANGELOG.md`: Unreleased entries.
- `docs/roadmap.md`: item 1 moves to the changelog; new small follow-up
  "peer-observed public address" (replaces `cluster.own_addresses` for
  NAT'd nodes and records which of our addresses was hit; the canary
  return host can adopt it with a `decoy_v` bump).
