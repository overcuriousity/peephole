# Host keys in the export, ETags, reverse DNS

Four of the roadmap's small follow-ups, in one PR: host keys in the
export, ETags of scanned sources, ETags as a return marker, and reverse
DNS of every source.

No new replicated record or field and no cluster protocol bump: every
piece is derived on each node from data it already has, or travels in
fields that exist (`decoy_v`).

## 1. Host keys in the export

Each scan object in the `scans` JSON column gains `host_keys`:

```json
"host_keys": [{"kind": "ssh-hostkey", "port": 22, "fingerprint": "SHA256:…", "detail": "ed25519 256"}]
```

- Read from `host_keys WHERE scan_id IN (…)` in `PageContext` loading
  (`src/store/export.rs`), one query per page, grouped by scan like
  `ports`. Ordered by port, kind, fingerprint.
- Keys a probe found (`probe_id`, no `scan_id`) are not exported.
- No new column: CSV, JSON Lines and Parquet schemas are unchanged
  (`scans` is JSON text in all three).
- `docs/dataset.md` documents the field and its kinds, including the new
  `http-etag`.

## 2. ETags of scanned sources

**Parsing** (`src/scan/hostkeys.rs`). `extract` also reads the
`http-headers` script on a port. nmap writes its result as the script's
`output` attribute (one header per line) and, depending on the version,
as `<elem>` lines. Both are read; each line whose name is `ETag`
(case-insensitive) gives one `HostKey`:

- `kind`: `http-etag` (new constant `HTTP_ETAG`);
- `fingerprint`: the value as sent, trimmed, quotes and `W/` kept, capped
  at 128 characters;
- `detail`: empty, or, for the nginx form `"<hex>-<hex>"` whose first part
  is a plausible Unix time (2000 to now + 1 day), `nginx: modified
  YYYY-MM-DD, N bytes`.

Repeats on the same port and value are kept once.

**Reparse.** `scans.keys_parsed` turns from a flag into a version:
`HOSTKEYS_V = 2` in `scan::hostkeys`, `derive` stores it, and `backfill`
reads every scan with `keys_parsed < HOSTKEYS_V`. A reparse removes the
scan's old `host_keys` rows first, so nothing is duplicated. No migration
is needed (the column already holds integers; existing 1s are below 2).

**Level 2.** `profiles::IDENTITY_SCRIPTS` becomes
`ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers` (`http-headers` is in
`discovery` and `safe`: one HEAD or GET to a port nmap found open). The
previous level-2 list is appended to `profiles::ACCEPTED` so scans from
nodes not yet upgraded still earn.

**Links.** A new soft `LinkKind::HttpEtag` (key `etag`, name "HTTP ETag")
beside Favicon and JARM: listed on Links, never in `IDENTITY`, shown on
the IP and scan pages beside the host keys. Distro default pages share an
ETag across thousands of hosts; like the other soft kinds it says "same
file", never "same operator".

## 3. ETags as a return marker

The ETag is a canary: the existing canary machinery records it, finds it
again and links the two requests.

- **`canary::Kind::Etag`** (name `etag`): 32 lower-case hex characters
  from the page token's stream, served as the header
  `etag: "<value>"` (the S3 / MD5 shape). 32 characters is above
  `tokens::MIN`, and the quotes split it out as one token.
- **`DECOY_V = 3`.** Version 3 renders every version 2 answer as before,
  plus the `etag` header on the non-AI decoys that answer 200: `dotenv`,
  `git-config`, `git-head`, `wp-login`, `wp-login-failed`, `wp-admin`,
  `admin`, `phpinfo`, `git-refs`. Snapshots `v3-*.txt` are added beside
  v1/v2; v1 and v2 snapshots stay byte-identical.
- **`canary::served`** returns `(Kind::Etag, value)` for those names at
  version ≥ 3 (as well as their other canaries).
- **Finding it.** A client that revalidates sends `If-None-Match:
  "<value>"`. `tokens::of_request` already scans every header, so the
  token lands in `request_tokens` under `header:if-none-match` and joins
  the served canary like any other reuse: `canary_used_from` in the
  export, the canary pages, request and IP pages.
- **Mixed-version clusters.** An older node shown a `decoy_v = 3` row
  cannot render it and derives none of its canaries until it upgrades,
  as with version 2. No protocol change.

## 4. Reverse DNS of every source

**Resolver** (`src/scan/crawler.rs`). The PTR query and forward check are
split out: `confirmed_names(ip) -> Vec<String>` returns the PTR names
(at most 4 checked) whose forward lookup includes `ip`, valid host names
only (`intel::dns::valid_name`), with the existing timeouts.
`Crawlers::confirmed` keeps its behaviour and caching (crawler domains
only, fail-safe on a timeout of the crawler's zone).

**Worker** (new `src/intel/rdns.rs`, started beside the other background
tasks). Every minute, up to 50 IPs, 4 lookups at a time:

- an IP qualifies when it has a recorded request and either
  `ips.rdns_at IS NULL` or its newest request is more than 24 h after
  `rdns_at`;
- confirmed names are upserted into `ip_names` with `source = 'rdns'`,
  `agreed = 1`, `first_seen`/`last_seen` as for `ptr`; names no longer
  confirmed keep their row (last_seen tells how old it is);
- `rdns_at` is set whether or not a name was found; a resolver error or
  timeout also sets it, so a broken resolver costs one try a day per IP.

Migration `0025_rdns.sql`: `ALTER TABLE ips ADD COLUMN rdns_at TEXT`.

**Lifetime.** `drop_orphan_ip` deletes an IP's `rdns` names once no
request of it remains (as `ptr` names go with the last scan), so they
never keep an IP alive.

**Switch.** `[enrichment] reverse_dns = true` (default). With `false`, no
lookups run. Without a resolver in `/etc/resolv.conf` the worker does not
start.

**Shown.** The IP page lists `rdns` names with the others, marked
"reverse DNS". The admin IP directory gains a `name` filter: the IP has a
name (any source) containing the text. The export's `names` column
carries them with `source: "rdns"` (documented in `docs/dataset.md`).

## Docs

- `CHANGELOG.md`: an Unreleased entry for all four.
- `docs/roadmap.md`: the four items leave "Small follow-ups".
- `docs/dataset.md`: `host_keys` in scans, `http-etag`, `rdns` source,
  `etag` canary kind.
- `docs/scanners.md`: `http-headers` at level 2.

## Testing

Focused unit tests per piece:

- `http-headers` parsing from both `output` and `<elem>` forms, nginx
  date decoding, cap and dedupe (fixture `tests/fixtures/nmap-http-headers.xml`);
- reparse to `HOSTKEYS_V` removes and rebuilds a scan's rows;
- level-2 profile: new list built and accepted, old list accepted;
- v3 decoy snapshots; `served` at v3; a request with `If-None-Match`
  carrying a served ETag is found as a reuse through `derive_request`;
- export JSON of a scan with host keys;
- `confirmed_names` with a fake resolver and forward lookup; the worker's
  selection (new IP, returning IP, within 24 h), upsert, and
  `drop_orphan_ip` removing `rdns` names;
- IP directory `name` filter.

One full `cargo test` (lib and cluster) at the end.
