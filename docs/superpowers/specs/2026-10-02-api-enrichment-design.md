# peephole — API enrichment providers

Date: 2026-10-02
Status: approved by user (brainstorming complete)
Builds on: `docs/superpowers/specs/2026-10-01-federated-cluster-design.md` §6
(enrichment as replicated per-IP results) and the `Provider` interface in
`src/intel/provider.rs`.

## 1. Goal

Four API-backed providers join MaxMind and the Tor list behind the existing
`Provider` interface:

| Provider name | Service | Key | Answers |
|---|---|---|---|
| `abuseipdb` | AbuseIPDB `/api/v2/check` | required | abuse confidence score, reports, reporters, last report, usage type, ISP, domain, report categories |
| `shodan` | Shodan `/shodan/host/{ip}` | required (membership) | ports, services (product/version), OS, org/ISP, hostnames, domains, tags, CVEs, last update |
| `shodan-internetdb` | `internetdb.shodan.io/{ip}` | none | ports, CPEs, hostnames, tags, CVEs (weekly snapshot, IPv4 only) |
| `greynoise-community` | GreyNoise `/v3/community/{ip}` | optional | noise, riot, classification, actor/provider name, last seen |

Success means:

- Every IP is looked up by one node of the cluster per provider, and only by a
  node configured for that provider. The result reaches every member.
- A daily or weekly quota is never exceeded by a node's own lookups, and a
  node whose quota runs out hands the work to another node with a key.
- Each lookup is kept in a replicated, append-only history with a UTC
  timestamp, as part of the research dataset.
- The admin IP page shows every provider's result. The admin IP list filters
  and sorts by them.

Spur.us is out of scope (no free API tier). Reporting to AbuseIPDB is out of
scope.

## 2. Decisions locked during brainstorming

- **Look-ups are once per IP, with refresh on return.** The first lookup
  happens when the IP is first seen. After `k` lookups the IP is due again
  only if it is seen again at least `N × 1.5^(k−1)` days after the last
  lookup (N = `[enrichment] refresh_after_days`, default 30): N, 1.5 N,
  2.25 N, … An IP that never comes back is never looked up again.
- **Order: newest first.** Candidates are processed by `last_seen`
  descending, so a returning IP and a fresh one go ahead of the backlog.
  The backlog of IPs stored before a provider was enabled is processed
  last, as quota allows.
- **Protocol: successes only, replicated.** Each answered lookup (including
  "nothing known") is one `ip_intel` record and one row in an append-only
  history. Failed attempts (quota, network, 5xx) are not recorded in the
  dataset; they are in the node's log file.
- **All four providers are admin-only.** Their results are never on public
  pages or in public filters (`ProviderInfo::public = false`). This keeps
  open ports and abuse reports off the wall of shame, and stays clear of
  the providers' redistribution terms.
- **InternetDB is opt-in and non-commercial.** It needs no key, so it would
  otherwise start talking to a new third party after an upgrade. It skips
  IPs that already have a Shodan host result.
- **Keys are strictly local.** They are in the node's TOML (mode 0600) and
  never replicated, announced, or logged. Nodes only announce provider
  names in heartbeats.

## 3. Scheduling

### 3.1 Who looks up

Unchanged from the cluster spec. Each node announces in its heartbeat the
providers that are `ready()`. For each provider, the live, unblocked nodes
announcing it rank themselves (dialable first, then by key). Rank 0 acts at
once. Rank `r` acts only on IPs that have been due for at least `r × 10`
minutes.

`ready()` is false while a provider's quota is used up, while it is backing
off after errors, or after the service rejected its key. The node then
stops announcing it, and the next node becomes rank 0. Two nodes sharing a
key cannot see each other's use, so the service's own 429 answer is what
takes a node out.

Because lookups are slow (a pace of one request per second), each API
provider runs in its own task. A slow provider never holds up MaxMind or
another provider.

### 3.2 Which IPs are due

For provider `p`, an IP is due when it is not on the node's skip list and:

- it has no result from `p` (from any node), or
- refresh is on (`N > 0`), it has `k ≥ 1` results from `p` in the history,
  the newest at time `t`, and `last_seen ≥ t + N × 1.5^(k−1)` days.

It has been due since `first_seen` (no result) or since the refresh time
`t + interval` (refresh).

InternetDB: an IP with a `shodan` result is never due. While any live node
announces `shodan`, InternetDB waits an extra 15 minutes, so Shodan gets
the IP first.

Candidates are fetched newest `last_seen` first, a batch at a time.

### 3.3 What is never sent

- Addresses that are not globally routable (`net::is_global`): private,
  loopback, CGNAT, documentation, and similar. They are kept off the
  candidate list for the life of the process and are never recorded.
- IPv6 addresses for providers that do not support them (InternetDB,
  GreyNoise Community).
- An IP the service rejected (HTTP 400/422) is skipped for 24 h, so a bad
  entry at the head of the queue cannot block it.

### 3.4 Quotas and pacing

| Provider | Pace | Default budget | On 429 |
|---|---|---|---|
| AbuseIPDB | 1 req/s | 1,000 per UTC day (`daily_limit`) | pause until `X-RateLimit-Reset` (else next UTC day) |
| Shodan host | 1 req/s | none (`daily_limit` optional) | back off 1 min, doubling to 1 h |
| InternetDB | 1 req/s | none (`daily_limit` optional) | back off 1 min, doubling to 1 h |
| GreyNoise | 1 req/s | with key 50 per ISO week, without 10 per UTC day (`daily_limit` / `weekly_limit` override) | pause until the next period |

- Use is counted per node in `intel_meta`, per period, so a restart does not
  reset the budget.
- AbuseIPDB's `X-RateLimit-Remaining` overrides the local count when it is
  lower.
- Network errors and 5xx: provider-wide back-off, 1 min doubling to 1 h. The
  IP is not marked and is retried.
- 401/403: the key is rejected. The provider stays off until restart and
  logs one warning.

## 4. Data

### 4.1 Records

No new record kind. Each lookup is an `ip_intel` record (`IpIntelRec`):
`provider` is one of the four names, `fetched_at` is the UTC time of the
lookup (`YYYY-MM-DD HH:MM:SS`), and `data_json` is the compact result
below. API providers write a record for every lookup, even when the result
is unchanged; MaxMind and Tor keep deduplicating.

`data_json` is capped at 16 KiB when written. Records from peers larger than
32 KiB are ignored on apply.

### 4.2 Result shapes

Absent fields are left out. `{}` means the provider knows nothing about
the IP (404).

- `abuseipdb`: `score` (0–100), `reports`, `reporters`, `last_reported_at`,
  `usage_type`, `isp`, `domain`, `whitelisted`, `categories` (distinct
  category names from the reports in the last `max_age_days`, default 90).
- `shodan`: `ports`, `services` (≤ 64 × `{port, transport, product,
  version, module}`), `os`, `org`, `isp`, `asn`, `hostnames`, `domains`,
  `tags`, `vulns` (≤ 100 CVE ids), `last_update`. Banners are not stored.
- `shodan-internetdb`: `ports`, `cpes`, `hostnames`, `tags`, `vulns`.
- `greynoise-community`: `noise`, `riot`, `classification`, `name`,
  `last_seen`. A 404 ("not observed") is stored as
  `{"noise": false, "riot": false}`.

### 4.3 Tables

- `ip_intel` (unchanged): newest result per (ip, provider, origin).
- `ip_intel_log` (new, replicated content): one row per applied `ip_intel`
  record, keyed `(ip, provider, origin, hlc)`. Backfilled from `ip_intel`.
  Deleted together with `ip_intel` on IP erase, on peer block (restored on
  unblock with the rest of the peer's records), and re-owned on adoption.
- Local read models (not replicated, rebuilt by `refresh_ip_view`):
  - `ips.abuse_score`: newest AbuseIPDB score, NULL if none.
  - `ip_intel_tags(ip, tag)`: tags from the newest result of each provider,
    written as `provider:tag` (`shodan:vpn`, `greynoise:malicious`,
    `abuseipdb:Port Scan`, `abuseipdb:usage:Data Center/Web Hosting/Transit`).

## 5. Web interface

- IP page: one admin-only card per provider, with the per-node history
  shown by the existing "older or other-node results" disclosure. Lists
  (ports, tags, CVEs, categories) are rendered as comma lists. CVE ids and
  ports are monospaced.
- Admin IP list (`/ips` with a session):
  - filter `min_abuse` (minimum AbuseIPDB score);
  - sort `abuse` (score descending, NULLs last);
  - filter `tag` (choice of the tags present in `ip_intel_tags`);
  - filter `intel=<provider>` / `nointel=<provider>` (has or lacks a
    result from that provider).

  These parameters are ignored without a session.
- Admin cluster page: per node, which providers it announces (already
  shown), plus this node's quota use for each provider.
- Export: the intel export gets a "full lookup history" variant that streams
  `ip_intel_log`.

## 6. Configuration and installer

```toml
[enrichment]
refresh_after_days = 30   # N; 0 = never refresh

[abuseipdb]
api_key = "…"
# daily_limit = 1000
# max_age_days = 90

[shodan]
api_key = "…"            # host lookups need a membership or paid plan
# daily_limit = 0         # 0 = no local cap

[internetdb]
enabled = true            # free, no key, non-commercial use only

[greynoise]
api_key = ""              # optional; empty = unauthenticated (10/day)
# daily_limit / weekly_limit override the defaults
```

A missing section means the provider is off. An empty `api_key` is rejected
for AbuseIPDB and Shodan.

Installer (first install only), after the MaxMind prompt and marked as
optional, each with a one-line note on what it gives and its limits:

- `ABUSEIPDB_API_KEY`
- `SHODAN_API_KEY`
- `GREYNOISE_API_KEY`. An empty answer leaves GreyNoise off. The prompt
  says that free keys need a business email.
- `PEEPHOLE_INTERNETDB` (y/n, default y, with a non-commercial note).

The example config documents all sections commented out.

## 7. Security notes

- The Shodan key is a query parameter. Errors are logged with
  `reqwest::Error::without_url()`, and no request URL is logged anywhere.
- Responses are parsed into the compact shapes above. Raw bodies are never
  stored or logged, and response bodies are read with a 1 MiB cap.
- Peer-supplied results are rendered through askama's escaping, as now.
- Looking up an IP tells the provider which IPs reached this node. This is
  accepted; it is how these services work.
