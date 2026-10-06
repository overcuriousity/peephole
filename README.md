<p align="center">
  <img src="assets/logo.svg" alt="peephole logo — a bloodshot eye peeping through a hole in a wall" width="160">
</p>

# peephole

A scan-the-scanners honeypot. peephole runs as the fallback vhost behind your
web stack: every request that matches no real site — vulnerability scanners,
exploit probes, internet-wide background noise — lands in the trap, is
classified and enriched, and the interesting sources get **scanned back** with
nmap.

[![CI](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml)

> [!WARNING]
> Counter-scanning is legally restricted in some jurisdictions, and scanning
> back can get your address reported for abuse — to your hosting provider
> among others. Check what applies to you before you deploy.

## Features

- **Trap** — records every request that reaches no real site, with headers
  and body, the raw request head as received, how it was answered and, over
  HTTPS, the raw TLS ClientHello and its JA4 fingerprint; and classifies it
  against TOML signature rules built into the binary — sixteen families from `sqli`,
  `rce` and path traversal to SSRF, webshells, deserialization and
  AI-infrastructure probes, each tagged with its OWASP reference (Top 10
  2021 class or Automated Threat) — into a severity 0–4. Floods are
  sampled, but every request still leaves at least a light row (time,
  method, path) or a count.
- **Enrichment** — MaxMind GeoLite2 country and ASN, the Tor exit list, and
  optionally AbuseIPDB, Shodan, Shodan InternetDB and GreyNoise, each within
  its own rate budget, refreshed when an IP returns.
- **Counter-scans** — rate-limited nmap scans in four levels that escalate by
  scope (more ports, `-sV`, `-O`, then safe discovery scripts), never by
  speed or aggressiveness. From level 2 they read the source's SSH host
  keys and TLS certificates, so sources that share one show up as linked.
  Bystanders are spared: one request earns at most a light scan, and
  verified crawlers, Tor exits, your own and `never_scan` networks are
  never scanned; per-network, per-ASN and queue budgets stop floods.
- **Tarpit** — for an hour after a source's request reaches severity 4,
  its requests get a slow-drip `200` that holds them up to 10 minutes, from
  a bounded pool of its own; the time held is recorded. Bystander and
  `never_scan` networks are never held.
- **Canaries** — decoys for the probes scanners send first (`.env`,
  `.git/config`, wp-login, phpinfo) serve realistic credentials derived
  from the request, with links back to the trap. When a harvested
  credential comes back, from any address to any node, the admin names the
  request that harvested it and the time in between.
- **Wall of shame** (public) — aggregate statistics per time range, shown
  after a delay (`[public] delay_minutes` plus up to `jitter_minutes` more,
  5 + 0–5 min by default) so the wall cannot be used to watch a scan live:
  trends against the previous period, scanner time wasted in the tarpit, requests over time
  by severity, a weekday × hour heatmap of the last 7 days, attack families and an OWASP Top 10 /
  Automated Threats map, a world map, top IPs and networks, the ports most
  often found open on the scanned sources, and a searchable IP directory
  (exact, prefix or CIDR). Each IP has its activity calendar, rank and
  neighbours (same /24 and ASN). The wall lists the latest requests as method
  and path only (no query string, cut at 80 characters). Bodies, headers,
  query strings and fingerprints are never public. Of the scan results only
  per-port counts of distinct IPs are, and a port only once it was found open
  on at least three. The card "What they asked our fake AI" shows only our
  own tool names and model names that are lowercased, match
  `[a-z0-9._:/-]{1,64}` and were asked by at least 2 IPs (else "other").
  Rule labels, and the families and OWASP tags derived from them, can be
  hidden too.
- **Admin area** (FIDO2 security keys only, no passwords) — request search
  and inspection (with the same IP's and same JA4's other requests), a live
  feed of new requests, analytics (top paths, user agents, JA4, methods,
  open ports, products, OS guesses, abuse scores; every row opens the
  matching requests or IPs), a search box for IPs, networks, AS numbers,
  requests, paths and fingerprints, per-IP pages with every
  enrichment result and counter-scan, the scan pace with the live queue and
  every finished job, a "needs attention" list on the Overview, a Links
  area (every browser fingerprint, SSH host key, TLS certificate, JA4, JA4H,
  HASSH and JA4X, filterable, each with a graph of the IPs it was seen on and
  what else links them), canary reuse, the
  false-positive inbox, deletion, and the dataset export: every request with
  everything known about it and its IP (enrichment history, scans,
  fingerprints) as typed Parquet, CSV or Timesketch JSONL, optionally
  without the results whose terms forbid passing them on. Every row says
  which node recorded it, by name and key, and which build it ran.
- **Dataset** — the whole thing as typed Parquet (or CSV / Timesketch JSON
  Lines): every request with headers, body, raw head, ClientHello and JA4,
  rule labels and severity, every enrichment lookup, counter-scan and
  fingerprint, plus which node and build recorded it. `peephole export`
  streams it from any node, a web node offers it under Admin → Export, and
  a "redistributable" mode strips the results whose terms forbid passing
  them on. Column by column in [docs/dataset.md](docs/dataset.md): built
  for machine learning on real scanner traffic.
- **Blocklist feed** (public) — `GET /api/blocklist` lists the addresses
  that sent requests of severity 3 or more in the last 24 hours, as released after the publication delay (parameters
  `hours`, `min_severity`, `networks=1` to collapse busy /24s), one per
  line, for nginx `deny`, nftables, ipset, fail2ban or CrowdSec. In a
  cluster it is drawn from every member's trap, so one node's catch
  protects everybody's real sites. Tor exits, verified crawlers, cluster
  members and the node's own networks are never listed. Every node
  documents its public endpoints at `/api` (linked in the footer).
- **Lookup** (admin) — ask every provider the cluster can reach about one
  address, now: this node's databases and keys first, then a member that
  announces the missing provider. Shown once, never stored.
- **Cluster** — several operators can share one dataset over mutual TLS:
  requests, the scan queue, results and lookups. Each node runs any mix of
  trap, scanner and web roles and decides for itself whom it trusts. A node
  may keep only the last N days (`retention_days`) while others keep the
  whole history. See [docs/cluster.md](docs/cluster.md).
- **Self-contained** — one binary with SQLite; fonts, scripts and the map are
  built in, light and dark themes, no external requests from the web pages.

## Running a node

Each node earns its keep for its operator: the blocklist feed built from
every member's trap for their own real sites, the whole dataset for their
own analysis or research, pooled enrichment (one member's MaxMind, AbuseIPDB
or Shodan key enriches everyone's view), and on-demand lookups of any
address through the cluster's providers. The trap itself also keeps scanner
noise out of the real sites' logs.

## Install

On a fresh Debian 12 / Ubuntu 22.04 or newer machine (x86_64 or aarch64):

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
```

The installer verifies the download, asks which roles the node runs (trap,
scanner, web interface), what is in front of the trap (nothing, so it takes
ports 80 and 443 itself; nginx on the machine; or a proxy elsewhere), the
admin domain, cluster membership and optional API keys, checks the ports are
free, writes `/etc/peephole/config.toml`, and starts a systemd service.
On request it also installs nginx with a Let's Encrypt certificate; otherwise
it writes a matching nginx example and prints the steps. Re-running it
upgrades in place and rolls back if the new version does not start.

Then open `https://<your-domain>/enroll` and register your first security key
with the one-time token the installer prints.

Details — unattended installs, the nginx setup, upgrades, day-to-day commands,
building from source and releases — are in
[docs/operations.md](docs/operations.md).

## How it fits

```
internet ──► nginx ──────────► (real sites)
                │
                ├─ :80, no matching site ──► peephole trap      127.0.0.1:8080
                ├─ :443, any other name ──► peephole trap TLS  127.0.0.1:8081
                │   (passed through untouched, PROXY protocol header)
                └─ :443, admin domain ────► nginx TLS ──► peephole web 127.0.0.1:8443
                                         peephole scanner ──► nmap ──► the source
```

On port 443 nginx routes by server name without decrypting, so the trap
terminates TLS itself and keeps the raw ClientHello and its JA4 fingerprint.
A trap-only node can also go without nginx and listen on 80 and 443 itself.

Configuration lives in `/etc/peephole/config.toml`
([annotated reference](deploy/config.example.toml)). The signature rules
([`rules/`](rules/)) ship inside the binary, so every node of a build
classifies alike and each request records which rules it was classified
with; changing them means a new build. Scan pace, rescan cooldown and roles
can also be changed at runtime from the admin area.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
