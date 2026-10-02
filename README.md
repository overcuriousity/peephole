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
  against editable TOML signature rules (`sqli`, `rce`, `traversal`, scanner
  user agents, …) into a severity 0–4. Floods are sampled, but every
  request still leaves at least a light row (time, method, path) or a count.
- **Enrichment** — MaxMind GeoLite2 country and ASN, the Tor exit list, and
  optionally AbuseIPDB, Shodan, Shodan InternetDB and GreyNoise, each within
  its own rate budget, refreshed when an IP returns.
- **Counter-scans** — rate-limited nmap scans in four levels that escalate by
  scope (more ports, `-sV`, `-O`, then safe discovery scripts), never by
  speed or aggressiveness. Bystanders are spared: one request earns at most a
  light scan, and verified crawlers, Tor exits, your own and `never_scan`
  networks are never scanned; per-network, per-ASN and queue budgets stop
  floods.
- **Wall of shame** (public) — aggregate statistics per time range, a world
  map, top IPs and networks, and a searchable IP directory (exact, prefix or
  CIDR) with per-IP geo, Tor status and counts. Request contents, scan results
  and fingerprints are never public; rule labels can be hidden too.
- **Admin area** (FIDO2 security keys only, no passwords) — request search
  and inspection, per-IP pages with every enrichment result and counter-scan,
  the live scan queue, browser-fingerprint correlation across IPs, the
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
  that sent requests of severity 3 or more in the last 24 hours (parameters
  `hours`, `min_severity`, `networks=1` to collapse busy /24s), one per
  line, for nginx `deny`, nftables, ipset, fail2ban or CrowdSec. In a
  cluster it is drawn from every member's trap, so one node's catch
  protects everybody's real sites. Tor exits, verified crawlers, cluster
  members and the node's own networks are never listed.
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
scanner, web interface), the admin domain, cluster membership and optional
API keys, writes `/etc/peephole/config.toml`, and starts a systemd service.
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

Configuration lives in `/etc/peephole/config.toml`
([annotated reference](deploy/config.example.toml)); signature rules are TOML
files in `/etc/peephole/rules` ([defaults](rules/)). Scan pace, rescan
cooldown and roles can also be changed at runtime from the admin area.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
