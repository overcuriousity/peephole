<p align="center">
  <img src="assets/logo.svg" alt="peephole logo: a door peephole whose ring carries three member nodes" width="160">
</p>

# peephole

*A cooperative honeypot network that no member has to trust.*

[![CI](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml)

peephole is a honeypot you run behind your web server, and a network of
such honeypots that share what they see. Each node catches the requests
that reach none of your real sites — vulnerability scanners, exploit
probes, background noise — classifies and enriches them, and can
investigate the sources. Nodes join a cluster over mutual TLS and
replicate one signed dataset. Operators need not know or trust each
other: every claim is checked against signed data, and shared work
(enrichment, lookups, scans) is paid in credits earned by doing work. In
return for running a node you get the cluster's blocklist for your real
sites, the whole dataset for your own analysis, and lookups through every
member's intelligence providers.

## How it works

- **A trap behind your web server.** peephole is the fallback for every
  request no real site claims, and records it in full, over HTTPS with the
  raw TLS ClientHello and its JA4 fingerprint.
- **Classified and enriched.** Signature rules built into the binary give
  each request labels and a severity from 0 to 4; the source gets its
  country, ASN, Tor status and registration data, and optionally AbuseIPDB
  and Shodan results. → [Detection](docs/detection.md)
- **Investigated, carefully.** An opt-in scanner role counter-scans
  sources with nmap, escalating by scope and never touching bystanders; a
  tarpit holds exploit senders, and decoys hand out canary credentials
  that give away whoever reuses them.
- **Shared without trust.** Every node holds the same signed dataset,
  checks what it receives, and decides for itself whom it trusts; nobody
  can be removed, only blocked locally. → [Protocol](docs/protocol.md)
- **Paid in credits.** Work one member does for another is bought with
  credits from a fixed daily pool and from selling. →
  [Credits](docs/overview.md#credits)

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
terminates TLS itself. A trap-only node can also go without nginx and
listen on 80 and 443 itself. It is one binary with SQLite; its web pages
make no external requests.

## What you put in, what you get back

You put in a machine with a trap in front of or behind your web server,
and optionally a scanner, a web interface and API keys (MaxMind, AbuseIPDB,
Shodan) that then enrich everybody's view.

You get back:

- **a blocklist** (`/api/blocklist`) drawn from every member's trap, for
  nginx, nftables, ipset, fail2ban or CrowdSec in front of your real sites;
- **the whole dataset** — every request with everything known about it and
  its source — as typed Parquet, CSV or Timesketch JSON Lines
  ([Dataset](docs/dataset.md));
- **lookups** of any address through every provider the cluster can reach;
- **a public dashboard** of what your cluster sees, delayed and aggregated
  ([What is public](docs/overview.md#what-is-public));
- scanner noise kept out of your real sites' logs.

## Risks

> [!WARNING]
> Counter-scanning is legally restricted in some jurisdictions, and scanning
> back can get your address reported for abuse — to your hosting provider
> among others. Check what applies to you before you deploy.

The scanner role is opt-in, and abuse reports go to the provider of the
node that scanned, not the trap's. The public dashboard names the addresses
that probed you. More in [Risks](docs/overview.md#risks).

## Install

On a fresh Debian 12 / Ubuntu 22.04 or newer machine (x86_64 or aarch64):

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
```

The installer verifies the download, asks which roles the node runs, what
is in front of the trap, the admin domain, the node's cluster name and
address, and an optional invite token and API keys, then starts a systemd
service; it can also set up nginx with a Let's Encrypt certificate.
Re-running it upgrades in place and rolls back if the new version does not
start. Then open `https://<your-domain>/enroll` and register your first
security key with the one-time token the installer prints. Details:
[Install](docs/operations.md#install).

## Documentation

| Page | For |
|---|---|
| [Overview](docs/overview.md) | deciding whether to run a node |
| [Protocol](docs/protocol.md) | how the cluster works, and why you need not trust it |
| [Dataset](docs/dataset.md) | using the exported data |
| [Operations](docs/operations.md) | installing and running a node |
| [Detection](docs/detection.md) | rules, enrichment, counter-scans |
| [Roadmap](docs/roadmap.md) | what is next |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT), at your option.
