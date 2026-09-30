<p align="center">
  <img src="assets/logo.svg" alt="peephole logo — a bloodshot eye peeking through a hole" width="200">
</p>

# peephole

A scan-the-scanners honeypot. peephole sits behind your web stack as the
fallback vhost: every request that matches no real site — vulnerability
scanners, exploit probes, internet-wide background noise — lands in the trap.
Requests are classified against TOML signature rules, enriched with GeoIP and
Tor-exit intelligence, and the interesting ones get **scanned back** with nmap.

[![CI](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml)
[![Release](https://github.com/overcuriousity/peephole/actions/workflows/release.yml/badge.svg)](https://github.com/overcuriousity/peephole/actions/workflows/release.yml)

**Think twice before deploying this!**
While I find it ethically ok to scan anybody who scans you, be aware that this procedure might be illegal in some jusrisdictions, and may get your ip-address flagged for abuse. Deploy mindfully!

## Install

One line, on a fresh Debian/Ubuntu machine:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
```

The installer:

- installs prerequisites (`nmap`, `curl`, `ca-certificates`, `sqlite3`),
- downloads and checksum-verifies the latest build,
- installs the binary to `/usr/local/bin/peephole` and the default signature
  rules to `/etc/peephole/rules`,
- asks for your **MaxMind GeoLite2 account ID and license key**
  (get them at <https://www.maxmind.com/en/accounts/current/license-key>),
  the public domain of the admin dashboard, and your trusted proxy CIDRs,
- writes `/etc/peephole/config.toml` and installs + starts a systemd service.

Non-interactive installs can pass the answers as environment variables:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | \
  sudo MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=yourkey \
       PEEPHOLE_DOMAIN=peephole.example.net bash
```

Re-running the installer upgrades in place: it skips when the installed
version already matches, validates your existing config with the new binary
before restarting, waits for `/healthz`, and rolls back to the previous
binary if the service does not come up. Shipped rule files are treated like
conffiles — a rule you edited is kept and the new upstream version is placed
beside it as `<name>.toml.new`. Your config is never rewritten.

The installer also drops `deploy/nginx.example.conf` into `/etc/peephole/`.
Use it as the basis for the TLS vhost: the live scan queue is streamed over
Server-Sent Events, which needs `proxy_buffering off` on `/admin/api/queue`
or the queue never updates behind nginx.

Published binaries are built on Ubuntu 22.04 and run on Debian 12 / Ubuntu
22.04 or newer (glibc ≥ 2.35).

## Architecture

```
internet ──► HAProxy ──► (real sites)
                │
                └─ fallback route ──► peephole trap listener  :8080  (public)

internet ──► nginx (TLS) ──► peephole admin listener  127.0.0.1:8443
```

- **Trap listener** — receives fallback traffic from HAProxy, classifies
  requests with the signature rules in `/etc/peephole/rules`, enriches with
  MaxMind GeoLite2 + Tor exit list, queues counter-scans.
- **Scanner** — rate-limited nmap counter-scans of caught scanners
  (configurable levels, cooldowns, and never-scan CIDRs).
- **Wall of shame** (public, no login) — aggregate statistics per time range,
  a choropleth map, a searchable IP directory (exact / prefix / CIDR), per-IP
  request history and request search. No query strings, payloads, headers,
  fingerprints or scan results are ever public: a legitimate client that
  mistypes an API URL would otherwise publish its credentials. Credentials
  embedded in the URL path itself are still shown.
- **Admin area** (FIDO2 only, no passwords, under `/admin`) — live scan queue
  over Server-Sent Events, counter-scan results with ports and raw nmap XML,
  raw request headers and bodies, fingerprint correlation across IPs, the
  false-positive inbox, exports (CSV, Timesketch JSONL, Parquet), key
  management, and deletion of records (single, checked, or everything
  matching a filter).

Both sites follow the system light/dark preference (with a manual toggle),
ship their fonts, scripts and map inside the binary, and make no external
requests.

## Configuration

Everything lives in `/etc/peephole/config.toml` — see
[`deploy/config.example.toml`](deploy/config.example.toml) for the annotated
reference. After editing, `systemctl restart peephole`.

Signature rules are plain TOML files in `/etc/peephole/rules` — edit or add
them without recompiling; see [`rules/`](rules/) for the shipped defaults.

## Operations

```sh
systemctl status peephole                     # service status
journalctl -u peephole -f                     # logs (incl. FIDO2 enrollment instructions)
peephole --version                            # installed build
peephole check-config /etc/peephole/config.toml   # validate config, rules and nmap
```

Additional FIDO2 keys can be enrolled from **Admin → Keys** while logged in;
the one-time setup token is only needed for the very first key.

## Building from source

Requires stable Rust. The test suite and release build:

```sh
cargo test
cargo build --release
```

The world map served on the wall of shame is a generated asset; see
[`assets/README.md`](assets/README.md) for provenance and how to regenerate it.

Every push to `master` runs CI (fmt, clippy, tests, an installer smoke test
in a container) and publishes a fresh binary to the rolling
[`latest` prerelease](https://github.com/overcuriousity/peephole/releases/tag/latest).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
