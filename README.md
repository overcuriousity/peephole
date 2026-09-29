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

Re-running the installer upgrades the binary and rules while leaving your
existing config untouched.

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
- **Admin dashboard** — FIDO2-only authentication (no passwords), wall-of-shame
  dashboard, request/IP detail views, live scan queue over SSE, and exports
  (CSV, Timesketch JSONL, Parquet).

## Configuration

Everything lives in `/etc/peephole/config.toml` — see
[`deploy/config.example.toml`](deploy/config.example.toml) for the annotated
reference. After editing, `systemctl restart peephole`.

Signature rules are plain TOML files in `/etc/peephole/rules` — edit or add
them without recompiling; see [`rules/`](rules/) for the shipped defaults.

## Operations

```sh
systemctl status peephole     # service status
journalctl -u peephole -f     # logs (incl. FIDO2 enrollment instructions)
```

## Building from source

Requires stable Rust. The test suite and release build:

```sh
cargo test
cargo build --release
```

Every push to `master` runs CI (fmt, clippy, tests) and publishes a fresh
binary to the rolling
[`latest` prerelease](https://github.com/overcuriousity/peephole/releases/tag/latest).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
