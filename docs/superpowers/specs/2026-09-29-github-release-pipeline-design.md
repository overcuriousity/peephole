# GitHub Publishing & Release Pipeline — Design

Date: 2026-09-29

## Decisions

- **Repo:** public, `github.com/overcuriousity/peephole`, existing history pushed to `master`.
- **License:** dual MIT / Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`), standard Rust practice.
- **Release model:** rolling `latest` prerelease. Every push to `master` compiles the release binary and publishes it to a GitHub prerelease named `latest`. The curl installer downloads from that prerelease.
- **Install script:** Debian/Ubuntu only (apt); fails loudly on other distros.

## Components

### 1. GitHub repo
`gh repo create peephole --public --source=. --push` using the existing local history. Default branch `master`.

### 2. GitHub Actions

**`.github/workflows/ci.yml`** — on push to `master` and on PRs:
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo build --release` (ubuntu-latest, stable toolchain, swatinem/rust-cache).

**`.github/workflows/release.yml`** — on push to `master`:
- `cargo build --release --locked` on ubuntu-latest.
- Package a tarball `peephole-x86_64-unknown-linux-gnu.tar.gz` containing: the `peephole` binary, `rules/` (default TOML signature rules), `deploy/peephole.service`, `deploy/config.example.toml`; plus a `sha256` checksum file.
- Create/update a rolling prerelease tagged `latest` (via `gh release`, deleting/recreating the tag) with the tarball + checksum as assets.

### 3. Dependabot
**`.github/dependabot.yml`** — weekly updates for `cargo` and `github-actions` ecosystems.

### 4. install.sh (repo root)
`curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash`

Steps:
1. Require root + apt-based system; detect non-interactive stdin (fail with message).
2. `apt-get install` prerequisites: `nmap`, `curl`, `ca-certificates`, `sqlite3`.
3. Download the latest prerelease tarball, verify sha256, extract; install binary to `/usr/local/bin/peephole`.
4. Create `/var/lib/peephole`, `/etc/peephole/rules`; install the bundled TOML rule files into `/etc/peephole/rules` (without overwriting existing ones).
5. Prompt for MaxMind account ID + license key, admin domain (WebAuthn `rp_id`/`origin`), trusted proxy CIDRs (default `10.0.0.0/8`). Env overrides: `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `PEEPHOLE_DOMAIN`, `PEEPHOLE_TRUSTED_PROXIES`.
6. Render `/etc/peephole/config.toml` from `deploy/config.example.toml` with those values.
7. Install `deploy/peephole.service` to `/etc/systemd/system/peephole.service`, `daemon-reload`, `enable --now`.
8. Print next steps (enrollment URL/token location, nginx/HAProxy notes).

### 5. README.md
Project description (scan-the-scanners honeypot), badges, one-line installer, architecture summary (trap listener behind HAProxy, admin behind nginx, FIDO2-only auth), config reference pointer, license section (dual MIT/Apache-2.0).

## Error handling
- install.sh: `set -euo pipefail`, explicit checks for root/apt/network, clear failure messages.
- release.yml: prerelease update is idempotent (delete + recreate `latest`).

## Testing
- CI runs the existing `tests/integration.rs` suite.
- install.sh syntax-checked with `bash -n` and `shellcheck` (if available) in CI.
- Local `cargo build --release` must pass before pushing.
