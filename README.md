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

**Think twice before deploying this!**
While I find it ethically ok to scan anybody who scans you, be aware that this procedure might be illegal in some jusrisdictions, and may get your ip-address flagged for abuse. Deploy mindfully!

## Install

One line, on a fresh Debian/Ubuntu machine:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
```

That installs the rolling build of `master`. A versioned release is
immutable; install one with the installer from the same tag:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/v0.1.0/install.sh | \
  sudo PEEPHOLE_VERSION=v0.1.0 bash
```

The installer:

- installs prerequisites (`nmap`, `curl`, `ca-certificates`, `sqlite3`),
- downloads the build for the machine (x86_64 or aarch64) and verifies its
  checksum; with the GitHub CLI (`gh`) installed it also verifies the
  build's provenance attestation (`PEEPHOLE_VERIFY=1` makes that required,
  `0` skips it), and prints the commit the binary was built from,
- installs the binary to `/usr/local/bin/peephole` and the default signature
  rules to `/etc/peephole/rules`,
- asks what this node should do:
  - run a **trap** (record requests that reach no real site), the
    **scanner** (nmap counter-scans), the **web interface** (wall of shame
    and admin area), in any combination,
  - whether a reverse proxy on the same machine fronts the trap, and
    otherwise which proxy addresses to trust,
  - the public domain of the admin area (with the web interface),
  - whether to take part in a **cluster**: node name, addresses, an invite
    token if you have one, and whether holders of this node's **config key**
    may change its settings,
  - optional **MaxMind GeoLite2** credentials
    (<https://www.maxmind.com/en/accounts/current/license-key>),
- writes `/etc/peephole/config.toml` and an nginx example that fits the
  answers to `/etc/peephole/nginx.example.conf`, and installs and starts a
  systemd service.

It does not install or change nginx. The example has a TLS server block for
the admin area (the live scan queue needs `proxy_buffering off` on
`/admin/api/queue`, which the example sets; `/login` and `/enroll` are rate
limited), a 443 `default_server` that refuses TLS for every other name
(`ssl_reject_handshake`, nginx ≥ 1.19.4, so the admin certificate is never
shown to scanners; the example shows how to trap HTTPS instead), and a
catch-all `default_server` on port 80 that sends everything no real site
claims to the trap. The catch-all sets
`X-Forwarded-For` to the real peer address, so a client cannot spoof it. The
installer prints the nginx steps in the order that works on a stock
Debian/Ubuntu nginx: get the admin site's certificate
(`certbot certonly --nginx`) while the default site still serves, remove
`/etc/nginx/sites-enabled/default` (it also claims `default_server`), then
enable the example and reload. If you front peephole with HAProxy instead,
route its fallback backend to the trap listener and list the proxy in
`trusted_proxies`.

Non-interactive installs can pass the answers as environment variables:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | \
  sudo MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=yourkey \
       PEEPHOLE_DOMAIN=peephole.example.net bash
```

Every question has a variable (`PEEPHOLE_ROLES`, `PEEPHOLE_LOCAL_PROXY`,
`PEEPHOLE_CLUSTER`, `PEEPHOLE_CLUSTER_NAME`, `PEEPHOLE_JOIN_TOKEN`,
`PEEPHOLE_REMOTE_CONFIG`, …; see the head of `install.sh`).

Re-running the installer upgrades in place: it skips when the installed
version already matches, validates your existing config with the new binary,
backs up the database (`/var/lib/peephole/backup-<time>.db`, the two newest
are kept), restarts, waits for `/healthz` (or for systemd to report the
service up), and if the new version does not come up rolls back the binary,
the rules, the unit and — when the new version changed its schema — the
database, then checks the old version is running again. Shipped rule files
and the systemd unit are treated like conffiles: a file you edited is kept
and the new upstream version is placed beside it as `<name>.new`. Keep your
own service settings (sandboxing, limits) in a drop-in
(`systemctl edit peephole`), which upgrades never touch. Your config and
nginx example are never rewritten.

Published binaries (x86_64 and aarch64) are built on Ubuntu 22.04 and run on
Debian 12 / Ubuntu 22.04 or newer (glibc ≥ 2.35).

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
  (configurable levels, cooldowns, and never-scan CIDRs). Scans are
  non-intrusive by design: no `-A`, no intrusive NSE scripts, timing capped
  at `-T3`. Severity escalates by *scope* (more ports, `-sV`, `-O`, then
  discovery/safe scripts that neither contact third parties nor
  broadcast), not by speed. Bystanders are spared: one request earns at
  most a light scan (a link preview or URL scanner may have fetched the
  trap), forward-confirmed crawlers, Tor exits and this node's own
  addresses are never scanned, and per-network, per-ASN and queue budgets
  stop floods. The Tor exit list covers IPv4 only.
- **Wall of shame** (public, no login) — aggregate statistics per time range,
  a choropleth map, top attacking IPs and networks, and a searchable IP
  directory (exact / prefix / CIDR) with per-IP geo, counts and max severity.
  Individual request rows are never public: no request paths, query strings,
  payloads, headers, fingerprints or scan results. The public side names the
  IPs it shames but not what each one requested; `/api/stats` carries only
  aggregates. The coarse rule categories an IP's requests matched (labels
  such as `sensitive-path` or `sqli`) are public unless
  `[public] show_labels = false` hides them (per-IP chips, the label filter
  and the label chart). Anonymous visitors are rate limited per address and
  see cached pages.
- **Admin area** (FIDO2 only, no passwords, under `/admin`) — everything the
  public side withholds: the full request search and per-IP request history,
  the live scan queue over Server-Sent Events, counter-scan results with
  ports and raw nmap XML, raw request headers and bodies, fingerprint
  correlation across IPs, the false-positive inbox, exports (CSV, Timesketch
  JSONL, Parquet), key management, and deletion of records (single, checked,
  or everything matching a filter).

Both sites follow the system light/dark preference (with a manual toggle),
ship their fonts, scripts and map inside the binary, and make no external
requests.

## Distributed mode

Several deployments can form a cluster that shares one dataset: every
request, the scan queue, scan results and what is known about each IP. The
operators do not need to know or trust each other. Each node runs any
combination of three roles, set in `[roles]`:

| Role | Does | Needs |
|---|---|---|
| `listener` | the trap: records and classifies requests, queues scans | `trap_listen`, `rules_dir` |
| `scanner` | runs nmap for jobs from any trap | nmap |
| `web` | wall of shame and admin area | `admin_listen`, `[webauthn]` |

Every node keeps a full copy of the dataset, so any web node shows the
whole cluster. Scanners take jobs from any trap; jobs go to the scanner
with the fewest recent scans.

Enable it with a `[cluster]` section (see the example config), then add
nodes:

```sh
peephole cluster id                       # this node's key
peephole cluster invite --label friends   # on a member: a reusable invite (a week, 10 uses)
peephole cluster invites                  # list them; invite-revoke <id> closes one
peephole cluster join <token>             # on the new node; or Admin → Cluster
peephole cluster members                  # who is in, and their standing
peephole cluster block <node>             # this node ignores a peer (unblock undoes it)
peephole cluster block --subtree <node>   # ... and every node it admitted, transitively
peephole cluster purge <node>             # delete a blocked peer's data here, stop relaying it
peephole cluster leave                    # this node leaves; it keeps its data
```

Nodes talk HTTP/2 over mutual TLS with pinned Ed25519 keys on
`cluster.listen` (default port 7443). A node without `advertise` is
outbound-only: it dials its peers and still syncs both ways. Peers can also
be listed under `[[cluster.peers]]` with their key.

How trust works:

- **Nobody can remove a node.** A node leaves by itself. A member that
  shows no sign of life for 30 days is pruned by every node on its own and
  rejoins with an invite.
- **An invite is reusable** until it expires, reaches its use limit or is
  revoked: by default after a week or 10 uses (`--ttl 0` / `--uses 0`
  lift a limit). Whoever holds a usable invite can join and cannot be
  removed afterwards. A member admits at most 20 new nodes a day; a node
  that left admits nobody.
- **Blocking is local.** A node that blocks a peer stops talking to it and
  shows none of its records. It still stores and relays them, so other
  nodes are unaffected. `--subtree` (or "Block with all it admitted" on
  the Cluster page) also blocks every node it admitted. Purging a blocked
  peer deletes what this node holds of it and stops relaying it.
- **Each node judges for itself.** Timestamps from the future count as of
  receipt; scan jobs must name a public address and a known level, at most
  2000 per member and hour; a member's jobs move to another arbiter only
  once this node, too, sees the arbiter silent (or the job untouched) for
  `takeover_hours`. Entries of a node nobody admitted are parked only up to
  100 per node and dropped after a week. `cluster.origin_quota_mb`
  (default 20 GiB) caps what one member's entries may take on this node.
- **Deletes reach your own records only.** Deleting something your node
  recorded removes it on every node. Deleting something another node
  recorded hides it on your node only.
- **The dataset is persistent.** What a node contributed stays when it
  leaves or is pruned. `scan.retention_days` applies to standalone nodes
  only; a cluster node's database grows with the cluster. To bound it
  cooperatively, a node can opt in to `cluster.retention_days`: it then
  deletes its *own* requests and scan results older than that, on every
  node. The log itself is never compacted: a node joining later fetches it
  in full from any member.

Changing another node's settings:

- A node's scan pace, rescan cooldown and roles are runtime settings. Its
  own admin (Cluster page, or `peephole settings set|reset|show`) can always
  change them, and roles switch without a restart.
- With `remote_config = true` under `[cluster]`, the node has a **config
  key** (`peephole cluster config-key show`). Whoever holds it can change
  those settings from their own node: paste the key on their Cluster page,
  or `peephole cluster config-key add <key>`.
- `peephole cluster config-key rotate` replaces the key and withdraws the
  permission from everyone at once. The node lists who changed what.
- Nothing else is changeable from outside: addresses, paths, WebAuthn, API
  keys, `never_scan`, nmap arguments and `remote_config` itself stay in the
  config file.

Things to know:

- Counter-scans come from the scanner node's address, not the trap's. Abuse
  reports go to that node's hosting provider.
- `scan.never_scan` protects what you do not want your own scanner to
  touch. It applies only on the node that sets it; other scanners may still
  scan those addresses. Scanners never scan the addresses of cluster
  members (published ones, and the ones members connect from).
- A scanner checks each job an arbiter grants against its own copy of the
  job and runs it only when requests it holds back the level;
  `scan.trusted_origins` limits whose requests count.
- Every member sees everything the cluster records, including raw requests
  and false-positive claims with their optional contact address.
- Run NTP on every node: cooldowns and the 30-day prune compare timestamps
  written by different nodes. The Cluster page flags clock differences.
- A standalone node that joins brings its history with it.
- Node names and keys appear only in the admin area, never on public pages.
- GeoIP: a node with MaxMind credentials downloads the GeoLite2 databases
  for itself. The databases are never passed on. That node looks up the IPs
  the other nodes recorded and shares the results, so one member with
  credentials is enough; without any, the dataset has no GeoIP data. The Tor
  exit list is public and is fetched by one node for all. Every result
  records which provider and which node it came from (Admin → Export).

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
peephole --version                            # installed build and its commit
peephole --help                               # commands and arguments
peephole check-config /etc/peephole/config.toml   # validate config, rules and nmap
peephole admin reset-token                    # new one-time admin setup token
peephole db vacuum                            # shrink the database file (stop the service first)
```

Additional FIDO2 keys can be enrolled from **Admin → Keys** while logged in;
the one-time setup token is only needed for the very first key. It is valid
for 24 hours; a restart without an enrolled key prints a new one once it has
expired. If it is lost, or every key is, `peephole admin reset-token`
issues a new one (and voids the old). Admin
sessions last at most 12 hours and end after an hour without use, on logout,
on the next sign-in, or when the key they signed in with is deleted.

The database maintains itself: expired sessions are removed, query
statistics refreshed and freed pages handed back to the file system daily.
Databases created before this release do not hand pages back until they are
converted once with `systemctl stop peephole && peephole db vacuum &&
systemctl start peephole` (needs free disk space of about the database's
size). Behind nginx, set `proxy_set_header X-Forwarded-For $remote_addr;`
in the admin site's locations: the per-client rate limits key on it and are
off without it.

## Building from source

Requires Rust 1.94 or newer (`rust-version` in `Cargo.toml`). The test
suite and release build:

```sh
cargo test
cargo build --release
```

The world map served on the wall of shame is a generated asset; see
[`assets/README.md`](assets/README.md) for provenance and how to regenerate it.

Every push to `master` runs CI (fmt, clippy, tests, cargo-deny, the MSRV
build, release builds for x86_64 and aarch64, an installer smoke test in a
container); only when all of it passes are the binaries attested and
published to the rolling
[`latest` prerelease](https://github.com/overcuriousity/peephole/releases/tag/latest),
whose files are replaced in place. Pushing a tag `v<version>` publishes an
immutable release the same way; the tag must equal the `version` in
`Cargo.toml` (`v0.1.0` for `0.1.0`), which CI checks. Verify a download with
`gh attestation verify <tarball> --repo overcuriousity/peephole`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
