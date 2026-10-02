# Operations

Installing, upgrading and running a peephole node. For the cluster, see
[cluster.md](cluster.md); every config key is annotated in
[`deploy/config.example.toml`](../deploy/config.example.toml).

## What the installer does

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
```

- Installs prerequisites (`nmap`, `curl`, `ca-certificates`, `sqlite3`).
- Downloads the build for the machine (x86_64 or aarch64) and verifies its
  checksum. With the GitHub CLI (`gh`) installed it also verifies the build's
  provenance attestation (`PEEPHOLE_VERIFY=1` makes that required, `0` skips
  it), and prints the commit the binary was built from.
- Installs the binary to `/usr/local/bin/peephole` and the default signature
  rules to `/etc/peephole/rules`.
- Asks what this node should do:
  - run a **trap**, the **scanner**, the **web interface**, in any combination;
  - whether a reverse proxy on the same machine fronts the trap, and otherwise
    which proxy addresses to trust;
  - the public domain of the admin area (with the web interface);
  - whether to take part in a **cluster**: node name, addresses, an invite
    token, and whether holders of this node's **config key** may change its
    settings;
  - optional **MaxMind GeoLite2** credentials
    (<https://www.maxmind.com/en/accounts/current/license-key>);
  - optional API keys for **AbuseIPDB**, **Shodan** and **GreyNoise**, and
    whether to use **Shodan InternetDB** (no key, non-commercial use only);
  - whether to **set up nginx** for you (see below).
- Writes `/etc/peephole/config.toml` and an nginx example that fits the answers
  to `/etc/peephole/nginx.example.conf`, and installs and starts a systemd
  service.

Unattended installs pass the answers as environment variables:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | \
  sudo MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=yourkey \
       PEEPHOLE_DOMAIN=peephole.example.net PEEPHOLE_NGINX=1 bash
```

Every question has a variable (`PEEPHOLE_ROLES`, `PEEPHOLE_LOCAL_PROXY`,
`PEEPHOLE_CLUSTER`, `PEEPHOLE_CLUSTER_NAME`, `PEEPHOLE_JOIN_TOKEN`,
`PEEPHOLE_REMOTE_CONFIG`, `PEEPHOLE_NGINX`, `PEEPHOLE_ACME_EMAIL`, …); the
head of `install.sh` lists them all.

Published binaries are built on Ubuntu 22.04 and run on Debian 12 / Ubuntu
22.04 or newer (glibc ≥ 2.35).

## nginx

The generated example has:

- a TLS server block for the admin area (the live scan queue needs
  `proxy_buffering off` on `/admin/api/queue`, which the example sets;
  `/login` and `/enroll` are rate limited);
- a catch-all `default_server` on port 80 that sends everything no real site
  claims to the trap. It sets `X-Forwarded-For` to the real peer address, so a
  client cannot spoof it.

With a trap on the machine, a second file, `nginx-stream.example.conf`,
takes port 443 at the TCP level (nginx's `stream` module, `ssl_preread`):

- the admin domain goes to nginx's own TLS server for the admin area, now on
  `127.0.0.1:8444` with `proxy_protocol` (the client address is restored
  with `real_ip_header proxy_protocol`);
- every other name, and connections without one, go untouched to the trap's
  TLS listener (`trap_tls_listen`, `127.0.0.1:8081`) with a PROXY protocol
  header. peephole terminates TLS itself (a self-signed certificate unless
  `trap_tls_cert`/`trap_tls_key` are set; scanners do not check it), so it
  keeps the raw ClientHello and its JA4 fingerprint, and the admin
  certificate is never shown to scanners.

The stream config belongs in nginx's main context, outside `http {}`: the
installer writes it to `/etc/nginx/peephole-stream.conf` and adds an
`include` line for it to `/etc/nginx/nginx.conf`. It needs the stream module
(Debian/Ubuntu: `libnginx-mod-stream`, installed with the automatic setup).
Without a trap, port 443 stays a plain TLS server that refuses unknown names
(`ssl_reject_handshake`, nginx ≥ 1.19.4).

Other HTTPS sites on the same nginx have to move behind the stream config
as well: one map line per name (`shop.example.net 127.0.0.1:8444;`) and, in
their server blocks, `listen 127.0.0.1:8444 ssl proxy_protocol;` with
`set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;` in place of
`listen 443 ssl`. The automatic setup does not rewrite other sites: when an
enabled site still listens on 443 it leaves nginx alone and prints the
manual steps. It also takes its changes back if nginx refuses to reload.

Both trap listeners answer one request per HTTP/1 connection and keep the
request head as received (header case and order). Behind nginx on port 80
that head is nginx's rewrite; on port 443 it is the client's.

Installs from before the TLS listener keep their config on upgrade, and so
the old 443 setup. To trap HTTPS there, add `trap_tls_listen =
"127.0.0.1:8081"` to `/etc/peephole/config.toml`, generate the two examples
(`PEEPHOLE_ROLES=… PEEPHOLE_DOMAIN=… bash install.sh --nginx-example` and
`--nginx-stream-example`), put them in place as in the manual steps below and
restart peephole.

**Automatic setup** (opt-in: answer yes, or `PEEPHOLE_NGINX=1`). Offered for
the web role and for a trap behind a proxy on the same machine. After
peephole is up, the installer installs nginx (and certbot with the web
role), gets a Let's Encrypt certificate for the admin domain (its DNS must
point at the machine and port 80 must be reachable; `PEEPHOLE_ACME_EMAIL`
sets the contact address), disables the distribution's default site (only
if it is the stock link), enables `/etc/nginx/sites-available/peephole` and,
with a trap, the stream config, checks it with `nginx -t` and reloads. On a machine without IPv6 the `[::]`
listeners are left out. If a step fails, the installer puts back what it
changed and prints the manual steps; the peephole install itself still
succeeds. An existing `/etc/nginx/sites-available/peephole` or
`/etc/nginx/peephole-stream.conf` is never overwritten. Certificates renew through certbot's systemd timer.

**Manual setup**, in the order that works on a stock Debian/Ubuntu nginx:

```sh
certbot certonly --nginx -d peephole.example.net   # while the default site still serves port 80
rm /etc/nginx/sites-enabled/default                # it also claims default_server
cp /etc/peephole/nginx.example.conf /etc/nginx/sites-available/peephole
ln -s ../sites-available/peephole /etc/nginx/sites-enabled/peephole
apt-get install libnginx-mod-stream                # with a trap: the stream module
cp /etc/peephole/nginx-stream.example.conf /etc/nginx/peephole-stream.conf
echo 'include /etc/nginx/peephole-stream.conf;' >> /etc/nginx/nginx.conf
nginx -t && systemctl reload nginx
```

Behind any other reverse proxy: send plain HTTP that matches no real site to
`trap_listen` with `X-Forwarded-For` set to the peer address, forward TLS for
unknown names untouched (TCP) to `trap_tls_listen` with a PROXY protocol
header (v1 or v2), and list the proxy in `trusted_proxies`. A trusted peer
that connects to `trap_tls_listen` without a PROXY header, or with one that
names no client (`UNKNOWN`, `LOCAL`), is dropped. In the
admin site's locations, set `X-Forwarded-For` to the peer address: the
per-client rate limits key on it and are off without it.

## Upgrades

Re-running the installer upgrades in place. It skips when the installed
version already matches (`PEEPHOLE_FORCE=1` reinstalls), validates the
existing config with the new binary, backs up the database
(`/var/lib/peephole/backup-<time>.db`, the two newest are kept), restarts and
waits for `/healthz` (or for systemd to report the service up). If the new
version does not come up, it rolls back the binary, the rules, the unit and —
when the new version changed its schema — the database, then checks the old
version is running again.

Shipped rule files and the systemd unit are treated like conffiles: a file you
edited is kept and the new upstream version is placed beside it as
`<name>.new`. Keep your own service settings (sandboxing, limits) in a drop-in
(`systemctl edit peephole`), which upgrades never touch. Your config, the
nginx example and the nginx site are never rewritten.

A versioned release is immutable; install one with the installer from the same
tag:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/v0.1.0/install.sh | \
  sudo PEEPHOLE_VERSION=v0.1.0 bash
```

## Day to day

```sh
systemctl status peephole                         # service status
journalctl -u peephole -f                         # logs (incl. FIDO2 enrollment instructions)
peephole --version                                # installed build and its commit
peephole --help                                   # commands and arguments
peephole check-config /etc/peephole/config.toml   # validate config, rules and nmap
peephole settings show|set|reset                  # runtime settings (pace, cooldown, roles)
peephole admin reset-token                        # new one-time admin setup token
peephole export -o data.parquet                   # the dataset (--format, --from, --redistributable, --help)
peephole db vacuum                                # shrink the database file (stop the service first)
```

Configuration lives in `/etc/peephole/config.toml`; restart after editing
(`systemctl restart peephole`). Scan pace, rescan cooldown and roles are
runtime settings, changed from **Admin → Cluster** or `peephole settings`
without a restart. Signature rules are plain TOML files in
`/etc/peephole/rules`; see [`rules/`](../rules/) for the shipped defaults.

**Admin keys and sessions.** The first FIDO2 key is enrolled at `/enroll` with
a one-time setup token from the service log. It is valid for 24 hours; a
restart without an enrolled key prints a new one once it has expired, and
`peephole admin reset-token` issues a new one (and voids the old) if it is
lost, or every key is. Further keys are enrolled from **Admin → Keys**. Admin
sessions last at most 12 hours and end after an hour without use, on logout,
on the next sign-in, or when the key they signed in with is deleted.

**Dataset.** `peephole export` writes every request with everything known
about it and its IP as Parquet (default), CSV or Timesketch JSON Lines, to
`-o FILE` or stdout; `--from`, `--to`, `--ip`, `--label` and
`--min-severity` narrow it, `--redistributable` leaves out the GeoIP and
API results whose terms forbid passing them on. It reads the database the
running service writes, so it needs no stop. The web interface has the same
export under **Admin → Export**. Columns, weights and the two modes:
[docs/dataset.md](dataset.md).

**Blocklist feed.** A web node serves `GET /api/blocklist` on its public
pages: one address (or prefix) per line, requests of severity 3+ in the
last 24 hours by default, with `?hours=`, `?min_severity=` and
`?networks=1`. Recomputed at most once a minute. Exclusions: Tor exits,
addresses a scanner refused as a verified crawler, cluster members'
addresses, this node's own addresses and `scan.never_scan`. For nginx:

```sh
curl -fsS https://<your-domain>/api/blocklist | grep -v '^#' | sed 's/.*/deny &;/' > /etc/nginx/blocklist.conf \
  && nginx -t && systemctl reload nginx
```

**Database.** It maintains itself: expired sessions are removed, query
statistics refreshed and freed pages handed back to the file system daily.
Databases created before that feature hand pages back only after a one-time
`systemctl stop peephole && peephole db vacuum && systemctl start peephole`
(needs free disk space of about the database's size). Everything is kept by
default; `retention_days = N` (top level, at least 7) keeps only the last N
days on this node: a standalone node deletes older requests and scan results,
a cluster node drops its old copies and history (see docs/cluster.md).

## Building and releases

Requires Rust 1.94 or newer (`rust-version` in `Cargo.toml`):

```sh
cargo test
cargo build --release
```

The world map is a generated asset; see
[`assets/README.md`](../assets/README.md) for provenance and how to regenerate
it.

Every push to `master` runs CI: fmt, clippy, tests, cargo-deny, the MSRV
build, release builds for x86_64 and aarch64, the deploy-file checks and an
installer smoke test in a container. Only when all of it passes are the
binaries attested and published to the rolling
[`latest` prerelease](https://github.com/overcuriousity/peephole/releases/tag/latest),
whose files are replaced in place. Pushing a tag `v<version>` publishes an
immutable release the same way; the tag must equal the `version` in
`Cargo.toml` (`v0.1.0` for `0.1.0`), which CI checks. Verify a download with
`gh attestation verify <tarball> --repo overcuriousity/peephole`.
