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
- Installs the binary to `/usr/local/bin/peephole`; the signature rules are
  built into it.
- Asks what this node should do:
  - run a **trap**, the **scanner**, the **web interface**, in any combination;
    the web interface needs a domain whose DNS points at the machine and
    HTTPS (WebAuthn), so without one answer no: in a cluster the admin area
    of another node shows everything;
  - with a trap, **what is in front of it** (see below);
  - the public domain of the admin area (with the web interface);
  - whether to take part in a **cluster**: node name, addresses, an invite
    token, and whether holders of this node's **config key** may change its
    settings;
  - optional **MaxMind GeoLite2** credentials
    (<https://www.maxmind.com/en/accounts/current/license-key>);
  - optional API keys for **AbuseIPDB**, **Shodan** and **GreyNoise**, and
    whether to use **Shodan InternetDB** (no key, non-commercial use only);
  - whether to **set up nginx** for you (see below).
- Checks that every port the new config listens on is free (from
  `/proc/net/tcp`, so it works without `ss`). Interactive installs are
  offered the next free port; unattended ones stop before anything is
  written. Upgrades skip this.
- Writes `/etc/peephole/config.toml` and an nginx example that fits the answers
  to `/etc/peephole/nginx.example.conf`, and installs and starts a systemd
  service.

### What is in front of the trap

| Answer | Trap listens on | `trusted_proxies` | nginx |
|---|---|---|---|
| `direct`: nothing | `0.0.0.0:80`, `0.0.0.0:443` | `[]` | none |
| `local`: nginx on this machine | `127.0.0.1:8080`, `127.0.0.1:8081` | loopback | example, optional automatic setup |
| `remote`: a proxy elsewhere | `0.0.0.0:8080`, `0.0.0.0:8081` | the proxy's addresses (asked, no default) | none for the trap |

- **direct** takes the public ports itself (the unit allows
  `CAP_NET_BIND_SERVICE`); open 80 and 443 in any firewall in front of the
  machine, and the cluster port if it is advertised. When `ufw` is active,
  the installer prints the `ufw allow` commands (it does not run them). It is
  the default when nothing listens on 80/443 and there is no web role.
- **direct is refused with the web role**: the admin site needs port 443
  too. Use **local** there: the nginx stream config splits 443 by name (the
  admin domain to the admin site, every other name to the trap), which the
  installer writes and can set up. Or run the web interface on another node
  of a cluster. With the web role, or when 80/443 are taken, the default is
  local.
- **remote**: the proxy sends plain HTTP that matches no real site to
  `trap_listen` with `X-Forwarded-For` set to the client, and passes TLS for
  unknown names untouched, with a PROXY protocol v2 header, to
  `trap_tls_listen`; no health checks on the TLS backend (a `LOCAL` header
  is refused). Hosts in `trusted_proxies` are believed about the client
  address, so list only the proxy (a bare address means that one host).

**Cloud machines.** On AWS, Google Cloud, Azure, Alibaba Cloud and Oracle
Cloud (recognised from the DMI data or the metadata service) the installer
warns before the scanner question and defaults it to no: their acceptable
use policies forbid scanning others, and the abuse reports counter-scans
draw risk suspension of the account. Behind 1:1 NAT no interface carries
the public address; with a trap or the scanner, the installer asks the
cloud's metadata service (AWS, Google Cloud, Azure, Hetzner, DigitalOcean;
one-second timeouts, no outside service) and, when it reports an address
no interface shows, offers it for `[scan] own_addresses` (never scanned,
never in the blocklist). It is also the example for the cluster's advertise
address.

Unattended installs pass the answers as environment variables:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | \
  sudo MAXMIND_ACCOUNT_ID=123456 MAXMIND_LICENSE_KEY=yourkey \
       PEEPHOLE_DOMAIN=peephole.example.net PEEPHOLE_NGINX=1 bash
```

Every question has a variable (`PEEPHOLE_ROLES`, `PEEPHOLE_FRONT`,
`PEEPHOLE_TRUSTED_PROXIES`, `PEEPHOLE_OWN_ADDRESSES`, `PEEPHOLE_CLUSTER`,
`PEEPHOLE_CLUSTER_NAME`, `PEEPHOLE_JOIN_TOKEN`, `PEEPHOLE_REMOTE_CONFIG`,
`PEEPHOLE_NGINX`, `PEEPHOLE_ACME_EMAIL`, …); the head of `install.sh` lists
them all. `PEEPHOLE_FRONT=direct|local|remote` answers what is in front of
the trap. Without it, unattended installs keep what they did before: the
older `PEEPHOLE_LOCAL_PROXY=1` means local and `0` remote, and a preset
`PEEPHOLE_TRUSTED_PROXIES` alone means remote; with none of these, the
default above applies (local with the web role or 80/443 taken, else
direct). `PEEPHOLE_OWN_ADDRESSES` overrides the metadata's address (`-` for
none); `PEEPHOLE_METADATA=0` skips asking the metadata service.

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

Behind any other reverse proxy (the installer's **remote** answer): send plain HTTP that matches no real site to
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
version does not come up, it rolls back the binary, the unit and — when the
new version changed its schema — the database, then checks the old version
is running again.

0.1.0 starts the schema afresh: it refuses a database written by an earlier
(pre-release) build, and says so in the journal. Stop peephole, move the
database (`database_path`, with its `-wal` and `-shm` files) aside and start
it again; it creates an empty one. In a cluster, do this on every node and
join them again with fresh invites.

The systemd unit is treated like a conffile: if you edited it, it is kept and
the new upstream version is placed beside it as `peephole.service.new`. Keep your own service settings (sandboxing, limits) in a drop-in
(`systemctl edit peephole`), which upgrades never touch. Your config, the
nginx example and the nginx site are never rewritten.

A versioned release is immutable; install one with the installer from the same
tag:

```sh
curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/v0.1.1/install.sh | \
  sudo PEEPHOLE_VERSION=v0.1.1 bash
```

## Day to day

```sh
systemctl status peephole                         # service status
journalctl -u peephole -f                         # logs (incl. FIDO2 enrollment instructions)
peephole --version                                # installed build and its commit
peephole --help                                   # commands and arguments
peephole check-config /etc/peephole/config.toml   # validate config and nmap; show the built-in rules
peephole settings show|set|reset                  # runtime settings (pace, cooldown, roles)
peephole admin reset-token                        # new one-time admin setup token
peephole export -o data.parquet                   # the dataset (--format, --from, --redistributable, --help)
peephole db vacuum                                # shrink the database file (stop the service first)
```

Configuration lives in `/etc/peephole/config.toml`; restart after editing
(`systemctl restart peephole`). Scan pace, rescan cooldown and roles are
runtime settings, changed from **Admin → Cluster** or `peephole settings`
without a restart.

**Signature rules** are built into the binary from [`rules/`](../rules/) at
build time: there is nothing to install or edit on the node, and changing a
rule means changing `rules/*.toml` and building (CI checks every rule loads).
`check-config` and the startup log show the number of rules and the start of
their fingerprint (SHA-256 over the files), which every classified request
stores. Installs from before this change had the rules in
`/etc/peephole/rules` and `rules_dir` in the config: both are now ignored
(peephole logs a warning, `check-config` a note, and the installer says so
once on upgrade). The installer leaves that directory in place; remove it and
the `rules_dir` line when you like.

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
addresses, this node's own addresses (with `scan.own_addresses`, e.g. its
public address behind 1:1 NAT) and `scan.never_scan`. For nginx:

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

### Public pages are delayed

The wall, the IP directory, IP pages, `/api/stats`, `/api/map` and
`/api/blocklist` show a request only after `[public] delay_minutes` plus
a random 0 to `jitter_minutes` (5 + 0–5 min by default), counted from when
this node stored it. Someone probing an address and watching the wall can't
tell from the timing whether it was one of yours. Signed-in admins see
everything at once; the live feed is on the admin Overview. A changed delay
applies to requests stored after the restart. Setting both to 0 publishes
at once (logged as a warning).

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

## Classification taxonomy

Rules live in `rules/*.toml` (built into the binary), one file per family; each rule has a weight,
a label and an `owasp` tag. The weight (1–4) is the request's severity and
drives the counter-scan level:

| Weight | Meaning | Labels |
|---|---|---|
| 1 | single weak tell | `probe` (behavioural floor), `php-probe` |
| 2 | automated reconnaissance | `scanner-ua`, `research-scanner`, `sensitive-path`, `path-scanner`, `ai-infra-probe`, `api-recon`, `proxy-probe`, `unusual-method`, `automation` |
| 3 | exploit-adjacent | `form-interaction`, `write-method`, `xss`, `crlf-injection`, `webshell-probe`, `app-probe`, `cloud-infra-probe`, `credential-attack`, `mcp-probe`, `graphql-introspection`, `appliance-probe`, `iot-probe`, `inhuman-behavior` |
| 4 | unambiguous exploit / post-exploitation | `sqli`, `rce`, `path-traversal`, `ssrf`, `ssti`, `nosqli`, `xxe`, `deserialization`, `webshell`, `mcp-abuse` |

The `owasp` tag is a Top-10 2021 class (`A03:2021`) for payload families or
an Automated Threat (`OAT-014`) for scanning behaviour. Tags are stored on
the request row (`owasp_json`), shown as badges next to the labels in the
web UI, and included in exports. A typo'd tag fails the build's tests.
Behavioural labels (`probe`, `path-scanner`, `form-interaction`, …) come
from code, not rule files, and carry no tag.

Label badge colours follow the family: blue = reconnaissance (any
`*-probe` label, plus `scanner-ua`/`research-scanner`/`path-scanner`/
`api-recon`/`graphql-introspection`), green = exposure (`sensitive-path`:
secrets, config, repos, dumps, admin and debug pages), red = injection,
violet = execution/impact, orange = interaction, solid = post-exploitation,
grey = automation tells (including `proxy-probe`), neutral accent =
everything else. New labels need no UI work: a `something-probe` label is
blue automatically, everything unknown is neutral.

The wall's "What they were after" counts each request once per family it
touched. `path-scanner` and `php-probe` say how a request came, not what
it was after, so they count (as reconnaissance) only when no other label
names a family; "other" likewise only when nothing else applies.

Weight rationale when adding rules: would you counter-scan a source that
did *only* this? Recon gets 2, anything that touches an exploit gets 4
only when the payload itself is unambiguous.
