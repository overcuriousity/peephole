# Installer rework, password login, routed RPC, GreyNoise removal

Date: 2026-10-07 · Status: draft.

Agreed question by question with the operator: every installer question was
reviewed, and the remarks are below. Four code changes came out of that
review and ride on the same branch (`installer-rework`):

| Part | What | Where |
|---|---|---|
| A | The installer's questions, rewritten | `install.sh`, `tests/install-smoke.sh`, docs |
| B | Password login next to passkeys | `src/admin`, `src/store`, templates, CLI |
| C | Routed RPC: outbound-only nodes answer paid requests | `src/cluster`, `src/credits`, `src/intel`, `src/scan/probe` |
| D | GreyNoise removed for good | everywhere |
| E | Hint for an untrusted PROXY header | `src/trap/listen.rs` |

B–E are independent of each other. A depends on B (the password question),
D (no GreyNoise question) and on nothing else.

## Goal

A first install whose questions say what each answer means, what has to be
done elsewhere because of it, and what can be changed later — with fewer
questions, sensible defaults for a distributed sensor network (a node
traps and joins a cluster; scanning is a deliberate choice), and checks
that find a doomed nginx/certificate setup before it is attempted.

## Part A: the installer's questions

Questions are asked only on a first install, as today; an upgrade asks
nothing. Every question keeps its environment variable for unattended
installs. A preset value is never asked again (as today). New order:

1. trap role
2. scanner role
3. web role
4. what is in front of the trap
5. trusted proxy addresses (remote only)
6. public addresses not on an interface
7. admin domain (web only)
8. password login (web only)
9. nginx setup (when nginx fits)
10. cluster node name
11. cluster advertise address
12. invite token
13. MaxMind account ID, 14. MaxMind license key
15. AbuseIPDB key, 16. Shodan key, 17. InternetDB

The port-conflict offer ("Use host:next instead?") stays as it is, wherever
a listener is claimed.

### 1. Trap role — unchanged

`[Y/n]`, default on.

### 2. Scanner role — opt-in

- Default **no**, interactive and without a terminal. The unattended
  default roles become `listener,web` (CHANGELOG: unattended installs that
  relied on the scanner being on add `scanner` to `PEEPHOLE_ROLES`).
- Before the question, always (no longer only on a detected cloud), the
  cost and the benefit:
  - benefit: counter-scans of the addresses that hit the trap give the
    cluster their open ports and services;
  - cost: nmap traffic from this machine's address to other people's
    machines, which draws abuse reports; most hosting and cloud providers
    forbid scanning in their terms and may suspend the account.
  - When cloud detection names a provider, one more line names it.
- Cloud detection (`cloud_from_dmi`, `cloud_public_ip`) stays; it no longer
  drives the scanner's default. The preset-roles warning on a detected cloud
  stays.

### 3. Web role — unchanged

`[Y/n]`, default on.

### 4. What is in front of the trap

- Before the choice, per option what it means and what the operator has to
  set up:
  - **direct**: nothing in front; the trap takes ports 80 and 443 itself.
    Both must be free; the web interface cannot run on this node.
  - **local**: nginx on this machine keeps 80/443; real sites keep their
    server blocks, every other name goes to the trap. The installer can set
    nginx up (question 9).
  - **remote**: a proxy or load balancer elsewhere sends plain HTTP for
    unknown names to port 8080 and passes TLS for unknown names through
    untouched, with a PROXY protocol v2 header, to port 8081. Ports
    8080/8081 should be reachable from the proxy only. Its addresses are
    asked next.
- `PEEPHOLE_FRONT` is the only selector. A preset `PEEPHOLE_TRUSTED_PROXIES`
  no longer implies `remote`; it only answers question 5. Default:
  `local` with the web role or when 80/443 are taken, `direct` otherwise.
  CHANGELOG: unattended remote installs add `PEEPHOLE_FRONT=remote`.
- `PEEPHOLE_LOCAL_PROXY` stays accepted (1 → local, 0 → remote).
- The re-ask on a contradictory answer stays.

### 5. Trusted proxy addresses (remote)

- No measurement.
- Before the question, this machine's interface addresses with their
  prefixes, so the operator sees which network the proxy is on, and
  examples (`10.0.0.5`, `10.0.0.0/24`, several comma-separated).
- The installer validates each entry (an IPv4/IPv6 address or CIDR with a
  valid prefix) and asks again on a bad one; a preset bad value stops the
  install with the entry named. Bare addresses still get /32 or /128.

### 6. Public addresses not on an interface

- Asked on every interactive install with the trap or scanner role (unless
  `PEEPHOLE_OWN_ADDRESSES` is set), not only when the metadata service
  found one. Default: the metadata address when there is one, else none
  (`-`).
- Before it, what it is for: the address this machine is reached at when no
  interface carries it (1:1 NAT in a cloud, port forwarding at home); the
  node never scans or blocklists it, and its own requests through the NAT
  arrive from it.
- Validation as today.

### 7. Admin domain

- The question says: the domain only, without `https://` or a path, for
  example `peephole.example.net`; its DNS must point here.
- The installer strips a scheme, a path and a trailing dot or slash, lower-
  cases it, and checks the hostname shape (labels of letters, digits and
  hyphens, at least one dot); it asks again on a bad one, a preset bad value
  stops the install.
- One line: changing the domain later makes enrolled passkeys unusable.

### 8. Password login (new, web only)

- "Also allow signing in with a password? [y/N]" — explained: a passkey
  (security key, phone, password manager) is the stronger option; a
  password works from any browser. Either way the admin site needs HTTPS.
- Yes: the password, asked twice, hidden (`read -s`), at least 12
  characters, asked again on a mismatch or a short one.
- After the config is written and before the service starts, the installer
  runs `peephole admin password --stdin CONFIG` with the password on stdin
  (never on the command line, never in the config) — this stores the hash
  and sets the login method to `both`.
- `PEEPHOLE_ADMIN_PASSWORD` presets it for unattended installs (same
  checks; a short one stops the install).
- The closing summary names the sign-in: the enroll link for a passkey, and
  "or sign in with your password" when one was set.

### 9. nginx setup

- Asked right after the questions it depends on (front, domain, password),
  no longer after the API keys. Same conditions as today (trap behind local
  nginx, or the web role without a trap).
- Before the question, a preflight runs the checks `setup_nginx` does today
  and shows the result, each as ok or a reason:
  - an existing `/etc/nginx/sites-available/peephole` or stream config;
  - other sites listening on 443 when the stream config is needed;
  - `sites-enabled/default` that is not a link;
  - packages to install while `PEEPHOLE_SKIP_APT=1`;
  - with the web role, the admin domain's DNS: `getent ahosts` must
    include one of this machine's addresses (interfaces, metadata address,
    the answer to question 6). A mismatch names what it resolves to and
    says the certificate request will fail. Port 80 reachability cannot be
    checked from here; it stays a hint.
- Then the exact list of changes: packages (nginx, certbot,
  python3-certbot-nginx, libnginx-mod-stream as needed), the certificate,
  the default site disabled, the site file, the nginx.conf include, test
  and reload; on failure everything is put back.
- Default **yes** when every check passes, otherwise **no** with the
  failing check named. A preset `PEEPHOLE_NGINX=1` with a failing check
  still tries (and falls back to the manual steps, as today).
- The Let's Encrypt contact email is gone (question removed,
  `PEEPHOLE_ACME_EMAIL` and its check removed, a preset value ignored):
  Let's Encrypt ended expiry emails on 2025-06-04 and no longer stores an
  ACME email with the account; it is only forwarded to the ISRG mailing
  list. certbot always runs with `--register-unsafely-without-email`. No
  "expiry notices" wording remains anywhere.
- The manual steps in the closing summary stay for "no".

### 10. Cluster node name (cluster question removed)

- "Take part in a cluster?" is removed: `[cluster]` is always written. A
  node without peers and without an invite runs alone, as before.
  `PEEPHOLE_CLUSTER` is ignored.
- The node name defaults to the machine's `hostname` (short form).
- The RPC listener is no longer asked: it is `0.0.0.0:<advertise port>`.
  `PEEPHOLE_CLUSTER_LISTEN` overrides it; the port check applies.

### 11. Cluster advertise address — required

- Before it: other members dial this node at this address; the port must
  be reachable from the internet. The installer does not change the
  firewall (ufw is mentioned, as in today's summary). To change it later:
  `advertise` and `listen` in config.toml, then restart.
- Required. Default `<admin domain>:7443` when the web role is on and the
  front is not `remote` (the domain then points here), otherwise
  `<public address>:7443` (interface, else metadata, else question 6);
  without either, no default and an answer is needed.
- Checked: `host:port` with a port 1–65535.
- Outbound-only stays in the code, for hand-edited configs only; the docs
  describe it as the fallback for a node that cannot be reached, and
  (after part C) what it can still do.

### 12. Invite token

- As today, plus the later command in the question:
  `peephole cluster join <token>`. The implementer checks whether a
  running daemon picks a join up or needs `systemctl restart peephole`,
  and the hint says so when it does.
- The join block after the config (`install.sh` "Node key", `cluster join`)
  runs without the old `PEEPHOLE_CLUSTER` condition.

### 13–15, 17. MaxMind, AbuseIPDB, InternetDB — unchanged

### 16. Shodan key

The question says what the key adds over the free InternetDB: product and
version per port, OS, organisation, ISP, ASN and domains, IPv6, and the
latest crawl (dated) instead of a weekly snapshot; commercial use as the
plan allows. Host lookups need a membership or a paid plan.

### Smoke test and docs

`tests/install-smoke.sh` follows every change: new order and defaults, the
scanner off without a terminal, no cluster question, the required advertise
address, the password via stdin, the nginx preflight (an unresolvable
domain gives default no), no ACME email. `docs/operations.md`, README and
`deploy/config.example.toml` follow. CHANGELOG lists the behaviour changes
for unattended installs (scanner default, `PEEPHOLE_FRONT=remote`,
`PEEPHOLE_CLUSTER`/`PEEPHOLE_ACME_EMAIL` ignored, advertise required).

## Part B: password login

- **Login method**, node-local: `passkey` (default), `password`, `both`.
  Stored in `intel_meta` (key `admin_login_method`), like the setup token.
  Not a runtime setting of `peephole settings` and not reachable by a fleet
  owner's commands: who may sign in to a node's admin area is that node's
  decision.
- **One account, no username.** The login form has a password field and a
  hidden `username` field fixed to `admin` (`autocomplete="username"`), so
  password managers store it properly.
- **Storage:** an Argon2id PHC string in `intel_meta`
  (`admin_password_hash`), crate `argon2` (RustCrypto; MIT/Apache, passes
  `deny.toml`), default parameters. Never in the config.
- **Login:** `POST /login/password` (form). Verifies in a blocking task,
  creates the same session as a passkey login, and is covered by the
  existing `/login/*` rate limit (`src/admin/limit.rs`). A failure says only
  "wrong password". Refused when the method is `passkey`.
- **Login page:** shows the passkey button, the password form, or both, by
  method.
- **Admin → Keys** gets a "Sign-in" section: the method (radio), and set or
  change the password (current password required when one exists; at least
  12 characters, twice).
- **Lockout guard**, on the page and in the CLI: `password` needs a stored
  password; `passkey` needs an enrolled key; `both` needs at least one of
  them. Removing the last key while the method is `passkey` stays refused
  as today; removing it under `both` switches to `password` only when a
  password exists, otherwise it is refused.
- **CLI** (`peephole admin`, local like `reset-token`):
  - `peephole admin password [--stdin] [CONFIG]`: set or replace the
    password (prompted twice without echo, or one line from stdin), and
    switch `passkey` to `both`. This is also the recovery path.
  - `peephole admin login-method passkey|password|both [CONFIG]`: with the
    same guard.
- HTTPS stays required: the admin site's cookies are `Secure`; no plain-HTTP
  password login.

## Part C: routed RPC for outbound-only nodes

Today a direct call (`node.call`) needs the target's address, so an
outbound-only member cannot be asked for paid lookups, DNS resolution or
probes. Directed messages already reach it (outbox + long-poll).

- **Messages:** `Msg::Rpc { path, body }` and `Msg::RpcReply { status,
  body }` (body: CBOR bytes, at most 1 MiB each way; larger is refused with
  413 before sending or on receipt).
- **Receiver:** dispatches the request to the RPC router in-process, with
  `Peer(from)` as the extension, so the handler and its member check are
  the same as for a direct call. Only `/rpc/v1/lookup`, `/rpc/v1/resolve`
  and `/rpc/v1/probe` are allowed this way; anything else answers 404.
- **Caller:** `Node::call_any::<Req, Resp>(id, path, req, timeout)`: a direct
  call when the target has a dial address, else `request` with `Msg::Rpc`.
- **Call sites:** `credits::pay::offer_and_ask` (and the dialability checks
  at `pay.rs` quote collection and `make_offer`), `intel::dns` (resolver
  choice and `ask`), `scan::probe::ask` (vantages and the call). The
  "reconcile after a declined offer" step runs only when the server is
  dialable; otherwise the outbound node's own sync brings its receipt.
  `dialled_ip` of an outbound-only scanner falls back to its announced
  public address.
- `credits::fleet` keeps its dial-only reconcile (a message already carries
  the draw; the reconcile is an optimisation).
- Protocol: v4 is not deployed; the new variants go into it. Members that
  cannot decode them do not exist yet.
- Docs: `docs/cluster.md` (the "cannot be asked" sentence goes).
- Tests: a lookup, a resolve and a probe answered by a node with no
  address; the path allow-list; the size cap.

## Part D: GreyNoise removed

Every reference goes: `src/intel/greynoise.rs`, its provider entry and
pricing (`src/intel/{api,mod}.rs`, `src/credits/share.rs`), the config
section (`src/config.rs`), stored-data rendering (`src/store/{requests,
browse}.rs`, `src/admin/public.rs`, `templates/ips.html`), README, docs,
`deploy/config.example.toml`, `install.sh`, the smoke test. No compatibility
code: the config has no `deny_unknown_fields`, so an old `[greynoise]`
section is ignored. No data migration (none stored anywhere). A finding
from an older member names an unknown provider and is dropped like any
unknown provider's (checked by a test). CHANGELOG: removed.

## Part E: untrusted PROXY header hint

When the TLS trap gets a connection from a peer outside `trusted_proxies`
that starts with a PROXY header (v1 or v2 signature), it logs a warning
naming the peer and saying to add it to `trusted_proxies` if it is the
operator's proxy. At most once per peer address per hour. The connection is
handled as today.

## Out of scope

- Several simultaneous long-polls of an outbound-only node (resilience of
  the outbox) — a later idea.
- End-to-end sealing of routed messages: all links are mutual TLS, and
  relays are members that hold the shared data anyway.
- A GreyNoise replacement.
