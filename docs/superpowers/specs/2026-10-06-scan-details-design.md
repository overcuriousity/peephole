# Scan details: what a source serves and what it is called

Date: 2026-10-06 · Status: draft.

Takes these items from `docs/roadmap.md` (Small follow-ups) and removes
them there when it is implemented:

- Peer-observed public address
- Host keys in the export
- ETags of scanned sources
- Reverse DNS of every source

## Goal

A counter-scan already holds more than the scan pages show. Today a scan
shows its ports (service, product, version), the OS guess, and the host keys,
certificates, JA4X and HASSH from `ssh-hostkey`, `ssl-cert` and
`ssh2-enum-algos` (`scan::hostkeys`). Everything else nmap found is only in
the raw XML.

Some of that is worth seeing at a glance:

- **What the source serves:** a page title, a `Server` header, a login realm,
  an ETag. One source in the 2026-10-06 export served "PentAGI" (an
  autonomous AI pentest agent) with a certificate for `pentagi.local`, MinIO,
  and a Basic realm "bifrost".
- **What the source calls itself:** Windows computer and domain names from
  RDP NTLM and SMB (`WIN-344VU98D3RU`, `32gb4vcpu28sept`), the hostname a
  service announces, and its reverse DNS name. This is for every source, not
  only the scanned ones.
- **Service details nmap already returns and the store drops:** `extrainfo`,
  `ostype`, `devicetype`, `hostname`, CPE.

The same export showed two problems, and this spec fixes them:

- **One script fills the dataset with noise.** `http-comments-displayer`
  produced 198 KB of 266 KB on one scan, almost all of it binary font files
  read as HTML comments. The export repeats a source's scans on each of its
  rows, so that one scan was 211 MB of a 2.1 GB file.
- **A scan can record the scanner's own address.** A mail server greets the
  client by address and name (`Hello i577b2938.versanet.de [87.123.41.56]`),
  and nmap keeps the greeting in `smtp-commands` and `banner`. The scan is
  signed, replicated to every member and exported, with the scanning node's
  residential address in it. A NAT'd node cannot even tell which address
  that is: no interface carries it.

Success:

- The scan page and the IP page show what a source serves and what it calls
  itself, from fields nmap writes as structure, and its forward-confirmed
  reverse DNS name.
- Scans stored before this release show the same after an upgrade.
- A NAT'd node knows its public address from its peers, never scans or
  blocklists it, and keeps it and its name out of new scans.
- The export carries host keys, ETags and the facts below per scan, and a
  `ptr` per source.
- New scans contain no `http-comments-displayer` output.
- Nothing is parsed from prose, and there is no list of strings to match
  against.

## The rule: deterministic fields only

A value is read only from a **fixed place**:

- an attribute of an nmap element (`<service product=…>`, `<cpe>`);
- an `<elem>` of a script's structured output at a fixed key path
  (`<script id="http-title"><elem key="title">`), the tree nmap's `-oX`
  writes for every run of that script;
- a protocol field with a fixed name: a DNS PTR or A/AAAA record, an HTTP
  response header field, the source address of a TCP connection.

Never from:

- a script's human-readable `output`, with one exception (`http-headers`,
  below: its output is the server's header block, not prose);
- an `<elem>` whose key is itself data (URLs or counts used as keys, as
  `http-grep` and `fcrdns` write them);
- a substring, keyword or regex list over any value.

Script ids, key paths and header names are fixed names, compared for
equality, in one table in the code. A script without structured output is
not parsed, however interesting its text: `banner`, `http-generator`,
`nbstat`, `smtp-commands` and `http-robots.txt` in the current data. It
stays in the raw XML.

Scrubbing follows the same rule: it replaces exact values this node knows
about itself, not patterns.

## 1. Peer-observed public address

### Learning it

The RPC server already knows each caller's source address (`RemoteAddr`;
`status.note_peer_ip` keeps it for the scan safety list).

- The `hello` answer gains an optional field `seen_from: Option<IpAddr>`: the
  address the caller's connection came from, as this server saw it.
- `Hello` is a CBOR map, so a peer of an earlier build ignores the field and
  sends none. No protocol version change.

A node takes a reported address as its own **public address** when either:

- a sibling reports it (same owner key: one of the operator's own nodes); or
- two members of different owners report it.

One stranger's report is not enough: a member could otherwise name an
attacker's address, and this node would never scan it.

An address must be a global unicast address, after `net::canonical`. A
private, loopback or link-local report is the peer seeing this node over a
LAN or a tunnel; it is ignored.

Public addresses are kept in memory with when they were last confirmed. An
address no peer has reported for 7 days is dropped. They are listed on
System › Status as "Public address (seen by peers)", with who reported each.

### What it is used for

- **The safety list.** Public addresses join this node's own addresses in
  `scan::safety` (with the interfaces, listeners, `cluster.advertise` and
  `scan.own_addresses`). They are never scanned and never on the blocklist.
  `scan.own_addresses` stays, for a standalone node and for a route peers
  do not see (scans leaving by another uplink). Its doc says that peers
  fill it in for a NAT'd node.
- **Scrubbing scans** (section 5).
- **Which of our addresses a request reached.** A request gains `reached`:
  the trap's local address when that address is global. Otherwise (behind
  NAT) it is the public address, when this node has exactly one; otherwise
  none. Shown on the request page. A `reached` column in the dataset.
- **Canary return host.** A decoy builds canary URLs from the request's
  `Host`. When that is missing, `localhost` or a private address, it uses
  the node's fixed site name today, which the client cannot reach
  (`canary::site::return_host`). With one public address known, it uses
  that address instead, so a canary can come back. This is a new decoy
  version: the next `decoy_v`, recorded on the request as every version is.

## 2. Reverse DNS of every source

Each node looks up the **forward-confirmed PTR name** of every source it
records: the PTR record of the IP, then the name's A/AAAA records, kept only
when they contain the IP. This is the lookup `scan::crawler` already does;
it moves into a shared module both use, with the crawler cache.

- **When:** after a request from an IP is recorded, when its last check is
  older than 24 hours (refreshed when the IP returns). The lookup runs in
  the background, at most 8 at once, and never delays recording. A failed
  or timed-out lookup is retried after the next request, at most once an
  hour.
- **Stored:** on `ips`: `ptr TEXT` (the confirmed name, or NULL) and
  `ptr_checked_at`. Local, not replicated. Every node looks up for itself,
  as with the crawler check, so two nodes can briefly disagree.
- **Shown:**
  - on the IP page, under the address;
  - as a filter in the IP directory (admin; a typed name part, matched
    against `ptr`);
  - as a `ptr` column in the dataset.

  Not on public pages.
- **Cost:** the reverse zone's operator sees a query from this node's
  resolver, as it already does for every source the crawler check looks at.

nmap's own `<hostnames>` PTR names are not parsed: this lookup covers every
source, scanned or not, and confirms the name.

## 3. Host keys, ETags and scan facts in the export

### Host keys in the export

Scans in the export gain `host_keys`: the rows `store::hostkeys` derives
for that scan, as `{kind, port, fingerprint, detail}`. This covers SSH host
keys, certificates, JA4X, HASSH, and ETags below. `docs/dataset.md`
documents the kinds. A dataset user then never parses the XML for them.

### ETags of scanned sources

nmap's `http-headers` (in `discovery` and `safe`) runs at levels 3 and 4,
so each HTTP port's response headers are in the stored XML. **Level 2 adds
it to its named scripts**: one request per HTTP port nmap already found
open, `safe`, in the spirit of `IDENTITY_SCRIPTS`.

**How the ETag is read.** `http-headers` writes no structured output; its
`output` is the server's header block, one header per line. That is the
single exception to the rule above, kept narrow:

- the output is read as HTTP header lines (`name: value`, leading spaces
  dropped);
- a line whose field name is `ETag`, compared case-insensitively (RFC 9110
  field names), gives the value. The first such line wins.
- nothing else in that output is read, and no other script's output is
  read this way. A line that is not `name: value` is skipped.

The value is kept as sent, quotes and `W/` included, and cut at 256 bytes.

**Where it goes.** The ETag becomes a `host_keys` kind (`http-etag`), derived
like the others and reparsed for old scans through `keys_parsed`. It is a
software-like kind like JA4X and HASSH (`identifies()` is false): a shared
ETag means the same file with the same mtime and size. That can be one kit
on many hosts, but a distro's default page shares it across thousands. So it
gets a Links item page like JA4X, a soft edge in the graph, and is never
shown as a host identity. It sits beside the host keys on the IP and scan
pages.

### Scan facts

The fields below go into the export too: scans gain `facts`, as `{port,
proto, kind, value}`.

## 4. What is parsed from the scan

### Per port: nmap's service element

`<port><service …>`, the attributes nmap sets after `-sV`:

| Field | From | Example |
|---|---|---|
| `extrainfo` | `service/@extrainfo` | `Ubuntu Linux; protocol 2.0` |
| `ostype` | `service/@ostype` | `Linux` |
| `devicetype` | `service/@devicetype` | `router` |
| `hostname` | `service/@hostname` | `23.133.66.148.host.secureserver.net` |
| `cpe` | each `service/cpe` text | `cpe:/a:openbsd:openssh:9.6p1` |

In the export these were set on 400, 402, 3 and 5 ports, with 784 CPEs, over
1,681 distinct scans.

### Per port: scripts with structured output

| Script | Key path | Shown as |
|---|---|---|
| `http-title` | `title` | Title |
| `http-title` | `redirect_url` | Redirects to |
| `http-server-header` | each unnamed `elem` | Server |
| `http-auth` | each table: `scheme`, `params/realm` | Login: `Basic realm="bifrost"` |
| `rdp-ntlm-info` | `NetBIOS_Computer_Name`, `NetBIOS_Domain_Name`, `DNS_Computer_Name`, `DNS_Domain_Name`, `DNS_Tree_Name`, `Product_Version` | Windows names and build |
| `socks-auth-info` | each table: `name` | SOCKS methods (an open proxy says so) |
| `dns-nsid` | `bind.version`, `id.server` | DNS server |

`rdp-ntlm-info`'s `System_Time` is left out: it changes with every scan and
says nothing about the source.

### Per host

| Field | From |
|---|---|
| Windows names | `hostscript/script[@id="smb-os-discovery"]`: `server`, `domain`, `fqdn`, `domain_dns`, `forest_dns`, `workgroup`, `os`, `lanmanager` |

### Kept as they are

`ssh-hostkey`, `ssl-cert` and `ssh2-enum-algos` stay with `scan::hostkeys`
and Links, unchanged.

### Storage

One migration, the next free number:

- `ports` gains `extrainfo`, `ostype`, `devicetype`, `hostname` (TEXT,
  nullable) and `cpe` (TEXT, a JSON array).
- A new table `scan_facts (scan_id, port, proto, kind, value)`, with `port`
  NULL for a host fact and an index on `(scan_id)`. The kinds are:
  - `http.title`, `http.redirect`, `http.server`, `http.auth`;
  - `ntlm.netbios_computer`, `ntlm.netbios_domain`, `ntlm.dns_computer`,
    `ntlm.dns_domain`, `ntlm.dns_tree`, `ntlm.product_version`;
  - `socks.method`, `dns.nsid`;
  - `smb.server`, `smb.domain`, `smb.fqdn`, `smb.domain_dns`,
    `smb.forest_dns`, `smb.workgroup`, `smb.os`, `smb.lanmanager`.
- `scans` gains `facts_parsed INTEGER NOT NULL DEFAULT 0`, like
  `keys_parsed`.
- `ips` gains `ptr` and `ptr_checked_at` (section 2).
- `requests` gains `reached` (section 1).

Facts are **derived, never replicated.** Each node derives them from the
scan's raw XML when it stores the scan, on the same path as host keys
(`store::hostkeys::derive`), so every node holds the same rows for the same
XML. At start, a backfill reads scans with `facts_parsed = 0` in batches of
50, like `hostkeys::backfill`, so scans of earlier releases show them too.

Limits:

- a value longer than 512 bytes is cut at a character boundary;
- at most 64 facts per scan, so a source that answers on thousands of ports
  cannot grow the table without bound;
- the XML is read under the existing `MAX_RAW_XML` cap.

### Display

**Scan page.**

- The ports table gains a "Details" column:
  - product, version and `extrainfo` on one line;
  - then `ostype` and `devicetype`, and the announced `hostname`;
  - CPEs, muted.
- Under a port that has script facts, one indented line per kind present:
  `Title`, `Server`, `Login`, `SOCKS`, `DNS`.
- A "Host" card above the host keys shows Windows names and build, when
  there are any.

**IP page.**

- The reverse DNS name sits under the address.
- Each counter-scan's heading gains a one-line summary of what the source
  serves, taken from the newest scan that has it: distinct titles and
  servers, at most three, each with its port (`8443 PentAGI · 9000 MinIO ·
  80 nginx/1.18.0`).
- The Windows computer name and domain follow, when known.

Every value comes from the source's own answers or its DNS, so it is
escaped like any other peer-supplied text (askama's default). Only the
ETag links anywhere (its Links page). Nothing is a URL the page fetches:
`redirect_url` is shown as text.

## 5. The scanning node's address stays out of its scans

### Scrubbing

A node's **own addresses** for this purpose are the safety list's own
addresses (section 1): interfaces, listeners, `cluster.advertise`,
`scan.own_addresses` and the peer-observed public addresses. Its **own
names** are the forward-confirmed PTR names of the global ones, from the
lookup in section 2, refreshed daily.

Before a scanner signs a `scan_result` or `scan_audit`, it replaces in the
raw XML each of the following with `[scanner]`:

- each own global address, as nmap prints it (IPv4 dotted; IPv6 in nmap's
  compressed form), where the bytes before and after are not part of an
  address (`[0-9A-Fa-f.:]`), so `87.123.41.5` does not match inside
  `87.123.41.56`;
- each own name, compared case-insensitively, where the bytes before and
  after are not part of a name (`[A-Za-z0-9.-]`).

When the scan's target is itself one of the own addresses, nothing is
scrubbed: that scan is about this node, and the safety list refuses it
anyway.

The record gains an optional field, `scrubbed: u16`, counting the
replacements. The scan page then says "the scanner's address was removed
from this scan's output (n times)".

What it does not change:

- The command line in the XML names the target, not the scanner, so
  `profiles::args_ok` judges it as before.
- Ports, identity keys and ETags are unchanged, and those are what audits
  compare (`credits::audit`). An audit of a scrubbed scan agrees exactly as
  before.

### Scans already stored

A scan is signed by its scanner, and no node can change an earlier one.

- Each node scrubs its **own** addresses and names from the raw XML when it
  serves it, in the XML download and the export. Its own old scans leave
  this node clean.
- A node does not know other members' addresses, beyond the ones it sees
  them connect from. It does not scrub those: they are the members' to
  protect, and a purge removes a record everywhere.

This fully fixes scans from this release on, and only partly fixes earlier
ones. The changelog says so.

## 6. The script selection

Levels 3 and 4: `profiles::SCRIPTS` becomes
`(discovery or safe) and not (intrusive or broadcast or external or dos or http-comments-displayer)`.

That script is the only one excluded. It spiders up to 20 pages per HTTP
port and copies every comment it finds, including ones it misreads in
binary files: unbounded text that is of no use for analysis. The other
large scripts in the data (`fingerprint-strings`, `port-states`,
`http-useragent-tester`) are a few KB each and stay.

Level 2: `profiles::IDENTITY_SCRIPTS` gains `http-headers` (section 3).

Both change what "built-in arguments" means for lookup credits
(`credits::earn`: a scan run with other arguments earns no scanner share).
The old lists for levels 2, 3 and 4 go into `profiles::ACCEPTED`, as that
constant's doc says, and are removed two releases later. A scanner on the
previous release keeps its earnings during a rolling upgrade.
`scan.level_argv` overrides are untouched.

## Tests

- **Peer-observed address:**
  - one stranger's `seen_from` is not taken;
  - one sibling's is, and so are two members of different owners;
  - a private or loopback report is ignored;
  - a `hello` without the field (an older peer) changes nothing;
  - an address unconfirmed for 7 days is dropped;
  - a taken address is on the safety list: never scanned, never
    blocklisted.
- **`reached`:** a global local address; behind NAT with one public
  address; with none.
- **Canary return host:** a missing or `localhost` Host with a public
  address known gives that address, with the new `decoy_v`; without one,
  the site name as before.
- **Reverse DNS:**
  - a PTR whose name resolves back is stored;
  - one that does not is NULL;
  - a timeout does not delay recording;
  - the 24-hour refresh and the hourly retry.
- **Parsing**, from XML fixtures cut from real scans (anonymised):
  - every field in section 4, present and absent;
  - a script with only `output` text yields nothing;
  - `http-grep` and `fcrdns` yield nothing;
  - the per-scan cap and the value cap.
- **ETag:**
  - from `http-headers` output, case-insensitive;
  - the first of two lines wins;
  - a line without `name: value` is skipped;
  - quotes and `W/` are kept;
  - the 256-byte cut;
  - old scans gain it through `keys_parsed`;
  - `identifies()` is false.
- **Backfill:** a scan stored before the migration gets its facts and
  `facts_parsed = 1`, once. Two nodes holding the same scan derive the
  same rows.
- **Scrubbing:**
  - an address inside a longer one is left alone;
  - IPv6 compressed form;
  - a name in another case;
  - the target equal to an own address leaves the XML unchanged;
  - the args line and the parsed ports are unchanged;
  - `scrubbed` counts the replacements;
  - the export and the XML download scrub this node's own addresses from
    old scans.
- **`profiles`:**
  - the new built-in lists are `args_ok`;
  - the old ones for levels 2 to 4 are too, through `ACCEPTED`;
  - a list with `http-comments-displayer` added back by hand is not.
- **Export:** `host_keys`, `facts`, `ptr` and `reached` are present.

## Not in this spec

- **New Links kinds for NTLM computer names, page titles or servers.** They
  would tie sources together like host keys. Wait until the data shows they
  repeat across sources often enough to be worth a graph. ETag is the one
  new Links kind.
- **Dating a source from its nginx ETag** (the mtime half). It needs a guess
  about which server wrote the ETag. The value is shown as sent.
- **ETags as a return marker** (decoys sending ETags). It stays a separate
  roadmap item.
- **Parsing other free-text scripts** (`banner`, `http-generator`, `nbstat`,
  `smtp-commands`). If one of them matters later, the fix is a newer nmap
  that writes it structured, not a parser for its text.
- **A smaller export beyond the script change.** Per-IP data on each row is
  how the export is built (`docs/dataset.md`). A separate per-IP file, or an
  option to leave out the XML, is its own change.
- **Removing other members' addresses from scans they signed.**
