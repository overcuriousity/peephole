# Overview

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

This page is for deciding whether to run a node. The details are linked
from each section.

## Roles

A node runs any mix of three roles:

| Role | Does | Needs |
|---|---|---|
| listener (the trap) | records and classifies every request no real site answers, and queues scans | a place in front of or behind your web server: ports 80 and 443 itself, or nginx or another proxy passing it the unmatched traffic |
| scanner | counter-scans and probes sources, for jobs from any trap | nmap, and a hosting provider that allows it; opt-in |
| web | the public dashboard and the admin area | a domain pointing at the machine, HTTPS, a FIDO2 security key (or a password) |

In a cluster a node need not run all three: a trap-only node can join, and
your own web node, or one you can sign in to, shows the whole cluster. The
admin area and the blocklist feed come with the web role. Roles can be
switched at runtime. Setting a node up: [Install](operations.md#install).

## What a node does

1. **Catch.** peephole runs as the fallback behind your web stack. Every
   request that matches no real site lands in the trap, which records it
   with headers, body, the raw request head and, over HTTPS, the raw TLS
   ClientHello and its JA4 fingerprint. Floods are sampled, but every
   request still leaves at least a light row or a count. As a side effect,
   scanner noise stays out of your real sites' logs.
2. **Classify.** Signature rules built into the binary label each request
   (sixteen families, from SQL injection and RCE to webshells and
   AI-infrastructure probes, each with its OWASP reference) and give it a
   severity from 0 to 4.
3. **Enrich.** The source address is looked up: country and ASN, the Tor
   exit list, registration data, and optionally AbuseIPDB and Shodan.
4. **Investigate.** A source that did enough is counter-scanned with nmap,
   escalating by scope, never by aggressiveness. A source that sent an
   exploit is held in a tarpit for up to 10 minutes per request. Decoys
   for the files scanners look for first (`.env`, `.git/config`, wp-login,
   phpinfo) serve credentials that name the request they were served to,
   so when one comes back, from any address to any node, you learn who
   harvested it and when.

How each step works: [Detection](detection.md).

The admin area (FIDO2 security keys, optionally a password) is where all of
it can be read: request search and inspection, a live feed, analytics, a
page per IP with every enrichment result and scan, the scan queue, a Links
area that connects addresses sharing a browser fingerprint, SSH host key,
TLS certificate or other fingerprint, canary reuse, a false-positive inbox,
and the dataset export. Every row says which node recorded it, by name and
key, and which build it ran.

peephole is one binary with SQLite. Fonts, scripts and the world map are
built in; its web pages make no external requests and come in light and
dark themes.

## The cluster

Nodes form a cluster over mutual TLS and share one dataset: every request,
the scan queue, scan results, lookups and what is known about each address.
Every node keeps a full copy (or the last N days of it), so any web node
shows the whole cluster.

- **No central server, no trust required.** Every entry is signed by the
  node that wrote it, and every node checks what it receives and decides
  for itself whom it trusts. Joining takes an invite from a member that
  others can reach.
- **Nobody can be removed.** A node leaves by itself, or is pruned after 30
  days without a sign of life. Instead, each node can block any member
  locally: it stops talking to it and stops showing its records, and other
  nodes are unaffected.
- **Every member sees everything** the cluster records, raw requests
  included, and can export the whole dataset. A node may keep only the last
  N days while others keep the whole history.
- **One operator, several nodes.** Your own nodes can share an ownership
  key and be managed from one place. In the market they may pool their
  credits for paid lookups, probes and name resolutions, and each trusts
  its own fleet's audits; nothing else differs.

How it works and what it cannot prevent:
[Membership and trust](protocol.md#membership-and-trust).

## Credits

Work one member does for another — a lookup through its providers, a name
resolution, a probe, a scan job, an audit, a relay — is a good bought with
credits.

- **Where they come from.** A fixed pool of credits a day is split among
  the members anyone can reach that run a trap and were up for at least
  half of the day. Everything else is earned by selling.
- **Prices follow sales.** A good that sells gets dearer, one that does not
  gets cheaper, down to free. Every node computes every price and balance
  for itself, from its own copy of the log.
- **Some answers are free.** What a node answers itself (its own providers,
  resolver, scanner) is free, and an answer under 24 hours old is served
  from the dataset for free.
- **Credits buy nothing outside the cluster.**

A standalone node uses its own providers only. The full rules, and what
they cannot prevent: [Credits](protocol.md#credits).

## What is public

A web node publishes a public dashboard and a blocklist. Everything else —
request contents, fingerprints, single scan results, node names and keys —
is admin-only.

**The public dashboard** shows aggregates per time range: trends against
the previous period, scanner time wasted in the tarpit, requests over time
by severity, a weekday × hour heatmap of the last 7 days, attack families
and an OWASP Top 10 / Automated Threats map, a world map, top IPs and
networks, the ports most often found open on the scanned sources, and a
searchable IP directory (exact, prefix or CIDR). Each IP has its activity
calendar, rank and neighbours (same /24 and ASN).

- **It is delayed**: a request appears only after `[public] delay_minutes`
  plus up to `jitter_minutes` more (5 + 0–5 minutes by default), so the
  dashboard cannot be used to watch a scan live.
- **It names addresses.** The IP directory and the IP pages are public.
- **Requests appear as method and path only**: no query string, cut at 80
  characters. Bodies, headers, query strings and fingerprints are never
  public.
- **Scan results only as counts**: per port, the number of distinct IPs it
  was found open on, and a port only once it was found open on at least
  three.
- **The card "What they asked our fake AI"** shows only our own tool names,
  and model names that are lowercased, match `[a-z0-9._:/-]{1,64}` and were
  asked by at least 2 IPs (else "other").
- **Rule labels**, and the families and OWASP tags derived from them, can
  be hidden too.

**The blocklist feed**, `GET /api/blocklist`, lists the addresses that sent
requests of severity 3 or more in the last 24 hours, after the same delay,
one per line, for nginx `deny`, nftables, ipset, fail2ban or CrowdSec. It
takes `hours`, `min_severity`, and `networks=1` to collapse busy /24s. In a
cluster it is drawn from every member's trap, so one node's catch protects
everybody's real sites. Tor exits, verified crawlers, cluster members and
the node's own networks are never listed. Every node documents its public
endpoints at `/api`, linked in the footer.

## Risks

> [!WARNING]
> Counter-scanning is legally restricted in some jurisdictions, and scanning
> back can get your address reported for abuse — to your hosting provider
> among others. Check what applies to you before you deploy.

- **The scanner role is opt-in.** Most hosting providers forbid scanning
  others, and the installer names the large clouds whose acceptable use
  policies do. A trap without a scanner scans nobody; its sources are
  scanned, if at all, by members who run one.
- **Abuse reports go to the scanner's provider.** Counter-scans come from
  the scanner node's address, not the trap's.
- **Bystanders are spared.** One request earns at most a light scan.
  Verified crawlers and research scanners, Tor exits, cluster members, your
  own addresses and the networks you list in `never_scan` are never
  scanned, and budgets per network, per ASN and for the queue stop floods.
  `never_scan` applies on your own scanner only; other members' scanners
  may still scan those addresses.
- **The public dashboard names addresses** that sent requests to your trap.
- **The other members see everything your trap records**, raw requests
  included.

## Is this for me?

You want this if:

- you run public web servers and want a blocklist built from what many
  traps saw, not only your own;
- you want a labelled dataset of real scanner traffic, with enrichment and
  scan results, for research or your own analysis;
- you want to see who probes you, from where, and with what.

It is not:

- a firewall or an intrusion prevention system: it records and publishes;
  blocking is up to you, with the feed;
- a shell or service emulator: it answers HTTP and HTTPS, with decoys for a
  few well-known files and AI endpoints (MCP, LLM gateways).

Next: [Install](operations.md#install).
