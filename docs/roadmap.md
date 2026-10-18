# Roadmap

What is planned, in order, with what each item costs and what it brings.
Shipped items move to the [changelog](../CHANGELOG.md).

**Cost**: S = about a day, M = a few days, L = a week or more, including
tests and docs. **Benefit**: what it adds for an operator, for the dataset,
or both.

Every item names where it shows up. The public dashboard only ever shows
aggregates: no request contents, no fingerprints, no single scan results
(see [What is public](overview.md#what-is-public)). Everything else goes to the admin area.

## Evidence from the running cluster

Measured on the real cluster, 30 days, before this roadmap (2026-10-04):

- **About 465 source IPs.** 453 were seen on a single day, 12 on 2–3 days,
  none on more. Scanners almost never come back from the same address, so
  linking work across addresses (campaigns, canary reuse) is what is
  missing.
- **Exact path-set matches.** Groups of 2–5 IPs sent the identical 132-path
  `.env`/cloud-credentials sweep, the identical 189-path webshell list and
  the identical 44-path phpunit sweep. Near-copies (132/131, 81/80, 44/42
  paths) are the same tool and should be grouped too. Benign crawler paths
  (`robots.txt`, `security.txt`, `favicon.ico`, `sitemap.xml`) also match
  exactly, so paths need weighting by rarity.
- **JA4 alone links too much.** The top value covered 27 IPs; it is a TLS
  library default, not an operator.
- **Decoy reach.** 307 requests from 55 IPs (about 12 % of sources) would
  have hit a decoy. Decoys were off then and are always on now.

## Next

### 1. New paths and exploit waves

- **Cost:** M (the path normalization shipped with campaign clustering)
- **Benefit:** high. It gives early warning when a new exploit starts
  spreading, often before CVE write-ups.

- A cluster-wide `first_seen` per normalized path, plus the number of
  distinct IPs that sent it. The node-local start exists: the `shapes`
  table (one row per path shape, with `first_seen`, `last_seen` and `ips`,
  derived on insert and backfilled); what is left is agreeing on it across
  the cluster.
- A path with no matching rule that reaches N distinct IPs within an hour
  is an exploit wave.
- It lives inside the campaign view ("campaign #N started probing a path no
  rule knows"), not as a separate inbox, which would only be noise.

**Shown:**

- **Admin:** a "New paths" view (first seen, distinct IPs, campaigns), a
  badge on the live feed, and an optional webhook or ntfy push.
- **Public dashboard:** a count of new path shapes this period (paths themselves
  are request contents, so not public).

### 2. Personas per node or hostname (opt-in)

- **Cost:** M
- **Benefit:** medium–high. A controlled comparison of targeted versus spray
  traffic across the cluster.

A node, or an SNI/Host name, consistently presents as one product
(WordPress, a Fortinet appliance, a GPU box). Three conditions keep the
dataset clean:

1. The persona is recorded on every request, like `answer`.
2. It stays stable over time.
3. It is opt-in.

Per-IP version roulette is ruled out: scanners that use many source IPs
would see the banner change from visit to visit, and that gives away the
honeypot.

**The AI decoys vary per node, persona or not.** Today every node's MCP
decoy answers with the same `serverInfo` (`internal-ops 0.3.1`), the same
resources and the same tools, and the LLM decoy with the same model list.
One fingerprint of those identifies every member of the cluster. The
server name and version, the tool and resource set, and the model list
are derived from the node's identity: stable per node, different between
nodes, and recorded like any persona. With a persona set they follow it.

**Shown:**

- **Admin:** Analytics follow-up rate and family mix per persona.
- **Public dashboard:** attack mix per persona.
- **Dataset:** a `persona` column.

### 3. AI agent detection

- **Cost:** M
- **Benefit:** high. It tells which traffic an LLM agent drives, a class of
  attacker that grows fast and that the dataset cannot name today.

`rules/ai.toml` labels what is probed (`ai-infra-probe`, `mcp-probe`,
`mcp-abuse`, `llm-key-use`), not who probes. An agent leaves traces of the
model in what it sends, and these are checked on every request: body,
query string and headers, not only on traffic to the AI decoys.

- **Model artifacts.** Chat-template tokens (`<|im_start|>`, `[INST]`),
  role and tool tags (`<tool_use>`, `<function_call>`, `<thinking>`),
  tool-call JSON, and an LLM's self-description or refusal text in a
  parameter. Label `ai-agent-artifact`.
- **Agent tooling.** SDK and framework headers and User-Agents (OpenAI and
  Anthropic SDK `X-Stainless-*` headers, LangChain, LlamaIndex, browser-use
  and the like), and the `clientInfo` an MCP client sends in `initialize`.
  Label `ai-agent-tooling`.

Both are ordinary built-in rules: deterministic, from the signed request
alone, so every node derives the same labels and nothing rests on a
peer's claim. No weighted score and no timing heuristics: regular timing
does not tell an agent from a scanner.

**Precision first.** Before release the rules run over the full 30-day
dataset; every hit is reviewed and every false positive becomes a negative
test. Pattern matches inside payloads that merely carry such strings (a
prompt-injection probe aimed at someone else's LLM) are kept apart from
an agent's own traces.

**Shown:**

- **Admin:** a filter on the live feed and `/requests`, a badge on the IP
  page, and an "agent-driven" mark on a campaign any of whose requests
  carries the label. Analytics gives the share of agent-driven sources and
  campaigns over time.
- **Public dashboard:** share of sources with agent traces this period.
- **Dataset:** the labels, in the existing `labels` column.

### 4. AI discovery lures

- **Cost:** M–L
- **Benefit:** high. Agents look for machine-readable descriptions first;
  answering them leads the agent into the MCP and LLM decoys and their
  canaries instead of letting it leave.

Requests for `/.well-known/ai-plugin.json` and `/openapi.json` are
classified but get no answer of their own, so an agent that finds nothing
there moves on. The trap answers the discovery documents agents read:

- `/.well-known/ai-plugin.json`, `/.well-known/mcp.json`,
  `/.well-known/agent.json` (A2A agent card), `/llms.txt`;
- `/openapi.json`, `/swagger.json` and the common `api-docs` paths, with
  a spec that describes only endpoints the existing decoys answer (MCP,
  the LLM gateway, the upload sink).

Each document points into the decoys and carries a canary derived for the
request (an MCP endpoint path, an API key), so a follow-up from another
address links back to the discovery request: a hard edge for campaign
clustering, where address rotation otherwise breaks the chain.

Rules that hold:

- **No runtime LLM.** Documents are rendered from the node's identity and
  persona (item 2), deterministic and cached.
- **Nothing real.** The documents never name or link the operator's real
  sites, and never echo request content beyond the canary.
- **Recorded like every decoy.** The answer is `decoy:discovery:<kind>`.

**Shown:**

- **Admin:** a Discovery tab under Decoys: which documents were fetched,
  and the funnel discovery → MCP `initialize` → tool call → canary reuse,
  per source and per campaign.
- **Public dashboard:** count of sources that followed a discovery
  document into a decoy.
- **Dataset:** the `answer` value, and the canary link in `campaign`.

## Small follow-ups

- **VPN and relay exits.** M, high. Scanning a VPN exit scans the VPN
  company, a bystander, as with Tor exits. Load X4BNet's `lists_vpn` (MIT,
  ASN-derived) the way the Tor list is loaded. Listed IPs are never
  scanned, flagged like `is_tor_exit`, and kept off the blocklist. Shown
  on the IP page, as an IP directory filter, and as a public "via VPN"
  share beside the Tor share.
- **Proxy signals from our own data.** S, medium. A `Via`, `Forwarded` or
  `X-Forwarded-For` header in the probe itself means a forwarding proxy
  (a rule label); a counter-scan finding `socks5`, `http-proxy` or OpenVPN
  means the source likely is one. Both are admin-only flags on the IP page.
- **JA4T on directly listening traps.** S–M, medium. `TCP_SAVE_SYN` and
  `TCP_SAVED_SYN` give the client's SYN without pcap. This works only where
  the trap listens on 80/443 itself; behind nginx the SYN goes to nginx.
  Shown on the request page and in Analytics. A lowered MSS (around 1380
  for WireGuard, 1360 for OpenVPN) also hints at a tunnel.
- **Dashboard timeline drill-down.** S, low. For admins, each bucket of the
  dashboard timeline links to `/requests` filtered by that bucket's `from`/`to`,
  as the Analytics charts already do.
- **Queue a counter-scan or block from the Lookup page.** S–M, low. The
  probe and vantage actions exist; the manual scan queue and the block
  action do not yet.
- **Cluster log polish.** S–M, low. The owner found the cluster log
  "a bit un-polished" (feedback on the Android app, 2026-10-10). The admin
  cluster pages get a UX pass first, then the fixes.

## Not planned

- **Passive DNS.** The useful sources (DNSDB, SecurityTrails, VirusTotal,
  OTX, CIRCL) need an API key or vetting and are proprietary data; and
  sources seen once from a throwaway VPS rarely have domains. Reverse DNS
  covers the free part.
- **Per-vendor VPN exit lists** (Mullvad, Proton VPN, NordVPN, iCloud
  Private Relay, …). Which vendors to include would be our own arbitrary
  choice, and every list is one more source to keep working as vendors
  change their endpoints.
- **Paid anonymizer detection** (ip-api, proxycheck.io, IPinfo privacy and
  the like). Residential proxy exits are ordinary home addresses and cannot
  be told apart without such a service, so they stay undetected.

## After 1.0

- **Feeds in other formats.** STIX/TAXII or a MISP feed beside
  `/api/blocklist`, and a CrowdSec-compatible endpoint. Cost M.
- **Weekly digest page.** A generated, permalinked public summary: new
  families, the largest campaign, new path shapes, top movers. Cost M; worth
  it once items 1 and 2 exist.
- **Hall of fame.** Oldest CVE still probed, strangest User-Agent, longest
  payload, as aggregates. Cost S–M.
