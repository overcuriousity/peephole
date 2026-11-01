# Attack chains and body X-ray: design

Status: written after the brainstorm of 2026-11-01. Marked **(my call)** where
Claude decided and the user has not specifically agreed. Everything else was
agreed in conversation.

## Why

peephole records attacks in great detail but shows them as isolated rows. One
request's body names the next stage of the attack, and today nobody can see that
from the address, the campaign or the request. The aim, in the user's words, is
to become "the number 1 cybersecurity threat intel tool". Analysis depth and the
interface are the product.

Measured on the observer node on 2026-11-01, with a rough extractor (real parser
numbers will differ):

- 163 addresses name one stager, `hxxps://217[.]60[.]102[.]5/sh`. **None is in a
  campaign.** They send too few shapes for a soft edge, and the 50-address hard
  cap would drop a stager edge.
- 967 of 57,530 requests with a body or query hide code or URLs in base64 (68
  addresses). Everything measured decoded in one layer. Another 2,659 use
  character escapes and 637 long hex strings; those were not decoded.
- Without decoding, `/hello.world` and `POST /` looked like harmless probes. They
  are a CVE-2024-4577 exploit. Decoding moved the operator from 144 to 163
  addresses.
- Decoded text holds operator-level evidence: one SSH private key across 73
  requests and 37 addresses, used for `scp` from the stager, with `wget`/`curl` as
  fallback.
- Attackers name their own exploits in an argument: `apache`, `php2shell`,
  `cve_2024_4577`, `cve_2024_4577.selfrep`, and `jaws` for Mozi.
- The upload trap holds 16 uploads, 6 distinct contents, 229 bytes in total, none
  encoded. Its value is linking, not decoding. `pr3d4t0r.php` was uploaded 4 times
  from 3 addresses and requested one second later under
  `/wp-content/plugins/wp-file-manager/lib/files/`, which answered 404 every time.

## Goals

1. From any request, address, campaign or piece, see the whole chain and your
   place in it.
2. Parse bodies fully, across layers, for requests and text uploads, and show the
   result in the UI beside the original bytes.
3. Tie addresses to one operator on the strong evidence decoding reveals.
4. Show honestly what was seen, what the attacker only claimed, and what is
   missing.
5. Show where our trap ended a chain, so those gaps can be closed.
6. After the feature, streamline the interface in general (Phase 2).

## Non-goals

- Nodes never fetch, contact or resolve anything found in a payload. The operator
  takes URLs to an external sandbox.
- No dynamic analysis, no emulation, no execution, no deobfuscation that needs an
  interpreter.
- Binary analysis. Binary uploads stay zip-only.
- Public pages and the public dashboard do not change.
- The Parquet dataset export does not change, apart from campaign keys moving (see
  Rollout).
- STIX, TAXII or other threat-feed output. The dossier is how chains leave the
  node for now.
- Sequence mining and kill-chain ordering. The median stager address sends two
  requests, so order carries little information. The Story view was rejected.

## Anti-goals

It fails, even if it technically works, when:

- Attacker-written text is presented as fact.
- A body string an attacker can write freely merges unrelated operators.
- The parser can be made to hang, exhaust memory or panic by a body sent to a trap.
- A captured private key is displayed by the feature, or ever used.
- Any page renders attacker content unescaped.

## Constraints from the codebase

- Derived data is node-local, recomputed from replicated rows, never replicated,
  and versioned. Follow `model::shape` with `requests.shape_v`, `store::webshell_cmd`
  with `cmd_v`, and the recompute style of `ip_evidence` (`0047_ip_evidence.sql`).
- Next migration number is 0052.
- `store::links` already splits kinds into identity (one operator) and software (a
  shared tool). `docs/detection.md` states the same rule for campaigns. Chains must
  not break it.
- `campaign_members` keeps one campaign per address. `K_SOFT_MERGE` already guards
  group merges.
- `trap::mod::MAX_BODY` keeps 64 KiB. The request page shows the first 16 KiB.
- `ip.html` and `_target.html` are shared by the public and admin address pages.
  Everything here is admin-only.
- Defang addresses and URLs from payloads in all output (`hxxps://`, `[.]`). Links
  to them are never clickable.

## The model

One parser, one kind of record, one chain.

```
requests ─┐
uploads  ─┼─► X-ray parser ─► pieces + sightings ─► chain(anything) ─► strip, flow map,
results  ─┘   (static, bounded)  (derived, versioned)                    X-ray, Links, dossier
```

**Piece:** a normalised thing found in a source, identified by
`crate::canary::hash(kind + value)`, so the same piece has the same id on every
node and across recomputes.

**Sighting:** a piece at a role, with an evidence grade, in a source. Links pages
already read kinds "as sightings", so that is the word.

**Chain:** never stored as fact. It is read from sightings, so a better parser
rebuilds past chains for as long as the bodies are retained.

### Describers and joiners

| | Describers | Joiners |
|---|---|---|
| Say | What happened | Who: one operator |
| Kinds | exploit, recipe, exploit tag, shell profile | stager, SSH key, file hash |
| Links kind | software | identity |
| Join addresses | Never | Yes, under the rules below |

Recipes are describers because they identify software, not an operator. Mozi's 17
addresses become browsable through their recipe but form no campaign.

### Roles and evidence

Roles: `exploit`, `tag`, `recipe`, `stager`, `self_hosted`, `queried`, `key`,
`file`, `opaque`.

Grades:

- **seen:** the trap received or held it (request path, uploaded file).
- **claimed:** the attacker's text says so; nothing confirmed it.
- **external:** an operator entered it from outside analysis.
- **gap** and **dead end** are display states computed for the strip, not stored.

### When a request gets an exploit piece

`model::shape` drops the query and has no method, so `POST /` alone says nothing.
An `exploit` piece exists only for a source that carries something executable: a
recipe, a PHP execution layer, a PHP-CGI argument injection, or an upload. Other
requests get no pieces, so they show no strip.

Its value is the method, the shape, and the query's normalised argument names, such
as `POST /hello.world ?-d allow_url_include -d auto_prepend_file`. The parser
recognises PHP-CGI argument injection as a layer of its own (soft hyphen `%AD`
before `-d`), because no rule covers it today.

The Exploit stage groups exploit pieces by attacker's tag, up to its first dot, so
`cve_2024_4577` and `cve_2024_4577.selfrep` are one row listing both paths.

### When a URL is a stager

A URL counts only if the recipe fetches it **and** runs or saves the result.
A URL that is only queried gets role `queried` and joins nothing. The dry run
proved this is required: `management.azure.com` and `metadata.google.internal`
formed false groups because a recon script queries them.

Normalised value:

- Default: lowercased host, without port. Every full URL or `scp` target seen for
  it is kept in `piece_urls`, because a bare host is no use in a sandbox.
- Hosts on the shared-host list: full URL without query. Pastebin and surge.sh
  users are unrelated.
- Not a joiner, recorded as `queried`: private, loopback, link-local, unspecified
  addresses, hosts with template characters, schema hosts such as `w3.org` and
  `schemas.xmlsoap.org`.
- URL host equals the sending address: role `self_hosted`, a describer. A bot
  serving its own payload says nothing about an operator.

The shared-host list lives in `rules/evidence/shared_hosts.toml` **(my call)** and
starts with pastebin.com, surge.sh, github.com, githubusercontent.com,
transfer.sh, gist hosts. The builder extends it from the data.

### SSH keys

Value: the SHA-256 fingerprint of the public key, read from the OpenSSH private
key's public section without decrypting anything, matching `ssh-keygen -lf`.
Other PEM keys: SHA-256 of the normalised PEM.

- The X-ray replaces key material in decoded text with `[private key]` and the
  fingerprint. The decoded layer is never stored.
- The X-ray's original-bytes pane masks it too, wherever it appears unencoded or
  percent-encoded. A `BEGIN … PRIVATE KEY` marker is enough, through the `END` marker
  or the end of the text, so cut or malformed keys are masked as well. Highlights are
  computed around the masked range, not from raw offsets.
- The stored body stays as it is, because it is the evidence record. The hex toggle
  and the dossier's `body_b64` still carry those bytes, as they do today. This is a
  known limit. A key written line by line across several commands has no marker to
  find and is not masked.
- peephole never uses the key. Nothing in the code may read it for any other
  purpose than the fingerprint.

### File hash

Uploads with at least 32 bytes **(my call)**, so `test` and empty files join
nothing. Generic webshells are shared between unrelated operators, so file hashes
keep `HARD_FANOUT_MAX`, for chains and campaigns alike.

### Webshell profile

The X-ray reads uploaded text webshells as well as requests. For one it records a
`shell_profile` describer **(my call)**: the input it reads (`$_GET['cmd']`), its
execution function, any password check, and strings it echoes as a marker. That
answers "which webshell is this" without running it, and shows two shells apart when
their hashes differ. A shell's input name also tells the Follow-up stage where to
look.

### Exploit tags

The last argument to the executed payload (`sh -s <tag>`, `out_sh <tag>`,
`Mozi.a <tag>`) is stored as a claimed `tag`. The UI labels it "attacker's tag".
It is treated as a hint, never as a verified CVE.

## Parser: `model::xray`

A pure module with no I/O, in the style of `model::shape`: total on any input,
never panics.

```rust
pub const XRAY_V: i64 = 1;
pub fn parse(input: Source<'_>) -> Xray;   // Source: path, query, headers, body or upload text
```

`Xray` is a tree of layers. Each layer has a kind, its text, the byte range it came
from in its parent, and pieces with byte ranges in that layer.

Layers, in order of need:

1. Percent and `+` decoding of query and form values.
2. Multipart fields, including field names and file names. Padding fields are
   collapsed when several fields share a name pattern and look random.
3. JSON string values, XML text.
4. PHP: `<?php` blocks, `system`, `shell_exec`, `exec`, `passthru`, `eval`,
   `assert`, and the decoders `base64_decode`, `gzinflate`, `gzuncompress`,
   `str_rot13`, `hex2bin`, `chr()` runs, recognised as text patterns and never run.
5. Base64 and base64url, including inside shell (`echo … | base64 -d`) and bare.
6. Gzip, zlib, deflate after base64.
7. `\xNN`, `%NN` runs, long hex strings.
8. Shell: a real tokeniser over `;`, `&&`, `||`, `|`, `if … then … else … fi`,
   `$( )`, backticks, quotes.

Base64 is only accepted when the output is mostly printable or a known container,
or bare hex and random tokens will become false layers.

Bodies that do not open get an `opaque` piece with the reason: `high entropy`,
`unknown encoding`, `too deep`, `over limit`. Never a guess.

Recipes are normalised into a tree of steps, so branches survive:

```
prepare(cd) → write(key) → try[ fetch(scp) → run(tag) ] else [ fetch(wget|curl) → run(tag) ] → cleanup
```

The recipe piece's value is that tree with hosts, URLs, file names and numbers
replaced by placeholders.

Limits, enforced in the parser:

| Limit | Value |
|---|---|
| Input | 64 KiB body, 1 MiB upload text (their existing caps) |
| Depth | 6 layers |
| Total decoded output | 256 KiB per source |
| Output of one decompression | 256 KiB, stopped as it streams |
| Layers per source | 128 |
| Pieces per source | 256 |

Past a limit the parser stops and records `opaque`. It uses no regex engine with
backtracking, and no recursion the depth limit does not bound.

Tests: unit cases from each family above, using `192.0.2.0/24` addresses and
generated keys, never captured material. A property test feeding arbitrary bytes.
Add a fuzz target if it fits the repo's tooling.

## Storage

Migration `0052_chains.sql`, all node-local, never replicated, never exported:

```sql
ALTER TABLE requests ADD COLUMN xray_v INTEGER NOT NULL DEFAULT 0;
ALTER TABLE uploads  ADD COLUMN xray_v INTEGER NOT NULL DEFAULT 0;

CREATE TABLE pieces (
  hash INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  ips INTEGER NOT NULL, sources INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE piece_sightings (
  piece INTEGER NOT NULL, source_kind TEXT NOT NULL,   -- 'request' | 'upload'
  source_id INTEGER NOT NULL, ip_id INTEGER NOT NULL,
  role TEXT NOT NULL, grade TEXT NOT NULL, ts TEXT NOT NULL,
  PRIMARY KEY (piece, source_kind, source_id, role)
) WITHOUT ROWID;
CREATE INDEX idx_sightings_source ON piece_sightings(source_kind, source_id);
CREATE INDEX idx_sightings_ip ON piece_sightings(ip_id);

CREATE TABLE piece_urls (                    -- raw attacker text, shown defanged
  piece INTEGER NOT NULL, url TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, sources INTEGER NOT NULL,
  PRIMARY KEY (piece, url)
) WITHOUT ROWID;

CREATE TABLE chains (
  key TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  ips INTEGER NOT NULL, sources INTEGER NOT NULL, v INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE chain_pieces (
  chain TEXT NOT NULL REFERENCES chains(key) ON DELETE CASCADE,
  piece INTEGER NOT NULL, PRIMARY KEY (chain, piece)
) WITHOUT ROWID;

CREATE TABLE piece_results (                 -- written by an admin, node-local
  piece INTEGER NOT NULL, id INTEGER NOT NULL, sha256 TEXT, family TEXT,
  source_url TEXT, note TEXT, added_by TEXT NOT NULL, added_at TEXT NOT NULL,
  PRIMARY KEY (piece, id)
) WITHOUT ROWID;
```

Decoded text is never stored. The X-ray for a page is computed when the page is
requested, from the stored source. Parsing is bounded, so this is safe, and it means
no decoded malware sits in the database. `piece_urls` keeps at most 32 URLs per
piece, the newest, at 512 bytes each.

Extraction runs in the maintenance loop in batches, like `shapes::backfill`, not on
the write path, so the trap never pays for parsing **(my call)**. Rows with
`xray_v < XRAY_V` are read again. Light rows (`skipped_requests`) carry no body and
are skipped. A piece value is capped at 512 bytes.

## What a chain is

A chain is one connected group of joiner pieces. Two joiners connect only when they
appear together in sources from **at least two distinct addresses**, so one forged
body naming two stagers fuses nothing. Sharing a recipe never connects them, and
neither does an address merely using both. File hashes over `HARD_FANOUT_MAX` are
left out. The stager and SSH key connect under this rule (37 addresses). A chain's
key is the hash of its oldest joiner, so it stays put as it grows.

What belongs to a chain:

- **Sources:** every source holding one of its joiners. A source naming two
  unconnected joiners counts in both chains.
- **Pieces (`chain_pieces`):** its joiners, and every describer sighted in its sources.
- **Follow-ups:** tied through the file, not the address: webshell commands and
  requests to an upload's answered path, which is what the upload page's timeline
  already reads. Nothing is attached just because the same address sent it, so a
  noisy scanner cannot fill a chain.

A chain is about pieces and a campaign is about addresses, so a chain can span
campaigns. A campaign page shows every chain of its members.

`chains` and `chain_pieces` are rebuilt in the hourly pass, in the transaction that
rebuilds campaigns.

`chain(anchor) -> Chain` lives in `store::chains` and is the only way views read:

| Anchor | Result |
|---|---|
| Request or upload | Its chain. With no joiner, a one-source chain of its own describers, plus a link to chains its address is in |
| Address | Every chain it has sightings in, newest first |
| Campaign | Every chain of its members |
| Piece | Its chain, or a chain of sources sharing it for describers |

An address can be in several chains. It stays in one campaign.

### Stages

| Stage | Holds |
|---|---|
| Exploit | Exploit shapes and attacker's tags |
| Command | Recipes |
| Delivery | Stagers, keys, uploaded files |
| Payload | Uploaded file text (seen) or `piece_results` (external), else a gap |
| Follow-up | Everything sent to a landed file, read through the X-ray, or a dead end |

Follow-ups do not depend on `requests.cmd`. That column reads 8 parameter names and
keeps 256 bytes, while the full query and body are stored, so the X-ray reads those
and uses the shell's own input name when its profile has one.

Requests answered `webshell` on `/` are not follow-ups. Until `411e2a6`, a `PUT /`
made the landing page answer as a webshell: 16,070 of 16,122 such rows on the
observer are ordinary traffic. Decoy paths are excluded the same way. Those rows
stay in the database, so views and counts of webshell activity must not treat them
as real use.

**Dead end:** the same address asks for the uploaded file's name within 60 seconds
and gets a 404 **(my call)**.

## Campaign changes

Add edge kinds `stager`, `key` and `file` to `campaign_edges`. Bump `CAMPAIGN_V` to
3 and extend the signature with `XRAY_V`.

- **Stars, not pairs.** 163 addresses as pairs is about 13,000 rows. A joiner links
  each address to the value's oldest address, so n−1 edges.
- **Stager and key are exempt from `HARD_FANOUT_MAX`.** They use the role and
  shared-host filters instead. File hash keeps it.
- **All three are guarded joiner edges, in a phase of their own.** Anyone can name
  someone else's stager or upload a public webshell. `compute()` runs its hard and
  soft phases as today, then this one, and joiner edges never count in the existing
  guard.
- **The guard counts addresses, not links.** An address outside any group joins
  freely, which keeps the 163-address group. Two groups of two or more addresses
  merge only when at least `K_SOFT_MERGE` distinct addresses in **each** group name
  the shared value. One value or several makes no difference, so a body naming a
  stager and its key still counts as one address. An unmet merge keeps its edge, shown
  as "not merged".
- **Known limit:** an attacker controlling two addresses in each of two groups can
  still merge them. The edge list shows these as claimed, so a person can see why.
- **Both ends must name it.** A value on one address forms no edge.
- `campaigns` gains a `joiner_edges` count. `hard_edges` keeps its meaning, so joiner
  edges do not make a campaign read as hard evidence. The edge list marks them as
  claimed. Glossary and `docs/detection.md` explain them.

## Interface

### Evidence styling

One visual language everywhere, with text as well as line style, so it does not
rely on colour: solid for seen, dashed for claimed, double or labelled for external,
hatched for gap, red for dead end. Joiners get an accent edge.

### Chain strip: `_chain_strip.html`

Five stage columns (Exploit, Command, Delivery, Payload, Follow-up), the same on
every page. Server-rendered. It wraps to a stack on narrow screens.

- **Request and upload pages:** at the top. Stages this source did not use stay
  visible and dimmed, so one request still shows the operation around it. "You are
  here" marks its own pieces.
- **Address page:** admin only, first section in `_target.html`. Several chains:
  the newest strip open, others collapsed, at most 5 with a link for the rest.
- **Campaign page:** one strip per chain, under the flow map.
- **No pieces:** no strip and no empty card.

Each piece links to its Links page. A gap in Payload links to the stager's page,
where the result form is.

### Flow map: `_chain_flow.html`

Main view on campaign pages, above Members. Band width is requests, and it is
server-rendered SVG. Columns are the stages, with gaps shown as gaps. It follows the
`dataviz` skill and `45-viz.css`, and keeps a table alternative. Above 12 pieces in
a stage, the rest group into "n more".

### Body X-ray: `_xray.html`

Replaces the Body card on the request page and appears on the upload page for text
uploads. Moved to directly below the strip.

- Left: original bytes. Right: layers as an indented tree, recipe as steps with
  branches.
- Hovering or focusing a highlight marks its counterpart. It works by keyboard and
  needs a small `assets/js/xray.js`. Without JS, everything is still readable.
- Random padding collapses with a count.
- Text and hex views stay. The display limit moves from 16 KiB to 64 KiB.
- Escaping is askama's. No `|safe` on anything from a body or upload.

### Pieces

New `LinkKind`s: `Stager`, `Key`, `File` (identity), `Recipe`, `ExploitTag`
(software). Their page is the existing Links page with a chain section, so sideways
navigation needs no new page type. `/admin/evidence/links` lists them and the graph
gains their kinds. The existing `sha256` pivot redirects to the `File` page.

Values are shown and copied defanged. On a stager's page, each entry in `piece_urls`
has a "Copy for sandbox" button that copies the raw URL. It is never a link. Results
attach to the stager piece, not to a single URL.

### Chains list

New Evidence child: `/admin/evidence/chains`, newest first: joiner, addresses,
requests, exploits, last seen, payload status. A "Dead ends" tab lists where the
trap stopped a chain, grouped by path. That list is the to-do list for the decoys.

### External results

On a stager or file page, an admin form: payload SHA-256, family, sandbox URL, note.
Results fill the Payload stage for the entire chain, marked external. The URL is
shown as text. Results are node-local and audit-logged like other admin writes
**(my call)**: replication would need a new signed log kind and is not worth it yet.

### Dossier and API

- Add a `chain` object and an `xray` summary (layers and pieces, not decoded text of
  uploads) to the request, IP and campaign dossiers. Additive, so `DOSSIER_V` stays
  1.
- Add `GET /api/v1/chains` and `GET /api/v1/chains/{key}`, under the existing admin
  scope, and document them in `docs/api-v1.md` and `docs/openapi.json`.
- Upload bytes and decoded upload text stay out of the API, dossier and export. Their
  pieces may leave; their content may not.

## Upload rule change (agreed 2026-11-01)

`docs/operations.md` says peephole never renders, inlines, unpacks or serves stored
upload content. New rule:

- Text uploads (`sniffed_type` text or php, and printable) are parsed statically and
  shown escaped on admin pages.
- Binaries are never parsed, rendered or unpacked. The zip stays their only way out.
- Nothing is served back on the trap, and the API and export stay metadata-only.

## Trap fix

An upload through `/wp-file-manager/lib/php/connector.minimal.php` should also be
answered at `/wp-content/plugins/wp-file-manager/lib/files/<name>`, which is where
the tool looks. This should capture real webshell commands, the only stage that is
fully seen. Before building, confirm on the observer that these four uploads came
through the connector path. Follow the rule of `411e2a6`: a dropped file does not
take over a path the trap already answers.

## Phase 2: streamline the interface

Starts once the feature is complete, on the same branch and in the same PR. The
user asked for a general clean-up, so this is the scope:

1. **Audit first.** Walk all 82 templates against one checklist and publish the
   findings in the PR: page header, back navigation, facts layout, empty states,
   table density, section order.
2. **Lead with evidence.** Detail pages open with what matters. Request page: strip,
   X-ray, then facts, with headers collapsed. Campaign page: flow map before members.
3. **One detail-page frame.** Request and address pages have no admin nav while
   upload, link and campaign pages do, and each page does back links its own way.
   Use one shared header and one rule.
4. **Reduce repetition.** Shared partials replace near-duplicates. The very long
   one-line templates are split where they are touched.
5. **Navigation.** Check whether 6 groups and 22 pages still suit the work, now that
   Chains exists.

Rules for Phase 2: no function removed without the user agreeing, URLs stay stable
through `admin::moved`, no new dependencies, tokens and brand stay, light and dark
both checked, and narrow screens and keyboard use keep working. It is a clean-up,
not a rebrand.

## Delivery

One PR and one release (the user's decision of 2026-11-01), in this order:

1. `model::xray` with limits, tests and the X-ray on request and upload pages.
2. Pieces, sightings, backfill, Links kinds.
3. Chains, strip, Chains list, dossier and API.
4. Campaign edges and flow map.
5. Trap fix and dead ends.
6. External results.
7. Acceptance on real data.
8. Phase 2.
9. The PR, then the release.

Tests, docs and CHANGELOG go with each step.

## Rollout

- Run on the observer first and compare with the dry-run figures.
- `peephole store recompute-campaigns` already reports version changes; use it to
  review the `CAMPAIGN_V` 3 change before release.
- Campaign keys and numbers can change on the upgrade. `docs/dataset.md` says a new
  clustering version may split a campaign; add that the `campaign` column can shift.
- Bodies older than a node's retention cannot be parsed, so a node with
  `retention_days` shows only what it still holds.

## Acceptance

On the observer's data:

1. The `217[.]60[.]102[.]5` chain has at least 163 addresses, the stager and key as
   joiners, and at least three exploit rows (`apache`, `cve_2024_4577`, `php2shell`),
   and forms one campaign.
2. `POST /hello.world` shows PHP, then base64, then a shell recipe with the `scp`
   branch and its fallback, and the key shown only as a fingerprint.
3. `management.azure.com` and `metadata.google.internal` are `queried` and join
   nothing.
4. Pastebin URLs join only by full URL. Mozi's addresses share a recipe and form no
   campaign from it.
5. `pr3d4t0r.php` shows as a dead end before the trap fix and answers after it, with
   a profile naming `$_GET['cmd']`, `system` and its marker.
6. Hex-blob bodies show as opaque with a reason.
7. One forged test body naming another group's stager and key merges no campaigns,
   and one naming two stagers merges no chains.
8. The same chain appears from a request, an address, the campaign and the piece.
9. Parser property tests pass on arbitrary bytes, within the limits.

## Docs to update

`docs/detection.md`, `docs/overview.md`, `docs/operations.md` (upload rule),
`docs/api-v1.md`, `docs/openapi.json`, `docs/dataset.md`, `docs/roadmap.md`,
`CHANGELOG.md`, `admin::glossary`.

## Left to the builder

Internal layout of `model::xray`, batch sizes, exact CSS, the padding heuristic, the
printable threshold, chart details within `dataviz`, and exact wording, following
the repo's plain-language style.
