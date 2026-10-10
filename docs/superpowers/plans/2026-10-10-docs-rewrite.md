# Docs Rewrite and Repositioning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite `README.md` and `docs/` so peephole reads as a cooperative honeypot network that no member has to trust, rename the "Wall of shame" UI label, and replace the logo with the door viewer ring (A1).

**Architecture:** Docs are organized by audience: a short README, a docs index, and the pages overview, operations, protocol, dataset, detection and roadmap. `cluster.md` and `scanners.md` become stubs that point to their successors. Code changes are limited to one template label, one nav label, comments, link comments and `assets/logo.svg`.

**Tech Stack:** Markdown (GitHub-flavored), askama templates, Rust (comments only), SVG; `python3` for the link checker and `rsvg-convert` for logo renders.

**Spec:** `docs/superpowers/specs/2026-10-10-docs-rewrite-design.md`

## Global Constraints

- Work in the worktree `/home/user01/Projekte/peephole-docs` on the branch `docs/rewrite`. Never edit `/home/user01/Projekte/peephole`, the main checkout.
- `SCRATCH=/tmp/claude-1000/-home-user01-Projekte-peephole/181eaae7-69c3-4ff3-b925-daebb7b8590a/scratchpad`. The fact inventory and the link checker live there and are never committed.
- Name stays `peephole`. Do not rename the binary, crate, config paths, routes, `[public]`, or `templates/wall.html`.
- Tagline, verbatim: *A cooperative honeypot network that no member has to trust.*
- "Wall of shame" → "Public dashboard" (prose and page h1/title); nav "Wall" → "Dashboard".
- Counter-scanning is presented as one capability among several, with its safeguards; the legal/abuse-report warning stays, in a Risks section.
- House style: short declarative sentences, no marketing vocabulary ("powerful", "seamless", "cutting-edge", "robust", "leverage"), examples given as commands. Match the existing docs' voice.
- **No new claims.** Only describe shipped behavior. Every number (limits, defaults, prices, delays, protocol versions) is checked against `src/` before it is written; on a docs/code mismatch the code wins and the mismatch is noted in `$SCRATCH/discrepancies.md` for the PR description.
- Do not touch `docs/superpowers/`, existing CHANGELOG entries, or the content of `deploy/config.example.toml` (only its doc links).
- Commit message trailer on every commit: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Cross-page anchors (interfaces between doc tasks)

Every page task must produce exactly these headings so that other pages can link to them. GitHub slugs are shown in brackets.

- `docs/overview.md`: `## Roles` [#roles], `## What a node does` [#what-a-node-does], `## The cluster` [#the-cluster], `## Credits` [#credits], `## What is public` [#what-is-public], `## Risks` [#risks], `## Is this for me?` [#is-this-for-me]
- `docs/operations.md`: `## Install` [#install], `## In front of the trap` [#in-front-of-the-trap], `## nginx` [#nginx], `## Upgrades` [#upgrades], `## Day to day` [#day-to-day], `## Cluster administration` [#cluster-administration], `## Building and releases` [#building-and-releases]
- `docs/protocol.md`: `## Design principles` [#design-principles], `## Membership and trust` [#membership-and-trust], `## Replication` [#replication], `## Retention windows` [#retention-windows], `## Ownership` [#ownership], `## Credits` [#credits], `## Relays and outbound-only nodes` [#relays-and-outbound-only-nodes], `## Protocol versions` [#protocol-versions], `## Things to know` [#things-to-know]
- `docs/detection.md`: `## Classification` [#classification], `## Rules` [#rules], `## Enrichment` [#enrichment], `## Counter-scans` [#counter-scans], `## Scanners we do not counter-scan` [#scanners-we-do-not-counter-scan]
- `docs/dataset.md`: keeps its current headings (`## Rows`, `## Columns`, `## Canaries`, `## Two exports`, `## Before sharing`).

## Review Focus

1. **Running nodes link to `blob/master/docs/cluster.md`** (`templates/admin_cluster.html` in v0.10 and older). Expected: the link still lands on a page that points onward. Pinned by the stub check in Task 10.
2. **The logo on GitHub dark mode and in a dark browser tab.** Expected: the ring is visible (light ink), not black on black. Pinned by the dark render in Task 2.
3. **Cross-page anchors drift** when a heading is reworded during writing. Expected: every `page.md#anchor` resolves. Pinned by the link checker in Task 0 and run in every page task.
4. **Numbers drift between the old docs and the code** (e.g. pool size, admission limit, delays). Expected: the new docs state what the code does. Pinned by the "check numbers" step in each page task, with the grep commands given.
5. **A fact silently lost** in the reorganization (e.g. the outbound-only node limitations or the `retention_days` minimum of 7). Expected: every old claim is either on a new page or on the cut list. Pinned by the inventory tick-off in Task 11.

---

### Task 0: Fact inventory and link checker (scratch, not committed)

**Files:**
- Create: `$SCRATCH/inventory.md`, `$SCRATCH/doclinks.py`, `$SCRATCH/discrepancies.md`

**Interfaces:**
- Produces: `python3 -I $SCRATCH/doclinks.py <repo>`, which exits 0 when every relative link and anchor in `README.md` and `docs/*.md` resolves, and exits 1 and lists the failures otherwise. It also produces `inventory.md`: one line per factual claim, in the format `- [ ] <source file>:<line> — <claim> → <target page or CUT: reason>`.

- [ ] **Step 1: Write the link checker**

```python
#!/usr/bin/env python3
"""Check relative links and #anchors in README.md and docs/*.md (not docs/superpowers)."""
import re, sys, pathlib

root = pathlib.Path(sys.argv[1]).resolve()
files = [root / "README.md"] + sorted((root / "docs").glob("*.md"))
link = re.compile(r"\]\(([^)\s]+)\)|href=\"([^\"]+)\"")

def slug(h):
    h = h.strip().lower()
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")

def anchors(path):
    out, seen = set(), {}
    in_code = False
    for line in path.read_text().splitlines():
        if line.startswith("```"):
            in_code = not in_code
        if in_code:
            continue
        m = re.match(r"#{1,6} (.+)", line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            out.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    return out

bad = []
for f in files:
    text = f.read_text()
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    for m in link.finditer(text):
        target = m.group(1) or m.group(2)
        if re.match(r"[a-z]+:", target):
            continue
        path, _, frag = target.partition("#")
        dest = (f.parent / path).resolve() if path else f
        if not dest.exists():
            bad.append(f"{f.relative_to(root)}: missing {target}")
        elif frag and dest.suffix == ".md" and frag not in anchors(dest):
            bad.append(f"{f.relative_to(root)}: no anchor {target}")
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
```

- [ ] **Step 2: Run it on the current docs**

Run: `python3 -I $SCRATCH/doclinks.py /home/user01/Projekte/peephole-docs; echo exit=$?`
Expected: `exit=0`, because today's links resolve. If it reports false positives, fix the checker and not the docs, then rerun until it prints `exit=0`.

- [ ] **Step 3: Build the inventory**

Read `README.md`, `docs/cluster.md`, `docs/operations.md`, `docs/dataset.md`, `docs/scanners.md` and `docs/roadmap.md` in full. For every factual claim (a behavior, a number, a default, a limit, a command, a guarantee), write one line in `$SCRATCH/inventory.md`, with its target page taken from the spec's mapping table. Group the lines by source file. Roadmap items stay in the roadmap and get a single line each. Create an empty `$SCRATCH/discrepancies.md`.

Expected size: about 250–400 lines. Do not commit.

---

### Task 1: "Wall of shame" → "Public dashboard" in the UI

**Files:**
- Modify: `templates/wall.html:2` and `:7`
- Modify: `templates/layout.html:21`
- Modify: `src/store/stats.rs:1`, `src/config.rs:309` (comments)
- Modify: `tests/integration.rs:408`, `:2033` (comments); add an assertion to `wall_shows_aggregates_not_payloads` (`tests/integration.rs:385`)
- Modify: `CHANGELOG.md` (Unreleased → Changed)

- [ ] **Step 1: Write the failing assertion**

In `tests/integration.rs`, inside `wall_shows_aggregates_not_payloads`, find the line `assert!(html.contains("203.0.113.99"));` (around line 410) and add right after it:

```rust
    assert!(html.contains("<h1>Public dashboard</h1>"));
    assert!(html.contains(">Dashboard</a>"));
    assert!(!html.to_lowercase().contains("wall of shame"));
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /home/user01/Projekte/peephole-docs && cargo test --locked --test integration wall_shows_aggregates_not_payloads`
Expected: FAIL on `html.contains("<h1>Public dashboard</h1>")`.

- [ ] **Step 3: Change the labels and comments**

- In `templates/wall.html`, change line 2 to `{% block title %}peephole — public dashboard{% endblock %}`, and on line 7 change `<h1>Wall of shame</h1>` to `<h1>Public dashboard</h1>`.
- In `templates/layout.html:21`, change `>Wall</a>` to `>Dashboard</a>`. Leave the `href` and `chrome.active == "wall"` as they are.
- In `src/store/stats.rs:1`, change the comment to `//! Aggregates for the public dashboard, per time range, plus a short`.
- In `src/config.rs:309`, change the comment to `/// Public dashboard and the FIDO2 admin area.`
- In `tests/integration.rs:408`, change the comment to `// The IP is named (public dashboard) and "Recent requests" lists paths,`.
- In `tests/integration.rs:2033`, change the comment to `// The IP directory stays public.`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --locked --test integration wall_shows_aggregates_not_payloads && cargo fmt --all -- --check && grep -rni 'wall of shame' src templates tests; echo grep-exit=$?`
Expected: the test PASSES, fmt is clean, and `grep-exit=1`, meaning no matches are left.

- [ ] **Step 5: CHANGELOG**

Under `## [Unreleased]` → `### Changed` in `CHANGELOG.md`, add as the first bullet:

```markdown
- The public page is called "Public dashboard" (nav: "Dashboard") instead of
  "Wall of shame". Its address and the `[public]` settings are unchanged.
```

- [ ] **Step 6: Commit**

```bash
git add templates/wall.html templates/layout.html src/store/stats.rs src/config.rs tests/integration.rs CHANGELOG.md
git commit -m "ui: the public page is the Public dashboard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: New logo (A1, door viewer ring)

**Files:**
- Modify (replace): `assets/logo.svg`
- Modify: `CHANGELOG.md` (Unreleased → Changed)

- [ ] **Step 1: Write the logo**

Replace the entire content of `assets/logo.svg` with:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="512" height="512">
  <title>peephole</title>
  <style>
    .ink { fill: #1f2024 }
    .line { stroke: #1f2024 }
    @media (prefers-color-scheme: dark) {
      .ink { fill: #e8e6df }
      .line { stroke: #e8e6df }
    }
  </style>
  <defs>
    <!-- cut the ring away under each member node, so the nodes stay hollow on any background -->
    <mask id="gaps" maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
      <rect width="64" height="64" fill="#fff"/>
      <circle cx="32" cy="10" r="5" fill="#000"/>
      <circle cx="51" cy="43" r="5" fill="#000"/>
      <circle cx="13" cy="43" r="5" fill="#000"/>
    </mask>
  </defs>
  <!-- the door viewer: ring, lens, pupil -->
  <circle class="line" cx="32" cy="32" r="22" fill="none" stroke-width="6" mask="url(#gaps)"/>
  <circle class="ink" cx="32" cy="32" r="13" opacity="0.14"/>
  <circle cx="32" cy="32" r="7" fill="#b30000"/>
  <!-- three cluster members on the ring -->
  <circle class="line" cx="32" cy="10" r="5" fill="none" stroke-width="3"/>
  <circle class="line" cx="51" cy="43" r="5" fill="none" stroke-width="3"/>
  <circle class="line" cx="13" cy="43" r="5" fill="none" stroke-width="3"/>
</svg>
```

- [ ] **Step 2: Render and look at it on both backgrounds**

```bash
cd /home/user01/Projekte/peephole-docs
sed 's/#1f2024/#e8e6df/g' assets/logo.svg > $SCRATCH/logo-dark.svg
for s in 16 32 160; do
  rsvg-convert -w $s -h $s -b '#f6f5f0' assets/logo.svg -o $SCRATCH/logo-light-$s.png
  rsvg-convert -w $s -h $s -b '#0d1117' $SCRATCH/logo-dark.svg -o $SCRATCH/logo-dark-$s.png
done
ls -l $SCRATCH/logo-*.png
```

Open all six PNGs with the Read tool. Expected: at 160 px the nodes are hollow, with the background showing through and no ring passing through them; the dark renders show a light ring; at 16 px a ring with a red centre is recognizable.

- [ ] **Step 3: Check it is still served**

Run: `cargo test --locked --test integration 2>&1 | tail -3`
Expected: `test result: ok`. The file is embedded via `include_bytes!` in `src/admin/assets.rs:76`, so its size does not matter.

- [ ] **Step 4: CHANGELOG**

Under `## [Unreleased]` → `### Changed`, add:

```markdown
- New logo: a door peephole whose ring carries three cluster members. It
  follows the system's light or dark theme.
```

- [ ] **Step 5: Commit**

```bash
git add assets/logo.svg CHANGELOG.md
git commit -m "assets: new logo, a door viewer ring with three members

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `docs/detection.md`

**Files:**
- Create: `docs/detection.md`
- Sources: `docs/scanners.md` (all), `docs/operations.md:434-477` (Classification taxonomy), README "Trap", "Enrichment", "Counter-scans", "Tarpit", "Canaries" bullets

**Interfaces:**
- Produces the anchors `#classification`, `#rules`, `#enrichment`, `#counter-scans` and `#scanners-we-do-not-counter-scan`.

- [ ] **Step 1: Check the numbers against the code**

```bash
cd /home/user01/Projekte/peephole-docs
ls rules/ | wc -l                                       # number of rule families ("sixteen" in README)
grep -rn 'DOMAINS' src/scan/crawler.rs | head -3        # exempt zones
grep -rn 'fn level_args\|"-sV"\|"-O"\|--script' src/scan/*.rs | head   # counter-scan levels
grep -rn 'rate\|budget' src/intel/*.rs | grep -i 'const' | head         # enrichment budgets
```

Record each mismatch with the old text in `$SCRATCH/discrepancies.md`.

- [ ] **Step 2: Write the page**

Structure:
1. An intro of 2–3 sentences: what happens to a request between arriving and being stored.
2. `## Classification`: severity 0–4, the weight table, and the level cap for `probe`/`path-scanner`/`php-probe`. Move the whole taxonomy table from `operations.md` here, without changing it.
3. `## Rules`: `rules/*.toml`, one family per file, OWASP tags; rules ship in the binary, every node of a build classifies alike, and each request records its rule version.
4. `## Enrichment`: GeoLite2, Tor exits, AbuseIPDB, Shodan and InternetDB, RDAP, reverse DNS; each with its own rate budget; refreshed when an IP returns.
5. `## Counter-scans`: levels 1–4 escalate by scope (ports, `-sV`, `-O`, safe scripts), never by speed. Safeguards: bystanders, verified crawlers, Tor exits, own and `never_scan` networks, and per-network, per-ASN and queue budgets. Also probes, bought scans and level 5 (bought only). Plus the tarpit and canaries as the other two active measures.
6. `## Scanners we do not counter-scan`: the content of `scanners.md`, kept nearly verbatim, including the "Are you a scanner operator?" and "Seeing who was refused" subsections as `###`.

Link `[operations](operations.md#day-to-day)` for the probe and bought-scan UI, and `[protocol](protocol.md#credits)` for prices.

- [ ] **Step 3: Tick the inventory and check the links**

In `$SCRATCH/inventory.md`, tick every line whose target is `detection.md`. Run `python3 -I $SCRATCH/doclinks.py .`. Links to pages that don't exist yet may fail now; they are resolved in Task 11. Every other failure gets fixed now.

- [ ] **Step 4: Commit**

```bash
git add docs/detection.md
git commit -m "docs: detection, from classification to counter-scans

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `docs/dataset.md`

**Files:**
- Modify: `docs/dataset.md`

- [ ] **Step 1: Check the column reference against the code**

```bash
grep -rn 'Field::new\|"[a-z_]*" *=>' src/export/*.rs | head -80
```

Compare the column names in the `## Columns` tables to the export schema. Each missing or extra column goes in `$SCRATCH/discrepancies.md` and gets fixed in the table.

- [ ] **Step 2: Rewrite the intro (everything above `## Rows`)**

The new intro covers:
- what the dataset is: real scanner traffic, labelled, from every member's trap;
- who it is for: researchers, ML on scanner traffic, operators' own analysis;
- how to get it: `peephole export` or Admin → Export, in Parquet, CSV or Timesketch JSONL;
- that every row names the node and build that recorded it.

The column reference, `## Canaries`, `## Two exports` and `## Before sharing` keep their content. Only rewrite wording where it says "wall of shame" or refers to `cluster.md` (now `protocol.md`).

- [ ] **Step 3: Tick the inventory and check the links**

Tick the `dataset.md` lines in the inventory and run `python3 -I $SCRATCH/doclinks.py .`.

- [ ] **Step 4: Commit**

```bash
git add docs/dataset.md
git commit -m "docs: dataset, an intro for the people who use it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: `docs/protocol.md`

**Files:**
- Create: `docs/protocol.md`
- Source: `docs/cluster.md`, everything except the CLI block (lines ~40–60) and the step-by-step ownership how-to (which goes to Task 6)

**Interfaces:**
- Produces the anchors listed under Cross-page anchors for `protocol.md`.

- [ ] **Step 1: Check the numbers against the code**

```bash
cd /home/user01/Projekte/peephole-docs
grep -rn '1000\b\|12 \|POOL\|pool' src/credits/*.rs | grep -i 'const\|pool' | head
grep -rn 'const.*ADMIT\|20\b.*day\|per_day' src/cluster/*.rs | head
grep -rn 'retention_days' src/config.rs | head
grep -rn 'takeover_hours\|origin_quota_mb\|2000' src/config.rs src/cluster/*.rs | head
grep -rn 'PROTOCOL\b\|const PROTOCOL' src/cluster/*.rs | head
grep -rn '30 \* 24\|prune' src/cluster/*.rs | head -5
```

Every number that `cluster.md` states must match. Each mismatch goes in `$SCRATCH/discrepancies.md`, and the page states the code's value.

- [ ] **Step 2: Write the page**

Structure:
1. **Intro.** Say who this page is for (contributors, and members who want to check the rules) and that every rule here is computed by each node from its own copy of the signed log.
2. **`## Design principles`.** Three points:
   - rules are derived from signed log data, never from a peer's claims;
   - every node judges for itself;
   - a fleet (one owner's nodes) is an ownership relation only, with no economic privilege, and the credit market is a free market.
3. **`## Membership and trust`.** The roles table, identity, invites and admission (the 20-a-day limit and the protocol 8 backdating rule), the 30-day prune, local blocking with `--subtree` and purge, "each node judges for itself" with its limits, and no deletes from the admin.
4. **`## Replication`.** Every node keeps a full copy; entries are signed; it uses an HLC; timestamps from the future count as of receipt; quotas apply. Cover only what `cluster.md` already says.
5. **`## Retention windows`.** `retention_days`: what is dropped and what is kept, and how history is fetched.
6. **`## Ownership`.** The model: the key, managing nodes, what can and cannot be done remotely, rotation, putting a node out, what relays see, and that local access always wins. The commands themselves go in operations.
7. **`## Credits`.** The whole credits section of `cluster.md` (lines 188–446), restructured into `###` subsections: where credits come from, prices, spending, audits and receipts, and what is free.
8. **`## Relays and outbound-only nodes`.** Content from the intro of `cluster.md` and wherever relays appear.
9. **`## Protocol versions`.** One line per protocol version, saying what it changed, taken from `cluster.md` and the CHANGELOG.
10. **`## Things to know`.** `cluster.md` lines 447–576.

If the page passes 600 lines, stop and split it into `docs/protocol/` instead: an `index.md` with the same anchors as links, and one file per `##`. Then update the cross-page anchors in this plan's later tasks.

- [ ] **Step 3: Tick the inventory and check the links**

Tick the inventory lines for `protocol.md`, then run `python3 -I $SCRATCH/doclinks.py .`.

- [ ] **Step 4: Commit**

```bash
git add docs/protocol.md
git commit -m "docs: protocol, the rules every member computes for itself

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: `docs/operations.md`

**Files:**
- Modify: `docs/operations.md`

**Interfaces:**
- Produces the anchors listed under Cross-page anchors for `operations.md`.
- Consumes: `protocol.md#ownership`, `protocol.md#credits`, `detection.md#classification`.

- [ ] **Step 1: Check the numbers against the code**

```bash
grep -rn 'delay_minutes\|jitter_minutes' src/config.rs | head
grep -rn 'Duration::from_secs(600)\|3600\|tarpit' src/trap/*.rs | grep -i 'const\|secs' | head
grep -rn 'hours.*24\|min_severity' src/admin/blocklist.rs | head
```

- [ ] **Step 2: Restructure the page**

- Rename the top headings to match the anchors: `## What the installer does` becomes `## Install` (with what it asks for and unattended installs), `### What is in front of the trap` becomes `## In front of the trap` (cloud machines and the cluster address stay under it), and `## nginx`, `## Upgrades`, `## Day to day` and `## Building and releases` stay.
- Add `## Cluster administration` before `## Building and releases`. It contains:
  - the CLI block from `cluster.md` (cluster, owner and credits commands), unchanged;
  - joining and outbound-only setup, as steps;
  - ownership how-to: `owner new`, `claim`, `--keep`, rotate, release, `forget-key`. Link to `[how ownership works](protocol.md#ownership)`.
- Remove `## Classification taxonomy`; it now lives in `detection.md#classification`. Leave a one-line link where the rules are mentioned in Day to day.
- Replace every `cluster.md` link with the matching `protocol.md#…` or `#cluster-administration` link, and every `scanners.md` link with `detection.md#scanners-we-do-not-counter-scan`.
- Replace "wall of shame" or "wall" (meaning the public page) with "public dashboard".

- [ ] **Step 3: Tick the inventory and check the links**

Tick the inventory lines for `operations.md`, then run `python3 -I $SCRATCH/doclinks.py .`.

- [ ] **Step 4: Commit**

```bash
git add docs/operations.md
git commit -m "docs: operations, now with cluster administration

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: `docs/overview.md`

**Files:**
- Create: `docs/overview.md`

**Interfaces:**
- Produces the anchors listed under Cross-page anchors for `overview.md`.
- Consumes all of `protocol.md`, `operations.md#install`, `detection.md` and `dataset.md`.

- [ ] **Step 1: Write the page (200–300 lines)**

The reader is a prospective operator deciding whether to run a node. Each section is plain words, with links to the detail page and no numbers that aren't needed.

1. Intro: the pitch paragraph from the spec.
2. `## Roles`: listener (trap), scanner (opt-in), web. What each needs, and that any mix runs on one node.
3. `## What a node does`: the path catch → classify → enrich → investigate (counter-scan, probe), plus the tarpit and canaries, one paragraph each, linking to `detection.md`.
4. `## The cluster`: no central server; mutual TLS; one signed dataset everyone holds; operators need not trust each other; nobody can be removed, only blocked locally; a node can keep only a window. Link to `protocol.md#membership-and-trust`.
5. `## Credits`: shared work is a good bought with credits. A fixed daily pool goes to reachable listeners; everything else is earned by selling; recent answers are free; a standalone node uses its own providers. Link to `protocol.md#credits`.
6. `## What is public`: the dashboard's aggregates and publication delay, the IP directory, what is never public (bodies, headers, query strings, fingerprints, single scan results), the per-port threshold of 3 IPs, the "fake AI" card rule, and the blocklist feed with its exclusions. Collect these from the README "Wall of shame" and "Blocklist feed" bullets.
7. `## Risks`: the legal warning (counter-scanning is restricted in some jurisdictions); abuse reports go to the scanner node's hosting provider; the scanner role is opt-in; the bystander safeguards; the public dashboard names IPs.
8. `## Is this for me?`: three short "you want this if…" lines and two "this is not…" lines. Check every line against the spec's pitch and add no new claims.

- [ ] **Step 2: Tick the inventory and check the links**

Tick the inventory lines for `overview.md`, then run `python3 -I $SCRATCH/doclinks.py .`.

- [ ] **Step 3: Commit**

```bash
git add docs/overview.md
git commit -m "docs: overview for operators deciding whether to join

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: `docs/roadmap.md` wording

**Files:**
- Modify: `docs/roadmap.md`

- [ ] **Step 1: Update the wording**

- Replace "Public wall" and "public wall" (as labels in the **Shown:** blocks and in prose) with "Public dashboard" and "public dashboard".
- Change "(see the README's privacy rules)" to "(see [What is public](overview.md#what-is-public))".
- Leave the items themselves, their order, costs and evidence as they are.

- [ ] **Step 2: Check the links and commit**

```bash
python3 -I $SCRATCH/doclinks.py .
git add docs/roadmap.md
git commit -m "docs: roadmap says public dashboard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: `README.md` and `docs/README.md`

**Files:**
- Modify (rewrite): `README.md`
- Create: `docs/README.md`

- [ ] **Step 1: Write `README.md` (90–120 lines)**

Write it in this order:

````markdown
<p align="center">
  <img src="assets/logo.svg" alt="peephole logo: a door peephole whose ring carries three member nodes" width="160">
</p>

# peephole

*A cooperative honeypot network that no member has to trust.*

[![CI](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml/badge.svg)](https://github.com/overcuriousity/peephole/actions/workflows/ci.yml)

<pitch paragraph from the spec, verbatim or tightened; no new claims>

## How it works

- **A trap behind your web server.** <one sentence: fallback vhost, records every request no real site answers, raw TLS ClientHello and JA4>
- **Classified and enriched.** <one sentence: built-in rules, severity 0–4, GeoLite2/ASN/Tor/RDAP and optional AbuseIPDB and Shodan> → [detection](docs/detection.md)
- **Investigated, carefully.** <one sentence: counter-scans by an opt-in scanner role, escalating by scope, never bystanders; tarpit; canaries>
- **Shared without trust.** <one sentence: mutual TLS, one signed dataset on every node, each node judges for itself, nobody can be removed> → [protocol](docs/protocol.md)
- **Paid in credits.** <one sentence: shared work bought with credits from a fixed daily pool and from selling> → [credits](docs/overview.md#credits)

<topology diagram from the current README, unchanged>

## What you put in, what you get back

<two short lists. In: a machine, a trap in front of your sites, optionally a scanner and API keys. Back: the cluster blocklist (`/api/blocklist`) for your real sites, the whole dataset (Parquet/CSV/Timesketch), lookups through every member's providers, scanner noise out of your logs, and a public dashboard.>

## Risks

> [!WARNING]
> <the current warning, verbatim>

<two sentences: the scanner role is opt-in; abuse reports go to the scanner node's provider. Link to overview#risks.>

## Install

<the current curl one-liner, verbatim>

<three sentences: what the installer asks for, then /enroll with the one-time token; link to operations#install>

## Documentation

| Page | For |
|---|---|
| [Overview](docs/overview.md) | deciding whether to run a node |
| [Protocol](docs/protocol.md) | how the cluster works and why you need not trust it |
| [Dataset](docs/dataset.md) | using the exported data |
| [Operations](docs/operations.md) | installing and running a node |
| [Detection](docs/detection.md) | rules, enrichment, counter-scans |
| [Roadmap](docs/roadmap.md) | what is next |

## License

<current license paragraph, verbatim>
````

Fill each `<…>` with the actual sentences. Every sentence must come from an inventory line.

- [ ] **Step 2: Write `docs/README.md`**

```markdown
# Documentation

Start with the page for what you want to do.

- **Deciding whether to run a node:** [Overview](overview.md). What a node does, what the cluster is, what is public, the risks.
- **Checking the cluster's rules:** [Protocol](protocol.md). Membership, replication, ownership, credits, protocol versions.
- **Using the data:** [Dataset](dataset.md). Every column, provenance, what may be shared.
- **Running a node:** [Operations](operations.md). Install, nginx, upgrades, day to day, cluster administration.
- **Understanding what gets flagged:** [Detection](detection.md). Classification, rules, enrichment, counter-scans, exempt scanners.
- **What is next:** [Roadmap](roadmap.md).

The [changelog](../CHANGELOG.md) lists what changed in each release.
```

- [ ] **Step 3: Tick the inventory and check the links**

Tick every README line in the inventory: each one is placed on a page or goes on the cut list with a reason. Then run `python3 -I $SCRATCH/doclinks.py .`.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/README.md
git commit -m "readme: a cooperative honeypot network that no member has to trust

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Retire `cluster.md` and `scanners.md`; repoint the links

**Files:**
- Modify (to stub): `docs/cluster.md`, `docs/scanners.md`
- Modify: `deploy/config.example.toml:31` and `:215`, `src/scan/crawler.rs:5` and `:53`, `src/credits/mod.rs:3`, `templates/admin_cluster.html:8`

- [ ] **Step 1: Write the stubs**

`docs/cluster.md`:

```markdown
# Distributed mode

This page has moved.

- How the cluster works (trust, replication, ownership, credits): [protocol.md](protocol.md)
- Commands to join, invite, block and manage your nodes: [operations.md](operations.md#cluster-administration)
- What it is and whether to join: [overview.md](overview.md)
```

`docs/scanners.md`:

```markdown
# Scanners we do not counter-scan

This page has moved to [detection.md](detection.md#scanners-we-do-not-counter-scan).
```

- [ ] **Step 2: Repoint the links**

- In `deploy/config.example.toml:31`, change `(see docs/cluster.md)` to `(see docs/protocol.md)`, and at `:215` change `(docs/cluster.md)` to `(docs/protocol.md)`.
- In `src/scan/crawler.rs:5` and `:53`, change `docs/scanners.md` to `docs/detection.md`.
- In `src/credits/mod.rs:3`, change `see "Credits" in docs/cluster.md` to `see "Credits" in docs/protocol.md`.
- In `templates/admin_cluster.html:8`, change the href `.../blob/master/docs/cluster.md` to `.../blob/master/docs/operations.md#cluster-administration`.

- [ ] **Step 3: Check for leftovers**

```bash
cd /home/user01/Projekte/peephole-docs
grep -rn 'cluster\.md\|scanners\.md' --exclude-dir=target --exclude-dir=.git --exclude-dir=superpowers --exclude-dir=.superpowers . \
  | grep -v '^./CHANGELOG.md' | grep -v '^./docs/cluster.md' | grep -v '^./docs/scanners.md'
echo grep-exit=$?
cargo build --locked 2>&1 | tail -1
```

Expected: no output lines from grep, `grep-exit=1`, and a build that finishes.

- [ ] **Step 4: Commit**

```bash
git add docs/cluster.md docs/scanners.md deploy/config.example.toml src/scan/crawler.rs src/credits/mod.rs templates/admin_cluster.html
git commit -m "docs: cluster.md and scanners.md point to their successors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: Verification and PR

- [ ] **Step 1: Links**

Run: `python3 -I $SCRATCH/doclinks.py /home/user01/Projekte/peephole-docs; echo exit=$?`
Expected: `exit=0`.

- [ ] **Step 2: Leftover wording**

```bash
grep -rni 'wall of shame\|public wall' README.md docs/*.md src templates tests | grep -v '^docs/superpowers'; echo grep-exit=$?
```

Expected: `grep-exit=1`.

- [ ] **Step 3: Inventory complete**

Run: `grep -c '^- \[ \]' $SCRATCH/inventory.md`
Expected: `0`. Every line is ticked, either placed on a page or marked `CUT: reason`.

- [ ] **Step 4: Full CI locally**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked 2>&1 | grep -E '^test result|FAILED|panicked'`
Expected: every `test result: ok`, with no `FAILED`.

- [ ] **Step 5: Newcomer read**

Read the first 40 lines of `README.md` as someone who has never heard of the project, and answer in writing in `$SCRATCH/newcomer.md`:
1. What is it?
2. Why would I run it?
3. What does it cost me, and what are the risks?

If any answer needs text below line 40, tighten the README and commit (`readme: tighten the first screen`).

- [ ] **Step 6: Push and open the PR**

```bash
git push -u origin docs/rewrite
gh pr create --base master --title "Docs rewrite: a cooperative honeypot network" --body-file $SCRATCH/pr-body.md
```

Write `$SCRATCH/pr-body.md` first. It contains:
- a summary of the new structure;
- the label and logo change;
- the full cut list from the inventory (each item with its reason);
- the full content of `$SCRATCH/discrepancies.md`;
- this line at the end: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

- [ ] **Step 7: Watch CI, fix every finding, then merge**

Run `gh pr checks --watch`. Fix every failure and every review finding, minor ones included, before merging. Once the checks are green, run `gh pr merge --merge`. Do not use `--auto`: master is unprotected, so it would merge instantly.
