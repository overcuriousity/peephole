# Docs rewrite and repositioning — design

## Goal

Rewrite `README.md` and everything in `docs/` (except `docs/superpowers/`)
so a visitor understands in the first sentence what peephole is: a
cooperative honeypot network that no member has to trust. A single node is
the way in; the cluster is the product.

The name `peephole` stays. Nothing is renamed in the binary, crate, config
paths, routes or protocol. The rebrand is positioning, tagline and tone, plus
one UI label.

## Decisions

- **Positioning:** cooperative network first. The single-node honeypot is the
  entry point, not the headline.
- **Tagline:** *A cooperative honeypot network that no member has to trust.*
- **Logo:** unchanged (the bloodshot eye stays; a redesign is out of scope).
- **Counter-scanning:** one capability among several, stated soberly with its
  safeguards: bystanders are never scanned, levels escalate by scope and
  never by aggressiveness, the scanner role is opt-in. The legal and
  abuse-report warning stays, in a risks section.
- **"Wall of shame" → "Public dashboard"**, in the docs and in the UI:
  - `templates/wall.html`: the title and the h1.
  - The comments in `src/store/stats.rs` and `src/config.rs`.
  - The comments in `tests/integration.rs` (lines ~408 and ~2033).

  The route, the `wall.html` filename and the `[public]` config section stay
  as they are.
- **Audiences**, in priority order: prospective operators,
  protocol readers and contributors, dataset consumers, running operators.
- **Tone:** sober and factual, in the existing house style: short
  declarative sentences, no marketing vocabulary, examples given as commands.

## Pitch paragraph (README, under the tagline)

> peephole is a honeypot you run behind your web server, and a network of
> such honeypots that share what they see. Each node catches the requests
> that reach none of your real sites — vulnerability scanners, exploit
> probes, background noise — classifies and enriches them, and can
> investigate the sources. Nodes join a cluster over mutual TLS and
> replicate one signed dataset. Operators need not know or trust each
> other: every claim is checked against signed data, and shared work
> (enrichment, lookups, scans) is paid in credits earned by doing work. In
> return for running a node you get the cluster's blocklist for your real
> sites, the whole dataset for your own analysis, and lookups through every
> member's intelligence providers.

The wording may be tightened during writing; the claims may not grow.

## Page structure

| Page | Reader | Contents | Sources |
|---|---|---|---|
| `README.md` (~100 lines) | anyone | logo and tagline; pitch; "how it works" in about 5 bullets with the topology diagram; what you contribute and what you get back; risks; quick install; docs map; license | README (feature list cut to one line per capability; details move to the pages below) |
| `docs/README.md` | anyone | one-screen index of the pages by audience | new |
| `docs/overview.md` | prospective operators | roles; a node's life (catch → classify → enrich → investigate); the cluster in plain words (no trust needed, no central server, nobody can be removed, blocking is local); credits on one page (daily pool, selling, prices); what is public and what never is; risks (legal, abuse reports, bystander protection); "is this for me?" | README features; the intros of cluster.md and its credits section; the privacy rules now spread over README and roadmap |
| `docs/operations.md` | running operators | install and installer choices; what sits in front of the trap; cloud machines; nginx; upgrades; day to day (admin keys and sessions, probes, bought scans, export, blocklist, database); public delay; tarpit and decoy streams; cluster administration CLI (invites, join, members, block/purge, leave, owner, credits) with the how-to steps of ownership; building and releases | operations.md; the CLI block and the how-to half of ownership in cluster.md |
| `docs/protocol.md` | contributors, skeptical members | design principles (rules from signed log data, not peer claims; a fleet is ownership only and carries no economic privilege); identity and admission; replication and the HLC; retention windows; trust rules; ownership mechanics; the full credit rules (pool, uptime and reach reports, prices, audits, receipts); relays and outbound-only nodes; protocol versions; things to know | cluster.md, everything except the CLI |
| `docs/dataset.md` | dataset consumers | what the dataset is and who it is for; provenance; rows and the column reference; canaries; the two exports; redistribution and "before sharing" | dataset.md (reference kept; new intro) |
| `docs/detection.md` | operators, contributors | classification and severity; rule families and OWASP tags; how rules ship in the binary; enrichment sources and budgets; counter-scan levels and safeguards; exempt scanners (FCrDNS) and how an operator gets exempted | operations.md "Classification taxonomy"; scanners.md; README features |
| `docs/roadmap.md` | all | same items; "public wall" wording updated to "public dashboard" | roadmap.md |

If `docs/protocol.md` exceeds about 600 lines, it becomes `docs/protocol/`
with one page per topic (membership and trust, replication, ownership,
credits) and an index. Otherwise it stays one file.

Deleted: `docs/cluster.md`, `docs/scanners.md`. Before deleting them, grep
`src/`, `templates/`, `deploy/`, `install.sh`, `rules/`, `tests/` and the
remaining docs for links or mentions of either file, and repoint each one
(e.g. `src/scan/crawler.rs` likely refers to `scanners.md`).

Out of scope and untouched: `docs/superpowers/`, existing CHANGELOG entries,
`deploy/config.example.toml` content (only links in it may be repointed), and
the logo.

## Accuracy rules

1. **Fact inventory first.** Before writing, list every factual claim in the
   old README and docs in a scratchpad file (not committed). Each claim ends
   up either on a named new page or on an explicit "cut" list, with a reason.
   The cut list goes into the PR description.
2. **Numbers are checked against the code**: limits, defaults, prices, pool
   size, delays, protocol versions. Where the docs and the code disagree, the
   code wins, and the discrepancy is reported in the PR description.
3. **No new claims.** The rewrite reorganizes and clarifies; it does not
   describe behavior that has not shipped. Roadmap items stay in the roadmap.

## Delivery

- Branch `docs/rewrite`, in the worktree `../peephole-docs`.
- Commits, in order:
  1. The UI label change, with its comments and a CHANGELOG entry under
     Unreleased → Changed.
  2. One commit per new or rewritten page.
  3. Deleting `cluster.md` and `scanners.md`, and repointing every link to
     them.
- One PR. I watch CI myself, fix every review finding (minor ones included)
  before merging, and merge only when CI is green.

## Verification

- A script resolves every relative link and anchor in `README.md` and
  `docs/*.md`.
- `grep -rni` finds no `cluster.md`, `scanners.md` or "wall of shame" outside
  `docs/superpowers/` and earlier CHANGELOG entries.
- `cargo test` passes.
- Every inventory item is ticked: placed on a page, or on the cut list.
- A newcomer read of the README: the first screen answers what this is, why
  you would run it, and what it costs or risks.
