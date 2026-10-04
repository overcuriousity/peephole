# Changelog

Notable changes per release. Versions follow [Semantic Versioning](https://semver.org/);
release builds are on the [releases page](https://github.com/overcuriousity/peephole/releases).

## [Unreleased]

### Added

- Counter-scans: level 2 runs nmap's `ssh-hostkey`, `ssh2-enum-algos` and
  `ssl-cert` scripts (all `safe`: one handshake with a port already found
  open). From their output, and from every stored scan's XML on upgrade,
  each node derives the source's SSH host keys (`SHA256:` as OpenSSH
  prints them), TLS certificates (SHA-256, subject, issuer, validity),
  JA4X and HASSH-server into a new `host_keys` table. Derived locally from
  the replicated XML, so nothing new is replicated.
- Admin: IP and scan pages list the host keys and certificates, marked
  where another source shares one; the fingerprints page shows shared SSH
  host keys and TLS certificates beside browser fingerprints, in the same
  graph; Analytics ranks HASSH and JA4X values.

### Changed

- Trap: decoys are always on. `/.env`, `/.git/config`, `/wp-login.php` and
  phpinfo probes get plausible fake content with canary credentials and
  status 200, so the follow-up request lands in the trap too. The
  `trap.decoys` setting is gone; an old `decoys = …` line is ignored.

### Fixed

- Fingerprint graph: nodes never moved vertically during layout (the
  update sat behind a comment).
- Analytics: OS guesses need level 2 since 0.2.1, not level 3.

## [0.2.1] - 2026-10-04

### Changed

- Counter-scans: level 2 now adds OS detection (`-O`), so OS guesses cover
  far more sources. Level 2 is also the most a single request earns by
  default (`scan.single_request_max_level`), so those sources are now
  OS-fingerprinted too; `-O` sends a few extra TCP/ICMP probes and stays
  non-intrusive. Override with `scan.level_argv` to keep the old preset.

## [0.2.0] - 2026-10-04

### Added

- Public wall: tiles with change against the previous window, new IPs, a
  request sparkline and time since the last hit; requests over time stacked
  by severity; a weekday × hour heatmap; requests per attack family; an
  OWASP Top 10 / Automated Threats grid; a ranked country list beside the
  map; data bars on top IPs and networks.
- Public wall: "What the scanners run", ports found open on scanned sources,
  counted as distinct IPs and shown only once open on at least 3 IPs. The
  README's privacy section says so.
- Public wall: soft auto-refresh once per cache lifetime while the tab is
  visible. No new public endpoint.
- Public IP pages: rank among all sources, a 7-day hourly chart by severity,
  a 26-week activity calendar, label families, and neighbours in the same
  /24 (/48) and ASN. The IP directory gets data bars, relative "last seen"
  and severity accents.
- Admin: an Analytics page (top paths, user agents, JA4, methods, transport,
  answers, open ports, products, OS guesses, AbuseIPDB bands, scans per
  level and status).
- Admin: a live feed of new requests on the wall (SSE, `/admin/api/recent`),
  which includes rows replicated from other nodes.
- Admin: request page shows the same IP's and the same JA4's other requests;
  fingerprints page has a draggable graph of fingerprints shared across IPs.
- Copy buttons on IPs and identifiers across the admin pages.

### Changed

- Attack families and OWASP tags follow `[public] show_labels`, on the wall
  and in `/api/stats`.
- Descriptive text on all pages cut to one short line or removed. The decoy
  trap page is unchanged.
- Severity chart fills use their own heat ramp, readable when stacked in
  both themes.
- A failed nmap scan that was killed by a signal now names the signal (for
  example `killed by SIGKILL (forced kill, often out of memory)`) instead of
  `exit None`. Normal exits read `exit <code>` instead of `exit Some(<code>)`.
  Failures already stored keep their old text.

### Fixed

- Phone-width layout: the top bar wraps instead of clipping links, stat tiles
  fit two per row, charts draw at their real width so labels keep their size,
  data tables scroll sideways instead of squeezing columns, and long IPv6
  addresses and paths wrap.
- Scan queue sparklines were always empty (charts.js was not loaded).
- Settings checkboxes, pace inputs and the standalone cluster page at phone
  width.

### Notes

- On the "all" range, the timeline/heatmap and the family/OWASP aggregates
  each scan the `requests` table once per cache refresh (5 minutes).

## [0.1.1] - 2026-10-04

### Added

- `cluster agreement` command.
- Installer: checks what sits in front of the trap, checks the port, and
  detects cloud addresses.

### Fixed

- False disagreement in the cluster rules check.

## [0.1.0] - 2026-10-03

First release.

[0.2.1]: https://github.com/overcuriousity/peephole/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/overcuriousity/peephole/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/overcuriousity/peephole/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/overcuriousity/peephole/releases/tag/v0.1.0
