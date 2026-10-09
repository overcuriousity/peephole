# Scan Details Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show what a scanned source serves and calls itself from the fields nmap writes as structure, keep the scanning node's own address and name out of its scans, and drop `http-comments-displayer` from levels 3 and 4.

**Architecture:** A new parser `scan::facts` reads service attributes and a fixed table of script `<elem>` keys from the stored nmap XML on every node, like `scan::hostkeys`, into new `ports` columns and a `scan_facts` table, with a startup backfill. A new pure module `scan::scrub` replaces the node's own global addresses and forward-confirmed names in the XML before the scanner signs it, and again when old XML is served or exported; `scan::safety::Safety` becomes the one source of "this node's addresses and names". `scan::profiles` changes the level 3 and 4 script list and keeps the old ones in `ACCEPTED`.

**Tech Stack:** Rust 2024, tokio, sqlx 0.9 (SQLite), quick-xml 0.42, askama templates, serde_json.

**Spec:** `docs/superpowers/specs/2026-10-06-scan-details-design.md` (sections 4 to 6; sections 1 to 3 shipped earlier and were removed from it).

## Global Constraints

- A value is read only from a fixed place: an attribute of an nmap element, an `<elem>` at a fixed key path, a protocol field with a fixed name. Never from a script's prose `output`, never from an `<elem>` whose key is data (`http-grep`, `fcrdns`), never by substring, keyword or regex over a value.
- Facts are derived, never replicated: every node derives them from the scan's raw XML it already holds. Nothing new goes on the wire except the optional `scrubbed` count on `ScanResultRec` (`#[serde(default, skip_serializing_if = …)]`, so older peers ignore it; no protocol bump).
- Limits: a fact value longer than 512 bytes is cut at a character boundary; at most 64 facts per scan; the XML is read under the existing `MAX_RAW_XML` cap.
- Scrubbing replaces exact values this node knows about itself with `[scanner]`, never patterns: each own global address as nmap prints it (IPv4 dotted, IPv6 compressed) where the bytes before and after are not `[0-9A-Fa-f.:]`; each own name, case-insensitively, where the bytes before and after are not `[A-Za-z0-9.-]`. A scan whose target is an own address is not scrubbed.
- Scrubbing leaves ports, identity keys and ETags unchanged (audits compare those: `credits::audit`), and leaves the `args` line alone (`profiles::args_ok` judges it).
- Levels 3 and 4: `profiles::SCRIPTS` becomes `(discovery or safe) and not (intrusive or broadcast or external or dos or http-comments-displayer)`. The previous level 3 and 4 lists go into `profiles::ACCEPTED` and are removed two releases later. `scan.level_argv` overrides are untouched.
- Every shown value is peer-supplied text: escaped by askama's default, never a URL the page fetches (`redirect_url` is shown as text).
- Migration `0027_scan_facts.sql` is the next free number. One migration for everything in this plan.
- Doc comments are prose in the repository's voice (see `src/scan/hostkeys.rs`); no em-dashes.
- Commit messages: imperative subject in the repository's style (`Scan facts: …`, `Scrub: …`, `Profiles: …`), ending with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Build with `source ~/.cargo/env` (or `export PATH="$HOME/.cargo/bin:$PATH"`) in the Bash tool; keep `target/` small (see memory `peephole-build-env`).

## Review Focus

- **A scan of a host that answers on thousands of ports with `http-title` everywhere.** The table must stop at 64 facts and the page must stay readable. Test: `facts::tests::the_per_scan_cap_holds` (Task 3).
- **A fact value with XML entities and multi-byte text cut at the limit.** `&amp;` arrives decoded; a 600-byte string of `ü` is cut at 512 bytes without splitting a character. Test: `facts::tests::values_are_cut_at_a_character_boundary` (Task 3).
- **A node whose own address is inside a longer address in the XML** (`87.123.41.5` in `87.123.41.56`), and its own name inside a subdomain (`host.example.net` in `mail.host.example.net`). Neither is touched. Test: `scrub::tests::an_address_inside_a_longer_one_is_left_alone`, `a_name_inside_a_longer_one_is_left_alone` (Task 6).
- **A scan stored by a build before this one, on a node that upgrades.** It gains its facts once (`facts_parsed`), and the XML download and export scrub this node's addresses from it. Tests: `store::facts::tests::backfill_reads_scans_stored_before` (Task 4), `export::tests::served_xml_scrubs_this_nodes_own_address` (Task 8).
- **A scanner on the previous release during a rolling upgrade.** Its level 3 and 4 scans still earn: the old lists are in `ACCEPTED`. Test: `profiles::tests::the_previous_level_3_and_4_lists_still_earn` (Task 1).

## Task graph

Task 1 is independent. Task 2 (walker and migration) comes first for the rest: Task 3 → Task 4 → Task 5 (facts), Task 6 → Task 7 → Task 8 (scrubbing; Task 7 also needs Task 2). Parallel implementers (see memory `sdd-dag-parallel-worktrees`): Task 1, Task 2 and Task 6 together; then Task 3 and Task 7; then Task 4 and Task 8; then Task 5.

Branch: `scan-details`, from `master`.

## File structure

- `src/scan/profiles.rs` (modify): the script list and `ACCEPTED`.
- `src/store/migrations/0027_scan_facts.sql` (create): port details, `scan_facts`, `facts_parsed`, `scrubbed`.
- `src/scan/hostkeys.rs` (modify): the script walker `walk_scripts`, shared with the facts parser; `extract` rewritten onto it.
- `src/scan/facts.rs` (create): the fact kinds, the parser, the labels, the caps.
- `tests/fixtures/nmap-facts.xml` (create): a hand-made report with every field of section 4, scripts with prose only, and data-keyed tables.
- `src/store/facts.rs` (create): derive, backfill, read models (`FactRow`), the summaries for the IP page.
- `src/store/inspect.rs` (modify): `PortRow` gains the details and its facts; `ScanSummary` gains `scrubbed`.
- `src/store/data.rs`, `src/lib.rs` (modify): derive on store, backfill at start.
- `templates/_ports.html`, `templates/admin_scan.html`, `templates/_target.html` (modify); `src/admin/scans.rs`, `src/admin/public.rs`, `src/admin/target.rs` (modify): display.
- `src/store/export.rs`, `src/export/mod.rs`, `src/export/cli.rs`, `src/admin/system.rs` (modify): `facts`, port details and `scrubbed` in the export; scrubbing of served XML.
- `src/scan/scrub.rs` (create): the replacement and `Own`.
- `src/scan/safety.rs` (modify): own global addresses, own names (daily forward-confirmed PTR), `Own`.
- `src/scan/nmap_xml.rs`, `src/cluster/record.rs`, `src/store/recorder.rs`, `src/scan/mod.rs` (modify): `scrubbed` through the record; scrubbing before signing.
- `docs/dataset.md`, `CHANGELOG.md` (modify).

---

### Task 1: The script selection (section 6)

**Files:**
- Modify: `src/scan/profiles.rs`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `SCRIPTS` without `http-comments-displayer`; `ACCEPTED` with the previous level 3 and level 4 lists.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/scan/profiles.rs`:

```rust
    #[test]
    fn levels_3_and_4_leave_out_http_comments_displayer_and_the_previous_lists_still_earn() {
        assert!(SCRIPTS.ends_with("or http-comments-displayer)"), "{SCRIPTS}");
        let plain = cfg("");
        for level in [3u8, 4] {
            let line = command_line(&plain, level, "203.0.113.7");
            assert!(args_ok(&line, level), "{line}");
            // The list of 0.9.0 and earlier, as nmap recorded it.
            let old = line.replace(
                " or http-comments-displayer)",
                ")",
            );
            assert_ne!(old, line);
            assert!(args_ok(&old, level), "previous list, level {level}: {old}");
            assert!(!args_ok(&old, 5 - level), "accepted for its level only");
            // Put back by hand: another list.
            let by_hand = line.replace(
                "or http-comments-displayer)",
                "or http-comments-displayer) or http-comments-displayer",
            );
            assert!(!args_ok(&by_hand, level));
        }
        let udp = cfg("level4_udp = true");
        let old_udp = command_line(&udp, 4, "203.0.113.7").replace(" or http-comments-displayer)", ")");
        assert!(args_ok(&old_udp, 4), "{old_udp}");
    }
```

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test --lib scan::profiles::tests::levels_3_and_4 -- --nocapture`
Expected: FAIL at the first assert (`SCRIPTS` does not end with the new exclusion).

- [ ] **Step 3: Change the list and keep the old ones**

In `src/scan/profiles.rs` replace the `SCRIPTS` constant and its comment:

```rust
/// One NSE argument; it contains spaces, so lists are built element by
/// element. `discovery` and `safe` also hold scripts that would leak the
/// target to third parties (`external`: whois, ASN and geolocation
/// lookups), broadcast on the scanner's own network (`broadcast`
/// prerules), or flood (`dos`); those categories are excluded. So is one
/// script by name: `http-comments-displayer` spiders up to 20 pages per
/// HTTP port and copies every comment it finds, binary files it misreads
/// included, unbounded text of no use for analysis (198 KB of one 266 KB
/// scan in the 2026-10-06 export).
pub const SCRIPTS: &str =
    "(discovery or safe) and not (intrusive or broadcast or external or dos or http-comments-displayer)";
```

Replace `ACCEPTED` with the old level 2 entry plus the previous level 3 and 4 lists. The level 4 entry is what `normalize` leaves of the old command line: no `-p-`, no `-sU -p T:…`, no timeouts, no target.

```rust
/// Built-in lists of earlier releases that still earn, normalized, with
/// their level. A release that changes a list appends the old one here
/// and removes it two releases later, so a rolling upgrade costs nobody
/// their earnings.
pub const ACCEPTED: &[(u8, &[&str])] = &[
    // Level 2 before `http-headers` (0.9.0 and earlier).
    (
        2,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--script",
            "ssh-hostkey,ssh2-enum-algos,ssl-cert",
        ],
    ),
    // Levels 3 and 4 with `http-comments-displayer` (0.9.0 and earlier).
    (
        3,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            OLD_SCRIPTS,
        ],
    ),
    (
        4,
        &[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--max-retries",
            "1",
            "--traceroute",
            "--script",
            OLD_SCRIPTS,
        ],
    ),
];

/// The level 3 and 4 script list of 0.9.0 and earlier.
const OLD_SCRIPTS: &str = "(discovery or safe) and not (intrusive or broadcast or external or dos)";
```

`words()` splits a command line at whitespace, so the script expression of a stored scan arrives as several words, while the `ACCEPTED` entries above keep it as one element (as `builtin` does). Compare both sides the same way: join an accepted list with spaces and run it through `words` and `normalize`, like the built-in list.

```rust
fn args_ok_among(command_line: &str, level: u8, accepted: &[(u8, &[&str])]) -> bool {
    let all = words(command_line);
    // The first word is the program as it was called.
    let Some((_, args)) = all.split_first() else {
        return false;
    };
    let got = normalize(args, level);
    if got.is_empty() {
        return false;
    }
    let built_in = builtin(level, false).map(|b| normalize(&words(&b.join(" ")), level));
    built_in.is_some_and(|b| b == got)
        || accepted
            .iter()
            .filter(|(l, _)| *l == level)
            .any(|(_, list)| normalize(&words(&list.join(" ")), level) == got)
}
```

The existing tests `an_earlier_built_in_list_stays_accepted` and `level_2_reads_http_headers_and_the_previous_list_still_earns` must keep passing.

- [ ] **Step 4: Run the module's tests**

Run: `cargo test --lib scan::profiles`
Expected: all pass, including the new one and `every_built_in_level_is_recognized_with_every_tunable_set`.

- [ ] **Step 5: Credits judge again**

`credits::earn::rejudge` (around `src/credits/earn.rs:156`) already re-judges scans an older build rejected with `args_ok = 0`; nothing to add. Confirm by reading it.

- [ ] **Step 6: Changelog**

In `CHANGELOG.md` under `## [Unreleased]` → `### Changed`, append:

```markdown
- Levels 3 and 4 no longer run nmap's `http-comments-displayer`: it
  copied every HTML comment it found, binary files included, and was most
  of some scans' XML. Scans run with the previous list still earn.
```

- [ ] **Step 7: Commit**

```bash
git add src/scan/profiles.rs CHANGELOG.md
git commit -m "Profiles: levels 3 and 4 drop http-comments-displayer; the old lists still earn"
```

---

### Task 2: The script walker and the migration

**Files:**
- Modify: `src/scan/hostkeys.rs`
- Create: `src/store/migrations/0027_scan_facts.sql`
- Modify: `src/store/mod.rs` (the `MIGRATIONS` list, around line 64)

**Interfaces:**
- Produces: `pub(crate) enum Node`, `pub(crate) fn elem`, `pub(crate) fn table`, `pub(crate) fn texts`, `pub(crate) fn key_attr`, and
  `pub(crate) fn walk_scripts(xml: &[u8], wanted: &[&str], f: &mut dyn FnMut(u16, &str, Option<&str>, &[Node]))` in `scan::hostkeys`: `f(port, id, output, root)` once per `<script>` whose id is in `wanted`, with port 0 for a host script (`<hostscript>`).
- Produces: columns `ports.extrainfo`, `ports.ostype`, `ports.devicetype`, `ports.hostname`, `ports.cpe` (TEXT, JSON array), table `scan_facts(id, scan_id, port, proto, kind, value)`, `scans.facts_parsed`, `scans.scrubbed`.

- [ ] **Step 1: Write the failing test for the walker**

Add to `mod tests` in `src/scan/hostkeys.rs`:

```rust
    #[test]
    fn the_walker_reports_port_and_host_scripts_with_their_output_and_tree() {
        let xml = br#"<nmaprun><host>
<ports>
<port protocol="tcp" portid="80"><script id="http-title" output="T"><elem key="title">T</elem></script>
<script id="other" output="x"/><script id="http-server-header" output="nginx"/></port>
</ports>
<hostscript><script id="smb-os-discovery" output="o"><elem key="os">Windows</elem><table key="t"><elem>v</elem></table></script></hostscript>
</host></nmaprun>"#;
        let mut seen: Vec<(u16, String, Option<String>, usize)> = vec![];
        walk_scripts(
            xml,
            &["http-title", "http-server-header", "smb-os-discovery"],
            &mut |port, id, output, root| {
                seen.push((port, id.to_string(), output.map(str::to_string), root.len()));
            },
        );
        assert_eq!(
            seen,
            vec![
                (80, "http-title".into(), Some("T".into()), 1),
                (80, "http-server-header".into(), Some("nginx".into()), 0),
                (0, "smb-os-discovery".into(), Some("o".into()), 2),
            ]
        );
    }
```

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test --lib scan::hostkeys::tests::the_walker`
Expected: compile error, `walk_scripts` not found.

- [ ] **Step 3: Write the walker and put `extract` on it**

In `src/scan/hostkeys.rs`:

1. Make `Node` and its helpers visible to the crate: `pub(crate) enum Node`, `pub(crate) fn elem`, `pub(crate) fn table`, `pub(crate) fn texts`, `pub(crate) fn key_attr`. Keep `text_attr` private.
2. Add the walker. Its `Text`, `CData`, `GeneralRef`, `elem` end and `table` end arms are the ones `extract` has today (shown below as they are); `extract` loses them.

```rust
/// Walk every `<script>` of an nmap report whose id is in `wanted`, port
/// scripts and host scripts (`<hostscript>`, reported with port 0) alike,
/// and call `f` once per script with the port, the id, the `output`
/// attribute and the structured output (`<table>` and `<elem>`) under it,
/// root first. Unparsable input ends the walk: what was found before the
/// error has been reported. The XML comes from nmap, but the values in it
/// from the scanned source.
pub(crate) fn walk_scripts(
    xml: &[u8],
    wanted: &[&str],
    f: &mut dyn FnMut(u16, &str, Option<&str>, &[Node]),
) {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut port: u16 = 0;
    // Inside a wanted script: its id and output, and the open tables.
    let mut script: Option<(String, Option<String>)> = None;
    let mut stack: Vec<(Option<String>, Vec<Node>)> = vec![];
    let mut text: Option<(Option<String>, String)> = None;
    while let Ok(ev) = reader.read_event_into(&mut buf) {
        match ev {
            Event::Start(e) => match e.name().as_ref() {
                "port" => {
                    port = key_attr(&e, "portid")
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(0)
                }
                "script" => {
                    let id = key_attr(&e, "id").unwrap_or_default();
                    if wanted.contains(&id.as_str()) {
                        script = Some((id, text_attr(&e, "output")));
                        stack = vec![(None, vec![])];
                    }
                }
                "table" if script.is_some() => stack.push((key_attr(&e, "key"), vec![])),
                "elem" if script.is_some() => text = Some((key_attr(&e, "key"), String::new())),
                _ => {}
            },
            Event::Empty(e) => match e.name().as_ref() {
                "script" => {
                    let id = key_attr(&e, "id").unwrap_or_default();
                    if wanted.contains(&id.as_str()) {
                        f(port, &id, text_attr(&e, "output").as_deref(), &[]);
                    }
                }
                "elem" if script.is_some() => {
                    if let Some(top) = stack.last_mut() {
                        top.1.push(Node::Elem {
                            key: key_attr(&e, "key"),
                            text: String::new(),
                        });
                    }
                }
                _ => {}
            },
            Event::Text(t) => {
                if let Some((_, s)) = text.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::CData(t) => {
                if let Some((_, s)) = text.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::GeneralRef(r) => {
                if let Some((_, s)) = text.as_mut() {
                    match r.resolve_char_ref() {
                        Ok(Some(c)) => s.push(c),
                        _ => s.push_str(match &*r {
                            "amp" => "&",
                            "lt" => "<",
                            "gt" => ">",
                            "quot" => "\"",
                            "apos" => "'",
                            _ => "",
                        }),
                    }
                }
            }
            Event::End(e) => match e.name().as_ref() {
                "port" => port = 0,
                "elem" => {
                    if let (Some((key, s)), Some(top)) = (text.take(), stack.last_mut()) {
                        top.1.push(Node::Elem { key, text: s });
                    }
                }
                "table" if stack.len() > 1 => {
                    let (key, children) = stack.pop().expect("len > 1");
                    if let Some(top) = stack.last_mut() {
                        top.1.push(Node::Table { key, children });
                    }
                }
                "script" => {
                    if let (Some((id, output)), Some((_, root))) = (script.take(), stack.pop()) {
                        f(port, &id, output.as_deref(), &root);
                    }
                    stack.clear();
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
}
```

3. Rewrite `extract` on it. Today it reads `http-headers` twice: the `output` attribute when the script starts and the `<elem>` texts when it ends, both into `out`; keep both calls so the host key rows stay identical:

```rust
/// Every identifier in an nmap XML report. Unparsable input yields what
/// was found before the error.
pub fn extract(xml: &[u8]) -> Vec<HostKey> {
    let mut out = vec![];
    walk_scripts(
        xml,
        &["ssh-hostkey", "ssl-cert", "ssh2-enum-algos", "http-headers"],
        &mut |port, id, output, root| {
            if port == 0 {
                return;
            }
            match id {
                "ssh-hostkey" => ssh_hostkeys(port, root, &mut out),
                "ssl-cert" => tls_cert(port, root, &mut out),
                "http-headers" => {
                    if let Some(o) = output {
                        etags(port, o, &mut out);
                    }
                    etags(port, &texts(root).join("\n"), &mut out);
                }
                _ => hassh(port, root, &mut out),
            }
        },
    );
    out
}
```

- [ ] **Step 4: Run the host key tests, scan and store**

Run: `cargo test --lib hostkeys`
Expected: every test in `scan::hostkeys::tests` and `store::hostkeys::tests` passes unchanged, plus the walker test.

- [ ] **Step 5: Write the migration**

Create `src/store/migrations/0027_scan_facts.sql`:

```sql
-- What a scan says a source serves and calls itself (scan::facts): the
-- service details nmap writes per port, and facts from scripts with
-- structured output. Derived from scans.raw_xml on each node like
-- host_keys, never replicated; facts_parsed marks the scans already read.
ALTER TABLE ports ADD COLUMN extrainfo TEXT;
ALTER TABLE ports ADD COLUMN ostype TEXT;
ALTER TABLE ports ADD COLUMN devicetype TEXT;
ALTER TABLE ports ADD COLUMN hostname TEXT;
ALTER TABLE ports ADD COLUMN cpe TEXT;  -- a JSON array of strings; NULL: none
CREATE TABLE scan_facts (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  port INTEGER,     -- NULL: a fact about the host (smb-os-discovery)
  proto TEXT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE INDEX idx_scan_facts_scan ON scan_facts(scan_id);
ALTER TABLE scans ADD COLUMN facts_parsed INTEGER NOT NULL DEFAULT 0;
-- How many times the scanner replaced its own address or name in the XML
-- before signing it (scan::scrub).
ALTER TABLE scans ADD COLUMN scrubbed INTEGER NOT NULL DEFAULT 0;
```

Register it in `src/store/mod.rs` after the `0026_job_handouts.sql` line:

```rust
    include_str!("migrations/0027_scan_facts.sql"),
```

- [ ] **Step 6: Run the store tests**

Run: `cargo test --lib store::`
Expected: pass (the migration applies on a fresh database in every test).

- [ ] **Step 7: Commit**

```bash
git add src/scan/hostkeys.rs src/store/migrations/0027_scan_facts.sql src/store/mod.rs
git commit -m "Scan facts: a shared script walker and the schema"
```

---

### Task 3: The facts parser (`scan::facts`)

**Files:**
- Create: `src/scan/facts.rs`
- Modify: `src/scan/mod.rs` (add `pub mod facts;` next to `pub mod hostkeys;`)
- Create: `tests/fixtures/nmap-facts.xml`

**Interfaces:**
- Consumes: `walk_scripts`, `Node`, `elem`, `table`, `key_attr` from `scan::hostkeys` (Task 2).
- Produces:
  - `pub const FACTS_V: i64 = 1;`
  - kind constants `HTTP_TITLE … SMB_LANMANAGER` (values as in the spec's Storage list);
  - `pub struct PortDetail { pub port: u16, pub proto: String, pub extrainfo: Option<String>, pub ostype: Option<String>, pub devicetype: Option<String>, pub hostname: Option<String>, pub cpe: Vec<String> }`
  - `pub struct Fact { pub port: Option<(u16, String)>, pub kind: &'static str, pub value: String }`
  - `#[derive(Default)] pub struct Facts { pub ports: Vec<PortDetail>, pub facts: Vec<Fact> }`
  - `pub fn extract(xml: &[u8]) -> Facts`
  - `pub fn kind_label(kind: &str) -> &'static str`

- [ ] **Step 1: Write the fixture**

Create `tests/fixtures/nmap-facts.xml`. Every section 4 field is present once; `banner`, `http-generator` (prose only), `http-grep` and `fcrdns` (data-keyed tables) are there to be ignored; `System_Time`, `Target_Name` and `date` are keys the table does not list.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -sS -sV -O -T3 --top-ports 1000 --traceroute --script (discovery or safe) and not (intrusive or broadcast or external or dos or http-comments-displayer) -oX - 192.0.2.7" start="1760000000" startstr="" version="7.94" xmloutputversion="1.05">
<host starttime="1760000000" endtime="1760000100"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.7" addrtype="ipv4"/>
<hostnames></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" devicetype="general purpose" hostname="host-7.example.net" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service><script id="banner" output="SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"/></port>
<port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="domain" method="table" conf="3"/><script id="dns-nsid" output="&#xa;  bind.version: 9.18.1&#xa;  id.server: ns1"><elem key="bind.version">9.18.1</elem><elem key="id.server">ns1</elem></script></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/><script id="http-title" output="PentAGI &amp; friends&#xa;Requested resource was /login"><elem key="title">PentAGI &amp; friends</elem><elem key="redirect_url">http://192.0.2.7/login</elem></script><script id="http-server-header" output="nginx/1.18.0"><elem>nginx/1.18.0</elem></script><script id="http-auth" output="&#xa;HTTP/1.1 401 Unauthorized&#xa;  Basic realm=bifrost"><table><elem key="scheme">Basic</elem><table key="params"><elem key="realm">bifrost</elem></table></table></script><script id="http-generator" output="WordPress 6.4"/><script id="http-grep" output="&#xa;  (1) http://192.0.2.7/: &#xa;    (1) ip: &#xa;      + 192.0.2.7"><table key="http://192.0.2.7/"><table key="(1) http://192.0.2.7/"><elem key="ip">192.0.2.7</elem></table></table></script></port>
<port protocol="tcp" portid="1080"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="socks" method="table" conf="3"/><script id="socks-auth-info" output="&#xa;  No authentication&#xa;  Username and password"><table><elem key="method">0</elem><elem key="name">No authentication</elem></table><table><elem key="method">2</elem><elem key="name">Username and password</elem></table></script></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/><script id="rdp-ntlm-info" output="&#xa;  Target_Name: WORKGROUP"><elem key="Target_Name">WORKGROUP</elem><elem key="NetBIOS_Domain_Name">WORKGROUP</elem><elem key="NetBIOS_Computer_Name">WIN-344VU98D3RU</elem><elem key="DNS_Domain_Name">WIN-344VU98D3RU</elem><elem key="DNS_Computer_Name">WIN-344VU98D3RU</elem><elem key="DNS_Tree_Name">corp.example</elem><elem key="Product_Version">10.0.17763</elem><elem key="System_Time">2026-10-06T10:00:00+00:00</elem></script></port>
<port protocol="tcp" portid="8443"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="https-alt" method="table" conf="3"/><script id="http-title" output="MinIO Console"><elem key="title">MinIO Console</elem></script></port>
</ports>
<hostscript><script id="smb-os-discovery" output="&#xa;  OS: Windows Server 2019 Standard 17763"><elem key="os">Windows Server 2019 Standard 17763</elem><elem key="lanmanager">Windows Server 2019 Standard 6.3</elem><elem key="server">WIN-344VU98D3RU\x00</elem><elem key="domain">WORKGROUP\x00</elem><elem key="workgroup">WORKGROUP\x00</elem><elem key="fqdn">WIN-344VU98D3RU</elem><elem key="domain_dns">corp.example</elem><elem key="forest_dns">corp.example</elem><elem key="date">2026-10-06T10:00:00</elem></script><script id="fcrdns" output="FAIL (No PTR record)"><table key="192.0.2.7"><elem key="status">fail</elem></table></script></hostscript>
<os><osmatch name="Linux 5.X" accuracy="95" line="1"/></os>
<runstats><finished time="1760000100" timestr="" summary="" elapsed="100" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
```

nmap writes a NUL terminator of SMB strings as the four characters `\x00`; that is a fixed suffix of nmap's own encoding, not a pattern over the data, and the parser strips it from `smb.*` values.

- [ ] **Step 2: Write the failing tests**

Create `src/scan/facts.rs` with the tests at the bottom (the module body comes in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/nmap-facts.xml");

    fn values<'a>(f: &'a Facts, kind: &str) -> Vec<(Option<u16>, &'a str)> {
        f.facts
            .iter()
            .filter(|x| x.kind == kind)
            .map(|x| (x.port.as_ref().map(|p| p.0), x.value.as_str()))
            .collect()
    }

    #[test]
    fn every_service_detail_is_read() {
        let f = extract(FIXTURE);
        assert_eq!(f.ports.len(), 1, "only port 22 has details: {:?}", f.ports);
        let p = &f.ports[0];
        assert_eq!((p.port, p.proto.as_str()), (22, "tcp"));
        assert_eq!(p.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));
        assert_eq!(p.ostype.as_deref(), Some("Linux"));
        assert_eq!(p.devicetype.as_deref(), Some("general purpose"));
        assert_eq!(p.hostname.as_deref(), Some("host-7.example.net"));
        assert_eq!(
            p.cpe,
            vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
        );
    }

    #[test]
    fn every_script_fact_is_read_from_its_fixed_key() {
        let f = extract(FIXTURE);
        assert_eq!(
            values(&f, HTTP_TITLE),
            vec![(Some(80), "PentAGI & friends"), (Some(8443), "MinIO Console")]
        );
        assert_eq!(values(&f, HTTP_REDIRECT), vec![(Some(80), "http://192.0.2.7/login")]);
        assert_eq!(values(&f, HTTP_SERVER), vec![(Some(80), "nginx/1.18.0")]);
        assert_eq!(values(&f, HTTP_AUTH), vec![(Some(80), "Basic realm=\"bifrost\"")]);
        assert_eq!(values(&f, NTLM_NETBIOS_COMPUTER), vec![(Some(3389), "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, NTLM_NETBIOS_DOMAIN), vec![(Some(3389), "WORKGROUP")]);
        assert_eq!(values(&f, NTLM_DNS_COMPUTER), vec![(Some(3389), "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, NTLM_DNS_DOMAIN), vec![(Some(3389), "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, NTLM_DNS_TREE), vec![(Some(3389), "corp.example")]);
        assert_eq!(values(&f, NTLM_PRODUCT_VERSION), vec![(Some(3389), "10.0.17763")]);
        assert_eq!(
            values(&f, SOCKS_METHOD),
            vec![(Some(1080), "No authentication"), (Some(1080), "Username and password")]
        );
        assert_eq!(values(&f, DNS_NSID), vec![(Some(53), "9.18.1"), (Some(53), "ns1")]);
        assert_eq!(values(&f, SMB_SERVER), vec![(None, "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, SMB_DOMAIN), vec![(None, "WORKGROUP")]);
        assert_eq!(values(&f, SMB_WORKGROUP), vec![(None, "WORKGROUP")]);
        assert_eq!(values(&f, SMB_FQDN), vec![(None, "WIN-344VU98D3RU")]);
        assert_eq!(values(&f, SMB_DOMAIN_DNS), vec![(None, "corp.example")]);
        assert_eq!(values(&f, SMB_FOREST_DNS), vec![(None, "corp.example")]);
        assert_eq!(values(&f, SMB_OS), vec![(None, "Windows Server 2019 Standard 17763")]);
        assert_eq!(values(&f, SMB_LANMANAGER), vec![(None, "Windows Server 2019 Standard 6.3")]);
        // Keys the table does not list, and prose or data-keyed scripts.
        let all: Vec<&str> = f.facts.iter().map(|x| x.value.as_str()).collect();
        for absent in [
            "2026-10-06T10:00:00+00:00", "2026-10-06T10:00:00", "WordPress 6.4",
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "192.0.2.7", "fail", "0", "2",
        ] {
            assert!(!all.contains(&absent), "{absent} in {all:?}");
        }
        assert!(f.facts.iter().all(|x| x.kind != "Target_Name"));
        // 2 titles, 1 redirect, 1 server, 1 login, 6 NTLM, 2 SOCKS, 2 NSID, 8 SMB.
        assert_eq!(f.facts.len(), 23, "{:?}", f.facts);
    }

    #[test]
    fn prose_only_and_data_keyed_scripts_yield_nothing() {
        let xml = br#"<nmaprun><host><ports>
<port protocol="tcp" portid="25"><service name="smtp"/><script id="smtp-commands" output="mail.example.net Hello scanner [203.0.113.5]"/><script id="banner" output="220 mail"/></port>
<port protocol="tcp" portid="80"><service name="http"/><script id="http-generator" output="Drupal 7"/><script id="http-grep" output="x"><table key="http://h/"><elem key="ip">1.2.3.4</elem></table></script></port>
</ports><hostscript><script id="fcrdns" output="FAIL"><table key="203.0.113.9"><elem key="status">fail</elem></table></script></hostscript></host></nmaprun>"#;
        let f = extract(xml);
        assert!(f.facts.is_empty(), "{:?}", f.facts);
        assert!(f.ports.is_empty(), "{:?}", f.ports);
    }

    #[test]
    fn values_are_cut_at_a_character_boundary() {
        let long = "ü".repeat(300); // 600 bytes
        let xml = format!(
            r#"<nmaprun><host><ports><port protocol="tcp" portid="80"><service name="http" extrainfo="{long}"/><script id="http-title" output="t"><elem key="title">{long}</elem><elem key="redirect_url">   </elem></script></port></ports></host></nmaprun>"#
        );
        let f = extract(xml.as_bytes());
        let title = &values(&f, HTTP_TITLE)[0].1;
        assert_eq!(title.len(), 512);
        assert_eq!(title.chars().count(), 256);
        assert_eq!(f.ports[0].extrainfo.as_deref().map(str::len), Some(512));
        assert!(values(&f, HTTP_REDIRECT).is_empty(), "blank values are skipped");
        // An odd cut lands on the boundary before the character.
        let odd = format!("{}ü", "a".repeat(511));
        let xml = format!(
            r#"<nmaprun><host><ports><port protocol="tcp" portid="80"><script id="http-title" output="t"><elem key="title">{odd}</elem></script></port></ports></host></nmaprun>"#
        );
        assert_eq!(values(&extract(xml.as_bytes()), HTTP_TITLE)[0].1.len(), 511);
    }

    #[test]
    fn the_per_scan_cap_holds() {
        let mut ports = String::new();
        for p in 1..=70u16 {
            ports.push_str(&format!(
                r#"<port protocol="tcp" portid="{p}"><script id="http-title" output="t"><elem key="title">T{p}</elem></script></port>"#
            ));
        }
        let xml = format!("<nmaprun><host><ports>{ports}</ports></host></nmaprun>");
        let f = extract(xml.as_bytes());
        assert_eq!(f.facts.len(), MAX_FACTS);
        assert_eq!(f.facts.last().unwrap().value, "T64", "document order, first ones kept");
    }

    #[test]
    fn unparsable_input_yields_what_came_before() {
        let cut = &FIXTURE[..FIXTURE.len() / 2];
        let f = extract(cut);
        assert!(!f.ports.is_empty() || !f.facts.is_empty());
        assert!(extract(b"not xml").facts.is_empty());
    }

    #[test]
    fn every_kind_has_a_label() {
        for k in KINDS {
            assert_ne!(kind_label(k), "Other", "{k}");
        }
        assert_eq!(kind_label("nope"), "Other");
    }
}
```

- [ ] **Step 3: Run them and see them fail**

Run: `cargo test --lib scan::facts`
Expected: compile errors (nothing defined yet).

- [ ] **Step 4: Write the parser**

The module body of `src/scan/facts.rs`, above the tests:

```rust
//! What a scan says a source serves and what it calls itself, read only
//! from the places nmap writes as structure: the attributes of `<service>`
//! and its `<cpe>` children, and the `<elem>`s of a few scripts at fixed
//! keys. Never from a script's prose `output`, and never from an `<elem>`
//! whose key is data (`http-grep`, `fcrdns`). Derived from the stored XML
//! on every node (`store::facts`), like host keys, so nothing is
//! replicated and older scans can be read after the fact.
use super::hostkeys::{Node, elem, key_attr, table, walk_scripts};
use quick_xml::Reader;
use quick_xml::events::Event;

/// Version of what `extract` reads (`scans.facts_parsed`). A change bumps
/// it, and the backfill reads every stored scan again.
pub const FACTS_V: i64 = 1;
/// Longest fact value kept, in bytes (cut at a character boundary).
pub const MAX_VALUE: usize = 512;
/// Most facts kept of one scan, in document order.
pub const MAX_FACTS: usize = 64;

pub const HTTP_TITLE: &str = "http.title";
pub const HTTP_REDIRECT: &str = "http.redirect";
pub const HTTP_SERVER: &str = "http.server";
pub const HTTP_AUTH: &str = "http.auth";
pub const NTLM_NETBIOS_COMPUTER: &str = "ntlm.netbios_computer";
pub const NTLM_NETBIOS_DOMAIN: &str = "ntlm.netbios_domain";
pub const NTLM_DNS_COMPUTER: &str = "ntlm.dns_computer";
pub const NTLM_DNS_DOMAIN: &str = "ntlm.dns_domain";
pub const NTLM_DNS_TREE: &str = "ntlm.dns_tree";
pub const NTLM_PRODUCT_VERSION: &str = "ntlm.product_version";
pub const SOCKS_METHOD: &str = "socks.method";
pub const DNS_NSID: &str = "dns.nsid";
pub const SMB_SERVER: &str = "smb.server";
pub const SMB_DOMAIN: &str = "smb.domain";
pub const SMB_FQDN: &str = "smb.fqdn";
pub const SMB_DOMAIN_DNS: &str = "smb.domain_dns";
pub const SMB_FOREST_DNS: &str = "smb.forest_dns";
pub const SMB_WORKGROUP: &str = "smb.workgroup";
pub const SMB_OS: &str = "smb.os";
pub const SMB_LANMANAGER: &str = "smb.lanmanager";

/// Every kind, for the label test and the docs.
pub const KINDS: [&str; 20] = [
    HTTP_TITLE, HTTP_REDIRECT, HTTP_SERVER, HTTP_AUTH,
    NTLM_NETBIOS_COMPUTER, NTLM_NETBIOS_DOMAIN, NTLM_DNS_COMPUTER, NTLM_DNS_DOMAIN,
    NTLM_DNS_TREE, NTLM_PRODUCT_VERSION, SOCKS_METHOD, DNS_NSID,
    SMB_SERVER, SMB_DOMAIN, SMB_FQDN, SMB_DOMAIN_DNS, SMB_FOREST_DNS, SMB_WORKGROUP,
    SMB_OS, SMB_LANMANAGER,
];

/// The `<elem>` keys read per script, and the kind each becomes. One
/// table: a script or key not here is not read, however interesting.
const KEYS: &[(&str, &str, &str)] = &[
    ("http-title", "title", HTTP_TITLE),
    ("http-title", "redirect_url", HTTP_REDIRECT),
    ("rdp-ntlm-info", "NetBIOS_Computer_Name", NTLM_NETBIOS_COMPUTER),
    ("rdp-ntlm-info", "NetBIOS_Domain_Name", NTLM_NETBIOS_DOMAIN),
    ("rdp-ntlm-info", "DNS_Computer_Name", NTLM_DNS_COMPUTER),
    ("rdp-ntlm-info", "DNS_Domain_Name", NTLM_DNS_DOMAIN),
    ("rdp-ntlm-info", "DNS_Tree_Name", NTLM_DNS_TREE),
    ("rdp-ntlm-info", "Product_Version", NTLM_PRODUCT_VERSION),
    ("dns-nsid", "bind.version", DNS_NSID),
    ("dns-nsid", "id.server", DNS_NSID),
    ("smb-os-discovery", "server", SMB_SERVER),
    ("smb-os-discovery", "domain", SMB_DOMAIN),
    ("smb-os-discovery", "fqdn", SMB_FQDN),
    ("smb-os-discovery", "domain_dns", SMB_DOMAIN_DNS),
    ("smb-os-discovery", "forest_dns", SMB_FOREST_DNS),
    ("smb-os-discovery", "workgroup", SMB_WORKGROUP),
    ("smb-os-discovery", "os", SMB_OS),
    ("smb-os-discovery", "lanmanager", SMB_LANMANAGER),
];

/// The scripts walked: the keyed ones above, and three with their own
/// shape (`http-server-header`: unnamed elems; `http-auth` and
/// `socks-auth-info`: one table per entry).
const SCRIPTS: [&str; 7] = [
    "http-title", "http-server-header", "http-auth", "rdp-ntlm-info",
    "socks-auth-info", "dns-nsid", "smb-os-discovery",
];

/// What nmap's `-sV` wrote about one port beyond name, product and version.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PortDetail {
    pub port: u16,
    pub proto: String,
    pub extrainfo: Option<String>,
    pub ostype: Option<String>,
    pub devicetype: Option<String>,
    pub hostname: Option<String>,
    pub cpe: Vec<String>,
}

impl PortDetail {
    fn any(&self) -> bool {
        self.extrainfo.is_some()
            || self.ostype.is_some()
            || self.devicetype.is_some()
            || self.hostname.is_some()
            || !self.cpe.is_empty()
    }
}

/// One fact from a script, on a port or (None) about the host.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub port: Option<(u16, String)>,
    pub kind: &'static str,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct Facts {
    pub ports: Vec<PortDetail>,
    pub facts: Vec<Fact>,
}

/// `s` trimmed and cut to `MAX_VALUE` bytes at a character boundary;
/// None when nothing is left.
fn value(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut end = s.len().min(MAX_VALUE);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Some(s[..end].to_string())
}

/// An SMB string as nmap writes it, without the NUL terminator nmap
/// encodes as the four characters `\x00`.
fn smb_value(s: &str) -> Option<String> {
    value(s.strip_suffix("\\x00").unwrap_or(s))
}

/// Everything in an nmap XML report that section 4 of the spec names.
/// Unparsable input yields what was found before the error.
pub fn extract(xml: &[u8]) -> Facts {
    let (details, protos) = port_details(xml);
    let mut out = Facts {
        ports: details,
        facts: vec![],
    };
    walk_scripts(xml, &SCRIPTS, &mut |port, id, _output, root| {
        let at = (port > 0).then(|| {
            let proto = protos
                .iter()
                .find(|(p, _)| *p == port)
                .map(|(_, pr)| pr.clone())
                .unwrap_or_else(|| "tcp".into());
            (port, proto)
        });
        let mut push = |kind: &'static str, v: Option<String>| {
            if let Some(value) = v {
                out.facts.push(Fact {
                    port: at.clone(),
                    kind,
                    value,
                });
            }
        };
        match id {
            "http-server-header" => {
                for n in root {
                    if let Node::Elem { key: None, text } = n {
                        push(HTTP_SERVER, value(text));
                    }
                }
            }
            "http-auth" => {
                for n in root {
                    let Node::Table { children, .. } = n else {
                        continue;
                    };
                    let Some(scheme) = elem(children, "scheme").and_then(value) else {
                        continue;
                    };
                    let realm = table(children, "params")
                        .and_then(|p| elem(p, "realm"))
                        .and_then(value);
                    push(
                        HTTP_AUTH,
                        value(&match realm {
                            Some(r) => format!("{scheme} realm=\"{r}\""),
                            None => scheme,
                        }),
                    );
                }
            }
            "socks-auth-info" => {
                for n in root {
                    if let Node::Table { children, .. } = n {
                        push(SOCKS_METHOD, elem(children, "name").and_then(value));
                    }
                }
            }
            _ => {
                for (script, key, kind) in KEYS {
                    if *script != id {
                        continue;
                    }
                    let v = elem(root, key);
                    let v = if id == "smb-os-discovery" {
                        v.and_then(smb_value)
                    } else {
                        v.and_then(value)
                    };
                    push(kind, v);
                }
            }
        }
    });
    out.facts.truncate(MAX_FACTS);
    out
}

/// The `<service>` attributes and `<cpe>` texts of every port that has
/// any, and the protocol of every port.
fn port_details(xml: &[u8]) -> (Vec<PortDetail>, Vec<(u16, String)>) {
    let mut out = vec![];
    let mut protos = vec![];
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut cur: Option<PortDetail> = None;
    let mut cpe: Option<String> = None;
    while let Ok(ev) = reader.read_event_into(&mut buf) {
        match ev {
            Event::Start(ref e) | Event::Empty(ref e) if e.name().as_ref() == "port" => {
                let port = key_attr(e, "portid").and_then(|p| p.parse().ok()).unwrap_or(0);
                let proto = key_attr(e, "protocol").unwrap_or_else(|| "tcp".into());
                if port > 0 {
                    protos.push((port, proto.clone()));
                }
                cur = Some(PortDetail { port, proto, ..Default::default() });
            }
            Event::Start(ref e) | Event::Empty(ref e) if e.name().as_ref() == "service" => {
                if let Some(p) = cur.as_mut() {
                    for a in e.attributes().flatten() {
                        let v = a
                            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                            .map(|c| c.into_owned())
                            .unwrap_or_else(|_| a.value.to_string());
                        match a.key.as_ref() {
                            "extrainfo" => p.extrainfo = value(&v),
                            "ostype" => p.ostype = value(&v),
                            "devicetype" => p.devicetype = value(&v),
                            "hostname" => p.hostname = value(&v),
                            _ => {}
                        }
                    }
                }
            }
            Event::Start(ref e) if e.name().as_ref() == "cpe" && cur.is_some() => cpe = Some(String::new()),
            Event::Text(t) => {
                if let Some(s) = cpe.as_mut() {
                    s.push_str(&t);
                }
            }
            Event::End(ref e) => match e.name().as_ref() {
                "cpe" => {
                    if let (Some(s), Some(p)) = (cpe.take(), cur.as_mut())
                        && let Some(v) = value(&s)
                    {
                        p.cpe.push(v);
                    }
                }
                "port" => {
                    if let Some(p) = cur.take()
                        && p.port > 0
                        && p.any()
                    {
                        out.push(p);
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }
    (out, protos)
}

/// The label a page shows before a value of `kind`.
pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        HTTP_TITLE => "Title",
        HTTP_REDIRECT => "Redirects to",
        HTTP_SERVER => "Server",
        HTTP_AUTH => "Login",
        NTLM_NETBIOS_COMPUTER | SMB_SERVER => "Computer",
        NTLM_NETBIOS_DOMAIN | SMB_DOMAIN => "Domain",
        NTLM_DNS_COMPUTER => "DNS name",
        NTLM_DNS_DOMAIN | SMB_DOMAIN_DNS => "DNS domain",
        NTLM_DNS_TREE | SMB_FOREST_DNS => "Forest",
        NTLM_PRODUCT_VERSION => "Windows build",
        SOCKS_METHOD => "SOCKS",
        DNS_NSID => "DNS server",
        SMB_FQDN => "FQDN",
        SMB_WORKGROUP => "Workgroup",
        SMB_OS => "OS",
        SMB_LANMANAGER => "LAN Manager",
        _ => "Other",
    }
}
```

The `Event::Text` arm pushes `&t` as `walk_scripts` does. A `<cpe>` text with an entity (`&amp;`) would arrive as a `GeneralRef` event; CPE strings never contain one, so it is ignored here. The `ref e` bindings in the `port` and `service` arms let the guard borrow the event.

Add `pub mod facts;` to `src/scan/mod.rs`.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib scan::facts`
Expected: all seven pass.

- [ ] **Step 6: Commit**

```bash
git add src/scan/facts.rs src/scan/mod.rs tests/fixtures/nmap-facts.xml
git commit -m "Scan facts: parse what a source serves and calls itself"
```

---

### Task 4: Storing and reading facts (`store::facts`)

**Files:**
- Create: `src/store/facts.rs`
- Modify: `src/store/mod.rs` (add `pub mod facts;`)
- Modify: `src/store/inspect.rs` (`PortRow`, `ports_for_scan`, `ports_for_scans`)
- Modify: `src/store/data.rs:901` (derive after host keys)
- Modify: `src/lib.rs:245-256` (backfill task)

**Interfaces:**
- Consumes: `scan::facts::{FACTS_V, Facts, Fact, PortDetail, extract, kind_label}` (Task 3); the columns of Task 2.
- Produces:
  - `pub struct FactRow { pub port: Option<i64>, pub kind: String, pub value: String }` with `pub fn label(&self) -> &'static str`.
  - `pub(crate) async fn derive(conn: &mut SqliteConnection, scan_id: i64, raw_xml: Option<&[u8]>) -> Result<()>`
  - `pub async fn backfill(pool: &SqlitePool, below: i64) -> Result<u64>`
  - `Store::host_facts_for_scan(&self, scan_id: i64) -> Result<Vec<FactRow>>`
  - `Store::host_facts_for_scans(&self, ids: &[i64]) -> Result<HashMap<i64, Vec<FactRow>>>`
  - `pub fn serves(ports: &[PortRow]) -> String` and `pub fn windows_names(host: &[FactRow], ports: &[PortRow]) -> String` (the IP page summaries).
  - `PortRow` gains `extrainfo, ostype, devicetype, hostname: Option<String>`, `cpe: Option<String>` (JSON), `#[sqlx(skip)] facts: Vec<FactRow>`, and `pub fn cpes(&self) -> Vec<String>`, `pub fn described(&self) -> String` (product, version, extrainfo joined with a space), `pub fn system(&self) -> String` (ostype, devicetype and hostname joined with ` · `).

- [ ] **Step 1: Write the failing tests**

In the new `src/store/facts.rs`, after the module body, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::nmap_xml::parse_nmap_xml;
    use crate::store::Store;

    const FACTS: &[u8] = include_bytes!("../../tests/fixtures/nmap-facts.xml");
    const BASIC: &[u8] = include_bytes!("../../tests/fixtures/nmap-basic.xml");

    /// A scan stored for `ip` (as the scanner stores it), and its id.
    async fn scan(s: &Store, ip: &str, xml: &[u8]) -> i64 {
        let ip = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        s.enqueue_scan(ip.id, 3, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = parse_nmap_xml(xml).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();
        sqlx::query_scalar("SELECT MAX(id) FROM scans")
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_stored_scan_yields_its_port_details_and_facts() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        let ports = s.ports_for_scan(id).await.unwrap();
        let ssh = ports.iter().find(|p| p.port == 22).unwrap();
        assert_eq!(ssh.extrainfo.as_deref(), Some("Ubuntu Linux; protocol 2.0"));
        assert_eq!(ssh.cpes(), vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]);
        assert_eq!(ssh.system(), "Linux · general purpose · host-7.example.net");
        assert_eq!(ssh.described(), "OpenSSH 9.6p1 Ubuntu Linux; protocol 2.0");
        assert!(ssh.facts.is_empty());
        let http = ports.iter().find(|p| p.port == 80).unwrap();
        assert!(http.cpes().is_empty() && http.extrainfo.is_none());
        let kinds: Vec<&str> = http.facts.iter().map(|f| f.kind.as_str()).collect();
        assert_eq!(kinds, vec!["http.title", "http.redirect", "http.server", "http.auth"]);
        assert_eq!(http.facts[0].label(), "Title");
        let host = s.host_facts_for_scan(id).await.unwrap();
        assert_eq!(host.len(), 8, "{host:?}");
        assert!(host.iter().all(|f| f.port.is_none()));
        let v: i64 = sqlx::query_scalar("SELECT facts_parsed FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(v, FACTS_V);
        // A plain scan: read, nothing found.
        let plain = scan(&s, "192.0.2.8", BASIC).await;
        assert!(s.host_facts_for_scan(plain).await.unwrap().is_empty());
        assert!(s.ports_for_scan(plain).await.unwrap().iter().all(|p| p.facts.is_empty()));
    }

    #[tokio::test]
    async fn backfill_reads_scans_stored_before() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        // As an older build would have left it.
        sqlx::query("DELETE FROM scan_facts").execute(&s.pool).await.unwrap();
        sqlx::query("UPDATE ports SET extrainfo = NULL, cpe = NULL").execute(&s.pool).await.unwrap();
        sqlx::query("UPDATE scans SET facts_parsed = 0").execute(&s.pool).await.unwrap();
        assert_eq!(backfill(&s.pool, FACTS_V).await.unwrap(), 1);
        assert_eq!(s.host_facts_for_scan(id).await.unwrap().len(), 8);
        assert!(s.ports_for_scan(id).await.unwrap()[0].extrainfo.is_some());
        assert_eq!(backfill(&s.pool, FACTS_V).await.unwrap(), 0, "each scan once");
    }

    #[tokio::test]
    async fn two_nodes_derive_the_same_rows() {
        let dir = tempfile::tempdir().unwrap();
        let a = Store::connect(&dir.path().join("a.db")).await.unwrap();
        let b = Store::connect(&dir.path().join("b.db")).await.unwrap();
        let (ia, ib) = (scan(&a, "192.0.2.7", FACTS).await, scan(&b, "192.0.2.7", FACTS).await);
        let rows = |s: &Store, id: i64| {
            let s = s.clone();
            async move {
                sqlx::query_as::<_, (Option<i64>, Option<String>, String, String)>(
                    "SELECT port, proto, kind, value FROM scan_facts WHERE scan_id = ? ORDER BY id",
                )
                .bind(id)
                .fetch_all(&s.pool)
                .await
                .unwrap()
            }
        };
        assert_eq!(rows(&a, ia).await, rows(&b, ib).await);
    }

    #[tokio::test]
    async fn deleting_a_scan_deletes_its_facts() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(&s, "192.0.2.7", FACTS).await;
        sqlx::query("DELETE FROM ports").execute(&s.pool).await.unwrap();
        sqlx::query("DELETE FROM host_keys").execute(&s.pool).await.unwrap();
        sqlx::query("DELETE FROM scans WHERE id = ?").bind(id).execute(&s.pool).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_facts").fetch_one(&s.pool).await.unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn the_ip_page_summaries() {
        let fact = |port: Option<i64>, kind: &str, value: &str| FactRow {
            port,
            kind: kind.into(),
            value: value.into(),
        };
        let port = |port: i64, facts: Vec<FactRow>| crate::store::inspect::PortRow {
            port,
            proto: "tcp".into(),
            state: "open".into(),
            service: None,
            product: None,
            version: None,
            extrainfo: None,
            ostype: None,
            devicetype: None,
            hostname: None,
            cpe: None,
            facts,
        };
        let ports = vec![
            port(8443, vec![fact(Some(8443), "http.title", "PentAGI")]),
            port(9000, vec![fact(Some(9000), "http.title", "MinIO"), fact(Some(9000), "http.server", "MinIO")]),
            port(80, vec![fact(Some(80), "http.server", "nginx/1.18.0")]),
            port(81, vec![fact(Some(81), "http.title", "PentAGI")]),
            port(82, vec![fact(Some(82), "http.title", "one more")]),
            port(3389, vec![fact(Some(3389), "ntlm.netbios_computer", "WIN-1"), fact(Some(3389), "ntlm.netbios_domain", "WORKGROUP")]),
        ];
        assert_eq!(serves(&ports), "8443 PentAGI · 9000 MinIO · 80 nginx/1.18.0");
        assert_eq!(windows_names(&[], &ports), "WIN-1 · WORKGROUP");
        let host = vec![fact(None, "smb.server", "SRV"), fact(None, "smb.domain", "CORP")];
        assert_eq!(windows_names(&host, &ports), "SRV · CORP", "the host script wins");
        assert_eq!(serves(&[]), "");
        assert_eq!(windows_names(&[], &[]), "");
    }
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `cargo test --lib store::facts`
Expected: compile errors.

- [ ] **Step 3: Extend `PortRow` and its queries**

In `src/store/inspect.rs`:

```rust
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PortRow {
    pub port: i64,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    /// What `-sV` added (`scan::facts`): free text after the version, the
    /// OS and device type it implies, the host name the service announced.
    pub extrainfo: Option<String>,
    pub ostype: Option<String>,
    pub devicetype: Option<String>,
    pub hostname: Option<String>,
    /// The CPEs as stored: a JSON array, or NULL.
    pub cpe: Option<String>,
    /// Script facts on this port (`scan_facts`), read separately.
    #[sqlx(skip)]
    pub facts: Vec<super::facts::FactRow>,
}

impl PortRow {
    pub fn cpes(&self) -> Vec<String> {
        self.cpe
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok())
            .unwrap_or_default()
    }

    /// Product, version and extra info on one line.
    pub fn described(&self) -> String {
        [&self.product, &self.version, &self.extrainfo]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// OS type, device type and announced host name, the ones set, joined.
    pub fn system(&self) -> String {
        [&self.ostype, &self.devicetype, &self.hostname]
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" · ")
    }
}
```

`ports_for_scan` selects the new columns too and attaches the facts:

```rust
    pub async fn ports_for_scan(&self, scan_id: i64) -> Result<Vec<PortRow>> {
        let mut ports = sqlx::query_as::<_, PortRow>(
            "SELECT port, proto, state, service, product, version, extrainfo, ostype, devicetype,
                    hostname, cpe
             FROM ports WHERE scan_id = ? ORDER BY port",
        )
        .bind(scan_id)
        .fetch_all(&self.read)
        .await?;
        let facts = self.facts_for_scans(&[scan_id]).await?;
        super::facts::attach(&mut ports, facts.get(&scan_id).map(Vec::as_slice).unwrap_or(&[]));
        Ok(ports)
    }
```

`ports_for_scans` the same with a `scan_id` column in front; replace the tuple `Row` with a flattened struct:

```rust
        #[derive(sqlx::FromRow)]
        struct Row {
            scan_id: i64,
            #[sqlx(flatten)]
            port: PortRow,
        }
```

select `scan_id, port, proto, state, service, product, version, extrainfo, ostype, devicetype, hostname, cpe`, group by `scan_id` as today, then fetch `self.facts_for_scans(scan_ids)` once and `attach` per scan.

- [ ] **Step 4: Write `store::facts`**

```rust
//! What a scan says a source serves and calls itself (`scan::facts`), kept
//! in `ports` (the service details) and `scan_facts`, derived from the
//! stored XML on every node like host keys, and read back per scan.
use super::Store;
use super::inspect::{MAX_RAW_XML, PortRow, zstd_decode_capped};
use crate::scan::facts::{FACTS_V, Facts, extract, kind_label};
use anyhow::Result;
use sqlx::SqliteConnection;
use std::collections::HashMap;

/// One fact as the pages show it. `port` None: about the host.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FactRow {
    pub port: Option<i64>,
    pub kind: String,
    pub value: String,
}

impl FactRow {
    pub fn label(&self) -> &'static str {
        kind_label(&self.kind)
    }
}

/// Read the facts out of a stored scan (zstd-compressed nmap XML) into
/// `ports` and `scan_facts`, and mark the scan as read at `FACTS_V`.
/// Unreadable XML yields none; only database errors fail.
pub(crate) async fn derive(
    conn: &mut SqliteConnection,
    scan_id: i64,
    raw_xml: Option<&[u8]>,
) -> Result<()> {
    let f = match raw_xml.map(|b| zstd_decode_capped(b, MAX_RAW_XML)) {
        Some(Ok(xml)) => extract(&xml),
        Some(Err(e)) => {
            tracing::debug!(scan_id, "scan facts: scan XML unreadable: {e:#}");
            Facts::default()
        }
        None => Facts::default(),
    };
    for p in &f.ports {
        let cpe = (!p.cpe.is_empty()).then(|| serde_json::to_string(&p.cpe).unwrap_or_default());
        sqlx::query(
            "UPDATE ports SET extrainfo = ?, ostype = ?, devicetype = ?, hostname = ?, cpe = ?
             WHERE scan_id = ? AND port = ? AND proto = ?",
        )
        .bind(&p.extrainfo)
        .bind(&p.ostype)
        .bind(&p.devicetype)
        .bind(&p.hostname)
        .bind(cpe)
        .bind(scan_id)
        .bind(p.port as i64)
        .bind(&p.proto)
        .execute(&mut *conn)
        .await?;
    }
    // Read again (a newer FACTS_V): what an older parse left goes.
    sqlx::query("DELETE FROM scan_facts WHERE scan_id = ?")
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
    for x in &f.facts {
        sqlx::query("INSERT INTO scan_facts (scan_id, port, proto, kind, value) VALUES (?,?,?,?,?)")
            .bind(scan_id)
            .bind(x.port.as_ref().map(|p| p.0 as i64))
            .bind(x.port.as_ref().map(|p| p.1.as_str()))
            .bind(x.kind)
            .bind(&x.value)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("UPDATE scans SET facts_parsed = ? WHERE id = ?")
        .bind(FACTS_V)
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Scans read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 50;
/// Pause between [`backfill`]'s transactions, so the trap's and
/// replication's writes get the lock in between.
const BACKFILL_PAUSE: std::time::Duration = std::time::Duration::from_millis(25);

/// Read the scans whose `facts_parsed` is below `below`: stored before
/// `scan_facts` existed, by an older build sharing the database, or by an
/// older parser. Walks the table once by id, a short transaction per
/// batch with a pause after it. Returns how many were read.
pub async fn backfill(pool: &sqlx::SqlitePool, below: i64) -> Result<u64> {
    let mut done = 0;
    let mut after = 0i64;
    loop {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(i64, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT id, raw_xml FROM scans WHERE facts_parsed < ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(below)
        .bind(after)
        .bind(BACKFILL_BATCH)
        .fetch_all(&mut *tx)
        .await?;
        let Some((last, _)) = rows.last() else {
            return Ok(done);
        };
        after = *last;
        for (id, xml) in &rows {
            derive(&mut tx, *id, xml.as_deref()).await?;
        }
        tx.commit().await?;
        done += rows.len() as u64;
        tokio::time::sleep(BACKFILL_PAUSE).await;
    }
}

/// Give each port its facts (`facts` are one scan's, host facts included
/// and left alone).
pub(crate) fn attach(ports: &mut [PortRow], facts: &[FactRow]) {
    for p in ports {
        p.facts = facts
            .iter()
            .filter(|f| f.port == Some(p.port))
            .cloned()
            .collect();
    }
}

impl Store {
    /// Every fact of each scan, host facts first, by scan id.
    pub(crate) async fn facts_for_scans(&self, scan_ids: &[i64]) -> Result<HashMap<i64, Vec<FactRow>>> {
        let mut out: HashMap<i64, Vec<FactRow>> = HashMap::new();
        for chunk in scan_ids.chunks(400) {
            let sql = format!(
                "SELECT scan_id, port, kind, value FROM scan_facts WHERE scan_id IN ({})
                 ORDER BY scan_id, port IS NOT NULL, port, id",
                vec!["?"; chunk.len()].join(",")
            );
            let mut q = sqlx::query_as::<_, (i64, Option<i64>, String, String)>(sqlx::AssertSqlSafe(sql));
            for id in chunk {
                q = q.bind(id);
            }
            for (scan_id, port, kind, value) in q.fetch_all(&self.read).await? {
                out.entry(scan_id).or_default().push(FactRow { port, kind, value });
            }
        }
        Ok(out)
    }

    /// The facts about the host itself (`smb-os-discovery`) of one scan.
    pub async fn host_facts_for_scan(&self, scan_id: i64) -> Result<Vec<FactRow>> {
        Ok(self
            .host_facts_for_scans(&[scan_id])
            .await?
            .remove(&scan_id)
            .unwrap_or_default())
    }

    pub async fn host_facts_for_scans(&self, scan_ids: &[i64]) -> Result<HashMap<i64, Vec<FactRow>>> {
        let mut all = self.facts_for_scans(scan_ids).await?;
        for v in all.values_mut() {
            v.retain(|f| f.port.is_none());
        }
        Ok(all)
    }
}

/// Most entries in [`serves`].
const SERVES_MAX: usize = 3;

/// What the source serves, for a scan's heading on the IP page: distinct
/// titles and servers, at most three, each with its port
/// (`8443 PentAGI · 9000 MinIO · 80 nginx/1.18.0`).
pub fn serves(ports: &[PortRow]) -> String {
    let mut seen: Vec<&str> = vec![];
    let mut out: Vec<String> = vec![];
    for p in ports {
        for f in &p.facts {
            if (f.kind == crate::scan::facts::HTTP_TITLE || f.kind == crate::scan::facts::HTTP_SERVER)
                && !seen.contains(&f.value.as_str())
            {
                seen.push(&f.value);
                out.push(format!("{} {}", p.port, f.value));
                if out.len() == SERVES_MAX {
                    return out.join(" · ");
                }
            }
        }
    }
    out.join(" · ")
}

/// The Windows computer name and domain, when known: from the SMB host
/// script first, else from RDP's NTLM reply.
pub fn windows_names(host: &[FactRow], ports: &[PortRow]) -> String {
    use crate::scan::facts::{NTLM_NETBIOS_COMPUTER, NTLM_NETBIOS_DOMAIN, SMB_DOMAIN, SMB_SERVER};
    let first = |kind: &str| -> Option<&str> {
        host.iter()
            .chain(ports.iter().flat_map(|p| p.facts.iter()))
            .find(|f| f.kind == kind)
            .map(|f| f.value.as_str())
    };
    let computer = first(SMB_SERVER).or_else(|| first(NTLM_NETBIOS_COMPUTER));
    let domain = first(SMB_DOMAIN).or_else(|| first(NTLM_NETBIOS_DOMAIN));
    [computer, domain].into_iter().flatten().collect::<Vec<_>>().join(" · ")
}
```

Add `pub mod facts;` to `src/store/mod.rs`.

- [ ] **Step 5: Derive on store and backfill at start**

In `src/store/data.rs` right after `super::hostkeys::derive(conn, scan_id, ip_id, r.raw_xml.as_deref()).await?;` (line 901):

```rust
        super::facts::derive(conn, scan_id, r.raw_xml.as_deref()).await?;
```

In `src/lib.rs`, after the host keys backfill task:

```rust
    // Facts of scans stored before this build or read by an older parser
    // (FACTS_V); new scans are read as stored.
    tokio::spawn({
        let pool = store.pool.clone();
        async move {
            match store::facts::backfill(&pool, scan::facts::FACTS_V).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(scans = n, "scan facts: read stored scans"),
                Err(e) => tracing::warn!(error = %e, "scan facts: backfill failed"),
            }
        }
    });
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib store::facts store::inspect store::hostkeys admin::`
Expected: pass. `admin::scans::tests::the_scan_page_shows_the_hand_out_line` and any other `PortRow` literal need the new fields (`extrainfo: None, ostype: None, devicetype: None, hostname: None, cpe: None, facts: vec![]`); fix those.

- [ ] **Step 7: Commit**

```bash
git add src/store/facts.rs src/store/mod.rs src/store/inspect.rs src/store/data.rs src/lib.rs src/admin/scans.rs
git commit -m "Scan facts: derived on store, backfilled at start, read per scan"
```

---

### Task 5: Facts on the pages and in the export

**Files:**
- Modify: `templates/_ports.html`, `templates/admin_scan.html`, `templates/_target.html`
- Modify: `src/admin/scans.rs` (`ScanPage`, `scan_page`), `src/admin/public.rs` (`ScanWithPorts`), `src/admin/target.rs` (`load`)
- Modify: `src/store/export.rs` (`ScanOut`, `PortOut`, `export_context`), `src/export/mod.rs` (`scan_json`)
- Modify: `docs/dataset.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `FactRow`, `PortRow` fields, `serves`, `windows_names`, `host_facts_for_scan(s)` (Task 4).
- Produces: `ScanPage.host_facts: Vec<FactRow>`; `ScanWithPorts { s, ports, serves: String, host: String }`; export `ports[].extrainfo|ostype|devicetype|hostname|cpe` and `scans[].facts[] { port, proto, kind, value }`.

- [ ] **Step 1: Write the failing render test**

In `src/admin/scans.rs` `mod tests`, next to `the_scan_page_shows_the_hand_out_line`:

```rust
    #[test]
    fn the_scan_page_shows_details_facts_and_the_host_card() {
        let fact = |port: Option<i64>, kind: &str, value: &str| crate::store::facts::FactRow {
            port,
            kind: kind.into(),
            value: value.into(),
        };
        let page = ScanPage {
            chrome: chrome(),
            s: ScanSummary {
                id: 1,
                ip_id: 1,
                ip: "203.0.113.7".into(),
                level: 3,
                started_at: String::new(),
                finished_at: None,
                os_guess: None,
                open_ports: 1,
                node: None,
                audit_of: None,
                audit_result: None,
            },
            ports: vec![PortRow {
                port: 80,
                proto: "tcp".into(),
                state: "open".into(),
                service: Some("http".into()),
                product: Some("nginx".into()),
                version: Some("1.18.0".into()),
                extrainfo: Some("Ubuntu".into()),
                ostype: Some("Linux".into()),
                devicetype: None,
                hostname: Some("host-7.example.net".into()),
                cpe: Some(r#"["cpe:/a:nginx:nginx:1.18.0"]"#.into()),
                facts: vec![
                    fact(Some(80), "http.title", "PentAGI <b>&</b> friends"),
                    fact(Some(80), "http.redirect", "http://203.0.113.7/login"),
                ],
            }],
            keys: vec![],
            host_facts: vec![fact(None, "smb.server", "WIN-1"), fact(None, "smb.domain", "CORP")],
            can_delete: false,
            audit_of: None,
            audits: vec![],
            handed_out: None,
        };
        let html = page.render().unwrap();
        for s in [
            "nginx 1.18.0 Ubuntu",
            "Linux · host-7.example.net",
            "cpe:/a:nginx:nginx:1.18.0",
            "Title</strong> PentAGI &#60;b&#62;&#38;&#60;/b&#62; friends",
            "Redirects to</strong> http://203.0.113.7/login",
            "<h2>Host</h2>",
            "Computer</strong> WIN-1",
            "Domain</strong> CORP",
        ] {
            assert!(html.contains(s), "missing {s:?} in\n{html}");
        }
        assert!(!html.contains("href=\"http://203.0.113.7/login\""), "a redirect is text, not a link");
    }
```

Askama escapes `<` as `&#60;` and `&` as `&#38;` (check against an existing render test if the first run disagrees, and adjust the expected entities, not the escaping).

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test --lib admin::scans::tests::the_scan_page_shows_details`
Expected: compile error (`host_facts` unknown).

- [ ] **Step 3: The ports table and the scan page**

Replace `templates/_ports.html` (used by the scan page and the IP page with a `ports` variable):

```html
{# The ports of one scan (store::inspect::PortRow), with what -sV and the scripts said about each. #}
<div class="table-wrap wide"><table>
  <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Details</th></tr></thead>
  <tbody>
  {% for p in ports %}
    <tr><td class="mono">{{ p.port }}/{{ p.proto }}</td>
        <td><span class="badge badge-status" data-status="{% if p.state == "open" %}done{% else %}queued{% endif %}">{{ p.state }}</span></td>
        <td>{{ p.service.as_deref().unwrap_or("") }}</td>
        <td>{{ p.described() }}
          {% let system = p.system() %}{% if !system.is_empty() %}<div class="muted">{{ system }}</div>{% endif %}
          {% let cpes = p.cpes() %}{% if !cpes.is_empty() %}<div class="muted mono small">{{ cpes.join(" ") }}</div>{% endif %}
          {% for f in p.facts %}<div class="small"><strong>{{ f.label() }}</strong> {{ f.value }}</div>{% endfor %}</td></tr>
  {% endfor %}
  {% if ports.is_empty() %}<tr><td colspan="4" class="empty">No ports recorded.</td></tr>{% endif %}
  </tbody>
</table></div>
```

In `src/admin/scans.rs`, `ScanPage` gains `host_facts: Vec<crate::store::facts::FactRow>` and `scan_page` fills it with `st.store.host_facts_for_scan(id).await?`. In `templates/admin_scan.html`, before the host keys section:

```html
{% if !host_facts.is_empty() %}<section class="card"><h2>Host</h2><p>{% for f in host_facts %}{% if !loop.first %} · {% endif %}<strong>{{ f.label() }}</strong> {{ f.value }}{% endfor %}</p></section>{% endif %}
```

- [ ] **Step 4: Run the render tests**

Run: `cargo test --lib admin::scans`
Expected: pass.

- [ ] **Step 5: The IP page heading**

In `src/admin/public.rs`:

```rust
pub struct ScanWithPorts {
    pub s: ScanSummary,
    pub ports: Vec<PortRow>,
    /// What the source serves, from this scan (`store::facts::serves`).
    pub serves: String,
    /// Its Windows computer name and domain, when known.
    pub host: String,
}
```

In `src/admin/target.rs` `load`, fetch `let mut host = state.store.host_facts_for_scans(&ids).await?;` and build each entry:

```rust
            .map(|s| {
                let ports = ports.remove(&s.id).unwrap_or_default();
                let host_facts = host.remove(&s.id).unwrap_or_default();
                ScanWithPorts {
                    serves: crate::store::facts::serves(&ports),
                    host: crate::store::facts::windows_names(&host_facts, &ports),
                    ports,
                    s,
                }
            })
```

In `templates/_target.html`, in the `<h3>` of each scan, after `{{ sc.s.open_ports }} open`:

```html
{% if !sc.serves.is_empty() %} · {{ sc.serves }}{% endif %}{% if !sc.host.is_empty() %} · {{ sc.host }}{% endif %}
```

Run `cargo test --lib admin::` and fix any other `ScanWithPorts` literal (grep for `ScanWithPorts {`).

- [ ] **Step 6: Write the failing export test**

In `src/export/mod.rs` `mod tests`, after `scans_export_their_host_keys`:

```rust
    #[tokio::test]
    async fn scans_export_their_facts_and_port_details() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let row = s.upsert_ip("192.0.2.7".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: row.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        s.enqueue_scan(row.id, 3, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        let res = crate::scan::nmap_xml::parse_nmap_xml(include_bytes!("../../tests/fixtures/nmap-facts.xml")).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();

        let out = text(&collect(&s, ExportFilter::default(), Format::Jsonl).await);
        let r: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        let scan = &r["scans"][0];
        let ssh = scan["ports"].as_array().unwrap().iter().find(|p| p["port"] == 22).unwrap();
        assert_eq!(ssh["extrainfo"], "Ubuntu Linux; protocol 2.0");
        assert_eq!(ssh["ostype"], "Linux");
        assert_eq!(ssh["hostname"], "host-7.example.net");
        assert_eq!(ssh["cpe"].as_array().unwrap().len(), 2);
        let http = scan["ports"].as_array().unwrap().iter().find(|p| p["port"] == 80).unwrap();
        assert!(http["cpe"].as_array().unwrap().is_empty());
        assert!(http["extrainfo"].is_null());
        let facts = scan["facts"].as_array().unwrap();
        assert!(facts.iter().any(|f| f["kind"] == "http.title" && f["port"] == 80 && f["proto"] == "tcp" && f["value"] == "PentAGI & friends"), "{facts:?}");
        assert!(facts.iter().any(|f| f["kind"] == "smb.server" && f["port"].is_null()), "{facts:?}");
        assert!(facts.iter().all(|f| f.get("scan_id").is_none()), "internal id not exported");
    }
```

- [ ] **Step 7: Run it and see it fail**

Run: `cargo test --lib export::tests::scans_export_their_facts`
Expected: FAIL on `extrainfo` (null).

- [ ] **Step 8: The export**

In `src/store/export.rs`:

```rust
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct PortOut {
    #[serde(skip)]
    pub scan_id: i64,
    pub port: i64,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub ostype: Option<String>,
    pub devicetype: Option<String>,
    pub hostname: Option<String>,
    /// As stored: a JSON array, or NULL.
    #[serde(skip)]
    #[sqlx(rename = "cpe")]
    pub cpe_json: Option<String>,
    /// The CPEs, filled from `cpe_json` after the read.
    #[sqlx(skip)]
    pub cpe: Vec<String>,
}

/// One fact a scan found (`scan_facts`). `port` null: about the host.
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct FactOut {
    #[serde(skip)]
    pub scan_id: i64,
    pub port: Option<i64>,
    pub proto: Option<String>,
    pub kind: String,
    pub value: String,
}
```

`ScanOut` gains `#[sqlx(skip)] pub facts: Vec<FactOut>`. In `export_context`, the ports query selects `scan_id, port, proto, state, service, product, version, extrainfo, ostype, devicetype, hostname, cpe`, and after the fetch:

```rust
        for p in &mut rows {
            p.cpe = p.cpe_json.as_deref().and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default();
        }
```

Then a facts query like the keys one:

```rust
        let mut facts: HashMap<i64, Vec<FactOut>> = HashMap::new();
        let rows: Vec<FactOut> = sqlx::query_as(
            "SELECT scan_id, port, proto, kind, value FROM scan_facts
             WHERE scan_id IN (SELECT value FROM json_each(?)) ORDER BY scan_id, port IS NOT NULL, port, id",
        )
        .bind(json_list(&scan_ids))
        .fetch_all(&self.read)
        .await?;
        for f in rows {
            facts.entry(f.scan_id).or_default().push(f);
        }
```

and `s.facts = facts.remove(&s.id).unwrap_or_default();` next to `s.host_keys`. In `src/export/mod.rs` `scan_json`, add `"facts": s.facts,` after `"host_keys"`.

- [ ] **Step 9: Run the export tests**

Run: `cargo test --lib export::`
Expected: pass.

- [ ] **Step 10: Docs and changelog**

In `docs/dataset.md`, the `scans` example gains the port fields and `facts`:

```json
  "ports": [{"port": 22, "proto": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "9.6",
             "extrainfo": "Ubuntu Linux; protocol 2.0", "ostype": "Linux", "devicetype": null,
             "hostname": "host-7.example.net", "cpe": ["cpe:/a:openbsd:openssh:9.6p1"]}],
  "host_keys": [{"kind": "ssh-hostkey", "port": 22, "fingerprint": "SHA256:…", "detail": "ed25519 256"}],
  "facts": [{"port": 80, "proto": "tcp", "kind": "http.title", "value": "PentAGI"},
            {"port": null, "proto": null, "kind": "smb.server", "value": "WIN-344VU98D3RU"}],
```

and after the `host_keys` paragraph:

```markdown
`ports[].extrainfo`, `ostype`, `devicetype`, `hostname` and `cpe` are what
nmap's `-sV` wrote beyond product and version. `facts`: what the source
serves and calls itself, read from the fixed fields of a few scripts, never
from their prose: `http.title`, `http.redirect`, `http.server`, `http.auth`
(`Basic realm="…"`), `ntlm.netbios_computer`, `ntlm.netbios_domain`,
`ntlm.dns_computer`, `ntlm.dns_domain`, `ntlm.dns_tree`,
`ntlm.product_version` (RDP), `socks.method`, `dns.nsid`, and from the SMB
host script `smb.server`, `smb.domain`, `smb.fqdn`, `smb.domain_dns`,
`smb.forest_dns`, `smb.workgroup`, `smb.os`, `smb.lanmanager` (`port`
null). Values are cut at 512 bytes; at most 64 per scan.
```

In `CHANGELOG.md` under `### Added`:

```markdown
- What a scanned source serves and calls itself. Each port of a scan
  shows what `-sV` added (extra info, OS and device type, the announced
  host name, CPEs) and the fixed fields of a few scripts: page title and
  redirect, `Server` header, login realm, Windows computer and domain
  names from RDP and SMB, SOCKS methods, DNS server id. The scan page has
  a Host card, each scan's heading on the IP page a one-line summary, and
  the export carries the port fields and a `facts` list per scan. Nothing
  is parsed from prose. Stored scans are read once at startup.
```

- [ ] **Step 11: Commit**

```bash
git add templates/_ports.html templates/admin_scan.html templates/_target.html src/admin/scans.rs src/admin/public.rs src/admin/target.rs src/store/export.rs src/export/mod.rs docs/dataset.md CHANGELOG.md
git commit -m "Scan facts: on the scan and IP pages and in the export"
```

---

### Task 6: The scrubber (`scan::scrub`)

**Files:**
- Create: `src/scan/scrub.rs`
- Modify: `src/scan/mod.rs` (add `pub mod scrub;`)

**Interfaces:**
- Produces:
  - `pub const MARK: &str = "[scanner]";`
  - `pub fn scrub(xml: &[u8], addrs: &[IpAddr], names: &[String]) -> (Vec<u8>, u16)`
  - `#[derive(Debug, Clone, Default, PartialEq)] pub struct Own { pub addrs: Vec<IpAddr>, pub names: Vec<String> }` with `pub fn apply(&self, xml: &[u8]) -> Vec<u8>` and `pub fn is_empty(&self) -> bool`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn run(xml: &str, addrs: &[&str], names: &[&str]) -> (String, u16) {
        let addrs: Vec<IpAddr> = addrs.iter().map(|a| ip(a)).collect();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let (out, n) = scrub(xml.as_bytes(), &addrs, &names);
        (String::from_utf8(out).unwrap(), n)
    }

    #[test]
    fn own_addresses_and_names_become_the_mark_and_are_counted() {
        let xml = r#"<script id="smtp-commands" output="mail.example.org Hello i577b2938.versanet.de [87.123.41.56], pleased"/>"#;
        let (out, n) = run(xml, &["87.123.41.56"], &["i577b2938.versanet.de"]);
        assert_eq!(out, r#"<script id="smtp-commands" output="mail.example.org Hello [scanner] [[scanner]], pleased"/>"#);
        assert_eq!(n, 2);
    }

    #[test]
    fn an_address_inside_a_longer_one_is_left_alone() {
        let (out, n) = run("a 87.123.41.56 b 187.123.41.5 c 87.123.41.5:25 d", &["87.123.41.5"], &[]);
        assert_eq!(out, "a 87.123.41.56 b 187.123.41.5 c [scanner]:25 d");
        assert_eq!(n, 1);
    }

    #[test]
    fn ipv6_is_matched_in_its_compressed_form() {
        let (out, n) = run(
            "from 2001:db8::1 and 2001:db8::10 and 2001:db8:0:0:0:0:0:1",
            &["2001:0db8:0000:0000:0000:0000:0000:0001"],
            &[],
        );
        assert_eq!(out, "from [scanner] and 2001:db8::10 and 2001:db8:0:0:0:0:0:1");
        assert_eq!(n, 1);
    }

    #[test]
    fn a_name_is_matched_in_any_case_and_not_inside_a_longer_one() {
        let (out, n) = run(
            "Host.Example.NET, mail.host.example.net, host.example.net-1, (host.example.net)",
            &[],
            &["host.example.net"],
        );
        assert_eq!(out, "[scanner], mail.host.example.net, host.example.net-1, ([scanner])");
        assert_eq!(n, 2);
    }

    #[test]
    fn nothing_to_scrub_leaves_the_bytes_untouched() {
        let xml = "<nmaprun args=\"nmap -oX - 203.0.113.7\"/>";
        assert_eq!(run(xml, &[], &[]), (xml.to_string(), 0));
        assert_eq!(run(xml, &["198.51.100.5"], &["", "x.example"]), (xml.to_string(), 0));
    }

    #[test]
    fn the_count_saturates() {
        let xml = "1.2.3.4 ".repeat(70_000);
        let (_, n) = run(&xml, &["1.2.3.4"], &[]);
        assert_eq!(n, u16::MAX);
    }

    #[test]
    fn own_applies_without_a_count() {
        let own = Own {
            addrs: vec![ip("198.51.100.5")],
            names: vec!["scanner-5.example.net".into()],
        };
        assert_eq!(own.apply(b"x 198.51.100.5 SCANNER-5.example.net"), b"x [scanner] [scanner]");
        assert!(Own::default().is_empty() && !own.is_empty());
    }
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `cargo test --lib scan::scrub`
Expected: compile errors.

- [ ] **Step 3: Write the module**

```rust
//! The scanning node's own address and name kept out of its scans. A
//! scanned mail server greets the client by address and name, and nmap
//! keeps the greeting in `smtp-commands` and `banner`; the scan is
//! signed, replicated to every member and exported. Before a scanner
//! signs a result it replaces, in the raw XML, each of its own global
//! addresses and forward-confirmed names with [`MARK`]: exact values this
//! node knows about itself, never patterns. The command line in the XML
//! names the target, not the scanner, so `profiles::args_ok` is
//! unaffected; ports, identity keys and ETags are unchanged, so audits
//! agree as before.
use std::net::IpAddr;

/// What replaces an own address or name.
pub const MARK: &str = "[scanner]";

/// A byte that can be part of an address as nmap prints one.
fn addr_byte(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b'.' || b == b':'
}

/// A byte that can be part of a host name.
fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-'
}

/// `xml` with every own address (as nmap prints it: IPv4 dotted, IPv6
/// compressed) and every own name (case-insensitively) replaced by
/// [`MARK`] where the bytes before and after are not part of an address
/// or a name, and how many replacements were made (saturating).
pub fn scrub(xml: &[u8], addrs: &[IpAddr], names: &[String]) -> (Vec<u8>, u16) {
    let mut out = xml.to_vec();
    let mut n: u32 = 0;
    for a in addrs {
        n = n.saturating_add(replace(&mut out, a.to_string().as_bytes(), false, addr_byte));
    }
    for name in names {
        n = n.saturating_add(replace(&mut out, name.as_bytes(), true, name_byte));
    }
    (out, n.min(u16::MAX as u32) as u16)
}

/// Replace each occurrence of `pat` in `buf` that is not surrounded by
/// bytes `part` accepts; case-insensitively when `ci`. An empty pattern
/// matches nothing.
fn replace(buf: &mut Vec<u8>, pat: &[u8], ci: bool, part: fn(u8) -> bool) -> u32 {
    if pat.is_empty() {
        return 0;
    }
    let mut out = Vec::with_capacity(buf.len());
    let mut n = 0;
    let mut i = 0;
    while i < buf.len() {
        let end = i + pat.len();
        let hit = end <= buf.len()
            && {
                let w = &buf[i..end];
                if ci { w.eq_ignore_ascii_case(pat) } else { w == pat }
            }
            && !(i > 0 && part(buf[i - 1]))
            && !(end < buf.len() && part(buf[end]));
        if hit {
            out.extend_from_slice(MARK.as_bytes());
            n += 1;
            i = end;
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    *buf = out;
    n
}

/// This node's own global addresses and names, as the pages and the
/// export scrub them from scans stored before scrubbing existed (and
/// from other nodes' scans that mention this node).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Own {
    pub addrs: Vec<IpAddr>,
    pub names: Vec<String>,
}

impl Own {
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty() && self.names.is_empty()
    }

    /// `xml` scrubbed of this node's addresses and names.
    pub fn apply(&self, xml: &[u8]) -> Vec<u8> {
        if self.is_empty() {
            return xml.to_vec();
        }
        scrub(xml, &self.addrs, &self.names).0
    }
}
```

Add `pub mod scrub;` to `src/scan/mod.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib scan::scrub`
Expected: all seven pass.

- [ ] **Step 5: Commit**

```bash
git add src/scan/scrub.rs src/scan/mod.rs
git commit -m "Scrub: replace the scanner's own address and name in nmap XML"
```

---

### Task 7: Own names in the safety list, scrubbing before signing, the count on the page

**Files:**
- Modify: `src/scan/safety.rs`
- Modify: `src/scan/nmap_xml.rs` (`ScanResult.scrubbed`)
- Modify: `src/cluster/record.rs` (`ScanResultRec.scrubbed`)
- Modify: `src/store/recorder.rs` (three `ScanResultRec` literals: lines 741, 861, 901), `src/store/data.rs` (`scan_result` insert; the test literals at 1524, 2145, 2201, 2298, 2433)
- Modify: `src/scan/mod.rs` (`run_scan`)
- Modify: `src/store/inspect.rs` (`ScanSummary.scrubbed`, `SCAN_SELECT`), `src/admin/scans.rs` (test literal), `templates/admin_scan.html`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `scan::scrub::{scrub, Own}` (Task 6); `scans.scrubbed` (Task 2); `scan::crawler::{confirmed_names, system_forward, system_resolver, Forward}` (existing).
- Produces on `Safety`: `pub fn own_global(&self) -> Vec<IpAddr>`, `pub fn own_names(&self) -> Vec<String>`, `pub fn is_own(&self, ip: &IpAddr) -> bool`, `pub fn own_identity(&self) -> scan::scrub::Own`, `pub(crate) fn set_dns(&mut self, resolver: SocketAddr, forward: Forward)`.
- Produces: `ScanResult.scrubbed: u16`, `ScanResultRec.scrubbed: u16` (serde default, skipped when 0), `ScanSummary.scrubbed: i64`.

- [ ] **Step 1: Write the failing safety test**

In `src/scan/safety.rs` `mod tests` (look at `own_addresses_are_refused_even_standalone` for the config helper it uses and reuse it):

```rust
    #[tokio::test]
    async fn own_names_are_the_forward_confirmed_ptr_of_own_global_addresses() {
        use crate::scan::crawler::testing::fake_resolver;
        use std::sync::{Arc, Mutex};
        let cfg = cfg_with("[scan]\nown_addresses = [\"198.51.100.5\", \"10.0.0.5\"]\n");
        let mut s = Safety::new(&cfg);
        assert!(s.own_names().is_empty());
        let answer = Arc::new(Mutex::new(Some("scanner-5.example.net".to_string())));
        let resolver = fake_resolver(answer.clone()).await;
        let forward: crate::scan::crawler::Forward = Arc::new(|name: String| {
            Box::pin(async move {
                if name.trim_end_matches('.') == "scanner-5.example.net" {
                    Ok(vec!["198.51.100.5".parse().unwrap()])
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        });
        s.set_dns(resolver, forward);
        s.refresh(&cfg, None).await;
        assert!(s.own_global().contains(&"198.51.100.5".parse().unwrap()));
        assert!(!s.own_global().contains(&"10.0.0.5".parse().unwrap()), "private: not global");
        assert_eq!(s.own_names(), vec!["scanner-5.example.net".to_string()]);
        assert!(s.is_own(&"198.51.100.5".parse().unwrap()));
        assert!(!s.is_own(&"198.51.100.6".parse().unwrap()));
        let own = s.own_identity();
        assert_eq!(own.names, s.own_names());
        assert!(own.addrs.contains(&"198.51.100.5".parse().unwrap()));
        // Looked up once a day: a changed answer is not seen yet.
        *answer.lock().unwrap() = Some("other.example.net".into());
        s.refresh(&cfg, None).await;
        assert_eq!(s.own_names(), vec!["scanner-5.example.net".to_string()]);
    }
```

If the existing tests build their `Config` differently (a helper with another name), use that helper. The `own_addresses` key lives under `[scan]`.

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test --lib scan::safety::tests::own_names`
Expected: compile error.

- [ ] **Step 3: Own names in `Safety`**

In `src/scan/safety.rs`:

```rust
use crate::scan::crawler::{Forward, confirmed_names, system_forward, system_resolver};

/// Own names are looked up again this long after the last successful
/// lookup ...
const NAMES_REFRESH: Duration = Duration::from_secs(24 * 3600);
/// ... for at most this many own global addresses.
const NAMES_MAX_ADDRS: usize = 8;

pub struct Safety {
    // … existing fields …
    /// Where own names are looked up: the system resolver and a forward
    /// lookup; None when reverse DNS is off (`enrichment.reverse_dns`),
    /// no nameserver is configured, or in tests (set with `set_dns`).
    dns: Option<(SocketAddr, Forward)>,
    /// The forward-confirmed PTR names of this node's global addresses.
    own_names: Vec<String>,
    names_at: Option<Instant>,
}
```

In `new`:

```rust
            dns: (!cfg!(test) && cfg.enrichment.reverse_dns)
                .then(system_resolver)
                .flatten()
                .map(|r| (r, system_forward())),
            own_names: vec![],
            names_at: None,
```

`cfg!(test)` keeps every existing test (they call `refresh` with real interface addresses) off the network; a test that wants names injects a fake with `set_dns`.

At the end of `refresh` (after `self.published = published;`):

```rust
        self.refresh_names().await;
```

and the methods:

```rust
    /// This node's global addresses: the ones a scanned host can see.
    pub fn own_global(&self) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self
            .own
            .iter()
            .copied()
            .filter(|ip| crate::net::is_scannable_target(*ip))
            .collect();
        v.sort();
        v
    }

    /// Whether `ip` is one of this node's own addresses.
    pub fn is_own(&self, ip: &IpAddr) -> bool {
        self.own.contains(&crate::net::canonical(*ip))
    }

    pub fn own_names(&self) -> Vec<String> {
        self.own_names.clone()
    }

    /// Addresses and names to scrub from served scans.
    pub fn own_identity(&self) -> crate::scan::scrub::Own {
        crate::scan::scrub::Own {
            addrs: self.own_global(),
            names: self.own_names(),
        }
    }

    /// Look own names up with `resolver` and `forward` instead of the
    /// system's, at the next refresh.
    pub(crate) fn set_dns(&mut self, resolver: SocketAddr, forward: Forward) {
        self.dns = Some((resolver, forward));
        self.names_at = None;
    }

    /// The forward-confirmed PTR names of the own global addresses, once a
    /// day. A failed lookup keeps the previous names and is tried again at
    /// the next refresh.
    async fn refresh_names(&mut self) {
        let Some((resolver, forward)) = self.dns.clone() else {
            return;
        };
        if self.names_at.is_some_and(|t| t.elapsed() < NAMES_REFRESH) {
            return;
        }
        let mut names: Vec<String> = vec![];
        let mut failed = false;
        for ip in self.own_global().into_iter().take(NAMES_MAX_ADDRS) {
            match confirmed_names(resolver, &forward, ip).await {
                Ok(found) => {
                    for n in found {
                        if !names.contains(&n) {
                            names.push(n);
                        }
                    }
                }
                Err(e) => {
                    failed = true;
                    // `tracing::debug`: add it to the module's `use` line.
                    debug!(%ip, error = %e, "own reverse DNS failed; keeping the previous names");
                }
            }
        }
        if failed && names.is_empty() {
            return;
        }
        self.own_names = names;
        self.names_at = Some(Instant::now());
    }
```

`refresh` returns early when the sets are not due; `refresh_names` sits after the full rebuild, which runs every 5 minutes, so the daily check costs nothing in between. In the test, the second `refresh` is not due either way: to make the "once a day" assertion meaningful, call `s.refresh_names().await` directly in the test's last step instead of `refresh` (it is a private method in the same module, reachable from `mod tests`).

- [ ] **Step 4: Run the safety tests**

Run: `cargo test --lib scan::safety`
Expected: pass (new and existing).

- [ ] **Step 5: `scrubbed` through the result and the record**

`src/scan/nmap_xml.rs`: `ScanResult` gains `pub scrubbed: u16` (doc: "How many times the scanner replaced its own address or name in `raw_xml` (`scan::scrub`); 0 until it has"), set to 0 in `parse_nmap_xml`.

`src/cluster/record.rs`, `ScanResultRec`, after `build`:

```rust
    /// How many times the scanner replaced its own address or name in
    /// `raw_xml` before signing (`scan::scrub`); left out when 0, so older
    /// peers see nothing new.
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub scrubbed: u16,
```

with `fn is_zero_u16(n: &u16) -> bool { *n == 0 }` next to `is_zero`.

`src/store/recorder.rs`: the three literals get `scrubbed: res.scrubbed,`. `src/store/data.rs` `scan_result`: add `scrubbed` to the `INSERT INTO scans` column list and `.bind(r.scrubbed as i64)`; the five test literals get `scrubbed: 0,`. Run `cargo build --tests` and fix every other `ScanResultRec {` or `ScanResult {` literal the compiler names.

- [ ] **Step 6: Scrub in `run_scan`**

In `src/scan/mod.rs`, rename the current `run_scan` to `run_leased` (same body) and add:

```rust
/// Run nmap for `job` (`run_leased`), then keep this node's own addresses
/// and names out of the result's XML before it is signed.
async fn run_scan(
    source: &Source,
    job: &Job,
    argv: Vec<String>,
    nmap: PathBuf,
    timeout: Duration,
) -> Outcome {
    let mut outcome = run_leased(source, job, argv, nmap, timeout).await;
    if let Outcome::Done(res) = &mut outcome {
        source.scrub(&job.ip(), res).await;
    }
    outcome
}

impl Source {
    /// Replace this node's own global addresses and names in the scan's
    /// XML (`scan::scrub`), unless the target is one of them: that scan is
    /// about this node.
    async fn scrub(&self, target: &IpAddr, res: &mut nmap_xml::ScanResult) {
        let s = self.safety.lock().await;
        if s.is_own(target) {
            return;
        }
        let (xml, n) = scrub::scrub(&res.raw_xml, &s.own_global(), &s.own_names());
        res.raw_xml = xml;
        res.scrubbed = n;
    }
}
```

- [ ] **Step 7: Write the failing worker test**

In `src/scan/mod.rs` `mod tests`, after `worker_runs_fake_nmap_and_stores_ports`:

```rust
    #[tokio::test]
    async fn worker_scrubs_its_own_address_from_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_nmap(dir.path());
        // The fixture, with a greeting that names the scanner.
        let xml = std::fs::read_to_string("tests/fixtures/nmap-basic.xml").unwrap().replacen(
            "</port>",
            r#"<script id="smtp-commands" output="mail Hello scanner-5.example.net [198.51.100.5], 198.51.100.50 pleased"/></port>"#,
            1,
        );
        std::fs::write(dir.path().join("nmap.xml"), xml).unwrap();
        let cfg = config_with(
            dir.path(),
            "tor_unknown = \"scan\"\nverify_crawlers = false\nown_addresses = [\"198.51.100.5\"]\n",
        );
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store.upsert_ip("198.51.100.23".parse().unwrap()).await.unwrap();
        store.enqueue_scan(ip.id, 2, 24).await.unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
            Classifier::builtin(),
        ));
        wait_for_scans(&store, 1).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
        let (scrubbed, raw): (i64, Vec<u8>) = sqlx::query_as("SELECT scrubbed, raw_xml FROM scans")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(scrubbed, 1);
        let xml = String::from_utf8(zstd::decode_all(raw.as_slice()).unwrap()).unwrap();
        assert!(xml.contains("Hello scanner-5.example.net [[scanner]], 198.51.100.50"), "{xml}");
        assert!(!xml.contains("[198.51.100.5]"));
        assert!(xml.contains("198.51.100.23"), "the target stays");
        assert!(xml.contains("args=\"nmap -sS -sV -oX - 198.51.100.23\""), "the args line stays");
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports").fetch_one(&store.pool).await.unwrap();
        assert_eq!(ports, 3, "ports as before");
        let s = store.scan_by_id(1).await.unwrap().unwrap();
        assert_eq!(s.scrubbed, 1);
    }
```

The name is not scrubbed here (no DNS in tests); the address is. `zstd::decode_all` is available through the `zstd` crate already in use.

And the case the worker cannot reach (the safety list refuses a scan of an own address before nmap runs): `Source::scrub` is private to the module, so test it directly.

```rust
    #[tokio::test]
    async fn a_scan_of_an_own_address_is_not_scrubbed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_with(
            dir.path(),
            "tor_unknown = \"scan\"\nverify_crawlers = false\nown_addresses = [\"198.51.100.5\"]\n",
        );
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(store.local(), cfg.clone(), p, Classifier::builtin());
        source.safety.lock().await.refresh(&cfg, None).await;
        let xml = b"<nmaprun><host><ports><port protocol=\"tcp\" portid=\"25\"><state state=\"open\"/><script id=\"banner\" output=\"hi 198.51.100.5\"/></port></ports></host></nmaprun>";
        let mut res = nmap_xml::parse_nmap_xml(xml).unwrap();
        source.scrub(&"198.51.100.5".parse().unwrap(), &mut res).await;
        assert_eq!((res.scrubbed, res.raw_xml.as_slice()), (0, &xml[..]), "about this node");
        source.scrub(&"198.51.100.23".parse().unwrap(), &mut res).await;
        assert_eq!(res.scrubbed, 1);
        assert!(String::from_utf8_lossy(&res.raw_xml).contains("hi [scanner]"));
    }
```

- [ ] **Step 8: `ScanSummary.scrubbed` and the page**

`src/store/inspect.rs`: `ScanSummary` gains `pub scrubbed: i64` (doc: "How many times the scanner removed its own address or name from the XML"); `SCAN_SELECT` selects `s.scrubbed`. The `ScanSummary` literals in `src/admin/scans.rs` tests get `scrubbed: 0`.

`templates/admin_scan.html`, in the `<div class="meta">`, after the `OS:` span:

```html
{% if s.scrubbed > 0 %}<span>the scanner's address was removed from this scan's output ({{ s.scrubbed }} time{% if s.scrubbed != 1 %}s{% endif %})</span>{% endif %}
```

- [ ] **Step 9: Run the tests**

Run: `cargo test --lib scan:: store:: admin::scans cluster::record`
Expected: pass, including `worker_scrubs_its_own_address_from_the_scan` and `worker_runs_fake_nmap_and_stores_ports`.

- [ ] **Step 10: Changelog**

In `CHANGELOG.md` under `### Added`:

```markdown
- The scanner's own address stays out of its scans. A scanned mail server
  greets the client by address and name, and nmap kept that in the XML
  that is signed, replicated and exported. Before signing, a scanner now
  replaces its own global addresses (interfaces, listeners, `advertise`,
  `scan.own_addresses`, the addresses peers saw it from) and their
  forward-confirmed names with `[scanner]`; the scan page says how often.
  Scans signed before this release cannot be changed; each node removes
  its own addresses and names from them when it serves the XML or the
  export, so a node's own old scans leave it clean. Other members'
  addresses in old scans stay (a purge removes a record everywhere).
```

- [ ] **Step 11: Commit**

```bash
git add src/scan/safety.rs src/scan/nmap_xml.rs src/cluster/record.rs src/store/recorder.rs src/store/data.rs src/scan/mod.rs src/store/inspect.rs src/admin/scans.rs templates/admin_scan.html CHANGELOG.md
git commit -m "Scrub: the scanner's own address and name leave the XML before signing"
```

---

### Task 8: Old scans scrubbed when served

**Files:**
- Modify: `src/admin/mod.rs` (`AdminState::own_identity`), `src/admin/scans.rs` (`scan_xml`), `src/admin/system.rs` (`export_download`)
- Modify: `src/export/mod.rs` (`ExportOptions.own`, `scan_json`), `src/export/cli.rs` (`run`, `write`)
- Modify: `src/store/export.rs` (`ScanOut.scrubbed`) and `src/export/mod.rs` (`"scrubbed"` in `scan_json`)
- Modify: `docs/dataset.md`

**Interfaces:**
- Consumes: `Safety::own_identity` (Task 7), `scan::scrub::Own` (Task 6), `scans.scrubbed` (Task 2).
- Produces: `ExportOptions { mode, names, own: Own }`; `AdminState::own_identity(&self) -> Own`; export `scans[].scrubbed`.

- [ ] **Step 1: Write the failing export test**

In `src/export/mod.rs` `mod tests`:

```rust
    #[tokio::test]
    async fn served_xml_scrubs_this_nodes_own_address() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let row = s.upsert_ip("192.0.2.7".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: row.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        s.enqueue_scan(row.id, 2, 0).await.unwrap();
        let job = s.next_queued_job().await.unwrap().unwrap();
        // A scan stored by a build before scrubbing: the greeting is in it.
        let xml = String::from_utf8(include_bytes!("../../tests/fixtures/nmap-basic.xml").to_vec())
            .unwrap()
            .replacen(
                "</port>",
                r#"<script id="smtp-commands" output="Hello scanner-5.example.net [198.51.100.5]"/></port>"#,
                1,
            );
        let res = crate::scan::nmap_xml::parse_nmap_xml(xml.as_bytes()).unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();

        let own = crate::scan::scrub::Own {
            addrs: vec!["198.51.100.5".parse().unwrap()],
            names: vec!["scanner-5.example.net".into()],
        };
        let opts = ExportOptions {
            mode: Mode::Full,
            names: HashMap::new(),
            own,
        };
        let parts: Vec<axum::body::Bytes> = stream_requests(s.clone(), ExportFilter::default(), Format::Jsonl, opts)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        let out = text(&parts);
        let r: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        let served = r["scans"][0]["xml"].as_str().unwrap();
        assert!(served.contains("Hello [scanner] [[scanner]]"), "{served}");
        assert!(!served.contains("198.51.100.5"));
        assert_eq!(r["scans"][0]["scrubbed"], 0, "as the scanner signed it");
        // The stored XML is untouched: only what is served changes.
        let stored = s.scan_raw_xml(1).await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&stored).contains("198.51.100.5"));
    }
```

Check how the existing `collect` helper builds its stream (around line 995) and mirror it rather than the inline version above if it differs.

- [ ] **Step 2: Run it and see it fail**

Run: `cargo test --lib export::tests::served_xml`
Expected: compile error (`own` unknown).

- [ ] **Step 3: `ExportOptions.own` and `scrubbed` in the export**

`src/export/mod.rs`:

```rust
pub struct ExportOptions {
    pub mode: Mode,
    /// Node names by node id, for the `node` columns.
    pub names: HashMap<Vec<u8>, String>,
    /// This node's own addresses and names, removed from every scan's XML
    /// as it is served (`scan::scrub`): scans signed before scrubbing
    /// existed still carry them.
    pub own: crate::scan::scrub::Own,
}
```

In `scan_json`, scrub before the lossy conversion and add the count:

```rust
    let xml = s.raw_xml.as_ref().and_then(|b| {
        crate::store::inspect::zstd_decode_capped(b, crate::store::inspect::MAX_RAW_XML)
            .ok()
            .map(|x| String::from_utf8_lossy(&opts.own.apply(&x)).into_owned())
    });
    // … in the json!: after "os_guess":
        "scrubbed": s.scrubbed,
```

`src/store/export.rs`: `ScanOut` gains `pub scrubbed: i64` and the `export_context` scan query selects `s.scrubbed`.

Fix the other `ExportOptions` literals: `src/export/mod.rs` tests (two: `own: Default::default()`), `src/admin/system.rs:287` and `src/export/cli.rs` (next steps).

- [ ] **Step 4: The admin: XML download and export**

`src/admin/mod.rs`, in an `impl AdminState`:

```rust
    /// This node's own addresses and names, to scrub from served scans
    /// (`scan::scrub`); the safety list is refreshed first, as the
    /// blocklist feed does.
    pub async fn own_identity(&self) -> crate::scan::scrub::Own {
        let mut s = self.safety.lock().await;
        s.refresh(&self.cfg, self.recorder.node().map(|n| &**n)).await;
        s.own_identity()
    }
```

`src/admin/scans.rs` `scan_xml`:

```rust
    let Some(xml) = st.store.scan_raw_xml(id).await? else {
        return Err(AppError::NotFound);
    };
    let xml = st.own_identity().await.apply(&xml);
```

`src/admin/system.rs` `export_download`: `crate::export::ExportOptions { mode, names, own: state.own_identity().await }`.

- [ ] **Step 5: The CLI export**

`src/export/cli.rs`: `write` gains an `own: crate::scan::scrub::Own` parameter after `names` and passes it in `ExportOptions`. In `run`, after `let store = …`:

```rust
    // This node's own addresses and names, kept out of the served XML.
    let mut safety = crate::scan::safety::Safety::new(&cfg);
    safety.refresh(&cfg, None).await;
    let own = safety.own_identity();
```

and `write(store, &a, names, own, &mut out)`. The test caller at `src/export/cli.rs:273` passes `Default::default()`.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib export:: admin::`
Expected: pass.

- [ ] **Step 7: Docs**

`docs/dataset.md`, in the `scans` paragraph after the `audit_of` sentences:

```markdown
`scrubbed`: how many times the scanner replaced its own address or name
with `[scanner]` in `xml` before signing the scan (0 for scans from before
0.10.0). The exporting node also removes its own addresses and names from
every scan's `xml` as it writes the file.
```

- [ ] **Step 8: Commit**

```bash
git add src/admin/mod.rs src/admin/scans.rs src/admin/system.rs src/export/mod.rs src/export/cli.rs src/store/export.rs docs/dataset.md
git commit -m "Scrub: served XML and the export leave out this node's own address"
```

---

## Final checks (after every task)

- [ ] `cargo fmt --all && cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test` (the whole suite; prune `target/` first if the disk is tight, see memory `disk-target-bloat`)
- [ ] `git diff master --stat` names only the files in this plan's file structure.
