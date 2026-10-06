# Rules Evaluation Adjustments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the decided rule/scan-policy adjustments from the dataset evaluation: webshell rule additions, a weak-label scan-level cap, verified research-scanner exclusion with admin transparency, and documentation.

**Architecture:** Small, independent changes to the ruleset (`rules/webshells.toml`), the classifier verdict assembly (`src/classify/mod.rs`), the FCrDNS crawler check (`src/scan/crawler.rs`), and the admin scans page (`src/scan/pace.rs`, `src/store/scans.rs`, `templates/admin_scans.html`), plus docs. Rules are embedded into the binary by `build.rs`, so editing `rules/*.toml` and running `cargo test` recompiles and re-validates them (meta-tests in `src/classify/rules.rs` enforce validity and that builtin == disk).

**Tech Stack:** Rust (axum, sqlx/SQLite, askama templates), TOML rules, Markdown docs.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-10-06-rules-dataset-evaluation-design.md`.
- Severity semantics are unchanged; only `scan_level` computation and scan refusal change.
- Rule weights stay within 1..=4; every shipped rule keeps an `owasp` tag (meta-test enforced).
- UA alone never exempts anyone from scans; only forward-confirmed reverse DNS (FCrDNS).
- `form-interaction` keeps weight 3 (decided; do not change).
- TDD: failing test first, minimal change, green, commit. Commit messages match repo style (see `git log --oneline`, e.g. "Rules: LLM gateway paths and llm-key-use").
- Full `cargo test` must pass at the end of every task.

---

### Task 1: webshell-probe shell-name additions

**Files:**
- Modify: `rules/webshells.toml` (both `target_regex` alternations, lines 12 and 21)
- Test: `src/classify/mod.rs` (test `webshell_probes_are_level_3_and_interaction_is_level_4`, lines 1570-1621)

**Interfaces:**
- Consumes: existing `check`/`classify` test helpers in `src/classify/mod.rs` tests.
- Produces: labels `webshell-probe` (weight 3) and `webshell` (weight 4) now also fire for the shell names `adminfuns`, `ccc`, `chosen`, `dex`, `ebkid`, `go`, `simple`, `sm`, `this_is_a_new_hello_world`.

- [ ] **Step 1: Write the failing test**

In `src/classify/mod.rs`, extend the probe list in
`webshell_probes_are_level_3_and_interaction_is_level_4` (line 1572) from:

```rust
        for p in [
            "/shell.php",
            "/alfa.php",
            "/wso.php",
            "/c99.php",
            "/x.php",
            "/1.php",
            "/wp-content/uploads/evil.php",
            "/.well-known/shell.phtml",
            "/images/cmd.php",
        ] {
```

to:

```rust
        // The second block: shell names the spray waves actually ask for
        // (dataset 2026-10, 24-42 distinct IPs each).
        for p in [
            "/shell.php",
            "/alfa.php",
            "/wso.php",
            "/c99.php",
            "/x.php",
            "/1.php",
            "/wp-content/uploads/evil.php",
            "/.well-known/shell.phtml",
            "/images/cmd.php",
            "/chosen.php",
            "/simple.php",
            "/adminfuns.php",
            "/dex.php",
            "/go.php",
            "/ccc.php",
            "/sm.php",
            "/ebkid.php",
            "/this_is_a_new_hello_world.php",
        ] {
```

And extend the interaction list (line 1595) from:

```rust
        for (p, q) in [("/shell.php", "cmd=id"), ("/index.php", "z0=aWQ9")] {
```

to:

```rust
        for (p, q) in [
            ("/shell.php", "cmd=id"),
            ("/index.php", "z0=aWQ9"),
            ("/chosen.php", "cmd=id"),
        ] {
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test webshell_probes_are_level_3`
Expected: FAIL — `/chosen.php: ["probe"] should be webshell-probe` (and the other new names).

- [ ] **Step 3: Extend the two alternations in `rules/webshells.toml`**

In the `webshell-probe` rule (line 12), replace the name alternation:

```toml
target_regex = '''/(x|1|2|3|aa|aaa|abc|alfa|b374k|backdoor|bash|bd|c99|cmd|cong|death|exec|hack|hacker|leaf|mini|r57|root|sh3ll|shell|shellz|small|up|upload|uploader|wso|wsoshell|xxx)\.(php[3457]?|phtml|phar|asp|aspx|ashx|jsp|jspx|cgi|pl|py)(/|\?|$)|...
```

with (adds `adminfuns|ccc|chosen|dex|ebkid|go|simple|sm|this_is_a_new_hello_world`, rest unchanged):

```toml
target_regex = '''/(x|1|2|3|aa|aaa|abc|adminfuns|alfa|b374k|backdoor|bash|bd|c99|ccc|chosen|cmd|cong|death|dex|ebkid|exec|go|hack|hacker|leaf|mini|r57|root|sh3ll|shell|shellz|simple|sm|small|this_is_a_new_hello_world|up|upload|uploader|wso|wsoshell|xxx)\.(php[3457]?|phtml|phar|asp|aspx|ashx|jsp|jspx|cgi|pl|py)(/|\?|$)|...
```

(Only the first alternation changes; keep the `/wp-content/uploads/...`, `/images?/...` and `/.well-known/...` clauses exactly as they are.)

In the `webshell` rule (line 21), replace:

```toml
target_regex = '''/(x|1|2|aa|aaa|alfa|b374k|c99|cmd|cong|exec|hack|r57|sh3ll|shell|shellz|small|up|upload|wso|root|backdoor)\.(php[3457]?|phtml|asp|aspx|jsp|cgi|pl)\?[^ ]{0,500}(cmd|c|exec|command|act|do|pass|pwd)=|...
```

with (same names added, rest unchanged):

```toml
target_regex = '''/(x|1|2|aa|aaa|adminfuns|alfa|b374k|c99|ccc|chosen|cmd|cong|dex|ebkid|exec|go|hack|r57|root|sh3ll|shell|shellz|simple|sm|small|this_is_a_new_hello_world|up|upload|wso|backdoor)\.(php[3457]?|phtml|asp|aspx|jsp|cgi|pl)\?[^ ]{0,500}(cmd|c|exec|command|act|do|pass|pwd)=|...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS, including the extended webshell test and the builtin-rules meta-tests.

- [ ] **Step 5: Commit**

```bash
git add rules/webshells.toml src/classify/mod.rs
git commit -m "Rules: webshell-probe learns the names the spray waves use"
```

---

### Task 2: Weak-label scan-level cap

**Files:**
- Modify: `src/classify/mod.rs` (verdict assembly at line 352; new const near `FAMILIES` at line 368)
- Test: `src/classify/mod.rs` (update test `repeated_scanning_is_level_2` at lines 486-495; add two tests after it)
- Docs: `docs/operations.md` (taxonomy section, line 339 area), `docs/dataset.md` (line 110)

**Interfaces:**
- Consumes: `Verdict { severity, scan_level, labels, owasp }` (`src/classify/mod.rs:34-40`).
- Produces: `Classifier::classify` returns `scan_level = min(1, weight)` when every label is in `WEAK_LABELS`, else `weight.min(4)` as before. `severity` is untouched.

- [ ] **Step 1: Write the failing tests**

Replace the test at `src/classify/mod.rs:486-495`:

```rust
    #[test]
    fn repeated_scanning_is_level_2() {
        let v = classifier().classify(
            &view("GET", "/a", None, "Mozilla/5.0", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 2);
        assert!(v.labels.contains(&"path-scanner".to_string()));
    }
```

with:

```rust
    #[test]
    fn repeated_scanning_alone_caps_the_scan_at_level_1() {
        // Severity records what was seen (a scan burst); the counter-scan
        // stays light while nothing specific was touched.
        let v = classifier().classify(
            &view("GET", "/a", None, "Mozilla/5.0", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert_eq!(v.severity, 2);
        assert_eq!(v.scan_level, 1);
        assert!(v.labels.contains(&"path-scanner".to_string()));
    }

    #[test]
    fn scanning_plus_a_named_rule_keeps_level_2() {
        let v = classifier().classify(
            &view("GET", "/.env", None, "Mozilla/5.0", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert!(v.labels.contains(&"sensitive-path".to_string()));
        assert_eq!(v.scan_level, 2);
    }

    #[test]
    fn php_probes_alone_stay_at_level_1() {
        let v = classifier().classify(
            &view("GET", "/myglu.php", None, "curl/8", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert_eq!(
            v.labels,
            vec!["path-scanner".to_string(), "php-probe".to_string()]
        );
        assert_eq!(v.scan_level, 1);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test scanning`
Expected: FAIL — `repeated_scanning_alone_caps_the_scan_at_level_1` (scan_level is 2, expected 1) and `php_probes_alone_stay_at_level_1`; `scanning_plus_a_named_rule_keeps_level_2` passes already.

- [ ] **Step 3: Implement the cap in `Classifier::classify`**

Add near `FAMILIES` (`src/classify/mod.rs:368`):

```rust
/// Labels that only say someone looked, never what they were after. A
/// request with no other label earns at most a level-1 counter-scan,
/// however often it looked.
const WEAK_LABELS: [&str; 3] = ["probe", "path-scanner", "php-probe"];
```

Replace `src/classify/mod.rs:352`:

```rust
        let scan_level = weight.min(4);
```

with:

```rust
        let weak_only = labels.iter().all(|l| WEAK_LABELS.contains(&l.as_str()));
        let scan_level = if weak_only {
            weight.min(1)
        } else {
            weight.min(4)
        };
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS (all classify tests, including the previously failing two).

- [ ] **Step 5: Update the docs**

In `docs/operations.md`, after line 339 ("drives the counter-scan level:") — i.e. after the weight table, before "The `owasp` tag is…" (line 348) — insert:

```markdown
The counter-scan level is the weight, with one cap: a request whose labels
only say someone looked (`probe`, `path-scanner`, `php-probe`) earns at
most a level-1 scan, whatever its severity — a lone drive-by probe does
not warrant a top-1000-port scan. Anything more specific scans at the
weight, capped at 4. `severity` itself is not capped: it records what was
seen.
```

In `docs/dataset.md`, replace line 110:

```markdown
| `scan_level` | int? | Counter-scan level this request earned (0: none, 1 to 4) |
```

with:

```markdown
| `scan_level` | int? | Counter-scan level this request earned (0: none, 1 to 4); weak tells alone (`probe`, `path-scanner`, `php-probe`) cap it at 1 whatever the severity |
```

- [ ] **Step 6: Commit**

```bash
git add src/classify/mod.rs docs/operations.md docs/dataset.md
git commit -m "Classify: weak tells alone cap the counter-scan at level 1"
```

---

### Task 3: Verified research scanners (Censys, LeakIX, Shodan)

**Files:**
- Modify: `src/scan/crawler.rs` (module doc lines 1-21, `DOMAINS` at line 34, tests)
- Create: `docs/scanners.md`
- Docs: `docs/operations.md` (line 269 area)

**Interfaces:**
- Consumes: existing FCrDNS machinery — `Crawlers::with_resolver`, `is_crawler_domain` (`crawler.rs:162`), `confirmed` (`crawler.rs:110`); the scan preflight already refuses `verified crawler ({name})` (`src/scan/mod.rs:376-380`).
- Produces: hosts forward-confirmed under `censys-scanner.com`, `scan.leakix.org` or `shodan.io` are never counter-scanned; the refusal reason names the confirmed host.

- [ ] **Step 1: Write the failing tests**

In `src/scan/crawler.rs` tests, extend `fake_forward` (line 428) from:

```rust
    fn fake_forward() -> Forward {
        std::sync::Arc::new(|name: String| {
            Box::pin(async move {
                if name.ends_with(".real.googlebot.com") {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else if name.ends_with(".slow.googlebot.com") {
                    std::future::pending().await
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        })
    }
```

to:

```rust
    /// `*.real.censys-scanner.com` resolves to 198.51.100.9.
    fn fake_forward() -> Forward {
        std::sync::Arc::new(|name: String| {
            Box::pin(async move {
                if name.ends_with(".real.googlebot.com") {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else if name.ends_with(".real.censys-scanner.com") {
                    Ok(vec!["198.51.100.9".parse().unwrap()])
                } else if name.ends_with(".slow.googlebot.com") {
                    std::future::pending().await
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        })
    }
```

Add two tests after `only_forward_confirmed_crawlers_count` (ends line 484):

```rust
    #[tokio::test]
    async fn research_scanners_are_forward_confirmed() {
        // A Censys scanner host, confirmed: exempt like any crawler.
        assert_eq!(
            check(Some("66-132-186-177.real.censys-scanner.com"), "198.51.100.9")
                .await
                .as_deref(),
            Some("66-132-186-177.real.censys-scanner.com")
        );
        // ... claiming the name from another IP: not a scanner.
        assert_eq!(
            check(Some("66-132-186-177.real.censys-scanner.com"), "198.51.100.7")
                .await,
            None
        );
        // A lookalike zone: not a scanner domain at all.
        assert_eq!(
            check(Some("x.real.censys-scanner.com.evil.net"), "198.51.100.9").await,
            None
        );
    }

    #[test]
    fn research_scanner_domains_match_on_label_boundaries() {
        let c = Crawlers::with_resolver(&[], None);
        assert!(c.is_crawler_domain("177.186.132.66.censys-scanner.com."));
        assert!(c.is_crawler_domain("f20a02ce01.scan.leakix.org."));
        assert!(c.is_crawler_domain("census12.shodan.io."));
        assert!(!c.is_crawler_domain("censys-scanner.com."), "the apex is no host");
        assert!(!c.is_crawler_domain("evilcensys-scanner.com."));
        assert!(!c.is_crawler_domain("censys-scanner.com.attacker.net."));
        assert!(
            !c.is_crawler_domain("evil.leakix.org."),
            "only hosts under scan.leakix.org scan for LeakIX"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test crawler`
Expected: FAIL — the three `is_crawler_domain` positives fail ("only hosts under scan.leakix.org" and the googlebot-only forward confirmations), the research-scanner end-to-end assertions fail.

- [ ] **Step 3: Add the domains**

In `src/scan/crawler.rs`, replace the `DOMAINS` tail (line 46):

```rust
    "crawl.amazonbot.amazon",
];
```

with:

```rust
    "crawl.amazonbot.amazon",
    // Verified research scanners (docs/scanners.md): Censys, LeakIX, Shodan.
    // Their operators publish these reverse zones; anything merely claiming
    // the UA (zgrab and friends) stays scannable.
    "censys-scanner.com",
    "scan.leakix.org",
    "shodan.io",
];
```

And update the module doc header (lines 1-3) from:

```rust
//! Known crawlers are not counter-scanned. A search engine, link preview or
//! feed fetcher that follows a link to the trap looks like a probe, and a
//! counter-scan would hit the crawler operator, not an attacker.
```

to:

```rust
//! Known crawlers and verified research scanners are not counter-scanned. A
//! search engine, link preview or feed fetcher that follows a link to the
//! trap looks like a probe, and so does a research scanner (Censys, LeakIX,
//! Shodan) that documents its addresses; a counter-scan would hit the
//! service's operator, not an attacker. See docs/scanners.md.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test crawler`
Expected: PASS.

- [ ] **Step 5: Write `docs/scanners.md`**

Create `docs/scanners.md`:

```markdown
# Scanners we do not counter-scan

Peephole answers reconnaissance with a counter-scan of the source — except
when the source is verified to be someone who scans the open internet as a
service, not an attacker. Counter-scanning them would hit the operator of a
documented service and buy nothing.

Verification is forward-confirmed reverse DNS (FCrDNS), the same mechanism
Google recommends for Googlebot: the address's PTR record must name a host
under the operator's domain, and that host must resolve back to the
address. A user-agent header alone proves nothing — anyone can send
`CensysInspect/1.1` or `zgrab` — so it is never accepted.

## Exempt operators

| Operator | Reverse zone | Reference |
|---|---|---|
| Censys | `*.censys-scanner.com` | <https://support.censys.io> (scanner IPs and UA) |
| LeakIX | `*.scan.leakix.org` | <https://leakix.net> (l9scan/l9explore) |
| Shodan | `*.shodan.io` | <https://www.shodan.io> (census hosts) |

Search engines and link-preview fetchers (Google, Bing, Apple, Yandex,
Baidu, Petal, Amazon) are exempt through the same check; their zones are
listed next to these in `src/scan/crawler.rs` (`DOMAINS`).

An operator whose reverse zone lapses becomes scannable again automatically
— verification runs per scan job, not once.

## Are you a scanner operator?

Publish your scanner addresses under a dedicated reverse zone that
forward-confirms, send a PR adding the zone to `DOMAINS` in
`src/scan/crawler.rs` and a row here, and peephole will leave your
addresses alone. Ranges without FCrDNS (a plain IP list) are not accepted:
a list file cannot prove who holds an address tomorrow.

## Seeing who was refused

Admin → Scans lists every refused scan job with its reason
(`status=refused`), e.g. `verified crawler (177.186.132.66.censys-scanner.com)`;
the pace card links the last 24 hours' refusals.
```

In `docs/operations.md`, extend the blocklist-exclusion sentence (line 269,
"addresses a scanner refused as a verified crawler, …") to read:

```markdown
addresses a scanner refused as a verified crawler or research scanner
(docs/scanners.md), cluster members'
```

(Keep the surrounding sentence intact; only the phrase and link are added.)

- [ ] **Step 6: Commit**

```bash
git add src/scan/crawler.rs docs/scanners.md docs/operations.md
git commit -m "Scans: verified research scanners (Censys, LeakIX, Shodan) are not counter-scanned"
```

---

### Task 4: Admin transparency for refused scans

**Files:**
- Modify: `src/scan/pace.rs` (`QueueMetrics` struct, line 208)
- Modify: `src/store/scans.rs` (`queue_metrics`, lines 76-173; test near line 348)
- Modify: `templates/admin_scans.html` (line 54 area)

**Interfaces:**
- Consumes: `queue_metrics()` SQL in `src/store/scans.rs`; `PaceView.m` is a `QueueMetrics`, rendered in `templates/admin_scans.html` (`pace.m.failed_24h` at line 54 is the pattern to copy). Refused jobs already carry their reason in `error` and are listed under `/admin/scans?status=refused#history` (`FINISHED_STATUSES`, `src/store/inspect.rs:55`).
- Produces: `QueueMetrics.refused_24h: i64`; a "N refused in 24 h →" link on the scans page, so an operator sees who was not scanned and why.

- [ ] **Step 1: Write the failing test**

In `src/store/scans.rs`, in the queue-metrics test (the block ending near
line 350 with `assert_eq!(m.left_recent, 3);`), add after that line:

```rust
        assert_eq!(m.refused_24h, 1, "one job was set to refused above");
```

(The test marks two queued jobs `refused`/`superseded` a few lines earlier
— exactly one of them counts.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test queue_metrics`
Expected: FAIL to compile — `QueueMetrics` has no field `refused_24h`.

- [ ] **Step 3: Add the field, the SQL and the template link**

In `src/scan/pace.rs`, after `failed_24h` (line 216):

```rust
    /// Failed / timed-out jobs among `completed_24h`.
    pub failed_24h: i64,
    /// Jobs refused in the last 24 h (never_scan, Tor exit, verified
    /// crawler, …); the reason is on each job.
    pub refused_24h: i64,
```

In `src/store/scans.rs` `queue_metrics`:

1. Add one more `Option<i64>` to the `Sums` tuple type (line 79-90), making eleven elements.
2. Change the destructure (line 91) to:

```rust
        let (backlog, running, a1, a24, c1, c24, f24, t24, ar, lr, r24): Sums = sqlx::query_as(
```

3. In the SQL, after the `left_recent` sum (lines 103-104), add a column:

```sql
                    SUM(status IN ('done','failed','refused','superseded')
                        AND finished_at > datetime('now', ?)),
                    SUM(status = 'refused' AND finished_at > datetime('now','-24 hours'))
             FROM scan_jobs
```

4. In the struct literal (line 156), after `failed_24h: f24.unwrap_or(0),` add:

```rust
            refused_24h: r24.unwrap_or(0),
```

In `templates/admin_scans.html`, after line 54 (the failed link):

```html
  {% if pace.m.failed_24h > 0 %}<p class="muted pace-retry"><a href="/admin/scans?status=failed#history">{{ pace.m.failed_24h }} failed in 24 h →</a></p>{% endif %}
```

add:

```html
  {% if pace.m.refused_24h > 0 %}<p class="muted pace-retry"><a href="/admin/scans?status=refused#history">{{ pace.m.refused_24h }} refused in 24 h →</a></p>{% endif %}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test queue_metrics && cargo build`
Expected: `queue_metrics` PASS; build succeeds (askama compiles the template — a typo'd field is a build error).

- [ ] **Step 5: Commit**

```bash
git add src/scan/pace.rs src/store/scans.rs templates/admin_scans.html
git commit -m "Admin: the Scans page links the day's refused jobs"
```

---

### Task 5: Changelog and full verification

**Files:**
- Modify: `CHANGELOG.md` (`[Unreleased]` section)

**Interfaces:**
- Consumes: everything above.
- Produces: release notes; green full test suite.

- [ ] **Step 1: Add the changelog entries**

Under `## [Unreleased]`, add to `### Added`:

```markdown
- Verified research scanners (Censys, LeakIX, Shodan) are recognised by
  forward-confirmed reverse DNS and never counter-scanned, like
  search-engine crawlers; the Scans page links the day's refused jobs with
  their reasons. See docs/scanners.md.
```

and to `### Changed`:

```markdown
- A source whose requests only look — probe, path-scanner, php-probe and
  nothing else — now earns at most a level-1 counter-scan, however often it
  looked; severity is unchanged. Level 2 and up needs a specific rule hit.
- webshell-probe knows the shell names the current spray waves use
  (chosen, simple, adminfuns, dex, go, ccc, sm, ebkid,
  this_is_a_new_hello_world).
```

- [ ] **Step 2: Run the full suite**

Run: `cargo test`
Expected: PASS, all suites.

- [ ] **Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "Changelog: scanner exemptions, weak-tell scan cap, webshell names"
```
