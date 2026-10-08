# Host keys in the export, ETags, reverse DNS — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship four roadmap follow-ups in one PR: host keys in the export, ETags of scanned sources (with `http-headers` at level 2), ETags as a canary return marker, and forward-confirmed reverse DNS of every source.

**Architecture:** Everything is derived locally on each node from data it already holds (scan XML, request rows, its own resolver); nothing new is replicated, so the cluster protocol stays at 6. The ETag return marker is a new canary kind served by decoy version 3 and found by the existing token/reuse machinery. Reverse DNS reuses the crawler check's PTR and forward lookups through a new background worker.

**Tech Stack:** Rust (tokio, axum, sqlx/SQLite, quick-xml, askama templates).

**Spec:** `docs/superpowers/specs/2026-10-08-etags-rdns-design.md`

## Global Constraints

- No new replicated record kind or record field; no cluster protocol bump (stays 6).
- `DECOY_V` becomes 3; version 0, 1 and 2 renders stay byte-identical (golden files unchanged).
- `host_keys.kind` for ETags: `http-etag`; `LinkKind::HttpEtag`, key `http-etag`, name "HTTP ETag"; soft (never identity).
- `ip_names.source` for reverse DNS: `rdns`; nmap's stay `ptr`.
- `HOSTKEYS_V = 2` stored in `scans.keys_parsed`.
- Canary kind `etag`: 32 lower-case hex characters, served as header `etag: "<value>"`.
- Config: `[enrichment] reverse_dns = true` by default.
- Migration `0025_rdns.sql`: `ALTER TABLE ips ADD COLUMN rdns_at TEXT;`
- Build env: `export PATH=$HOME/.cargo/bin:$PATH` before cargo. Run only the focused tests named in each task (`cargo test --lib <filter>`), never the full suite per task. Shared target dir: `CARGO_TARGET_DIR=/home/user01/peephole/target`.
- Match the surrounding code: short doc comments that say why, British-neutral plain English, no new dependencies.

## Review Focus

1. A port whose `http-headers` output has no ETag, malformed lines or a huge value: no key, or a value capped at 128 characters (Task 2, test `etag_lines_are_capped_and_malformed_ones_skipped`).
2. The startup reparse of every stored scan must not duplicate rows or drop keys a probe found (Task 2, test `reparse_replaces_scan_keys_and_keeps_probe_keys`).
3. Rows served by decoy version 1 or 2 must derive no ETag canary (Task 4, assertion in `etag_canary_is_served_from_version_3`).
4. A reverse zone answering with an IP literal or junk as the PTR name: no name stored (Task 5, `confirmed_names_checks_every_name`).
5. Reverse DNS names must never keep an IP alive once its last request is gone (Task 5, `rdns_names_go_with_the_last_request`).

## Task graph

Tasks 1–6 are independent of each other (no shared files) and can run in parallel. Task 7 (docs) runs after all of them.

---

### Task 1: Host keys in the export

**Files:**
- Modify: `src/store/export.rs` (struct `ScanOut` ~line 81, `export_context` ~line 273–302)
- Modify: `src/export/mod.rs` (`scan_json` ~line 528; tests module)

**Interfaces:**
- Produces: `crate::store::export::KeyOut { scan_id, port, kind, fingerprint, detail }`; `ScanOut.host_keys: Vec<KeyOut>`; JSON field `host_keys` in each object of the `scans` column.

- [ ] **Step 1: Write the failing test** (in `src/export/mod.rs` tests, next to `an_audit_names_its_auditor_as_scanner`)

```rust
    #[tokio::test]
    async fn scans_export_their_host_keys() {
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
        let res = crate::scan::nmap_xml::parse_nmap_xml(include_bytes!(
            "../../tests/fixtures/nmap-hostkeys.xml"
        ))
        .unwrap();
        s.finish_job(job.id, Some(&res), None).await.unwrap();

        let out = text(&collect(&s, ExportFilter::default(), Format::Jsonl).await);
        let r: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        let keys = r["scans"][0]["host_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 5, "{keys:?}");
        assert!(keys.iter().any(|k| k["kind"] == "ssh-hostkey"
            && k["fingerprint"].as_str().unwrap().starts_with("SHA256:")
            && k["port"].as_i64().is_some()));
        assert!(keys.iter().any(|k| k["kind"] == "tls-cert"));
        assert!(keys[0].get("scan_id").is_none(), "internal id not exported");
    }
```

If `enqueue_scan` returns an `EnqueueOutcome` in this signature, follow the `scan()` helper in `src/store/hostkeys.rs` tests, which this test copies.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib export::tests::scans_export_their_host_keys`
Expected: FAIL (`host_keys` is null, `as_array().unwrap()` panics).

- [ ] **Step 3: Implement**

In `src/store/export.rs`, after `PortOut`:

```rust
/// A host key, certificate or other identifier a scan found (`host_keys`).
#[derive(sqlx::FromRow, serde::Serialize)]
pub struct KeyOut {
    #[serde(skip)]
    pub scan_id: i64,
    pub port: i64,
    pub kind: String,
    pub fingerprint: String,
    pub detail: String,
}
```

In `ScanOut` add as the last field:

```rust
    /// Read separately, by scan.
    #[sqlx(skip)]
    pub host_keys: Vec<KeyOut>,
```

In `export_context`, after the `ports` loop and before `for s in scans`:

```rust
        let mut keys: HashMap<i64, Vec<KeyOut>> = HashMap::new();
        let rows: Vec<KeyOut> = sqlx::query_as(
            "SELECT scan_id, port, kind, fingerprint, detail FROM host_keys
             WHERE scan_id IN (SELECT value FROM json_each(?))
             ORDER BY scan_id, port, kind, fingerprint",
        )
        .bind(json_list(&scan_ids))
        .fetch_all(&self.read)
        .await?;
        for k in rows {
            keys.entry(k.scan_id).or_default().push(k);
        }
```

and change the loop to:

```rust
        for mut s in scans {
            let p = ports.remove(&s.id).unwrap_or_default();
            s.host_keys = keys.remove(&s.id).unwrap_or_default();
            c.scans.entry(s.ip_id).or_default().push((s, p));
        }
```

In `src/export/mod.rs` `scan_json`, add after `"ports": ports,`:

```rust
        "host_keys": s.host_keys,
```

- [ ] **Step 4: Run the export tests**

Run: `cargo test --lib export::`
Expected: PASS (the new test and the existing export tests).

- [ ] **Step 5: Commit**

```bash
git add src/store/export.rs src/export/mod.rs
git commit -m "Export: each scan carries its host keys"
```

---

### Task 2: ETags of scanned sources

**Files:**
- Create: `tests/fixtures/nmap-http-headers.xml`
- Modify: `src/scan/hostkeys.rs` (constants, `extract`, new `etags` / `nginx_detail`, tests)
- Modify: `src/store/hostkeys.rs` (`kind_name`, `derive`, `backfill`, tests)
- Modify: `src/store/links.rs` (`LinkKind`)
- Modify: `templates/_host_keys.html` (empty-state text)

**Interfaces:**
- Produces: `crate::scan::hostkeys::HTTP_ETAG: &str = "http-etag"`, `crate::scan::hostkeys::HOSTKEYS_V: i64 = 2`, `LinkKind::HttpEtag`.

- [ ] **Step 1: Write the fixture** `tests/fixtures/nmap-http-headers.xml`. Port 80 has nmap's real form (an `output` attribute only); port 8080 has `<elem>` lines too, repeating the ETag in both places and in two spellings to check dedupe:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -Pn -sS -sV -O -T3 --top-ports 1000 --script ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers -oX - 192.0.2.7" start="1760000000" startstr="" version="7.94" xmloutputversion="1.05">
<host starttime="1760000000" endtime="1760000100"><status state="up" reason="user-set" reason_ttl="0"/>
<address addr="192.0.2.7" addrtype="ipv4"/>
<hostnames></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="nginx" version="1.18.0" method="probed" conf="10"/><script id="http-headers" output="&#xa;  Server: nginx/1.18.0 (Ubuntu)&#xa;  Date: Wed, 08 Oct 2025 10:00:00 GMT&#xa;  Content-Type: text/html&#xa;  Content-Length: 612&#xa;  Last-Modified: Tue, 21 Apr 2020 14:09:01 GMT&#xa;  Connection: close&#xa;  ETag: &quot;5e9efe7d-264&quot;&#xa;  Accept-Ranges: bytes&#xa;  &#xa;  (Request type: HEAD)&#xa;"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http-proxy" method="table" conf="3"/><script id="http-headers" output="&#xa;  Server: Apache&#xa;  ETag: W/&quot;2aa6-5f3c9a4b1e2c0&quot;&#xa;"><elem>Server: Apache</elem><elem>etag: W/&quot;2aa6-5f3c9a4b1e2c0&quot;</elem></script></port>
</ports>
</host>
<runstats><finished time="1760000100" timestr="" summary="" elapsed="100" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
```

Compare with `tests/fixtures/nmap-basic.xml`; if `parse_nmap_xml` needs any element that file has and this one lacks, add it.

- [ ] **Step 2: Write the failing parser tests** (in `src/scan/hostkeys.rs` tests)

```rust
    #[test]
    fn etags_are_read_from_http_headers() {
        let keys = extract(include_bytes!("../../tests/fixtures/nmap-http-headers.xml"));
        let etags: Vec<_> = keys.iter().filter(|k| k.kind == HTTP_ETAG).collect();
        assert_eq!(etags.len(), 2, "{etags:?}");
        assert_eq!(etags[0].port, 80);
        assert_eq!(etags[0].fingerprint, "\"5e9efe7d-264\"");
        assert_eq!(etags[0].detail, "nginx: modified 2020-04-21, 612 bytes");
        assert_eq!(etags[1].port, 8080);
        assert_eq!(etags[1].fingerprint, "W/\"2aa6-5f3c9a4b1e2c0\"");
        assert_eq!(etags[1].detail, "", "Apache's size-mtime form is not dated");
    }

    #[test]
    fn etag_lines_are_capped_and_malformed_ones_skipped() {
        let mut out = vec![];
        let long = "a".repeat(400);
        etags(
            80,
            &format!("no colon here\nETag:\n  X-ETag: \"nope\"\nETag: \"{long}\"\n"),
            &mut out,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].fingerprint.chars().count(), MAX_ETAG);
    }

    #[test]
    fn nginx_etags_are_dated_when_plausible() {
        assert_eq!(
            nginx_detail("\"5e9efe7d-264\""),
            "nginx: modified 2020-04-21, 612 bytes"
        );
        assert_eq!(nginx_detail("W/\"5e9efe7d-264\""), "nginx: modified 2020-04-21, 612 bytes");
        assert_eq!(nginx_detail("\"1-2\""), "", "before 2000");
        assert_eq!(nginx_detail("\"ffffffff-2\""), "", "far future");
        assert_eq!(nginx_detail("\"abc\""), "");
        assert_eq!(nginx_detail("\"5e9efe7d-zz\""), "");
    }
```

- [ ] **Step 3: Run them to verify they fail**

Run: `cargo test --lib scan::hostkeys`
Expected: compile errors (`HTTP_ETAG`, `etags`, `MAX_ETAG`, `nginx_detail` missing).

- [ ] **Step 4: Implement the parser** in `src/scan/hostkeys.rs`

Constants, after `HTTP_404`:

```rust
pub const HTTP_ETAG: &str = "http-etag";
/// Version of what `extract` reads (`scans.keys_parsed`). A change bumps
/// it, and the backfill reads every stored scan again.
pub const HOSTKEYS_V: i64 = 2;
/// Longest ETag kept, in characters.
const MAX_ETAG: usize = 128;
```

Update the module doc comment to mention `http-headers` (ETags: the same file, not the same operator) and the `HostKey.kind` doc to list `HTTP_ETAG`.

An unescaping attribute reader (nmap writes newlines as `&#xa;` and quotes as `&quot;` in `output`), next to `key_attr`:

```rust
fn text_attr(e: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    e.attributes().flatten().find(|a| a.key.as_ref() == name).map(|a| {
        #[allow(deprecated)]
        a.unescape_value()
            .map(|c| c.into_owned())
            .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned())
    })
}
```

(If `a.key.as_ref() == name` does not compile against `&str` here, compare the way `key_attr` does.)

In `extract`, in the `Event::Start` arm's `"script" if port > 0` branch, add `"http-headers"` to the `matches!` list and read its output first:

```rust
                "script" if port > 0 => {
                    let id = key_attr(&e, "id").unwrap_or_default();
                    if id == "http-headers"
                        && let Some(o) = text_attr(&e, "output")
                    {
                        etags(port, &o, &mut out);
                    }
                    if matches!(
                        id.as_str(),
                        "ssh-hostkey" | "ssl-cert" | "ssh2-enum-algos" | "http-headers"
                    ) {
                        script = Some(id);
                        stack = vec![(None, vec![])];
                    }
                }
```

Add a new arm before the existing `Event::Empty(e) if script.is_some() …` arm, for nmap's usual self-closing form:

```rust
            Event::Empty(e)
                if port > 0
                    && e.name().as_ref() == "script"
                    && key_attr(&e, "id").as_deref() == Some("http-headers") =>
            {
                if let Some(o) = text_attr(&e, "output") {
                    etags(port, &o, &mut out);
                }
            }
```

In the `"script"` end arm's `match id.as_str()`, add before `_ => hassh(…)`:

```rust
                            "http-headers" => etags(port, &texts(&root).join("\n"), &mut out),
```

The parsing helpers, after `hassh`:

```rust
/// The `ETag` lines of an `http-headers` result, once per port and value.
fn etags(port: u16, text: &str, out: &mut Vec<HostKey>) {
    for line in text.lines() {
        let Some((name, value)) = line.trim().split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("etag") {
            continue;
        }
        let value: String = value.trim().chars().take(MAX_ETAG).collect();
        if value.is_empty()
            || out
                .iter()
                .any(|k| k.kind == HTTP_ETAG && k.port == port && k.fingerprint == value)
        {
            continue;
        }
        out.push(HostKey {
            port,
            kind: HTTP_ETAG,
            detail: nginx_detail(&value),
            fingerprint: value,
        });
    }
}

/// nginx's ETag is `"<mtime hex>-<size hex>"`: when the first part is a
/// plausible time (2000 to tomorrow), when the file was written and its
/// size. Empty for any other form.
fn nginx_detail(etag: &str) -> String {
    let v = etag.strip_prefix("W/").unwrap_or(etag).trim_matches('"');
    let Some((t, n)) = v.split_once('-') else {
        return String::new();
    };
    let hex = |s: &str| !s.is_empty() && s.len() <= 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex(t) || !hex(n) {
        return String::new();
    }
    let (Ok(t), Ok(n)) = (i64::from_str_radix(t, 16), u64::from_str_radix(n, 16)) else {
        return String::new();
    };
    let tomorrow = chrono::Utc::now().timestamp() + 86_400;
    if !(946_684_800..=tomorrow).contains(&t) {
        return String::new();
    }
    match chrono::DateTime::from_timestamp(t, 0) {
        Some(d) => format!("nginx: modified {}, {n} bytes", d.format("%Y-%m-%d")),
        None => String::new(),
    }
}
```

- [ ] **Step 5: Run the parser tests**

Run: `cargo test --lib scan::hostkeys`
Expected: PASS, including the existing tests.

- [ ] **Step 6: Write the failing store tests** (in `src/store/hostkeys.rs` tests)

```rust
    #[tokio::test]
    async fn reparse_replaces_scan_keys_and_keeps_probe_keys() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = scan(
            &s,
            "192.0.2.7",
            include_bytes!("../../tests/fixtures/nmap-http-headers.xml"),
        )
        .await;
        let ip_id: i64 = sqlx::query_scalar("SELECT ip_id FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        let probe: i64 = sqlx::query_scalar(
            "INSERT INTO probes (uid, group_uid, ip_id, asker, started_at, finished_at)
             VALUES ('p', 'g', ?, x'01', datetime('now'), datetime('now')) RETURNING id",
        )
        .bind(ip_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO host_keys (probe_id, ip_id, port, kind, fingerprint)
             VALUES (?, ?, 443, 'jarm', 'j')",
        )
        .bind(probe)
        .bind(ip_id)
        .execute(&s.pool)
        .await
        .unwrap();
        // As a build before ETags left it: read, but at version 1.
        sqlx::query("UPDATE scans SET keys_parsed = 1")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 1);
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "each scan once");
        let rows = s.host_keys_for_scan(id).await.unwrap();
        assert_eq!(rows.iter().filter(|r| r.kind == HTTP_ETAG).count(), 2, "{rows:?}");
        assert_eq!(rows[0].kind_name(), "HTTP ETag");
        assert!(rows.iter().all(|r| !r.identifies()));
        assert!(rows[0].link_href().starts_with("/admin/links/http-etag/%22"));
        let probe_keys: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM host_keys WHERE probe_id IS NOT NULL")
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert_eq!(probe_keys, 1, "a scan's reparse leaves probe keys alone");
        let v: i64 = sqlx::query_scalar("SELECT keys_parsed FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(v, HOSTKEYS_V);
    }
```

Also change the existing assertion in `stored_scans_yield_host_keys_shared_across_ips` from `WHERE keys_parsed = 1` to `WHERE keys_parsed = 2`. Import `HOSTKEYS_V` and `HTTP_ETAG` in the `use crate::scan::hostkeys::{…}` line at the top of the file.

- [ ] **Step 7: Run to verify it fails**

Run: `cargo test --lib store::hostkeys`
Expected: FAIL (backfill finds 0 scans at `keys_parsed = 1`; `kind_name` says "other").

- [ ] **Step 8: Implement the store side** in `src/store/hostkeys.rs`

- `kind_name`: add `HTTP_ETAG => "HTTP ETag",`.
- `derive`: before the `for k in keys` insert loop:

```rust
    // Read again (a newer HOSTKEYS_V): what an older parse left goes.
    sqlx::query("DELETE FROM host_keys WHERE scan_id = ?")
        .bind(scan_id)
        .execute(&mut *conn)
        .await?;
```

  and the final update becomes `UPDATE scans SET keys_parsed = ? WHERE id = ?` binding `HOSTKEYS_V` then `scan_id`. Update the doc comment ("mark the scan as read at `HOSTKEYS_V`").
- `backfill`: `"SELECT id, ip_id, raw_xml FROM scans WHERE keys_parsed < ? LIMIT 50"` with `.bind(HOSTKEYS_V)`; doc: "or by an older parser".

In `src/store/links.rs`:
- import `HTTP_ETAG` with the other `crate::scan::hostkeys` constants;
- add variant `HttpEtag` after `Http404`;
- `ALL: [LinkKind; 13]` with `HttpEtag` appended; `LIST: [LinkKind; 12]` with `HttpEtag` appended;
- `key`: `HttpEtag => "http-etag"`; `name`: `HttpEtag => "HTTP ETag"`;
- `host_kind`: `HttpEtag => Some(HTTP_ETAG)`;
- `legs`: `HttpEtag => &HTTP_ETAG_LEGS`, with `const HTTP_ETAG_LEGS: [Leg; 1] = [Leg::host_key("h.kind = 'http-etag'")];` beside `HTTP_404_LEGS`.
- In `probe_hashes_link_addresses_softly`, add: `assert!(!LinkKind::HttpEtag.identity()); assert_eq!(LinkKind::of_host_kind("http-etag"), Some(LinkKind::HttpEtag));`

In `templates/_host_keys.html`, the empty-state text becomes: `None found (nmap's ssh-hostkey, ssh2-enum-algos, ssl-cert and http-headers run from level 2).`

- [ ] **Step 9: Run the focused tests**

Run: `cargo test --lib hostkeys` then `cargo test --lib links`
Expected: PASS. If a test elsewhere counts link kinds (e.g. tabs in `src/admin/links.rs` tests), fix its expected count.

- [ ] **Step 10: Commit**

```bash
git add tests/fixtures/nmap-http-headers.xml src/scan/hostkeys.rs src/store/hostkeys.rs src/store/links.rs templates/_host_keys.html
git commit -m "Host keys: ETags from http-headers, a soft link kind; reparse old scans"
```

---

### Task 3: `http-headers` at level 2

**Files:**
- Modify: `src/scan/profiles.rs` (`IDENTITY_SCRIPTS`, `ACCEPTED`, tests)

**Interfaces:**
- Produces: level 2's built-in list ends `--script ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers`; the previous list stays accepted for credits.

- [ ] **Step 1: Write the failing test** (in `src/scan/profiles.rs` tests)

```rust
    #[test]
    fn level_2_reads_http_headers_and_the_previous_list_still_earns() {
        let l2 = builtin(2, false).unwrap();
        assert!(l2.last().unwrap().ends_with(",http-headers"), "{l2:?}");
        let old = "nmap -Pn -sS -sV -O -T3 --top-ports 1000 --script \
                   ssh-hostkey,ssh2-enum-algos,ssl-cert --host-timeout 900s \
                   --script-timeout 570s -oX - 203.0.113.7";
        assert!(args_ok(old, 2));
        assert!(!args_ok(old, 3), "accepted for level 2 only");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib scan::profiles`
Expected: FAIL on the `ends_with` assertion.

- [ ] **Step 3: Implement**

```rust
/// Level 2 names its scripts: the source's own identifiers (SSH host keys
/// and algorithm lists, the TLS certificate, the HTTP headers with their
/// ETag), each one handshake or request to a port nmap already found
/// open, all in `safe`.
pub const IDENTITY_SCRIPTS: &str = "ssh-hostkey,ssh2-enum-algos,ssl-cert,http-headers";
```

```rust
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
];
```

- [ ] **Step 4: Run the focused tests**

Run: `cargo test --lib scan::profiles` then `cargo test --lib credits`
Expected: PASS. If a credits or scan test hard-codes the old level-2 line, update it to the new list.

- [ ] **Step 5: Commit**

```bash
git add src/scan/profiles.rs
git commit -m "Scans: level 2 also reads the HTTP headers; the old list still earns"
```

---

### Task 4: ETags as a return marker (decoy version 3)

**Files:**
- Modify: `src/canary/derive.rs` (`DECOY_V`, `Kind`, `value`, `served`, new `ETAG_DECOYS`, tests)
- Modify: `src/canary/mod.rs` (re-export `ETAG_DECOYS`)
- Modify: `src/trap/decoy/mod.rs` (`render`, golden test)
- Create: `tests/fixtures/decoys/v3-*.txt` (blessed)
- Modify: `src/store/canaries.rs` (test)
- Modify: `src/admin/links.rs` (canary kind filter list ~line 315)

**Interfaces:**
- Produces: `crate::canary::Kind::Etag` (name `"etag"`); `crate::canary::ETAG_DECOYS: [&str; 9]`; `DECOY_V = 3`.

- [ ] **Step 1: Write the failing canary tests** (in `src/canary/derive.rs` tests)

```rust
    #[test]
    fn etag_canary_is_served_from_version_3() {
        let e = value(TOK, Kind::Etag);
        assert!(e.len() == 32 && all(&e, "0123456789abcdef"), "{e}");
        let has = |v, name| served(v, TOK, name, None).iter().any(|(k, _)| *k == Kind::Etag);
        for name in ETAG_DECOYS {
            assert!(has(Some(3), name), "{name}");
            assert!(!has(Some(2), name) && !has(Some(1), name), "{name}: not before v3");
        }
        assert!(!has(Some(3), "git-pack") && !has(Some(3), "wp-login-ok"));
        // The other canaries of a v3 answer are those of v2.
        let v3: Vec<_> = served(Some(3), TOK, "dotenv", None)
            .into_iter()
            .filter(|(k, _)| *k != Kind::Etag)
            .collect();
        assert_eq!(v3, served(Some(2), TOK, "dotenv", None));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib canary::derive`
Expected: compile errors (`Kind::Etag`, `ETAG_DECOYS`).

- [ ] **Step 3: Implement the canary side** in `src/canary/derive.rs`

- `pub const DECOY_V: i64 = 3;`
- `Kind`: add `/// The ETag a web decoy answers with (version 3).` `Etag,` after `McpSession`; `name`: `Kind::Etag => "etag",`; `value`: `Kind::Etag => data_encoding::HEXLOWER.encode(&stream(page_token, kind, 16)),`
- Before `served`:

```rust
/// The web decoys that answer with an ETag from version 3: the ones that
/// answer 200 (a client revalidating sends it back in `If-None-Match`).
pub const ETAG_DECOYS: [&str; 9] = [
    "dotenv",
    "git-config",
    "git-head",
    "wp-login",
    "wp-login-failed",
    "wp-admin",
    "admin",
    "phpinfo",
    "git-refs",
];
```

- In `served`, replace the `1 | 2 => match decoy { … },` arm with:

```rust
        1..=3 => {
            let mut out = match decoy {
                "dotenv" => v(&DOTENV),
                "git-config" => v(&[Kind::GitToken]),
                "wp-login-ok" => v(&[Kind::WpSession]),
                _ => vec![],
            };
            if ver >= 3 && ETAG_DECOYS.contains(&decoy) {
                out.extend(v(&[Kind::Etag]));
            }
            out
        }
```

In `src/canary/mod.rs`, add `ETAG_DECOYS` to the `pub use derive::{…}` list.

- [ ] **Step 4: Run the canary tests**

Run: `cargo test --lib canary::`
Expected: PASS.

- [ ] **Step 5: Add the v3 golden cases** in `src/trap/decoy/mod.rs` `golden_decoys`, appended to `cases`:

```rust
            (3, "GET", "/.env", "dotenv"),
            (3, "GET", "/.git/config", "git-config"),
            (3, "GET", "/.git/HEAD", "git-head"),
            (3, "GET", "/wp-login.php", "wp-login"),
            (3, "POST", "/wp-login.php", "wp-login-failed"),
            (3, "GET", "/wp-admin/", "wp-admin"),
            (3, "GET", "/admin/", "admin"),
            (3, "GET", "/git/x.git/info/refs", "git-refs"),
            (3, "GET", "/phpinfo.php", "phpinfo"),
            (3, "POST", "/wp-login.php", "wp-login-ok"),
            (3, "POST", "/git/x.git/git-upload-pack", "git-pack"),
```

Run: `cargo test --lib trap::decoy::tests::golden_decoys`
Expected: FAIL (render returns None for v3, `unwrap` panics).

- [ ] **Step 6: Implement the render side** in `src/trap/decoy/mod.rs`

- import `ETAG_DECOYS` with the other `crate::canary` items;
- make the tuple binding mutable: `let (status, mut headers, body): (u16, Vec<(&'static str, String)>, String) = match inp.v {`
- change the `1 | 2 => {` arm to `1..=3 => {`;
- before `Some(Decoy { … })`:

```rust
    if inp.v >= 3 && ETAG_DECOYS.contains(&name) {
        headers.push(("etag", format!("\"{}\"", value(inp.page_token, Kind::Etag))));
    }
```

- update the module doc: "Version 3 adds an ETag canary to the web decoys that answer 200."

Bless the new files and check the old ones did not move:

```bash
PEEPHOLE_BLESS=1 cargo test --lib trap::decoy::tests::golden_decoys
git status --short tests/fixtures/decoys   # only new v3-*.txt files, no modified v0/v1 files
cargo test --lib trap::decoy
```

Expected: 11 new `v3-*.txt` files; `v3-dotenv.txt` ends its header block with `etag: "<32 hex>"`; `v3-git-pack.txt` and `v3-wp-login-ok.txt` have no `etag` line; all decoy tests PASS.

- [ ] **Step 7: Write the reuse test** (in `src/store/canaries.rs` tests, after `a_reuse_is_found_in_either_arrival_order`)

```rust
    /// A client that revalidates sends a decoy's ETag back in
    /// `If-None-Match`: an ordinary canary reuse.
    #[tokio::test]
    async fn an_etag_sent_back_is_a_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let etag = crate::canary::value(&format!("{TOK}-srv"), crate::canary::Kind::Etag);
        let serve = req(
            "srv",
            "2026-10-04 10:00:00",
            "198.51.100.1",
            "/.env",
            "[]",
            "decoy:dotenv",
            Some(3),
        );
        let using = req(
            "use",
            "2026-10-04 13:00:00",
            "198.51.100.2",
            "/.env",
            &format!(r#"[["if-none-match","\"{etag}\""]]"#),
            "not-found",
            None,
        );
        let old = req(
            "old",
            "2026-10-04 09:00:00",
            "198.51.100.3",
            "/.env",
            "[]",
            "decoy:dotenv",
            Some(2),
        );
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx { origin: None, hlc: 1 };
        for r in [&old, &serve, &using] {
            apply(&mut conn, ctx, r).await.unwrap();
        }
        assert_eq!(reuses(&s.pool).await, vec![("srv".into(), "use".into())]);
    }
```

Run: `cargo test --lib store::canaries`
Expected: PASS (no production change needed: `tokens::of_request` scans every header). If it fails, find out why before changing anything; the spec's premise is that it needs no change.

- [ ] **Step 8: Canary filter list** in `src/admin/links.rs` (~line 315): `.chain(["etag", "legacy"])` instead of `.chain(["legacy"])`.

Run: `cargo test --lib admin::links`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/canary src/trap/decoy/mod.rs tests/fixtures/decoys src/store/canaries.rs src/admin/links.rs
git commit -m "Decoys v3: web decoys answer with an ETag canary"
```

---

### Task 5: Reverse DNS of every source

**Files:**
- Modify: `src/scan/crawler.rs` (shared lookup helpers; a test-only fake resolver module)
- Create: `src/intel/rdns.rs` (worker)
- Modify: `src/intel/mod.rs` (`pub mod rdns;`)
- Create: `src/store/rdns.rs` (due IPs, storing names)
- Modify: `src/store/mod.rs` (`mod rdns;` / `pub mod rdns;` like the siblings)
- Create: `src/store/migrations/0025_rdns.sql`
- Modify: `src/store/data.rs` (`drop_orphan_ip`)
- Modify: `src/config.rs` (`EnrichmentConfig.reverse_dns`, optional-keys list ~line 610)
- Modify: `deploy/config.example.toml` (`[enrichment]`)
- Modify: `src/lib.rs` (spawn the worker, beside `intel::enrich_loop`)
- Modify: `templates/_names.html`

**Interfaces:**
- Produces: `crate::scan::crawler::{Forward, system_forward, system_resolver, confirmed_names}` (all `pub(crate)`); `Store::rdns_due(limit: i64) -> Result<Vec<(i64, String)>>`; `Store::record_rdns(ip_id: i64, names: &[String]) -> Result<()>`; `crate::intel::rdns::run(store: Store, enabled: bool, shutdown: tokio::sync::watch::Receiver<bool>)` (match the receiver type the sibling loops in `src/lib.rs` take); `crate::intel::rdns::pass(store: &Store, resolver: SocketAddr, forward: &Forward) -> anyhow::Result<usize>`.

- [ ] **Step 1: Share the test fakes.** In `src/scan/crawler.rs`, move the test helpers `reply` and `fake_resolver` out of `mod tests` into a new module at the end of the file, then `use super::testing::*;` in `mod tests`:

```rust
/// A fake PTR resolver for tests here and in `intel::rdns`.
#[cfg(test)]
pub(crate) mod testing {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    // `reply` and `fake_resolver` moved here unchanged, both `pub(crate)`.
}
```

Run: `cargo test --lib scan::crawler`
Expected: PASS (pure move).

- [ ] **Step 2: Write the failing lookup test** (in `crawler.rs` `mod tests`)

```rust
    #[tokio::test]
    async fn confirmed_names_checks_every_name() {
        let run = |name: Option<&str>, ip: &str| {
            let answer = std::sync::Arc::new(Mutex::new(name.map(str::to_string)));
            let ip: IpAddr = ip.parse().unwrap();
            async move {
                let r = fake_resolver(answer).await;
                confirmed_names(r, &fake_forward(), ip).await
            }
        };
        // Any domain counts here, not only crawlers, once it resolves back.
        assert_eq!(
            run(Some("crawl-1.real.googlebot.com"), "198.51.100.7").await.unwrap(),
            vec!["crawl-1.real.googlebot.com".to_string()]
        );
        assert!(run(Some("crawl-1.real.googlebot.com"), "198.51.100.8").await.unwrap().is_empty());
        assert!(run(Some("host.example.net"), "198.51.100.7").await.unwrap().is_empty());
        assert!(run(None, "198.51.100.7").await.unwrap().is_empty(), "NXDOMAIN");
        assert!(run(Some("198.51.100.7"), "198.51.100.7").await.unwrap().is_empty(), "an address is no name");
        assert!(run(Some("TIMEOUT"), "198.51.100.7").await.is_err());
        assert!(run(Some("x.slow.googlebot.com"), "198.51.100.7").await.unwrap().is_empty(),
            "a forward timeout is no confirmation here");
    }
```

Run: `cargo test --lib scan::crawler::tests::confirmed_names_checks_every_name`
Expected: compile error (`confirmed_names` missing).

- [ ] **Step 3: Implement the shared lookups** in `src/scan/crawler.rs`

- `type Forward` → `pub(crate) type Forward`; `fn system_forward` → `pub(crate) fn system_forward`.
- Add, and use it in `Crawlers::new`:

```rust
/// The first `nameserver` of `/etc/resolv.conf`, where PTR queries go.
pub(crate) fn system_resolver() -> Option<SocketAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|t| nameserver(&t))
}
```

- Add after `impl Crawlers`:

```rust
/// Most PTR names of one address checked forward.
const MAX_NAMES: usize = 4;

/// The PTR names of `ip` that resolve back to it, as valid host names, in
/// the order the reverse zone gave them. Err when the PTR lookup fails or
/// times out; a name whose forward lookup fails or times out is left out
/// (unlike the crawler check, nothing is exempted here, so there is no
/// fail-safe to keep).
pub(crate) async fn confirmed_names(
    resolver: SocketAddr,
    forward: &Forward,
    ip: IpAddr,
) -> anyhow::Result<Vec<String>> {
    let ip = crate::net::canonical(ip);
    let names = tokio::time::timeout(LOOKUP_TIMEOUT, ptr(resolver, ip))
        .await
        .map_err(|_| anyhow::anyhow!("reverse lookup timed out"))??;
    let mut valid: Vec<String> = vec![];
    for n in names.iter().filter_map(|n| crate::intel::dns::valid_name(n)) {
        if !valid.contains(&n) {
            valid.push(n);
        }
    }
    let mut out = vec![];
    for name in valid.into_iter().take(MAX_NAMES) {
        if let Ok(Ok(addrs)) = tokio::time::timeout(LOOKUP_TIMEOUT, forward(name.clone())).await
            && addrs.into_iter().any(|a| crate::net::canonical(a) == ip)
        {
            out.push(name);
        }
    }
    Ok(out)
}
```

Update the module doc: the PTR and forward lookups also serve reverse DNS of every source (`intel::rdns`).

Run: `cargo test --lib scan::crawler`
Expected: PASS.

- [ ] **Step 4: Migration and config**

`src/store/migrations/0025_rdns.sql`:

```sql
-- When this node last looked up the source's reverse DNS (intel::rdns);
-- NULL: never. Local, like the names it finds.
ALTER TABLE ips ADD COLUMN rdns_at TEXT;
```

Check how migrations are registered (`grep -rn 0024_no_collecting_node src/store`); if they are listed by hand, add 0025 the same way.

In `src/config.rs` `EnrichmentConfig`, add the field, its default (follow the crate's existing `default_true`-style helper if there is one; otherwise add `fn default_reverse_dns() -> bool { true }`), and the `Default` impl entry:

```rust
    /// Look up the forward-confirmed reverse DNS name of every source, when
    /// first seen and when it returns a day later (`intel::rdns`).
    #[serde(default = "default_reverse_dns")]
    pub reverse_dns: bool,
```

Add `("enrichment", "reverse_dns", "true"),` after `("enrichment", "offer_per_day", "1000"),`.

In `deploy/config.example.toml` under `[enrichment]`, after `refresh_after_days`:

```toml
# Look up each source's reverse DNS name (only names that resolve back to
# the address count), when first seen and when it returns a day later.
# reverse_dns = true
```

- [ ] **Step 5: Write the failing store tests** in the new `src/store/rdns.rs`

```rust
//! Reverse DNS names of the sources (`intel::rdns`): which addresses are
//! due a lookup, and storing what one found. Local to this node, like
//! nmap's PTR names: never replicated.
use super::Store;
use anyhow::Result;

impl Store {
    // implemented in step 7
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn source(s: &Store, ip: &str) -> i64 {
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
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
        row.id
    }

    #[tokio::test]
    async fn new_and_returning_sources_are_due() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let fresh = source(&s, "198.51.100.7").await;
        let done = source(&s, "198.51.100.8").await;
        s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap(); // no request
        s.record_rdns(done, &[]).await.unwrap();
        let due: Vec<i64> = s.rdns_due(50).await.unwrap().into_iter().map(|d| d.0).collect();
        assert_eq!(due, vec![fresh]);

        s.record_rdns(fresh, &["host-7.example.net".into()]).await.unwrap();
        assert!(s.rdns_due(50).await.unwrap().is_empty());
        // Back more than a day after the lookup: due again.
        sqlx::query("UPDATE ips SET last_seen = datetime('now', '+2 days') WHERE id = ?")
            .bind(done)
            .execute(&s.pool)
            .await
            .unwrap();
        let due: Vec<i64> = s.rdns_due(50).await.unwrap().into_iter().map(|d| d.0).collect();
        assert_eq!(due, vec![done]);

        let names = s.names_for_ip(fresh).await.unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!((names[0].name.as_str(), names[0].source.as_str(), names[0].agreed),
            ("host-7.example.net", "rdns", true));
        // Found again: one row, last_seen moves.
        s.record_rdns(fresh, &["host-7.example.net".into()]).await.unwrap();
        assert_eq!(s.names_for_ip(fresh).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rdns_names_go_with_the_last_request() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = source(&s, "198.51.100.7").await;
        s.record_rdns(id, &["host-7.example.net".into()]).await.unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id).await.unwrap();
        assert_eq!(s.names_for_ip(id).await.unwrap().len(), 1, "a request remains");
        sqlx::query("DELETE FROM requests WHERE ip_id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, 0, "the name kept nothing alive");
    }
}
```

Adjust `NewRequest`'s path and `insert_request` to the real module if they differ (see `src/export/mod.rs` tests, which use both). If deleting `requests` rows directly trips a foreign key from a derived table, delete those rows first as `delete_records` in `data.rs` does.

Register the module in `src/store/mod.rs` next to `mod hostkeys;` (same visibility).

Run: `cargo test --lib store::rdns`
Expected: compile errors (`rdns_due`, `record_rdns` missing).

- [ ] **Step 6: Make `drop_orphan_ip` drop `rdns` names** in `src/store/data.rs`, after the `ptr` delete:

```rust
    // Reverse DNS names come from the requests: they go with the last one.
    sqlx::query(
        "DELETE FROM ip_names WHERE ip_id = ?1 AND source = 'rdns'
           AND NOT EXISTS (SELECT 1 FROM requests WHERE ip_id = ?1)",
    )
    .bind(ip_id)
    .execute(&mut *conn)
    .await?;
```

- [ ] **Step 7: Implement the store methods** in `src/store/rdns.rs`

```rust
/// Most names kept of one lookup (`crawler::confirmed_names` checks 4).
const MAX_NAMES: usize = 4;

impl Store {
    /// Sources due a reverse lookup, most recently seen first: never looked
    /// up, or seen again more than a day after the last lookup.
    pub async fn rdns_due(&self, limit: i64) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, ip FROM ips
             WHERE request_count > 0
               AND (rdns_at IS NULL OR last_seen > datetime(rdns_at, '+1 day'))
             ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// Store what a lookup found (possibly nothing) and when it ran.
    /// Names no longer found keep their row; `last_seen` dates them.
    pub async fn record_rdns(&self, ip_id: i64, names: &[String]) -> Result<()> {
        let now = super::data::now_ts();
        let mut tx = self.pool.begin().await?;
        for name in names.iter().take(MAX_NAMES) {
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 VALUES (?1, ?2, 'rdns', ?3, ?3, 1)
                 ON CONFLICT(ip_id, name, source) DO UPDATE SET last_seen = excluded.last_seen",
            )
            .bind(ip_id)
            .bind(name)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE ips SET rdns_at = ? WHERE id = ?")
            .bind(&now)
            .bind(ip_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
```

Check that `now_ts()` gives `YYYY-MM-DD HH:MM:SS` (the format `ips.last_seen` uses, so the `datetime(rdns_at, '+1 day')` comparison holds); if not, bind `datetime('now')` in SQL instead.

Run: `cargo test --lib store::rdns`
Expected: PASS.

- [ ] **Step 8: Write the failing worker test** in the new `src/intel/rdns.rs`

```rust
//! Reverse DNS of every source: the PTR names of each address that sent
//! requests, kept when they resolve back to it (forward-confirmed), looked
//! up when the source is first seen and again when it returns a day after
//! the last lookup. Each node looks up on its own and keeps the names
//! locally (`ip_names`, source `rdns`); a source's own DNS often names its
//! hoster or a research scanner.
use crate::scan::crawler::{Forward, confirmed_names, system_forward, system_resolver};
use crate::store::Store;
use futures::StreamExt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Sources looked up per pass.
const BATCH: i64 = 50;
/// Lookups at a time.
const PARALLEL: usize = 4;
/// Between passes.
const EVERY: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::crawler::testing::fake_resolver;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn a_pass_stores_confirmed_names_and_marks_every_source() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut ids = vec![];
        for ip in ["198.51.100.7", "198.51.100.8"] {
            let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            s.insert_request(&crate::store::requests::NewRequest {
                ip_id: row.id,
                method: "GET".into(),
                path: "/".into(),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                ..Default::default()
            })
            .await
            .unwrap();
            ids.push(row.id);
        }
        let resolver =
            fake_resolver(Arc::new(Mutex::new(Some("host-7.example.net".into())))).await;
        let forward: Forward = Arc::new(|name: String| {
            Box::pin(async move {
                if name == "host-7.example.net" {
                    Ok(vec!["198.51.100.7".parse().unwrap()])
                } else {
                    Err(std::io::Error::other("no such host"))
                }
            })
        });
        assert_eq!(pass(&s, resolver, &forward).await.unwrap(), 2);
        let n7 = s.names_for_ip(ids[0]).await.unwrap();
        assert_eq!(n7.len(), 1);
        assert_eq!(n7[0].source, "rdns");
        assert!(s.names_for_ip(ids[1]).await.unwrap().is_empty(), "the name points elsewhere");
        assert_eq!(pass(&s, resolver, &forward).await.unwrap(), 0, "both marked");
    }
}
```

Add `pub mod rdns;` to `src/intel/mod.rs`.

Run: `cargo test --lib intel::rdns`
Expected: compile error (`pass` missing).

- [ ] **Step 9: Implement the worker** in `src/intel/rdns.rs` (above the tests). Look at a sibling loop (`store::publish::run` or `store::maintenance::run`) for the shutdown-receiver type and the wait-or-shutdown idiom, and copy it:

```rust
/// Look up the sources that are due, `BATCH` at a time, until shutdown.
/// Off when `enabled` is false or no resolver is configured.
pub async fn run(store: Store, enabled: bool, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    if !enabled {
        return;
    }
    let Some(resolver) = system_resolver() else {
        tracing::info!("reverse DNS: no nameserver in /etc/resolv.conf, off");
        return;
    };
    let forward = system_forward();
    loop {
        match pass(&store, resolver, &forward).await {
            Ok(0) => {}
            Ok(n) => tracing::debug!(sources = n, "reverse DNS: looked up"),
            Err(e) => tracing::warn!(error = %e, "reverse DNS: pass failed"),
        }
        tokio::select! {
            _ = tokio::time::sleep(EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

/// One batch: every due source is marked looked up, whatever the
/// resolver answered (a broken resolver costs one try a day per source).
/// Returns how many sources were handled.
pub(crate) async fn pass(
    store: &Store,
    resolver: SocketAddr,
    forward: &Forward,
) -> anyhow::Result<usize> {
    let due = store.rdns_due(BATCH).await?;
    let n = due.len();
    let found: Vec<(i64, Vec<String>)> = futures::stream::iter(due)
        .map(|(id, ip)| async move {
            let names = match ip.parse::<IpAddr>() {
                Ok(addr) if crate::net::is_scannable_target(addr) => {
                    confirmed_names(resolver, forward, addr).await.unwrap_or_else(|e| {
                        tracing::debug!(%ip, error = %e, "reverse DNS failed");
                        vec![]
                    })
                }
                _ => vec![],
            };
            (id, names)
        })
        .buffer_unordered(PARALLEL)
        .collect()
        .await;
    for (id, names) in found {
        store.record_rdns(id, &names).await?;
    }
    Ok(n)
}
```

Run: `cargo test --lib intel::rdns`
Expected: PASS.

- [ ] **Step 10: Start the worker and show the names**

In `src/lib.rs`, after the `intel::enrich_loop` spawn:

```rust
    // Reverse DNS of the sources, forward-confirmed, kept on this node.
    tokio::spawn(intel::rdns::run(
        store.clone(),
        cfg.enrichment.reverse_dns,
        shutdown_rx.clone(),
    ));
```

`templates/_names.html`: the comment says "(DNS), seen by nmap (PTR) or by this node's reverse lookup (reverse DNS)"; the source branch becomes:

```
({% if n.source == "ptr" %}PTR from scan, {{ n.day() }}, unverified{% else if n.source == "rdns" %}reverse DNS, forward-confirmed, {{ n.day() }}{% else %}DNS, {% if n.agreed %}agreed{% else %}disputed{% endif %} {{ n.votes }}/{{ n.answered }}, {{ n.day() }}{% endif %})
```

Run: `cargo build` (templates compile with the crate), then `cargo test --lib config` and `cargo test --lib store::rdns intel::rdns scan::crawler`
Expected: PASS. If a config test lists every optional key or counts the notes, update it for `reverse_dns`.

- [ ] **Step 11: Commit**

```bash
git add src/scan/crawler.rs src/intel/rdns.rs src/intel/mod.rs src/store/rdns.rs src/store/mod.rs src/store/migrations/0025_rdns.sql src/store/data.rs src/config.rs deploy/config.example.toml src/lib.rs templates/_names.html
git commit -m "Reverse DNS of every source, forward-confirmed, kept per node"
```

---

### Task 6: IP directory name filter

**Files:**
- Modify: `src/store/browse.rs` (`IpFilter`, `ip_filter_sql`, tests)
- Modify: `src/admin/public.rs` (public filter ~line 367, `ip_pairs` ~line 373)
- Modify: `templates/ips.html` (admin filter inputs ~line 20)

**Interfaces:**
- Produces: `IpFilter.name: Option<String>` (admin only), query parameter `name`.

- [ ] **Step 1: Write the failing test** (in `src/store/browse.rs` tests, after the port/product/os filter test)

```rust
    #[tokio::test]
    async fn ips_are_found_by_name_for_the_admin_only() {
        let s = seeded().await;
        let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM ips ORDER BY id LIMIT 2")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        for (id, name, agreed) in [
            (ids[0], "crawl-1.googlebot.com", 1),
            (ids[1], "xay.example.net", 0),
        ] {
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 VALUES (?, ?, 'rdns', '2026-10-08 10:00:00', '2026-10-08 10:00:00', ?)",
            )
            .bind(id)
            .bind(name)
            .bind(agreed)
            .execute(&s.pool)
            .await
            .unwrap();
        }
        let n = |name: &str, a: Audience| {
            let s = s.clone();
            let f = IpFilter {
                name: Some(name.into()),
                ..Default::default()
            };
            async move { s.list_ips_as(&f, a).await.unwrap().items.len() }
        };
        assert_eq!(n("googlebot", Audience::Admin).await, 1);
        assert_eq!(n("GoogleBot", Audience::Admin).await, 1, "names are lower-case");
        assert_eq!(n("example.net", Audience::Admin).await, 0, "disputed names do not count");
        assert_eq!(n("x_y", Audience::Admin).await, 0, "LIKE wildcards are literal");
        let all = s.list_ips_as(&IpFilter::default(), Audience::Public).await.unwrap().items.len();
        assert_eq!(n("googlebot", Audience::Public).await, all, "admin only");
    }
```

(Use the test helper the neighbouring tests use for a seeded store; if it is not called `seeded`, use that one. If `seeded()` has fewer than two IPs, add them with `upsert_ip` plus a request.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib store::browse::tests::ips_are_found_by_name_for_the_admin_only`
Expected: compile error (`name` field missing).

- [ ] **Step 3: Implement**

In `IpFilter`, after `os`:

```rust
    /// Admin only: an agreed name of the address (looked up, PTR or
    /// reverse DNS) contains this text.
    pub name: Option<String>,
```

In `ip_filter_sql`, inside `if a == Audience::Admin {`, after the `os` block:

```rust
        if let Some(v) = nonempty(&f.name) {
            wheres.push(
                "EXISTS (SELECT 1 FROM ip_names n WHERE n.ip_id = i.id AND n.agreed = 1
                   AND n.name LIKE ? ESCAPE '\\')"
                    .into(),
            );
            binds.push(format!("%{}%", like_escape(&v.to_ascii_lowercase())));
        }
```

In `src/admin/public.rs`: the public filter literal gets `name: None,`; `ip_pairs` gets `("name", f.name.clone()),` after `os`. Fix any other `IpFilter { … }` literal the compiler flags.

In `templates/ips.html`, after the OS guess label:

```html
  <label>Name <input name="name" size="14" value="{{ f.name.as_deref().unwrap_or_default() }}" placeholder="example.net"></label>
```

- [ ] **Step 4: Run the focused tests**

Run: `cargo test --lib store::browse` then `cargo test --lib admin::public`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/store/browse.rs src/admin/public.rs templates/ips.html
git commit -m "IP directory: filter by name"
```

---

### Task 7: Docs

Runs after Tasks 1–6.

**Files:**
- Modify: `CHANGELOG.md` (`## [Unreleased]`)
- Modify: `docs/roadmap.md` (Small follow-ups)
- Modify: `docs/dataset.md` (`scans`, `names`, canaries)
- Modify: `README.md` (~line 40)

- [ ] **Step 1: CHANGELOG** under `## [Unreleased]`:

```markdown
### Added

- Host keys in the export: each scan in the `scans` column lists its
  `host_keys` (kind, port, fingerprint, detail), so nobody has to parse
  the XML for them.
- ETags of scanned sources. Level 2 also runs nmap's `http-headers`; each
  HTTP port's `ETag` is a new soft link kind (`http-etag`, "same file",
  never "same operator"), and nginx's form is dated. Stored scans are read
  again once at startup. The previous level-2 list still earns.
- ETags as a return marker. Decoy version 3 answers the web decoys that
  return 200 with an ETag derived from the request, a canary of kind
  `etag`: a client that sends it back in `If-None-Match`, from any
  address, is a canary reuse.
- Reverse DNS of every source. Each node looks up the PTR names of the
  addresses that sent requests and keeps those that resolve back
  (`ip_names` source `rdns`), when first seen and when the source returns
  a day later. Shown on the IP page, in the `names` export column, and as
  the IP directory's new Name filter. `[enrichment] reverse_dns = false`
  turns it off.
```

- [ ] **Step 2: Roadmap.** Remove the four bullets "Host keys in the export", "ETags of scanned sources", "ETags as a return marker" and "Reverse DNS of every source" from "Small follow-ups".

- [ ] **Step 3: dataset.md**
  - In the `scans` example JSON add `"host_keys": [{"kind": "ssh-hostkey", "port": 22, "fingerprint": "SHA256:…", "detail": "ed25519 256"}],` before `"xml"`, and after the paragraph about level 2 add: "`host_keys`: what peephole read from the XML: `ssh-hostkey` (OpenSSH's `SHA256:` fingerprint), `tls-cert` (SHA-256 of the DER), `ja4x`, `hassh` (HASSH-server) and `http-etag` (the ETag as sent; for nginx's form the detail gives the file's modification date and size)." Update the sentence listing level-2 scripts to include `http-headers`.
  - In `names`: add an `rdns` example row and: "`rdns`: this node's reverse lookup of the address: a PTR name that resolves back to it (forward-confirmed). Each node looks up on its own, so two nodes' exports can differ here."
  - Where canary kinds are listed (search for `wp-session` or `mcp-session`), add `etag` (decoy version 3: the `ETag` header of the web decoys answering 200; found again in `If-None-Match`).

- [ ] **Step 4: README** ~line 40: "From level 2 they read the source's SSH host keys, TLS certificates and HTTP ETags, so sources that share one show up as linked."

- [ ] **Step 5: Commit**

```bash
git add CHANGELOG.md docs/roadmap.md docs/dataset.md README.md
git commit -m "Docs: host keys in the export, ETags, reverse DNS"
```

---

### Final verification (controller)

- [ ] `df -h .`; prune stale test binaries in `target/debug/deps` if low (keep the newest per name).
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test --lib` and `cargo test --test cluster` (and any other `tests/*.rs` that touch decoys, export or scans: `cargo test --tests`)
- [ ] One thorough whole-branch review on the most capable model; fix every finding, minors included.
