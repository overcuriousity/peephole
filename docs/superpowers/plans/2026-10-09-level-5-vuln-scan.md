# Level-5 Vulnerability Scan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a manually-purchased scan level 5 that runs nmap's `vuln` NSE category (minus `external`) on the level-3 port set, priced at 256× the level-1 price, offered under Lookup → actions.

**Architecture:** Extend the existing level system (bounds `1..=4` → `1..=5`) rather than special-casing. Level 5 shares level 4's concurrency budget and 4× timeout. A new cluster protocol version (8) gates level-5 grants to capable nodes. Spec: `docs/superpowers/specs/2026-10-09-level-5-vuln-scan-design.md`.

**Tech Stack:** Rust (askama templates, sqlx/SQLite, tokio), nmap.

## Global Constraints

- Level-5 argv is exactly: `-Pn -sS -sV -O -T3 --top-ports 1000 --traceroute --script "vuln and not external"` (plus per-run flags added by `complete()`).
- Level 5 is manual-buy only: classification rule weights stay 1..=4 (`src/classify/rules.rs` is NOT touched), so the automatic queue never produces level 5.
- Price ladder stays 4^(level−1): level 5 = 256× the level-1 price.
- Levels 4 and 5 share one concurrency budget (`scan.level4_max_share`) and the 4× timeout (`level_timeout_secs` already covers `level >= 4`).
- `PROTO_VERSION` 7 → 8; level-5 grants go only to claimants with `proto_max >= 8`. `ECONOMY_PROTO` stays 7.
- Verification after every task: `cargo test --locked` (or the narrow test named in the step), plus `cargo fmt --all -- --check` and `cargo clippy --all-targets --locked -- -D warnings` before each commit.
- Follow existing file idioms: doc comments on every public item, no inline code comments unless the neighboring style has them.

---

### Task 1: Level-5 nmap profile

**Files:**
- Modify: `src/scan/profiles.rs:13-30` (consts and `builtin`), `:253-368` (tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `pub const VULN_SCRIPTS: &str = "vuln and not external"`; `builtin(5, _)` → `Some` of the level-5 list (the `udp` flag is ignored, as at levels 1–3). Later tasks call `crate::scan::profiles::builtin(5, …)` via `Config::default_level_argv`.

- [ ] **Step 1: Write the failing test**

Add to `mod tests` in `src/scan/profiles.rs`:

```rust
    #[test]
    fn level_5_runs_the_vuln_category_without_external_lookups() {
        let argv = builtin(5, false).unwrap();
        assert_eq!(builtin(5, true).unwrap(), argv, "no UDP variant at level 5");
        let i = argv.iter().position(|a| a == "--script").unwrap();
        assert_eq!(argv[i + 1], "vuln and not external");
        assert!(argv.contains(&"--top-ports".to_string()));
        assert!(!argv.iter().any(|a| a == "-p-"), "the level-3 port set");
        let plain = cfg("");
        let line = command_line(&plain, 5, "203.0.113.7");
        assert!(args_ok(&line, 5), "{line}");
        assert!(!args_ok(&line, 4), "level 5's list is not level 4's");
    }
```

Also change the loop bound in `every_built_in_level_is_recognized_with_every_tunable_set` (line 257) from `for level in 1..=4u8` to `for level in 1..=5u8`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked --lib scan::profiles`
Expected: FAIL — `builtin(5, false)` returns `None` ("called `Option::unwrap()` on a `None` value"), and the extended loop fails at level 5.

- [ ] **Step 3: Implement the level-5 profile**

In `src/scan/profiles.rs`, after the `IDENTITY_SCRIPTS` const (line 23), add:

```rust
/// Level 5 runs the `vuln` category — checks that probe a service for a
/// known vulnerability — but not the ones that ask third parties
/// (`external`: whois, ASN and CVE-API lookups). Unlike every other level
/// it is deliberately intrusive; only an admin's bought scan reaches it,
/// never the automatic queue.
pub const VULN_SCRIPTS: &str = "vuln and not external";
```

Update the doc comment on `builtin` (line 26-27): "None for a level outside 1..=4." → "None for a level outside 1..=5."

Add the level-5 arm to `builtin`, after the level-4 arm (before `_ => return None`):

```rust
        5 => s(&[
            "-Pn",
            "-sS",
            "-sV",
            "-O",
            "-T3",
            "--top-ports",
            "1000",
            "--traceroute",
            "--script",
            VULN_SCRIPTS,
        ]),
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --locked --lib scan::profiles`
Expected: PASS (all profiles tests, including the extended loop).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/scan/profiles.rs
git commit -m "scan: level-5 profile runs the vuln scripts, minus external"
```

---

### Task 2: Extend the level bounds to 1..=5

**Files:**
- Modify: `src/scan/mod.rs:37-42` (`valid_level`), `:94-95` (`nmap_argv` doc), `:1423` (comment), `:1605-1624` (test)
- Modify: `src/config.rs:828-845` (validation), `:904-929` (`default_level_argv`), `:975-1058` (tests)
- Modify: `src/store/recorder.rs:425-430`, `:543-546`
- Modify: `src/store/data.rs:641-642`

**Interfaces:**
- Consumes: `builtin(5, _)` from Task 1.
- Produces: `valid_level(5) == Some(5)`; `Config::default_level_argv(5) -> Some(...)`; `MAX_SCAN_LEVEL = 5`. Everything downstream (buy form, enqueue, grant checks) accepts level 5 after this task.

- [ ] **Step 1: Update the failing tests first**

In `src/scan/mod.rs`, replace the test at line 1605-1624:

```rust
    /// Levels are 1..=5: nothing else gets an argv, nothing is truncated.
    #[test]
    fn levels_outside_1_to_5_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        for l in [0u8, 6, 255] {
            assert!(nmap_argv(l, &ip, &cfg, 1800).is_none(), "level {l}");
        }
        for (l, ok) in [
            (0, None),
            (1, Some(1)),
            (4, Some(4)),
            (5, Some(5)),
            (6, None),
            (260, None),
            (-1, None),
        ] {
            assert_eq!(valid_level(l), ok, "level {l}");
        }
    }
```

In `src/config.rs` test `levels_outside_the_presets_have_no_argv` (line 1053): change `for level in [0, 5, 9, 255]` to `for level in [0, 6, 9, 255]`.

In `src/config.rs` test `default_presets_are_non_intrusive` the loop stays `1..=4` (level 5 IS intrusive by design). Add after it:

```rust
    /// Level 5 is the exception: it runs the vuln category, minus the
    /// scripts that ask third parties. Only an admin's bought scan reaches
    /// it; the automatic queue's levels (rule weights) stay within 1..=4.
    #[test]
    fn level_5_is_intrusive_by_design() {
        let cfg: Config = toml::from_str("database_path = \"/x\"\ndata_dir = \"/x\"\n").unwrap();
        let argv = cfg.default_level_argv(5).unwrap();
        let i = argv.iter().position(|a| a == "--script").unwrap();
        assert_eq!(argv[i + 1], "vuln and not external");
        assert!(!argv.iter().any(|a| a == "-p-"), "the level-3 port set");
    }
```

Also change the loop at line 975 (`for level in 1..=4` asserting `-Pn`) to `for level in 1..=5`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --locked --lib -- scan::tests::levels_outside config::tests`
Expected: FAIL — level 5 has no argv yet (`valid_level(5)` is `None`, `default_level_argv(5)` is `None`).

- [ ] **Step 3: Extend the bounds**

`src/scan/mod.rs:37-42`:

```rust
/// A scan level as stored or granted, if it is one (1..=5). Anything else is
/// refused rather than truncated: `6 as u8`, or 260 truncated to 4, must
/// not pick a preset.
pub fn valid_level(level: i64) -> Option<u8> {
    u8::try_from(level).ok().filter(|l| (1..=5).contains(l))
}
```

`src/scan/mod.rs:95`: doc "None for a level outside 1..=4." → "None for a level outside 1..=5."
`src/scan/mod.rs:1423`: comment "Unreachable: acquire only hands out levels 1..=4." → "levels 1..=5".

`src/config.rs:828-834` — change the range and message:

```rust
        for (level, argv) in &s.level_argv {
            if !(1..=5).contains(level) {
                bail!("scan.level_argv: level {level} is out of range (1..=5)");
            }
```

`src/config.rs:843-845`:

```rust
        if !(1..=5).contains(&s.safety.single_request_max_level) {
            bail!("scan.single_request_max_level must be between 1 and 5");
        }
```

`src/config.rs` `default_level_argv` (921-929): change the bound to `if !(1..=5).contains(&level)`. Update its doc comment: the paragraph "None for a level outside 1..=4" → "None for a level outside 1..=5", and append to the "Non-intrusive by design" paragraph:

```
/// Level 5 is the one exception, and it is never queued automatically: a
/// bought scan runs the `vuln` scripts (`profiles::VULN_SCRIPTS`).
```

`src/store/recorder.rs:425` and `:544`: change both `if !(1..=4).contains(&level)` to `if !(1..=5).contains(&level)`.

`src/store/data.rs:641-642`:

```rust
/// Highest scan level (the nmap presets are 1..=5).
pub const MAX_SCAN_LEVEL: i64 = 5;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --locked --lib -- scan:: config:: store::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/scan/mod.rs src/config.rs src/store/recorder.rs src/store/data.rs
git commit -m "scan: accept level 5 everywhere levels are bounded"
```

---

### Task 3: Level 5 shares the heavy-scan budget, timeout and rate floor

**Files:**
- Modify: `src/scan/mod.rs:52-92` (`complete`), `:1303-1317` (`L4Slot`), `:1359-1406` (worker loop), `:1554-1583` (min-rate test), `:2581-2638` (share test)
- Modify: `src/scan/arbiter.rs:404-406`
- Modify: `src/scan/pace.rs:18-25`, `:35-59`, `:406-415` (comments and tests)

**Interfaces:**
- Consumes: level 5 accepted (Task 2).
- Produces: workers treat `job.level() >= 4` as "heavy": one shared slot counter, exclude list `vec![4, 5]` when at cap, `--min-rate` for levels 4 and 5.

- [ ] **Step 1: Update the tests first**

In `src/scan/mod.rs`, replace `min_rate_is_added_at_level_4_only` (1554-1583):

```rust
    /// --min-rate at levels 4 and 5 only, from the config, and an
    /// operator's own value is kept.
    #[test]
    fn min_rate_is_added_at_levels_4_and_5_only() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let cfg = config_with(dir.path(), "min_rate = 120\n");
        let after = |argv: &[String], flag: &str| {
            argv.iter()
                .position(|a| a == flag)
                .map(|i| argv[i + 1].clone())
        };
        for l in [4, 5] {
            let a = nmap_argv(l, &ip, &cfg, 3600).unwrap();
            assert_eq!(after(&a, "--min-rate").as_deref(), Some("120"), "level {l}");
        }
        for l in 1..=3 {
            assert!(
                !nmap_argv(l, &ip, &cfg, 1800)
                    .unwrap()
                    .iter()
                    .any(|a| a == "--min-rate")
            );
        }
        let cfg = config_with(
            dir.path(),
            "[scan.level_argv]\n4 = [\"-sS\", \"-p-\", \"--min-rate\", \"999\"]\n",
        );
        let a4 = nmap_argv(4, &ip, &cfg, 3600).unwrap();
        assert_eq!(a4.iter().filter(|a| *a == "--min-rate").count(), 1);
        assert_eq!(after(&a4, "--min-rate").as_deref(), Some("999"));
    }
```

In the same file, `counting_nmap` (2581-2596) detects heavy scans by ` -p- ` in argv; level 5 has no `-p-`. Extend the `case` pattern to also match the vuln selector, and update `level4_never_takes_more_than_its_share` (2598-2638) to mix levels 4 and 5:

```rust
    /// A fake nmap that records how many heavy scans (level 4 or 5: argv has
    /// -p- or the vuln selector) run at once, holding each for `secs`.
    fn counting_nmap(dir: &std::path::Path, secs: &str) -> PathBuf {
        let fake = fake_nmap(dir); // writes nmap.xml next to it
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nd=\"$(dirname \"$0\")\"\n\
                 case \" $* \" in *\" -p- \"*|*\" vuln and not external \"*) mkdir -p \"$d/l4\"; \
                 touch \"$d/l4/$$\"; \
                 ls \"$d/l4\" | wc -l >> \"$d/l4-seen\"; sleep {secs}; rm \"$d/l4/$$\";; esac\n\
                 cat \"$d/nmap.xml\"\n"
            ),
        )
        .unwrap();
        fake
    }

    /// With 2 workers at most one heavy scan (level 4 or 5) runs, the other
    /// worker keeps the shorter levels moving, and a queue of only heavy
    /// jobs still drains.
    #[tokio::test]
    async fn heavy_scans_never_take_more_than_their_share() {
        let dir = tempfile::tempdir().unwrap();
        let fake = counting_nmap(dir.path(), "1.5");
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (i, level) in [4, 5, 2, 2].into_iter().enumerate() {
            let ip = store
                .upsert_ip(format!("198.51.100.{}", 80 + i).parse().unwrap())
                .await
                .unwrap();
            store.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: 2,
            timeout_secs: 60,
        });
        let pool = tokio::spawn(run_workers(
            store.local(),
            cfg,
            p,
            fake,
            rx,
            crate::events::Notifier::new(),
            Classifier::builtin(),
        ));
        wait_for_scans(&store, 4).await;
        tx.send(true).unwrap();
        pool.await.unwrap();
        let seen = std::fs::read_to_string(dir.path().join("l4-seen")).unwrap();
        let max: u32 = seen
            .split_whitespace()
            .map(|n| n.parse::<u32>().unwrap())
            .max()
            .unwrap();
        assert_eq!(max, 1, "two heavy scans ran at once: {seen:?}");
    }
```

In `src/scan/pace.rs` tests, add after `level4_cap_is_half_the_workers_and_at_least_one`:

```rust
    #[test]
    fn level_5_gets_the_heavy_scan_timeout() {
        assert_eq!(level_timeout_secs(60, 3), 60);
        assert_eq!(level_timeout_secs(60, 4), 240);
        assert_eq!(level_timeout_secs(60, 5), 240);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --locked --lib -- scan::tests::min_rate scan::tests::heavy`
Expected: FAIL — level 5 gets no `--min-rate`, and two heavy scans (levels 4 and 5) run at once.

- [ ] **Step 3: Share the budget**

`src/scan/mod.rs` `complete()` (73-82): change `if level == 4` to `if level >= 4` and the comment to:

```rust
    // Levels 4 and 5 are the heavy scans: a floor on the send rate keeps
    // hosts that drop probes from slowing nmap's adaptive timing to a crawl.
```

Also update the doc on `complete` (line 52-53): "the rate floor of level 4" → "the rate floor of levels 4 and 5".

`src/scan/mod.rs` `L4Slot` (1303): comment "One running level-4 scan, counted while it lives." → "One running heavy scan (level 4 or 5), counted while it lives." Leave the struct name `L4Slot` unchanged (renaming ripples for no gain).

Worker loop (1359-1406): comment "Level-4 scans running now (see `L4Slot`)." → "Heavy scans (levels 4 and 5) running now (see `L4Slot`)."; then:

```rust
            let cap = pace::level4_cap(p.max_workers, cfg.scan.level4_max_share);
            let exclude: Vec<u8> = if running_l4.load(std::sync::atomic::Ordering::SeqCst) >= cap {
                vec![4, 5]
            } else {
                vec![]
            };
```

and line 1406:

```rust
            let l4 = (job.level() >= 4).then(|| L4Slot::take(&running_l4));
```

`src/scan/arbiter.rs:404`:

```rust
        let excluded: Vec<u8> = (1..=5u8)
            .filter(|l| claims.iter().all(|c| c.exclude.contains(l)))
            .collect();
```

`src/scan/pace.rs` doc updates only: `level4_cap` comment "Level-4 scans one scanner runs at once" → "Heavy scans (levels 4 and 5) one scanner runs at once"; `LEVEL4_TIMEOUT_FACTOR` comment "Level 4 scans every port with version, OS and script detection: it gets this many times the base limit." → "Level 4 scans every port with version, OS and script detection, and level 5 runs the vuln scripts: they get this many times the base limit."; `level_timeout_secs` doc "level 4 gets [`LEVEL4_TIMEOUT_FACTOR`] times `base`" → "levels 4 and 5 get [`LEVEL4_TIMEOUT_FACTOR`] times `base`".

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --locked --lib -- scan::`
Expected: PASS. Note: `level_timeout_secs` already applied the factor to `level >= 4`, so the new pace test passes without code change there — that is intended (it locks the behavior in).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/scan/mod.rs src/scan/arbiter.rs src/scan/pace.rs
git commit -m "scan: level 5 shares level 4's worker budget, timeout and rate floor"
```

---

### Task 4: Queue-order estimates cover level 5

**Files:**
- Modify: `src/scan/order.rs:20-90`, `:126-233` (tests)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Estimates(pub [f64; 5])`, index `level - 1`; `Estimates::DEFAULT = Estimates([5.0, 5.0, 5.0, 20.0, 20.0])`. `est()` and `ratio_sql()` map level 5 to its own estimate instead of clamping to level 4's.

- [ ] **Step 1: Update the tests first**

In `estimates_are_clamped` (141-148), the expected array becomes five elements (index 4 keeps the default 20.0 since no level-5 rows are given):

```rust
        assert_eq!(e.0, [FLOOR_MIN, 5.0, 5.0, CEIL_MIN, 20.0]);
```

In `levels_without_enough_jobs_use_the_defaults` (131-136), add after the existing asserts:

```rust
        assert_eq!(e.0[4], Estimates::DEFAULT.0[4]);
```

Add a new test after `short_jobs_first_but_waiting_long_jobs_catch_up`:

```rust
    #[test]
    fn level_5_has_its_own_estimate() {
        let e = Estimates::from_rows(&[(5, 9, Some(45.0))]);
        assert_eq!(e.0[4], 45.0);
        assert_eq!(e.ratio(5, 45.0), 2.0);
        // The SQL expression agrees.
        let sql = e.ratio_sql("j");
        assert!(sql.contains("WHEN 5 THEN 45.0000"), "{sql}");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --locked --lib scan::order`
Expected: FAIL — wrong array length / no level-5 estimate.

- [ ] **Step 3: Extend `Estimates`**

`src/scan/order.rs:20-25`:

```rust
/// Minutes a scan of each level keeps a worker busy; index `level - 1`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimates(pub [f64; 5]);

impl Estimates {
    pub const DEFAULT: Estimates = Estimates([5.0, 5.0, 5.0, 20.0, 20.0]);
```

`from_rows` (line 31): change the filter to `*i < 5`.

`est` (line 59-61):

```rust
    fn est(&self, level: u8) -> f64 {
        self.0[(level.clamp(1, 5) - 1) as usize]
    }
```

`ratio_sql` (line 71-76):

```rust
    pub fn ratio_sql(&self, alias: &str) -> String {
        let [a, b, c, d, e] = self.0;
        let est = format!(
            "(CASE {alias}.level WHEN 1 THEN {a:.4} WHEN 2 THEN {b:.4} \
             WHEN 3 THEN {c:.4} WHEN 4 THEN {d:.4} ELSE {e:.4} END)"
        );
        format!(
            "((MAX(0.0, (julianday('now') - julianday({alias}.queued_at)) * 1440.0) + {est}) / {est})"
        )
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --locked --lib scan::order`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/scan/order.rs
git commit -m "scan: queue-order estimates cover level 5"
```

---

### Task 5: Price level 5 and audit it

**Files:**
- Modify: `src/credits/jobs.rs:90-95`, `:267-273` (test)
- Modify: `src/credits/audit.rs:394`, `:557`, `:786`, `:953`

**Interfaces:**
- Consumes: level 5 accepted (Task 2).
- Produces: `level_factor(5) == 256` (callers: `src/admin/scan_buy.rs:104,202`, `src/scan/arbiter.rs:429` — all unchanged, they pick the factor up). Level-5 scans enter audit designation and audit-owed queries.

- [ ] **Step 1: Update the failing test**

`src/credits/jobs.rs` test `the_level_factor_is_four_to_the_level_minus_one` (267-273):

```rust
    #[test]
    fn the_level_factor_is_four_to_the_level_minus_one() {
        assert_eq!(level_factor(1), 1);
        assert_eq!(level_factor(2), 4);
        assert_eq!(level_factor(3), 16);
        assert_eq!(level_factor(4), 64);
        assert_eq!(level_factor(5), 256);
        assert_eq!(level_factor(9), 256, "clamped at the highest level");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked --lib credits::jobs`
Expected: FAIL — `level_factor(5)` is 64 (clamped at 4).

- [ ] **Step 3: Extend the clamp and the audit ranges**

`src/credits/jobs.rs:90-95`:

```rust
/// The factor a bought (manual) job's level scales its funding price by:
/// 4^(level-1) — level 1 at the scanner's price, level 4 at 64 and level 5
/// at 256 times it.
pub fn level_factor(level: i64) -> u32 {
    1u32.checked_shl(2 * level.clamp(1, 5) as u32 - 2)
        .unwrap_or(u32::MAX)
}
```

`src/credits/audit.rs`, four mechanical edits:
- line 394: `!(1..=4).contains(&level)` → `!(1..=5).contains(&level)`
- line 557: `AND s.level BETWEEN 1 AND 4` → `AND s.level BETWEEN 1 AND 5`
- line 786: `!(1..=4).contains(&level)` → `!(1..=5).contains(&level)`
- line 953: `AND s.level BETWEEN 1 AND 4` → `AND s.level BETWEEN 1 AND 5`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --locked --lib credits::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/credits/jobs.rs src/credits/audit.rs
git commit -m "credits: level 5 costs 256x and is audited like the other levels"
```

---

### Task 6: Cluster protocol 8 gates level-5 grants

**Files:**
- Modify: `src/cluster/rpc/proto.rs:5`, add `VULN_SCAN_PROTO`
- Modify: `src/scan/arbiter.rs:306-321` (`hand_out`), add `gate_level5`; tests

**Interfaces:**
- Consumes: level 5 accepted cluster-wide (Task 2's `MAX_SCAN_LEVEL`).
- Produces: `pub const VULN_SCAN_PROTO: u32 = 8` in `crate::cluster::rpc::proto`; `PROTO_VERSION = 8`. `hand_out` adds 5 to the exclusions of claimants whose member record announces `proto_max < VULN_SCAN_PROTO`.

Background for the implementer: old nodes refuse level-5 grants ("invalid scan level" via `valid_level` at `src/scan/mod.rs:786`) and ignore replicated level-5 jobs (`MAX_SCAN_LEVEL` at `src/store/data.rs:654`). Gating the grant keeps level-5 jobs queued for a capable scanner instead of bouncing off old ones. The wire formats (`Msg::Claim`, `Grant`) are unchanged — level already travels as `i64` and exclusions as `Vec<u8>` (compat test `claims_stay_compatible_across_versions` at `src/cluster/msg.rs:753` stays valid).

- [ ] **Step 1: Write the failing test**

In `src/scan/arbiter.rs` tests (near `claim_of`, line 1623), add:

```rust
    #[test]
    fn level_5_jobs_skip_claimants_that_predate_vuln_scan_proto() {
        let capable = crate::cluster::rpc::proto::VULN_SCAN_PROTO;
        let mut claims = vec![claim_of(id(1), &[]), claim_of(id(2), &[]), claim_of(id(3), &[5])];
        let protos: std::collections::HashMap<NodeId, u32> =
            [(id(1), capable - 1), (id(2), capable)].into_iter().collect();
        gate_level5(&mut claims, &protos);
        assert!(claims[0].exclude.contains(&5), "protocol {} excludes 5", capable - 1);
        assert!(!claims[1].exclude.contains(&5), "capable");
        assert_eq!(
            claims[2].exclude.iter().filter(|l| **l == 5).count(),
            1,
            "not pushed twice"
        );
    }
```

Check the test module's helpers first: `claim_of(id: NodeId, exclude: &[u8])` exists at line 1623; use whatever `id(n: u8) -> NodeId` helper the neighboring tests use (e.g. the one near line 1615) — if it is named differently, call that instead.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked --lib scan::arbiter`
Expected: FAIL — `gate_level5` does not exist (compile error).

- [ ] **Step 3: Implement the gate**

`src/cluster/rpc/proto.rs`: change `pub const PROTO_VERSION: u32 = 7;` to `8` and add after `ROUTED_PROTO`:

```rust
/// First version that knows scan level 5 (the `vuln` scripts). An arbiter
/// grants a level-5 job only to claimants announcing at least this version:
/// older nodes refuse the grant as an invalid scan level, so the job would
/// bounce instead of waiting for a capable scanner.
pub const VULN_SCAN_PROTO: u32 = 8;
```

`src/scan/arbiter.rs`: add near `Claimant` (after line 95):

```rust
/// Claimants that would refuse a level-5 grant (their build predates
/// `VULN_SCAN_PROTO`) get 5 among their exclusions, so a level-5 job waits
/// for a capable scanner. A claimant without a member record is not gated:
/// claims arrive from authenticated members only.
fn gate_level5(claims: &mut [Claimant], protos: &std::collections::HashMap<NodeId, u32>) {
    for c in claims.iter_mut() {
        if protos
            .get(&c.id)
            .is_some_and(|p| *p < crate::cluster::rpc::proto::VULN_SCAN_PROTO)
            && !c.exclude.contains(&5)
        {
            c.exclude.push(5);
        }
    }
}
```

In `hand_out` (306-321), gate between building `claims` and calling `round`:

```rust
        let mut claims: Vec<Claimant> = waiters
            .iter()
            .map(|(id, exclude, min_mc, _)| Claimant {
                id: *id,
                exclude: exclude.clone(),
                min_mc: *min_mc,
            })
            .collect();
        let protos = crate::cluster::members::all(&self.node.store)
            .await?
            .into_iter()
            .map(|m| (m.id, m.proto_max))
            .collect();
        gate_level5(&mut claims, &protos);
        let grants = self.round(&claims).await?;
```

(Verify the member row's field names against `src/cluster/members.rs:83-113` — the struct has `id: NodeId` and `proto_max: u32`. If `members::all` returns a different shape, adapt the `.map(...)` accordingly; `src/credits/audit.rs:782-790` shows a usage.)

- [ ] **Step 4: Run tests, and sweep for protocol-7 assumptions**

Run: `cargo test --locked --lib scan::arbiter cluster::`
Expected: PASS.

Then sweep for tests that pin the old version:

Run: `rg -n "PROTO_VERSION|proto_max: 7|, 7\)" tests/ src/ | rg -iv "ECONOMY_PROTO"`
Expected: review each hit; test data using `proto_max: 7` as "an economy-protocol member" (e.g. `src/credits/reach.rs:358`, `src/credits/pay.rs:811-812`) is still valid because `ECONOMY_PROTO` stays 7. Fix only anything asserting `PROTO_VERSION == 7` itself.

Run the full suite: `cargo test --locked`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/cluster/rpc/proto.rs src/scan/arbiter.rs
git commit -m "cluster: protocol 8; level-5 grants only to nodes that know level 5"
```

---

### Task 7: Offer level 5 in the admin UI

**Files:**
- Modify: `src/admin/scan_buy.rs:58-119` (`about`, `offers_for`), `:440-496` (tests)
- Modify: `src/admin/credits.rs:148-155`, `:447`, `:726-800` (tests)
- Modify: `src/admin/cluster.rs:275-284`
- Modify: `src/admin/probes.rs:82` (comment only)
- Modify: `templates/admin_cluster_credits.html:52`, `:55`

**Interfaces:**
- Consumes: `level_factor(5)` (Task 5), level 5 valid (Task 2).
- Produces: `offers_for` returns five `ScanOffer`s; `about(5)` describes the vuln scan; the Credits page scanner table has an L5 column. `templates/_actions.html` needs no change (it loops `a.scans`).

- [ ] **Step 1: Update the failing tests**

`src/admin/scan_buy.rs` `standalone_offers_are_free_and_a_fresh_result_stands` (line 444): `assert_eq!(offers.len(), 4);` → `assert_eq!(offers.len(), 5);`.

`an_offer_shows_its_job_on_the_way` (line 484-487): the expected vector becomes:

```rust
        assert_eq!(
            waiting(&offers),
            vec![(1, None), (2, None), (3, Some("queued")), (4, None), (5, None)]
        );
```

`src/admin/credits.rs` `each_level_shows_the_price_per_delivered_result` (726-747): add a fifth element to every 4-tuple — the rows become e.g. `(Some(20), [(1.0, t), (1.0, t), (1.0, t), (0.5, t), (1.0, t)])` (append `(1.0, t)` to each row; keep the existing per-column assertions, they index 0 and 3 and stay valid).

`the_page_shows_where_credits_come_from` (781-800): append `(1.0, Default::default())` as the fifth element of both arrays passed to `level_cells`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --locked --lib admin::`
Expected: FAIL — 4 offers, tuple arity errors in credits tests (after `LevelInputs` changes in Step 3; run again to confirm the offer-count failure first if you prefer).

- [ ] **Step 3: Extend the UI code**

`src/admin/scan_buy.rs` `about` (58-66):

```rust
/// What each level scans (`scan::profiles::builtin`).
fn about(level: u8) -> &'static str {
    match level {
        1 => "top 100 ports, light version detection",
        2 => "top 1000 ports, versions, OS, host keys and certificates",
        3 => "top 1000 ports, versions, OS, traceroute, safe scripts",
        4 => "every port, versions, OS, traceroute, safe scripts",
        _ => "top 1000 ports, versions, OS, traceroute, vulnerability scripts",
    }
}
```

`offers_for` (76-82): doc "The four levels' offers for `ip_id`." → "The five levels' offers for `ip_id`."; range `(1u8..=4)` → `(1u8..=5)`.

`src/admin/credits.rs`:
- line 148-149: doc "its weight and tally at levels 1 to 4" → "levels 1 to 5"; type `[(f64, crate::scan::weight::Tally); 4]` → `; 5]`.
- line 151: doc "Cells of the L1–L4 columns" → "L1–L5".
- line 155: `(0..4)` → `(0..5)`.
- line 447: `let levels = [1, 2, 3, 4].map(|l| {` → `[1, 2, 3, 4, 5]`.

`src/admin/cluster.rs:276`: `(1..=4)` → `(1..=5)`.

`src/admin/probes.rs:82`: comment "The four scan levels' offers (`admin::scan_buy`)." → "The scan levels' offers (`admin::scan_buy`)."

`templates/admin_cluster_credits.html`:
- line 52: `{% for l in 1..=4 %}` → `{% for l in 1..=5 %}`
- line 55: "L1 to L4: what one delivered result costs per level" → "L1 to L5: what one delivered result costs per level"

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --locked --lib admin::`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add src/admin/scan_buy.rs src/admin/credits.rs src/admin/cluster.rs src/admin/probes.rs templates/admin_cluster_credits.html
git commit -m "admin: offer a level-5 vulnerability scan on the Actions card"
```

---

### Task 8: Scrub test with vuln-script output

**Files:**
- Create: `tests/fixtures/nmap-vuln.xml`
- Modify: `src/scan/scrub.rs:125-243` (tests)

**Interfaces:**
- Consumes: `scrub()`'s existing API.
- Produces: proof that scanner identity inside `vuln` script output (table-structured `<elem>`/`<table>` output naming the scanner's address) is masked, and that `nmap_xml` parsing tolerates vuln `<script>` elements (they are ignored by the parser, kept in raw XML).

- [ ] **Step 1: Write the fixture and the failing test**

Create `tests/fixtures/nmap-vuln.xml` (a trimmed level-5 result; the scanner's own address `198.51.100.5` appears inside vuln output, as happens when a service banners the connecting host):

```xml
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -Pn -sS -sV -O -T3 --top-ports 1000 --traceroute --script &quot;vuln and not external&quot; --host-timeout 1710s --script-timeout 570s --min-rate 300 -oX - 203.0.113.7" start="1">
<host><address addr="203.0.113.7" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"/>
<script id="http-vuln-cve-2021-41773" output="VULNERABLE: Path traversal (CVE-2021-41773) — probe from 198.51.100.5 succeeded"><table><elem key="state">VULNERABLE</elem></table></script>
</port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>
```

Add to `mod tests` in `src/scan/scrub.rs`:

```rust
    #[test]
    fn vuln_script_output_is_scrubbed_and_still_parses() {
        let xml = std::fs::read("tests/fixtures/nmap-vuln.xml").unwrap();
        let (out, n) = scrub(&xml, &[ip("198.51.100.5")], &[]);
        assert_eq!(n, 1);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("probe from [scanner] succeeded"), "{text}");
        assert!(!text.contains("198.51.100.5"));
        // The vuln <script> elements are not parsed into ports, but the
        // ports themselves survive.
        let parsed = crate::scan::nmap_xml::parse_nmap_xml(text.as_bytes()).unwrap();
        assert_eq!(parsed.ports.len(), 2);
        assert_eq!(parsed.ports[0].port, 80);
    }
```

Check the exact signature of `parse_nmap_xml` in `src/scan/nmap_xml.rs` (it takes `&[u8]` and returns a result with a struct holding `ports: Vec<PortResult>` where `PortResult` has `port: u16`, per lines 12-90) and adjust field access to match.

- [ ] **Step 2: Run test to verify it fails (or passes immediately)**

Run: `cargo test --locked --lib scan::scrub`
Expected: this is a characterization test — scrub already handles arbitrary bytes, so it may pass on the first run. If it fails, the failure shows a real gap (e.g. the address glued to an em dash token): report it before changing scrub semantics; only adapt the fixture if the fixture itself is unrealistic.

- [ ] **Step 3: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets --locked -- -D warnings
git add tests/fixtures/nmap-vuln.xml src/scan/scrub.rs
git commit -m "scan: prove vuln-script output is scrubbed of scanner identity"
```

---

### Task 9: Docs and changelog

**Files:**
- Modify: `README.md:35-46`
- Modify: `docs/operations.md:291-293`, `:302-306`
- Modify: `docs/dataset.md:110`, `:159`
- Modify: `docs/cluster.md:237-240`
- Modify: `deploy/config.example.toml:139-147`
- Modify: `templates/admin_scans.html:9`, `:30`
- Modify: `CHANGELOG.md:6` (`## [Unreleased]`)

**Interfaces:**
- Consumes: all previous tasks (behavior is final).
- Produces: user-facing text that matches the implementation.

- [ ] **Step 1: Update the docs with these exact edits**

`README.md:35-43` — replace the Counter-scans bullet's two relevant sentences:

```markdown
- **Counter-scans** — rate-limited nmap scans in four levels that escalate by
  scope (more ports, `-sV`, `-O`, then safe discovery scripts), never by
  speed or aggressiveness; that rule governs the automatic counter-scans.
```

becomes (keep the surrounding text, change "in four levels" → "in four automatic levels" and, later in the bullet, replace "The admin can also buy a full counter-scan of level 1–4 from the cluster's cheapest scanner, four times the price per level." with):

```markdown
  The admin can also buy a full counter-scan of level 1–4 from the
  cluster's cheapest scanner, four times the price per level — or a level-5
  scan, which runs nmap's vulnerability scripts (never queued automatically).
```

`docs/operations.md:292-293`: "a scan times out after 30 minutes (level 4 after 2 hours)" → "a scan times out after 30 minutes (levels 4 and 5 after 2 hours)".

`docs/operations.md:302-306`: "The Actions card also sells a counter-scan of level 1–4: level 1 costs the cluster's cheapest scanner offer, each level above four times the previous." → "The Actions card also sells a counter-scan of level 1–5: level 1 costs the cluster's cheapest scanner offer, each level above four times the previous. Level 5 runs the `vuln` scripts (minus the ones that ask third parties) on the top 1000 ports and is sold only here — the automatic queue never reaches it."

`docs/dataset.md:110`: "Counter-scan level this request earned (0: none, 1 to 4)" stays as-is (automatic levels still top out at 4 — add nothing here). `docs/dataset.md:159`: "`level` 1 to 4 (more ports, service versions, OS detection, safe scripts)" → "`level` 1 to 4 for queued scans (more ports, service versions, OS detection, safe scripts); a bought scan may be level 5 (vulnerability scripts)".

`docs/cluster.md:237-240`: "The Actions card sells counter-scans the same way: the arbiter funds a bought (manual) job at the scanner's price times 4^(level−1)" — append after that sentence: "Level 5 (the vulnerability scripts) is granted only to members of protocol 8 and up; older members are never asked."

`deploy/config.example.toml:141-146`:
- "a scan times out after 30 min (level 4: 2 h)" → "(levels 4–5: 2 h)"
- `level4_max_share` comment "runs level 4 at once" → "runs levels 4 and 5 at once"
- `min_rate` comment "level 4 sends at least" → "levels 4 and 5 send at least"

`templates/admin_scans.html`:
- line 9: "({{ pace.timeout_min }} min, level 4: {{ pace.level4_timeout_min }} min)." → "({{ pace.timeout_min }} min, levels 4–5: {{ pace.level4_timeout_min }} min)."
- line 30: "At most {{ pace.level4_cap }} at once on level 4." → "At most {{ pace.level4_cap }} at once on levels 4 and 5."; "A scan times out after {{ pace.timeout_min }} min (level 4: {{ pace.level4_timeout_min }} min)" → "(levels 4–5: {{ pace.level4_timeout_min }} min)"

`CHANGELOG.md` under `## [Unreleased]`, add:

```markdown
### Added

- Scan level 5, sold on the Actions card at 256 times the level-1 price:
  nmap's `vuln` scripts (minus `external`) on the top 1000 ports. Only an
  admin's bought scan reaches it; the automatic queue stays within levels
  1–4. Level 5 shares level 4's worker budget and two-hour timeout, and is
  granted only to cluster members of protocol 8 and up.
```

- [ ] **Step 2: Verify deploy-check still passes**

Run: `bash tests/deploy-check.sh` (or note if it needs root; CI runs it with sudo. If it fails without root, run `cargo test --locked` instead and rely on CI for the deploy check.)
Expected: PASS.

- [ ] **Step 3: Full verification**

Run: `cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/operations.md docs/dataset.md docs/cluster.md deploy/config.example.toml templates/admin_scans.html CHANGELOG.md
git commit -m "docs: scan level 5 (vulnerability scripts, bought on the Actions card)"
```
