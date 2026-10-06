# Scan Scheduling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop L4 scans from starving the queue: cap L4 at half a node's workers, make L4 fast with `--min-rate`, order the queue by highest response ratio, and rebalance the nmap presets.

**Architecture:** The scanner counts its running L4 scans and, at the cap, names level 4 as excluded in its claim (`Msg::Claim { exclude_levels }`); the arbiter's pick honours it. A new `scan::order` module measures per-level durations and renders one SQL `ORDER BY` expression that the arbiter pick, the standalone pick and the scanner's arbiter order all share. Presets and `nmap_argv` gain the new flags, driven by three new `[scan]` keys.

**Tech Stack:** Rust, tokio, sqlx (SQLite), serde + ciborium (cluster messages), askama templates.

**Spec:** `docs/superpowers/specs/2026-10-06-scan-scheduling-design.md`

**Branch:** `ai-decoys` (PR #41). Commit there. No new branch, no new PR, no push unless asked.

## Global Constraints

- Workers: 0 (paused) or `2..=16`. Never 1.
- `scan.level4_max_share`: `0.0 < share ≤ 1.0`, default `0.5`. L4 cap = `max(1, floor(workers × share))`.
- `scan.min_rate`: `50..=5000`, default `300`. Added at level 4 only.
- `scan.level4_udp`: bool, default `false`.
- `scan.level4_timeout_factor` default `4` → `2`.
- Response ratio = `(waited_min + est_min) / est_min`; ties by `queued_at`, then `uid` (cluster) or `id` (standalone).
- Estimates: mean minutes of `done` + `failed` jobs over 7 days, per level, clamped to `[5, 720]`; fewer than 5 jobs → default `L1 5, L2 5, L3 5, L4 20`.
- Non-intrusive presets: no `-A`, no `-T4`/`-T5`, scripts only from the existing safelist expression.
- Level-ordered logic that does not change: `outranked_by`, full-queue eviction, cooldown, `Recorder::next_queued_job`.
- Tests: focused unit tests only (`cargo test --lib <module>`); no new multi-node e2e test.

## Deviations from the spec (deliberate, small)

- Estimate upper clamp is 720 min (the longest any scan can run, `MAX_RUN_SECS`), not each level's timeout: a finished job cannot exceed its timeout anyway, and the arbiter has no access to the scanner's pace.
- The Scans page shows the L4 share for this node only, in the pace note. Other nodes' shares are not in heartbeats.
- The spec's cluster e2e case is covered by a worker-pool unit test (standalone, real `run_workers`, fake nmap) plus arbiter unit tests.

## Review Focus

1. A node whose `settings` table holds `scan.max_workers = 1` (saved earlier through "Apply recommendation") must come up with 2 workers and keep its saved rate and timeout, not fall back to config defaults → test in Task 1.
2. An operator `scan.level_argv.4` that already sets `--min-rate` keeps its own value and gets no second one; levels 1–3 never get `--min-rate` → test in Task 3.
3. An old arbiter (unit `Claim` variant) receiving a new claim with `exclude_levels: [4]` must decode it as a claim, not error → test in Task 5.
4. A queue holding only L4 jobs on a 2-worker scanner: one L4 runs, the other worker idles (no errors, no busy loop of refusals), and every L4 job still finishes → test in Task 6.
5. Rows with `started_at` NULL or `finished_at` before `started_at` (clock skew across nodes) must not drag an estimate below the floor or produce NaN → test in Task 4.

---

### Task 1: Worker minimum and L4 cap in `pace`

**Files:**
- Modify: `src/scan/pace.rs` (constants near line 13, `validate` ~line 87, `load` ~line 133, `recommend` ~line 307, tests)

**Interfaces:**
- Produces: `pub const MIN_WORKERS: usize = 2;` and `pub fn level4_cap(workers: usize, share: f64) -> usize` in `crate::scan::pace`.

- [ ] **Step 1: Write the failing tests** (append inside `mod tests` in `src/scan/pace.rs`)

```rust
    #[test]
    fn one_worker_is_not_a_valid_pace() {
        let one = Pace { max_workers: 1, ..P };
        assert!(one.validate().unwrap_err().contains("0 or between 2"));
        assert!(Pace { max_workers: 0, ..P }.validate().is_ok(), "0 pauses");
        assert!(Pace { max_workers: 2, ..P }.validate().is_ok());
    }

    #[test]
    fn recommendations_never_go_below_two_workers() {
        let r = recommend(&m(0, 0, None), P, Others::default());
        assert_eq!(r.pace.max_workers, MIN_WORKERS);
    }

    #[test]
    fn level4_cap_is_half_the_workers_and_at_least_one() {
        assert_eq!(level4_cap(2, 0.5), 1);
        assert_eq!(level4_cap(3, 0.5), 1);
        assert_eq!(level4_cap(4, 0.5), 2);
        assert_eq!(level4_cap(16, 0.5), 8);
        assert_eq!(level4_cap(2, 0.1), 1, "never 0 while scanning");
        assert_eq!(level4_cap(2, 1.0), 2);
        assert_eq!(level4_cap(0, 0.5), 0, "paused");
    }

    /// Review focus 1: a stored 1 from before the minimum is raised to 2;
    /// the other saved values survive.
    #[tokio::test]
    async fn a_stored_single_worker_is_raised_not_reset() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        store.setting_set(KEY_WORKERS, "1").await.unwrap();
        store.setting_set(KEY_PER_HOUR, "11").await.unwrap();
        let c = crate::config::ScanConfig::default();
        let p = SharedPace::load(&store, &c).await.unwrap().get();
        assert_eq!(p.max_workers, 2);
        assert_eq!(p.max_scans_per_hour, 11);
    }
```

Also update the two existing assertions that expect 1 worker:
- In `other_scanners_count_toward_capacity_and_the_need_is_split_evenly`: `assert_eq!(r.pace.max_workers, 1);` → `assert_eq!(r.pace.max_workers, MIN_WORKERS);`
- In `idle_queue_recommends_the_minimum`: `max_workers: 1,` → `max_workers: MIN_WORKERS,`

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib scan::pace`
Expected: compile error (`MIN_WORKERS`, `level4_cap` not found).

- [ ] **Step 3: Implement**

Below `MAX_WORKERS`:

```rust
/// Fewest workers a scanning node runs: one may run a level-4 scan while
/// the other keeps the shorter levels moving (0 still pauses).
pub const MIN_WORKERS: usize = 2;

/// Level-4 scans one scanner runs at once: `share` of its workers, rounded
/// down, but at least one while it scans at all.
pub fn level4_cap(workers: usize, share: f64) -> usize {
    if workers == 0 {
        return 0;
    }
    ((workers as f64 * share).floor() as usize).clamp(1, workers)
}
```

In `validate`, replace the workers check:

```rust
        if self.max_workers != 0 && !(MIN_WORKERS..=MAX_WORKERS).contains(&self.max_workers) {
            return Err(format!(
                "workers must be 0 or between {MIN_WORKERS} and {MAX_WORKERS}"
            ));
        }
```

In `load`, right after the `KEY_WORKERS` block:

```rust
        // Saved before the minimum existed (e.g. an applied recommendation).
        if p.max_workers == 1 {
            p.max_workers = MIN_WORKERS;
        }
```

In `recommend`, change the workers clamp `.clamp(1, MAX_WORKERS)` → `.clamp(MIN_WORKERS, MAX_WORKERS)`, and in its doc comment "never below one scan per hour and one worker" → "never below one scan per hour and [`MIN_WORKERS`] workers".

- [ ] **Step 4: Run tests**

Run: `cargo test --lib scan::pace`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/scan/pace.rs
git commit -m "Pace: at least 2 workers, level-4 cap helper"
```

---

### Task 2: New `[scan]` keys and config validation

**Files:**
- Modify: `src/config.rs` (`ScanConfig` ~line 293, defaults ~line 436, `Default for ScanConfig`, `OPTIONAL_KEYS`, validation ~line 660, tests)
- Modify: `deploy/config.example.toml` (`[scan]` block, lines ~118–120)

**Interfaces:**
- Consumes: `crate::scan::pace::{MIN_WORKERS, MAX_WORKERS}` (Task 1).
- Produces: `ScanConfig { level4_max_share: f64, min_rate: u32, level4_udp: bool, .. }`; `pub const MIN_RATE: u32 = 50; pub const MAX_RATE: u32 = 5000;` in `crate::config`.

- [ ] **Step 1: Write the failing tests** (in `mod tests` of `src/config.rs`; the module already has a helper that loads TOML — reuse the pattern of the test near line 994 that asserts `cfg.scan.max_workers == 2`. If that helper is named differently, use the same `toml::from_str::<Config>` + `validate` path the neighbouring tests use.)

```rust
    #[test]
    fn scheduling_keys_have_defaults() {
        let s = ScanConfig::default();
        assert_eq!(s.level4_max_share, 0.5);
        assert_eq!(s.min_rate, 300);
        assert!(!s.level4_udp);
        assert_eq!(s.level4_timeout_factor, 2);
    }
```

And the rejected values. `mod tests` already has `fn parse(text) -> anyhow::Result<Config>` (deserialize + `validate`) and `const BASE` (~line 1027); a scanner-only config needs no webauthn or maxmind. Add this helper next to them:

```rust
    /// A scanner-only config with `extra` under `[scan]`.
    fn with_scan(extra: &str) -> anyhow::Result<Config> {
        parse(&format!(
            "{BASE}[roles]\nlistener = false\nweb = false\n[scan]\n{extra}\n"
        ))
    }
```

```rust
    #[test]
    fn scheduling_keys_are_validated() {
        let err = |extra: &str| format!("{:#}", with_scan(extra).unwrap_err());
        assert!(err("max_workers = 1").contains("scan.max_workers must be between 2"));
        assert!(err("level4_max_share = 0.0").contains("level4_max_share"));
        assert!(err("level4_max_share = 1.5").contains("level4_max_share"));
        assert!(err("min_rate = 10").contains("scan.min_rate"));
        assert!(err("min_rate = 9000").contains("scan.min_rate"));
        assert!(with_scan("max_workers = 2\nlevel4_max_share = 1.0\nmin_rate = 50").is_ok());
    }
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib config::tests::scheduling`
Expected: compile error (unknown fields).

- [ ] **Step 3: Implement**

In `ScanConfig`, after `level4_timeout_factor`:

```rust
    /// Share of `max_workers` that may run level-4 scans at once (rounded
    /// down, at least one), so shorter levels never wait behind them.
    #[serde(default = "default_level4_share")]
    pub level4_max_share: f64,
    /// nmap `--min-rate` (packets per second) for level 4, so hosts that
    /// drop probes cannot stretch a full-range scan for hours. Per node: a
    /// scanner behind a home router may want less.
    #[serde(default = "default_min_rate")]
    pub min_rate: u32,
    /// Level 4 also scans the top 50 UDP ports.
    #[serde(default)]
    pub level4_udp: bool,
```

Defaults (next to `default_level4_timeout_factor`, which now returns `2`):

```rust
pub const MIN_RATE: u32 = 50;
pub const MAX_RATE: u32 = 5000;

fn default_level4_timeout_factor() -> u32 {
    2
}
fn default_level4_share() -> f64 {
    0.5
}
fn default_min_rate() -> u32 {
    300
}
```

Fix the `default_timeout` comment ("Full-range levels … need well over 15 min") → `// Base limit; level 4 gets level4_timeout_factor times this.`

`Default for ScanConfig`: add `level4_max_share: default_level4_share(), min_rate: default_min_rate(), level4_udp: false,`.

`OPTIONAL_KEYS`: change `("scan", "level4_timeout_factor", "4")` → `"2"`, and add after it:

```rust
    ("scan", "level4_max_share", "0.5"),
    ("scan", "min_rate", "300"),
    ("scan", "level4_udp", "false"),
```

Validation: replace the `max_workers` check and add the new ones after the `level4_timeout_factor` check:

```rust
        if !(crate::scan::pace::MIN_WORKERS..=crate::scan::pace::MAX_WORKERS)
            .contains(&s.max_workers)
        {
            bail!(
                "scan.max_workers must be between {} and {}",
                crate::scan::pace::MIN_WORKERS,
                crate::scan::pace::MAX_WORKERS
            );
        }
```

```rust
        if !(s.level4_max_share > 0.0 && s.level4_max_share <= 1.0) {
            bail!("scan.level4_max_share must be above 0 and at most 1");
        }
        if !(MIN_RATE..=MAX_RATE).contains(&s.min_rate) {
            bail!("scan.min_rate must be between {MIN_RATE} and {MAX_RATE}");
        }
```

(`level4_max_share > 0.0 && <= 1.0` is false for NaN, so NaN is rejected too.)

`deploy/config.example.toml`: replace the `level4_timeout_factor = 4` line and add below it:

```toml
level4_timeout_factor = 2  # level 4 (all ports, -sV -O, scripts) gets this many times timeout_secs, at most 12 h
level4_max_share = 0.5     # at most this share of max_workers runs level 4 at once (at least one)
min_rate = 300             # level 4 sends at least this many probes per second (--min-rate);
#                            lower it on a node behind a home router
level4_udp = false         # level 4 also scans the top 50 UDP ports
```

and change the `max_workers` comment to `# concurrent nmap subprocesses (2–16)`. In the comment block "Default scans are non-intrusive: … timing capped at -T3." append: ` Level 4 sets --min-rate (min_rate above).`

- [ ] **Step 4: Run tests**

Run: `cargo test --lib config`
Expected: all pass. If an existing test builds a config with `max_workers = 1`, change it to `2`.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs deploy/config.example.toml
git commit -m "Config: level4_max_share, min_rate, level4_udp; 2 workers minimum"
```

---

### Task 3: Presets and `nmap_argv`

**Files:**
- Modify: `src/config.rs` (`default_level_argv` ~line 776 and its tests ~line 861–1000)
- Modify: `src/scan/mod.rs` (`nmap_argv` ~line 46, tests ~line 1010)

**Interfaces:**
- Consumes: `ScanConfig.min_rate`, `ScanConfig.level4_udp` (Task 2).
- Produces: `pub const UDP_TOP50: &str` in `crate::config`.

- [ ] **Step 1: Write the failing tests**

In `src/config.rs` tests, next to the existing preset tests (uses `with_scan` from Task 2):

```rust
    #[test]
    fn rebalanced_presets() {
        let cfg = with_scan("").unwrap();
        let argv = |l| cfg.default_level_argv(l).unwrap();
        let has = |l, f: &str| argv(l).iter().any(|a| a == f);
        assert!(!has(1, "-T2") && has(1, "-T3"), "{:?}", argv(1));
        assert!(has(1, "--version-light") && has(1, "-sV"));
        assert!(!has(1, "-O"));
        assert!(!has(2, "--traceroute"));
        assert!(has(3, "--traceroute") && has(4, "--traceroute"));
        let a4 = argv(4);
        let after = |f: &str| a4.iter().position(|a| a == f).map(|i| a4[i + 1].clone());
        assert_eq!(after("--max-retries").as_deref(), Some("1"));
        assert!(has(4, "-p-") && !has(4, "-sU"), "UDP off by default");
    }

    #[test]
    fn level4_udp_scans_all_tcp_and_top_udp() {
        let cfg = with_scan("level4_udp = true").unwrap();
        let a4 = cfg.default_level_argv(4).unwrap();
        assert!(a4.iter().any(|a| a == "-sU") && a4.iter().any(|a| a == "-sS"));
        assert!(!a4.iter().any(|a| a == "-p-"));
        let p = a4.iter().position(|a| a == "-p").map(|i| a4[i + 1].clone()).unwrap();
        assert_eq!(p, format!("T:1-65535,U:{UDP_TOP50}"));
        assert_eq!(UDP_TOP50.split(',').count(), 50);
    }
```

The existing test around line 921 ("OS detection from level 2 up; only level 4 scans all ports") must keep passing unchanged.

In `src/scan/mod.rs` tests:

```rust
    /// Review focus 2: --min-rate at level 4 only, from the config, and an
    /// operator's own value is kept.
    #[test]
    fn min_rate_is_added_at_level_4_only() {
        let dir = tempfile::tempdir().unwrap();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let cfg = config_with(dir.path(), "min_rate = 120\n");
        let after = |argv: &[String], flag: &str| {
            argv.iter().position(|a| a == flag).map(|i| argv[i + 1].clone())
        };
        let a4 = nmap_argv(4, &ip, &cfg, 3600).unwrap();
        assert_eq!(after(&a4, "--min-rate").as_deref(), Some("120"));
        for l in 1..=3 {
            assert!(!nmap_argv(l, &ip, &cfg, 1800).unwrap().iter().any(|a| a == "--min-rate"));
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

(`config_with` puts its argument under `[scan]`, so `[scan.level_argv]` after it is valid TOML, as the existing `--host-timeout` test shows.)

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib -- config::tests::rebalanced config::tests::level4_udp scan::tests::min_rate`
Expected: FAIL / compile error (`UDP_TOP50`).

- [ ] **Step 3: Implement**

In `src/config.rs`, above `impl Config` (or next to `default_level_argv`):

```rust
/// nmap's 50 most frequent UDP ports (`nmap-services` frequency order),
/// for level 4 with `scan.level4_udp`.
pub const UDP_TOP50: &str = "631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,\
4500,514,49152,162,69,5353,111,49154,1701,998,996,997,999,3283,49153,1812,136,2222,2049,\
32768,5060,1025,1433,3456,80,20031,1026,7,1646,1645,593,518,2048,626,1027";
```

Rewrite the preset `match` in `default_level_argv` to build owned vectors (the UDP variant needs a formatted string):

```rust
        let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<String>>();
        let argv = match level {
            1 => s(&["-Pn", "-sS", "-sV", "--version-light", "-T3", "--top-ports", "100"]),
            2 => s(&[
                "-Pn", "-sS", "-sV", "-O", "-T3", "--top-ports", "1000",
                "--script", IDENTITY_SCRIPTS,
            ]),
            3 => s(&[
                "-Pn", "-sS", "-sV", "-O", "-T3", "--top-ports", "1000",
                "--traceroute", "--script", SCRIPTS,
            ]),
            4 => {
                let mut v = s(&["-Pn", "-sS"]);
                if self.scan.level4_udp {
                    v.push("-sU".into());
                    v.push("-p".into());
                    v.push(format!("T:1-65535,U:{UDP_TOP50}"));
                } else {
                    v.push("-p-".into());
                }
                v.extend(s(&[
                    "-sV", "-O", "-T3", "--max-retries", "1", "--traceroute",
                    "--script", SCRIPTS,
                ]));
                v
            }
            _ => return None,
        };
        Some(argv)
```

Update the doc comment of `default_level_argv`: replace "timing capped at `-T3`" with "timing template capped at `-T3`; level 4 also gets `--min-rate` (see `scan::nmap_argv`) so hosts that drop probes cannot stretch a full-range scan".

In `src/scan/mod.rs` `nmap_argv`, after the `--script-timeout` block and before the `-6` block:

```rust
    // Level 4 scans every port: a floor on the send rate keeps hosts that
    // drop probes from slowing nmap's adaptive timing to a crawl.
    if level == 4 && !argv.iter().any(|a| a == "--min-rate" || a.starts_with("--min-rate=")) {
        argv.push("--min-rate".into());
        argv.push(cfg.scan.min_rate.to_string());
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test --lib config && cargo test --lib scan::tests`
Expected: all pass, including the existing non-intrusive preset tests.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs src/scan/mod.rs
git commit -m "Presets: L1 at -T3 with service names, traceroute at L3/L4, L4 min-rate and optional UDP"
```

---

### Task 4: `scan::order` — duration estimates and the response-ratio order

**Files:**
- Create: `src/scan/order.rs`
- Modify: `src/scan/mod.rs:1-8` (add `pub mod order;`)

**Interfaces:**
- Produces (all in `crate::scan::order`):
  - `pub struct Estimates(pub [f64; 4])` — minutes, index `level - 1`; `Copy`, `Debug`, `PartialEq`.
  - `impl Estimates { pub const DEFAULT: Estimates; pub fn from_rows(rows: &[(i64, i64, Option<f64>)]) -> Self; pub async fn measure(pool: &sqlx::SqlitePool) -> anyhow::Result<Self>; pub fn ratio(&self, level: u8, waited_min: f64) -> f64; pub fn ratio_sql(&self, alias: &str) -> String; pub fn order_by(&self, alias: &str, tie: &str) -> String }`
  - `pub struct Cached` with `pub fn new() -> Self` (also `Default`) and `pub async fn get(&self, pool: &sqlx::SqlitePool) -> Estimates`.

- [ ] **Step 1: Write the module with its tests first (tests fail to compile until the bodies exist; write the tests, then the code in Step 3)**

Tests at the bottom of `src/scan/order.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_without_enough_jobs_use_the_defaults() {
        let e = Estimates::from_rows(&[(1, 4, Some(30.0)), (4, 9, Some(13.0))]);
        assert_eq!(e.0[0], 5.0, "4 jobs are too few");
        assert_eq!(e.0[3], 13.0);
        assert_eq!(e.0[1], Estimates::DEFAULT.0[1]);
    }

    /// Review focus 5: NULL averages and skewed (negative) durations clamp
    /// to the floor; nothing is NaN.
    #[test]
    fn estimates_are_clamped() {
        let e = Estimates::from_rows(&[
            (1, 50, Some(-3.0)),
            (2, 50, None),
            (3, 50, Some(f64::NAN)),
            (4, 50, Some(10_000.0)),
        ]);
        assert_eq!(e.0, [FLOOR_MIN, 5.0, 5.0, CEIL_MIN]);
    }

    #[test]
    fn short_jobs_first_but_waiting_long_jobs_catch_up() {
        let e = Estimates::DEFAULT; // L2 5 min, L4 20 min
        assert!(e.ratio(2, 5.0) > e.ratio(4, 10.0));
        assert!(e.ratio(4, 60.0) > e.ratio(2, 5.0));
        assert_eq!(e.ratio(4, 40.0), e.ratio(2, 10.0));
    }

    /// The SQL expression orders rows exactly like `ratio`.
    #[tokio::test]
    async fn sql_order_matches_ratio() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mut ids = vec![];
        for (level, mins) in [(4, 10), (2, 5), (4, 60), (1, 1)] {
            let ip = store
                .upsert_ip(format!("203.0.113.{}", 10 + ids.len()).parse().unwrap())
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at)
                 VALUES (?, ?, 'queued', datetime('now', ?))",
            )
            .bind(ip.id)
            .bind(level)
            .bind(format!("-{mins} minutes"))
            .execute(&store.pool)
            .await
            .unwrap();
            ids.push((level, mins));
        }
        let e = Estimates::DEFAULT;
        let sql = format!(
            "SELECT j.level FROM scan_jobs j WHERE j.status = 'queued' ORDER BY {}",
            e.order_by("j", "j.id")
        );
        let got: Vec<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_all(&store.pool)
            .await
            .unwrap();
        // ratios: L4/60 → 4.0, L2/5 → 2.0, L4/10 → 1.5, L1/1 → 1.2
        assert_eq!(got, vec![4, 2, 4, 1]);
    }

    #[tokio::test]
    async fn measure_reads_done_and_failed_jobs_of_the_last_week() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = store.upsert_ip("203.0.113.40".parse().unwrap()).await.unwrap();
        for (status, mins, age_days) in [
            ("done", 10, 1), ("done", 20, 1), ("failed", 30, 1), ("done", 20, 1),
            ("failed", 20, 1), ("done", 999, 30), ("refused", 999, 1),
        ] {
            sqlx::query(
                "INSERT INTO scan_jobs (ip_id, level, status, queued_at, started_at, finished_at)
                 VALUES (?1, 4, ?2, datetime('now', ?3), datetime('now', ?3),
                         datetime('now', ?3, ?4))",
            )
            .bind(ip.id)
            .bind(status)
            .bind(format!("-{age_days} days"))
            .bind(format!("+{mins} minutes"))
            .execute(&store.pool)
            .await
            .unwrap();
        }
        let e = Estimates::measure(&store.pool).await.unwrap();
        assert!((e.0[3] - 20.0).abs() < 0.01, "{e:?}"); // (10+20+30+20+20)/5
        assert_eq!(e.0[0], Estimates::DEFAULT.0[0]);
    }
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib scan::order`
Expected: compile errors (items missing).

- [ ] **Step 3: Implement** (top of `src/scan/order.rs`)

```rust
//! Queue order: highest response ratio next. A job's priority is
//! `(minutes waited + estimate) / estimate`, where the estimate is how long
//! a scan of its level keeps a worker busy. Short jobs go first while
//! everything is fresh; a waiting long job's priority keeps rising, so no
//! level starves. Every node measures the estimates from its replicated
//! `scan_jobs`, so arbiters and scanners agree closely (order is a
//! preference, not a correctness property).
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Lowest estimate: keeps a 30-second level from outranking everything.
pub const FLOOR_MIN: f64 = 5.0;
/// Highest estimate: the longest any scan may run (`pace::MAX_RUN_SECS`).
pub const CEIL_MIN: f64 = (super::pace::MAX_RUN_SECS / 60) as f64;
/// Finished jobs of a level before its measured mean replaces the default.
const MIN_SAMPLE: i64 = 5;
/// How often [`Cached`] re-measures.
const REFRESH: Duration = Duration::from_secs(60);

/// Minutes a scan of each level keeps a worker busy; index `level - 1`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimates(pub [f64; 4]);

impl Estimates {
    pub const DEFAULT: Estimates = Estimates([5.0, 5.0, 5.0, 20.0]);

    /// From `(level, jobs, mean minutes)` rows.
    pub fn from_rows(rows: &[(i64, i64, Option<f64>)]) -> Self {
        let mut e = Self::DEFAULT;
        for &(level, n, mean) in rows {
            let Some(i) = usize::try_from(level - 1).ok().filter(|i| *i < 4) else {
                continue;
            };
            if n < MIN_SAMPLE {
                continue;
            }
            let m = mean.filter(|m| m.is_finite()).unwrap_or(FLOOR_MIN);
            e.0[i] = m.clamp(FLOOR_MIN, CEIL_MIN);
        }
        e
    }

    /// Mean worker time per level of the jobs that finished or failed in
    /// the last 7 days.
    pub async fn measure(pool: &sqlx::SqlitePool) -> anyhow::Result<Self> {
        let rows: Vec<(i64, i64, Option<f64>)> = sqlx::query_as(
            "SELECT level, COUNT(*),
                    AVG((julianday(finished_at) - julianday(started_at)) * 1440.0)
             FROM scan_jobs
             WHERE status IN ('done', 'failed') AND started_at IS NOT NULL
               AND finished_at > datetime('now', '-7 days')
             GROUP BY level",
        )
        .fetch_all(pool)
        .await?;
        Ok(Self::from_rows(&rows))
    }

    fn est(&self, level: u8) -> f64 {
        self.0[(level.clamp(1, 4) - 1) as usize]
    }

    /// Response ratio of a job of `level` that has waited `waited_min`.
    pub fn ratio(&self, level: u8, waited_min: f64) -> f64 {
        let e = self.est(level);
        (waited_min.max(0.0) + e) / e
    }

    /// SQL expression for the response ratio of the `scan_jobs` row `alias`.
    /// The estimates are our own floats, so they are inlined, not bound.
    pub fn ratio_sql(&self, alias: &str) -> String {
        let [a, b, c, d] = self.0;
        let est = format!(
            "(CASE {alias}.level WHEN 1 THEN {a:.4} WHEN 2 THEN {b:.4} \
             WHEN 3 THEN {c:.4} ELSE {d:.4} END)"
        );
        format!(
            "((MAX(0.0, (julianday('now') - julianday({alias}.queued_at)) * 1440.0) + {est}) / {est})"
        )
    }

    /// `ORDER BY` body: highest ratio first, then `queued_at`, then `tie`
    /// (`j.uid` in a cluster, `j.id` standalone).
    pub fn order_by(&self, alias: &str, tie: &str) -> String {
        format!(
            "{} DESC, {alias}.queued_at ASC, {tie} ASC",
            self.ratio_sql(alias)
        )
    }
}

/// [`Estimates`] re-measured at most once per [`REFRESH`]. A failed
/// measurement keeps the last value.
pub struct Cached(Mutex<Option<(Instant, Estimates)>>);

impl Default for Cached {
    fn default() -> Self {
        Self::new()
    }
}

impl Cached {
    pub fn new() -> Self {
        Self(Mutex::new(None))
    }

    pub async fn get(&self, pool: &sqlx::SqlitePool) -> Estimates {
        let cur = *self.0.lock().unwrap();
        if let Some((at, e)) = cur
            && at.elapsed() < REFRESH
        {
            return e;
        }
        let e = match Estimates::measure(pool).await {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(?err, "measuring scan durations failed");
                cur.map(|(_, e)| e).unwrap_or(Estimates::DEFAULT)
            }
        };
        *self.0.lock().unwrap() = Some((Instant::now(), e));
        e
    }
}
```

Note `MAX(0.0, x)` with two arguments is SQLite's scalar max, not the aggregate. In `src/scan/mod.rs` add `pub mod order;` between `pub mod nmap_xml;` and `pub mod pace;`.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib scan::order`
Expected: all 5 pass.

- [ ] **Step 5: Commit**

```bash
git add src/scan/order.rs src/scan/mod.rs
git commit -m "Scan order: per-level duration estimates and response-ratio ORDER BY"
```

---

### Task 5: Claim carries excluded levels; arbiter honours them and orders by response ratio

**Files:**
- Modify: `src/cluster/msg.rs:48-53` (variant) and its tests (~line 476)
- Modify: `src/scan/arbiter.rs` (struct fields ~line 37, `handle` ~line 125, `claim` ~line 149, `hand_out` ~line 178, `next_job` ~line 200, `next_job_skipping` ~line 248, tests)
- Modify: `src/scan/mod.rs:418` (only to keep it compiling: `Msg::Claim { exclude_levels: vec![] }`; Task 6 fills it)

**Interfaces:**
- Consumes: `crate::scan::order::{Cached, Estimates}` (Task 4).
- Produces: `Msg::Claim { exclude_levels: Vec<u8> }`; `Arbiter::next_job(&self, scanner: NodeId, exclude: &[u8]) -> Result<Option<Grant>>`.

- [ ] **Step 1: Write the failing tests**

In `src/cluster/msg.rs` `mod tests`:

```rust
    /// The claim as nodes before `exclude_levels` know it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "m", rename_all = "snake_case")]
    enum OldMsg {
        Claim,
    }

    /// Mixed versions: an empty exclusion encodes exactly like the old
    /// unit claim, each side decodes the other's claim, and (review focus
    /// 3) an old node decodes a claim that carries exclusions.
    #[test]
    fn claims_stay_compatible_across_versions() {
        use crate::cluster::rpc::cbor::{decode, encode};
        let new_empty = Msg::Claim { exclude_levels: vec![] };
        assert_eq!(encode(&new_empty).unwrap(), encode(&OldMsg::Claim).unwrap());
        assert_eq!(decode::<Msg>(&encode(&OldMsg::Claim).unwrap()).unwrap(), new_empty);
        let excl = Msg::Claim { exclude_levels: vec![4] };
        assert_eq!(decode::<Msg>(&encode(&excl).unwrap()).unwrap(), excl);
        assert_eq!(decode::<OldMsg>(&encode(&excl).unwrap()).unwrap(), OldMsg::Claim);
    }
```

Change the existing `msg: Msg::Claim,` in `messages_from_the_future_are_not_fresh` to `msg: Msg::Claim { exclude_levels: vec![] },`.

In `src/scan/arbiter.rs` `mod tests`:

```rust
    /// A scanner at its level-4 share is offered no level-4 job, however
    /// long it has waited (unlike the weight skips).
    #[tokio::test]
    async fn excluded_levels_are_never_granted() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        let scanner = Identity::generate().unwrap().id;
        let a = store.upsert_ip("203.0.113.90".parse().unwrap()).await.unwrap();
        let b = store.upsert_ip("203.0.113.91".parse().unwrap()).await.unwrap();
        rec.enqueue_scan(a.id, 4, 24).await.unwrap();
        rec.enqueue_scan(b.id, 2, 24).await.unwrap();
        sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', '-3 hours') WHERE level = 4")
            .execute(&store.pool)
            .await
            .unwrap();
        let g = arbiter.next_job(scanner, &[4]).await.unwrap().unwrap();
        assert_eq!(g.level, 2);
        assert!(arbiter.next_job(scanner, &[4]).await.unwrap().is_none());
        assert_eq!(arbiter.next_job(scanner, &[]).await.unwrap().unwrap().level, 4);
    }

    /// Highest response ratio first: a fresher short job beats a younger
    /// long one; a long job that has waited long enough goes first.
    #[tokio::test]
    async fn jobs_are_granted_by_response_ratio() {
        let dir = tempfile::tempdir().unwrap();
        let (node, arbiter, store, _tx) = setup(dir.path()).await;
        let rec = Recorder::Cluster(node.clone());
        let scanner = Identity::generate().unwrap().id;
        let a = store.upsert_ip("203.0.113.92".parse().unwrap()).await.unwrap();
        let b = store.upsert_ip("203.0.113.93".parse().unwrap()).await.unwrap();
        rec.enqueue_scan(a.id, 4, 24).await.unwrap();
        rec.enqueue_scan(b.id, 2, 24).await.unwrap();
        let age = |level: i64, mins: i64| {
            let pool = store.pool.clone();
            async move {
                sqlx::query("UPDATE scan_jobs SET queued_at = datetime('now', ?) WHERE level = ?")
                    .bind(format!("-{mins} minutes"))
                    .bind(level)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        };
        age(4, 10).await; // ratio 1.5 with the default 20-min estimate
        age(2, 5).await; // ratio 2.0
        let g = arbiter.next_job(scanner, &[]).await.unwrap().unwrap();
        assert_eq!(g.level, 2);
    }
```

Replace every existing `arbiter.next_job(X)` call in the tests with `arbiter.next_job(X, &[])` (10 call sites; `grep -n "next_job(" src/scan/arbiter.rs`).

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib -- cluster::msg scan::arbiter`
Expected: compile errors (variant shape, `next_job` arity).

- [ ] **Step 3: Implement**

`src/cluster/msg.rs`:

```rust
    /// Scanner → arbiter: give me a job, but none of these levels (a
    /// scanner at its level-4 share excludes 4). Empty encodes exactly like
    /// the claim of nodes that predate the field; such nodes ignore it.
    Claim {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude_levels: Vec<u8>,
    },
```

`src/scan/arbiter.rs`:

- `type Waiter = (NodeId, Vec<u8>, oneshot::Sender<Option<Grant>>);`
- Add field `order: super::order::Cached,` to `Arbiter`, initialised with `order: super::order::Cached::new(),` in `start`.
- `handle`: `Msg::Claim { exclude_levels } => Some(Msg::ClaimReply { grant: self.claim(from, exclude_levels).await }),`
- `claim(self: &Arc<Self>, scanner: NodeId, exclude: Vec<u8>)`: push `(scanner, exclude, tx)`.
- `hand_out`: iterate `for (s, _, _) in &waiters` for the load map; sort key `|(s, _, _)| (load[s], *s)`; loop `for (scanner, exclude, tx) in waiters { let grant = self.next_job(scanner, &exclude).await?; … }`.
- `next_job(&self, scanner: NodeId, exclude: &[u8])` → passes `exclude` on: `self.next_job_skipping(scanner, declined, &skipped, exclude).await`.
- `next_job_skipping(&self, scanner, declined, skipped: &[i64], exclude: &[u8])`: before the loop `let est = self.order.get(&self.node.store.pool).await;` then the query becomes:

```rust
            let row: Option<(String, String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT j.uid, i.ip, j.level, j.attempts FROM scan_jobs j JOIN ips i ON i.id = j.ip_id
                 WHERE j.status = 'queued' AND j.arbiter = ?
                   AND j.uid NOT IN (SELECT value FROM json_each(?))
                   AND (j.level NOT IN (SELECT value FROM json_each(?))
                        OR j.queued_at < datetime('now', '-{} minutes'))
                   AND j.level NOT IN (SELECT value FROM json_each(?))
                 ORDER BY {} LIMIT 1",
                super::weight::OVERRIDE_WAIT_MINS,
                est.order_by("j", "j.uid"),
            )))
            .bind(&me.0[..])
            .bind(serde_json::to_string(&declined)?)
            .bind(serde_json::to_string(skipped)?)
            .bind(serde_json::to_string(exclude)?)
```

Update the doc comment of `next_job_skipping`: "… and the jobs of the levels it sits out (unless they have waited `OVERRIDE_WAIT_MINS`) or excludes (always). Highest response ratio first (`order`)."

Update the module doc's fairness paragraph with one sentence: "Among an arbiter's jobs, the highest response ratio goes first (see `order`)."

In `src/scan/mod.rs:418` change `Msg::Claim` → `Msg::Claim { exclude_levels: vec![] }` (temporary; Task 6 passes the real list).

- [ ] **Step 4: Run tests**

Run: `cargo test --lib -- cluster::msg scan::arbiter`
Expected: all pass. If `the_same_ip_queued_by_two_arbiters_is_granted_once` now picks differently, it is because it relied on `level DESC`: its jobs are on the same IP and resolved by `outranked_by`, which is unchanged — re-read the failure before touching the test; only adjust if the assertion encoded the old global order.

- [ ] **Step 5: Commit**

```bash
git add src/cluster/msg.rs src/scan/arbiter.rs src/scan/mod.rs
git commit -m "Arbiter: claims exclude levels; pick by response ratio"
```

---

### Task 6: Scanner keeps to its L4 share and orders by response ratio

**Files:**
- Modify: `src/scan/mod.rs` (`Source` struct ~line 200 and `new`, `acquire` ~line 320, `acquire_local` ~line 328, `acquire_granted` ~line 392, `run_workers` ~line 839, tests)
- Modify: `src/admin/scans.rs:285` area and `templates/admin_scans.html:33` (pace note)

**Interfaces:**
- Consumes: `pace::level4_cap` (Task 1), `cfg.scan.level4_max_share` (Task 2), `order::Cached` (Task 4), `Msg::Claim { exclude_levels }` (Task 5).
- Produces: `Source::acquire(&self, exclude: &[u8])`; `fn over_share(level: i64, exclude: &[u8]) -> bool`.

- [ ] **Step 1: Write the failing tests** (in `src/scan/mod.rs` `mod tests`)

```rust
    #[test]
    fn a_grant_at_an_excluded_level_is_over_the_share() {
        assert!(over_share(4, &[4]));
        assert!(!over_share(2, &[4]));
        assert!(!over_share(4, &[]));
    }

    #[tokio::test]
    async fn standalone_pick_skips_excluded_levels() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (ip, level) in [("203.0.113.70", 4), ("203.0.113.71", 2)] {
            let ip = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
            store.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let p = pace::SharedPace::new(pace::Pace::from_config(&cfg.scan));
        let source = Source::new(store.local(), cfg, p, Classifier::builtin());
        let job = source.acquire(&[4]).await.unwrap().unwrap();
        assert_eq!(job.level(), 2);
        assert!(source.acquire(&[4]).await.unwrap().is_none());
        assert_eq!(source.acquire(&[]).await.unwrap().unwrap().level(), 4);
    }

    /// A fake nmap that records how many level-4 scans (argv has -p-) run
    /// at once, holding each for `secs`.
    fn counting_nmap(dir: &std::path::Path, secs: &str) -> PathBuf {
        let fake = fake_nmap(dir); // writes nmap.xml next to it
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nd=\"$(dirname \"$0\")\"\n\
                 case \" $* \" in *\" -p- \"*) mkdir -p \"$d/l4\"; touch \"$d/l4/$$\"; \
                 ls \"$d/l4\" | wc -l >> \"$d/l4-seen\"; sleep {secs}; rm \"$d/l4/$$\";; esac\n\
                 cat \"$d/nmap.xml\"\n"
            ),
        )
        .unwrap();
        fake
    }

    /// With 2 workers at most one level-4 scan runs, the other worker keeps
    /// the shorter levels moving, and (review focus 4) a queue of only
    /// level-4 jobs still drains.
    #[tokio::test]
    async fn level4_never_takes_more_than_its_share() {
        let dir = tempfile::tempdir().unwrap();
        let fake = counting_nmap(dir.path(), "1.5");
        let cfg = test_config(dir.path());
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        for (i, level) in [4, 4, 2, 2].into_iter().enumerate() {
            let ip = store
                .upsert_ip(format!("198.51.100.{}", 80 + i).parse().unwrap())
                .await
                .unwrap();
            store.enqueue_scan(ip.id, level, 24).await.unwrap();
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let p = pace::SharedPace::new(pace::Pace {
            max_workers: 2,
            max_scans_per_hour: 3600,
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
        let max: u32 = seen.split_whitespace().map(|n| n.parse::<u32>().unwrap()).max().unwrap();
        assert_eq!(max, 1, "two level-4 scans ran at once: {seen:?}");
    }
```

Why this fails without the cap: starts are spaced 1 s apart (3600/h). By response ratio the two L2 jobs start first (t≈0, 1 s; their ratio grows 4× faster than an L4's), then the first L4 at t≈2 s, which sleeps until t≈3.5 s. At t≈3 s the second L4 would start beside it; with the cap the worker finds nothing it may take and the second L4 starts once the first ends. Total ≈ 5.5 s, inside `wait_for_scans`' 10 s.

Update every existing `source.acquire()` call in the tests to `source.acquire(&[])` (`grep -n "acquire()" src/scan/mod.rs`).

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib scan::tests`
Expected: compile errors (`over_share`, `acquire` arity).

- [ ] **Step 3: Implement**

`Source`: add field `order: order::Cached,` (init `order: order::Cached::new(),` in `new`).

Free function near `locally_refused`:

```rust
/// A grant at a level this scanner excluded from its claim: an arbiter
/// older than `exclude_levels` ignored it. Handed back "later".
fn over_share(level: i64, exclude: &[u8]) -> bool {
    u8::try_from(level).is_ok_and(|l| exclude.contains(&l))
}
```

`acquire(&self, exclude: &[u8])` → `acquire_local(exclude)` / `acquire_granted(node, exclude)`.

`acquire_local(&self, exclude: &[u8])`: before the loop `let est = self.order.get(pool).await;`; query becomes

```rust
            let row: Option<(i64, Option<String>, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT j.id, i.ip, j.level, j.queued_at FROM scan_jobs j
                 LEFT JOIN ips i ON i.id = j.ip_id
                 WHERE j.status = 'queued' AND j.arbiter IS NULL
                   AND j.id NOT IN (SELECT value FROM json_each(?))
                   AND j.level NOT IN (SELECT value FROM json_each(?))
                 ORDER BY {} LIMIT 1",
                est.order_by("j", "j.id")
            )))
            .bind(serde_json::to_string(&skip)?)
            .bind(serde_json::to_string(exclude)?)
```

`acquire_granted(&self, node: &Arc<Node>, exclude: &[u8])`: replace the arbiter query with

```rust
        let est = self.order.get(&node.store.pool).await;
        let arbiters: Vec<(Vec<u8>, f64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT j.arbiter, MAX({}) AS r FROM scan_jobs j
             WHERE j.status = 'queued' AND j.arbiter IS NOT NULL
               AND j.level NOT IN (SELECT value FROM json_each(?))
             GROUP BY j.arbiter ORDER BY r DESC",
            est.ratio_sql("j")
        )))
        .bind(serde_json::to_string(exclude)?)
        .fetch_all(&node.store.pool)
        .await?;
        for (a, _) in arbiters {
```

and the claim `node.request(arbiter, Msg::Claim { exclude_levels: exclude.to_vec() }, CLAIM_TIMEOUT)`. Right after `let Some(g) = grant else { continue };`, before `check_grant`:

```rust
            if over_share(g.level, exclude) {
                info!(job = %g.job_uid, target = %g.ip, "scan grant turned down: at the level-4 share");
                let (node, uid) = (node.clone(), g.job_uid);
                tokio::spawn(async move {
                    Self::report(&node, arbiter, &uid, "later", Some("at the level-4 share".into())).await;
                });
                continue;
            }
```

`run_workers`: before the loop

```rust
    // Level-4 scans running now (see `L4Slot`).
    let running_l4 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
```

Inside `while joinset.len() < p.max_workers { … }`, replace `let job = match source.acquire().await {` with

```rust
            let cap = pace::level4_cap(p.max_workers, cfg.scan.level4_max_share);
            let exclude: Vec<u8> =
                if running_l4.load(std::sync::atomic::Ordering::SeqCst) >= cap {
                    vec![4]
                } else {
                    vec![]
                };
            let job = match source.acquire(&exclude).await {
```

and after `let job = …;` succeeds (before `joinset.spawn`):

```rust
            let l4 = (job.level() == 4).then(|| L4Slot::take(&running_l4));
```

with `let _l4 = l4;` as the first line inside the spawned `async move` block, so the slot is held until the task ends.

Add near `run_workers`:

```rust
/// One running level-4 scan, counted while it lives.
struct L4Slot(Arc<std::sync::atomic::AtomicUsize>);

impl L4Slot {
    fn take(n: &Arc<std::sync::atomic::AtomicUsize>) -> Self {
        n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(n.clone())
    }
}

impl Drop for L4Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
```

Pace note: in `src/admin/scans.rs` add a field `level4_cap: usize` to the pace view struct (next to `level4_timeout_min`), set to `pace::level4_cap(current.max_workers, st.cfg.scan.level4_max_share)`; in `templates/admin_scans.html:33` change the note to

```html
      <p class="muted pace-note">0 pauses scanning; otherwise at least 2. At most {{ pace.level4_cap }} at once on level 4. Level 4 timeout: {{ pace.level4_timeout_min }} min.</p>
```

- [ ] **Step 4: Run tests**

Run: `cargo test --lib scan && cargo test --lib admin`
Expected: all pass. Then `cargo build` and `cargo clippy --all-targets -- -D warnings`.

- [ ] **Step 5: Commit**

```bash
git add src/scan/mod.rs src/admin/scans.rs templates/admin_scans.html
git commit -m "Scanner: keep level 4 to its share of workers; pick and claim by response ratio"
```

---

### Task 7: Changelog and spec status

**Files:**
- Modify: `CHANGELOG.md` (the unreleased section at the top; follow its existing heading style)
- Modify: `docs/superpowers/specs/2026-10-06-scan-scheduling-design.md` (status line)

- [ ] **Step 1: Write the entry**

Under the unreleased heading (create `## Unreleased` in the file's style if none exists):

```markdown
### Scan scheduling
- At most half of a node's workers run level-4 scans (`scan.level4_max_share`, default 0.5); the rest keep shorter scans moving. Workers are now 0 (paused) or at least 2; a saved 1 is raised to 2.
- Level 4 sends at least `scan.min_rate` probes per second (default 300; lower it behind a home router) with `--max-retries 1`, and `level4_timeout_factor` defaults to 2.
- The queue runs the job with the highest response ratio (time waited relative to how long its level takes) instead of the highest level first.
- Presets: level 1 runs at `-T3` with `--version-light`; levels 3 and 4 add `--traceroute`; `scan.level4_udp` adds the top 50 UDP ports to level 4 (off by default).
- Cluster: claims name the levels a scanner cannot take; older nodes ignore the field and interoperate.
```

- [ ] **Step 2: Spec status**

Change the spec's status line to `Date: 2026-10-06 · Status: implemented (branch \`ai-decoys\`, PR #41).`

- [ ] **Step 3: Full check**

Run: `cargo test` (whole suite once, since this is the last task) and `cargo clippy --all-targets -- -D warnings`.
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md docs/superpowers/specs/2026-10-06-scan-scheduling-design.md
git commit -m "Docs: scan scheduling in changelog"
```

## Rollout checks (operator, after deploy — not part of the tasks)

1. On one node: `nmap -sS -sU -p T:1-65535,U:53 -sV -O --traceroute --min-rate 300 -oX - <own test host>` runs (only before enabling `level4_udp`).
2. Residential: set `scan.min_rate` lower (e.g. 100) in its config.
3. After a day, rerun the per-level duration query from the spec and the L4 failure query; then decide on `level4_udp` and re-check for old L4 jobs being skipped.
