# Level-5 vulnerability scan — design

Add a scan level 5 that runs nmap's `vuln` NSE category, offered as a manual
purchase under Lookup → actions, priced above level 4.

## Decisions (confirmed with the operator)

- **Base:** the level-3 port set (`--top-ports 1000`, with `-sV -O
  --traceroute`), not level 4's all-ports sweep. Vuln scripts multiply the
  per-port cost; `-p-` with vuln scripts would not finish in reasonable time.
- **Script selector:** literally `vuln and not external`. The `safe` and
  `discovery` scripts of levels 3–4 do not run at level 5, and `intrusive` /
  `dos` / `broadcast` are not excluded — the operator accepts that vuln
  checks tagged `dos` may run.
- **Price:** the existing 4^(level−1) ladder continues: level 5 costs 256×
  the level-1 price (level 4 is 64×). Only the `level_factor` clamp extends.
- **Manual-buy only.** The automatic queue stays capped at level 4: its level
  derives from classification rule weights, bounded 1..=4 at
  `src/classify/rules.rs:68`, and this feature does not change trap
  classification.
- **Concurrency:** level 5 counts against the level-4 slot/share
  (`level4_max_share`, the `L4Slot`/`running_l4` machinery in
  `src/scan/mod.rs`). Both are heavy scans; one budget keeps a node from
  running several expensive scans at once. No separate level-5 cap.
- **Timeout:** level 5 inherits the 4× timeout factor —
  `level_timeout_secs` in `src/scan/pace.rs` already applies it to
  `level >= 4`. No change needed there.
- **Rate floor:** `--min-rate` applies to level 5 as it does to level 4
  (`complete()` in `src/scan/mod.rs:75`).
- **Cluster:** bump `PROTO_VERSION` and hand out level-5 jobs/grants only to
  peers speaking the new protocol, mirroring how `exclude_levels` was
  versioned (`src/cluster/msg.rs:742-765`). Old nodes refuse level 5
  ("invalid scan level" at `src/scan/mod.rs:786`; jobs ignored via
  `MAX_SCAN_LEVEL` at `src/store/data.rs:654`), so without a gate level-5
  work would bounce around a mixed fleet.

## Level-5 nmap argv

```
-Pn -sS -sV -O -T3 --top-ports 1000 --traceroute --script "vuln and not external"
```

(plus the per-run `--host-timeout`, `--script-timeout`, `--min-rate`, `-oX
-`, and target added by `complete()`). The exact list goes into
`profiles::builtin(5, _)` so the scan earns its scanner share via
`args_ok`; the level-4-specific cases in `profiles::normalize` do not apply
to level 5 (no `-sU`/`-p-`). A new `VULN_SCRIPTS` const names the selector.

## Changes by area

### Core scan logic

- `src/scan/profiles.rs` — `VULN_SCRIPTS` const; level-5 arm in `builtin()`
  (the `udp` flag is ignored at level 5, as it is at levels 1–3); tests.
- `src/scan/mod.rs` — `valid_level` bound `1..=4` → `1..=5` (line 40);
  `complete()` min-rate for level 5; L4 slot/exclude logic treats level 5
  as level 4 (the `exclude = vec![4]` at-cap case and `job.level() == 4`
  slot acquisition); the "levels 1..=4" comment at line 1423;
  `levels_outside_1_to_4_are_refused` test.
- `src/config.rs` — `default_level_argv` bound (line 922), `level_argv`
  range validation (829), `single_request_max_level` validation (843),
  config-docs table (589), per-level tests (975–1058, including the
  non-intrusive-scripts assertion, which gains a level-5 exception).
- `src/store/recorder.rs` — enqueue bounds (425, 544).
- `src/store/data.rs` — `MAX_SCAN_LEVEL` → 5 (641).
- `src/scan/arbiter.rs` — excluded-level set `(1..=4u8)` → `(1..=5u8)`
  (404); the `level_factor` payment at 426–431 follows automatically.

### Pricing / credits

- `src/credits/jobs.rs` — `level_factor` clamp 4 → 5 (93); tests (268).
- `src/credits/audit.rs` — extend `!(1..=4)` at 394 and 786 and
  `BETWEEN 1 AND 4` at 557 and 953 so level-5 scans are audited and
  scanners are paid for them.

### Admin UI

- `src/admin/scan_buy.rs` — `offers_for` range → `1..=5` (82); `about()`
  gains an explicit level-4 arm and a level-5 arm (59–66, currently a
  catch-all); tests asserting 4 offers.
- `src/admin/credits.rs` — `LevelInputs` tuple size (149), `[1, 2, 3, 4]`
  (447), `0..4` (155).
- `src/admin/cluster.rs` — `level_weights` range (276).
- `templates/admin_cluster_credits.html` — `{% for l in 1..=4 %}` (52) and
  the "L1 to L4" footnote (55).
- `templates/_actions.html` — no change (data-driven over `a.scans`).
- `templates/admin_scans.html` — pace-note wording where it describes
  level-4 timeouts/cap, if it would misdescribe level 5.

### Storage / export

No functional changes: `parse_nmap_xml` keeps the raw XML whole, `scrub()`
only masks scanner identity, export embeds the raw XML, and level columns
are plain integers. Add a test fixture with vuln script output
(`tests/fixtures/`) confirming the scrub still masks the scanner inside
vuln tables. Watch: vuln output can be large; the existing `MAX_STDOUT`
(16 MB, `src/scan/mod.rs:33`) and `MAX_RAW_XML` (64 MB,
`src/store/inspect.rs:191`) caps stay as they are.

### Cluster

- `src/cluster/rpc/proto.rs` — `PROTO_VERSION` bump (PROTO_MIN unchanged);
  gate level-5 grants/jobs to peers at the new version.

### Docs

- `README.md` ("four levels", "level 1–4", price ladder)
- `docs/operations.md` (timeouts, bought-scan levels, price ladder)
- `docs/dataset.md` (`scan_level … 1 to 4`, level descriptions)
- `docs/cluster.md` ("a known level", `4^(level−1)`)
- `deploy/config.example.toml` (scan-section comments)
- `CHANGELOG.md` (new entry)

## Error handling

- A level-5 job reaching an old node is refused before the protocol gate
  ever lets it happen; the gate is the primary defense, `valid_level` and
  `MAX_SCAN_LEVEL` stay as backstops.
- nmap output beyond 16 MB is killed as today; the scan records as failed,
  not partial.

## Testing

- Extend in-file unit tests listed above (profiles, config, scan mod,
  scan_buy, credits/jobs, credits page, pace).
- New fixture test: vuln-script XML parses, stores, scrubs.
- `tests/integration.rs` / `tests/cluster.rs`: a level-5 buy enqueues and,
  in a mixed-version cluster, only capable nodes claim it.
