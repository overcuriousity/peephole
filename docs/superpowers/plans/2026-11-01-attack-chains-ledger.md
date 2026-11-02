# SDD ledger — plan: docs/superpowers/plans/2026-11-01-attack-chains.md

Spec: docs/superpowers/specs/2026-11-01-attack-chains-design.md
User instruction: subagent-driven; parallelise with a DAG; one PR, one release; member expiry stays 30 days.
Base: 4a88727 (branch feat/attack-chains)

## DAG (user override of "never parallel": separate worktrees, merged by the controller)
L0 T1 | L1 T2 T3 | L2 T4 | L3 T5 | L4 T6 | L5 T7 T8 | L6 T9 T11 | L7 T10 T12 T13 T14 | L8 T15 | L9 T16 (STOP: user approves audit) | L10 T17 T18 | L11 T19 | L12 T20 (PR, merge, release)

## Pre-flight scan
| Pair / task | Produces vs consumes | Finding |
|---|---|---|
| T1-T2 | xray/mod.rs types; parse in T2 | ok; T1 tests call decode_all directly |
| T1-T3, T1-T4 | Piece, Recipe placeholders filled later | ok; T2 and T3 both edit xray/mod.rs, only mod lines |
| T3-T4 | Recipe, Step, Span consumed by pieces | T4 after T3 |
| T2-T4 | Policy used by parse | T2 uses a default until T4 |
| T4-T5 | parse, mask_ranges, defang | ok |
| T5-T6 | text_for_xray in uploads.rs, consumed by T6 extraction | CONFLICT if parallel: see ruling 1 |
| T6-T7, T6-T8 | pieces, sightings | ok |
| T7-T8 | links.rs vs chains.rs | no shared file except store/mod.rs lines |
| T8-T9 | chains tables; chains_of | ok |
| T8-T11 | campaigns.rs: signature (T8), compute (T11) | T11 after T8 |
| T9-T11 | campaign.html both edit | merge at controller; low risk |
| T9-T10, T9-T12, T9-T13, T9-T14 | Chain struct | all after T9 |
| T11-T12 | campaign.html | T12 after T11 |
| T13-T14 | store/chains.rs both add | merge at controller |
| T5-T18, T9-T18, T12-T18 | section order | T18 after |
| T17-T18 | request.html, campaign.html both edit | parallel risk; merge at controller |
| Each task, self-agreement | tests vs code vs files | T1..T14 agree. T13 Step 1 reads the observer: controller does it. T15/T16/T20 are controller-run. |

Ruling: T6 runs after T5 instead of beside it — text_for_xray is T5's and T6 needs it — costs one level of parallelism.
Ruling: review minors enter the fix loop, not a deferred list — user's standing rule "no deferred review findings" outranks the skill — costs extra fix rounds.
Ruling: parallel tasks get own worktree and own reflinked target dir; controller merges into feat/attack-chains after review — user asked for parallel sessions, skill forbids it for shared checkouts — a merge conflict costs one fix dispatch.

Ruling: tasks 1-4 add no CHANGELOG entry; Task 5 writes it for the whole parser — the parser is not user-visible before then — costs nothing if wrong.
Task 1: implementer done e89a8b4 (DONE_WITH_CONCERNS: allow(dead_code) in decode.rs, drop when parse calls decode_all in Task 2)
Ruling: per-task reviews are targeted and quick, per-task tests are targeted unit tests only; the full suite and the full review run once at the end (Task 20) — user instruction, overrides the skill and the plan's "run the full suite" steps — a cross-task regression surfaces later, at the final run.
Task 1: review needs fixes (3 important, 8 minor); fix round 1 sent to the implementer. Ruling: Task 1 CHANGELOG folds into Task 5 — not user-visible yet — costs nothing. Findings: task-1-findings.md
Task 1: fix round 1/5 implementer done 6465229 (re-review pending)
Ruling: T2 and T3 start before the T1 re-review ends — fixes only touch decode.rs — a re-review finding costs a small rebase.
Ruling: T3 exposes shell::read_recipes(xray, layer, budget) and its tests call it directly; T4 wires it into parse — T2 owns parse and runs in parallel — costs one wiring step.
Task 1: fix round 1/5 (12 addressed, 0 open; commits e89a8b4..6465229)
Task 1: complete (commits 4a88727..6465229, review clean)
Open for final pass (no deferral): decode.rs B64 wrapped-line tail can swallow a following line holding a real token; zlib output labelled LayerKind::Gzip.
Task 2: implementer done f8f0a80 on ac/t2 (agent a5575d1caa7df58e8)
Task 2: review needs fixes (1 critical, 6 important, 5 minor); fix round 1 sent. Findings: task-2-findings.md
Task 2: fix round 1/5 (12 fixed; commits f8f0a80..0fe9b4d), flagged decode gap outside container parts
Ruling: cross-parent text dedupe in decode::open, layer 0 always decoded — a missed payload is worse than a decoder change — costs a small hash set per parse.
Task 2: fix round 2/5 implementer done e559c93
Task 2: fix round 2/5 (13 addressed, 0 open; commits f8f0a80..e559c93)
Task 2: complete (commits 6465229..e559c93, review clean), fast-forwarded into feat/attack-chains
Open for final pass (no deferral): padding collapse folds short noise-looking fragments of a split payload; text_boundary reads only the first line, so a preamble leaves boundary noise.
Task 3: implementer done 96b8d15 on ac/t3 (agent a1e2ded4618edff0d); gap fixes sent before review
Ruling: recipe steps get Budget.steps (256), separate from Budget.pieces — a long recipe must not starve stagers and keys — costs one more limit than the spec lists.
Ruling: tag hidden as <tag> in normal; MAX_NEST 32 for group height — implementer's calls accepted — costs little.
Task 3: gap fixes done c82880d (merge 1421411); process substitution still open, goes with review findings
Task 3: review needs fixes (3 important, 3 minor); fix round 1 sent. Ruling: feat advanced to c82880d so T4 can start while fixes touch shell.rs on ac/t3 — T4 only wires shell.rs — costs a small merge.
Ruling: read_recipes runs only on non-Shell layers whose text holds a shell indicator — avoids false OverLimit on prose — a payload with no indicator word gives no recipe.
Ruling: PHP fetchers count as stagers: a URL in a PHP layer with curl_init/file_get_contents/copy and a write (fopen w, CURLOPT_FILE, file_put_contents) — the surge.sh dropper is PHP with no shell — costs a text heuristic.
Task 3: fix round 1/5 implementer done 73006b4. Ruling: `_` allowed in payload paths — out_sh is the spec's own example — base64 lines still fail the shape rule. Merge into feat after T4 finishes, to avoid touching its working tree.
Task 3: fix round 1/5 (6 addressed, 0 open; commits c82880d..73006b4)
Task 3: complete (commits e559c93..73006b4, review clean); merge ac/t3 into feat when T4 ends
Open for final pass (no deferral): `cat "$(curl …)" | sh` marks a fetch whose output is a file name; substitution found by text can miss a layer already open as non-Shell.
Task 4: implementer done aafa9a8 (agent ab5954ba0ecd417ec), 14 decisions in its report; ac/t3 merged after it
Ruling: php_calls opens exec literals as Shell, read_shell skips containers, marker-only keys give a mask and no piece — implementer's calls accepted, each avoids a false joiner or a missed dropper — costs shell text outside container parts not being read.
Ruling: T5 starts during the T4 review in worktree ac/t5 — it consumes parse and mask_ranges, whose signatures are fixed — a T4 fix costs a small merge.
Task 4: review needs fixes (2 critical, 5 important, 7 minor); fix round 1 sent. Findings: task-4-findings.md
Ruling: every URL piece has kind Stager, so T6 and T11 must filter joins on Role::Stager, not on kind — carried to T6 dispatch.
Ruling: copy() with a URL source is a save, plain wget saves by default — spec says "runs or saves" — overrides the earlier "needs a write" call.
Task 4: fix round 1/5 implementer done b26753e; T5 merge must add LayerKind::Path to layer_title
Session restarted: T4 fix round 2 (agent ad5147e05aee0d6a8) and T5 (agent a7f1175acdd6314d7) resumed from uncommitted working trees.
Task 4: fix round 2/5 implementer done 0cc76cd; literal passed to a custom function still promotes, needed for the adminer() dropper
Task 4: fix round 2/5 (3 addressed, 0 open; commits b26753e..0cc76cd)
Task 4: complete (commits c82880d..0cc76cd, review clean)
Open for final pass (no deferral): a key with no END masks to end of text, dropping later fetches; copy() of a function parameter and array URLs stay queried; a literal passed to a custom function promotes in a fetching and writing layer.
INCIDENT 2026-11-01 20:54: machine froze. Kernel soft lockup: kswapd in btrfs_drop_extent_map_range during inode cache reclaim (CPU#0 stuck 1333 s), not a full disk (49 GB free). Likely trigger: parallel cargo builds, each with a reflinked 19-34 GB target and incremental caches.
Ruling: all worktrees use an untracked .cargo/config.toml: shared target ~/.cache/peephole-ac-target (nocow), jobs 4, no incremental, debug 0. New worktrees copy it; target dirs are never copied — costs slower parallel compiles (one at a time through cargo's lock).
Task 5: implementer done 329ee3f on ac/t5; merging feat for LayerKind::Path, then review.
Ruling: raw bytes and decoded layer text stay escaped and undefanged, never links — they are the evidence and the pieces beside them are defanged — costs a live-looking address as plain text on an admin page.
Ruling: BODY_LIMIT 64 KiB also lengthens dossier body_text — same admin audience — costs larger dossiers.
Task 5: merged feat, head ce53468; fuzz inputs shrunk to fit 30 s, parser speed goes to review
Task 5: review needs fixes (2 important, 3 minor, exploit value defang); fix round 1 sent.
Ruling: fuzz test keeps 20,000 small inputs plus 300 large ones, debug budget 90 s instead of 30 s — debug regex is slow and shrinking inputs proves nothing — costs a slower test, not a weaker one.
Task 5: fix round 1/5 implementer done e825024; fast-forwarded into feat; quick re-review running beside T6.
Ruling: extraction reads rows with a body, a query or shell characters in the path, and stamps xray_v on all rows — parsing 300k plain GETs buys nothing — a payload in a plain path with none of `;|&$` and backtick or blanks is missed.
Ruling: extraction parses on spawn_blocking with a pause between batches — a trap node must not stall on backfill — costs a slower backfill.
Task 5: fix round 1/5 (6 addressed, 0 open; commits ce53468..e825024)
Task 5: complete (commits 0cc76cd..e825024, review clean)
Task 6: implementer done b712065; review running, T7 and T8 start beside it.
Ruling: piece_url_sources table added beyond the spec — needed so a URL only a deleted source named disappears — costs one more node-local table.
Task 6: review needs fixes (4 important, 3 minor); fix round 1 sent. Findings: task-6-findings.md
Task 7: implementer done c05c490 on ac/t7 (agent ae7b8a2a835771c46)
Task 7: review approved; 4 minors sent to the implementer.
Task 6: fix round 1/5 implementer done feb956e
Task 6: fix round 1/5 (7 addressed, 0 open; commits b712065..feb956e)
Task 6: complete (commits e825024..feb956e, review clean)
Task 7: complete (commits b712065..c39b90e, review clean, minors fixed), merged into feat as 854d252; 49 targeted tests pass after merge
Task 8: implementer done bb187cd on ac/t8 (agent a05dfa1b6f77080ad)
Ruling: trap uses decoy::answers_itself with its real presentation, stored rows use keeps_its_own_answer over all presentations — brief's single function could not keep trap answers unchanged — a real no-cookie follow-up under /wp-admin/ is excluded.
Task 8: review needs fixes (1 important, 3 minor); fix round 1 sent.
Task 8: fix round 1/5 implementer done 47d0730, fast-forwarded into feat; quick re-review beside T9 and T11.
Ruling: rebuild split into chains::plan and chains::store_plan — heavy reads must not hold the write lock — plan's Interfaces line is stale; T9 fixtures use a campaign pass.
Ruling: a source naming over 64 joiners is skipped in pairing — bounds memory against a forged body — an attacker padding a body can hide its own link, never fuse others.
Task 8: fix round 1/5 (4 addressed, 0 open; commits bb187cd..47d0730)
Task 8: complete (commits b712065..47d0730, review clean)
Carry to final pass: readers of chain_pieces must join pieces, since a stale row can survive one pass.
Task 11: implementer done 0a8b2a2 on ac/t11 (agent a8619107691eb816f)
Ruling: joiner star is per final group (each member to the oldest naming address of its own group), plus one merged=0 edge between group anchors — a member must have evidence inside its campaign — costs at most k-1 edges more than n-1.
Task 11: review needs fixes (2 critical, 2 important, docs, minor): the plan's pseudocode was unsafe. Fix round 1 sent. Findings: task-11-findings.md
Ruling: campaign joiner phase rewritten: value clouds connect at max(K, 10 % of the smaller cloud) shared loose addresses, blocks connect on K distinct addresses each on one value with pre-absorption counts, lone addresses join once and never count — one address could otherwise merge two 163-address clouds — costs real links under 10 % overlap staying apart, and more code than the spec's sketch.
Task 9: implementer done 7f3fd65 on ac/t9 (agent a00ea9cf41c4f2e95); Follow-up not yet read through the X-ray, public test failing on layer name
Task 9: review needs fixes (2 from the spec, 4 important, 3 minor); fix round 1 sent. Findings: task-9-findings.md
Ruling: Payload "seen" uses metadata only — a chain must not read upload content — a file that starts as text and turns binary shows as seen.
Task 11: fix round 1/5 implementer done b6fbaff; two departures accepted, re-review pending.
Ruling: cloud size ties break by members, not value key; an assigned address counts only for its own cloud's values in step 3 — findings' wording broke their own invariants — costs nothing.
Task 9: fix round 1/5 implementer done cfa25d2; also closed key and php://input label leaks
Task 9: fix round 1/5 (9 addressed, 0 open; commits 7f3fd65..cfa25d2)
Task 9: complete (commits 47d0730..cfa25d2, review clean), fast-forwarded into feat. Chain has a `more` field and holds at most 200 pieces.
Open for final pass: browser check of the strip in light, dark and narrow; query cost on a large chain; shell inputs are the union across a chain's profiles.

Stopped 2026-11-01 at the user's request (machine off): agents for T10, T13, T14 and the T11 re-review stopped. WIP committed on ac/t10, ac/t13, ac/t14, unverified. Handoff: docs/superpowers/plans/2026-11-01-attack-chains-handoff.md
