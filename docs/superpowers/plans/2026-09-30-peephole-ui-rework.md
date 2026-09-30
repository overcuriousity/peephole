# peephole UI Rework & Public/Admin Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild peephole's two web surfaces on askama templates with a tokenized light/dark design, split the admin listener into a public wall of shame and a FIDO2-gated admin area, and make the installer an idempotent install-or-upgrade tool.

**Architecture:** One axum router on the admin listener serves public pages (aggregates, map, IP/request search, per-IP request history) and, behind the existing `SessionUser` extractor, the admin pages (live queue over broadcast-fed SSE, scan results, raw payloads, fingerprints, inbox, exports, keys, deletes). All HTML comes from askama templates fed by typed store rows; the store never renders HTML. CSS layers are concatenated by `build.rs` and embedded with fonts, JS and a pre-projected world map via `include_bytes!`.

**Tech Stack:** Rust 2024, axum 0.8, askama 0.16, sqlx/SQLite, tokio broadcast, vanilla JS + inline SVG charts, Inter + JetBrains Mono (woff2), bash installer, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-30-peephole-ui-rework-design.md`

## Global Constraints

- Public pages never query or render: raw headers, request bodies, fingerprint attributes, scan results (ports/services/OS), false-positive claims or emails. Admin-only data is only loaded when `authed` is true (spec §5).
- Aggregate "counter-scans completed" count is public; per-IP scan results are not (spec §2).
- No external network requests from any page: fonts, scripts, styles and the map are served from the binary (spec §2, §8).
- Admin listener responses carry `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`. No inline `<script>` or `style=` attributes on the admin listener (spec §10).
- Trap page: inline CSS, system font stack, `noindex,nofollow`, no link to `/login` or `/admin` (spec §9.3).
- `range` ∈ {`24h`,`7d`,`30d`,`all`}, default and fallback `24h`. `page` is 1-based, page size 100, `LIMIT 101` detects `has_next` (spec §4).
- Stats cache TTL 15 s for `/`, `/api/stats`, `/api/map` (spec §6.3).
- `askama = "0.16"`, `askama.toml` → `dirs = ["templates"]`. No `rust-embed`, no Node in `cargo build` (spec §2; version amended from 0.14 to 0.16 because 0.16 is the line engram uses and the only one cached locally).
- Every fg/bg pair in both themes ≥ 4.5:1 (spec §9.1).
- Commit after every task; `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` clean before each commit.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs
  ```

## Review Focus

1. `/ip/{addr}` with a string that is not an IP (`/ip/hello`, `/ip/%00`) must 404 with the styled page, never 500. Test in Task 9.
2. `/ips?q=2001:db8::/32` and `/ip/2001:db8::1` (IPv6 with colons in the path and CIDR in the query) must work like IPv4. Test in Task 6 (store) and Task 9 (route).
3. `?page=0`, `?page=-1`, `?page=abc`, `?range=1y` must fall back to page 1 / `24h`, never error. Test in Task 6 and Task 4.
4. Deleting an IP while one of its scan jobs is `running`: the worker's later `finish_job` must log and continue, not panic; the job row must already be gone. Test in Task 7.
5. An SSE client that falls behind (broadcast `Lagged`) must receive a fresh `snapshot`, not a dropped stream. Test in Task 3.

---

## File Map

Create:
- `askama.toml` — template dir.
- `build.rs` — concatenates `assets/css/*.css` → `assets/app.css`, exports `ASSET_STAMP`, `PEEPHOLE_VERSION`.
- `assets/css/00-tokens.css`, `10-base.css`, `20-layout.css`, `30-components.css`, `40-charts.css`
- `assets/js/theme.js`, `assets/js/app.js`, `assets/js/charts.js`
- `assets/fonts/inter-400.woff2`, `inter-500.woff2`, `inter-600.woff2`, `jetbrains-mono-400.woff2`, `jetbrains-mono-500.woff2`
- `assets/world.svg`, `assets/README.md`, `tools/build-world-map.mjs`, `tools/package.json`
- `src/events.rs` — `QueueJob`, `Notifier`.
- `src/admin/assets.rs`, `src/admin/error.rs`, `src/admin/public.rs`, `src/admin/pages.rs` (admin pages), `src/admin/countries.rs`, `src/admin/views.rs`
- `src/store/stats.rs`, `src/store/browse.rs`, `src/store/delete.rs`, `src/store/inspect.rs` (admin-only reads)
- `templates/layout.html`, `_pagination.html`, `_severity.html`, `wall.html`, `ips.html`, `ip.html`, `requests.html`, `request.html`, `admin_home.html`, `admin_queue.html`, `admin_scans.html`, `admin_scan.html`, `admin_fingerprints.html`, `admin_inbox.html`, `admin_export.html`, `admin_keys.html`, `login.html`, `enroll.html`, `error.html`, `trap.html`
- `deploy/nginx.example.conf`
- `tests/install.sh` (installer smoke, run in CI)

Modify:
- `Cargo.toml` (askama 0.16, build script), `.gitignore`
- `src/lib.rs` (notifier wiring), `src/main.rs` (`--version`, `check-config`)
- `src/admin/mod.rs` (state, router, middleware), `src/admin/auth.rs` (session-or-token enroll, Secure cookie, JS moved out), `src/admin/sse.rs`
- `src/scan/mod.rs` (publish events), `src/trap/mod.rs` + `src/trap/pages.rs` (notifier, new trap template)
- `src/store/mod.rs` (remove `ip_detail`/`public_stats`/HTML; re-export new modules), `src/store/schema.sql` (indexes), `src/store/scans.rs` (`queue_job`)
- `tests/integration.rs`
- `install.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `README.md`

Delete:
- `src/admin/detail.rs`, `templates/dashboard.html`, `templates/ip_detail.html`, `templates/inbox.html`, `templates/keys.html`, `templates/export.html`, `templates/request_detail.html` (replaced by the new files above).

---

### Task 1: Build script, askama, embedded assets, layout and design tokens

**Files:**
- Create: `askama.toml`, `build.rs`, `assets/css/00-tokens.css`, `assets/css/10-base.css`, `assets/css/20-layout.css`, `assets/css/30-components.css`, `assets/css/40-charts.css` (empty stub for now), `assets/js/theme.js`, `assets/js/app.js` (theme toggle only for now), `assets/fonts/*.woff2`, `src/admin/assets.rs`, `templates/layout.html`
- Modify: `Cargo.toml`, `.gitignore`, `src/admin/mod.rs`
- Test: `tests/integration.rs`

**Interfaces:**
- Produces: `crate::admin::assets::{STAMP: &'static str, router() -> Router<Arc<AdminState>>}`; `crate::admin::views::Chrome { authed: bool, active: &'static str, stamp: &'static str, version: &'static str }` with `Chrome::new(authed, active)`; `templates/layout.html` with blocks `title`, `head`, `content` and a `chrome` field expected on every page struct.

- [ ] **Step 1: Bump askama, add build script and gitignore entries**

`Cargo.toml`: change `askama = "0.14"` to `askama = "0.16"`, and under `[package]` add `build = "build.rs"`.

`askama.toml`:
```toml
[general]
dirs = ["templates"]
```

`.gitignore` append:
```
/assets/app.css
/tools/node_modules
```

`build.rs`:
```rust
//! Concatenates the CSS layers into one embedded stylesheet, stamps the
//! asset URLs with a content hash, and bakes the release version in.
use std::path::Path;

fn main() {
    build_stylesheet();
    stamp_assets();
    println!("cargo:rerun-if-env-changed=PEEPHOLE_VERSION");
    let version = std::env::var("PEEPHOLE_VERSION").unwrap_or_else(|_| "dev".into());
    println!("cargo:rustc-env=PEEPHOLE_VERSION={version}");
}

/// `assets/app.css` = `assets/css/*.css` in filename order (numeric prefixes
/// order the cascade: tokens first). Generated and gitignored.
fn build_stylesheet() {
    println!("cargo:rerun-if-changed=assets/css");
    let dir = Path::new("assets/css");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("assets/css")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".css"))
        .collect();
    names.sort();
    let mut out = String::new();
    for name in &names {
        let body = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("assets/css/{name}: {e}"));
        out.push_str(&format!("/* ===== {name} ===== */\n{body}\n"));
    }
    let dest = Path::new("assets/app.css");
    // Only write when changed: cargo watches this file's mtime.
    if std::fs::read_to_string(dest).ok().as_deref() != Some(out.as_str()) {
        std::fs::write(dest, &out).expect("assets/app.css");
    }
}

/// FNV-1a over the files pages reference by URL. Cache-busting query stamp.
fn stamp_assets() {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for name in [
        "assets/app.css",
        "assets/js/app.js",
        "assets/js/charts.js",
        "assets/js/theme.js",
        "assets/world.svg",
    ] {
        println!("cargo:rerun-if-changed={name}");
        for b in std::fs::read(name).unwrap_or_default() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    println!("cargo:rustc-env=ASSET_STAMP={h:x}");
}
```

Note `unwrap_or_default()` on read: `assets/world.svg` does not exist until Task 8; the stamp still builds.

- [ ] **Step 2: Copy fonts**

```bash
mkdir -p assets/fonts assets/js assets/css
cp ../engram/assets/fonts/inter-400.woff2 ../engram/assets/fonts/inter-500.woff2 \
   ../engram/assets/fonts/inter-600.woff2 ../engram/assets/fonts/jetbrains-mono-400.woff2 assets/fonts/
cp ../Vestigo/frontend/dist/assets/jetbrains-mono-latin-500-normal-BWZEU5yA.woff2 assets/fonts/jetbrains-mono-500.woff2
ls -la assets/fonts
```
Expected: five woff2 files, ~20–25 KB each. Both families are SIL OFL 1.1; note that in `assets/README.md` (created in Task 8, add the font line then).

- [ ] **Step 3: Write the design tokens**

`assets/css/00-tokens.css`:
```css
/* Tokens: fonts, type scale, geometry, both themes. Sorted first so every
   later layer can rely on them. Structure follows engram; palette is
   peephole's own: near-black with the logo's bloodshot red as brand hue and
   a cool cyan as the interactive accent. */

@font-face { font-family: Inter; font-weight: 400; font-display: swap;
  src: url("/assets/fonts/inter-400.woff2") format("woff2"); }
@font-face { font-family: Inter; font-weight: 500; font-display: swap;
  src: url("/assets/fonts/inter-500.woff2") format("woff2"); }
@font-face { font-family: Inter; font-weight: 600; font-display: swap;
  src: url("/assets/fonts/inter-600.woff2") format("woff2"); }
@font-face { font-family: "JetBrains Mono"; font-weight: 400; font-display: swap;
  src: url("/assets/fonts/jetbrains-mono-400.woff2") format("woff2"); }
@font-face { font-family: "JetBrains Mono"; font-weight: 500; font-display: swap;
  src: url("/assets/fonts/jetbrains-mono-500.woff2") format("woff2"); }

:root {
  --font-sans: "Inter", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, "SF Mono", Consolas, monospace;

  --text-xs: 0.75rem;
  --text-sm: 0.8125rem;
  --text-base: 0.875rem;
  --text-md: 0.9375rem;
  --text-lg: 1.125rem;
  --text-xl: 1.375rem;
  --text-2xl: 1.75rem;
  --text-3xl: 2.5rem;

  --radius-sm: 3px;
  --radius-md: 6px;
  --radius-lg: 10px;

  --shell-max: 80rem;

  /* Light: warm paper, ink, teal-blue accent, the logo's red as brand. */
  --color-bg-base: #f6f5f0;
  --color-bg-surface: #efede6;
  --color-bg-elevated: #ffffff;
  --color-bg-hover: #e8e5dc;
  --color-bg-active: #ddd9cd;

  --color-fg-primary: #1f2024;
  --color-fg-secondary: #4f5159;
  --color-fg-muted: #66686f;          /* 5.0:1 on base */

  --color-border: #d9d5c9;
  --color-border-strong: #c3beaf;
  --color-border-subtle: #e6e3da;

  --color-accent: #1f6f8b;            /* 5.2:1 on base */
  --color-accent-dim: rgba(31, 111, 139, 0.10);
  --color-accent-muted: rgba(31, 111, 139, 0.30);
  --color-accent-fg: #ffffff;

  --color-brand: #b30000;             /* logo red, darkened for AA on paper */
  --color-brand-dim: rgba(179, 0, 0, 0.10);

  --color-danger: #b3382c;  --color-danger-dim: rgba(179, 56, 44, 0.10);
  --color-warning: #845b16; --color-warning-dim: rgba(132, 91, 22, 0.10);
  --color-success: #2b7048; --color-success-dim: rgba(43, 112, 72, 0.10);

  /* Severity 0..4: grey → amber → orange → red → violet. Text-safe on base. */
  --sev-0: #6b6d74; --sev-0-dim: rgba(107, 109, 116, 0.14);
  --sev-1: #8a6a00; --sev-1-dim: rgba(138, 106, 0, 0.14);
  --sev-2: #b04a00; --sev-2-dim: rgba(176, 74, 0, 0.14);
  --sev-3: #b31c1c; --sev-3-dim: rgba(179, 28, 28, 0.14);
  --sev-4: #7a1fa2; --sev-4-dim: rgba(122, 31, 162, 0.14);

  /* Sequential ramp for the map (accent-based, not severity). */
  --ramp-0: var(--color-bg-hover);
  --ramp-1: rgba(31, 111, 139, 0.25);
  --ramp-2: rgba(31, 111, 139, 0.45);
  --ramp-3: rgba(31, 111, 139, 0.70);
  --ramp-4: #1f6f8b;

  --grid-texture: none;
  color-scheme: light;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --color-bg-base: #0a0b10;
    --color-bg-surface: #10121a;
    --color-bg-elevated: #171a24;
    --color-bg-hover: #1f2330;
    --color-bg-active: #282d3c;

    --color-fg-primary: #e4e6ee;
    --color-fg-secondary: #a0a4b8;
    --color-fg-muted: #8a8ea6;        /* 5.4:1 on base */

    --color-border: #22263a;
    --color-border-strong: #2f3449;
    --color-border-subtle: #171a26;

    --color-accent: #4fd1e0;          /* 10:1 on base */
    --color-accent-dim: rgba(79, 209, 224, 0.14);
    --color-accent-muted: rgba(79, 209, 224, 0.35);
    --color-accent-fg: #0a0b10;

    --color-brand: #ff3b3b;
    --color-brand-dim: rgba(255, 59, 59, 0.14);

    --color-danger: #ff6b6b;  --color-danger-dim: rgba(255, 107, 107, 0.15);
    --color-warning: #f0b344; --color-warning-dim: rgba(240, 179, 68, 0.15);
    --color-success: #5fd39a; --color-success-dim: rgba(95, 211, 154, 0.15);

    --sev-0: #9a9eb2; --sev-0-dim: rgba(154, 158, 178, 0.16);
    --sev-1: #f0c34a; --sev-1-dim: rgba(240, 195, 74, 0.16);
    --sev-2: #ff9440; --sev-2-dim: rgba(255, 148, 64, 0.16);
    --sev-3: #ff5c5c; --sev-3-dim: rgba(255, 92, 92, 0.16);
    --sev-4: #d17dff; --sev-4-dim: rgba(209, 125, 255, 0.16);

    --ramp-0: #1a1e2b;
    --ramp-1: rgba(79, 209, 224, 0.22);
    --ramp-2: rgba(79, 209, 224, 0.42);
    --ramp-3: rgba(79, 209, 224, 0.68);
    --ramp-4: #4fd1e0;

    --grid-texture:
      repeating-linear-gradient(0deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 32px),
      repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 32px);
    color-scheme: dark;
  }
}

:root[data-theme="dark"] {
  --color-bg-base: #0a0b10;
  --color-bg-surface: #10121a;
  --color-bg-elevated: #171a24;
  --color-bg-hover: #1f2330;
  --color-bg-active: #282d3c;
  --color-fg-primary: #e4e6ee;
  --color-fg-secondary: #a0a4b8;
  --color-fg-muted: #8a8ea6;
  --color-border: #22263a;
  --color-border-strong: #2f3449;
  --color-border-subtle: #171a26;
  --color-accent: #4fd1e0;
  --color-accent-dim: rgba(79, 209, 224, 0.14);
  --color-accent-muted: rgba(79, 209, 224, 0.35);
  --color-accent-fg: #0a0b10;
  --color-brand: #ff3b3b;
  --color-brand-dim: rgba(255, 59, 59, 0.14);
  --color-danger: #ff6b6b;  --color-danger-dim: rgba(255, 107, 107, 0.15);
  --color-warning: #f0b344; --color-warning-dim: rgba(240, 179, 68, 0.15);
  --color-success: #5fd39a; --color-success-dim: rgba(95, 211, 154, 0.15);
  --sev-0: #9a9eb2; --sev-0-dim: rgba(154, 158, 178, 0.16);
  --sev-1: #f0c34a; --sev-1-dim: rgba(240, 195, 74, 0.16);
  --sev-2: #ff9440; --sev-2-dim: rgba(255, 148, 64, 0.16);
  --sev-3: #ff5c5c; --sev-3-dim: rgba(255, 92, 92, 0.16);
  --sev-4: #d17dff; --sev-4-dim: rgba(209, 125, 255, 0.16);
  --ramp-0: #1a1e2b;
  --ramp-1: rgba(79, 209, 224, 0.22);
  --ramp-2: rgba(79, 209, 224, 0.42);
  --ramp-3: rgba(79, 209, 224, 0.68);
  --ramp-4: #4fd1e0;
  --grid-texture:
    repeating-linear-gradient(0deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 32px),
    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 32px);
  color-scheme: dark;
}
```

- [ ] **Step 4: Verify contrast**

Run this script from the scratchpad; every printed ratio must be ≥ 4.5. Adjust the token if not.

```python
# contrast.py
def lum(h):
    h=h.lstrip('#'); r,g,b=[int(h[i:i+2],16)/255 for i in (0,2,4)]
    f=lambda c: c/12.92 if c<=0.03928 else ((c+0.055)/1.055)**2.4
    return 0.2126*f(r)+0.7152*f(g)+0.0722*f(b)
def ratio(a,b):
    la,lb=lum(a),lum(b); hi,lo=max(la,lb),min(la,lb); return (hi+0.05)/(lo+0.05)
light_bg=['#f6f5f0','#efede6','#ffffff']
dark_bg=['#0a0b10','#10121a','#171a24']
light_fg={'muted':'#66686f','accent':'#1f6f8b','brand':'#b30000','danger':'#b3382c','warning':'#845b16','success':'#2b7048','sev1':'#8a6a00','sev2':'#b04a00','sev3':'#b31c1c','sev4':'#7a1fa2','sev0':'#6b6d74'}
dark_fg={'muted':'#8a8ea6','accent':'#4fd1e0','brand':'#ff3b3b','danger':'#ff6b6b','warning':'#f0b344','success':'#5fd39a','sev1':'#f0c34a','sev2':'#ff9440','sev3':'#ff5c5c','sev4':'#d17dff','sev0':'#9a9eb2'}
for name,fgs,bgs in (('light',light_fg,light_bg),('dark',dark_fg,dark_bg)):
    for k,fg in fgs.items():
        worst=min(ratio(fg,bg) for bg in bgs)
        print(f"{name} {k:8} {worst:5.2f} {'OK' if worst>=4.5 else 'FAIL'}")
```
Run: `python3 contrast.py`. Expected: all `OK`.

- [ ] **Step 5: Base, layout and component layers**

`assets/css/10-base.css`:
```css
*, *::before, *::after { box-sizing: border-box; }
html { font-size: 16px; -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; }
body {
  margin: 0; min-height: 100vh;
  background: var(--color-bg-base); background-image: var(--grid-texture);
  color: var(--color-fg-primary); font-family: var(--font-sans);
  font-size: var(--text-base); line-height: 1.5;
  font-variant-numeric: tabular-nums;
}
a { color: var(--color-accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.mono, code, pre, kbd { font-family: var(--font-mono); font-size: 0.95em; }
h1 { font-size: var(--text-2xl); font-weight: 600; letter-spacing: -0.02em; margin: 0 0 0.5rem; }
h2 { font-size: var(--text-lg); font-weight: 600; letter-spacing: -0.01em; margin: 0 0 0.75rem; }
h3 { font-size: var(--text-md); font-weight: 600; margin: 0 0 0.5rem; }
p { margin: 0 0 0.75rem; }
.label { font-size: var(--text-xs); color: var(--color-fg-muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 500; }
.muted { color: var(--color-fg-muted); }
.secondary { color: var(--color-fg-secondary); }
.num { font-variant-numeric: tabular-nums; text-align: right; }
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-thumb { background: var(--color-border-strong); border-radius: 3px; }
:focus-visible { outline: 1.5px solid var(--color-accent); outline-offset: 2px; }
::selection { background: var(--color-accent-muted); }
.visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
```

`assets/css/20-layout.css`:
```css
.topbar { position: sticky; top: 0; z-index: 10; border-bottom: 1px solid var(--color-border);
  background: color-mix(in srgb, var(--color-bg-surface) 88%, transparent); backdrop-filter: blur(8px); }
.topbar-row { max-width: var(--shell-max); margin: 0 auto; padding: 0 1rem; height: 3.25rem;
  display: flex; align-items: center; gap: 1.25rem; }
.brand { display: flex; align-items: center; gap: 0.6rem; color: var(--color-fg-primary); font-weight: 600; letter-spacing: -0.01em; }
.brand img { width: 26px; height: 26px; border-radius: 6px; }
.brand:hover { text-decoration: none; }
.nav { display: flex; gap: 0.25rem; flex: 1; }
.nav a { color: var(--color-fg-secondary); padding: 0.35rem 0.6rem; border-radius: var(--radius-md); font-size: var(--text-sm); }
.nav a:hover { background: var(--color-bg-hover); text-decoration: none; color: var(--color-fg-primary); }
.nav a[aria-current="page"] { color: var(--color-fg-primary); background: var(--color-bg-active); }
.topbar-actions { display: flex; align-items: center; gap: 0.5rem; }
.shell { max-width: var(--shell-max); margin: 0 auto; padding: 1.5rem 1rem 3rem; }
.page-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.75rem; margin-bottom: 1.25rem; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
.stack { display: grid; gap: 1rem; }
.footer { max-width: var(--shell-max); margin: 0 auto; padding: 1rem; color: var(--color-fg-muted); font-size: var(--text-xs); display: flex; justify-content: space-between; }
@media (max-width: 48rem) {
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .nav { overflow-x: auto; }
  .topbar-row { gap: 0.75rem; }
  .table-wrap { overflow-x: auto; }
}
```

`assets/css/30-components.css`:
```css
.card { background: var(--color-bg-elevated); border: 1px solid var(--color-border); border-radius: var(--radius-lg); padding: 1rem 1.25rem; }
.card > h2:first-child { margin-top: 0; }
.card-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: 0.75rem; }
.tile { background: var(--color-bg-elevated); border: 1px solid var(--color-border); border-radius: var(--radius-lg); padding: 0.9rem 1.1rem; }
.tile .label { display: block; margin-bottom: 0.25rem; }
.tile .value { font-size: var(--text-2xl); font-weight: 600; letter-spacing: -0.02em; line-height: 1.1; }
.tile .value.brand { color: var(--color-brand); }
.tile .hint { color: var(--color-fg-muted); font-size: var(--text-xs); margin-top: 0.25rem; }

.table-wrap { border: 1px solid var(--color-border); border-radius: var(--radius-lg); background: var(--color-bg-elevated); overflow: hidden; }
table { width: 100%; border-collapse: collapse; font-size: var(--text-sm); }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--color-border-subtle); vertical-align: top; }
th { position: sticky; top: 0; background: var(--color-bg-surface); color: var(--color-fg-muted); font-weight: 500; font-size: var(--text-xs); text-transform: uppercase; letter-spacing: 0.05em; }
tbody tr:hover { background: var(--color-bg-hover); }
tbody tr:last-child td { border-bottom: 0; }
td.path { font-family: var(--font-mono); word-break: break-all; max-width: 40rem; }
td.ip { font-family: var(--font-mono); white-space: nowrap; }
td.ts { white-space: nowrap; color: var(--color-fg-secondary); font-family: var(--font-mono); font-size: var(--text-xs); }
.empty { padding: 2rem; text-align: center; color: var(--color-fg-muted); }

.badge { display: inline-block; padding: 0.05rem 0.45rem; border-radius: 999px; font-size: var(--text-xs); font-weight: 500; line-height: 1.5; white-space: nowrap; border: 1px solid transparent; }
.badge-label { background: var(--color-accent-dim); color: var(--color-accent); border-color: var(--color-accent-muted); font-family: var(--font-mono); }
.badge-tor { background: var(--color-brand-dim); color: var(--color-brand); }
.badge-status { background: var(--color-bg-active); color: var(--color-fg-secondary); }
.badge-status[data-status="running"] { background: var(--color-warning-dim); color: var(--color-warning); }
.badge-status[data-status="done"] { background: var(--color-success-dim); color: var(--color-success); }
.badge-status[data-status="failed"] { background: var(--color-danger-dim); color: var(--color-danger); }
.sev { display: inline-block; min-width: 1.6rem; text-align: center; padding: 0.05rem 0.4rem; border-radius: var(--radius-sm); font-family: var(--font-mono); font-size: var(--text-xs); font-weight: 500; }
.sev-0 { background: var(--sev-0-dim); color: var(--sev-0); }
.sev-1 { background: var(--sev-1-dim); color: var(--sev-1); }
.sev-2 { background: var(--sev-2-dim); color: var(--sev-2); }
.sev-3 { background: var(--sev-3-dim); color: var(--sev-3); }
.sev-4 { background: var(--sev-4-dim); color: var(--sev-4); }
.chips { display: flex; flex-wrap: wrap; gap: 0.35rem; }

.btn { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.85rem; border-radius: var(--radius-md); border: 1px solid var(--color-border-strong);
  background: var(--color-bg-elevated); color: var(--color-fg-primary); font: inherit; font-size: var(--text-sm); cursor: pointer; }
.btn:hover { background: var(--color-bg-hover); text-decoration: none; }
.btn-primary { background: var(--color-accent); border-color: var(--color-accent); color: var(--color-accent-fg); }
.btn-primary:hover { filter: brightness(1.08); background: var(--color-accent); }
.btn-ghost { background: transparent; border-color: transparent; color: var(--color-fg-secondary); }
.btn-ghost:hover { background: var(--color-bg-hover); color: var(--color-fg-primary); }
.btn-danger { background: var(--color-danger-dim); border-color: transparent; color: var(--color-danger); }
.btn-danger:hover { background: var(--color-danger); color: #fff; }
.btn-sm { padding: 0.2rem 0.55rem; font-size: var(--text-xs); }
.btn-block { width: 100%; justify-content: center; }

input, select { font: inherit; font-size: var(--text-sm); color: var(--color-fg-primary); background: var(--color-bg-elevated);
  border: 1px solid var(--color-border-strong); border-radius: var(--radius-md); padding: 0.4rem 0.6rem; }
input:focus, select:focus { border-color: var(--color-accent); outline: none; box-shadow: 0 0 0 3px var(--color-accent-dim); }
.filters { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: end; margin-bottom: 1rem; }
.filters label { display: grid; gap: 0.2rem; font-size: var(--text-xs); color: var(--color-fg-muted); }
.filters input[name="q"], .filters input[name="path"] { min-width: 16rem; font-family: var(--font-mono); }

.seg { display: inline-flex; border: 1px solid var(--color-border-strong); border-radius: var(--radius-md); overflow: hidden; }
.seg a { padding: 0.3rem 0.7rem; font-size: var(--text-xs); color: var(--color-fg-secondary); border-right: 1px solid var(--color-border); }
.seg a:last-child { border-right: 0; }
.seg a:hover { background: var(--color-bg-hover); text-decoration: none; }
.seg a[aria-current="true"] { background: var(--color-accent); color: var(--color-accent-fg); }

.pagination { display: flex; justify-content: space-between; align-items: center; margin-top: 0.75rem; color: var(--color-fg-muted); font-size: var(--text-sm); }

.banner { border-radius: var(--radius-md); padding: 0.6rem 0.9rem; margin-bottom: 1rem; font-size: var(--text-sm); border: 1px solid; }
.banner-warning { background: var(--color-warning-dim); color: var(--color-warning); border-color: var(--color-warning); }

.live { display: inline-flex; align-items: center; gap: 0.4rem; font-size: var(--text-xs); color: var(--color-fg-muted); }
.live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--color-fg-muted); }
.live[data-state="open"] .live-dot { background: var(--color-success); box-shadow: 0 0 0 0 var(--color-success); animation: pulse 1.8s infinite; }
.live[data-state="reconnecting"] .live-dot { background: var(--color-warning); }
@keyframes pulse { 0% { box-shadow: 0 0 0 0 var(--color-success-dim); } 70% { box-shadow: 0 0 0 8px transparent; } 100% { box-shadow: 0 0 0 0 transparent; } }

dialog { border: 1px solid var(--color-border-strong); border-radius: var(--radius-lg); background: var(--color-bg-elevated); color: var(--color-fg-primary); padding: 1.25rem; max-width: 26rem; }
dialog::backdrop { background: rgba(0,0,0,0.5); }
dialog .actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }

.kv { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; font-size: var(--text-sm); }
.kv dt { color: var(--color-fg-muted); }
.kv dd { margin: 0; font-family: var(--font-mono); word-break: break-all; }
pre.panel { background: var(--color-bg-surface); border: 1px solid var(--color-border); border-radius: var(--radius-md); padding: 0.75rem 1rem; overflow: auto; font-size: var(--text-xs); max-height: 32rem; }
.ip-head h1 { font-family: var(--font-mono); font-size: var(--text-3xl); letter-spacing: 0; }
.meta { display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; color: var(--color-fg-secondary); font-size: var(--text-sm); }
.danger-zone { border-color: var(--color-danger); }
.auth-card { max-width: 24rem; margin: 4rem auto; text-align: center; }
.auth-card img { width: 72px; height: 72px; border-radius: 16px; margin-bottom: 1rem; }
.status { min-height: 1.5rem; margin-top: 0.75rem; color: var(--color-danger); font-size: var(--text-sm); }
```

`assets/css/40-charts.css`: create with the single line `/* charts: filled in Task 8 */`.

- [ ] **Step 6: Theme script and app.js skeleton**

`assets/js/theme.js` (loaded blocking, first in `<head>`):
```js
(function () {
  try {
    var t = localStorage.getItem("peephole.theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) {}
})();
```

`assets/js/app.js` (deferred; grows in later tasks):
```js
(function () {
  "use strict";
  // Theme toggle: system → light → dark → system.
  var btn = document.querySelector("[data-theme-toggle]");
  if (btn) {
    var label = btn.querySelector("[data-theme-label]");
    var render = function () {
      var t = document.documentElement.getAttribute("data-theme") || "auto";
      if (label) label.textContent = t === "auto" ? "Auto" : t === "dark" ? "Dark" : "Light";
    };
    btn.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme") || "auto";
      var next = cur === "auto" ? "light" : cur === "light" ? "dark" : "auto";
      if (next === "auto") document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", next);
      try { if (next === "auto") localStorage.removeItem("peephole.theme"); else localStorage.setItem("peephole.theme", next); } catch (e) {}
      render();
    });
    render();
  }
  window.peephole = window.peephole || {};
})();
```

- [ ] **Step 7: Embedded asset router**

`src/admin/assets.rs`:
```rust
//! Assets compiled into the binary. URLs carry `?v=STAMP` (content hash from
//! build.rs) so they can be cached for a year.
use crate::admin::AdminState;
use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;

pub const STAMP: &str = env!("ASSET_STAMP");
pub const VERSION: &str = env!("PEEPHOLE_VERSION");

struct Asset {
    path: &'static str,
    mime: &'static str,
    bytes: &'static [u8],
}

static ASSETS: &[Asset] = &[
    Asset { path: "app.css", mime: "text/css; charset=utf-8", bytes: include_bytes!("../../assets/app.css") },
    Asset { path: "js/theme.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../../assets/js/theme.js") },
    Asset { path: "js/app.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../../assets/js/app.js") },
    Asset { path: "js/charts.js", mime: "text/javascript; charset=utf-8", bytes: include_bytes!("../../assets/js/charts.js") },
    Asset { path: "fonts/inter-400.woff2", mime: "font/woff2", bytes: include_bytes!("../../assets/fonts/inter-400.woff2") },
    Asset { path: "fonts/inter-500.woff2", mime: "font/woff2", bytes: include_bytes!("../../assets/fonts/inter-500.woff2") },
    Asset { path: "fonts/inter-600.woff2", mime: "font/woff2", bytes: include_bytes!("../../assets/fonts/inter-600.woff2") },
    Asset { path: "fonts/jetbrains-mono-400.woff2", mime: "font/woff2", bytes: include_bytes!("../../assets/fonts/jetbrains-mono-400.woff2") },
    Asset { path: "fonts/jetbrains-mono-500.woff2", mime: "font/woff2", bytes: include_bytes!("../../assets/fonts/jetbrains-mono-500.woff2") },
    Asset { path: "logo.svg", mime: "image/svg+xml", bytes: include_bytes!("../../assets/logo.svg") },
    Asset { path: "world.svg", mime: "image/svg+xml", bytes: include_bytes!("../../assets/world.svg") },
];

pub fn router() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/assets/{*path}", get(serve))
        .route("/logo.svg", get(|| async { serve(Path("logo.svg".into())).await }))
}

async fn serve(Path(path): Path<String>) -> Response {
    match ASSETS.iter().find(|a| a.path == path) {
        Some(a) => (
            [
                (header::CONTENT_TYPE, a.mime),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            a.bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
```

Create an empty `assets/js/charts.js` containing `/* charts: filled in Task 8 */` and a placeholder `assets/world.svg` containing `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 500"></svg>` so `include_bytes!` compiles before Task 8 replaces it.

- [ ] **Step 8: Chrome struct and layout template**

`src/admin/views.rs`:
```rust
//! Shared template context. Every page struct carries a `Chrome`.
use crate::admin::assets::{STAMP, VERSION};

pub struct Chrome {
    pub authed: bool,
    /// Which nav item is current: "wall" | "ips" | "requests" | "admin" | "".
    pub active: &'static str,
    pub stamp: &'static str,
    pub version: &'static str,
}

impl Chrome {
    pub fn new(authed: bool, active: &'static str) -> Self {
        Self { authed, active, stamp: STAMP, version: VERSION }
    }
}

/// CSS class for a severity 0..4 (clamped). Generic so templates can pass
/// either an `i64` or the `&i64` a `{% let %}` binding produces.
pub fn sev_class<S: std::borrow::Borrow<i64>>(sev: S) -> String {
    format!("sev sev-{}", sev.borrow().clamp(&0, &4))
}
```

`templates/layout.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <script src="/assets/js/theme.js?v={{ chrome.stamp }}"></script>
  <title>{% block title %}peephole{% endblock %}</title>
  <link rel="icon" href="/assets/logo.svg?v={{ chrome.stamp }}" type="image/svg+xml">
  <meta name="theme-color" content="#f6f5f0" media="(prefers-color-scheme: light)">
  <meta name="theme-color" content="#0a0b10" media="(prefers-color-scheme: dark)">
  <link rel="stylesheet" href="/assets/app.css?v={{ chrome.stamp }}">
  <script src="/assets/js/app.js?v={{ chrome.stamp }}" defer></script>
  {% block head %}{% endblock %}
</head>
<body>
<header class="topbar">
  <div class="topbar-row">
    <a class="brand" href="/"><img src="/assets/logo.svg?v={{ chrome.stamp }}" alt=""><span>peephole</span></a>
    <nav class="nav" aria-label="Primary">
      <a href="/"{% if chrome.active == "wall" %} aria-current="page"{% endif %}>Wall</a>
      <a href="/ips"{% if chrome.active == "ips" %} aria-current="page"{% endif %}>IPs</a>
      <a href="/requests"{% if chrome.active == "requests" %} aria-current="page"{% endif %}>Requests</a>
      {% if chrome.authed %}<a href="/admin"{% if chrome.active == "admin" %} aria-current="page"{% endif %}>Admin</a>{% endif %}
    </nav>
    <div class="topbar-actions">
      <button class="btn btn-ghost btn-sm" type="button" data-theme-toggle aria-label="Toggle theme"><span data-theme-label>Auto</span></button>
      {% if chrome.authed %}
        <form method="post" action="/logout"><button class="btn btn-ghost btn-sm" type="submit">Log out</button></form>
      {% else %}
        <a class="btn btn-ghost btn-sm" href="/login">Admin login</a>
      {% endif %}
    </div>
  </div>
</header>
<main class="shell">
{% block content %}{% endblock %}
</main>
<footer class="footer"><span>peephole · scan the scanners</span><span class="mono">{{ chrome.version }}</span></footer>
</body>
</html>
```

- [ ] **Step 9: Wire the assets router and a security-header middleware into `admin::router`**

In `src/admin/mod.rs` add `pub mod assets; pub mod views;`, and replace `router` with:

```rust
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(stats_json))
        .route("/api/queue", get(sse::queue_stream))
        .merge(assets::router())
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; \
             connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    h.insert(axum::http::header::REFERRER_POLICY, axum::http::HeaderValue::from_static("no-referrer"));
    h.insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, axum::http::HeaderValue::from_static("nosniff"));
    res
}
```
Remove the old `logo` handler and its route (the assets router now serves `/logo.svg`). Keep `dashboard`, `stats_json`, `render_dashboard` for now; they are replaced in Task 8.

Note: `router_with_auth` merges `auth::auth_routes()` and `detail::routes()` after `router(...)`; those merged routes are outside the `.layer` call, so move the layer: build all routes first, then apply the layer once. Restructure `router_with_auth`:

```rust
pub fn router_with_auth(store: Store, cfg: Config) -> Router {
    let state = Arc::new(AdminState::public_only(store, cfg));
    full_router(state)
}

pub fn full_router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/stats", get(stats_json))
        .route("/api/queue", get(sse::queue_stream))
        .merge(assets::router())
        .merge(auth::auth_routes())
        .merge(detail::routes())
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Public-only router used by early tests; same middleware.
pub fn router(state: Arc<AdminState>) -> Router {
    full_router(state)
}
```

- [ ] **Step 10: Write the failing integration test**

Append to `tests/integration.rs`:
```rust
#[tokio::test]
async fn assets_and_security_headers() {
    let (_trap, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let resp = reqwest::get(format!("{base}/assets/app.css")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("cache-control").unwrap().to_str().unwrap().contains("max-age=31536000"));
    assert!(resp.headers().get("content-type").unwrap().to_str().unwrap().starts_with("text/css"));
    let css = resp.text().await.unwrap();
    assert!(css.contains("--color-accent"));
    assert!(css.contains("@font-face"));

    let resp = reqwest::get(format!("{base}/assets/fonts/inter-400.woff2")).await.unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "font/woff2");

    let resp = reqwest::get(format!("{base}/")).await.unwrap();
    let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(resp.headers().get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(resp.headers().get("x-content-type-options").unwrap(), "nosniff");

    assert_eq!(reqwest::get(format!("{base}/assets/nope.css")).await.unwrap().status(), 404);
}
```

- [ ] **Step 11: Run the test, expect failure**

Run: `cargo test --test integration assets_and_security_headers`
Expected: compile error (module `assets` missing) before Steps 7–9, then FAIL/404 until wiring is complete. After completing Steps 1–9 re-run.

- [ ] **Step 12: Run the test, expect pass; run the whole suite**

Run: `cargo test`
Expected: all pass (existing tests untouched: `/`, `/api/stats`, `/api/queue`, `/logo.svg` still served).

- [ ] **Step 13: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add Cargo.toml Cargo.lock askama.toml build.rs .gitignore assets src/admin tests/integration.rs
git commit -m "feat(ui): build script, askama 0.16, embedded assets, design tokens, layout

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 2: Error type and styled error pages

**Files:**
- Create: `src/admin/error.rs`, `templates/error.html`
- Modify: `src/admin/mod.rs`
- Test: `tests/integration.rs`

**Interfaces:**
- Produces: `crate::admin::error::{AppError, AppResult<T>}`; `AppError::NotFound`, `AppError::BadRequest(String)`, `AppError::Internal(anyhow::Error)`; `From<anyhow::Error>`, `From<sqlx::Error>`, `From<askama::Error>`; `IntoResponse` renders `error.html`. Helper `crate::admin::error::render<T: askama::Template>(t: &T) -> AppResult<axum::response::Html<String>>`.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn unknown_route_renders_styled_404() {
    let (_trap, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let resp = reqwest::get(format!("{base}/this/does/not/exist")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Not found"));
    assert!(html.contains("/assets/app.css"));
}
```

- [ ] **Step 2: Run it, expect failure**

Run: `cargo test --test integration unknown_route_renders_styled_404`
Expected: FAIL — body is axum's empty 404.

- [ ] **Step 3: Implement**

`templates/error.html`:
```html
{% extends "layout.html" %}
{% block title %}{{ title }} — peephole{% endblock %}
{% block content %}
<div class="card auth-card">
  <img src="/assets/logo.svg?v={{ chrome.stamp }}" alt="">
  <h1>{{ title }}</h1>
  <p class="muted">{{ detail }}</p>
  <a class="btn" href="/">Back to the wall</a>
</div>
{% endblock %}
```

`src/admin/error.rs`:
```rust
use crate::admin::views::Chrome;
use askama::Template;
use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    chrome: Chrome,
    title: &'static str,
    detail: String,
}

#[derive(Debug)]
pub enum AppError {
    NotFound,
    BadRequest(String),
    Internal(anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        AppError::Internal(e)
    }
}
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}
impl From<askama::Error> for AppError {
    fn from(e: askama::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, title, detail) = match self {
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not found", "Nothing lives at this address.".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "Bad request", m),
            AppError::Internal(e) => {
                tracing::error!(error = ?e, "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "Something broke", "The error has been logged.".to_string())
            }
        };
        let page = ErrorPage { chrome: Chrome::new(false, ""), title, detail };
        match page.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, title).into_response(),
        }
    }
}

/// Render any template into an `Html` response, mapping template errors.
pub fn render<T: Template>(t: &T) -> AppResult<Html<String>> {
    Ok(Html(t.render()?))
}

pub async fn not_found() -> AppError {
    AppError::NotFound
}
```

In `src/admin/mod.rs`: `pub mod error;` and add `.fallback(error::not_found)` to `full_router` before `.layer(...)`.

- [ ] **Step 4: Run test, expect pass**

Run: `cargo test --test integration unknown_route_renders_styled_404`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/admin templates/error.html tests/integration.rs
git commit -m "feat(admin): AppError with styled 404/500 pages

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 3: Queue events — Notifier, worker/trap publishing, gated SSE

**Files:**
- Create: `src/events.rs`
- Modify: `src/lib.rs`, `src/admin/mod.rs`, `src/admin/sse.rs`, `src/scan/mod.rs`, `src/trap/mod.rs`, `src/store/scans.rs`
- Test: `tests/integration.rs`, `src/events.rs` unit test

**Interfaces:**
- Produces:
  ```rust
  // src/events.rs
  #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
  pub struct QueueJob { pub id: i64, pub ip: String, pub level: i64, pub status: String,
      pub queued_at: String, pub started_at: Option<String>, pub finished_at: Option<String>, pub error: Option<String> }
  #[derive(Clone)] pub struct Notifier { tx: tokio::sync::broadcast::Sender<QueueJob> }
  impl Notifier { pub fn new() -> Self; pub fn publish(&self, job: QueueJob); pub fn subscribe(&self) -> broadcast::Receiver<QueueJob>; }
  impl Default for Notifier
  // src/store/scans.rs
  impl Store { pub async fn queue_job(&self, id: i64) -> Result<Option<QueueJob>>;
               pub async fn queue_snapshot(&self, limit: i64) -> Result<Vec<QueueJob>>; }
  // src/admin/mod.rs
  pub struct AdminState { pub store: Store, pub cfg: Config, pub notifier: Notifier, pub stats_cache: crate::store::stats::StatsCache /* Task 4 */ }
  impl AdminState { pub fn new(store, cfg, notifier) -> Self; pub fn public_only(store, cfg) -> Self /* = new(.., Notifier::new()) */ }
  // src/trap/mod.rs
  pub struct TrapState { ..., pub notifier: Notifier }
  // src/scan/mod.rs
  pub async fn run_workers(store, cfg, nmap_path, shutdown, notifier: Notifier)
  ```
  SSE route moves to `/admin/api/queue`, gated by `SessionUser`; events: `snapshot` (JSON array of `QueueJob`), `job` (one `QueueJob`).

- [ ] **Step 1: Write the unit test for Notifier and the store queries**

`src/events.rs` (test module at bottom, implementation in Step 3):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn publish_reaches_subscribers_and_lag_is_reported() {
        let n = Notifier::new();
        let mut rx = n.subscribe();
        n.publish(QueueJob { id: 1, ip: "203.0.113.1".into(), level: 2, status: "queued".into(),
            queued_at: "now".into(), started_at: None, finished_at: None, error: None });
        assert_eq!(rx.recv().await.unwrap().id, 1);
        // Overflow the channel (capacity 256) → Lagged.
        for i in 0..300 {
            n.publish(QueueJob { id: i, ip: String::new(), level: 1, status: "queued".into(),
                queued_at: String::new(), started_at: None, finished_at: None, error: None });
        }
        assert!(matches!(rx.recv().await, Err(tokio::sync::broadcast::error::RecvError::Lagged(_))));
    }
}
```

Add to `src/store/scans.rs` tests:
```rust
#[tokio::test]
async fn queue_job_and_snapshot_join_ip() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
    let id = match s.enqueue_scan(ip.id, 2, 24).await.unwrap() {
        EnqueueOutcome::Queued(id) => id,
        other => panic!("{other:?}"),
    };
    let job = s.queue_job(id).await.unwrap().unwrap();
    assert_eq!(job.ip, "203.0.113.5");
    assert_eq!(job.status, "queued");
    let snap = s.queue_snapshot(50).await.unwrap();
    assert_eq!(snap.len(), 1);
    assert!(s.queue_job(9999).await.unwrap().is_none());
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `cargo test events:: store::scans::tests::queue_job_and_snapshot_join_ip`
Expected: FAIL — `events` module / `queue_job` missing.

- [ ] **Step 3: Implement events.rs and store queries**

`src/events.rs`:
```rust
//! Scan-queue change notifications. Publishers: the trap (enqueue) and the
//! scan workers (running/done/failed). Subscriber: the admin SSE stream.
use tokio::sync::broadcast;

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct QueueJob {
    pub id: i64,
    pub ip: String,
    pub level: i64,
    pub status: String,
    pub queued_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Notifier {
    tx: broadcast::Sender<QueueJob>,
}

impl Notifier {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self { tx }
    }
    /// Never fails: with no subscribers the event is simply dropped.
    pub fn publish(&self, job: QueueJob) {
        let _ = self.tx.send(job);
    }
    pub fn subscribe(&self) -> broadcast::Receiver<QueueJob> {
        self.tx.subscribe()
    }
}

impl Default for Notifier {
    fn default() -> Self {
        Self::new()
    }
}
```

`src/lib.rs`: add `pub mod events;`.

`src/store/scans.rs` additions:
```rust
use crate::events::QueueJob;

const QUEUE_JOB_SQL: &str =
    "SELECT j.id, i.ip, j.level, j.status, j.queued_at, j.started_at, j.finished_at, j.error
     FROM scan_jobs j JOIN ips i ON j.ip_id = i.id";

impl Store {
    pub async fn queue_job(&self, id: i64) -> Result<Option<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(&format!("{QUEUE_JOB_SQL} WHERE j.id = ?"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// Newest jobs first; `limit` rows.
    pub async fn queue_snapshot(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(&format!("{QUEUE_JOB_SQL} ORDER BY j.id DESC LIMIT ?"))
            .bind(limit)
            .fetch_all(&self.pool)
            .await?)
    }
}
```
`queued_at` etc. are stored as `datetime('now')` TEXT; `QueueJob` reads them as `String`, which sqlx's SQLite driver supports directly.

- [ ] **Step 4: Run unit tests, expect pass**

Run: `cargo test events:: queue_job_and_snapshot_join_ip`
Expected: PASS.

- [ ] **Step 5: Thread the Notifier through state, trap and workers**

`src/admin/mod.rs`:
```rust
pub struct AdminState {
    pub store: Store,
    pub cfg: Config,
    pub notifier: crate::events::Notifier,
}

impl AdminState {
    pub fn new(store: Store, cfg: Config, notifier: crate::events::Notifier) -> Self {
        Self { store, cfg, notifier }
    }
    pub fn public_only(store: Store, cfg: Config) -> Self {
        Self::new(store, cfg, crate::events::Notifier::new())
    }
}
```
(Task 4 adds `stats_cache`.)

`src/trap/mod.rs`: add `pub notifier: crate::events::Notifier` to `TrapState`; `for_test` sets `notifier: Default::default()`. In `record_and_respond`, after `enqueue_scan` returns, publish:
```rust
    if verdict.scan_level > 0 && !is_tor && !allowlisted {
        if let crate::store::scans::EnqueueOutcome::Queued(job_id) = state
            .store
            .enqueue_scan(ip_row.id, verdict.scan_level, state.cfg.scan.rescan_cooldown_hours)
            .await?
            && let Ok(Some(job)) = state.store.queue_job(job_id).await
        {
            state.notifier.publish(job);
        }
    }
```

`src/scan/mod.rs`: `run_workers` gains a fifth parameter `notifier: crate::events::Notifier`. After `Ok(Some(job))` from `next_queued_job` (the job is now `running`):
```rust
                    if let Ok(Some(j)) = store.queue_job(job.id).await {
                        notifier.publish(j);
                    }
```
and inside the spawned task, clone `notifier` before spawn (`let notifier2 = notifier.clone();`) and after every `finish_job` call add:
```rust
                        if let Ok(Some(j)) = store2.queue_job(job.id).await {
                            notifier2.publish(j);
                        }
```
Simplest: wrap the match in a helper closure-free structure — after the whole `match tokio::time::timeout(...)` block ends, add the publish once (the job row has its final status by then). Do that: one publish after the match.

Update the existing scan unit test `worker_runs_fake_nmap_and_stores_ports` to pass `crate::events::Notifier::new()`.

`src/lib.rs::run`: create `let notifier = events::Notifier::new();` before spawning workers; pass `notifier.clone()` to `scan::run_workers`, put `notifier: notifier.clone()` in `TrapState`, and build the admin router with `admin::full_router(Arc::new(admin::AdminState::new(store.clone(), cfg.clone(), notifier)))`.

- [ ] **Step 6: Write the failing SSE integration tests**

Replace `queue_sse_streams_job_updates` in `tests/integration.rs` with:
```rust
async fn read_sse_until(resp: reqwest::Response, needle: &str, secs: u64) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(secs), async {
        let mut resp = resp;
        let mut buf = String::new();
        while !buf.contains(needle) {
            match resp.chunk().await.unwrap() {
                Some(c) => buf.push_str(&String::from_utf8_lossy(&c)),
                None => break,
            }
        }
        buf
    })
    .await
    .expect("sse deadline")
}

#[tokio::test]
async fn queue_sse_requires_session_and_streams_snapshot_then_jobs() {
    let (trap_base, store, dir) = spawn_trap().await;
    let _ = reqwest::get(format!("{trap_base}/probe")).await.unwrap();
    // Unauthenticated → redirect to /login.
    let admin_base = spawn_admin_with(store.clone(), dir.path()).await;
    let resp = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
        .get(format!("{admin_base}/admin/api/queue")).send().await.unwrap();
    assert_eq!(resp.status(), 303);
    assert_eq!(resp.headers().get("location").unwrap(), "/login");

    // Authenticated: first event is a snapshot containing the queued probe job.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base, state) = enrolled_admin_client_with_state(store.clone(), cfg).await;
    let resp = client.get(format!("{base}/admin/api/queue")).send().await.unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "text/event-stream");
    let body = read_sse_until(resp, "event: snapshot", 5).await;
    assert!(body.contains("\"status\":\"queued\""));

    // A published job arrives as `event: job`.
    let resp = client.get(format!("{base}/admin/api/queue")).send().await.unwrap();
    let ip = store.upsert_ip("198.51.100.77".parse().unwrap()).await.unwrap();
    let id = match store.enqueue_scan(ip.id, 3, 24).await.unwrap() {
        peephole::store::scans::EnqueueOutcome::Queued(id) => id,
        o => panic!("{o:?}"),
    };
    state.notifier.publish(store.queue_job(id).await.unwrap().unwrap());
    let body = read_sse_until(resp, "event: job", 5).await;
    assert!(body.contains("198.51.100.77"));
}
```

Refactor `enrolled_admin_client` into `enrolled_admin_client_with_state(store, cfg) -> (reqwest::Client, String, Arc<AdminState>)` that builds `let state = Arc::new(AdminState::public_only(store.clone(), cfg)); let app = admin::full_router(state.clone());` and returns `state`; keep `enrolled_admin_client` as a thin wrapper dropping the state so other tests are unchanged.

Also update `authenticated_routes_redirect_without_session` so its list of gated paths includes `/admin/api/queue` (paths like `/requests/1` change in Task 10; leave them for now).

- [ ] **Step 7: Run, expect failure**

Run: `cargo test --test integration queue_sse_requires_session_and_streams_snapshot_then_jobs`
Expected: FAIL — `/admin/api/queue` is 404.

- [ ] **Step 8: Rewrite `src/admin/sse.rs`**

```rust
use crate::admin::{AdminState, auth::SessionUser};
use crate::events::QueueJob;
use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

const SNAPSHOT_ROWS: i64 = 100;

fn snapshot_event(jobs: &[QueueJob]) -> Event {
    Event::default()
        .event("snapshot")
        .data(serde_json::to_string(jobs).unwrap_or_else(|_| "[]".into()))
}

pub async fn queue_stream(
    _u: SessionUser,
    State(state): State<Arc<AdminState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.notifier.subscribe();
    let stream = async_stream(state, rx);
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keepalive"))
}

fn async_stream(
    state: Arc<AdminState>,
    rx: tokio::sync::broadcast::Receiver<QueueJob>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    struct St {
        state: Arc<AdminState>,
        rx: tokio::sync::broadcast::Receiver<QueueJob>,
        first: bool,
    }
    futures::stream::unfold(St { state, rx, first: true }, |mut st| async move {
        if st.first {
            st.first = false;
            let jobs = st.state.store.queue_snapshot(SNAPSHOT_ROWS).await.unwrap_or_default();
            return Some((Ok(snapshot_event(&jobs)), st));
        }
        let ev = tokio::select! {
            msg = st.rx.recv() => match msg {
                Ok(job) => Event::default().event("job").data(serde_json::to_string(&job).unwrap_or_default()),
                Err(RecvError::Lagged(_)) => {
                    let jobs = st.state.store.queue_snapshot(SNAPSHOT_ROWS).await.unwrap_or_default();
                    snapshot_event(&jobs)
                }
                Err(RecvError::Closed) => return None,
            },
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let jobs = st.state.store.queue_snapshot(SNAPSHOT_ROWS).await.unwrap_or_default();
                snapshot_event(&jobs)
            }
        };
        Some((Ok(ev), st))
    })
}
```

Route: in `full_router` replace `.route("/api/queue", get(sse::queue_stream))` with `.route("/admin/api/queue", get(sse::queue_stream))`. Remove the SSE `<script>` and queue table from `templates/dashboard.html` (the old dashboard dies in Task 8 anyway; removing the `/api/queue` reference now keeps the page from erroring in the console).

- [ ] **Step 9: Run all tests, expect pass**

Run: `cargo test`
Expected: PASS, including `full_stack_smoke` (still uses `/api/stats`).

- [ ] **Step 10: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src tests
git commit -m "feat(queue): broadcast notifier, gated SSE with snapshot/job events

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 4: Ranged statistics, timeline, map counts and the 15 s cache

**Files:**
- Create: `src/store/stats.rs`
- Modify: `src/store/mod.rs` (remove `PublicStats`, `RecentRequest`, `public_stats`; add `pub mod stats;`), `src/admin/mod.rs` (`stats_cache` field; `/api/stats` and `/api/map` use it), `src/store/schema.sql` (indexes)
- Test: `src/store/stats.rs` unit tests, `tests/integration.rs`

**Interfaces:**
- Produces:
  ```rust
  pub enum Range { H24, D7, D30, All }           // Copy, Eq, Hash, Serialize
  impl Range { pub fn parse(s: Option<&str>) -> Range; pub fn key(self) -> &'static str;
               pub fn label(self) -> &'static str; pub fn since(self) -> Option<&'static str>; pub fn hourly(self) -> bool; pub const ALL: [Range; 4]; }
  pub struct Named { pub name: String, pub count: i64 }
  pub struct TopIp { pub ip: String, pub count: i64, pub country: Option<String>, pub max_severity: i64, pub is_tor: bool }
  pub struct Bucket { pub ts: String, pub count: i64 }
  pub struct RecentRequest { pub id: i64, pub ts: String, pub ip: String, pub method: String, pub path: String, pub severity: i64, pub labels: Vec<String>, pub country: Option<String>, pub is_tor: bool }
  pub struct Stats { pub range: &'static str, pub generated_at: String, pub total_requests: i64, pub unique_ips: i64, pub countries: i64, pub tor_ips: i64,
      pub scans_done: i64, pub top_ips: Vec<TopIp>, pub top_countries: Vec<Named>, pub top_asns: Vec<Named>, pub top_labels: Vec<Named>,
      pub severity_distribution: Vec<Named>, pub timeline: Vec<Bucket>, pub recent: Vec<RecentRequest>, pub intel: HashMap<String,String> }
  pub struct MapCounts { pub range: &'static str, pub generated_at: String, pub countries: HashMap<String, i64>, pub max: i64 }
  impl Store { pub async fn stats(&self, r: Range) -> Result<Stats>; pub async fn map_counts(&self, r: Range) -> Result<MapCounts>; }
  pub struct StatsCache { .. } impl StatsCache { pub fn new() -> Self; pub async fn stats(&self, store: &Store, r: Range) -> Result<Arc<Stats>>; pub async fn map(&self, store: &Store, r: Range) -> Result<Arc<MapCounts>>; }
  pub fn intel_stale(intel: &HashMap<String,String>) -> bool   // moved from admin::render_dashboard
  ```
  All structs derive `Clone, serde::Serialize`.

- [ ] **Step 1: Write failing unit tests**

Bottom of `src/store/stats.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("198.51.100.2".parse().unwrap()).await.unwrap();
        s.set_ip_geo(a.id, Some("DE"), Some(3320), Some("Deutsche Telekom")).await.unwrap();
        s.set_ip_geo(b.id, Some("US"), Some(15169), Some("Google")).await.unwrap();
        s.set_ip_tor(b.id, true).await.unwrap();
        let req = |ip_id, path: &str, sev| NewRequest {
            ip_id, method: "GET".into(), path: path.into(), query: None, headers_json: "[]".into(), body: None,
            labels_json: r#"["sensitive-path"]"#.into(), severity: sev, scan_level: 1, is_fp_claim: false, page_token: None,
        };
        s.insert_request(&req(a.id, "/.env", 3)).await.unwrap();
        s.insert_request(&req(a.id, "/wp-login.php", 2)).await.unwrap();
        s.insert_request(&req(b.id, "/", 0)).await.unwrap();
        // One request 3 days old: outside 24h, inside 7d.
        sqlx::query("INSERT INTO requests (ts, ip_id, method, path, headers_json, labels_json, severity) VALUES (datetime('now','-3 days'), ?, 'GET', '/old', '[]', '[]', 1)")
            .bind(b.id).execute(&s.pool).await.unwrap();
        s
    }

    #[test]
    fn range_parse_falls_back_to_24h() {
        assert_eq!(Range::parse(Some("7d")), Range::D7);
        assert_eq!(Range::parse(Some("all")), Range::All);
        assert_eq!(Range::parse(Some("1y")), Range::H24);
        assert_eq!(Range::parse(None), Range::H24);
    }

    #[tokio::test]
    async fn stats_respect_range() {
        let s = seeded().await;
        let h24 = s.stats(Range::H24).await.unwrap();
        assert_eq!(h24.total_requests, 3);
        assert_eq!(h24.unique_ips, 2);
        assert_eq!(h24.countries, 2);
        assert_eq!(h24.tor_ips, 1);
        assert_eq!(h24.top_ips[0].ip, "203.0.113.1");
        assert_eq!(h24.top_ips[0].count, 2);
        assert_eq!(h24.top_ips[0].max_severity, 3);
        assert_eq!(h24.top_labels[0].name, "sensitive-path");
        assert_eq!(h24.top_labels[0].count, 3);
        assert_eq!(h24.recent.len(), 3);
        assert_eq!(h24.recent[0].labels, vec!["sensitive-path".to_string()]);
        let d7 = s.stats(Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 4);
        assert!(d7.timeline.iter().map(|b| b.count).sum::<i64>() == 4);
        assert!(d7.timeline.len() >= 2, "hourly buckets over 7 days");
        let all = s.stats(Range::All).await.unwrap();
        assert_eq!(all.total_requests, 4);
        assert!(all.timeline.iter().all(|b| b.ts.len() == 10), "daily buckets are YYYY-MM-DD");
    }

    #[tokio::test]
    async fn map_counts_unique_ips_per_country() {
        let s = seeded().await;
        let m = s.map_counts(Range::All).await.unwrap();
        assert_eq!(m.countries.get("DE"), Some(&1));
        assert_eq!(m.countries.get("US"), Some(&1));
        assert_eq!(m.max, 1);
    }

    #[tokio::test]
    async fn cache_serves_same_instance_within_ttl() {
        let s = seeded().await;
        let c = StatsCache::new();
        let a = c.stats(&s, Range::H24).await.unwrap();
        s.insert_request(&NewRequest { ip_id: 1, method: "GET".into(), path: "/new".into(), query: None, headers_json: "[]".into(), body: None,
            labels_json: "[]".into(), severity: 0, scan_level: 0, is_fp_claim: false, page_token: None }).await.unwrap();
        let b = c.stats(&s, Range::H24).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(b.total_requests, 3, "stale within ttl by design");
        let d7 = c.stats(&s, Range::D7).await.unwrap();
        assert_eq!(d7.total_requests, 5, "other range is computed fresh");
    }

    #[test]
    fn intel_stale_when_missing_or_old() {
        let mut m = HashMap::new();
        assert!(intel_stale(&m));
        m.insert("tor_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        m.insert("maxmind_last_fetch".into(), (chrono::Utc::now() - chrono::Duration::hours(72)).to_rfc3339());
        assert!(intel_stale(&m));
        m.insert("maxmind_last_fetch".into(), chrono::Utc::now().to_rfc3339());
        assert!(!intel_stale(&m));
    }
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `cargo test store::stats`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `src/store/stats.rs`**

```rust
//! Aggregates for the public wall of shame, per time range, plus a short
//! TTL cache so anonymous traffic cannot hammer SQLite.
use super::Store;
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Range {
    H24,
    D7,
    D30,
    All,
}

impl Range {
    pub const ALL: [Range; 4] = [Range::H24, Range::D7, Range::D30, Range::All];

    pub fn parse(s: Option<&str>) -> Range {
        match s {
            Some("7d") => Range::D7,
            Some("30d") => Range::D30,
            Some("all") => Range::All,
            _ => Range::H24,
        }
    }
    pub fn key(self) -> &'static str {
        match self { Range::H24 => "24h", Range::D7 => "7d", Range::D30 => "30d", Range::All => "all" }
    }
    pub fn label(self) -> &'static str {
        match self { Range::H24 => "Last 24 hours", Range::D7 => "Last 7 days", Range::D30 => "Last 30 days", Range::All => "All time" }
    }
    /// SQLite modifier for `datetime('now', ?)`; `None` = no bound.
    pub fn since(self) -> Option<&'static str> {
        match self { Range::H24 => Some("-24 hours"), Range::D7 => Some("-7 days"), Range::D30 => Some("-30 days"), Range::All => None }
    }
    pub fn hourly(self) -> bool {
        matches!(self, Range::H24 | Range::D7)
    }
    /// `WHERE`-fragment and bind value for `requests.ts`.
    fn ts_clause(self, col: &str) -> (String, Option<&'static str>) {
        match self.since() {
            Some(m) => (format!(" AND {col} >= datetime('now', ?)"), Some(m)),
            None => (String::new(), None),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct Named { pub name: String, pub count: i64 }

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct TopIp { pub ip: String, pub count: i64, pub country: Option<String>, pub max_severity: i64, pub is_tor: bool }

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct Bucket { pub ts: String, pub count: i64 }

#[derive(Clone, Debug, serde::Serialize)]
pub struct RecentRequest {
    pub id: i64, pub ts: String, pub ip: String, pub method: String, pub path: String,
    pub severity: i64, pub labels: Vec<String>, pub country: Option<String>, pub is_tor: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Stats {
    pub range: &'static str,
    pub generated_at: String,
    pub total_requests: i64,
    pub unique_ips: i64,
    pub countries: i64,
    pub tor_ips: i64,
    pub scans_done: i64,
    pub top_ips: Vec<TopIp>,
    pub top_countries: Vec<Named>,
    pub top_asns: Vec<Named>,
    pub top_labels: Vec<Named>,
    pub severity_distribution: Vec<Named>,
    pub timeline: Vec<Bucket>,
    pub recent: Vec<RecentRequest>,
    pub intel: HashMap<String, String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MapCounts {
    pub range: &'static str,
    pub generated_at: String,
    pub countries: HashMap<String, i64>,
    pub max: i64,
}

/// Bind the optional range modifier onto a query builder.
macro_rules! bind_since {
    ($q:expr, $since:expr) => {{
        let mut q = $q;
        if let Some(m) = $since { q = q.bind(m); }
        q
    }};
}

impl Store {
    pub async fn stats(&self, r: Range) -> Result<Stats> {
        let (w, since) = r.ts_clause("r.ts");
        let one = |sql: String| async move {
            bind_since!(sqlx::query_scalar::<_, i64>(&sql), since).fetch_one(&self.pool).await
        };
        let total_requests = one(format!("SELECT COUNT(*) FROM requests r WHERE 1=1{w}")).await?;
        let unique_ips = one(format!("SELECT COUNT(DISTINCT r.ip_id) FROM requests r WHERE 1=1{w}")).await?;
        let countries = one(format!(
            "SELECT COUNT(DISTINCT i.country) FROM requests r JOIN ips i ON r.ip_id = i.id WHERE i.country IS NOT NULL{w}")).await?;
        let tor_ips = one(format!(
            "SELECT COUNT(DISTINCT r.ip_id) FROM requests r JOIN ips i ON r.ip_id = i.id WHERE i.is_tor_exit = 1{w}")).await?;
        let (ws, since_s) = r.ts_clause("s.finished_at");
        let scans_done = bind_since!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM scans s WHERE 1=1{ws}")), since_s)
            .fetch_one(&self.pool).await?;

        let top_ips = bind_since!(sqlx::query_as::<_, TopIp>(&format!(
            "SELECT i.ip, COUNT(*) AS count, i.country, MAX(r.severity) AS max_severity, i.is_tor_exit AS is_tor
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             GROUP BY i.id ORDER BY count DESC LIMIT 20")), since).fetch_all(&self.pool).await?;
        let top_countries = bind_since!(sqlx::query_as::<_, Named>(&format!(
            "SELECT COALESCE(i.country,'??') AS name, COUNT(DISTINCT i.id) AS count
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             GROUP BY i.country ORDER BY count DESC LIMIT 20")), since).fetch_all(&self.pool).await?;
        let top_asns = bind_since!(sqlx::query_as::<_, Named>(&format!(
            "SELECT COALESCE(i.asn_org,'unknown') AS name, COUNT(DISTINCT i.id) AS count
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w}
             GROUP BY i.asn_org ORDER BY count DESC LIMIT 20")), since).fetch_all(&self.pool).await?;
        let top_labels = bind_since!(sqlx::query_as::<_, Named>(&format!(
            "SELECT je.value AS name, COUNT(*) AS count
             FROM requests r, json_each(r.labels_json) je WHERE 1=1{w}
             GROUP BY je.value ORDER BY count DESC LIMIT 20")), since).fetch_all(&self.pool).await?;
        let severity_distribution = bind_since!(sqlx::query_as::<_, Named>(&format!(
            "SELECT CAST(r.severity AS TEXT) AS name, COUNT(*) AS count FROM requests r WHERE 1=1{w}
             GROUP BY r.severity ORDER BY r.severity")), since).fetch_all(&self.pool).await?;
        let fmt = if r.hourly() { "%Y-%m-%dT%H:00" } else { "%Y-%m-%d" };
        let timeline = bind_since!(sqlx::query_as::<_, Bucket>(&format!(
            "SELECT strftime('{fmt}', r.ts) AS ts, COUNT(*) AS count FROM requests r WHERE 1=1{w}
             GROUP BY ts ORDER BY ts")), since).fetch_all(&self.pool).await?;
        let recent_rows = bind_since!(sqlx::query_as::<_, (i64, String, String, String, String, i64, String, Option<String>, bool)>(&format!(
            "SELECT r.id, r.ts, i.ip, r.method, r.path, r.severity, r.labels_json, i.country, i.is_tor_exit
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1{w} ORDER BY r.id DESC LIMIT 50")), since)
            .fetch_all(&self.pool).await?;
        let recent = recent_rows.into_iter().map(|(id, ts, ip, method, path, severity, labels, country, is_tor)| RecentRequest {
            id, ts, ip, method, path, severity, labels: serde_json::from_str(&labels).unwrap_or_default(), country, is_tor,
        }).collect();
        let intel = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
            .fetch_all(&self.pool).await?.into_iter().collect();
        Ok(Stats {
            range: r.key(), generated_at: chrono::Utc::now().to_rfc3339(),
            total_requests, unique_ips, countries, tor_ips, scans_done,
            top_ips, top_countries, top_asns, top_labels, severity_distribution, timeline, recent, intel,
        })
    }

    pub async fn map_counts(&self, r: Range) -> Result<MapCounts> {
        let (w, since) = r.ts_clause("r.ts");
        let rows = bind_since!(sqlx::query_as::<_, Named>(&format!(
            "SELECT i.country AS name, COUNT(DISTINCT i.id) AS count
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE i.country IS NOT NULL{w} GROUP BY i.country")), since)
            .fetch_all(&self.pool).await?;
        let max = rows.iter().map(|n| n.count).max().unwrap_or(0);
        Ok(MapCounts {
            range: r.key(), generated_at: chrono::Utc::now().to_rfc3339(),
            countries: rows.into_iter().map(|n| (n.name, n.count)).collect(), max,
        })
    }
}

/// Spec §9 of the original design: warn when Tor/MaxMind data is missing or >48h old.
pub fn intel_stale(intel: &HashMap<String, String>) -> bool {
    let stale = |key: &str| {
        intel.get(key)
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|t| chrono::Utc::now().signed_duration_since(t).num_hours() > 48)
            .unwrap_or(true)
    };
    stale("tor_last_fetch") || stale("maxmind_last_fetch")
}

const TTL: Duration = Duration::from_secs(15);

#[derive(Default)]
pub struct StatsCache {
    stats: RwLock<HashMap<Range, (Instant, Arc<Stats>)>>,
    map: RwLock<HashMap<Range, (Instant, Arc<MapCounts>)>>,
}

impl StatsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn stats(&self, store: &Store, r: Range) -> Result<Arc<Stats>> {
        if let Some((t, v)) = self.stats.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let fresh = Arc::new(store.stats(r).await?);
        self.stats.write().await.insert(r, (Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    pub async fn map(&self, store: &Store, r: Range) -> Result<Arc<MapCounts>> {
        if let Some((t, v)) = self.map.read().await.get(&r)
            && t.elapsed() < TTL
        {
            return Ok(v.clone());
        }
        let fresh = Arc::new(store.map_counts(r).await?);
        self.map.write().await.insert(r, (Instant::now(), fresh.clone()));
        Ok(fresh)
    }
}
```

`src/store/mod.rs`: add `pub mod stats;`, delete `PublicStats`, `RecentRequest`, `default_stats`, and `public_stats`. Fix compile errors in `src/admin/mod.rs` by switching `dashboard`/`stats_json` to `state.stats_cache.stats(&state.store, Range::parse(q.get("range")))` and adapt `render_dashboard` minimally (it dies in Task 8): use `s.top_ips` `TopIp` fields, `s.recent` fields, and `stats::intel_stale(&s.intel)`. Add `pub stats_cache: crate::store::stats::StatsCache` to `AdminState::new`.

Add the `/api/map` route:
```rust
#[derive(serde::Deserialize, Default)]
pub struct RangeQuery { pub range: Option<String> }

async fn stats_json(State(state): State<Arc<AdminState>>, Query(q): Query<RangeQuery>) -> AppResult<Json<Arc<Stats>>> {
    Ok(Json(state.stats_cache.stats(&state.store, Range::parse(q.range.as_deref())).await?))
}
async fn map_json(State(state): State<Arc<AdminState>>, Query(q): Query<RangeQuery>) -> AppResult<Json<Arc<MapCounts>>> {
    Ok(Json(state.stats_cache.map(&state.store, Range::parse(q.range.as_deref())).await?))
}
```
Route `.route("/api/map", get(map_json))`.

Append the indexes from spec §6.2 to `src/store/schema.sql`:
```sql
CREATE INDEX IF NOT EXISTS idx_requests_severity ON requests(severity);
CREATE INDEX IF NOT EXISTS idx_requests_ip_id_id ON requests(ip_id, id);
CREATE INDEX IF NOT EXISTS idx_ips_country ON ips(country);
CREATE INDEX IF NOT EXISTS idx_ips_asn ON ips(asn);
CREATE INDEX IF NOT EXISTS idx_scans_ip ON scans(ip_id);
CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_fingerprints_ip ON fingerprints(ip_id);
CREATE INDEX IF NOT EXISTS idx_fp_claims_ip ON fp_claims(ip_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_ip ON scan_jobs(ip_id);
```

- [ ] **Step 4: Integration test for the JSON endpoints**

```rust
#[tokio::test]
async fn stats_and_map_json_by_range() {
    let (trap_base, store, dir) = spawn_trap().await;
    let _ = reqwest::Client::new().get(format!("{trap_base}/x")).header("x-forwarded-for", "203.0.113.9").send().await.unwrap();
    let base = spawn_admin_with(store, dir.path()).await;
    let s: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=7d")).await.unwrap().json().await.unwrap();
    assert_eq!(s["range"], "7d");
    assert_eq!(s["total_requests"], 1);
    assert!(s["timeline"].as_array().unwrap().len() == 1);
    let s2: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=7d")).await.unwrap().json().await.unwrap();
    assert_eq!(s["generated_at"], s2["generated_at"], "served from cache");
    let bad: serde_json::Value = reqwest::get(format!("{base}/api/stats?range=1y")).await.unwrap().json().await.unwrap();
    assert_eq!(bad["range"], "24h");
    let m: serde_json::Value = reqwest::get(format!("{base}/api/map")).await.unwrap().json().await.unwrap();
    assert!(m["countries"].is_object());
    assert_eq!(m["max"], 0, "no geoip in tests");
}
```

- [ ] **Step 5: Run everything, expect pass**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src tests
git commit -m "feat(stats): ranged aggregates, timeline, map counts, 15s cache, indexes

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 5: Country names

**Files:**
- Create: `src/admin/countries.rs`
- Modify: `src/admin/mod.rs`
- Test: unit tests in the file

**Interfaces:**
- Produces: `pub fn country_name(alpha2: &str) -> &str` (returns the input when unknown), `pub fn flag(alpha2: &str) -> String` (regional-indicator emoji, empty string for unknown/`??`).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_unknown_and_flag() {
        assert_eq!(country_name("DE"), "Germany");
        assert_eq!(country_name("us"), "United States");
        assert_eq!(country_name("ZZ"), "ZZ");
        assert_eq!(country_name("??"), "??");
        assert_eq!(flag("DE"), "🇩🇪");
        assert_eq!(flag("??"), "");
        assert!(TABLE.len() >= 240);
    }
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test admin::countries`

- [ ] **Step 3: Implement**

Generate the table with Python from `pycountry` if installed, otherwise from the ISO 3166-1 list below (it is complete; copy it verbatim):

```rust
//! ISO 3166-1 alpha-2 → English short name. Static, ~250 rows.
pub static TABLE: &[(&str, &str)] = &[
    ("AD","Andorra"),("AE","United Arab Emirates"),("AF","Afghanistan"),("AG","Antigua and Barbuda"),("AI","Anguilla"),("AL","Albania"),("AM","Armenia"),("AO","Angola"),("AQ","Antarctica"),("AR","Argentina"),("AS","American Samoa"),("AT","Austria"),("AU","Australia"),("AW","Aruba"),("AX","Åland Islands"),("AZ","Azerbaijan"),
    ("BA","Bosnia and Herzegovina"),("BB","Barbados"),("BD","Bangladesh"),("BE","Belgium"),("BF","Burkina Faso"),("BG","Bulgaria"),("BH","Bahrain"),("BI","Burundi"),("BJ","Benin"),("BL","Saint Barthélemy"),("BM","Bermuda"),("BN","Brunei"),("BO","Bolivia"),("BQ","Caribbean Netherlands"),("BR","Brazil"),("BS","Bahamas"),("BT","Bhutan"),("BV","Bouvet Island"),("BW","Botswana"),("BY","Belarus"),("BZ","Belize"),
    ("CA","Canada"),("CC","Cocos Islands"),("CD","DR Congo"),("CF","Central African Republic"),("CG","Congo"),("CH","Switzerland"),("CI","Côte d'Ivoire"),("CK","Cook Islands"),("CL","Chile"),("CM","Cameroon"),("CN","China"),("CO","Colombia"),("CR","Costa Rica"),("CU","Cuba"),("CV","Cabo Verde"),("CW","Curaçao"),("CX","Christmas Island"),("CY","Cyprus"),("CZ","Czechia"),
    ("DE","Germany"),("DJ","Djibouti"),("DK","Denmark"),("DM","Dominica"),("DO","Dominican Republic"),("DZ","Algeria"),
    ("EC","Ecuador"),("EE","Estonia"),("EG","Egypt"),("EH","Western Sahara"),("ER","Eritrea"),("ES","Spain"),("ET","Ethiopia"),
    ("FI","Finland"),("FJ","Fiji"),("FK","Falkland Islands"),("FM","Micronesia"),("FO","Faroe Islands"),("FR","France"),
    ("GA","Gabon"),("GB","United Kingdom"),("GD","Grenada"),("GE","Georgia"),("GF","French Guiana"),("GG","Guernsey"),("GH","Ghana"),("GI","Gibraltar"),("GL","Greenland"),("GM","Gambia"),("GN","Guinea"),("GP","Guadeloupe"),("GQ","Equatorial Guinea"),("GR","Greece"),("GS","South Georgia"),("GT","Guatemala"),("GU","Guam"),("GW","Guinea-Bissau"),("GY","Guyana"),
    ("HK","Hong Kong"),("HM","Heard Island"),("HN","Honduras"),("HR","Croatia"),("HT","Haiti"),("HU","Hungary"),
    ("ID","Indonesia"),("IE","Ireland"),("IL","Israel"),("IM","Isle of Man"),("IN","India"),("IO","British Indian Ocean Territory"),("IQ","Iraq"),("IR","Iran"),("IS","Iceland"),("IT","Italy"),
    ("JE","Jersey"),("JM","Jamaica"),("JO","Jordan"),("JP","Japan"),
    ("KE","Kenya"),("KG","Kyrgyzstan"),("KH","Cambodia"),("KI","Kiribati"),("KM","Comoros"),("KN","Saint Kitts and Nevis"),("KP","North Korea"),("KR","South Korea"),("KW","Kuwait"),("KY","Cayman Islands"),("KZ","Kazakhstan"),
    ("LA","Laos"),("LB","Lebanon"),("LC","Saint Lucia"),("LI","Liechtenstein"),("LK","Sri Lanka"),("LR","Liberia"),("LS","Lesotho"),("LT","Lithuania"),("LU","Luxembourg"),("LV","Latvia"),("LY","Libya"),
    ("MA","Morocco"),("MC","Monaco"),("MD","Moldova"),("ME","Montenegro"),("MF","Saint Martin"),("MG","Madagascar"),("MH","Marshall Islands"),("MK","North Macedonia"),("ML","Mali"),("MM","Myanmar"),("MN","Mongolia"),("MO","Macao"),("MP","Northern Mariana Islands"),("MQ","Martinique"),("MR","Mauritania"),("MS","Montserrat"),("MT","Malta"),("MU","Mauritius"),("MV","Maldives"),("MW","Malawi"),("MX","Mexico"),("MY","Malaysia"),("MZ","Mozambique"),
    ("NA","Namibia"),("NC","New Caledonia"),("NE","Niger"),("NF","Norfolk Island"),("NG","Nigeria"),("NI","Nicaragua"),("NL","Netherlands"),("NO","Norway"),("NP","Nepal"),("NR","Nauru"),("NU","Niue"),("NZ","New Zealand"),
    ("OM","Oman"),
    ("PA","Panama"),("PE","Peru"),("PF","French Polynesia"),("PG","Papua New Guinea"),("PH","Philippines"),("PK","Pakistan"),("PL","Poland"),("PM","Saint Pierre and Miquelon"),("PN","Pitcairn"),("PR","Puerto Rico"),("PS","Palestine"),("PT","Portugal"),("PW","Palau"),("PY","Paraguay"),
    ("QA","Qatar"),
    ("RE","Réunion"),("RO","Romania"),("RS","Serbia"),("RU","Russia"),("RW","Rwanda"),
    ("SA","Saudi Arabia"),("SB","Solomon Islands"),("SC","Seychelles"),("SD","Sudan"),("SE","Sweden"),("SG","Singapore"),("SH","Saint Helena"),("SI","Slovenia"),("SJ","Svalbard and Jan Mayen"),("SK","Slovakia"),("SL","Sierra Leone"),("SM","San Marino"),("SN","Senegal"),("SO","Somalia"),("SR","Suriname"),("SS","South Sudan"),("ST","São Tomé and Príncipe"),("SV","El Salvador"),("SX","Sint Maarten"),("SY","Syria"),("SZ","Eswatini"),
    ("TC","Turks and Caicos Islands"),("TD","Chad"),("TF","French Southern Territories"),("TG","Togo"),("TH","Thailand"),("TJ","Tajikistan"),("TK","Tokelau"),("TL","Timor-Leste"),("TM","Turkmenistan"),("TN","Tunisia"),("TO","Tonga"),("TR","Türkiye"),("TT","Trinidad and Tobago"),("TV","Tuvalu"),("TW","Taiwan"),("TZ","Tanzania"),
    ("UA","Ukraine"),("UG","Uganda"),("UM","U.S. Minor Outlying Islands"),("US","United States"),("UY","Uruguay"),("UZ","Uzbekistan"),
    ("VA","Vatican City"),("VC","Saint Vincent and the Grenadines"),("VE","Venezuela"),("VG","British Virgin Islands"),("VI","U.S. Virgin Islands"),("VN","Vietnam"),("VU","Vanuatu"),
    ("WF","Wallis and Futuna"),("WS","Samoa"),
    ("XK","Kosovo"),
    ("YE","Yemen"),("YT","Mayotte"),
    ("ZA","South Africa"),("ZM","Zambia"),("ZW","Zimbabwe"),
];

pub fn country_name(alpha2: &str) -> &str {
    let up = alpha2.to_ascii_uppercase();
    match TABLE.binary_search_by(|(k, _)| k.cmp(&up.as_str())) {
        Ok(i) => TABLE[i].1,
        Err(_) => alpha2,
    }
}

/// Regional-indicator pair, or empty when the code is not two ASCII letters.
pub fn flag(alpha2: &str) -> String {
    let b = alpha2.as_bytes();
    if b.len() != 2 || !b.iter().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }
    b.iter().map(|c| char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() - b'A') as u32).unwrap()).collect()
}
```
The table must be sorted by code for `binary_search_by`; add a test `assert!(TABLE.windows(2).all(|w| w[0].0 < w[1].0));`. Because `country_name` returns a `&str` tied to either the table or the input, write its signature as `pub fn country_name<'a>(alpha2: &'a str) -> &'a str` (table entries are `'static`, which coerces).

Register `pub mod countries;` in `src/admin/mod.rs`.

- [ ] **Step 4: Run, expect pass; commit**

```bash
cargo test admin::countries
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src/admin
git commit -m "feat(admin): ISO country name table

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 6: Browse layer — IP directory, paginated request search, IP overview

**Files:**
- Create: `src/store/browse.rs`
- Modify: `src/store/mod.rs` (move `RequestListRow`, delete old `search_requests`, `ip_detail`; add `pub mod browse;`), `src/admin/detail.rs` (temporarily import `RequestFilter` from the store so it still compiles; it is deleted in Task 10)
- Test: unit tests in `src/store/browse.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const PAGE_SIZE: i64 = 100;
  pub struct Page<T> { pub items: Vec<T>, pub page: u32, pub has_next: bool }
  impl<T> Page<T> { pub fn prev(&self) -> Option<u32>; pub fn next(&self) -> Option<u32>; }
  pub fn page_num(p: Option<i64>) -> u32   // <1 or None → 1
  pub fn lenient_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error>  // serde helper: garbage → None
  #[derive(serde::Deserialize, Default, Clone)] pub struct IpFilter { pub q: Option<String>, pub country: Option<String>, pub asn: Option<i64>, pub label: Option<String>, pub min_severity: Option<i64>, pub tor: Option<String>, pub sort: Option<String>, pub page: Option<i64> }
  #[derive(serde::Serialize, sqlx::FromRow, Clone)] pub struct IpSummary { pub ip: String, pub country: Option<String>, pub asn: Option<i64>, pub asn_org: Option<String>, pub is_tor: bool, pub first_seen: String, pub last_seen: String, pub request_count: i64, pub max_severity: i64 }
  #[derive(serde::Deserialize, Default, Clone)] pub struct RequestFilter { pub ip: Option<String>, pub path: Option<String>, pub label: Option<String>, pub severity: Option<i64>, pub min_severity: Option<i64>, pub country: Option<String>, pub asn: Option<i64>, pub from: Option<String>, pub to: Option<String>, pub page: Option<i64> }
  #[derive(serde::Serialize, sqlx::FromRow, Clone)] pub struct RequestListRow { pub id: i64, pub ts: String, pub ip_id: i64, pub ip: String, pub method: String, pub path: String, pub query: Option<String>, pub severity: i64, pub labels_json: String, pub country: Option<String>, pub is_tor: bool }
  impl RequestListRow { pub fn labels(&self) -> Vec<String>; }
  pub struct IpOverview { pub ip: crate::store::requests::IpRow, pub request_count: i64, pub max_severity: i64, pub labels: Vec<crate::store::stats::Named>, pub sparkline: Vec<i64> /* 24 buckets, oldest first */ }
  impl Store {
    pub async fn list_ips(&self, f: &IpFilter) -> Result<Page<IpSummary>>;
    pub async fn ip_by_addr(&self, addr: &str) -> Result<Option<IpRow>>;      // None for unparsable input
    pub async fn ip_overview(&self, ip_id: i64) -> Result<Option<IpOverview>>;
    pub async fn requests_for_ip(&self, ip_id: i64, page: u32) -> Result<Page<RequestListRow>>;
    pub async fn search_requests(&self, f: &RequestFilter) -> Result<Page<RequestListRow>>;
  }
  ```
  `IpFilter.q` accepts: exact IP, CIDR (`a.b.c.0/24`, `2001:db8::/32`), or a bare prefix (`203.0.113.`) matched with `LIKE prefix%`. `tor` is `Some("1")` when checked. `sort` is `"recent"` or anything else = by count.

- [ ] **Step 1: Failing unit tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn seeded() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mk = |ip_id, path: &str, sev, labels: &str| NewRequest {
            ip_id, method: "GET".into(), path: path.into(), query: Some("a=1".into()), headers_json: "[]".into(), body: None,
            labels_json: labels.into(), severity: sev, scan_level: 1, is_fp_claim: false, page_token: None,
        };
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.200".parse().unwrap()).await.unwrap();
        let c = s.upsert_ip("2001:db8::1".parse().unwrap()).await.unwrap();
        s.set_ip_geo(a.id, Some("DE"), Some(3320), Some("DTAG")).await.unwrap();
        s.set_ip_geo(b.id, Some("DE"), Some(3320), Some("DTAG")).await.unwrap();
        s.set_ip_geo(c.id, Some("US"), Some(15169), Some("Google")).await.unwrap();
        s.set_ip_tor(c.id, true).await.unwrap();
        for _ in 0..3 { s.insert_request(&mk(a.id, "/.env", 3, r#"["sensitive-path"]"#)).await.unwrap(); }
        s.insert_request(&mk(b.id, "/wp-login.php", 2, r#"["wp"]"#)).await.unwrap();
        s.insert_request(&mk(c.id, "/", 0, "[]")).await.unwrap();
        s
    }

    #[test]
    fn lenient_query_numbers() {
        let f: RequestFilter = serde_urlencoded::from_str("page=abc&asn=&min_severity=2").unwrap();
        assert_eq!(f.page, None);
        assert_eq!(f.asn, None);
        assert_eq!(f.min_severity, Some(2));
    }

    #[test]
    fn page_num_clamps() {
        assert_eq!(page_num(None), 1);
        assert_eq!(page_num(Some(0)), 1);
        assert_eq!(page_num(Some(-5)), 1);
        assert_eq!(page_num(Some(7)), 7);
    }

    #[tokio::test]
    async fn list_ips_filters_and_sorts() {
        let s = seeded().await;
        let all = s.list_ips(&IpFilter::default()).await.unwrap();
        assert_eq!(all.items.len(), 3);
        assert_eq!(all.items[0].ip, "203.0.113.1", "most requests first");
        assert_eq!(all.items[0].request_count, 3);
        assert_eq!(all.items[0].max_severity, 3);
        let cidr = s.list_ips(&IpFilter { q: Some("203.0.113.0/25".into()), ..Default::default() }).await.unwrap();
        assert_eq!(cidr.items.len(), 1);
        assert_eq!(cidr.items[0].ip, "203.0.113.1");
        let v6 = s.list_ips(&IpFilter { q: Some("2001:db8::/32".into()), ..Default::default() }).await.unwrap();
        assert_eq!(v6.items.len(), 1);
        let prefix = s.list_ips(&IpFilter { q: Some("203.0.113.".into()), ..Default::default() }).await.unwrap();
        assert_eq!(prefix.items.len(), 2);
        let exact = s.list_ips(&IpFilter { q: Some("203.0.113.200".into()), ..Default::default() }).await.unwrap();
        assert_eq!(exact.items.len(), 1);
        let tor = s.list_ips(&IpFilter { tor: Some("1".into()), ..Default::default() }).await.unwrap();
        assert_eq!(tor.items.len(), 1);
        assert!(tor.items[0].is_tor);
        let sev = s.list_ips(&IpFilter { min_severity: Some(2), ..Default::default() }).await.unwrap();
        assert_eq!(sev.items.len(), 2);
        let label = s.list_ips(&IpFilter { label: Some("wp".into()), ..Default::default() }).await.unwrap();
        assert_eq!(label.items.len(), 1);
        let asn = s.list_ips(&IpFilter { asn: Some(15169), ..Default::default() }).await.unwrap();
        assert_eq!(asn.items[0].ip, "2001:db8::1");
        let garbage = s.list_ips(&IpFilter { q: Some("not an ip".into()), ..Default::default() }).await.unwrap();
        assert!(garbage.items.is_empty());
        assert!(!garbage.has_next);
    }

    #[tokio::test]
    async fn ip_by_addr_and_overview() {
        let s = seeded().await;
        assert!(s.ip_by_addr("hello").await.unwrap().is_none());
        assert!(s.ip_by_addr("203.0.113.77").await.unwrap().is_none());
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let ov = s.ip_overview(ip.id).await.unwrap().unwrap();
        assert_eq!(ov.request_count, 3);
        assert_eq!(ov.max_severity, 3);
        assert_eq!(ov.labels[0].name, "sensitive-path");
        assert_eq!(ov.sparkline.len(), 24);
        assert_eq!(ov.sparkline.iter().sum::<i64>(), 3);
        assert_eq!(*ov.sparkline.last().unwrap(), 3, "current hour is the last bucket");
        let v6 = s.ip_by_addr("2001:db8::1").await.unwrap().unwrap();
        assert_eq!(v6.ip, "2001:db8::1");
    }

    #[tokio::test]
    async fn requests_paginate_and_filter() {
        let s = seeded().await;
        let ip = s.ip_by_addr("203.0.113.1").await.unwrap().unwrap();
        let p = s.requests_for_ip(ip.id, 1).await.unwrap();
        assert_eq!(p.items.len(), 3);
        assert!(!p.has_next);
        assert_eq!(p.items[0].labels(), vec!["sensitive-path".to_string()]);
        assert_eq!(p.items[0].query.as_deref(), Some("a=1"));
        let f = RequestFilter { path: Some("wp".into()), ..Default::default() };
        let r = s.search_requests(&f).await.unwrap();
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].ip, "203.0.113.200");
        assert_eq!(r.items[0].country.as_deref(), Some("DE"));
        let f = RequestFilter { min_severity: Some(1), country: Some("DE".into()), ..Default::default() };
        assert_eq!(s.search_requests(&f).await.unwrap().items.len(), 4);
        // Pagination: 101 rows → page 1 has 100 and has_next, page 2 has the rest.
        for _ in 0..100 {
            s.insert_request(&NewRequest { ip_id: ip.id, method: "GET".into(), path: "/bulk".into(), query: None, headers_json: "[]".into(), body: None,
                labels_json: "[]".into(), severity: 0, scan_level: 0, is_fp_claim: false, page_token: None }).await.unwrap();
        }
        let p1 = s.requests_for_ip(ip.id, 1).await.unwrap();
        assert_eq!(p1.items.len(), 100);
        assert!(p1.has_next);
        assert_eq!(p1.next(), Some(2));
        assert_eq!(p1.prev(), None);
        let p2 = s.requests_for_ip(ip.id, 2).await.unwrap();
        assert_eq!(p2.items.len(), 3);
        assert!(!p2.has_next);
        assert_eq!(p2.prev(), Some(1));
    }
}
```

`serde_urlencoded` is what axum's `Query` uses; add `serde_urlencoded = "0.7"` to `[dev-dependencies]`.

- [ ] **Step 2: Run, expect compile failure**

Run: `cargo test store::browse`

- [ ] **Step 3: Implement `src/store/browse.rs`**

```rust
//! Read models for the public directory and search pages (and, with a
//! session, the same pages' admin affordances). No admin-only data here.
use super::Store;
use super::requests::IpRow;
use super::stats::Named;
use anyhow::Result;
use ipnet::IpNet;
use std::net::IpAddr;

pub const PAGE_SIZE: i64 = 100;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: u32,
    pub has_next: bool,
}

impl<T> Page<T> {
    pub fn prev(&self) -> Option<u32> {
        (self.page > 1).then(|| self.page - 1)
    }
    pub fn next(&self) -> Option<u32> {
        self.has_next.then(|| self.page + 1)
    }
    fn from_rows(mut items: Vec<T>, page: u32) -> Self {
        let has_next = items.len() as i64 > PAGE_SIZE;
        items.truncate(PAGE_SIZE as usize);
        Self { items, page, has_next }
    }
}

pub fn page_num(p: Option<i64>) -> u32 {
    p.filter(|n| *n >= 1).map(|n| n.min(u32::MAX as i64) as u32).unwrap_or(1)
}

fn offset(page: u32) -> i64 {
    (page as i64 - 1) * PAGE_SIZE
}

/// Numeric query params that must never 400: garbage becomes `None`.
pub fn lenient_i64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    let s: Option<String> = serde::Deserialize::deserialize(d)?;
    Ok(s.and_then(|v| v.trim().parse().ok()))
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct IpFilter {
    pub q: Option<String>,
    pub country: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub asn: Option<i64>,
    pub label: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub min_severity: Option<i64>,
    pub tor: Option<String>,
    pub sort: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub page: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct IpSummary {
    pub ip: String,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub is_tor: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: i64,
    pub max_severity: i64,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct RequestFilter {
    pub ip: Option<String>,
    pub path: Option<String>,
    pub label: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub severity: Option<i64>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub min_severity: Option<i64>,
    pub country: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub asn: Option<i64>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub page: Option<i64>,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct RequestListRow {
    pub id: i64,
    pub ts: String,
    pub ip_id: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub severity: i64,
    pub labels_json: String,
    pub country: Option<String>,
    pub is_tor: bool,
}

impl RequestListRow {
    pub fn labels(&self) -> Vec<String> {
        serde_json::from_str(&self.labels_json).unwrap_or_default()
    }
}

pub struct IpOverview {
    pub ip: IpRow,
    pub request_count: i64,
    pub max_severity: i64,
    pub labels: Vec<Named>,
    /// 24 hourly buckets, oldest first, last = current hour.
    pub sparkline: Vec<i64>,
}

/// What the `q` box means.
enum IpQuery {
    Exact(String),
    Net(IpNet),
    Prefix(String),
    Invalid,
}

fn parse_q(q: &str) -> IpQuery {
    let q = q.trim();
    if q.is_empty() {
        return IpQuery::Prefix(String::new());
    }
    if let Ok(ip) = q.parse::<IpAddr>() {
        return IpQuery::Exact(ip.to_string());
    }
    if let Ok(net) = q.parse::<IpNet>() {
        return IpQuery::Net(net);
    }
    // A bare prefix: only digits, dots, hex and colons.
    if q.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':') {
        return IpQuery::Prefix(q.to_string());
    }
    IpQuery::Invalid
}

/// LIKE prefix that bounds a CIDR's candidates before exact filtering in Rust.
fn net_like_prefix(net: &IpNet) -> String {
    match net {
        IpNet::V4(n) => {
            let o = n.network().octets();
            match n.prefix_len() {
                0..=7 => String::new(),
                8..=15 => format!("{}.", o[0]),
                16..=23 => format!("{}.{}.", o[0], o[1]),
                _ => format!("{}.{}.{}.", o[0], o[1], o[2]),
            }
        }
        IpNet::V6(n) => {
            // First hextet is stable for /16 and longer; SQLite stores the
            // canonical Rust `Display` form, whose first group has no leading zeros.
            if n.prefix_len() >= 16 {
                let s = n.network().segments();
                format!("{:x}:", s[0])
            } else {
                String::new()
            }
        }
    }
}

const IP_SUMMARY_SELECT: &str =
    "SELECT i.ip, i.country, i.asn, i.asn_org, i.is_tor_exit AS is_tor, i.first_seen, i.last_seen,
            COUNT(r.id) AS request_count, COALESCE(MAX(r.severity), 0) AS max_severity
     FROM ips i LEFT JOIN requests r ON r.ip_id = i.id";

impl Store {
    pub async fn list_ips(&self, f: &IpFilter) -> Result<Page<IpSummary>> {
        let page = page_num(f.page);
        let mut wheres: Vec<String> = vec![];
        let mut binds: Vec<String> = vec![];
        let mut net_filter: Option<IpNet> = None;
        if let Some(q) = f.q.as_deref().filter(|s| !s.trim().is_empty()) {
            match parse_q(q) {
                IpQuery::Exact(ip) => { wheres.push("i.ip = ?".into()); binds.push(ip); }
                IpQuery::Net(net) => {
                    let p = net_like_prefix(&net);
                    if !p.is_empty() { wheres.push("i.ip LIKE ?".into()); binds.push(format!("{p}%")); }
                    net_filter = Some(net);
                }
                IpQuery::Prefix(p) => { wheres.push("i.ip LIKE ?".into()); binds.push(format!("{p}%")); }
                IpQuery::Invalid => return Ok(Page { items: vec![], page, has_next: false }),
            }
        }
        if let Some(c) = f.country.as_deref().filter(|s| !s.is_empty()) { wheres.push("i.country = ?".into()); binds.push(c.to_ascii_uppercase()); }
        if let Some(a) = f.asn { wheres.push("i.asn = ?".into()); binds.push(a.to_string()); }
        if f.tor.as_deref() == Some("1") { wheres.push("i.is_tor_exit = 1".into()); }
        if let Some(l) = f.label.as_deref().filter(|s| !s.is_empty()) {
            wheres.push("EXISTS (SELECT 1 FROM requests rx, json_each(rx.labels_json) je WHERE rx.ip_id = i.id AND je.value = ?)".into());
            binds.push(l.to_string());
        }
        let having = match f.min_severity { Some(m) => { binds.push(m.to_string()); " HAVING COALESCE(MAX(r.severity),0) >= ?" } None => "" };
        let order = if f.sort.as_deref() == Some("recent") { "i.last_seen DESC" } else { "request_count DESC, i.last_seen DESC" };
        let where_sql = if wheres.is_empty() { String::new() } else { format!(" WHERE {}", wheres.join(" AND ")) };
        // CIDR: fetch candidates unpaged (bounded by the LIKE prefix), filter, then page in Rust.
        let (limit, off) = if net_filter.is_some() { (100_000, 0) } else { (PAGE_SIZE + 1, offset(page)) };
        let sql = format!("{IP_SUMMARY_SELECT}{where_sql} GROUP BY i.id{having} ORDER BY {order} LIMIT {limit} OFFSET {off}");
        let mut q = sqlx::query_as::<_, IpSummary>(&sql);
        for b in &binds { q = q.bind(b); }
        let mut rows = q.fetch_all(&self.pool).await?;
        if let Some(net) = net_filter {
            rows.retain(|r| r.ip.parse::<IpAddr>().map(|ip| net.contains(&ip)).unwrap_or(false));
            let start = offset(page) as usize;
            rows = rows.into_iter().skip(start).take(PAGE_SIZE as usize + 1).collect();
        }
        Ok(Page::from_rows(rows, page))
    }

    pub async fn ip_by_addr(&self, addr: &str) -> Result<Option<IpRow>> {
        let Ok(ip) = addr.trim().parse::<IpAddr>() else { return Ok(None) };
        Ok(sqlx::query_as::<_, IpRow>("SELECT * FROM ips WHERE ip = ?")
            .bind(ip.to_string())
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn ip_overview(&self, ip_id: i64) -> Result<Option<IpOverview>> {
        let Some(ip) = self.ip_by_id(ip_id).await? else { return Ok(None) };
        let (request_count, max_severity): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(MAX(severity),0) FROM requests WHERE ip_id = ?")
            .bind(ip_id).fetch_one(&self.pool).await?;
        let labels = sqlx::query_as::<_, Named>(
            "SELECT je.value AS name, COUNT(*) AS count FROM requests r, json_each(r.labels_json) je
             WHERE r.ip_id = ? GROUP BY je.value ORDER BY count DESC LIMIT 20")
            .bind(ip_id).fetch_all(&self.pool).await?;
        // Hours ago (0 = current hour) → count.
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT CAST((julianday('now') - julianday(ts)) * 24 AS INTEGER) AS h, COUNT(*)
             FROM requests WHERE ip_id = ? AND ts >= datetime('now','-24 hours') GROUP BY h")
            .bind(ip_id).fetch_all(&self.pool).await?;
        let mut sparkline = vec![0i64; 24];
        for (h, c) in rows {
            if (0..24).contains(&h) { sparkline[23 - h as usize] += c; }
        }
        Ok(Some(IpOverview { ip, request_count, max_severity, labels, sparkline }))
    }

    pub async fn requests_for_ip(&self, ip_id: i64, page: u32) -> Result<Page<RequestListRow>> {
        let rows = sqlx::query_as::<_, RequestListRow>(&format!(
            "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, r.query, r.severity, r.labels_json, i.country, i.is_tor_exit AS is_tor
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE r.ip_id = ? ORDER BY r.id DESC LIMIT {} OFFSET {}",
            PAGE_SIZE + 1, offset(page)))
            .bind(ip_id).fetch_all(&self.pool).await?;
        Ok(Page::from_rows(rows, page))
    }

    pub async fn search_requests(&self, f: &RequestFilter) -> Result<Page<RequestListRow>> {
        let page = page_num(f.page);
        let mut sql = String::from(
            "SELECT r.id, r.ts, r.ip_id, i.ip, r.method, r.path, r.query, r.severity, r.labels_json, i.country, i.is_tor_exit AS is_tor
             FROM requests r JOIN ips i ON r.ip_id = i.id WHERE 1=1");
        let mut binds: Vec<String> = vec![];
        let nonempty = |s: &Option<String>| s.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
        if let Some(v) = nonempty(&f.ip) { sql.push_str(" AND i.ip = ?"); binds.push(v); }
        if let Some(v) = nonempty(&f.path) { sql.push_str(" AND (r.path LIKE ? OR r.query LIKE ?)"); binds.push(format!("%{v}%")); binds.push(format!("%{v}%")); }
        if let Some(v) = nonempty(&f.label) { sql.push_str(" AND EXISTS (SELECT 1 FROM json_each(r.labels_json) je WHERE je.value = ?)"); binds.push(v); }
        if let Some(v) = f.severity { sql.push_str(" AND r.severity = ?"); binds.push(v.to_string()); }
        if let Some(v) = f.min_severity { sql.push_str(" AND r.severity >= ?"); binds.push(v.to_string()); }
        if let Some(v) = nonempty(&f.country) { sql.push_str(" AND i.country = ?"); binds.push(v.to_ascii_uppercase()); }
        if let Some(v) = f.asn { sql.push_str(" AND i.asn = ?"); binds.push(v.to_string()); }
        if let Some(v) = nonempty(&f.from) { sql.push_str(" AND r.ts >= ?"); binds.push(v.replace('T', " ")); }
        if let Some(v) = nonempty(&f.to) { sql.push_str(" AND r.ts <= ?"); binds.push(v.replace('T', " ")); }
        sql.push_str(&format!(" ORDER BY r.id DESC LIMIT {} OFFSET {}", PAGE_SIZE + 1, offset(page)));
        let mut q = sqlx::query_as::<_, RequestListRow>(&sql);
        for b in &binds { q = q.bind(b); }
        Ok(Page::from_rows(q.fetch_all(&self.pool).await?, page))
    }
}
```

`datetime-local` inputs send `2026-09-30T12:00`; SQLite `datetime('now')` stores `2026-09-30 12:00:00`, hence the `T`→space replace.

In `src/store/mod.rs`: delete `RequestListRow`, `search_requests`, `ip_detail`; add `pub mod browse;`. In `src/admin/detail.rs`: delete its `RequestFilter`, `use crate::store::browse::RequestFilter;`, and read `rows.items` where it iterated `rows`. Export still uses `export_requests` — unchanged.

- [ ] **Step 4: Run, expect pass**

Run: `cargo test`
Expected: PASS (the `detail_views_and_inbox_work_with_session` test still hits `/requests?path=/hello` through `detail.rs`; it keeps working because `search_requests` semantics are preserved. `/ips/{id}` in that test still renders via the old template — it now needs a replacement since `ip_detail` is gone: make `ip_detail_page` in `detail.rs` return a minimal `<h1>{ip}</h1>` plus request paths via `requests_for_ip` so the test passes until Task 10 rewrites it.)

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src
git commit -m "feat(store): browse layer — IP directory with CIDR search, paginated requests, IP overview

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 7: Admin-only reads and transactional deletes

**Files:**
- Create: `src/store/inspect.rs`, `src/store/delete.rs`
- Modify: `src/store/mod.rs` (register modules; move `inbox`, `FpClaimRow`, `list_credential_labels` into `inspect.rs`), `src/scan/mod.rs` (tolerate a vanished job)
- Test: unit tests in both files, one worker test

**Interfaces:**
- Produces (`inspect.rs`):
  ```rust
  #[derive(serde::Serialize, sqlx::FromRow, Clone)] pub struct ScanSummary { pub id: i64, pub ip_id: i64, pub ip: String, pub level: i64, pub started_at: String, pub finished_at: Option<String>, pub os_guess: Option<String>, pub open_ports: i64 }
  #[derive(serde::Serialize, sqlx::FromRow, Clone)] pub struct PortRow { pub port: i64, pub proto: String, pub state: String, pub service: Option<String>, pub product: Option<String>, pub version: Option<String> }
  #[derive(serde::Serialize, Clone)] pub struct FpSummary { pub hash: String, pub count: i64, pub other_ips: i64, pub visitor_ids: Vec<String> }
  #[derive(serde::Serialize, Clone)] pub struct FpCluster { pub hash: String, pub ips: Vec<String>, pub count: i64 }
  #[derive(serde::Serialize, sqlx::FromRow, Clone)] pub struct FpClaimRow { pub id: i64, pub ts: String, pub ip: String, pub contact_email: Option<String>, pub user_agent: String }
  #[derive(serde::Serialize, Clone)] pub struct QueueSummary { pub queued: i64, pub running: i64, pub done_24h: i64, pub failed_24h: i64, pub scans_last_hour: i64 }
  pub struct RequestDetail { pub row: RequestRow, pub ip: String, pub headers: Vec<(String,String)>, pub body_text: String, pub body_len: usize, pub body_truncated: bool, pub fingerprint: Option<FpSummary> }
  impl Store {
    pub async fn scans_for_ip(&self, ip_id: i64) -> Result<Vec<ScanSummary>>;
    pub async fn list_scans(&self, page: u32) -> Result<Page<ScanSummary>>;
    pub async fn scan_by_id(&self, id: i64) -> Result<Option<ScanSummary>>;
    pub async fn ports_for_scan(&self, scan_id: i64) -> Result<Vec<PortRow>>;
    pub async fn scan_raw_xml(&self, id: i64) -> Result<Option<Vec<u8>>>;     // zstd-decompressed
    pub async fn fingerprints_for_ip(&self, ip_id: i64) -> Result<Vec<FpSummary>>;
    pub async fn fingerprint_clusters(&self) -> Result<Vec<FpCluster>>;       // hashes seen from >1 IP
    pub async fn claims_for_ip(&self, ip_id: i64) -> Result<Vec<FpClaimRow>>;
    pub async fn inbox(&self) -> Result<Vec<FpClaimRow>>;
    pub async fn queue_summary(&self) -> Result<QueueSummary>;
    pub async fn recent_failed_jobs(&self, limit: i64) -> Result<Vec<crate::events::QueueJob>>;
    pub async fn request_detail(&self, id: i64) -> Result<Option<RequestDetail>>;
    pub async fn list_credential_labels(&self) -> Result<Vec<(String, String, String)>>;  // moved
  }
  ```
  (`delete.rs`):
  ```rust
  impl Store {
    pub async fn delete_request(&self, id: i64) -> Result<bool>;   // false when it did not exist
    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool>;
    pub async fn delete_scan(&self, scan_id: i64) -> Result<bool>;
    pub async fn delete_claim(&self, id: i64) -> Result<bool>;
  }
  ```

- [ ] **Step 1: Failing tests for deletes**

`src/store/delete.rs` tests:
```rust
#[cfg(test)]
mod tests {
    use crate::store::Store;
    use crate::store::requests::NewRequest;
    use crate::scan::nmap_xml::{PortResult, ScanResult};

    async fn seeded() -> (Store, i64, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let mut ids = vec![];
        for ip in ["203.0.113.1", "203.0.113.2"] {
            let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
            let rid = s.insert_request(&NewRequest { ip_id: row.id, method: "GET".into(), path: "/x".into(), query: None,
                headers_json: "[]".into(), body: None, labels_json: "[]".into(), severity: 1, scan_level: 1, is_fp_claim: false, page_token: None }).await.unwrap();
            s.insert_fp_claim(row.id, rid, Some("a@b.c"), "UA").await.unwrap();
            s.insert_fingerprint(Some(rid), row.id, "hash", None, "{}", "{}", b"[]").await.unwrap();
            let job = match s.enqueue_scan(row.id, 2, 24).await.unwrap() { crate::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
            s.next_queued_job().await.unwrap();
            s.finish_job(job, Some(&ScanResult { os_guess: Some("Linux".into()), raw_xml: b"<nmaprun/>".to_vec(),
                ports: vec![PortResult { port: 22, proto: "tcp".into(), state: "open".into(), service: Some("ssh".into()), product: None, version: None }] }), None).await.unwrap();
            ids.push(row.id);
        }
        (s, ids[0], ids[1])
    }

    async fn count(s: &Store, table: &str, col: &str, id: i64) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?")).bind(id).fetch_one(&s.pool).await.unwrap()
    }

    #[tokio::test]
    async fn delete_ip_cascades_and_spares_neighbours() {
        let (s, a, b) = seeded().await;
        assert!(s.delete_ip(a).await.unwrap());
        for t in ["requests", "fp_claims", "fingerprints", "scan_jobs", "scans"] {
            assert_eq!(count(&s, t, "ip_id", a).await, 0, "{t}");
            assert_eq!(count(&s, t, "ip_id", b).await, 1, "{t} neighbour");
        }
        assert_eq!(count(&s, "ips", "id", a).await, 0);
        let ports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ports").fetch_one(&s.pool).await.unwrap();
        assert_eq!(ports, 1);
        assert!(!s.delete_ip(a).await.unwrap(), "second delete reports absence");
    }

    #[tokio::test]
    async fn delete_request_removes_dependents_only() {
        let (s, a, _) = seeded().await;
        let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE ip_id = ?").bind(a).fetch_one(&s.pool).await.unwrap();
        assert!(s.delete_request(rid).await.unwrap());
        assert_eq!(count(&s, "requests", "id", rid).await, 0);
        assert_eq!(count(&s, "fp_claims", "request_id", rid).await, 0);
        assert_eq!(count(&s, "fingerprints", "request_id", rid).await, 0);
        assert_eq!(count(&s, "ips", "id", a).await, 1, "ip row stays");
        assert_eq!(count(&s, "scans", "ip_id", a).await, 1, "scans stay");
    }

    #[tokio::test]
    async fn delete_scan_and_claim() {
        let (s, a, _) = seeded().await;
        let sid: i64 = sqlx::query_scalar("SELECT id FROM scans WHERE ip_id = ?").bind(a).fetch_one(&s.pool).await.unwrap();
        assert!(s.delete_scan(sid).await.unwrap());
        assert_eq!(count(&s, "ports", "scan_id", sid).await, 0);
        let cid: i64 = sqlx::query_scalar("SELECT id FROM fp_claims WHERE ip_id = ?").bind(a).fetch_one(&s.pool).await.unwrap();
        assert!(s.delete_claim(cid).await.unwrap());
        assert!(!s.delete_claim(cid).await.unwrap());
    }
}
```

`PortResult.port` is a `u16`; the integer literals above infer to it.

- [ ] **Step 2: Run, expect compile failure**

Run: `cargo test store::delete`

- [ ] **Step 3: Implement `src/store/delete.rs`**

```rust
//! Admin deletes. Each runs in one transaction and returns whether the
//! primary row existed. Foreign keys are ON, so dependents go first.
use super::Store;
use anyhow::Result;

impl Store {
    pub async fn delete_request(&self, id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM fp_claims WHERE request_id = ?").bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM fingerprints WHERE request_id = ?").bind(id).execute(&mut *tx).await?;
        let n = sqlx::query("DELETE FROM requests WHERE id = ?").bind(id).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_ip(&self, ip_id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ports WHERE scan_id IN (SELECT id FROM scans WHERE ip_id = ?)").bind(ip_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM scans WHERE ip_id = ?").bind(ip_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM scan_jobs WHERE ip_id = ?").bind(ip_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM fingerprints WHERE ip_id = ?").bind(ip_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM fp_claims WHERE ip_id = ?").bind(ip_id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM requests WHERE ip_id = ?").bind(ip_id).execute(&mut *tx).await?;
        let n = sqlx::query("DELETE FROM ips WHERE id = ?").bind(ip_id).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_scan(&self, scan_id: i64) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ports WHERE scan_id = ?").bind(scan_id).execute(&mut *tx).await?;
        let n = sqlx::query("DELETE FROM scans WHERE id = ?").bind(scan_id).execute(&mut *tx).await?.rows_affected();
        tx.commit().await?;
        Ok(n > 0)
    }

    pub async fn delete_claim(&self, id: i64) -> Result<bool> {
        let n = sqlx::query("DELETE FROM fp_claims WHERE id = ?").bind(id).execute(&self.pool).await?.rows_affected();
        Ok(n > 0)
    }
}
```

- [ ] **Step 4: Worker tolerance for a vanished job (Review Focus 4)**

`finish_job` does `fetch_one` on the job → `RowNotFound` error when the IP was deleted mid-scan. In `src/scan/mod.rs`, every `let _ = store2.finish_job(...)` becomes:
```rust
if let Err(e) = store2.finish_job(job.id, Some(&res), None).await {
    warn!(job = job.id, ?e, "could not record scan result (job deleted?)");
}
```
(and likewise for the failure branches). Add a unit test in `src/scan/mod.rs` tests:
```rust
#[tokio::test]
async fn finish_job_on_deleted_ip_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
    let ip = s.upsert_ip("203.0.113.9".parse().unwrap()).await.unwrap();
    let job = match s.enqueue_scan(ip.id, 1, 24).await.unwrap() { crate::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
    s.next_queued_job().await.unwrap();
    assert!(s.delete_ip(ip.id).await.unwrap());
    assert!(s.finish_job(job, None, Some("timeout")).await.is_err());
    assert!(s.queue_job(job).await.unwrap().is_none());
}
```

- [ ] **Step 5: Failing tests for inspect.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;
    use crate::scan::nmap_xml::{PortResult, ScanResult};

    async fn seeded() -> (Store, i64) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        let s = Store::connect(&path).await.unwrap();
        let a = s.upsert_ip("203.0.113.1".parse().unwrap()).await.unwrap();
        let b = s.upsert_ip("203.0.113.2".parse().unwrap()).await.unwrap();
        let rid = s.insert_request(&NewRequest { ip_id: a.id, method: "POST".into(), path: "/login".into(), query: None,
            headers_json: r#"[["user-agent","sqlmap"],["x-a","b"]]"#.into(), body: Some(b"username=admin".to_vec()),
            labels_json: r#"["bait"]"#.into(), severity: 3, scan_level: 3, is_fp_claim: false, page_token: Some("tok".into()) }).await.unwrap();
        s.insert_fingerprint(Some(rid), a.id, "h1", Some("v1"), "{}", "{}", b"[]").await.unwrap();
        s.insert_fingerprint(None, b.id, "h1", Some("v1"), "{}", "{}", b"[]").await.unwrap();
        s.insert_fp_claim(a.id, rid, Some("me@x.y"), "UA").await.unwrap();
        let job = match s.enqueue_scan(a.id, 3, 24).await.unwrap() { crate::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
        s.next_queued_job().await.unwrap();
        s.finish_job(job, Some(&ScanResult { os_guess: Some("Linux 5".into()), raw_xml: b"<nmaprun/>".to_vec(),
            ports: vec![PortResult { port: 22, proto: "tcp".into(), state: "open".into(), service: Some("ssh".into()), product: Some("OpenSSH".into()), version: Some("9".into()) },
                        PortResult { port: 80, proto: "tcp".into(), state: "closed".into(), service: None, product: None, version: None }] }), None).await.unwrap();
        let job2 = match s.enqueue_scan(b.id, 1, 24).await.unwrap() { crate::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
        s.next_queued_job().await.unwrap();
        s.finish_job(job2, None, Some("timeout")).await.unwrap();
        (s, a.id)
    }

    #[tokio::test]
    async fn scans_ports_and_xml() {
        let (s, a) = seeded().await;
        let scans = s.scans_for_ip(a).await.unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].open_ports, 1);
        assert_eq!(scans[0].os_guess.as_deref(), Some("Linux 5"));
        let ports = s.ports_for_scan(scans[0].id).await.unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 22);
        assert_eq!(s.scan_raw_xml(scans[0].id).await.unwrap().unwrap(), b"<nmaprun/>");
        assert!(s.scan_raw_xml(999).await.unwrap().is_none());
        let page = s.list_scans(1).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].ip, "203.0.113.1");
        assert_eq!(s.scan_by_id(scans[0].id).await.unwrap().unwrap().level, 3);
    }

    #[tokio::test]
    async fn fingerprints_claims_and_clusters() {
        let (s, a) = seeded().await;
        let fps = s.fingerprints_for_ip(a).await.unwrap();
        assert_eq!(fps.len(), 1);
        assert_eq!(fps[0].hash, "h1");
        assert_eq!(fps[0].other_ips, 1);
        assert_eq!(fps[0].visitor_ids, vec!["v1".to_string()]);
        let clusters = s.fingerprint_clusters().await.unwrap();
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].ips.len(), 2);
        let claims = s.claims_for_ip(a).await.unwrap();
        assert_eq!(claims[0].contact_email.as_deref(), Some("me@x.y"));
        assert_eq!(s.inbox().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn queue_summary_failed_jobs_and_request_detail() {
        let (s, a) = seeded().await;
        let q = s.queue_summary().await.unwrap();
        assert_eq!(q.done_24h, 1);
        assert_eq!(q.failed_24h, 1);
        assert_eq!(q.queued, 0);
        assert_eq!(q.scans_last_hour, 1);
        let failed = s.recent_failed_jobs(10).await.unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].error.as_deref(), Some("timeout"));
        let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE ip_id = ?").bind(a).fetch_one(&s.pool).await.unwrap();
        let d = s.request_detail(rid).await.unwrap().unwrap();
        assert_eq!(d.ip, "203.0.113.1");
        assert_eq!(d.headers[0].0, "user-agent");
        assert_eq!(d.body_text, "username=admin");
        assert_eq!(d.body_len, 14);
        assert!(!d.body_truncated);
        assert_eq!(d.fingerprint.as_ref().unwrap().hash, "h1");
        assert!(s.request_detail(999).await.unwrap().is_none());
    }
}
```

- [ ] **Step 6: Implement `src/store/inspect.rs`**

```rust
//! Admin-only read models: scans, ports, fingerprints, claims, queue
//! health, full request detail. Never called from public handlers.
use super::Store;
use super::browse::{PAGE_SIZE, Page};
use super::requests::RequestRow;
use crate::events::QueueJob;
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ScanSummary {
    pub id: i64, pub ip_id: i64, pub ip: String, pub level: i64,
    pub started_at: String, pub finished_at: Option<String>, pub os_guess: Option<String>, pub open_ports: i64,
}

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct PortRow {
    pub port: i64, pub proto: String, pub state: String,
    pub service: Option<String>, pub product: Option<String>, pub version: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FpSummary { pub hash: String, pub count: i64, pub other_ips: i64, pub visitor_ids: Vec<String> }

#[derive(Debug, Clone, serde::Serialize)]
pub struct FpCluster { pub hash: String, pub ips: Vec<String>, pub count: i64 }

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct FpClaimRow { pub id: i64, pub ts: String, pub ip: String, pub contact_email: Option<String>, pub user_agent: String }

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueueSummary { pub queued: i64, pub running: i64, pub done_24h: i64, pub failed_24h: i64, pub scans_last_hour: i64 }

pub struct RequestDetail {
    pub row: RequestRow,
    pub ip: String,
    pub headers: Vec<(String, String)>,
    pub body_text: String,
    pub body_len: usize,
    pub body_truncated: bool,
    pub fingerprint: Option<FpSummary>,
}

const SCAN_SELECT: &str =
    "SELECT s.id, s.ip_id, i.ip, s.level, s.started_at, s.finished_at, s.os_guess,
            (SELECT COUNT(*) FROM ports p WHERE p.scan_id = s.id AND p.state = 'open') AS open_ports
     FROM scans s JOIN ips i ON s.ip_id = i.id";

const BODY_LIMIT: usize = 16 * 1024;

impl Store {
    pub async fn scans_for_ip(&self, ip_id: i64) -> Result<Vec<ScanSummary>> {
        Ok(sqlx::query_as::<_, ScanSummary>(&format!("{SCAN_SELECT} WHERE s.ip_id = ? ORDER BY s.id DESC"))
            .bind(ip_id).fetch_all(&self.pool).await?)
    }
    pub async fn list_scans(&self, page: u32) -> Result<Page<ScanSummary>> {
        let rows = sqlx::query_as::<_, ScanSummary>(&format!(
            "{SCAN_SELECT} ORDER BY s.id DESC LIMIT {} OFFSET {}", PAGE_SIZE + 1, (page.max(1) as i64 - 1) * PAGE_SIZE))
            .fetch_all(&self.pool).await?;
        let has_next = rows.len() as i64 > PAGE_SIZE;
        Ok(Page { items: rows.into_iter().take(PAGE_SIZE as usize).collect(), page: page.max(1), has_next })
    }
    pub async fn scan_by_id(&self, id: i64) -> Result<Option<ScanSummary>> {
        Ok(sqlx::query_as::<_, ScanSummary>(&format!("{SCAN_SELECT} WHERE s.id = ?")).bind(id).fetch_optional(&self.pool).await?)
    }
    pub async fn ports_for_scan(&self, scan_id: i64) -> Result<Vec<PortRow>> {
        Ok(sqlx::query_as::<_, PortRow>(
            "SELECT port, proto, state, service, product, version FROM ports WHERE scan_id = ? ORDER BY port")
            .bind(scan_id).fetch_all(&self.pool).await?)
    }
    pub async fn scan_raw_xml(&self, id: i64) -> Result<Option<Vec<u8>>> {
        let blob: Option<Option<Vec<u8>>> = sqlx::query_scalar("SELECT raw_xml FROM scans WHERE id = ?")
            .bind(id).fetch_optional(&self.pool).await?;
        match blob.flatten() {
            Some(b) => Ok(Some(zstd::decode_all(b.as_slice())?)),
            None => Ok(None),
        }
    }

    pub async fn fingerprints_for_ip(&self, ip_id: i64) -> Result<Vec<FpSummary>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT fp_hash, COUNT(*) FROM fingerprints WHERE ip_id = ? AND fp_hash IS NOT NULL GROUP BY fp_hash ORDER BY 2 DESC")
            .bind(ip_id).fetch_all(&self.pool).await?;
        let mut out = vec![];
        for (hash, count) in rows {
            let other_ips = self.fingerprint_ip_count(&hash, ip_id).await?;
            let visitor_ids: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT visitor_id FROM fingerprints WHERE ip_id = ? AND fp_hash = ? AND visitor_id IS NOT NULL")
                .bind(ip_id).bind(&hash).fetch_all(&self.pool).await?;
            out.push(FpSummary { hash, count, other_ips, visitor_ids });
        }
        Ok(out)
    }

    pub async fn fingerprint_clusters(&self) -> Result<Vec<FpCluster>> {
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT f.fp_hash, GROUP_CONCAT(DISTINCT i.ip), COUNT(*)
             FROM fingerprints f JOIN ips i ON f.ip_id = i.id WHERE f.fp_hash IS NOT NULL
             GROUP BY f.fp_hash HAVING COUNT(DISTINCT f.ip_id) > 1 ORDER BY COUNT(DISTINCT f.ip_id) DESC LIMIT 200")
            .fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|(hash, ips, count)| FpCluster {
            hash, ips: ips.split(',').map(str::to_string).collect(), count,
        }).collect())
    }

    pub async fn claims_for_ip(&self, ip_id: i64) -> Result<Vec<FpClaimRow>> {
        Ok(sqlx::query_as::<_, FpClaimRow>(
            "SELECT c.id, c.ts, i.ip, c.contact_email, c.user_agent FROM fp_claims c JOIN ips i ON c.ip_id = i.id
             WHERE c.ip_id = ? ORDER BY c.id DESC").bind(ip_id).fetch_all(&self.pool).await?)
    }
    pub async fn inbox(&self) -> Result<Vec<FpClaimRow>> {
        Ok(sqlx::query_as::<_, FpClaimRow>(
            "SELECT c.id, c.ts, i.ip, c.contact_email, c.user_agent FROM fp_claims c JOIN ips i ON c.ip_id = i.id ORDER BY c.id DESC LIMIT 500")
            .fetch_all(&self.pool).await?)
    }

    pub async fn queue_summary(&self) -> Result<QueueSummary> {
        // SUM over zero rows is NULL, hence the Options.
        let (q, r, d, f): (Option<i64>, Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT SUM(status='queued'), SUM(status='running'),
                    SUM(status='done' AND finished_at > datetime('now','-24 hours')),
                    SUM(status='failed' AND finished_at > datetime('now','-24 hours'))
             FROM scan_jobs").fetch_one(&self.pool).await?;
        Ok(QueueSummary {
            queued: q.unwrap_or(0), running: r.unwrap_or(0), done_24h: d.unwrap_or(0), failed_24h: f.unwrap_or(0),
            scans_last_hour: self.recent_scans_last_hour().await?,
        })
    }

    pub async fn recent_failed_jobs(&self, limit: i64) -> Result<Vec<QueueJob>> {
        Ok(sqlx::query_as::<_, QueueJob>(
            "SELECT j.id, i.ip, j.level, j.status, j.queued_at, j.started_at, j.finished_at, j.error
             FROM scan_jobs j JOIN ips i ON j.ip_id = i.id WHERE j.status = 'failed' ORDER BY j.id DESC LIMIT ?")
            .bind(limit).fetch_all(&self.pool).await?)
    }

    pub async fn request_detail(&self, id: i64) -> Result<Option<RequestDetail>> {
        let Some(row) = self.request_by_id(id).await? else { return Ok(None) };
        let ip: String = sqlx::query_scalar("SELECT ip FROM ips WHERE id = ?").bind(row.ip_id).fetch_one(&self.pool).await?;
        let headers: Vec<(String, String)> = serde_json::from_str(&row.headers_json).unwrap_or_default();
        let body = row.body.clone().unwrap_or_default();
        let body_len = body.len();
        let body_truncated = body_len > BODY_LIMIT;
        let body_text = String::from_utf8_lossy(&body[..body_len.min(BODY_LIMIT)]).into_owned();
        let fp: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT fp_hash, visitor_id FROM fingerprints WHERE request_id = ? ORDER BY id DESC LIMIT 1")
            .bind(id).fetch_optional(&self.pool).await?;
        let fingerprint = match fp {
            Some((hash, visitor)) => Some(FpSummary {
                other_ips: self.fingerprint_ip_count(&hash, row.ip_id).await?,
                count: 1, visitor_ids: visitor.into_iter().collect(), hash,
            }),
            None => None,
        };
        Ok(Some(RequestDetail { row, ip, headers, body_text, body_len, body_truncated, fingerprint }))
    }

    pub async fn list_credential_labels(&self) -> Result<Vec<(String, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT hex(cred_id), COALESCE(label,'(unnamed)'), created_at FROM credentials ORDER BY id")
            .fetch_all(&self.pool).await?)
    }
}
```

In `src/store/mod.rs`: add `pub mod delete; pub mod inspect;`; delete the old `FpClaimRow`, `inbox`, `request_detail`, `list_credential_labels` there. `src/admin/detail.rs` compiles again by importing `crate::store::inspect::FpClaimRow` and using `request_detail(...)` fields `d.row`, `d.headers`, `d.body_text` (temporary until Task 10).

- [ ] **Step 7: Run everything, expect pass; commit**

```bash
cargo test
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src
git commit -m "feat(store): admin inspect reads and transactional deletes; worker tolerates deleted jobs

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 8: World map asset, wall of shame page, charts

**Files:**
- Create: `tools/package.json`, `tools/build-world-map.mjs`, `assets/world.svg` (generated, replaces the placeholder), `assets/README.md`, `assets/js/charts.js`, `assets/css/40-charts.css`, `src/admin/public.rs`, `templates/wall.html`, `templates/_severity.html`, `templates/_range.html`
- Modify: `src/admin/mod.rs` (mount `public::routes()`, remove `dashboard`, `render_dashboard`, `esc`; keep `stats_json`/`map_json` or move them into `public.rs`), delete `templates/dashboard.html`
- Test: `tests/integration.rs`

**Interfaces:**
- Consumes: `StatsCache`, `Range`, `Stats`, `MapCounts`, `country_name`, `flag`, `Chrome`, `sev_class`, `render`, `AppResult`.
- Produces: `crate::admin::public::routes() -> Router<Arc<AdminState>>` (mounts `/`, `/api/stats`, `/api/map`, `/healthz`); `crate::admin::public::MaybeUser(pub bool)` extractor (true when a valid session cookie is present, never rejects); `templates/_severity.html` partial expecting a variable `sev: i64`; `templates/_range.html` partial expecting `range: Range` and `base: &str`.

Before writing `charts.js` and `40-charts.css`, **load the `dataviz` skill** (`Skill: dataviz`) and follow its form and color guidance; the token ramp defined in Task 1 is the palette.

- [ ] **Step 1: Generate the map**

`tools/package.json`:
```json
{
  "name": "peephole-tools",
  "private": true,
  "type": "module",
  "dependencies": {
    "d3-geo": "^3.1.1",
    "i18n-iso-countries": "^7.14.0",
    "topojson-client": "^3.1.0",
    "world-atlas": "^2.0.2"
  }
}
```

`tools/build-world-map.mjs`:
```js
// Generates assets/world.svg: one <path id="XX"> per country (ISO alpha-2),
// Natural Earth 1 projection, 960x500. Source: world-atlas countries-110m
// (Natural Earth, public domain). Run: cd tools && npm install && node build-world-map.mjs
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import countries from "i18n-iso-countries";

const require = createRequire(import.meta.url);
const topo = JSON.parse(readFileSync(require.resolve("world-atlas/countries-110m.json"), "utf8"));
const fc = feature(topo, topo.objects.countries);

const W = 960, H = 500;
const projection = geoNaturalEarth1().fitSize([W, H], { type: "Sphere" });
const path = geoPath(projection);

let out = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="World map">\n`;
out += `<path class="sphere" d="${path({ type: "Sphere" })}"/>\n`;
let n = 0, skipped = [];
for (const f of fc.features) {
  const numeric = String(f.id).padStart(3, "0");
  const alpha2 = countries.numericToAlpha2(numeric);
  if (!alpha2 || alpha2 === "AQ") { skipped.push(numeric); continue; }
  const d = path(f);
  if (!d) continue;
  out += `<path class="country" id="${alpha2}" d="${d.replace(/(\d)\.(\d)\d+/g, "$1.$2")}"/>\n`;
  n++;
}
out += `</svg>\n`;
writeFileSync(new URL("../assets/world.svg", import.meta.url), out);
console.log(`wrote ${n} countries, skipped ${skipped.length}: ${skipped.join(",")}`);
```

Run:
```bash
cd tools && npm install && node build-world-map.mjs && cd ..
ls -la assets/world.svg && grep -c 'class="country"' assets/world.svg && grep -o 'id="DE"' assets/world.svg
```
Expected: ~170 countries, file 150–300 KB, `id="DE"` present. If `npm install` cannot reach the registry, stop and report; do not hand-draw a map.

`assets/README.md`:
```markdown
# Embedded assets

- `fonts/inter-*.woff2`, `fonts/jetbrains-mono-*.woff2` — Inter and JetBrains Mono, SIL Open Font License 1.1. Latin subsets.
- `world.svg` — generated by `tools/build-world-map.mjs` from `world-atlas` `countries-110m.json` (Natural Earth, public domain) via d3-geo (Natural Earth 1 projection). One `<path id="XX">` per ISO 3166-1 alpha-2 code; Antarctica omitted. Regenerate with `cd tools && npm install && node build-world-map.mjs`.
- `logo.svg` — peephole mark.
- `app.css` — generated by `build.rs` from `css/*.css`; do not edit.
```

- [ ] **Step 2: Failing integration test for the wall**

Replace `dashboard_shows_aggregates_not_payloads` with:
```rust
#[tokio::test]
async fn wall_shows_aggregates_not_payloads() {
    let (trap_base, store, dir) = spawn_trap().await;
    let client = reqwest::Client::new();
    let _ = client.post(format!("{trap_base}/login")).header("x-forwarded-for", "203.0.113.99")
        .form(&[("username", "SECRET-PAYLOAD-MARKER"), ("password", "x")]).send().await.unwrap();
    let _ = client.get(format!("{trap_base}/wp-login.php")).header("x-forwarded-for", "203.0.113.99")
        .header("x-secret-header", "HEADER-MARKER").send().await.unwrap();
    let admin_base = spawn_admin_with(store.clone(), dir.path()).await;
    let resp = reqwest::get(format!("{admin_base}/?range=7d")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let html = resp.text().await.unwrap();
    assert!(html.contains("203.0.113.99"));
    assert!(html.contains("/wp-login.php"));
    assert!(html.contains("href=\"/ip/203.0.113.99\""));
    assert!(html.contains("Last 7 days"));
    assert!(html.contains("data-range=\"7d\""));
    assert!(html.contains("id=\"map\""));
    assert!(html.contains("/assets/js/charts.js"));
    assert!(!html.contains("SECRET-PAYLOAD-MARKER"));
    assert!(!html.contains("HEADER-MARKER"));
    assert!(!html.contains("<script>"), "no inline scripts under CSP");
    assert!(!html.contains(" style=\""), "no inline styles under CSP");
    let ok = reqwest::get(format!("{admin_base}/healthz")).await.unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.text().await.unwrap(), "ok");
    let svg = reqwest::get(format!("{admin_base}/assets/world.svg")).await.unwrap().text().await.unwrap();
    assert!(svg.contains("id=\"DE\""));
}
```

- [ ] **Step 3: Run, expect failure**

Run: `cargo test --test integration wall_shows_aggregates_not_payloads`

- [ ] **Step 4: Partials and the wall template**

`templates/_severity.html`:
```html
<span class="{{ crate::admin::views::sev_class(sev) }}" title="severity {{ sev }}">{{ sev }}</span>
```

`templates/_range.html`:
```html
<nav class="seg" aria-label="Time range">
  {% for r in crate::store::stats::Range::ALL %}
  <a href="{{ base }}?range={{ r.key() }}"{% if r.key() == range.key() %} aria-current="true"{% endif %}>{{ r.key() }}</a>
  {% endfor %}
</nav>
```

`templates/wall.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — wall of shame{% endblock %}
{% block head %}<script src="/assets/js/charts.js?v={{ chrome.stamp }}" defer></script>{% endblock %}
{% block content %}
<div class="page-head" data-range="{{ range.key() }}" id="wall">
  <div>
    <h1>Wall of shame</h1>
    <p class="muted">Everything that knocked on a door that does not exist. {{ range.label() }}.</p>
  </div>
  {% let base = "/" %}{% include "_range.html" %}
</div>
{% if stale %}<div class="banner banner-warning">Intel data (Tor exit list / GeoIP) is missing or older than 48 hours — check the scheduler.</div>{% endif %}

<div class="tiles">
  <div class="tile"><span class="label">Requests</span><div class="value">{{ stats.total_requests }}</div></div>
  <div class="tile"><span class="label">Unique IPs</span><div class="value">{{ stats.unique_ips }}</div></div>
  <div class="tile"><span class="label">Countries</span><div class="value">{{ stats.countries }}</div></div>
  <div class="tile"><span class="label">Tor exits</span><div class="value">{{ stats.tor_ips }}</div></div>
  <div class="tile"><span class="label">Counter-scans</span><div class="value brand">{{ stats.scans_done }}</div><div class="hint">completed</div></div>
</div>

<div class="stack">
  <section class="card">
    <div class="card-head"><h2>Requests over time</h2><span class="muted">{% if range.hourly() %}per hour{% else %}per day{% endif %}</span></div>
    <div class="chart" id="chart-timeline" data-chart="timeline" role="img" aria-label="Requests over time"></div>
  </section>

  <div class="grid-3">
    <section class="card">
      <h2>Severity</h2>
      <div class="chart" id="chart-severity" data-chart="severity"></div>
      <table class="visually-hidden"><tbody>{% for n in stats.severity_distribution %}<tr><td>{{ n.name }}</td><td>{{ n.count }}</td></tr>{% endfor %}</tbody></table>
    </section>
    <section class="card">
      <h2>Top labels</h2>
      <div class="chart" id="chart-labels" data-chart="labels"></div>
      <ol class="visually-hidden">{% for n in stats.top_labels %}<li>{{ n.name }} {{ n.count }}</li>{% endfor %}</ol>
    </section>
    <section class="card">
      <h2>Top countries</h2>
      <div class="chart" id="chart-countries" data-chart="countries"></div>
      <ol class="visually-hidden">{% for n in stats.top_countries %}<li>{{ crate::admin::countries::country_name(n.name.as_str()) }} {{ n.count }}</li>{% endfor %}</ol>
    </section>
  </div>

  <section class="card">
    <div class="card-head"><h2>Where it comes from</h2><span class="muted">unique source IPs per country</span></div>
    <div class="map" id="map" data-src="/assets/world.svg?v={{ chrome.stamp }}"></div>
    <div class="legend" id="map-legend"></div>
  </section>

  <div class="grid-2">
    <section class="card">
      <h2>Top attacking IPs</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>Country</th><th class="num">Requests</th><th>Max sev</th></tr></thead>
        <tbody>
        {% for t in stats.top_ips %}
          <tr>
            <td class="ip"><a href="/ip/{{ t.ip }}">{{ t.ip }}</a>{% if t.is_tor %} <span class="badge badge-tor">tor</span>{% endif %}</td>
            <td>{% if let Some(c) = t.country %}{{ crate::admin::countries::flag(c) }} {{ c }}{% else %}<span class="muted">—</span>{% endif %}</td>
            <td class="num">{{ t.count }}</td>
            <td>{% let sev = t.max_severity %}{% include "_severity.html" %}</td>
          </tr>
        {% endfor %}
        {% if stats.top_ips.is_empty() %}<tr><td colspan="4" class="empty">Nothing yet.</td></tr>{% endif %}
        </tbody>
      </table></div>
    </section>
    <section class="card">
      <h2>Top networks</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>ASN organisation</th><th class="num">IPs</th></tr></thead>
        <tbody>
        {% for n in stats.top_asns %}<tr><td>{{ n.name }}</td><td class="num">{{ n.count }}</td></tr>{% endfor %}
        {% if stats.top_asns.is_empty() %}<tr><td colspan="2" class="empty">Nothing yet.</td></tr>{% endif %}
        </tbody>
      </table></div>
    </section>
  </div>

  <section class="card">
    <div class="card-head"><h2>Recent activity</h2><a href="/requests">search all →</a></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Path</th><th>Sev</th><th>Labels</th></tr></thead>
      <tbody>
      {% for r in stats.recent %}
        <tr>
          <td class="ts">{{ r.ts }}</td>
          <td class="ip"><a href="/ip/{{ r.ip }}">{{ r.ip }}</a></td>
          <td class="mono">{{ r.method }}</td>
          <td class="path">{{ r.path }}</td>
          <td>{% let sev = r.severity %}{% include "_severity.html" %}</td>
          <td><span class="chips">{% for l in r.labels %}<span class="badge badge-label">{{ l }}</span>{% endfor %}</span></td>
        </tr>
      {% endfor %}
      {% if stats.recent.is_empty() %}<tr><td colspan="6" class="empty">Nothing yet.</td></tr>{% endif %}
      </tbody>
    </table></div>
  </section>
</div>
{% endblock %}
```

`{% let base = "/" %}` before the include gives `_range.html` its `base`; `range` and `chrome` come from the page struct.

- [ ] **Step 5: `src/admin/public.rs` (wall part)**

```rust
//! Unauthenticated pages. Never load admin-only data here.
use crate::admin::countries;
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::admin::{AdminState, RangeQuery};
use crate::store::stats::{MapCounts, Range, Stats, intel_stale};
use askama::Template;
use axum::{
    Router,
    extract::{FromRequestParts, Query, State},
    http::request::Parts,
    response::{Html, IntoResponse, Json, Response},
    routing::get,
};
use std::convert::Infallible;
use std::sync::Arc;

/// `true` when the request carries a valid admin session. Never rejects.
pub struct MaybeUser(pub bool);

impl FromRequestParts<Arc<AdminState>> for MaybeUser {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, state: &Arc<AdminState>) -> Result<Self, Infallible> {
        let jar = axum_extra::extract::CookieJar::from_request_parts(parts, state).await.unwrap_or_else(|_| axum_extra::extract::CookieJar::new());
        let ok = match jar.get("peephole_session") {
            Some(c) => state.store.validate_session(c.value()).await.unwrap_or(false),
            None => false,
        };
        Ok(MaybeUser(ok))
    }
}

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/", get(wall))
        .route("/api/stats", get(stats_json))
        .route("/api/map", get(map_json))
        .route("/healthz", get(healthz))
}

#[derive(Template)]
#[template(path = "wall.html")]
struct WallPage {
    chrome: Chrome,
    range: Range,
    stats: Arc<Stats>,
    stale: bool,
}

async fn wall(MaybeUser(authed): MaybeUser, State(state): State<Arc<AdminState>>, Query(q): Query<RangeQuery>) -> AppResult<Html<String>> {
    let range = Range::parse(q.range.as_deref());
    let stats = state.stats_cache.stats(&state.store, range).await?;
    let stale = intel_stale(&stats.intel);
    render(&WallPage { chrome: Chrome::new(authed, "wall"), range, stats, stale })
}

async fn stats_json(State(state): State<Arc<AdminState>>, Query(q): Query<RangeQuery>) -> AppResult<Json<Arc<Stats>>> {
    Ok(Json(state.stats_cache.stats(&state.store, Range::parse(q.range.as_deref())).await?))
}

async fn map_json(State(state): State<Arc<AdminState>>, Query(q): Query<RangeQuery>) -> AppResult<Json<Arc<MapCounts>>> {
    Ok(Json(state.stats_cache.map(&state.store, Range::parse(q.range.as_deref())).await?))
}

async fn healthz(State(state): State<Arc<AdminState>>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&state.store.pool).await {
        Ok(_) => "ok".into_response(),
        Err(e) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}
```

In `src/admin/mod.rs`: `pub mod public;`, make `RangeQuery` `pub`, remove `dashboard`, `render_dashboard`, `esc`, `stats_json`, `map_json`, and the `/`, `/api/stats`, `/api/map` routes; `.merge(public::routes())` in `full_router`. Delete `templates/dashboard.html`.

- [ ] **Step 6: Charts**

`assets/css/40-charts.css`:
```css
.chart { width: 100%; min-height: 8rem; }
.chart svg { display: block; width: 100%; height: auto; overflow: visible; }
.chart .bar { fill: var(--color-accent); }
.chart .bar:hover { fill: var(--color-brand); }
.chart .axis text { fill: var(--color-fg-muted); font-size: 10px; font-family: var(--font-mono); }
.chart .axis line, .chart .grid line { stroke: var(--color-border); }
.chart .hbar-label { fill: var(--color-fg-primary); font-size: 11px; }
.chart .hbar-value { fill: var(--color-fg-muted); font-size: 11px; font-family: var(--font-mono); }
.chart .hbar { fill: var(--color-accent-muted); }
.chart .sev-bar-0 { fill: var(--sev-0); } .chart .sev-bar-1 { fill: var(--sev-1); }
.chart .sev-bar-2 { fill: var(--sev-2); } .chart .sev-bar-3 { fill: var(--sev-3); } .chart .sev-bar-4 { fill: var(--sev-4); }
.chart .empty-note { fill: var(--color-fg-muted); font-size: 12px; }
.map svg { display: block; width: 100%; height: auto; }
.map .sphere { fill: var(--color-bg-surface); }
.map .country { fill: var(--ramp-0); stroke: var(--color-bg-elevated); stroke-width: 0.5; transition: fill 200ms; }
.map .country[data-bin="1"] { fill: var(--ramp-1); } .map .country[data-bin="2"] { fill: var(--ramp-2); }
.map .country[data-bin="3"] { fill: var(--ramp-3); } .map .country[data-bin="4"] { fill: var(--ramp-4); }
.map .country:hover { stroke: var(--color-brand); stroke-width: 1; }
.legend { display: flex; gap: 0.75rem; align-items: center; margin-top: 0.5rem; font-size: var(--text-xs); color: var(--color-fg-muted); flex-wrap: wrap; }
.legend .swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; vertical-align: -2px; margin-right: 0.3rem; }
.legend .swatch[data-bin="0"] { background: var(--ramp-0); } .legend .swatch[data-bin="1"] { background: var(--ramp-1); }
.legend .swatch[data-bin="2"] { background: var(--ramp-2); } .legend .swatch[data-bin="3"] { background: var(--ramp-3); }
.legend .swatch[data-bin="4"] { background: var(--ramp-4); }
.tooltip { position: fixed; pointer-events: none; background: var(--color-bg-elevated); border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-md); padding: 0.3rem 0.55rem; font-size: var(--text-xs); color: var(--color-fg-primary); z-index: 20; display: none; }
.sparkline { width: 100%; height: 2.5rem; }
.sparkline rect { fill: var(--color-accent-muted); }
.sparkline rect:last-child { fill: var(--color-accent); }
```

`assets/js/charts.js`:
```js
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg";
  function el(tag, attrs, parent) {
    var e = document.createElementNS(NS, tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, s, cls, anchor) {
    var t = el("text", { x: x, y: y, "class": cls, "text-anchor": anchor || "start" }, parent);
    t.textContent = s; return t;
  }
  function svg(host, w, h) {
    host.innerHTML = "";
    return el("svg", { viewBox: "0 0 " + w + " " + h, preserveAspectRatio: "xMidYMid meet" }, host);
  }
  function empty(host, w, h) { var s = svg(host, w, h); text(s, w / 2, h / 2, "no data in this range", "empty-note", "middle"); }
  var tip = document.createElement("div"); tip.className = "tooltip"; document.body.appendChild(tip);
  function showTip(ev, html) { tip.innerHTML = html; tip.style.display = "block"; tip.style.left = (ev.clientX + 12) + "px"; tip.style.top = (ev.clientY + 12) + "px"; }
  function hideTip() { tip.style.display = "none"; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // Vertical bars: [{ts, count}]
  function timeline(host, buckets) {
    var W = 900, H = 180, L = 36, B = 22, T = 6;
    if (!buckets.length) return empty(host, W, H);
    var s = svg(host, W, H), max = Math.max.apply(null, buckets.map(function (b) { return b.count; })) || 1;
    var n = buckets.length, bw = (W - L) / n, plotH = H - B - T;
    var grid = el("g", { "class": "grid" }, s), axis = el("g", { "class": "axis" }, s);
    [0, 0.5, 1].forEach(function (f) {
      var y = T + plotH - f * plotH;
      el("line", { x1: L, x2: W, y1: y, y2: y }, grid);
      text(axis, L - 6, y + 3, Math.round(f * max), "", "end");
    });
    buckets.forEach(function (b, i) {
      var h = (b.count / max) * plotH, r = el("rect", { "class": "bar", x: L + i * bw + 1, y: T + plotH - h, width: Math.max(bw - 2, 1), height: h, rx: 1 }, s);
      r.addEventListener("mousemove", function (ev) { showTip(ev, "<b>" + b.count + "</b> · " + esc(b.ts)); });
      r.addEventListener("mouseleave", hideTip);
    });
    var step = Math.max(1, Math.ceil(n / 8));
    buckets.forEach(function (b, i) { if (i % step === 0) text(axis, L + i * bw + bw / 2, H - 6, b.ts.slice(5).replace("T", " "), "", "middle"); });
  }

  // Horizontal bars: [{name, count}], optional class per item
  function hbars(host, items, opts) {
    opts = opts || {};
    var W = 400, rowH = 22, H = Math.max(rowH * items.length + 4, 40);
    if (!items.length) return empty(host, W, 80);
    var s = svg(host, W, H), max = Math.max.apply(null, items.map(function (i) { return i.count; })) || 1;
    var labelW = 150;
    items.forEach(function (it, i) {
      var y = 2 + i * rowH, w = ((W - labelW - 50) * it.count) / max;
      text(s, labelW - 8, y + 15, (opts.label ? opts.label(it) : it.name).slice(0, 22), "hbar-label", "end");
      el("rect", { "class": (opts.cls ? opts.cls(it) : "hbar"), x: labelW, y: y + 4, width: Math.max(w, 2), height: rowH - 8, rx: 2 }, s);
      text(s, labelW + w + 6, y + 15, it.count, "hbar-value");
    });
  }

  function countryName(code) { return (window.peephole.countryNames && window.peephole.countryNames[code]) || code; }

  function map(host, legend, data) {
    var src = host.getAttribute("data-src");
    fetch(src).then(function (r) { return r.text(); }).then(function (svgText) {
      host.innerHTML = svgText;
      var max = data.max || 0, thresholds = [0, 1, Math.ceil(max * 0.1), Math.ceil(max * 0.35), Math.ceil(max * 0.7)];
      function bin(v) { if (!v) return 0; for (var b = 4; b >= 1; b--) if (v >= thresholds[b]) return b; return 1; }
      host.querySelectorAll(".country").forEach(function (p) {
        var code = p.id, v = data.countries[code] || 0;
        p.setAttribute("data-bin", bin(v));
        p.addEventListener("mousemove", function (ev) { showTip(ev, "<b>" + esc(countryName(code)) + "</b> · " + v + (v === 1 ? " IP" : " IPs")); });
        p.addEventListener("mouseleave", hideTip);
        p.addEventListener("click", function () { location.href = "/ips?country=" + code; });
      });
      if (legend) {
        legend.innerHTML = "";
        var labels = ["0", "1–" + Math.max(thresholds[2] - 1, 1), thresholds[2] + "–" + Math.max(thresholds[3] - 1, thresholds[2]), thresholds[3] + "–" + Math.max(thresholds[4] - 1, thresholds[3]), thresholds[4] + "+"];
        for (var b = 0; b < 5; b++) {
          var span = document.createElement("span"); var sw = document.createElement("i"); sw.className = "swatch"; sw.setAttribute("data-bin", b);
          span.appendChild(sw); span.appendChild(document.createTextNode(max ? labels[b] : (b ? "" : "no data")));
          if (max || b === 0) legend.appendChild(span);
        }
      }
    }).catch(function () {});
  }

  function sparkline(host, values) {
    var W = 240, H = 40, n = values.length, s = svg(host, W, H), max = Math.max.apply(null, values) || 1, bw = W / n;
    values.forEach(function (v, i) { el("rect", { x: i * bw + 0.5, y: H - (v / max) * H, width: bw - 1, height: (v / max) * H }, s); });
  }

  function boot() {
    var wall = document.getElementById("wall");
    if (wall) {
      var range = wall.getAttribute("data-range") || "24h";
      fetch("/api/stats?range=" + range).then(function (r) { return r.json(); }).then(function (st) {
        timeline(document.getElementById("chart-timeline"), st.timeline);
        hbars(document.getElementById("chart-severity"), st.severity_distribution, { label: function (i) { return "severity " + i.name; }, cls: function (i) { return "sev-bar-" + i.name; } });
        hbars(document.getElementById("chart-labels"), st.top_labels.slice(0, 10));
        hbars(document.getElementById("chart-countries"), st.top_countries.slice(0, 10), { label: function (i) { return countryName(i.name); } });
      }).catch(function () {});
      fetch("/api/map?range=" + range).then(function (r) { return r.json(); }).then(function (m) {
        map(document.getElementById("map"), document.getElementById("map-legend"), m);
      }).catch(function () {});
    }
    document.querySelectorAll("[data-sparkline]").forEach(function (h) {
      try { sparkline(h, JSON.parse(h.getAttribute("data-sparkline"))); } catch (e) {}
    });
  }
  window.peephole = window.peephole || {};
  window.peephole.charts = { timeline: timeline, hbars: hbars, map: map, sparkline: sparkline };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
```

Country names for tooltips: `wall.html` gets, inside `{% block head %}`, nothing inline (CSP). Instead add a public JSON route `/api/countries` returning `countries::TABLE` as an object, fetched once by `charts.js` before rendering the map (`fetch("/api/countries").then(...).then(function(n){ window.peephole.countryNames = n; ... })`). Add the route to `public::routes()`:
```rust
async fn countries_json() -> impl IntoResponse {
    let map: std::collections::HashMap<&'static str, &'static str> = countries::TABLE.iter().copied().collect();
    ([(axum::http::header::CACHE_CONTROL, "public, max-age=86400")], Json(map))
}
```
Chain the map fetch after the countries fetch in `boot()`.

- [ ] **Step 7: Run tests, expect pass**

Run: `cargo test`
Expected: PASS. `full_stack_smoke` still uses `/api/stats` (`total_requests`, `scans_done` unchanged).

- [ ] **Step 8: Visual check in a browser**

Run the binary against a temp config with a fake nmap (copy the recipe from `full_stack_smoke`), send a few probes with `curl -H 'X-Forwarded-For: 203.0.113.5' http://127.0.0.1:18080/.env`, open `http://127.0.0.1:18443/` and screenshot both themes (toggle in the topbar). Check: no console errors, map renders, charts render, layout holds at 400 px width. Fix CSS issues found; this is the moment for polish.

- [ ] **Step 9: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add tools/package.json tools/build-world-map.mjs assets src templates tests
git rm -q templates/dashboard.html
git commit -m "feat(public): wall of shame with ranged stats, charts and choropleth map

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 9: Public IP directory, IP page, request search

**Files:**
- Create: `templates/ips.html`, `templates/ip.html`, `templates/requests.html` (replaces the old one), `templates/_pagination.html`, `templates/_ports.html`
- Modify: `src/admin/public.rs`, `src/admin/detail.rs` (remove `/requests` and `/ips/{id}` routes; they move here)
- Test: `tests/integration.rs`

**Interfaces:**
- Consumes: `IpFilter`, `RequestFilter`, `Page<T>`, `IpSummary`, `IpOverview`, `RequestListRow`, `ScanSummary`, `PortRow`, `FpSummary`, `FpClaimRow`, `MaybeUser`.
- Produces: routes `/ips`, `/ip/{addr}`, `/requests` in `public::routes()`. `ip.html` renders admin sections only when `authed` **and** the optional admin data is `Some`; the handler passes `None` for anonymous requests. `_pagination.html` expects `page: Page<_>` and `qs: String` (query string without `page`).

- [ ] **Step 1: Failing integration tests**

```rust
#[tokio::test]
async fn public_ip_page_shows_requests_but_hides_admin_data() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let _ = c.get(format!("{trap_base}/wp-login.php")).header("x-forwarded-for", "203.0.113.42")
        .header("x-secret-header", "HEADER-MARKER").send().await.unwrap();
    let _ = c.post(format!("{trap_base}/claim")).header("x-forwarded-for", "203.0.113.42")
        .form(&[("email", "claimant@example.org")]).send().await.unwrap();
    let ip = store.ip_by_addr("203.0.113.42").await.unwrap().unwrap();
    store.insert_fingerprint(None, ip.id, "FPHASHMARKER", Some("VISITORMARKER"), "{}", "{}", b"[]").await.unwrap();
    let job = match store.enqueue_scan(ip.id, 2, 24).await.unwrap() { peephole::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
    store.next_queued_job().await.unwrap();
    store.finish_job(job, Some(&peephole::scan::nmap_xml::ScanResult { os_guess: Some("OSGUESSMARKER".into()), raw_xml: b"<nmaprun/>".to_vec(),
        ports: vec![peephole::scan::nmap_xml::PortResult { port: 31337, proto: "tcp".into(), state: "open".into(), service: Some("SERVICEMARKER".into()), product: None, version: None }] }), None).await.unwrap();

    let base = spawn_admin_with(store.clone(), dir.path()).await;
    let html = reqwest::get(format!("{base}/ip/203.0.113.42")).await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.42"));
    assert!(html.contains("/wp-login.php"));
    assert!(html.contains("data-sparkline=\"["));
    for marker in ["HEADER-MARKER", "claimant@example.org", "FPHASHMARKER", "VISITORMARKER", "OSGUESSMARKER", "SERVICEMARKER", "31337", "Counter-scans", "Delete"] {
        assert!(!html.contains(marker), "public page leaked {marker}");
    }
    assert_eq!(reqwest::get(format!("{base}/ip/hello")).await.unwrap().status(), 404);
    assert_eq!(reqwest::get(format!("{base}/ip/203.0.113.43")).await.unwrap().status(), 404);
    let v6 = store.upsert_ip("2001:db8::1".parse().unwrap()).await.unwrap();
    let _ = v6;
    assert_eq!(reqwest::get(format!("{base}/ip/2001:db8::1")).await.unwrap().status(), 200);

    // With a session the same page shows everything.
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, abase) = enrolled_admin_client(store.clone(), cfg).await;
    let html = client.get(format!("{abase}/ip/203.0.113.42")).send().await.unwrap().text().await.unwrap();
    for marker in ["claimant@example.org", "FPHASHMARKER", "OSGUESSMARKER", "SERVICEMARKER", "31337", "Counter-scans", "Delete this IP"] {
        assert!(html.contains(marker), "admin page missing {marker}");
    }
}

#[tokio::test]
async fn public_directory_and_request_search() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    for (ip, path) in [("203.0.113.1", "/a"), ("203.0.113.1", "/b"), ("203.0.113.200", "/c"), ("198.51.100.7", "/d")] {
        let _ = c.get(format!("{trap_base}{path}")).header("x-forwarded-for", ip).send().await.unwrap();
    }
    let base = spawn_admin_with(store, dir.path()).await;
    let html = reqwest::get(format!("{base}/ips")).await.unwrap().text().await.unwrap();
    assert!(html.contains("href=\"/ip/203.0.113.1\""));
    assert!(html.contains("198.51.100.7"));
    let html = reqwest::get(format!("{base}/ips?q=203.0.113.0/24")).await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.1") && html.contains("203.0.113.200"));
    assert!(!html.contains("198.51.100.7"));
    let html = reqwest::get(format!("{base}/ips?q=garbage&page=-3")).await.unwrap().text().await.unwrap();
    assert!(html.contains("No IPs match"));
    let html = reqwest::get(format!("{base}/requests?path=/c")).await.unwrap().text().await.unwrap();
    assert!(html.contains("/c") && !html.contains(">/a<"));
    assert!(!html.contains("href=\"/admin/requests/"), "no detail links for anonymous users");
    let html = reqwest::get(format!("{base}/requests?page=abc")).await.unwrap().text().await.unwrap();
    assert!(html.contains("/a"), "bad page falls back to page 1");
}
```

`?page=abc` and `?asn=abc` deserialize to `None` through `lenient_i64` (Task 6), so they never 400.

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --test integration public_`

- [ ] **Step 3: Templates**

`templates/_pagination.html`:
```html
{% if page.prev().is_some() || page.next().is_some() %}
<nav class="pagination" aria-label="Pagination">
  <span>{% if let Some(p) = page.prev() %}<a class="btn btn-sm" href="?{{ qs }}page={{ p }}">← Previous</a>{% endif %}</span>
  <span class="muted">page {{ page.page }}</span>
  <span>{% if let Some(n) = page.next() %}<a class="btn btn-sm" href="?{{ qs }}page={{ n }}">Next →</a>{% endif %}</span>
</nav>
{% endif %}
```

`templates/_ports.html` (expects `ports: Vec<PortRow>`; reused by `admin_scan.html`):
```html
<div class="table-wrap"><table>
  <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
  <tbody>
  {% for p in ports %}
    <tr><td class="mono">{{ p.port }}/{{ p.proto }}</td>
        <td><span class="badge badge-status" data-status="{% if p.state == "open" %}done{% else %}queued{% endif %}">{{ p.state }}</span></td>
        <td>{{ p.service.as_deref().unwrap_or("") }}</td><td>{{ p.product.as_deref().unwrap_or("") }}</td><td>{{ p.version.as_deref().unwrap_or("") }}</td></tr>
  {% endfor %}
  {% if ports.is_empty() %}<tr><td colspan="5" class="empty">No ports recorded.</td></tr>{% endif %}
  </tbody>
</table></div>
```

`templates/ips.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — IPs{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Source IPs</h1><p class="muted">Every address that has hit the trap. Search by IP, prefix or CIDR.</p></div></div>
<form class="filters" method="get" action="/ips">
  <label>Address / prefix / CIDR <input name="q" value="{{ f.q.as_deref().unwrap_or_default() }}" placeholder="203.0.113.0/24"></label>
  <label>Country <input name="country" size="3" maxlength="2" value="{{ f.country.as_deref().unwrap_or_default() }}" placeholder="DE"></label>
  <label>ASN <input name="asn" size="7" value="{% if let Some(a) = f.asn %}{{ a }}{% endif %}"></label>
  <label>Label <input name="label" value="{{ f.label.as_deref().unwrap_or_default() }}"></label>
  <label>Min severity <select name="min_severity">
    <option value="">any</option>
    {% for s in 1..5 %}<option value="{{ s }}"{% if f.min_severity == Some(s) %} selected{% endif %}>{{ s }}+</option>{% endfor %}
  </select></label>
  <label>Tor <select name="tor"><option value="">any</option><option value="1"{% if f.tor.as_deref() == Some("1") %} selected{% endif %}>exits only</option></select></label>
  <label>Sort <select name="sort">
    <option value="count"{% if f.sort.as_deref() != Some("recent") %} selected{% endif %}>most requests</option>
    <option value="recent"{% if f.sort.as_deref() == Some("recent") %} selected{% endif %}>last seen</option>
  </select></label>
  <button class="btn btn-primary" type="submit">Filter</button>
</form>
<div class="table-wrap"><table>
  <thead><tr><th>IP</th><th>Country</th><th>Network</th><th class="num">Requests</th><th>Max sev</th><th>First seen</th><th>Last seen</th></tr></thead>
  <tbody>
  {% for i in page.items %}
    <tr>
      <td class="ip"><a href="/ip/{{ i.ip }}">{{ i.ip }}</a>{% if i.is_tor %} <span class="badge badge-tor">tor</span>{% endif %}</td>
      <td>{% if let Some(c) = i.country %}{{ crate::admin::countries::flag(c) }} {{ crate::admin::countries::country_name(c) }}{% else %}<span class="muted">—</span>{% endif %}</td>
      <td>{% if let Some(o) = i.asn_org %}{{ o }}{% if let Some(a) = i.asn %} <span class="muted mono">AS{{ a }}</span>{% endif %}{% else %}<span class="muted">—</span>{% endif %}</td>
      <td class="num">{{ i.request_count }}</td>
      <td>{% let sev = i.max_severity %}{% include "_severity.html" %}</td>
      <td class="ts">{{ i.first_seen }}</td>
      <td class="ts">{{ i.last_seen }}</td>
    </tr>
  {% endfor %}
  {% if page.items.is_empty() %}<tr><td colspan="7" class="empty">No IPs match.</td></tr>{% endif %}
  </tbody>
</table></div>
{% include "_pagination.html" %}
{% endblock %}
```

`templates/requests.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — requests{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Requests</h1><p class="muted">Every captured request. Paths and query strings are shown as received.</p></div></div>
<form class="filters" method="get" action="/requests">
  <label>IP <input name="ip" value="{{ f.ip.as_deref().unwrap_or_default() }}"></label>
  <label>Path contains <input name="path" value="{{ f.path.as_deref().unwrap_or_default() }}"></label>
  <label>Label <input name="label" value="{{ f.label.as_deref().unwrap_or_default() }}"></label>
  <label>Min severity <select name="min_severity"><option value="">any</option>
    {% for s in 1..5 %}<option value="{{ s }}"{% if f.min_severity == Some(s) %} selected{% endif %}>{{ s }}+</option>{% endfor %}</select></label>
  <label>Country <input name="country" size="3" maxlength="2" value="{{ f.country.as_deref().unwrap_or_default() }}"></label>
  <label>ASN <input name="asn" size="7" value="{% if let Some(a) = f.asn %}{{ a }}{% endif %}"></label>
  <label>From (UTC) <input name="from" type="datetime-local" value="{{ f.from.as_deref().unwrap_or_default() }}"></label>
  <label>To (UTC) <input name="to" type="datetime-local" value="{{ f.to.as_deref().unwrap_or_default() }}"></label>
  <button class="btn btn-primary" type="submit">Filter</button>
</form>
<div class="table-wrap"><table>
  <thead><tr><th>Time (UTC)</th><th>IP</th><th>Method</th><th>Path</th><th>Sev</th><th>Labels</th>{% if chrome.authed %}<th></th>{% endif %}</tr></thead>
  <tbody>
  {% for r in page.items %}
    <tr>
      <td class="ts">{{ r.ts }}</td>
      <td class="ip"><a href="/ip/{{ r.ip }}">{{ r.ip }}</a>{% if r.is_tor %} <span class="badge badge-tor">tor</span>{% endif %}</td>
      <td class="mono">{{ r.method }}</td>
      <td class="path">{% if chrome.authed %}<a href="/admin/requests/{{ r.id }}">{% endif %}{{ r.path }}{% if let Some(q) = r.query %}<span class="muted">?{{ q }}</span>{% endif %}{% if chrome.authed %}</a>{% endif %}</td>
      <td>{% let sev = r.severity %}{% include "_severity.html" %}</td>
      <td><span class="chips">{% for l in r.labels() %}<span class="badge badge-label">{{ l }}</span>{% endfor %}</span></td>
      {% if chrome.authed %}<td><a class="btn btn-sm btn-ghost" href="/admin/requests/{{ r.id }}">inspect</a></td>{% endif %}
    </tr>
  {% endfor %}
  {% if page.items.is_empty() %}<tr><td colspan="7" class="empty">No requests match.</td></tr>{% endif %}
  </tbody>
</table></div>
{% include "_pagination.html" %}
{% endblock %}
```

`templates/ip.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — {{ ov.ip.ip }}{% endblock %}
{% block head %}<script src="/assets/js/charts.js?v={{ chrome.stamp }}" defer></script>{% endblock %}
{% block content %}
<div class="page-head ip-head">
  <div>
    <h1>{{ ov.ip.ip }}{% if ov.ip.is_tor_exit %} <span class="badge badge-tor">tor exit</span>{% endif %}</h1>
    <div class="meta">
      {% if let Some(c) = ov.ip.country %}<span>{{ crate::admin::countries::flag(c) }} {{ crate::admin::countries::country_name(c) }}</span>{% endif %}
      {% if let Some(o) = ov.ip.asn_org %}<span>{{ o }}{% if let Some(a) = ov.ip.asn %} <span class="mono muted">AS{{ a }}</span>{% endif %}</span>{% endif %}
      <span>first seen <span class="mono">{{ ov.ip.first_seen }}</span></span>
      <span>last seen <span class="mono">{{ ov.ip.last_seen }}</span></span>
    </div>
  </div>
  <div class="tiles">
    <div class="tile"><span class="label">Requests</span><div class="value">{{ ov.request_count }}</div></div>
    <div class="tile"><span class="label">Max severity</span><div class="value">{% let sev = ov.max_severity %}{% include "_severity.html" %}</div></div>
  </div>
</div>

<div class="stack">
  <section class="card">
    <div class="card-head"><h2>Last 24 hours</h2><span class="muted">requests per hour</span></div>
    <div class="sparkline" data-sparkline="{{ sparkline_json }}"></div>
    {% if !ov.labels.is_empty() %}<div class="chips">{% for l in ov.labels %}<span class="badge badge-label">{{ l.name }} <span class="muted">×{{ l.count }}</span></span>{% endfor %}</div>{% endif %}
  </section>

  {% if let Some(adm) = admin %}
  <section class="card">
    <div class="card-head"><h2>Counter-scans</h2><span class="muted">admin only</span></div>
    {% if adm.scans.is_empty() %}<p class="muted">No completed scans.</p>{% endif %}
    {% for sc in adm.scans %}
      <h3>Level {{ sc.s.level }} · <span class="mono">{{ sc.s.finished_at.as_deref().unwrap_or("unfinished") }}</span> · {{ sc.s.os_guess.as_deref().unwrap_or("OS unknown") }}
        · <a href="/admin/scans/{{ sc.s.id }}">details</a> · <a href="/admin/scans/{{ sc.s.id }}/xml">raw XML</a></h3>
      {% let ports = sc.ports %}{% include "_ports.html" %}
    {% endfor %}
  </section>

  <section class="card">
    <div class="card-head"><h2>Fingerprints</h2><span class="muted">admin only</span></div>
    {% if adm.fingerprints.is_empty() %}<p class="muted">No browser fingerprints collected.</p>{% endif %}
    {% for f in adm.fingerprints %}
      <p><a class="mono" href="/admin/fingerprints#{{ f.hash }}">{{ f.hash }}</a> ×{{ f.count }} — seen from <b>{{ f.other_ips }}</b> other IPs
        {% for v in f.visitor_ids %}<span class="badge badge-label">visitor {{ v }}</span>{% endfor %}</p>
    {% endfor %}
  </section>

  <section class="card">
    <div class="card-head"><h2>False-positive claims</h2><span class="muted">admin only</span></div>
    {% if adm.claims.is_empty() %}<p class="muted">None.</p>{% endif %}
    {% for c in adm.claims %}<p><span class="mono">{{ c.ts }}</span> · {{ c.contact_email.as_deref().unwrap_or("no email") }} · <span class="muted">{{ c.user_agent }}</span></p>{% endfor %}
  </section>
  {% endif %}

  <section class="card">
    <div class="card-head"><h2>Requests</h2></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Time (UTC)</th><th>Method</th><th>Path</th><th>Sev</th><th>Labels</th>{% if chrome.authed %}<th></th>{% endif %}</tr></thead>
      <tbody>
      {% for r in page.items %}
        <tr>
          <td class="ts">{{ r.ts }}</td><td class="mono">{{ r.method }}</td>
          <td class="path">{{ r.path }}{% if let Some(q) = r.query %}<span class="muted">?{{ q }}</span>{% endif %}</td>
          <td>{% let sev = r.severity %}{% include "_severity.html" %}</td>
          <td><span class="chips">{% for l in r.labels() %}<span class="badge badge-label">{{ l }}</span>{% endfor %}</span></td>
          {% if chrome.authed %}<td><a class="btn btn-sm btn-ghost" href="/admin/requests/{{ r.id }}">inspect</a></td>{% endif %}
        </tr>
      {% endfor %}
      </tbody>
    </table></div>
    {% let qs = String::new() %}{% include "_pagination.html" %}
  </section>

  {% if admin.is_some() %}
  <section class="card danger-zone">
    <h2>Danger zone</h2>
    <p class="muted">Removes this IP with all its requests, scans, fingerprints and claims. Cannot be undone.</p>
    <button class="btn btn-danger" type="button" data-confirm="dlg-delete-ip">Delete this IP</button>
    <dialog id="dlg-delete-ip">
      <h3>Delete {{ ov.ip.ip }}?</h3>
      <p class="muted">All {{ ov.request_count }} requests and every dependent record will be removed.</p>
      <form method="post" action="/admin/ips/{{ ov.ip.ip }}/delete" class="actions">
        <button class="btn" type="button" data-close>Cancel</button>
        <button class="btn btn-danger" type="submit">Delete</button>
      </form>
    </dialog>
  </section>
  {% endif %}
</div>
{% endblock %}
```

Add the dialog wiring to `assets/js/app.js` (inside the IIFE):
```js
  document.querySelectorAll("[data-confirm]").forEach(function (b) {
    b.addEventListener("click", function () { var d = document.getElementById(b.getAttribute("data-confirm")); if (d && d.showModal) d.showModal(); });
  });
  document.querySelectorAll("dialog [data-close]").forEach(function (b) {
    b.addEventListener("click", function () { b.closest("dialog").close(); });
  });
```

- [ ] **Step 4: Handlers in `src/admin/public.rs`**

```rust
use crate::store::browse::{IpFilter, IpOverview, Page, RequestFilter, RequestListRow, IpSummary, page_num};
use crate::store::inspect::{FpClaimRow, FpSummary, PortRow, ScanSummary};
use axum::extract::Path;
use crate::admin::error::AppError;

// in routes():
        .route("/ips", get(ips))
        .route("/ip/{addr}", get(ip_page))
        .route("/requests", get(requests))
        .route("/api/countries", get(countries_json))

#[derive(Template)]
#[template(path = "ips.html")]
struct IpsPage { chrome: Chrome, f: IpFilter, page: Page<IpSummary>, qs: String }

/// Query string of every filter except `page`, ending in `&` when non-empty.
fn qs_without_page(pairs: &[(&str, Option<String>)]) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if let Some(v) = v.as_deref().filter(|s| !s.is_empty()) {
            out.push_str(&format!("{k}={}&", urlencoding(v)));
        }
    }
    out
}
fn urlencoding(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

async fn ips(MaybeUser(authed): MaybeUser, State(state): State<Arc<AdminState>>, Query(f): Query<IpFilter>) -> AppResult<Html<String>> {
    let page = state.store.list_ips(&f).await?;
    let qs = qs_without_page(&[
        ("q", f.q.clone()), ("country", f.country.clone()), ("asn", f.asn.map(|a| a.to_string())), ("label", f.label.clone()),
        ("min_severity", f.min_severity.map(|a| a.to_string())), ("tor", f.tor.clone()), ("sort", f.sort.clone()),
    ]);
    render(&IpsPage { chrome: Chrome::new(authed, "ips"), f, page, qs })
}

#[derive(Template)]
#[template(path = "requests.html")]
struct RequestsPage { chrome: Chrome, f: RequestFilter, page: Page<RequestListRow>, qs: String }

async fn requests(MaybeUser(authed): MaybeUser, State(state): State<Arc<AdminState>>, Query(f): Query<RequestFilter>) -> AppResult<Html<String>> {
    let page = state.store.search_requests(&f).await?;
    let qs = qs_without_page(&[
        ("ip", f.ip.clone()), ("path", f.path.clone()), ("label", f.label.clone()), ("severity", f.severity.map(|a| a.to_string())),
        ("min_severity", f.min_severity.map(|a| a.to_string())), ("country", f.country.clone()), ("asn", f.asn.map(|a| a.to_string())),
        ("from", f.from.clone()), ("to", f.to.clone()),
    ]);
    render(&RequestsPage { chrome: Chrome::new(authed, "requests"), f, page, qs })
}

pub struct ScanWithPorts { pub s: ScanSummary, pub ports: Vec<PortRow> }

/// Admin-only sections of the IP page. Loaded only with a session.
pub struct IpAdminData {
    pub scans: Vec<ScanWithPorts>,
    pub fingerprints: Vec<FpSummary>,
    pub claims: Vec<FpClaimRow>,
}

#[derive(Template)]
#[template(path = "ip.html")]
struct IpPage { chrome: Chrome, ov: IpOverview, sparkline_json: String, page: Page<RequestListRow>, admin: Option<IpAdminData> }

#[derive(serde::Deserialize, Default)]
pub struct PageQuery { #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")] pub page: Option<i64> }

async fn ip_page(MaybeUser(authed): MaybeUser, State(state): State<Arc<AdminState>>, Path(addr): Path<String>, Query(q): Query<PageQuery>) -> AppResult<Html<String>> {
    let Some(ip) = state.store.ip_by_addr(&addr).await? else { return Err(AppError::NotFound) };
    let Some(ov) = state.store.ip_overview(ip.id).await? else { return Err(AppError::NotFound) };
    let page = state.store.requests_for_ip(ip.id, page_num(q.page)).await?;
    let admin = if authed {
        let mut scans = vec![];
        for s in state.store.scans_for_ip(ip.id).await? {
            let ports = state.store.ports_for_scan(s.id).await?;
            scans.push(ScanWithPorts { s, ports });
        }
        Some(IpAdminData { scans, fingerprints: state.store.fingerprints_for_ip(ip.id).await?, claims: state.store.claims_for_ip(ip.id).await? })
    } else {
        None
    };
    let sparkline_json = serde_json::to_string(&ov.sparkline).unwrap_or_else(|_| "[]".into());
    render(&IpPage { chrome: Chrome::new(authed, "ips"), ov, sparkline_json, page, admin })
}
```

`data-sparkline="{{ sparkline_json }}"` is HTML-escaped by askama (`"` → `&quot;`), which the browser decodes before `JSON.parse`. The test asserts `data-sparkline="[` — a JSON array of integers has no quotes, so that holds.

Remove `/requests`, `/requests/{id}`, `/ips/{id}` from `detail::routes()` (the request detail moves to `/admin/requests/{id}` in Task 10; keep the handler function for now, unrouted, or move it in Task 10 — either way the old test `detail_views_and_inbox_work_with_session` is rewritten in Task 10; until then mark it `#[ignore]` with a comment naming Task 10).

- [ ] **Step 5: Run, expect pass; browser check; commit**

Run: `cargo test`
Open `/ips`, `/ip/<addr>`, `/requests` in both themes; check the phone width.

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src templates assets tests
git commit -m "feat(public): IP directory with CIDR search, per-IP page, request search

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 10: Admin area — home, queue, detail pages, deletes, keys, export, login/enroll

**Files:**
- Create: `src/admin/pages.rs`, `templates/admin_home.html`, `_queue_row.html`, `admin_queue.html`, `request.html`, `admin_scans.html`, `admin_scan.html`, `admin_fingerprints.html`, `admin_inbox.html`, `admin_export.html`, `admin_keys.html`, `login.html` (rewritten), `enroll.html` (rewritten)
- Modify: `src/admin/mod.rs`, `src/admin/auth.rs`, `assets/js/app.js`
- Delete: `src/admin/detail.rs`, `templates/inbox.html`, `templates/keys.html`, `templates/export.html`, `templates/request_detail.html`, `templates/ip_detail.html`
- Test: `tests/integration.rs`

**Interfaces:**
- Consumes: everything from Tasks 3–7; `SessionUser`, `MaybeUser`.
- Produces: `crate::admin::pages::routes() -> Router<Arc<AdminState>>` mounting every `/admin/*` route from spec §4. `auth::enroll_start` accepts either `setup_token` **or** a valid session. Session cookie has `Secure` when `cfg.webauthn.origin` starts with `https://`. Login success redirects to `/admin`; enroll success redirects to `/admin/keys`.

- [ ] **Step 1: Rewrite the auth integration tests**

Replace `authenticated_routes_redirect_without_session` and `detail_views_and_inbox_work_with_session`; keep `webauthn_ceremony_with_soft_token` and `export_download_requires_auth_and_filters` but change `/export/download` to `/admin/export/download` in the latter.

```rust
#[tokio::test]
async fn admin_routes_redirect_without_session() {
    let (_trap_base, store, dir) = spawn_trap().await;
    let base = spawn_admin_with(store, dir.path()).await;
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    for path in ["/admin", "/admin/queue", "/admin/requests/1", "/admin/scans", "/admin/scans/1", "/admin/scans/1/xml",
                 "/admin/fingerprints", "/admin/inbox", "/admin/export", "/admin/export/download?format=csv", "/admin/keys"] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path}");
        assert_eq!(resp.headers().get("location").unwrap(), "/login", "{path}");
    }
    for path in ["/admin/requests/1/delete", "/admin/ips/203.0.113.1/delete", "/admin/scans/1/delete", "/admin/claims/1/delete", "/admin/keys/delete"] {
        let resp = client.post(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(resp.status(), 303, "{path}");
    }
}

#[tokio::test]
async fn admin_pages_and_deletes_with_session() {
    let (trap_base, store, dir) = spawn_trap().await;
    let c = reqwest::Client::new();
    let _ = c.get(format!("{trap_base}/hello")).header("x-forwarded-for", "203.0.113.77").header("x-marker", "HEADER-MARKER").send().await.unwrap();
    let _ = c.post(format!("{trap_base}/claim")).header("x-forwarded-for", "203.0.113.77").form(&[("email", "lost@example.org")]).send().await.unwrap();
    let _ = c.post(format!("{trap_base}/login")).header("x-forwarded-for", "203.0.113.78").form(&[("username", "BODY-MARKER"), ("password", "x")]).send().await.unwrap();
    let ip77 = store.ip_by_addr("203.0.113.77").await.unwrap().unwrap();
    let ip78 = store.ip_by_addr("203.0.113.78").await.unwrap().unwrap();
    store.insert_fingerprint(None, ip77.id, "CLUSTERHASH", None, "{}", "{}", b"[]").await.unwrap();
    store.insert_fingerprint(None, ip78.id, "CLUSTERHASH", None, "{}", "{}", b"[]").await.unwrap();
    let job = match store.enqueue_scan(ip78.id, 2, 24).await.unwrap() { peephole::store::scans::EnqueueOutcome::Queued(j) => j, o => panic!("{o:?}") };
    store.next_queued_job().await.unwrap();
    store.finish_job(job, Some(&peephole::scan::nmap_xml::ScanResult { os_guess: Some("Linux".into()), raw_xml: b"<nmaprun>RAWXML</nmaprun>".to_vec(),
        ports: vec![peephole::scan::nmap_xml::PortResult { port: 22, proto: "tcp".into(), state: "open".into(), service: Some("ssh".into()), product: None, version: None }] }), None).await.unwrap();

    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;

    let html = client.get(format!("{base}/admin")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("Scan queue") && html.contains("data-queue") && html.contains("/admin/api/queue"));
    assert!(html.contains("1 unread") || html.contains("Inbox"));
    let html = client.get(format!("{base}/admin/queue")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.78") && html.contains("done"));

    let rid: i64 = sqlx::query_scalar("SELECT id FROM requests WHERE path = '/login'").fetch_one(&store.pool).await.unwrap();
    let html = client.get(format!("{base}/admin/requests/{rid}")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("BODY-MARKER") && html.contains("x-forwarded-for") && html.contains("bait"));

    let html = client.get(format!("{base}/admin/scans")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("203.0.113.78"));
    let sid: i64 = sqlx::query_scalar("SELECT id FROM scans").fetch_one(&store.pool).await.unwrap();
    let html = client.get(format!("{base}/admin/scans/{sid}")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("22/tcp") && html.contains("ssh"));
    let xml = client.get(format!("{base}/admin/scans/{sid}/xml")).send().await.unwrap();
    assert_eq!(xml.headers().get("content-type").unwrap(), "application/xml");
    assert!(xml.text().await.unwrap().contains("RAWXML"));

    let html = client.get(format!("{base}/admin/fingerprints")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("CLUSTERHASH") && html.contains("203.0.113.77") && html.contains("203.0.113.78"));
    let html = client.get(format!("{base}/admin/inbox")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("lost@example.org"));
    let html = client.get(format!("{base}/admin/keys")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("test-key") && html.contains("/enroll"));
    let html = client.get(format!("{base}/admin/export")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("/admin/export/download"));

    // Deletes.
    let resp = client.post(format!("{base}/admin/scans/{sid}/delete")).send().await.unwrap();
    assert_eq!(resp.status(), 200); // followed redirect
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans").fetch_one(&store.pool).await.unwrap();
    assert_eq!(n, 0);
    let cid: i64 = sqlx::query_scalar("SELECT id FROM fp_claims").fetch_one(&store.pool).await.unwrap();
    client.post(format!("{base}/admin/claims/{cid}/delete")).send().await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fp_claims").fetch_one(&store.pool).await.unwrap();
    assert_eq!(n, 0);
    client.post(format!("{base}/admin/requests/{rid}/delete")).send().await.unwrap();
    assert!(store.request_by_id(rid).await.unwrap().is_none());
    let resp = client.post(format!("{base}/admin/ips/203.0.113.77/delete")).send().await.unwrap();
    assert_eq!(resp.url().path(), "/ips", "redirects to the directory");
    assert!(store.ip_by_addr("203.0.113.77").await.unwrap().is_none());
    assert!(store.ip_by_addr("203.0.113.78").await.unwrap().is_some());
    assert_eq!(client.post(format!("{base}/admin/ips/nope/delete")).send().await.unwrap().status(), 404);
}

#[tokio::test]
async fn enroll_additional_key_with_session() {
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_authenticator_rs::prelude::Url;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let (_trap_base, store, dir) = spawn_trap().await;
    let cfg = Config::load(&dir.path().join("c.toml")).unwrap();
    let (client, base) = enrolled_admin_client(store.clone(), cfg).await;
    // No setup token: the session alone authorises enrollment.
    let resp = client.post(format!("{base}/enroll/start")).json(&serde_json::json!({"label": "second"})).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let cco: serde_json::Value = resp.json().await.unwrap();
    let options: webauthn_rs_proto::PublicKeyCredentialCreationOptions = serde_json::from_value(cco["publicKey"].clone()).unwrap();
    let mut soft = SoftPasskey::new(true);
    let cred = soft.perform_register(Url::parse("https://localhost").unwrap(), options, 60_000).unwrap();
    let resp = client.post(format!("{base}/enroll/finish")).json(&serde_json::json!({"credential": cred})).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(store.load_credentials().await.unwrap().len(), 2);
    // Anonymous without token → 403.
    let anon = reqwest::Client::new();
    let resp = anon.post(format!("{base}/enroll/start")).json(&serde_json::json!({"label": "x"})).send().await.unwrap();
    assert_eq!(resp.status(), 403);
}
```

- [ ] **Step 2: Run, expect failures**

Run: `cargo test --test integration admin_ enroll_additional`

- [ ] **Step 3: Auth changes in `src/admin/auth.rs`**

- `EnrollStart.setup_token` becomes `Option<String>`. In `enroll_start`, authorise when either the token matches **or** the session cookie validates:
```rust
    let by_session = match jar.get("peephole_session") {
        Some(c) => state.store.validate_session(c.value()).await.unwrap_or(false),
        None => false,
    };
    let by_token = match (&body.setup_token, state.store.intel_get("webauthn_setup_token_hash").await) {
        (Some(t), Ok(Some(stored))) => stored == data_encoding::HEXLOWER.encode(&Sha256::digest(t.as_bytes())),
        _ => false,
    };
    if !by_session && !by_token {
        return (StatusCode::FORBIDDEN, "invalid setup token").into_response();
    }
```
- Store the label: `enroll_finish` currently ignores `label`; put it in the `wa_reg` flow by adding a second cookie `wa_label` (or store `label` inside a small JSON wrapper next to the registration state) and pass it to `save_credential`. Check `save_credential`'s signature in `src/store/auth.rs`; it already takes a label parameter if the keys page can show `test-key` (the existing test asserts `test-key || credential`, so it may not). If it does not, add `label: Option<&str>` to `save_credential` and write it to `credentials.label`.
- Session cookie builder helper:
```rust
fn session_cookie(cfg: &crate::config::Config, id: String) -> axum_extra::extract::cookie::Cookie<'static> {
    axum_extra::extract::cookie::Cookie::build(("peephole_session", id))
        .path("/")
        .http_only(true)
        .secure(cfg.webauthn.origin.starts_with("https://"))
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .build()
}
```
Use it in both `enroll_finish` and `login_finish`. Note: tests run over `http://127.0.0.1` with origin `https://localhost` → `Secure` is set → reqwest's cookie store **drops** Secure cookies on plain http. Fix in tests: `spawn_trap`'s config keeps `origin = "https://localhost"` (required by validation), so instead make the flag configurable for tests: add `#[serde(default = "default_true")] pub secure_cookies: bool` to `WebauthnConfig`, default `true`, and set `secure_cookies = false` in the test configs. Document the key in `deploy/config.example.toml` ("leave true; only for tests").
- `login_page`/`enroll_page` render askama templates (below) via `render`, with `Chrome::new(false, "")`.
- `logout` redirects to `/`.

- [ ] **Step 4: Login and enroll templates, JS into app.js**

`templates/login.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — admin login{% endblock %}
{% block content %}
<div class="card auth-card" data-webauthn="login">
  <img src="/assets/logo.svg?v={{ chrome.stamp }}" alt="">
  <h1>Admin login</h1>
  <p class="muted">FIDO2 security key required. There is no password.</p>
  <button class="btn btn-primary btn-block" type="button" data-go>Authenticate with security key</button>
  <div class="status" data-msg></div>
</div>
{% endblock %}
```

`templates/enroll.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — enroll security key{% endblock %}
{% block content %}
<div class="card auth-card" data-webauthn="enroll">
  <img src="/assets/logo.svg?v={{ chrome.stamp }}" alt="">
  <h1>Enroll security key</h1>
  {% if chrome.authed %}
  <p class="muted">You are logged in; the new key is added to your account.</p>
  {% else %}
  <p class="muted">Enter the one-time setup token printed to the service log on first start.</p>
  <label class="label">Setup token <input type="text" data-token autocomplete="off"></label>
  {% endif %}
  <label class="label">Key label (optional) <input type="text" data-label placeholder="yubikey-5"></label>
  <button class="btn btn-primary btn-block" type="button" data-go>Register security key</button>
  <div class="status" data-msg></div>
</div>
{% endblock %}
```
The enroll page handler uses `MaybeUser` so `chrome.authed` is accurate.

Append to `assets/js/app.js` inside the IIFE:
```js
  // WebAuthn ceremonies (moved out of inline scripts for CSP).
  function b64uToBuf(s) { return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }).buffer; }
  function bufToB64u(b) { return btoa(String.fromCharCode.apply(null, new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  var wa = document.querySelector("[data-webauthn]");
  if (wa) {
    var mode = wa.getAttribute("data-webauthn"), msg = wa.querySelector("[data-msg]");
    wa.querySelector("[data-go]").addEventListener("click", async function () {
      msg.textContent = "";
      try {
        if (mode === "login") {
          var start = await fetch("/login/start", { method: "POST" });
          if (!start.ok) throw new Error("login start failed: " + start.status);
          var opts = (await start.json()).publicKey;
          opts.challenge = b64uToBuf(opts.challenge);
          if (opts.allowCredentials) opts.allowCredentials = opts.allowCredentials.map(function (c) { c.id = b64uToBuf(c.id); return c; });
          var cred = await navigator.credentials.get({ publicKey: opts });
          var body = { credential: { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: {
            authenticatorData: bufToB64u(cred.response.authenticatorData), clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            signature: bufToB64u(cred.response.signature), userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null } } };
          var fin = await fetch("/login/finish", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
          if (fin.ok) location.href = "/admin"; else msg.textContent = "authentication failed (" + fin.status + ")";
        } else {
          var tokenEl = wa.querySelector("[data-token]"), labelEl = wa.querySelector("[data-label]");
          var payload = { label: (labelEl && labelEl.value.trim()) || null };
          if (tokenEl) payload.setup_token = tokenEl.value.trim();
          var start2 = await fetch("/enroll/start", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
          if (!start2.ok) throw new Error("enroll start failed: " + start2.status);
          var copts = (await start2.json()).publicKey;
          copts.challenge = b64uToBuf(copts.challenge);
          copts.user.id = b64uToBuf(copts.user.id);
          if (copts.excludeCredentials) copts.excludeCredentials = copts.excludeCredentials.map(function (c) { c.id = b64uToBuf(c.id); return c; });
          var ccred = await navigator.credentials.create({ publicKey: copts });
          var cbody = { credential: { id: ccred.id, rawId: bufToB64u(ccred.rawId), type: ccred.type, response: {
            attestationObject: bufToB64u(ccred.response.attestationObject), clientDataJSON: bufToB64u(ccred.response.clientDataJSON) },
            extensions: ccred.getClientExtensionResults ? ccred.getClientExtensionResults() : {} } };
          var fin2 = await fetch("/enroll/finish", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(cbody) });
          if (fin2.ok) location.href = "/admin/keys"; else msg.textContent = "enrollment failed (" + fin2.status + ")";
        }
      } catch (e) { msg.textContent = e.message || String(e); }
    });
  }
```
Compare against the existing inline scripts in the old `templates/login.html` and `templates/enroll.html` for the exact credential JSON shape before deleting them; the `webauthn_ceremony_with_soft_token` test only exercises the server side, so a browser check of a real key (or Chrome's virtual authenticator in DevTools → WebAuthn) is the verification here.

- [ ] **Step 5: Admin templates**

`templates/admin_home.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — admin{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Admin</h1><p class="muted">Operational view. Everything on this page is private.</p></div>
  <nav class="seg"><a href="/admin/queue">Queue</a><a href="/admin/scans">Scans</a><a href="/admin/fingerprints">Fingerprints</a><a href="/admin/inbox">Inbox</a><a href="/admin/export">Export</a><a href="/admin/keys">Keys</a></nav>
</div>
{% if stale %}<div class="banner banner-warning">Intel data (Tor exit list / GeoIP) is missing or older than 48 hours.</div>{% endif %}
<div class="tiles">
  <div class="tile"><span class="label">Queued</span><div class="value">{{ q.queued }}</div></div>
  <div class="tile"><span class="label">Running</span><div class="value">{{ q.running }}</div><div class="hint">{{ workers }} workers</div></div>
  <div class="tile"><span class="label">Done · 24h</span><div class="value">{{ q.done_24h }}</div></div>
  <div class="tile"><span class="label">Failed · 24h</span><div class="value{% if q.failed_24h > 0 %} brand{% endif %}">{{ q.failed_24h }}</div></div>
  <div class="tile"><span class="label">Scans this hour</span><div class="value">{{ q.scans_last_hour }}<span class="muted"> / {{ cap }}</span></div></div>
  <div class="tile"><span class="label">Inbox</span><div class="value">{{ inbox }}</div><div class="hint"><a href="/admin/inbox">{{ inbox }} unread claims</a></div></div>
</div>
<div class="stack">
  <section class="card">
    <div class="card-head"><h2>Scan queue</h2><span class="live" data-live><span class="live-dot"></span><span data-live-label>connecting…</span></span></div>
    <div class="table-wrap"><table data-queue data-src="/admin/api/queue" data-limit="25">
      <thead><tr><th>Job</th><th>Target</th><th>Level</th><th>Status</th><th>Queued</th><th>Finished</th><th>Error</th></tr></thead>
      <tbody>{% for j in jobs %}{% include "_queue_row.html" %}{% endfor %}
      {% if jobs.is_empty() %}<tr data-empty><td colspan="7" class="empty">Queue empty.</td></tr>{% endif %}</tbody>
    </table></div>
  </section>
  <section class="card">
    <div class="card-head"><h2>Recent failures</h2></div>
    {% if failed.is_empty() %}<p class="muted">None.</p>{% else %}
    <div class="table-wrap"><table><thead><tr><th>Job</th><th>Target</th><th>Level</th><th>Finished</th><th>Error</th></tr></thead><tbody>
      {% for j in failed %}<tr><td class="mono">#{{ j.id }}</td><td class="ip"><a href="/ip/{{ j.ip }}">{{ j.ip }}</a></td><td>{{ j.level }}</td><td class="ts">{{ j.finished_at.as_deref().unwrap_or("") }}</td><td class="mono">{{ j.error.as_deref().unwrap_or("") }}</td></tr>{% endfor %}
    </tbody></table></div>{% endif %}
  </section>
  <section class="card">
    <div class="card-head"><h2>Intel</h2></div>
    <dl class="kv">
      <dt>Tor exit list</dt><dd>{{ tor_fetch }}</dd>
      <dt>MaxMind GeoLite2</dt><dd>{{ maxmind_fetch }}</dd>
    </dl>
  </section>
</div>
{% endblock %}
```

`templates/_queue_row.html` (expects `j: QueueJob`):
```html
<tr data-job="{{ j.id }}">
  <td class="mono">#{{ j.id }}</td>
  <td class="ip"><a href="/ip/{{ j.ip }}">{{ j.ip }}</a></td>
  <td>{{ j.level }}</td>
  <td><span class="badge badge-status" data-status="{{ j.status }}">{{ j.status }}</span></td>
  <td class="ts">{{ j.queued_at }}</td>
  <td class="ts">{{ j.finished_at.as_deref().unwrap_or("") }}</td>
  <td class="mono">{{ j.error.as_deref().unwrap_or("") }}</td>
</tr>
```

`templates/request.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — request #{{ d.row.id }}{% endblock %}
{% block content %}
<div class="page-head"><div>
  <h1><span class="mono">{{ d.row.method }}</span> <span class="mono">{{ d.row.path }}</span></h1>
  <div class="meta"><span class="mono">{{ d.row.ts }}</span><span>from <a class="mono" href="/ip/{{ d.ip }}">{{ d.ip }}</a></span>
    <span>severity {% let sev = d.row.severity %}{% include "_severity.html" %}</span><span>scan level {{ d.row.scan_level }}</span>{% if d.row.is_fp_claim %}<span class="badge badge-label">fp claim</span>{% endif %}</div>
</div>
<button class="btn btn-danger" type="button" data-confirm="dlg-del">Delete request</button>
<dialog id="dlg-del"><h3>Delete request #{{ d.row.id }}?</h3><form method="post" action="/admin/requests/{{ d.row.id }}/delete" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Delete</button></form></dialog>
</div>
<div class="stack">
  <section class="card"><h2>Labels</h2><div class="chips">{% for l in labels %}<span class="badge badge-label">{{ l }}</span>{% endfor %}{% if labels.is_empty() %}<span class="muted">none</span>{% endif %}</div></section>
  {% if let Some(q) = d.row.query %}<section class="card"><h2>Query string</h2><pre class="panel">{{ q }}</pre></section>{% endif %}
  <section class="card"><h2>Headers <span class="muted">in received order</span></h2>
    <dl class="kv">{% for (k, v) in d.headers %}<dt>{{ k }}</dt><dd>{{ v }}</dd>{% endfor %}</dl></section>
  <section class="card"><div class="card-head"><h2>Body <span class="muted">{{ d.body_len }} bytes{% if d.body_truncated %}, showing first 16 KiB{% endif %}</span></h2>
    <button class="btn btn-sm" type="button" data-hex-toggle="body">hex</button></div>
    <pre class="panel" id="body" data-text="{{ d.body_text }}">{% if d.body_text.is_empty() %}<span class="muted">(empty)</span>{% else %}{{ d.body_text }}{% endif %}</pre></section>
  {% if let Some(fp) = d.fingerprint %}<section class="card"><h2>Fingerprint</h2><p><a class="mono" href="/admin/fingerprints#{{ fp.hash }}">{{ fp.hash }}</a> — seen from <b>{{ fp.other_ips }}</b> other IPs</p></section>{% endif %}
</div>
{% endblock %}
```
Hex toggle in `app.js`:
```js
  document.querySelectorAll("[data-hex-toggle]").forEach(function (b) {
    var pre = document.getElementById(b.getAttribute("data-hex-toggle")), text = pre.getAttribute("data-text"), hex = null, on = false;
    b.addEventListener("click", function () {
      on = !on;
      if (on && hex === null) {
        var bytes = new TextEncoder().encode(text), lines = [];
        for (var i = 0; i < bytes.length; i += 16) {
          var chunk = Array.prototype.slice.call(bytes, i, i + 16);
          lines.push(i.toString(16).padStart(8, "0") + "  " + chunk.map(function (x) { return x.toString(16).padStart(2, "0"); }).join(" ").padEnd(48) + "  " +
            chunk.map(function (x) { return x >= 32 && x < 127 ? String.fromCharCode(x) : "."; }).join(""));
        }
        hex = lines.join("\n");
      }
      pre.textContent = on ? hex : text; b.textContent = on ? "text" : "hex";
    });
  });
```

`templates/admin_scans.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — scans{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Counter-scans</h1><p class="muted">Completed nmap runs, newest first.</p></div></div>
<div class="table-wrap"><table>
  <thead><tr><th>Scan</th><th>Target</th><th>Level</th><th>Finished</th><th>OS guess</th><th class="num">Open ports</th></tr></thead>
  <tbody>
  {% for s in page.items %}
    <tr><td class="mono"><a href="/admin/scans/{{ s.id }}">#{{ s.id }}</a></td><td class="ip"><a href="/ip/{{ s.ip }}">{{ s.ip }}</a></td><td>{{ s.level }}</td>
        <td class="ts">{{ s.finished_at.as_deref().unwrap_or("") }}</td><td>{{ s.os_guess.as_deref().unwrap_or("—") }}</td><td class="num">{{ s.open_ports }}</td></tr>
  {% endfor %}
  {% if page.items.is_empty() %}<tr><td colspan="6" class="empty">No scans yet.</td></tr>{% endif %}
  </tbody>
</table></div>
{% include "_pagination.html" %}
{% endblock %}
```

`templates/admin_scan.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — scan #{{ s.id }}{% endblock %}
{% block content %}
<div class="page-head"><div>
  <h1>Scan #{{ s.id }} · <a class="mono" href="/ip/{{ s.ip }}">{{ s.ip }}</a></h1>
  <div class="meta"><span>level {{ s.level }}</span><span>started <span class="mono">{{ s.started_at }}</span></span>
    <span>finished <span class="mono">{{ s.finished_at.as_deref().unwrap_or("—") }}</span></span><span>OS: {{ s.os_guess.as_deref().unwrap_or("unknown") }}</span></div>
</div>
<div class="row">
  <a class="btn" href="/admin/scans/{{ s.id }}/xml">Download raw XML</a>
  <button class="btn btn-danger" type="button" data-confirm="dlg-del">Delete scan</button>
  <dialog id="dlg-del"><h3>Delete scan #{{ s.id }}?</h3><p class="muted">Ports recorded by this scan are removed too.</p>
    <form method="post" action="/admin/scans/{{ s.id }}/delete" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Delete</button></form></dialog>
</div></div>
<section class="card"><h2>Ports</h2>{% include "_ports.html" %}</section>
{% endblock %}
```
(`.row { display:flex; gap:.5rem; }` — add to `30-components.css`.)

`templates/admin_fingerprints.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — fingerprints{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Fingerprint clusters</h1><p class="muted">Browser fingerprints seen from more than one source IP — the same operator hopping addresses.</p></div></div>
<div class="stack">
{% for c in clusters %}
  <section class="card" id="{{ c.hash }}">
    <div class="card-head"><h2 class="mono">{{ c.hash }}</h2><span class="muted">{{ c.count }} sightings · {{ c.ips.len() }} IPs</span></div>
    <div class="chips">{% for ip in c.ips %}<a class="badge badge-label" href="/ip/{{ ip }}">{{ ip }}</a>{% endfor %}</div>
  </section>
{% endfor %}
{% if clusters.is_empty() %}<div class="card empty">No fingerprint has been seen from more than one IP yet.</div>{% endif %}
</div>
{% endblock %}
```

`templates/admin_inbox.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — inbox{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Inbox</h1><p class="muted">"I landed here by accident" claims. The counter-scan still ran.</p></div></div>
<div class="table-wrap"><table>
  <thead><tr><th>Time (UTC)</th><th>IP</th><th>Contact</th><th>User agent</th><th></th></tr></thead>
  <tbody>
  {% for c in claims %}
    <tr><td class="ts">{{ c.ts }}</td><td class="ip"><a href="/ip/{{ c.ip }}">{{ c.ip }}</a></td>
        <td>{% if let Some(e) = c.contact_email %}<a href="mailto:{{ e }}">{{ e }}</a>{% else %}<span class="muted">none</span>{% endif %}</td>
        <td class="muted">{{ c.user_agent }}</td>
        <td><button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-claim-{{ c.id }}">Delete</button>
          <dialog id="dlg-claim-{{ c.id }}"><h3>Delete this claim?</h3>
            <form method="post" action="/admin/claims/{{ c.id }}/delete" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Delete</button></form></dialog></td></tr>
  {% endfor %}
  {% if claims.is_empty() %}<tr><td colspan="5" class="empty">Nobody has claimed an accident.</td></tr>{% endif %}
  </tbody>
</table></div>
{% endblock %}
```

`templates/admin_export.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — export{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Export requests</h1><p class="muted">CSV, Timesketch JSONL or Parquet. Filters are optional; up to 100 000 rows.</p></div></div>
<form class="filters card" method="get" action="/admin/export/download">
  <label>Format <select name="format"><option value="csv">CSV</option><option value="jsonl">Timesketch JSONL</option><option value="parquet">Parquet</option></select></label>
  <label>From (UTC) <input name="from" type="datetime-local"></label>
  <label>To (UTC) <input name="to" type="datetime-local"></label>
  <label>IP <input name="ip"></label>
  <label>Label <input name="label"></label>
  <label>Min severity <input name="min_severity" type="number" min="0" max="4"></label>
  <button class="btn btn-primary" type="submit">Download</button>
</form>
{% endblock %}
```

`templates/admin_keys.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — security keys{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Security keys</h1><p class="muted">FIDO2 credentials that can log in. Keep at least two.</p></div>
  <a class="btn btn-primary" href="/enroll">Enroll another key</a></div>
<div class="table-wrap"><table>
  <thead><tr><th>Credential</th><th>Label</th><th>Created</th><th></th></tr></thead>
  <tbody>
  {% for (cred, label, created) in keys %}
    <tr><td class="mono">{{ cred.chars().take(16).collect::<String>() }}…</td><td>{{ label }}</td><td class="ts">{{ created }}</td>
        <td>{% if can_delete %}
          <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-key-{{ loop.index }}">Remove</button>
          <dialog id="dlg-key-{{ loop.index }}"><h3>Remove key "{{ label }}"?</h3><p class="muted">It will no longer be able to log in.</p>
            <form method="post" action="/admin/keys/delete" class="actions"><input type="hidden" name="cred_id" value="{{ cred }}">
              <button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Remove</button></form></dialog>
        {% else %}<span class="muted" title="the last key cannot be removed">last key</span>{% endif %}</td></tr>
  {% endfor %}
  </tbody>
</table></div>
{% endblock %}
```
If askama rejects the turbofish in `collect::<String>()`, precompute a `short: String` per key in the handler (`Vec<(String, String, String, String)>`: short id, full id, label, created).

`templates/admin_queue.html`:
```html
{% extends "layout.html" %}
{% block title %}peephole — scan queue{% endblock %}
{% block content %}
<div class="page-head"><div><h1>Scan queue</h1><p class="muted">Every job, live. Filters apply to the initial snapshot; live rows are appended unfiltered.</p></div>
  <span class="live" data-live><span class="live-dot"></span><span data-live-label>connecting…</span></span></div>
<form class="filters" method="get" action="/admin/queue">
  <label>Status <select name="status"><option value="">any</option>
    {% for st in ["queued", "running", "done", "failed"] %}<option value="{{ st }}"{% if f.status.as_deref() == Some(st) %} selected{% endif %}>{{ st }}</option>{% endfor %}</select></label>
  <label>Level <input name="level" size="3" value="{{ f.level.as_deref().unwrap_or_default() }}"></label>
  <button class="btn btn-primary" type="submit">Filter</button>
</form>
<div class="table-wrap"><table data-queue data-src="/admin/api/queue" data-limit="500">
  <thead><tr><th>Job</th><th>Target</th><th>Level</th><th>Status</th><th>Queued</th><th>Finished</th><th>Error</th></tr></thead>
  <tbody>{% for j in jobs %}{% include "_queue_row.html" %}{% endfor %}
  {% if jobs.is_empty() %}<tr data-empty><td colspan="7" class="empty">Queue empty.</td></tr>{% endif %}</tbody>
</table></div>
{% endblock %}
```
If askama rejects the array literal in `{% for st in [...] %}`, pass `statuses: [&'static str; 4]` from the handler.

Every list/detail template extends `layout.html`, passes `Chrome::new(true, "admin")`, and uses no inline `style=` or `<script>`.

- [ ] **Step 6: `src/admin/pages.rs`**

```rust
//! Authenticated admin pages. Every handler takes `SessionUser` first.
use crate::admin::auth::SessionUser;
use crate::admin::error::{AppError, AppResult, render};
use crate::admin::views::Chrome;
use crate::admin::AdminState;
use crate::events::QueueJob;
use crate::store::browse::{Page, page_num};
use crate::store::inspect::*;
use crate::store::stats::intel_stale;
use askama::Template;
use axum::{
    Router,
    extract::{Form, Path, Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route("/admin", get(home))
        .route("/admin/queue", get(queue))
        .route("/admin/requests/{id}", get(request_page))
        .route("/admin/requests/{id}/delete", post(request_delete))
        .route("/admin/ips/{addr}/delete", post(ip_delete))
        .route("/admin/scans", get(scans))
        .route("/admin/scans/{id}", get(scan_page))
        .route("/admin/scans/{id}/xml", get(scan_xml))
        .route("/admin/scans/{id}/delete", post(scan_delete))
        .route("/admin/fingerprints", get(fingerprints))
        .route("/admin/inbox", get(inbox))
        .route("/admin/claims/{id}/delete", post(claim_delete))
        .route("/admin/export", get(export_page))
        .route("/admin/export/download", get(export_download))
        .route("/admin/keys", get(keys))
        .route("/admin/keys/delete", post(key_delete))
}

fn chrome() -> Chrome { Chrome::new(true, "admin") }

#[derive(Template)]
#[template(path = "admin_home.html")]
struct HomePage { chrome: Chrome, q: QueueSummary, workers: usize, cap: i64, inbox: usize, jobs: Vec<QueueJob>, failed: Vec<QueueJob>, tor_fetch: String, maxmind_fetch: String, stale: bool }

async fn home(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let intel: HashMap<String, String> = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM intel_meta")
        .fetch_all(&st.store.pool).await?.into_iter().collect();
    let stale = intel_stale(&intel);
    let fetched = |k: &str| intel.get(k).cloned().unwrap_or_else(|| "never".into());
    render(&HomePage {
        chrome: chrome(), q: st.store.queue_summary().await?, workers: st.cfg.scan.max_workers, cap: st.cfg.scan.max_scans_per_hour,
        inbox: st.store.inbox().await?.len(), jobs: st.store.queue_snapshot(25).await?, failed: st.store.recent_failed_jobs(10).await?,
        tor_fetch: fetched("tor_last_fetch"), maxmind_fetch: fetched("maxmind_last_fetch"), stale,
    })
}

#[derive(serde::Deserialize, Default)]
pub struct QueueFilter { pub status: Option<String>, pub level: Option<String> }

#[derive(Template)]
#[template(path = "admin_queue.html")]
struct QueuePage { chrome: Chrome, jobs: Vec<QueueJob>, f: QueueFilter }

async fn queue(_u: SessionUser, State(st): State<Arc<AdminState>>, Query(f): Query<QueueFilter>) -> AppResult<Html<String>> {
    let mut jobs = st.store.queue_snapshot(500).await?;
    if let Some(s) = f.status.as_deref().filter(|s| !s.is_empty()) { jobs.retain(|j| j.status == s); }
    if let Some(l) = f.level.as_deref().and_then(|l| l.parse::<i64>().ok()) { jobs.retain(|j| j.level == l); }
    render(&QueuePage { chrome: chrome(), jobs, f })
}

#[derive(Template)]
#[template(path = "request.html")]
struct RequestPage { chrome: Chrome, d: RequestDetail, labels: Vec<String> }

async fn request_page(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Html<String>> {
    let Some(d) = st.store.request_detail(id).await? else { return Err(AppError::NotFound) };
    let labels = serde_json::from_str(&d.row.labels_json).unwrap_or_default();
    render(&RequestPage { chrome: chrome(), d, labels })
}

async fn request_delete(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Redirect> {
    if !st.store.delete_request(id).await? { return Err(AppError::NotFound) }
    Ok(Redirect::to("/requests"))
}

async fn ip_delete(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(addr): Path<String>) -> AppResult<Redirect> {
    let Some(ip) = st.store.ip_by_addr(&addr).await? else { return Err(AppError::NotFound) };
    st.store.delete_ip(ip.id).await?;
    Ok(Redirect::to("/ips"))
}

#[derive(Template)]
#[template(path = "admin_scans.html")]
struct ScansPage { chrome: Chrome, page: Page<ScanSummary>, qs: String }

#[derive(serde::Deserialize, Default)]
pub struct PageOnly { #[serde(default, deserialize_with = "crate::store::browse::lenient_i64")] pub page: Option<i64> }

async fn scans(_u: SessionUser, State(st): State<Arc<AdminState>>, Query(q): Query<PageOnly>) -> AppResult<Html<String>> {
    render(&ScansPage { chrome: chrome(), page: st.store.list_scans(page_num(q.page)).await?, qs: String::new() })
}

#[derive(Template)]
#[template(path = "admin_scan.html")]
struct ScanPage { chrome: Chrome, s: ScanSummary, ports: Vec<PortRow> }

async fn scan_page(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Html<String>> {
    let Some(s) = st.store.scan_by_id(id).await? else { return Err(AppError::NotFound) };
    let ports = st.store.ports_for_scan(id).await?;
    render(&ScanPage { chrome: chrome(), s, ports })
}

async fn scan_xml(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Response> {
    let Some(xml) = st.store.scan_raw_xml(id).await? else { return Err(AppError::NotFound) };
    Ok(([(header::CONTENT_TYPE, "application/xml".to_string()),
         (header::CONTENT_DISPOSITION, format!("attachment; filename=\"peephole-scan-{id}.xml\""))], xml).into_response())
}

async fn scan_delete(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Redirect> {
    if !st.store.delete_scan(id).await? { return Err(AppError::NotFound) }
    Ok(Redirect::to("/admin/scans"))
}

#[derive(Template)]
#[template(path = "admin_fingerprints.html")]
struct FingerprintsPage { chrome: Chrome, clusters: Vec<FpCluster> }

async fn fingerprints(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render(&FingerprintsPage { chrome: chrome(), clusters: st.store.fingerprint_clusters().await? })
}

#[derive(Template)]
#[template(path = "admin_inbox.html")]
struct InboxPage { chrome: Chrome, claims: Vec<FpClaimRow> }

async fn inbox(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render(&InboxPage { chrome: chrome(), claims: st.store.inbox().await? })
}

async fn claim_delete(_u: SessionUser, State(st): State<Arc<AdminState>>, Path(id): Path<i64>) -> AppResult<Redirect> {
    if !st.store.delete_claim(id).await? { return Err(AppError::NotFound) }
    Ok(Redirect::to("/admin/inbox"))
}

#[derive(Template)]
#[template(path = "admin_export.html")]
struct ExportPage { chrome: Chrome }

async fn export_page(_u: SessionUser) -> AppResult<Html<String>> {
    render(&ExportPage { chrome: chrome() })
}

async fn export_download(_u: SessionUser, State(state): State<Arc<AdminState>>, Query(q): Query<HashMap<String, String>>) -> Response {
    // Body unchanged from the previous detail.rs implementation.
    ...
}

#[derive(Template)]
#[template(path = "admin_keys.html")]
struct KeysPage { chrome: Chrome, keys: Vec<(String, String, String)>, can_delete: bool }

async fn keys(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    let keys = st.store.list_credential_labels().await?;
    render(&KeysPage { chrome: chrome(), can_delete: keys.len() > 1, keys })
}

#[derive(serde::Deserialize)]
pub struct KeyDeleteForm { cred_id: String }

async fn key_delete(_u: SessionUser, State(st): State<Arc<AdminState>>, Form(f): Form<KeyDeleteForm>) -> AppResult<Redirect> {
    // Body unchanged from the previous detail.rs implementation (never delete the last key).
    ...
}
```
For `export_download` and `key_delete`, move the bodies verbatim from `src/admin/detail.rs`, then delete that file. Replace `...` with those bodies — the plan shows `...` only because the code already exists in the repository at `src/admin/detail.rs:150-215` and `:119-142`.

In `src/admin/mod.rs`: `pub mod pages;`, remove `pub mod detail;`, `.merge(pages::routes())` in `full_router`, and remove `.merge(detail::routes())`. Delete the five old templates listed in the task header.

- [ ] **Step 7: Live queue client in `app.js`**

```js
  var qt = document.querySelector("[data-queue]");
  if (qt && window.EventSource) {
    var live = document.querySelector("[data-live]"), liveLabel = live && live.querySelector("[data-live-label]");
    var tbody = qt.querySelector("tbody"), limit = parseInt(qt.getAttribute("data-limit") || "25", 10);
    function setLive(state, label) { if (live) { live.setAttribute("data-state", state); if (liveLabel) liveLabel.textContent = label; } }
    function cell(cls, html) { var td = document.createElement("td"); if (cls) td.className = cls; td.innerHTML = html; return td; }
    function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
    function row(j) {
      var tr = document.createElement("tr"); tr.setAttribute("data-job", j.id);
      tr.appendChild(cell("mono", "#" + j.id));
      tr.appendChild(cell("ip", '<a href="/ip/' + esc(j.ip) + '">' + esc(j.ip) + "</a>"));
      tr.appendChild(cell("", esc(j.level)));
      tr.appendChild(cell("", '<span class="badge badge-status" data-status="' + esc(j.status) + '">' + esc(j.status) + "</span>"));
      tr.appendChild(cell("ts", esc(j.queued_at)));
      tr.appendChild(cell("ts", esc(j.finished_at)));
      tr.appendChild(cell("mono", esc(j.error)));
      return tr;
    }
    function apply(j) {
      var empty = tbody.querySelector("[data-empty]"); if (empty) empty.remove();
      var existing = tbody.querySelector('[data-job="' + j.id + '"]'), fresh = row(j);
      if (existing) tbody.replaceChild(fresh, existing); else tbody.insertBefore(fresh, tbody.firstChild);
      while (tbody.children.length > limit) tbody.removeChild(tbody.lastChild);
    }
    function snapshot(jobs) { tbody.innerHTML = ""; jobs.slice(0, limit).forEach(function (j) { tbody.appendChild(row(j)); }); if (!jobs.length) { var tr = document.createElement("tr"); tr.setAttribute("data-empty", ""); tr.appendChild(cell("empty", "Queue empty.")).setAttribute("colspan", "7"); tbody.appendChild(tr); } }
    var es = new EventSource(qt.getAttribute("data-src"));
    es.addEventListener("open", function () { setLive("open", "live"); });
    es.addEventListener("error", function () { setLive("reconnecting", "reconnecting…"); });
    es.addEventListener("snapshot", function (ev) { try { snapshot(JSON.parse(ev.data)); } catch (e) {} });
    es.addEventListener("job", function (ev) { try { apply(JSON.parse(ev.data)); } catch (e) {} });
  }
```

- [ ] **Step 8: Run all tests, expect pass**

Run: `cargo test`
Also un-ignore/remove the test marked `#[ignore]` in Task 9 (it is replaced by `admin_pages_and_deletes_with_session`).

- [ ] **Step 9: Browser check**

Log in with Chrome's virtual authenticator (DevTools → More tools → WebAuthn → enable, add a `ctap2`/`internal` authenticator with resident keys and user verification). Verify: enroll via token, login, `/admin` live dot turns green, a probe on the trap port appends a row without reload, delete dialogs work, theme toggle persists, and no CSP violations in the console.

- [ ] **Step 10: Commit**

```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src templates assets tests deploy/config.example.toml
git rm -q src/admin/detail.rs templates/inbox.html templates/keys.html templates/export.html templates/request_detail.html templates/ip_detail.html
git commit -m "feat(admin): admin area — live queue, detail pages, deletes, keys, export; CSP-clean login/enroll

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 11: Trap page redesign

**Files:**
- Modify: `templates/trap.html`, `src/trap/pages.rs` (`claim_confirmation` styled the same way)
- Test: `tests/integration.rs`

**Interfaces:**
- Consumes: nothing new. `trap_page(token)` signature unchanged; `__PAGE_TOKEN__` placeholder stays (the trap listener has no CSP and keeps its inline scripts).

- [ ] **Step 1: Failing test**

```rust
#[tokio::test]
async fn trap_page_is_a_realistic_notice_with_honest_footnote() {
    let (base, _store, _dir) = spawn_trap().await;
    let resp = reqwest::get(format!("{base}/anything")).await.unwrap();
    assert_eq!(resp.status(), 404);
    let html = resp.text().await.unwrap();
    assert!(html.contains("Staff sign-in"));
    assert!(html.contains("decoy for automated tools"));
    assert!(html.contains("I landed here by accident"));
    assert!(html.contains("prefers-color-scheme: dark"));
    assert!(html.contains("noindex"));
    assert!(html.contains("window.PEEPHOLE_TOKEN"));
    assert!(!html.contains("href=\"/login\"") && !html.contains("/admin"));
    assert!(!html.contains("@font-face"), "trap uses the system font stack");
    assert!(!html.contains("⚠"));
    let ok = reqwest::Client::new().post(format!("{base}/claim")).form(&[("email", "")]).send().await.unwrap().text().await.unwrap();
    assert!(ok.contains("Thank you") && ok.contains("prefers-color-scheme: dark"));
}
```

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --test integration trap_page_is_a_realistic_notice_with_honest_footnote`

- [ ] **Step 3: Rewrite `templates/trap.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Undefined route</title>
<style>
  :root {
    --bg: #f6f5f0; --surface: #ffffff; --fg: #1f2024; --muted: #66686f; --border: #d9d5c9;
    --accent: #1f6f8b; --accent-fg: #ffffff; --brand: #b30000; --field: #ffffff;
    --font: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    color-scheme: light;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #0a0b10; --surface: #171a24; --fg: #e4e6ee; --muted: #8a8ea6; --border: #22263a;
            --accent: #4fd1e0; --accent-fg: #0a0b10; --brand: #ff3b3b; --field: #10121a; color-scheme: dark; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font-family: var(--font); font-size: 15px; line-height: 1.55;
         padding: 3rem 1rem 4rem; }
  main { max-width: 40rem; margin: 0 auto; display: grid; gap: 1rem; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; }
  .head { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
  .mark { width: 28px; height: 28px; border-radius: 50%; background: radial-gradient(circle at 50% 50%, var(--brand) 0 28%, var(--surface) 30% 45%, var(--fg) 47% 100%); flex: none; }
  h1 { font-size: 1.2rem; margin: 0; letter-spacing: -0.01em; }
  h2 { font-size: 1rem; margin: 0 0 0.75rem; }
  p { margin: 0 0 0.5rem; }
  .muted { color: var(--muted); font-size: 0.85rem; }
  .fine { color: var(--muted); font-size: 0.75rem; margin: 0.75rem 0 0; }
  label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.6rem; }
  input { display: block; width: 100%; margin-top: 0.25rem; padding: 0.55rem 0.7rem; border: 1px solid var(--border); border-radius: 6px;
          background: var(--field); color: var(--fg); font: inherit; }
  input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); }
  .btn { display: inline-block; padding: 0.55rem 1rem; border-radius: 6px; border: 1px solid var(--accent); background: var(--accent); color: var(--accent-fg);
         font: inherit; font-weight: 500; cursor: pointer; }
  .btn:hover { filter: brightness(1.08); }
  .link { background: none; border: 0; padding: 0; color: var(--accent); font: inherit; cursor: pointer; text-decoration: underline; }
  .row { display: flex; gap: 0.5rem; align-items: center; }
  .mt { margin-top: 0.75rem; }
  #email-row { display: none; margin-top: 0.75rem; }
  #fingerprint-panel:empty { display: none; }
  #fingerprint-panel div { font-size: 0.85rem; }
  #fingerprint-panel span { color: var(--muted); }
  #fingerprint-panel i { font-style: normal; font-family: var(--mono); }
  .ref { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }
</style>
</head>
<body>
<main>
  <section class="card">
    <div class="head"><span class="mark" aria-hidden="true"></span><h1>Undefined route</h1></div>
    <p>This request was directed to a route which does not exist. Your IP address was classified as potentially malicious and will be scanned.</p>
    <p class="muted">Browser characteristics are recorded for security research.</p>
    <p class="ref">ref <span id="ref"></span></p>
    <div class="row mt">
      <button id="accident-btn" type="button" class="link">I landed here by accident</button>
    </div>
    <form id="email-row" method="post" action="/claim">
      <p class="muted">The administrator has been notified. If you want to be contacted for clarification, leave an email address (optional).</p>
      <label>Email <input type="email" name="email" placeholder="you@example.org"></label>
      <button type="submit" class="btn">Send</button>
    </form>
  </section>

  <section class="card">
    <h2>Staff sign-in</h2>
    <form method="post" action="/login" autocomplete="off">
      <label>Username <input type="text" name="username"></label>
      <label>Password <input type="password" name="password"></label>
      <button type="submit" class="btn">Sign in</button>
    </form>
    <p class="fine">This form is a decoy for automated tools. Real staff do not sign in here; submissions are recorded and flagged.</p>
  </section>

  <section class="card" id="fingerprint-panel"></section>

  <script>
    document.getElementById('accident-btn').addEventListener('click', function () {
      this.style.display = 'none';
      document.getElementById('email-row').style.display = 'block';
    });
    window.PEEPHOLE_TOKEN = "__PAGE_TOKEN__";
    document.getElementById('ref').textContent = window.PEEPHOLE_TOKEN.slice(0, 8);
  </script>
  <script src="/collect.js" defer></script>
</main>
</body>
</html>
```
The panel loader in `collector.js` sets `host.className = "card"` — keep that; the `#fingerprint-panel:empty` rule hides the card until content arrives.

`src/trap/pages.rs::claim_confirmation`: same `<style>` block (copy the `:root`, dark media query, `body`, `main`, `.card`, `h1`, `p`, `.muted` rules), body:
```html
<main><section class="card"><h1>Thank you.</h1>
<p>The administrator has been notified. If you left an email address it will only be used to clarify this incident.</p></section></main>
```

- [ ] **Step 4: Run tests, browser check, commit**

Run: `cargo test`
Open the trap port in both themes.
```bash
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add templates/trap.html src/trap/pages.rs tests
git commit -m "feat(trap): calm notice page with realistic decoy sign-in and honest footnote

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 12: `--version`, `check-config`, release workflow

**Files:**
- Modify: `src/main.rs`, `src/lib.rs`, `.github/workflows/release.yml`, `deploy/config.example.toml`
- Create: `deploy/nginx.example.conf`
- Test: `tests/cli.rs` (new integration test binary)

**Interfaces:**
- Produces: `peephole --version` → `peephole <PEEPHOLE_VERSION>`; `peephole check-config <path>` → exit 0 with `ok: config, rules (N), nmap <version line>`; exit 1 with the error otherwise. `peephole [<config>]` runs as before. `pub fn check_config(path: &Path) -> anyhow::Result<String>` in `lib.rs`. Release tarball contains `VERSION` and `deploy/nginx.example.conf`.

- [ ] **Step 1: Failing CLI tests**

`tests/cli.rs`:
```rust
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_peephole"))
}

#[test]
fn version_flag_prints_version() {
    let out = bin().arg("--version").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.starts_with("peephole "), "{s}");
    assert!(s.trim().len() > "peephole ".len());
}

#[test]
fn check_config_accepts_example_and_rejects_garbage() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.toml");
    std::fs::write(&good, format!(r#"
trap_listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"
database_path = "{d}/t.db"
data_dir = "{d}"
rules_dir = "rules"
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
[maxmind]
account_id = "1"
license_key = "k"
"#, d = dir.path().display())).unwrap();
    let out = bin().args(["check-config", good.to_str().unwrap()]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout} {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("ok:") && stdout.contains("rules"), "{stdout}");

    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "trap_listen = 12\n").unwrap();
    let out = bin().args(["check-config", bad.to_str().unwrap()]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("config"));

    let out = bin().args(["check-config", "/nonexistent/x.toml"]).output().unwrap();
    assert!(!out.status.success());
}
```
`check-config` runs `nmap --version`; CI and dev machines have nmap. Honour `PEEPHOLE_NMAP_PATH` like `run()` does.

- [ ] **Step 2: Run, expect failure**

Run: `cargo test --test cli`

- [ ] **Step 3: Implement**

`src/lib.rs` — factor the startup validation out of `run` and reuse it:
```rust
pub const VERSION: &str = env!("PEEPHOLE_VERSION");

/// Startup validation shared by `run` and `check-config`: config parses and
/// is sane, rules load, nmap is executable. Returns a one-line summary.
pub async fn check_config(config_path: &std::path::Path) -> Result<(config::Config, classify::Classifier, String)> {
    let cfg = config::Config::load(config_path).context("config")?;
    let classifier = classify::Classifier::from_dir(&cfg.rules_dir).context("loading rules")?;
    let nmap_path = std::env::var("PEEPHOLE_NMAP_PATH").unwrap_or_else(|_| "nmap".into());
    let out = tokio::process::Command::new(&nmap_path).arg("--version").output().await
        .with_context(|| format!("nmap not found at {nmap_path} — install nmap"))?;
    anyhow::ensure!(out.status.success(), "nmap --version failed");
    let nmap_line = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("nmap").to_string();
    let summary = format!("ok: config, rules ({}), {}", classifier.rule_count(), nmap_line);
    Ok((cfg, classifier, summary))
}
```
`Classifier::rule_count()` — add `pub fn rule_count(&self) -> usize` returning the compiled rule vector's length (the `Vec<CompiledRule>` field in `src/classify/mod.rs`). `run()` calls `check_config` first and continues with the returned `cfg` and `classifier`; the duplicated nmap/rules code in `run` is removed.

`src/main.rs`:
```rust
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("peephole {}", peephole::VERSION);
            return Ok(());
        }
        Some("check-config") => {
            let path = PathBuf::from(args.get(1).map(String::as_str).unwrap_or("/etc/peephole/config.toml"));
            match peephole::check_config(&path).await {
                Ok((_, _, summary)) => { println!("{summary}"); return Ok(()); }
                Err(e) => { eprintln!("error: {e:#}"); std::process::exit(1); }
            }
        }
        Some("--help") | Some("-h") => {
            println!("usage: peephole [CONFIG]\n       peephole check-config [CONFIG]\n       peephole --version");
            return Ok(());
        }
        _ => {}
    }
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let config = args.first().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/etc/peephole/config.toml"));
    peephole::run(config).await
}
```
`Config::load` errors are wrapped with `.context("config")` so the stderr assertion holds.

`deploy/nginx.example.conf`:
```nginx
# peephole admin listener behind nginx (TLS termination).
# Copy to /etc/nginx/sites-available/peephole, adjust server_name and
# certificate paths, enable, reload nginx.
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name peephole.example.net;

    ssl_certificate     /etc/letsencrypt/live/peephole.example.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/peephole.example.net/privkey.pem;

    # Server-Sent Events for the live scan queue: no buffering, long timeout.
    location /admin/api/queue {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        add_header X-Accel-Buffering no;
    }

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name peephole.example.net;
    return 301 https://$host$request_uri;
}
```

`.github/workflows/release.yml` — in "Build release binary": `run: PEEPHOLE_VERSION="${GITHUB_SHA::12}" cargo build --release --locked`. In "Package tarball" add before `tar`:
```bash
          printf '%s %s\n' "${GITHUB_SHA::12}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$staging/VERSION"
          cp deploy/nginx.example.conf "$staging/deploy/"
```

`deploy/config.example.toml`: document `secure_cookies` (from Task 10) under `[webauthn]`.

- [ ] **Step 4: Run tests, commit**

```bash
cargo test
cargo fmt --all && cargo clippy --all-targets -- -D warnings
git add src tests/cli.rs deploy .github/workflows/release.yml
git commit -m "feat(cli): --version and check-config; nginx example; VERSION in release tarball

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 13: Installer — idempotent install-or-upgrade with rollback

**Files:**
- Modify: `install.sh`, `.github/workflows/ci.yml`
- Create: `tests/install-smoke.sh`

**Interfaces:**
- Consumes: `peephole --version`, `peephole check-config`, `/healthz`, `VERSION` file, `deploy/nginx.example.conf` (Task 12).
- Produces: `install.sh` honouring env overrides `BASE_URL` (download base), `PEEPHOLE_FORCE=1`, `PEEPHOLE_SKIP_APT=1` (tests), plus the existing `MAXMIND_*`, `PEEPHOLE_DOMAIN`, `PEEPHOLE_TRUSTED_PROXIES`.

- [ ] **Step 1: Write the smoke test script first**

`tests/install-smoke.sh` (runs as root inside a Debian container in CI; also runnable locally with `docker run --rm -v "$PWD":/src -w /src debian:bookworm bash tests/install-smoke.sh` after `cargo build --release`):
```bash
#!/usr/bin/env bash
# Exercises install.sh against a locally served tarball: fresh install,
# no-op re-run, forced upgrade preserving an edited rule file.
set -euo pipefail
cd "$(dirname "$0")/.."
ASSET="peephole-x86_64-unknown-linux-gnu"
apt-get update -qq && apt-get install -y -qq curl ca-certificates python3 systemd nmap sqlite3 procps >/dev/null

# Build a tarball from the release binary exactly like release.yml does.
rm -rf "/tmp/$ASSET" /tmp/srv && mkdir -p "/tmp/$ASSET/deploy" /tmp/srv
cp target/release/peephole "/tmp/$ASSET/"
cp -r rules "/tmp/$ASSET/rules"
cp deploy/peephole.service deploy/config.example.toml deploy/nginx.example.conf "/tmp/$ASSET/deploy/"
printf 'test1 2026-01-01T00:00:00Z\n' > "/tmp/$ASSET/VERSION"
( cd /tmp && tar -czf "srv/$ASSET.tar.gz" "$ASSET" && cd srv && sha256sum "$ASSET.tar.gz" > "$ASSET.tar.gz.sha256" )
( cd /tmp/srv && python3 -m http.server 8999 >/dev/null 2>&1 & )
sleep 1

# systemd is not PID 1 in a container: stub systemctl so the script's
# service steps become no-ops we can observe.
mkdir -p /tmp/bin
cat > /tmp/bin/systemctl <<'EOF'
#!/bin/sh
echo "systemctl $*" >> /tmp/systemctl.log
case "$1" in is-enabled) [ -e /tmp/enabled ] ;; enable) touch /tmp/enabled ;; is-active) exit 0 ;; esac
exit 0
EOF
chmod +x /tmp/bin/systemctl
export PATH="/tmp/bin:$PATH"
export PEEPHOLE_SKIP_APT=1 PEEPHOLE_SKIP_HEALTH=1 BASE_URL="http://127.0.0.1:8999"
export MAXMIND_ACCOUNT_ID=1 MAXMIND_LICENSE_KEY=k PEEPHOLE_DOMAIN=peephole.test PEEPHOLE_TRUSTED_PROXIES=10.0.0.0/8

echo "== fresh install"
bash install.sh
test -x /usr/local/bin/peephole
test -f /etc/peephole/config.toml
test -f /etc/peephole/rules/sqli.toml
test -f /etc/peephole/nginx.example.conf
test -f /var/lib/peephole/.installed-rules.sha256
grep -q 'peephole.test' /etc/peephole/config.toml
grep -q 'systemctl enable --now peephole' /tmp/systemctl.log

echo "== re-run is a no-op"
out="$(bash install.sh)"
echo "$out" | grep -q "already up to date"

echo "== forced upgrade keeps an edited rule and drops .new beside it"
echo '# operator edit' >> /etc/peephole/rules/sqli.toml
cp /etc/peephole/rules/xss.toml /tmp/xss.orig
printf 'test2 2026-01-02T00:00:00Z\n' > "/tmp/$ASSET/VERSION"
echo '# upstream change' >> "/tmp/$ASSET/rules/xss.toml"
( cd /tmp && tar -czf "srv/$ASSET.tar.gz" "$ASSET" && cd srv && sha256sum "$ASSET.tar.gz" > "$ASSET.tar.gz.sha256" )
PEEPHOLE_FORCE=1 bash install.sh
grep -q '# operator edit' /etc/peephole/rules/sqli.toml
test -f /etc/peephole/rules/sqli.toml.new
grep -q '# upstream change' /etc/peephole/rules/xss.toml
test ! -e /etc/peephole/rules/xss.toml.new
grep -q 'systemctl restart peephole' /tmp/systemctl.log
test -x /usr/local/bin/peephole.prev
echo "== ok"
```
(The binary is built by the same CI job with `PEEPHOLE_VERSION=test1` before the container runs; the container gets the repo with `target/` mounted.)

- [ ] **Step 2: Rewrite `install.sh`**

```bash
#!/usr/bin/env bash
# peephole installer / upgrader (Debian/Ubuntu, x86_64):
#   curl -fsSL https://raw.githubusercontent.com/overcuriousity/peephole/master/install.sh | sudo bash
#
# Re-running upgrades an existing installation. Environment overrides:
#   MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, PEEPHOLE_DOMAIN, PEEPHOLE_TRUSTED_PROXIES  (first install)
#   PEEPHOLE_FORCE=1   reinstall even when the installed version matches
#   BASE_URL           alternative download base (tests, mirrors)
set -euo pipefail

main() {
REPO="overcuriousity/peephole"
ASSET="peephole-x86_64-unknown-linux-gnu"
BASE_URL="${BASE_URL:-https://github.com/${REPO}/releases/download/latest}"
INSTALL_BIN="/usr/local/bin/peephole"
CONFIG_DIR="/etc/peephole"
CONFIG_FILE="${CONFIG_DIR}/config.toml"
DATA_DIR="/var/lib/peephole"
UNIT_FILE="/etc/systemd/system/peephole.service"
RULES_MANIFEST="${DATA_DIR}/.installed-rules.sha256"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --- preconditions -----------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
command -v apt-get >/dev/null 2>&1 || die "this installer supports Debian/Ubuntu (apt) systems only"
command -v systemctl >/dev/null 2>&1 || die "systemd is required (systemctl not found)"
[ "$(uname -m)" = "x86_64" ] || die "only x86_64 builds are published; build from source on $(uname -m) (see README)"

if [ -r /dev/tty ]; then INTERACTIVE=1; else INTERACTIVE=0; fi

prompt() {
    local var="$1" msg="$2" default="${3:-}" value
    if [ -n "${!var:-}" ]; then return 0; fi
    [ "$INTERACTIVE" -eq 1 ] || die "missing required setting: ${var} (set it as an environment variable for non-interactive installs)"
    if [ -n "$default" ]; then printf '%s [%s]: ' "$msg" "$default" > /dev/tty; else printf '%s: ' "$msg" > /dev/tty; fi
    read -r value < /dev/tty
    [ -n "$value" ] || value="$default"
    [ -n "$value" ] || die "no value provided for ${var}"
    printf -v "$var" '%s' "$value"
}

toml_safe() {
    if [[ "$1" == *[\"\\]* ]] || [[ "$1" == *$'\n'* ]]; then
        die "value contains characters that are not allowed (quote, backslash, newline): $1"
    fi
}

# --- prerequisites (only what is missing) ------------------------------------
if [ "${PEEPHOLE_SKIP_APT:-0}" != "1" ]; then
    missing=()
    for pkg in nmap curl ca-certificates sqlite3; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        info "Installing prerequisites: ${missing[*]}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "${missing[@]}"
    fi
fi

# --- download + verify -------------------------------------------------------
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fetch() { curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors "$1" -o "$2"; }

info "Downloading latest peephole build"
fetch "${BASE_URL}/${ASSET}.tar.gz"        "${tmpdir}/${ASSET}.tar.gz"        || die "download failed (the rolling release may be mid-rebuild; retry in a minute)"
fetch "${BASE_URL}/${ASSET}.tar.gz.sha256" "${tmpdir}/${ASSET}.tar.gz.sha256" || die "checksum download failed"
info "Verifying checksum"
( cd "$tmpdir" && sha256sum -c --quiet "${ASSET}.tar.gz.sha256" ) || die "checksum mismatch"
tar -xzf "${tmpdir}/${ASSET}.tar.gz" -C "$tmpdir"
src="${tmpdir}/${ASSET}"

new_version="$(cut -d' ' -f1 "${src}/VERSION" 2>/dev/null || echo unknown)"
installed_version=""
if [ -x "$INSTALL_BIN" ]; then
    installed_version="$("$INSTALL_BIN" --version 2>/dev/null | awk '{print $2}' || true)"
fi
upgrade=0
[ -e "$CONFIG_FILE" ] && upgrade=1

if [ "$upgrade" -eq 1 ] && [ -n "$installed_version" ] && [ "$installed_version" = "$new_version" ] && [ "${PEEPHOLE_FORCE:-0}" != "1" ]; then
    info "peephole ${installed_version} is already up to date (set PEEPHOLE_FORCE=1 to reinstall)"
    exit 0
fi

# --- validate the new binary against the existing config before touching anything
if [ "$upgrade" -eq 1 ]; then
    info "Checking existing configuration with the new binary"
    if ! "${src}/peephole" check-config "$CONFIG_FILE"; then
        die "the new version rejects ${CONFIG_FILE}; nothing was changed. Fix the config and re-run."
    fi
fi

# --- install files -----------------------------------------------------------
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "${CONFIG_DIR}/rules"
info "Installing binary to ${INSTALL_BIN}"
install -m 0755 "${src}/peephole" "${INSTALL_BIN}.new"
if [ -x "$INSTALL_BIN" ]; then cp -p "$INSTALL_BIN" "${INSTALL_BIN}.prev"; fi
mv -f "${INSTALL_BIN}.new" "$INSTALL_BIN"

# Rules as conffiles: replace only files the operator has not edited.
info "Installing signature rules to ${CONFIG_DIR}/rules"
touch "$RULES_MANIFEST"
new_manifest="$(mktemp)"
for rule in "${src}/rules/"*.toml; do
    name="$(basename "$rule")"
    dest="${CONFIG_DIR}/rules/${name}"
    new_sum="$(sha256sum "$rule" | cut -d' ' -f1)"
    if [ ! -e "$dest" ]; then
        install -m 0644 "$rule" "$dest"
    else
        recorded="$(awk -v n="$name" '$2==n{print $1}' "$RULES_MANIFEST")"
        current="$(sha256sum "$dest" | cut -d' ' -f1)"
        if [ "$current" = "$new_sum" ]; then
            : # identical already
        elif [ -n "$recorded" ] && [ "$current" = "$recorded" ]; then
            install -m 0644 "$rule" "$dest"   # unedited → take upstream
        else
            install -m 0644 "$rule" "${dest}.new"
            warn "kept your edited ${dest}; new upstream version saved as ${dest}.new"
        fi
    fi
    printf '%s %s\n' "$new_sum" "$name" >> "$new_manifest"
done
mv -f "$new_manifest" "$RULES_MANIFEST"

install -m 0644 "${src}/deploy/nginx.example.conf" "${CONFIG_DIR}/nginx.example.conf"

# --- configuration (first install only) --------------------------------------
if [ "$upgrade" -eq 1 ]; then
    info "Existing config at ${CONFIG_FILE} left untouched"
else
    info "Configuring peephole"
    prompt MAXMIND_ACCOUNT_ID  "MaxMind GeoLite2 account ID (https://www.maxmind.com/en/accounts/current/license-key)"
    prompt MAXMIND_LICENSE_KEY "MaxMind GeoLite2 license key"
    prompt PEEPHOLE_DOMAIN     "Public domain of the admin dashboard (WebAuthn relying party)"
    prompt PEEPHOLE_TRUSTED_PROXIES "Trusted proxy CIDRs, comma-separated (X-Forwarded-For is trusted from these)" "10.0.0.0/8"
    toml_safe "$MAXMIND_ACCOUNT_ID"; toml_safe "$MAXMIND_LICENSE_KEY"; toml_safe "$PEEPHOLE_DOMAIN"
    proxies_toml="$(printf '%s' "$PEEPHOLE_TRUSTED_PROXIES" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed 's/.*/"&"/' | paste -sd',' -)"
    cat > "$CONFIG_FILE" <<EOF
# peephole configuration — generated by install.sh
# Full reference: https://github.com/${REPO}/blob/master/deploy/config.example.toml

trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "${DATA_DIR}/peephole.db"
data_dir = "${DATA_DIR}"
rules_dir = "${CONFIG_DIR}/rules"
trusted_proxies = [${proxies_toml}]

[webauthn]
rp_id = "${PEEPHOLE_DOMAIN}"
origin = "https://${PEEPHOLE_DOMAIN}"
rp_name = "peephole"

[maxmind]
account_id = "${MAXMIND_ACCOUNT_ID}"
license_key = "${MAXMIND_LICENSE_KEY}"

[scan]
max_workers = 2
timeout_secs = 900
rescan_cooldown_hours = 24
max_scans_per_hour = 30
never_scan = ["192.168.0.0/16"]
EOF
    chmod 0600 "$CONFIG_FILE"
    info "Wrote ${CONFIG_FILE} (mode 0600 — contains your MaxMind license key)"
    "$INSTALL_BIN" check-config "$CONFIG_FILE" || die "generated config failed validation"
fi

# --- systemd -----------------------------------------------------------------
info "Installing systemd service"
install -m 0644 "${src}/deploy/peephole.service" "$UNIT_FILE"
systemctl daemon-reload
if systemctl is-enabled peephole >/dev/null 2>&1; then
    systemctl restart peephole; info "Restarted peephole service"
else
    systemctl enable --now peephole; info "Enabled and started peephole service"
fi

# --- health check with rollback ----------------------------------------------
admin_listen="$(sed -n 's/^admin_listen *= *"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -1)"
if [ "${PEEPHOLE_SKIP_HEALTH:-0}" != "1" ]; then
    info "Waiting for http://${admin_listen}/healthz"
    healthy=0
    for _ in $(seq 1 20); do
        if curl -fs "http://${admin_listen}/healthz" >/dev/null 2>&1; then healthy=1; break; fi
        sleep 1
    done
    if [ "$healthy" -ne 1 ]; then
        journalctl -u peephole -n 30 --no-pager >&2 || true
        if [ -x "${INSTALL_BIN}.prev" ] && [ "$upgrade" -eq 1 ]; then
            warn "new version did not become healthy; rolling back to the previous binary"
            mv -f "${INSTALL_BIN}.prev" "$INSTALL_BIN"
            systemctl restart peephole
            die "rolled back. The log above shows why the new version failed."
        fi
        die "peephole did not become healthy; see the log above"
    fi
fi

# --- done --------------------------------------------------------------------
if [ "$upgrade" -eq 1 ]; then
    info "Upgraded peephole ${installed_version:-?} → ${new_version}"
    exit 0
fi

token=""
if [ "${PEEPHOLE_SKIP_HEALTH:-0}" != "1" ]; then
    token="$(journalctl -u peephole --since '-2min' --no-pager 2>/dev/null | grep -A2 'enter this one-time token' | tail -1 | tr -d ' ' || true)"
fi
cat <<EOF

peephole ${new_version} is installed and running.

  service status : systemctl status peephole
  logs           : journalctl -u peephole -f
  config         : ${CONFIG_FILE}
  nginx example  : ${CONFIG_DIR}/nginx.example.conf  (SSE needs proxy_buffering off — see file)

Next steps:
  1. Route fallback traffic from HAProxy to the trap listener (0.0.0.0:8080).
  2. Terminate TLS with nginx in front of the admin listener (${admin_listen}) using the example config.
  3. Enroll your first FIDO2 admin key at https://${PEEPHOLE_DOMAIN:-<your-domain>}/enroll
EOF
if [ -n "$token" ]; then
    printf '     one-time setup token: %s\n' "$token"
else
    printf '     the one-time setup token is in the service log: journalctl -u peephole | grep -A2 token\n'
fi
}

main "$@"
```

Check the exact wording of the token banner in `src/admin/auth.rs::ensure_setup_token` ("enter this one-time token:") and keep the `grep` in sync.

- [ ] **Step 3: CI job**

Append to `.github/workflows/ci.yml` under `jobs:`:
```yaml
  installer:
    name: install.sh smoke (Debian container)
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: swatinem/rust-cache@v2
      - name: build release binary (stamped like the smoke test's first tarball)
        run: PEEPHOLE_VERSION=test1 cargo build --release --locked
      - name: run installer smoke test in debian:bookworm
        run: docker run --rm -v "$PWD":/src -w /src debian:bookworm bash tests/install-smoke.sh
```
Keep the existing `shellcheck install.sh` step; add `shellcheck tests/install-smoke.sh` to it.

- [ ] **Step 4: Run locally**

```bash
shellcheck install.sh tests/install-smoke.sh
PEEPHOLE_VERSION=test1 cargo build --release
docker run --rm -v "$PWD":/src -w /src debian:bookworm bash tests/install-smoke.sh
```
The binary must report `test1` so the second run hits the "already up to date" path against the `VERSION` file the script writes.
Expected: ends with `== ok`. If docker is unavailable locally, `bash -n install.sh` + shellcheck, and rely on CI; say so in the commit message.

- [ ] **Step 5: Commit**

```bash
chmod +x tests/install-smoke.sh
git add install.sh tests/install-smoke.sh .github/workflows/ci.yml
git commit -m "feat(install): idempotent install-or-upgrade with version check, conffile rules, health check and rollback

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

---

### Task 14: Documentation, dead code, final verification

**Files:**
- Modify: `README.md`, `deploy/config.example.toml`, `docs/superpowers/specs/2026-09-30-peephole-ui-rework-design.md` (askama version line)
- Test: full suite

- [ ] **Step 1: README**

Update the Architecture bullet for the admin dashboard:
```markdown
- **Wall of shame** (public) — aggregate statistics per time range, choropleth
  map, searchable IP directory (exact / prefix / CIDR), per-IP request history,
  request search. No payloads, headers, fingerprints or scan results.
- **Admin area** (FIDO2 only, `/admin`) — live scan queue over SSE, counter-scan
  results with ports and raw nmap XML, raw request headers and bodies,
  fingerprint correlation across IPs, false-positive inbox, exports (CSV,
  Timesketch JSONL, Parquet), key management, record deletion.
```
Under Install, add a paragraph: re-running the installer upgrades in place, validates the existing config with the new binary first, rolls back if the service does not become healthy, and treats shipped rule files like conffiles (edited files are kept, the new version is placed beside them as `.new`). Mention `deploy/nginx.example.conf` and why SSE needs `proxy_buffering off`. Under Operations add `peephole check-config` and `peephole --version`. Add a "Building the world map" note pointing at `assets/README.md`.

- [ ] **Step 2: Spec amendment**

In the spec's §2, change the askama bullet to `askama = "0.16"` with the reason (engram's line; the only one cached locally).

- [ ] **Step 3: Dead code sweep**

```bash
grep -rn "fn esc\b\|fn escape\b" src/        # only src/trap/mod.rs::escape should remain
grep -rn "include_str!(\"../../templates" src/  # only src/trap/pages.rs (trap.html)
grep -rn "PublicStats\|ip_detail\|render_dashboard\|detail::" src/ tests/   # none
cargo build 2>&1 | grep -i "warning" ; true  # none
```
Remove anything the grep still finds.

- [ ] **Step 4: Full verification**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo build --release --locked
shellcheck install.sh tests/install-smoke.sh
```
All clean. Then run the release binary against a temp config, open the wall, an IP page, the admin home with the live queue, the trap page — both themes, desktop and 400 px — and fix any visual defects before the final commit.

- [ ] **Step 5: Commit**

```bash
git add README.md deploy docs
git commit -m "docs: README for the public/admin split, installer upgrade path, nginx SSE note

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013RowmGTWy4WJN7FrdvTCvs"
```

Then invoke `superpowers:finishing-a-development-branch`.

---

### Task 15: Bulk delete on the request and IP lists (added mid-execution at the user's request)

**Files:**
- Modify: `src/store/browse.rs` (`matching_request_ids`, `matching_ip_ids`), `src/store/delete.rs` (`delete_requests`, `delete_ips`), `src/admin/pages.rs` (two bulk routes), `src/admin/public.rs` (pass `bulk_total` when authed), `templates/requests.html`, `templates/ips.html`, `assets/js/app.js` (check-all, enable button), `Cargo.toml` (`serde_urlencoded` as a normal dependency)
- Test: `src/store/delete.rs`, `tests/integration.rs`

**Interfaces:**
- Produces:
  ```rust
  impl Store {
    pub async fn matching_request_ids(&self, f: &RequestFilter) -> Result<Vec<i64>>;  // unpaged, ≤100_000
    pub async fn matching_ip_ids(&self, f: &IpFilter) -> Result<Vec<i64>>;            // CIDR filtered in Rust
    pub async fn delete_requests(&self, ids: &[i64]) -> Result<u64>;                  // one transaction
    pub async fn delete_ips(&self, ids: &[i64]) -> Result<u64>;
  }
  ```
  Routes: `POST /admin/requests/bulk-delete`, `POST /admin/ips/bulk-delete`. Body is a urlencoded form parsed as `Vec<(String,String)>`: repeated `ids` = checked rows (request ids / IP addresses); `all=1` = every row matching the filter fields also present in the body. Redirects back to the list with the filter preserved. Anonymous → 303 `/login`.
  Templates gain (authed only) a checkbox column, a "check all on this page" header box, a "Delete selected" dialog and a "Delete all N matching" dialog whose form carries the current filter as hidden fields.

- [ ] **Step 1: Failing tests**

Store (`delete.rs` tests): seed 3 IPs × requests; `matching_request_ids(path="/x")` returns all; `delete_requests(&ids[..2])` → 2 rows gone, dependents gone; `matching_ip_ids(q="203.0.113.0/24")` → the two matching; `delete_ips` removes them and their requests, spares the third.

Integration: anonymous POST to both bulk routes → 303; with a session: seed 120 requests on `/bulk` from one IP plus one `/keep`; POST `ids=<two ids>` → those two gone; POST `all=1&path=/bulk` → zero `/bulk` remain, `/keep` remains (pagination crossed); redirect `Location` ends with `/requests?path=%2Fbulk&`; IPs: seed `127.0.0.1`, `127.0.0.2`, `203.0.113.1`; POST `all=1&q=127.0.0.0/8` → both loopbacks gone, the third stays; GET `/requests?path=/keep` with session contains `name="ids"` and `Delete all`; anonymous GET does not contain `name="ids"`.

- [ ] **Step 2: Implement store methods** — `matching_*` reuse the filter SQL by extracting `fn request_filter_sql(f) -> (String, Vec<String>)` and the IP where/having builder; `delete_*` loop the four `DELETE`s per id inside one transaction (ids chunked, ≤ 500 per statement via `IN (...)` placeholders).
- [ ] **Step 3: Handlers** — `bulk_delete_requests` / `bulk_delete_ips` read `String` body, `serde_urlencoded::from_str::<Vec<(String,String)>>`, collect `ids`, detect `all`, rebuild filter with `serde_urlencoded::from_str::<RequestFilter>(&body)` (unknown keys ignored), resolve ids, delete, redirect to `/requests?{qs}` / `/ips?{qs}` using `qs_without_page` (make it `pub(crate)`).
- [ ] **Step 4: Templates + JS** — checkbox column and toolbar only under `{% if chrome.authed %}`; `bulk_total: Option<i64>` on the page structs; JS: header checkbox toggles all, "Delete selected" disabled until one box is checked.
- [ ] **Step 5: fmt, clippy, full suite, commit** `feat(admin): bulk delete of filtered/checked requests and IPs`.
