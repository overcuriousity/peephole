# Federated Cluster, Part 2: Config Key and Runtime Settings — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A node's runtime settings (scan pace, rescan cooldown, roles) can be changed locally and, if the owner allows it, by holders of the node's config key; roles switch on and off without a restart.

**Architecture:** One `Settings` handle per process owns the effective runtime values: TOML defaults overlaid by rows in the existing `settings` table, with a version counter. Every change, local or remote, goes through `Settings::apply`. A role supervisor in `lib.rs` reconciles the running trap listener, scan workers and admin listener with the effective roles. Remote changes arrive as a directed cluster message authenticated by an HMAC under the target's config key, so the key itself never travels through relaying members.

**Tech Stack:** Rust, tokio, axum, sqlx/SQLite, askama, `aws_lc_rs::hmac`.

**Spec:** `docs/superpowers/specs/2026-10-01-federated-cluster-design.md`, section 5 (and §8: no legacy).

## Global Constraints

- `cluster.remote_config` defaults to `false`; with `false` every remote change is refused.
- The config key is 32 random bytes, stored only in the node's local database, never replicated, shown as `peephole-cfg1:<base64url>`.
- Rotation invalidates every holder at once.
- A remote change is accepted only if: remote config is on, the MAC verifies, `base_version` equals the current settings version, and the values pass the same validation as a local change.
- Remotely changeable: scan pace (workers, scans per hour, timeout), rescan cooldown, roles. Nothing else.
- A role can be switched on only if its local prerequisites exist (`trap_listen` + `rules_dir`; a working nmap; `admin_listen` + `[webauthn]`). At least one role stays on.
- Role changes take effect without a restart; running nmap processes finish.
- `Msg::SetPace` is removed: remote pace changes need the key.
- Every task ends green on: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Review Focus

1. A role is switched on but its listener cannot bind (port taken). Expected: an error in the log, the node keeps running, and the supervisor retries; other roles are unaffected.
2. The last enabled role is switched off, or a role is switched on without its prerequisites. Expected: refused with a message naming the reason; nothing is persisted.
3. Two holders change the same node at once. Expected: the second is refused as stale and nothing of it is applied.
4. A replayed `ConfigSet` (same bytes, sent again by a relay). Expected: refused as stale once the first one was applied.
5. Settings written by the CLI while the daemon runs. Expected: the daemon picks them up within a few seconds, including role changes.

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `src/settings.rs` | create | `Changes`, `Snapshot`, `Prereqs`, `Settings` (load, apply, reset, reload, audit) |
| `src/scan/pace.rs` | modify | `SharedPace` also carries the rescan cooldown; remote pace code removed |
| `src/lib.rs` | modify | builds `Settings`; role supervisor |
| `src/cluster/mod.rs` | modify | `Node::roles()` dynamic; `set_roles` |
| `src/cluster/confkey.rs` | create | config key, held keys, MAC, message handler, client calls |
| `src/cluster/msg.rs`, `src/cluster/record.rs`, `src/cluster/members.rs`, `src/config.rs` | modify | new messages; `remote_config` flag |
| `src/cluster/cli.rs`, `src/main.rs` | modify | `config-key …`, `settings …` |
| `src/admin/cluster.rs`, `src/admin/pages.rs`, `src/admin/mod.rs`, templates | modify | settings forms, config key card, node page |
| `src/store/migrations/0014_config_audit.sql`, `0015_config_keys.sql` | create | audit list; held keys; `members.remote_config` |
| `tests/roles_e2e.rs` | create | live role toggle on a real `peephole::run` |
| `tests/cluster.rs` | modify | remote configuration tests |

---

### Task 1: The `Settings` handle

**Files:**
- Create: `src/settings.rs`, `src/store/migrations/0014_config_audit.sql`
- Modify: `src/lib.rs`, `src/store/mod.rs`, `src/scan/pace.rs`, `src/scan/mod.rs`, `src/trap/mod.rs`, `src/admin/mod.rs`, `src/admin/pages.rs`, `src/admin/cluster.rs`
- Test: `src/settings.rs` (unit)

**Interfaces (produced):**

```rust
// src/settings.rs
pub const KEY_COOLDOWN: &str = "scan.rescan_cooldown_hours";
pub const KEY_ROLE_LISTENER: &str = "roles.listener";
pub const KEY_ROLE_SCANNER: &str = "roles.scanner";
pub const KEY_ROLE_WEB: &str = "roles.web";
/// Every key a runtime override can use (CLI `settings set|reset`).
pub const KEYS: [&str; 7];           // the three pace keys from scan::pace, then the four above

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Changes {
    pub max_workers: Option<u32>,
    pub max_scans_per_hour: Option<i64>,
    pub timeout_secs: Option<u64>,
    pub cooldown_hours: Option<i64>,
    pub listener: Option<bool>,
    pub scanner: Option<bool>,
    pub web: Option<bool>,
}
impl Changes {
    pub fn is_empty(&self) -> bool;
    /// "workers=2, scanner=off", for the audit list and logs.
    pub fn describe(&self) -> String;
    /// One `key value` pair from the CLI.
    pub fn from_key_value(key: &str, value: &str) -> Result<Self, String>;
}

/// Why a role cannot be switched on here; `None` means it can.
#[derive(Debug, Clone, Default)]
pub struct Prereqs { pub listener: Option<String>, pub scanner: Option<String>, pub web: Option<String> }
impl Prereqs { pub fn from_config(cfg: &Config, nmap_ok: bool) -> Self; }

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Snapshot { pub pace: Pace, pub cooldown_hours: i64, pub roles: Roles, pub version: u64 }

/// Pure: `current` with `c` applied, or why not.
pub fn validate(current: Snapshot, c: &Changes, prereqs: &Prereqs) -> Result<Snapshot, String>;

#[derive(Debug, Clone)]
pub struct AuditRow { pub at: String, pub by: Option<NodeId>, pub changes: String }

#[derive(Clone)]
pub struct Settings { pub pace: SharedPace, /* private: store, defaults, prereqs, roles, version, changed, lock */ }
impl Settings {
    pub async fn load(store: &Store, cfg: &Config, prereqs: Prereqs) -> Result<Self>;
    /// Without reading overrides (tests, `AdminState::new`): `pace` as given, the rest from `cfg`.
    pub fn with_pace(store: Store, cfg: &Config, pace: SharedPace) -> Self;
    pub fn snapshot(&self) -> Snapshot;
    pub fn roles(&self) -> Roles;
    pub fn prereqs(&self) -> &Prereqs;
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64>;
    /// Validate, persist, bump the version, apply. `by`: the remote node that asked, for the audit list.
    pub async fn apply(&self, c: &Changes, by: Option<NodeId>) -> Result<Result<u64, String>>;
    /// Like `apply`, refused unless the current version is `base_version`.
    pub async fn apply_at(&self, base_version: u64, c: &Changes, by: Option<NodeId>) -> Result<Result<u64, String>>;
    /// Drop one override (`Some(key)`) or all of them; back to the TOML values.
    pub async fn reset(&self, key: Option<&str>) -> Result<Result<u64, String>>;
    /// Re-read the database (another process may have written); true if anything changed.
    pub async fn reload(&self) -> Result<bool>;
    pub async fn audit(&self, limit: i64) -> Result<Vec<AuditRow>>;
}

// src/scan/pace.rs
impl SharedPace {
    pub fn cooldown_hours(&self) -> i64;
    pub fn set_cooldown_hours(&self, h: i64);   // in memory; Settings persists
}
pub const KEY_WORKERS / KEY_PER_HOUR / KEY_TIMEOUT: now `pub`
```

- [ ] **Step 1: Write the failing unit tests** in `src/settings.rs` (create the file with only the tests module and `use super::*;` first, add `pub mod settings;` to `src/lib.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\nrules_dir = \"r\"\n{extra}"
        ))
        .unwrap()
    }

    fn snap(roles: (bool, bool, bool)) -> Snapshot {
        Snapshot {
            pace: Pace {
                max_workers: 2,
                max_scans_per_hour: 30,
                timeout_secs: 1800,
            },
            cooldown_hours: 24,
            roles: Roles {
                listener: roles.0,
                scanner: roles.1,
                web: roles.2,
            },
            version: 7,
        }
    }

    #[test]
    fn validate_applies_only_what_is_given() {
        let out = validate(
            snap((true, true, false)),
            &Changes {
                max_workers: Some(4),
                cooldown_hours: Some(48),
                ..Default::default()
            },
            &Prereqs::default(),
        )
        .unwrap();
        assert_eq!(out.pace.max_workers, 4);
        assert_eq!(out.pace.max_scans_per_hour, 30);
        assert_eq!(out.cooldown_hours, 48);
        assert_eq!(out.version, 7, "validate does not bump the version");
    }

    #[test]
    fn validate_refuses_bad_values_roles_without_prerequisites_and_no_role_at_all() {
        let none = Prereqs::default();
        for (c, needle) in [
            (
                Changes {
                    max_workers: Some(99),
                    ..Default::default()
                },
                "workers",
            ),
            (
                Changes {
                    cooldown_hours: Some(-1),
                    ..Default::default()
                },
                "cooldown",
            ),
            (
                Changes {
                    listener: Some(false),
                    scanner: Some(false),
                    ..Default::default()
                },
                "at least one role",
            ),
        ] {
            let e = validate(snap((true, true, false)), &c, &none).unwrap_err();
            assert!(e.contains(needle), "{e}");
        }
        let missing = Prereqs {
            web: Some("admin_listen is not set".into()),
            ..Default::default()
        };
        let e = validate(
            snap((true, true, false)),
            &Changes {
                web: Some(true),
                ..Default::default()
            },
            &missing,
        )
        .unwrap_err();
        assert!(e.contains("admin_listen is not set"), "{e}");
        // Switching a role off needs no prerequisite.
        assert!(
            validate(
                snap((true, true, true)),
                &Changes {
                    web: Some(false),
                    ..Default::default()
                },
                &missing
            )
            .is_ok()
        );
    }

    #[test]
    fn prereqs_name_what_is_missing() {
        let p = Prereqs::from_config(&cfg("[roles]\nweb = false\n"), false);
        assert!(p.listener.is_none());
        assert!(p.scanner.as_deref().unwrap().contains("nmap"));
        assert!(p.web.as_deref().unwrap().contains("admin_listen"));
    }

    #[test]
    fn changes_parse_from_cli_pairs_and_describe_themselves() {
        let c = Changes::from_key_value("roles.scanner", "false").unwrap();
        assert_eq!(c.scanner, Some(false));
        assert_eq!(c.describe(), "scanner=off");
        let c = Changes::from_key_value("scan.max_workers", "3").unwrap();
        assert_eq!(c.describe(), "workers=3");
        assert!(Changes::from_key_value("scan.level_argv", "x").is_err());
        assert!(Changes::from_key_value("roles.web", "maybe").is_err());
        assert!(Changes::default().is_empty());
    }

    async fn open(extra: &str) -> (Settings, crate::store::Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let s = Settings::load(&store, &cfg(extra), Prereqs::default())
            .await
            .unwrap();
        (s, store, dir)
    }

    #[tokio::test]
    async fn overrides_persist_bump_the_version_and_reset_to_toml() {
        let (s, store, _d) = open("[roles]\nweb = false\n[scan]\nrescan_cooldown_hours = 12\n").await;
        let before = s.snapshot();
        assert_eq!((before.cooldown_hours, before.version), (12, 0));
        let v = s
            .apply(
                &Changes {
                    cooldown_hours: Some(48),
                    scanner: Some(false),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v, 1);
        assert_eq!(s.pace.cooldown_hours(), 48);
        assert!(!s.roles().scanner);
        // A second handle on the same database (the CLI, or a restart) sees it.
        let again = Settings::load(&store, &cfg("[roles]\nweb = false\n"), Prereqs::default())
            .await
            .unwrap();
        assert_eq!(again.snapshot().cooldown_hours, 48);
        assert_eq!(again.snapshot().version, 1);
        // A refused change persists nothing.
        let e = s
            .apply(
                &Changes {
                    listener: Some(false),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .unwrap_err();
        assert!(e.contains("at least one role"), "{e}");
        assert_eq!(s.snapshot().version, 1);
        // The other handle changes something; reload picks it up.
        again
            .apply(
                &Changes {
                    max_workers: Some(5),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(s.reload().await.unwrap());
        assert_eq!(s.snapshot().pace.max_workers, 5);
        assert!(!s.reload().await.unwrap());
        // Reset one key, then all.
        s.reset(Some(KEY_COOLDOWN)).await.unwrap().unwrap();
        assert_eq!(s.snapshot().cooldown_hours, 12);
        s.reset(None).await.unwrap().unwrap();
        let end = s.snapshot();
        assert!(end.roles.scanner);
        assert_eq!(end.pace.max_workers, 2);
        assert!(s.reset(Some("no.such.key")).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn apply_at_refuses_a_stale_version_and_remote_changes_are_audited() {
        let (s, _store, _d) = open("").await;
        let who = crate::cluster::identity::Identity::generate().unwrap().id;
        let c = Changes {
            max_scans_per_hour: Some(77),
            ..Default::default()
        };
        assert_eq!(s.apply_at(0, &c, Some(who)).await.unwrap(), Ok(1));
        let e = s.apply_at(0, &c, Some(who)).await.unwrap().unwrap_err();
        assert!(e.contains("changed meanwhile"), "{e}");
        let audit = s.audit(10).await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].by, Some(who));
        assert_eq!(audit[0].changes, "scans/h=77");
        // An empty change proves the caller may configure; it changes nothing.
        assert_eq!(s.apply_at(1, &Changes::default(), Some(who)).await.unwrap(), Ok(1));
        assert_eq!(s.audit(10).await.unwrap().len(), 1);
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib settings::`
Expected: compile errors (`Changes`, `Settings` … not found).

- [ ] **Step 3: Schema.** Create `src/store/migrations/0014_config_audit.sql` and append it to `MIGRATIONS`:

```sql
-- Local list of settings changes made by other nodes (config key holders).
CREATE TABLE config_audit (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, by BLOB, changes TEXT NOT NULL
)
```

- [ ] **Step 4: Cooldown on `SharedPace`.** In `src/scan/pace.rs` make `KEY_WORKERS`, `KEY_PER_HOUR`, `KEY_TIMEOUT` `pub`, and give `SharedPace` the cooldown:

```rust
/// Shared between the admin UI (writer) and the scan workers (reader): the
/// scan pace, and the rescan cooldown that trap and scanners apply.
#[derive(Clone)]
pub struct SharedPace(Arc<RwLock<Pace>>, Arc<std::sync::atomic::AtomicI64>);

impl SharedPace {
    pub fn new(p: Pace) -> Self {
        Self(
            Arc::new(RwLock::new(p)),
            Arc::new(std::sync::atomic::AtomicI64::new(24)),
        )
    }

    /// Hours within which an IP is not scanned again at the same level.
    pub fn cooldown_hours(&self) -> i64 {
        self.1.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_cooldown_hours(&self, h: i64) {
        self.1.store(h, std::sync::atomic::Ordering::Relaxed);
    }
```

`SharedPace::load` ends with `let s = Self::new(p); s.set_cooldown_hours(c.rescan_cooldown_hours); Ok(s)`. Add `pub fn replace(&self, p: Pace) { *self.0.write().unwrap() = p; }` (in-memory only; `Settings` persists).

Use it: `src/scan/mod.rs` — add `pace: pace::SharedPace` to `Source` (set in `run_workers`), and in `duplicate` bind `format!("-{} hours", self.pace.cooldown_hours())`. `src/trap/mod.rs` — add `pub pace: crate::scan::pace::SharedPace,` to `TrapState` and replace both `state.cfg.scan.rescan_cooldown_hours` with `state.pace.cooldown_hours()`; `src/lib.rs` passes `pace: pace.clone(),` when it builds `TrapState`.

- [ ] **Step 5: Implement `src/settings.rs`** above the tests:

```rust
//! Runtime settings: the values an operator may change while the node runs
//! (scan pace, rescan cooldown, roles). The TOML gives the defaults; rows in
//! the `settings` table override them. Every change, from the local admin
//! UI, the CLI or a config key holder, goes through [`Settings::apply`].
use crate::cluster::identity::NodeId;
use crate::config::{Config, Roles};
use crate::scan::pace::{self, Pace, SharedPace};
use crate::store::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub const KEY_COOLDOWN: &str = "scan.rescan_cooldown_hours";
pub const KEY_ROLE_LISTENER: &str = "roles.listener";
pub const KEY_ROLE_SCANNER: &str = "roles.scanner";
pub const KEY_ROLE_WEB: &str = "roles.web";
const KEY_VERSION: &str = "settings.version";
/// Longest rescan cooldown (one year).
const MAX_COOLDOWN_HOURS: i64 = 24 * 365;

/// Every key a runtime override can use.
pub const KEYS: [&str; 7] = [
    pace::KEY_WORKERS,
    pace::KEY_PER_HOUR,
    pace::KEY_TIMEOUT,
    KEY_COOLDOWN,
    KEY_ROLE_LISTENER,
    KEY_ROLE_SCANNER,
    KEY_ROLE_WEB,
];

/// A set of changes; absent fields stay as they are.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Changes {
    pub max_workers: Option<u32>,
    pub max_scans_per_hour: Option<i64>,
    pub timeout_secs: Option<u64>,
    pub cooldown_hours: Option<i64>,
    pub listener: Option<bool>,
    pub scanner: Option<bool>,
    pub web: Option<bool>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// "workers=2, scanner=off", for the audit list and logs.
    pub fn describe(&self) -> String {
        let on = |b: bool| if b { "on" } else { "off" };
        let mut v = vec![];
        if let Some(x) = self.max_workers {
            v.push(format!("workers={x}"));
        }
        if let Some(x) = self.max_scans_per_hour {
            v.push(format!("scans/h={x}"));
        }
        if let Some(x) = self.timeout_secs {
            v.push(format!("timeout={x}s"));
        }
        if let Some(x) = self.cooldown_hours {
            v.push(format!("cooldown={x}h"));
        }
        if let Some(x) = self.listener {
            v.push(format!("listener={}", on(x)));
        }
        if let Some(x) = self.scanner {
            v.push(format!("scanner={}", on(x)));
        }
        if let Some(x) = self.web {
            v.push(format!("web={}", on(x)));
        }
        v.join(", ")
    }

    /// One `key value` pair from the CLI.
    pub fn from_key_value(key: &str, value: &str) -> Result<Self, String> {
        let num = || {
            value
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("{key}: `{value}` is not a number"))
        };
        let flag = || match value.trim() {
            "true" | "on" | "1" => Ok(true),
            "false" | "off" | "0" => Ok(false),
            _ => Err(format!("{key}: use true or false")),
        };
        let mut c = Self::default();
        match key {
            pace::KEY_WORKERS => c.max_workers = Some(num()?.clamp(0, u32::MAX as i64) as u32),
            pace::KEY_PER_HOUR => c.max_scans_per_hour = Some(num()?),
            pace::KEY_TIMEOUT => c.timeout_secs = Some(num()?.max(0) as u64),
            KEY_COOLDOWN => c.cooldown_hours = Some(num()?),
            KEY_ROLE_LISTENER => c.listener = Some(flag()?),
            KEY_ROLE_SCANNER => c.scanner = Some(flag()?),
            KEY_ROLE_WEB => c.web = Some(flag()?),
            _ => {
                return Err(format!(
                    "`{key}` is not a runtime setting (one of: {})",
                    KEYS.join(", ")
                ));
            }
        }
        Ok(c)
    }
}

/// Why a role cannot be switched on here; `None` means it can.
#[derive(Debug, Clone, Default)]
pub struct Prereqs {
    pub listener: Option<String>,
    pub scanner: Option<String>,
    pub web: Option<String>,
}

impl Prereqs {
    pub fn from_config(cfg: &Config, nmap_ok: bool) -> Self {
        let listener = match (&cfg.trap_listen, &cfg.rules_dir) {
            (None, _) => Some("trap_listen is not set in the config file".to_string()),
            (_, None) => Some("rules_dir is not set in the config file".to_string()),
            _ => None,
        };
        let web = match (&cfg.admin_listen, &cfg.webauthn) {
            (None, _) => Some("admin_listen is not set in the config file".to_string()),
            (_, None) => Some("[webauthn] is missing in the config file".to_string()),
            _ => None,
        };
        Self {
            listener,
            scanner: (!nmap_ok).then(|| "nmap is not installed on this node".to_string()),
            web,
        }
    }
}

/// The effective runtime settings at one moment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Snapshot {
    pub pace: Pace,
    pub cooldown_hours: i64,
    pub roles: Roles,
    pub version: u64,
}

/// `current` with `c` applied, or why not. The version is left alone.
pub fn validate(current: Snapshot, c: &Changes, prereqs: &Prereqs) -> Result<Snapshot, String> {
    let mut s = current;
    if let Some(x) = c.max_workers {
        s.pace.max_workers = x as usize;
    }
    if let Some(x) = c.max_scans_per_hour {
        s.pace.max_scans_per_hour = x;
    }
    if let Some(x) = c.timeout_secs {
        s.pace.timeout_secs = x;
    }
    s.pace.validate()?;
    if let Some(x) = c.cooldown_hours {
        if !(0..=MAX_COOLDOWN_HOURS).contains(&x) {
            return Err(format!(
                "rescan cooldown must be between 0 and {MAX_COOLDOWN_HOURS} hours"
            ));
        }
        s.cooldown_hours = x;
    }
    for (new, cur, missing, name) in [
        (c.listener, &mut s.roles.listener, &prereqs.listener, "trap"),
        (c.scanner, &mut s.roles.scanner, &prereqs.scanner, "scanner"),
        (c.web, &mut s.roles.web, &prereqs.web, "web interface"),
    ] {
        let Some(new) = new else { continue };
        if new && !*cur && let Some(why) = missing {
            return Err(format!("the {name} role cannot be switched on: {why}"));
        }
        *cur = new;
    }
    if !(s.roles.listener || s.roles.scanner || s.roles.web) {
        return Err("at least one role must stay on".into());
    }
    Ok(s)
}

/// One remote settings change, as the owner sees it.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub at: String,
    pub by: Option<NodeId>,
    pub changes: String,
}

#[derive(Clone)]
pub struct Settings {
    pub pace: SharedPace,
    store: Store,
    /// The TOML values, to fall back to when an override is dropped.
    defaults: Snapshot,
    prereqs: Arc<Prereqs>,
    roles: Arc<RwLock<Roles>>,
    version: Arc<AtomicU64>,
    changed: tokio::sync::watch::Sender<u64>,
    /// Serializes writers in this process.
    lock: Arc<tokio::sync::Mutex<()>>,
}

fn defaults(cfg: &Config) -> Snapshot {
    Snapshot {
        pace: Pace::from_config(&cfg.scan),
        cooldown_hours: cfg.scan.rescan_cooldown_hours,
        roles: cfg.roles,
        version: 0,
    }
}

impl Settings {
    /// Without reading overrides (tests): `pace` as given, the rest from `cfg`.
    pub fn with_pace(store: Store, cfg: &Config, pace: SharedPace) -> Self {
        let d = defaults(cfg);
        Self {
            pace,
            store,
            defaults: d,
            prereqs: Arc::new(Prereqs::default()),
            roles: Arc::new(RwLock::new(d.roles)),
            version: Arc::new(AtomicU64::new(0)),
            changed: tokio::sync::watch::channel(0).0,
            lock: Default::default(),
        }
    }

    pub async fn load(store: &Store, cfg: &Config, prereqs: Prereqs) -> Result<Self> {
        let d = defaults(cfg);
        let pace = SharedPace::new(d.pace);
        pace.set_cooldown_hours(d.cooldown_hours);
        let mut s = Self::with_pace(store.clone(), cfg, pace);
        s.prereqs = Arc::new(prereqs);
        s.reload().await?;
        Ok(s)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            pace: self.pace.get(),
            cooldown_hours: self.pace.cooldown_hours(),
            roles: self.roles(),
            version: self.version.load(Ordering::Relaxed),
        }
    }

    pub fn roles(&self) -> Roles {
        *self.roles.read().unwrap()
    }

    pub fn prereqs(&self) -> &Prereqs {
        &self.prereqs
    }

    /// Notified with the new version after every change.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// The settings as the database has them: defaults plus overrides. An
    /// override the current build would refuse is ignored.
    async fn stored(&self) -> Result<Snapshot> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings")
            .fetch_all(&self.store.pool)
            .await?;
        let mut s = self.defaults;
        for (k, v) in &rows {
            if k == KEY_VERSION {
                s.version = v.parse().unwrap_or(0);
                continue;
            }
            if !KEYS.contains(&k.as_str()) {
                continue;
            }
            // Overrides are trusted like the TOML: no prerequisite check here.
            if let Ok(c) = Changes::from_key_value(k, v)
                && let Ok(next) = validate(s, &c, &Prereqs::default())
            {
                s = next;
            }
        }
        Ok(s)
    }

    fn adopt(&self, s: Snapshot) {
        self.pace.replace(s.pace);
        self.pace.set_cooldown_hours(s.cooldown_hours);
        *self.roles.write().unwrap() = s.roles;
        self.version.store(s.version, Ordering::Relaxed);
        self.changed.send_replace(s.version);
    }

    /// Re-read the database (another process may have written); true if
    /// anything changed.
    pub async fn reload(&self) -> Result<bool> {
        let s = self.stored().await?;
        if s == self.snapshot() {
            return Ok(false);
        }
        self.adopt(s);
        Ok(true)
    }

    async fn set(&self, tx: &mut sqlx::SqliteConnection, key: &str, value: String) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *tx)
        .await?;
        Ok(())
    }

    pub async fn apply(&self, c: &Changes, by: Option<NodeId>) -> Result<Result<u64, String>> {
        self.write(None, c, by).await
    }

    /// Like [`Settings::apply`], refused unless the current version is
    /// `base_version`: two editors cannot overwrite each other, and a
    /// replayed request changes nothing.
    pub async fn apply_at(
        &self,
        base_version: u64,
        c: &Changes,
        by: Option<NodeId>,
    ) -> Result<Result<u64, String>> {
        self.write(Some(base_version), c, by).await
    }

    async fn write(
        &self,
        base: Option<u64>,
        c: &Changes,
        by: Option<NodeId>,
    ) -> Result<Result<u64, String>> {
        let _g = self.lock.lock().await;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        // Judge against the database, not this process's memory: the CLI or
        // another handle may have written since.
        let current = self.stored().await?;
        if let Some(b) = base
            && b != current.version
        {
            return Ok(Err(format!(
                "the settings changed meanwhile (version {} now); reload and try again",
                current.version
            )));
        }
        let mut next = match validate(current, c, &self.prereqs) {
            Ok(n) => n,
            Err(e) => return Ok(Err(e)),
        };
        if c.is_empty() {
            return Ok(Ok(current.version));
        }
        for (key, value) in [
            (pace::KEY_WORKERS, c.max_workers.map(|v| v.to_string())),
            (pace::KEY_PER_HOUR, c.max_scans_per_hour.map(|v| v.to_string())),
            (pace::KEY_TIMEOUT, c.timeout_secs.map(|v| v.to_string())),
            (KEY_COOLDOWN, c.cooldown_hours.map(|v| v.to_string())),
            (KEY_ROLE_LISTENER, c.listener.map(|v| v.to_string())),
            (KEY_ROLE_SCANNER, c.scanner.map(|v| v.to_string())),
            (KEY_ROLE_WEB, c.web.map(|v| v.to_string())),
        ] {
            if let Some(v) = value {
                self.set(&mut tx, key, v).await?;
            }
        }
        next.version = current.version + 1;
        self.set(&mut tx, KEY_VERSION, next.version.to_string())
            .await?;
        if let Some(by) = by {
            sqlx::query("INSERT INTO config_audit (at, by, changes) VALUES (datetime('now'), ?, ?)")
                .bind(&by.0[..])
                .bind(c.describe())
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        self.adopt(next);
        Ok(Ok(next.version))
    }

    /// Drop one override (`Some(key)`) or all of them.
    pub async fn reset(&self, key: Option<&str>) -> Result<Result<u64, String>> {
        if let Some(k) = key
            && !KEYS.contains(&k)
        {
            return Ok(Err(format!(
                "`{k}` is not a runtime setting (one of: {})",
                KEYS.join(", ")
            )));
        }
        let _g = self.lock.lock().await;
        let mut tx = self.store.pool.begin_with("BEGIN IMMEDIATE").await?;
        let version = self.stored().await?.version + 1;
        for k in KEYS {
            if key.is_none_or(|only| only == k) {
                sqlx::query("DELETE FROM settings WHERE key = ?")
                    .bind(k)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        self.set(&mut tx, KEY_VERSION, version.to_string()).await?;
        tx.commit().await?;
        let s = self.stored().await?;
        self.adopt(s);
        Ok(Ok(version))
    }

    /// The newest remote changes, newest first.
    pub async fn audit(&self, limit: i64) -> Result<Vec<AuditRow>> {
        let rows: Vec<(String, Option<Vec<u8>>, String)> =
            sqlx::query_as("SELECT at, by, changes FROM config_audit ORDER BY id DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.store.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(|(at, by, changes)| AuditRow {
                at,
                by: by.and_then(|b| NodeId::from_slice(&b).ok()),
                changes,
            })
            .collect())
    }
}
```

Note for the implementer: `stored()` reads through the pool while `write` holds an open `BEGIN IMMEDIATE` transaction on another connection. SQLite WAL allows that read; it sees the state before the transaction, which is what is wanted. If the pool's busy handling makes this deadlock in practice, read through `&mut *tx` instead (give `stored` a connection parameter).

- [ ] **Step 6: Run the unit tests**

Run: `cargo test --lib settings::`
Expected: PASS.

- [ ] **Step 7: Wire it in.**

`src/admin/mod.rs`: add `pub settings: crate::settings::Settings,` to `AdminState`; in `new` build it with `settings: crate::settings::Settings::with_pace(store.clone(), &cfg, pace.clone()),` (before `store` and `cfg` are moved into the struct); add

```rust
    /// Use the process-wide runtime settings (so UI changes reach the trap,
    /// the scan workers and the role supervisor).
    pub fn with_settings(mut self, settings: crate::settings::Settings) -> Self {
        self.pace = settings.pace.clone();
        self.settings = settings;
        self
    }
```

`src/lib.rs`, in `run`: replace `let pace = scan::pace::SharedPace::load(&store, &cfg.scan).await?;` with

```rust
    // Runtime settings: config defaults, overridden from the admin UI, the
    // CLI or a config key holder.
    let nmap_ok = tokio::process::Command::new(nmap_path())
        .arg("--version")
        .output()
        .await
        .is_ok_and(|o| o.status.success());
    let settings = settings::Settings::load(
        &store,
        &cfg,
        settings::Prereqs::from_config(&cfg, nmap_ok),
    )
    .await?;
    let pace = settings.pace.clone();
```

and build the admin state with `.with_recorder(recorder.clone()).with_settings(settings.clone())`.

`src/admin/pages.rs`, `queue_pace`: replace the `st.pace.set(&st.store, p)` call by `st.settings.apply(&Changes { max_workers: Some(p.max_workers as u32), max_scans_per_hour: Some(p.max_scans_per_hour), timeout_secs: Some(p.timeout_secs), ..Default::default() }, None)` (`use crate::settings::Changes;`); its `Ok(Ok(_))` arm is the success arm. Do the same in the self branch of `set_pace` in `src/admin/cluster.rs`.

- [ ] **Step 8: Run everything**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: PASS (the existing pace tests in `tests/integration.rs` still pass: `SharedPace::load` reads what `Settings` wrote under the same keys).

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(settings): one runtime settings handle for pace, cooldown and roles"
```

---

### Task 2: Roles switch without a restart

**Files:**
- Modify: `src/lib.rs`, `src/cluster/mod.rs`, `src/cluster/status.rs`, `src/scan/arbiter.rs`, `src/admin/cluster.rs`, `src/admin/pages.rs`, `src/cluster/cli.rs`, `src/main.rs`
- Create: `src/settings_cli.rs`, `tests/roles_e2e.rs`

**Interfaces:**
- Consumes: `Settings` from Task 1.
- Produces:
  - `pub fn Node::roles(&self) -> Roles`; `pub async fn Node::set_roles(&self, r: Roles) -> Result<()>` (republishes the member info when it changed). The public field `Node::roles` is gone.
  - `pub async fn settings_cli::run(args: &[String], default_config: &str) -> Result<()>` for `peephole settings show|set KEY VALUE|reset [KEY] [CONFIG]`.
  - `lib::SETTINGS_TICK: Duration` (2 s): how often the daemon re-reads settings another process may have written.

- [ ] **Step 1: Write the failing end-to-end test** `tests/roles_e2e.rs`:

```rust
//! A real `peephole::run` whose trap role is switched off and on again
//! while it runs, by writing settings the way the CLI does.
use peephole::settings::{Changes, KEY_ROLE_LISTENER, Prereqs, Settings};
use peephole::store::Store;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn trap_answers(port: u16) -> bool {
    reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/x"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .is_ok()
}

async fn eventually(what: &str, port: u16, want: bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while trap_answers(port).await != want {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn trap_role_switches_off_and_on_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (trap, admin) = (free_port(), free_port());
    let cfg_path = dir.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
trap_listen = "127.0.0.1:{trap}"
admin_listen = "127.0.0.1:{admin}"
database_path = "{d}/p.db"
data_dir = "{d}"
rules_dir = "rules"
[roles]
scanner = false
[webauthn]
rp_id = "localhost"
origin = "https://localhost"
rp_name = "t"
secure_cookies = false
"#,
            d = dir.path().display()
        ),
    )
    .unwrap();
    let cfg = peephole::config::Config::load(&cfg_path).unwrap();
    let node = tokio::spawn(peephole::run(cfg_path));
    eventually("trap up", trap, true).await;

    // What `peephole settings set roles.listener false` does.
    let store = Store::connect(&cfg.database_path).await.unwrap();
    let cli = Settings::load(&store, &cfg, Prereqs::from_config(&cfg, false))
        .await
        .unwrap();
    cli.apply(
        &Changes {
            listener: Some(false),
            ..Default::default()
        },
        None,
    )
    .await
    .unwrap()
    .unwrap();
    eventually("trap down", trap, false).await;
    // The web role is untouched.
    let health = reqwest::get(format!("http://127.0.0.1:{admin}/healthz"))
        .await
        .unwrap();
    assert!(health.status().is_success());

    // `peephole settings reset roles.listener`: back to the config file.
    cli.reset(Some(KEY_ROLE_LISTENER)).await.unwrap().unwrap();
    eventually("trap up again", trap, true).await;
    node.abort();
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --test roles_e2e`
Expected: FAIL with `timed out: trap down` (the running node ignores the setting).

- [ ] **Step 3: Dynamic roles on the node.** In `src/cluster/mod.rs` change the field to `roles: RwLock<Roles>,` (initialise with `RwLock::new(p.roles)`) and add:

```rust
    /// The roles this node runs right now.
    pub fn roles(&self) -> Roles {
        *self.roles.read().unwrap()
    }

    /// Adopt new roles and tell the cluster (member info and heartbeat).
    pub async fn set_roles(&self, r: Roles) -> Result<()> {
        if self.roles() == r {
            return Ok(());
        }
        *self.roles.write().unwrap() = r;
        repl::append(self, &[Record::MemberUpdate(self.self_info())]).await?;
        self.publish_status();
        Ok(())
    }
```

Replace every `self.roles.names()` / `node.roles.names()` by `self.roles().names()` / `node.roles().names()` and every `node.roles.scanner` by `node.roles().scanner` (`src/cluster/mod.rs` ×2, `src/cluster/status.rs`, `src/scan/arbiter.rs` ×2, `src/admin/cluster.rs` ×2). In `src/admin/pages.rs` the `not_scanning` flag becomes `st.recorder.node().is_some() && !st.settings.roles().scanner`.

- [ ] **Step 4: The role supervisor.** In `src/lib.rs` replace everything in `run` from the comment `// Scan worker pool.` down to (not including) `let _ = shutdown_tx.send(true);` with:

```rust
    // Roles run under a supervisor that starts and stops them when the
    // effective roles change (admin UI, CLI, or a config key holder).
    if let Some(node) = &node {
        node.set_roles(settings.roles()).await?;
    }
    let roles = RoleRunner {
        cfg: cfg.clone(),
        store: store.clone(),
        recorder: recorder.clone(),
        geo,
        tor,
        notifier,
        settings: settings.clone(),
        node: node.clone(),
    };
    let supervisor = tokio::spawn(roles.supervise(shutdown_rx.clone()));
    info!(roles = %settings.roles().names().join(","), "peephole up");
    shutdown_signal().await;
    info!("shutting down");
    let _ = shutdown_tx.send(true);
    let _ = supervisor.await;
    Ok(())
}

/// How often the daemon re-reads settings another process (the CLI) may
/// have written, and retries a role that failed to start.
pub const SETTINGS_TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// A running role: stop it by sending `true`, then wait for the task.
struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// Everything needed to start any role.
struct RoleRunner {
    cfg: config::Config,
    store: store::Store,
    recorder: store::recorder::Recorder,
    geo: intel::SharedGeo,
    tor: intel::SharedTor,
    notifier: events::Notifier,
    settings: settings::Settings,
    node: Option<Arc<cluster::Node>>,
}

impl RoleRunner {
    /// Keep the running roles equal to the effective ones until shutdown.
    async fn supervise(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let (mut trap, mut scanner, mut web) = (None, None, None);
        let mut changes = self.settings.subscribe();
        loop {
            let want = self.settings.roles();
            reconcile(&mut trap, want.listener, "trap", || self.start_trap()).await;
            reconcile(&mut scanner, want.scanner, "scanner", || {
                self.start_scanner()
            })
            .await;
            reconcile(&mut web, want.web, "web", || self.start_web()).await;
            if let Some(node) = &self.node
                && let Err(e) = node.set_roles(want).await
            {
                warn!(?e, "publishing the new roles failed");
            }
            tokio::select! {
                _ = changes.changed() => {}
                _ = tokio::time::sleep(SETTINGS_TICK) => {
                    if let Err(e) = self.settings.reload().await {
                        warn!(?e, "reloading settings failed");
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
        for r in [trap, scanner, web].into_iter().flatten() {
            r.stop().await;
        }
    }

    async fn start_trap(&self) -> Result<Running> {
        let (Some(addr), Some(dir)) = (self.cfg.trap_listen, &self.cfg.rules_dir) else {
            anyhow::bail!("trap_listen and rules_dir are required");
        };
        // Loaded on every start, so edited rules apply when the role is
        // switched off and on.
        let classifier = classify::Classifier::from_dir(dir).context("loading rules")?;
        let app = trap::router(Arc::new(trap::TrapState {
            store: self.store.clone(),
            recorder: self.recorder.clone(),
            cfg: self.cfg.clone(),
            classifier,
            geo: self.geo.clone(),
            tor: self.tor.clone(),
            notifier: self.notifier.clone(),
            helper_rate: Default::default(),
            pace: self.settings.pace.clone(),
        }));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding trap listener {addr}"))?;
        info!(%addr, "trap listener up");
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(serve_trap(listener, app, rx)),
        })
    }

    async fn start_scanner(&self) -> Result<Running> {
        let (stop, rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(scan::run_workers(
                self.recorder.clone(),
                self.cfg.clone(),
                self.settings.pace.clone(),
                PathBuf::from(nmap_path()),
                rx,
                self.notifier.clone(),
            )),
        })
    }

    async fn start_web(&self) -> Result<Running> {
        let Some(addr) = self.cfg.admin_listen else {
            anyhow::bail!("admin_listen is required");
        };
        // First-run admin setup token (spec §8.4).
        let _ = admin::auth::ensure_setup_token(&self.store, &self.cfg.data_dir).await;
        let app = admin::full_router(Arc::new(
            admin::AdminState::new(
                self.store.clone(),
                self.cfg.clone(),
                self.notifier.clone(),
                self.settings.pace.clone(),
            )
            .with_recorder(self.recorder.clone())
            .with_settings(self.settings.clone()),
        ));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding admin listener {addr}"))?;
        info!(%addr, "admin listener up");
        let (stop, mut rx) = tokio::sync::watch::channel(false);
        Ok(Running {
            stop,
            task: tokio::spawn(async move {
                let served = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                if let Err(e) = served {
                    warn!(?e, "admin listener stopped");
                }
            }),
        })
    }
}

/// Start or stop one role so that it runs exactly when `want` says so. A
/// role that fails to start is logged and tried again on the next pass.
async fn reconcile<F, Fut>(slot: &mut Option<Running>, want: bool, name: &str, start: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<Running>>,
{
    // A task that ended by itself (listener error) is started afresh.
    if slot.as_ref().is_some_and(|r| r.task.is_finished()) {
        *slot = None;
    }
    match (want, slot.is_some()) {
        (true, false) => match start().await {
            Ok(r) => {
                info!(role = name, "role started");
                *slot = Some(r);
            }
            Err(e) => warn!(role = name, error = %format!("{e:#}"), "role could not start; retrying"),
        },
        (false, true) => {
            if let Some(r) = slot.take() {
                r.stop().await;
                info!(role = name, "role stopped");
            }
        }
        _ => {}
    }
}
```

Above that block, `run` no longer needs the `classifier` from `check_config` (bind it as `_`), and the two `if cfg.roles.scanner { … }` blocks change: inside `if let Some(node) = &node { … }` always register the remote-settings handler (Task 3 replaces `scan::pace::serve_remote`; until then keep the `serve_remote` call unconditional) and always spawn `scan::arbiter::takeover_loop` (it already does nothing unless this node currently scans). `geo`, `tor` and `notifier` are moved into `RoleRunner`, so clone them where earlier code in `run` still uses them (`intel::run_scheduler` takes clones already; `forward_job_events` needs `notifier.clone()`).

The old `served` future and the `servers` `JoinSet` are gone.

- [ ] **Step 5: The `settings` command.** Create `src/settings_cli.rs` (`pub mod settings_cli;` in `src/lib.rs`):

```rust
//! `peephole settings …`: inspect and change runtime settings from the
//! shell. Works on the node's database; a running daemon picks the change
//! up within a few seconds.
use crate::config::Config;
use crate::settings::{Changes, KEYS, Prereqs, Settings};
use crate::store::Store;
use anyhow::{Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole settings show [CONFIG]
       peephole settings set KEY VALUE [CONFIG]
       peephole settings reset [KEY] [CONFIG]";

/// Run a `settings` subcommand; `args` excludes `settings` itself.
pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let arg = |i: usize| args.get(i).map(String::as_str);
    // A trailing argument that is not a settings key is the config path.
    let config = |i: usize| arg(i).unwrap_or(default_config);
    let open = |path: &str| {
        let path = path.to_string();
        async move {
            let cfg = Config::load(Path::new(&path))?;
            let store = Store::connect(&cfg.database_path).await?;
            let nmap_ok = tokio::process::Command::new(
                std::env::var("PEEPHOLE_NMAP_PATH").unwrap_or_else(|_| "nmap".into()),
            )
            .arg("--version")
            .output()
            .await
            .is_ok_and(|o| o.status.success());
            let s = Settings::load(&store, &cfg, Prereqs::from_config(&cfg, nmap_ok)).await?;
            anyhow::Ok((cfg, s))
        }
    };
    match arg(0) {
        Some("show") => {
            let (cfg, s) = open(config(1)).await?;
            let now = s.snapshot();
            let toml = Settings::with_pace(
                Store::connect(&cfg.database_path).await?,
                &cfg,
                crate::scan::pace::SharedPace::new(crate::scan::pace::Pace::from_config(&cfg.scan)),
            );
            let base = toml.snapshot();
            let src = |changed: bool| if changed { "override" } else { "config file" };
            println!("version {}", now.version);
            for (key, value, changed) in [
                (KEYS[0], now.pace.max_workers.to_string(), now.pace.max_workers != base.pace.max_workers),
                (KEYS[1], now.pace.max_scans_per_hour.to_string(), now.pace.max_scans_per_hour != base.pace.max_scans_per_hour),
                (KEYS[2], now.pace.timeout_secs.to_string(), now.pace.timeout_secs != base.pace.timeout_secs),
                (KEYS[3], now.cooldown_hours.to_string(), now.cooldown_hours != cfg.scan.rescan_cooldown_hours),
                (KEYS[4], now.roles.listener.to_string(), now.roles.listener != cfg.roles.listener),
                (KEYS[5], now.roles.scanner.to_string(), now.roles.scanner != cfg.roles.scanner),
                (KEYS[6], now.roles.web.to_string(), now.roles.web != cfg.roles.web),
            ] {
                println!("{key:<28} {value:<8} ({})", src(changed));
            }
        }
        Some("set") => {
            let (Some(key), Some(value)) = (arg(1), arg(2)) else {
                bail!("{USAGE}");
            };
            let changes = Changes::from_key_value(key, value).map_err(anyhow::Error::msg)?;
            let (_, s) = open(config(3)).await?;
            match s.apply(&changes, None).await? {
                Ok(v) => println!("{} (settings version {v}); a running node applies it within seconds", changes.describe()),
                Err(e) => bail!("{e}"),
            }
        }
        Some("reset") => {
            let (key, cfg_at) = match arg(1) {
                Some(k) if KEYS.contains(&k) => (Some(k), 2),
                _ => (None, 1),
            };
            let (_, s) = open(config(cfg_at)).await?;
            match s.reset(key).await? {
                Ok(v) => println!(
                    "{} back to the config file (settings version {v})",
                    key.unwrap_or("all runtime settings")
                ),
                Err(e) => bail!("{e}"),
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
```

In `src/main.rs` add the arm next to `Some("cluster")`:

```rust
        Some("settings") => {
            if let Err(e) = peephole::settings_cli::run(&args[1..], DEFAULT_CONFIG).await {
                eprintln!("error: {e:#}");
                std::process::exit(1);
            }
            return Ok(());
        }
```

and add `peephole settings (show|set|reset) …` to the `--help` text.

- [ ] **Step 6: Run the tests**

Run: `cargo test`
Expected: PASS, including `tests/roles_e2e.rs` and `tests/cluster_e2e.rs`.

- [ ] **Step 7: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(roles): roles start and stop at runtime; peephole settings command"
```

---

### Task 3: The config key

**Files:**
- Create: `src/cluster/confkey.rs`, `src/store/migrations/0015_config_keys.sql`
- Modify: `src/store/mod.rs`, `src/config.rs`, `src/cluster/mod.rs`, `src/cluster/record.rs`, `src/cluster/members.rs`, `src/cluster/msg.rs`, `src/scan/pace.rs`, `src/lib.rs`, `src/admin/cluster.rs`, `tests/cluster.rs`
- Test: `src/cluster/confkey.rs` (unit), `tests/cluster.rs`

**Interfaces:**
- Consumes: `Settings::{apply_at, snapshot}`, `Changes` (Task 1); `Node::roles()` (Task 2).
- Produces:

```rust
// src/config.rs
ClusterConfig::remote_config: bool        // #[serde(default)]

// src/cluster/record.rs / members.rs
MemberInfo::remote_config: bool           // #[serde(default)]
MemberRow::remote_config: bool

// src/cluster/msg.rs  (SetPace, SetPaceReply are removed)
Msg::ConfigGet
Msg::ConfigState(confkey::State)
Msg::ConfigSet { base_version: u64, changes: Changes, mac: serde_bytes::ByteBuf }
Msg::ConfigSetReply { version: Option<u64>, error: Option<String> }

// src/cluster/confkey.rs
pub struct ConfigKey { pub id: NodeId, pub key: [u8; 32] }
impl ConfigKey { pub fn encode(&self) -> String; pub fn parse(s: &str) -> Result<Self>; }
pub struct State { pub open: bool, pub version: u64, pub pace: PaceInfo, pub cooldown_hours: i64,
                   pub roles: Vec<String>, pub recommended: Option<PaceInfo> }
pub async fn own(store: &Store, me: NodeId) -> Result<Option<ConfigKey>>;
pub async fn ensure(store: &Store, me: NodeId) -> Result<ConfigKey>;       // create if absent
pub async fn rotate(store: &Store, me: NodeId) -> Result<ConfigKey>;
pub async fn add(store: &Store, me: NodeId, token: &str) -> Result<NodeId>; // remember a key someone gave us
pub async fn forget(store: &Store, node: &NodeId) -> Result<bool>;
pub async fn held(store: &Store) -> Result<Vec<NodeId>>;
pub fn mac(key: &[u8; 32], from: &NodeId, to: &NodeId, base_version: u64, c: &Changes) -> Vec<u8>;
pub fn serve(node: &Arc<Node>, settings: Settings);                         // answer ConfigGet / ConfigSet
pub async fn get(node: &Arc<Node>, target: NodeId) -> Result<State>;
pub async fn set(node: &Arc<Node>, target: NodeId, base_version: u64, c: &Changes) -> Result<Result<u64, String>>;
```

- [ ] **Step 1: Write the failing unit tests** in `src/cluster/confkey.rs` (file with `use super::*`-style test module first; `pub mod confkey;` in `src/cluster/mod.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn key_round_trips_and_rejects_garbage() {
        let k = ConfigKey {
            id: Identity::generate().unwrap().id,
            key: [7u8; 32],
        };
        let s = k.encode();
        assert!(s.starts_with("peephole-cfg1:"), "{s}");
        let back = ConfigKey::parse(&format!("  {s}\n")).unwrap();
        assert_eq!((back.id, back.key), (k.id, k.key));
        for bad in ["", "peephole1:abc", "peephole-cfg1:!!!", "peephole-cfg1:AAAA"] {
            assert!(ConfigKey::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mac_binds_key_parties_version_and_changes() {
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let c = Changes {
            max_workers: Some(3),
            ..Default::default()
        };
        let m = mac(&[1; 32], &a, &b, 5, &c);
        assert_eq!(m, mac(&[1; 32], &a, &b, 5, &c));
        assert_ne!(m, mac(&[2; 32], &a, &b, 5, &c), "key");
        assert_ne!(m, mac(&[1; 32], &b, &a, 5, &c), "direction");
        assert_ne!(m, mac(&[1; 32], &a, &b, 6, &c), "version");
        assert_ne!(m, mac(&[1; 32], &a, &b, 5, &Changes::default()), "changes");
    }

    #[tokio::test]
    async fn own_key_is_created_once_rotated_on_demand_and_held_keys_are_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let me = Identity::generate().unwrap().id;
        assert!(own(&store, me).await.unwrap().is_none());
        let first = ensure(&store, me).await.unwrap();
        assert_eq!(ensure(&store, me).await.unwrap().key, first.key);
        let second = rotate(&store, me).await.unwrap();
        assert_ne!(second.key, first.key);
        assert_eq!(own(&store, me).await.unwrap().unwrap().key, second.key);

        let other = ConfigKey {
            id: Identity::generate().unwrap().id,
            key: [9; 32],
        };
        assert_eq!(add(&store, me, &other.encode()).await.unwrap(), other.id);
        assert_eq!(held(&store).await.unwrap(), vec![other.id]);
        assert!(add(&store, me, &second.encode()).await.is_err(), "own key");
        assert!(forget(&store, &other.id).await.unwrap());
        assert!(!forget(&store, &other.id).await.unwrap());
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --lib confkey::`
Expected: compile errors.

- [ ] **Step 3: Schema and config flag.** Create `src/store/migrations/0015_config_keys.sql`, append it to `MIGRATIONS`:

```sql
-- Config keys other operators gave to this node (local, never replicated).
CREATE TABLE config_keys (
  node BLOB PRIMARY KEY, key BLOB NOT NULL, added_at TEXT NOT NULL
) WITHOUT ROWID;
-- Whether a member lets config key holders change its runtime settings.
ALTER TABLE members ADD COLUMN remote_config INTEGER NOT NULL DEFAULT 0
```

`src/config.rs`: add to `ClusterConfig`

```rust
    /// Let holders of this node's config key change its runtime settings
    /// (scan pace, rescan cooldown, roles). Default: only the local admin
    /// interface, the CLI and this file can.
    #[serde(default)]
    pub remote_config: bool,
```

and `("cluster", "remote_config", "false"),` to `OPTIONAL_KEYS` only if a missing `[cluster]` table does not then produce a note (check `optional_key_notes`: a missing table adds "optional [cluster] section absent" — that is wrong for `[cluster]`, so do **not** add it there; instead add to `check_config` in `src/lib.rs`, inside `if cfg.cluster.is_some()`: `summary.push_str(if c.remote_config { "\nremote config: on (config key holders may change runtime settings)" } else { "\nremote config: off" });` with `c` the cluster config).

Every `ClusterConfig { … }` literal in tests gets `remote_config: false,` (`src/cluster/repl.rs`, `tests/cluster.rs`); in `tests/cluster.rs` add `remote_config: bool` to `Opts` (`false` in `DEFAULT`) and pass `remote_config: o.remote_config` in `boot_in`.

`src/cluster/record.rs`: add `#[serde(default)] pub remote_config: bool,` to `MemberInfo`. `src/cluster/members.rs`: add the column to `SELECT` (after `revoked_hlc`, before the subquery), to `Row` (`i64`), to `MemberRow` (`pub remote_config: bool`, from `r.10 != 0`; the subquery becomes `r.11`), and to `write_info` / `insert` (bind `info.remote_config`). `Node::self_info` sets `remote_config: self.cfg.remote_config`, and `bootstrap`'s `up_to_date` compares it. Other `MemberInfo { … }` literals get `remote_config: false,`.

- [ ] **Step 4: Implement `src/cluster/confkey.rs`** above the tests:

```rust
//! The config key: a secret a node hands to operators it lets change its
//! runtime settings. Holding it is the permission; rotating it withdraws the
//! permission from everyone at once.
//!
//! The key never travels. Directed messages are relayed by other members,
//! so each change request carries an HMAC under the key instead; the target
//! checks it against its own copy.
use super::Node;
use super::identity::NodeId;
use super::msg::Msg;
use super::status::PaceInfo;
use crate::settings::{Changes, Settings};
use crate::store::Store;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PREFIX: &str = "peephole-cfg1:";
const OWN_KEY: &str = "cluster.config_key";
const MAC_DOMAIN: &[u8] = b"peephole-cfg-v1\0";
/// How long to wait for a node's answer.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A node's config key together with the node it belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigKey {
    pub id: NodeId,
    pub key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    id: NodeId,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

impl ConfigKey {
    /// The string an operator copies: `peephole-cfg1:…`.
    pub fn encode(&self) -> String {
        let wire = Wire {
            v: 1,
            id: self.id,
            key: self.key.to_vec(),
        };
        // Encoding a plain struct into a Vec cannot fail.
        let raw = super::rpc::cbor::encode(&wire).unwrap_or_default();
        format!("{PREFIX}{}", data_encoding::BASE64URL_NOPAD.encode(&raw))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let b64 = s
            .trim()
            .strip_prefix(PREFIX)
            .context("not a peephole config key")?;
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(b64.as_bytes())
            .context("config key: invalid base64url")?;
        let w: Wire = super::rpc::cbor::decode(&raw).context("config key: malformed")?;
        let key: [u8; 32] = w
            .key
            .try_into()
            .map_err(|_| anyhow::anyhow!("config key: malformed"))?;
        if w.v != 1 {
            bail!("config key: unsupported version");
        }
        Ok(Self { id: w.id, key })
    }
}

/// A node's runtime settings as it reports them to a member that asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// Whether the node accepts changes from config key holders at all.
    pub open: bool,
    pub version: u64,
    pub pace: PaceInfo,
    pub cooldown_hours: i64,
    pub roles: Vec<String>,
    /// What the node's own queue metrics suggest (scanners only).
    pub recommended: Option<PaceInfo>,
}

async fn stored_key(store: &Store) -> Result<Option<[u8; 32]>> {
    let Some(v) = store.setting_get(OWN_KEY).await? else {
        return Ok(None);
    };
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(v.as_bytes())
        .context("stored config key")?;
    Ok(raw.try_into().ok())
}

/// This node's config key, if one was created.
pub async fn own(store: &Store, me: NodeId) -> Result<Option<ConfigKey>> {
    Ok(stored_key(store).await?.map(|key| ConfigKey { id: me, key }))
}

/// This node's config key, created on first use.
pub async fn ensure(store: &Store, me: NodeId) -> Result<ConfigKey> {
    match own(store, me).await? {
        Some(k) => Ok(k),
        None => rotate(store, me).await,
    }
}

/// Replace this node's config key. Every holder of the old one loses the
/// right to configure this node.
pub async fn rotate(store: &Store, me: NodeId) -> Result<ConfigKey> {
    let mut key = [0u8; 32];
    aws_lc_rs::rand::fill(&mut key).map_err(|_| anyhow::anyhow!("rng failure"))?;
    store
        .setting_set(OWN_KEY, &data_encoding::BASE64URL_NOPAD.encode(&key))
        .await?;
    Ok(ConfigKey { id: me, key })
}

/// Remember a key another operator gave us; returns the node it configures.
pub async fn add(store: &Store, me: NodeId, token: &str) -> Result<NodeId> {
    let k = ConfigKey::parse(token)?;
    if k.id == me {
        bail!("this is this node's own config key; give it to the operator who should configure this node");
    }
    sqlx::query(
        "INSERT INTO config_keys (node, key, added_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(node) DO UPDATE SET key = excluded.key, added_at = excluded.added_at",
    )
    .bind(&k.id.0[..])
    .bind(&k.key[..])
    .execute(&store.pool)
    .await?;
    Ok(k.id)
}

pub async fn forget(store: &Store, node: &NodeId) -> Result<bool> {
    Ok(sqlx::query("DELETE FROM config_keys WHERE node = ?")
        .bind(&node.0[..])
        .execute(&store.pool)
        .await?
        .rows_affected()
        == 1)
}

/// Nodes we hold a config key for.
pub async fn held(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM config_keys ORDER BY added_at")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

async fn held_key(store: &Store, node: &NodeId) -> Result<Option<[u8; 32]>> {
    let k: Option<Vec<u8>> = sqlx::query_scalar("SELECT key FROM config_keys WHERE node = ?")
        .bind(&node.0[..])
        .fetch_optional(&store.pool)
        .await?;
    Ok(k.and_then(|k| k.try_into().ok()))
}

/// The authenticator of a change request: who asks whom, based on which
/// settings version, for what.
pub fn mac(key: &[u8; 32], from: &NodeId, to: &NodeId, base_version: u64, c: &Changes) -> Vec<u8> {
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let mut ctx = aws_lc_rs::hmac::Context::with_key(&k);
    ctx.update(MAC_DOMAIN);
    ctx.update(&from.0);
    ctx.update(&to.0);
    ctx.update(&base_version.to_be_bytes());
    ctx.update(&super::rpc::cbor::encode(c).unwrap_or_default());
    ctx.sign().as_ref().to_vec()
}

fn pace_info(p: crate::scan::pace::Pace) -> PaceInfo {
    PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: p.max_scans_per_hour,
        timeout_secs: p.timeout_secs,
    }
}

/// Answer other members' questions about this node's settings, and change
/// them for holders of the config key.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let (settings, weak) = (settings.clone(), weak.clone());
        Box::pin(async move {
            let node = weak.upgrade()?;
            let open = node.cfg.remote_config;
            match msg {
                Msg::ConfigGet => {
                    let s = settings.snapshot();
                    let recommended = match (s.roles.scanner, node.store.queue_metrics().await) {
                        (true, Ok(m)) => Some(pace_info(crate::scan::pace::recommend(&m, s.pace).pace)),
                        _ => None,
                    };
                    Some(Msg::ConfigState(State {
                        open,
                        version: s.version,
                        pace: pace_info(s.pace),
                        cooldown_hours: s.cooldown_hours,
                        roles: s.roles.names().into_iter().map(str::to_string).collect(),
                        recommended,
                    }))
                }
                Msg::ConfigSet {
                    base_version,
                    changes,
                    mac: theirs,
                } => {
                    let refuse = |e: &str| {
                        Some(Msg::ConfigSetReply {
                            version: None,
                            error: Some(e.to_string()),
                        })
                    };
                    if !open {
                        return refuse("remote configuration is switched off on this node");
                    }
                    let Ok(Some(key)) = stored_key(&node.store).await else {
                        return refuse("this node has no config key");
                    };
                    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
                    let mut msg = MAC_DOMAIN.to_vec();
                    msg.extend_from_slice(&from.0);
                    msg.extend_from_slice(&node.id().0);
                    msg.extend_from_slice(&base_version.to_be_bytes());
                    msg.extend_from_slice(&super::rpc::cbor::encode(&changes).unwrap_or_default());
                    // Constant-time comparison.
                    if aws_lc_rs::hmac::verify(&k, &msg, &theirs).is_err() {
                        tracing::warn!(by = %from.short(), "settings change with a wrong config key refused");
                        return refuse("config key not accepted (wrong, or rotated since)");
                    }
                    match settings.apply_at(base_version, &changes, Some(from)).await {
                        Ok(Ok(v)) => {
                            if !changes.is_empty() {
                                tracing::info!(by = %from.short(), changes = %changes.describe(), "settings changed by a config key holder");
                                node.status.local.lock().unwrap().pace =
                                    Some(pace_info(settings.snapshot().pace));
                                node.publish_status();
                            }
                            Some(Msg::ConfigSetReply {
                                version: Some(v),
                                error: None,
                            })
                        }
                        Ok(Err(e)) => refuse(&e),
                        Err(e) => refuse(&format!("{e:#}")),
                    }
                }
                _ => None,
            }
        })
    }));
}

/// Ask `target` for its runtime settings.
pub async fn get(node: &Arc<Node>, target: NodeId) -> Result<State> {
    match node.request(target, Msg::ConfigGet, TIMEOUT).await? {
        Msg::ConfigState(s) => Ok(s),
        other => bail!("unexpected answer {other:?}"),
    }
}

/// Change `target`'s settings with the config key we hold for it. The inner
/// error is the target's refusal.
pub async fn set(
    node: &Arc<Node>,
    target: NodeId,
    base_version: u64,
    c: &Changes,
) -> Result<Result<u64, String>> {
    let Some(key) = held_key(&node.store, &target).await? else {
        return Ok(Err(
            "no config key for this node; ask its operator for one".into(),
        ));
    };
    let msg = Msg::ConfigSet {
        base_version,
        changes: c.clone(),
        mac: serde_bytes::ByteBuf::from(mac(&key, &node.id(), &target, base_version, c)),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::ConfigSetReply {
            version: Some(v), ..
        } => Ok(Ok(v)),
        Msg::ConfigSetReply { error, .. } => Ok(Err(error.unwrap_or_else(|| "refused".into()))),
        other => bail!("unexpected answer {other:?}"),
    }
}
```

`mac()` and the verification must build identical bytes; if `cbor::encode` of `Changes` is not byte-stable between two encodes of an equal value, replace the `Context` updates and the `msg` vector by one shared helper `fn mac_input(from, to, base_version, c) -> Vec<u8>` used by both (do that anyway if it reads better).

In `src/cluster/msg.rs` remove `SetPace` and `SetPaceReply` and add:

```rust
    /// Any member → node: what are your runtime settings?
    ConfigGet,
    ConfigState(super::confkey::State),
    /// Config key holder → node: change your settings. `mac` proves the
    /// sender holds the node's config key without sending it.
    ConfigSet {
        base_version: u64,
        changes: crate::settings::Changes,
        mac: serde_bytes::ByteBuf,
    },
    /// `version` is the new settings version on success.
    ConfigSetReply {
        version: Option<u64>,
        error: Option<String>,
    },
```

In `src/scan/pace.rs` delete `serve_remote` and `set_remote`. In `src/lib.rs` replace the `scan::pace::serve_remote(node, pace.clone());` call with:

```rust
        if cfg.cluster.as_ref().is_some_and(|c| c.remote_config) {
            cluster::confkey::ensure(&store, node.id()).await?;
        }
        cluster::confkey::serve(node, settings.clone());
```

In `src/admin/cluster.rs`, `set_pace`, the remote branch becomes:

```rust
        let changes = crate::settings::Changes {
            max_workers: Some(w as u32),
            max_scans_per_hour: Some(h),
            timeout_secs: Some(p.timeout_secs),
            ..Default::default()
        };
        match crate::cluster::confkey::get(node, id).await {
            Ok(state) => match crate::cluster::confkey::set(node, id, state.version, &changes).await {
                Ok(r) => r.map(|_| ()),
                Err(e) => Err(format!("{e:#}")),
            },
            Err(e) => Err(format!("{e:#}")),
        }
```

- [ ] **Step 5: Run the unit tests**

Run: `cargo test --lib confkey::`
Expected: PASS.

- [ ] **Step 6: Write the cluster tests.** In `tests/cluster.rs`: `TestNode` gains `settings: peephole::settings::Settings`; `boot_in` builds it right after `pace` with

```rust
    let settings = peephole::settings::Settings::with_pace(
        node.store.clone(),
        &scan_config(&o.never_scan),
        pace.clone(),
    );
    if o.remote_config {
        cluster::confkey::ensure(&node.store, node.id()).await.unwrap();
    }
    cluster::confkey::serve(&node, settings.clone());
```

(remove the `peephole::scan::pace::serve_remote(&node, pace.clone());` line; `scan_config` yields all three roles on, which is what the role assertions below rely on.) Replace `pace_is_set_remotely` with:

```rust
/// A config key holder changes another node's settings; nobody else can.
#[tokio::test]
async fn config_key_holders_change_a_nodes_settings() {
    use peephole::cluster::confkey;
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a, &c],
        Opts {
            remote_config: true,
            ..DEFAULT
        },
    )
    .await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    eventually("a sees that b is open", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.remote_config)
    })
    .await;

    // Anyone may look.
    let state = confkey::get(&na.node, b.id).await.unwrap();
    assert!(state.open);
    assert_eq!(state.version, 0);
    let faster = Changes {
        max_scans_per_hour: Some(77),
        ..Default::default()
    };

    // Without the key: refused, before any message is sent.
    let e = confkey::set(&na.node, b.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no config key"), "{e}");

    // B's operator hands A the key.
    let key = confkey::own(&nb.store, b.id).await.unwrap().unwrap();
    assert_eq!(
        confkey::add(&na.store, a.id, &key.encode()).await.unwrap(),
        b.id
    );
    assert_eq!(confkey::set(&na.node, b.id, 0, &faster).await.unwrap(), Ok(1));
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    let audit = nb.settings.audit(10).await.unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].by, Some(a.id));

    // A stale version (a second editor, or a replay) changes nothing.
    let e = confkey::set(&na.node, b.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("changed meanwhile"), "{e}");

    // Invalid values are refused by the same rules as locally.
    let e = confkey::set(
        &na.node,
        b.id,
        1,
        &Changes {
            listener: Some(false),
            scanner: Some(false),
            web: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(e.contains("at least one role"), "{e}");

    // C holds a wrong key for B.
    let wrong = confkey::ConfigKey {
        id: b.id,
        key: [0u8; 32],
    };
    confkey::add(&nc.store, c.id, &wrong.encode()).await.unwrap();
    let e = confkey::set(&nc.node, b.id, 1, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");

    // Rotation cuts A off.
    confkey::rotate(&nb.store, b.id).await.unwrap();
    let e = confkey::set(&na.node, b.id, 1, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    assert_eq!(nb.settings.snapshot().version, 1);

    // A locked node refuses even a correct key.
    confkey::ensure(&na.store, a.id).await.unwrap();
    let a_key = confkey::own(&na.store, a.id).await.unwrap().unwrap();
    confkey::add(&nb.store, b.id, &a_key.encode()).await.unwrap();
    assert!(!confkey::get(&nb.node, a.id).await.unwrap().open);
    let e = confkey::set(&nb.node, a.id, 0, &faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("switched off"), "{e}");
}
```

In `admin_cluster_page_and_private_attribution` the block `// Remote pace from the UI.` posts a pace for B; B is not open there, so it must now fail. Replace its two assertions with:

```rust
    assert!(r.status().is_success());
    assert_ne!(
        nb.pace.get().max_scans_per_hour,
        77,
        "no config key: the pace of another node cannot be changed"
    );
```

- [ ] **Step 7: Run the tests**

Run: `cargo test`
Expected: PASS.

- [ ] **Step 8: Lint and commit**

```bash
cargo fmt && cargo clippy --all-targets -- -D warnings
git add -A
git commit -m "feat(cluster)!: config key authorises remote settings changes; SetPace removed"
```

---

### Task 4: Admin interface, CLI and documentation

**Files:**
- Modify: `src/admin/cluster.rs`, `templates/admin_cluster.html`, `templates/_cluster_pace_row.html`, `src/cluster/cli.rs`, `src/main.rs`, `README.md`, `deploy/config.example.toml`
- Create: `templates/admin_cluster_node.html`
- Test: `tests/cluster.rs`, `tests/cli.rs`

**Interfaces:**
- Consumes: `Settings`, `Changes`, `confkey::*`.
- Produces routes: `POST /admin/cluster/settings` (this node), `POST /admin/cluster/config-key/rotate`, `POST /admin/cluster/config-key/add`, `POST /admin/cluster/config-key/forget`, `GET|POST /admin/cluster/node/{key}`; CLI `peephole cluster config-key show|rotate|add KEY|forget NODE`.

- [ ] **Step 1: Write the failing tests.**

`tests/cluster.rs`:

```rust
/// The admin of A configures B through the UI once B's key is added.
#[tokio::test]
async fn admin_configures_another_node_with_its_key() {
    use peephole::cluster::confkey;
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[&a],
        Opts {
            remote_config: true,
            ..DEFAULT
        },
    )
    .await;
    eventually("a sees that b is open", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.remote_config)
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let page = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(page.contains("open for config key holders"), "b is shown as open");
    assert!(page.contains("locked"), "a itself is locked");
    assert!(!page.contains("peephole-cfg1:"), "a locked node shows no key");

    // Add B's key, then change B from A's node page.
    let key = confkey::own(&nb.store, b.id).await.unwrap().unwrap();
    let r = admin
        .post(format!("{base}/admin/cluster/config-key/add"))
        .form(&[("key", key.encode())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let node_page = text(&admin, format!("{base}/admin/cluster/node/{}", b.id)).await;
    assert!(node_page.contains("node-bravo"));
    assert!(node_page.contains("name=\"base_version\" value=\"0\""), "{node_page}");
    let r = admin
        .post(format!("{base}/admin/cluster/node/{}", b.id))
        .form(&[
            ("base_version", "0"),
            ("max_workers", "3"),
            ("max_scans_per_hour", "55"),
            ("timeout_minutes", "20"),
            ("cooldown_hours", "12"),
            ("listener", "on"),
            ("web", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let s = nb.settings.snapshot();
    assert_eq!((s.pace.max_workers, s.pace.max_scans_per_hour), (3, 55));
    assert_eq!(s.pace.timeout_secs, 1200);
    assert_eq!(s.cooldown_hours, 12);
    assert!(s.roles.listener && s.roles.web && !s.roles.scanner, "unchecked role is off");

    // This node's own settings from its own page.
    let r = admin
        .post(format!("{base}/admin/cluster/settings"))
        .form(&[("cooldown_hours", "6"), ("listener", "on"), ("scanner", "on"), ("web", "on")])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(na.settings.snapshot().cooldown_hours, 6);
}
```

`admin_on` must hand the node's settings to the admin state: change its `AdminState` construction to end with `.with_recorder(Recorder::Cluster(n.node.clone())).with_settings(n.settings.clone())`.

`tests/cli.rs`, in the same style as `cluster_invite_and_members_work_headless` (reuse its config, adding `remote_config = true` under `[cluster]`, and its `run` closure):

```rust
    let shown = run(&["config-key", "show"]);
    assert!(shown.starts_with("peephole-cfg1:"), "{shown}");
    let rotated = run(&["config-key", "rotate"]);
    assert!(rotated.starts_with("peephole-cfg1:") && rotated != shown, "{rotated}");
    assert_eq!(run(&["config-key", "show"]), rotated);
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test --test cluster admin_configures_another_node` and `cargo test --test cli`
Expected: FAIL (page lacks the text; unknown subcommand).

- [ ] **Step 3: CLI.** In `src/cluster/cli.rs` add to `USAGE`:

```rust
       peephole cluster config-key show|rotate [CONFIG]
       peephole cluster config-key add KEY [CONFIG]
       peephole cluster config-key forget NODE [CONFIG]
```

and the arm:

```rust
        Some("config-key") => {
            reject_unknown_flags(&flags, &[])?;
            let sub = pos.get(1).map(String::as_str);
            let takes_arg = matches!(sub, Some("add" | "forget"));
            let cfg = Config::load(Path::new(cfg_at(if takes_arg { 3 } else { 2 })))?;
            let Some(c) = &cfg.cluster else {
                bail!("config has no [cluster] section");
            };
            let store = Store::connect(&cfg.database_path).await?;
            let me = Identity::load_or_create(&cfg.node_key_path())?.id;
            match sub {
                Some("show" | "rotate") => {
                    if !c.remote_config {
                        bail!(
                            "remote configuration is off (cluster.remote_config = false): \
                             this node has no usable config key"
                        );
                    }
                    let key = if sub == Some("rotate") {
                        super::confkey::rotate(&store, me).await?
                    } else {
                        super::confkey::ensure(&store, me).await?
                    };
                    println!("{}", key.encode());
                    eprintln!(
                        "whoever holds this key can change this node's scan pace, rescan \
                         cooldown and roles. `peephole cluster config-key rotate` withdraws it \
                         from everyone."
                    );
                }
                Some("add") => {
                    let id = super::confkey::add(&store, me, pos.get(2).context(USAGE)?).await?;
                    println!("config key for {} stored; configure it on Admin → Cluster", id.short());
                }
                Some("forget") => {
                    let id = resolve(&members::all(&store).await?, pos.get(2).context(USAGE)?)?;
                    if super::confkey::forget(&store, &id).await? {
                        println!("config key for {} forgotten", id.short());
                    } else {
                        println!("no config key held for {}", id.short());
                    }
                }
                _ => bail!("{USAGE}"),
            }
        }
```

`src/main.rs`: add `config-key` to the cluster help list.

- [ ] **Step 4: Cluster page.** In `src/admin/cluster.rs`:

- `MemberView` gains `pub remote_config: bool` (from `m.remote_config`; `node.cfg.remote_config` in the fallback) and `pub key_held: bool` (the member is in `confkey::held(&node.store)`).
- `ClusterPage` gains:

```rust
    /// This node's config key, shown only when remote configuration is on.
    config_key: Option<String>,
    remote_config: bool,
    /// This node's runtime settings and why a role cannot be switched on.
    settings: Option<SettingsView>,
    audit: Vec<AuditView>,
```

```rust
pub struct SettingsView {
    pub version: u64,
    pub cooldown_hours: i64,
    pub listener: bool,
    pub scanner: bool,
    pub web: bool,
    /// Reasons a role that is off cannot be switched on here ("" = it can).
    pub listener_missing: String,
    pub scanner_missing: String,
    pub web_missing: String,
}

pub struct AuditView {
    pub at: String,
    pub by: String,
    pub changes: String,
}
```

  filled in `render_page` from `st.settings.snapshot()`, `st.settings.prereqs()` and `st.settings.audit(20)` (names resolved through the member list like `invites` does; unknown node → its short key); `config_key` is `Some(confkey::ensure(&node.store, node.id()).await?.encode())` only when `node.cfg.remote_config`.

- Routes and handlers:

```rust
        .route("/admin/cluster/settings", post(set_own))
        .route("/admin/cluster/config-key/rotate", post(rotate_key))
        .route("/admin/cluster/config-key/add", post(add_key))
        .route("/admin/cluster/config-key/forget", post(forget_key))
        .route("/admin/cluster/node/{key}", get(node_page).post(node_set))
```

```rust
/// The settings form. A checkbox that is not ticked is not sent, so the
/// role fields always describe the wanted state in full.
#[derive(serde::Deserialize)]
struct SettingsForm {
    base_version: Option<u64>,
    max_workers: Option<String>,
    max_scans_per_hour: Option<String>,
    timeout_minutes: Option<String>,
    cooldown_hours: Option<String>,
    listener: Option<String>,
    scanner: Option<String>,
    web: Option<String>,
}

impl SettingsForm {
    fn changes(&self) -> Result<crate::settings::Changes, String> {
        fn num<T: std::str::FromStr>(v: &Option<String>, what: &str) -> Result<Option<T>, String> {
            match v.as_deref().map(str::trim) {
                None | Some("") => Ok(None),
                Some(s) => s.parse().map(Some).map_err(|_| format!("{what} must be a number")),
            }
        }
        let timeout_secs = match num::<f64>(&self.timeout_minutes, "timeout")? {
            Some(m) if !m.is_finite() || m <= 0.0 => return Err("timeout must be positive".into()),
            Some(m) => Some((m * 60.0).round() as u64),
            None => None,
        };
        Ok(crate::settings::Changes {
            max_workers: num(&self.max_workers, "workers")?,
            max_scans_per_hour: num(&self.max_scans_per_hour, "scans per hour")?,
            timeout_secs,
            cooldown_hours: num(&self.cooldown_hours, "cooldown")?,
            listener: Some(self.listener.is_some()),
            scanner: Some(self.scanner.is_some()),
            web: Some(self.web.is_some()),
        })
    }
}

async fn set_own(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Redirect> {
    let changes = match f.changes() {
        Ok(c) => c,
        Err(e) => return Ok(back(None, Some(e))),
    };
    Ok(match st.settings.apply(&changes, None).await? {
        Ok(_) => back(Some("Settings saved. Roles switch within seconds.".into()), None),
        Err(e) => back(None, Some(format!("Settings not saved: {e}"))),
    })
}

async fn rotate_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Redirect> {
    let node = node(&st)?;
    crate::cluster::confkey::rotate(&node.store, node.id()).await?;
    Ok(back(
        Some("Config key rotated. Everyone who held the old key can no longer configure this node.".into()),
        None,
    ))
}

async fn add_key(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    Ok(match crate::cluster::confkey::add(&node.store, node.id(), &f.key).await {
        Ok(id) => Redirect::to(&format!("/admin/cluster/node/{id}")),
        Err(e) => back(None, Some(format!("{e:#}"))),
    })
}

async fn forget_key(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<KeyForm>,
) -> AppResult<Redirect> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&f.key) else {
        return Ok(back(None, Some("unknown node".into())));
    };
    crate::cluster::confkey::forget(&node.store, &id).await?;
    Ok(back(Some(format!("Config key for {} forgotten.", id.short())), None))
}

#[derive(Template)]
#[template(path = "admin_cluster_node.html")]
struct NodePage {
    chrome: Chrome,
    key: String,
    name: String,
    short: String,
    /// None: the node did not answer.
    state: Option<crate::cluster::confkey::State>,
    timeout_min: String,
    rec: Option<(u32, i64, String)>,
    key_held: bool,
    has: (bool, bool, bool),
    notice: Option<String>,
    error: Option<String>,
}

async fn node_view(st: &AdminState, key: &str, flash: Flash) -> AppResult<Html<String>> {
    let node = node(st)?;
    let Ok(id) = NodeId::parse(key) else {
        return Err(AppError::NotFound);
    };
    let Some(m) = members::all(&node.store).await?.into_iter().find(|m| m.id == id) else {
        return Err(AppError::NotFound);
    };
    let (state, error) = match crate::cluster::confkey::get(node, id).await {
        Ok(s) => (Some(s), flash.error),
        Err(e) => (None, Some(format!("{} did not answer: {e:#}", m.name))),
    };
    let minutes = |secs: u64| {
        if secs.is_multiple_of(60) {
            (secs / 60).to_string()
        } else {
            format!("{:.1}", secs as f64 / 60.0)
        }
    };
    let has = |s: &crate::cluster::confkey::State, r: &str| s.roles.iter().any(|x| x == r);
    render(&NodePage {
        chrome: Chrome::new(true, "admin"),
        key: id.to_string(),
        name: m.name,
        short: id.short(),
        timeout_min: state.as_ref().map(|s| minutes(s.pace.timeout_secs)).unwrap_or_default(),
        rec: state
            .as_ref()
            .and_then(|s| s.recommended)
            .map(|p| (p.max_workers, p.max_scans_per_hour, minutes(p.timeout_secs))),
        has: state
            .as_ref()
            .map(|s| (has(s, "listener"), has(s, "scanner"), has(s, "web")))
            .unwrap_or_default(),
        key_held: crate::cluster::confkey::held(&node.store).await?.contains(&id),
        state,
        notice: flash.notice,
        error,
    })
}

async fn node_page(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Query(flash): Query<Flash>,
) -> AppResult<Html<String>> {
    node_view(&st, &key, flash).await
}

async fn node_set(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Html<String>> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let flash = match (f.changes(), f.base_version) {
        (Err(e), _) => Flash {
            notice: None,
            error: Some(e),
        },
        (_, None) => Flash {
            notice: None,
            error: Some("reload the page and try again".into()),
        },
        (Ok(c), Some(base)) => match crate::cluster::confkey::set(node, id, base, &c).await {
            Ok(Ok(_)) => Flash {
                notice: Some("Saved. Roles switch within seconds.".into()),
                error: None,
            },
            Ok(Err(e)) => Flash {
                notice: None,
                error: Some(format!("Not saved: {e}")),
            },
            Err(e) => Flash {
                notice: None,
                error: Some(format!("Not saved: {e:#}")),
            },
        },
    };
    node_view(&st, &key, flash).await
}
```

Create `templates/admin_cluster_node.html`:

```html
{% extends "layout.html" %}
{% block title %}peephole — {{ name }}{% endblock %}
{% block content %}
<div class="page-head"><div><h1>{{ name }} <span class="mono muted">{{ short }}</span></h1><p class="muted">Runtime settings of another node, changed with its config key.</p></div>
  <nav class="seg"><a href="/admin/cluster">Cluster</a></nav></div>
{% if let Some(n) = notice %}<div class="banner banner-success">{{ n }}</div>{% endif %}
{% if let Some(e) = error %}<div class="banner banner-warning">{{ e }}</div>{% endif %}
{% if let Some(s) = state %}
{% if !s.open %}<div class="banner banner-warning">This node is locked: its operator has not switched remote configuration on, so a config key does nothing here.</div>{% endif %}
{% if !key_held %}<div class="banner banner-warning">You hold no config key for this node. Ask its operator for one and add it on the Cluster page.</div>{% endif %}
<section class="card">
  <div class="card-head"><h2>Settings</h2><span class="muted">version {{ s.version }}</span></div>
  <form method="post" action="/admin/cluster/node/{{ key }}" class="filters">
    <input type="hidden" name="base_version" value="{{ s.version }}">
    <label>Workers <input type="number" name="max_workers" min="0" max="16" value="{{ s.pace.max_workers }}" required></label>
    <label>Scans per hour <input type="number" name="max_scans_per_hour" min="0" max="3600" value="{{ s.pace.max_scans_per_hour }}" required></label>
    <label>Timeout (min) <input type="number" name="timeout_minutes" min="1" max="240" step="any" value="{{ timeout_min }}" required></label>
    <label>Rescan cooldown (h) <input type="number" name="cooldown_hours" min="0" max="8760" value="{{ s.cooldown_hours }}" required></label>
    <label><input type="checkbox" name="listener"{% if has.0 %} checked{% endif %}> Trap</label>
    <label><input type="checkbox" name="scanner"{% if has.1 %} checked{% endif %}> Scanner</label>
    <label><input type="checkbox" name="web"{% if has.2 %} checked{% endif %}> Web interface</label>
    <button class="btn btn-primary" type="submit"{% if !s.open || !key_held %} disabled{% endif %}>Save</button>
  </form>
  {% if let Some(r) = rec %}<p class="muted">Recommended pace from this node's queue: {{ r.0 }} workers, {{ r.1 }} scans per hour, {{ r.2 }} min timeout.</p>{% endif %}
  <p class="muted">Switching a role on needs its settings in that node's config file. Switching the web interface off removes that node's own admin pages; its operator restores them with <code>peephole settings reset roles.web</code>.</p>
</section>
{% endif %}
{% endblock %}
```

In `templates/admin_cluster.html`:

- In the "This node" card, after the `</dl>`:

```html
  {% if let Some(s) = settings %}
  <form method="post" action="/admin/cluster/settings" class="filters">
    <label>Rescan cooldown (h) <input type="number" name="cooldown_hours" min="0" max="8760" value="{{ s.cooldown_hours }}" required></label>
    <label title="{{ s.listener_missing }}"><input type="checkbox" name="listener"{% if s.listener %} checked{% endif %}{% if !s.listener && !s.listener_missing.is_empty() %} disabled{% endif %}> Trap</label>
    <label title="{{ s.scanner_missing }}"><input type="checkbox" name="scanner"{% if s.scanner %} checked{% endif %}{% if !s.scanner && !s.scanner_missing.is_empty() %} disabled{% endif %}> Scanner</label>
    <label title="{{ s.web_missing }}"><input type="checkbox" name="web"{% if s.web %} checked{% endif %}{% if !s.web && !s.web_missing.is_empty() %} disabled{% endif %}> Web interface</label>
    <button class="btn btn-sm" type="submit">Save</button>
    <span class="muted">settings version {{ s.version }}; the pace is set below</span>
  </form>
  {% endif %}
  {% if remote_config %}
  <h3>Config key</h3>
  <p class="muted">Whoever holds this key can change this node's scan pace, rescan cooldown and roles from their own node. Rotating it withdraws that from everyone.</p>
  {% if let Some(k) = config_key %}<details><summary>Show key</summary><pre class="panel mono break" data-copy>{{ k }}</pre></details>{% endif %}
  <form method="post" action="/admin/cluster/config-key/rotate"><button class="btn btn-sm btn-danger" type="submit">Rotate key</button></form>
  {% if !audit.is_empty() %}
  <div class="table-wrap"><table><thead><tr><th>When (UTC)</th><th>By</th><th>Change</th></tr></thead>
    <tbody>{% for a in audit %}<tr><td class="ts">{{ a.at }}</td><td>{{ a.by }}</td><td class="mono">{{ a.changes }}</td></tr>{% endfor %}</tbody></table></div>
  {% endif %}
  {% else %}
  <p class="muted">Remote configuration: <b>locked</b>. Only this page, the CLI and the config file change this node's settings. To let others do it, set <code>remote_config = true</code> under <code>[cluster]</code>.</p>
  {% endif %}
```

- In the members table add a column header `<th>Settings</th>` before the last empty `<th></th>` and the cell before the block/unblock cell:

```html
        <td>{% if m.key_held %}<a class="btn btn-sm" href="/admin/cluster/node/{{ m.key }}">Configure</a>{% else if m.remote_config %}<span class="muted">open for config key holders</span>{% else %}<span class="muted">locked</span>{% endif %}</td>
```

  and raise the `colspan` of the empty row by one.
- After the Invites card add:

```html
<section class="card">
  <div class="card-head"><h2>Configure another node</h2></div>
  <p class="muted">Paste a config key its operator gave you. The key says which node it belongs to.</p>
  <form method="post" action="/admin/cluster/config-key/add" class="filters"><label>Config key <input name="key" size="60" class="mono" required></label><button class="btn btn-primary" type="submit">Add key</button></form>
</section>
```

- `templates/_cluster_pace_row.html`: other nodes' pace is changed on their node page now. Wrap the three inputs and the Save button in `{% if m.is_self %}…{% else %}` showing the values as text (`<td>{{ p.max_workers }}</td><td>{{ p.max_scans_per_hour }}</td><td>{{ m.timeout_min }}</td><td>{% if m.key_held %}<a href="/admin/cluster/node/{{ m.key }}">Configure</a>{% endif %}</td>`) `{% endif %}`.

- [ ] **Step 5: Documentation.** `README.md`, in "Distributed mode" after the "How trust works" list, add:

```markdown
Changing another node's settings:

- A node's scan pace, rescan cooldown and roles are runtime settings. Its
  own admin (Cluster page, or `peephole settings set|reset|show`) can always
  change them, and roles switch without a restart.
- With `remote_config = true` under `[cluster]`, the node has a **config
  key** (`peephole cluster config-key show`). Whoever holds it can change
  those settings from their own node: paste the key on their Cluster page,
  or `peephole cluster config-key add <key>`.
- `peephole cluster config-key rotate` replaces the key and withdraws the
  permission from everyone at once. The node lists who changed what.
- Nothing else is changeable from outside: addresses, paths, WebAuthn, API
  keys, `never_scan`, nmap arguments and `remote_config` itself stay in the
  config file.
```

`deploy/config.example.toml`, in the commented `[cluster]` block after `lease_secs`:

```toml
# remote_config  = false            # true: holders of this node's config key may change its
#                                   # scan pace, rescan cooldown and roles (peephole cluster config-key show)
```

- [ ] **Step 6: Run everything**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(admin): configure own and other nodes' runtime settings; config key CLI; docs"
```
