//! Runtime settings: the values an operator may change while the node runs
//! (scan workers, roles). The TOML gives the defaults; rows in
//! the `settings` table override them. Every change, from the local admin
//! UI, the CLI or the owner, goes through [`Settings::apply`].
use crate::cluster::identity::NodeId;
use crate::config::{Config, Roles};
use crate::scan::pace::{self, Pace, SharedPace};
use crate::store::Store;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub const KEY_ROLE_LISTENER: &str = "roles.listener";
pub const KEY_ROLE_SCANNER: &str = "roles.scanner";
pub const KEY_ROLE_WEB: &str = "roles.web";
const KEY_VERSION: &str = "settings.version";

/// Every key a runtime override can use. Rows of keys earlier versions
/// had (the hourly start cap, the scan timeout, the rescan cooldown) are
/// ignored.
pub const KEYS: [&str; 4] = [
    pace::KEY_WORKERS,
    KEY_ROLE_LISTENER,
    KEY_ROLE_SCANNER,
    KEY_ROLE_WEB,
];

/// A set of changes; absent fields stay as they are. Fields an earlier
/// version sends that this one no longer has are ignored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Changes {
    pub max_workers: Option<u32>,
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

    /// Take over every field `other` sets.
    pub fn merge(&mut self, other: Self) {
        self.max_workers = other.max_workers.or(self.max_workers);
        self.listener = other.listener.or(self.listener);
        self.scanner = other.scanner.or(self.scanner);
        self.web = other.web.or(self.web);
    }

    /// Which key is which field: the one place that says so, in the order
    /// of [`KEYS`].
    fn fields(&mut self) -> [(&'static str, Field<'_>); 4] {
        [
            (pace::KEY_WORKERS, Field::Number(&mut self.max_workers)),
            (KEY_ROLE_LISTENER, Field::Flag(&mut self.listener)),
            (KEY_ROLE_SCANNER, Field::Flag(&mut self.scanner)),
            (KEY_ROLE_WEB, Field::Flag(&mut self.web)),
        ]
    }

    /// The fields this set gives, as `(key, value)` the way the CLI takes
    /// them and the settings table stores them.
    pub fn pairs(&self) -> Vec<(&'static str, String)> {
        let mut c = self.clone();
        c.fields()
            .into_iter()
            .filter_map(|(key, f)| f.value().map(|v| (key, v)))
            .collect()
    }

    /// One `key value` pair from the CLI.
    pub fn from_key_value(key: &str, value: &str) -> Result<Self, String> {
        let mut c = Self::default();
        let Some((_, field)) = c.fields().into_iter().find(|(k, _)| *k == key) else {
            return Err(format!(
                "`{key}` is not a runtime setting (one of: {})",
                KEYS.join(", ")
            ));
        };
        field.parse(key, value)?;
        Ok(c)
    }
}

/// Every setting of `s`, as a change (what `peephole settings show` lists).
impl From<Snapshot> for Changes {
    fn from(s: Snapshot) -> Self {
        Self {
            max_workers: Some(s.pace.max_workers as u32),
            listener: Some(s.roles.listener),
            scanner: Some(s.roles.scanner),
            web: Some(s.roles.web),
        }
    }
}

/// A field of [`Changes`], by its type.
enum Field<'a> {
    Number(&'a mut Option<u32>),
    Flag(&'a mut Option<bool>),
}

impl Field<'_> {
    fn value(&self) -> Option<String> {
        match self {
            Field::Number(v) => v.map(|v| v.to_string()),
            Field::Flag(v) => v.map(|v| v.to_string()),
        }
    }

    fn parse(self, key: &str, value: &str) -> Result<(), String> {
        match self {
            Field::Number(v) => {
                let n = value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| format!("{key}: `{value}` is not a number"))?;
                *v = Some(n.clamp(0, u32::MAX as i64) as u32);
            }
            Field::Flag(v) => {
                *v = Some(match value.trim() {
                    "true" | "on" | "1" => true,
                    "false" | "off" | "0" => false,
                    _ => return Err(format!("{key}: use true or false")),
                });
            }
        }
        Ok(())
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
        let listener = cfg
            .trap_listen
            .is_none()
            .then(|| "trap_listen is not set in the config file".to_string());
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
    pub roles: Roles,
    pub version: u64,
}

/// `current` with `c` applied, or why not. The version is left alone.
pub fn validate(current: Snapshot, c: &Changes, prereqs: &Prereqs) -> Result<Snapshot, String> {
    let mut s = current;
    if let Some(x) = c.max_workers {
        s.pace.max_workers = x as usize;
    }
    s.pace.validate()?;
    for (new, cur, missing, name) in [
        (c.listener, &mut s.roles.listener, &prereqs.listener, "trap"),
        (c.scanner, &mut s.roles.scanner, &prereqs.scanner, "scanner"),
        (c.web, &mut s.roles.web, &prereqs.web, "web interface"),
    ] {
        let Some(new) = new else { continue };
        if new
            && !*cur
            && let Some(why) = missing
        {
            return Err(format!("the {name} role cannot be switched on: {why}"));
        }
        *cur = new;
    }
    if !(s.roles.listener || s.roles.scanner || s.roles.web) {
        return Err("at least one role must stay on".into());
    }
    Ok(s)
}

/// Stored overrides left out, by key, with why.
type Dropped = Vec<(&'static str, String)>;

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
    /// A stored override was ignored and said so (once, not every reload).
    warned_ignored: Arc<std::sync::atomic::AtomicBool>,
}

fn defaults(cfg: &Config) -> Snapshot {
    Snapshot {
        pace: Pace::new(cfg.scan.max_workers),
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
            warned_ignored: Default::default(),
        }
    }

    pub async fn load(store: &Store, cfg: &Config, prereqs: Prereqs) -> Result<Self> {
        let d = defaults(cfg);
        let pace = SharedPace::new(d.pace);
        let mut s = Self::with_pace(store.clone(), cfg, pace);
        s.prereqs = Arc::new(prereqs);
        s.reload().await?;
        Ok(s)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            pace: self.pace.get(),
            roles: self.roles(),
            version: self.version.load(Ordering::Relaxed),
        }
    }

    /// The config file's values: what a reset goes back to.
    pub fn defaults(&self) -> Snapshot {
        self.defaults
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

    /// The settings as the database has them: defaults plus overrides, and
    /// the overrides left out. The overrides are judged together (switching
    /// one role off and another on is fine as a whole); one the build would
    /// refuse is left out with why, the rest still count. Read on `conn`: a
    /// writer passes its transaction, so it never waits for a second
    /// connection while it holds the write lock.
    async fn stored(&self, conn: &mut sqlx::SqliteConnection) -> Result<(Snapshot, Dropped)> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings")
            .fetch_all(&mut *conn)
            .await?;
        let mut s = self.defaults;
        let mut all = Changes::default();
        for (k, v) in &rows {
            if k == KEY_VERSION {
                s.version = v.parse().unwrap_or(0);
            } else if KEYS.contains(&k.as_str())
                && let Ok(c) = Changes::from_key_value(k, v)
            {
                all.merge(c);
            }
        }
        // A single worker was valid before the minimum of 2; raise it so the
        // other saved overrides are not thrown away with it.
        if all.max_workers == Some(1) {
            all.max_workers = Some(pace::MIN_WORKERS as u32);
        }
        let mut dropped = Dropped::new();
        // An override cannot switch on a role the config file no longer
        // has the sections for (its listener or `[webauthn]` removed since):
        // starting it would fail or panic. The rest are trusted like the
        // TOML (nmap is checked by the scanner).
        for (want, on, missing, key) in [
            (
                &mut all.listener,
                s.roles.listener,
                &self.prereqs.listener,
                KEY_ROLE_LISTENER,
            ),
            (&mut all.web, s.roles.web, &self.prereqs.web, KEY_ROLE_WEB),
        ] {
            if *want == Some(true)
                && !on
                && let Some(why) = missing
            {
                dropped.push((key, why.clone()));
                *want = None;
            }
        }
        let none = Prereqs::default();
        let workers = Changes {
            max_workers: all.max_workers,
            ..Default::default()
        };
        if let Err(why) = validate(s, &workers, &none) {
            dropped.push((pace::KEY_WORKERS, why));
            all.max_workers = None;
        }
        // No role left on: the overrides switching one off go (the TOML has
        // one on).
        if let Err(why) = validate(s, &all, &none) {
            for (want, key) in [
                (&mut all.listener, KEY_ROLE_LISTENER),
                (&mut all.scanner, KEY_ROLE_SCANNER),
                (&mut all.web, KEY_ROLE_WEB),
            ] {
                if *want == Some(false) {
                    dropped.push((key, why.clone()));
                    *want = None;
                }
            }
        }
        // Reloaded every few seconds: say it once per process.
        if !dropped.is_empty() && !self.warned_ignored.swap(true, Ordering::Relaxed) {
            for (key, why) in &dropped {
                tracing::warn!(
                    key,
                    why,
                    "a stored runtime setting is ignored (`peephole settings reset {key}` drops it)"
                );
            }
        }
        Ok((validate(s, &all, &none).unwrap_or(s), dropped))
    }

    fn adopt(&self, s: Snapshot) {
        self.pace.replace(s.pace);
        *self.roles.write().unwrap() = s.roles;
        self.version.store(s.version, Ordering::Relaxed);
        self.changed.send_replace(s.version);
    }

    /// Re-read the database (another process may have written); true if
    /// anything changed.
    pub async fn reload(&self) -> Result<bool> {
        // Under the writers' lock: a write committed and adopted between
        // the read and the adopt would otherwise be rolled back in memory.
        let _g = self.lock.lock().await;
        let (s, _) = self.stored(&mut *self.store.pool.acquire().await?).await?;
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
        let (current, ignored) = self.stored(&mut tx).await?;
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
        for (key, value) in c.pairs() {
            self.set(&mut tx, key, value).await?;
        }
        next.version = current.version + 1;
        self.set(&mut tx, KEY_VERSION, next.version.to_string())
            .await?;
        // The stored set must give what was judged: a stored override
        // ignored so far must not apply again with it.
        let (after, _) = self.stored(&mut tx).await?;
        if after != next {
            let back: Vec<&str> = ignored.iter().map(|(k, _)| *k).collect();
            return Ok(Err(format!(
                "a saved setting ignored so far would apply again with this change ({}); \
                 `peephole settings reset KEY` drops it",
                back.join(", ")
            )));
        }
        if let Some(by) = by {
            sqlx::query(
                "INSERT INTO config_audit (at, by, changes) VALUES (datetime('now'), ?, ?)",
            )
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
        let (before, ignored) = self.stored(&mut tx).await?;
        let version = before.version + 1;
        for k in KEYS {
            if key.is_none_or(|only| only == k) {
                sqlx::query("DELETE FROM settings WHERE key = ?")
                    .bind(k)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        self.set(&mut tx, KEY_VERSION, version.to_string()).await?;
        // The overrides kept must still be usable without the reset ones.
        let (s, dropped) = self.stored(&mut tx).await?;
        if let Some((k, why)) = dropped.iter().find(|d| !ignored.contains(d)) {
            return Ok(Err(format!(
                "resetting {} would leave {k} unusable ({why}); reset {k} too",
                key.unwrap_or("all runtime settings")
            )));
        }
        tx.commit().await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(extra: &str) -> Config {
        toml::from_str(&format!(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n{extra}"
        ))
        .unwrap()
    }

    fn snap(roles: (bool, bool, bool)) -> Snapshot {
        Snapshot {
            pace: Pace::new(2),
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
                ..Default::default()
            },
            &Prereqs::default(),
        )
        .unwrap();
        assert_eq!(out.pace.max_workers, 4);
        assert!(out.roles.scanner);
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
        assert!(Changes::from_key_value("scan.rescan_cooldown_hours", "48").is_err());
        assert!(Changes::from_key_value("roles.web", "maybe").is_err());
        assert!(Changes::default().is_empty());
    }

    /// Every key maps to one field and back, the way the settings table
    /// stores it; a snapshot lists every key with its value.
    #[test]
    fn every_key_is_one_field() {
        for (key, value) in [
            (pace::KEY_WORKERS, "3"),
            (KEY_ROLE_LISTENER, "false"),
            (KEY_ROLE_SCANNER, "true"),
            (KEY_ROLE_WEB, "false"),
        ] {
            let c = Changes::from_key_value(key, value).unwrap();
            assert_eq!(c.pairs(), [(key, value.to_string())]);
        }
        let all = Changes::from(snap((true, false, true)));
        let keys: Vec<&str> = all.pairs().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, KEYS);
        assert_eq!(all.pairs()[2], (KEY_ROLE_SCANNER, "false".to_string()));
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

    /// A stored single worker (from before the minimum of 2) is raised to 2
    /// on load; the other saved overrides, roles included, survive, and
    /// rows of keys earlier versions had are ignored.
    #[tokio::test]
    async fn a_stored_single_worker_is_raised_and_other_overrides_survive() {
        let (s, store, _d) = open("").await;
        for (k, v) in [
            (pace::KEY_WORKERS, "1"),
            ("scan.max_scans_per_hour", "11"),
            ("scan.timeout_secs", "60"),
            ("scan.rescan_cooldown_hours", "0"),
            (KEY_ROLE_SCANNER, "false"),
        ] {
            sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?)")
                .bind(k)
                .bind(v)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        drop(s);
        let loaded = Settings::load(&store, &cfg(""), Prereqs::default())
            .await
            .unwrap();
        let snap = loaded.snapshot();
        assert_eq!(snap.pace, Pace::new(2));
        assert!(!snap.roles.scanner);
        assert_eq!(loaded.pace.cooldown_hours(), pace::COOLDOWN_HOURS);
    }

    /// A stored `roles.web = true` does not switch on a web role whose
    /// `[webauthn]` was removed from the config since.
    #[tokio::test]
    async fn a_stored_role_override_needs_the_config_sections() {
        let (s, store, _d) = open("").await;
        for (k, v) in [(KEY_ROLE_WEB, "true"), (pace::KEY_WORKERS, "3")] {
            sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?)")
                .bind(k)
                .bind(v)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        drop(s);
        let c = cfg("[roles]\nweb = false\n");
        let loaded = Settings::load(&store, &c, Prereqs::from_config(&c, true))
            .await
            .unwrap();
        assert!(!loaded.snapshot().roles.web);
        assert_eq!(loaded.snapshot().pace.max_workers, 3);
    }

    #[tokio::test]
    async fn overrides_persist_bump_the_version_and_reset_to_toml() {
        let (s, store, _d) = open("[roles]\nweb = false\n[scan]\nmax_workers = 3\n").await;
        let before = s.snapshot();
        assert_eq!((before.pace.max_workers, before.version), (3, 0));
        let v = s
            .apply(
                &Changes {
                    max_workers: Some(4),
                    scanner: Some(false),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v, 1);
        assert_eq!(s.pace.get().max_workers, 4);
        assert!(!s.roles().scanner);
        // A second handle on the same database (the CLI, or a restart) sees it.
        let again = Settings::load(&store, &cfg("[roles]\nweb = false\n"), Prereqs::default())
            .await
            .unwrap();
        assert_eq!(again.snapshot().pace.max_workers, 4);
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
        s.reset(Some(pace::KEY_WORKERS)).await.unwrap().unwrap();
        assert_eq!(s.snapshot().pace.max_workers, 3);
        assert!(!s.snapshot().roles.scanner);
        s.reset(None).await.unwrap().unwrap();
        let end = s.snapshot();
        assert!(end.roles.scanner);
        assert_eq!(end.pace.max_workers, 3);
        assert!(s.reset(Some("no.such.key")).await.unwrap().is_err());
    }

    async fn store_rows(store: &crate::store::Store, rows: &[(&str, &str)]) {
        for (k, v) in rows {
            sqlx::query("INSERT INTO settings (key, value) VALUES (?, ?)")
                .bind(k)
                .bind(v)
                .execute(&store.pool)
                .await
                .unwrap();
        }
    }

    /// A stored override the build refuses is left out alone: the others
    /// still count.
    #[tokio::test]
    async fn an_unusable_stored_override_drops_only_itself() {
        let only_trap = "[roles]\nscanner = false\nweb = false\n";
        let (s, store, _d) = open(only_trap).await;
        // No role would be left on: the listener override goes, not the workers.
        store_rows(
            &store,
            &[(KEY_ROLE_LISTENER, "false"), (pace::KEY_WORKERS, "3")],
        )
        .await;
        assert!(s.reload().await.unwrap());
        let now = s.snapshot();
        assert!(now.roles.listener);
        assert_eq!(now.pace.max_workers, 3);
        // An out-of-range worker count goes; the role overrides stay.
        let (s, store, _d) = open("").await;
        store_rows(
            &store,
            &[(pace::KEY_WORKERS, "999"), (KEY_ROLE_WEB, "false")],
        )
        .await;
        assert!(s.reload().await.unwrap());
        let now = s.snapshot();
        assert_eq!(now.pace.max_workers, 2);
        assert!(!now.roles.web);
    }

    /// A reset that would leave the other overrides unusable is refused,
    /// and so is a write that would bring back an override ignored so far.
    #[tokio::test]
    async fn resets_and_writes_keep_the_stored_overrides_usable() {
        let only_trap = "[roles]\nscanner = false\nweb = false\n";
        let (s, store, _d) = open(only_trap).await;
        let swap = Changes {
            listener: Some(false),
            scanner: Some(true),
            ..Default::default()
        };
        assert_eq!(s.apply(&swap, None).await.unwrap(), Ok(1));
        let e = s.reset(Some(KEY_ROLE_SCANNER)).await.unwrap().unwrap_err();
        assert!(e.contains(KEY_ROLE_LISTENER), "{e}");
        let again = Settings::load(&store, &cfg(only_trap), Prereqs::default())
            .await
            .unwrap()
            .snapshot();
        assert_eq!((again.roles.scanner, again.version), (true, 1));
        assert_eq!(s.reset(None).await.unwrap(), Ok(2));
        // An ignored `roles.listener = false` would apply again once the
        // scanner is on: refused, nothing written.
        store_rows(&store, &[(KEY_ROLE_LISTENER, "false")]).await;
        s.reload().await.unwrap();
        assert!(s.snapshot().roles.listener);
        let on = Changes {
            scanner: Some(true),
            ..Default::default()
        };
        let e = s.apply(&on, None).await.unwrap().unwrap_err();
        assert!(e.contains(KEY_ROLE_LISTENER), "{e}");
        assert!(!s.snapshot().roles.scanner);
        assert_eq!(s.snapshot().version, 2);
    }

    /// A write reads the settings in its own transaction: holding the write
    /// lock, it never waits for a second connection the busy pool cannot
    /// give (every other writer would wait behind it).
    #[tokio::test]
    async fn writes_need_one_connection_only() {
        let (s, store, _d) = open("").await;
        let mut held = vec![];
        while held.len() + 1 < store.pool.options().get_max_connections() as usize {
            held.push(store.pool.acquire().await.unwrap());
        }
        let c = Changes {
            max_workers: Some(3),
            ..Default::default()
        };
        let quick = std::time::Duration::from_secs(5);
        let applied = tokio::time::timeout(quick, s.apply(&c, None)).await;
        assert_eq!(
            applied.expect("apply waited for a connection").unwrap(),
            Ok(1)
        );
        let reset = tokio::time::timeout(quick, s.reset(None)).await;
        assert_eq!(
            reset.expect("reset waited for a connection").unwrap(),
            Ok(2)
        );
        assert_eq!(s.snapshot().pace.max_workers, 2);
    }

    #[tokio::test]
    async fn apply_at_refuses_a_stale_version_and_remote_changes_are_audited() {
        let (s, _store, _d) = open("").await;
        let who = crate::cluster::identity::Identity::generate().unwrap().id;
        let c = Changes {
            max_workers: Some(7),
            ..Default::default()
        };
        assert_eq!(s.apply_at(0, &c, Some(who)).await.unwrap(), Ok(1));
        let e = s.apply_at(0, &c, Some(who)).await.unwrap().unwrap_err();
        assert!(e.contains("changed meanwhile"), "{e}");
        let audit = s.audit(10).await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].by, Some(who));
        assert_eq!(audit[0].changes, "workers=7");
        // An empty change proves the caller may configure; it changes nothing.
        assert_eq!(
            s.apply_at(1, &Changes::default(), Some(who)).await.unwrap(),
            Ok(1)
        );
        assert_eq!(s.audit(10).await.unwrap().len(), 1);
    }
}
