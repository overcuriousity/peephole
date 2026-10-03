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
pub const MAX_COOLDOWN_HOURS: i64 = 24 * 365;

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

    /// Take over every field `other` sets.
    pub fn merge(&mut self, other: Self) {
        self.max_workers = other.max_workers.or(self.max_workers);
        self.max_scans_per_hour = other.max_scans_per_hour.or(self.max_scans_per_hour);
        self.timeout_secs = other.timeout_secs.or(self.timeout_secs);
        self.cooldown_hours = other.cooldown_hours.or(self.cooldown_hours);
        self.listener = other.listener.or(self.listener);
        self.scanner = other.scanner.or(self.scanner);
        self.web = other.web.or(self.web);
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

    /// The settings as the database has them: defaults plus overrides. The
    /// overrides are judged together (switching one role off and another on
    /// is fine as a whole); if the build would refuse them, the defaults
    /// stand.
    async fn stored(&self) -> Result<Snapshot> {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, value FROM settings")
            .fetch_all(&self.store.pool)
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
        // Overrides are trusted like the TOML: no prerequisite check here.
        Ok(validate(s, &all, &Prereqs::default()).unwrap_or(s))
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
        // Under the writers' lock: a write committed and adopted between
        // the read and the adopt would otherwise be rolled back in memory.
        let _g = self.lock.lock().await;
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
            (
                pace::KEY_PER_HOUR,
                c.max_scans_per_hour.map(|v| v.to_string()),
            ),
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
        let (s, store, _d) =
            open("[roles]\nweb = false\n[scan]\nrescan_cooldown_hours = 12\n").await;
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
        assert_eq!(
            s.apply_at(1, &Changes::default(), Some(who)).await.unwrap(),
            Ok(1)
        );
        assert_eq!(s.audit(10).await.unwrap().len(), 1);
    }
}
