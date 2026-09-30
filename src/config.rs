use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub trap_listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub database_path: PathBuf,
    pub data_dir: PathBuf,
    pub rules_dir: PathBuf,
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    pub webauthn: WebauthnConfig,
    pub maxmind: MaxmindConfig,
    #[serde(default)]
    pub scan: ScanConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebauthnConfig {
    pub rp_id: String,
    pub origin: String,
    pub rp_name: String,
    /// `Secure` flag on the session cookie. Leave `true`; tests over plain
    /// http set it to `false`.
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct MaxmindConfig {
    pub account_id: String,
    pub license_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanConfig {
    #[serde(default = "default_workers")]
    pub max_workers: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_cooldown")]
    pub rescan_cooldown_hours: i64,
    #[serde(default = "default_rate")]
    pub max_scans_per_hour: i64,
    #[serde(default)]
    pub never_scan: Vec<IpNet>,
    /// Optional per-level argv overrides; `{target}` is replaced with the IP.
    #[serde(default)]
    pub level_argv: std::collections::HashMap<u8, Vec<String>>,
}

fn default_workers() -> usize {
    2
}
fn default_timeout() -> u64 {
    // Full-range levels (-p- -sV -O) on filtered hosts need well over 15 min.
    1800
}
fn default_cooldown() -> i64 {
    24
}
fn default_rate() -> i64 {
    30
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_workers: default_workers(),
            timeout_secs: default_timeout(),
            rescan_cooldown_hours: default_cooldown(),
            max_scans_per_hour: default_rate(),
            never_scan: vec![],
            level_argv: Default::default(),
        }
    }
}

/// Optional settings and their defaults, so `check-config` can point out
/// keys an older config predates. (`table`, `key`, `default`)
const OPTIONAL_KEYS: &[(&str, &str, &str)] = &[
    ("", "trusted_proxies", "[]"),
    ("webauthn", "secure_cookies", "true"),
    ("scan", "max_workers", "2"),
    ("scan", "timeout_secs", "1800"),
    ("scan", "rescan_cooldown_hours", "24"),
    ("scan", "max_scans_per_hour", "30"),
    ("scan", "never_scan", "[]"),
];

/// One human-readable note per optional key the file does not set.
/// Unparsable files yield no notes; `load` reports those errors.
pub fn optional_key_notes(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(doc) = text.parse::<toml::Table>() else {
        return vec![];
    };
    let mut notes = vec![];
    let mut missing_tables = std::collections::BTreeSet::new();
    for (table, key, default) in OPTIONAL_KEYS {
        let present = if table.is_empty() {
            doc.get(*key).is_some()
        } else {
            match doc.get(*table) {
                Some(t) => t.get(*key).is_some(),
                None => {
                    missing_tables.insert(*table);
                    continue;
                }
            }
        };
        if !present {
            let full = if table.is_empty() {
                key.to_string()
            } else {
                format!("{table}.{key}")
            };
            notes.push(format!(
                "note: optional `{full}` not set (default {default})"
            ));
        }
    }
    for t in missing_tables {
        notes.push(format!(
            "note: optional [{t}] section absent; defaults apply (see deploy/config.example.toml)"
        ));
    }
    notes
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config = toml::from_str(&text).context("parsing config.toml")?;
        if cfg.webauthn.rp_id.is_empty() || cfg.webauthn.origin.starts_with("http://") {
            bail!("webauthn.rp_id must be set and origin must be https");
        }
        Ok(cfg)
    }

    /// Default nmap arguments per scan level (spec §5), without the target.
    /// Operator overrides come from `scan.level_argv`.
    pub fn default_level_argv(&self, level: u8) -> Vec<String> {
        if let Some(custom) = self.scan.level_argv.get(&level) {
            return custom.clone();
        }
        // -Pn: the target just connected to us, so it is up; nmap's own
        // discovery probes are often filtered and would report it down.
        // Full-range levels cap retransmissions so filtered ports don't
        // stretch a scan past the timeout.
        match level {
            1 => "-Pn -sS -T2 --top-ports 100",
            2 => "-Pn -sS -sV -T3 --top-ports 1000",
            3 => "-Pn -sS -sV -O -T4 --max-retries 2 -p- --script=default",
            4 => "-Pn -sS -sV -O -A -T4 --max-retries 2 -p- --script=default,intrusive",
            _ => "",
        }
        .split_whitespace()
        .map(str::to_string)
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target just connected to us, so it is up. Without -Pn nmap's own
    /// discovery probes (often filtered) decide "down" and nothing is scanned.
    #[test]
    fn default_presets_skip_host_discovery() {
        let cfg: Config = toml::from_str(
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "/tmp/x.db"
data_dir = "/tmp"
rules_dir = "rules"
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
[maxmind]
account_id = "1"
license_key = "k"
"#,
        )
        .unwrap();
        for level in 1..=4 {
            let argv = cfg.default_level_argv(level);
            assert!(argv.iter().any(|a| a == "-Pn"), "level {level}: {argv:?}");
        }
    }

    #[test]
    fn loads_minimal_valid_config() {
        let dir = std::env::temp_dir().join(format!("peephole-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "/var/lib/peephole/peephole.db"
data_dir = "/var/lib/peephole"
rules_dir = "/etc/peephole/rules"
trusted_proxies = ["10.0.0.0/8"]

[webauthn]
rp_id = "peephole.example.net"
origin = "https://peephole.example.net"
rp_name = "peephole"

[maxmind]
account_id = "123456"
license_key = "testkey"

[scan]
max_workers = 2
timeout_secs = 900
rescan_cooldown_hours = 24
max_scans_per_hour = 30
never_scan = ["192.168.0.0/16"]
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.trap_listen.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.webauthn.rp_id, "peephole.example.net");
        assert_eq!(cfg.scan.max_workers, 2);
        assert_eq!(cfg.scan.never_scan.len(), 1);
        assert!(cfg.default_level_argv(4).iter().any(|a| a == "-sS"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_missing_webauthn() {
        let dir = std::env::temp_dir().join(format!("peephole-cfg2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "/tmp/x.db"
data_dir = "/tmp"
rules_dir = "/tmp/rules"
[maxmind]
account_id = "1"
license_key = "k"
"#,
        )
        .unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
