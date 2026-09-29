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

fn default_workers() -> usize { 2 }
fn default_timeout() -> u64 { 900 }
fn default_cooldown() -> i64 { 24 }
fn default_rate() -> i64 { 30 }

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

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
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
        match level {
            1 => "-sS -T2 --top-ports 100",
            2 => "-sS -sV -T3 --top-ports 1000",
            3 => "-sS -sV -O -T3 -p- --script=default",
            4 => "-sS -sV -O -A -T4 -p- --script=default,intrusive",
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

    #[test]
    fn loads_minimal_valid_config() {
        let dir = std::env::temp_dir().join(format!("peephole-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, r#"
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
"#).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.trap_listen.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.webauthn.rp_id, "peephole.example.net");
        assert_eq!(cfg.scan.max_workers, 2);
        assert_eq!(cfg.scan.never_scan.len(), 1);
        assert_eq!(cfg.default_level_argv(4)[0], "-sS");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_missing_webauthn() {
        let dir = std::env::temp_dir().join(format!("peephole-cfg2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "/tmp/x.db"
data_dir = "/tmp"
rules_dir = "/tmp/rules"
[maxmind]
account_id = "1"
license_key = "k"
"#).unwrap();
        assert!(Config::load(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
