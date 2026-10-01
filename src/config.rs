use anyhow::{Context, bail};
use ipnet::IpNet;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub roles: Roles,
    /// Required with the listener role.
    pub trap_listen: Option<SocketAddr>,
    /// Required with the web role.
    pub admin_listen: Option<SocketAddr>,
    pub database_path: PathBuf,
    pub data_dir: PathBuf,
    /// Required with the listener role.
    pub rules_dir: Option<PathBuf>,
    #[serde(default)]
    pub trusted_proxies: Vec<IpNet>,
    /// Required with the web role.
    pub webauthn: Option<WebauthnConfig>,
    /// Optional: without credentials GeoIP enrichment is unavailable.
    pub maxmind: Option<MaxmindConfig>,
    #[serde(default)]
    pub scan: ScanConfig,
    /// Distributed mode. Absent: standalone, no RPC listener.
    pub cluster: Option<ClusterConfig>,
}

/// `[cluster]`: this node's RPC endpoint and its bootstrap peers.
#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    /// Label shown in the admin UI (never on public pages).
    pub node_name: String,
    /// RPC listener (mutual TLS with pinned node keys).
    pub listen: SocketAddr,
    /// `host:port` other nodes dial. Absent: outbound-only node.
    pub advertise: Option<String>,
    /// Node key; generated on first start. Default: `<data_dir>/node.key`.
    pub key_path: Option<PathBuf>,
    /// Adopt an unreachable origin's queued jobs after this many hours.
    #[serde(default = "default_takeover_hours")]
    pub takeover_hours: u64,
    /// Scan lease length; renewed while nmap runs.
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

fn default_takeover_hours() -> u64 {
    6
}
fn default_lease_secs() -> u64 {
    120
}

/// `[[cluster.peers]]`: a node this one vouches for and dials.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    pub name: String,
    /// `host:port` of the peer's RPC listener.
    pub address: String,
    /// `ed25519:<base64url>` as printed by `peephole cluster id`.
    pub public_key: String,
}

/// What this deployment does. All on by default (a single standalone node).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
pub struct Roles {
    /// Trap listener: records and classifies requests, enqueues scans.
    #[serde(default = "default_true")]
    pub listener: bool,
    /// nmap workers that run counter-scans.
    #[serde(default = "default_true")]
    pub scanner: bool,
    /// Public wall of shame and the FIDO2 admin area.
    #[serde(default = "default_true")]
    pub web: bool,
}

impl Default for Roles {
    fn default() -> Self {
        Self {
            listener: true,
            scanner: true,
            web: true,
        }
    }
}

impl Roles {
    /// Enabled roles in a fixed order, for logs and summaries.
    pub fn names(&self) -> Vec<&'static str> {
        [
            (self.listener, "listener"),
            (self.scanner, "scanner"),
            (self.web, "web"),
        ]
        .into_iter()
        .filter_map(|(on, n)| on.then_some(n))
        .collect()
    }
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
    ("roles", "listener", "true"),
    ("roles", "scanner", "true"),
    ("roles", "web", "true"),
    ("", "trusted_proxies", "[]"),
    ("webauthn", "secure_cookies", "true"),
    ("scan", "max_workers", "2"),
    ("scan", "timeout_secs", "1800"),
    ("scan", "rescan_cooldown_hours", "24"),
    ("scan", "max_scans_per_hour", "30"),
    ("scan", "never_scan", "[]"),
];

/// Sections that are required when their role is on and unused otherwise.
const REQUIRED_BY_ROLE: &[&str] = &["webauthn"];

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
                // A missing role-specific section is a load error (or the
                // role is off), not a defaults note.
                None if REQUIRED_BY_ROLE.contains(table) => continue,
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
        cfg.validate()?;
        Ok(cfg)
    }

    /// Role-dependent requirements that serde cannot express.
    fn validate(&self) -> anyhow::Result<()> {
        let r = self.roles;
        if !(r.listener || r.scanner || r.web) {
            bail!("[roles]: enable at least one of listener, scanner, web");
        }
        if r.listener {
            if self.trap_listen.is_none() {
                bail!("trap_listen is required with roles.listener");
            }
            if self.rules_dir.is_none() {
                bail!("rules_dir is required with roles.listener");
            }
        }
        if r.web {
            if self.admin_listen.is_none() {
                bail!("admin_listen is required with roles.web");
            }
            let Some(w) = &self.webauthn else {
                bail!("[webauthn] is required with roles.web");
            };
            if w.rp_id.is_empty() || w.origin.starts_with("http://") {
                bail!("webauthn.rp_id must be set and origin must be https");
            }
        }
        if let Some(m) = &self.maxmind
            && (m.account_id.is_empty() || m.license_key.is_empty())
        {
            bail!("[maxmind] needs both account_id and license_key (or omit the section)");
        }
        if let Some(c) = &self.cluster {
            if c.node_name.trim().is_empty() {
                bail!("cluster.node_name must be set");
            }
            if c.lease_secs < 10 {
                bail!("cluster.lease_secs must be at least 10");
            }
            for p in &c.peers {
                crate::cluster::identity::NodeId::parse(&p.public_key)
                    .with_context(|| format!("cluster.peers `{}`: public_key", p.name))?;
                if !p.address.contains(':') {
                    bail!("cluster.peers `{}`: address must be host:port", p.name);
                }
            }
        }
        Ok(())
    }

    /// Path of this node's private key (distributed mode).
    pub fn node_key_path(&self) -> PathBuf {
        self.cluster
            .as_ref()
            .and_then(|c| c.key_path.clone())
            .unwrap_or_else(|| self.data_dir.join("node.key"))
    }

    /// The `[webauthn]` section. Only call with the web role on:
    /// [`Config::load`] guarantees it is present then.
    pub fn webauthn(&self) -> &WebauthnConfig {
        self.webauthn
            .as_ref()
            .expect("[webauthn] is validated by Config::load when roles.web is on")
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
        assert_eq!(cfg.trap_listen.unwrap().to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.webauthn().rp_id, "peephole.example.net");
        assert_eq!(cfg.roles, Roles::default(), "no [roles] means all on");
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

    fn parse(text: &str) -> anyhow::Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    const BASE: &str = r#"
database_path = "/tmp/x.db"
data_dir = "/tmp"
"#;

    #[test]
    fn scanner_only_needs_no_listener_web_or_maxmind() {
        let cfg = parse(&format!("{BASE}[roles]\nlistener = false\nweb = false\n")).unwrap();
        assert_eq!(cfg.roles.names(), ["scanner"]);
        assert!(cfg.maxmind.is_none() && cfg.webauthn.is_none());
    }

    #[test]
    fn each_role_requires_its_settings() {
        // listener without trap_listen / rules_dir
        let e = parse(&format!(
            "{BASE}rules_dir = \"r\"\n[roles]\nscanner = false\nweb = false\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("trap_listen"), "{e}");
        let e = parse(&format!(
            "trap_listen = \"0.0.0.0:1\"\n{BASE}[roles]\nscanner = false\nweb = false\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("rules_dir"), "{e}");
        // web without admin_listen / [webauthn]
        let e = parse(&format!(
            "{BASE}[roles]\nlistener = false\nscanner = false\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("admin_listen"), "{e}");
        let e = parse(&format!(
            "admin_listen = \"127.0.0.1:1\"\n{BASE}[roles]\nlistener = false\nscanner = false\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("[webauthn]"), "{e}");
        // listener-only with what it needs
        let cfg = parse(&format!(
            "trap_listen = \"0.0.0.0:1\"\nrules_dir = \"r\"\n{BASE}[roles]\nscanner = false\nweb = false\n"
        ))
        .unwrap();
        assert_eq!(cfg.roles.names(), ["listener"]);
    }

    #[test]
    fn no_roles_is_rejected() {
        let e = parse(&format!(
            "{BASE}[roles]\nlistener = false\nscanner = false\nweb = false\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("at least one"), "{e}");
    }

    #[test]
    fn empty_maxmind_credentials_are_rejected() {
        let e = parse(&format!(
            "{BASE}[roles]\nlistener = false\nweb = false\n[maxmind]\naccount_id = \"\"\nlicense_key = \"k\"\n"
        ))
        .unwrap_err();
        assert!(e.to_string().contains("maxmind"), "{e}");
    }

    #[test]
    fn notes_skip_webauthn_when_section_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, format!("{BASE}[roles]\nweb = false\n")).unwrap();
        let notes = optional_key_notes(&path).join("\n");
        assert!(!notes.contains("webauthn"), "{notes}");
        assert!(notes.contains("roles.listener"), "{notes}");
    }
}
