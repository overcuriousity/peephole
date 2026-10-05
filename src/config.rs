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
    /// Optional second trap listener for TLS: peephole terminates TLS
    /// itself, keeping the ClientHello (JA4). Trusted proxies must send a
    /// PROXY protocol header on it.
    pub trap_tls_listen: Option<SocketAddr>,
    /// PEM certificate chain and key for `trap_tls_listen`; without them a
    /// self-signed certificate is made at start.
    pub trap_tls_cert: Option<PathBuf>,
    pub trap_tls_key: Option<PathBuf>,
    /// Required with the web role.
    pub admin_listen: Option<SocketAddr>,
    pub database_path: PathBuf,
    pub data_dir: PathBuf,
    /// Obsolete and ignored: the signature rules are built into the binary.
    /// Still accepted so older configs load; see [`Config::obsolete_notes`].
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
    /// How the trap listener records and answers.
    #[serde(default)]
    pub trap: crate::trap::TrapConfig,
    /// What the public (anonymous) pages show.
    #[serde(default)]
    pub public: PublicConfig,
    /// When API providers look an IP up again.
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
    /// Optional API providers; a missing section means the provider is off.
    pub abuseipdb: Option<AbuseIpDbConfig>,
    pub shodan: Option<ShodanConfig>,
    pub internetdb: Option<InternetDbConfig>,
    pub greynoise: Option<GreyNoiseConfig>,
    /// Keep records and replication history of the last this many days on
    /// this node only; other nodes keep theirs. 0 (default): keep everything.
    /// At least 7 when set.
    #[serde(default)]
    pub retention_days: u32,
}

/// `[enrichment]`: shared by the API providers.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrichmentConfig {
    /// An IP with `k` results from a provider is looked up again when it is
    /// seen `N × 1.5^(k−1)` days after the newest one (N = this); 0 never.
    #[serde(default = "default_refresh_days")]
    pub refresh_after_days: f64,
}

fn default_refresh_days() -> f64 {
    30.0
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            refresh_after_days: default_refresh_days(),
        }
    }
}

/// `[abuseipdb]`: abuse reports per IP (API key required).
#[derive(Debug, Clone, Deserialize)]
pub struct AbuseIpDbConfig {
    pub api_key: String,
    /// Checks per UTC day (the free plan allows 1000).
    #[serde(default = "default_abuseipdb_daily")]
    pub daily_limit: u64,
    /// Reports older than this are not counted (1–365).
    #[serde(default = "default_abuseipdb_age")]
    pub max_age_days: u32,
}

fn default_abuseipdb_daily() -> u64 {
    1000
}

fn default_abuseipdb_age() -> u32 {
    90
}

/// `[shodan]`: host lookups (a key whose plan includes them, e.g. a
/// membership).
#[derive(Debug, Clone, Deserialize)]
pub struct ShodanConfig {
    pub api_key: String,
    /// Lookups per UTC day; 0 = no local cap (Shodan paces at 1/s).
    #[serde(default)]
    pub daily_limit: u64,
}

/// `[internetdb]`: Shodan InternetDB, no key, free for non-commercial use.
#[derive(Debug, Clone, Deserialize)]
pub struct InternetDbConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Lookups per UTC day; 0 = no local cap.
    #[serde(default)]
    pub daily_limit: u64,
}

/// `[greynoise]`: GreyNoise Community. The key is optional; without one
/// the allowance is far smaller.
#[derive(Debug, Clone, Deserialize)]
pub struct GreyNoiseConfig {
    #[serde(default)]
    pub api_key: String,
    /// Default: 10 without a key, none with one.
    pub daily_limit: Option<u64>,
    /// Default: 50 with a key (the free plan), none without.
    pub weekly_limit: Option<u64>,
}

impl GreyNoiseConfig {
    /// The budgets this node keeps to: what is configured, else the free
    /// plan's (with a key 50 a week, without 10 a day).
    pub fn limits(&self) -> Vec<crate::intel::api::Limit> {
        use crate::intel::api::{Limit, Period};
        let keyed = !self.api_key.trim().is_empty();
        let daily = self.daily_limit.or((!keyed).then_some(10));
        let weekly = self.weekly_limit.or(keyed.then_some(50));
        [(Period::Day, daily), (Period::Week, weekly)]
            .into_iter()
            .filter_map(|(period, max)| max.filter(|m| *m > 0).map(|max| Limit { period, max }))
            .collect()
    }
}

/// `[public]`: what anonymous visitors see.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicConfig {
    /// Rule labels (coarse categories of what an IP requested) on public
    /// pages: per-IP label chips, the label filter and the label chart.
    #[serde(default = "default_true")]
    pub show_labels: bool,
    /// Minutes before a request shows on public pages ...
    #[serde(default = "default_public_delay")]
    pub delay_minutes: u32,
    /// ... plus a random 0 to this many minutes per request.
    #[serde(default = "default_public_delay")]
    pub jitter_minutes: u32,
    /// Rows of the wall's "Recent requests".
    #[serde(default = "default_recent_rows")]
    pub recent_rows: usize,
}

fn default_public_delay() -> u32 {
    5
}

fn default_recent_rows() -> usize {
    50
}

impl Default for PublicConfig {
    fn default() -> Self {
        Self {
            show_labels: true,
            delay_minutes: default_public_delay(),
            jitter_minutes: default_public_delay(),
            recent_rows: default_recent_rows(),
        }
    }
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
    pub takeover_hours: f64,
    /// Scan lease length; renewed while nmap runs.
    #[serde(default = "default_lease_secs")]
    pub lease_secs: u64,
    /// Let holders of this node's config key change its runtime settings
    /// (scan pace, rescan cooldown, roles). Default: only the local admin
    /// interface, the CLI and this file can.
    #[serde(default)]
    pub remote_config: bool,
    /// Stop storing a member's entries once they take this many MiB here
    /// (this node's own entries are exempt). 0: no limit.
    #[serde(default = "default_origin_quota_mb")]
    pub origin_quota_mb: u64,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

fn default_takeover_hours() -> f64 {
    6.0
}
fn default_lease_secs() -> u64 {
    120
}
fn default_origin_quota_mb() -> u64 {
    20 * 1024
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
    /// Level 4 (every port, -sV -O, scripts) runs this many times
    /// `timeout_secs`, capped at 12 h.
    #[serde(default = "default_level4_timeout_factor")]
    pub level4_timeout_factor: u32,
    #[serde(default = "default_cooldown")]
    pub rescan_cooldown_hours: i64,
    #[serde(default = "default_rate")]
    pub max_scans_per_hour: i64,
    #[serde(default)]
    pub never_scan: Vec<IpNet>,
    /// More addresses of this node, never scanned and never in the
    /// blocklist like the ones it finds itself: e.g. its public address
    /// behind 1:1 NAT, which no interface carries.
    #[serde(default)]
    pub own_addresses: Vec<std::net::IpAddr>,
    /// Optional per-level argv overrides. The target IP is appended as the
    /// final argument (there is no `{target}` placeholder).
    #[serde(default)]
    pub level_argv: std::collections::HashMap<u8, Vec<String>>,
    /// The nmap program, looked up in PATH unless it contains a slash.
    /// `PEEPHOLE_NMAP_PATH` in the environment overrides it; see [`ScanConfig::nmap`].
    #[serde(default = "default_nmap_path")]
    pub nmap_path: String,
    /// Scan safety knobs (see [`ScanSafety`]); flattened into `[scan]`.
    #[serde(flatten)]
    pub safety: ScanSafety,
}

/// `[scan]` keys that keep counter-scans away from bystanders and bound
/// how much one source can make this node scan.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanSafety {
    /// Highest level for an IP with thin evidence: fewer than
    /// `full_scan_min_requests` requests and not two requests with
    /// different labels. A link-preview bot or URL scanner fetching a
    /// trap URL once is not scanned at level 4. 4 disables the cap.
    #[serde(default = "default_thin_max_level")]
    pub single_request_max_level: u8,
    /// Requests from an IP after which its level is no longer capped.
    #[serde(default = "default_full_scan_min_requests")]
    pub full_scan_min_requests: u32,
    /// IPs per /24 (IPv4) or /64 (IPv6) queued within the rescan cooldown;
    /// further IPs of that network are not queued. 0: no limit.
    #[serde(default = "default_prefix_max_scans")]
    pub prefix_max_scans: u32,
    /// Queued jobs this node keeps at most. When full, a new job evicts the
    /// oldest queued job of a lower level, or is not queued. 0: no cap.
    #[serde(default = "default_max_queued")]
    pub max_queued: u32,
    /// Jobs queued per hour for IPs of one autonomous system (needs GeoLite2
    /// ASN data). 0: no budget.
    #[serde(default = "default_asn_max_per_hour")]
    pub asn_max_per_hour: u32,
    /// Directory of local CIDR lists (`*.txt`/`*.list`/`*.conf`, one address
    /// or CIDR per line, `#` comments) this scanner never scans, e.g. the
    /// published ranges of search engine crawlers. Nothing is downloaded.
    /// Must be a readable directory at startup; while its lists have not
    /// loaded, the scanner scans nothing.
    #[serde(default)]
    pub never_scan_dir: Option<PathBuf>,
    /// Skip IPs whose reverse DNS names a known crawler domain and resolves
    /// back to the IP (forward-confirmed reverse DNS).
    #[serde(default = "default_true")]
    pub verify_crawlers: bool,
    /// Crawler domains in addition to the built-in list.
    #[serde(default)]
    pub crawler_domains: Vec<String>,
    /// Cluster: scan only jobs backed by requests recorded by these nodes
    /// (`ed25519:...` keys) or this node. Absent: any member; `[]`: this
    /// node's own traps only.
    #[serde(default)]
    pub trusted_origins: Option<Vec<String>>,
    /// What to do with an IP whose Tor exit status is unknown because no
    /// exit list has loaded: `defer` (wait up to `tor_wait_hours`, then
    /// refuse) or `scan` (scan anyway, with a warning).
    #[serde(default)]
    pub tor_unknown: TorUnknown,
    #[serde(default = "default_tor_wait_hours")]
    pub tor_wait_hours: u32,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TorUnknown {
    #[default]
    Defer,
    Scan,
}

fn default_thin_max_level() -> u8 {
    2
}
fn default_full_scan_min_requests() -> u32 {
    3
}
fn default_prefix_max_scans() -> u32 {
    4
}
fn default_max_queued() -> u32 {
    5000
}
fn default_asn_max_per_hour() -> u32 {
    20
}
fn default_tor_wait_hours() -> u32 {
    6
}

impl Default for ScanSafety {
    fn default() -> Self {
        Self {
            single_request_max_level: default_thin_max_level(),
            full_scan_min_requests: default_full_scan_min_requests(),
            prefix_max_scans: default_prefix_max_scans(),
            max_queued: default_max_queued(),
            asn_max_per_hour: default_asn_max_per_hour(),
            never_scan_dir: None,
            verify_crawlers: true,
            crawler_domains: vec![],
            trusted_origins: None,
            tor_unknown: TorUnknown::Defer,
            tor_wait_hours: default_tor_wait_hours(),
        }
    }
}

impl ScanConfig {
    /// The nmap program to run: `PEEPHOLE_NMAP_PATH` if set, else `nmap_path`.
    pub fn nmap(&self) -> String {
        std::env::var("PEEPHOLE_NMAP_PATH")
            .ok()
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| self.nmap_path.clone())
    }
}

fn default_nmap_path() -> String {
    "nmap".into()
}

fn default_workers() -> usize {
    2
}
fn default_level4_timeout_factor() -> u32 {
    4
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
            level4_timeout_factor: default_level4_timeout_factor(),
            rescan_cooldown_hours: default_cooldown(),
            max_scans_per_hour: default_rate(),
            never_scan: vec![],
            own_addresses: vec![],
            level_argv: Default::default(),
            safety: ScanSafety::default(),
            nmap_path: default_nmap_path(),
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
    ("", "retention_days", "0"),
    ("webauthn", "secure_cookies", "true"),
    ("scan", "max_workers", "2"),
    ("scan", "timeout_secs", "1800"),
    ("scan", "level4_timeout_factor", "4"),
    ("scan", "rescan_cooldown_hours", "24"),
    ("scan", "max_scans_per_hour", "30"),
    ("scan", "never_scan", "[]"),
    ("scan", "single_request_max_level", "2"),
    ("scan", "prefix_max_scans", "4"),
    ("scan", "max_queued", "5000"),
    ("scan", "asn_max_per_hour", "20"),
    ("scan", "verify_crawlers", "true"),
    ("scan", "tor_unknown", "\"defer\""),
    ("public", "show_labels", "true"),
    ("public", "delay_minutes", "5"),
    ("public", "jitter_minutes", "5"),
    ("public", "recent_rows", "50"),
];

/// Sections that are required when their role is on and unused otherwise.
const REQUIRED_BY_ROLE: &[&str] = &["webauthn"];

/// One human-readable note per optional key the file does not set.
/// Unparsable files yield no notes; `load` reports those errors.
impl Config {
    /// Keys this config sets that no longer do anything.
    pub fn obsolete_notes(&self) -> Vec<String> {
        let mut notes = vec![];
        if let Some(dir) = &self.rules_dir {
            notes.push(format!(
                "note: `rules_dir` ({}) is ignored: the signature rules are built into the \
                 binary (changing them means a new build); remove the key, and the directory \
                 if nothing else uses it",
                dir.display()
            ));
        }
        notes
    }
}

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
        self.trap.validate()?;
        if (1..7).contains(&self.retention_days) {
            bail!("retention_days must be 0 (keep everything) or at least 7");
        }
        let p = &self.public;
        if p.delay_minutes > 60 || p.jitter_minutes > 60 {
            bail!("public.delay_minutes and public.jitter_minutes must be between 0 and 60");
        }
        if !(1..=200).contains(&p.recent_rows) {
            bail!("public.recent_rows must be between 1 and 200");
        }
        let r = self.roles;
        if !(r.listener || r.scanner || r.web) {
            bail!("[roles]: enable at least one of listener, scanner, web");
        }
        if self.trap_tls_cert.is_some() != self.trap_tls_key.is_some() {
            bail!(
                "trap_tls_cert and trap_tls_key go together (or omit both for a self-signed one)"
            );
        }
        if r.listener && self.trap_listen.is_none() {
            bail!("trap_listen is required with roles.listener");
        }
        if r.web {
            if self.admin_listen.is_none() {
                bail!("admin_listen is required with roles.web");
            }
            let Some(w) = &self.webauthn else {
                bail!("[webauthn] is required with roles.web");
            };
            // The scheme is lowercased by the parser; the builder checks
            // that rp_id is the origin's host or a registrable suffix of it.
            let origin = webauthn_rs::prelude::Url::parse(&w.origin)
                .ok()
                .filter(|u| u.scheme() == "https")
                .context("webauthn.origin must be an https:// URL")?;
            webauthn_rs::WebauthnBuilder::new(&w.rp_id, &origin)
                .and_then(|b| b.build())
                .context("webauthn.rp_id must be the origin's host or a parent domain of it")?;
        }
        if let Some(m) = &self.maxmind
            && (m.account_id.is_empty() || m.license_key.is_empty())
        {
            bail!("[maxmind] needs both account_id and license_key (or omit the section)");
        }
        let e = self.enrichment.refresh_after_days;
        if !(e == 0.0 || (1.0..=3650.0).contains(&e)) {
            bail!("enrichment.refresh_after_days must be 0 (never) or between 1 and 3650");
        }
        if let Some(a) = &self.abuseipdb {
            if a.api_key.trim().is_empty() {
                bail!("[abuseipdb] needs api_key (or omit the section)");
            }
            if !(1..=365).contains(&a.max_age_days) {
                bail!("abuseipdb.max_age_days must be between 1 and 365");
            }
            if a.daily_limit == 0 {
                bail!("abuseipdb.daily_limit must be at least 1");
            }
        }
        if let Some(s) = &self.shodan
            && s.api_key.trim().is_empty()
        {
            bail!("[shodan] needs api_key (or omit the section)");
        }
        for (name, key) in [
            (
                "abuseipdb",
                self.abuseipdb.as_ref().map(|a| a.api_key.as_str()),
            ),
            ("shodan", self.shodan.as_ref().map(|s| s.api_key.as_str())),
            (
                "greynoise",
                self.greynoise.as_ref().map(|g| g.api_key.as_str()),
            ),
        ] {
            // Keys go into headers and URLs.
            if key.is_some_and(|k| k.chars().any(|c| !c.is_ascii_graphic())) {
                bail!("{name}.api_key may only contain printable ASCII without spaces");
            }
        }
        // [scan]: reject values that are accepted by serde but break scanning
        // (e.g. a 5s timeout fails every scan; a negative cooldown builds a
        // NULL datetime that silently disables the cooldown).
        // Bounds mirror the runtime pace limits (scan::pace) so the config
        // defaults are always a valid pace.
        let s = &self.scan;
        if !(1..=crate::scan::pace::MAX_WORKERS).contains(&s.max_workers) {
            bail!(
                "scan.max_workers must be between 1 and {}",
                crate::scan::pace::MAX_WORKERS
            );
        }
        if !(crate::scan::pace::MIN_TIMEOUT..=crate::scan::pace::MAX_TIMEOUT)
            .contains(&s.timeout_secs)
        {
            bail!(
                "scan.timeout_secs must be between {} and {}",
                crate::scan::pace::MIN_TIMEOUT,
                crate::scan::pace::MAX_TIMEOUT
            );
        }
        if !(1..=crate::scan::pace::MAX_LEVEL4_FACTOR).contains(&s.level4_timeout_factor) {
            bail!(
                "scan.level4_timeout_factor must be between 1 and {}",
                crate::scan::pace::MAX_LEVEL4_FACTOR
            );
        }
        if !(0..=crate::settings::MAX_COOLDOWN_HOURS).contains(&s.rescan_cooldown_hours) {
            bail!(
                "scan.rescan_cooldown_hours must be between 0 and {}",
                crate::settings::MAX_COOLDOWN_HOURS
            );
        }
        if !(1..=crate::scan::pace::MAX_PER_HOUR).contains(&s.max_scans_per_hour) {
            bail!(
                "scan.max_scans_per_hour must be between 1 and {}",
                crate::scan::pace::MAX_PER_HOUR
            );
        }
        for (level, argv) in &s.level_argv {
            if !(1..=4).contains(level) {
                bail!("scan.level_argv: level {level} is out of range (1..=4)");
            }
            if argv.is_empty() {
                bail!("scan.level_argv: level {level} is empty (nmap would run its default scan)");
            }
        }
        if let Some(a) = s
            .own_addresses
            .iter()
            .find(|a| a.is_unspecified() || a.is_multicast())
        {
            bail!("scan.own_addresses: `{a}` is not a host address");
        }
        if !(1..=4).contains(&s.safety.single_request_max_level) {
            bail!("scan.single_request_max_level must be between 1 and 4");
        }
        for o in s.safety.trusted_origins.iter().flatten() {
            crate::cluster::identity::NodeId::parse(o)
                .with_context(|| format!("scan.trusted_origins: `{o}`"))?;
        }
        // An unreadable list must stop the start, not silently protect nothing.
        if let Some(d) = &s.safety.never_scan_dir {
            std::fs::read_dir(d)
                .with_context(|| format!("scan.never_scan_dir `{}`", d.display()))?;
        }
        if let Some(c) = &self.cluster {
            if c.node_name.trim().is_empty() {
                bail!("cluster.node_name must be set");
            }
            if !(10..=86_400).contains(&c.lease_secs) {
                bail!("cluster.lease_secs must be between 10 and 86400");
            }
            if !c.takeover_hours.is_finite() || c.takeover_hours <= 0.0 {
                bail!("cluster.takeover_hours must be a positive, finite number");
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
    ///
    /// Non-intrusive by design: no `-A`, no intrusive NSE scripts, and timing
    /// capped at `-T3`. Severity escalates by *scope* — more ports, service
    /// (`-sV`) and OS (`-O`) detection, then discovery/safe scripts — not by
    /// speed or aggressiveness, so a higher level maps to a more thorough but
    /// still defensible scan.
    ///
    /// `-Pn`: the target just connected to us, so it is up; nmap's own
    /// discovery probes are often filtered and would report it down. The
    /// full-range level caps retransmissions so filtered ports don't stretch
    /// a scan past the timeout.
    ///
    /// None for a level outside 1..=4: there is no preset to fall back on,
    /// and an empty argv would run nmap's own default scan.
    pub fn default_level_argv(&self, level: u8) -> Option<Vec<String>> {
        if !(1..=4).contains(&level) {
            return None;
        }
        if let Some(custom) = self.scan.level_argv.get(&level) {
            return Some(custom.clone());
        }
        // One NSE argument; it contains spaces, so argv is built element by
        // element rather than split from a string. `discovery` and `safe`
        // also hold scripts that would leak the target to third parties
        // (`external`: whois, ASN and geolocation lookups), broadcast on
        // the scanner's own network (`broadcast` prerules), or flood
        // (`dos`); those categories are excluded.
        const SCRIPTS: &str =
            "(discovery or safe) and not (intrusive or broadcast or external or dos)";
        // Level 2 names its scripts: the source's own identifiers (SSH host
        // keys and algorithm lists, the TLS certificate), each one handshake
        // with a port nmap already found open, all in `safe`.
        const IDENTITY_SCRIPTS: &str = "ssh-hostkey,ssh2-enum-algos,ssl-cert";
        let argv: &[&str] = match level {
            1 => &["-Pn", "-sS", "-T2", "--top-ports", "100"],
            2 => &[
                "-Pn",
                "-sS",
                "-sV",
                "-O",
                "-T3",
                "--top-ports",
                "1000",
                "--script",
                IDENTITY_SCRIPTS,
            ],
            3 => &[
                "-Pn",
                "-sS",
                "-sV",
                "-O",
                "-T3",
                "--top-ports",
                "1000",
                "--script",
                SCRIPTS,
            ],
            4 => &[
                "-Pn",
                "-sS",
                "-sV",
                "-O",
                "-T3",
                "-p-",
                "--max-retries",
                "2",
                "--script",
                SCRIPTS,
            ],
            _ => return None,
        };
        Some(argv.iter().map(|s| s.to_string()).collect())
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
            let argv = cfg.default_level_argv(level).unwrap();
            assert!(argv.iter().any(|a| a == "-Pn"), "level {level}: {argv:?}");
        }
    }

    /// Scans stay non-intrusive: no -A, no intrusive NSE category, timing
    /// never above -T3; the script selector is one argv element (it contains
    /// spaces), and scope grows with the level.
    #[test]
    fn default_presets_are_non_intrusive() {
        let cfg: Config = toml::from_str(
            r#"
trap_listen = "0.0.0.0:8080"
admin_listen = "127.0.0.1:8443"
database_path = "/tmp/x.db"
data_dir = "/tmp"
[webauthn]
rp_id = "x.example"
origin = "https://x.example"
rp_name = "x"
"#,
        )
        .unwrap();
        for level in 1..=4 {
            let argv = cfg.default_level_argv(level).unwrap();
            assert!(!argv.iter().any(|a| a == "-A"), "level {level} has -A");
            assert!(
                !argv.iter().any(|a| a == "-T4" || a == "-T5"),
                "level {level} timing too fast: {argv:?}"
            );
            // Scripts, when present, are one argv element that excludes the
            // intrusive category and the ones that talk to third parties,
            // broadcast on the local network, or flood.
            if let Some(i) = argv.iter().position(|a| a == "--script") {
                let expr = &argv[i + 1];
                // A named list holds only scripts of the `safe` category.
                if !expr.contains(' ') {
                    for script in expr.split(',') {
                        assert!(
                            ["ssh-hostkey", "ssh2-enum-algos", "ssl-cert"].contains(&script),
                            "level {level}: {script} is not on the safe list"
                        );
                    }
                    continue;
                }
                let (_, excluded) = expr.split_once("and not").unwrap();
                for cat in ["intrusive", "broadcast", "external", "dos"] {
                    assert!(
                        excluded.contains(cat),
                        "level {level}: {expr} lets {cat} in"
                    );
                }
            } else {
                assert!(
                    !argv.iter().any(|a| a.contains("intrusive")),
                    "level {level} enables intrusive scripts: {argv:?}"
                );
            }
        }
        // OS detection from level 2 up; only level 4 scans all ports.
        let has = |level, flag| {
            cfg.default_level_argv(level)
                .unwrap()
                .iter()
                .any(|a| a == flag)
        };
        assert!(!has(1, "-O"));
        assert!(has(2, "-O"));
        assert!(has(3, "-O"));
        assert!(!has(3, "-p-"));
        assert!(has(4, "-p-"));
    }

    /// No level outside 1..=4 gets an argv: an empty one would run nmap's
    /// own default scan.
    #[test]
    fn levels_outside_the_presets_have_no_argv() {
        let cfg: Config = toml::from_str("database_path = \"/x\"\ndata_dir = \"/x\"\n").unwrap();
        for level in [0, 5, 9, 255] {
            assert_eq!(cfg.default_level_argv(level), None, "level {level}");
        }
    }

    #[test]
    fn a_trap_certificate_needs_its_key() {
        let base = "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n\
                    [roles]\nweb = false\n";
        let cfg: Config = toml::from_str(&format!("trap_tls_cert = \"/c.pem\"\n{base}")).unwrap();
        assert!(cfg.validate().is_err());
        let cfg: Config = toml::from_str(&format!(
            "trap_tls_listen = \"127.0.0.1:2\"\ntrap_tls_cert = \"/c.pem\"\ntrap_tls_key = \"/k.pem\"\n{base}"
        ))
        .unwrap();
        cfg.validate().unwrap();
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
        assert!(
            cfg.default_level_argv(4)
                .unwrap()
                .iter()
                .any(|a| a == "-sS")
        );
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
        // listener without trap_listen
        let e = parse(&format!("{BASE}[roles]\nscanner = false\nweb = false\n")).unwrap_err();
        assert!(e.to_string().contains("trap_listen"), "{e}");
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
        // listener-only with what it needs (rules are built in)
        let cfg = parse(&format!(
            "trap_listen = \"0.0.0.0:1\"\n{BASE}[roles]\nscanner = false\nweb = false\n"
        ))
        .unwrap();
        assert_eq!(cfg.roles.names(), ["listener"]);
        assert!(cfg.obsolete_notes().is_empty());
    }

    /// An older config's `rules_dir` still loads, and is reported as
    /// ignored.
    #[test]
    fn rules_dir_is_accepted_and_ignored() {
        let cfg = parse(&format!(
            "trap_listen = \"0.0.0.0:1\"\nrules_dir = \"/etc/peephole/rules\"\n{BASE}[roles]\nscanner = false\nweb = false\n"
        ))
        .unwrap();
        let notes = cfg.obsolete_notes();
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("rules_dir") && notes[0].contains("built into the binary"),
            "{notes:?}"
        );
    }

    /// Keep everything unless asked; a window shorter than a week would cut
    /// into replication lag.
    #[test]
    fn retention_defaults_to_keep_everything_and_is_at_least_a_week() {
        let roles = "[roles]\nlistener = false\nweb = false\n";
        assert_eq!(parse(&format!("{BASE}{roles}")).unwrap().retention_days, 0);
        for days in [1, 6] {
            let e = parse(&format!("retention_days = {days}\n{BASE}{roles}")).unwrap_err();
            assert!(e.to_string().contains("at least 7"), "{e}");
        }
        let cfg = parse(&format!("retention_days = 7\n{BASE}{roles}")).unwrap();
        assert_eq!(cfg.retention_days, 7);
    }

    #[test]
    fn public_delay_defaults_and_bounds() {
        let base = format!("{BASE}[roles]\nlistener = false\nweb = false\n");
        let cfg = parse(&base).unwrap();
        assert_eq!(
            (
                cfg.public.delay_minutes,
                cfg.public.jitter_minutes,
                cfg.public.recent_rows
            ),
            (5, 5, 50)
        );
        let with = |extra: &str| parse(&format!("{base}[public]\n{extra}\n"));
        assert!(with("delay_minutes = 0\njitter_minutes = 0").is_ok());
        assert!(with("delay_minutes = 60\njitter_minutes = 60").is_ok());
        assert!(with("delay_minutes = 61").is_err());
        assert!(with("jitter_minutes = 61").is_err());
        assert!(with("recent_rows = 0").is_err());
        assert!(with("recent_rows = 201").is_err());
        assert!(with("recent_rows = 200").is_ok());
    }

    #[test]
    fn retention_is_listed_among_the_optional_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, BASE).unwrap();
        let notes = optional_key_notes(&path).join("\n");
        assert!(
            notes.contains("`retention_days` not set (default 0)"),
            "{notes}"
        );
        assert!(!notes.contains("scan.retention_days"), "{notes}");
    }

    #[test]
    fn own_addresses_must_be_host_addresses() {
        let scan = |list: &str| {
            parse(&format!(
                "{BASE}[roles]\nlistener = false\nweb = false\n[scan]\nown_addresses = [{list}]\n"
            ))
        };
        let cfg = scan("\"203.0.113.5\", \"2001:db8::5\"").unwrap();
        assert_eq!(cfg.scan.own_addresses.len(), 2);
        for bad in ["0.0.0.0", "::", "224.0.0.1"] {
            let e = scan(&format!("\"{bad}\"")).unwrap_err();
            assert!(e.to_string().contains("own_addresses"), "{e}");
        }
        assert!(scan("\"nat.example\"").is_err(), "addresses, not names");
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

    #[test]
    fn cluster_section_parses_with_integer_hours() {
        let cfg = parse(&format!(
            "{BASE}[roles]\nlistener = false\nweb = false\n[cluster]\nnode_name = \"n\"\nlisten = \"0.0.0.0:7443\"\ntakeover_hours = 2\n"
        ))
        .unwrap();
        let c = cfg.cluster.unwrap();
        assert_eq!(c.takeover_hours, 2.0);
        assert_eq!(c.lease_secs, 120);
    }

    /// The annotated example parses and states the defaults.
    #[test]
    fn example_config_states_the_scan_safety_defaults() {
        let text = std::fs::read_to_string("deploy/config.example.toml").unwrap();
        let cfg: Config = toml::from_str(&text).unwrap();
        let (s, d) = (&cfg.scan.safety, ScanSafety::default());
        assert_eq!(
            (
                s.single_request_max_level,
                s.full_scan_min_requests,
                s.prefix_max_scans,
                s.max_queued,
                s.asn_max_per_hour,
                s.verify_crawlers,
                s.tor_unknown,
                s.tor_wait_hours
            ),
            (
                d.single_request_max_level,
                d.full_scan_min_requests,
                d.prefix_max_scans,
                d.max_queued,
                d.asn_max_per_hour,
                d.verify_crawlers,
                d.tor_unknown,
                d.tor_wait_hours
            )
        );
    }

    #[test]
    fn scan_safety_keys_parse_next_to_level_argv() {
        let cfg = parse(&format!(
            "{BASE}[roles]\nlistener = false\nweb = false\n[scan]\n\
             single_request_max_level = 3\nmax_queued = 10\ntor_unknown = \"scan\"\n\
             trusted_origins = []\nnever_scan_dir = \"/tmp\"\n\
             [scan.level_argv]\n1 = [\"-sS\"]\n"
        ))
        .unwrap();
        let s = &cfg.scan.safety;
        assert_eq!(s.single_request_max_level, 3);
        assert_eq!(s.max_queued, 10);
        assert_eq!(s.tor_unknown, TorUnknown::Scan);
        assert_eq!(s.trusted_origins.as_deref(), Some(&[][..]));
        assert_eq!(cfg.scan.level_argv[&1], ["-sS"]);
        // Defaults are the safe ones.
        let cfg = parse(&format!("{BASE}[roles]\nlistener = false\nweb = false\n")).unwrap();
        let s = &cfg.scan.safety;
        assert_eq!(
            (s.single_request_max_level, s.tor_unknown, s.verify_crawlers),
            (2, TorUnknown::Defer, true)
        );
        assert!(s.trusted_origins.is_none());
        // Out of range, bad keys, empty argv and a missing list directory
        // are refused.
        for bad in [
            "single_request_max_level = 0",
            "single_request_max_level = 5",
            "trusted_origins = [\"nope\"]",
            "never_scan_dir = \"/nonexistent/never_scan.d\"",
            "level_argv = { 2 = [] }",
            "rescan_cooldown_hours = -1",
            "rescan_cooldown_hours = 8761",
        ] {
            let e = parse(&format!(
                "{BASE}[roles]\nlistener = false\nweb = false\n[scan]\n{bad}\n"
            ));
            assert!(e.is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn webauthn_origin_must_be_https_and_match_rp_id() {
        let with = |rp_id: &str, origin: &str| {
            parse(&format!(
                "{BASE}admin_listen = \"127.0.0.1:1\"\n[roles]\nlistener = false\n\
                 [webauthn]\nrp_id = \"{rp_id}\"\norigin = \"{origin}\"\nrp_name = \"x\"\n"
            ))
        };
        with("x.example", "https://x.example").unwrap();
        with("x.example", "HTTPS://admin.x.example:8443").unwrap();
        with("localhost", "https://localhost").unwrap();
        for (rp_id, origin) in [
            ("", "https://x.example"),
            ("x.example", "http://x.example"),
            ("x.example", "HTTP://x.example"),
            ("x.example", "ftp://x.example"),
            ("x.example", "x.example"),
            ("x.example", "https://y.example"),
            ("admin.x.example", "https://x.example"),
        ] {
            assert!(with(rp_id, origin).is_err(), "{rp_id} {origin} accepted");
        }
    }

    #[test]
    fn api_providers_are_off_unless_configured() {
        let cfg = parse(&format!("{BASE}[roles]\nlistener = false\nweb = false\n")).unwrap();
        assert!(cfg.abuseipdb.is_none() && cfg.shodan.is_none());
        assert!(cfg.internetdb.is_none() && cfg.greynoise.is_none());
        assert_eq!(cfg.enrichment.refresh_after_days, 30.0);
    }

    #[test]
    fn api_provider_sections_are_checked() {
        let with = |extra: &str| {
            parse(&format!(
                "{BASE}[roles]\nlistener = false\nweb = false\n{extra}"
            ))
        };
        let a = with("[abuseipdb]\napi_key = \"abc\"\n").unwrap();
        let a = a.abuseipdb.unwrap();
        assert_eq!((a.daily_limit, a.max_age_days), (1000, 90));
        for bad in [
            "[abuseipdb]\napi_key = \"\"\n",
            "[abuseipdb]\napi_key = \"k\"\nmax_age_days = 0\n",
            "[shodan]\napi_key = \" \"\n",
            "[shodan]\napi_key = \"a b\"\n",
            "[enrichment]\nrefresh_after_days = 0.5\n",
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }
        assert!(with("[enrichment]\nrefresh_after_days = 0\n").is_ok());
        let i = with("[internetdb]\nenabled = true\n").unwrap();
        assert!(i.internetdb.unwrap().enabled);
    }

    #[test]
    fn greynoise_budgets_follow_the_free_plan_unless_set() {
        use crate::intel::api::{Limit, Period};
        let g = |toml: &str| -> GreyNoiseConfig { toml::from_str(toml).unwrap() };
        assert_eq!(
            g("").limits(),
            [Limit {
                period: Period::Day,
                max: 10
            }]
        );
        assert_eq!(
            g("api_key = \"k\"").limits(),
            [Limit {
                period: Period::Week,
                max: 50
            }]
        );
        assert_eq!(
            g("api_key = \"k\"\ndaily_limit = 20\nweekly_limit = 0").limits(),
            [Limit {
                period: Period::Day,
                max: 20
            }]
        );
    }
}
