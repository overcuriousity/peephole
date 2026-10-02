//! Targets a scanner never touches whoever asks: this node's own addresses,
//! the cluster members' addresses, and the operator's local CIDR lists
//! (`scan.never_scan_dir`).
//!
//! Member addresses come from three places: the configured and published
//! `host:port` of each member (resolved via DNS), and the source addresses
//! members actually connected from (outbound-only members have no published
//! address). A failed DNS lookup keeps the previous resolution and is
//! retried within a minute instead of leaving the set short.
//!
//! A member's published address is its own claim: a hostile member could
//! publish a victim's host name to shield the victim from scans. Refusing
//! is the safe direction (a missed scan, never a scan of a member), so such
//! addresses stay protected, but a refusal that rests only on a published
//! address no member has connected from is logged with the member's name,
//! so an operator can spot the shielding.
use crate::cluster::Node;
use crate::config::Config;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

/// Rebuild the address sets this often.
const REFRESH: Duration = Duration::from_secs(300);
/// ... or this soon after a lookup failed.
const RETRY: Duration = Duration::from_secs(60);
/// Per DNS lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

pub struct Safety {
    /// Host names (`host:port`) resolved before, kept when a lookup fails.
    resolved: HashMap<String, Vec<IpAddr>>,
    /// This node's addresses.
    own: HashSet<IpAddr>,
    /// Published member addresses, and whose they are.
    published: HashMap<IpAddr, String>,
    /// Addresses members connected from, and whose they are.
    observed: HashMap<IpAddr, String>,
    built: Option<Instant>,
    retry: bool,
    lists: Lists,
}

impl Safety {
    pub fn new(cfg: &Config) -> Self {
        Self {
            resolved: HashMap::new(),
            own: HashSet::new(),
            published: HashMap::new(),
            observed: HashMap::new(),
            built: None,
            retry: false,
            lists: Lists::new(cfg.scan.safety.never_scan_dir.clone()),
        }
    }

    /// Rebuild the sets when due. `node` is None standalone.
    pub async fn refresh(&mut self, cfg: &Config, node: Option<&Node>) {
        self.lists.refresh();
        if let Some(node) = node {
            // Cheap and in memory: always current.
            let names: HashMap<_, _> = node
                .members()
                .values()
                .map(|m| (m.id, m.name.clone()))
                .collect();
            for (id, ip) in node.status.peer_ips() {
                let who = names.get(&id).cloned().unwrap_or_else(|| id.short());
                self.observed.insert(ip, who);
            }
        }
        let due = if self.retry { RETRY } else { REFRESH };
        if self.built.is_some_and(|t| t.elapsed() < due) {
            return;
        }
        self.built = Some(Instant::now());
        self.retry = false;

        // This node: listeners bound to specific addresses, the advertised
        // RPC address, and the addresses of its interfaces.
        let mut own: HashSet<IpAddr> = local_addresses().await;
        let listeners = [cfg.trap_listen, cfg.admin_listen]
            .into_iter()
            .flatten()
            .chain(cfg.cluster.as_ref().map(|c| c.listen));
        own.extend(listeners.map(|a| a.ip()).filter(|ip| !ip.is_unspecified()));
        let mut hosts: Vec<(String, String)> = vec![];
        if let Some(a) = cfg.cluster.as_ref().and_then(|c| c.advertise.clone()) {
            hosts.push((a, "this node".into()));
        }
        // Members: configured peers and published addresses.
        if let Some(node) = node {
            hosts.extend(
                node.dial_targets()
                    .into_iter()
                    .map(|(_, name, addr)| (addr, name)),
            );
            if let Ok(rows) = crate::cluster::members::all(&node.store).await {
                hosts.extend(
                    rows.into_iter()
                        .filter(|m| m.id != node.id())
                        .filter_map(|m| Some((m.address?, m.name))),
                );
            }
        }
        let mut published = HashMap::new();
        for (host, who) in hosts {
            let ips = match self.resolve(&host).await {
                Some(ips) => ips,
                None => continue,
            };
            for ip in ips {
                if who == "this node" {
                    own.insert(ip);
                } else {
                    published.insert(ip, who.clone());
                }
            }
        }
        self.own = own.into_iter().map(crate::net::canonical).collect();
        self.published = published;
    }

    /// Resolve `host:port` (or a bare host); on failure the previous
    /// answer, and an earlier retry.
    async fn resolve(&mut self, host: &str) -> Option<Vec<IpAddr>> {
        if let Ok(sa) = host.parse::<SocketAddr>() {
            return Some(vec![crate::net::canonical(sa.ip())]);
        }
        let lookup =
            tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host(host.to_string())).await;
        match lookup {
            Ok(Ok(it)) => {
                let ips: Vec<IpAddr> = it.map(|sa| crate::net::canonical(sa.ip())).collect();
                if !ips.is_empty() {
                    self.resolved.insert(host.to_string(), ips.clone());
                    return Some(ips);
                }
            }
            Ok(Err(e)) => {
                warn!(%host, error = %e, "cluster address lookup failed; keeping the previous answer")
            }
            Err(_) => warn!(%host, "cluster address lookup timed out; keeping the previous answer"),
        }
        self.retry = true;
        self.resolved.get(host).cloned()
    }

    /// Why `ip` must not be scanned, if it must not.
    pub fn refuses(&self, ip: &IpAddr) -> Option<String> {
        let ip = crate::net::canonical(*ip);
        if self.own.contains(&ip) {
            return Some("this node's own address".into());
        }
        if let Some(who) = self.observed.get(&ip) {
            return Some(format!("cluster member address ({who})"));
        }
        if let Some(who) = self.published.get(&ip) {
            info!(
                target = %ip,
                member = %who,
                "scan refused: the target is the published address of member `{who}`, \
                 which this node has not seen it connect from; if `{who}` is not at \
                 this address, it is shielding the target from scans"
            );
            return Some(format!("cluster member address ({who})"));
        }
        None
    }

    /// The local CIDR list that covers `ip`, if one does.
    pub fn listed(&self, ip: &IpAddr) -> Option<String> {
        self.lists.covering(ip)
    }
}

/// Addresses of this host's interfaces (Linux `/proc`), plus the source
/// addresses it would use towards the internet (a connected UDP socket;
/// nothing is sent).
async fn local_addresses() -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    if let Ok(t) = tokio::fs::read_to_string("/proc/net/fib_trie").await {
        out.extend(fib_trie_locals(&t));
    }
    if let Ok(t) = tokio::fs::read_to_string("/proc/net/if_inet6").await {
        out.extend(if_inet6(&t));
    }
    for (bind, probe) in [("0.0.0.0:0", "192.0.2.1:9"), ("[::]:0", "[2001:db8::1]:9")] {
        if let Ok(s) = tokio::net::UdpSocket::bind(bind).await
            && s.connect(probe).await.is_ok()
            && let Ok(a) = s.local_addr()
        {
            out.insert(a.ip());
        }
    }
    out
}

/// Local (`/32 host LOCAL`) addresses in `/proc/net/fib_trie`.
fn fib_trie_locals(text: &str) -> Vec<IpAddr> {
    let mut out = vec![];
    let mut last: Option<IpAddr> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("|--") {
            last = rest.trim().parse().ok();
        } else if t.contains("host LOCAL")
            && let Some(ip) = last
        {
            out.push(ip);
        }
    }
    out
}

/// Addresses in `/proc/net/if_inet6` (32 hex digits per line).
fn if_inet6(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|hex| u128::from_str_radix(hex, 16).ok())
        .map(|n| IpAddr::V6(std::net::Ipv6Addr::from(n)))
        .collect()
}

/// The operator's CIDR lists in `scan.never_scan_dir`, reloaded when a
/// file changes.
struct Lists {
    dir: Option<PathBuf>,
    stamp: Vec<(PathBuf, SystemTime, u64)>,
    nets: Vec<(IpNet, String)>,
    checked: Option<Instant>,
}

/// How often the directory is looked at.
const LISTS_CHECK: Duration = Duration::from_secs(60);

impl Lists {
    fn new(dir: Option<PathBuf>) -> Self {
        Self {
            dir,
            stamp: vec![],
            nets: vec![],
            checked: None,
        }
    }

    fn refresh(&mut self) {
        let Some(dir) = &self.dir else { return };
        if self.checked.is_some_and(|t| t.elapsed() < LISTS_CHECK) {
            return;
        }
        self.checked = Some(Instant::now());
        let files = list_files(dir);
        let stamp: Vec<_> = files
            .iter()
            .filter_map(|p| {
                let m = std::fs::metadata(p).ok()?;
                Some((p.clone(), m.modified().ok()?, m.len()))
            })
            .collect();
        if stamp == self.stamp {
            return;
        }
        self.stamp = stamp;
        self.nets = files.iter().flat_map(|p| parse_list(p)).collect();
        info!(dir = %dir.display(), networks = self.nets.len(), files = files.len(), "never-scan lists loaded");
    }

    fn covering(&self, ip: &IpAddr) -> Option<String> {
        let ip = crate::net::canonical(*ip);
        self.nets
            .iter()
            .find(|(n, _)| n.contains(&ip))
            .map(|(n, file)| format!("never_scan_dir {file}: {n}"))
    }
}

fn list_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .is_some_and(|e| e == "txt" || e == "list" || e == "conf")
        })
        .collect();
    v.sort();
    v
}

/// One address or CIDR per line; `#` starts a comment; bad lines are
/// skipped with a warning.
fn parse_list(path: &Path) -> Vec<(IpNet, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        warn!(file = %path.display(), "never-scan list unreadable");
        return vec![];
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut out = vec![];
    for (i, line) in text.lines().enumerate() {
        let entry = line.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let net = entry
            .parse::<IpNet>()
            .ok()
            .or_else(|| entry.parse::<IpAddr>().ok().map(IpNet::from));
        match net {
            Some(n) => out.push((n.trunc(), name.clone())),
            None => {
                warn!(file = %path.display(), line = i + 1, %entry, "never-scan list: not an address or CIDR")
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_trie_yields_local_addresses() {
        let t = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     \
                 +-- 203.0.113.0/24 2 0 2\n        |-- 203.0.113.0\n           /24 link UNICAST\n        \
                 |-- 203.0.113.10\n           /32 host LOCAL\n        |-- 203.0.113.255\n           \
                 /32 link BROADCAST\n";
        assert_eq!(
            fib_trie_locals(t),
            ["203.0.113.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn if_inet6_lines_parse() {
        let t = "20010db8000000000000000000000001 02 40 00 80 eth0\n\
                 00000000000000000000000000000001 01 80 10 80 lo\n";
        assert_eq!(
            if_inet6(t),
            [
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn never_scan_lists_load_and_match() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("googlebot.txt"),
            "# crawler ranges\n66.249.64.0/19\n2001:4860:4801:10::/64  # v6\n\nnot-an-ip\n198.51.100.7\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("ignored.json"), "203.0.113.0/24\n").unwrap();
        let mut l = Lists::new(Some(dir.path().to_path_buf()));
        l.refresh();
        assert_eq!(l.nets.len(), 3);
        assert!(
            l.covering(&"66.249.66.1".parse().unwrap())
                .unwrap()
                .contains("googlebot.txt")
        );
        assert!(
            l.covering(&"2001:4860:4801:10::5".parse().unwrap())
                .is_some()
        );
        assert!(
            l.covering(&"::ffff:198.51.100.7".parse().unwrap())
                .is_some()
        );
        assert!(
            l.covering(&"203.0.113.5".parse().unwrap()).is_none(),
            "only list files"
        );
        // No directory: nothing listed.
        let mut none = Lists::new(None);
        none.refresh();
        assert!(none.covering(&"66.249.66.1".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn own_addresses_are_refused_even_standalone() {
        let dir = tempfile::tempdir().unwrap();
        let cfg: Config = toml::from_str(&format!(
            "database_path = \"{d}/t.db\"\ndata_dir = \"{d}\"\ntrap_listen = \"203.0.113.80:8080\"\n",
            d = dir.path().display()
        ))
        .unwrap();
        let mut s = Safety::new(&cfg);
        s.refresh(&cfg, None).await;
        assert_eq!(
            s.refuses(&"203.0.113.80".parse().unwrap()).as_deref(),
            Some("this node's own address")
        );
        assert!(s.refuses(&"203.0.113.81".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn a_failed_lookup_keeps_the_previous_answer() {
        let dir = tempfile::tempdir().unwrap();
        let cfg: Config = toml::from_str(&format!(
            "database_path = \"{d}/t.db\"\ndata_dir = \"{d}\"\n",
            d = dir.path().display()
        ))
        .unwrap();
        let mut s = Safety::new(&cfg);
        let host = "peer.invalid:7443";
        s.resolved
            .insert(host.into(), vec!["203.0.113.90".parse().unwrap()]);
        assert_eq!(
            s.resolve(host).await,
            Some(vec!["203.0.113.90".parse().unwrap()])
        );
        assert!(s.retry, "retried soon");
        assert_eq!(
            s.resolve("203.0.113.91:7443").await,
            Some(vec!["203.0.113.91".parse().unwrap()])
        );
    }
}
