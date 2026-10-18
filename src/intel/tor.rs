use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The bulk exit list. It holds IPv4 addresses only (it is built from the
/// exit lists TorDNSEL measures over IPv4), so a Tor exit that reaches the
/// trap over IPv6 is not recognised as one.
pub const TOR_EXIT_URL: &str = "https://check.torproject.org/torbulkexitlist";

/// A real exit list has well over a thousand entries; fewer than this is a
/// truncated or bogus file, whoever it came from.
pub const MIN_EXITS: u64 = 100;

/// Addresses in an exit list, or an error when it is suspiciously small.
pub fn sane_count(body: &[u8]) -> Result<u64> {
    let count = String::from_utf8_lossy(body)
        .lines()
        .filter(|l| l.trim().parse::<IpAddr>().is_ok())
        .count() as u64;
    anyhow::ensure!(
        count > MIN_EXITS,
        "tor exit list suspiciously small ({count})"
    );
    Ok(count)
}

/// An exit list older than this counts as none: it misses the exits that
/// appeared since, and those would pass for ordinary scanners. As long as a
/// recorded "not an exit" holds (`scan::guard`), and the oldest list a node
/// copies from the cluster (`share::MAX_COPY_AGE_HOURS`).
pub const MAX_AGE: Duration = Duration::from_secs(72 * 3600);

/// Whether a list file last modified at `mtime` is older than [`MAX_AGE`]
/// (a time in the future is not).
pub fn too_old(mtime: SystemTime) -> bool {
    SystemTime::now()
        .duration_since(mtime)
        .is_ok_and(|age| age > MAX_AGE)
}

/// Whether the list file in `data_dir` exists and is older than [`MAX_AGE`].
pub fn stale(data_dir: &Path) -> bool {
    std::fs::metadata(file(data_dir))
        .and_then(|m| m.modified())
        .is_ok_and(too_old)
}

/// The bulk list, and the Onionoo relay index when a sane one is loaded
/// (`super::relays`): an address is an exit if either says so.
#[derive(Clone, Default)]
pub struct TorExitList {
    set: BTreeSet<IpAddr>,
    relays: Option<std::sync::Arc<super::relays::Relays>>,
}

fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("tor-exit.txt")
}

impl TorExitList {
    /// The list file in `data_dir`, empty when there is none or it is
    /// [`stale`], and the relay index there if it is sane.
    pub fn load(data_dir: &Path) -> Result<Self> {
        let relays = super::relays::Relays::load(data_dir).map(std::sync::Arc::new);
        Ok(Self {
            relays,
            ..Self::load_bulk(data_dir)?
        })
    }

    fn load_bulk(data_dir: &Path) -> Result<Self> {
        let path = file(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        if stale(data_dir) {
            tracing::warn!(
                file = %path.display(),
                "tor exit list older than {} h: not used until a fresh one is fetched",
                MAX_AGE.as_secs() / 3600
            );
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).context("reading tor exit list")?;
        let set = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
        Ok(Self { set, relays: None })
    }

    /// Whether neither a bulk list nor a relay index is loaded (so nothing
    /// can be said about any IP).
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.relays().is_none()
    }

    /// Addresses in the bulk list.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether `ip` is an exit: on the bulk list, or one by the relay index.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.set.contains(ip) || self.relays().is_some_and(|r| r.is_exit(ip))
    }

    /// Where the exit status of `ip` comes from: "bulk list", "Onionoo".
    pub fn exit_sources(&self, ip: &IpAddr) -> Vec<&'static str> {
        let mut out = vec![];
        if self.set.contains(ip) {
            out.push("bulk list");
        }
        if self.relays().is_some_and(|r| r.is_exit(ip)) {
            out.push("Onionoo");
        }
        out
    }

    /// The relay index, while it is not older than [`MAX_AGE`].
    pub fn relays(&self) -> Option<&super::relays::Relays> {
        self.relays.as_deref().filter(|r| !r.too_old())
    }

    /// The same without the bulk list (gone stale), keeping the index.
    pub fn without_bulk(&self) -> Self {
        Self {
            set: BTreeSet::new(),
            relays: self.relays.clone(),
        }
    }

    /// Download a fresh list; on failure the old file is left untouched.
    pub async fn refresh(data_dir: &Path) -> Result<u64> {
        // Connect and overall timeouts: a hung connection must not stall the
        // intel scheduler (which also drives the MaxMind refresh) indefinitely.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("building tor http client")?;
        let body = client
            .get(TOR_EXIT_URL)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await
            .context("fetching tor exit list")?;
        let count = sane_count(body.as_bytes())?;
        let tmp = data_dir.join("tor-exit.txt.tmp");
        std::fs::write(&tmp, &body)?;
        std::fs::rename(&tmp, file(data_dir))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn parses_exit_list_and_matches() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tor-exit.txt"),
            "203.0.113.1\n198.51.100.44\n\n2001:db8::5\n",
        )
        .unwrap();
        let list = TorExitList::load(dir.path()).unwrap();
        assert!(list.contains(&"203.0.113.1".parse::<IpAddr>().unwrap()));
        assert!(list.contains(&"2001:db8::5".parse::<IpAddr>().unwrap()));
        assert!(!list.contains(&"192.0.2.9".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn a_stale_list_is_no_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tor-exit.txt");
        std::fs::write(&path, "203.0.113.1\n").unwrap();
        assert!(!stale(dir.path()));
        assert!(!TorExitList::load(dir.path()).unwrap().is_empty());
        let old = SystemTime::now() - MAX_AGE - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(stale(dir.path()));
        assert!(TorExitList::load(dir.path()).unwrap().is_empty());
        assert!(!too_old(SystemTime::now() + Duration::from_secs(3600)));
    }

    #[test]
    fn missing_file_is_empty_list_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let list = TorExitList::load(dir.path()).unwrap();
        assert!(!list.contains(&"203.0.113.1".parse::<IpAddr>().unwrap()));
    }
}
