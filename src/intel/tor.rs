use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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

#[derive(Clone, Default)]
pub struct TorExitList {
    set: BTreeSet<IpAddr>,
}

fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("tor-exit.txt")
}

impl TorExitList {
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = file(data_dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path).context("reading tor exit list")?;
        let set = text.lines().filter_map(|l| l.trim().parse().ok()).collect();
        Ok(Self { set })
    }

    /// Whether no list is loaded (so nothing can be said about any IP).
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Addresses in the list.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.set.contains(ip)
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
    fn missing_file_is_empty_list_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let list = TorExitList::load(dir.path()).unwrap();
        assert!(!list.contains(&"203.0.113.1".parse::<IpAddr>().unwrap()));
    }
}
