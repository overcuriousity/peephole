//! Every running Tor relay, from Onionoo (GH #138): which relays an address
//! belongs to, in which role, and whether it exits. The bulk exit list
//! ([`super::tor`]) holds IPv4 exits only; this adds the IPv6 exits, the
//! exit addresses Onionoo observed, and the guards and middles (which are
//! information only, never a reason to refuse a scan).
//!
//! The Onionoo document (about 27 MB) is reduced to `tor-relays.json`: the
//! publish time and one compact record per relay with its addresses. The
//! node indexes it by address on load. That file is what the cluster shares.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Running relays with just the fields the index keeps.
pub const ONIONOO_URL: &str = "https://onionoo.torproject.org/details?running=true&fields=nickname,fingerprint,or_addresses,exit_addresses,flags,exit_policy_summary,exit_policy_v6_summary,effective_family,first_seen,version";

pub const FILE: &str = "tor-relays.json";

/// A real consensus has several thousand running relays; fewer than this is
/// a truncated or bogus file, whoever it came from.
pub const MIN_RELAYS: usize = 1000;

/// The largest Onionoo answer read (it is about 27 MB uncompressed).
const MAX_BODY: usize = 128 * 1024 * 1024;

/// One relay as the index keeps it. No contact, by decision (MIK-507).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Relay {
    pub nickname: String,
    pub fingerprint: String,
    /// `ip:port` as Onionoo writes them (`[v6]:port` for IPv6).
    #[serde(default)]
    pub or_addresses: Vec<String>,
    /// Addresses it was seen exiting from that differ from its ORPorts.
    #[serde(default)]
    pub exit_addresses: Vec<String>,
    #[serde(default)]
    pub flags: Vec<String>,
    /// The `Exit` flag, or an IPv4 or IPv6 exit policy that is not
    /// `reject *:*`: every address of the relay counts as an exit then.
    pub exit: bool,
    #[serde(default)]
    pub family_size: usize,
    #[serde(default)]
    pub first_seen: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

impl Relay {
    /// Its roles, lower case: `exit`, `guard`, `middle` (neither), `hsdir`.
    pub fn roles(&self) -> Vec<&'static str> {
        let flag = |f: &str| self.flags.iter().any(|x| x == f);
        let mut out = vec![];
        if self.exit {
            out.push("exit");
        }
        if flag("Guard") {
            out.push("guard");
        }
        if out.is_empty() {
            out.push("middle");
        }
        if flag("HSDir") {
            out.push("hsdir");
        }
        out
    }

    /// The ORPorts it listens on at `ip`.
    pub fn or_ports(&self, ip: &IpAddr) -> Vec<u16> {
        self.or_addresses
            .iter()
            .filter_map(|a| a.parse::<SocketAddr>().ok())
            .filter(|s| crate::net::canonical(s.ip()) == *ip)
            .map(|s| s.port())
            .collect()
    }
}

/// `tor-relays.json`.
#[derive(Serialize, Deserialize)]
struct Stored {
    relays_published: Option<String>,
    /// Onionoo's `Last-Modified`, sent back as `If-Modified-Since`.
    #[serde(default)]
    last_modified: Option<String>,
    #[serde(default)]
    relays: Vec<Relay>,
}

#[derive(Deserialize)]
struct Details {
    relays_published: Option<String>,
    #[serde(default)]
    relays: Vec<OnionooRelay>,
}

#[derive(Deserialize)]
struct OnionooRelay {
    #[serde(default)]
    nickname: String,
    fingerprint: String,
    #[serde(default)]
    or_addresses: Vec<String>,
    #[serde(default)]
    exit_addresses: Vec<String>,
    #[serde(default)]
    flags: Vec<String>,
    exit_policy_summary: Option<serde_json::Value>,
    exit_policy_v6_summary: Option<serde_json::Value>,
    #[serde(default)]
    effective_family: Vec<String>,
    first_seen: Option<String>,
    version: Option<String>,
}

/// Whether an Onionoo policy summary is `reject *:*`.
fn rejects_all(summary: &serde_json::Value) -> bool {
    summary.get("accept").is_none()
        && summary
            .get("reject")
            .and_then(|r| r.as_array())
            .is_some_and(|r| r.len() == 1 && r[0] == "1-65535")
}

impl OnionooRelay {
    /// Fails toward "exit": a missing IPv4 summary counts as exiting.
    /// Onionoo leaves the IPv6 summary out when it rejects everything.
    fn exits(&self) -> bool {
        self.flags.iter().any(|f| f == "Exit")
            || self
                .exit_policy_summary
                .as_ref()
                .is_none_or(|s| !rejects_all(s))
            || self
                .exit_policy_v6_summary
                .as_ref()
                .is_some_and(|s| !rejects_all(s))
    }

    fn reduce(self) -> Relay {
        let exit = self.exits();
        Relay {
            nickname: self.nickname,
            fingerprint: self.fingerprint,
            or_addresses: self.or_addresses,
            exit_addresses: self.exit_addresses,
            flags: self.flags,
            exit,
            family_size: self.effective_family.len().max(1),
            first_seen: self.first_seen,
            version: self.version,
        }
    }
}

/// The address in an Onionoo `ip:port`, `[v6]:port` or bare address.
fn ip_of(addr: &str) -> Option<IpAddr> {
    addr.parse::<SocketAddr>()
        .map(|s| s.ip())
        .or_else(|_| addr.trim_matches(['[', ']']).parse())
        .ok()
        .map(crate::net::canonical)
}

const TS: &str = "%Y-%m-%d %H:%M:%S";

/// The relay index, by address.
#[derive(Debug)]
pub struct Relays {
    published: String,
    published_at: chrono::NaiveDateTime,
    last_modified: Option<String>,
    relays: Vec<Relay>,
    by_ip: HashMap<IpAddr, Vec<usize>>,
    exits: HashSet<IpAddr>,
}

impl Relays {
    fn index(s: Stored) -> Result<Self> {
        let published = s
            .relays_published
            .context("tor relay index without relays_published")?;
        let published_at = chrono::NaiveDateTime::parse_from_str(&published, TS)
            .with_context(|| format!("tor relay index: bad relays_published {published:?}"))?;
        let mut by_ip: HashMap<IpAddr, Vec<usize>> = HashMap::new();
        let mut exits = HashSet::new();
        for (i, r) in s.relays.iter().enumerate() {
            for ip in r.or_addresses.iter().filter_map(|a| ip_of(a)) {
                let at = by_ip.entry(ip).or_default();
                if !at.contains(&i) {
                    at.push(i);
                }
                if r.exit {
                    exits.insert(ip);
                }
            }
            // Seen exiting from there: an exit whatever the policy says.
            for ip in r.exit_addresses.iter().filter_map(|a| ip_of(a)) {
                let at = by_ip.entry(ip).or_default();
                if !at.contains(&i) {
                    at.push(i);
                }
                exits.insert(ip);
            }
        }
        Ok(Self {
            published,
            published_at,
            last_modified: s.last_modified,
            relays: s.relays,
            by_ip,
            exits,
        })
    }

    /// An Onionoo `details` document, reduced. Not checked for sanity.
    pub fn from_onionoo(body: &[u8], last_modified: Option<String>) -> Result<Self> {
        let d: Details = serde_json::from_slice(body).context("parsing onionoo details")?;
        Self::index(Stored {
            relays_published: d.relays_published,
            last_modified,
            relays: d.relays.into_iter().map(OnionooRelay::reduce).collect(),
        })
    }

    /// A `tor-relays.json`. Not checked for sanity.
    pub fn parse(body: &[u8]) -> Result<Self> {
        Self::index(serde_json::from_slice(body).context("parsing tor relay index")?)
    }

    /// The file form.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(&Stored {
            relays_published: Some(self.published.clone()),
            last_modified: self.last_modified.clone(),
            relays: self.relays.clone(),
        })
        .unwrap_or_default()
    }

    /// Whether its publish time is older than [`super::tor::MAX_AGE`].
    pub fn too_old(&self) -> bool {
        let age = chrono::Utc::now().naive_utc() - self.published_at;
        age.to_std().is_ok_and(|a| a > super::tor::MAX_AGE)
    }

    /// Too few relays, or too old: a truncated, bogus or stale index.
    pub fn sane(&self) -> Result<()> {
        anyhow::ensure!(
            self.relays.len() >= MIN_RELAYS,
            "tor relay index suspiciously small ({} relays)",
            self.relays.len()
        );
        anyhow::ensure!(
            !self.too_old(),
            "tor relay index published {} UTC, older than {} h",
            self.published,
            super::tor::MAX_AGE.as_secs() / 3600
        );
        Ok(())
    }

    /// Relays in a `tor-relays.json`, or an error when it fails [`sane`].
    pub fn check(body: &[u8]) -> Result<usize> {
        let r = Self::parse(body)?;
        r.sane()?;
        Ok(r.relays.len())
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// `relays_published` as Onionoo states it (UTC).
    pub fn published(&self) -> &str {
        &self.published
    }

    /// Whether Onionoo says `ip` exits Tor traffic.
    pub fn is_exit(&self, ip: &IpAddr) -> bool {
        self.exits.contains(&crate::net::canonical(*ip))
    }

    /// The relays at `ip`.
    pub fn at(&self, ip: &IpAddr) -> Vec<&Relay> {
        self.by_ip
            .get(&crate::net::canonical(*ip))
            .map(|v| v.iter().map(|&i| &self.relays[i]).collect())
            .unwrap_or_default()
    }

    /// The index in `data_dir`: None when there is none, or it fails
    /// [`sane`] (warned once per file version). The bulk exit list then
    /// works alone, as before.
    pub fn load(data_dir: &Path) -> Option<Self> {
        let path = file(data_dir);
        let stamp = std::fs::metadata(&path)
            .ok()
            .and_then(|m| Some((m.modified().ok()?, m.len())))?;
        let loaded = std::fs::read(&path)
            .context("reading tor relay index")
            .and_then(|b| Self::parse(&b))
            .and_then(|r| r.sane().map(|()| r));
        match loaded {
            Ok(r) => Some(r),
            Err(e) => {
                static WARNED: Mutex<Option<(PathBuf, SystemTime, u64)>> = Mutex::new(None);
                let key = (path.clone(), stamp.0, stamp.1);
                let mut w = crate::lock::MutexExt::lock_or_recover(&WARNED);
                if w.as_ref() != Some(&key) {
                    tracing::warn!(
                        file = %path.display(),
                        error = %format!("{e:#}"),
                        "tor relay index not used: only the bulk exit list says what is an exit"
                    );
                    *w = Some(key);
                }
                None
            }
        }
    }

    /// Fetch Onionoo (conditionally) and replace the file if it changed;
    /// on failure the old file is left untouched.
    pub async fn refresh(data_dir: &Path) -> Result<Refreshed> {
        let since = std::fs::read(file(data_dir))
            .ok()
            .and_then(|b| serde_json::from_slice::<Stored>(&b).ok())
            .and_then(|s| s.last_modified);
        // As for the bulk list: a hung connection must not hold the refresh
        // forever. Longer overall, the answer is tens of megabytes.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(180))
            .build()
            .context("building onionoo http client")?;
        let mut req = client.get(ONIONOO_URL);
        if let Some(s) = &since {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, s);
        }
        let mut resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Refreshed::NotModified);
        }
        resp = resp.error_for_status()?;
        let last_modified = resp
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.context("fetching onionoo details")? {
            anyhow::ensure!(
                body.len() + chunk.len() <= MAX_BODY,
                "onionoo answer over {MAX_BODY} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        let dir = data_dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            let r = Self::from_onionoo(&body, last_modified)?;
            r.sane()?;
            let tmp = dir.join(format!("{FILE}.tmp"));
            std::fs::write(&tmp, r.to_json())?;
            std::fs::rename(&tmp, file(&dir))?;
            Ok(Refreshed::Updated(r.len()))
        })
        .await?
    }
}

/// What a [`Relays::refresh`] did.
#[derive(Debug, PartialEq)]
pub enum Refreshed {
    /// Relays in the new file.
    Updated(usize),
    /// Onionoo answered 304: the file stays.
    NotModified,
}

/// Tags of a `tor-relays` result: `exit`, the roles of its relays.
pub fn tags(data: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    if data.get("exit").and_then(|e| e.as_bool()) == Some(true) {
        out.push("exit".into());
    }
    let roles = data
        .get("relays")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("roles")?.as_array())
        .flatten()
        .filter_map(|r| r.as_str());
    for r in roles {
        if !out.iter().any(|o| o == r) {
            out.push(r.to_string());
        }
    }
    out
}

pub fn file(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

/// Test support: the Onionoo fixture, published now and padded with
/// middle relays (on 10.0.0.0/8) to pass [`MIN_RELAYS`].
#[cfg(test)]
pub fn fixture_index() -> Relays {
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read("tests/fixtures/onionoo-details.json").unwrap())
            .unwrap();
    v["relays_published"] = chrono::Utc::now().format(TS).to_string().into();
    let relays = v["relays"].as_array_mut().unwrap();
    for i in 0..MIN_RELAYS {
        relays.push(serde_json::json!({
            "nickname": format!("pad{i}"),
            "fingerprint": format!("{i:040X}"),
            "or_addresses": [format!("10.{}.{}.1:9001", i / 256, i % 256)],
            "flags": ["Running", "Valid"],
            "exit_policy_summary": {"reject": ["1-65535"]},
        }));
    }
    Relays::from_onionoo(
        &serde_json::to_vec(&v).unwrap(),
        Some("Sun, 18 Oct 2026 10:00:00 GMT".into()),
    )
    .unwrap()
}

/// Test support: [`fixture_index`] written to `data_dir`.
#[cfg(test)]
pub fn write_fixture(data_dir: &Path) {
    std::fs::write(file(data_dir), fixture_index().to_json()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn indexes_every_address_of_a_relay_in_both_families() {
        let r = fixture_index();
        for a in ["144.76.159.218", "2a01:4f8:200:32e6::2"] {
            let at = r.at(&ip(a));
            assert_eq!(at.len(), 1, "{a}");
            assert_eq!(at[0].nickname, "BEEzar");
            assert!(!at[0].exit);
            assert_eq!(at[0].roles(), ["guard", "hsdir"]);
            assert_eq!(at[0].or_ports(&ip(a)), [8443]);
            assert!(!r.is_exit(&ip(a)), "a guard is not an exit");
        }
        assert!(r.at(&ip("192.0.2.99")).is_empty());
    }

    #[test]
    fn exits_are_or_addresses_of_exiting_relays_and_their_exit_addresses() {
        let r = fixture_index();
        // Exit flag and accepting policies: both ORPorts, both exit addresses.
        for a in [
            "198.51.100.20",
            "2001:db8:6::1",
            "203.0.113.77",
            "2001:db8:6::99",
        ] {
            assert!(r.is_exit(&ip(a)), "{a}");
            assert_eq!(r.at(&ip(a))[0].nickname, "SixExit");
        }
        // No Exit flag, but an IPv6 policy that accepts: fails toward exit.
        assert!(r.is_exit(&ip("2001:db8:40::1")));
        assert!(r.is_exit(&ip("192.0.2.40")));
        // reject *:* on both families: a middle.
        assert!(!r.is_exit(&ip("2001:db8:30::1")));
        assert_eq!(r.at(&ip("2001:db8:30::1"))[0].roles(), ["middle"]);
        // An IPv4-mapped form is the same address.
        assert!(r.is_exit(&ip("::ffff:198.51.100.20")));
    }

    #[test]
    fn the_file_form_round_trips_and_passes_the_sanity_check() {
        let r = fixture_index();
        let body = r.to_json();
        assert_eq!(Relays::check(&body).unwrap(), r.len());
        let back = Relays::parse(&body).unwrap();
        assert_eq!(back.at(&ip("144.76.159.218")), r.at(&ip("144.76.159.218")));
        assert_eq!(back.last_modified, r.last_modified);
        assert!(!body.windows(7).any(|w| w == b"contact"));
    }

    #[test]
    fn truncated_unpublished_or_stale_indexes_are_rejected() {
        let truncated = std::fs::read("tests/fixtures/onionoo-details.json").unwrap();
        let few = Relays::from_onionoo(&truncated, None).unwrap();
        assert!(format!("{:#}", few.sane().unwrap_err()).contains("suspiciously small"));
        let cut = &truncated[..truncated.len() / 2];
        assert!(Relays::from_onionoo(cut, None).is_err(), "cut JSON");
        let mut v: serde_json::Value = serde_json::from_slice(&fixture_index().to_json()).unwrap();
        v.as_object_mut().unwrap().remove("relays_published");
        assert!(Relays::check(&serde_json::to_vec(&v).unwrap()).is_err());
        let old = chrono::Utc::now() - super::super::tor::MAX_AGE - chrono::Duration::hours(1);
        v["relays_published"] = old.format(TS).to_string().into();
        let e = Relays::check(&serde_json::to_vec(&v).unwrap()).unwrap_err();
        assert!(format!("{e:#}").contains("older than"), "{e:#}");
    }

    #[test]
    fn load_skips_a_rejected_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Relays::load(dir.path()).is_none(), "no file");
        std::fs::write(file(dir.path()), b"{\"relays\":[]}").unwrap();
        assert!(Relays::load(dir.path()).is_none(), "rejected");
        write_fixture(dir.path());
        assert!(Relays::load(dir.path()).is_some());
    }
}
