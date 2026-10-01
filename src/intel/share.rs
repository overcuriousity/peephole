//! Intel sharing in a cluster: one node fetches the GeoLite2 databases
//! (only key holders) and the Tor exit list, announces each file version
//! with a signed manifest, and every other node copies the file from any
//! peer that holds that exact version (verified by SHA-256).
//!
//! Who fetches: each node ranks itself among the live eligible members
//! (dialable ones first, then by key); the node at rank `r` fetches once
//! the current version is older than `24h * (r + 1)`. Rank 0 is the
//! elected fetcher; the others only step in if it keeps failing.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{IntelManifestRec, Record};
use crate::store::recorder::Recorder;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::{info, warn};

pub const CITY: &str = "geolite2-city";
pub const ASN: &str = "geolite2-asn";
pub const TOR: &str = "tor-exits";
pub const KINDS: [&str; 3] = [CITY, ASN, TOR];

/// Bytes per chunk request.
pub const CHUNK: u64 = 4 * 1024 * 1024;

pub fn file_name(kind: &str) -> Option<&'static str> {
    match kind {
        CITY => Some("GeoLite2-City.mmdb"),
        ASN => Some("GeoLite2-ASN.mmdb"),
        TOR => Some("tor-exit.txt"),
        _ => None,
    }
}

/// `(mtime, size, sha256)` of a file we hashed already.
type Hashed = (SystemTime, u64, String);
static HASHES: Mutex<Option<HashMap<PathBuf, Hashed>>> = Mutex::new(None);

/// SHA-256 (hex) and size of a file; cached until it changes.
pub fn file_hash(path: &Path) -> Result<(String, u64)> {
    let meta = std::fs::metadata(path)?;
    let key = (meta.modified()?, meta.len());
    if let Some((m, s, h)) = HASHES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(path)
        && (*m, *s) == key
    {
        return Ok((h.clone(), *s));
    }
    let mut f = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hex = data_encoding::HEXLOWER.encode(&hasher.finalize());
    HASHES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(path.to_path_buf(), (key.0, key.1, hex.clone()));
    Ok((hex, key.1))
}

/// The newest announced version of a file.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub kind: String,
    pub sha256: String,
    pub size: u64,
    pub fetched_at: String,
    pub origin: Option<NodeId>,
}

impl Manifest {
    /// Hours since it was fetched (fetch time as stated by its fetcher).
    pub fn age_hours(&self) -> f64 {
        chrono::NaiveDateTime::parse_from_str(&self.fetched_at, "%Y-%m-%d %H:%M:%S")
            .map(|t| (chrono::Utc::now().naive_utc() - t).num_seconds() as f64 / 3600.0)
            .unwrap_or(f64::INFINITY)
    }
}

pub async fn manifests(store: &crate::store::Store) -> Result<HashMap<String, Manifest>> {
    type Row = (String, String, i64, String, Option<Vec<u8>>);
    let rows: Vec<Row> =
        sqlx::query_as("SELECT kind, sha256, size, fetched_at, origin FROM intel_files")
            .fetch_all(&store.pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(kind, sha256, size, fetched_at, origin)| {
            (
                kind.clone(),
                Manifest {
                    kind,
                    sha256,
                    size: size as u64,
                    fetched_at,
                    origin: origin.and_then(|o| NodeId::from_slice(&o).ok()),
                },
            )
        })
        .collect())
}

/// Announce the local copies of `kinds` as their newest version.
pub async fn publish(node: &Node, data_dir: &Path, kinds: &[&str]) -> Result<()> {
    let mut records = vec![];
    for kind in kinds {
        let name = file_name(kind).context("unknown intel kind")?;
        let (sha256, size) = file_hash(&data_dir.join(name))?;
        records.push(Record::IntelManifest(IntelManifestRec {
            kind: kind.to_string(),
            sha256,
            size,
            fetched_at: crate::store::data::now_ts(),
        }));
    }
    crate::cluster::repl::append(node, &records).await?;
    Ok(())
}

/// Position of `me` in the fetch order of `eligible`: members with an
/// address first, then by key. None if `me` is not eligible.
pub fn rank(me: NodeId, eligible: &[(NodeId, bool)]) -> Option<usize> {
    let mut order = eligible.to_vec();
    order.sort_by_key(|(id, dialable)| (!dialable, *id));
    order.iter().position(|(id, _)| *id == me)
}

/// Whether the node at `rank` should fetch a file `age_hours` old.
pub fn due(rank: usize, age_hours: f64) -> bool {
    age_hours > 24.0 * (rank as f64 + 1.0)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChunkReq {
    pub kind: String,
    pub sha256: String,
    pub offset: u64,
    pub len: u64,
}

/// A chunk of our copy of `kind`, if we hold exactly that version.
pub fn read_chunk(data_dir: &Path, req: &ChunkReq) -> Result<Option<Vec<u8>>> {
    let Some(name) = file_name(&req.kind) else {
        return Ok(None);
    };
    let path = data_dir.join(name);
    if !path.exists() || file_hash(&path)?.0 != req.sha256 {
        return Ok(None);
    }
    use std::io::Seek;
    let mut f = std::fs::File::open(&path)?;
    f.seek(std::io::SeekFrom::Start(req.offset))?;
    let mut buf = vec![0u8; req.len.min(CHUNK) as usize];
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(Some(buf))
}

/// Copy the announced version of `m` from a peer; the file is replaced
/// atomically only if size and hash match.
async fn download(node: &Node, data_dir: &Path, m: &Manifest) -> Result<()> {
    let name = file_name(&m.kind).context("unknown intel kind")?;
    let mut peers = node.dial_targets();
    // The fetcher first: it certainly holds the file.
    peers.sort_by_key(|(id, _, _)| Some(*id) != m.origin);
    let tmp = data_dir.join(format!("{name}.part"));
    let mut last_err = None;
    for (peer, _, addr) in peers {
        let mut out = Vec::with_capacity(m.size as usize);
        let fetched = async {
            while (out.len() as u64) < m.size {
                let req = ChunkReq {
                    kind: m.kind.clone(),
                    sha256: m.sha256.clone(),
                    offset: out.len() as u64,
                    len: CHUNK,
                };
                let (status, bytes) = node.call_raw(peer, &addr, "/rpc/v1/intel", &req).await?;
                if !status.is_success() || bytes.is_empty() {
                    bail!("peer does not hold this version (HTTP {status})");
                }
                out.extend_from_slice(&bytes);
            }
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = fetched {
            last_err = Some(e);
            continue;
        }
        let sha = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(&out));
        if out.len() as u64 != m.size || sha != m.sha256 {
            last_err = Some(anyhow::anyhow!(
                "{name} from {} failed verification",
                peer.short()
            ));
            continue;
        }
        std::fs::write(&tmp, &out)?;
        std::fs::rename(&tmp, data_dir.join(name))?;
        return Ok(());
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no peer to copy {name} from")))
}

/// Bring local copies up to the announced versions; returns the kinds
/// that changed.
pub async fn sync_files(node: &Node, data_dir: &Path) -> Result<Vec<String>> {
    let mut changed = vec![];
    for (kind, m) in manifests(&node.store).await? {
        let Some(name) = file_name(&kind) else {
            continue;
        };
        let path = data_dir.join(name);
        if path.exists() && file_hash(&path)?.0 == m.sha256 {
            continue;
        }
        match download(node, data_dir, &m).await {
            Ok(()) => {
                info!(%kind, sha = %&m.sha256[..12], "intel file copied from the cluster");
                changed.push(kind);
            }
            Err(e) => warn!(%kind, error = %format!("{e:#}"), "intel file copy failed"),
        }
    }
    Ok(changed)
}

/// Enrich IPs that have no GeoIP data yet (they were recorded by nodes
/// without the databases). Only the node that fetched the current
/// databases does this, so the cluster writes each fact once.
pub async fn backfill_missing_geo(rec: &Recorder, geo: &super::SharedGeo) -> Result<usize> {
    let rows: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, ip, is_tor_exit FROM ips WHERE country IS NULL AND asn IS NULL LIMIT 5000",
    )
    .fetch_all(&rec.store().pool)
    .await?;
    let updates: Vec<_> = {
        let guard = geo.read().unwrap();
        let Some(g) = guard.as_ref() else {
            return Ok(0);
        };
        rows.into_iter()
            .filter_map(|(id, ip, tor)| {
                let hit = g.lookup(&ip.parse().ok()?);
                (hit.country.is_some() || hit.asn.is_some()).then_some((id, hit, tor))
            })
            .collect()
    };
    let n = updates.len();
    for (id, g, tor) in updates {
        rec.enrich_ip(id, g.country.as_deref(), g.asn, g.asn_org.as_deref(), tor)
            .await?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_order_prefers_dialable_then_key_and_staggers_failover() {
        let ids: Vec<NodeId> = (0..3)
            .map(|_| crate::cluster::identity::Identity::generate().unwrap().id)
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        let eligible = vec![(sorted[0], false), (sorted[1], true), (sorted[2], true)];
        // The outbound-only node goes last despite the lowest key.
        assert_eq!(rank(sorted[1], &eligible), Some(0));
        assert_eq!(rank(sorted[2], &eligible), Some(1));
        assert_eq!(rank(sorted[0], &eligible), Some(2));
        assert_eq!(
            rank(
                crate::cluster::identity::Identity::generate().unwrap().id,
                &eligible
            ),
            None
        );
        assert!(!due(0, 23.0) && due(0, 25.0));
        assert!(!due(1, 47.0) && due(1, 49.0));
        assert!(due(0, f64::INFINITY), "never fetched: due at once");
    }

    #[test]
    fn chunks_are_served_only_for_the_exact_version() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("tor-exit.txt"), b"192.0.2.1\n192.0.2.2\n").unwrap();
        let (sha, size) = file_hash(&dir.path().join("tor-exit.txt")).unwrap();
        assert_eq!(size, 20);
        let req = |sha: &str, offset| ChunkReq {
            kind: TOR.into(),
            sha256: sha.into(),
            offset,
            len: 10,
        };
        assert_eq!(
            read_chunk(dir.path(), &req(&sha, 10)).unwrap().unwrap(),
            b"192.0.2.2\n"
        );
        assert!(read_chunk(dir.path(), &req("00", 0)).unwrap().is_none());
    }
}
