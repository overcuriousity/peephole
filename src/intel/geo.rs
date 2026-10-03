use anyhow::{Context, Result};
use maxminddb::Reader;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Geo {
    /// ISO 3166-1 alpha-2 code, e.g. "DE".
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

pub struct GeoIp {
    city: Reader<Vec<u8>>,
    asn: Reader<Vec<u8>>,
}

#[derive(serde::Deserialize)]
struct CityRecord {
    country: Option<CountryRecord>,
}
#[derive(serde::Deserialize)]
struct CountryRecord {
    iso_code: Option<String>,
}
#[derive(serde::Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

/// The GeoLite2 editions a node downloads.
pub const EDITIONS: [&str; 2] = ["GeoLite2-City", "GeoLite2-ASN"];

impl GeoIp {
    /// Read both databases into memory. Blocking (tens of MB of file I/O):
    /// from async code use [`GeoIp::load_blocking`].
    pub fn load(data_dir: &Path) -> Result<Self> {
        let city = Reader::open_readfile(data_dir.join("GeoLite2-City.mmdb"))
            .context("opening city mmdb")?;
        let asn = Reader::open_readfile(data_dir.join("GeoLite2-ASN.mmdb"))
            .context("opening asn mmdb")?;
        Ok(Self { city, asn })
    }

    /// [`GeoIp::load`] on a blocking thread, off the async workers.
    pub async fn load_blocking(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.to_path_buf();
        tokio::task::spawn_blocking(move || Self::load(&dir))
            .await
            .context("maxmind load task")?
    }

    /// Build date of the city database (`YYYY-MM-DD`), as the version of
    /// the data a lookup came from.
    pub fn build_date(&self) -> Option<String> {
        chrono::DateTime::from_timestamp(self.city.metadata().build_epoch as i64, 0)
            .map(|t| t.format("%Y-%m-%d").to_string())
    }

    pub fn lookup(&self, ip: &IpAddr) -> Geo {
        let mut g = Geo::default();
        // maxminddb 0.32: lookup yields a LookupResult; decode the record.
        if let Some(rec) = self
            .city
            .lookup(*ip)
            .ok()
            .and_then(|r| r.decode::<CityRecord>().ok().flatten())
        {
            // ISO 3166-1 alpha-2: the map, flags and country filters all key on it.
            g.country = rec
                .country
                .and_then(|c| c.iso_code)
                .map(|c| c.to_ascii_uppercase());
        }
        if let Some(rec) = self
            .asn
            .lookup(*ip)
            .ok()
            .and_then(|r| r.decode::<AsnRecord>().ok().flatten())
        {
            g.asn = rec.autonomous_system_number;
            g.asn_org = rec.autonomous_system_organization;
        }
        g
    }
}

/// Download GeoLite2-City and GeoLite2-ASN into `data_dir` (spec §9).
///
/// The HTTP client has connect and overall timeouts so one hung TLS
/// connection cannot stall the whole intel scheduler forever. The archive is
/// decompressed and the database validated (opened as an mmdb) in a temp file
/// *before* it replaces the working copy, so a truncated or corrupt download
/// never overwrites a good database. The blocking gunzip/untar/write runs on a
/// blocking thread.
pub async fn download(data_dir: &Path, account_id: &str, license_key: &str) -> Result<()> {
    let client = client()?;
    for edition in EDITIONS {
        download_with(&client, data_dir, edition, account_id, license_key).await?;
    }
    Ok(())
}

/// Download one edition (see [`download`]).
pub async fn download_edition(
    data_dir: &Path,
    edition: &'static str,
    account_id: &str,
    license_key: &str,
) -> Result<()> {
    download_with(&client()?, data_dir, edition, account_id, license_key).await
}

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("building maxmind http client")
}

async fn download_with(
    client: &reqwest::Client,
    data_dir: &Path,
    edition: &'static str,
    account_id: &str,
    license_key: &str,
) -> Result<()> {
    let url =
        format!("https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz");
    let bytes = client
        .get(&url)
        .basic_auth(account_id, Some(license_key))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let data_dir = data_dir.to_path_buf();
    tokio::task::spawn_blocking(move || extract_and_install(&data_dir, edition, &bytes))
        .await
        .context("maxmind extract task")??;
    Ok(())
}

/// Decompress one edition's archive to a temp file, verify it parses as an
/// mmdb, then atomically move it into place.
fn extract_and_install(data_dir: &Path, edition: &str, bytes: &[u8]) -> Result<()> {
    let tar = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(tar);
    let tmp = data_dir.join(format!("{edition}.mmdb.tmp"));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.extension().is_some_and(|e| e == "mmdb") {
            let mut out = std::fs::File::create(&tmp)?;
            std::io::copy(&mut entry, &mut out)?;
            found = true;
        }
    }
    if !found {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("no .mmdb in {edition} archive");
    }
    // Validate before replacing the working copy.
    if let Err(e) = Reader::open_readfile(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::Error::new(e).context(format!("{edition}: downloaded mmdb is invalid")));
    }
    std::fs::rename(&tmp, data_dir.join(format!("{edition}.mmdb")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // Uses the MaxMind-DB test fixture downloaded by Step 0 below.
    #[test]
    fn lookup_known_ip_from_fixture() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            "tests/fixtures/GeoLite2-City-Test.mmdb",
            dir.path().join("GeoLite2-City.mmdb"),
        )
        .unwrap();
        std::fs::copy(
            "tests/fixtures/GeoLite2-ASN-Test.mmdb",
            dir.path().join("GeoLite2-ASN.mmdb"),
        )
        .unwrap();
        let geo = GeoIp::load(dir.path()).unwrap();
        let g = geo.lookup(&"2.125.160.216".parse::<IpAddr>().unwrap());
        assert_eq!(g.country.as_deref(), Some("GB"));
    }

    #[test]
    fn unknown_ip_yields_empty_geo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::copy(
            "tests/fixtures/GeoLite2-City-Test.mmdb",
            dir.path().join("GeoLite2-City.mmdb"),
        )
        .unwrap();
        std::fs::copy(
            "tests/fixtures/GeoLite2-ASN-Test.mmdb",
            dir.path().join("GeoLite2-ASN.mmdb"),
        )
        .unwrap();
        let geo = GeoIp::load(dir.path()).unwrap();
        let g = geo.lookup(&"10.1.2.3".parse::<IpAddr>().unwrap());
        assert!(g.country.is_none());
    }
}
