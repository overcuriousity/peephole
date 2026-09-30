use anyhow::{Context, Result};
use maxminddb::Reader;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Geo {
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
    names: Option<std::collections::HashMap<String, String>>,
}
#[derive(serde::Deserialize)]
struct AsnRecord {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

impl GeoIp {
    pub fn load(data_dir: &Path) -> Result<Self> {
        let city = Reader::open_readfile(data_dir.join("GeoLite2-City.mmdb"))
            .context("opening city mmdb")?;
        let asn = Reader::open_readfile(data_dir.join("GeoLite2-ASN.mmdb"))
            .context("opening asn mmdb")?;
        Ok(Self { city, asn })
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
            g.country = rec
                .country
                .and_then(|c| c.names)
                .and_then(|mut n| n.remove("en"));
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
pub async fn download(data_dir: &Path, account_id: &str, license_key: &str) -> Result<()> {
    for edition in ["GeoLite2-City", "GeoLite2-ASN"] {
        let url = format!(
            "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
        );
        let client = reqwest::Client::new();
        let bytes = client
            .get(&url)
            .basic_auth(account_id, Some(license_key))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        let tar = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(tar);
        let mut found = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            if path.extension().is_some_and(|e| e == "mmdb") {
                let tmp = data_dir.join(format!("{edition}.mmdb.tmp"));
                let mut out = std::fs::File::create(&tmp)?;
                std::io::copy(&mut entry, &mut out)?;
                std::fs::rename(&tmp, data_dir.join(format!("{edition}.mmdb")))?;
                found = true;
            }
        }
        anyhow::ensure!(found, "no .mmdb in {edition} archive");
    }
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
        assert_eq!(g.country.as_deref(), Some("United Kingdom"));
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
