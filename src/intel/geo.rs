use anyhow::{Context, Result};
use maxminddb::Reader;
use std::net::IpAddr;
use std::path::Path;

use crate::store::Store;

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

impl GeoIp {
    /// Re-resolve rows from [`Store::ips_with_legacy_country`] to fresh
    /// geo data. Synchronous so callers can hold the shared lock briefly and
    /// release it before the async write in [`backfill_iso_codes`].
    pub fn relookup(&self, rows: &[(i64, String, String)]) -> Vec<(i64, Geo)> {
        rows.iter()
            .map(|(id, ip, legacy)| {
                let mut g = ip.parse().map(|ip| self.lookup(&ip)).unwrap_or_default();
                if g.country.is_none() {
                    // No longer in the database: map the stored English name.
                    g.country = crate::admin::countries::code_for_name(legacy).map(str::to_string);
                }
                (*id, g)
            })
            .collect()
    }
}

/// Older builds stored the English country name instead of the ISO code,
/// which left the choropleth empty. Rewrite those rows; returns how many
/// were fixed. Rows that cannot be resolved are left untouched.
pub async fn backfill_iso_codes(store: &Store, updates: Vec<(i64, Geo)>) -> Result<usize> {
    let mut n = 0;
    for (id, g) in updates {
        let Some(code) = g.country.as_deref() else {
            continue;
        };
        store
            .set_ip_geo(id, Some(code), g.asn, g.asn_org.as_deref())
            .await?;
        n += 1;
    }
    Ok(n)
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
        assert_eq!(g.country.as_deref(), Some("GB"));
    }

    #[tokio::test]
    async fn backfill_rewrites_legacy_country_names() {
        let dir = tempfile::tempdir().unwrap();
        for f in ["GeoLite2-City", "GeoLite2-ASN"] {
            std::fs::copy(
                format!("tests/fixtures/{f}-Test.mmdb"),
                dir.path().join(format!("{f}.mmdb")),
            )
            .unwrap();
        }
        let geo = GeoIp::load(dir.path()).unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let gb = store
            .upsert_ip("2.125.160.216".parse().unwrap())
            .await
            .unwrap();
        store
            .set_ip_geo(gb.id, Some("United Kingdom"), None, None)
            .await
            .unwrap();
        let de = store.upsert_ip("10.0.0.1".parse().unwrap()).await.unwrap();
        store
            .set_ip_geo(de.id, Some("DE"), None, None)
            .await
            .unwrap();

        let rows = store.ips_with_legacy_country().await.unwrap();
        assert_eq!(rows.len(), 1);
        let n = backfill_iso_codes(&store, geo.relookup(&rows))
            .await
            .unwrap();
        assert_eq!(n, 1);
        let gb = store.ip_by_id(gb.id).await.unwrap().unwrap();
        assert_eq!(gb.country.as_deref(), Some("GB"));
        let de = store.ip_by_id(de.id).await.unwrap().unwrap();
        assert_eq!(de.country.as_deref(), Some("DE"), "ISO rows untouched");
        assert!(store.ips_with_legacy_country().await.unwrap().is_empty());
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
