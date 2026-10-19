//! The X4BNet datacenter ASN list (MIT, `rules/evidence/x4bnet/`): the
//! source of the `net.hosting` evidence rows (docs/detection.md, "AS
//! type"). A snapshot is built in; a fetched copy in the data dir
//! supersedes it, refreshed daily like the Tor exit list, and a failed
//! fetch keeps the last good copy. The list says "hosting" and nothing
//! else: an ASN missing from it is not thereby an eyeball network.
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The list upstream.
pub const X4B_URL: &str =
    "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/input/datacenter/ASN.txt";

/// The built-in snapshot, unmodified.
pub const BUILTIN: &str = include_str!("../../rules/evidence/x4bnet/ASN.txt");
/// The day of the upstream commit the snapshot is from, and that commit.
pub const SNAPSHOT_DATE: &str = "2026-10-17";
pub const SNAPSHOT_COMMIT: &str = "5eaa1bb207164e270eeee579b3d0a09edd794fa1";

/// The list holds over 900 ASNs; fewer than this is a truncated or bogus
/// file.
pub const MIN_ASNS: usize = 300;

/// `intel_meta` key: the last successful fetch.
pub const FETCHED_KEY: &str = "asn_hosting_last_fetch";

/// The fetched copy in `data_dir`.
pub fn file(data_dir: &Path) -> PathBuf {
    data_dir.join("x4b-datacenter-asn.txt")
}

/// The ASNs in a list: one `AS<n>` per line, a `#` starts a comment. Any
/// other line, or fewer than [`MIN_ASNS`], is an error (an HTML error page,
/// a truncated download).
pub fn parse(text: &str) -> Result<BTreeSet<i64>> {
    let mut out = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let asn = line
            .strip_prefix("AS")
            .or_else(|| line.strip_prefix("as"))
            .and_then(|d| d.parse::<u32>().ok())
            .with_context(|| format!("line {}: not an ASN: {line:?}", n + 1))?;
        out.insert(i64::from(asn));
    }
    anyhow::ensure!(
        out.len() >= MIN_ASNS,
        "datacenter ASN list suspiciously small ({})",
        out.len()
    );
    Ok(out)
}

/// The built-in snapshot's ASNs.
pub fn builtin() -> BTreeSet<i64> {
    parse(BUILTIN).expect("built-in X4BNet ASN list")
}

/// The fetched copy when there is a sane one, else the snapshot.
pub fn load(data_dir: &Path) -> BTreeSet<i64> {
    let path = file(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(text) => match parse(&text) {
            Ok(set) => return set,
            Err(e) => tracing::warn!(
                file = %path.display(),
                error = %format!("{e:#}"),
                "fetched datacenter ASN list unusable: using the built-in snapshot"
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(?e, "reading the datacenter ASN list failed"),
    }
    builtin()
}

/// Load the list in `data_dir` into the evidence catalogue.
pub fn install(data_dir: &Path) {
    crate::store::evidence::Catalogue::install_hosting(&load(data_dir));
}

/// Download a fresh list; on failure the old file is left untouched.
pub async fn refresh(data_dir: &Path) -> Result<usize> {
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("building http client")?;
    let body = client
        .get(X4B_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
        .context("fetching the datacenter ASN list")?;
    let count = parse(&body)?.len();
    let tmp = data_dir.join("x4b-datacenter-asn.txt.tmp");
    std::fs::write(&tmp, &body)?;
    std::fs::rename(&tmp, file(data_dir))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_snapshot_parses() {
        let set = builtin();
        assert!(set.len() > 900, "{}", set.len());
        // Hetzner and OVH, as they appear upstream.
        assert!(set.contains(&24940) && set.contains(&16276));
    }

    /// The snapshot is upstream's file as fetched: a new snapshot replaces
    /// the file and these constants, never an edit by hand.
    #[test]
    fn the_snapshot_is_unmodified() {
        use sha2::Digest;
        assert_eq!(
            data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(BUILTIN)),
            "49c95d9219a060b8f29525e0b648bd40a5a39c124c09d6831b20f3768ccf3dd2",
            "rules/evidence/x4bnet/ASN.txt changed: refetch it from {X4B_URL} and \
             update SNAPSHOT_DATE, SNAPSHOT_COMMIT and NOTICE"
        );
    }

    #[test]
    fn a_bad_list_is_an_error() {
        assert!(parse("<html>404</html>\n").is_err());
        let short: String = (1..=10).map(|n| format!("AS{n} # x\n")).collect();
        assert!(parse(&short).is_err());
        let ok: String = (1..=MIN_ASNS).map(|n| format!("AS{n}\n\n")).collect();
        assert_eq!(parse(&ok).unwrap().len(), MIN_ASNS);
    }

    #[test]
    fn a_fetched_copy_supersedes_the_snapshot_and_a_bad_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()), builtin());
        let ok: String = (1..=MIN_ASNS).map(|n| format!("AS{n}\n")).collect();
        std::fs::write(file(dir.path()), &ok).unwrap();
        assert_eq!(load(dir.path()).len(), MIN_ASNS);
        std::fs::write(file(dir.path()), "garbage\n").unwrap();
        assert_eq!(load(dir.path()), builtin());
    }
}
