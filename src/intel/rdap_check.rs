//! RDAP spot-checks (MIK-259): this node re-queries a share of the RDAP
//! rows other origins write and counts the ones whose tags differ. Which
//! rows it checks follows from its own secret key, so a writer cannot tell
//! which of its rows are checked. [`super::check_pass`] runs them.

use std::time::Duration;

/// Share of IPs this node checks.
pub const CHECK_SHARE: f64 = 0.10;
/// Rows checked per pass at most.
pub const CHECK_BATCH: i64 = 5;
/// Only rows fetched this recently are checked.
pub const CHECK_WINDOW_DAYS: i64 = 7;
/// A first mismatch is queried once more after this long: a registry may
/// just have changed the record.
pub const RECHECK_AFTER: Duration = Duration::from_secs(600);
/// The label of the node key derived for [`designated`].
pub const KEY_LABEL: &[u8] = b"peephole rdap spot-check v1";

/// Whether this node checks the RDAP rows of `ip`: true for [`CHECK_SHARE`]
/// of IPs, from a keyed hash of `ip` under `me_key` (the node's key
/// derived with [`KEY_LABEL`]).
pub fn designated(me_key: &[u8; 32], ip: &str) -> bool {
    use aws_lc_rs::hmac;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, me_key), ip.as_bytes());
    let n = u64::from_be_bytes(tag.as_ref()[..8].try_into().expect("8 bytes"));
    n % 10_000 < (CHECK_SHARE * 10_000.0) as u64
}

/// Per origin: its RDAP rows this node checked, and the disputes among them.
pub async fn counts(
    pool: &sqlx::SqlitePool,
) -> anyhow::Result<std::collections::HashMap<Vec<u8>, (i64, i64)>> {
    let rows: Vec<(Vec<u8>, i64, i64)> = sqlx::query_as(
        "SELECT origin, COUNT(agreed), COALESCE(SUM(agreed = 0), 0) FROM rdap_checks
         GROUP BY origin",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(o, c, d)| (o, (c, d))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    fn ips() -> impl Iterator<Item = String> {
        (0..10_000u32).map(|i| std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string())
    }

    #[test]
    fn a_tenth_of_ips_is_designated_and_each_node_picks_its_own() {
        let a = Identity::generate().unwrap().derive_key(KEY_LABEL);
        let b = Identity::generate().unwrap().derive_key(KEY_LABEL);
        let picked_a: Vec<String> = ips().filter(|ip| designated(&a, ip)).collect();
        let picked_b: Vec<String> = ips().filter(|ip| designated(&b, ip)).collect();
        for n in [picked_a.len(), picked_b.len()] {
            assert!((900..=1100).contains(&n), "{n} of 10 000");
        }
        assert_ne!(picked_a, picked_b);
        let both = picked_a.iter().filter(|ip| picked_b.contains(ip)).count();
        assert!(both < 300, "{both} in common: not independent");
        // The same key picks the same IPs.
        assert!(picked_a.iter().all(|ip| designated(&a, ip)));
    }
}
