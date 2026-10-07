//! Where credits come from: a fixed amount a day, split among the
//! scanners by the scans that counted that day, and a small allowance for
//! every member that earns here and recorded a request that day. Both are
//! dated the day's last instant, so they land in its lot, and are final
//! once the day is closed.
use super::earn::{JUDGE_AFTER_SECS, Paid};
use super::gates::Standings;
use super::ledger::Earned;
use super::{CREDIT, DAY_MS, Mc, day_of};
use crate::cluster::identity::NodeId;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::{BTreeMap, BTreeSet};

/// Split among the scanners per UTC day.
pub const MINT_PER_DAY: Mc = 1000 * CREDIT;
/// Per member that earns here and recorded a request, per UTC day.
pub const ALLOWANCE_PER_DAY: Mc = 5 * CREDIT;

/// The last instant of `day` as an HLC.
pub fn end_of(day: u32) -> u64 {
    (((day as u64 + 1) * DAY_MS - 1) << 16) | 0xFFFF
}

/// `day` has ended and its scans have had time to be judged.
pub fn closed(day: u32, now_ms: u64) -> bool {
    now_ms >= (day as u64 + 1) * DAY_MS + JUDGE_AFTER_SECS.max(0) as u64 * 1000
}

/// Each closed day's mint, split by the weights of its counted scans
/// (largest remainder, ties by node key, so the shares sum exactly).
pub fn split(paid: &[Paid], now_ms: u64) -> Vec<Earned> {
    let mut days: BTreeMap<u32, BTreeMap<NodeId, u64>> = BTreeMap::new();
    for p in paid.iter().filter(|p| p.weight > 0) {
        *days
            .entry(day_of(p.scan.hlc))
            .or_default()
            .entry(p.scan.scanner)
            .or_default() += p.weight as u64;
    }
    let mut out = vec![];
    for (day, weights) in days.into_iter().filter(|(d, _)| closed(*d, now_ms)) {
        let total: u64 = weights.values().sum();
        let mut shares: Vec<(NodeId, Mc, u64)> = weights
            .iter()
            .map(|(n, w)| {
                let x = MINT_PER_DAY as u128 * *w as u128;
                (*n, (x / total as u128) as Mc, (x % total as u128) as u64)
            })
            .collect();
        let mut left = MINT_PER_DAY - shares.iter().map(|s| s.1).sum::<Mc>();
        shares.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        for s in shares.iter_mut() {
            if left == 0 {
                break;
            }
            s.1 += 1;
            left -= 1;
        }
        shares.sort_by_key(|s| s.0);
        out.extend(
            shares
                .into_iter()
                .filter(|s| s.1 > 0)
                .map(|(node, mc, _)| Earned {
                    node,
                    hlc: end_of(day),
                    mc,
                }),
        );
    }
    out
}

/// The allowance of every closed day for the members active that day
/// that earn here.
pub fn allowances(
    active: &BTreeSet<(NodeId, u32)>,
    standings: &Standings,
    now_ms: u64,
) -> Vec<Earned> {
    active
        .iter()
        .filter(|(n, d)| closed(*d, now_ms) && standings.get(n).is_none_or(|s| s.earns()))
        .map(|(node, day)| Earned {
            node: *node,
            hlc: end_of(*day),
            mc: ALLOWANCE_PER_DAY,
        })
        .collect()
}

/// `(member, day)` for every day from `from_day` to `to_day` on which this
/// node holds a request the member recorded.
pub async fn active_days(
    pool: &SqlitePool,
    members: &[NodeId],
    from_day: u32,
    to_day: u32,
) -> Result<BTreeSet<(NodeId, u32)>> {
    let mut out = BTreeSet::new();
    for m in members {
        for day in from_day..=to_day {
            let lo = (day as u64 * DAY_MS) << 16;
            let hi = end_of(day);
            let any: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM requests WHERE origin = ? AND hlc BETWEEN ? AND ?)",
            )
            .bind(&m.0[..])
            .bind(crate::cluster::hlc::to_db(lo))
            .bind(crate::cluster::hlc::to_db(hi))
            .fetch_one(pool)
            .await?;
            if any {
                out.insert((*m, day));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::earn::{Judged, Paid};

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }
    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }
    fn paid(n: u32, scanner: u8, day: u32, weight: u8) -> Paid {
        Paid {
            scan: Judged {
                scan_uid: format!("s{n}"),
                job_uid: format!("j{n}"),
                ip: format!("203.0.113.{}", n % 250),
                scanner: id(scanner),
                trap: id(9),
                hlc: at(day, n as u64 % 1000),
                level: 2,
                job_level: 2,
                args_ok: true,
            },
            weight,
            note: String::new(),
        }
    }
    fn after(day: u32) -> u64 {
        (day as u64 + 1) * DAY_MS + JUDGE_AFTER_SECS as u64 * 1000
    }

    #[test]
    fn a_closed_day_is_split_by_weight_and_dated_in_its_lot() {
        let p = [paid(1, 1, DAY, 1), paid(2, 1, DAY, 2), paid(3, 2, DAY, 1)];
        let e = split(&p, after(DAY));
        let get = |n| e.iter().find(|x| x.node == id(n)).unwrap();
        assert_eq!((get(1).mc, get(2).mc), (750 * CREDIT, 250 * CREDIT));
        assert_eq!(crate::credits::day_of(get(1).hlc), DAY);
        // Not closed yet: nothing.
        assert!(split(&p, after(DAY) - 1).is_empty());
        // Weight 0 does not count; an empty day mints nothing.
        assert!(split(&[paid(4, 3, DAY, 0)], after(DAY)).is_empty());
    }

    #[test]
    fn split_sums_exactly_with_remainders() {
        let mut p = vec![paid(1, 1, DAY, 1)];
        p.extend((2..=500).map(|n| paid(n, 2, DAY, 1)));
        p.push(paid(501, 3, DAY, 2));
        let e = split(&p, after(DAY));
        assert_eq!(e.iter().map(|x| x.mc).sum::<Mc>(), MINT_PER_DAY);
        assert!(e.iter().all(|x| x.mc > 0));
        assert_eq!(split(&p, after(DAY)), e, "deterministic");
    }

    #[test]
    fn a_late_scan_shifts_a_closed_day() {
        let before = split(&[paid(1, 1, DAY, 1)], after(DAY));
        assert_eq!(before[0].mc, MINT_PER_DAY);
        let later = split(
            &[paid(1, 1, DAY, 1), paid(2, 2, DAY, 1)],
            after(DAY) + 3_600_000,
        );
        assert_eq!(
            later.iter().find(|x| x.node == id(1)).unwrap().mc,
            MINT_PER_DAY / 2
        );
        // The ledger lets a shrunk lot cover only what is there.
        let entries = [crate::credits::entries::Entry {
            origin: id(1),
            seq: 1,
            hlc: at(DAY + 1, 10),
            kind: crate::credits::entries::Kind::Offer {
                to: id(3),
                parts: vec![(DAY, (MINT_PER_DAY * 3 / 4) as u32)],
                job: None,
            },
            seal: crate::credits::entries::SealState::Consistent,
        }];
        let l = crate::credits::ledger::run(
            &later,
            &entries,
            &Default::default(),
            (DAY as u64 + 1) * DAY_MS + 11 * 60_000,
        );
        assert_eq!(l.offer(&id(1), 1).unwrap().covered, MINT_PER_DAY / 2);
        assert_eq!(l.balance(&id(1)), 0);
    }

    #[test]
    fn the_allowance_goes_to_active_members_that_earn_here() {
        let active: BTreeSet<(NodeId, u32)> =
            [(id(1), DAY), (id(2), DAY), (id(3), DAY), (id(1), DAY + 1)].into();
        let mut st = Standings::new();
        st.entry(id(2)).or_default().blocked = true;
        st.entry(id(3)).or_default().rules = Some(crate::classify::stored::Agreement {
            sampled: 100,
            differing: 50,
        });
        let e = allowances(&active, &st, after(DAY));
        assert_eq!(
            e.iter().map(|x| (x.node, x.mc)).collect::<Vec<_>>(),
            [(id(1), ALLOWANCE_PER_DAY)]
        );
        assert_eq!(crate::credits::day_of(e[0].hlc), DAY);
    }

    #[tokio::test]
    async fn active_days_come_from_recorded_requests() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let ip = store
            .upsert_ip("203.0.113.7".parse().unwrap())
            .await
            .unwrap();
        for (who, day) in [(1u8, DAY), (1, DAY), (2, DAY + 1)] {
            sqlx::query("INSERT INTO requests (ts, ip_id, method, path, headers_json, origin, hlc) VALUES ('2026-01-01T00:00:00Z', ?, 'GET', '/', '[]', ?, ?)")
                .bind(ip.id)
                .bind(&id(who).0[..])
                .bind(crate::cluster::hlc::to_db(at(day, 5)))
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let got = active_days(&store.pool, &[id(1), id(2), id(3)], DAY, DAY + 1)
            .await
            .unwrap();
        assert_eq!(got, [(id(1), DAY), (id(2), DAY + 1)].into());
    }
}
