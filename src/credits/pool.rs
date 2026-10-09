//! Where credits come from: a fixed pool a day, split evenly among that
//! day's verified listeners (`credits::reach`). Nothing else mints and
//! nothing burns, so the supply is six pools. The pool of day d is dated
//! the day's last instant, lands in its lot and lives on days d to d+6.
use super::ledger::Earned;
use super::{CREDIT, DAY_MS, Mc};
use crate::cluster::identity::NodeId;
use std::collections::{BTreeMap, BTreeSet};

/// Split among the verified listeners per UTC day.
pub const POOL_PER_DAY: Mc = 1000 * CREDIT;
/// A day's pool is credited this long after the day ends: the reports of
/// its last hour are written at midnight and need time to arrive.
pub const REPORT_GRACE_MS: u64 = 3_600_000;

/// The last instant of `day` as an HLC.
pub fn end_of(day: u32) -> u64 {
    (((day as u64 + 1) * DAY_MS - 1) << 16) | 0xFFFF
}

/// Whether `day`'s pool is credited at `now_ms`.
pub fn closed(day: u32, now_ms: u64) -> bool {
    now_ms >= (day as u64 + 1) * DAY_MS + REPORT_GRACE_MS
}

/// `day`'s pool, evenly among `listeners`; the remainder one mc each to
/// the lowest keys.
pub fn split(day: u32, listeners: &BTreeSet<NodeId>) -> Vec<Earned> {
    let n = listeners.len() as Mc;
    if n == 0 {
        return vec![];
    }
    let (each, left) = (POOL_PER_DAY / n, POOL_PER_DAY % n);
    listeners
        .iter()
        .enumerate()
        .map(|(i, node)| Earned {
            node: *node,
            hlc: end_of(day),
            mc: each + Mc::from((i as Mc) < left),
        })
        .collect()
}

/// The shares of every day in `listeners` that is closed at `now_ms`.
pub fn credited(listeners: &BTreeMap<u32, BTreeSet<NodeId>>, now_ms: u64) -> Vec<Earned> {
    listeners
        .iter()
        .filter(|(day, _)| closed(**day, now_ms))
        .flat_map(|(day, set)| split(*day, set))
        .collect()
}

/// For tests: whole days of reports naming listeners.
#[doc(hidden)]
pub mod testing {
    use crate::cluster::identity::NodeId;

    /// Make `listeners` up in every hour of `day` on this store: a
    /// reporter, made an advertised member of this store so its reports
    /// count, names them in each hour (merged with what it named before).
    /// Its address refuses at once, so nothing waits to dial it.
    pub async fn report_all_day(
        pool: &sqlx::SqlitePool,
        day: u32,
        listeners: &[NodeId],
    ) -> anyhow::Result<()> {
        let reporter = NodeId([0xEE; 32]);
        let now = crate::cluster::hlc::wall_ms() << 16;
        sqlx::query(
            "INSERT INTO members (id, name, address, roles_json, proto_min, proto_max, sponsor,
                                  info_hlc, admitted_hlc)
             VALUES (?1, 'pool-reporter', '127.0.0.1:1', '[]', ?2, ?3, ?1, ?4, ?4)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&reporter.0[..])
        .bind(crate::cluster::rpc::proto::PROTO_MIN as i64)
        .bind(crate::cluster::rpc::proto::PROTO_VERSION as i64)
        .bind(crate::cluster::hlc::to_db(now))
        .execute(pool)
        .await?;
        let blob: Vec<u8> = listeners.iter().flat_map(|n| n.0).collect();
        for hour in day * 24..(day + 1) * 24 {
            sqlx::query(
                "INSERT INTO reach_reports (origin, hour, reached) VALUES (?, ?, ?)
                 ON CONFLICT(origin, hour) DO UPDATE SET reached = reached || excluded.reached",
            )
            .bind(&reporter.0[..])
            .bind(hour as i64)
            .bind(&blob)
            .execute(pool)
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u32 = 20_000;
    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    #[test]
    fn the_pool_is_split_evenly_and_the_rest_goes_to_the_lowest_keys() {
        let three: BTreeSet<NodeId> = [id(9), id(1), id(5)].into();
        let shares = split(DAY, &three);
        assert_eq!(
            shares.iter().map(|e| (e.node, e.mc)).collect::<Vec<_>>(),
            [(id(1), 333_334), (id(5), 333_333), (id(9), 333_333)]
        );
        assert_eq!(shares.iter().map(|e| e.mc).sum::<Mc>(), POOL_PER_DAY);
        assert!(shares.iter().all(|e| e.hlc == end_of(DAY)));
        assert!(split(DAY, &BTreeSet::new()).is_empty(), "nobody: nothing");
        assert_eq!(split(DAY, &[id(3)].into())[0].mc, POOL_PER_DAY);
    }

    #[test]
    fn a_day_is_credited_an_hour_after_it_ends() {
        let end = (DAY as u64 + 1) * DAY_MS;
        assert!(!closed(DAY, end - 1));
        assert!(
            !closed(DAY, end + 30 * 60_000),
            "00:30: reports of 23:00 may be on their way"
        );
        assert!(closed(DAY, end + REPORT_GRACE_MS));
        let days: BTreeMap<u32, BTreeSet<NodeId>> =
            [(DAY, [id(1)].into()), (DAY + 1, [id(2)].into())].into();
        let got = credited(&days, end + REPORT_GRACE_MS);
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].node, crate::credits::day_of(got[0].hlc)),
            (id(1), DAY)
        );
    }
}
