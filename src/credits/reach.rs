//! Who could be reached, hour by hour. Every member writes one
//! `reach_report` per UTC hour naming the advertised members it completed
//! a sync round with in that hour. A member is up in an hour when more
//! than half of that hour's reports, from other active members with an
//! advertised address not left out here, name it; an advertised listener
//! of protocol 7 up for at least [`MIN_UP_HOURS`] of a UTC day is a
//! verified listener of that day and shares its pool (`credits::pool`).
use crate::cluster::Node;
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::members::MemberRow;
use crate::cluster::record::{ReachReportRec, Record};
use crate::store::data::{Ctx, Effect};
use anyhow::Result;
use sqlx::{SqliteConnection, SqlitePool};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub const HOUR_MS: u64 = 3_600_000;
/// Up hours a listener needs in a UTC day to be verified.
pub const MIN_UP_HOURS: u32 = 12;
/// A report is taken for an hour at most this many hours before the one
/// its entry is written in.
pub const MAX_BACK_HOURS: u32 = 25;
/// Most members one report names.
pub const MAX_REACHED: usize = 1024;

/// The UTC hour of `ms`, in hours since the epoch.
pub fn hour_of(ms: u64) -> u32 {
    (ms / HOUR_MS).min(u32::MAX as u64) as u32
}

/// Whether a report for `hour` written at `hlc` is taken: not for an hour
/// after the one it is written in, nor more than [`MAX_BACK_HOURS`] before.
pub fn hour_ok(hour: u32, hlc: u64) -> bool {
    let at = hour_of(hlc::physical_ms(hlc));
    hour <= at && hour.saturating_add(MAX_BACK_HOURS) >= at
}

/// Keep a report: the first of its origin for its hour.
pub async fn apply(
    conn: &mut SqliteConnection,
    ctx: Ctx<'_>,
    r: &ReachReportRec,
) -> Result<Effect> {
    let Some(origin) = ctx.origin else {
        return Ok(Effect::Ignored);
    };
    if r.reached.len() > MAX_REACHED || !hour_ok(r.hour, ctx.hlc) {
        return Ok(Effect::Ignored);
    }
    record(conn, origin, r.hour, &r.reached).await?;
    Ok(Effect::Applied)
}

/// Store a report row; a later one of `origin` for `hour` is ignored.
pub async fn record(
    conn: &mut SqliteConnection,
    origin: &NodeId,
    hour: u32,
    reached: &[NodeId],
) -> Result<()> {
    let blob: Vec<u8> = reached.iter().flat_map(|n| n.0).collect();
    sqlx::query("INSERT OR IGNORE INTO reach_reports (origin, hour, reached) VALUES (?, ?, ?)")
        .bind(&origin.0[..])
        .bind(hour as i64)
        .bind(blob)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// One report as the tally reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub reporter: NodeId,
    pub hour: u32,
    pub reached: BTreeSet<NodeId>,
}

/// Every report for `from_hour` or later.
pub async fn since(pool: &SqlitePool, from_hour: u32) -> Result<Vec<Report>> {
    let rows: Vec<(Vec<u8>, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT origin, hour, reached FROM reach_reports WHERE hour >= ? ORDER BY hour, origin",
    )
    .bind(from_hour as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(origin, hour, reached)| {
            Some(Report {
                reporter: NodeId::from_slice(&origin).ok()?,
                hour: u32::try_from(hour).ok()?,
                reached: reached
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .map(|c| NodeId(*c))
                    .collect(),
            })
        })
        .collect())
}

/// Drop the reports for hours before `before_hour`.
pub async fn prune(pool: &SqlitePool, before_hour: u32) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM reach_reports WHERE hour < ?")
        .bind(before_hour as i64)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Up hours per member and UTC day.
pub type Uptime = BTreeMap<(NodeId, u32), u32>;

/// Whether `member` was up in the hour of `reports`: more than half of
/// those from `reporters` (the counted ones, [`reporters`]) other than
/// itself name it.
pub fn up(reports: &[&Report], member: &NodeId, reporters: &HashSet<NodeId>) -> bool {
    let counted: Vec<&&Report> = reports
        .iter()
        .filter(|r| r.reporter != *member && reporters.contains(&r.reporter))
        .collect();
    let named = counted
        .iter()
        .filter(|r| r.reached.contains(member))
        .count();
    named * 2 > counted.len()
}

/// The up hours of `members` per day, from `reports` (one per reporter
/// and hour counts, and only those of `reporters`, [`reporters`]).
pub fn uptime(reports: &[Report], members: &[NodeId], reporters: &HashSet<NodeId>) -> Uptime {
    let mut by_hour: BTreeMap<u32, Vec<&Report>> = BTreeMap::new();
    let mut seen: HashSet<(NodeId, u32)> = HashSet::new();
    for r in reports {
        if seen.insert((r.reporter, r.hour)) {
            by_hour.entry(r.hour).or_default().push(r);
        }
    }
    let mut out = Uptime::new();
    for (hour, rs) in &by_hour {
        // The reporters that count, and how many of them name each member.
        let mut named: HashMap<&NodeId, usize> = HashMap::new();
        let mut counted: Vec<&Report> = vec![];
        for r in rs.iter().filter(|r| reporters.contains(&r.reporter)) {
            counted.push(r);
            for n in &r.reached {
                *named.entry(n).or_default() += 1;
            }
        }
        for m in members {
            // A member's own report does not count for it.
            let own = counted.iter().filter(|r| r.reporter == *m).count();
            let others = counted.len() - own;
            let by_others = named.get(m).copied().unwrap_or(0)
                - counted
                    .iter()
                    .filter(|r| r.reporter == *m && r.reached.contains(m))
                    .count();
            if by_others * 2 > others {
                *out.entry((*m, hour / 24)).or_default() += 1;
            }
        }
    }
    out
}

/// The verified listeners of `day`: the listener role, an advertised
/// address and protocol 7 in their member record (a member below it is
/// not paid until it upgrades, and a pool share is a payment), up at
/// least [`MIN_UP_HOURS`] that day.
pub fn verified(members: &[MemberRow], uptime: &Uptime, day: u32) -> BTreeSet<NodeId> {
    members
        .iter()
        .filter(|m| m.active && m.address.is_some() && m.roles.iter().any(|r| r == "listener"))
        .filter(|m| crate::credits::pay::pays_with(m.proto_max))
        .filter(|m| uptime.get(&(m.id, day)).copied().unwrap_or(0) >= MIN_UP_HOURS)
        .map(|m| m.id)
        .collect()
}

/// The reporters whose reports count here: active members with an
/// advertised address in their member record, not left out here (blocked,
/// or shown two histories). Nobody can check what a key without an
/// address reports, and keys that cost nothing to run must not outvote the
/// reachable members; a non-member's report counts for nothing.
pub fn reporters(members: &[MemberRow], left_out: &HashSet<NodeId>) -> HashSet<NodeId> {
    members
        .iter()
        .filter(|m| m.active && m.address.is_some() && !left_out.contains(&m.id))
        .map(|m| m.id)
        .collect()
}

/// The advertised members this node completed a sync round with, per
/// hour this process ran in, until the hour is reported.
#[derive(Default)]
pub struct Tracker {
    hours: Mutex<BTreeMap<u32, BTreeSet<NodeId>>>,
}

impl Tracker {
    /// This node runs in the hour of `now_ms`: it reports that hour, even
    /// naming nobody.
    pub fn note_alive(&self, now_ms: u64) {
        self.hours
            .lock()
            .unwrap()
            .entry(hour_of(now_ms))
            .or_default();
    }

    /// A sync round with `peer` completed at `now_ms`.
    pub fn note(&self, peer: NodeId, now_ms: u64) {
        self.hours
            .lock()
            .unwrap()
            .entry(hour_of(now_ms))
            .or_default()
            .insert(peer);
    }

    /// Put hours taken by [`Tracker::take_due`] back, merged with what was
    /// noted since (a report that could not be written).
    pub fn restore(&self, taken: Vec<(u32, Vec<NodeId>)>) {
        let mut hours = self.hours.lock().unwrap();
        for (h, reached) in taken {
            hours.entry(h).or_default().extend(reached);
        }
    }

    /// The hours before the one of `now_ms`, with whom they reached; taken
    /// out, so each is reported once.
    pub fn take_due(&self, now_ms: u64) -> Vec<(u32, Vec<NodeId>)> {
        let mut hours = self.hours.lock().unwrap();
        let current = hours.split_off(&hour_of(now_ms));
        std::mem::replace(&mut *hours, current)
            .into_iter()
            .map(|(h, s)| (h, s.into_iter().collect()))
            .collect()
    }
}

/// Write this node's report of every hour that ended (at most
/// [`MAX_BACK_HOURS`] back). Returns how many were written.
pub async fn report_due(node: &Arc<Node>, now_ms: u64) -> Result<usize> {
    node.reach.note_alive(now_ms);
    let now = hour_of(now_ms);
    let taken = node.reach.take_due(now_ms);
    let records: Vec<Record> = taken
        .iter()
        .filter(|(h, _)| h.saturating_add(MAX_BACK_HOURS) >= now)
        .map(|(hour, reached)| {
            Record::ReachReport(ReachReportRec {
                hour: *hour,
                reached: reached.iter().copied().take(MAX_REACHED).collect(),
            })
        })
        .collect();
    if records.is_empty() {
        return Ok(0);
    }
    if let Err(e) = crate::cluster::repl::append(node, &records).await {
        node.reach.restore(taken);
        return Err(e);
    }
    Ok(records.len())
}

/// `credits uptime`: a header of `MM-DD` days, then per member its up
/// hours each day, `*` where it was a verified listener.
pub fn uptime_lines(
    names: &[(NodeId, String)],
    uptime: &Uptime,
    verified: &BTreeMap<u32, BTreeSet<NodeId>>,
    days: &[u32],
) -> Vec<String> {
    let date = |d: u32| {
        chrono::DateTime::from_timestamp(d as i64 * 86_400, 0)
            .map(|t| t.format("%m-%d").to_string())
            .unwrap_or_default()
    };
    let mut out = vec![days.iter().fold(format!("{:<24}", "member"), |mut s, d| {
        s.push_str(&format!("{:>7}", date(*d)));
        s
    })];
    for (id, name) in names {
        let mut line = format!("{name:<24}");
        for d in days {
            let h = uptime.get(&(*id, *d)).copied().unwrap_or(0);
            let star = if verified.get(d).is_some_and(|v| v.contains(id)) {
                "*"
            } else {
                ""
            };
            line.push_str(&format!("{:>7}", format!("{h}{star}")));
        }
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::members::{MemberRow, Standing};

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn report(reporter: u8, hour: u32, reached: &[u8]) -> Report {
        Report {
            reporter: id(reporter),
            hour,
            reached: reached.iter().map(|n| id(*n)).collect(),
        }
    }

    fn member(n: u8, listener: bool, address: bool) -> MemberRow {
        MemberRow {
            id: id(n),
            name: format!("n{n}"),
            address: address.then(|| format!("198.51.100.{n}:7443")),
            roles: if listener {
                vec!["listener".into()]
            } else {
                vec![]
            },
            proto_min: 2,
            proto_max: 7,
            sponsor: id(n),
            active: true,
            standing: Standing::Active,
            info_hlc: 0,
            last_entry_hlc: 0,
            admitted_hlc: 0,
            remote_config: false,
        }
    }

    #[test]
    fn up_needs_more_than_half_of_the_other_reporters() {
        let none: HashSet<NodeId> = [id(1), id(2), id(3), id(4)].into();
        let rs = [report(2, 7, &[1]), report(3, 7, &[1]), report(4, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(up(&refs, &id(1), &none), "2 of 3");
        let rs = [report(2, 7, &[1]), report(3, 7, &[]), report(4, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(!up(&refs, &id(1), &none), "1 of 3");
        let rs = [report(2, 7, &[1]), report(3, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(!up(&refs, &id(1), &none), "half is not more than half");
        assert!(!up(&[], &id(1), &none), "nobody reported");
    }

    #[test]
    fn a_reporter_never_counts_for_itself_and_ignored_ones_not_at_all() {
        let rs = [report(1, 7, &[1]), report(2, 7, &[1]), report(3, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        // Its own report is left out: 1 of 2 others.
        assert!(!up(&refs, &id(1), &[id(1), id(2), id(3)].into()));
        // Reporter 3 does not count here: 1 of 1.
        assert!(up(&refs, &id(1), &[id(1), id(2)].into()));
    }

    #[test]
    fn uptime_counts_up_hours_per_day_and_a_second_report_for_an_hour_is_ignored() {
        let day = 20_000u32;
        let h = day * 24;
        let reports = vec![
            report(2, h, &[1]),
            report(2, h, &[]), // a second report of 2 for that hour
            report(2, h + 1, &[1]),
            report(2, h + 24, &[1]), // the next day
        ];
        let up = uptime(&reports, &[id(1), id(2)], &[id(1), id(2)].into());
        assert_eq!(up.get(&(id(1), day)), Some(&2));
        assert_eq!(up.get(&(id(1), day + 1)), Some(&1));
        assert_eq!(up.get(&(id(2), day)), None, "nobody reported 2");
    }

    #[test]
    fn only_advertised_active_members_not_left_out_count_as_reporters() {
        let mut gone = member(5, true, true);
        gone.active = false;
        let members = [
            member(1, true, true),
            member(2, true, false),
            member(3, true, true),
            member(4, false, true),
            gone,
        ];
        let counted = reporters(&members, &[id(3)].into());
        assert_eq!(counted, [id(1), id(4)].into());
        // 2 (outbound-only), 3 (left out) and 5 (departed) name 1; 4
        // (advertised) does not.
        let rs = [
            report(2, 7, &[1]),
            report(3, 7, &[1]),
            report(5, 7, &[1]),
            report(4, 7, &[]),
        ];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(
            !up(&refs, &id(1), &counted),
            "0 of the 1 report that counts"
        );
    }

    #[test]
    fn a_non_members_report_does_not_count() {
        let members = [member(1, true, true), member(4, true, true)];
        let counted = reporters(&members, &HashSet::new());
        // 9 is no member: its report naming 1 counts for nothing.
        let rs = [report(9, 7, &[1]), report(4, 7, &[])];
        let refs: Vec<&Report> = rs.iter().collect();
        assert!(!up(&refs, &id(1), &counted));
        let up = uptime(&rs, &[id(1)], &counted);
        assert_eq!(up.get(&(id(1), 0)), None);
    }

    #[test]
    fn a_verified_listener_is_an_advertised_protocol_seven_listener_up_twelve_hours() {
        let day = 20_000u32;
        let mut up = Uptime::new();
        for n in [1u8, 2, 3, 4] {
            up.insert((id(n), day), 12);
        }
        up.insert((id(5), day), 11);
        up.insert((id(6), day), 24);
        let mut old = member(6, true, true);
        old.proto_max = crate::cluster::rpc::proto::ECONOMY_PROTO - 1;
        let members = [
            member(1, true, true),
            member(2, false, true), // not a listener
            member(3, true, false), // outbound-only
            member(4, true, true),
            member(5, true, true), // 11 hours
            old,                   // below protocol 7
        ];
        assert_eq!(verified(&members, &up, day), [id(1), id(4)].into());
        assert!(verified(&members, &up, day + 1).is_empty());
    }

    #[test]
    fn a_report_is_taken_for_its_hour_and_up_to_25_hours_before() {
        let at = |hour: u64| (hour * HOUR_MS + 60_000) << 16;
        assert!(
            hour_ok(100, at(101)),
            "written at the start of the next hour"
        );
        assert!(hour_ok(101, at(101)), "the hour it is written in");
        assert!(!hour_ok(102, at(101)), "an hour still to come");
        assert!(hour_ok(76, at(101)), "25 hours back");
        assert!(!hour_ok(75, at(101)), "26 hours back");
    }

    #[test]
    fn the_tracker_reports_only_hours_it_ran_in_and_each_once() {
        let t = Tracker::default();
        let ms = |hour: u64, min: u64| hour * HOUR_MS + min * 60_000;
        // Started in hour 10: nothing before it is ever reported.
        t.note_alive(ms(10, 30));
        t.note(id(2), ms(10, 31));
        t.note(id(3), ms(10, 59));
        t.note(id(2), ms(10, 59));
        assert!(t.take_due(ms(10, 59)).is_empty(), "the hour is not over");
        t.note_alive(ms(11, 0));
        let due = t.take_due(ms(11, 0));
        assert_eq!(due, vec![(10, vec![id(2), id(3)])]);
        assert!(t.take_due(ms(11, 1)).is_empty(), "taken once");
        // An hour it was alive in but reached nobody is reported empty.
        t.note_alive(ms(12, 5));
        assert_eq!(t.take_due(ms(12, 6)), vec![(11, vec![])]);
    }

    #[tokio::test]
    async fn the_first_report_of_an_origin_for_an_hour_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let origin = id(9);
        let ctx = |hlc| Ctx {
            origin: Some(&origin),
            hlc,
        };
        let at = (101 * HOUR_MS) << 16;
        let mut conn = store.pool.acquire().await.unwrap();
        let first = ReachReportRec {
            hour: 100,
            reached: vec![id(1)],
        };
        let second = ReachReportRec {
            hour: 100,
            reached: vec![id(1), id(2)],
        };
        let late = ReachReportRec {
            hour: 70,
            reached: vec![id(1)],
        };
        assert_eq!(
            apply(&mut conn, ctx(at), &first).await.unwrap(),
            Effect::Applied
        );
        assert_eq!(
            apply(&mut conn, ctx(at), &second).await.unwrap(),
            Effect::Applied
        );
        assert_eq!(
            apply(&mut conn, ctx(at), &late).await.unwrap(),
            Effect::Ignored
        );
        drop(conn);
        let all = since(&store.pool, 0).await.unwrap();
        assert_eq!(all, vec![report(9, 100, &[1])]);
        assert_eq!(prune(&store.pool, 101).await.unwrap(), 1);
        assert!(since(&store.pool, 0).await.unwrap().is_empty());
    }

    #[test]
    fn restored_hours_merge_with_what_was_noted_since() {
        let t = Tracker::default();
        let ms = |hour: u64, min: u64| hour * HOUR_MS + min * 60_000;
        t.note_alive(ms(10, 1));
        t.note(id(2), ms(10, 2));
        let taken = t.take_due(ms(11, 0));
        assert_eq!(taken, vec![(10, vec![id(2)])]);
        t.note(id(3), ms(10, 59)); // a late note for the same hour
        t.restore(taken);
        assert_eq!(t.take_due(ms(11, 1)), vec![(10, vec![id(2), id(3)])]);
    }

    async fn test_node() -> (tempfile::TempDir, Arc<Node>) {
        use crate::cluster::identity::Identity;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let node = Node::open(crate::cluster::NodeParams {
            identity: Identity::generate().unwrap(),
            cluster: crate::config::ClusterConfig {
                node_name: "n".into(),
                listen: "127.0.0.1:0".parse().unwrap(),
                advertise: None,
                key_path: None,
                takeover_hours: 6.0,
                lease_secs: 120,
                remote_config: false,
                origin_quota_mb: 20 * 1024,
                relay_slots: 16,
                peers: vec![],
            },
            roles: Default::default(),
            store,
            proto: (1, 1),
            data_dir: dir.path().to_path_buf(),
            retention_days: 30,
        })
        .await
        .unwrap();
        node.bootstrap().await.unwrap();
        (dir, node)
    }

    #[tokio::test]
    async fn report_due_writes_the_ended_hour_once() {
        let (_dir, node) = test_node().await;
        let now = crate::cluster::hlc::wall_ms();
        let hour = hour_of(now) - 1;
        let before = (hour as u64) * HOUR_MS + 5;
        node.reach.note_alive(before);
        node.reach.note(id(7), before);
        assert_eq!(report_due(&node, now).await.unwrap(), 1);
        assert_eq!(report_due(&node, now).await.unwrap(), 0, "once");
        let rows = since(&node.store.pool, 0).await.unwrap();
        assert_eq!(
            rows,
            vec![Report {
                reporter: node.id(),
                hour,
                reached: [id(7)].into(),
            }]
        );
        let kinds: Vec<String> =
            sqlx::query_scalar("SELECT kind FROM repl_log WHERE kind = 'reach_report'")
                .fetch_all(&node.store.pool)
                .await
                .unwrap();
        assert_eq!(kinds.len(), 1);
    }

    #[test]
    fn uptime_lines_mark_the_verified_days() {
        let day = 20_000u32;
        let mut up = Uptime::new();
        up.insert((id(1), day), 24);
        up.insert((id(1), day + 1), 5);
        let verified: BTreeMap<u32, BTreeSet<NodeId>> = [(day, [id(1)].into())].into();
        let lines = uptime_lines(
            &[(id(1), "node-alpha".into()), (id(2), "node-bravo".into())],
            &up,
            &verified,
            &[day, day + 1],
        );
        assert_eq!(
            lines[0],
            format!("{:<24}{:>7}{:>7}", "member", "10-04", "10-05")
        );
        assert_eq!(
            lines[1],
            format!("{:<24}{:>7}{:>7}", "node-alpha", "24*", "5")
        );
        assert_eq!(
            lines[2],
            format!("{:<24}{:>7}{:>7}", "node-bravo", "0", "0")
        );
    }
}
