//! Earning: a completed counter-scan pays its scanner and the trap that
//! queued the job. A node judges each payable scan once, when the requests
//! behind it have had time to arrive (`judge`, stored in `credit_scans`),
//! and decides what it pays at every recomputation of the ledger (`pay`),
//! because that depends on the other scans and on who earns here now.
use super::ledger::Earned;
use super::{DAY_MS, Mc};
use crate::classify::Classifier;
use crate::cluster::hlc::{self, physical_ms};
use crate::cluster::identity::NodeId;
use crate::scan::guard;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::HashMap;

/// A scan is judged this long after its result arrived here, so the
/// requests behind it have had time to replicate.
pub const JUDGE_AFTER_SECS: i64 = 600;
/// Paid scans per node, role and UTC day.
pub const PER_NODE_PER_DAY: u32 = 500;
/// One paid scan per IP in this window, cluster-wide. Fixed here, not a
/// node's rescan cooldown: that is each node's own setting and can be 0.
pub const IP_WINDOW_MS: u64 = DAY_MS;
/// Scans judged per pass.
const JUDGE_BATCH: i64 = 200;
/// Bytes of a scan's XML read to find its command line.
const XML_HEAD: u64 = 64 * 1024;

/// A payable scan as this node judged it.
#[derive(Debug, Clone, PartialEq)]
pub struct Judged {
    pub scan_uid: String,
    pub job_uid: String,
    pub ip: String,
    pub scanner: NodeId,
    /// The node that queued the job (also after another arbiter adopted it).
    pub trap: NodeId,
    /// The HLC of the scan result: its time, and its lot's day.
    pub hlc: u64,
    /// The level it is paid for: the job's, capped by what the requests
    /// held here back under this build's rules. 0: nothing backs it.
    pub level: u8,
    pub job_level: u8,
    /// It ran with the built-in arguments of the job's level.
    pub args_ok: bool,
}

/// What judging a scan needs from the node.
pub struct Judge<'a> {
    pub pool: &'a SqlitePool,
    /// Whose requests count as evidence (`scan.trusted_origins`).
    pub origins: &'a guard::Origins,
    pub classifier: &'a Classifier,
}

/// The command line in a stored (zstd-compressed) nmap XML.
fn command_line(raw_xml: Option<&[u8]>) -> Option<String> {
    use std::io::Read;
    let mut head = Vec::new();
    zstd::stream::read::Decoder::new(raw_xml?)
        .ok()?
        .take(XML_HEAD)
        .read_to_end(&mut head)
        .ok()?;
    crate::scan::profiles::xml_args(&head)
}

/// Judge the payable scans that arrived at least `min_age_secs` ago and
/// have no judgment yet. A scan is payable when its job is done by a
/// scanner as its arbiter recorded it, and a result of that scanner for
/// the job's address and level is held; the earliest one of a job counts,
/// and is judged only while no earlier one of the job is held, so every
/// node that holds both picks the same. A scan is dated no earlier than
/// its job was queued: its own date is the scanner's word, and dating it
/// back would slip it past the daily and per-address limits. A scan
/// dated before the ledger window is left alone: its judgment would be
/// pruned again within the hour, and judging it would only crowd out
/// the scans that can still be paid. The earlier-result check goes by the
/// job's index: without statistics (a node just upgraded, before its
/// first `PRAGMA optimize`) SQLite may pick the origin index and walk
/// every scan of the scanner, once per row.
/// Returns how many were judged.
pub async fn judge(j: &Judge<'_>, min_age_secs: i64) -> Result<usize> {
    type Row = (
        String,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Option<Vec<u8>>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.uid, j.uid, i.ip, j.scanner, j.origin, MAX(s.hlc, COALESCE(j.hlc, 0)),
                j.level, s.raw_xml
         FROM scans s
         JOIN scan_jobs j ON j.uid = s.job_uid
         JOIN ips i ON i.id = s.ip_id
         JOIN repl_log l ON l.uid = s.uid AND l.origin = s.origin
         WHERE j.status = 'done' AND j.scanner IS NOT NULL AND j.origin IS NOT NULL
           AND s.origin = j.scanner AND s.audit_of IS NULL AND s.ip_id = j.ip_id AND s.level = j.level
           AND l.received_at <= datetime('now', ?)
           AND MAX(s.hlc, COALESCE(j.hlc, 0)) >= ?
           AND NOT EXISTS (SELECT 1 FROM credit_scans c WHERE c.job_uid = j.uid)
           AND NOT EXISTS (SELECT 1 FROM scans e INDEXED BY idx_scans_job_uid
                           WHERE e.job_uid = s.job_uid AND e.origin = s.origin
                             AND e.audit_of IS NULL
                             AND (e.hlc < s.hlc OR (e.hlc = s.hlc AND e.uid < s.uid)))
         ORDER BY s.hlc, s.uid LIMIT ?",
    )
    .bind(format!("-{} seconds", min_age_secs.max(0)))
    .bind(hlc::to_db(super::window_start(hlc::wall_ms())))
    .bind(JUDGE_BATCH)
    .fetch_all(j.pool)
    .await?;
    let mut n = 0;
    for (scan_uid, job_uid, ip, scanner, trap, at, job_level, raw_xml) in rows {
        let job_level = job_level.clamp(0, 4) as u8;
        let backed = guard::evidence(j.pool, &ip, j.origins, Some(j.classifier))
            .await?
            .max_level;
        let args_ok = command_line(raw_xml.as_deref())
            .is_some_and(|line| crate::scan::profiles::args_ok(&line, job_level));
        // The unique index on the job keeps the earliest scan of a job.
        n += sqlx::query(
            "INSERT OR IGNORE INTO credit_scans
               (scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok, judged_at)
             VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))",
        )
        .bind(&scan_uid)
        .bind(&job_uid)
        .bind(&ip)
        .bind(&scanner)
        .bind(&trap)
        .bind(at)
        .bind(job_level.min(backed) as i64)
        .bind(job_level as i64)
        .bind(args_ok)
        .execute(j.pool)
        .await?
        .rows_affected() as usize;
    }
    Ok(n)
}

type JudgedRow = (
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    bool,
);

const JUDGED_COLUMNS: &str = "scan_uid, job_uid, ip, scanner, trap, hlc, level, job_level, args_ok";

fn from_row(r: JudgedRow) -> Result<Judged> {
    Ok(Judged {
        scan_uid: r.0,
        job_uid: r.1,
        ip: r.2,
        scanner: NodeId::from_slice(&r.3)?,
        trap: NodeId::from_slice(&r.4)?,
        hlc: hlc::from_db(r.5),
        level: r.6.clamp(0, 4) as u8,
        job_level: r.7.clamp(0, 4) as u8,
        args_ok: r.8,
    })
}

/// The judged scans dated `from_hlc` or later, in the order they are paid.
pub async fn judged_since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Judged>> {
    let rows: Vec<JudgedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {JUDGED_COLUMNS} FROM credit_scans WHERE hlc >= ? ORDER BY hlc, scan_uid"
    )))
    .bind(hlc::to_db(from_hlc))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(from_row).collect()
}

/// How this node judged one scan.
pub async fn judged_one(pool: &SqlitePool, scan_uid: &str) -> Result<Option<Judged>> {
    let row: Option<JudgedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {JUDGED_COLUMNS} FROM credit_scans WHERE scan_uid = ?"
    )))
    .bind(scan_uid)
    .fetch_optional(pool)
    .await?;
    row.map(from_row).transpose()
}

pub async fn prune(pool: &SqlitePool, before_hlc: u64) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM credit_scans WHERE hlc < ?")
        .bind(hlc::to_db(before_hlc))
        .execute(pool)
        .await?
        .rows_affected())
}

/// Who does not earn here right now, and why (in words, for the pages).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Gates {
    /// None of the node's shares count, as scanner or as trap.
    pub no_shares: HashMap<NodeId, String>,
    /// Its scanner shares do not count.
    pub no_scanner_share: HashMap<NodeId, String>,
}

/// What one judged scan pays.
#[derive(Debug, Clone, PartialEq)]
pub struct Paid {
    pub scan: Judged,
    pub scanner_mc: Mc,
    pub trap_mc: Mc,
    /// Why the share is not the full one of the scan's level; empty when
    /// it is.
    pub scanner_note: String,
    pub trap_note: String,
}

/// `(scanner, trap)` shares of a tier: 1 for levels 1 and 2, 2 for 3 and 4.
fn tier_shares(tier: u8) -> (Mc, Mc) {
    match tier {
        2 => (2000, 500),
        _ => (1000, 250),
    }
}

/// Decide what every judged scan pays. A pure function of its input: the
/// scans are walked in the order of their HLCs (then uids), whatever
/// order they are given in.
pub fn pay(scans: &[Judged], gates: &Gates) -> Vec<Paid> {
    let mut order: Vec<&Judged> = scans.iter().collect();
    order.sort_by(|a, b| (a.hlc, &a.scan_uid).cmp(&(b.hlc, &b.scan_uid)));
    // Per IP: when its 24-hour window opened, and the tier paid in it.
    let mut windows: HashMap<&str, (u64, u8)> = HashMap::new();
    // Paid scans per node, UTC day and role (0 scanner, 1 trap).
    let mut counts: HashMap<(NodeId, u32, u8), u32> = HashMap::new();
    let mut out = Vec::with_capacity(order.len());
    for s in order {
        let mut p = Paid {
            scan: s.clone(),
            scanner_mc: 0,
            trap_mc: 0,
            scanner_note: String::new(),
            trap_note: String::new(),
        };
        if s.level == 0 {
            let why = format!("no request held here backs a scan of {}", s.ip);
            p.scanner_note = why.clone();
            p.trap_note = why;
            out.push(p);
            continue;
        }
        let tier = if s.level >= 3 { 2 } else { 1 };
        let ms = physical_ms(s.hlc);
        let mut note = String::new();
        let (scanner, trap) = match windows.get_mut(s.ip.as_str()) {
            Some((start, paid_tier)) if ms < *start + IP_WINDOW_MS => {
                if tier > *paid_tier {
                    let (hi, lo) = (tier_shares(tier), tier_shares(*paid_tier));
                    *paid_tier = tier;
                    note = "the difference to the scan this IP was already paid for".into();
                    (hi.0 - lo.0, hi.1 - lo.1)
                } else {
                    note = "this IP was already paid within 24 hours".into();
                    (0, 0)
                }
            }
            _ => {
                windows.insert(s.ip.as_str(), (ms, tier));
                tier_shares(tier)
            }
        };
        if note.is_empty() && s.level < s.job_level {
            note = format!(
                "paid as level {}: no request held here backs level {}",
                s.level, s.job_level
            );
        }
        (p.scanner_mc, p.trap_mc) = (scanner, trap);
        p.scanner_note = note.clone();
        p.trap_note = note;
        if !s.args_ok {
            p.scanner_mc = 0;
            p.scanner_note = "arguments differ from the built-in ones".into();
        }
        if let Some(why) = gates
            .no_shares
            .get(&s.scanner)
            .or_else(|| gates.no_scanner_share.get(&s.scanner))
        {
            p.scanner_mc = 0;
            p.scanner_note = format!("not earning here: {why}");
        }
        if let Some(why) = gates.no_shares.get(&s.trap) {
            p.trap_mc = 0;
            p.trap_note = format!("not earning here: {why}");
        }
        let day = super::day_of(s.hlc);
        for (node, role, mc, why) in [
            (s.scanner, 0u8, &mut p.scanner_mc, &mut p.scanner_note),
            (s.trap, 1u8, &mut p.trap_mc, &mut p.trap_note),
        ] {
            if *mc == 0 {
                continue;
            }
            let n = counts.entry((node, day, role)).or_insert(0);
            if *n >= PER_NODE_PER_DAY {
                *mc = 0;
                *why = "daily limit reached".into();
            } else {
                *n += 1;
            }
        }
        out.push(p);
    }
    out
}

/// What `paid` gives the ledger: one earning per share that is not nothing.
pub fn earned(paid: &[Paid]) -> Vec<Earned> {
    paid.iter()
        .flat_map(|p| {
            [(p.scan.scanner, p.scanner_mc), (p.scan.trap, p.trap_mc)]
                .into_iter()
                .filter(|(_, mc)| *mc > 0)
                .map(|(node, mc)| Earned {
                    node,
                    hlc: p.scan.hlc,
                    mc,
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    const DAY: u32 = 20_000;

    fn id(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn at(day: u32, min: u64) -> u64 {
        (day as u64 * DAY_MS + min * 60_000) << 16
    }

    /// A judged scan of `ip` by scanner 1 for trap 2.
    fn scan(n: u32, ip: &str, hlc: u64, level: u8) -> Judged {
        Judged {
            scan_uid: format!("s{n}"),
            job_uid: format!("j{n}"),
            ip: ip.into(),
            scanner: id(1),
            trap: id(2),
            hlc,
            level,
            job_level: level,
            args_ok: true,
        }
    }

    fn shares(p: &Paid) -> (Mc, Mc) {
        (p.scanner_mc, p.trap_mc)
    }

    #[test]
    fn shares_by_level() {
        let scans: Vec<Judged> = (1..=4u8)
            .map(|l| scan(l as u32, &format!("203.0.113.{l}"), at(DAY, l as u64), l))
            .collect();
        let paid = pay(&scans, &Gates::default());
        let got: Vec<(Mc, Mc)> = paid.iter().map(shares).collect();
        assert_eq!(got, [(1000, 250), (1000, 250), (2000, 500), (2000, 500)]);
        assert!(
            paid.iter()
                .all(|p| p.scanner_note.is_empty() && p.trap_note.is_empty())
        );
        let e = earned(&paid);
        assert_eq!(e.len(), 8);
        assert_eq!(
            e.iter()
                .filter(|x| x.node == id(1))
                .map(|x| x.mc)
                .sum::<Mc>(),
            6000
        );
        assert_eq!(
            e.iter()
                .filter(|x| x.node == id(2))
                .map(|x| x.mc)
                .sum::<Mc>(),
            1500
        );
        assert_eq!(e[0].hlc, at(DAY, 1), "dated like the scan");
    }

    #[test]
    fn one_paid_scan_per_ip_in_24_hours() {
        let ip = "203.0.113.9";
        let scans = [
            scan(1, ip, at(DAY, 0), 2),
            // Within the window: nothing.
            scan(2, ip, at(DAY, 600), 1),
            // A higher tier pays the difference, once.
            scan(3, ip, at(DAY, 700), 3),
            scan(4, ip, at(DAY, 800), 4),
            // 24 hours after the first: paid again (the window did not
            // move with the scans in between).
            scan(5, ip, at(DAY + 1, 0), 1),
            // Another address is not affected.
            scan(6, "203.0.113.10", at(DAY, 5), 1),
        ];
        let paid = pay(&scans, &Gates::default());
        let by_uid = |u: &str| paid.iter().find(|p| p.scan.scan_uid == u).unwrap();
        assert_eq!(shares(by_uid("s1")), (1000, 250));
        assert_eq!(shares(by_uid("s2")), (0, 0));
        assert!(
            by_uid("s2")
                .scanner_note
                .contains("already paid within 24 hours")
        );
        assert!(
            by_uid("s2")
                .trap_note
                .contains("already paid within 24 hours")
        );
        assert_eq!(shares(by_uid("s3")), (1000, 250));
        assert!(by_uid("s3").scanner_note.contains("difference"));
        assert_eq!(shares(by_uid("s4")), (0, 0));
        assert_eq!(shares(by_uid("s5")), (1000, 250));
        assert_eq!(shares(by_uid("s6")), (1000, 250));
        // The result does not depend on the order the scans are given in.
        let mut rev = scans.to_vec();
        rev.reverse();
        assert_eq!(pay(&rev, &Gates::default()), paid);
    }

    #[test]
    fn the_five_hundred_and_first_scan_of_a_day_pays_nothing_in_that_role() {
        let mut scans: Vec<Judged> = (0..501u32)
            .map(|n| {
                scan(
                    n,
                    &format!("198.51.{}.{}", n / 250, n % 250),
                    at(DAY, n as u64),
                    1,
                )
            })
            .collect();
        // The last one was queued by another trap, which is not at its limit.
        scans[500].trap = id(3);
        let paid = pay(&scans, &Gates::default());
        assert_eq!(shares(&paid[499]), (1000, 250));
        assert_eq!(shares(&paid[500]), (0, 250));
        assert!(paid[500].scanner_note.contains("daily limit"));
        // The next UTC day starts a new count.
        let next = pay(
            &[scan(600, "192.0.2.1", at(DAY + 1, 0), 1)],
            &Gates::default(),
        );
        assert_eq!(shares(&next[0]), (1000, 250));
    }

    #[test]
    fn arguments_evidence_and_gates_take_shares_away() {
        let mut other_args = scan(1, "203.0.113.1", at(DAY, 1), 2);
        other_args.args_ok = false;
        // Asked for level 4; the requests held here back level 2.
        let mut capped = scan(2, "203.0.113.2", at(DAY, 2), 2);
        capped.job_level = 4;
        let mut none = scan(3, "203.0.113.3", at(DAY, 3), 0);
        none.job_level = 2;
        let paid = pay(&[other_args, capped, none], &Gates::default());
        assert_eq!(
            shares(&paid[0]),
            (0, 250),
            "the trap is paid, the scanner is not"
        );
        assert!(paid[0].scanner_note.contains("arguments differ"));
        assert!(paid[0].trap_note.is_empty());
        assert_eq!(
            shares(&paid[1]),
            (1000, 250),
            "paid as the level it is backed for"
        );
        assert!(
            paid[1].scanner_note.contains("backs level 4"),
            "{}",
            paid[1].scanner_note
        );
        assert_eq!(shares(&paid[2]), (0, 0));
        assert!(paid[2].scanner_note.contains("no request held here backs"));
        // A scan that pays nothing opens no window: a real one later does.
        let later = [
            scan(3, "203.0.113.3", at(DAY, 3), 0),
            scan(4, "203.0.113.3", at(DAY, 9), 1),
        ];
        assert_eq!(shares(&pay(&later, &Gates::default())[1]), (1000, 250));

        // A node that does not earn here, and one whose audits fail.
        let scans = [scan(1, "203.0.113.1", at(DAY, 1), 3)];
        let mut gates = Gates::default();
        gates
            .no_shares
            .insert(id(2), "rules: disagree on 12% of 500".into());
        let p = pay(&scans, &gates);
        assert_eq!(shares(&p[0]), (2000, 0));
        assert!(
            p[0].trap_note
                .contains("not earning here: rules: disagree on 12% of 500")
        );
        let mut gates = Gates::default();
        gates
            .no_scanner_share
            .insert(id(1), "audits: 3 of 5 differ".into());
        let p = pay(&scans, &gates);
        assert_eq!(shares(&p[0]), (0, 500));
        assert!(p[0].scanner_note.contains("audits: 3 of 5 differ"));
        // A gated scan does not use up the daily limit of its node.
        let mut many: Vec<Judged> = (0..500u32)
            .map(|n| {
                scan(
                    n,
                    &format!("198.51.{}.{}", n / 250, n % 250),
                    at(DAY, n as u64),
                    1,
                )
            })
            .collect();
        for s in many.iter_mut().take(10) {
            s.args_ok = false;
        }
        many.push(scan(900, "192.0.2.9", at(DAY, 900), 1));
        assert_eq!(
            shares(pay(&many, &Gates::default()).last().unwrap()),
            (1000, 0)
        );
    }

    /// Rows as replication leaves them for one finished job.
    async fn finished_scan(store: &Store, ip: &str, job_level: i64, args: &str, n: u8) -> String {
        let row = store.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let (scanner, trap) = (id(1), id(2));
        let (job, uid) = (format!("job-{n}"), format!("scan-{n}"));
        let xml = format!(
            "<?xml version=\"1.0\"?>\n<nmaprun scanner=\"nmap\" args=\"{args}\" start=\"1\"><host/></nmaprun>"
        );
        sqlx::query(
            "INSERT INTO scan_jobs (uid, ip_id, level, status, queued_at, origin, hlc, arbiter, scanner)
             VALUES (?, ?, ?, 'done', datetime('now'), ?, 1, ?, ?)",
        )
        .bind(&job)
        .bind(row.id)
        .bind(job_level)
        .bind(&trap.0[..])
        .bind(&trap.0[..])
        .bind(&scanner.0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        let hlc = (hlc::wall_ms() << 16) as i64 + n as i64;
        sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, raw_xml)
             VALUES (?, ?, ?, (SELECT id FROM scan_jobs WHERE uid = ?), ?, ?, ?, datetime('now'), ?)",
        )
        .bind(&uid)
        .bind(&scanner.0[..])
        .bind(hlc)
        .bind(&job)
        .bind(&job)
        .bind(row.id)
        .bind(job_level)
        .bind(zstd::encode_all(xml.as_bytes(), 3).unwrap())
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, applied, received_at)
             VALUES (?, ?, ?, 'scan_result', ?, 1, datetime('now', '-5 minutes'))",
        )
        .bind(&scanner.0[..])
        .bind(n as i64)
        .bind(hlc)
        .bind(&uid)
        .execute(&store.pool)
        .await
        .unwrap();
        uid
    }

    /// A result of `job` by scanner 1, dated `hlc`, that arrived
    /// `arrived` ago (an SQLite modifier like "-5 minutes").
    async fn result_of(store: &Store, job: &str, uid: &str, seq: i64, hlc: i64, arrived: &str) {
        sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at)
             SELECT ?, ?, ?, id, uid, ip_id, level, datetime('now') FROM scan_jobs WHERE uid = ?",
        )
        .bind(uid)
        .bind(&id(1).0[..])
        .bind(hlc)
        .bind(job)
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, applied, received_at)
             VALUES (?, ?, ?, 'scan_result', ?, 1, datetime('now', ?))",
        )
        .bind(&id(1).0[..])
        .bind(seq)
        .bind(hlc)
        .bind(uid)
        .bind(arrived)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_scan_is_paid_no_earlier_than_its_job_and_the_earliest_result_counts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let now = (hlc::wall_ms() << 16) as i64;
        let day = (DAY_MS << 16) as i64;
        // Job 1, queued now; its result is dated two days back.
        finished_scan(&store, "203.0.113.20", 1, "nmap", 20).await;
        sqlx::query("UPDATE scan_jobs SET hlc = ? WHERE uid = 'job-20'")
            .bind(now)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE scans SET hlc = ? WHERE uid = 'scan-20'")
            .bind(now - 2 * day)
            .execute(&store.pool)
            .await
            .unwrap();
        // Job 2: a later result arrived first; the earlier one only now.
        finished_scan(&store, "203.0.113.21", 1, "nmap", 21).await;
        result_of(&store, "job-21", "scan-21-early", 50, now + 2, "-1 minutes").await;
        let origins = guard::Origins::Any;
        let j = Judge {
            pool: &store.pool,
            origins: &origins,
            classifier: Classifier::builtin(),
        };
        assert_eq!(judge(&j, 120).await.unwrap(), 1);
        let backdated = judged_one(&store.pool, "scan-20").await.unwrap().unwrap();
        assert_eq!(backdated.hlc, now as u64, "paid as of its job");
        assert_eq!(judged_one(&store.pool, "scan-21").await.unwrap(), None);
        // Once the earlier result has been here long enough, it is the one.
        assert_eq!(judge(&j, 30).await.unwrap(), 1);
        assert!(
            judged_one(&store.pool, "scan-21-early")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(judged_one(&store.pool, "scan-21").await.unwrap(), None);
    }

    #[tokio::test]
    async fn scans_older_than_the_window_are_not_judged_again_after_pruning() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let day = (DAY_MS << 16) as i64;
        let now = (hlc::wall_ms() << 16) as i64;
        // An old scan whose judgment the hourly prune has removed, and a
        // fresh one behind it.
        finished_scan(&store, "203.0.113.30", 1, "nmap", 30).await;
        sqlx::query("UPDATE scans SET hlc = ? WHERE uid = 'scan-30'")
            .bind(now - 20 * day)
            .execute(&store.pool)
            .await
            .unwrap();
        finished_scan(&store, "203.0.113.31", 1, "nmap", 31).await;
        let origins = guard::Origins::Any;
        let j = Judge {
            pool: &store.pool,
            origins: &origins,
            classifier: Classifier::builtin(),
        };
        assert_eq!(judge(&j, 60).await.unwrap(), 1, "only the fresh one");
        assert_eq!(judged_one(&store.pool, "scan-30").await.unwrap(), None);
        assert!(judged_one(&store.pool, "scan-31").await.unwrap().is_some());
        prune(&store.pool, super::super::window_start(hlc::wall_ms()))
            .await
            .unwrap();
        assert_eq!(judge(&j, 60).await.unwrap(), 0, "nothing to judge again");
    }

    #[tokio::test]
    async fn a_scan_is_judged_once_when_it_has_been_here_long_enough() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let cfg: crate::config::Config = toml::from_str(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n",
        )
        .unwrap();
        let line = |level: u8| {
            let argv =
                crate::scan::nmap_argv(level, &"203.0.113.7".parse().unwrap(), &cfg, 600).unwrap();
            format!("nmap {}", argv.join(" "))
        };
        // No request from this address is held here.
        let unbacked = finished_scan(&store, "203.0.113.7", 2, &line(2), 1).await;
        // Requests are held; the scanner used its own arguments.
        let rec = store.local();
        let ip = store
            .upsert_ip("203.0.113.8".parse().unwrap())
            .await
            .unwrap();
        for i in 0..3 {
            rec.insert_request(&crate::store::requests::NewRequest {
                ip_id: ip.id,
                method: "GET".into(),
                path: format!("/.env?{i}"),
                headers_json: "[]".into(),
                labels_json: "[]".into(),
                scan_level: 4,
                severity: 4,
                ..Default::default()
            })
            .await
            .unwrap();
        }
        let own_args =
            finished_scan(&store, "203.0.113.8", 2, "nmap -A -T5 -oX - 203.0.113.8", 2).await;
        let built_in = finished_scan(&store, "203.0.113.8", 1, &line(1), 3).await;

        // An audit of the last scan, by another node: not a payable scan.
        sqlx::query(
            "INSERT INTO scans (uid, origin, hlc, job_id, job_uid, ip_id, level, started_at, audit_of)
             SELECT 'audit-1', ?, hlc - 1, job_id, job_uid, ip_id, level, started_at, uid
             FROM scans WHERE uid = ?",
        )
        .bind(&id(1).0[..])
        .bind(&built_in)
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO repl_log (origin, seq, hlc, kind, uid, applied, received_at)
             VALUES (?, 99, 99, 'scan_audit', 'audit-1', 1, datetime('now', '-5 minutes'))",
        )
        .bind(&id(1).0[..])
        .execute(&store.pool)
        .await
        .unwrap();
        let origins = guard::Origins::Any;
        let j = Judge {
            pool: &store.pool,
            origins: &origins,
            classifier: Classifier::builtin(),
        };
        // Arrived five minutes ago: not yet.
        assert_eq!(judge(&j, 600).await.unwrap(), 0);
        assert_eq!(judge(&j, 60).await.unwrap(), 3);
        assert_eq!(judge(&j, 60).await.unwrap(), 0, "once");

        let all = judged_since(&store.pool, 0).await.unwrap();
        assert_eq!(all.len(), 3);
        let pool = store.pool.clone();
        let one = |uid: String| {
            let pool = pool.clone();
            async move { judged_one(&pool, &uid).await }
        };
        let a = one(unbacked.clone()).await.unwrap().unwrap();
        assert_eq!((a.level, a.job_level, a.args_ok), (0, 2, true));
        assert_eq!(
            (a.scanner, a.trap, a.ip.as_str()),
            (id(1), id(2), "203.0.113.7")
        );
        // What the requests held here back, as a scanner would judge them.
        let backed = guard::evidence(
            &store.pool,
            "203.0.113.8",
            &origins,
            Some(Classifier::builtin()),
        )
        .await
        .unwrap()
        .max_level;
        assert!(backed >= 1, "the test's requests ask for a scan");
        let b = one(own_args.clone()).await.unwrap().unwrap();
        assert_eq!((b.level, b.args_ok), (backed.min(2), false));
        let c = one(built_in.clone()).await.unwrap().unwrap();
        assert_eq!((c.level, c.args_ok), (1, true));
        assert_eq!(one("nope".into()).await.unwrap(), None);

        assert_eq!(prune(&store.pool, u64::MAX >> 1).await.unwrap(), 3);
    }
}
