//! Why an arbiter gave a scan job to the scanner it did (`job_handouts`):
//! one row per grant, local to the arbiter (nothing goes between nodes),
//! kept for [`KEEP_DAYS`]. Shown on the scan page and in the Scans history.
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::credits::show;
use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::HashMap;

/// Days a grant's record is kept.
const KEEP_DAYS: i64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Paid, to the cheapest per delivered result.
    Cheapest,
    /// Paid, after the job waited out the reserve.
    Override,
    /// The scan budget did not cover it.
    Unpaid,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Reason::Cheapest => "cheapest",
            Reason::Override => "override",
            Reason::Unpaid => "unpaid",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "cheapest" => Reason::Cheapest,
            "override" => Reason::Override,
            "unpaid" => Reason::Unpaid,
            _ => return None,
        })
    }
}

/// One grant of a job and why.
#[derive(Debug, Clone)]
pub struct Handout {
    pub job_uid: String,
    pub scanner: NodeId,
    pub level: i64,
    /// Whether the grant was funded.
    pub paid: bool,
    pub price_mc: Option<u32>,
    /// The scanner's weight at the level.
    pub rate: f64,
    pub effective_mc: u32,
    /// The next best claimant and its price per delivered result.
    pub next: Option<(NodeId, u32)>,
    /// How long the job was held for the reserve ([`Reason::Cheapest`]),
    /// or queued ([`Reason::Override`]).
    pub waited_secs: i64,
    pub reason: Reason,
    /// Unpaid: claimants that sat the level out by the old rule.
    pub sat_out: i64,
}

/// Keep `h`, and drop records older than [`KEEP_DAYS`].
pub async fn record(pool: &SqlitePool, h: &Handout) -> Result<()> {
    sqlx::query(
        "INSERT INTO job_handouts (job_uid, scanner, level, paid, price_mc, rate, effective_mc,
                                   next_scanner, next_effective_mc, waited_secs, reason, sat_out)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&h.job_uid)
    .bind(&h.scanner.0[..])
    .bind(h.level)
    .bind(h.paid)
    .bind(h.price_mc.map(i64::from))
    .bind(h.rate)
    .bind(h.effective_mc as i64)
    .bind(h.next.map(|(id, _)| id.0.to_vec()))
    .bind(h.next.map(|(_, e)| e as i64))
    .bind(h.waited_secs)
    .bind(h.reason.as_str())
    .bind(h.sat_out)
    .execute(pool)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM job_handouts WHERE at < datetime('now', '-{KEEP_DAYS} days')"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

type Row = (
    String,
    Vec<u8>,
    i64,
    bool,
    Option<i64>,
    f64,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    i64,
    String,
    i64,
);

/// The latest grant of each of `job_uids` recorded here.
pub async fn latest(pool: &SqlitePool, job_uids: &[String]) -> Result<HashMap<String, Handout>> {
    if job_uids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT job_uid, scanner, level, paid, price_mc, rate, effective_mc,
                next_scanner, next_effective_mc, waited_secs, reason, sat_out
         FROM job_handouts WHERE id IN (
           SELECT MAX(id) FROM job_handouts
           WHERE job_uid IN (SELECT value FROM json_each(?)) GROUP BY job_uid)",
    )
    .bind(serde_json::to_string(job_uids)?)
    .fetch_all(pool)
    .await?;
    let mc = |v: i64| v.clamp(0, u32::MAX as i64) as u32;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let h = Handout {
                job_uid: r.0,
                scanner: NodeId::from_slice(&r.1).ok()?,
                level: r.2,
                paid: r.3,
                price_mc: r.4.map(mc),
                rate: r.5,
                effective_mc: mc(r.6),
                next: match (r.7, r.8) {
                    (Some(s), Some(e)) => Some((NodeId::from_slice(&s).ok()?, mc(e))),
                    _ => None,
                },
                waited_secs: r.9,
                reason: Reason::parse(&r.10)?,
                sat_out: r.11,
            };
            Some((h.job_uid.clone(), h))
        })
        .collect())
}

/// The record in a sentence, for the scan page and the history.
pub fn describe(h: &Handout, name: &dyn Fn(&NodeId) -> String) -> String {
    let s = name(&h.scanner);
    let eff = show(h.effective_mc as u64);
    match h.reason {
        Reason::Cheapest => {
            let price = h.price_mc.map_or_else(|| "–".into(), |p| show(p as u64));
            let mut t = format!(
                "Given to {s} for {eff} per delivered result (price {price}, {:.0} % at L{}).",
                h.rate * 100.0,
                h.level
            );
            if let Some((n, e)) = h.next {
                t.push_str(&format!(" Next best: {}, {}.", name(&n), show(e as u64)));
            }
            if h.waited_secs >= 60 {
                t.push_str(&format!(" Waited {} min for {s}.", h.waited_secs / 60));
            }
            t
        }
        Reason::Override => format!(
            "Waited {} min, then went to whoever asked: {s}, {eff} per delivered result.",
            h.waited_secs / 60
        ),
        Reason::Unpaid => {
            let sat = if h.sat_out > 0 {
                format!(" (scanners weak at L{} sat out by the old rule)", h.level)
            } else {
                String::new()
            };
            format!("Unpaid: the scan budget did not cover it; went to {s}{sat}.")
        }
    }
}

/// Member names as this node knows them; a short key otherwise.
pub fn names(node: &Node) -> impl Fn(&NodeId) -> String + Send + Sync + use<> {
    let m = node.members();
    move |id| m.get(id).map_or_else(|| id.short(), |r| r.name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_reason_reads_plainly() {
        let fast = NodeId([1; 32]);
        let flaky = NodeId([2; 32]);
        let name = |id: &NodeId| {
            if *id == fast {
                "Fast".to_string()
            } else {
                "Flaky".to_string()
            }
        };
        let mut h = Handout {
            job_uid: "j".into(),
            scanner: fast,
            level: 4,
            paid: true,
            price_mc: Some(30),
            rate: 1.0,
            effective_mc: 30,
            next: Some((flaky, 40)),
            waited_secs: 720,
            reason: Reason::Cheapest,
            sat_out: 0,
        };
        assert_eq!(
            describe(&h, &name),
            "Given to Fast for 0.03 per delivered result (price 0.03, 100 % at L4). \
             Next best: Flaky, 0.04. Waited 12 min for Fast."
        );
        h.waited_secs = 0;
        h.next = None;
        assert_eq!(
            describe(&h, &name),
            "Given to Fast for 0.03 per delivered result (price 0.03, 100 % at L4)."
        );
        let o = Handout {
            scanner: flaky,
            price_mc: Some(20),
            rate: 0.5,
            effective_mc: 40,
            waited_secs: 1830,
            reason: Reason::Override,
            ..h.clone()
        };
        assert_eq!(
            describe(&o, &name),
            "Waited 30 min, then went to whoever asked: Flaky, 0.04 per delivered result."
        );
        let u = Handout {
            paid: false,
            reason: Reason::Unpaid,
            sat_out: 2,
            ..o.clone()
        };
        assert_eq!(
            describe(&u, &name),
            "Unpaid: the scan budget did not cover it; went to Flaky \
             (scanners weak at L4 sat out by the old rule)."
        );
        let u = Handout { sat_out: 0, ..u };
        assert_eq!(
            describe(&u, &name),
            "Unpaid: the scan budget did not cover it; went to Flaky."
        );
    }

    #[tokio::test]
    async fn the_latest_grant_is_kept_for_eight_days() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let h = |uid: &str, eff: u32| Handout {
            job_uid: uid.into(),
            scanner: NodeId([1; 32]),
            level: 2,
            paid: true,
            price_mc: Some(eff),
            rate: 1.0,
            effective_mc: eff,
            next: Some((NodeId([2; 32]), eff + 1)),
            waited_secs: 0,
            reason: Reason::Cheapest,
            sat_out: 0,
        };
        record(&s.pool, &h("old", 1)).await.unwrap();
        sqlx::query("UPDATE job_handouts SET at = datetime('now', '-9 days')")
            .execute(&s.pool)
            .await
            .unwrap();
        record(&s.pool, &h("a", 10)).await.unwrap();
        record(&s.pool, &h("a", 20)).await.unwrap(); // a retry's grant
        let got = latest(&s.pool, &["a".into(), "old".into()]).await.unwrap();
        assert_eq!(got["a"].effective_mc, 20);
        assert_eq!(got["a"].next, Some((NodeId([2; 32]), 21)));
        assert_eq!(got["a"].reason, Reason::Cheapest);
        assert!(!got.contains_key("old"), "pruned after 8 days");
    }
}
