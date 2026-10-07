//! What the log says about payments. Offers, receipts and transfers are
//! kept as rows when their log entry is applied, so the ledger reads a
//! week of them without walking the log. A row is the entry as it was
//! signed; whether it moves anything is the ledger's business.
use super::day_of;
use crate::cluster::hlc;
use crate::cluster::identity::NodeId;
use crate::cluster::record::{Record, WireEntry};
use anyhow::Result;
use sqlx::{SqliteConnection, SqlitePool};

/// How an entry's seal checked out here (`cluster::seal`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SealState {
    /// The entry carries no seal (a receipt).
    None,
    Consistent,
    /// Part of the range is not held here, or only as an erased stub.
    Unchecked,
    Inconsistent,
}

impl SealState {
    fn to_db(self) -> i64 {
        match self {
            SealState::None => 0,
            SealState::Consistent => 1,
            SealState::Unchecked => 2,
            SealState::Inconsistent => 3,
        }
    }

    fn from_db(v: i64) -> Self {
        match v {
            1 => SealState::Consistent,
            2 => SealState::Unchecked,
            3 => SealState::Inconsistent,
            _ => SealState::None,
        }
    }
}

/// A payment as its origin signed it.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Offer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        /// The scan job it funds; such an offer lapses after the longest scan.
        job: Option<String>,
    },
    Receipt {
        payer: NodeId,
        offer_seq: u64,
        charged_mc: u32,
        answered: Vec<String>,
    },
    Transfer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub origin: NodeId,
    pub seq: u64,
    pub hlc: u64,
    pub kind: Kind,
    pub seal: SealState,
}

/// Providers one receipt may name, and how long a name may be.
const MAX_ANSWERED: usize = 16;
const MAX_PROVIDER_LEN: usize = 64;

/// Whether `parts` (of an offer or transfer written on `day`) name 1 to 7
/// lots, each once, each of that day or the 6 before, each with more than
/// nothing.
pub fn parts_ok(parts: &[(u32, u32)], day: u32) -> bool {
    let first = day.saturating_sub(super::LOT_DAYS - 1);
    (1..=super::LOT_DAYS as usize).contains(&parts.len())
        && parts
            .iter()
            .all(|(d, mc)| (first..=day).contains(d) && *mc > 0)
        && parts
            .iter()
            .enumerate()
            .all(|(i, (d, _))| parts[..i].iter().all(|(x, _)| x != d))
}

/// Keep `r` (the record of `e`) as a row. False: `r` is no payment, or it
/// breaks a shape rule and the ledger ignores it.
pub async fn apply(
    conn: &mut SqliteConnection,
    e: &WireEntry,
    r: &Record,
    seal: SealState,
) -> Result<bool> {
    let day = day_of(e.hlc);
    type Cols<'a> = (
        &'static str,
        &'a NodeId,
        &'a [(u32, u32)],
        Option<u64>,
        Option<u32>,
        Option<&'a [String]>,
        Option<&'a str>,
    );
    let (kind, peer, parts, offer_seq, charged, answered, job_uid): Cols = match r {
        Record::CreditOffer { to, parts, job, .. }
            if parts_ok(parts, day) && job.as_ref().is_none_or(|j| j.len() <= 64) =>
        {
            ("offer", to, parts, None, None, None, job.as_deref())
        }
        Record::CreditTransfer { to, parts, .. } if *to != e.origin && parts_ok(parts, day) => {
            ("transfer", to, parts, None, None, None, None)
        }
        Record::CreditReceipt {
            payer,
            offer_seq,
            charged_mc,
            answered,
        } if answered.len() <= MAX_ANSWERED
            && answered.iter().all(|a| a.len() <= MAX_PROVIDER_LEN) =>
        {
            (
                "receipt",
                payer,
                &[],
                Some(*offer_seq),
                Some(*charged_mc),
                Some(answered),
                None,
            )
        }
        _ => return Ok(false),
    };
    sqlx::query(
        "INSERT OR IGNORE INTO credit_entries
           (origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, job_uid)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&e.origin.0[..])
    .bind(e.seq.min(i64::MAX as u64) as i64)
    .bind(hlc::to_db(e.hlc))
    .bind(kind)
    .bind(&peer.0[..])
    .bind(serde_json::to_string(parts)?)
    .bind(offer_seq.map(|s| s.min(i64::MAX as u64) as i64))
    .bind(charged.map(i64::from))
    .bind(answered.map(serde_json::to_string).transpose()?)
    .bind(seal.to_db())
    .bind(job_uid)
    .execute(&mut *conn)
    .await?;
    Ok(true)
}

type Row = (
    Vec<u8>,
    i64,
    i64,
    String,
    Vec<u8>,
    String,
    Option<i64>,
    Option<i64>,
    Option<String>,
    i64,
    Option<String>,
);

const COLUMNS: &str =
    "origin, seq, hlc, kind, peer, parts, offer_seq, charged_mc, answered, seal, job_uid";

fn from_row(r: Row) -> Result<Entry> {
    let peer = NodeId::from_slice(&r.4)?;
    let kind = match r.3.as_str() {
        "offer" => Kind::Offer {
            to: peer,
            parts: serde_json::from_str(&r.5)?,
            job: r.10,
        },
        "transfer" => Kind::Transfer {
            to: peer,
            parts: serde_json::from_str(&r.5)?,
        },
        "receipt" => Kind::Receipt {
            payer: peer,
            offer_seq: r.6.unwrap_or(0).max(0) as u64,
            charged_mc: r.7.unwrap_or(0).clamp(0, u32::MAX as i64) as u32,
            answered: serde_json::from_str(r.8.as_deref().unwrap_or("[]"))?,
        },
        other => anyhow::bail!("credit entry of unknown kind `{other}`"),
    };
    Ok(Entry {
        origin: NodeId::from_slice(&r.0)?,
        seq: r.1.max(0) as u64,
        hlc: hlc::from_db(r.2),
        kind,
        seal: SealState::from_db(r.9),
    })
}

/// The payments dated `from_hlc` or later, in the order the ledger walks
/// them: by HLC, then origin, then sequence number.
pub async fn since(pool: &SqlitePool, from_hlc: u64) -> Result<Vec<Entry>> {
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM credit_entries WHERE hlc >= ? ORDER BY hlc, origin, seq"
    )))
    .bind(hlc::to_db(from_hlc))
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(from_row).collect()
}

pub async fn get(pool: &SqlitePool, origin: &NodeId, seq: u64) -> Result<Option<Entry>> {
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM credit_entries WHERE origin = ? AND seq = ?"
    )))
    .bind(&origin.0[..])
    .bind(seq.min(i64::MAX as u64) as i64)
    .fetch_optional(pool)
    .await?;
    row.map(from_row).transpose()
}

/// Drop the rows dated before `before_hlc` (their lots are long gone).
pub async fn prune(pool: &SqlitePool, before_hlc: u64) -> Result<u64> {
    Ok(sqlx::query("DELETE FROM credit_entries WHERE hlc < ?")
        .bind(hlc::to_db(before_hlc))
        .execute(pool)
        .await?
        .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::cluster::record::Seal;
    use crate::store::Store;

    #[test]
    fn parts_name_one_to_seven_live_days_once_each() {
        let day = 20_000;
        assert!(parts_ok(&[(day, 1)], day));
        assert!(parts_ok(&[(day - 6, 5), (day, 5)], day));
        assert!(!parts_ok(&[], day), "none");
        assert!(!parts_ok(&[(day, 0)], day), "nothing");
        assert!(!parts_ok(&[(day - 7, 5)], day), "gone");
        assert!(!parts_ok(&[(day + 1, 5)], day), "not earned yet");
        assert!(!parts_ok(&[(day, 5), (day, 5)], day), "twice");
        let all: Vec<(u32, u32)> = (0..7).map(|i| (day - i, 1)).collect();
        assert!(parts_ok(&all, day));
        let mut eight = all.clone();
        eight.push((day - 6, 1));
        assert!(!parts_ok(&eight, day));
        // The first days of the epoch do not underflow.
        assert!(parts_ok(&[(0, 1)], 3));
    }

    #[tokio::test]
    async fn a_scan_offer_keeps_its_job_and_a_long_job_is_not_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let day = 20_000u32;
        let at = |min: u64| ((day as u64 * crate::credits::DAY_MS + min * 60_000) << 16) | 1;
        let offer = |job: String| Record::CreditOffer {
            to: b.id,
            parts: vec![(day, 200)],
            seal: Seal::default(),
            job: Some(job),
        };
        let mut conn = store.pool.acquire().await.unwrap();
        let kept = offer("job".into());
        let e = WireEntry::sign(&a, 3, at(1), &kept).unwrap();
        assert!(apply(&mut conn, &e, &kept, SealState::Consistent).await.unwrap());
        let long = offer("j".repeat(65));
        let e = WireEntry::sign(&a, 4, at(2), &long).unwrap();
        assert!(!apply(&mut conn, &e, &long, SealState::Consistent).await.unwrap());
        // 64 bytes is still a job.
        let edge = offer("j".repeat(64));
        let e = WireEntry::sign(&a, 5, at(3), &edge).unwrap();
        assert!(apply(&mut conn, &e, &edge, SealState::Consistent).await.unwrap());
        drop(conn);
        let got = get(&store.pool, &a.id, 3).await.unwrap().unwrap();
        assert_eq!(
            got.kind,
            Kind::Offer {
                to: b.id,
                parts: vec![(day, 200)],
                job: Some("job".into()),
            }
        );
        assert_eq!(get(&store.pool, &a.id, 4).await.unwrap(), None);
        assert_eq!(since(&store.pool, 0).await.unwrap().len(), 2);
    }

    #[test]
    fn an_offer_without_a_job_encodes_like_one_before_jobs() {
        use crate::cluster::rpc::cbor;
        #[derive(serde::Serialize)]
        #[serde(tag = "k", rename_all = "snake_case")]
        enum Old {
            CreditOffer {
                to: NodeId,
                parts: Vec<(u32, u32)>,
                seal: Seal,
            },
        }
        let to = Identity::generate().unwrap().id;
        let parts = vec![(20_000, 250)];
        let new = Record::CreditOffer {
            to,
            parts: parts.clone(),
            seal: Seal::default(),
            job: None,
        };
        let old = Old::CreditOffer {
            to,
            parts,
            seal: Seal::default(),
        };
        assert_eq!(cbor::encode(&new).unwrap(), cbor::encode(&old).unwrap());
        // What an old node wrote reads as an offer without a job.
        let back: Record = cbor::decode(&cbor::encode(&old).unwrap()).unwrap();
        assert!(matches!(back, Record::CreditOffer { job: None, .. }));
    }

    #[tokio::test]
    async fn payments_are_kept_as_rows_and_broken_ones_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (Identity::generate().unwrap(), Identity::generate().unwrap());
        let day = 20_000u32;
        let at = |min: u64| ((day as u64 * crate::credits::DAY_MS + min * 60_000) << 16) | 1;
        let seal = Seal::default();
        let sign = |id: &Identity, seq: u64, hlc: u64, r: &Record| {
            (WireEntry::sign(id, seq, hlc, r).unwrap(), r.clone())
        };
        let offer = sign(
            &a,
            4,
            at(1),
            &Record::CreditOffer {
                to: b.id,
                parts: vec![(day - 1, 300), (day, 200)],
                seal: seal.clone(),
                job: None,
            },
        );
        let receipt = sign(
            &b,
            9,
            at(2),
            &Record::CreditReceipt {
                payer: a.id,
                offer_seq: 4,
                charged_mc: 400,
                answered: vec!["abuseipdb".into()],
            },
        );
        let transfer = sign(
            &a,
            5,
            at(3),
            &Record::CreditTransfer {
                to: b.id,
                parts: vec![(day, 50)],
                seal: seal.clone(),
            },
        );
        let to_self = sign(
            &a,
            6,
            at(4),
            &Record::CreditTransfer {
                to: a.id,
                parts: vec![(day, 50)],
                seal: seal.clone(),
            },
        );
        let stale = sign(
            &a,
            7,
            at(5),
            &Record::CreditOffer {
                to: b.id,
                parts: vec![(day - 7, 50)],
                seal: seal.clone(),
                job: None,
            },
        );
        let other = sign(&a, 8, at(6), &Record::LogSeal { seal });
        let mut conn = store.pool.acquire().await.unwrap();
        for ((e, r), kept, state) in [
            (&offer, true, SealState::Consistent),
            (&receipt, true, SealState::None),
            (&transfer, true, SealState::Unchecked),
            (&to_self, false, SealState::Consistent),
            (&stale, false, SealState::Consistent),
            (&other, false, SealState::Consistent),
        ] {
            assert_eq!(apply(&mut conn, e, r, state).await.unwrap(), kept, "{r:?}");
        }
        // Applied twice (a replay after an unblock): still one row.
        assert!(
            apply(&mut conn, &offer.0, &offer.1, SealState::Consistent)
                .await
                .unwrap()
        );
        drop(conn);

        let all = since(&store.pool, 0).await.unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0],
            Entry {
                origin: a.id,
                seq: 4,
                hlc: at(1),
                kind: Kind::Offer {
                    to: b.id,
                    parts: vec![(day - 1, 300), (day, 200)],
                    job: None,
                },
                seal: SealState::Consistent,
            }
        );
        assert_eq!(
            all[1].kind,
            Kind::Receipt {
                payer: a.id,
                offer_seq: 4,
                charged_mc: 400,
                answered: vec!["abuseipdb".into()]
            }
        );
        assert_eq!((all[2].seq, all[2].seal), (5, SealState::Unchecked));
        assert_eq!(since(&store.pool, at(3)).await.unwrap().len(), 1);
        assert_eq!(
            get(&store.pool, &a.id, 4).await.unwrap(),
            Some(all[0].clone())
        );
        assert_eq!(get(&store.pool, &a.id, 99).await.unwrap(), None);
        assert_eq!(prune(&store.pool, at(3)).await.unwrap(), 2);
        assert_eq!(since(&store.pool, 0).await.unwrap().len(), 1);
    }
}
