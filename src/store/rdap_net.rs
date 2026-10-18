//! The RDAP network an IP belongs to, kept in columns of its own
//! (`ips.rdap_handle`, `ips.rdap_name`) so the admin network page, the
//! `/ips?net=` filter and the search find it through an index. Derived on
//! each node from every origin's RDAP row with the intel card's agreement
//! rule keyed by the handle ([`pick_handle`]), so not replicated itself: an
//! IP gets it whenever its intel view is refreshed, and IPs stored before
//! this build get it from [`backfill`].
//!
//! Handle and name come from registries through other members' rows:
//! attacker-controlled text, cut at [`MAX_LEN`] and only ever bound by
//! equality.
use super::Store;
use super::data::{RdapAnswer, RdapPick};
use anyhow::Result;
use sqlx::SqliteConnection;

/// Version of the derivation an IP was read with (0: not yet).
pub const RDAP_V: i64 = 1;

/// Longest handle or name kept, in characters (as `intel::rdap::compact`).
pub const MAX_LEN: usize = 200;

/// A text field of an RDAP answer, trimmed and cut at [`MAX_LEN`]; `""`
/// when absent.
fn field(a: &RdapAnswer, k: &str) -> String {
    a.data
        .get(k)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim()
        .chars()
        .take(MAX_LEN)
        .collect()
}

/// `(rdap_handle, rdap_name)` of an IP from its origins' RDAP rows (newest
/// first): the rows agreeing on the handle as `data::pick_rdap_by` decides,
/// none when they are disputed or there are none. An empty handle or name
/// is none.
pub fn pick_handle(rows: Vec<RdapAnswer>, me: Option<&[u8]>) -> (Option<String>, Option<String>) {
    let some = |s: String| (!s.is_empty()).then_some(s);
    match super::data::pick_rdap_by(rows, me, |a| vec![field(a, "handle")]) {
        Some(RdapPick::Chosen(a)) => (some(field(&a, "handle")), some(field(&a, "name"))),
        Some(RdapPick::Disputed(_)) | None => (None, None),
    }
}

/// Derive the network of `ip` from its stored RDAP rows. `pending`: only
/// while the IP has not been derived yet (the backfill's write).
async fn derive(conn: &mut SqliteConnection, ip: &str, pending: bool) -> Result<()> {
    let (rows, me) = super::data::rdap_answers(conn, ip).await?;
    let (handle, name) = pick_handle(rows, me.as_deref());
    let sql = if pending {
        "UPDATE ips SET rdap_handle = ?, rdap_name = ?, rdap_v = ? WHERE ip = ? AND rdap_v = 0"
    } else {
        "UPDATE ips SET rdap_handle = ?, rdap_name = ?, rdap_v = ? WHERE ip = ?"
    };
    sqlx::query(sql)
        .bind(handle)
        .bind(name)
        .bind(RDAP_V)
        .bind(ip)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Set the network of `ip` (`data::refresh_ip_view`, after every intel
/// write). Does nothing while the IP has no row yet.
pub(crate) async fn refresh(conn: &mut SqliteConnection, ip: &str) -> Result<()> {
    derive(conn, ip, false).await
}

/// IPs read per write transaction by [`backfill`].
const BACKFILL_BATCH: i64 = 500;

type Row = (i64, String);

/// The IPs [`backfill`] has left, through `idx_ips_rdap_pending`.
const PENDING: &str = "SELECT id, ip FROM ips WHERE rdap_v = 0 AND id > ? ORDER BY id LIMIT ?";

fn write_pending<'c>(
    conn: &'c mut SqliteConnection,
    r: &'c Row,
    _: (),
) -> super::backfill::WriteFut<'c> {
    Box::pin(derive(conn, &r.1, true))
}

/// Derive the network of the IPs stored before this build,
/// [`BACKFILL_BATCH`] at a time (see [`super::backfill`]); the RDAP rows
/// are read inside the write transaction. Returns how many IPs were read.
pub async fn backfill(pool: &sqlx::SqlitePool) -> Result<u64> {
    super::backfill::run(
        pool,
        super::backfill::Walk {
            pending: PENDING,
            below: None,
            batch: BACKFILL_BATCH,
            id: |r: &Row| r.0,
            derive: |_: &Row| (),
            write: write_pending,
        },
    )
    .await
}

/// What a search text names: a network's handle, or a name several
/// networks carry.
#[derive(Debug, PartialEq, Eq)]
pub enum NetHit {
    Handle(String),
    Name(String),
}

impl Store {
    /// The network `v` names: its handle, the one handle of the networks
    /// named `v`, or the name when several are. `None` when no IP is in
    /// such a network or `v` is longer than any stored value.
    pub async fn net_by_handle_or_name(&self, v: &str) -> Result<Option<NetHit>> {
        if v.is_empty() || v.chars().count() > MAX_LEN {
            return Ok(None);
        }
        let by_handle: Option<String> =
            sqlx::query_scalar("SELECT rdap_handle FROM ips WHERE rdap_handle = ? LIMIT 1")
                .bind(v)
                .fetch_optional(&self.read)
                .await?;
        if let Some(h) = by_handle {
            return Ok(Some(NetHit::Handle(h)));
        }
        let handles: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT rdap_handle FROM ips
             WHERE rdap_name = ? AND rdap_handle IS NOT NULL LIMIT 2",
        )
        .bind(v)
        .fetch_all(&self.read)
        .await?;
        Ok(match <[String; 1]>::try_from(handles) {
            Ok([h]) => Some(NetHit::Handle(h)),
            Err(h) if h.is_empty() => None,
            Err(_) => Some(NetHit::Name(v.to_string())),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::cluster::identity::{Identity, NodeId};
    use crate::cluster::record::{IpIntelRec, Record};
    use crate::store::data::{Ctx, SELF_ORIGIN_KEY, apply};

    async fn store() -> Store {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        Store::connect(&path).await.unwrap()
    }

    fn id() -> NodeId {
        Identity::generate().unwrap().id
    }

    /// Store `origin`'s RDAP row for `ip` with `handle` and `name`, as a
    /// replicated write (`None`: this node's, standalone).
    pub(crate) async fn rdap(
        s: &Store,
        ip: &str,
        origin: Option<&NodeId>,
        hlc: u64,
        handle: &str,
        name: &str,
    ) {
        let mut conn = s.pool.acquire().await.unwrap();
        let data = serde_json::json!({
            "handle": handle, "name": name, "range": "192.0.2.0 - 192.0.2.255",
            "cidrs": ["192.0.2.0/24"], "type": "ASSIGNED PA", "country": "NL",
            "org": "Example Registrant",
        });
        let r = Record::IpIntel(IpIntelRec {
            build: String::new(),
            ip: ip.into(),
            provider: crate::intel::RDAP.into(),
            fetched_at: crate::store::data::now_ts(),
            source_version: None,
            data_json: data.to_string(),
        });
        apply(&mut conn, Ctx { origin, hlc }, &r).await.unwrap();
    }

    type Net = (Option<String>, Option<String>, i64);

    pub(crate) async fn net(s: &Store, ip: &str) -> Net {
        sqlx::query_as("SELECT rdap_handle, rdap_name, rdap_v FROM ips WHERE ip = ?")
            .bind(ip)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    }

    async fn ip(s: &Store, ip: &str) {
        s.upsert_ip(ip.parse().unwrap()).await.unwrap();
    }

    const IP: &str = "203.0.113.7";

    #[tokio::test]
    async fn origins_agreeing_on_the_handle_set_it() {
        let s = store().await;
        ip(&s, IP).await;
        let (a, b) = (id(), id());
        rdap(&s, IP, Some(&a), 10, "NET-1", "Example").await;
        rdap(&s, IP, Some(&b), 20, "NET-1", "Example").await;
        assert_eq!(
            net(&s, IP).await,
            (Some("NET-1".into()), Some("Example".into()), RDAP_V)
        );
    }

    #[tokio::test]
    async fn origins_disagreeing_on_the_handle_set_none() {
        let s = store().await;
        ip(&s, IP).await;
        let (a, b) = (id(), id());
        rdap(&s, IP, Some(&a), 10, "NET-1", "One").await;
        rdap(&s, IP, Some(&b), 20, "NET-2", "Two").await;
        assert_eq!(net(&s, IP).await, (None, None, RDAP_V));
    }

    #[tokio::test]
    async fn this_nodes_own_row_settles_a_disagreement() {
        let s = store().await;
        let (a, b, me) = (id(), id(), id());
        s.intel_set(SELF_ORIGIN_KEY, &data_encoding::HEXUPPER.encode(&me.0))
            .await
            .unwrap();
        ip(&s, IP).await;
        rdap(&s, IP, Some(&a), 10, "NET-1", "One").await;
        rdap(&s, IP, Some(&b), 20, "NET-2", "Two").await;
        rdap(&s, IP, Some(&me), 5, "NET-3", "Mine").await;
        assert_eq!(
            net(&s, IP).await,
            (Some("NET-3".into()), Some("Mine".into()), RDAP_V)
        );
    }

    #[tokio::test]
    async fn an_ip_without_rdap_rows_is_derived_as_none() {
        let s = store().await;
        ip(&s, IP).await;
        assert_eq!(net(&s, IP).await, (None, None, RDAP_V));
    }

    #[tokio::test]
    async fn the_backfill_derives_every_pending_ip_once() {
        let s = store().await;
        for (i, h) in [("203.0.113.1", "NET-1"), ("203.0.113.2", "NET-1")] {
            ip(&s, i).await;
            rdap(&s, i, None, 1, h, "Example").await;
        }
        ip(&s, "203.0.113.3").await;
        // As a database from before this build left them.
        sqlx::query("UPDATE ips SET rdap_handle = NULL, rdap_name = NULL, rdap_v = 0")
            .execute(&s.pool)
            .await
            .unwrap();
        assert_eq!(backfill(&s.pool).await.unwrap(), 3);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM ips WHERE rdap_v = 0")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
        assert_eq!(net(&s, "203.0.113.2").await.0.as_deref(), Some("NET-1"));
        assert_eq!(net(&s, "203.0.113.3").await, (None, None, RDAP_V));
        assert_eq!(backfill(&s.pool).await.unwrap(), 0, "nothing left");
    }

    #[tokio::test]
    async fn a_new_rdap_result_moves_the_ip_without_the_backfill() {
        let s = store().await;
        ip(&s, IP).await;
        let data = |h: &str| serde_json::json!({"handle": h, "name": "Example"});
        s.local()
            .record_intel(IP, crate::intel::RDAP, None, data("NET-1"))
            .await
            .unwrap();
        assert_eq!(net(&s, IP).await.0.as_deref(), Some("NET-1"));
        s.local()
            .record_intel(IP, crate::intel::RDAP, None, data("NET-2"))
            .await
            .unwrap();
        assert_eq!(net(&s, IP).await.0.as_deref(), Some("NET-2"));
    }

    #[tokio::test]
    async fn an_rdap_result_stored_before_the_ip_applies_when_it_is_created() {
        let s = store().await;
        rdap(&s, IP, None, 1, "NET-1", "Example").await;
        ip(&s, IP).await;
        assert_eq!(
            net(&s, IP).await,
            (Some("NET-1".into()), Some("Example".into()), RDAP_V)
        );
    }

    #[tokio::test]
    async fn long_handles_and_names_are_cut() {
        let s = store().await;
        ip(&s, IP).await;
        let long = "x".repeat(300);
        rdap(&s, IP, None, 1, &format!("  {long}  "), &long).await;
        let (h, n, _) = net(&s, IP).await;
        assert_eq!(h.unwrap().chars().count(), MAX_LEN);
        assert_eq!(n.unwrap().chars().count(), MAX_LEN);
    }

    #[tokio::test]
    async fn search_finds_a_handle_a_unique_name_and_a_shared_name() {
        let s = store().await;
        for (i, h, n) in [
            ("203.0.113.1", "NET-1", "Solo"),
            ("203.0.113.2", "NET-2", "Shared"),
            ("203.0.113.3", "NET-3", "Shared"),
        ] {
            ip(&s, i).await;
            rdap(&s, i, None, 1, h, n).await;
        }
        let hit = |v: &'static str| {
            let s = s.clone();
            async move { s.net_by_handle_or_name(v).await.unwrap() }
        };
        assert_eq!(hit("NET-2").await, Some(NetHit::Handle("NET-2".into())));
        assert_eq!(hit("Solo").await, Some(NetHit::Handle("NET-1".into())));
        assert_eq!(hit("Shared").await, Some(NetHit::Name("Shared".into())));
        assert_eq!(hit("nope").await, None);
        assert_eq!(hit("").await, None);
    }
}
