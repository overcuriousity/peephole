//! Reverse DNS names of the sources (`intel::rdns`). In a cluster the node
//! that recorded a source buys its names from a quorum and replicates the
//! answers (`rdns_name`); every node tallies them. A standalone node looks
//! up on its own.
use super::Store;
use crate::cluster::identity::NodeId;
use anyhow::Result;

// Most names kept of one lookup: as many as the lookup checks.
use crate::scan::crawler::MAX_NAMES;

/// Per name, how many of those that answered gave it, and whether that
/// is more than half; most votes first. A node's second answer counts for
/// nothing; a failure is no answer.
pub fn tally_names(
    answers: &[(NodeId, Result<Vec<String>, String>)],
) -> (usize, Vec<(String, usize, bool)>) {
    let mut seen = std::collections::HashSet::new();
    let mut votes: std::collections::BTreeMap<String, usize> = Default::default();
    let mut answered = 0;
    for (id, a) in answers {
        if !seen.insert(*id) {
            continue;
        }
        let Ok(names) = a else { continue };
        answered += 1;
        let distinct: std::collections::BTreeSet<&String> = names.iter().collect();
        for n in distinct {
            *votes.entry(n.clone()).or_default() += 1;
        }
    }
    let mut out: Vec<(String, usize, bool)> = votes
        .into_iter()
        .map(|(n, v)| (n, v, v * 2 > answered))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    (answered, out)
}

/// Keep a reverse-name record: every name with its votes and flag; the
/// newest record's tally stands.
pub(crate) async fn apply_rdns(
    conn: &mut sqlx::SqliteConnection,
    _ctx: super::data::Ctx<'_>,
    r: &crate::cluster::record::RdnsRec,
) -> Result<super::data::Effect> {
    use super::data::Effect;
    let ok_name = |n: &String| crate::intel::dns::valid_name(n).as_deref() == Some(n.as_str());
    if r.uid.len() > 128
        || r.answers.len() > crate::intel::dns::MAX_QUORUM
        || !r
            .ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(crate::net::is_scannable_target)
        || r.answers.iter().any(|(_, a)| match a {
            Ok(v) => v.len() > MAX_NAMES || !v.iter().all(ok_name),
            Err(e) => e.len() > 200,
        })
        || chrono::NaiveDateTime::parse_from_str(&r.at, "%Y-%m-%d %H:%M:%S").is_err()
    {
        return Ok(Effect::Ignored);
    }
    if let Some(t) = super::data::erased_by(conn, &r.uid).await? {
        return Ok(Effect::Erased(t));
    }
    let Some(ip_id) = super::data::ensure_ip(conn, &r.ip, None).await? else {
        return Ok(Effect::Ignored);
    };
    let (answered, names) = tally_names(&r.answers);
    for (name, votes, agreed) in names {
        sqlx::query(
            "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen)
             VALUES (?1, ?2, 'rdns', ?3, ?3)
             ON CONFLICT(ip_id, name, source) DO UPDATE
               SET first_seen = min(first_seen, excluded.first_seen)",
        )
        .bind(ip_id)
        .bind(&name)
        .bind(&r.at)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "UPDATE ip_names SET last_seen = ?1, agreed = ?2, asked = ?3, answered = ?4,
                    votes = ?5, record_uid = ?6
             WHERE ip_id = ?7 AND name = ?8 AND source = 'rdns'
               AND (last_seen < ?1 OR (last_seen = ?1 AND record_uid <= ?6))",
        )
        .bind(&r.at)
        .bind(agreed)
        .bind(r.answers.len() as i64)
        .bind(answered as i64)
        .bind(votes as i64)
        .bind(&r.uid)
        .bind(ip_id)
        .bind(&name)
        .execute(&mut *conn)
        .await?;
    }
    // A newer tally no longer agrees names it omits (the rows stay).
    sqlx::query(
        "UPDATE ip_names SET agreed = 0
         WHERE ip_id = ?1 AND source = 'rdns'
           AND (last_seen < ?2 OR (last_seen = ?2 AND record_uid < ?3))",
    )
    .bind(ip_id)
    .bind(&r.at)
    .bind(&r.uid)
    .execute(&mut *conn)
    .await?;
    Ok(Effect::Applied)
}

impl Store {
    /// Sources due a reverse lookup, most recently seen first: never looked
    /// up, or seen again more than a day after the last lookup.
    pub async fn rdns_due(&self, limit: i64) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, ip FROM ips
             WHERE request_count > 0
               AND (rdns_at IS NULL OR last_seen > datetime(rdns_at, '+1 day'))
             ORDER BY last_seen DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// This node's own sources due a reverse lookup: the first request held
    /// for them is its own (`origin` is this node, or none: recorded before
    /// it joined), never looked up or seen again a day after the last time.
    pub async fn rdns_due_own(&self, limit: i64, me: &NodeId) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT i.id, i.ip FROM ips i
             WHERE i.request_count > 0
               AND (i.rdns_at IS NULL OR i.last_seen > datetime(i.rdns_at, '+1 day'))
               AND (SELECT r.origin IS NULL OR r.origin = ?1 FROM requests r
                    WHERE r.ip_id = i.id ORDER BY r.id LIMIT 1)
             ORDER BY i.last_seen DESC LIMIT ?2",
        )
        .bind(&me.0[..])
        .bind(limit)
        .fetch_all(&self.read)
        .await?)
    }

    /// The source was looked up now (whatever was found).
    pub async fn mark_rdns(&self, ip_id: i64) -> Result<()> {
        sqlx::query("UPDATE ips SET rdns_at = ? WHERE id = ?")
            .bind(super::data::now_ts())
            .bind(ip_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store what a lookup found (possibly nothing) and when it ran.
    /// Names no longer found keep their row; `last_seen` dates them. An IP
    /// deleted while it was looked up gets nothing.
    pub async fn record_rdns(&self, ip_id: i64, names: &[String]) -> Result<()> {
        let now = super::data::now_ts();
        let mut tx = self.pool.begin().await?;
        for name in names.iter().take(MAX_NAMES) {
            sqlx::query(
                "INSERT INTO ip_names (ip_id, name, source, first_seen, last_seen, agreed)
                 SELECT ?1, ?2, 'rdns', ?3, ?3, 1 WHERE EXISTS (SELECT 1 FROM ips WHERE id = ?1)
                 ON CONFLICT(ip_id, name, source) DO UPDATE SET last_seen = excluded.last_seen",
            )
            .bind(ip_id)
            .bind(name)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("UPDATE ips SET rdns_at = ? WHERE id = ?")
            .bind(&now)
            .bind(ip_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::requests::NewRequest;

    async fn source(s: &Store, ip: &str) -> i64 {
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        s.insert_request(&NewRequest {
            ip_id: row.id,
            method: "GET".into(),
            path: "/".into(),
            headers_json: "[]".into(),
            labels_json: "[]".into(),
            ..Default::default()
        })
        .await
        .unwrap();
        row.id
    }

    #[test]
    fn a_reverse_name_stands_with_more_than_half_of_those_that_answered() {
        use crate::cluster::identity::NodeId;
        let id = |n: u8| NodeId([n; 32]);
        let answers = vec![
            (id(1), Ok(vec!["host.example.net".to_string()])),
            (
                id(2),
                Ok(vec!["host.example.net".into(), "alias.example.net".into()]),
            ),
            (id(3), Err("timed out".to_string())),
            (id(2), Ok(vec!["alias.example.net".into()])), // a second answer counts for nothing
        ];
        let (answered, names) = tally_names(&answers);
        assert_eq!(answered, 2);
        assert_eq!(
            names,
            vec![
                ("host.example.net".to_string(), 2, true),
                ("alias.example.net".to_string(), 1, false),
            ]
        );
    }

    #[tokio::test]
    async fn only_this_nodes_own_sources_are_due_for_buying() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let mine = source(&s, "198.51.100.7").await;
        let theirs = source(&s, "198.51.100.8").await;
        let me = crate::cluster::identity::NodeId([1; 32]);
        let other = crate::cluster::identity::NodeId([2; 32]);
        for (ip_id, origin) in [(mine, me), (theirs, other)] {
            sqlx::query("UPDATE requests SET origin = ? WHERE ip_id = ?")
                .bind(&origin.0[..])
                .bind(ip_id)
                .execute(&s.pool)
                .await
                .unwrap();
        }
        let due: Vec<i64> = s
            .rdns_due_own(10, &me)
            .await
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(due, [mine]);
        s.mark_rdns(mine).await.unwrap();
        assert!(s.rdns_due_own(10, &me).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_reverse_name_record_keeps_every_name_with_its_flag() {
        use crate::cluster::identity::NodeId;
        use crate::cluster::record::RdnsRec;
        use crate::store::data::{Ctx, Effect};
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let origin = NodeId([1; 32]);
        let r = RdnsRec {
            uid: format!("{}u1", origin.uid_prefix()),
            ip: "198.51.100.9".into(),
            at: "2026-10-09 12:00:00".into(),
            answers: vec![
                (NodeId([1; 32]), Ok(vec!["host.example.net".into()])),
                (
                    NodeId([2; 32]),
                    Ok(vec!["host.example.net".into(), "alias.example.net".into()]),
                ),
            ],
            build: String::new(),
        };
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: Some(&origin),
            hlc: 5,
        };
        assert_eq!(
            apply_rdns(&mut conn, ctx, &r).await.unwrap(),
            Effect::Applied
        );
        let mut bad = r.clone();
        bad.answers = (0..10).map(|i| (NodeId([i; 32]), Ok(vec![]))).collect();
        assert_eq!(
            apply_rdns(&mut conn, ctx, &bad).await.unwrap(),
            Effect::Ignored,
            "over the quorum"
        );
        drop(conn);
        let ip = s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap();
        let names = s.names_for_ip(ip.id).await.unwrap();
        let got: Vec<(String, bool, i64, i64)> = names
            .iter()
            .map(|n| (n.name.clone(), n.agreed, n.votes, n.answered))
            .collect();
        assert!(
            got.contains(&("host.example.net".into(), true, 2, 2)),
            "{got:?}"
        );
        assert!(
            got.contains(&("alias.example.net".into(), false, 1, 2)),
            "{got:?}"
        );
        assert!(names.iter().all(|n| n.source == "rdns"));
    }

    #[tokio::test]
    async fn a_newer_record_clears_the_agreement_of_names_it_omits_and_erasing_removes_rows() {
        use crate::cluster::identity::NodeId;
        use crate::cluster::record::RdnsRec;
        use crate::store::data::{Ctx, Effect};
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let origin = NodeId([1; 32]);
        let rec = |n: u8, at: &str, name: &str| RdnsRec {
            uid: format!("{}u{n}", origin.uid_prefix()),
            ip: "198.51.100.9".into(),
            at: at.into(),
            answers: vec![(origin, Ok(vec![name.into()]))],
            build: String::new(),
        };
        let mut conn = s.pool.acquire().await.unwrap();
        let ctx = Ctx {
            origin: Some(&origin),
            hlc: 5,
        };
        let old = rec(1, "2026-10-09 12:00:00", "old.example.net");
        let new = rec(2, "2026-10-10 12:00:00", "new.example.net");
        for r in [&old, &new] {
            assert_eq!(
                apply_rdns(&mut conn, ctx, r).await.unwrap(),
                Effect::Applied
            );
        }
        let ip = crate::store::data::ensure_ip(&mut conn, "198.51.100.9", None)
            .await
            .unwrap()
            .unwrap();
        let agreed = async |conn: &mut sqlx::SqliteConnection, name: &str| -> Option<bool> {
            sqlx::query_scalar("SELECT agreed FROM ip_names WHERE ip_id = ? AND name = ?")
                .bind(ip)
                .bind(name)
                .fetch_optional(&mut *conn)
                .await
                .unwrap()
        };
        assert_eq!(agreed(&mut conn, "old.example.net").await, Some(false));
        assert_eq!(agreed(&mut conn, "new.example.net").await, Some(true));
        // Erasing the newest record removes its rows.
        crate::store::data::unmaterialize(&mut conn, "rdns_name", &new.uid)
            .await
            .unwrap();
        assert_eq!(agreed(&mut conn, "new.example.net").await, None);
        assert_eq!(agreed(&mut conn, "old.example.net").await, Some(false));
    }

    #[tokio::test]
    async fn new_and_returning_sources_are_due() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let fresh = source(&s, "198.51.100.7").await;
        let done = source(&s, "198.51.100.8").await;
        s.upsert_ip("198.51.100.9".parse().unwrap()).await.unwrap(); // no request
        s.record_rdns(done, &[]).await.unwrap();
        let due: Vec<i64> = s
            .rdns_due(50)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(due, vec![fresh]);

        s.record_rdns(fresh, &["host-7.example.net".into()])
            .await
            .unwrap();
        assert!(s.rdns_due(50).await.unwrap().is_empty());
        // Back more than a day after the lookup: due again.
        sqlx::query("UPDATE ips SET last_seen = datetime('now', '+2 days') WHERE id = ?")
            .bind(done)
            .execute(&s.pool)
            .await
            .unwrap();
        let due: Vec<i64> = s
            .rdns_due(50)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(due, vec![done]);

        let names = s.names_for_ip(fresh).await.unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            (
                names[0].name.as_str(),
                names[0].source.as_str(),
                names[0].agreed
            ),
            ("host-7.example.net", "rdns", true)
        );
        // Found again: one row, last_seen moves.
        s.record_rdns(fresh, &["host-7.example.net".into()])
            .await
            .unwrap();
        assert_eq!(s.names_for_ip(fresh).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rdns_names_go_with_the_last_request() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = source(&s, "198.51.100.7").await;
        s.record_rdns(id, &["host-7.example.net".into()])
            .await
            .unwrap();
        let mut conn = s.pool.acquire().await.unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id)
            .await
            .unwrap();
        assert_eq!(
            s.names_for_ip(id).await.unwrap().len(),
            1,
            "a request remains"
        );
        sqlx::query("DELETE FROM requests WHERE ip_id = ?")
            .bind(id)
            .execute(&mut *conn)
            .await
            .unwrap();
        crate::store::data::drop_orphan_ip(&mut conn, id)
            .await
            .unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ips WHERE id = ?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(left, 0, "the name kept nothing alive");
        // A lookup that finishes after its IP went stores nothing.
        s.record_rdns(id, &["host-7.example.net".into()])
            .await
            .unwrap();
        assert!(s.names_for_ip(id).await.unwrap().is_empty());
    }
}
