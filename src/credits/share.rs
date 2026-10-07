//! The on-demand share: the part of each API provider's budget that paid
//! lookups may use, and `offer_per_day` for a provider without a budget
//! and for names resolved for other members. An operator who mints
//! credits out of nothing can still take no more than this from any
//! server. Counted per good and UTC day.
use crate::intel::provider::Provider;
use crate::store::Store;
use anyhow::Result;
use chrono::{Duration, NaiveDate, Utc};

/// Counters of days older than this are deleted.
const KEEP_DAYS: i64 = 8;

/// This node's on-demand shares.
#[derive(Clone)]
pub struct Shares {
    store: Store,
    share: f64,
    offer_per_day: u32,
}

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

fn used_key(provider: &str, day: NaiveDate) -> String {
    format!("ondemand:{provider}:{day}")
}

impl Shares {
    pub fn new(store: Store, share: f64, offer_per_day: u32) -> Self {
        Self {
            store,
            share: share.clamp(0.0, 1.0),
            offer_per_day,
        }
    }

    /// Paid lookups of `p` this node serves a UTC day: its API budget times
    /// the share, rounded down, or `offer_per_day` without a budget.
    pub fn allowance(&self, p: &dyn Provider) -> u32 {
        match p.per_day() {
            Some(d) => (d * self.share).floor().clamp(0.0, u32::MAX as f64) as u32,
            None => self.offer_per_day,
        }
    }

    pub fn offer_per_day(&self) -> u32 {
        self.offer_per_day
    }

    pub async fn used_on(&self, provider: &str, day: NaiveDate) -> Result<u32> {
        Ok(self
            .store
            .intel_get(&used_key(provider, day))
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    pub async fn used(&self, provider: &str) -> Result<u32> {
        self.used_on(provider, today()).await
    }

    pub async fn spent_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<bool> {
        Ok(self.used_on(p.name(), day).await? >= self.allowance(p))
    }

    /// Whether today's share of `p` is used up.
    pub async fn spent(&self, p: &dyn Provider) -> Result<bool> {
        self.spent_on(p, today()).await
    }

    /// Count one on-demand lookup of `p`, unless its share of the day is
    /// spent (false). Written through, so a restart does not hand the
    /// share out twice.
    pub async fn take_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<bool> {
        self.take_named(p.name(), self.allowance(p), day).await
    }

    pub async fn take(&self, p: &dyn Provider) -> Result<bool> {
        self.take_on(p, today()).await
    }

    /// Count one paid unit of `good` (a resolution) against
    /// `offer_per_day`; false when today's are used up.
    pub async fn take_good(&self, good: &str) -> Result<bool> {
        self.take_named(good, self.offer_per_day, today()).await
    }

    async fn take_named(&self, name: &str, allowance: u32, day: NaiveDate) -> Result<bool> {
        if allowance == 0 {
            return Ok(false);
        }
        if self.used_on(name, day).await? == 0 {
            // The first of the day: the counters of days long past go.
            sqlx::query("DELETE FROM intel_meta WHERE key LIKE ? AND key < ?")
                .bind(format!("ondemand:{name}:%"))
                .bind(used_key(name, day - Duration::days(KEEP_DAYS)))
                .execute(&self.store.pool)
                .await?;
        }
        let taken = sqlx::query(
            "INSERT INTO intel_meta (key, value) VALUES (?1, '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
             WHERE CAST(value AS INTEGER) < ?2",
        )
        .bind(used_key(name, day))
        .bind(allowance as i64)
        .execute(&self.store.pool)
        .await?
        .rows_affected();
        Ok(taken == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::provider::Finding;
    use futures::future::BoxFuture;

    /// A provider with a budget of `per_day` requests a day.
    struct Budget(&'static str, Option<f64>);

    impl Provider for Budget {
        fn name(&self) -> &'static str {
            self.0
        }
        fn ready(&self) -> bool {
            true
        }
        fn per_day(&self) -> Option<f64> {
            self.1
        }
        fn lookup<'a>(&'a self, _ips: &'a [String]) -> BoxFuture<'a, Vec<Finding>> {
            Box::pin(async { vec![] })
        }
    }

    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, d).unwrap()
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn the_share_is_counted_per_provider_and_day_and_survives_a_restart() {
        let (store, _dir) = store().await;
        let s = Shares::new(store.clone(), 0.2, 1000);
        // A daily budget of 12: two on-demand lookups (2.4, rounded down).
        let daily = Budget("abuseipdb", Some(12.0));
        // A weekly budget of 50 is about 7.14 a day: one.
        let weekly = Budget("weekly-test", Some(50.0 / 7.0));
        let none = Budget("maxmind-geolite2", None);
        assert_eq!(s.allowance(&daily), 2);
        assert_eq!(s.allowance(&weekly), 1);
        assert_eq!(s.allowance(&none), 1000, "no budget: offer_per_day");

        assert!(s.take_on(&daily, day(6)).await.unwrap());
        assert!(!s.spent_on(&daily, day(6)).await.unwrap());
        assert!(s.take_on(&daily, day(6)).await.unwrap());
        assert!(s.spent_on(&daily, day(6)).await.unwrap());
        assert!(!s.take_on(&daily, day(6)).await.unwrap(), "spent");
        assert_eq!(s.used_on("abuseipdb", day(6)).await.unwrap(), 2);
        // Another provider, another day: their own counts.
        assert!(s.take_on(&weekly, day(6)).await.unwrap());
        assert!(!s.take_on(&weekly, day(6)).await.unwrap());
        assert!(s.take_on(&daily, day(7)).await.unwrap());
        // A provider without a budget is counted against offer_per_day.
        for _ in 0..5 {
            assert!(s.take_on(&none, day(6)).await.unwrap());
        }
        assert_eq!(s.used_on("maxmind-geolite2", day(6)).await.unwrap(), 5);
        // A restart does not hand the share out again.
        let again = Shares::new(store.clone(), 0.2, 1000);
        assert!(!again.take_on(&daily, day(6)).await.unwrap());
        // No share at all: nothing is served on demand.
        let closed = Shares::new(store, 0.0, 1000);
        assert_eq!(closed.allowance(&daily), 0);
        assert!(closed.spent_on(&daily, day(9)).await.unwrap());
        assert!(!closed.take_on(&daily, day(9)).await.unwrap());
    }

    #[tokio::test]
    async fn a_good_is_counted_against_offer_per_day() {
        let (store, _dir) = store().await;
        let s = Shares::new(store, 0.2, 2);
        assert_eq!(s.offer_per_day(), 2);
        assert!(s.take_good("resolve").await.unwrap());
        assert!(s.take_good("resolve").await.unwrap());
        assert!(!s.take_good("resolve").await.unwrap(), "used up");
    }
}
