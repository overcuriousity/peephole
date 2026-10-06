//! The on-demand share: the part of each API provider's budget that paid
//! lookups may use. An operator who mints credits out of nothing can
//! still take no more than this from any server. Counted per provider and
//! UTC day; a day on which the share ran out makes the provider cost
//! double the next day (the surge), a day on which it did not halves that
//! again.
use crate::intel::provider::Provider;
use crate::store::Store;
use anyhow::Result;
use chrono::{Duration, NaiveDate, Utc};

/// The surge of a provider is at most this.
pub const SURGE_MAX: u32 = 8;
/// Counters of days older than this are deleted.
const KEEP_DAYS: i64 = 8;

/// This node's on-demand shares.
#[derive(Clone)]
pub struct Shares {
    store: Store,
    share: f64,
}

fn today() -> NaiveDate {
    Utc::now().date_naive()
}

fn used_key(provider: &str, day: NaiveDate) -> String {
    format!("ondemand:{provider}:{day}")
}

impl Shares {
    pub fn new(store: Store, share: f64) -> Self {
        Self {
            store,
            share: share.clamp(0.0, 1.0),
        }
    }

    /// On-demand lookups of `p` this node serves per UTC day: its budget
    /// times the share, rounded down. None: `p` has no budget, so no limit.
    pub fn allowance(&self, p: &dyn Provider) -> Option<u32> {
        p.per_day()
            .map(|d| (d * self.share).floor().clamp(0.0, u32::MAX as f64) as u32)
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
        Ok(match self.allowance(p) {
            None => false,
            Some(a) => self.used_on(p.name(), day).await? >= a,
        })
    }

    /// Whether today's share of `p` is used up.
    pub async fn spent(&self, p: &dyn Provider) -> Result<bool> {
        self.spent_on(p, today()).await
    }

    /// Count one on-demand lookup of `p`, unless its share of the day is
    /// spent (false). Written through, so a restart does not hand the
    /// share out twice.
    pub async fn take_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<bool> {
        let Some(allowance) = self.allowance(p) else {
            return Ok(true);
        };
        if allowance == 0 {
            return Ok(false);
        }
        let taken = sqlx::query(
            "INSERT INTO intel_meta (key, value) VALUES (?1, '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
             WHERE CAST(value AS INTEGER) < ?2",
        )
        .bind(used_key(p.name(), day))
        .bind(allowance as i64)
        .execute(&self.store.pool)
        .await?
        .rows_affected();
        Ok(taken == 1)
    }

    pub async fn take(&self, p: &dyn Provider) -> Result<bool> {
        self.take_on(p, today()).await
    }

    /// The surge of `p` on `day`: 1 at first; doubled (up to
    /// [`SURGE_MAX`]) for every day since it was last looked at on which
    /// the share ran out, halved (down to 1) for every day on which it did
    /// not. Kept with the budget counters.
    pub async fn surge_on(&self, p: &dyn Provider, day: NaiveDate) -> Result<u32> {
        let Some(allowance) = self.allowance(p) else {
            return Ok(1);
        };
        let key = format!("surge:{}", p.name());
        let stored = self.store.intel_get(&key).await?;
        let (mut factor, mut seen) = stored
            .as_deref()
            .and_then(|v| v.split_once('|'))
            .and_then(|(f, d)| Some((f.parse::<u32>().ok()?, d.parse::<NaiveDate>().ok()?)))
            .unwrap_or((1, day));
        factor = factor.clamp(1, SURGE_MAX);
        // Days long past all count as "did not run out": start from 1.
        if (day - seen).num_days() > 30 {
            (factor, seen) = (1, day);
        }
        while seen < day {
            let ran_out = allowance > 0 && self.used_on(p.name(), seen).await? >= allowance;
            factor = if ran_out {
                (factor * 2).min(SURGE_MAX)
            } else {
                (factor / 2).max(1)
            };
            seen += Duration::days(1);
        }
        let now = format!("{factor}|{day}");
        if stored.as_deref() != Some(now.as_str()) {
            self.store.intel_set(&key, &now).await?;
            // The counters of days no surge looks at any more.
            sqlx::query("DELETE FROM intel_meta WHERE key LIKE ? AND key < ?")
                .bind(format!("ondemand:{}:%", p.name()))
                .bind(used_key(p.name(), day - Duration::days(KEEP_DAYS)))
                .execute(&self.store.pool)
                .await?;
        }
        Ok(factor)
    }

    pub async fn surge(&self, p: &dyn Provider) -> Result<u32> {
        self.surge_on(p, today()).await
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
        let s = Shares::new(store.clone(), 0.2);
        // A daily budget of 12: two on-demand lookups (2.4, rounded down).
        let daily = Budget("abuseipdb", Some(12.0));
        // A weekly budget of 50 is about 7.14 a day: one.
        let weekly = Budget("greynoise-community", Some(50.0 / 7.0));
        let none = Budget("maxmind-geolite2", None);
        assert_eq!(s.allowance(&daily), Some(2));
        assert_eq!(s.allowance(&weekly), Some(1));
        assert_eq!(s.allowance(&none), None, "no budget, no limit");

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
        // A provider without a budget is never spent and not counted.
        for _ in 0..5 {
            assert!(s.take_on(&none, day(6)).await.unwrap());
        }
        assert_eq!(s.used_on("maxmind-geolite2", day(6)).await.unwrap(), 0);
        // A restart does not hand the share out again.
        let again = Shares::new(store.clone(), 0.2);
        assert!(!again.take_on(&daily, day(6)).await.unwrap());
        // No share at all: nothing is served on demand.
        let closed = Shares::new(store, 0.0);
        assert_eq!(closed.allowance(&daily), Some(0));
        assert!(closed.spent_on(&daily, day(9)).await.unwrap());
        assert!(!closed.take_on(&daily, day(9)).await.unwrap());
    }

    #[tokio::test]
    async fn the_surge_doubles_after_a_day_the_share_ran_out_and_halves_after_one_it_did_not() {
        let (store, _dir) = store().await;
        let s = Shares::new(store.clone(), 0.5);
        let p = Budget("shodan", Some(2.0));
        let spend = |d: u32| {
            let (s, p) = (&s, &p);
            async move {
                assert!(s.take_on(p, day(d)).await.unwrap());
            }
        };
        assert_eq!(s.surge_on(&p, day(1)).await.unwrap(), 1);
        spend(1).await;
        assert_eq!(s.surge_on(&p, day(1)).await.unwrap(), 1, "the same day");
        assert_eq!(s.surge_on(&p, day(2)).await.unwrap(), 2);
        spend(2).await;
        spend(3).await;
        // Read only on day 4: both days are taken into account.
        assert_eq!(s.surge_on(&p, day(4)).await.unwrap(), 8);
        spend(4).await;
        assert_eq!(s.surge_on(&p, day(5)).await.unwrap(), 8, "at most 8");
        // A restart keeps it.
        let again = Shares::new(store, 0.5);
        assert_eq!(again.surge_on(&p, day(5)).await.unwrap(), 8);
        // Two days on which it did not run out.
        assert_eq!(again.surge_on(&p, day(7)).await.unwrap(), 2);
        assert_eq!(again.surge_on(&p, day(20)).await.unwrap(), 1, "at least 1");
        // No budget, no surge.
        let free = Budget("maxmind-geolite2", None);
        assert_eq!(again.surge_on(&free, day(20)).await.unwrap(), 1);
    }
}
