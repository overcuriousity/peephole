//! Poison-tolerant lock acquisition.
//!
//! A panic while a std lock is held poisons it, and `lock().unwrap()` then
//! panics in every later acquirer: one bad request takes the HLC clock, the
//! scan arbiter or a rate limiter down with it. These helpers take the guard
//! anyway, warn once with the call site, and clear the poison so the next
//! acquirer does not warn again.

use std::panic::Location;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

fn recovered(kind: &str, at: &Location<'_>) {
    tracing::warn!(
        "recovered a poisoned {kind} at {}:{} (a thread panicked while holding it)",
        at.file(),
        at.line()
    );
}

pub trait MutexExt<T: ?Sized> {
    /// `lock()`, but a poisoned mutex yields its guard instead of panicking.
    fn lock_or_recover(&self) -> MutexGuard<'_, T>;
}

impl<T: ?Sized> MutexExt<T> for Mutex<T> {
    #[track_caller]
    fn lock_or_recover(&self) -> MutexGuard<'_, T> {
        let at = Location::caller();
        match self.lock() {
            Ok(g) => g,
            Err(p) => {
                recovered("mutex", at);
                self.clear_poison();
                p.into_inner()
            }
        }
    }
}

pub trait RwLockExt<T: ?Sized> {
    /// `read()`, but a poisoned lock yields its guard instead of panicking.
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T>;
    /// `write()`, but a poisoned lock yields its guard instead of panicking.
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T: ?Sized> RwLockExt<T> for RwLock<T> {
    #[track_caller]
    fn read_or_recover(&self) -> RwLockReadGuard<'_, T> {
        let at = Location::caller();
        match self.read() {
            Ok(g) => g,
            Err(p) => {
                recovered("rwlock", at);
                self.clear_poison();
                p.into_inner()
            }
        }
    }

    #[track_caller]
    fn write_or_recover(&self) -> RwLockWriteGuard<'_, T> {
        let at = Location::caller();
        match self.write() {
            Ok(g) => g,
            Err(p) => {
                recovered("rwlock", at);
                self.clear_poison();
                p.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn poison_mutex<T: Send + 'static>(m: &Arc<Mutex<T>>) {
        let m = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m.lock().unwrap();
            panic!("poison");
        })
        .join();
    }

    #[test]
    fn poisoned_mutex_stays_usable() {
        let m = Arc::new(Mutex::new(1));
        poison_mutex(&m);
        assert!(m.is_poisoned());
        *m.lock_or_recover() += 1;
        assert_eq!(*m.lock_or_recover(), 2);
        // Cleared: the next plain lock() succeeds, and only one warning fires.
        assert!(!m.is_poisoned());
        assert!(m.lock().is_ok());
    }

    #[test]
    fn poisoned_rwlock_stays_usable() {
        let l = Arc::new(RwLock::new(1));
        let l2 = l.clone();
        let _ = std::thread::spawn(move || {
            let _g = l2.write().unwrap();
            panic!("poison");
        })
        .join();
        assert!(l.is_poisoned());
        assert_eq!(*l.read_or_recover(), 1);
        *l.write_or_recover() = 3;
        assert_eq!(*l.read_or_recover(), 3);
        assert!(!l.is_poisoned());
    }
}
