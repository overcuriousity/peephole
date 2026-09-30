//! Shared template context. Every page struct carries a `Chrome`.
use crate::admin::assets::{STAMP, VERSION};

pub struct Chrome {
    pub authed: bool,
    /// Which nav item is current: "wall" | "ips" | "requests" | "admin" | "".
    pub active: &'static str,
    pub stamp: &'static str,
    pub version: &'static str,
}

impl Chrome {
    pub fn new(authed: bool, active: &'static str) -> Self {
        Self {
            authed,
            active,
            stamp: STAMP,
            version: VERSION,
        }
    }
}

/// Anything a template may hand us as a severity: `i64` or any depth of
/// reference to one (askama binds loop variables and `{% let %}` by reference).
pub trait SevValue {
    fn sev(&self) -> i64;
}
impl SevValue for i64 {
    fn sev(&self) -> i64 {
        *self
    }
}
impl<T: SevValue + ?Sized> SevValue for &T {
    fn sev(&self) -> i64 {
        (**self).sev()
    }
}

/// CSS class for a severity 0..4 (clamped).
pub fn sev_class<S: SevValue>(sev: S) -> String {
    format!("sev sev-{}", sev.sev().clamp(0, 4))
}
