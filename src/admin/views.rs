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

/// CSS class for a severity 0..4 (clamped). Generic so templates can pass
/// either an `i64` or the `&i64` a `{% let %}` binding produces.
pub fn sev_class<S: std::borrow::Borrow<i64>>(sev: S) -> String {
    format!("sev sev-{}", sev.borrow().clamp(&0, &4))
}
