//! Wire protocol versioning and the `hello` handshake.
use serde::{Deserialize, Serialize};

/// Highest protocol version this build speaks.
pub const PROTO_VERSION: u32 = 2;
/// Lowest protocol version this build still speaks. Version 1 let any
/// member revoke others and delete their records; it is not spoken.
pub const PROTO_MIN: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub proto_min: u32,
    pub proto_max: u32,
    pub node_name: String,
    /// peephole build version, informational.
    pub version: String,
    pub roles: Vec<String>,
}

/// Highest protocol version both ranges include.
pub fn negotiate(a: (u32, u32), b: (u32, u32)) -> Option<u32> {
    let lo = a.0.max(b.0);
    let hi = a.1.min(b.1);
    (lo <= hi).then_some(hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_picks_highest_common_version() {
        assert_eq!(negotiate((1, 3), (2, 5)), Some(3));
        assert_eq!(negotiate((1, 1), (1, 1)), Some(1));
        assert_eq!(negotiate((1, 2), (3, 4)), None);
    }
}
