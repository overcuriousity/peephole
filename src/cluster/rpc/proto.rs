//! Wire protocol versioning and the `hello` handshake.
use serde::{Deserialize, Serialize};

/// Highest protocol version this build speaks.
pub const PROTO_VERSION: u32 = 7;
/// Lowest protocol version this build still speaks. Version 1 let any
/// member revoke others and delete their records; it is not spoken.
pub const PROTO_MIN: u32 = 2;
/// First version that knows the owner messages (`OwnerHello`, `OwnerCmd`).
/// A node cannot decode a message kind it does not know, so these go only
/// to members that announce at least this version.
pub const OWNER_PROTO: u32 = 3;
/// Members from this version count the credits of protocol 7 (a fixed
/// supply, `credits::pool`) and sell scans at their own prices: payments,
/// funded jobs and every paid good run only between them, and sync
/// withholds protocol-7-only entries from older members.
pub const ECONOMY_PROTO: u32 = 7;
/// Members from this version answer `Msg::Rpc` sent through their outbox;
/// older ones cannot decode or relay it, so neither the target nor any
/// relay or outbox holder on the way may be older.
pub const ROUTED_PROTO: u32 = 6;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hello {
    pub proto_min: u32,
    pub proto_max: u32,
    pub node_name: String,
    /// peephole build version, informational.
    pub version: String,
    pub roles: Vec<String>,
    /// The address the caller's connection came from, as this server saw
    /// it. Older peers send none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_from: Option<std::net::IpAddr>,
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
