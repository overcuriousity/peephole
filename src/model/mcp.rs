//! The MCP decoy's session ids (`trap::decoy::mcp`), recomputed the same
//! by the decoy and by the store's session list.

use crate::canary::{Kind, value};

/// The session id served to the request with this page token.
pub fn session_id(page_token: &str) -> String {
    value(page_token, Kind::McpSession)
}
