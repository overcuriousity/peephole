//! What the AI decoys answer from: [`DecoyIn`], parsed from the request
//! once by [`choose`] and stored with the row (`decoy_in`), so
//! [`super::render`] needs nothing else to render the answer again.
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Longest free-text field kept (model, path, command, SQL, URL).
pub const MAX_FIELD: usize = 128;
/// Longest JSON-RPC id string echoed.
pub const MAX_RPC_ID: usize = 64;
/// Longest `decoy_in` stored.
pub const MAX_LEN: usize = 512;
/// Largest body parsed as JSON (the trap keeps 64 KiB).
const MAX_JSON: usize = 64 * 1024;

/// The parsed parts of an MCP or LLM request its answer depends on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DecoyIn {
    /// JSON-RPC id to echo: a number or a short string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rpc: Option<Value>,
    /// MCP method as sent (cut to 64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
    /// MCP `initialize` protocolVersion asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// MCP tool called.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The tool's main argument (path, command, SQL, URL) or resource URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arg: Option<String>,
    /// The answer class picked from `arg` (`dotenv`, `select`, `id`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cls: Option<String>,
    /// `sse`: a legacy MCP transport request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// LLM API style: `ollama`, `openai`, `anthropic`, `azure`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<String>,
    /// LLM endpoint (`chat`, `chat-completions`, `messages`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Azure deployment name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<String>,
    /// Anthropic count_tokens estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<i64>,
}

impl DecoyIn {
    /// A stored value; anything unreadable is the default.
    pub fn parse(s: Option<&str>) -> Self {
        s.and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    /// As stored: at most [`MAX_LEN`] bytes. Fields are cut further, and
    /// `arg` dropped last, until it fits.
    pub fn to_json(&self) -> String {
        let s = serde_json::to_string(self).unwrap_or_default();
        if s.len() <= MAX_LEN {
            return s;
        }
        let mut d = self.clone();
        for f in [
            &mut d.arg,
            &mut d.model,
            &mut d.tool,
            &mut d.deployment,
            &mut d.m,
            &mut d.proto,
        ] {
            *f = f.as_deref().map(|v| cut(v, 32));
        }
        let s = serde_json::to_string(&d).unwrap_or_default();
        if s.len() <= MAX_LEN {
            return s;
        }
        d.arg = None;
        serde_json::to_string(&d).unwrap_or_default()
    }

    /// The JSON-RPC id to echo (`null` when none was kept).
    pub fn rpc_id(&self) -> Value {
        self.rpc.clone().unwrap_or(Value::Null)
    }
}

/// `s` cut to at most `n` characters.
pub fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// The JSON-RPC id worth echoing: a number, or a string of at most
/// [`MAX_RPC_ID`] characters.
pub fn rpc_id(v: Option<&Value>) -> Option<Value> {
    match v? {
        Value::Number(n) => Some(Value::Number(n.clone())),
        Value::String(s) if s.chars().count() <= MAX_RPC_ID => Some(Value::String(s.clone())),
        _ => None,
    }
}

/// A request as the AI decoys look at it. `body` is decoded
/// (`classify::decoded_body`).
pub struct Ask<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
}

impl Ask<'_> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query?
            .split('&')
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
    }

    /// The body as JSON (None: empty, too large, or not JSON).
    pub fn json(&self) -> Option<Value> {
        if self.body.is_empty() || self.body.len() > MAX_JSON {
            return None;
        }
        serde_json::from_slice(self.body).ok()
    }
}

/// The AI decoy for this request, if any: its name (`mcp:…`, `llm:…`) and
/// what it is rendered from.
pub fn choose(ask: &Ask) -> Option<(String, DecoyIn)> {
    super::mcp::choose(ask).or_else(|| super::llm::choose(ask))
}
