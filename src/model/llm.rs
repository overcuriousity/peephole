//! The models the LLM gateway decoy (`trap::decoy::llm`) serves, read the
//! same by the decoy and by the store's decoy tallies.

/// Local Ollama models: name, family, parameter size, bytes.
pub const LOCAL: [(&str, &str, &str, i64); 4] = [
    ("llama3.1:8b", "llama", "8.0B", 4_920_753_328),
    ("qwen2.5-coder:7b", "qwen2", "7.6B", 4_683_087_332),
    ("deepseek-r1:14b", "qwen2", "14.8B", 8_988_112_040),
    ("nomic-embed-text:latest", "nomic-bert", "137M", 274_302_450),
];
/// Upstream models the gateway proxies: id, owner, display name.
pub const UPSTREAM: [(&str, &str, &str); 6] = [
    ("gpt-4o", "openai", "GPT-4o"),
    ("gpt-4o-mini", "openai", "GPT-4o mini"),
    ("gpt-4.1", "openai", "GPT-4.1"),
    ("claude-sonnet-5-5", "anthropic", "Claude Sonnet 5.5"),
    ("claude-opus-5-5", "anthropic", "Claude Opus 5.5"),
    ("claude-haiku-4-5-20251001", "anthropic", "Claude Haiku 4.5"),
];

pub(crate) fn local(m: &str) -> Option<&'static (&'static str, &'static str, &'static str, i64)> {
    LOCAL
        .iter()
        .find(|l| l.0 == m || (!m.contains(':') && l.0 == format!("{m}:latest")))
}

/// Whether the gateway serves `model`.
pub fn listed(m: &str) -> bool {
    local(m).is_some() || UPSTREAM.iter().any(|u| u.0 == m)
}
