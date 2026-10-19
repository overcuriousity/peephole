//! The models the LLM gateway decoy (`trap::decoy::llm`) serves, read the
//! same by the decoy and by the store's decoy tallies. Each node serves its
//! own share of the pools, drawn from its `ident` ([`super::ai_id`]); a row
//! without one serves the fixed list every node served before (the first
//! four local models, all six upstream ones, version 0.6.5). Under the
//! `gpu-box` persona a node lists more local models, large ones among them.
use crate::trap::persona::AiIdentity;

/// A local Ollama model: name, family, parameter size, bytes.
pub type Local = (&'static str, &'static str, &'static str, i64);
/// An upstream model the gateway proxies: id, owner, display name.
pub type Upstream = (&'static str, &'static str, &'static str);

/// Local Ollama models a node lists 3 or 4 of, in this order.
pub const LOCAL: [Local; 10] = [
    ("llama3.1:8b", "llama", "8.0B", 4_920_753_328),
    ("qwen2.5-coder:7b", "qwen2", "7.6B", 4_683_087_332),
    ("deepseek-r1:14b", "qwen2", "14.8B", 8_988_112_040),
    ("nomic-embed-text:latest", "nomic-bert", "137M", 274_302_450),
    ("mistral:7b", "llama", "7.2B", 4_113_301_824),
    ("gemma2:9b", "gemma2", "9.2B", 5_443_152_417),
    ("phi3:mini", "phi3", "3.8B", 2_176_178_913),
    ("llama3.2:3b", "llama", "3.2B", 2_019_393_189),
    ("codellama:13b", "llama", "13B", 7_365_960_935),
    ("mxbai-embed-large:latest", "bert", "334M", 669_615_493),
];
/// Large local models a `gpu-box` node lists 2 or 3 of, after its share
/// of [`LOCAL`].
pub const LARGE: [Local; 6] = [
    ("llama3.3:70b", "llama", "70.6B", 42_520_413_916),
    ("qwen2.5:32b", "qwen2", "32.8B", 19_851_336_879),
    ("deepseek-r1:32b", "qwen2", "32.8B", 19_851_337_640),
    ("mixtral:8x7b", "llama", "46.7B", 26_442_481_545),
    ("qwen2.5-coder:32b", "qwen2", "32.8B", 19_851_349_856),
    ("gemma2:27b", "gemma2", "27.2B", 15_628_387_454),
];
/// Upstream models: a node drops at most one OpenAI and one Anthropic one.
pub const UPSTREAM: [Upstream; 6] = [
    ("gpt-4o", "openai", "GPT-4o"),
    ("gpt-4o-mini", "openai", "GPT-4o mini"),
    ("gpt-4.1", "openai", "GPT-4.1"),
    ("claude-sonnet-5-5", "anthropic", "Claude Sonnet 5.5"),
    ("claude-opus-5-5", "anthropic", "Claude Opus 5.5"),
    ("claude-haiku-4-5-20251001", "anthropic", "Claude Haiku 4.5"),
];
/// Ollama versions a node reports one of; the first is the fixed one.
pub const VERSIONS: [&str; 6] = ["0.6.5", "0.6.8", "0.7.1", "0.9.6", "0.11.4", "0.12.3"];

/// What one node's gateway serves.
#[derive(Debug, Clone, PartialEq)]
pub struct Models {
    pub local: Vec<&'static Local>,
    pub upstream: Vec<&'static Upstream>,
    pub version: &'static str,
}

impl Models {
    /// The models of the node with this `ident` (None: the fixed list)
    /// under `persona` (None: node-neutral).
    pub fn of(ident: Option<&str>, persona: Option<&str>) -> Self {
        let ai = AiIdentity::derive(ident, persona);
        let Some(id) = ai.id else {
            return Models {
                local: LOCAL[..4].iter().collect(),
                upstream: UPSTREAM.iter().collect(),
                version: VERSIONS[0],
            };
        };
        let s = &id.sel;
        let mut pick: Vec<usize> = id.order(19, LOCAL.len());
        let large = ai.persona.is_some_and(|p| p.large_models);
        pick.truncate(3 + s[18] as usize % 2 + if large { 2 } else { 0 });
        pick.sort_unstable();
        let mut local: Vec<&'static Local> = pick.into_iter().map(|i| &LOCAL[i]).collect();
        if large {
            // Bits of `s[18]` the count above does not read.
            let start = (s[18] >> 1) as usize;
            local.extend(
                (0..2 + (s[18] >> 4) as usize % 2).map(|k| &LARGE[(start + k) % LARGE.len()]),
            );
        }
        // 0-2 drop that OpenAI (Anthropic) model, 3 keeps all three.
        let drop = |b: u8, base: usize| (b % 4 < 3).then_some(base + b as usize % 4);
        let (oai, ant) = (drop(s[30], 0), drop(s[31], 3));
        Models {
            local,
            upstream: UPSTREAM
                .iter()
                .enumerate()
                .filter(|(i, _)| Some(*i) != oai && Some(*i) != ant)
                .map(|(_, u)| u)
                .collect(),
            version: VERSIONS[s[29] as usize % VERSIONS.len()],
        }
    }

    /// The local model `m` names (`name` alone means `name:latest`).
    pub fn local(&self, m: &str) -> Option<&'static Local> {
        self.local
            .iter()
            .find(|l| l.0 == m || (!m.contains(':') && l.0 == format!("{m}:latest")))
            .copied()
    }

    pub fn upstream(&self, m: &str) -> Option<&'static Upstream> {
        self.upstream.iter().find(|u| u.0 == m).copied()
    }

    /// Whether this gateway serves `m`.
    pub fn listed(&self, m: &str) -> bool {
        self.local(m).is_some() || self.upstream(m).is_some()
    }

    /// The model `ps` shows loaded: the first that is not an embedding model.
    pub fn loaded(&self) -> &'static Local {
        self.local
            .iter()
            .find(|l| !l.1.ends_with("bert"))
            .copied()
            .unwrap_or(&LOCAL[0])
    }
}

/// Whether the gateway of the node with this `ident` serves `m` under
/// `persona`.
pub fn listed(ident: Option<&str>, persona: Option<&str>, m: &str) -> bool {
    Models::of(ident, persona).listed(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ai_id::derive;

    #[test]
    fn no_ident_is_the_fixed_list() {
        let m = Models::of(None, None);
        assert_eq!(
            m.local.iter().map(|l| l.0).collect::<Vec<_>>(),
            [
                "llama3.1:8b",
                "qwen2.5-coder:7b",
                "deepseek-r1:14b",
                "nomic-embed-text:latest"
            ]
        );
        assert_eq!(m.upstream.len(), 6);
        assert_eq!((m.version, m.loaded().0), ("0.6.5", "llama3.1:8b"));
        assert!(listed(None, None, "nomic-embed-text") && !listed(None, None, "mistral:7b"));
    }

    #[test]
    fn each_node_lists_its_own_share() {
        let mut seen = std::collections::HashSet::new();
        for n in 0..64u8 {
            let i = derive(Some(&[n; 32]));
            let m = Models::of(Some(&i), None);
            assert_eq!(m, Models::of(Some(&i), None));
            assert_eq!(
                m,
                Models::of(Some(&i), Some("wordpress")),
                "only gpu-box differs"
            );
            assert!((3..=4).contains(&m.local.len()), "{i}");
            assert!((4..=6).contains(&m.upstream.len()), "{i}");
            for o in ["openai", "anthropic"] {
                assert!(m.upstream.iter().filter(|u| u.1 == o).count() >= 2, "{i}");
            }
            assert!(!m.loaded().1.ends_with("bert"));
            for l in &LOCAL {
                assert_eq!(
                    listed(Some(&i), None, l.0),
                    m.local.contains(&l),
                    "{i} {}",
                    l.0
                );
            }
            seen.insert(format!("{m:?}"));
        }
        assert!(seen.len() > 32, "{}", seen.len());
    }

    #[test]
    fn gpu_box_lists_more_and_larger_local_models() {
        for n in 0..64u8 {
            let i = derive(Some(&[n; 32]));
            let (gpu, wp) = (
                Models::of(Some(&i), Some("gpu-box")),
                Models::of(Some(&i), Some("wordpress")),
            );
            assert_ne!(gpu, wp, "{i}");
            assert!((7..=9).contains(&gpu.local.len()), "{i}");
            assert!(gpu.local.len() > wp.local.len());
            let large = gpu.local.iter().filter(|l| LARGE.contains(l)).count();
            assert!((2..=3).contains(&large), "{i}");
            assert_eq!(
                (gpu.upstream.clone(), gpu.version),
                (wp.upstream.clone(), wp.version)
            );
            for l in LOCAL.iter().chain(&LARGE) {
                assert_eq!(
                    listed(Some(&i), Some("gpu-box"), l.0),
                    gpu.local.contains(&l)
                );
            }
        }
        // No ident: the fixed list whatever the persona.
        assert_eq!(Models::of(None, Some("gpu-box")), Models::of(None, None));
    }
}
