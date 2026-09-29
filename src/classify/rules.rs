use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    pub rule: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub label: String,
    pub weight: u8,
    /// Regex applied to `path + "?" + query`.
    pub target_regex: Option<String>,
    /// Regex applied to the decoded body (lossy UTF-8).
    pub body_regex: Option<String>,
    /// Regex applied to the User-Agent header (case-insensitive).
    pub ua_regex: Option<String>,
    /// Exact path match (e.g. "/.env").
    pub path_exact: Option<String>,
}

pub fn load_dir(dir: &Path) -> Result<Vec<Rule>> {
    let mut rules = vec![];
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading rules dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    entries.sort();
    for path in entries {
        let text = std::fs::read_to_string(&path)?;
        let file: RuleFile = toml::from_str(&text)
            .with_context(|| format!("parsing {}", path.display()))?;
        rules.extend(file.rule);
    }
    Ok(rules)
}
