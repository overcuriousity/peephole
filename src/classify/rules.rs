use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    pub rule: Vec<Rule>,
}

/// `deny_unknown_fields` turns a typo (e.g. `target_rgex`) into a load error
/// instead of a rule that silently never matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub label: String,
    pub weight: u8,
    /// Regex applied to `path + "?" + query`, raw and percent-decoded.
    pub target_regex: Option<String>,
    /// Regex applied to the request body, raw and percent-decoded.
    pub body_regex: Option<String>,
    /// Regex applied to the User-Agent header (case-insensitive).
    pub ua_regex: Option<String>,
    /// Regex applied to every header as `name: value`, raw and decoded
    /// (catches e.g. Shellshock or Log4Shell payloads in any header).
    pub header_regex: Option<String>,
    /// Exact path match (e.g. "/.env").
    pub path_exact: Option<String>,
}

impl Rule {
    /// At least one matcher, and a weight in range. A matcher-less rule or a
    /// weight of 0 (which would suppress the default "probe" label) is almost
    /// always a mistake; reject it so `check-config` catches it.
    fn validate(&self) -> Result<()> {
        if self.target_regex.is_none()
            && self.body_regex.is_none()
            && self.ua_regex.is_none()
            && self.header_regex.is_none()
            && self.path_exact.is_none()
        {
            anyhow::bail!("rule `{}` has no matcher", self.label);
        }
        if !(1..=4).contains(&self.weight) {
            anyhow::bail!(
                "rule `{}` has weight {} (must be 1..=4)",
                self.label,
                self.weight
            );
        }
        Ok(())
    }
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
        let file: RuleFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        for r in &file.rule {
            r.validate()
                .with_context(|| format!("in {}", path.display()))?;
        }
        rules.extend(file.rule);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(toml_src: &str) -> Result<()> {
        let f: RuleFile = toml::from_str(toml_src)?;
        for r in &f.rule {
            r.validate()?;
        }
        Ok(())
    }

    #[test]
    fn unknown_field_is_rejected() {
        // A typo'd matcher key must fail to load, not become a dead rule.
        let e = one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_rgex=\"foo\"\n").unwrap_err();
        assert!(e.to_string().contains("unknown field"), "{e}");
    }

    #[test]
    fn matcherless_and_bad_weight_are_rejected() {
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=0\ntarget_regex=\"a\"\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=5\ntarget_regex=\"a\"\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=3\ntarget_regex=\"a\"\n").is_ok());
    }

    #[test]
    fn shipped_rules_load_and_validate() {
        let rules = load_dir(std::path::Path::new("rules")).unwrap();
        assert!(!rules.is_empty());
    }
}
