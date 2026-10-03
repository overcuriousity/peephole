use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    /// A file with every rule commented out is empty, not an error.
    #[serde(default)]
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
    /// HTTP methods, exact and case-sensitive as sent (e.g. `["PUT"]`). With
    /// other matchers the rule only fires for these methods; on its own it
    /// fires on the method alone.
    pub methods: Option<Vec<String>>,
    /// OWASP references for the family: Top-10 2021 classes (`A03:2021`)
    /// and/or Automated Threats (`OAT-014`). Optional; all shipped rules
    /// carry it (a meta-test enforces that).
    pub owasp: Option<Vec<String>>,
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
            && self.methods.is_none()
        {
            anyhow::bail!("rule `{}` has no matcher", self.label);
        }
        if let Some(m) = &self.methods {
            // A method is an HTTP token; an empty list would never match.
            let token = |s: &str| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            };
            if m.is_empty() || !m.iter().all(|s| token(s)) {
                anyhow::bail!(
                    "rule `{}` has an empty or invalid `methods` list",
                    self.label
                );
            }
        }
        if !(1..=4).contains(&self.weight) {
            anyhow::bail!(
                "rule `{}` has weight {} (must be 1..=4)",
                self.label,
                self.weight
            );
        }
        for tag in self.owasp.iter().flatten() {
            let top10 = tag
                .strip_prefix('A')
                .and_then(|r| r.strip_suffix(":2021"))
                .is_some_and(|n| {
                    n.len() == 2
                        && n.bytes().all(|b| b.is_ascii_digit())
                        && ("01"..="10").contains(&n)
                });
            let oat = tag
                .strip_prefix("OAT-0")
                .is_some_and(|n| n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()));
            if !top10 && !oat {
                anyhow::bail!("rule `{}` has an invalid owasp tag `{tag}`", self.label);
            }
        }
        Ok(())
    }
}

/// A rules file: its name (as in `rules/`) and its text.
pub type RulesFile = (String, String);

/// The rules files built into the binary (`rules/*.toml` at build time, by
/// name), from `build.rs`.
pub const BUILTIN: &[(&str, &str)] = include!(concat!(env!("OUT_DIR"), "/builtin_rules.rs"));

/// The built-in rules files, owned.
pub fn builtin_files() -> Vec<RulesFile> {
    BUILTIN
        .iter()
        .map(|(n, t)| (n.to_string(), t.to_string()))
        .collect()
}

/// The rules of `files`, parsed and validated, in the files' order.
pub fn parse(files: &[RulesFile]) -> Result<Vec<Rule>> {
    let mut rules = vec![];
    for (name, text) in files {
        let file: RuleFile = toml::from_str(text).with_context(|| format!("parsing {name}"))?;
        for r in &file.rule {
            r.validate().with_context(|| format!("in {name}"))?;
        }
        rules.extend(file.rule);
    }
    Ok(rules)
}

/// The fingerprint of a ruleset: SHA-256 (lower-case hex) over its files
/// sorted by name, each as its name's and its text's length (8 bytes, big
/// endian) followed by the bytes, so no two rulesets share an encoding.
pub fn fingerprint(files: &[RulesFile]) -> String {
    use sha2::Digest;
    let mut sorted: Vec<&RulesFile> = files.iter().collect();
    sorted.sort();
    let mut h = sha2::Sha256::new();
    for (name, text) in sorted {
        for part in [name.as_bytes(), text.as_bytes()] {
            h.update((part.len() as u64).to_be_bytes());
            h.update(part);
        }
    }
    data_encoding::HEXLOWER.encode(&h.finalize())
}

/// Whether `s` has the form of a [`fingerprint`].
pub fn is_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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
    fn empty_files_are_fine_and_errors_name_the_file() {
        let files = |list: &[(&str, &str)]| {
            list.iter()
                .map(|(n, t)| (n.to_string(), t.to_string()))
                .collect::<Vec<_>>()
        };
        let rules = parse(&files(&[
            ("a.toml", "# [[rule]]\n# label = \"x\"\n"),
            (
                "b.toml",
                "[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\n",
            ),
        ]))
        .unwrap();
        assert_eq!(rules.len(), 1);
        let e = parse(&files(&[("c.toml", "not toml")])).unwrap_err();
        assert!(format!("{e:#}").contains("c.toml"), "{e:#}");
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
    fn methods_are_validated() {
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\nmethods=[\"PUT\"]\n").is_ok());
        assert!(
            one("[[rule]]\nlabel=\"x\"\nweight=2\nmethods=[\"PUT\"]\ntarget_regex=\"a\"\n").is_ok()
        );
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\nmethods=[]\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\nmethods=[\"P T\"]\n").is_err());
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\nmethod_regex=\"P\"\n").is_err());
    }

    #[test]
    fn owasp_tags_are_validated() {
        assert!(
            one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"A03:2021\",\"OAT-014\"]\n").is_ok()
        );
        assert!(
            one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"A13:2021\"]\n")
                .is_err()
        );
        assert!(
            one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\nowasp=[\"T1190\"]\n")
                .is_err()
        );
        // Absent stays legal for operator rules.
        assert!(one("[[rule]]\nlabel=\"x\"\nweight=2\ntarget_regex=\"a\"\n").is_ok());
    }

    #[test]
    fn the_fingerprint_covers_names_and_texts_in_any_order() {
        let f = |files: &[(&str, &str)]| {
            fingerprint(
                &files
                    .iter()
                    .map(|(n, t)| (n.to_string(), t.to_string()))
                    .collect::<Vec<_>>(),
            )
        };
        let base = f(&[("a.toml", "x"), ("b.toml", "y")]);
        assert!(is_fingerprint(&base), "{base}");
        assert_eq!(base, f(&[("b.toml", "y"), ("a.toml", "x")]));
        for other in [
            f(&[("a.toml", "x"), ("b.toml", "z")]),
            f(&[("a.toml", "x"), ("c.toml", "y")]),
            f(&[("a.toml", "xb.toml"), ("", "y")]),
            f(&[("a.toml", "x")]),
        ] {
            assert_ne!(base, other);
        }
        assert!(!is_fingerprint("abc"));
        assert!(!is_fingerprint(&base.to_uppercase()));
    }

    /// The built-in rules are the `*.toml` files of `rules/` (not hidden
    /// ones), in name order, as they are on disk.
    #[test]
    fn builtin_rules_are_the_rules_directory() {
        let mut on_disk: Vec<RulesFile> = std::fs::read_dir("rules")
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter(|p| !p.file_name().unwrap().as_encoded_bytes().starts_with(b"."))
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        on_disk.sort();
        assert_eq!(builtin_files(), on_disk);
    }

    #[test]
    fn shipped_rules_load_and_validate() {
        let rules = parse(&builtin_files()).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn shipped_rules_all_carry_owasp_tags() {
        let rules = parse(&builtin_files()).unwrap();
        assert!(rules.len() >= 30, "rule-count sanity: {}", rules.len());
        for r in &rules {
            assert!(
                r.owasp.as_ref().is_some_and(|t| !t.is_empty()),
                "rule `{}` has no owasp tag",
                r.label
            );
        }
    }
}
