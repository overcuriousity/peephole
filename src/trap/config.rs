//! `[trap]`: how the trap listener records and answers.
use anyhow::bail;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct TrapConfig {
    /// Requests per second one IP may have recorded in full, sustained.
    /// Beyond it requests are still answered, but only sampled (see
    /// `sample_every`). 0 turns the limit off.
    #[serde(default = "default_record_rate")]
    pub record_rate: f64,
    /// Requests one IP may have recorded in a burst before `record_rate`
    /// applies.
    #[serde(default = "default_record_burst")]
    pub record_burst: u32,
    /// Over the limit, record one request in this many. The recorded one
    /// carries the number of requests left out before it (`unrecorded`).
    /// 0: record none over the limit (the count goes on the next recorded
    /// request).
    #[serde(default = "default_sample_every")]
    pub sample_every: u32,
    /// Requests not recorded in full still leave a light row (time,
    /// method, path): at most this many per IP and second; past it they are
    /// only counted. 0: no limit.
    #[serde(default = "default_skip_log_rate")]
    pub skip_log_rate: u32,
    /// Path prefix of the trap page's helper endpoints (`/claim`,
    /// `/collect`, `/panel`, `/collect.js`), e.g. `/_a7f3`. Empty: at the
    /// root. A prefix of your own makes the trap harder to fingerprint.
    #[serde(default)]
    pub helper_prefix: String,
}

fn default_record_rate() -> f64 {
    10.0
}
fn default_record_burst() -> u32 {
    100
}
fn default_sample_every() -> u32 {
    20
}
fn default_skip_log_rate() -> u32 {
    100
}

impl Default for TrapConfig {
    fn default() -> Self {
        Self {
            record_rate: default_record_rate(),
            record_burst: default_record_burst(),
            sample_every: default_sample_every(),
            skip_log_rate: default_skip_log_rate(),
            helper_prefix: String::new(),
        }
    }
}

impl TrapConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.record_rate.is_finite() || self.record_rate < 0.0 {
            bail!("trap.record_rate must be a finite number >= 0");
        }
        if self.record_rate > 0.0 && self.record_burst == 0 {
            bail!("trap.record_burst must be at least 1");
        }
        let p = &self.helper_prefix;
        // Rendered into the trap page's HTML and JS: path characters only.
        let ok_char = |c: char| c.is_ascii_alphanumeric() || "-._~/".contains(c);
        if !p.is_empty()
            && (!p.starts_with('/')
                || p.ends_with('/')
                || !p.chars().all(ok_char)
                || p[1..]
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == ".."))
        {
            bail!(
                "trap.helper_prefix must be empty or a path like \"/_a7f3\" \
                 (leading /, no trailing /, letters, digits, - . _ ~)"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> anyhow::Result<TrapConfig> {
        let c: TrapConfig = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn defaults_and_validation() {
        let c = parse("").unwrap();
        assert_eq!(c.record_rate, 10.0);
        assert_eq!(c.record_burst, 100);
        assert_eq!(c.sample_every, 20);
        assert_eq!(c.helper_prefix, "");
        assert!(parse("record_rate = 0").is_ok());
        assert!(parse("record_rate = -1").is_err());
        assert!(parse("record_burst = 0").is_err());
        assert!(parse("record_rate = 0\nrecord_burst = 0").is_ok());
        assert!(parse("helper_prefix = \"/_a7f3\"").is_ok());
        assert!(parse("helper_prefix = \"/a/b-c.d~e_f\"").is_ok());
        for bad in [
            "a", "/a/", "//a", "/..", "/a/./b", "/a\\\"b", "/a<b", "/a b", "/a?b",
        ] {
            assert!(
                parse(&format!("helper_prefix = \"{bad}\"")).is_err(),
                "{bad}"
            );
        }
    }
}
