//! `[trap]`: how the trap listener records and answers.
use anyhow::bail;
use serde::Deserialize;

/// Most connections the tarpit may hold (`tarpit_pool`).
const MAX_TARPIT_POOL: usize = 16 * 1024;
/// Longest hold (`tarpit_hold_secs`): a day.
const MAX_TARPIT_HOLD_SECS: u64 = 24 * 3600;
/// Most bytes per drip (`tarpit_drip_bytes`).
const MAX_TARPIT_DRIP_BYTES: usize = 4096;

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
    /// Connections held at once in the tarpit: the slow answer for sources
    /// whose requests reached severity 4. Past it they get the normal
    /// answer. 0 turns the tarpit off.
    #[serde(default = "default_tarpit_pool")]
    pub tarpit_pool: usize,
    /// Of those, at most this many from one source (IPv6 by /64).
    #[serde(default = "default_tarpit_per_source")]
    pub tarpit_per_source: usize,
    /// Longest a tarpitted connection is held, in seconds.
    #[serde(default = "default_tarpit_hold_secs")]
    pub tarpit_hold_secs: u64,
    /// Bytes sent per drip.
    #[serde(default = "default_tarpit_drip_bytes")]
    pub tarpit_drip_bytes: usize,
    /// Seconds between drips; shorter than the hold.
    #[serde(default = "default_tarpit_drip_every_secs")]
    pub tarpit_drip_every_secs: u64,
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
fn default_tarpit_pool() -> usize {
    256
}
fn default_tarpit_per_source() -> usize {
    8
}
fn default_tarpit_hold_secs() -> u64 {
    600
}
fn default_tarpit_drip_bytes() -> usize {
    1
}
fn default_tarpit_drip_every_secs() -> u64 {
    10
}

impl Default for TrapConfig {
    fn default() -> Self {
        Self {
            record_rate: default_record_rate(),
            record_burst: default_record_burst(),
            sample_every: default_sample_every(),
            skip_log_rate: default_skip_log_rate(),
            helper_prefix: String::new(),
            tarpit_pool: default_tarpit_pool(),
            tarpit_per_source: default_tarpit_per_source(),
            tarpit_hold_secs: default_tarpit_hold_secs(),
            tarpit_drip_bytes: default_tarpit_drip_bytes(),
            tarpit_drip_every_secs: default_tarpit_drip_every_secs(),
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
        if self.tarpit_pool > MAX_TARPIT_POOL {
            bail!("trap.tarpit_pool must be at most {MAX_TARPIT_POOL}");
        }
        if self.tarpit_pool > 0 {
            if self.tarpit_per_source == 0 {
                bail!("trap.tarpit_per_source must be at least 1");
            }
            if !(1..=MAX_TARPIT_HOLD_SECS).contains(&self.tarpit_hold_secs) {
                bail!("trap.tarpit_hold_secs must be 1..={MAX_TARPIT_HOLD_SECS}");
            }
            if !(1..=MAX_TARPIT_DRIP_BYTES).contains(&self.tarpit_drip_bytes) {
                bail!("trap.tarpit_drip_bytes must be 1..={MAX_TARPIT_DRIP_BYTES}");
            }
            if self.tarpit_drip_every_secs == 0
                || self.tarpit_drip_every_secs >= self.tarpit_hold_secs
            {
                bail!("trap.tarpit_drip_every_secs must be at least 1 and below tarpit_hold_secs");
            }
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

    #[test]
    fn tarpit_defaults_and_validation() {
        let c = parse("").unwrap();
        assert_eq!(c.tarpit_pool, 256);
        assert_eq!(c.tarpit_per_source, 8);
        assert_eq!(c.tarpit_hold_secs, 600);
        assert_eq!(c.tarpit_drip_bytes, 1);
        assert_eq!(c.tarpit_drip_every_secs, 10);
        assert!(parse("tarpit_pool = 0").is_ok(), "0 turns it off");
        assert!(parse("tarpit_pool = 100000").is_err());
        assert!(parse("tarpit_per_source = 0").is_err());
        assert!(parse("tarpit_hold_secs = 0").is_err());
        assert!(parse("tarpit_hold_secs = 100000").is_err());
        assert!(parse("tarpit_drip_bytes = 0").is_err());
        assert!(parse("tarpit_drip_bytes = 100000").is_err());
        assert!(parse("tarpit_drip_every_secs = 0").is_err());
        assert!(parse("tarpit_hold_secs = 10\ntarpit_drip_every_secs = 10").is_err());
        assert!(parse("tarpit_hold_secs = 11\ntarpit_drip_every_secs = 10").is_ok());
        // Off: the rest is not checked.
        assert!(parse("tarpit_pool = 0\ntarpit_drip_bytes = 0").is_ok());
    }
}
