//! Shared template context. Every page struct carries a `Chrome`.
use crate::admin::assets::{STAMP, VERSION};

pub struct Chrome {
    pub authed: bool,
    /// Which nav item is current: "wall" | "ips" | "requests" | "admin" | "".
    pub active: &'static str,
    pub stamp: &'static str,
    pub version: &'static str,
}

impl Chrome {
    pub fn new(authed: bool, active: &'static str) -> Self {
        Self {
            authed,
            active,
            stamp: STAMP,
            version: VERSION,
        }
    }
}

/// Anything a template may hand us as a severity (or another integer):
/// `i64` or any depth of reference to one (askama binds loop variables and `{% let %}` by reference).
pub trait SevValue {
    fn sev(&self) -> i64;
}
impl SevValue for i64 {
    fn sev(&self) -> i64 {
        *self
    }
}
impl<T: SevValue + ?Sized> SevValue for &T {
    fn sev(&self) -> i64 {
        (**self).sev()
    }
}

/// CSS class for a severity 0..4 (clamped).
pub fn sev_class<S: SevValue>(sev: S) -> String {
    format!("sev sev-{}", sev.sev().clamp(0, 4))
}

/// CSS modifier class colouring a label by family
/// ([`crate::classify::label_family`]); a label of no known family keeps
/// the neutral `.badge-label` accent.
pub fn label_class<S: AsRef<str>>(label: S) -> &'static str {
    family_class(crate::classify::label_family(label.as_ref()))
}

/// CSS modifier class of a label family; "" for "other".
pub fn family_class<S: AsRef<str>>(family: S) -> &'static str {
    match family.as_ref() {
        "recon" => "badge-cat-recon",
        "inject" => "badge-cat-inject",
        "impact" => "badge-cat-impact",
        "interact" => "badge-cat-interact",
        "postex" => "badge-cat-postex",
        "bot" => "badge-cat-bot",
        _ => "",
    }
}

/// Human name of a label family.
pub fn family_name<S: AsRef<str>>(family: S) -> &'static str {
    match family.as_ref() {
        "recon" => "Reconnaissance",
        "inject" => "Injection",
        "impact" => "Impact",
        "interact" => "Interaction",
        "postex" => "Post-exploitation",
        "bot" => "Automation",
        _ => "Other",
    }
}

/// A UTC point in time as stored: SQLite text (`YYYY-MM-DD HH:MM:SS`) or a
/// decoded `DateTime<Utc>`, or any reference to either.
pub trait Stamp {
    fn utc(&self) -> Option<chrono::NaiveDateTime>;
}
impl Stamp for str {
    fn utc(&self) -> Option<chrono::NaiveDateTime> {
        chrono::NaiveDateTime::parse_from_str(self, "%Y-%m-%d %H:%M:%S").ok()
    }
}
impl Stamp for String {
    fn utc(&self) -> Option<chrono::NaiveDateTime> {
        self.as_str().utc()
    }
}
impl Stamp for chrono::DateTime<chrono::Utc> {
    fn utc(&self) -> Option<chrono::NaiveDateTime> {
        Some(self.naive_utc())
    }
}
impl<T: Stamp + ?Sized> Stamp for &T {
    fn utc(&self) -> Option<chrono::NaiveDateTime> {
        (**self).utc()
    }
}

/// `YYYY-MM-DD HH:MM:SS` (UTC), the form `<time datetime>` carries for
/// the page script; "" when unparsable.
pub fn stamp<S: Stamp>(ts: S) -> String {
    ts.utc()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// "3 s", "5 min", "2 h", "4 d" since a UTC timestamp, for compact "ago"
/// columns; "" when unparsable. The page script keeps these current; this
/// is the no-script value.
pub fn ago<S: Stamp>(ts: S) -> String {
    let Some(t) = ts.utc() else {
        return String::new();
    };
    let s = (chrono::Utc::now().naive_utc() - t).num_seconds().max(0);
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", s / 60),
        3600..86400 => format!("{} h", s / 3600),
        _ => format!("{} d", s / 86400),
    }
}

/// Change against a previous value as "+23%" / "−5%" and a direction
/// ("up" | "down" | "flat"); `None` without a previous value to compare.
pub fn delta(cur: i64, prev: Option<i64>) -> Option<(String, &'static str)> {
    let prev = prev?;
    if prev == 0 {
        return (cur > 0).then(|| ("new".to_string(), "up"));
    }
    let pct = ((cur - prev) as f64 / prev as f64 * 100.0).round() as i64;
    Some(match pct {
        0 => ("±0%".to_string(), "flat"),
        p if p > 0 => (format!("+{p}%"), "up"),
        p => (format!("−{}%", -p), "down"),
    })
}

/// Thousands separators: 12345 → "12,345".
pub fn thousands<N: std::fmt::Display>(n: N) -> String {
    let s = n.to_string();
    let (sign, digits) = s.strip_prefix('-').map_or(("", s.as_str()), |d| ("-", d));
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    format!("{sign}{out}")
}

/// Bar width in percent of `max`, at least 1 for a non-zero value. Takes
/// any integer a template hands over (see [`SevValue`]).
pub fn pct<V: SevValue, M: SevValue>(v: V, max: M) -> i64 {
    let (v, max) = (v.sev(), max.sev());
    if max <= 0 || v <= 0 {
        return 0;
    }
    ((v as f64 / max as f64) * 100.0).round().clamp(1.0, 100.0) as i64
}

/// Human name of an OWASP tag, for badge tooltips; "" for unknown tags.
pub fn owasp_name<S: AsRef<str>>(tag: S) -> &'static str {
    match tag.as_ref() {
        "A01:2021" => "Broken Access Control",
        "A02:2021" => "Cryptographic Failures",
        "A03:2021" => "Injection",
        "A04:2021" => "Insecure Design",
        "A05:2021" => "Security Misconfiguration",
        "A06:2021" => "Vulnerable and Outdated Components",
        "A07:2021" => "Identification and Authentication Failures",
        "A08:2021" => "Software and Data Integrity Failures",
        "A09:2021" => "Security Logging and Monitoring Failures",
        "A10:2021" => "Server-Side Request Forgery",
        "OAT-001" => "Carding",
        "OAT-002" => "Token Cracking",
        "OAT-003" => "Ad Fraud",
        "OAT-004" => "Fingerprinting",
        "OAT-005" => "Scalping",
        "OAT-006" => "Expediting",
        "OAT-007" => "Account Cracking",
        "OAT-008" => "Credential Stuffing",
        "OAT-009" => "CAPTCHA Bypass",
        "OAT-010" => "Card Cracking",
        "OAT-011" => "Scraping",
        "OAT-012" => "Cashing Out",
        "OAT-013" => "Sniping",
        "OAT-014" => "Vulnerability Scanning",
        "OAT-015" => "Denial of Service",
        "OAT-016" => "Skewing",
        "OAT-017" => "Spam",
        "OAT-018" => "Footprinting",
        "OAT-019" => "Account Creation",
        "OAT-020" => "Account Aggregation",
        "OAT-021" => "Denial of Inventory",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_families_map_to_their_colour_class() {
        assert_eq!(label_class("sqli"), "badge-cat-inject");
        assert_eq!(label_class("xss"), "badge-cat-inject");
        assert_eq!(label_class("rce"), "badge-cat-impact");
        assert_eq!(label_class("ssrf"), "badge-cat-impact");
        assert_eq!(label_class("form-interaction"), "badge-cat-interact");
        assert_eq!(label_class("credential-attack"), "badge-cat-interact");
        assert_eq!(label_class("webshell"), "badge-cat-postex");
        assert_eq!(label_class("mcp-abuse"), "badge-cat-postex");
        assert_eq!(label_class("automation"), "badge-cat-bot");
        // An explicit entry beats the suffix rule.
        assert_eq!(label_class("proxy-probe"), "badge-cat-bot");
        // The suffix rule covers every probe family, including future ones.
        assert_eq!(label_class("appliance-probe"), "badge-cat-recon");
        assert_eq!(label_class("some-future-probe"), "badge-cat-recon");
        // Everything else keeps the neutral accent.
        assert_eq!(label_class("fp-claim"), "");
        assert_eq!(label_class("path-scanner"), "");
    }

    #[test]
    fn deltas_and_thousands() {
        assert_eq!(delta(123, Some(100)), Some(("+23%".into(), "up")));
        assert_eq!(delta(95, Some(100)), Some(("−5%".into(), "down")));
        assert_eq!(delta(100, Some(100)), Some(("±0%".into(), "flat")));
        assert_eq!(delta(4, Some(0)), Some(("new".into(), "up")));
        assert_eq!(delta(4, None), None);
        assert_eq!(thousands(1234567), "1,234,567");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(-1000), "-1,000");
        // Templates hand over references, at any depth.
        let (ten, one) = (10i64, 1i64);
        let (r, rr) = (&ten, &&one);
        assert_eq!(pct(5, r), 50);
        assert_eq!(pct(rr, 1000), 1);
        assert_eq!(pct(0, 10), 0);
    }

    #[test]
    fn owasp_tags_have_names() {
        assert_eq!(owasp_name("A03:2021"), "Injection");
        assert_eq!(owasp_name("A10:2021"), "Server-Side Request Forgery");
        assert_eq!(owasp_name("OAT-014"), "Vulnerability Scanning");
        assert_eq!(owasp_name("OAT-018"), "Footprinting");
        assert_eq!(owasp_name("bogus"), "");
    }
}
