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

/// Anything a template may hand us as a severity: `i64` or any depth of
/// reference to one (askama binds loop variables and `{% let %}` by reference).
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

/// CSS modifier class colouring a label by family. The explicit map comes
/// first; then the suffix rule makes every other `-probe` family — including
/// ones added later — recon blue without touching code; anything unknown
/// keeps the neutral `.badge-label` accent.
pub fn label_class<S: AsRef<str>>(label: S) -> &'static str {
    let l = label.as_ref();
    match l {
        "sqli" | "xss" | "ssti" | "nosqli" | "xxe" | "crlf-injection" => "badge-cat-inject",
        "rce" | "deserialization" | "ssrf" | "path-traversal" => "badge-cat-impact",
        "form-interaction" | "write-method" | "credential-attack" => "badge-cat-interact",
        "webshell" | "mcp-abuse" => "badge-cat-postex",
        "automation" | "inhuman-behavior" | "proxy-probe" | "unusual-method" => "badge-cat-bot",
        _ if l.ends_with("-probe") => "badge-cat-recon",
        _ => "",
    }
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
    fn owasp_tags_have_names() {
        assert_eq!(owasp_name("A03:2021"), "Injection");
        assert_eq!(owasp_name("A10:2021"), "Server-Side Request Forgery");
        assert_eq!(owasp_name("OAT-014"), "Vulnerability Scanning");
        assert_eq!(owasp_name("OAT-018"), "Footprinting");
        assert_eq!(owasp_name("bogus"), "");
    }
}
