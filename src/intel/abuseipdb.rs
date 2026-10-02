//! AbuseIPDB `check`: how often an IP was reported for abuse, and what for.
use super::api::{Service, put, strings};
use reqwest::StatusCode;
use serde_json::{Map, Value, json};

pub const BASE: &str = "https://api.abuseipdb.com/api/v2";

pub struct AbuseIpDb {
    pub base: String,
    pub key: String,
    /// Reports older than this many days are not counted.
    pub max_age_days: u32,
}

/// Report categories (https://www.abuseipdb.com/categories).
fn category(id: u64) -> Option<&'static str> {
    Some(match id {
        1 => "DNS Compromise",
        2 => "DNS Poisoning",
        3 => "Fraud Orders",
        4 => "DDoS Attack",
        5 => "FTP Brute-Force",
        6 => "Ping of Death",
        7 => "Phishing",
        8 => "Fraud VoIP",
        9 => "Open Proxy",
        10 => "Web Spam",
        11 => "Email Spam",
        12 => "Blog Spam",
        13 => "VPN IP",
        14 => "Port Scan",
        15 => "Hacking",
        16 => "SQL Injection",
        17 => "Spoofing",
        18 => "Brute-Force",
        19 => "Bad Web Bot",
        20 => "Exploited Host",
        21 => "Web App Attack",
        22 => "SSH",
        23 => "IoT Targeted",
        _ => return None,
    })
}

impl Service for AbuseIpDb {
    fn name(&self) -> &'static str {
        super::ABUSEIPDB
    }

    fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder {
        client
            .get(format!("{}/check", self.base))
            .query(&[
                ("ipAddress", ip),
                ("maxAgeInDays", &self.max_age_days.to_string()),
                // The reports, for their categories.
                ("verbose", ""),
            ])
            .header("Key", &self.key)
            .header("Accept", "application/json")
    }

    // Verbose answers list every report with its comment.
    fn max_body(&self) -> usize {
        16 << 20
    }

    fn parse(&self, status: StatusCode, body: &[u8]) -> Option<Value> {
        if !status.is_success() {
            return None;
        }
        let v: Value = serde_json::from_slice(body).ok()?;
        let d = v.get("data")?.as_object()?;
        let mut m = Map::new();
        put(&mut m, "score", d.get("abuseConfidenceScore")?.clone());
        for (from, to) in [
            ("totalReports", "reports"),
            ("numDistinctUsers", "reporters"),
            ("lastReportedAt", "last_reported_at"),
            ("usageType", "usage_type"),
            ("isp", "isp"),
            ("domain", "domain"),
            ("isWhitelisted", "whitelisted"),
            ("isTor", "tor"),
        ] {
            if let Some(x) = d.get(from) {
                put(&mut m, to, x.clone());
            }
        }
        put(&mut m, "hostnames", json!(strings(d.get("hostnames"), 20)));
        // Categories by how many reports name them, most first.
        let mut counts: Vec<(u64, u64)> = vec![];
        for r in d
            .get("reports")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            for c in r
                .get("categories")
                .and_then(|c| c.as_array())
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_u64())
            {
                match counts.iter_mut().find(|(id, _)| *id == c) {
                    Some((_, n)) => *n += 1,
                    None => counts.push((c, 1)),
                }
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let names: Vec<&str> = counts.iter().filter_map(|(c, _)| category(*c)).collect();
        put(&mut m, "categories", json!(names));
        Some(Value::Object(m))
    }
}

/// Tags for the IP list: the report categories and the usage type.
pub fn tags(data: &Map<String, Value>) -> Vec<String> {
    let mut out = strings(data.get("categories"), 32);
    if let Some(u) = data.get("usage_type").and_then(|v| v.as_str()) {
        out.push(format!("usage:{u}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> AbuseIpDb {
        AbuseIpDb {
            base: BASE.into(),
            key: "k".into(),
            max_age_days: 90,
        }
    }

    #[test]
    fn a_check_answer_becomes_a_compact_result() {
        let body = br#"{"data":{"ipAddress":"198.51.100.7","isPublic":true,"ipVersion":4,
            "isWhitelisted":false,"abuseConfidenceScore":87,"countryCode":"CN",
            "usageType":"Data Center/Web Hosting/Transit","isp":"Example Cloud",
            "domain":"example.net","hostnames":[],"isTor":false,"totalReports":41,
            "numDistinctUsers":12,"lastReportedAt":"2026-10-01T22:10:05+00:00",
            "reports":[{"categories":[18,22],"comment":"ssh"},{"categories":[22]},
                       {"categories":[14,999]}]}}"#;
        let v = svc().parse(StatusCode::OK, body).unwrap();
        assert_eq!(v["score"], 87);
        assert_eq!(v["reports"], 41);
        assert_eq!(v["reporters"], 12);
        assert_eq!(v["whitelisted"], false);
        assert_eq!(v["categories"], json!(["SSH", "Port Scan", "Brute-Force"]));
        assert!(v.get("hostnames").is_none(), "empty lists are left out");
        assert!(v.get("comment").is_none());
        let t = tags(v.as_object().unwrap());
        assert!(t.contains(&"SSH".to_string()));
        assert!(t.contains(&"usage:Data Center/Web Hosting/Transit".to_string()));
    }

    #[test]
    fn errors_and_garbage_are_no_result() {
        assert!(svc().parse(StatusCode::NOT_FOUND, b"{}").is_none());
        assert!(svc().parse(StatusCode::OK, b"<html>").is_none());
        assert!(svc().parse(StatusCode::OK, br#"{"data":{}}"#).is_none());
    }
}
