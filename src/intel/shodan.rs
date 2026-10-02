//! Shodan: the host API (needs a key with host lookups, e.g. a membership)
//! and InternetDB (no key, weekly data, IPv4 only, non-commercial use).
use super::api::{Service, put, strings};
use reqwest::StatusCode;
use serde_json::{Map, Value, json};

pub const HOST_BASE: &str = "https://api.shodan.io";
pub const INTERNETDB_BASE: &str = "https://internetdb.shodan.io";

/// Services kept per host; banners are never kept.
const MAX_SERVICES: usize = 64;
const MAX_VULNS: usize = 100;
const MAX_NAMES: usize = 20;

pub struct ShodanHost {
    pub base: String,
    pub key: String,
}

impl Service for ShodanHost {
    fn name(&self) -> &'static str {
        super::SHODAN
    }

    fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder {
        client
            .get(format!("{}/shodan/host/{ip}", self.base))
            .query(&[("key", self.key.as_str())])
    }

    // Full host answers carry every banner.
    fn max_body(&self) -> usize {
        16 << 20
    }

    fn parse(&self, status: StatusCode, body: &[u8]) -> Option<Value> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let h = v.as_object()?;
        if status == StatusCode::NOT_FOUND {
            // "No information available for that IP."
            return Some(json!({}));
        }
        if !status.is_success() || h.contains_key("error") {
            return None;
        }
        let mut m = Map::new();
        let mut ports: Vec<u64> = h
            .get("ports")
            .and_then(|p| p.as_array())
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_u64())
            .collect();
        ports.sort_unstable();
        ports.dedup();
        put(&mut m, "ports", json!(ports));
        let services: Vec<Value> = h
            .get("data")
            .and_then(|d| d.as_array())
            .into_iter()
            .flatten()
            .filter_map(|s| {
                let mut o = Map::new();
                o.insert("port".into(), s.get("port")?.clone());
                for k in ["transport", "product", "version"] {
                    if let Some(x) = s.get(k).filter(|x| x.is_string()) {
                        put(&mut o, k, x.clone());
                    }
                }
                if let Some(x) = s.pointer("/_shodan/module").filter(|x| x.is_string()) {
                    put(&mut o, "module", x.clone());
                }
                Some(Value::Object(o))
            })
            .take(MAX_SERVICES)
            .collect();
        put(&mut m, "services", json!(services));
        for k in ["os", "org", "isp", "asn", "last_update"] {
            if let Some(x) = h.get(k).filter(|x| x.is_string()) {
                put(&mut m, k, x.clone());
            }
        }
        put(
            &mut m,
            "hostnames",
            json!(strings(h.get("hostnames"), MAX_NAMES)),
        );
        put(
            &mut m,
            "domains",
            json!(strings(h.get("domains"), MAX_NAMES)),
        );
        put(&mut m, "tags", json!(strings(h.get("tags"), MAX_NAMES)));
        put(&mut m, "vulns", json!(vulns(h.get("vulns"))));
        Some(Value::Object(m))
    }
}

/// CVE ids, sorted; Shodan sends a list (or, in older answers, an object
/// keyed by id).
fn vulns(v: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = match v {
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        other => strings(other, usize::MAX),
    };
    out.sort();
    out.dedup();
    out.truncate(MAX_VULNS);
    out
}

pub struct InternetDb {
    pub base: String,
}

impl Service for InternetDb {
    fn name(&self) -> &'static str {
        super::INTERNETDB
    }

    fn ipv6(&self) -> bool {
        false
    }

    fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder {
        client.get(format!("{}/{ip}", self.base))
    }

    fn parse(&self, status: StatusCode, body: &[u8]) -> Option<Value> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let h = v.as_object()?;
        if status == StatusCode::NOT_FOUND {
            return Some(json!({}));
        }
        if !status.is_success() || !h.contains_key("ports") {
            return None;
        }
        let mut m = Map::new();
        let mut ports: Vec<u64> = h
            .get("ports")
            .and_then(|p| p.as_array())
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_u64())
            .collect();
        ports.sort_unstable();
        put(&mut m, "ports", json!(ports));
        put(&mut m, "cpes", json!(strings(h.get("cpes"), MAX_SERVICES)));
        put(
            &mut m,
            "hostnames",
            json!(strings(h.get("hostnames"), MAX_NAMES)),
        );
        put(&mut m, "tags", json!(strings(h.get("tags"), MAX_NAMES)));
        put(&mut m, "vulns", json!(vulns(h.get("vulns"))));
        Some(Value::Object(m))
    }
}

/// Tags for the IP list: Shodan's own tags (`vpn`, `cloud`, `self-signed`, …).
pub fn tags(data: &Map<String, Value>) -> Vec<String> {
    strings(data.get("tags"), MAX_NAMES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_answer_keeps_services_but_no_banners() {
        let s = ShodanHost {
            base: HOST_BASE.into(),
            key: "k".into(),
        };
        let body = br#"{"ip_str":"198.51.100.7","ports":[443,22,22],"os":null,
            "org":"Example Cloud","isp":"Example","asn":"AS64500",
            "hostnames":["a.example.net"],"domains":["example.net"],"tags":["cloud"],
            "vulns":["CVE-2023-48795","CVE-2021-1234"],"last_update":"2026-09-30T01:02:03.456",
            "data":[{"port":22,"transport":"tcp","product":"OpenSSH","version":"8.9p1",
                     "data":"SSH-2.0-OpenSSH_8.9p1 ...banner...","_shodan":{"module":"ssh"}},
                    {"port":443,"transport":"tcp","http":{"html":"<html>..."}}]}"#;
        let v = s.parse(StatusCode::OK, body).unwrap();
        assert_eq!(v["ports"], json!([22, 443]));
        assert_eq!(v["services"][0]["product"], "OpenSSH");
        assert_eq!(v["services"][0]["module"], "ssh");
        assert_eq!(v["services"][1], json!({"port": 443, "transport": "tcp"}));
        assert_eq!(v["vulns"], json!(["CVE-2021-1234", "CVE-2023-48795"]));
        assert!(v.get("os").is_none());
        assert!(!v.to_string().contains("banner"));
        assert_eq!(tags(v.as_object().unwrap()), ["cloud"]);
    }

    #[test]
    fn not_found_is_nothing_known() {
        let s = ShodanHost {
            base: HOST_BASE.into(),
            key: "k".into(),
        };
        let nf = br#"{"error":"No information available for that IP."}"#;
        assert_eq!(s.parse(StatusCode::NOT_FOUND, nf), Some(json!({})));
        assert_eq!(s.parse(StatusCode::OK, nf), None);
        let i = InternetDb {
            base: INTERNETDB_BASE.into(),
        };
        let nf = br#"{"detail":"No information available"}"#;
        assert_eq!(i.parse(StatusCode::NOT_FOUND, nf), Some(json!({})));
    }

    #[test]
    fn an_internetdb_answer() {
        let i = InternetDb {
            base: INTERNETDB_BASE.into(),
        };
        let body = br#"{"cpes":["cpe:/a:openbsd:openssh:8.9p1"],"hostnames":[],"ip":"198.51.100.7",
            "ports":[80,22],"tags":["vpn"],"vulns":["CVE-2023-48795"]}"#;
        let v = i.parse(StatusCode::OK, body).unwrap();
        assert_eq!(v["ports"], json!([22, 80]));
        assert_eq!(v["tags"], json!(["vpn"]));
        assert!(v.get("hostnames").is_none());
        assert!(!i.ipv6());
    }
}
