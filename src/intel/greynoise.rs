//! GreyNoise Community: whether an IP mass-scans the internet (`noise`) or
//! belongs to a known benign service (`riot`), and who it is.
use super::api::{Service, put};
use reqwest::StatusCode;
use serde_json::{Map, Value, json};

pub const BASE: &str = "https://api.greynoise.io/v3/community";

pub struct GreyNoise {
    pub base: String,
    /// None: unauthenticated (a much smaller daily allowance).
    pub key: Option<String>,
}

impl Service for GreyNoise {
    fn name(&self) -> &'static str {
        super::GREYNOISE
    }

    fn ipv6(&self) -> bool {
        false
    }

    fn request(&self, client: &reqwest::Client, ip: &str) -> reqwest::RequestBuilder {
        let r = client
            .get(format!("{}/{ip}", self.base))
            .header("Accept", "application/json");
        match &self.key {
            Some(k) => r.header("key", k),
            None => r,
        }
    }

    fn parse(&self, status: StatusCode, body: &[u8]) -> Option<Value> {
        let v: Value = serde_json::from_slice(body).ok()?;
        let h = v.as_object()?;
        if status == StatusCode::NOT_FOUND {
            // Not observed scanning, not in RIOT.
            return h
                .contains_key("noise")
                .then(|| json!({"noise": false, "riot": false}));
        }
        if !status.is_success() {
            return None;
        }
        let mut m = Map::new();
        put(&mut m, "noise", h.get("noise")?.clone());
        put(&mut m, "riot", h.get("riot")?.clone());
        for k in ["classification", "name", "last_seen"] {
            if let Some(x) = h.get(k).filter(|x| x.is_string()) {
                put(&mut m, k, x.clone());
            }
        }
        Some(Value::Object(m))
    }
}

/// Tags for the IP list: the classification, `noise`/`riot`, and the actor
/// or provider name.
pub fn tags(data: &Map<String, Value>) -> Vec<String> {
    let mut out = vec![];
    if let Some(c) = data.get("classification").and_then(|v| v.as_str()) {
        out.push(c.to_string());
    }
    for k in ["noise", "riot"] {
        if data.get(k).and_then(|v| v.as_bool()) == Some(true) {
            out.push(k.to_string());
        }
    }
    if let Some(n) = data
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|n| !n.eq_ignore_ascii_case("unknown"))
    {
        out.push(format!("name:{n}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> GreyNoise {
        GreyNoise {
            base: BASE.into(),
            key: None,
        }
    }

    #[test]
    fn a_noisy_ip() {
        let body = br#"{"ip":"198.51.100.7","noise":true,"riot":false,
            "classification":"malicious","name":"unknown",
            "link":"https://viz.greynoise.io/ip/198.51.100.7","last_seen":"2026-10-01",
            "message":"Success"}"#;
        let v = svc().parse(StatusCode::OK, body).unwrap();
        assert_eq!(v["classification"], "malicious");
        assert!(v.get("message").is_none() && v.get("link").is_none());
        assert_eq!(tags(v.as_object().unwrap()), ["malicious", "noise"]);
    }

    #[test]
    fn not_observed_is_a_result_and_limits_are_not() {
        let nf = br#"{"ip":"198.51.100.8","noise":false,"riot":false,
            "message":"IP not observed scanning the internet or contained in RIOT data set."}"#;
        assert_eq!(
            svc().parse(StatusCode::NOT_FOUND, nf),
            Some(json!({"noise": false, "riot": false}))
        );
        let other = br#"{"message":"Not Found"}"#;
        assert_eq!(svc().parse(StatusCode::NOT_FOUND, other), None);
    }
}
