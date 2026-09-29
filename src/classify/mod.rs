pub mod rules;

use anyhow::Result;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug)]
pub struct RequestView<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: Vec<(String, String)>,
    pub body: Option<&'a [u8]>,
}

#[derive(Debug, Default, Clone)]
pub struct IpHistory {
    pub distinct_paths_1h: u32,
    pub requests_1h: u32,
    pub last_scan_level: u8,
}

#[derive(Debug, Default, Clone)]
pub struct BotTells {
    pub webdriver: bool,
    pub inhuman_fill: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    pub severity: u8,
    pub scan_level: u8,
    pub labels: Vec<String>,
}

struct CompiledRule {
    label: String,
    weight: u8,
    target: Option<Regex>,
    body: Option<Regex>,
    ua: Option<Regex>,
    path_exact: Option<String>,
}

pub struct Classifier {
    rules: Vec<CompiledRule>,
}

impl Classifier {
    pub fn from_dir(dir: &Path) -> Result<Self> {
        let rules = rules::load_dir(dir)?
            .into_iter()
            .map(|r| {
                Ok(CompiledRule {
                    label: r.label,
                    weight: r.weight,
                    target: r.target_regex.as_deref().map(compile_ci).transpose()?,
                    body: r.body_regex.as_deref().map(compile_ci).transpose()?,
                    ua: r.ua_regex.as_deref().map(compile_ci).transpose()?,
                    path_exact: r.path_exact,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }

    pub fn classify(&self, req: &RequestView, hist: &IpHistory, bot: &BotTells) -> Verdict {
        let mut labels: Vec<String> = vec![];
        let mut weight: u8 = 0;

        let target = match req.query {
            Some(q) => format!("{}?{}", req.path, q),
            None => req.path.to_string(),
        };
        let ua = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        let body = req
            .body
            .map(|b| String::from_utf8_lossy(b))
            .unwrap_or_default();

        for r in &self.rules {
            let hit = r.path_exact.as_deref() == Some(req.path)
                || r.target.as_ref().is_some_and(|re| re.is_match(&target))
                || r.body
                    .as_ref()
                    .is_some_and(|re| !body.is_empty() && re.is_match(&body))
                || r.ua.as_ref().is_some_and(|re| re.is_match(ua));
            if hit {
                labels.push(r.label.clone());
                weight = weight.max(r.weight);
            }
        }

        // Behavioral ladder (spec §6).
        if hist.distinct_paths_1h >= 10 || hist.requests_1h >= 20 {
            labels.push("path-scanner".into());
            weight = weight.max(2);
        } else if labels.is_empty() {
            labels.push("probe".into());
            weight = weight.max(1);
        }
        if req.method == "POST" {
            labels.push("form-interaction".into());
            weight = weight.max(3);
        }
        if bot.webdriver {
            labels.push("automation".into());
            weight = weight.max(2);
        }
        if bot.inhuman_fill {
            labels.push("inhuman-behavior".into());
            weight = weight.max(3);
        }

        labels.sort();
        labels.dedup();
        let scan_level = weight.min(4);
        Verdict {
            severity: weight,
            scan_level,
            labels,
        }
    }
}

fn compile_ci(pattern: &str) -> Result<Regex> {
    static WRAP: OnceLock<()> = OnceLock::new();
    let _ = WRAP; // keeps import trivial; case-insensitivity via inline flag
    Ok(Regex::new(&format!("(?i){pattern}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::from_dir(std::path::Path::new("rules")).unwrap()
    }
    fn view<'a>(
        method: &'a str,
        path: &'a str,
        query: Option<&'a str>,
        ua: &'a str,
        body: Option<&'a [u8]>,
    ) -> RequestView<'a> {
        RequestView {
            method,
            path,
            query,
            headers: vec![("user-agent".into(), ua.into())],
            body,
        }
    }
    fn hist(paths: u32, reqs: u32) -> IpHistory {
        IpHistory {
            distinct_paths_1h: paths,
            requests_1h: reqs,
            last_scan_level: 0,
        }
    }

    #[test]
    fn single_plain_probe_is_level_1() {
        let v = classifier().classify(
            &view("GET", "/nonexistent", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 1);
        assert!(v.labels.contains(&"probe".to_string()));
    }

    #[test]
    fn repeated_scanning_is_level_2() {
        let v = classifier().classify(
            &view("GET", "/a", None, "Mozilla/5.0", None),
            &hist(15, 20),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 2);
        assert!(v.labels.contains(&"path-scanner".to_string()));
    }

    #[test]
    fn scanner_user_agent_is_level_2() {
        let v = classifier().classify(
            &view("GET", "/", None, "sqlmap/1.7.11", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 2);
        assert!(v.labels.contains(&"scanner-ua".to_string()));
    }

    #[test]
    fn sqli_in_query_is_level_4() {
        let v = classifier().classify(
            &view(
                "GET",
                "/login",
                Some("user=admin'%20OR%20'1'='1"),
                "Mozilla/5.0",
                None,
            ),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert_eq!(v.scan_level, 4);
        assert!(v.labels.iter().any(|l| l == "sqli"));
    }

    #[test]
    fn bait_form_post_is_at_least_level_3() {
        let v = classifier().classify(
            &view(
                "POST",
                "/login",
                None,
                "Mozilla/5.0",
                Some(b"username=a&password=b"),
            ),
            &hist(2, 3),
            &BotTells::default(),
        );
        assert!(v.scan_level >= 3);
        assert!(v.labels.contains(&"form-interaction".to_string()));
    }

    #[test]
    fn sensitive_path_label() {
        let v = classifier().classify(
            &view("GET", "/.env", None, "curl/8.0", None),
            &hist(1, 1),
            &BotTells::default(),
        );
        assert!(v.labels.contains(&"sensitive-path".to_string()));
        assert!(v.scan_level >= 2);
    }

    #[test]
    fn webdriver_escalates() {
        let bot = BotTells {
            webdriver: true,
            inhuman_fill: false,
        };
        let v = classifier().classify(
            &view("GET", "/x", None, "Mozilla/5.0", None),
            &hist(1, 1),
            &bot,
        );
        assert!(v.scan_level >= 2);
        assert!(v.labels.contains(&"automation".to_string()));
    }
}
