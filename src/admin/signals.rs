//! The signals strip above the provider cards: one verdict per provider,
//! read from the facts the cards already show (`public::intel_facts`).
use crate::admin::public::{IntelCard, IntelFact};

/// One pill: a short label, its value and how it reads.
pub struct Signal {
    pub label: &'static str,
    pub value: String,
    /// `ok`, `warn`, `bad` or `info`: the pill's colour.
    pub tone: &'static str,
    /// 0..=100: a small meter in the pill (the abuse score).
    pub meter: Option<u8>,
}

fn find<'a>(facts: &'a [IntelFact], label: &str) -> Option<&'a str> {
    facts
        .iter()
        .find(|f| f.label == label)
        .map(|f| f.value.as_str())
}

/// Items in a comma-separated fact.
fn count(list: &str) -> usize {
    list.split(',').filter(|s| !s.trim().is_empty()).count()
}

fn plural(n: usize, one: &str) -> String {
    format!("{n} {one}{}", if n == 1 { "" } else { "s" })
}

/// Signals from each card's newest result, in the cards' order. A provider
/// without a reading here (MaxMind is in the page head) adds nothing.
pub fn of<'a>(cards: impl IntoIterator<Item = &'a IntelCard>) -> Vec<Signal> {
    use crate::intel::{ABUSEIPDB, INTERNETDB, RDAP, SHODAN, TOR};
    let mut out = vec![];
    for c in cards {
        let Some(r) = &c.newest else { continue };
        let f = &r.facts[..];
        match c.name.as_str() {
            TOR => match find(f, "Exit node") {
                Some("listed") => out.push(sig("Tor exit", "listed", "bad")),
                Some("not listed") => out.push(sig("Tor exit", "no", "ok")),
                _ => {}
            },
            ABUSEIPDB => {
                if let Some(score) = find(f, "Abuse score")
                    .and_then(|s| s.split('/').next())
                    .and_then(|s| s.trim().parse::<u8>().ok())
                {
                    let tone = match score {
                        75.. => "bad",
                        25.. => "warn",
                        _ => "ok",
                    };
                    out.push(Signal {
                        meter: Some(score.min(100)),
                        ..sig("Abuse", &format!("{score}/100"), tone)
                    });
                }
            }
            SHODAN | INTERNETDB => {
                let label = if c.name == SHODAN {
                    "Shodan"
                } else {
                    "InternetDB"
                };
                match find(f, "Open ports") {
                    Some(p) => out.push(sig(label, &plural(count(p), "open port"), "info")),
                    None if find(f, "Result").is_some() => {
                        out.push(sig(label, "nothing known", "ok"))
                    }
                    None => {}
                }
                if let Some(v) = find(f, "CVEs") {
                    let n = v
                        .split_once(':')
                        .and_then(|(n, _)| n.parse().ok())
                        .unwrap_or_else(|| count(v));
                    out.push(sig("CVEs", &n.to_string(), "bad"));
                }
            }
            RDAP => {
                let holder: Vec<&str> =
                    ["Name", "Type"].iter().filter_map(|l| find(f, l)).collect();
                if !holder.is_empty() {
                    out.push(sig("Registry", &holder.join(" · "), "info"));
                }
                if find(f, "Fresh block") == Some("yes") {
                    out.push(sig("Block", "new, under 90 days", "warn"));
                }
            }
            _ => {}
        }
    }
    out
}

fn sig(label: &'static str, value: &str, tone: &'static str) -> Signal {
    Signal {
        label,
        value: value.to_string(),
        tone,
        meter: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::public::IntelResult;

    fn card(name: &str, facts: &[(&str, &str)]) -> IntelCard {
        IntelCard {
            label: "L",
            name: name.into(),
            newest: Some(IntelResult {
                facts: facts
                    .iter()
                    .map(|(l, v)| IntelFact {
                        label: l.to_string(),
                        value: v.to_string(),
                        mono: false,
                    })
                    .collect(),
                fetched_at: String::new(),
                source_version: None,
                node: None,
            }),
            others: vec![],
        }
    }

    fn shown(s: &[Signal]) -> Vec<String> {
        s.iter()
            .map(|s| format!("{}={} {}", s.label, s.value, s.tone))
            .collect()
    }

    #[test]
    fn verdicts_per_provider() {
        let cards = [
            card("tor-exits", &[("Exit node", "not listed")]),
            card("maxmind-geolite2", &[("Country", "DE")]),
            card("abuseipdb", &[("Abuse score", "87 / 100")]),
            card("shodan", &[("Result", "nothing known about this address")]),
            card(
                "shodan-internetdb",
                &[("Open ports", "22, 80, 443"), ("CVEs", "2: CVE-1, CVE-2")],
            ),
            card(
                "rdap",
                &[
                    ("Name", "MSFT"),
                    ("Type", "DIRECT ALLOCATION"),
                    ("Fresh block", "yes"),
                ],
            ),
        ];
        let s = of(&cards);
        assert_eq!(
            shown(&s),
            [
                "Tor exit=no ok",
                "Abuse=87/100 bad",
                "Shodan=nothing known ok",
                "InternetDB=3 open ports info",
                "CVEs=2 bad",
                "Registry=MSFT · DIRECT ALLOCATION info",
                "Block=new, under 90 days warn",
            ]
        );
        assert_eq!(s[1].meter, Some(87));
    }

    #[test]
    fn low_scores_and_missing_results() {
        let mut empty = card("tor-exits", &[]);
        empty.newest = None;
        let s = of(&[
            empty,
            card("abuseipdb", &[("Abuse score", "0 / 100")]),
            card("tor-exits", &[("Exit node", "listed")]),
            card("unknown-provider", &[("x", "y")]),
        ]);
        assert_eq!(shown(&s), ["Abuse=0/100 ok", "Tor exit=listed bad"]);
    }
}
