//! Precision gate for the `ai-agent-*` rules (MIK-565): reclassifies the
//! last 30 days of a real database's `requests` with the built-in rules and
//! prints one TSV line per agent-label hit, for a human to review. Every
//! false positive found becomes a negative test in `src/classify/mod.rs`.
//!
//! Ignored, and skipped unless `PEEPHOLE_GATE_DB` names the database. It is
//! opened `mode=ro`; nothing is written.
//!
//! ```text
//! PEEPHOLE_GATE_DB=/path/to/peephole.db cargo test --test agent_rules_gate -- --ignored --nocapture
//! ```
use peephole::classify::stored::{STORED_COLUMNS, StoredRequest};
use peephole::classify::{Classifier, IpHistory, rules};
use regex::Regex;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::collections::BTreeMap;
use std::str::FromStr;

const AGENT_PREFIX: &str = "ai-agent-";
const TARGET_MAX: usize = 120;
const SNIPPET_CONTEXT: usize = 40;

/// One line of TSV: tabs, newlines and other controls shown escaped.
fn cell(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            c if c.is_control() => format!("\\u{{{:x}}}", c as u32).chars().collect(),
            c => vec![c],
        })
        .collect()
}

/// At most `max` chars of `s`.
fn clip(s: &str, max: usize) -> &str {
    s.char_indices().nth(max).map_or(s, |(i, _)| &s[..i])
}

/// `SNIPPET_CONTEXT` chars either side of the first match of `re` in `hay`.
fn snippet(re: &Regex, hay: &str) -> Option<String> {
    let m = re.find(hay)?;
    let start = hay[..m.start()]
        .char_indices()
        .rev()
        .nth(SNIPPET_CONTEXT - 1)
        .map_or(0, |(i, _)| i);
    let end = hay[m.end()..]
        .char_indices()
        .nth(SNIPPET_CONTEXT)
        .map_or(hay.len(), |(i, _)| m.end() + i);
    Some(hay[start..end].to_string())
}

/// The regexes of one agent rule, by the part of the request each reads.
struct AgentRule {
    target: Option<Regex>,
    ua: Option<Regex>,
    header: Option<Regex>,
    body: Option<Regex>,
}

fn ci(p: &Option<String>) -> Option<Regex> {
    p.as_deref()
        .map(|p| Regex::new(&format!("(?i){p}")).expect("rule regex compiles"))
}

/// Where in `row` a rule fired, and the text around it. Raw text only: a
/// match only in the decoded text is reported as such, without a snippet.
fn locate(rule: &AgentRule, row: &StoredRequest) -> (&'static str, String) {
    let target = match &row.query {
        Some(q) => format!("{}?{q}", row.path),
        None => row.path.clone(),
    };
    let headers: Vec<(String, String)> =
        serde_json::from_str(&row.headers_json).unwrap_or_default();
    let ua = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let joined = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = peephole::classify::decoded_body(&headers, row.body.as_deref().unwrap_or_default());
    let body = String::from_utf8_lossy(&body);
    let parts: [(&'static str, &Option<Regex>, &str); 4] = [
        ("target", &rule.target, &target),
        ("ua", &rule.ua, &ua),
        ("header", &rule.header, &joined),
        ("body", &rule.body, &body),
    ];
    for (name, re, hay) in parts {
        if let Some(s) = re.as_ref().and_then(|re| snippet(re, hay)) {
            return (name, s);
        }
    }
    ("decoded", String::new())
}

#[tokio::test]
#[ignore = "needs PEEPHOLE_GATE_DB; run by hand before a release"]
async fn agent_rules_precision_gate() {
    let Ok(path) = std::env::var("PEEPHOLE_GATE_DB") else {
        eprintln!("PEEPHOLE_GATE_DB not set; skipped");
        return;
    };
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{path}?mode=ro"))
        .expect("database url")
        .read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("open the database read-only");

    let agent_rules: BTreeMap<String, AgentRule> = rules::parse(&rules::builtin_files())
        .expect("built-in rules parse")
        .into_iter()
        .filter(|r| r.label.starts_with(AGENT_PREFIX))
        .map(|r| {
            let rule = AgentRule {
                target: ci(&r.target_regex),
                ua: ci(&r.ua_regex),
                header: ci(&r.header_regex),
                body: ci(&r.body_regex),
            };
            (r.label, rule)
        })
        .collect();
    assert!(
        !agent_rules.is_empty(),
        "the built-in rules have agent rules"
    );

    let rows: Vec<StoredRequest> =
        sqlx::query_as::<_, StoredRequest>(sqlx::AssertSqlSafe(format!(
            "SELECT {STORED_COLUMNS} FROM requests r
             WHERE r.ts > datetime('now', '-30 days') ORDER BY r.id"
        )))
        .fetch_all(&pool)
        .await
        .expect("read requests");
    let ips: BTreeMap<i64, String> = sqlx::query_as::<_, (i64, String)>("SELECT id, ip FROM ips")
        .fetch_all(&pool)
        .await
        .expect("read ips")
        .into_iter()
        .collect();

    // Agent rules read no history, so one fixed history serves every row.
    let c = Classifier::builtin();
    let hist = IpHistory {
        distinct_paths_1h: 1,
        requests_1h: 1,
    };
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    println!("id\tts\tip\tmethod\ttarget\tlabel\twhere\tsnippet");
    for row in &rows {
        let verdict = row.classify(c, &hist);
        for label in verdict
            .labels
            .iter()
            .filter(|l| l.starts_with(AGENT_PREFIX))
        {
            *counts.entry(label.clone()).or_default() += 1;
            let (place, snip) = locate(&agent_rules[label], row);
            let target = match &row.query {
                Some(q) => format!("{}?{q}", row.path),
                None => row.path.clone(),
            };
            println!(
                "{}\t{}\t{}\t{}\t{}\t{label}\t{place}\t{}",
                row.id,
                row.ts,
                ips.get(&row.ip_id).map_or("?", String::as_str),
                cell(&row.method),
                cell(clip(&target, TARGET_MAX)),
                cell(&snip),
            );
        }
    }
    eprintln!("rows: {}; agent hits: {counts:?}", rows.len());
}
