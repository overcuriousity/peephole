pub mod parquet;

#[derive(serde::Deserialize, Default)]
pub struct ExportFilter {
    pub from: Option<String>,
    pub to: Option<String>,
    pub ip: Option<String>,
    pub label: Option<String>,
    pub min_severity: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ExportRow {
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub severity: i64,
    pub scan_level: i64,
    pub labels: Vec<String>,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub is_tor: bool,
}

/// Neutralise spreadsheet formula injection: a cell that a spreadsheet would
/// evaluate because it starts with = + - @ (or a leading tab/CR that some
/// apps strip first) is prefixed with a single quote. Attacker-controlled
/// fields (path, query, method, ASN org) can otherwise execute on open.
fn csv_safe(s: &str) -> std::borrow::Cow<'_, str> {
    match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => std::borrow::Cow::Owned(format!("'{s}")),
        _ => std::borrow::Cow::Borrowed(s),
    }
}

pub fn requests_csv(rows: &[ExportRow]) -> String {
    // Header unquoted; data rows fully quoted (fields like joined labels are
    // always delimited, keeping downstream parsing unambiguous).
    let mut out = String::from(
        "ts,ip,method,path,query,severity,scan_level,labels,country,asn,asn_org,is_tor\n",
    );
    let mut w = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Always)
        .has_headers(false)
        .from_writer(vec![]);
    for r in rows {
        w.write_record([
            csv_safe(&r.ts).as_ref(),
            csv_safe(&r.ip).as_ref(),
            csv_safe(&r.method).as_ref(),
            csv_safe(&r.path).as_ref(),
            csv_safe(r.query.as_deref().unwrap_or("")).as_ref(),
            &r.severity.to_string(),
            &r.scan_level.to_string(),
            csv_safe(&r.labels.join(";")).as_ref(),
            csv_safe(r.country.as_deref().unwrap_or("")).as_ref(),
            &r.asn.map(|a| a.to_string()).unwrap_or_default(),
            csv_safe(r.asn_org.as_deref().unwrap_or("")).as_ref(),
            if r.is_tor { "1" } else { "0" },
        ])
        .unwrap();
    }
    out.push_str(&String::from_utf8(w.into_inner().unwrap()).unwrap());
    out
}

/// Timesketch-ingestible JSONL (spec §10).
pub fn requests_timesketch(rows: &[ExportRow]) -> String {
    let mut out = String::new();
    for r in rows {
        // Stored timestamps are "YYYY-MM-DD HH:MM:SS" (UTC); emit RFC 3339 so
        // Timesketch parses them unambiguously.
        let full_path = match &r.query {
            Some(q) if !q.is_empty() => format!("{}?{}", r.path, q),
            _ => r.path.clone(),
        };
        let v = serde_json::json!({
            "datetime": iso8601(&r.ts),
            "timestamp_desc": "HTTP request logged",
            "message": format!("{} {} {} (severity {}, labels: {})", r.ip, r.method, full_path, r.severity, r.labels.join(",")),
            "source_ip": r.ip,
            "method": r.method,
            "path": r.path,
            "query": r.query,
            "severity": r.severity,
            "scan_level": r.scan_level,
            "labels": r.labels,
            "country": r.country,
            "asn": r.asn,
            "asn_org": r.asn_org,
            "is_tor_exit": r.is_tor,
        });
        out.push_str(&v.to_string());
        out.push('\n');
    }
    out
}

/// Convert a stored "YYYY-MM-DD HH:MM:SS" UTC timestamp to RFC 3339. Values
/// already carrying a `T`/timezone (or unparseable) pass through unchanged.
fn iso8601(ts: &str) -> String {
    if ts.contains('T') {
        return ts.to_string();
    }
    match chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        Ok(dt) => dt.and_utc().to_rfc3339(),
        Err(_) => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> ExportRow {
        ExportRow {
            ts: "2026-09-29T12:00:00Z".into(),
            ip: "203.0.113.5".into(),
            method: "GET".into(),
            path: "/.env".into(),
            query: None,
            severity: 2,
            scan_level: 2,
            labels: vec!["sensitive-path".into()],
            country: Some("Germany".into()),
            asn: Some(3320),
            asn_org: Some("DTAG".into()),
            is_tor: false,
        }
    }

    #[test]
    fn csv_has_header_and_escaped_row() {
        let csv = requests_csv(&[row()]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("ts,ip,method,path"));
        assert!(lines[1].contains("203.0.113.5"));
        assert!(lines[1].contains("\"sensitive-path\""));
    }

    #[test]
    fn csv_neutralises_formula_injection() {
        let mut r = row();
        r.query = Some("=HYPERLINK(\"http://evil\")".into());
        r.method = "-2+3".into();
        let csv = requests_csv(&[r]);
        // The dangerous cells are prefixed with a single quote.
        assert!(csv.contains("\"'=HYPERLINK"), "{csv}");
        assert!(csv.contains("\"'-2+3\""), "{csv}");
    }

    #[test]
    fn timesketch_lines_have_required_fields() {
        let mut r = row();
        r.ts = "2026-09-29 12:00:00".into();
        r.query = Some("id=1".into());
        let out = requests_timesketch(&[r]);
        let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        // "YYYY-MM-DD HH:MM:SS" is emitted as RFC 3339.
        assert_eq!(v["datetime"], "2026-09-29T12:00:00+00:00");
        assert!(v["message"].as_str().unwrap().contains("/.env?id=1"));
        assert_eq!(v["query"], "id=1");
        assert_eq!(v["timestamp_desc"], "HTTP request logged");
        assert_eq!(v["source_ip"], "203.0.113.5");
    }

    #[test]
    fn parquet_roundtrip_has_one_row() {
        let bytes = crate::export::parquet::requests_parquet(&[row()]).unwrap();
        assert!(bytes.len() > 100);
        // Parse back with parquet's reader and count rows.
        use ::parquet::file::reader::{FileReader, SerializedFileReader};
        let reader = SerializedFileReader::new(bytes::Bytes::from(bytes)).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), 1);
    }
}
