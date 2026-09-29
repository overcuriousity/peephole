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

pub fn requests_csv(rows: &[ExportRow]) -> String {
    // Header unquoted; data rows fully quoted (fields like joined labels are
    // always delimited, keeping downstream parsing unambiguous).
    let mut out = String::from("ts,ip,method,path,query,severity,scan_level,labels,country,asn,asn_org,is_tor\n");
    let mut w = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Always)
        .has_headers(false)
        .from_writer(vec![]);
    for r in rows {
        w.write_record([
            r.ts.as_str(), r.ip.as_str(), r.method.as_str(), r.path.as_str(),
            r.query.as_deref().unwrap_or(""), &r.severity.to_string(), &r.scan_level.to_string(),
            &r.labels.join(";"), r.country.as_deref().unwrap_or(""),
            &r.asn.map(|a| a.to_string()).unwrap_or_default(),
            r.asn_org.as_deref().unwrap_or(""), if r.is_tor { "1" } else { "0" },
        ]).unwrap();
    }
    out.push_str(&String::from_utf8(w.into_inner().unwrap()).unwrap());
    out
}

/// Timesketch-ingestible JSONL (spec §10).
pub fn requests_timesketch(rows: &[ExportRow]) -> String {
    let mut out = String::new();
    for r in rows {
        let v = serde_json::json!({
            "datetime": r.ts,
            "timestamp_desc": "HTTP request logged",
            "message": format!("{} {} {} (severity {}, labels: {})", r.ip, r.method, r.path, r.severity, r.labels.join(",")),
            "source_ip": r.ip,
            "method": r.method,
            "path": r.path,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> ExportRow {
        ExportRow {
            ts: "2026-09-29T12:00:00Z".into(), ip: "203.0.113.5".into(),
            method: "GET".into(), path: "/.env".into(), query: None,
            severity: 2, scan_level: 2, labels: vec!["sensitive-path".into()],
            country: Some("Germany".into()), asn: Some(3320), asn_org: Some("DTAG".into()),
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
    fn timesketch_lines_have_required_fields() {
        let out = requests_timesketch(&[row()]);
        let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        assert_eq!(v["datetime"], "2026-09-29T12:00:00Z");
        assert!(v["message"].as_str().unwrap().contains("/.env"));
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
