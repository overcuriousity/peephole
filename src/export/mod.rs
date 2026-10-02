pub mod parquet;

#[derive(serde::Deserialize, Default, Clone, Debug)]
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

/// First line of the CSV export (unquoted).
pub const CSV_HEADER: &str =
    "ts,ip,method,path,query,severity,scan_level,labels,country,asn,asn_org,is_tor\n";

pub fn requests_csv(rows: &[ExportRow]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push_str(&csv_rows(rows));
    out
}

/// CSV data rows, without the header.
pub fn csv_rows(rows: &[ExportRow]) -> String {
    // Data rows fully quoted (fields like joined labels are always
    // delimited, keeping downstream parsing unambiguous).
    let mut out = String::new();
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

/// Export file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Csv,
    Jsonl,
    Parquet,
}

/// Rows read from the database per step of a streamed export (and rows per
/// Parquet row group): bounds the memory an export of any size needs.
pub const STREAM_PAGE: i64 = 5_000;

/// Every request matching `f`, oldest first, as a stream of file chunks.
/// Nothing is capped: the rows are read page by page (keyset paging) and
/// written out as they come, so memory stays bounded whatever the size.
pub fn stream_requests(
    store: crate::store::Store,
    f: ExportFilter,
    format: Format,
) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
    struct St {
        store: crate::store::Store,
        f: ExportFilter,
        after: Option<crate::store::ExportCursor>,
        started: bool,
        done: bool,
        parquet: Option<parquet::ParquetStream>,
    }
    let io = |e: anyhow::Error| {
        tracing::warn!(?e, "export failed");
        std::io::Error::other(e.to_string())
    };
    let st = St {
        store,
        f,
        after: None,
        started: false,
        done: false,
        parquet: None,
    };
    futures::stream::try_unfold(st, move |mut st| async move {
        if st.done {
            return Ok(None);
        }
        let mut out: Vec<u8> = vec![];
        if !st.started {
            st.started = true;
            match format {
                Format::Csv => out.extend_from_slice(CSV_HEADER.as_bytes()),
                Format::Parquet => st.parquet = Some(parquet::ParquetStream::new().map_err(io)?),
                Format::Jsonl => {}
            }
        }
        let page = st
            .store
            .export_page(&st.f, st.after.as_ref(), STREAM_PAGE)
            .await
            .map_err(io)?;
        st.done = (page.len() as i64) < STREAM_PAGE;
        if let Some((_, last)) = page.last() {
            st.after = Some(last.clone());
        }
        let rows: Vec<ExportRow> = page.into_iter().map(|(r, _)| r).collect();
        match format {
            Format::Csv => out.extend_from_slice(csv_rows(&rows).as_bytes()),
            Format::Jsonl => out.extend_from_slice(requests_timesketch(&rows).as_bytes()),
            Format::Parquet => {
                let w = st
                    .parquet
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("parquet writer"))?;
                if !rows.is_empty() {
                    out.extend(w.write(&rows).map_err(io)?);
                }
                if st.done
                    && let Some(w) = st.parquet.take()
                {
                    out.extend(w.finish().map_err(io)?);
                }
            }
        }
        Ok(Some((axum::body::Bytes::from(out), st)))
    })
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

    async fn collect(
        s: &crate::store::Store,
        f: ExportFilter,
        format: Format,
    ) -> Vec<axum::body::Bytes> {
        use futures::TryStreamExt;
        stream_requests(s.clone(), f, format)
            .try_collect()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn exports_stream_every_row_without_a_cap() {
        let dir = tempfile::tempdir().unwrap();
        let s = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let ip = s.upsert_ip("203.0.113.5".parse().unwrap()).await.unwrap();
        // More rows than one page, many sharing a timestamp (keyset ties).
        let n = STREAM_PAGE * 2 + 7;
        sqlx::query(
            "WITH RECURSIVE k(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM k WHERE x < ?)
             INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json, severity)
             SELECT 'u' || x, datetime('2026-01-01', '+' || (x / 3) || ' seconds'), ?, 'GET',
                    '=cmd|' || x, '[]', '[\"a\"]', x % 5 FROM k",
        )
        .bind(n)
        .bind(ip.id)
        .execute(&s.pool)
        .await
        .unwrap();
        let csv = collect(&s, ExportFilter::default(), Format::Csv).await;
        assert!(csv.len() >= 3, "written page by page");
        let text: String = csv.iter().map(|b| String::from_utf8_lossy(b)).collect();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len() as i64, n + 1);
        assert_eq!(lines[0], CSV_HEADER.trim_end());
        assert!(lines[1].contains("\"'=cmd|"), "formula guard: {}", lines[1]);
        let mut paths: Vec<i64> = lines[1..]
            .iter()
            .map(|l| {
                l.split("=cmd|")
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len() as i64, n, "every row exactly once");

        let jsonl = collect(&s, ExportFilter::default(), Format::Jsonl).await;
        let lines: usize = jsonl
            .iter()
            .map(|b| b.iter().filter(|c| **c == b'\n').count())
            .sum();
        assert_eq!(lines as i64, n);

        use ::parquet::file::reader::{FileReader, SerializedFileReader};
        let pq = collect(&s, ExportFilter::default(), Format::Parquet).await;
        assert!(pq.len() >= 3, "one piece per page");
        assert!(!pq[0].is_empty(), "row groups go out as they are written");
        let reader = SerializedFileReader::new(axum::body::Bytes::from(pq.concat())).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), n);
        assert!(reader.metadata().num_row_groups() >= 3);
        let f = ExportFilter {
            min_severity: Some(4),
            ..Default::default()
        };
        let pq = collect(&s, f, Format::Parquet).await;
        let reader = SerializedFileReader::new(axum::body::Bytes::from(pq.concat())).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), n / 5);

        // An empty export is still a valid file.
        let none = ExportFilter {
            ip: Some("192.0.2.1".into()),
            ..Default::default()
        };
        let pq: Vec<u8> = collect(&s, none, Format::Parquet).await.concat();
        let reader = SerializedFileReader::new(axum::body::Bytes::from(pq)).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), 0);
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
