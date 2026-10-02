//! The dataset export: one row per request (`kind = request`) and per
//! light row of a request the flood gate skipped (`kind = skipped`), with
//! everything peephole stored about it and its IP. CSV and JSON Lines carry
//! the Timesketch fields; Parquet is typed. Claim e-mails and texts are
//! never exported, only whether the IP filed a claim.
pub mod parquet;

use crate::store::Store;
use crate::store::export::{FpOut, IntelOut, PageContext, ReqRow, ScanOut, SkipOut};
use data_encoding::BASE64;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[derive(serde::Deserialize, Default, Clone, Debug)]
pub struct ExportFilter {
    pub from: Option<String>,
    pub to: Option<String>,
    pub ip: Option<String>,
    pub label: Option<String>,
    pub min_severity: Option<i64>,
}

impl ExportFilter {
    /// Light rows have no labels or severity: a filter on those leaves
    /// them out.
    fn includes_skipped(&self) -> bool {
        self.label.is_none() && self.min_severity.is_none()
    }
}

/// Which enrichment results go out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    /// Everything.
    #[default]
    Full,
    /// Only results whose terms allow passing them on
    /// ([`crate::intel::ProviderInfo::redistributable`]); GeoLite2-derived
    /// columns are empty.
    Redistributable,
}

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    pub mode: Mode,
    /// Node names by node id, for the `node` columns.
    pub names: HashMap<Vec<u8>, String>,
}

/// One exported row. See [`COLUMNS`] for the order in CSV.
#[derive(Debug, Clone, Default)]
pub struct ExportRow {
    pub kind: &'static str,
    pub uid: String,
    pub node: String,
    pub ts_ms: i64,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub http_version: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    /// Every stored header in order, names as received; the trap's
    /// observations are the `:`-pseudo-headers.
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub body_size: Option<i64>,
    pub body_truncated_at: Option<i64>,
    pub transport: Option<String>,
    pub via_proxy: Option<bool>,
    pub raw_head: Option<Vec<u8>>,
    pub tls_client_hello: Option<Vec<u8>>,
    pub ja4: Option<String>,
    pub answer: Option<String>,
    pub status: Option<i64>,
    /// Requests from the IP answered but not recorded since the previous
    /// recorded one (for a light row: drops of its batch, on its last row).
    pub unrecorded: i64,
    /// Answered requests this row stands for, so that the weights of an
    /// export add up to the requests answered. With light rows in the
    /// export, a recorded request stands for itself (its skipped
    /// predecessors are light rows or counted drops); without them, it also
    /// stands for its `unrecorded` predecessors. Rows recorded before light
    /// rows existed always carry theirs.
    pub weight: i64,
    pub labels: Vec<String>,
    pub severity: Option<i64>,
    pub scan_level: Option<i64>,
    pub fp_claim: bool,
    pub country: Option<String>,
    pub asn: Option<i64>,
    pub asn_org: Option<String>,
    pub is_tor: Option<bool>,
    /// JSON text, shared by every row of the IP on a page (it can be
    /// large: nmap XML) rather than copied.
    pub intel: Arc<str>,
    pub scans: Arc<str>,
    pub fingerprints: Arc<str>,
}

/// Columns of the text exports, in order.
pub const COLUMNS: &[&str] = &[
    "kind",
    "uid",
    "node",
    "ts",
    "ip",
    "method",
    "path",
    "query",
    "http_version",
    "host",
    "user_agent",
    "headers",
    "body",
    "body_size",
    "body_truncated_at",
    "transport",
    "via_proxy",
    "raw_head",
    "tls_client_hello",
    "ja4",
    "answer",
    "status",
    "unrecorded",
    "weight",
    "labels",
    "severity",
    "scan_level",
    "fp_claim",
    "country",
    "asn",
    "asn_org",
    "is_tor",
    "intel",
    "scans",
    "fingerprints",
    "message",
    "datetime",
    "timestamp_desc",
];

/// Neutralise spreadsheet formula injection: a cell that a spreadsheet would
/// evaluate because it starts with = + - @ (or a leading tab/CR that some
/// apps strip first) is prefixed with a single quote. Attacker-controlled
/// fields (path, query, method, headers) can otherwise execute on open.
fn csv_safe(s: &str) -> std::borrow::Cow<'_, str> {
    match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => std::borrow::Cow::Owned(format!("'{s}")),
        _ => std::borrow::Cow::Borrowed(s),
    }
}

/// RFC 3339 UTC time of a Unix millisecond timestamp.
fn rfc3339(ts_ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_ms)
        .map(|t| t.to_rfc3339())
        .unwrap_or_default()
}

/// Unix milliseconds of a stored `YYYY-MM-DD HH:MM:SS` (or RFC 3339) time.
fn millis(ts: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
        .map(|t| t.and_utc().timestamp_millis())
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(ts).map(|t| t.timestamp_millis()))
        .unwrap_or(0)
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

fn b64(b: &Option<Vec<u8>>) -> Value {
    b.as_ref()
        .map_or(Value::Null, |b| Value::String(BASE64.encode(b)))
}

impl ExportRow {
    fn timestamp_desc(&self) -> &'static str {
        if self.kind == "skipped" {
            "HTTP request skipped"
        } else {
            "HTTP request logged"
        }
    }

    fn message(&self) -> String {
        let target = match &self.query {
            Some(q) if !q.is_empty() => format!("{}?{}", self.path, q),
            _ => self.path.clone(),
        };
        if self.kind == "skipped" {
            return format!(
                "{} {} {} (not recorded in full)",
                self.ip, self.method, target
            );
        }
        format!(
            "{} {} {} ({}, severity {}, labels: {})",
            self.ip,
            self.method,
            target,
            self.answer.as_deref().unwrap_or("answer not recorded"),
            self.severity.unwrap_or(0),
            self.labels.join(",")
        )
    }

    /// Bytes this row adds to an export, roughly.
    fn size(&self) -> usize {
        512 + self.intel.len()
            + self.scans.len()
            + self.fingerprints.len()
            + self.path.len()
            + self.query.as_ref().map_or(0, String::len)
            + self
                .headers
                .iter()
                .map(|(n, v)| n.len() + v.len() + 8)
                .sum::<usize>()
            + [&self.body, &self.raw_head, &self.tls_client_hello]
                .iter()
                .map(|b| b.as_ref().map_or(0, |b| b.len() * 4 / 3))
                .sum::<usize>()
    }

    /// The per-IP JSON columns, as stored text.
    fn json_text(&self, column: &str) -> Option<&str> {
        match column {
            "intel" => Some(&self.intel),
            "scans" => Some(&self.scans),
            "fingerprints" => Some(&self.fingerprints),
            _ => None,
        }
    }

    /// The row as JSON, keyed by [`COLUMNS`]; blobs in base64. The JSON
    /// text columns (`intel`, `scans`, `fingerprints`) are not in it.
    pub fn to_json(&self) -> serde_json::Map<String, Value> {
        let headers: Vec<[&str; 2]> = self
            .headers
            .iter()
            .map(|(n, v)| [n.as_str(), v.as_str()])
            .collect();
        let v = json!({
            "kind": self.kind,
            "uid": self.uid,
            "node": self.node,
            "ts": rfc3339(self.ts_ms),
            "ip": self.ip,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "http_version": self.http_version,
            "host": self.host,
            "user_agent": self.user_agent,
            "headers": headers,
            "body": b64(&self.body),
            "body_size": self.body_size,
            "body_truncated_at": self.body_truncated_at,
            "transport": self.transport,
            "via_proxy": self.via_proxy,
            "raw_head": b64(&self.raw_head),
            "tls_client_hello": b64(&self.tls_client_hello),
            "ja4": self.ja4,
            "answer": self.answer,
            "status": self.status,
            "unrecorded": self.unrecorded,
            "weight": self.weight,
            "labels": self.labels,
            "severity": self.severity,
            "scan_level": self.scan_level,
            "fp_claim": self.fp_claim,
            "country": self.country,
            "asn": self.asn,
            "asn_org": self.asn_org,
            "is_tor": self.is_tor,
            "message": self.message(),
            "datetime": rfc3339(self.ts_ms),
            "timestamp_desc": self.timestamp_desc(),
        });
        match v {
            Value::Object(m) => m,
            _ => unreachable!(),
        }
    }
}

/// First line of the CSV export.
pub fn csv_header() -> String {
    format!("{}\n", COLUMNS.join(","))
}

/// CSV data rows, without the header: every field quoted, lists and
/// objects as JSON, blobs in base64.
pub fn csv_rows(rows: &[ExportRow]) -> String {
    let mut w = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Always)
        .has_headers(false)
        .from_writer(vec![]);
    for r in rows {
        let m = r.to_json();
        let cells: Vec<String> = COLUMNS
            .iter()
            .map(|c| {
                match r
                    .json_text(c)
                    .map(|t| Value::String(t.to_string()))
                    .as_ref()
                    .or(m.get(*c))
                {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => csv_safe(s).into_owned(),
                    Some(v @ (Value::Array(_) | Value::Object(_))) => {
                        csv_safe(&v.to_string()).into_owned()
                    }
                    Some(v) => v.to_string(),
                }
            })
            .collect();
        w.write_record(&cells).expect("writing to memory");
    }
    String::from_utf8(w.into_inner().expect("writing to memory")).expect("valid UTF-8")
}

/// Timesketch-ingestible JSON Lines.
pub fn jsonl_rows(rows: &[ExportRow]) -> String {
    let mut out = String::new();
    for r in rows {
        // The JSON text columns go in as they are, not parsed again.
        let small = Value::Object(r.to_json()).to_string();
        out.push_str(&small[..small.len() - 1]);
        for c in ["intel", "scans", "fingerprints"] {
            out.push_str(&format!(",\"{c}\":"));
            out.push_str(r.json_text(c).unwrap_or("null"));
        }
        out.push_str("}\n");
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

/// Most bytes of rows (estimated) written out in one piece, and per Parquet
/// row group: per-IP data such as nmap XML repeats on each of the IP's rows,
/// so a page of rows alone does not bound memory.
pub const CHUNK_BYTES: usize = 8 * 1024 * 1024;

fn node_name(names: &HashMap<Vec<u8>, String>, origin: &[u8]) -> String {
    match names.get(origin) {
        Some(n) => n.clone(),
        None if origin.is_empty() => "this node".to_string(),
        None => data_encoding::HEXLOWER.encode(&origin[..origin.len().min(6)]),
    }
}

/// Context-dependent columns of an IP, shared by its rows on a page.
struct IpCols {
    intel: Arc<str>,
    scans: Arc<str>,
    /// GeoLite2 and Tor results with their times, oldest first.
    geo: Vec<(i64, Value)>,
    tor: Vec<(i64, bool)>,
}

/// The newest entry at or before `ts_ms`, else the earliest.
fn as_of<T: Clone>(v: &[(i64, T)], ts_ms: i64) -> Option<T> {
    v.iter()
        .rev()
        .find(|(t, _)| *t <= ts_ms)
        .or_else(|| v.first())
        .map(|(_, x)| x.clone())
}

fn ip_cols(ip: &str, ip_id: i64, ctx: &PageContext, opts: &ExportOptions) -> IpCols {
    let allowed = |provider: &str| {
        opts.mode == Mode::Full
            || crate::intel::provider_info(provider).is_some_and(|p| p.redistributable)
    };
    let lookups: Vec<&IntelOut> = ctx
        .intel
        .get(ip)
        .map(|v| v.iter().filter(|i| allowed(&i.provider)).collect())
        .unwrap_or_default();
    let data = |i: &IntelOut| serde_json::from_str::<Value>(&i.data_json).unwrap_or(Value::Null);
    let intel = lookups
        .iter()
        .map(|i| {
            json!({
                "provider": i.provider,
                "fetched_at": iso8601(&i.fetched_at),
                "source_version": i.source_version,
                "node": node_name(&opts.names, &i.origin),
                "data": data(i),
            })
        })
        .collect::<Vec<_>>();
    let geo = lookups
        .iter()
        .filter(|i| i.provider == crate::intel::MAXMIND)
        .map(|i| (millis(&i.fetched_at), data(i)))
        .collect();
    let tor = lookups
        .iter()
        .filter(|i| i.provider == crate::intel::TOR)
        .map(|i| {
            (
                millis(&i.fetched_at),
                data(i)["exit"].as_bool().unwrap_or(false),
            )
        })
        .collect();
    let scans = ctx
        .scans
        .get(&ip_id)
        .map(|v| {
            v.iter()
                .map(|(s, p)| scan_json(s, p, opts))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    IpCols {
        intel: Value::Array(intel).to_string().into(),
        scans: Value::Array(scans).to_string().into(),
        geo,
        tor,
    }
}

fn scan_json(s: &ScanOut, ports: &[crate::store::export::PortOut], opts: &ExportOptions) -> Value {
    let xml = s.raw_xml.as_ref().and_then(|b| {
        crate::store::inspect::zstd_decode_capped(b, crate::store::inspect::MAX_RAW_XML)
            .ok()
            .map(|x| String::from_utf8_lossy(&x).into_owned())
    });
    json!({
        "level": s.level,
        "status": s.status,
        "started_at": iso8601(&s.started_at),
        "finished_at": s.finished_at.as_deref().map(iso8601),
        "node": node_name(&opts.names, s.origin.as_deref().unwrap_or_default()),
        "scanner": s.scanner.as_deref().map(|id| node_name(&opts.names, id)),
        "os_guess": s.os_guess,
        "ports": ports,
        "xml": xml,
    })
}

/// Largest decompressed fingerprint event log exported.
const MAX_EVENTS: u64 = 16 * 1024 * 1024;

fn fingerprint_json(f: &FpOut) -> Value {
    let parse = |s: &Option<String>| {
        s.as_deref()
            .map(|s| serde_json::from_str::<Value>(s).unwrap_or_else(|_| Value::String(s.into())))
    };
    let events = f.event_blob.as_ref().and_then(|b| {
        crate::store::inspect::zstd_decode_capped(b, MAX_EVENTS)
            .ok()
            .map(|raw| {
                serde_json::from_slice::<Value>(&raw)
                    .unwrap_or_else(|_| Value::String(BASE64.encode(&raw)))
            })
    });
    json!({
        "ts": iso8601(&f.ts),
        "fp_hash": f.fp_hash,
        "visitor_id": f.visitor_id,
        "attributes": parse(&f.attributes_json),
        "behavior_summary": parse(&f.behavior_summary_json),
        "events": events,
    })
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn fill_ip(
    row: &mut ExportRow,
    cols: &IpCols,
    ip_id: i64,
    ctx: &PageContext,
    opts: &ExportOptions,
) {
    row.intel = cols.intel.clone();
    row.scans = cols.scans.clone();
    row.fp_claim = ctx.claimed.contains(&ip_id);
    if opts.mode == Mode::Full
        && let Some(g) = as_of(&cols.geo, row.ts_ms)
    {
        row.country = g["country"].as_str().map(str::to_string);
        row.asn = g["asn"].as_i64();
        row.asn_org = g["asn_org"].as_str().map(str::to_string);
    }
    row.is_tor = as_of(&cols.tor, row.ts_ms);
}

fn request_row(
    r: ReqRow,
    ctx: &PageContext,
    cols: &IpCols,
    opts: &ExportOptions,
    with_skipped: bool,
) -> ExportRow {
    let headers: Vec<(String, String)> = serde_json::from_str(&r.headers_json).unwrap_or_default();
    // Rows recorded before the column existed carry the count as a header;
    // no light rows were kept for them.
    let legacy = r.unrecorded.is_none();
    let unrecorded = r
        .unrecorded
        .or_else(|| header(&headers, ":unrecorded").and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    let weight = if with_skipped && !legacy {
        1
    } else {
        unrecorded + 1
    };
    let fingerprints = r
        .uid
        .as_ref()
        .and_then(|u| ctx.fingerprints.get(u))
        .map(|v| v.iter().map(fingerprint_json).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut row = ExportRow {
        kind: "request",
        uid: r.uid.unwrap_or_else(|| r.id.to_string()),
        node: node_name(&opts.names, r.origin.as_deref().unwrap_or_default()),
        ts_ms: millis(&r.ts),
        ip: r.ip,
        method: r.method,
        path: r.path,
        query: r.query,
        http_version: header(&headers, ":version").map(str::to_string),
        host: header(&headers, ":authority")
            .or_else(|| header(&headers, "host"))
            .map(str::to_string),
        user_agent: header(&headers, "user-agent").map(str::to_string),
        body_size: r.body.as_ref().map(|b| b.len() as i64),
        body_truncated_at: header(&headers, ":body-truncated").and_then(|v| v.parse().ok()),
        body: r.body,
        headers,
        transport: r.transport,
        via_proxy: r.via_proxy,
        raw_head: r.raw_head,
        tls_client_hello: r.tls_client_hello,
        ja4: r.ja4,
        answer: r.answer,
        status: r.status,
        unrecorded,
        weight,
        labels: serde_json::from_str(&r.labels_json).unwrap_or_default(),
        severity: Some(r.severity),
        scan_level: Some(r.scan_level),
        fingerprints: Value::Array(fingerprints).to_string().into(),
        ..Default::default()
    };
    fill_ip(&mut row, cols, r.ip_id, ctx, opts);
    row
}

fn skipped_row(s: SkipOut, ctx: &PageContext, cols: &IpCols, opts: &ExportOptions) -> ExportRow {
    let unrecorded = if s.last_in_batch { s.dropped } else { 0 };
    let mut row = ExportRow {
        kind: "skipped",
        uid: format!("{}#{}", s.uid, s.rowid),
        node: node_name(&opts.names, s.origin.as_deref().unwrap_or_default()),
        ts_ms: s.ts_ms,
        ip: s.ip,
        method: s.method,
        path: s.path,
        unrecorded,
        weight: unrecorded + 1,
        fingerprints: "[]".into(),
        ..Default::default()
    };
    fill_ip(&mut row, cols, s.ip_id, ctx, opts);
    row
}

/// Where a streamed export is.
enum Phase {
    Requests(Option<(String, i64)>),
    Skipped(Option<(i64, i64)>),
    Done,
}

/// Read the next page and turn it into rows.
async fn next_rows(
    store: &Store,
    f: &ExportFilter,
    opts: &ExportOptions,
    phase: &mut Phase,
) -> anyhow::Result<Vec<ExportRow>> {
    match phase {
        Phase::Requests(after) => {
            let page = store
                .export_requests(f, after.as_ref(), STREAM_PAGE)
                .await?;
            *phase = match page.last() {
                _ if (page.len() as i64) < STREAM_PAGE => {
                    if f.includes_skipped() {
                        Phase::Skipped(None)
                    } else {
                        Phase::Done
                    }
                }
                Some(last) => Phase::Requests(Some((last.ts.clone(), last.id))),
                None => Phase::Done,
            };
            let ips: Vec<String> = page.iter().map(|r| r.ip.clone()).collect();
            let ip_ids: Vec<i64> = page.iter().map(|r| r.ip_id).collect();
            let uids: Vec<String> = page.iter().filter_map(|r| r.uid.clone()).collect();
            let ctx = store.export_context(&ips, &ip_ids, &uids).await?;
            let mut cols: HashMap<i64, IpCols> = HashMap::new();
            Ok(page
                .into_iter()
                .map(|r| {
                    let c = cols
                        .entry(r.ip_id)
                        .or_insert_with(|| ip_cols(&r.ip, r.ip_id, &ctx, opts));
                    request_row(r, &ctx, c, opts, f.includes_skipped())
                })
                .collect())
        }
        Phase::Skipped(after) => {
            let page = store.export_skipped(f, after.as_ref(), STREAM_PAGE).await?;
            *phase = match page.last() {
                Some(last) if page.len() as i64 == STREAM_PAGE => {
                    Phase::Skipped(Some((last.ts_ms, last.rowid)))
                }
                _ => Phase::Done,
            };
            let ips: Vec<String> = page.iter().map(|r| r.ip.clone()).collect();
            let ip_ids: Vec<i64> = page.iter().map(|r| r.ip_id).collect();
            let ctx = store.export_context(&ips, &ip_ids, &[]).await?;
            let mut cols: HashMap<i64, IpCols> = HashMap::new();
            Ok(page
                .into_iter()
                .map(|s| {
                    let c = cols
                        .entry(s.ip_id)
                        .or_insert_with(|| ip_cols(&s.ip, s.ip_id, &ctx, opts));
                    skipped_row(s, &ctx, c, opts)
                })
                .collect())
        }
        Phase::Done => Ok(vec![]),
    }
}

/// Every row matching `f`, recorded requests then light rows, each oldest
/// first, as a stream of file chunks. Nothing is capped: rows are read page
/// by page and written out as they come, so memory stays bounded whatever
/// the size.
pub fn stream_requests(
    store: Store,
    f: ExportFilter,
    format: Format,
    opts: ExportOptions,
) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
    struct St {
        store: Store,
        f: ExportFilter,
        opts: ExportOptions,
        phase: Phase,
        /// Rows read but not written yet.
        pending: VecDeque<ExportRow>,
        started: bool,
        finished: bool,
        parquet: Option<parquet::ParquetStream>,
    }
    let io = |e: anyhow::Error| {
        tracing::warn!(?e, "export failed");
        std::io::Error::other(e.to_string())
    };
    let st = St {
        store,
        f,
        opts,
        phase: Phase::Requests(None),
        pending: VecDeque::new(),
        started: false,
        finished: false,
        parquet: None,
    };
    futures::stream::try_unfold(st, move |mut st| async move {
        if st.finished {
            return Ok(None);
        }
        let mut out: Vec<u8> = vec![];
        if !st.started {
            st.started = true;
            match format {
                Format::Csv => out.extend_from_slice(csv_header().as_bytes()),
                Format::Parquet => {
                    st.parquet = Some(parquet::ParquetStream::new(&st.f, st.opts.mode).map_err(io)?)
                }
                Format::Jsonl => {}
            }
        }
        if st.pending.is_empty() && !matches!(st.phase, Phase::Done) {
            let page = next_rows(&st.store, &st.f, &st.opts, &mut st.phase)
                .await
                .map_err(io)?;
            st.pending.extend(page);
        }
        // Up to CHUNK_BYTES of rows (at least one) per piece.
        let mut rows = vec![];
        let mut bytes = 0;
        while let Some(r) = st.pending.front() {
            let n = r.size();
            if !rows.is_empty() && bytes + n > CHUNK_BYTES {
                break;
            }
            bytes += n;
            rows.extend(st.pending.pop_front());
        }
        let done = st.pending.is_empty() && matches!(st.phase, Phase::Done);
        match format {
            Format::Csv => out.extend_from_slice(csv_rows(&rows).as_bytes()),
            Format::Jsonl => out.extend_from_slice(jsonl_rows(&rows).as_bytes()),
            Format::Parquet => {
                let w = st
                    .parquet
                    .as_mut()
                    .ok_or_else(|| std::io::Error::other("parquet writer"))?;
                if !rows.is_empty() {
                    out.extend(w.write(&rows).map_err(io)?);
                }
                if done && let Some(w) = st.parquet.take() {
                    out.extend(w.finish().map_err(io)?);
                }
            }
        }
        st.finished = done;
        Ok(Some((axum::body::Bytes::from(out), st)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::requests::NewRequest;

    fn row() -> ExportRow {
        ExportRow {
            kind: "request",
            uid: "u1".into(),
            node: "this node".into(),
            ts_ms: 1_790_000_000_000,
            ip: "203.0.113.5".into(),
            method: "GET".into(),
            path: "/.env".into(),
            query: None,
            headers: vec![("User-Agent".into(), "curl".into())],
            labels: vec!["sensitive-path".into()],
            severity: Some(2),
            scan_level: Some(2),
            weight: 1,
            country: Some("Germany".into()),
            asn: Some(3320),
            asn_org: Some("DTAG".into()),
            is_tor: Some(false),
            body: Some(b"a=1".to_vec()),
            intel: "[]".into(),
            scans: "[]".into(),
            fingerprints: "[]".into(),
            ..Default::default()
        }
    }

    #[test]
    fn csv_has_every_column_and_escaped_row() {
        let csv = csv_rows(&[row()]);
        let header = csv_header();
        for col in COLUMNS {
            assert!(header.split(',').any(|h| h.trim() == *col), "{col}");
        }
        assert!(csv.contains("\"203.0.113.5\""));
        assert!(
            csv.contains("[\"\"sensitive-path\"\"]"),
            "labels as JSON: {csv}"
        );
        assert!(csv.contains("\"YT0x\""), "body as base64: {csv}");
        assert!(csv.contains("\"2026-09-21T14:13:20+00:00\""), "{csv}");
    }

    #[test]
    fn csv_neutralises_formula_injection() {
        let mut r = row();
        r.query = Some("=HYPERLINK(\"http://evil\")".into());
        r.method = "-2+3".into();
        let csv = csv_rows(&[r]);
        assert!(csv.contains("\"'=HYPERLINK"), "{csv}");
        assert!(csv.contains("\"'-2+3\""), "{csv}");
    }

    #[test]
    fn timesketch_fields_in_jsonl() {
        let mut r = row();
        r.query = Some("id=1".into());
        let out = jsonl_rows(&[r]);
        let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        assert_eq!(v["datetime"], "2026-09-21T14:13:20+00:00");
        assert!(v["message"].as_str().unwrap().contains("/.env?id=1"));
        assert_eq!(v["timestamp_desc"], "HTTP request logged");
        assert_eq!(v["headers"][0][0], "User-Agent");
        assert_eq!(v["body"], "YT0x");
        assert_eq!(v["labels"][0], "sensitive-path");
    }

    async fn collect(s: &Store, f: ExportFilter, format: Format) -> Vec<axum::body::Bytes> {
        use futures::TryStreamExt;
        stream_requests(s.clone(), f, format, Default::default())
            .try_collect()
            .await
            .unwrap()
    }

    fn text(parts: &[axum::body::Bytes]) -> String {
        parts.iter().map(|b| String::from_utf8_lossy(b)).collect()
    }

    #[tokio::test]
    async fn exports_stream_every_row_without_a_cap() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
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
        let body = text(&csv);
        let mut rdr = csv::Reader::from_reader(body.as_bytes());
        let path_col = rdr
            .headers()
            .unwrap()
            .iter()
            .position(|h| h == "path")
            .unwrap();
        let mut paths: Vec<i64> = rdr
            .records()
            .map(|r| {
                let p = r.unwrap()[path_col].to_string();
                assert!(p.starts_with("'=cmd|"), "formula guard: {p}");
                p.trim_start_matches("'=cmd|").parse().unwrap()
            })
            .collect();
        assert_eq!(paths.len() as i64, n);
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len() as i64, n, "every row exactly once");

        let jsonl = collect(&s, ExportFilter::default(), Format::Jsonl).await;
        assert_eq!(text(&jsonl).lines().count() as i64, n);

        use ::parquet::file::reader::{FileReader, SerializedFileReader};
        let pq = collect(&s, ExportFilter::default(), Format::Parquet).await;
        assert!(pq.len() >= 3, "one piece per page");
        let reader = SerializedFileReader::new(axum::body::Bytes::from(pq.concat())).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), n);
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

    /// One request with every kind of data about it and its IP, and one
    /// batch of two light rows plus three counted drops.
    async fn rich() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let ip = "203.0.113.5";
        let row = s.upsert_ip(ip.parse().unwrap()).await.unwrap();
        let rec = s.local();
        rec.record_intel(
            ip,
            crate::intel::MAXMIND,
            Some("2026-09-01"),
            serde_json::json!({"country": "Germany", "asn": 3320, "asn_org": "DTAG"}),
        )
        .await
        .unwrap();
        rec.record_intel(
            ip,
            crate::intel::TOR,
            None,
            serde_json::json!({"exit": false}),
        )
        .await
        .unwrap();
        rec.record_lookup(
            ip,
            crate::intel::ABUSEIPDB,
            None,
            serde_json::json!({"score": 90}),
        )
        .await
        .unwrap();
        let rid = s
            .insert_request(&NewRequest {
                ip_id: row.id,
                method: "POST".into(),
                path: "/login".into(),
                query: Some("a=1".into()),
                headers_json: r#"[[":version","HTTP/1.1"],[":body-truncated","99999"],["Host","x.test"],["User-Agent","sqlmap"]]"#.into(),
                body: Some(b"user=admin".to_vec()),
                labels_json: r#"["bait"]"#.into(),
                severity: 3,
                scan_level: 3,
                answer: Some("not-found".into()),
                status: Some(404),
                unrecorded: Some(2),
                transport: Some("https".into()),
                via_proxy: Some(true),
                raw_head: Some(b"POST /login HTTP/1.1\r\n\r\n".to_vec()),
                tls_client_hello: Some(vec![0x16, 3, 1]),
                ja4: Some("t13d0305h2_aaaaaaaaaaaa_bbbbbbbbbbbb".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        s.insert_fp_claim(row.id, rid, Some("secret@mail.test"), "UA")
            .await
            .unwrap();
        s.insert_fingerprint(
            Some(rid),
            row.id,
            "fphash",
            Some("v1"),
            "{\"a\":1}",
            "{}",
            b"[1,2]",
        )
        .await
        .unwrap();
        let job = match s.enqueue_scan(row.id, 2, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        s.finish_job(
            job,
            Some(&crate::scan::nmap_xml::ScanResult {
                os_guess: Some("Linux".into()),
                raw_xml: b"<nmaprun>XML</nmaprun>".to_vec(),
                ports: vec![crate::scan::nmap_xml::PortResult {
                    port: 22,
                    proto: "tcp".into(),
                    state: "open".into(),
                    service: Some("ssh".into()),
                    product: None,
                    version: None,
                }],
            }),
            None,
        )
        .await
        .unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        let light = |ts_ms, path: &str| crate::cluster::record::SkipRow {
            ts_ms,
            method: "GET".into(),
            path: path.into(),
        };
        rec.insert_skip_batch(ip, 3, vec![light(now, "/s1"), light(now + 1, "/s2")])
            .await
            .unwrap();
        (s, dir)
    }

    #[tokio::test]
    async fn the_export_carries_every_field_and_both_kinds() {
        let (s, _d) = rich().await;
        let out = text(&collect(&s, ExportFilter::default(), Format::Jsonl).await);
        let rows: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3, "{out}");
        let r = &rows[0];
        assert_eq!(r["kind"], "request");
        assert_eq!(r["answer"], "not-found");
        assert_eq!(r["status"], 404);
        assert_eq!(r["ja4"], "t13d0305h2_aaaaaaaaaaaa_bbbbbbbbbbbb");
        assert_eq!(r["transport"], "https");
        assert_eq!(r["via_proxy"], true);
        assert_eq!(r["http_version"], "HTTP/1.1");
        assert_eq!(r["host"], "x.test");
        assert_eq!(r["user_agent"], "sqlmap");
        assert_eq!(r["body_size"], 10);
        assert_eq!(r["body_truncated_at"], 99999);
        assert_eq!(r["fp_claim"], true);
        assert!(
            !out.contains("secret@mail.test"),
            "claim e-mails never leave"
        );
        assert_eq!(r["country"], "Germany");
        assert_eq!(r["asn"], 3320);
        assert_eq!(r["is_tor"], false);
        assert_eq!(r["intel"].as_array().unwrap().len(), 3);
        assert_eq!(r["scans"][0]["ports"][0]["port"], 22);
        assert!(r["scans"][0]["xml"].as_str().unwrap().contains("XML"));
        assert_eq!(r["fingerprints"][0]["fp_hash"], "fphash");
        assert_eq!(r["fingerprints"][0]["events"], serde_json::json!([1, 2]));
        assert_eq!(r["unrecorded"], 2);
        assert_eq!(
            r["weight"], 1,
            "its skipped predecessors are light rows here"
        );
        assert_eq!(rows[1]["kind"], "skipped");
        assert_eq!(rows[1]["path"], "/s1");
        assert_eq!(rows[1]["timestamp_desc"], "HTTP request skipped");
        assert_eq!(rows[1]["intel"].as_array().unwrap().len(), 3);
        // The batch's drops weigh on its last light row.
        assert_eq!(rows[1]["weight"], 1);
        assert_eq!(rows[2]["weight"], 4);
        let w: i64 = rows.iter().map(|r| r["weight"].as_i64().unwrap()).sum();
        assert_eq!(w, 1 + 1 + 4);

        let csv = text(&collect(&s, ExportFilter::default(), Format::Csv).await);
        let mut rdr = csv::Reader::from_reader(csv.as_bytes());
        let header: Vec<String> = rdr.headers().unwrap().iter().map(String::from).collect();
        assert_eq!(header, COLUMNS);
        assert_eq!(rdr.records().count(), 3);

        use ::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let pq = axum::body::Bytes::from(
            collect(&s, ExportFilter::default(), Format::Parquet)
                .await
                .concat(),
        );
        let b = ParquetRecordBatchReaderBuilder::try_new(pq).unwrap();
        let meta = b.metadata().file_metadata().key_value_metadata().unwrap();
        assert!(
            meta.iter()
                .any(|kv| kv.key == "peephole.format_version" && kv.value.as_deref() == Some("1"))
        );
        let schema = b.schema().clone();
        assert!(matches!(
            schema.field_with_name("ts").unwrap().data_type(),
            arrow::datatypes::DataType::Timestamp(arrow::datatypes::TimeUnit::Millisecond, Some(_))
        ));
        let rows: usize = b.build().unwrap().map(|b| b.unwrap().num_rows()).sum();
        assert_eq!(rows, 3);
    }

    /// Large per-IP data (an nmap XML) repeated on many rows: the export
    /// goes out in chunks of bounded size, not a page at a time.
    #[tokio::test]
    async fn chunks_stay_bounded_with_large_per_ip_data() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let row = s.upsert_ip("203.0.113.6".parse().unwrap()).await.unwrap();
        let job = match s.enqueue_scan(row.id, 2, 24).await.unwrap() {
            crate::store::scans::EnqueueOutcome::Queued(j) => j,
            o => panic!("{o:?}"),
        };
        s.next_queued_job().await.unwrap();
        let xml = format!("<nmaprun>{}</nmaprun>", "<host/>".repeat(30_000));
        s.finish_job(
            job,
            Some(&crate::scan::nmap_xml::ScanResult {
                os_guess: None,
                raw_xml: xml.into_bytes(),
                ports: vec![],
            }),
            None,
        )
        .await
        .unwrap();
        sqlx::query(
            "WITH RECURSIVE k(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM k WHERE x < 200)
             INSERT INTO requests (uid, ts, ip_id, method, path, headers_json, labels_json)
             SELECT 'u' || x, datetime('2026-01-01', '+' || x || ' seconds'), ?, 'GET', '/', '[]', '[]'
             FROM k",
        )
        .bind(row.id)
        .execute(&s.pool)
        .await
        .unwrap();
        for format in [Format::Csv, Format::Jsonl] {
            let parts = collect(&s, ExportFilter::default(), format).await;
            let total: usize = parts.iter().map(|b| b.len()).sum();
            let largest = parts.iter().map(|b| b.len()).max().unwrap();
            assert!(total > 30 * 1024 * 1024, "{format:?}: {total}");
            assert!(
                largest < CHUNK_BYTES + 1024 * 1024,
                "{format:?}: a {largest}-byte chunk"
            );
        }
        use ::parquet::file::reader::{FileReader, SerializedFileReader};
        let pq = collect(&s, ExportFilter::default(), Format::Parquet).await;
        let reader = SerializedFileReader::new(axum::body::Bytes::from(pq.concat())).unwrap();
        assert_eq!(reader.metadata().file_metadata().num_rows(), 200);
        assert!(
            reader.metadata().num_row_groups() > 1,
            "row groups bounded by size"
        );
    }

    #[tokio::test]
    async fn a_label_filter_leaves_out_light_rows() {
        let (s, _d) = rich().await;
        let f = ExportFilter {
            label: Some("bait".into()),
            ..Default::default()
        };
        let out = text(&collect(&s, f, Format::Jsonl).await);
        assert_eq!(out.lines().count(), 1, "{out}");
        let r: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
        assert_eq!(
            r["weight"], 3,
            "without light rows it carries its predecessors"
        );
        let f = ExportFilter {
            ip: Some("203.0.113.5".into()),
            ..Default::default()
        };
        assert_eq!(
            text(&collect(&s, f, Format::Jsonl).await).lines().count(),
            3
        );
    }

    #[tokio::test]
    async fn redistributable_leaves_out_restricted_providers() {
        let (s, _d) = rich().await;
        use futures::TryStreamExt;
        for format in [Format::Csv, Format::Jsonl, Format::Parquet] {
            let parts: Vec<axum::body::Bytes> = stream_requests(
                s.clone(),
                ExportFilter::default(),
                format,
                ExportOptions {
                    mode: Mode::Redistributable,
                    ..Default::default()
                },
            )
            .try_collect()
            .await
            .unwrap();
            let all = parts.concat();
            let hay = String::from_utf8_lossy(&all);
            for gone in ["abuseipdb", "maxmind", "DTAG", "Germany"] {
                assert!(!hay.contains(gone), "{format:?} contains {gone}");
            }
            if format == Format::Jsonl {
                let r: serde_json::Value =
                    serde_json::from_str(hay.lines().next().unwrap()).unwrap();
                assert_eq!(r["intel"].as_array().unwrap().len(), 1, "tor only");
                assert_eq!(r["is_tor"], false);
            }
        }
    }
}
