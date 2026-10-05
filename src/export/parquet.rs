//! The export as typed Parquet: real timestamps, lists, binary blobs; the
//! per-IP JSON columns as text. Footer metadata names the format version,
//! the mode and the filter.
use super::{ExportFilter, ExportRow, Mode};
use anyhow::Result;
use arrow::array::{
    ArrayRef, BinaryBuilder, BooleanBuilder, Int64Builder, ListBuilder, StringBuilder,
    StructBuilder, TimestampMillisecondBuilder,
};
use arrow::datatypes::{DataType, Field, Fields, Schema, SchemaRef, TimeUnit};
use arrow::record_batch::RecordBatch;
use parquet::file::metadata::KeyValue;
use std::sync::{Arc, Mutex};

/// Version of this file layout (`peephole.format_version`).
pub const FORMAT_VERSION: &str = "1";

fn header_fields() -> Fields {
    Fields::from(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, false),
    ])
}

fn schema() -> SchemaRef {
    let s = |n: &str, null| Field::new(n, DataType::Utf8, null);
    let i = |n: &str, null| Field::new(n, DataType::Int64, null);
    let b = |n: &str| Field::new(n, DataType::Binary, true);
    let flag = |n: &str, null| Field::new(n, DataType::Boolean, null);
    Arc::new(Schema::new(vec![
        s("kind", false),
        s("uid", false),
        s("node", false),
        s("node_id", false),
        s("build", false),
        Field::new(
            "ts",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        s("ip", false),
        s("method", false),
        s("path", false),
        s("query", true),
        s("http_version", true),
        s("host", true),
        s("user_agent", true),
        Field::new(
            "headers",
            DataType::List(Arc::new(Field::new(
                "item",
                DataType::Struct(header_fields()),
                true,
            ))),
            false,
        ),
        b("body"),
        i("body_size", true),
        i("body_truncated_at", true),
        s("transport", true),
        flag("via_proxy", true),
        b("raw_head"),
        b("tls_client_hello"),
        s("ja4", true),
        s("ja4h", true),
        s("answer", true),
        i("decoy_v", true),
        Field::new(
            "canary_used_from",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        i("status", true),
        i("unrecorded", false),
        i("weight", false),
        Field::new(
            "labels",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new(
            "owasp",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        i("severity", true),
        i("scan_level", true),
        s("rules", true),
        flag("fp_claim", false),
        s("country", true),
        i("asn", true),
        s("asn_org", true),
        flag("is_tor", true),
        s("intel", false),
        s("scans", false),
        s("fingerprints", false),
        s("message", false),
        s("timestamp_desc", false),
    ]))
}

fn strs<'a>(it: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    let mut b = StringBuilder::new();
    for v in it {
        b.append_option(v);
    }
    Arc::new(b.finish())
}

fn ints(it: impl Iterator<Item = Option<i64>>) -> ArrayRef {
    let mut b = Int64Builder::new();
    for v in it {
        b.append_option(v);
    }
    Arc::new(b.finish())
}

fn bools(it: impl Iterator<Item = Option<bool>>) -> ArrayRef {
    let mut b = BooleanBuilder::new();
    for v in it {
        b.append_option(v);
    }
    Arc::new(b.finish())
}

fn bins<'a>(it: impl Iterator<Item = Option<&'a [u8]>>) -> ArrayRef {
    let mut b = BinaryBuilder::new();
    for v in it {
        b.append_option(v);
    }
    Arc::new(b.finish())
}

fn batch(schema: SchemaRef, rows: &[ExportRow]) -> Result<RecordBatch> {
    let mut ts = TimestampMillisecondBuilder::new().with_timezone("UTC");
    for r in rows {
        ts.append_value(r.ts_ms);
    }
    let mut headers = ListBuilder::new(StructBuilder::from_fields(header_fields(), 0));
    for r in rows {
        let st = headers.values();
        for (n, v) in &r.headers {
            st.field_builder::<StringBuilder>(0)
                .expect("name builder")
                .append_value(n);
            st.field_builder::<StringBuilder>(1)
                .expect("value builder")
                .append_value(v);
            st.append(true);
        }
        headers.append(true);
    }
    let mut labels = ListBuilder::new(StringBuilder::new());
    for r in rows {
        for l in &r.labels {
            labels.values().append_value(l);
        }
        labels.append(true);
    }
    let mut used_from = ListBuilder::new(StringBuilder::new());
    for r in rows {
        for u in &r.canary_used_from {
            used_from.values().append_value(u);
        }
        used_from.append(true);
    }
    let mut owasp = ListBuilder::new(StringBuilder::new());
    for r in rows {
        for t in &r.owasp {
            owasp.values().append_value(t);
        }
        owasp.append(true);
    }
    let json = |f: fn(&ExportRow) -> &str| -> ArrayRef {
        let mut b = StringBuilder::new();
        for r in rows {
            b.append_value(f(r));
        }
        Arc::new(b.finish())
    };
    let columns: Vec<ArrayRef> = vec![
        strs(rows.iter().map(|r| Some(r.kind))),
        strs(rows.iter().map(|r| Some(r.uid.as_str()))),
        strs(rows.iter().map(|r| Some(r.node.as_str()))),
        strs(rows.iter().map(|r| Some(r.node_id.as_str()))),
        strs(rows.iter().map(|r| Some(r.build.as_str()))),
        Arc::new(ts.finish()),
        strs(rows.iter().map(|r| Some(r.ip.as_str()))),
        strs(rows.iter().map(|r| Some(r.method.as_str()))),
        strs(rows.iter().map(|r| Some(r.path.as_str()))),
        strs(rows.iter().map(|r| r.query.as_deref())),
        strs(rows.iter().map(|r| r.http_version.as_deref())),
        strs(rows.iter().map(|r| r.host.as_deref())),
        strs(rows.iter().map(|r| r.user_agent.as_deref())),
        Arc::new(headers.finish()),
        bins(rows.iter().map(|r| r.body.as_deref())),
        ints(rows.iter().map(|r| r.body_size)),
        ints(rows.iter().map(|r| r.body_truncated_at)),
        strs(rows.iter().map(|r| r.transport.as_deref())),
        bools(rows.iter().map(|r| r.via_proxy)),
        bins(rows.iter().map(|r| r.raw_head.as_deref())),
        bins(rows.iter().map(|r| r.tls_client_hello.as_deref())),
        strs(rows.iter().map(|r| r.ja4.as_deref())),
        strs(rows.iter().map(|r| r.ja4h.as_deref())),
        strs(rows.iter().map(|r| r.answer.as_deref())),
        ints(rows.iter().map(|r| r.decoy_v)),
        Arc::new(used_from.finish()),
        ints(rows.iter().map(|r| r.status)),
        ints(rows.iter().map(|r| Some(r.unrecorded))),
        ints(rows.iter().map(|r| Some(r.weight))),
        Arc::new(labels.finish()),
        Arc::new(owasp.finish()),
        ints(rows.iter().map(|r| r.severity)),
        ints(rows.iter().map(|r| r.scan_level)),
        strs(rows.iter().map(|r| r.rules.as_deref())),
        bools(rows.iter().map(|r| Some(r.fp_claim))),
        strs(rows.iter().map(|r| r.country.as_deref())),
        ints(rows.iter().map(|r| r.asn)),
        strs(rows.iter().map(|r| r.asn_org.as_deref())),
        bools(rows.iter().map(|r| r.is_tor)),
        json(|r| &r.intel),
        json(|r| &r.scans),
        json(|r| &r.fingerprints),
        strs(
            rows.iter()
                .map(|r| Some(r.message()))
                .collect::<Vec<_>>()
                .iter()
                .map(|m| m.as_deref()),
        ),
        strs(rows.iter().map(|r| Some(r.timestamp_desc()))),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

/// Output the writer has produced and the caller has not taken yet.
#[derive(Clone, Default)]
struct Pending(Arc<Mutex<Vec<u8>>>);

impl Pending {
    fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }
}

impl std::io::Write for Pending {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A Parquet file written as it is produced: every [`ParquetStream::write`]
/// becomes one row group and returns the bytes it adds to the file, and
/// [`ParquetStream::finish`] returns the footer. Parquet writes strictly
/// forward (the footer records the row-group offsets), so the file can go
/// to the client while it is written; memory holds one row group at most.
pub struct ParquetStream {
    writer: parquet::arrow::ArrowWriter<Pending>,
    out: Pending,
    schema: SchemaRef,
}

impl ParquetStream {
    pub fn new(filter: &ExportFilter, mode: Mode) -> Result<Self> {
        let out = Pending::default();
        let schema = schema();
        let meta = vec![
            KeyValue::new("peephole.format_version".into(), FORMAT_VERSION.to_string()),
            KeyValue::new(
                "peephole.version".into(),
                env!("CARGO_PKG_VERSION").to_string(),
            ),
            KeyValue::new(
                "peephole.exported_at".into(),
                chrono::Utc::now().to_rfc3339(),
            ),
            KeyValue::new(
                "peephole.mode".into(),
                match mode {
                    Mode::Full => "full",
                    Mode::Redistributable => "redistributable",
                }
                .to_string(),
            ),
            KeyValue::new(
                "peephole.filter".into(),
                serde_json::json!({
                    "from": filter.from, "to": filter.to, "ip": filter.ip,
                    "label": filter.label, "min_severity": filter.min_severity,
                })
                .to_string(),
            ),
        ];
        let props = parquet::file::properties::WriterProperties::builder()
            .set_max_row_group_row_count(Some(super::STREAM_PAGE as usize))
            .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
            .set_key_value_metadata(Some(meta))
            .build();
        let writer =
            parquet::arrow::ArrowWriter::try_new(out.clone(), schema.clone(), Some(props))?;
        Ok(Self {
            writer,
            out,
            schema,
        })
    }

    /// Append `rows` as a row group; returns the bytes written so far.
    pub fn write(&mut self, rows: &[ExportRow]) -> Result<Vec<u8>> {
        self.writer.write(&batch(self.schema.clone(), rows)?)?;
        self.writer.flush()?;
        Ok(self.out.take())
    }

    /// Close the file; returns its remaining bytes (the footer).
    pub fn finish(self) -> Result<Vec<u8>> {
        self.writer.close()?;
        Ok(self.out.take())
    }
}
