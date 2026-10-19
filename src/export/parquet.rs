//! The export as typed Parquet: real timestamps, lists, binary blobs; the
//! per-IP JSON columns as text. Footer metadata names the format version,
//! the mode and the filter.
use super::{ExportFilter, ExportRow, Mode};
use crate::lock::MutexExt;
use crate::store::Store;
use crate::store::uploads::{UploadMeta, UploadQuery};
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
        s("decoy_in", true),
        Field::new(
            "canary_used_from",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        i("status", true),
        i("held_ms", true),
        s("persona", true),
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
        flag("is_tor_relay", true),
        s("campaign", true),
        s("intel", false),
        s("scans", false),
        s("names", false),
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
        strs(rows.iter().map(|r| r.decoy_in.as_deref())),
        Arc::new(used_from.finish()),
        ints(rows.iter().map(|r| r.status)),
        ints(rows.iter().map(|r| r.held_ms)),
        strs(rows.iter().map(|r| r.persona.as_deref())),
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
        bools(rows.iter().map(|r| r.is_tor_relay)),
        strs(rows.iter().map(|r| r.campaign.as_deref())),
        json(|r| &r.intel),
        json(|r| &r.scans),
        json(|r| &r.names),
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
        std::mem::take(&mut *self.0.lock_or_recover())
    }
}

impl std::io::Write for Pending {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock_or_recover().extend_from_slice(buf);
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

/// Version of the `uploads` file layout (`peephole.format_version`).
pub const UPLOADS_FORMAT_VERSION: &str = "1";

/// Uploads read per row group.
const UPLOADS_PAGE: i64 = 5_000;

/// The `uploads` table (MIK-121): metadata and hash only. It has no
/// content column, and nothing that fills it reads content.
pub fn uploads_schema() -> SchemaRef {
    let s = |n: &str, null| Field::new(n, DataType::Utf8, null);
    let flag = |n: &str| Field::new(n, DataType::Boolean, false);
    Arc::new(Schema::new(vec![
        s("uid", false),
        s("request_uid", false),
        s("node_id", true),
        Field::new(
            "ts",
            DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            false,
        ),
        s("ip", false),
        s("kind", false),
        s("filename", true),
        s("sniffed_type", false),
        Field::new("size", DataType::Int64, false),
        flag("truncated"),
        s("sha256", false),
        s("answered_path", false),
        flag("path_is_prefix"),
        s("content_state", false),
    ]))
}

fn uploads_batch(schema: SchemaRef, rows: &[UploadMeta]) -> Result<RecordBatch> {
    let hex = |b: &[u8]| data_encoding::HEXLOWER.encode(b);
    let node: Vec<Option<String>> = rows.iter().map(|r| r.node_id.as_deref().map(hex)).collect();
    let sha: Vec<String> = rows.iter().map(|r| hex(&r.sha256)).collect();
    let mut ts = TimestampMillisecondBuilder::new().with_timezone("UTC");
    for r in rows {
        ts.append_value(super::millis(&r.ts));
    }
    let columns: Vec<ArrayRef> = vec![
        strs(rows.iter().map(|r| Some(r.uid.as_str()))),
        strs(rows.iter().map(|r| Some(r.request_uid.as_str()))),
        strs(node.iter().map(|n| n.as_deref())),
        Arc::new(ts.finish()),
        strs(rows.iter().map(|r| Some(r.ip.as_str()))),
        strs(rows.iter().map(|r| Some(r.kind.as_str()))),
        strs(rows.iter().map(|r| r.filename.as_deref())),
        strs(rows.iter().map(|r| Some(r.sniffed_type.as_str()))),
        ints(rows.iter().map(|r| Some(r.size))),
        bools(rows.iter().map(|r| Some(r.truncated))),
        strs(sha.iter().map(|h| Some(h.as_str()))),
        strs(rows.iter().map(|r| Some(r.answered_path.as_str()))),
        bools(rows.iter().map(|r| Some(r.path_is_prefix))),
        strs(rows.iter().map(|r| Some(r.content_state.as_str()))),
    ];
    Ok(RecordBatch::try_new(schema, columns)?)
}

/// The `uploads` table within `filter`'s time and IP bounds, as one
/// Parquet file, oldest first. Labels and severity belong to requests and
/// do not narrow it.
pub async fn uploads(store: &Store, filter: &ExportFilter) -> Result<Vec<u8>> {
    let out = Pending::default();
    let schema = uploads_schema();
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
        .set_key_value_metadata(Some(vec![
            KeyValue::new(
                "peephole.format_version".into(),
                UPLOADS_FORMAT_VERSION.to_string(),
            ),
            KeyValue::new("peephole.table".into(), "uploads".to_string()),
            KeyValue::new(
                "peephole.version".into(),
                env!("CARGO_PKG_VERSION").to_string(),
            ),
            KeyValue::new(
                "peephole.exported_at".into(),
                chrono::Utc::now().to_rfc3339(),
            ),
        ]))
        .build();
    let mut writer =
        parquet::arrow::ArrowWriter::try_new(out.clone(), schema.clone(), Some(props))?;
    let mut after = 0;
    loop {
        let rows = store
            .uploads_meta(
                &UploadQuery {
                    after: Some(after),
                    from: filter.from.as_deref(),
                    to: filter.to.as_deref(),
                    ip: filter.ip.as_deref(),
                    ..Default::default()
                },
                UPLOADS_PAGE,
            )
            .await?;
        let Some(last) = rows.last() else { break };
        after = last.id;
        writer.write(&uploads_batch(schema.clone(), &rows)?)?;
        if (rows.len() as i64) < UPLOADS_PAGE {
            break;
        }
    }
    writer.close()?;
    Ok(out.take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_uploads_schema_has_no_content_column() {
        let names: Vec<_> = uploads_schema()
            .fields()
            .iter()
            .map(|f| f.name().clone())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| !n.contains("content") || n == "content_state"),
            "{names:?}"
        );
        assert!(
            names.iter().all(|n| n != "body" && n != "bytes"),
            "{names:?}"
        );
        assert!(names.contains(&"sha256".to_string()));
    }

    #[tokio::test]
    async fn uploads_export_is_metadata_and_hash_only() {
        use ::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let marker = b"<?php echo 'MARK-9c1e4f'; ?>";
        crate::store::uploads::seed_upload(&s, "203.0.113.40", "/a.php", marker).await;
        crate::store::uploads::seed_upload(&s, "198.51.100.41", "/b.php", b"other").await;
        let pq = uploads(&s, &ExportFilter::default()).await.unwrap();
        assert!(
            !pq.windows(11).any(|w| w == b"MARK-9c1e4f"),
            "content leaked into the file"
        );
        let b = ParquetRecordBatchReaderBuilder::try_new(axum::body::Bytes::from(pq)).unwrap();
        assert_eq!(b.schema().fields().len(), uploads_schema().fields().len());
        let batches: Vec<_> = b.build().unwrap().map(|r| r.unwrap()).collect();
        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        let sha = batches[0]
            .column_by_name("sha256")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .unwrap()
            .value(0)
            .to_string();
        use sha2::Digest;
        assert_eq!(
            sha,
            data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(marker))
        );
        // The IP bound narrows it.
        let f = ExportFilter {
            ip: Some("198.51.100.41".into()),
            ..Default::default()
        };
        let pq = uploads(&s, &f).await.unwrap();
        let n: usize = ParquetRecordBatchReaderBuilder::try_new(axum::body::Bytes::from(pq))
            .unwrap()
            .build()
            .unwrap()
            .map(|r| r.unwrap().num_rows())
            .sum();
        assert_eq!(n, 1);
    }
}
