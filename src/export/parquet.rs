use super::ExportRow;
use anyhow::Result;
use arrow::array::{BooleanArray, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use arrow::record_batch::RecordBatch;
use std::sync::{Arc, Mutex};

fn schema() -> SchemaRef {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Utf8, false),
        Field::new("ip", DataType::Utf8, false),
        Field::new("method", DataType::Utf8, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("query", DataType::Utf8, true),
        Field::new("severity", DataType::Int64, false),
        Field::new("scan_level", DataType::Int64, false),
        Field::new("labels", DataType::Utf8, false),
        Field::new("country", DataType::Utf8, true),
        Field::new("asn", DataType::Int64, true),
        Field::new("asn_org", DataType::Utf8, true),
        Field::new("is_tor", DataType::Boolean, false),
    ]))
}

fn batch(schema: SchemaRef, rows: &[ExportRow]) -> Result<RecordBatch> {
    Ok(RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.ts.as_str()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.ip.as_str()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.query.as_deref()).collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(
                rows.iter().map(|r| r.severity).collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(
                rows.iter().map(|r| r.scan_level).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter().map(|r| r.labels.join(";")).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|r| r.country.as_deref())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int64Array::from(
                rows.iter().map(|r| r.asn).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                rows.iter()
                    .map(|r| r.asn_org.as_deref())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                rows.iter().map(|r| r.is_tor).collect::<Vec<_>>(),
            )),
        ],
    )?)
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
    pub fn new() -> Result<Self> {
        let out = Pending::default();
        let schema = schema();
        let props = parquet::file::properties::WriterProperties::builder()
            .set_max_row_group_row_count(Some(super::STREAM_PAGE as usize))
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

/// A whole Parquet file in memory (small exports and tests).
pub fn requests_parquet(rows: &[ExportRow]) -> Result<Vec<u8>> {
    let mut w = ParquetStream::new()?;
    let mut out = vec![];
    for chunk in rows.chunks(super::STREAM_PAGE as usize) {
        out.extend(w.write(chunk)?);
    }
    out.extend(w.finish()?);
    Ok(out)
}
