use anyhow::Result;
use arrow::array::{BooleanArray, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use std::sync::Arc;
use super::ExportRow;

pub fn requests_parquet(rows: &[ExportRow]) -> Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
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
    ]));
    let opt = |v: &Option<String>| v.clone();
    let batch = RecordBatch::try_new(schema.clone(), vec![
        Arc::new(StringArray::from(rows.iter().map(|r| r.ts.as_str()).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| r.ip.as_str()).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| r.method.as_str()).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| r.path.as_str()).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| r.query.clone()).collect::<Vec<_>>())),
        Arc::new(Int64Array::from(rows.iter().map(|r| r.severity).collect::<Vec<_>>())),
        Arc::new(Int64Array::from(rows.iter().map(|r| r.scan_level).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| r.labels.join(";")).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| opt(&r.country)).collect::<Vec<_>>())),
        Arc::new(Int64Array::from(rows.iter().map(|r| r.asn).collect::<Vec<_>>())),
        Arc::new(StringArray::from(rows.iter().map(|r| opt(&r.asn_org)).collect::<Vec<_>>())),
        Arc::new(BooleanArray::from(rows.iter().map(|r| r.is_tor).collect::<Vec<_>>())),
    ])?;
    let mut buf = Vec::new();
    let mut writer = parquet::arrow::ArrowWriter::try_new(&mut buf, schema, None)?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(buf)
}
