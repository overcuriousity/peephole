use super::Store;
use anyhow::Result;

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_fingerprint(
        &self,
        request_id: Option<i64>,
        ip_id: i64,
        fp_hash: &str,
        visitor_id: Option<&str>,
        attributes_json: &str,
        behavior_summary_json: &str,
        event_blob: &[u8],
    ) -> Result<i64> {
        let compressed = zstd::encode_all(event_blob, 3)?;
        let r = sqlx::query(
            "INSERT INTO fingerprints (request_id, ip_id, ts, fp_hash, visitor_id, attributes_json, behavior_summary_json, event_blob)
             VALUES (?,?,datetime('now'),?,?,?,?,?)",
        )
        .bind(request_id).bind(ip_id).bind(fp_hash).bind(visitor_id)
        .bind(attributes_json).bind(behavior_summary_json).bind(&compressed)
        .execute(&self.pool).await?;
        Ok(r.last_insert_rowid())
    }

    /// Distinct *other* IPs sharing this fingerprint (spec §8.2 correlation).
    pub async fn fingerprint_ip_count(&self, fp_hash: &str, exclude_ip_id: i64) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(DISTINCT ip_id) FROM fingerprints WHERE fp_hash = ? AND ip_id != ?",
        )
        .bind(fp_hash)
        .bind(exclude_ip_id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn fingerprint_by_token(
        &self,
        token: &str,
    ) -> Result<Option<(i64, String, String, String)>> {
        Ok(sqlx::query_as(
            "SELECT f.ip_id, f.fp_hash, f.attributes_json, f.behavior_summary_json
             FROM fingerprints f JOIN requests r ON f.request_id = r.id
             WHERE r.page_token = ? ORDER BY f.id DESC LIMIT 1",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?)
    }
}
