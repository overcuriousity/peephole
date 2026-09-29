use anyhow::Result;
use super::Store;

impl Store {
    pub async fn save_credential(&self, cred_id: &[u8], passkey_json: &str, label: Option<&str>) -> Result<()> {
        sqlx::query("INSERT INTO credentials (cred_id, passkey_json, created_at, label) VALUES (?,?,datetime('now'),?)")
            .bind(cred_id).bind(passkey_json).bind(label).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn load_credentials(&self) -> Result<Vec<(Vec<u8>, String)>> {
        Ok(sqlx::query_as("SELECT cred_id, passkey_json FROM credentials ORDER BY id")
            .fetch_all(&self.pool).await?)
    }

    pub async fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        sqlx::query("DELETE FROM credentials WHERE cred_id = ?")
            .bind(cred_id).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn create_session(&self) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO sessions (id, created_at, expires_at) VALUES (?,datetime('now'),datetime('now','+12 hours'))")
            .bind(&id).execute(&self.pool).await?;
        Ok(id)
    }

    pub async fn validate_session(&self, id: &str) -> Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions WHERE id = ? AND expires_at > datetime('now')")
            .bind(id).fetch_one(&self.pool).await?;
        Ok(n == 1)
    }

    pub async fn destroy_session(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?").bind(id).execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::store::Store;

    #[tokio::test]
    async fn credential_roundtrip_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.save_credential(b"cred-1", r#"{"k":"v"}"#, Some("yubikey-5")).await.unwrap();
        s.save_credential(b"cred-2", r#"{"k":"w"}"#, None).await.unwrap();
        let all = s.load_credentials().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, b"cred-1");
        s.delete_credential(b"cred-2").await.unwrap();
        assert_eq!(s.load_credentials().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = s.create_session().await.unwrap();
        assert!(s.validate_session(&id).await.unwrap());
        s.destroy_session(&id).await.unwrap();
        assert!(!s.validate_session(&id).await.unwrap());
    }
}
