use super::Store;
use anyhow::Result;

impl Store {
    pub async fn save_credential(
        &self,
        cred_id: &[u8],
        passkey_json: &str,
        label: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO credentials (cred_id, passkey_json, created_at, label) VALUES (?,?,datetime('now'),?)")
            .bind(cred_id).bind(passkey_json).bind(label).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn load_credentials(&self) -> Result<Vec<(Vec<u8>, String)>> {
        Ok(
            sqlx::query_as("SELECT cred_id, passkey_json FROM credentials ORDER BY id")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Replace a key's stored passkey JSON (post-authentication counter and
    /// backup-state updates).
    pub async fn update_credential(&self, cred_id: &[u8], passkey_json: &str) -> Result<()> {
        sqlx::query("UPDATE credentials SET passkey_json = ? WHERE cred_id = ?")
            .bind(passkey_json)
            .bind(cred_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        sqlx::query("DELETE FROM credentials WHERE cred_id = ?")
            .bind(cred_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a key only while at least one other remains, atomically, so two
    /// concurrent deletes cannot both pass a "more than one key" check and
    /// leave the admin locked out. Returns whether a row was deleted.
    pub async fn delete_credential_keeping_last(&self, cred_id: &[u8]) -> Result<bool> {
        let r = sqlx::query(
            "DELETE FROM credentials
             WHERE cred_id = ? AND (SELECT COUNT(*) FROM credentials) > 1",
        )
        .bind(cred_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    pub async fn create_session(&self) -> Result<String> {
        // Opportunistic cleanup of stale rows; cheap and keeps the tables bounded.
        let _ = self.prune_expired_auth().await;
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO sessions (id, created_at, expires_at) VALUES (?,datetime('now'),datetime('now','+12 hours'))")
            .bind(&id).execute(&self.pool).await?;
        Ok(id)
    }

    /// Delete expired sessions and WebAuthn ceremony states.
    pub async fn prune_expired_auth(&self) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE expires_at <= datetime('now')")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM webauthn_states WHERE expires_at <= datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store a WebAuthn ceremony state server-side and return its random id.
    /// The id is all the client ever holds; it cannot see or alter the state.
    pub async fn put_webauthn_state(
        &self,
        kind: &str,
        state_json: &str,
        label: Option<&str>,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO webauthn_states (id, kind, state_json, label, created_at, expires_at)
             VALUES (?,?,?,?,datetime('now'),datetime('now','+10 minutes'))",
        )
        .bind(&id)
        .bind(kind)
        .bind(state_json)
        .bind(label)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Consume a ceremony state: returns `(state_json, label)` and deletes the
    /// row in the same statement, so a captured id works at most once and an
    /// expired one never works.
    pub async fn take_webauthn_state(
        &self,
        id: &str,
        kind: &str,
    ) -> Result<Option<(String, Option<String>)>> {
        Ok(sqlx::query_as(
            "DELETE FROM webauthn_states
             WHERE id = ? AND kind = ? AND expires_at > datetime('now')
             RETURNING state_json, label",
        )
        .bind(id)
        .bind(kind)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn validate_session(&self, id: &str) -> Result<bool> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sessions WHERE id = ? AND expires_at > datetime('now')",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(n == 1)
    }

    pub async fn destroy_session(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
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
        s.save_credential(b"cred-1", r#"{"k":"v"}"#, Some("yubikey-5"))
            .await
            .unwrap();
        s.save_credential(b"cred-2", r#"{"k":"w"}"#, None)
            .await
            .unwrap();
        let all = s.load_credentials().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].0, b"cred-1");
        s.delete_credential(b"cred-2").await.unwrap();
        assert_eq!(s.load_credentials().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn webauthn_state_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = s
            .put_webauthn_state("auth", r#"{"x":1}"#, None)
            .await
            .unwrap();
        // Wrong kind never matches.
        assert!(s.take_webauthn_state(&id, "reg").await.unwrap().is_none());
        // First take succeeds.
        let got = s.take_webauthn_state(&id, "auth").await.unwrap();
        assert_eq!(got.unwrap().0, r#"{"x":1}"#);
        // Second take finds nothing (deleted in the same statement).
        assert!(s.take_webauthn_state(&id, "auth").await.unwrap().is_none());
        // An unknown id never matches.
        assert!(
            s.take_webauthn_state("nope", "auth")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_keeps_last_key() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.save_credential(b"a", "{}", None).await.unwrap();
        s.save_credential(b"b", "{}", None).await.unwrap();
        assert!(s.delete_credential_keeping_last(b"a").await.unwrap());
        // Only one left: refuse to delete it.
        assert!(!s.delete_credential_keeping_last(b"b").await.unwrap());
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
