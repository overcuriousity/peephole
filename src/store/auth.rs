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
        let mut tx = self.pool.begin().await?;
        for sql in [
            "DELETE FROM credentials WHERE cred_id = ?",
            "DELETE FROM sessions WHERE cred_id = ?",
        ] {
            sqlx::query(sql).bind(cred_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Delete a key only while at least one other remains, atomically, so two
    /// concurrent deletes cannot both pass a "more than one key" check and
    /// leave the admin locked out. Returns whether a row was deleted.
    /// Sessions signed in with the key end with it.
    pub async fn delete_credential_keeping_last(&self, cred_id: &[u8]) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let r = sqlx::query(
            "DELETE FROM credentials
             WHERE cred_id = ? AND (SELECT COUNT(*) FROM credentials) > 1",
        )
        .bind(cred_id)
        .execute(&mut *tx)
        .await?;
        let deleted = r.rows_affected() > 0;
        if deleted {
            sqlx::query("DELETE FROM sessions WHERE cred_id = ?")
                .bind(cred_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(deleted)
    }

    /// A session not bound to a key (tests and tooling).
    pub async fn create_session(&self) -> Result<String> {
        self.create_session_for(None, None).await
    }

    /// Start a session for the key `cred_id` (deleting the key ends it) and
    /// end `replacing`, the session the browser held before, if any. Returns
    /// the token for the cookie; only its SHA-256 is stored.
    pub async fn create_session_for(
        &self,
        cred_id: Option<&[u8]>,
        replacing: Option<&str>,
    ) -> Result<String> {
        // Opportunistic cleanup of stale rows; cheap and keeps the tables bounded.
        let _ = self.prune_expired_auth().await;
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let mut tx = self.pool.begin().await?;
        if let Some(old) = replacing {
            sqlx::query("DELETE FROM sessions WHERE id_hash = ?")
                .bind(token_hash(old))
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO sessions (id_hash, cred_id, created_at, last_seen, expires_at)
             VALUES (?, ?, datetime('now'), datetime('now'), datetime('now', '+{SESSION_HOURS} hours'))"
        )))
        .bind(token_hash(&token))
        .bind(cred_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(token)
    }

    /// Delete expired sessions (absolute or idle) and WebAuthn ceremony states.
    pub async fn prune_expired_auth(&self) -> Result<()> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM sessions WHERE expires_at <= datetime('now')
                OR last_seen <= datetime('now', '-{SESSION_IDLE_MINUTES} minutes')"
        )))
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM webauthn_states WHERE expires_at <= datetime('now')")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Store a WebAuthn ceremony state server-side and return its random id.
    /// The id is all the client ever holds; it cannot see or alter the state.
    /// At most [`MAX_OPEN_CEREMONIES`] are open, since anonymous clients start
    /// sign-ins. At the cap the oldest open ceremony makes room rather than
    /// refusing, so a flood of sign-in starts cannot lock the admin out: a
    /// sign-in (`auth`) evicts only the oldest sign-in, an enrollment (only
    /// started when authorised) the oldest of any kind. `None` when nothing
    /// may be evicted.
    pub async fn put_webauthn_state(
        &self,
        kind: &str,
        state_json: &str,
        label: Option<&str>,
    ) -> Result<Option<String>> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM webauthn_states WHERE rowid = (
               SELECT rowid FROM webauthn_states
               WHERE expires_at > datetime('now') AND (kind = ?1 OR ?1 <> 'auth')
               ORDER BY created_at, rowid LIMIT 1)
             AND (SELECT COUNT(*) FROM webauthn_states
                  WHERE expires_at > datetime('now')) >= ?2",
        )
        .bind(kind)
        .bind(MAX_OPEN_CEREMONIES)
        .execute(&mut *tx)
        .await?;
        let stored = sqlx::query(
            "INSERT INTO webauthn_states (id, kind, state_json, label, created_at, expires_at)
             SELECT ?, ?, ?, ?, datetime('now'), datetime('now','+10 minutes')
             WHERE (SELECT COUNT(*) FROM webauthn_states
                    WHERE expires_at > datetime('now')) < ?",
        )
        .bind(&id)
        .bind(kind)
        .bind(state_json)
        .bind(label)
        .bind(MAX_OPEN_CEREMONIES)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        tx.commit().await?;
        Ok(stored.then_some(id))
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

    /// Whether `token` is a live session: within its absolute lifetime and
    /// used within the idle timeout. Use slides the idle timeout (at most
    /// one write a minute per session).
    pub async fn validate_session(&self, token: &str) -> Result<bool> {
        let hash = token_hash(token);
        let row: Option<i64> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT last_seen < datetime('now', '-60 seconds') FROM sessions
             WHERE id_hash = ? AND expires_at > datetime('now')
               AND last_seen > datetime('now', '-{SESSION_IDLE_MINUTES} minutes')"
        )))
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(touch) = row else {
            return Ok(false);
        };
        if touch == 1 {
            sqlx::query("UPDATE sessions SET last_seen = datetime('now') WHERE id_hash = ?")
                .bind(&hash)
                .execute(&self.pool)
                .await?;
        }
        Ok(true)
    }

    pub async fn destroy_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id_hash = ?")
            .bind(token_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Whether the admin setup token `token` is the current one and unexpired.
    pub async fn setup_token_valid(&self, token: &str) -> Result<bool> {
        let (Some(hash), Some(expires)) = (
            self.intel_get(SETUP_TOKEN_HASH).await?,
            self.intel_get(SETUP_TOKEN_EXPIRES).await?,
        ) else {
            return Ok(false);
        };
        let live =
            chrono::DateTime::parse_from_rfc3339(&expires).is_ok_and(|t| t > chrono::Utc::now());
        Ok(live && hash == token_hash(token))
    }

    /// Issue a fresh setup token (replacing any earlier one), valid for
    /// [`SETUP_TOKEN_HOURS`]. Returns the token; only its hash is stored.
    pub async fn issue_setup_token(&self) -> Result<String> {
        let token = uuid::Uuid::new_v4().to_string();
        let expires = chrono::Utc::now() + chrono::Duration::hours(SETUP_TOKEN_HOURS);
        let mut tx = self.pool.begin().await?;
        for (k, v) in [
            (SETUP_TOKEN_HASH, token_hash(&token)),
            (SETUP_TOKEN_EXPIRES, expires.to_rfc3339()),
        ] {
            sqlx::query(
                "INSERT INTO intel_meta (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(k)
            .bind(v)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(token)
    }

    /// Mark the setup token used (the first key is enrolled).
    pub async fn consume_setup_token(&self) -> Result<()> {
        self.intel_set(SETUP_TOKEN_HASH, "consumed").await
    }

    /// The setup token's state, for deciding whether to issue a new one.
    pub async fn setup_token_state(&self) -> Result<SetupToken> {
        let hash = self.intel_get(SETUP_TOKEN_HASH).await?;
        let expires = self.intel_get(SETUP_TOKEN_EXPIRES).await?;
        Ok(match (hash.as_deref(), expires) {
            (None, _) | (Some("consumed"), _) => SetupToken::None,
            (Some(_), None) => SetupToken::Legacy,
            (Some(_), Some(e)) => match chrono::DateTime::parse_from_rfc3339(&e) {
                Ok(t) if t > chrono::Utc::now() => SetupToken::Live,
                _ => SetupToken::Expired,
            },
        })
    }

    /// Give a token issued before tokens expired a lifetime from now.
    pub async fn date_legacy_setup_token(&self) -> Result<()> {
        let expires = chrono::Utc::now() + chrono::Duration::hours(SETUP_TOKEN_HOURS);
        self.intel_set(SETUP_TOKEN_EXPIRES, &expires.to_rfc3339())
            .await
    }
}

/// Absolute session lifetime.
pub const SESSION_HOURS: i64 = 12;
/// Sessions end after this long without a request.
pub const SESSION_IDLE_MINUTES: i64 = 60;
/// Open (unexpired) WebAuthn ceremonies at most; more evict the oldest.
pub const MAX_OPEN_CEREMONIES: i64 = 256;
/// Lifetime of the first-run setup token.
pub const SETUP_TOKEN_HOURS: i64 = 24;
const SETUP_TOKEN_HASH: &str = "webauthn_setup_token_hash";
const SETUP_TOKEN_EXPIRES: &str = "webauthn_setup_token_expires";

/// The first-run setup token, as far as the database knows.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupToken {
    /// None issued, or the one issued was used.
    None,
    /// Issued and still valid.
    Live,
    /// Issued and expired.
    Expired,
    /// Issued by a build without expiry.
    Legacy,
}

/// What is stored for a session or setup token: hex SHA-256.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
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
            .unwrap()
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
        // Only a hash of the token is stored.
        let stored: String = sqlx::query_scalar("SELECT id_hash FROM sessions")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_ne!(stored, id);
        assert_eq!(stored, super::token_hash(&id));
        s.destroy_session(&id).await.unwrap();
        assert!(!s.validate_session(&id).await.unwrap());
    }

    async fn set_last_seen(s: &Store, modifier: &str) {
        sqlx::query("UPDATE sessions SET last_seen = datetime('now', ?)")
            .bind(modifier)
            .execute(&s.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn idle_sessions_expire_and_use_slides_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let id = s.create_session().await.unwrap();
        set_last_seen(&s, "-50 minutes").await;
        assert!(s.validate_session(&id).await.unwrap(), "within idle window");
        // Validation moved last_seen to now.
        let fresh: i64 =
            sqlx::query_scalar("SELECT last_seen > datetime('now', '-1 minute') FROM sessions")
                .fetch_one(&s.pool)
                .await
                .unwrap();
        assert_eq!(fresh, 1);
        set_last_seen(&s, "-61 minutes").await;
        assert!(!s.validate_session(&id).await.unwrap(), "idle too long");
        // The absolute lifetime still applies to a busy session.
        let id = s.create_session().await.unwrap();
        sqlx::query("UPDATE sessions SET expires_at = datetime('now', '-1 second')")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(!s.validate_session(&id).await.unwrap());
        s.prune_expired_auth().await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn a_new_login_replaces_the_old_session_and_key_deletion_ends_its_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        s.save_credential(b"a", "{}", None).await.unwrap();
        s.save_credential(b"b", "{}", None).await.unwrap();
        let first = s.create_session_for(Some(b"a"), None).await.unwrap();
        let second = s
            .create_session_for(Some(b"a"), Some(&first))
            .await
            .unwrap();
        assert!(!s.validate_session(&first).await.unwrap(), "replaced");
        assert!(s.validate_session(&second).await.unwrap());
        let with_b = s.create_session_for(Some(b"b"), None).await.unwrap();
        assert!(s.delete_credential_keeping_last(b"a").await.unwrap());
        assert!(!s.validate_session(&second).await.unwrap(), "key deleted");
        assert!(s.validate_session(&with_b).await.unwrap(), "other key");
    }

    #[tokio::test]
    async fn open_ceremonies_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let open = |s: &Store| {
            let pool = s.pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webauthn_states")
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        let reg = s
            .put_webauthn_state("reg", "{}", None)
            .await
            .unwrap()
            .unwrap();
        let mut auth = Vec::new();
        for _ in 1..super::MAX_OPEN_CEREMONIES {
            auth.push(
                s.put_webauthn_state("auth", "{}", None)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        // At the cap a new sign-in still starts: it evicts the oldest
        // sign-in, never the enrollment.
        let newest = s.put_webauthn_state("auth", "{}", None).await.unwrap();
        assert!(newest.is_some());
        assert_eq!(open(&s).await, super::MAX_OPEN_CEREMONIES);
        assert!(
            s.take_webauthn_state(&auth[0], "auth")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            s.take_webauthn_state(&auth[1], "auth")
                .await
                .unwrap()
                .is_some()
        );
        assert!(s.take_webauthn_state(&reg, "reg").await.unwrap().is_some());
        // Refilled with enrollments only, a sign-in has nothing to evict.
        sqlx::query("DELETE FROM webauthn_states")
            .execute(&s.pool)
            .await
            .unwrap();
        for _ in 0..super::MAX_OPEN_CEREMONIES {
            s.put_webauthn_state("reg", "{}", None).await.unwrap();
        }
        assert!(
            s.put_webauthn_state("auth", "{}", None)
                .await
                .unwrap()
                .is_none()
        );
        // An enrollment evicts the oldest of any kind.
        assert!(
            s.put_webauthn_state("reg", "{}", None)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(open(&s).await, super::MAX_OPEN_CEREMONIES);
    }

    #[tokio::test]
    async fn setup_tokens_expire() {
        use super::SetupToken;
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        assert_eq!(s.setup_token_state().await.unwrap(), SetupToken::None);
        let t = s.issue_setup_token().await.unwrap();
        assert_eq!(s.setup_token_state().await.unwrap(), SetupToken::Live);
        assert!(s.setup_token_valid(&t).await.unwrap());
        assert!(!s.setup_token_valid("other").await.unwrap());
        s.intel_set(
            "webauthn_setup_token_expires",
            &(chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
        )
        .await
        .unwrap();
        assert_eq!(s.setup_token_state().await.unwrap(), SetupToken::Expired);
        assert!(!s.setup_token_valid(&t).await.unwrap());
        // A new one replaces it.
        let t2 = s.issue_setup_token().await.unwrap();
        assert!(s.setup_token_valid(&t2).await.unwrap());
        assert!(!s.setup_token_valid(&t).await.unwrap());
        s.consume_setup_token().await.unwrap();
        assert!(!s.setup_token_valid(&t2).await.unwrap());
        assert_eq!(s.setup_token_state().await.unwrap(), SetupToken::None);
    }
}
