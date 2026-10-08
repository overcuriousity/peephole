use super::Store;
use anyhow::{Result, bail};
use std::str::FromStr;

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

    /// Delete a key only while the admin keeps a way in: another key remains,
    /// or the method is `Both` and a password is set (the method then
    /// becomes `Password` if no key is left). One immediate transaction, so
    /// two concurrent deletes cannot both pass the check. Returns whether a
    /// row was deleted. Sessions signed in with the key end with it.
    pub async fn delete_credential_guarded(&self, cred_id: &[u8]) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credentials")
            .fetch_one(&mut *tx)
            .await?;
        let method = get_meta(&mut tx, LOGIN_METHOD).await?;
        let method: LoginMethod = method.and_then(|m| m.parse().ok()).unwrap_or_default();
        let has_password = get_meta(&mut tx, PASSWORD_HASH).await?.is_some();
        let last = keys <= 1;
        if last && !(method != LoginMethod::Passkey && has_password) {
            return Ok(false);
        }
        let r = sqlx::query("DELETE FROM credentials WHERE cred_id = ?")
            .bind(cred_id)
            .execute(&mut *tx)
            .await?;
        let deleted = r.rows_affected() > 0;
        if deleted {
            sqlx::query("DELETE FROM sessions WHERE cred_id = ?")
                .bind(cred_id)
                .execute(&mut *tx)
                .await?;
            if last {
                put_meta(&mut tx, LOGIN_METHOD, LoginMethod::Password.as_str()).await?;
            }
        }
        tx.commit().await?;
        Ok(deleted)
    }

    /// How the admin signs in (`Passkey` when never set).
    pub async fn login_method(&self) -> Result<LoginMethod> {
        Ok(self
            .intel_get(LOGIN_METHOD)
            .await?
            .and_then(|m| m.parse().ok())
            .unwrap_or_default())
    }

    /// Choose the sign-in method; refused when it would leave no usable
    /// sign-in (no password for `Password`, no key for `Passkey`, neither
    /// for `Both`).
    pub async fn set_login_method(&self, m: LoginMethod) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM credentials")
            .fetch_one(&mut *tx)
            .await?;
        let has_password = get_meta(&mut tx, PASSWORD_HASH).await?.is_some();
        if m == LoginMethod::Password && !has_password {
            bail!("no password is set");
        }
        if m == LoginMethod::Passkey && keys == 0 {
            bail!("no passkey is enrolled");
        }
        if m == LoginMethod::Both && keys == 0 && !has_password {
            bail!("neither a password nor a passkey is set");
        }
        put_meta(&mut tx, LOGIN_METHOD, m.as_str()).await?;
        if m == LoginMethod::Passkey {
            // No password sign-in any more: its sessions end.
            sqlx::query("DELETE FROM sessions WHERE cred_id IS NULL")
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The admin password as a PHC string, if one is set.
    pub async fn password_hash(&self) -> Result<Option<String>> {
        self.intel_get(PASSWORD_HASH).await
    }

    /// Store the password hash. A `Passkey` method becomes `Both`. Sessions
    /// not bound to a key (earlier password sign-ins) end, except
    /// `keep_session`, the caller's own.
    pub async fn set_password_hash(&self, phc: &str, keep_session: Option<&str>) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        put_meta(&mut tx, PASSWORD_HASH, phc).await?;
        let current = get_meta(&mut tx, LOGIN_METHOD).await?;
        let current: LoginMethod = current.and_then(|m| m.parse().ok()).unwrap_or_default();
        if current == LoginMethod::Passkey {
            put_meta(&mut tx, LOGIN_METHOD, LoginMethod::Both.as_str()).await?;
        }
        sqlx::query("DELETE FROM sessions WHERE cred_id IS NULL AND id_hash != ?")
            .bind(keep_session.map(token_hash).unwrap_or_default())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
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
    /// sign-in (`auth`) evicts only the oldest sign-in at least
    /// [`MIN_CEREMONY_SECS`] old, so a sign-in in progress cannot be pushed
    /// out before the authenticator times out; an enrollment (only started
    /// when authorised) evicts the oldest of any kind. `None` when nothing
    /// may be evicted.
    pub async fn put_webauthn_state(
        &self,
        kind: &str,
        state_json: &str,
        label: Option<&str>,
    ) -> Result<Option<String>> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut tx = self.pool.begin().await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM webauthn_states WHERE rowid = (
               SELECT rowid FROM webauthn_states
               WHERE expires_at > datetime('now')
                 AND (?1 <> 'auth' OR (kind = 'auth'
                      AND created_at <= datetime('now', '-{MIN_CEREMONY_SECS} seconds')))
               ORDER BY created_at, rowid LIMIT 1)
             AND (SELECT COUNT(*) FROM webauthn_states
                  WHERE expires_at > datetime('now')) >= ?2"
        )))
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
        Ok(unexpired(&expires) && hash == token_hash(token))
    }

    /// Store a key enrolled under the session whose hash is `session_hash`,
    /// in the same statement that checks the session is still live, so a
    /// session that ended mid-ceremony (expired, signed out, its key
    /// deleted) enrolls nothing. Returns whether the key was stored.
    pub async fn save_credential_in_session(
        &self,
        cred_id: &[u8],
        passkey_json: &str,
        label: Option<&str>,
        session_hash: &str,
    ) -> Result<bool> {
        let r = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO credentials (cred_id, passkey_json, created_at, label)
             SELECT ?, ?, datetime('now'), ? WHERE EXISTS (
               SELECT 1 FROM sessions
               WHERE id_hash = ? AND expires_at > datetime('now')
                 AND last_seen > datetime('now', '-{SESSION_IDLE_MINUTES} minutes'))"
        )))
        .bind(cred_id)
        .bind(passkey_json)
        .bind(label)
        .bind(session_hash)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Store a key enrolled with the setup token whose hash is `setup_hash`
    /// and use that token up, in one transaction: nothing is stored unless
    /// the token is still the current unexpired one (not used meanwhile, not
    /// replaced by `peephole admin reset-token`), and a key that was not
    /// stored leaves the token usable. Returns whether the key was stored.
    pub async fn save_credential_with_setup_token(
        &self,
        cred_id: &[u8],
        passkey_json: &str,
        label: Option<&str>,
        setup_hash: &str,
    ) -> Result<bool> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let expires: Option<String> =
            sqlx::query_scalar("SELECT value FROM intel_meta WHERE key = ?")
                .bind(SETUP_TOKEN_EXPIRES)
                .fetch_optional(&mut *tx)
                .await?;
        if !expires.is_some_and(|e| unexpired(&e)) {
            return Ok(false);
        }
        let used =
            sqlx::query("UPDATE intel_meta SET value = 'consumed' WHERE key = ? AND value = ?")
                .bind(SETUP_TOKEN_HASH)
                .bind(setup_hash)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                == 1;
        if !used {
            return Ok(false);
        }
        sqlx::query("INSERT INTO credentials (cred_id, passkey_json, created_at, label) VALUES (?,?,datetime('now'),?)")
            .bind(cred_id).bind(passkey_json).bind(label).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
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

    /// The setup token's state, for deciding whether to issue a new one.
    pub async fn setup_token_state(&self) -> Result<SetupToken> {
        let hash = self.intel_get(SETUP_TOKEN_HASH).await?;
        let expires = self.intel_get(SETUP_TOKEN_EXPIRES).await?;
        Ok(match (hash.as_deref(), expires) {
            (None, _) | (Some("consumed"), _) => SetupToken::None,
            (Some(_), None) => SetupToken::Expired,
            (Some(_), Some(e)) => match chrono::DateTime::parse_from_rfc3339(&e) {
                Ok(t) if t > chrono::Utc::now() => SetupToken::Live,
                _ => SetupToken::Expired,
            },
        })
    }
}

/// Absolute session lifetime.
pub const SESSION_HOURS: i64 = 12;
/// Sessions end after this long without a request.
pub const SESSION_IDLE_MINUTES: i64 = 60;
/// Open (unexpired) WebAuthn ceremonies at most; more evict the oldest.
pub const MAX_OPEN_CEREMONIES: i64 = 256;
/// A sign-in this young is never evicted: the authenticator's own timeout
/// (60 s) plus a margin for the round trips.
pub const MIN_CEREMONY_SECS: i64 = 90;
/// Lifetime of the first-run setup token.
pub const SETUP_TOKEN_HOURS: i64 = 24;
const LOGIN_METHOD: &str = "admin_login_method";
const PASSWORD_HASH: &str = "admin_password_hash";
const SETUP_TOKEN_HASH: &str = "webauthn_setup_token_hash";
const SETUP_TOKEN_EXPIRES: &str = "webauthn_setup_token_expires";

/// The first-run setup token, as far as the database knows.
#[derive(Debug, PartialEq, Eq)]
pub enum SetupToken {
    /// None issued, or the one issued was used.
    None,
    /// Issued and still valid.
    Live,
    /// Issued and expired (or without an expiry).
    Expired,
}

/// Whether an RFC 3339 expiry lies in the future.
fn unexpired(expires: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(expires).is_ok_and(|t| t > chrono::Utc::now())
}

/// What is stored for a session or setup token: hex SHA-256.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(token.as_bytes()))
}

/// How the admin signs in on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoginMethod {
    #[default]
    Passkey,
    Password,
    Both,
}

impl LoginMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passkey => "passkey",
            Self::Password => "password",
            Self::Both => "both",
        }
    }
    pub fn passkey(self) -> bool {
        matches!(self, Self::Passkey | Self::Both)
    }
    pub fn password(self) -> bool {
        matches!(self, Self::Password | Self::Both)
    }
}

impl FromStr for LoginMethod {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "passkey" => Ok(Self::Passkey),
            "password" => Ok(Self::Password),
            "both" => Ok(Self::Both),
            _ => bail!("login method must be passkey, password or both"),
        }
    }
}

/// Read one `intel_meta` value inside a transaction.
async fn get_meta(tx: &mut sqlx::SqliteConnection, key: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT value FROM intel_meta WHERE key = ?")
            .bind(key)
            .fetch_optional(tx)
            .await?,
    )
}

/// Upsert one `intel_meta` value inside a transaction.
async fn put_meta(tx: &mut sqlx::SqliteConnection, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO intel_meta (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::LoginMethod;
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
        assert!(s.delete_credential_guarded(b"a").await.unwrap());
        // Only one left: refuse to delete it.
        assert!(!s.delete_credential_guarded(b"b").await.unwrap());
        assert_eq!(s.load_credentials().await.unwrap().len(), 1);
    }

    /// A store in a temp dir; keep the guard alive while using the store.
    async fn test_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (dir, s)
    }

    #[tokio::test]
    async fn login_method_guard_and_last_key() {
        let (_dir, s) = test_store().await;
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Passkey);
        assert!(
            s.set_login_method(LoginMethod::Password).await.is_err(),
            "no password yet"
        );
        s.save_credential(b"k1", "{}", Some("one")).await.unwrap();
        // Last key, method passkey: refused.
        assert!(!s.delete_credential_guarded(b"k1").await.unwrap());
        // Both, but no password: still refused.
        s.set_login_method(LoginMethod::Both).await.unwrap();
        assert!(!s.delete_credential_guarded(b"k1").await.unwrap());
        // With a password: the last key goes and the method becomes password.
        s.set_password_hash("$argon2id$v=19$x", None).await.unwrap();
        assert!(s.delete_credential_guarded(b"k1").await.unwrap());
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Password);
        assert!(
            s.set_login_method(LoginMethod::Passkey).await.is_err(),
            "no key left"
        );
    }

    #[tokio::test]
    async fn the_last_key_may_go_under_password_when_a_password_exists() {
        let (_dir, s) = test_store().await;
        s.save_credential(b"k1", "{}", Some("one")).await.unwrap();
        s.save_credential(b"k2", "{}", Some("two")).await.unwrap();
        s.set_password_hash("$argon2id$v=19$x", None).await.unwrap();
        s.set_login_method(LoginMethod::Password).await.unwrap();
        assert!(s.delete_credential_guarded(b"k1").await.unwrap());
        assert!(s.delete_credential_guarded(b"k2").await.unwrap());
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Password);
        assert!(s.load_credentials().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn switching_to_passkey_ends_password_sessions() {
        let (_dir, s) = test_store().await;
        s.save_credential(b"k1", "{}", Some("one")).await.unwrap();
        s.set_password_hash("$argon2id$v=19$x", None).await.unwrap();
        let pw = s.create_session().await.unwrap();
        let key = s.create_session_for(Some(b"k1"), None).await.unwrap();
        s.set_login_method(LoginMethod::Passkey).await.unwrap();
        assert!(!s.validate_session(&pw).await.unwrap());
        assert!(s.validate_session(&key).await.unwrap());
    }

    #[tokio::test]
    async fn setting_a_password_turns_passkey_into_both_and_ends_password_sessions() {
        let (_dir, s) = test_store().await;
        let a = s.create_session().await.unwrap();
        let b = s.create_session().await.unwrap();
        s.set_password_hash("$argon2id$v=19$x", Some(&b))
            .await
            .unwrap();
        assert_eq!(s.login_method().await.unwrap(), LoginMethod::Both);
        assert!(!s.validate_session(&a).await.unwrap());
        assert!(s.validate_session(&b).await.unwrap());
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
        assert!(s.delete_credential_guarded(b"a").await.unwrap());
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
        // At the cap, with every sign-in still young, a new one is refused
        // rather than pushing out one in progress.
        assert!(
            s.put_webauthn_state("auth", "{}", None)
                .await
                .unwrap()
                .is_none()
        );
        // Once they are old enough, a new sign-in evicts the oldest sign-in,
        // never the enrollment.
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE webauthn_states SET created_at = datetime(created_at, '-{} seconds')",
            super::MIN_CEREMONY_SECS
        )))
        .execute(&s.pool)
        .await
        .unwrap();
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
        let h2 = super::token_hash(&t2);
        // Only the token a ceremony started with can be used up with it.
        assert!(
            !s.save_credential_with_setup_token(b"k0", "{}", None, &super::token_hash(&t))
                .await
                .unwrap()
        );
        assert!(
            s.save_credential_with_setup_token(b"k1", "{}", None, &h2)
                .await
                .unwrap()
        );
        assert!(!s.setup_token_valid(&t2).await.unwrap());
        assert_eq!(s.setup_token_state().await.unwrap(), SetupToken::None);
        // Used once: a second ceremony with it stores nothing.
        assert!(
            !s.save_credential_with_setup_token(b"k2", "{}", None, &h2)
                .await
                .unwrap()
        );
        assert_eq!(s.load_credentials().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_key_not_stored_leaves_the_setup_token_usable() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let t = s.issue_setup_token().await.unwrap();
        let h = super::token_hash(&t);
        s.save_credential(b"dup", "{}", None).await.unwrap();
        // The insert fails (duplicate cred_id): the token is not used up.
        assert!(
            s.save_credential_with_setup_token(b"dup", "{}", None, &h)
                .await
                .is_err()
        );
        assert!(s.setup_token_valid(&t).await.unwrap());
        // An expired token stores nothing either.
        s.intel_set(
            "webauthn_setup_token_expires",
            &(chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
        )
        .await
        .unwrap();
        assert!(
            !s.save_credential_with_setup_token(b"new", "{}", None, &h)
                .await
                .unwrap()
        );
        assert_eq!(s.load_credentials().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_key_enrolled_in_a_session_needs_that_session_live() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let live = s.create_session().await.unwrap();
        let ended = s.create_session().await.unwrap();
        s.destroy_session(&ended).await.unwrap();
        let hash = super::token_hash;
        assert!(
            !s.save_credential_in_session(b"a", "{}", None, &hash(&ended))
                .await
                .unwrap()
        );
        assert!(
            s.save_credential_in_session(b"b", "{}", None, &hash(&live))
                .await
                .unwrap()
        );
        // Idle too long counts as ended.
        sqlx::query("UPDATE sessions SET last_seen = datetime('now', '-61 minutes')")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(
            !s.save_credential_in_session(b"c", "{}", None, &hash(&live))
                .await
                .unwrap()
        );
        let creds = s.load_credentials().await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, b"b");
    }
}
