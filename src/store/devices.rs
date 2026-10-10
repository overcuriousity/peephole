//! Devices paired with this node's machine API (`/api/v1`) and the
//! single-use codes that pair them. Only SHA-256 hashes are stored: of the
//! pairing code (5-minute TTL, deleted by the transaction that redeems it)
//! and of the device token (shown once, at pairing). Both lookups are
//! indexed exact matches on the hash, so comparison runs in constant time
//! by construction.
use super::Store;
use super::auth::token_hash;
use anyhow::Result;

/// Minutes a pairing code may be redeemed.
pub const PAIRING_CODE_MINUTES: i64 = 5;

/// A paired device. `token_hash` never leaves the store.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    /// Comma-separated: "read", or "read,act".
    pub scopes: String,
    /// Who paired it: the passkey label, "password", or "admin".
    pub paired_by: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub revoked_at: Option<String>,
}

impl Device {
    pub fn scopes(&self) -> Vec<&str> {
        self.scopes.split(',').collect()
    }
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.split(',').any(|s| s == scope)
    }
    pub fn revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// `bytes` of OS randomness, base64url without padding (24 for a pairing
/// code, 32 for a device token).
fn random_b64url(bytes: usize) -> String {
    use rand::Rng;
    let mut b = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut b);
    data_encoding::BASE64URL_NOPAD.encode(&b)
}

const DEVICE_COLS: &str =
    "id, name, token_hash, scopes, paired_by, created_at, last_seen_at, revoked_at";

impl Store {
    /// Mint a single-use pairing code (192-bit), valid for
    /// [`PAIRING_CODE_MINUTES`]. Returns the code; only its hash is stored.
    pub async fn mint_pairing_code(&self, scopes: &str, paired_by: &str) -> Result<String> {
        let code = random_b64url(24);
        // Opportunistic cleanup of expired rows; cheap and keeps the table bounded.
        sqlx::query("DELETE FROM pairing_codes WHERE expires_at <= datetime('now')")
            .execute(&self.pool)
            .await?;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO pairing_codes (code_hash, scopes, paired_by, expires_at)
             VALUES (?, ?, ?, datetime('now', '+{PAIRING_CODE_MINUTES} minutes'))"
        )))
        .bind(token_hash(&code))
        .bind(scopes)
        .bind(paired_by)
        .execute(&self.pool)
        .await?;
        Ok(code)
    }

    /// Redeem a pairing code: its row is deleted in the same immediate
    /// transaction that inserts the device, so a code pairs exactly one
    /// device and a reused, expired or unknown one pairs none. Returns the
    /// device and its token (256-bit; only the hash is stored).
    pub async fn redeem_pairing_code(
        &self,
        code: &str,
        name: &str,
    ) -> Result<Option<(Device, String)>> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let found: Option<(String, String)> = sqlx::query_as(
            "DELETE FROM pairing_codes
             WHERE code_hash = ? AND expires_at > datetime('now')
             RETURNING scopes, paired_by",
        )
        .bind(token_hash(code))
        .fetch_optional(&mut *tx)
        .await?;
        let Some((scopes, paired_by)) = found else {
            return Ok(None);
        };
        let token = random_b64url(32);
        let id = uuid::Uuid::new_v4().to_string();
        let device = sqlx::query_as::<_, Device>(sqlx::AssertSqlSafe(format!(
            "INSERT INTO devices (id, name, token_hash, scopes, paired_by, created_at, last_seen_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
             RETURNING {DEVICE_COLS}"
        )))
        .bind(&id)
        .bind(name)
        .bind(token_hash(&token))
        .bind(&scopes)
        .bind(&paired_by)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some((device, token)))
    }

    /// The device a bearer token belongs to: live (not revoked) only.
    /// `last_seen_at` follows use, at most one write a minute per device
    /// (mirrors [`Store::validate_session`]).
    pub async fn validate_device_token(&self, token: &str) -> Result<Option<Device>> {
        #[derive(sqlx::FromRow)]
        struct Row {
            #[sqlx(flatten)]
            device: Device,
            touch: bool,
        }
        let row = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(format!(
            "SELECT {DEVICE_COLS}, last_seen_at < datetime('now', '-60 seconds') AS touch
             FROM devices WHERE token_hash = ? AND revoked_at IS NULL"
        )))
        .bind(token_hash(token))
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.touch {
            sqlx::query("UPDATE devices SET last_seen_at = datetime('now') WHERE id = ?")
                .bind(&row.device.id)
                .execute(&self.pool)
                .await?;
        }
        Ok(Some(row.device))
    }

    /// Every paired device, newest first (the admin Devices page).
    pub async fn list_devices(&self) -> Result<Vec<Device>> {
        Ok(sqlx::query_as::<_, Device>(sqlx::AssertSqlSafe(format!(
            "SELECT {DEVICE_COLS} FROM devices ORDER BY created_at DESC, id DESC"
        )))
        .fetch_all(&self.read)
        .await?)
    }

    /// Mark a device revoked; its token is refused from then on. Returns
    /// whether a live device of that id existed.
    pub async fn revoke_device(&self, id: &str) -> Result<bool> {
        let n = sqlx::query(
            "UPDATE devices SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Who an admin session is: the label of the passkey it is bound to,
    /// "password" for a password session, "admin" when neither resolves
    /// (a session whose key was deleted meanwhile ends with it, so this is
    /// the tooling-and-tests case).
    pub async fn session_admin_label(&self, session_token: &str) -> Result<String> {
        let cred: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT cred_id FROM sessions WHERE id_hash = ? AND expires_at > datetime('now')",
        )
        .bind(token_hash(session_token))
        .fetch_optional(&self.read)
        .await?;
        let Some(cred) = cred else {
            // No such session (ended meanwhile): unresolvable.
            return Ok("admin".into());
        };
        match cred {
            None => Ok("password".into()),
            Some(cred_id) => {
                let label: Option<String> =
                    sqlx::query_scalar("SELECT label FROM credentials WHERE cred_id = ?")
                        .bind(&cred_id)
                        .fetch_optional(&self.read)
                        .await?;
                Ok(label
                    .filter(|l| !l.trim().is_empty())
                    .unwrap_or_else(|| "admin".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (dir, s)
    }

    #[tokio::test]
    async fn a_code_pairs_exactly_one_device() {
        let (_d, s) = test_store().await;
        let code = s.mint_pairing_code("read,act", "yubikey-5").await.unwrap();
        assert_eq!(code.len(), 32, "192-bit base64url");
        let (device, token) = s
            .redeem_pairing_code(&code, "Pixel 8")
            .await
            .unwrap()
            .expect("fresh code redeems");
        assert_eq!(token.len(), 43, "256-bit base64url");
        assert_eq!(device.scopes(), ["read", "act"]);
        assert_eq!(device.paired_by, "yubikey-5");
        assert!(!device.revoked());
        // Only hashes are stored.
        assert_ne!(device.token_hash, token);
        assert_eq!(device.token_hash, token_hash(&token));
        // Single-use, atomically: the second redemption finds nothing.
        assert!(
            s.redeem_pairing_code(&code, "again")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(s.list_devices().await.unwrap().len(), 1);
        // An unknown code pairs nothing.
        assert!(s.redeem_pairing_code("nope", "x").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_expired_code_pairs_nothing() {
        let (_d, s) = test_store().await;
        let code = s.mint_pairing_code("read", "admin").await.unwrap();
        sqlx::query("UPDATE pairing_codes SET expires_at = datetime('now', '-1 second')")
            .execute(&s.pool)
            .await
            .unwrap();
        assert!(
            s.redeem_pairing_code(&code, "Pixel 8")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(s.list_devices().await.unwrap().len(), 0);
        // Minting again sweeps the expired row.
        s.mint_pairing_code("read", "admin").await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_codes")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(left, 1);
    }

    #[tokio::test]
    async fn a_revoked_token_is_refused_and_last_seen_is_throttled() {
        let (_d, s) = test_store().await;
        let code = s.mint_pairing_code("read", "admin").await.unwrap();
        let (device, token) = s
            .redeem_pairing_code(&code, "Pixel 8")
            .await
            .unwrap()
            .unwrap();
        assert!(s.validate_device_token("nope").await.unwrap().is_none());
        let seen = s.validate_device_token(&token).await.unwrap().unwrap();
        assert_eq!(seen.id, device.id);
        // Within a minute of the last write: no write.
        let before: String = sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE id = ?")
            .bind(&device.id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        s.validate_device_token(&token).await.unwrap();
        let after: String = sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE id = ?")
            .bind(&device.id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(before, after, "throttled to one write a minute");
        // Older than a minute: use moves it.
        sqlx::query("UPDATE devices SET last_seen_at = datetime('now', '-2 minutes')")
            .execute(&s.pool)
            .await
            .unwrap();
        s.validate_device_token(&token).await.unwrap();
        let fresh: i64 = sqlx::query_scalar(
            "SELECT last_seen_at > datetime('now', '-1 minute') FROM devices WHERE id = ?",
        )
        .bind(&device.id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
        assert_eq!(fresh, 1);
        // Revoked: refused from then on; revoking twice reports it.
        assert!(s.revoke_device(&device.id).await.unwrap());
        assert!(s.validate_device_token(&token).await.unwrap().is_none());
        assert!(!s.revoke_device(&device.id).await.unwrap());
        assert!(!s.revoke_device("no-such-id").await.unwrap());
        assert!(s.list_devices().await.unwrap()[0].revoked());
    }

    #[tokio::test]
    async fn the_pairing_admin_is_named_by_their_session() {
        let (_d, s) = test_store().await;
        // Password session (no key bound).
        let pw = s.create_session().await.unwrap();
        assert_eq!(s.session_admin_label(&pw).await.unwrap(), "password");
        // Key-bound session: the key's label.
        s.save_credential(b"k1", "{}", Some("yubikey-5"))
            .await
            .unwrap();
        let key = s.create_session_for(b"k1", None).await.unwrap().unwrap();
        assert_eq!(s.session_admin_label(&key).await.unwrap(), "yubikey-5");
        // A key without a label, and a session that is gone.
        s.save_credential(b"k2", "{}", None).await.unwrap();
        let bare = s.create_session_for(b"k2", None).await.unwrap().unwrap();
        assert_eq!(s.session_admin_label(&bare).await.unwrap(), "admin");
        assert_eq!(
            s.session_admin_label("no-such-session").await.unwrap(),
            "admin"
        );
    }
}
