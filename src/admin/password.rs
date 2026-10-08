//! The admin password: an alternative or addition to passkeys, one account,
//! stored as an Argon2id hash in the database.
use anyhow::Result;
use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};

pub const MIN_LEN: usize = 12;

/// Whether `pw` is acceptable as a new password.
pub fn check_new(pw: &str) -> Result<(), &'static str> {
    if pw.chars().count() < MIN_LEN {
        Err("at least 12 characters")
    } else {
        Ok(())
    }
}

/// Argon2id hash of `pw` with a random salt, as a PHC string.
pub fn hash(pw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing the password: {e}"))?
        .to_string())
}

/// Whether `pw` matches the PHC string `phc`.
pub fn verify(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_verify_and_special_characters_survive() {
        let pw = r#"a "quoted" \ $dollar pass"#;
        let phc = hash(pw).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify(pw, &phc));
        assert!(!verify("a quoted pass", &phc));
        assert!(!verify(pw, "not a phc string"));
    }
    #[test]
    fn short_passwords_are_refused() {
        assert!(check_new("elevenchars").is_err());
        assert!(check_new("twelve chars").is_ok());
    }
}
