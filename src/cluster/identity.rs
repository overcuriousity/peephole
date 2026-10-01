//! Node identity: an Ed25519 keypair generated on first start. The public
//! key *is* the node ID — peers pin it, records are signed with it, and the
//! lowest key wins deterministic elections.
use anyhow::{Context, Result, bail};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use std::path::Path;

const KEY_FILE_HEADER: &str = "peephole-node-key-v1";
const TEXT_PREFIX: &str = "ed25519:";

/// An Ed25519 public key identifying a node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Parse the `ed25519:<base64url>` form printed by `peephole cluster id`.
    pub fn parse(s: &str) -> Result<Self> {
        let Some(b64) = s.trim().strip_prefix(TEXT_PREFIX) else {
            bail!("expected `{TEXT_PREFIX}<base64url>`");
        };
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(b64.as_bytes())
            .context("invalid base64url")?;
        Self::from_slice(&raw)
    }

    pub fn from_slice(raw: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("an Ed25519 public key is 32 bytes"))?;
        Ok(Self(bytes))
    }

    /// Short, stable label for logs and the admin UI (12 hex chars of the
    /// key's SHA-256). Not unique enough to authenticate anything.
    /// Prefix of every uid this node creates. It binds a record's uid to
    /// its origin: no other node can create a record under the same uid, so
    /// nobody can shadow or delete it.
    pub fn uid_prefix(&self) -> String {
        format!("{}-", data_encoding::HEXLOWER.encode(&self.0[..12]))
    }

    pub fn short(&self) -> String {
        use sha2::Digest;
        data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(self.0)[..6])
    }

    /// Verify an Ed25519 signature made by this node.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(msg, sig)
            .is_ok()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{TEXT_PREFIX}{}",
            data_encoding::BASE64URL_NOPAD.encode(&self.0)
        )
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// This node's keypair.
pub struct Identity {
    seed: [u8; 32],
    pair: Ed25519KeyPair,
    pub id: NodeId,
}

impl Identity {
    fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|e| anyhow::anyhow!("invalid node key: {e}"))?;
        let id = NodeId::from_slice(pair.public_key().as_ref())?;
        Ok(Self { seed, pair, id })
    }

    /// Fresh random identity (tests, and first start via [`load_or_create`]).
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        aws_lc_rs::rand::fill(&mut seed).map_err(|_| anyhow::anyhow!("rng failure"))?;
        Self::from_seed(seed)
    }

    /// Load the key at `path`, or create it (mode 0600) if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match Self::load(path) {
            Ok(id) => Ok(id),
            Err(e) if path.exists() => Err(e),
            Err(_) => {
                let id = Self::generate()?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                let text = format!(
                    "{KEY_FILE_HEADER}\n{}\n",
                    data_encoding::BASE64.encode(&id.seed)
                );
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                // create_new: two processes racing must not overwrite each other.
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                {
                    Ok(mut f) => {
                        f.write_all(text.as_bytes())?;
                        f.sync_all()?;
                        Ok(id)
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::load(path),
                    Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
                }
            }
        }
    }

    /// Load an existing key; errors if the file is missing or malformed.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading node key {}", path.display()))?;
        let mut lines = text.lines();
        if lines.next() != Some(KEY_FILE_HEADER) {
            bail!("{}: not a peephole node key", path.display());
        }
        let raw = data_encoding::BASE64
            .decode(lines.next().unwrap_or("").trim().as_bytes())
            .context("node key: invalid base64")?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("node key: wrong length"))?;
        Self::from_seed(seed)
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }

    /// PKCS#8 v1 DER of the private key, for rustls and rcgen.
    pub fn pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self
            .pair
            .to_pkcs8v1()
            .map_err(|_| anyhow::anyhow!("pkcs8 encoding failed"))?
            .as_ref()
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_roundtrips_and_rejects_garbage() {
        let id = Identity::generate().unwrap().id;
        let s = id.to_string();
        assert!(s.starts_with("ed25519:"));
        assert_eq!(NodeId::parse(&s).unwrap(), id);
        assert!(NodeId::parse("ed25519:abc").is_err());
        assert!(NodeId::parse(&s.replace("ed25519:", "rsa:")).is_err());
        assert_eq!(id.short().len(), 12);
    }

    #[test]
    fn signatures_verify_only_for_the_signer() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        let sig = a.sign(b"hello");
        assert!(a.id.verify(b"hello", &sig));
        assert!(!a.id.verify(b"hellO", &sig));
        assert!(!b.id.verify(b"hello", &sig));
    }

    #[test]
    fn key_file_is_created_private_and_reloaded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/node.key");
        let a = Identity::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let b = Identity::load_or_create(&path).unwrap();
        assert_eq!(a.id, b.id);
        std::fs::write(&path, "garbage").unwrap();
        assert!(
            Identity::load_or_create(&path).is_err(),
            "never overwrite a bad key"
        );
    }
}
