//! Node ownership: one key per operator. A node stores the owner's public
//! key (the owner id) and a certificate the owner key signed for it; only
//! a managing node keeps the key itself. Nothing here is replicated.
use super::identity::NodeId;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

pub mod cli;
pub mod cmd;
pub mod fleet;

const PREFIX: &str = "peephole-own1:";
const CERT_DOMAIN: &[u8] = b"peephole-owner-cert-v1\0";
const KEY_ID: &str = "owner.id";
const KEY_CERT: &str = "owner.cert";
const KEY_SEED: &str = "owner.seed";
/// The previous key after a rotation, while siblings are still on it.
pub(crate) const KEY_OLD_SEED: &str = "owner.old_seed";
/// The key a rotation is moving to, from before the first sibling is told
/// until this node has switched: an interrupted rotation is finished with
/// it, instead of leaving siblings on a key nobody holds.
pub(crate) const KEY_NEXT_SEED: &str = "owner.next_seed";
const KEY_COUNTER: &str = "owner.counter";

/// What must not interleave on one node (see [`cmd`]).
#[derive(Default)]
pub struct Locks {
    /// Owner commands are checked one at a time, and one that changes the
    /// owner is also carried out before the next is looked at: a command
    /// signed under the owner being replaced cannot slip in between.
    pub(crate) commands: tokio::sync::Mutex<()>,
    /// One rotation or retry at a time.
    pub(crate) rotation: tokio::sync::Mutex<()>,
}

/// An owner: the public half of an ownership key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerId(pub [u8; 32]);

impl OwnerId {
    pub fn from_slice(raw: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("an owner id is 32 bytes"))?;
        Ok(Self(bytes))
    }

    /// The first 12 hex characters, for the admin area.
    pub fn short(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0[..6])
    }

    /// Verify a signature made with this owner's key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(msg, sig)
            .is_ok()
    }
}

impl std::fmt::Debug for OwnerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnerId({})", self.short())
    }
}

/// An ownership key: whoever holds it owns the nodes it certified.
pub struct OwnerKey {
    seed: [u8; 32],
    pair: Ed25519KeyPair,
    pub id: OwnerId,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    #[serde(with = "serde_bytes")]
    seed: Vec<u8>,
}

fn encode_wire(v: u8, seed: &[u8; 32]) -> String {
    let wire = Wire {
        v,
        seed: seed.to_vec(),
    };
    // Encoding a plain struct into a Vec cannot fail.
    let raw = super::rpc::cbor::encode(&wire).unwrap_or_default();
    format!("{PREFIX}{}", data_encoding::BASE64URL_NOPAD.encode(&raw))
}

impl OwnerKey {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self> {
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|e| anyhow::anyhow!("invalid ownership key: {e}"))?;
        let id = OwnerId::from_slice(pair.public_key().as_ref())?;
        Ok(Self { seed, pair, id })
    }

    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        aws_lc_rs::rand::fill(&mut seed).map_err(|_| anyhow::anyhow!("rng failure"))?;
        Self::from_seed(seed)
    }

    /// The string an operator copies: `peephole-own1:…`.
    pub fn encode(&self) -> String {
        encode_wire(1, &self.seed)
    }

    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let Some(b64) = s.strip_prefix(PREFIX) else {
            if s.starts_with("peephole1:") {
                bail!("not a peephole ownership key: this is an invite token");
            }
            if s.starts_with("peephole-cfg1:") {
                bail!(
                    "not a peephole ownership key: this is a config key of an earlier \
                     version; create an ownership key with `peephole owner new`"
                );
            }
            bail!("not a peephole ownership key");
        };
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(b64.as_bytes())
            .context("ownership key: invalid base64url")?;
        let w: Wire = super::rpc::cbor::decode(&raw).context("ownership key: malformed")?;
        if w.v != 1 {
            bail!("ownership key: unsupported version");
        }
        let seed: [u8; 32] = w
            .seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("ownership key: malformed"))?;
        Self::from_seed(seed)
    }

    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.pair.sign(msg).as_ref().to_vec()
    }

    /// The certificate that makes `node` a node of this owner.
    pub fn certify(&self, node: &NodeId) -> Vec<u8> {
        self.sign(&[CERT_DOMAIN, &node.0[..]].concat())
    }
}

/// Whether `cert` is `owner`'s certificate for `node`.
pub fn cert_valid(owner: &OwnerId, node: &NodeId, cert: &[u8]) -> bool {
    owner.verify(&[CERT_DOMAIN, &node.0[..]].concat(), cert)
}

/// What this node stores about its owner.
pub struct Owned {
    pub id: OwnerId,
    pub cert: Vec<u8>,
    /// The ownership key, on a managing node.
    pub key: Option<OwnerKey>,
}

impl Owned {
    /// Whether this node keeps the key and can command its siblings.
    pub fn managing(&self) -> bool {
        self.key.is_some()
    }
}

async fn get(store: &Store, key: &str) -> Result<Option<Vec<u8>>> {
    let Some(v) = store.setting_get(key).await? else {
        return Ok(None);
    };
    Ok(Some(
        data_encoding::BASE64URL_NOPAD
            .decode(v.as_bytes())
            .with_context(|| format!("stored {key}"))?,
    ))
}

async fn put(conn: &mut sqlx::SqliteConnection, key: &str, value: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn del(conn: &mut sqlx::SqliteConnection, key: &str) -> Result<bool> {
    Ok(sqlx::query("DELETE FROM settings WHERE key = ?")
        .bind(key)
        .execute(&mut *conn)
        .await?
        .rows_affected()
        > 0)
}

/// The owner changed: nobody known under the old one is a sibling, and a
/// rotation of the old key is over.
async fn forget_fleet(conn: &mut sqlx::SqliteConnection) -> Result<()> {
    for sql in ["DELETE FROM siblings", "DELETE FROM reown_pending"] {
        sqlx::query(sql).execute(&mut *conn).await?;
    }
    del(conn, KEY_OLD_SEED).await?;
    del(conn, KEY_NEXT_SEED).await?;
    Ok(())
}

async fn set_owner(
    store: &Store,
    id: &OwnerId,
    cert: &[u8],
    seed: Option<&[u8; 32]>,
) -> Result<()> {
    let b64 = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    put(&mut tx, KEY_ID, &b64(&id.0)).await?;
    put(&mut tx, KEY_CERT, &b64(cert)).await?;
    match seed {
        Some(s) => put(&mut tx, KEY_SEED, &b64(s)).await?,
        None => {
            del(&mut tx, KEY_SEED).await?;
        }
    }
    forget_fleet(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// This node's owner, if it has one: an owner id with a certificate that
/// fits this node. Read from the database every time, so a change made by
/// the CLI takes effect on the running node at once.
pub async fn load(store: &Store, me: NodeId) -> Result<Option<Owned>> {
    let (Some(id), Some(cert)) = (get(store, KEY_ID).await?, get(store, KEY_CERT).await?) else {
        return Ok(None);
    };
    let id = OwnerId::from_slice(&id)?;
    if !cert_valid(&id, &me, &cert) {
        return Ok(None);
    }
    let key = match get(store, KEY_SEED).await? {
        Some(seed) => {
            let seed: [u8; 32] = seed
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored ownership key: wrong length"))?;
            let k = OwnerKey::from_seed(seed)?;
            // A key of another owner does not make this a managing node.
            (k.id == id).then_some(k)
        }
        None => None,
    };
    Ok(Some(Owned { id, cert, key }))
}

/// Make this node a node of `key`'s owner, replacing any owner it had.
/// With `keep`, the key stays here and this becomes a managing node.
pub async fn adopt(store: &Store, me: NodeId, key: &OwnerKey, keep: bool) -> Result<()> {
    let seed = key.seed();
    set_owner(store, &key.id, &key.certify(&me), keep.then_some(&seed)).await
}

/// Generate a key and make this node owned by it and managing.
pub async fn create(store: &Store, me: NodeId) -> Result<OwnerKey> {
    let key = OwnerKey::generate()?;
    adopt(store, me, &key, true).await?;
    Ok(key)
}

/// Take over an owner by its id and a certificate for this node (the
/// owner's `Reown` command). The key is not kept.
pub async fn reown(store: &Store, me: NodeId, id: OwnerId, cert: &[u8]) -> Result<()> {
    if !cert_valid(&id, &me, cert) {
        bail!("the certificate is not for this node");
    }
    set_owner(store, &id, cert, None).await
}

/// A key stored beside the owner's (`owner.next_seed`, `owner.old_seed`).
pub(crate) async fn stored_key(store: &Store, key: &str) -> Result<Option<OwnerKey>> {
    let Some(seed) = get(store, key).await? else {
        return Ok(None);
    };
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored {key}: wrong length"))?;
    Ok(Some(OwnerKey::from_seed(seed)?))
}

/// Remember the key a rotation is about to move to.
pub(crate) async fn store_next(store: &Store, key: &OwnerKey) -> Result<()> {
    store
        .setting_set(
            KEY_NEXT_SEED,
            &data_encoding::BASE64URL_NOPAD.encode(&key.seed()),
        )
        .await
}

/// Whether a rotation was started here and not finished.
pub async fn rotation_unfinished(store: &Store) -> Result<bool> {
    Ok(store.setting_get(KEY_NEXT_SEED).await?.is_some())
}

/// The last step of a rotation, all or nothing: this node takes `new`,
/// counts the siblings that `moved` as its own again, and keeps `old` for
/// the ones still `pending` on it.
pub(crate) async fn switch_key(
    store: &Store,
    me: NodeId,
    new: &OwnerKey,
    old: &OwnerKey,
    moved: &[NodeId],
    pending: &[NodeId],
) -> Result<()> {
    let b64 = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    put(&mut tx, KEY_ID, &b64(&new.id.0)).await?;
    put(&mut tx, KEY_CERT, &b64(&new.certify(&me))).await?;
    put(&mut tx, KEY_SEED, &b64(&new.seed())).await?;
    forget_fleet(&mut tx).await?;
    for m in moved {
        sqlx::query(
            "INSERT OR REPLACE INTO siblings (node, cert, seen_at) VALUES (?, ?, datetime('now'))",
        )
        .bind(&m.0[..])
        .bind(new.certify(m))
        .execute(&mut *tx)
        .await?;
    }
    if !pending.is_empty() {
        put(&mut tx, KEY_OLD_SEED, &b64(&old.seed())).await?;
        for p in pending {
            sqlx::query("INSERT OR IGNORE INTO reown_pending (node) VALUES (?)")
                .bind(&p.0[..])
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Delete the key here; the node stays owned. False: no key was kept.
pub async fn forget_key(store: &Store) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let had = del(&mut tx, KEY_SEED).await?;
    del(&mut tx, KEY_OLD_SEED).await?;
    del(&mut tx, KEY_NEXT_SEED).await?;
    sqlx::query("DELETE FROM reown_pending")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(had)
}

/// Drop the owner. False: the node had none.
pub async fn release(store: &Store) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let had = del(&mut tx, KEY_ID).await?;
    del(&mut tx, KEY_CERT).await?;
    del(&mut tx, KEY_SEED).await?;
    forget_fleet(&mut tx).await?;
    tx.commit().await?;
    Ok(had)
}

/// The counter the next owner command must name.
pub async fn counter(store: &Store) -> Result<u64> {
    Ok(store
        .setting_get(KEY_COUNTER)
        .await?
        .and_then(|v| v.parse().ok())
        .unwrap_or(0))
}

/// Use up `expected` if it is the current counter and `owner` is still
/// this node's owner (the one the command was checked against; it may have
/// changed since, on the node's own console). Never reset, not even when
/// the owner changes: a reset would let an old command be replayed.
pub async fn take_counter(store: &Store, expected: u64, owner: &OwnerId) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let read = "SELECT value FROM settings WHERE key = ?";
    let id: Option<String> = sqlx::query_scalar(read)
        .bind(KEY_ID)
        .fetch_optional(&mut *tx)
        .await?;
    if id.as_deref() != Some(data_encoding::BASE64URL_NOPAD.encode(&owner.0).as_str()) {
        return Ok(false);
    }
    let cur: Option<String> = sqlx::query_scalar(read)
        .bind(KEY_COUNTER)
        .fetch_optional(&mut *tx)
        .await?;
    let cur: u64 = cur.and_then(|v| v.parse().ok()).unwrap_or(0);
    if cur != expected {
        return Ok(false);
    }
    put(&mut tx, KEY_COUNTER, &(cur + 1).to_string()).await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn key_round_trips_and_rejects_garbage() {
        let k = OwnerKey::generate().unwrap();
        let s = k.encode();
        assert!(s.starts_with("peephole-own1:"), "{s}");
        // Pasted with whitespace around it.
        let back = OwnerKey::parse(&format!("  {s}\n")).unwrap();
        assert_eq!(back.id, k.id);
        assert_eq!(back.seed(), k.seed());
        for (bad, says) in [
            ("", "not a peephole ownership key"),
            ("peephole-own1:!!!", "invalid base64url"),
            ("peephole-own1:AAAA", "malformed"),
            ("peephole1:abc", "invite"),
            ("peephole-cfg1:abc", "config key"),
        ] {
            let e = OwnerKey::parse(bad).err().expect(bad).to_string();
            assert!(e.contains(says), "{bad}: {e}");
        }
        // A key of a later format version is refused, not misread.
        let v2 = super::encode_wire(2, &k.seed());
        let e = OwnerKey::parse(&v2).err().unwrap().to_string();
        assert!(e.contains("unsupported version"), "{e}");
    }

    #[test]
    fn certificate_binds_owner_and_node() {
        let (k, other) = (OwnerKey::generate().unwrap(), OwnerKey::generate().unwrap());
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let cert = k.certify(&a);
        assert!(cert_valid(&k.id, &a, &cert));
        assert!(!cert_valid(&k.id, &b, &cert), "another node");
        assert!(!cert_valid(&other.id, &a, &cert), "another owner");
        assert!(!cert_valid(&k.id, &a, &[]), "empty");
        assert_eq!(k.id.short().len(), 12);
    }

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn owner_state_lifecycle() {
        let (store, _dir) = store().await;
        let me = Identity::generate().unwrap().id;
        assert!(load(&store, me).await.unwrap().is_none());

        // Create: owned and managing.
        let k1 = create(&store, me).await.unwrap();
        let o = load(&store, me).await.unwrap().unwrap();
        assert_eq!(o.id, k1.id);
        assert!(o.managing());

        // Forget the key: still owned.
        assert!(forget_key(&store).await.unwrap());
        assert!(!forget_key(&store).await.unwrap());
        let o = load(&store, me).await.unwrap().unwrap();
        assert!(!o.managing());

        // Managing again, with a known sibling and a pending rotation, to
        // see them go.
        adopt(&store, me, &k1, true).await.unwrap();
        let sib = Identity::generate().unwrap().id;
        sqlx::query("INSERT INTO siblings (node, cert, seen_at) VALUES (?, x'00', 'now')")
            .bind(&sib.0[..])
            .execute(&store.pool)
            .await
            .unwrap();
        store.setting_set(KEY_OLD_SEED, "AAAA").await.unwrap();
        store.setting_set(KEY_NEXT_SEED, "AAAA").await.unwrap();

        // Adopting with another key replaces the owner and forgets the fleet.
        let k2 = OwnerKey::generate().unwrap();
        adopt(&store, me, &k2, false).await.unwrap();
        let o = load(&store, me).await.unwrap().unwrap();
        assert_eq!(o.id, k2.id);
        assert!(
            !o.managing(),
            "the old owner's key is gone, the new one was not kept"
        );
        assert!(store.setting_get(KEY_SEED).await.unwrap().is_none());
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM siblings")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(store.setting_get(KEY_OLD_SEED).await.unwrap().is_none());
        assert!(store.setting_get(KEY_NEXT_SEED).await.unwrap().is_none());

        // Reown needs a certificate for this node.
        let k3 = OwnerKey::generate().unwrap();
        assert!(reown(&store, me, k3.id, &k3.certify(&sib)).await.is_err());
        reown(&store, me, k3.id, &k3.certify(&me)).await.unwrap();
        assert_eq!(load(&store, me).await.unwrap().unwrap().id, k3.id);

        // A certificate that does not fit this node means: not owned.
        let other = Identity::generate().unwrap().id;
        assert!(load(&store, other).await.unwrap().is_none());

        // Release.
        assert!(release(&store).await.unwrap());
        assert!(!release(&store).await.unwrap());
        assert!(load(&store, me).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_counter_only_moves_forward() {
        let (store, _dir) = store().await;
        let me = Identity::generate().unwrap().id;
        assert_eq!(counter(&store).await.unwrap(), 0);
        let k1 = create(&store, me).await.unwrap();
        assert!(take_counter(&store, 0, &k1.id).await.unwrap());
        assert!(!take_counter(&store, 0, &k1.id).await.unwrap(), "used");
        assert!(!take_counter(&store, 5, &k1.id).await.unwrap(), "ahead");
        assert_eq!(counter(&store).await.unwrap(), 1);
        // A change of owner does not reset it, and a command that was
        // checked against the previous owner no longer takes it.
        let k2 = OwnerKey::generate().unwrap();
        adopt(&store, me, &k2, false).await.unwrap();
        assert_eq!(counter(&store).await.unwrap(), 1);
        assert!(
            !take_counter(&store, 1, &k1.id).await.unwrap(),
            "owner changed"
        );
        assert_eq!(counter(&store).await.unwrap(), 1);
        assert!(take_counter(&store, 1, &k2.id).await.unwrap());
        // Nor does a release: without an owner nothing takes it.
        release(&store).await.unwrap();
        assert_eq!(counter(&store).await.unwrap(), 2);
        assert!(!take_counter(&store, 2, &k2.id).await.unwrap(), "no owner");
    }
}
