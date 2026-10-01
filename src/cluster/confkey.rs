//! The config key: a secret a node hands to operators it lets change its
//! runtime settings. Holding it is the permission; rotating it withdraws the
//! permission from everyone at once.
//!
//! The key never travels. Directed messages are relayed by other members,
//! so each change request carries an HMAC under the key instead; the target
//! checks it against its own copy.
use super::Node;
use super::identity::NodeId;
use super::msg::Msg;
use super::status::PaceInfo;
use crate::settings::{Changes, Settings};
use crate::store::Store;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PREFIX: &str = "peephole-cfg1:";
const OWN_KEY: &str = "cluster.config_key";
const MAC_DOMAIN: &[u8] = b"peephole-cfg-v1\0";
/// How long to wait for a node's answer.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A node's config key together with the node it belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigKey {
    pub id: NodeId,
    pub key: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Wire {
    v: u8,
    id: NodeId,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

impl ConfigKey {
    /// The string an operator copies: `peephole-cfg1:…`.
    pub fn encode(&self) -> String {
        let wire = Wire {
            v: 1,
            id: self.id,
            key: self.key.to_vec(),
        };
        // Encoding a plain struct into a Vec cannot fail.
        let raw = super::rpc::cbor::encode(&wire).unwrap_or_default();
        format!("{PREFIX}{}", data_encoding::BASE64URL_NOPAD.encode(&raw))
    }

    pub fn parse(s: &str) -> Result<Self> {
        let b64 = s
            .trim()
            .strip_prefix(PREFIX)
            .context("not a peephole config key")?;
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(b64.as_bytes())
            .context("config key: invalid base64url")?;
        let w: Wire = super::rpc::cbor::decode(&raw).context("config key: malformed")?;
        let key: [u8; 32] = w
            .key
            .try_into()
            .map_err(|_| anyhow::anyhow!("config key: malformed"))?;
        if w.v != 1 {
            bail!("config key: unsupported version");
        }
        Ok(Self { id: w.id, key })
    }
}

/// A node's runtime settings as it reports them to a member that asks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    /// Whether the node accepts changes from config key holders at all.
    pub open: bool,
    pub version: u64,
    pub pace: PaceInfo,
    pub cooldown_hours: i64,
    pub roles: Vec<String>,
    /// What the node's own queue metrics suggest (scanners only).
    pub recommended: Option<PaceInfo>,
}

async fn stored_key(store: &Store) -> Result<Option<[u8; 32]>> {
    let Some(v) = store.setting_get(OWN_KEY).await? else {
        return Ok(None);
    };
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(v.as_bytes())
        .context("stored config key")?;
    Ok(raw.try_into().ok())
}

/// This node's config key, if one was created.
pub async fn own(store: &Store, me: NodeId) -> Result<Option<ConfigKey>> {
    Ok(stored_key(store)
        .await?
        .map(|key| ConfigKey { id: me, key }))
}

/// This node's config key, created on first use.
pub async fn ensure(store: &Store, me: NodeId) -> Result<ConfigKey> {
    match own(store, me).await? {
        Some(k) => Ok(k),
        None => rotate(store, me).await,
    }
}

/// Replace this node's config key. Every holder of the old one loses the
/// right to configure this node.
pub async fn rotate(store: &Store, me: NodeId) -> Result<ConfigKey> {
    let mut key = [0u8; 32];
    aws_lc_rs::rand::fill(&mut key).map_err(|_| anyhow::anyhow!("rng failure"))?;
    store
        .setting_set(OWN_KEY, &data_encoding::BASE64URL_NOPAD.encode(&key))
        .await?;
    Ok(ConfigKey { id: me, key })
}

/// Remember a key another operator gave us; returns the node it configures.
pub async fn add(store: &Store, me: NodeId, token: &str) -> Result<NodeId> {
    let k = ConfigKey::parse(token)?;
    if k.id == me {
        bail!(
            "this is this node's own config key; give it to the operator who should configure this node"
        );
    }
    sqlx::query(
        "INSERT INTO config_keys (node, key, added_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(node) DO UPDATE SET key = excluded.key, added_at = excluded.added_at",
    )
    .bind(&k.id.0[..])
    .bind(&k.key[..])
    .execute(&store.pool)
    .await?;
    Ok(k.id)
}

pub async fn forget(store: &Store, node: &NodeId) -> Result<bool> {
    Ok(sqlx::query("DELETE FROM config_keys WHERE node = ?")
        .bind(&node.0[..])
        .execute(&store.pool)
        .await?
        .rows_affected()
        == 1)
}

/// Nodes we hold a config key for.
pub async fn held(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM config_keys ORDER BY added_at")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

async fn held_key(store: &Store, node: &NodeId) -> Result<Option<[u8; 32]>> {
    let k: Option<Vec<u8>> = sqlx::query_scalar("SELECT key FROM config_keys WHERE node = ?")
        .bind(&node.0[..])
        .fetch_optional(&store.pool)
        .await?;
    Ok(k.and_then(|k| k.try_into().ok()))
}

/// What the authenticator covers: who asks whom, based on which settings
/// version, for what.
fn mac_input(from: &NodeId, to: &NodeId, base_version: u64, c: &Changes) -> Vec<u8> {
    let mut m = MAC_DOMAIN.to_vec();
    m.extend_from_slice(&from.0);
    m.extend_from_slice(&to.0);
    m.extend_from_slice(&base_version.to_be_bytes());
    // Encoding a plain struct into a Vec cannot fail.
    m.extend_from_slice(&super::rpc::cbor::encode(c).unwrap_or_default());
    m
}

/// The authenticator of a change request under `key`.
pub fn mac(key: &[u8; 32], from: &NodeId, to: &NodeId, base_version: u64, c: &Changes) -> Vec<u8> {
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    aws_lc_rs::hmac::sign(&k, &mac_input(from, to, base_version, c))
        .as_ref()
        .to_vec()
}

fn pace_info(p: crate::scan::pace::Pace) -> PaceInfo {
    PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: p.max_scans_per_hour,
        timeout_secs: p.timeout_secs,
    }
}

/// Answer other members' questions about this node's settings, and change
/// them for holders of the config key.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let (settings, weak) = (settings.clone(), weak.clone());
        Box::pin(async move {
            let node = weak.upgrade()?;
            let open = node.cfg.remote_config;
            match msg {
                Msg::ConfigGet => {
                    let s = settings.snapshot();
                    let recommended = match (s.roles.scanner, node.store.queue_metrics().await) {
                        (true, Ok(m)) => Some(pace_info(crate::scan::pace::recommend(&m, s.pace).pace)),
                        _ => None,
                    };
                    Some(Msg::ConfigState(State {
                        open,
                        version: s.version,
                        pace: pace_info(s.pace),
                        cooldown_hours: s.cooldown_hours,
                        roles: s.roles.names().into_iter().map(str::to_string).collect(),
                        recommended,
                    }))
                }
                Msg::ConfigSet {
                    base_version,
                    changes,
                    mac: theirs,
                } => {
                    let refuse = |e: &str| {
                        Some(Msg::ConfigSetReply {
                            version: None,
                            error: Some(e.to_string()),
                        })
                    };
                    if !open {
                        return refuse("remote configuration is switched off on this node");
                    }
                    let Ok(Some(key)) = stored_key(&node.store).await else {
                        return refuse("this node has no config key");
                    };
                    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &key);
                    let msg = mac_input(&from, &node.id(), base_version, &changes);
                    // Constant-time comparison.
                    if aws_lc_rs::hmac::verify(&k, &msg, &theirs).is_err() {
                        tracing::warn!(by = %from.short(), "settings change with a wrong config key refused");
                        return refuse("config key not accepted (wrong, or rotated since)");
                    }
                    match settings.apply_at(base_version, &changes, Some(from)).await {
                        Ok(Ok(v)) => {
                            if !changes.is_empty() {
                                tracing::info!(by = %from.short(), changes = %changes.describe(), "settings changed by a config key holder");
                                node.status.local.lock().unwrap().pace =
                                    Some(pace_info(settings.snapshot().pace));
                                node.publish_status();
                            }
                            Some(Msg::ConfigSetReply {
                                version: Some(v),
                                error: None,
                            })
                        }
                        Ok(Err(e)) => refuse(&e),
                        Err(e) => refuse(&format!("{e:#}")),
                    }
                }
                _ => None,
            }
        })
    }));
}

/// Ask `target` for its runtime settings.
pub async fn get(node: &Arc<Node>, target: NodeId) -> Result<State> {
    match node.request(target, Msg::ConfigGet, TIMEOUT).await? {
        Msg::ConfigState(s) => Ok(s),
        other => bail!("unexpected answer {other:?}"),
    }
}

/// Change `target`'s settings with the config key we hold for it. The inner
/// error is the target's refusal.
pub async fn set(
    node: &Arc<Node>,
    target: NodeId,
    base_version: u64,
    c: &Changes,
) -> Result<Result<u64, String>> {
    let Some(key) = held_key(&node.store, &target).await? else {
        return Ok(Err(
            "no config key for this node; ask its operator for one".into()
        ));
    };
    let msg = Msg::ConfigSet {
        base_version,
        changes: c.clone(),
        mac: serde_bytes::ByteBuf::from(mac(&key, &node.id(), &target, base_version, c)),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::ConfigSetReply {
            version: Some(v), ..
        } => Ok(Ok(v)),
        Msg::ConfigSetReply { error, .. } => Ok(Err(error.unwrap_or_else(|| "refused".into()))),
        other => bail!("unexpected answer {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn key_round_trips_and_rejects_garbage() {
        let k = ConfigKey {
            id: Identity::generate().unwrap().id,
            key: [7u8; 32],
        };
        let s = k.encode();
        assert!(s.starts_with("peephole-cfg1:"), "{s}");
        let back = ConfigKey::parse(&format!("  {s}\n")).unwrap();
        assert_eq!((back.id, back.key), (k.id, k.key));
        for bad in [
            "",
            "peephole1:abc",
            "peephole-cfg1:!!!",
            "peephole-cfg1:AAAA",
        ] {
            assert!(ConfigKey::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn mac_binds_key_parties_version_and_changes() {
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let c = Changes {
            max_workers: Some(3),
            ..Default::default()
        };
        let m = mac(&[1; 32], &a, &b, 5, &c);
        assert_eq!(m, mac(&[1; 32], &a, &b, 5, &c));
        assert_ne!(m, mac(&[2; 32], &a, &b, 5, &c), "key");
        assert_ne!(m, mac(&[1; 32], &b, &a, 5, &c), "direction");
        assert_ne!(m, mac(&[1; 32], &a, &b, 6, &c), "version");
        assert_ne!(m, mac(&[1; 32], &a, &b, 5, &Changes::default()), "changes");
    }

    #[tokio::test]
    async fn own_key_is_created_once_rotated_on_demand_and_held_keys_are_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::connect(&dir.path().join("t.db"))
            .await
            .unwrap();
        let me = Identity::generate().unwrap().id;
        assert!(own(&store, me).await.unwrap().is_none());
        let first = ensure(&store, me).await.unwrap();
        assert_eq!(ensure(&store, me).await.unwrap().key, first.key);
        let second = rotate(&store, me).await.unwrap();
        assert_ne!(second.key, first.key);
        assert_eq!(own(&store, me).await.unwrap().unwrap().key, second.key);

        let other = ConfigKey {
            id: Identity::generate().unwrap().id,
            key: [9; 32],
        };
        assert_eq!(add(&store, me, &other.encode()).await.unwrap(), other.id);
        assert_eq!(held(&store).await.unwrap(), vec![other.id]);
        assert!(add(&store, me, &second.encode()).await.is_err(), "own key");
        assert!(forget(&store, &other.id).await.unwrap());
        assert!(!forget(&store, &other.id).await.unwrap());
    }
}
