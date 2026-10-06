# Node Ownership Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the per-node config key with one ownership key per operator: nodes of one key form a fleet, find each other, and a fleet node that keeps the key can command its siblings.

**Architecture:** A new module `cluster::owner` holds the key, the certificate and the node's owner state (in the `settings` table). `owner::fleet` finds siblings with a directed hello message; `owner::cmd` signs, checks and executes owner commands over the existing directed messaging. The admin area gets a Cluster › Ownership page and the member page drives siblings through `owner::cmd`. `cluster::confkey` and everything around it is removed last, once its replacement works.

**Tech Stack:** Rust 2024, tokio, axum, askama templates, sqlx/SQLite, aws-lc-rs (Ed25519), ciborium (CBOR), sha2, data-encoding. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-06-node-ownership-design.md`. Read it first; this plan argues from it.

## Global Constraints

- Branch `ownership-credits`. No new branch, no PR.
- No new crates in `Cargo.toml`.
- Signature and hash domains, verbatim: `"peephole-owner-cert-v1\0"`, `"peephole-owner-hello-v1\0"`, `"peephole-owner-cmd-v1\0"`. Key prefix `peephole-own1:`.
- Settings keys, verbatim: `owner.id`, `owner.cert`, `owner.seed`, `owner.old_seed`, `owner.counter`.
- `owner.counter` is never reset, not on release and not on a change of owner: a reset would let an old signed command be replayed.
- The owner id and certificates are never written to a replicated record or a heartbeat.
- Migrations are append-only: add `0010_ownership.sql` and `0011_drop_config_keys.sql`, never edit an older file. Statements must not contain `;` inside themselves; `--` comments are stripped.
- `PROTO_VERSION` becomes 3, `PROTO_MIN` stays 2. Owner messages go only to members with `proto_max >= 3`.
- Not in this plan (the lookup-credits plan adds them): `OwnerCmd::SendCredits`, the `credits.collect_to` setting, credit balances in `Status` and on the Ownership page.
- Run only the tests a task names. No full `cargo test` per task (the disk fills up); the last task runs the wider set once, after checking `df -h .`.
- Before each commit: `cargo fmt --all`.
- Commit messages follow the repo's style (`Ownership: …`, `Tests: …`, `Docs: …`) and end with the line `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Admin copy is plain: "No owner", "key kept here", "key not kept here", "yours", "My nodes", "Commands received". Never "sibling" or "fleet" in the UI; those are code and doc words.

## Review Focus

Inputs the spec implies but that are easy to leave untested. Each has its test in the task named.

1. **The wrong kind of token pasted as a key** (an invite `peephole1:…`, an old config key `peephole-cfg1:…`, a key with spaces and a newline around it): a clear error naming what it is; the padded key is accepted. → Task 2, `key_round_trips_and_rejects_garbage`.
2. **Adopting a node that already has another owner**: the owner is replaced, a kept key of the old owner is gone, known siblings are forgotten. → Task 2, `owner_state_lifecycle`.
3. **The owner changes while the daemon runs** (the CLI writes the database of a running node): the next command and the next hello see the new owner without a restart. → Task 5, `a_managing_node_changes_a_siblings_settings` (nodes are adopted after boot).
4. **A sibling that cannot be reached during rotation**: it is listed as not moved, a retry moves it, and until then commands under the new key are refused there. → Task 6, `rotating_the_key_moves_reachable_siblings_and_retries_the_rest`.
5. **An admin on a node that does not keep the key opens a sibling's page or posts an action**: the page says where the key is missing and no command is sent; nothing panics. → Task 8, `a_node_without_the_key_shows_its_siblings_read_only`.

## File Structure

| File | Responsibility |
|---|---|
| `src/cluster/remote.rs` (new) | What a node tells members about its runtime settings (`State`, `ConfigGet`) |
| `src/cluster/owner/mod.rs` (new) | Ownership key, certificate, this node's owner state and command counter |
| `src/cluster/owner/cli.rs` (new) | `peephole owner …` |
| `src/cluster/owner/fleet.rs` (new) | Sibling discovery and the `siblings` table |
| `src/cluster/owner/cmd.rs` (new) | Owner commands: types, signing, serving, sending, the log, key rotation |
| `src/admin/cluster_owner.rs` (new) | Cluster › Ownership page and its actions |
| `templates/admin_cluster_ownership.html` (new) | That page |
| `src/store/migrations/0010_ownership.sql` (new) | `siblings`, `owner_log`, `reown_pending` |
| `src/store/migrations/0011_drop_config_keys.sql` (new) | Drops `config_keys` and the stored config key |
| `src/cluster/confkey.rs` (deleted in Task 8) | — |
| `src/cluster/msg.rs`, `src/cluster/rpc/proto.rs`, `src/cluster/mod.rs`, `src/lib.rs`, `src/main.rs` | New message kinds, protocol version, wiring, the `owner` subcommand |
| `src/admin/cluster.rs`, `src/admin/cluster_access.rs`, `src/admin/views.rs`, `src/admin/mod.rs`, templates | Member page through ownership, tabs, removal of config-key UI |
| `tests/cluster.rs`, `tests/cli.rs` | Integration tests |
| `install.sh`, `tests/install-smoke.sh`, `deploy/config.example.toml`, `docs/*.md`, `CHANGELOG.md` | Installer and docs |

---

### Task 1: Move the settings state out of `confkey`

A pure refactor so later tasks can use `State` and `ConfigGet` without the config key. No behaviour changes.

**Files:**
- Create: `src/cluster/remote.rs`
- Modify: `src/cluster/confkey.rs`, `src/cluster/mod.rs:3-19`, `src/cluster/msg.rs:85`, `src/admin/cluster.rs` (every `confkey::State` and `confkey::get`), `src/lib.rs:263`, `tests/cluster.rs:176` and its `confkey::get` calls
- Test: existing `tests/cluster.rs::config_key_holders_change_a_nodes_settings`

**Interfaces:**
- Produces:
  - `cluster::remote::State { open: bool, version: u64, pace: PaceInfo, cooldown_hours: i64, roles: Vec<String>, recommended: Option<PaceInfo> }` (moved, unchanged)
  - `cluster::remote::pace_info(p: crate::scan::pace::Pace) -> PaceInfo`
  - `cluster::remote::state(node: &Node, settings: &Settings) -> State` (async)
  - `cluster::remote::serve(node: &Arc<Node>, settings: Settings)` — answers `Msg::ConfigGet`
  - `cluster::remote::get(node: &Arc<Node>, target: NodeId) -> anyhow::Result<State>` (async)
  - `cluster::remote::TIMEOUT: Duration` (15 s)

- [ ] **Step 1: Create `src/cluster/remote.rs`**

```rust
//! What a node tells other members about its runtime settings. Any member
//! may ask ([`Msg::ConfigGet`]); the cluster pages show every scanner's
//! pace from the answers.
use super::Node;
use super::identity::NodeId;
use super::msg::Msg;
use super::status::PaceInfo;
use crate::settings::Settings;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// How long to wait for a node's answer.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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

pub fn pace_info(p: crate::scan::pace::Pace) -> PaceInfo {
    PaceInfo {
        max_workers: p.max_workers as u32,
        max_scans_per_hour: p.max_scans_per_hour,
        timeout_secs: p.timeout_secs,
    }
}

/// This node's settings, as it reports them.
pub async fn state(node: &Node, settings: &Settings) -> State {
    let s = settings.snapshot();
    let recommended = match (s.roles.scanner, node.store.queue_metrics().await) {
        (true, Ok(m)) => {
            let others = crate::scan::pace::others(
                node,
                m.avg_scan_secs
                    .unwrap_or(crate::scan::pace::DEFAULT_SCAN_SECS),
            );
            Some(pace_info(
                crate::scan::pace::recommend(&m, s.pace, others).pace,
            ))
        }
        _ => None,
    };
    State {
        open: node.cfg.remote_config,
        version: s.version,
        pace: pace_info(s.pace),
        cooldown_hours: s.cooldown_hours,
        roles: s.roles.names().into_iter().map(str::to_string).collect(),
        recommended,
    }
}

/// Answer other members' questions about this node's settings.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |_from, msg| {
        let (settings, weak) = (settings.clone(), weak.clone());
        Box::pin(async move {
            let node = weak.upgrade()?;
            match msg {
                Msg::ConfigGet => Some(Msg::ConfigState(state(&node, &settings).await)),
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
```

If `crate::scan::pace::others` takes `&Arc<Node>` rather than `&Node` (check its signature at `src/scan/pace.rs:290`: it takes `&crate::cluster::Node`), keep the call as written.

- [ ] **Step 2: Shrink `confkey.rs` to the key and `ConfigSet`**

In `src/cluster/confkey.rs`:

- Delete `struct State`, `fn pace_info`, `pub async fn get`, the `TIMEOUT` constant and the `Msg::ConfigGet => { … }` arm of `serve`.
- Add `use super::remote::{TIMEOUT, pace_info};` and drop the now unused `use super::status::PaceInfo;`.
- In the `Msg::ConfigSet` arm, keep `let open = node.cfg.remote_config;` and everything else as it is.

- [ ] **Step 3: Point every user at `remote`**

- `src/cluster/mod.rs`: add `pub mod remote;` after `pub mod record;`.
- `src/cluster/msg.rs:85`: `ConfigState(super::remote::State),`.
- `src/admin/cluster.rs`: replace `crate::cluster::confkey::State` with `crate::cluster::remote::State` (two places: `Remote::Settings.state` and the page struct near line 1014) and `crate::cluster::confkey::get(node, id)` with `crate::cluster::remote::get(node, id)`.
- `src/lib.rs`: directly above `cluster::confkey::serve(node, settings.clone());` add `cluster::remote::serve(node, settings.clone());`.
- `tests/cluster.rs`: in `boot_in`, above `cluster::confkey::serve(&node, settings.clone());` add `cluster::remote::serve(&node, settings.clone());`. In the two config-key tests replace `confkey::get(` with `peephole::cluster::remote::get(`.

- [ ] **Step 4: Build and run the covering tests**

Run: `cargo test --lib cluster::confkey && cargo test --test cluster config_key_holders_change_a_nodes_settings`
Expected: both PASS (3 unit tests, 1 integration test).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/cluster/remote.rs src/cluster/confkey.rs src/cluster/mod.rs src/cluster/msg.rs src/admin/cluster.rs src/lib.rs tests/cluster.rs
git commit -m "Cluster: settings state moves out of the config key module

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Ownership key, certificate and owner state

**Files:**
- Create: `src/cluster/owner/mod.rs`, `src/store/migrations/0010_ownership.sql`
- Modify: `src/cluster/mod.rs` (module list), `src/store/mod.rs:36-46` (`MIGRATIONS`)
- Test: unit tests in `src/cluster/owner/mod.rs`

**Interfaces:**
- Produces (all in `crate::cluster::owner`):
  - `struct OwnerId(pub [u8; 32])` — `Clone, Copy, PartialEq, Eq, Hash, Debug`; `OwnerId::from_slice(&[u8]) -> Result<Self>`, `short(&self) -> String` (12 hex chars), `verify(&self, msg: &[u8], sig: &[u8]) -> bool`
  - `struct OwnerKey { pub id: OwnerId, .. }` — `generate() -> Result<Self>`, `from_seed([u8; 32]) -> Result<Self>`, `parse(&str) -> Result<Self>`, `encode(&self) -> String`, `seed(&self) -> [u8; 32]`, `sign(&self, msg: &[u8]) -> Vec<u8>`, `certify(&self, node: &NodeId) -> Vec<u8>`
  - `fn cert_valid(owner: &OwnerId, node: &NodeId, cert: &[u8]) -> bool`
  - `struct Owned { pub id: OwnerId, pub cert: Vec<u8>, pub key: Option<OwnerKey> }`, `Owned::managing(&self) -> bool`
  - `async fn load(store: &Store, me: NodeId) -> Result<Option<Owned>>`
  - `async fn create(store: &Store, me: NodeId) -> Result<OwnerKey>`
  - `async fn adopt(store: &Store, me: NodeId, key: &OwnerKey, keep: bool) -> Result<()>`
  - `async fn reown(store: &Store, me: NodeId, id: OwnerId, cert: &[u8]) -> Result<()>`
  - `async fn forget_key(store: &Store) -> Result<bool>`
  - `async fn release(store: &Store) -> Result<bool>`
  - `async fn counter(store: &Store) -> Result<u64>`
  - `async fn take_counter(store: &Store, expected: u64) -> Result<bool>`
  - `pub(crate) const KEY_OLD_SEED: &str = "owner.old_seed"`
  - Tables `siblings (node, cert, seen_at)`, `owner_log (id, at, from_node, command, result)`, `reown_pending (node)`

- [ ] **Step 1: Add the migration**

Create `src/store/migrations/0010_ownership.sql`:

```sql
-- Node ownership: the nodes that share this node's owner, the owner
-- commands this node received, and siblings still on the previous key
-- after a rotation.
CREATE TABLE siblings (
  node BLOB PRIMARY KEY, cert BLOB NOT NULL, seen_at TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE owner_log (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, from_node BLOB NOT NULL,
  command TEXT NOT NULL, result TEXT NOT NULL
);

CREATE TABLE reown_pending (node BLOB PRIMARY KEY) WITHOUT ROWID
```

In `src/store/mod.rs`, append to `MIGRATIONS` after the `0009_decoy_in.sql` line:

```rust
    include_str!("migrations/0010_ownership.sql"),
```

- [ ] **Step 2: Write the failing tests**

Create `src/cluster/owner/mod.rs` with only the tests and the imports they need (the items do not exist yet):

```rust
//! Node ownership: one key per operator. A node stores the owner's public
//! key (the owner id) and a certificate the owner key signed for it; only
//! a managing node keeps the key itself. Nothing here is replicated.
use super::identity::NodeId;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

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

        // Adopting with another key replaces the owner and forgets the fleet.
        let k2 = OwnerKey::generate().unwrap();
        adopt(&store, me, &k2, false).await.unwrap();
        let o = load(&store, me).await.unwrap().unwrap();
        assert_eq!(o.id, k2.id);
        assert!(!o.managing(), "the old owner's key is gone, the new one was not kept");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM siblings")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        assert!(store.setting_get(KEY_OLD_SEED).await.unwrap().is_none());

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
        assert!(take_counter(&store, 0).await.unwrap());
        assert!(!take_counter(&store, 0).await.unwrap(), "used");
        assert!(!take_counter(&store, 5).await.unwrap(), "ahead");
        assert_eq!(counter(&store).await.unwrap(), 1);
        // A change of owner does not reset it.
        create(&store, me).await.unwrap();
        release(&store).await.unwrap();
        assert_eq!(counter(&store).await.unwrap(), 1);
    }
}
```

In `src/cluster/mod.rs` add `pub mod owner;` after `pub mod msg;`.

- [ ] **Step 3: Run the tests to see them fail**

Run: `cargo test --lib cluster::owner`
Expected: does not compile (`cannot find type OwnerKey`, …).

- [ ] **Step 4: Implement**

Insert between the imports and the test module of `src/cluster/owner/mod.rs`:

```rust
const PREFIX: &str = "peephole-own1:";
const CERT_DOMAIN: &[u8] = b"peephole-owner-cert-v1\0";
const KEY_ID: &str = "owner.id";
const KEY_CERT: &str = "owner.cert";
const KEY_SEED: &str = "owner.seed";
/// The previous key after a rotation, while siblings are still on it.
pub(crate) const KEY_OLD_SEED: &str = "owner.old_seed";
const KEY_COUNTER: &str = "owner.counter";

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

/// Delete the key here; the node stays owned. False: no key was kept.
pub async fn forget_key(store: &Store) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let had = del(&mut tx, KEY_SEED).await?;
    del(&mut tx, KEY_OLD_SEED).await?;
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

/// Use up `expected` if it is the current counter. Never reset, not even
/// when the owner changes: a reset would let an old command be replayed.
pub async fn take_counter(store: &Store, expected: u64) -> Result<bool> {
    let mut tx = store.pool.begin_with("BEGIN IMMEDIATE").await?;
    let cur: Option<String> = sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
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
```

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib cluster::owner && cargo test --lib store::`
Expected: PASS (4 owner tests; the store tests confirm the migration applies).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/cluster/owner/mod.rs src/cluster/mod.rs src/store/mod.rs src/store/migrations/0010_ownership.sql
git commit -m "Ownership: key, certificate and a node's owner state

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `peephole owner` on the command line

**Files:**
- Create: `src/cluster/owner/cli.rs`
- Modify: `src/cluster/owner/mod.rs` (add `pub mod cli;`), `src/main.rs` (usage, `Cmd`, `parse`, dispatch, parse test near line 178)
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `owner::{OwnerKey, load, create, adopt, forget_key, release}` from Task 2.
- Produces: `cluster::owner::cli::run(args: &[String], default_config: &str) -> anyhow::Result<()>` (async), `cluster::owner::cli::USAGE`.

- [ ] **Step 1: Write the failing test**

Append to `tests/cli.rs`:

```rust
/// The ownership key from the shell: created on one node, adopted on
/// another from standard input, forgotten and released.
#[test]
fn ownership_key_is_created_adopted_and_released_from_the_shell() {
    use std::io::Write;
    use std::process::Stdio;
    let config = |name: &str| {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("c.toml");
        std::fs::write(
            &cfg,
            format!(
                "database_path = \"{d}/t.db\"\ndata_dir = \"{d}\"\n[roles]\nlistener = false\nweb = false\n\
                 [cluster]\nnode_name = \"{name}\"\nlisten = \"127.0.0.1:0\"\n",
                d = dir.path().display()
            ),
        )
        .unwrap();
        (dir, cfg)
    };
    let run = |cfg: &std::path::Path, args: &[&str], stdin: Option<&str>| {
        let mut child = bin()
            .arg("owner")
            .args(args)
            .arg(cfg.to_str().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        (
            out.status.success(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    };
    let (_da, a) = config("a");
    let (_db, b) = config("b");

    let (ok, shown, _) = run(&a, &["show"], None);
    assert!(ok && shown.contains("no owner"), "{shown}");

    let (ok, key, err) = run(&a, &["new"], None);
    assert!(ok, "{err}");
    let key = key.trim().to_string();
    assert!(key.starts_with("peephole-own1:"), "{key}");
    let (_, shown, _) = run(&a, &["show"], None);
    assert!(shown.contains("key kept here"), "{shown}");
    let owner = shown.split_whitespace().nth(1).unwrap().to_string();
    let (ok, _, err) = run(&a, &["new"], None);
    assert!(!ok && err.contains("already has an owner"), "{err}");

    // The key never goes on the command line: adopt reads standard input.
    let (ok, _, err) = run(&b, &["adopt"], Some(&format!("{key}\n")));
    assert!(ok, "{err}");
    let (_, shown, _) = run(&b, &["show"], None);
    assert!(
        shown.contains(&owner) && shown.contains("key not kept here"),
        "{shown}"
    );
    let (ok, _, err) = run(&b, &["adopt"], Some("peephole1:abc\n"));
    assert!(!ok && err.contains("invite"), "{err}");

    let (ok, _, _) = run(&a, &["forget-key"], None);
    assert!(ok);
    let (_, shown, _) = run(&a, &["show"], None);
    assert!(shown.contains("key not kept here"), "{shown}");

    let (ok, _, _) = run(&b, &["release"], None);
    assert!(ok);
    let (_, shown, _) = run(&b, &["show"], None);
    assert!(shown.contains("no owner"), "{shown}");
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `cargo test --test cli ownership_key_is_created`
Expected: FAIL (`unknown command 'owner'`, exit status not success).

- [ ] **Step 3: Implement the subcommand**

Create `src/cluster/owner/cli.rs`:

```rust
//! `peephole owner …`: the ownership key on this node. Like `peephole
//! cluster`, it opens the node's database directly, so it works on
//! headless nodes and while the daemon runs.
use super::OwnerKey;
use crate::cluster::identity::Identity;
use crate::cluster::members;
use crate::config::Config;
use crate::store::Store;
use anyhow::{Context, Result, bail};
use std::path::Path;

pub const USAGE: &str = "usage: peephole owner new [CONFIG]
       peephole owner adopt [--keep] [CONFIG]   (reads the key from standard input;
                                                 --keep: manage other nodes from here)
       peephole owner show [CONFIG]
       peephole owner forget-key [CONFIG]       (the node stays owned)
       peephole owner release [CONFIG]          (the node has no owner afterwards)";

pub async fn run(args: &[String], default_config: &str) -> Result<()> {
    let mut keep = false;
    let mut pos: Vec<&str> = vec![];
    for a in args {
        match a.as_str() {
            "--keep" => keep = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            f if f.starts_with("--") => bail!("unknown flag {f}\n\n{USAGE}"),
            p => pos.push(p),
        }
    }
    let sub = *pos.first().context(USAGE)?;
    if pos.len() > 2 {
        bail!("unexpected argument '{}'\n\n{USAGE}", pos[2]);
    }
    if keep && sub != "adopt" {
        bail!("--keep belongs to `adopt`\n\n{USAGE}");
    }
    let cfg = Config::load(Path::new(pos.get(1).copied().unwrap_or(default_config)))?;
    if cfg.cluster.is_none() {
        bail!("config has no [cluster] section: ownership is for cluster nodes");
    }
    let store = Store::connect(&cfg.database_path).await?;
    let me = Identity::load_or_create(&cfg.node_key_path())?.id;
    match sub {
        "new" => {
            if let Some(o) = super::load(&store, me).await? {
                bail!(
                    "this node already has an owner ({}); release it first: peephole owner release",
                    o.id.short()
                );
            }
            let key = super::create(&store, me).await?;
            println!("{}", key.encode());
            eprintln!(
                "this is the ownership key, shown once. Whoever holds it controls every node \
                 it is entered on. Enter it on your other nodes with: peephole owner adopt"
            );
        }
        "adopt" => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading the key from standard input")?;
            let key = OwnerKey::parse(&line)?;
            super::adopt(&store, me, &key, keep).await?;
            println!(
                "this node is now owned by {} ({})",
                key.id.short(),
                if keep {
                    "key kept here"
                } else {
                    "key not kept here"
                }
            );
        }
        "show" => match super::load(&store, me).await? {
            None => println!("no owner"),
            Some(o) => {
                println!(
                    "owner {} ({})",
                    o.id.short(),
                    if o.managing() {
                        "key kept here"
                    } else {
                        "key not kept here"
                    }
                );
                let names: std::collections::HashMap<_, _> = members::all(&store)
                    .await?
                    .into_iter()
                    .map(|m| (m.id, m.name))
                    .collect();
                let rows: Vec<Vec<u8>> =
                    sqlx::query_scalar("SELECT node FROM siblings ORDER BY node")
                        .fetch_all(&store.pool)
                        .await?;
                for r in rows {
                    let id = crate::cluster::identity::NodeId::from_slice(&r)?;
                    println!(
                        "  {} {}",
                        id.short(),
                        names.get(&id).map(String::as_str).unwrap_or("?")
                    );
                }
            }
        },
        "forget-key" => {
            if super::forget_key(&store).await? {
                println!("the ownership key is no longer kept on this node; it stays owned");
            } else {
                println!("no ownership key was kept on this node");
            }
        }
        "release" => {
            if super::release(&store).await? {
                println!("this node has no owner now");
            } else {
                println!("this node had no owner");
            }
        }
        other => bail!("unknown subcommand '{other}'\n\n{USAGE}"),
    }
    Ok(())
}
```

In `src/cluster/owner/mod.rs` add `pub mod cli;` below the `use` lines.

In `src/main.rs`:

- Usage: after the `peephole cluster (…) …` line add
  `       peephole owner (new|adopt|show|forget-key|release) …    the ownership key on this node`
- `enum Cmd`: add `Owner,` after `Cluster,`.
- `parse`: after `Some("cluster") => Ok(Cmd::Cluster),` add `Some("owner") => Ok(Cmd::Owner),`.
- Dispatch, after the `Cmd::Cluster` arm:

```rust
        Cmd::Owner => {
            if let Err(e) = peephole::cluster::owner::cli::run(&args[1..], DEFAULT_CONFIG).await {
                fail(e);
            }
        }
```

- In the parse test next to `assert_eq!(p(&["cluster", "anything", "goes"]), Ok(Cmd::Cluster));` add
  `assert_eq!(p(&["owner", "show"]), Ok(Cmd::Owner));`

- [ ] **Step 4: Run the tests**

Run: `cargo test --test cli ownership_key_is_created && cargo test --bin peephole`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add src/cluster/owner/cli.rs src/cluster/owner/mod.rs src/main.rs tests/cli.rs
git commit -m "Ownership: peephole owner new, adopt, show, forget-key, release

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: The fleet: siblings find each other

**Files:**
- Create: `src/cluster/owner/fleet.rs`
- Modify: `src/cluster/owner/mod.rs` (add `pub mod fleet;`), `src/cluster/msg.rs` (two `Msg` variants), `src/cluster/rpc/proto.rs` (version 3), `src/lib.rs` (wiring next to `cluster::remote::serve`), `tests/cluster.rs` (`boot_in`, new test)
- Test: unit tests in `fleet.rs`; `tests/cluster.rs::fleet_nodes_find_each_other_and_nobody_else`

**Interfaces:**
- Consumes: `owner::{OwnerId, load, cert_valid}` (Task 2); `Node::request`, `Node::on_message`, `Node::members`, `Node::live_members`, `Node::is_blocked`.
- Produces:
  - `Msg::OwnerHello { tag: serde_bytes::ByteBuf, cert: serde_bytes::ByteBuf }`, `Msg::OwnerHelloReply { cert: serde_bytes::ByteBuf }`
  - `cluster::rpc::proto::OWNER_PROTO: u32 = 3`
  - `fleet::hello_tag(owner: &OwnerId, from: &NodeId, to: &NodeId) -> [u8; 32]`
  - `fleet::siblings(store: &Store) -> Result<Vec<NodeId>>` (async, sorted by node id)
  - `fleet::remember(store: &Store, node: &NodeId, cert: &[u8]) -> Result<()>` (async, `pub(crate)`)
  - `fleet::forget(store: &Store, node: &NodeId) -> Result<()>` (async, `pub(crate)`)
  - `fleet::serve(node: &Arc<Node>)`
  - `fleet::discover(node: &Arc<Node>) -> Result<Vec<NodeId>>` (async; one round, returns the siblings afterwards)
  - `fleet::run(node: Arc<Node>, shutdown: tokio::sync::watch::Receiver<bool>)` (async loop)

- [ ] **Step 1: Protocol version and message kinds**

`src/cluster/rpc/proto.rs`:

```rust
/// Highest protocol version this build speaks.
pub const PROTO_VERSION: u32 = 3;
```

and below `PROTO_MIN`:

```rust
/// First version that knows the owner messages (`OwnerHello`, `OwnerCmd`).
/// A node cannot decode a message kind it does not know, so these go only
/// to members that announce at least this version.
pub const OWNER_PROTO: u32 = 3;
```

`src/cluster/msg.rs`, in `enum Msg` after `ConfigSetReply { … }`:

```rust
    /// Owned node → member: are you a node of my owner? `tag` is a hash
    /// that only a node with the same owner id can recompute, `cert` the
    /// sender's certificate.
    OwnerHello {
        tag: serde_bytes::ByteBuf,
        cert: serde_bytes::ByteBuf,
    },
    /// The answerer's certificate; empty when it is no sibling.
    OwnerHelloReply { cert: serde_bytes::ByteBuf },
```

- [ ] **Step 2: Write the failing tests**

Create `src/cluster/owner/fleet.rs` with the tests only:

```rust
//! The fleet: the members that share this node's owner. They are found
//! with a directed hello and kept in the `siblings` table. The rest of
//! the cluster takes no part: the owner id never travels, and a node of
//! another owner (or of none) only answers that it is no sibling.
use super::{OwnerId, cert_valid, load};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::rpc::proto::OWNER_PROTO;
use crate::store::Store;
use anyhow::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;
    use crate::cluster::owner::OwnerKey;

    #[test]
    fn the_hello_tag_binds_owner_and_both_nodes() {
        let (o1, o2) = (
            OwnerKey::generate().unwrap().id,
            OwnerKey::generate().unwrap().id,
        );
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let t = hello_tag(&o1, &a, &b);
        assert_eq!(t, hello_tag(&o1, &a, &b));
        assert_ne!(t, hello_tag(&o2, &a, &b), "another owner");
        assert_ne!(t, hello_tag(&o1, &b, &a), "direction");
    }

    #[tokio::test]
    async fn siblings_are_remembered_and_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        remember(&store, &a, b"c1").await.unwrap();
        remember(&store, &a, b"c2").await.unwrap();
        remember(&store, &b, b"c3").await.unwrap();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(siblings(&store).await.unwrap(), want);
        forget(&store, &a).await.unwrap();
        assert_eq!(siblings(&store).await.unwrap(), vec![b]);
    }
}
```

Add `pub mod fleet;` to `src/cluster/owner/mod.rs`.

Append to `tests/cluster.rs`:

```rust
/// Nodes with one ownership key find each other; nobody else is a sibling,
/// and a released node is dropped at the next round.
#[tokio::test]
async fn fleet_nodes_find_each_other_and_nobody_else() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id, d) = new_node("d");
    let na = boot(ia, &a, &[&b, &c, &d], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c, &d], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b, &d], DEFAULT).await;
    let nd = boot(id, &d, &[&a, &b, &c], DEFAULT).await;
    // a and b share a key, c has its own, d has none.
    let k1 = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &k1, false).await.unwrap();
    owner::create(&nc.store, c.id).await.unwrap();

    eventually("a and b find each other", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
            && fleet::siblings(&nb.store).await.unwrap() == vec![a.id]
    })
    .await;
    eventually("c and d reach the others and find nobody", || async {
        nc.live_members(Duration::from_secs(45)).len() == 4
            && nd.live_members(Duration::from_secs(45)).len() == 4
    })
    .await;
    assert!(fleet::discover(&nc.node).await.unwrap().is_empty());
    assert!(fleet::discover(&nd.node).await.unwrap().is_empty());
    assert!(fleet::siblings(&nd.store).await.unwrap().is_empty());

    // b is released on its own console: a learns it at its next round.
    owner::release(&nb.store).await.unwrap();
    eventually("a drops b", || async {
        fleet::discover(&na.node).await.unwrap().is_empty()
    })
    .await;
}
```

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib cluster::owner::fleet`
Expected: does not compile (`cannot find function hello_tag`, …).

- [ ] **Step 4: Implement `fleet.rs`**

Insert between the imports and the test module:

```rust
const HELLO_DOMAIN: &[u8] = b"peephole-owner-hello-v1\0";
/// How long a member has to answer a hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Greet every reachable member at least this often.
const ROUND: Duration = Duration::from_secs(600);
/// How often the loop looks whether the owner or the live members changed.
const TICK: Duration = Duration::from_secs(60);
/// A member heard from within this time is greeted.
const LIVE: Duration = Duration::from_secs(45);

/// What a hello carries instead of the owner id: only a node that holds
/// the same owner id can recompute it.
pub fn hello_tag(owner: &OwnerId, from: &NodeId, to: &NodeId) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(HELLO_DOMAIN);
    h.update(owner.0);
    h.update(from.0);
    h.update(to.0);
    h.finalize().into()
}

/// This node's siblings, by node id.
pub async fn siblings(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM siblings ORDER BY node")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

pub(crate) async fn remember(store: &Store, node: &NodeId, cert: &[u8]) -> Result<()> {
    sqlx::query(
        "INSERT INTO siblings (node, cert, seen_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(node) DO UPDATE SET cert = excluded.cert, seen_at = excluded.seen_at",
    )
    .bind(&node.0[..])
    .bind(cert)
    .execute(&store.pool)
    .await?;
    Ok(())
}

pub(crate) async fn forget(store: &Store, node: &NodeId) -> Result<()> {
    sqlx::query("DELETE FROM siblings WHERE node = ?")
        .bind(&node.0[..])
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// Answer hellos: a sibling gets this node's certificate, anyone else an
/// empty one.
pub fn serve(node: &Arc<Node>) {
    let weak = Arc::downgrade(node);
    node.on_message(Arc::new(move |from, msg| {
        let weak = weak.clone();
        Box::pin(async move {
            let Msg::OwnerHello { tag, cert } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            let no = Some(Msg::OwnerHelloReply {
                cert: serde_bytes::ByteBuf::new(),
            });
            let Ok(Some(owned)) = load(&node.store, node.id()).await else {
                return no;
            };
            if tag.as_slice() != hello_tag(&owned.id, &from, &node.id())
                || !cert_valid(&owned.id, &from, &cert)
            {
                return no;
            }
            if let Err(e) = remember(&node.store, &from, &cert).await {
                tracing::debug!(?e, "sibling not stored");
            }
            Some(Msg::OwnerHelloReply {
                cert: serde_bytes::ByteBuf::from(owned.cert),
            })
        })
    }));
}

/// One round: forget siblings that are no longer members, greet every
/// live member, and return the siblings afterwards. A member that answers
/// with its certificate is a sibling; one that answers without is not
/// (any more); one that does not answer stays what it was.
pub async fn discover(node: &Arc<Node>) -> Result<Vec<NodeId>> {
    let me = node.id();
    let Some(owned) = load(&node.store, me).await? else {
        return Ok(vec![]);
    };
    let members = node.members();
    let stored: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT node, cert FROM siblings")
        .fetch_all(&node.store.pool)
        .await?;
    for (id, cert) in stored {
        let id = NodeId::from_slice(&id)?;
        let member = members.get(&id).is_some_and(|m| m.active);
        if !member || !cert_valid(&owned.id, &id, &cert) {
            forget(&node.store, &id).await?;
        }
    }
    let targets: Vec<NodeId> = node
        .live_members(LIVE)
        .into_iter()
        .filter(|id| *id != me && !node.is_blocked(id))
        .filter(|id| {
            members
                .get(id)
                .is_some_and(|m| m.active && m.proto_max >= OWNER_PROTO)
        })
        .collect();
    let asks = targets.iter().map(|to| {
        let hello = Msg::OwnerHello {
            tag: serde_bytes::ByteBuf::from(hello_tag(&owned.id, &me, to).to_vec()),
            cert: serde_bytes::ByteBuf::from(owned.cert.clone()),
        };
        async move { (*to, node.request(*to, hello, HELLO_TIMEOUT).await) }
    });
    for (to, answer) in futures::future::join_all(asks).await {
        match answer {
            Ok(Msg::OwnerHelloReply { cert }) if cert_valid(&owned.id, &to, &cert) => {
                remember(&node.store, &to, &cert).await?;
            }
            Ok(_) => forget(&node.store, &to).await?,
            // Unreachable: it stays what it was.
            Err(_) => {}
        }
    }
    siblings(&node.store).await
}

/// Keep the siblings current: a round whenever the owner or the set of
/// live members changed, and at least every [`ROUND`].
pub async fn run(node: Arc<Node>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let mut seen: Option<(Option<OwnerId>, Vec<NodeId>)> = None;
    let mut last = Instant::now();
    loop {
        let owner = load(&node.store, node.id())
            .await
            .ok()
            .flatten()
            .map(|o| o.id);
        let mut live = node.live_members(LIVE);
        live.sort();
        let now = (owner, live);
        if seen.as_ref() != Some(&now) || last.elapsed() >= ROUND {
            if let Err(e) = discover(&node).await {
                tracing::debug!(?e, "sibling discovery failed");
            }
            seen = Some(now);
            last = Instant::now();
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }
    }
}
```

`OwnerId` needs `PartialEq` for the comparison in `run`; Task 2 derives it.

- [ ] **Step 5: Wire it in**

`src/lib.rs`, below `cluster::remote::serve(node, settings.clone());`:

```rust
        cluster::owner::fleet::serve(node);
        tokio::spawn(cluster::owner::fleet::run(
            node.clone(),
            shutdown_rx.clone(),
        ));
```

`tests/cluster.rs`, in `boot_in` below `cluster::remote::serve(&node, settings.clone());`:

```rust
    cluster::owner::fleet::serve(&node);
```

(Tests call `fleet::discover` themselves; the loop is not started there.)

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib cluster::owner::fleet && cargo test --lib cluster::rpc::proto && cargo test --lib cluster::msg && cargo test --test cluster fleet_nodes_find_each_other && cargo test --test cluster incompatible_protocol_ranges_are_reported`
Expected: all PASS. If a `proto` unit test or the incompatible-ranges test pinned version 2 as the highest, change the pinned number to `PROTO_VERSION` and say so in the commit message.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add src/cluster/owner/fleet.rs src/cluster/owner/mod.rs src/cluster/msg.rs src/cluster/rpc/proto.rs src/lib.rs tests/cluster.rs
git commit -m "Ownership: nodes of one key find each other

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Owner commands: status and settings

**Files:**
- Create: `src/cluster/owner/cmd.rs`
- Modify: `src/cluster/owner/mod.rs` (add `pub mod cmd;`), `src/cluster/msg.rs` (two `Msg` variants), `src/lib.rs` and `tests/cluster.rs::boot_in` (wiring), `tests/cluster.rs` (two tests)
- Test: unit tests in `cmd.rs`; `tests/cluster.rs::a_managing_node_changes_a_siblings_settings`, `tests/cluster.rs::owner_commands_reach_an_outbound_only_sibling`

**Interfaces:**
- Consumes: `owner::{OwnerId, OwnerKey, load, counter, take_counter}` (Task 2); `remote::{State, state, pace_info}` (Task 1); `proto::OWNER_PROTO` (Task 4); `Settings::apply_at`.
- Produces (in `crate::cluster::owner::cmd`):
  - `enum OwnerCmd { Status, Settings { base_version: u64, changes: Changes } }` — `Debug, Clone, PartialEq, Serialize, Deserialize`, `#[serde(tag = "c", rename_all = "snake_case")]`; `OwnerCmd::describe(&self) -> String`
  - `struct InviteInfo { id: i64, label: String, uses: i64, max_uses: Option<i64>, expires_at: Option<String>, usable: bool }`
  - `struct Status { counter: u64, state: remote::State, build: String, blocked: Vec<NodeId>, invites: Vec<InviteInfo> }`
  - `enum OwnerData { Status(Box<Status>), Done { note: String } }` — `#[serde(tag = "d", rename_all = "snake_case")]`
  - `Msg::OwnerCmd { counter: u64, cmd: OwnerCmd, sig: serde_bytes::ByteBuf }`, `Msg::OwnerReply { counter: u64, error: Option<String>, data: Option<OwnerData> }`
  - `fn sign(key: &OwnerKey, from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd) -> Vec<u8>`
  - `fn verify(owner: &OwnerId, from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd, sig: &[u8]) -> bool`
  - `fn serve(node: &Arc<Node>, settings: Settings)`
  - `async fn kept_key(node: &Node) -> Result<OwnerKey>` — errors with "the ownership key is not kept on this node"
  - `async fn status(node: &Arc<Node>, key: &OwnerKey, target: NodeId) -> Result<Status>`
  - `async fn run(node: &Arc<Node>, key: &OwnerKey, target: NodeId, counter: u64, cmd: OwnerCmd) -> Result<Result<String, String>>` — outer error: no answer; inner error: the target's refusal; `Ok(Ok(note))`: done
  - `struct LogRow { at: String, from: NodeId, command: String, result: String }`, `async fn log_rows(store: &Store, limit: i64) -> Result<Vec<LogRow>>`
  - `const TIMEOUT: Duration` (15 s)

- [ ] **Step 1: Message kinds**

`src/cluster/msg.rs`, in `enum Msg` after `OwnerHelloReply`:

```rust
    /// Managing node → sibling: do this. `sig` is the owner key's
    /// signature over sender, target, `counter` and the command.
    OwnerCmd {
        counter: u64,
        cmd: super::owner::cmd::OwnerCmd,
        sig: serde_bytes::ByteBuf,
    },
    /// `counter` is the node's counter after the command.
    OwnerReply {
        counter: u64,
        error: Option<String>,
        data: Option<super::owner::cmd::OwnerData>,
    },
```

- [ ] **Step 2: Write the failing tests**

Create `src/cluster/owner/cmd.rs` with imports and tests:

```rust
//! Owner commands: what a managing node tells a sibling to do. A command
//! is signed with the ownership key over who sends it to whom, the
//! target's command counter and the command itself, so nobody without the
//! key can issue one and no relay can replay or redirect one.
use super::{OwnerId, OwnerKey};
use crate::cluster::Node;
use crate::cluster::identity::NodeId;
use crate::cluster::msg::Msg;
use crate::cluster::remote::{self, State};
use crate::cluster::rpc::proto::OWNER_PROTO;
use crate::settings::{Changes, Settings};
use crate::store::Store;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::identity::Identity;

    #[test]
    fn the_signature_covers_sender_target_counter_and_command() {
        let (k, other) = (OwnerKey::generate().unwrap(), OwnerKey::generate().unwrap());
        let (a, b) = (
            Identity::generate().unwrap().id,
            Identity::generate().unwrap().id,
        );
        let cmd = OwnerCmd::Settings {
            base_version: 4,
            changes: Changes {
                max_workers: Some(3),
                ..Default::default()
            },
        };
        let sig = sign(&k, &a, &b, 7, &cmd);
        assert!(verify(&k.id, &a, &b, 7, &cmd, &sig));
        assert!(!verify(&other.id, &a, &b, 7, &cmd, &sig), "another owner");
        assert!(!verify(&k.id, &b, &a, 7, &cmd, &sig), "direction");
        assert!(!verify(&k.id, &a, &b, 8, &cmd, &sig), "counter");
        assert!(!verify(&k.id, &a, &b, 7, &OwnerCmd::Status, &sig), "command");
    }

    #[test]
    fn commands_describe_themselves_for_the_log() {
        assert_eq!(OwnerCmd::Status.describe(), "status");
        let c = OwnerCmd::Settings {
            base_version: 0,
            changes: Changes {
                max_workers: Some(2),
                scanner: Some(false),
                ..Default::default()
            },
        };
        assert_eq!(c.describe(), "settings: workers=2, scanner=off");
    }

    #[tokio::test]
    async fn the_log_lists_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(&dir.path().join("t.db")).await.unwrap();
        let from = Identity::generate().unwrap().id;
        log(&store, &from, "one", "done").await.unwrap();
        log(&store, &from, "two", "refused: x").await.unwrap();
        let rows = log_rows(&store, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].command.as_str(), rows[0].from), ("two", from));
        assert_eq!(rows[1].result, "done");
    }
}
```

Add `pub mod cmd;` to `src/cluster/owner/mod.rs`.

Append to `tests/cluster.rs`:

```rust
/// A managing node changes a sibling's settings; nobody else can, and a
/// command works only once.
#[tokio::test]
async fn a_managing_node_changes_a_siblings_settings() {
    use peephole::cluster::owner::{self, cmd, fleet};
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let (id, d) = new_node("d");
    let na = boot(ia, &a, &[&b, &c, &d], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c, &d], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b, &d], DEFAULT).await;
    let _nd = boot(id, &d, &[&a, &b, &c], DEFAULT).await;
    // Adopted while the nodes run: no restart is needed.
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    let stranger = owner::create(&nc.store, c.id).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;

    // Commands go only to members known to speak version 3: wait until a
    // and c have b's and d's own descriptions.
    eventually("the nodes know each other's version", || async {
        [&na, &nc].iter().all(|n| {
            let m = n.members();
            [b.id, d.id]
                .iter()
                .all(|id| m.get(id).is_some_and(|x| x.proto_max >= 3))
        })
    })
    .await;

    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    assert_eq!((st.counter, st.state.version), (0, 0));
    let faster = cmd::OwnerCmd::Settings {
        base_version: 0,
        changes: Changes {
            max_scans_per_hour: Some(77),
            ..Default::default()
        },
    };
    let note = cmd::run(&na.node, &key, b.id, 0, faster.clone())
        .await
        .unwrap()
        .unwrap();
    assert!(note.contains("version 1"), "{note}");
    assert_eq!(nb.pace.get().max_scans_per_hour, 77);
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 1);
    let log = cmd::log_rows(&nb.store, 10).await.unwrap();
    assert_eq!(log.len(), 1, "status is not logged");
    assert_eq!(log[0].from, a.id);
    assert!(log[0].command.contains("scans/h=77"), "{}", log[0].command);

    // The same counter again (a replay, or a second manager): refused.
    let e = cmd::run(&na.node, &key, b.id, 0, faster.clone())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("changed meanwhile"), "{e}");

    // The settings' own rules still apply; the counter is used up anyway.
    let none = cmd::OwnerCmd::Settings {
        base_version: 1,
        changes: Changes {
            listener: Some(false),
            scanner: Some(false),
            web: Some(false),
            ..Default::default()
        },
    };
    let e = cmd::run(&na.node, &key, b.id, 1, none)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("at least one role"), "{e}");
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 2);

    // Another owner's key is not accepted, and nothing changes.
    let e = cmd::run(&nc.node, &stranger, b.id, 2, faster.clone())
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 2);

    // A node that does not keep the key has nothing to send with.
    let e = cmd::kept_key(&nb.node).await.err().unwrap().to_string();
    assert!(e.contains("not kept on this node"), "{e}");

    // A node without an owner refuses.
    let e = cmd::run(&na.node, &key, d.id, 0, faster)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no owner"), "{e}");
}

/// A sibling that only dials out gets its commands from the outbox of a
/// member it dials, once.
#[tokio::test]
async fn owner_commands_reach_an_outbound_only_sibling() {
    use peephole::cluster::owner::{self, cmd};
    use peephole::settings::Changes;
    let (ia, a) = new_node("a");
    let (ir, r) = new_node("r");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&r], DEFAULT).await;
    let nr = boot(ir, &r, &[&a], DEFAULT).await;
    let nb = boot(
        ib,
        &b,
        &[],
        Opts {
            advertise: false,
            ..DEFAULT
        },
    )
    .await;
    let token = invite::create(&nr, &Default::default()).await.unwrap();
    invite::join(&nb, &token).await.unwrap();
    eventually("a knows b, which has no address", || async {
        members::all(&na.store)
            .await
            .unwrap()
            .iter()
            .any(|m| m.id == b.id && m.info_hlc > 0 && m.address.is_none())
    })
    .await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    let slower = cmd::OwnerCmd::Settings {
        base_version: 0,
        changes: Changes {
            cooldown_hours: Some(48),
            ..Default::default()
        },
    };
    eventually_for(Duration::from_secs(40), "the command arrives", || async {
        matches!(
            cmd::run(&na.node, &key, b.id, 0, slower.clone()).await,
            Ok(Ok(_))
        ) || nb.settings.snapshot().cooldown_hours == 48
    })
    .await;
    assert_eq!(nb.settings.snapshot().cooldown_hours, 48);
    assert_eq!(owner::counter(&nb.store).await.unwrap(), 1, "applied once");
}
```

- [ ] **Step 3: Run to see them fail**

Run: `cargo test --lib cluster::owner::cmd`
Expected: does not compile (`cannot find type OwnerCmd`, …).

- [ ] **Step 4: Implement `cmd.rs`**

Insert between the imports and the test module:

```rust
const CMD_DOMAIN: &[u8] = b"peephole-owner-cmd-v1\0";
/// How long to wait for a node's answer.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Commands with a bad signature logged per sender and hour.
const BAD_SIGNATURES_LOGGED: u32 = 10;

/// What an owner may tell a node to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "c", rename_all = "snake_case")]
pub enum OwnerCmd {
    /// Report settings, counter, block list and invites. Changes nothing,
    /// so it is accepted with any counter and not logged.
    Status,
    /// Change runtime settings, like the node's own settings form.
    Settings { base_version: u64, changes: Changes },
}

impl OwnerCmd {
    /// One line for the log.
    pub fn describe(&self) -> String {
        match self {
            OwnerCmd::Status => "status".into(),
            OwnerCmd::Settings { changes, .. } => format!("settings: {}", changes.describe()),
        }
    }
}

/// An invite of the node, without its secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InviteInfo {
    pub id: i64,
    pub label: String,
    pub uses: i64,
    pub max_uses: Option<i64>,
    pub expires_at: Option<String>,
    pub usable: bool,
}

/// What a node tells its owner about itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    /// The counter the next command must name.
    pub counter: u64,
    pub state: State,
    pub build: String,
    pub blocked: Vec<NodeId>,
    pub invites: Vec<InviteInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "d", rename_all = "snake_case")]
pub enum OwnerData {
    Status(Box<Status>),
    /// The command was carried out; `note` says what happened.
    Done { note: String },
}

fn signing_bytes(from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd) -> Vec<u8> {
    let mut m = CMD_DOMAIN.to_vec();
    m.extend_from_slice(&from.0);
    m.extend_from_slice(&to.0);
    m.extend_from_slice(&counter.to_be_bytes());
    // Encoding a plain enum into a Vec cannot fail.
    m.extend_from_slice(&crate::cluster::rpc::cbor::encode(cmd).unwrap_or_default());
    m
}

pub fn sign(key: &OwnerKey, from: &NodeId, to: &NodeId, counter: u64, cmd: &OwnerCmd) -> Vec<u8> {
    key.sign(&signing_bytes(from, to, counter, cmd))
}

pub fn verify(
    owner: &OwnerId,
    from: &NodeId,
    to: &NodeId,
    counter: u64,
    cmd: &OwnerCmd,
    sig: &[u8],
) -> bool {
    owner.verify(&signing_bytes(from, to, counter, cmd), sig)
}

/// One received command, as the node's Ownership page lists it.
#[derive(Debug, Clone)]
pub struct LogRow {
    pub at: String,
    pub from: NodeId,
    pub command: String,
    pub result: String,
}

async fn log(store: &Store, from: &NodeId, command: &str, result: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO owner_log (at, from_node, command, result)
         VALUES (datetime('now'), ?, ?, ?)",
    )
    .bind(&from.0[..])
    .bind(command)
    .bind(result)
    .execute(&store.pool)
    .await?;
    Ok(())
}

/// The newest received commands, newest first.
pub async fn log_rows(store: &Store, limit: i64) -> Result<Vec<LogRow>> {
    let rows: Vec<(String, Vec<u8>, String, String)> = sqlx::query_as(
        "SELECT at, from_node, command, result FROM owner_log ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(&store.pool)
    .await?;
    rows.into_iter()
        .map(|(at, from, command, result)| {
            Ok(LogRow {
                at,
                from: NodeId::from_slice(&from)?,
                command,
                result,
            })
        })
        .collect()
}

/// Bad signatures seen per sender in the current hour.
type Refusals = Arc<Mutex<HashMap<NodeId, (u64, u32)>>>;

fn may_log(seen: &Refusals, from: NodeId) -> bool {
    let hour = crate::cluster::hlc::wall_ms() / 3_600_000;
    let mut all = seen.lock().unwrap();
    all.retain(|_, (h, _)| *h == hour);
    let e = all.entry(from).or_insert((hour, 0));
    e.1 += 1;
    e.1 <= BAD_SIGNATURES_LOGGED
}

async fn status_of(node: &Node, settings: &Settings) -> Result<Status> {
    let invites = crate::cluster::invite::list(&node.store)
        .await?
        .into_iter()
        .map(|i| InviteInfo {
            id: i.id,
            label: i.label,
            uses: i.uses,
            max_uses: i.max_uses,
            expires_at: i.expires_at,
            usable: i.usable,
        })
        .collect();
    Ok(Status {
        counter: super::counter(&node.store).await?,
        state: remote::state(node, settings).await,
        build: crate::VERSION.to_string(),
        blocked: crate::cluster::block::list(&node.store).await?,
        invites,
    })
}

/// Carry out a verified command. Ok: what happened; Err: why not.
async fn execute(
    node: &Arc<Node>,
    settings: &Settings,
    from: NodeId,
    cmd: &OwnerCmd,
) -> Result<String, String> {
    match cmd {
        OwnerCmd::Status => Ok(String::new()),
        OwnerCmd::Settings {
            base_version,
            changes,
        } => match settings.apply_at(*base_version, changes, Some(from)).await {
            Ok(Ok(v)) => {
                if !changes.is_empty() {
                    node.status.local.lock().unwrap().pace =
                        Some(remote::pace_info(settings.snapshot().pace));
                    node.publish_status();
                }
                Ok(format!("settings saved (version {v})"))
            }
            Ok(Err(e)) => Err(e),
            Err(e) => Err(format!("{e:#}")),
        },
    }
}

async fn handle(
    node: &Arc<Node>,
    settings: &Settings,
    seen: &Refusals,
    from: NodeId,
    counter: u64,
    cmd: OwnerCmd,
    sig: &[u8],
) -> Msg {
    let refuse = |counter: u64, e: String| Msg::OwnerReply {
        counter,
        error: Some(e),
        data: None,
    };
    let owned = match super::load(&node.store, node.id()).await {
        Ok(Some(o)) => o,
        Ok(None) => return refuse(0, "this node has no owner".into()),
        Err(e) => return refuse(0, format!("{e:#}")),
    };
    if !verify(&owned.id, &from, &node.id(), counter, &cmd, sig) {
        if may_log(seen, from) {
            tracing::warn!(by = %from.short(), "owner command with a wrong ownership key refused");
            let _ = log(
                &node.store,
                &from,
                &format!("(not verified) {}", cmd.describe()),
                "refused: the ownership key was not accepted",
            )
            .await;
        }
        return refuse(0, "the ownership key was not accepted".into());
    }
    let current = super::counter(&node.store).await.unwrap_or(0);
    if cmd == OwnerCmd::Status {
        return match status_of(node, settings).await {
            Ok(s) => Msg::OwnerReply {
                counter: current,
                error: None,
                data: Some(OwnerData::Status(Box::new(s))),
            },
            Err(e) => refuse(current, format!("{e:#}")),
        };
    }
    // Used up before the command runs: a copy of it never runs again.
    match super::take_counter(&node.store, counter).await {
        Ok(true) => {}
        Ok(false) => {
            let why = "the node changed meanwhile; reload and try again";
            let _ = log(&node.store, &from, &cmd.describe(), &format!("refused: {why}")).await;
            return refuse(current, why.into());
        }
        Err(e) => return refuse(current, format!("{e:#}")),
    }
    let result = execute(node, settings, from, &cmd).await;
    let text = match &result {
        Ok(note) => note.clone(),
        Err(e) => format!("refused: {e}"),
    };
    tracing::info!(by = %from.short(), command = %cmd.describe(), result = %text, "owner command");
    let _ = log(&node.store, &from, &cmd.describe(), &text).await;
    match result {
        Ok(note) => Msg::OwnerReply {
            counter: counter + 1,
            error: None,
            data: Some(OwnerData::Done { note }),
        },
        Err(e) => refuse(counter + 1, e),
    }
}

/// Carry out the owner's commands.
pub fn serve(node: &Arc<Node>, settings: Settings) {
    let weak = Arc::downgrade(node);
    let seen: Refusals = Default::default();
    node.on_message(Arc::new(move |from, msg| {
        let (settings, weak, seen) = (settings.clone(), weak.clone(), seen.clone());
        Box::pin(async move {
            let Msg::OwnerCmd { counter, cmd, sig } = msg else {
                return None;
            };
            let node = weak.upgrade()?;
            Some(handle(&node, &settings, &seen, from, counter, cmd, &sig).await)
        })
    }));
}

/// The ownership key this node keeps.
pub async fn kept_key(node: &Node) -> Result<OwnerKey> {
    match super::load(&node.store, node.id()).await? {
        Some(o) => match o.key {
            Some(k) => Ok(k),
            None => bail!("the ownership key is not kept on this node"),
        },
        None => bail!("this node has no owner"),
    }
}

fn speaks_owner(node: &Node, target: &NodeId) -> Result<()> {
    match node.members().get(target) {
        Some(m) if m.proto_max >= OWNER_PROTO => Ok(()),
        Some(m) => bail!("{} runs a version without ownership", m.name),
        None => bail!("{} is not a member", target.short()),
    }
}

/// Ask `target` for its status, signed with `key`.
pub async fn status(node: &Arc<Node>, key: &OwnerKey, target: NodeId) -> Result<Status> {
    speaks_owner(node, &target)?;
    let cmd = OwnerCmd::Status;
    let sig = sign(key, &node.id(), &target, 0, &cmd);
    let msg = Msg::OwnerCmd {
        counter: 0,
        cmd,
        sig: serde_bytes::ByteBuf::from(sig),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::OwnerReply {
            data: Some(OwnerData::Status(s)),
            ..
        } => Ok(*s),
        Msg::OwnerReply { error: Some(e), .. } => bail!("{e}"),
        other => bail!("unexpected answer {other:?}"),
    }
}

/// Send `cmd` to `target` for its counter `counter`, signed with `key`.
/// The inner error is the target's refusal.
pub async fn run(
    node: &Arc<Node>,
    key: &OwnerKey,
    target: NodeId,
    counter: u64,
    cmd: OwnerCmd,
) -> Result<Result<String, String>> {
    speaks_owner(node, &target)?;
    let sig = sign(key, &node.id(), &target, counter, &cmd);
    let msg = Msg::OwnerCmd {
        counter,
        cmd,
        sig: serde_bytes::ByteBuf::from(sig),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::OwnerReply { error: Some(e), .. } => Ok(Err(e)),
        Msg::OwnerReply {
            data: Some(OwnerData::Done { note }),
            ..
        } => Ok(Ok(note)),
        other => bail!("unexpected answer {other:?}"),
    }
}
```

`crate::cluster::hlc::wall_ms` is `pub(crate)`; that is enough here.

- [ ] **Step 5: Wire it in**

`src/lib.rs`, below `cluster::owner::fleet::serve(node);`:

```rust
        cluster::owner::cmd::serve(node, settings.clone());
```

`tests/cluster.rs::boot_in`, below `cluster::owner::fleet::serve(&node);`:

```rust
    cluster::owner::cmd::serve(&node, settings.clone());
```

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib cluster::owner::cmd && cargo test --test cluster a_managing_node_changes_a_siblings_settings && cargo test --test cluster owner_commands_reach_an_outbound_only_sibling`
Expected: PASS (3 unit tests, 2 integration tests).

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add src/cluster/owner/cmd.rs src/cluster/owner/mod.rs src/cluster/msg.rs src/lib.rs tests/cluster.rs
git commit -m "Ownership: signed owner commands for status and settings

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: The remaining commands and key rotation

**Files:**
- Modify: `src/cluster/owner/cmd.rs`, `tests/cluster.rs`
- Test: unit test additions in `cmd.rs`; `tests/cluster.rs::owner_commands_block_revoke_release_and_leave`, `tests/cluster.rs::rotating_the_key_moves_reachable_siblings_and_retries_the_rest`

**Interfaces:**
- Consumes: Task 5's `cmd` items; `owner::{adopt, reown, release, KEY_OLD_SEED}`; `fleet::{siblings, remember, forget}`; `cluster::block::{block, block_subtree, unblock, purge}`; `cluster::invite::revoke`; `cluster::leave`.
- Produces:
  - New `OwnerCmd` variants: `Block { node: NodeId, subtree: bool }`, `Unblock { node: NodeId }`, `Purge { node: NodeId }`, `InviteRevoke { id: i64 }`, `Leave`, `Reown { owner_id: serde_bytes::ByteBuf, cert: serde_bytes::ByteBuf }`, `Release`
  - `struct Rotation { pub key: OwnerKey, pub moved: Vec<NodeId>, pub pending: Vec<(NodeId, String)> }`
  - `async fn rotate(node: &Arc<Node>) -> Result<Rotation>`
  - `async fn pending(store: &Store) -> Result<Vec<NodeId>>`
  - `async fn retry(node: &Arc<Node>) -> Result<Vec<(NodeId, Result<(), String>)>>`
  - `async fn discard(store: &Store) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

In `cmd.rs`'s test module, extend `commands_describe_themselves_for_the_log`:

```rust
        let n = Identity::generate().unwrap().id;
        assert_eq!(
            OwnerCmd::Block {
                node: n,
                subtree: true
            }
            .describe(),
            format!("block {} with all it admitted", n.short())
        );
        assert_eq!(OwnerCmd::InviteRevoke { id: 4 }.describe(), "revoke invite 4");
        assert_eq!(OwnerCmd::Leave.describe(), "leave the cluster");
        assert_eq!(OwnerCmd::Release.describe(), "release (drop the owner)");
```

Append to `tests/cluster.rs`:

```rust
/// The owner's other commands on a sibling: block and unblock a peer,
/// revoke an invite, release the node, have it leave.
#[tokio::test]
async fn owner_commands_block_revoke_release_and_leave() {
    use peephole::cluster::owner::{self, cmd, cmd::OwnerCmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    // Each command with the counter the node reports.
    let go = |c: OwnerCmd| {
        let (node, key) = (na.node.clone(), &key);
        async move {
            let st = cmd::status(&node, key, b.id).await.unwrap();
            cmd::run(&node, key, b.id, st.counter, c).await.unwrap()
        }
    };

    go(OwnerCmd::Block {
        node: c.id,
        subtree: false,
    })
    .await
    .unwrap();
    assert!(nb.is_blocked(&c.id));
    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    assert_eq!(st.blocked, vec![c.id]);
    // A node is not told to block the node that manages it.
    let e = go(OwnerCmd::Block {
        node: a.id,
        subtree: false,
    })
    .await
    .unwrap_err();
    assert!(e.contains("manages it"), "{e}");
    go(OwnerCmd::Unblock { node: c.id }).await.unwrap();
    eventually("b unblocked c", || async { !nb.is_blocked(&c.id) }).await;

    invite::create(&nb, &Default::default()).await.unwrap();
    let st = cmd::status(&na.node, &key, b.id).await.unwrap();
    let inv = st.invites.iter().find(|i| i.usable).expect("an invite").id;
    go(OwnerCmd::InviteRevoke { id: inv }).await.unwrap();
    let e = go(OwnerCmd::InviteRevoke { id: inv }).await.unwrap_err();
    assert!(e.contains("no usable invite"), "{e}");

    // Released: b has no owner, a no longer counts it, commands end.
    go(OwnerCmd::Release).await.unwrap();
    assert!(owner::load(&nb.store, b.id).await.unwrap().is_none());
    assert!(fleet::siblings(&na.store).await.unwrap().is_empty());
    let e = cmd::run(&na.node, &key, b.id, 0, OwnerCmd::Leave)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("no owner"), "{e}");

    // Leave: adopted again, then told to leave.
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    go(OwnerCmd::Leave).await.unwrap();
    eventually("a sees that b left", || async {
        knows(&na, b.id, false).await
    })
    .await;
}

/// Rotation moves the siblings that answer to the new key and keeps the
/// old one for the rest until they are moved or given up.
#[tokio::test]
async fn rotating_the_key_moves_reachable_siblings_and_retries_the_rest() {
    use peephole::cluster::owner::{self, cmd, cmd::OwnerCmd, fleet};
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let (ic, c) = new_node("c");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let old = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &old, false).await.unwrap();
    owner::adopt(&nc.store, c.id, &old, false).await.unwrap();
    eventually("a finds b and c", || async {
        fleet::discover(&na.node).await.unwrap().len() == 2
    })
    .await;
    // c cannot answer a for now: a drops what a blocked peer says.
    peephole::cluster::block::block(&na.node, c.id).await.unwrap();

    let rot = cmd::rotate(&na.node).await.unwrap();
    assert_eq!(rot.moved, vec![b.id]);
    assert_eq!(rot.pending.len(), 1);
    assert_eq!(rot.pending[0].0, c.id);
    assert_ne!(rot.key.id, old.id);
    let mine = owner::load(&na.store, a.id).await.unwrap().unwrap();
    assert_eq!(mine.id, rot.key.id);
    assert!(mine.managing());
    assert_eq!(
        owner::load(&nb.store, b.id).await.unwrap().unwrap().id,
        rot.key.id
    );
    assert_eq!(fleet::siblings(&na.store).await.unwrap(), vec![b.id]);
    assert_eq!(cmd::pending(&na.store).await.unwrap(), vec![c.id]);
    // b no longer takes the old key.
    let e = cmd::run(&na.node, &old, b.id, 0, OwnerCmd::Leave)
        .await
        .unwrap()
        .unwrap_err();
    assert!(e.contains("not accepted"), "{e}");
    // c is still on the old key.
    assert_eq!(owner::load(&nc.store, c.id).await.unwrap().unwrap().id, old.id);

    // Reachable again: the retry moves it and the old key is dropped.
    peephole::cluster::block::unblock(&na.node, c.id).await.unwrap();
    eventually_for(Duration::from_secs(40), "the retry moves c", || async {
        cmd::retry(&na.node)
            .await
            .unwrap()
            .iter()
            .all(|(_, r)| r.is_ok())
    })
    .await;
    assert_eq!(
        owner::load(&nc.store, c.id).await.unwrap().unwrap().id,
        rot.key.id
    );
    assert!(cmd::pending(&na.store).await.unwrap().is_empty());
    assert!(na.store.setting_get("owner.old_seed").await.unwrap().is_none());
    let mut sibs = fleet::siblings(&na.store).await.unwrap();
    sibs.sort();
    let mut want = vec![b.id, c.id];
    want.sort();
    assert_eq!(sibs, want);

    // Giving up on the rest instead: nothing pending, no old key.
    na.store.setting_set("owner.old_seed", "AAAA").await.unwrap();
    cmd::discard(&na.store).await.unwrap();
    assert!(na.store.setting_get("owner.old_seed").await.unwrap().is_none());
}
```

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --lib cluster::owner::cmd`
Expected: does not compile (`no variant named Block`).

- [ ] **Step 3: Add the commands**

In `cmd.rs`, extend `enum OwnerCmd`:

```rust
    /// Block a peer on the node (its local block list).
    Block { node: NodeId, subtree: bool },
    Unblock { node: NodeId },
    /// Delete a blocked peer's data on the node.
    Purge { node: NodeId },
    /// Revoke one of the node's invites.
    InviteRevoke { id: i64 },
    /// The node leaves the cluster and keeps its data.
    Leave,
    /// Take another owner: its id and its certificate for the node.
    Reown {
        owner_id: serde_bytes::ByteBuf,
        cert: serde_bytes::ByteBuf,
    },
    /// The node drops its owner.
    Release,
```

Extend `describe`:

```rust
            OwnerCmd::Block { node, subtree } => format!(
                "block {}{}",
                node.short(),
                if *subtree { " with all it admitted" } else { "" }
            ),
            OwnerCmd::Unblock { node } => format!("unblock {}", node.short()),
            OwnerCmd::Purge { node } => format!("purge {}", node.short()),
            OwnerCmd::InviteRevoke { id } => format!("revoke invite {id}"),
            OwnerCmd::Leave => "leave the cluster".into(),
            OwnerCmd::Reown { owner_id, .. } => match OwnerId::from_slice(owner_id) {
                Ok(id) => format!("take owner {}", id.short()),
                Err(_) => "take another owner".into(),
            },
            OwnerCmd::Release => "release (drop the owner)".into(),
```

Extend `execute` (the `err` helper goes at the top of the function):

```rust
    let err = |e: anyhow::Error| format!("{e:#}");
```

```rust
        OwnerCmd::Block { node: peer, subtree } => {
            if *peer == from {
                return Err("a node is not told to block the node that manages it".into());
            }
            if *subtree {
                let (ids, n) = crate::cluster::block::block_subtree(node, *peer)
                    .await
                    .map_err(err)?;
                Ok(format!(
                    "blocked {} and the {} node(s) it admitted ({n} records out of view)",
                    peer.short(),
                    ids.len() - 1
                ))
            } else {
                let n = crate::cluster::block::block(node, *peer).await.map_err(err)?;
                Ok(format!("blocked {} ({n} records out of view)", peer.short()))
            }
        }
        OwnerCmd::Unblock { node: peer } => {
            if crate::cluster::block::unblock(node, *peer).await.map_err(err)? {
                Ok(format!("unblocked {}", peer.short()))
            } else {
                Err(format!("{} was not blocked", peer.short()))
            }
        }
        OwnerCmd::Purge { node: peer } => {
            let n = crate::cluster::block::purge(node, *peer).await.map_err(err)?;
            Ok(format!("purged {} ({n} log entries deleted)", peer.short()))
        }
        OwnerCmd::InviteRevoke { id } => {
            if crate::cluster::invite::revoke(&node.store, *id).await.map_err(err)? {
                Ok(format!("invite {id} revoked"))
            } else {
                Err(format!("no usable invite {id}"))
            }
        }
        OwnerCmd::Leave => {
            // After the answer is on its way: leaving stops the node's
            // contact with its peers.
            let node = node.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Err(e) = crate::cluster::leave(&node).await {
                    tracing::warn!(?e, "leaving on the owner's command failed");
                }
            });
            Ok("leaving the cluster".into())
        }
        OwnerCmd::Reown { owner_id, cert } => {
            let id = OwnerId::from_slice(owner_id).map_err(err)?;
            super::reown(&node.store, node.id(), id, cert)
                .await
                .map_err(err)?;
            Ok(format!("owner is now {}", id.short()))
        }
        OwnerCmd::Release => {
            super::release(&node.store).await.map_err(err)?;
            Ok("released: this node has no owner".into())
        }
```

`block::block`, `block_subtree`, `unblock` and `purge` take `&Node`; `node` here is `&Arc<Node>` and derefs. If `cluster::leave` is not reachable as `crate::cluster::leave`, it is defined in `src/cluster/mod.rs:145`.

In `run`, after a successful answer, keep the sender's own list right. The first line (`speaks_owner(node, &target)?;`) stays; the rest of the body becomes:

```rust
    let leaves_fleet = matches!(cmd, OwnerCmd::Release | OwnerCmd::Reown { .. });
    let sig = sign(key, &node.id(), &target, counter, &cmd);
    let msg = Msg::OwnerCmd {
        counter,
        cmd,
        sig: serde_bytes::ByteBuf::from(sig),
    };
    match node.request(target, msg, TIMEOUT).await? {
        Msg::OwnerReply { error: Some(e), .. } => Ok(Err(e)),
        Msg::OwnerReply {
            data: Some(OwnerData::Done { note }),
            ..
        } => {
            if leaves_fleet {
                super::fleet::forget(&node.store, &target).await?;
            }
            Ok(Ok(note))
        }
        other => bail!("unexpected answer {other:?}"),
    }
```

- [ ] **Step 4: Add rotation**

Append to `cmd.rs` (before the test module):

```rust
/// What a key rotation did.
pub struct Rotation {
    /// The new key, to show once.
    pub key: OwnerKey,
    pub moved: Vec<NodeId>,
    /// Siblings still on the old key, and why.
    pub pending: Vec<(NodeId, String)>,
}

/// Tell `target` (still under `signer`) to take `new` as its owner.
async fn reown_one(
    node: &Arc<Node>,
    signer: &OwnerKey,
    new: &OwnerKey,
    target: NodeId,
) -> Result<(), String> {
    let st = status(node, signer, target)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let cmd = OwnerCmd::Reown {
        owner_id: serde_bytes::ByteBuf::from(new.id.0.to_vec()),
        cert: serde_bytes::ByteBuf::from(new.certify(&target)),
    };
    match run(node, signer, target, st.counter, cmd).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Siblings still on the previous key after a rotation.
pub async fn pending(store: &Store) -> Result<Vec<NodeId>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT node FROM reown_pending ORDER BY node")
        .fetch_all(&store.pool)
        .await?;
    rows.iter().map(|r| NodeId::from_slice(r)).collect()
}

/// Replace the ownership key: every sibling that answers takes the new
/// one, then this node does. The old key stays here for the rest (see
/// [`retry`], [`discard`]).
pub async fn rotate(node: &Arc<Node>) -> Result<Rotation> {
    let old = kept_key(node).await?;
    let new = OwnerKey::generate()?;
    let (mut moved, mut pending) = (vec![], vec![]);
    for s in super::fleet::siblings(&node.store).await? {
        match reown_one(node, &old, &new, s).await {
            Ok(()) => moved.push(s),
            Err(e) => pending.push((s, e)),
        }
    }
    // Forgets the siblings and any earlier rotation.
    super::adopt(&node.store, node.id(), &new, true).await?;
    for m in &moved {
        super::fleet::remember(&node.store, m, &new.certify(m)).await?;
    }
    if !pending.is_empty() {
        node.store
            .setting_set(
                super::KEY_OLD_SEED,
                &data_encoding::BASE64URL_NOPAD.encode(&old.seed()),
            )
            .await?;
        for (p, _) in &pending {
            sqlx::query("INSERT OR IGNORE INTO reown_pending (node) VALUES (?)")
                .bind(&p.0[..])
                .execute(&node.store.pool)
                .await?;
        }
    }
    Ok(Rotation {
        key: new,
        moved,
        pending,
    })
}

/// Try again to move the siblings a rotation did not reach. When none is
/// left, the old key is deleted.
pub async fn retry(node: &Arc<Node>) -> Result<Vec<(NodeId, Result<(), String>)>> {
    let new = kept_key(node).await?;
    let Some(old) = node.store.setting_get(super::KEY_OLD_SEED).await? else {
        bail!("no rotation is waiting for siblings");
    };
    let seed: [u8; 32] = data_encoding::BASE64URL_NOPAD
        .decode(old.as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("the stored previous key is unreadable"))?;
    let old = OwnerKey::from_seed(seed)?;
    let mut out = vec![];
    for p in pending(&node.store).await? {
        let r = reown_one(node, &old, &new, p).await;
        if r.is_ok() {
            sqlx::query("DELETE FROM reown_pending WHERE node = ?")
                .bind(&p.0[..])
                .execute(&node.store.pool)
                .await?;
            super::fleet::remember(&node.store, &p, &new.certify(&p)).await?;
        }
        out.push((p, r));
    }
    if pending(&node.store).await?.is_empty() {
        discard(&node.store).await?;
    }
    Ok(out)
}

/// Give up on the siblings still on the previous key: delete it.
pub async fn discard(store: &Store) -> Result<()> {
    for sql in [
        "DELETE FROM reown_pending",
        "DELETE FROM settings WHERE key = 'owner.old_seed'",
    ] {
        sqlx::query(sql).execute(&store.pool).await?;
    }
    Ok(())
}
```

`run` forgets the target after a `Reown`; `rotate` and `retry` remember it again right after, under the new key, so the order above matters.

- [ ] **Step 5: Run the tests**

Run: `cargo test --lib cluster::owner && cargo test --test cluster owner_commands_block_revoke_release_and_leave && cargo test --test cluster rotating_the_key_moves`
Expected: PASS. The rotation test takes about 20 s (one command to the blocked sibling runs into its timeout).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add src/cluster/owner/cmd.rs tests/cluster.rs
git commit -m "Ownership: block, invites, leave, release and key rotation

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Cluster › Ownership page

**Files:**
- Create: `src/admin/cluster_owner.rs`, `templates/admin_cluster_ownership.html`
- Modify: `src/admin/mod.rs` (module, router), `src/admin/views.rs:275-278` (`CLUSTER_TABS`), `tests/cluster.rs`
- Test: `tests/cluster.rs::admin_takes_and_gives_up_ownership_in_the_web_interface`

**Interfaces:**
- Consumes: `owner::{load, create, adopt, forget_key, release, OwnerKey}`, `fleet::{siblings, discover}`, `cmd::{kept_key, rotate, retry, discard, pending, log_rows}`; `admin::cluster::{node, back_to, views, rules_check, MemberView}`.
- Produces: `admin::cluster_owner::routes() -> Router<Arc<AdminState>>`; routes `GET /admin/cluster/ownership` and `POST /admin/cluster/ownership/{create,adopt,forget-key,release,show-key,rotate,retry,discard}`; tab key `"ownership"`.

Notices and errors after a redirect travel in a cookie that the page script shows (`admin::pages::redirect_with_notice`), so they are not in the HTML a test receives. Tests assert on state and on text the template renders itself.

- [ ] **Step 1: Write the failing test**

Append to `tests/cluster.rs`:

```rust
/// The Ownership page: create a key (shown once), adopt it on a second
/// node, see that node listed, see received commands, forget and release.
#[tokio::test]
async fn admin_takes_and_gives_up_ownership_in_the_web_interface() {
    use peephole::cluster::owner::{self, cmd, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let (admin_a, base_a) = admin_on(&na).await;
    let (admin_b, base_b) = admin_on(&nb).await;
    let page_a = format!("{base_a}/admin/cluster/ownership");
    let page_b = format!("{base_b}/admin/cluster/ownership");

    let html = text(&admin_a, page_a.clone()).await;
    assert!(html.contains("No owner"), "{html}");
    assert!(html.contains("Ownership</a>"), "the tab is there");

    // Create: the key is on the answer, and nowhere afterwards.
    let r = admin_a.post(format!("{page_a}/create")).send().await.unwrap();
    assert!(r.status().is_success());
    let html = r.text().await.unwrap();
    let key = html
        .split("peephole-own1:")
        .nth(1)
        .and_then(|s| s.split('<').next())
        .map(|s| format!("peephole-own1:{}", s.trim()))
        .expect("the key is shown");
    let html = text(&admin_a, page_a.clone()).await;
    assert!(!html.contains("peephole-own1:"), "shown once");
    assert!(html.contains("key kept here"), "{html}");
    // A second create does not replace the owner.
    let before = owner::load(&na.store, a.id).await.unwrap().unwrap().id;
    admin_a.post(format!("{page_a}/create")).send().await.unwrap();
    assert_eq!(owner::load(&na.store, a.id).await.unwrap().unwrap().id, before);

    // On b: an invite token is not a key; the real key is adopted, not kept.
    admin_b
        .post(format!("{page_b}/adopt"))
        .form(&[("key", "peephole1:abc")])
        .send()
        .await
        .unwrap();
    assert!(owner::load(&nb.store, b.id).await.unwrap().is_none());
    let r = admin_b
        .post(format!("{page_b}/adopt"))
        .form(&[("key", key.as_str())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let html = text(&admin_b, page_b.clone()).await;
    assert!(html.contains("key not kept here"), "{html}");

    // a lists b under My nodes; b lists what a told it to do.
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    let html = text(&admin_a, page_a.clone()).await;
    assert!(html.contains("My nodes") && html.contains("node-bravo"), "{html}");
    let kept = cmd::kept_key(&na.node).await.unwrap();
    cmd::run(
        &na.node,
        &kept,
        b.id,
        0,
        cmd::OwnerCmd::Settings {
            base_version: 0,
            changes: peephole::settings::Changes {
                cooldown_hours: Some(12),
                ..Default::default()
            },
        },
    )
    .await
    .unwrap()
    .unwrap();
    let html = text(&admin_b, page_b.clone()).await;
    assert!(
        html.contains("Commands received") && html.contains("settings: cooldown=12h"),
        "{html}"
    );
    assert!(html.contains("node-alpha"), "who sent it");

    // Show key again, forget it, release b.
    let r = admin_a.post(format!("{page_a}/show-key")).send().await.unwrap();
    assert!(r.text().await.unwrap().contains(&key));
    admin_a.post(format!("{page_a}/forget-key")).send().await.unwrap();
    let html = text(&admin_a, page_a.clone()).await;
    assert!(html.contains("key not kept here"), "{html}");
    admin_b.post(format!("{page_b}/release")).send().await.unwrap();
    let html = text(&admin_b, page_b).await;
    assert!(html.contains("No owner"), "{html}");
}
```

- [ ] **Step 2: Run to see it fail**

Run: `cargo test --test cluster admin_takes_and_gives_up_ownership`
Expected: FAIL (the page answers 404).

- [ ] **Step 3: The tab**

`src/admin/views.rs`, `CLUSTER_TABS`:

```rust
pub const CLUSTER_TABS: &[(&str, &str, &str)] = &[
    ("members", "/admin/cluster", "Members"),
    ("access", "/admin/cluster/access", "Access"),
    ("ownership", "/admin/cluster/ownership", "Ownership"),
];
```

- [ ] **Step 4: The handlers**

Create `src/admin/cluster_owner.rs`:

```rust
//! Cluster › Ownership: this node's owner, the nodes that share it, and
//! the owner commands this node received.
use crate::admin::AdminState;
use crate::admin::auth::SessionUser;
use crate::admin::cluster::{MemberView, back_to, node, rules_check, views};
use crate::admin::error::{AppResult, render};
use crate::admin::views::Chrome;
use crate::cluster::Node;
use crate::cluster::owner::{self, OwnerKey, cmd, fleet};
use askama::Template;
use axum::{
    Router,
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use std::collections::HashMap;
use std::sync::Arc;

const PAGE: &str = "/admin/cluster/ownership";

pub fn routes() -> Router<Arc<AdminState>> {
    Router::new()
        .route(PAGE, get(page))
        .route("/admin/cluster/ownership/create", post(create))
        .route("/admin/cluster/ownership/adopt", post(adopt))
        .route("/admin/cluster/ownership/forget-key", post(forget_key))
        .route("/admin/cluster/ownership/release", post(release))
        .route("/admin/cluster/ownership/show-key", post(show_key))
        .route("/admin/cluster/ownership/rotate", post(rotate))
        .route("/admin/cluster/ownership/retry", post(retry))
        .route("/admin/cluster/ownership/discard", post(discard))
}

/// One of the operator's nodes.
struct NodeRow {
    key: String,
    name: String,
    short: String,
    roles: String,
    version: String,
    seen: String,
    is_self: bool,
}

/// One received command.
struct LogView {
    at: String,
    from: String,
    command: String,
    result: String,
}

#[derive(Template)]
#[template(path = "admin_cluster_ownership.html")]
struct OwnershipPage {
    chrome: Chrome,
    /// The owner id, short; None: no owner.
    owner: Option<String>,
    /// This node keeps the key.
    managing: bool,
    /// The key itself: after creating or rotating it, or when asked for.
    shown_key: Option<String>,
    nodes: Vec<NodeRow>,
    /// Names of nodes still on the previous key after a rotation.
    pending: Vec<String>,
    log: Vec<LogView>,
}

async fn render_page(st: &AdminState, shown_key: Option<String>) -> AppResult<Html<String>> {
    let node = node(st)?;
    let owned = owner::load(&node.store, node.id()).await?;
    let check = rules_check(st, node).await?;
    let (me, members) = views(node, &check).await?;
    let sibs: Vec<String> = fleet::siblings(&node.store)
        .await?
        .iter()
        .map(|id| id.to_string())
        .collect();
    let names: HashMap<String, String> = members
        .iter()
        .map(|m| (m.key.clone(), m.name.clone()))
        .collect();
    let row = |m: &MemberView| NodeRow {
        key: m.key.clone(),
        name: m.name.clone(),
        short: m.short.clone(),
        roles: m.roles.clone(),
        version: m.version.clone(),
        seen: m.last_seen.clone(),
        is_self: m.is_self,
    };
    let mut nodes = vec![];
    if owned.is_some() {
        nodes.push(row(&me));
        nodes.extend(members.iter().filter(|m| sibs.contains(&m.key)).map(row));
    }
    let pending = cmd::pending(&node.store)
        .await?
        .iter()
        .map(|id| {
            names
                .get(&id.to_string())
                .cloned()
                .unwrap_or_else(|| id.short())
        })
        .collect();
    let log = cmd::log_rows(&node.store, 50)
        .await?
        .into_iter()
        .map(|r| LogView {
            from: names
                .get(&r.from.to_string())
                .cloned()
                .unwrap_or_else(|| r.from.short()),
            at: r.at,
            command: r.command,
            result: r.result,
        })
        .collect();
    render(&OwnershipPage {
        chrome: Chrome::new(true, "admin"),
        owner: owned.as_ref().map(|o| o.id.short()),
        managing: owned.as_ref().is_some_and(|o| o.managing()),
        shown_key,
        nodes,
        pending,
        log,
    })
}

async fn page(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Html<String>> {
    render_page(&st, None).await
}

/// Look for siblings now instead of at the loop's next tick.
fn discover_soon(node: &Arc<Node>) {
    let node = node.clone();
    tokio::spawn(async move {
        if let Err(e) = fleet::discover(&node).await {
            tracing::debug!(?e, "sibling discovery failed");
        }
    });
}

/// Generate a key, make this node owned and managing, show the key once.
async fn create(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    if owner::load(&node.store, node.id()).await?.is_some() {
        return Ok(back_to(
            PAGE,
            None,
            Some("This node already has an owner. Release it first.".into()),
        ));
    }
    let key = owner::create(&node.store, node.id()).await?;
    Ok(render_page(&st, Some(key.encode())).await?.into_response())
}

#[derive(serde::Deserialize)]
struct AdoptForm {
    key: String,
    /// Ticked: this node keeps the key and manages the others.
    keep: Option<String>,
}

async fn adopt(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    Form(f): Form<AdoptForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let key = match OwnerKey::parse(&f.key) {
        Ok(k) => k,
        Err(e) => return Ok(back_to(PAGE, None, Some(format!("{e:#}")))),
    };
    owner::adopt(&node.store, node.id(), &key, f.keep.is_some()).await?;
    discover_soon(node);
    Ok(back_to(
        PAGE,
        Some(format!("This node is now owned by {}.", key.id.short())),
        None,
    ))
}

async fn forget_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(if owner::forget_key(&node.store).await? {
        back_to(
            PAGE,
            Some("The key is no longer kept on this node. It stays owned.".into()),
            None,
        )
    } else {
        back_to(PAGE, None, Some("No key was kept on this node.".into()))
    })
}

async fn release(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(if owner::release(&node.store).await? {
        back_to(PAGE, Some("This node has no owner now.".into()), None)
    } else {
        back_to(PAGE, None, Some("This node had no owner.".into()))
    })
}

async fn show_key(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match cmd::kept_key(node).await {
        Ok(k) => render_page(&st, Some(k.encode())).await?.into_response(),
        Err(e) => back_to(PAGE, None, Some(format!("{e:#}"))),
    })
}

/// Replace the key on every node that answers, then here; show the new one.
async fn rotate(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match cmd::rotate(node).await {
        Ok(r) => render_page(&st, Some(r.key.encode()))
            .await?
            .into_response(),
        Err(e) => back_to(PAGE, None, Some(format!("Not rotated: {e:#}"))),
    })
}

async fn retry(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    Ok(match cmd::retry(node).await {
        Ok(results) => {
            let failed = results.iter().filter(|(_, r)| r.is_err()).count();
            back_to(
                PAGE,
                Some(format!(
                    "{} node(s) moved to the new key, {failed} still on the previous one.",
                    results.len() - failed
                )),
                None,
            )
        }
        Err(e) => back_to(PAGE, None, Some(format!("{e:#}"))),
    })
}

async fn discard(_u: SessionUser, State(st): State<Arc<AdminState>>) -> AppResult<Response> {
    let node = node(&st)?;
    cmd::discard(&node.store).await?;
    Ok(back_to(
        PAGE,
        Some(
            "The previous key is deleted. Nodes still on it are no longer yours until you adopt them again."
                .into(),
        ),
        None,
    ))
}
```

If `admin::cluster::node` returns `Option`/`Result<&Arc<Node>>` under another name or visibility than the import assumes, look at how `src/admin/cluster_access.rs` imports and calls it (`use crate::admin::cluster::{…, node};`, `let node = node(&st)?;`) and do the same. `MemberView`, `views` and `rules_check` are already `pub`/`pub(crate)` in `src/admin/cluster.rs`.

In `src/admin/mod.rs` add `pub mod cluster_owner;` below `pub mod cluster_access;` and `.merge(cluster_owner::routes())` below `.merge(cluster_access::routes())`.

- [ ] **Step 5: The template**

Create `templates/admin_cluster_ownership.html`:

```html
{% extends "layout.html" %}
{% block title %}peephole — cluster ownership{% endblock %}
{% block content %}
{% let sub = "cluster" %}{% include "_admin_nav.html" %}
{% let subtab = "ownership" %}{% let tabs = crate::admin::views::CLUSTER_TABS %}{% let tabs_label = "Cluster pages" %}{% include "_subtabs.html" %}
<div class="page-head"><div><h1>Ownership</h1><p class="muted">One key for all your nodes. Enter it on each; manage them from the ones that keep it.</p></div></div>
<div class="stack">
{% if let Some(k) = shown_key %}
<section class="card"><h2>Ownership key</h2>
  <div class="banner banner-warning">Whoever holds this key controls every node it is entered on. Keep it somewhere safe; this page does not show it again unless you ask.</div>
  <pre class="panel mono break" data-copy>{{ k }}</pre>
  <p class="muted">Enter it on your other nodes: Cluster › Ownership there, or <code>peephole owner adopt</code>.</p>
</section>
{% endif %}
<section class="card"><h2>This node</h2>
{% match owner %}
{% when None %}
  <p><b>No owner.</b> <span class="muted">Nobody can change this node from another node.</span></p>
  <form method="post" action="/admin/cluster/ownership/create"><button class="btn btn-primary" type="submit">Create key</button> <span class="muted small">on your first node; it keeps the key</span></form>
  <form method="post" action="/admin/cluster/ownership/adopt" class="filters">
    <label>Ownership key <input name="key" size="60" class="mono" autocomplete="off" required></label>
    <label class="check"><input type="checkbox" name="keep"> Manage my other nodes from here (keeps the key on this node)</label>
    <button class="btn" type="submit">Adopt with a key</button>
  </form>
{% when Some(o) %}
  <p>Owned by <span class="mono">{{ o }}</span> · {% if managing %}<b>key kept here</b>{% else %}key not kept here{% endif %}</p>
  <div class="row">
    {% if managing %}
    <form method="post" action="/admin/cluster/ownership/show-key"><button class="btn btn-sm" type="submit">Show key</button></form>
    <button class="btn btn-sm" type="button" data-confirm="dlg-forget">Forget key here</button>
    <dialog id="dlg-forget"><h3>Forget the key on this node?</h3><p class="muted">This node stays owned but can no longer manage the others. Make sure you have the key elsewhere.</p>
      <form method="post" action="/admin/cluster/ownership/forget-key" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Forget key</button></form></dialog>
    <button class="btn btn-sm" type="button" data-confirm="dlg-rotate">Rotate key</button>
    <dialog id="dlg-rotate"><h3>Replace the ownership key?</h3><p class="muted">Every node of yours that answers takes the new key; the old one stops working there. The new key is shown once.</p>
      <form method="post" action="/admin/cluster/ownership/rotate" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Rotate key</button></form></dialog>
    {% endif %}
    <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-release">Release this node</button>
    <dialog id="dlg-release"><h3>Release this node?</h3><p class="muted">It has no owner afterwards and cannot be managed from your other nodes.</p>
      <form method="post" action="/admin/cluster/ownership/release" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Release</button></form></dialog>
  </div>
  <details><summary>Adopt with another key</summary>
    <p class="muted">Replaces the current owner of this node.</p>
    <form method="post" action="/admin/cluster/ownership/adopt" class="filters">
      <label>Ownership key <input name="key" size="60" class="mono" autocomplete="off" required></label>
      <label class="check"><input type="checkbox" name="keep"> Keep the key on this node</label>
      <button class="btn" type="submit">Adopt</button>
    </form>
  </details>
{% endmatch %}
</section>
{% if !pending.is_empty() %}
<section class="card"><h2>Still on the previous key</h2>
  <div class="banner banner-warning">{% for p in pending %}{% if !loop.first %}, {% endif %}{{ p }}{% endfor %} did not answer when the key was rotated. The previous key is kept here for them.</div>
  <div class="row">
    <form method="post" action="/admin/cluster/ownership/retry"><button class="btn btn-sm btn-primary" type="submit">Retry</button></form>
    <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-discard">Give up on them</button>
    <dialog id="dlg-discard"><h3>Delete the previous key?</h3><p class="muted">These nodes are then no longer yours until you adopt them again on the node itself.</p>
      <form method="post" action="/admin/cluster/ownership/discard" class="actions"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Delete previous key</button></form></dialog>
  </div>
</section>
{% endif %}
{% if owner.is_some() %}
<section class="card">
  <div class="card-head"><h2>My nodes</h2>{% if !managing %}<span class="muted">read-only: the key is not kept on this node</span>{% endif %}</div>
  <div class="table-wrap"><table>
    <thead><tr><th>Node</th><th>Roles</th><th>Version</th><th>Seen</th></tr></thead>
    <tbody>{% for n in nodes %}<tr>
      <td><a href="/admin/cluster/node/{{ n.key }}"><b>{{ n.name }}</b></a> <span class="mono muted">{{ n.short }}</span>{% if n.is_self %} <span class="muted small">this node</span>{% endif %}</td>
      <td>{{ n.roles }}</td><td class="mono">{{ n.version }}</td><td>{{ n.seen }}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
  {% if nodes.len() == 1 %}<p class="muted">No other node with this key was found yet. Nodes are looked for every few minutes, and at once when a member comes online.</p>{% endif %}
</section>
{% endif %}
<section class="card">
  <div class="card-head"><h2>Commands received</h2><span class="muted">what your managing nodes told this node to do, newest first (UTC)</span></div>
  {% if log.is_empty() %}<p class="muted">None.</p>{% else %}
  <div class="table-wrap"><table>
    <thead><tr><th>When</th><th>From</th><th>Command</th><th>Result</th></tr></thead>
    <tbody>{% for l in log %}<tr>
      <td class="ts">{{ l.at }}</td><td>{{ l.from }}</td><td>{{ l.command }}</td><td>{{ l.result }}</td>
    </tr>{% endfor %}</tbody>
  </table></div>{% endif %}
</section>
</div>
{% endblock %}
```

- [ ] **Step 6: Run the test**

Run: `cargo test --test cluster admin_takes_and_gives_up_ownership`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add src/admin/cluster_owner.rs src/admin/mod.rs src/admin/views.rs templates/admin_cluster_ownership.html tests/cluster.rs
git commit -m "Admin: Cluster › Ownership page

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Member pages through ownership; the config key goes

**Files:**
- Delete: `src/cluster/confkey.rs`
- Create: `src/store/migrations/0011_drop_config_keys.sql`
- Modify: `src/cluster/mod.rs`, `src/cluster/remote.rs`, `src/cluster/msg.rs` (doc comments), `src/cluster/cli.rs`, `src/main.rs`, `src/lib.rs`, `src/config.rs`, `src/settings.rs` (doc comment), `src/store/mod.rs`, `src/admin/cluster.rs`, `src/admin/cluster_access.rs`, `templates/admin_cluster_node.html`, `templates/admin_cluster_access.html`, `templates/admin_cluster.html`, `templates/_cluster_pace_row.html`, `tests/cluster.rs`, `tests/cli.rs`, `install.sh`, `tests/install-smoke.sh`
- Test: `tests/cluster.rs::admin_manages_a_sibling_from_its_page`, `::a_node_without_the_key_shows_its_siblings_read_only`, `::old_config_key_requests_are_answered_with_the_replacement`; unit test in `src/admin/cluster.rs`

**Interfaces:**
- Consumes: `cmd::{kept_key, status, run, OwnerCmd, Status}`, `fleet::siblings`, `owner::load`.
- Produces:
  - `MemberView.sibling: bool` (one of the operator's nodes) and `MemberView.managed: bool` (a sibling, and this node keeps the key) replace `remote_config` and `key_held`
  - `POST /admin/cluster/node/{key}/owner` with form fields `counter`, `action` (`block`, `unblock`, `purge`, `invite-revoke`, `leave`, `release`), `target`, `subtree`, `invite`
  - `POST /admin/cluster/node/{key}` (settings) now needs the form field `counter`
  - `remote::CONFIG_KEY_GONE: &str`

- [ ] **Step 1: Write the failing tests**

In `tests/cluster.rs`, delete the tests `config_key_holders_change_a_nodes_settings` and `admin_configures_another_node_with_its_key` and add:

```rust
/// A node of an earlier version sends a config key request: it is told
/// what replaced it, and no node reports itself open any more.
#[tokio::test]
async fn old_config_key_requests_are_answered_with_the_replacement() {
    use peephole::cluster::msg::Msg;
    let (ia, a) = new_node("a");
    let (ib, b) = new_node("b");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let _nb = boot(ib, &b, &[&a], DEFAULT).await;
    eventually("b answers", || async {
        peephole::cluster::remote::get(&na.node, b.id).await.is_ok()
    })
    .await;
    assert!(!peephole::cluster::remote::get(&na.node, b.id).await.unwrap().open);
    let old = Msg::ConfigSet {
        base_version: 0,
        changes: Default::default(),
        mac: serde_bytes::ByteBuf::new(),
    };
    match na
        .node
        .request(b.id, old, Duration::from_secs(10))
        .await
        .unwrap()
    {
        Msg::ConfigSetReply {
            version: None,
            error: Some(e),
        } => assert!(e.contains("replaced by the ownership key"), "{e}"),
        other => panic!("{other:?}"),
    }
}

/// The counter a member page's forms carry.
fn counter_on(html: &str) -> String {
    html.split("name=\"counter\" value=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("the page carries the counter")
        .to_string()
}

/// The admin of a managing node changes a sibling from its page.
#[tokio::test]
async fn admin_manages_a_sibling_from_its_page() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let (ic, c) = new_node("node-charlie");
    let na = boot(ia, &a, &[&b, &c], DEFAULT).await;
    let nb = boot(ib, &b, &[&a, &c], DEFAULT).await;
    let _nc = boot(ic, &c, &[&a, &b], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("a finds b", || async {
        fleet::discover(&na.node).await.unwrap() == vec![b.id]
    })
    .await;
    let (admin, base) = admin_on(&na).await;
    let b_page = format!("{base}/admin/cluster/node/{}", b.id);

    let members = text(&admin, format!("{base}/admin/cluster")).await;
    assert!(members.contains(">yours<"), "b is marked in the table");
    let html = text(&admin, b_page.clone()).await;
    assert!(html.contains("node-bravo") && html.contains(">yours<"));
    assert!(html.contains("name=\"base_version\" value=\"0\""), "{html}");
    assert!(!html.contains("Remote configuration"), "the old line is gone");
    // c is a member, not a sibling.
    let c_html = text(&admin, format!("{base}/admin/cluster/node/{}", c.id)).await;
    assert!(c_html.contains("Not one of your nodes"), "{c_html}");

    let r = admin
        .post(b_page.clone())
        .form(&[
            ("counter", counter_on(&html).as_str()),
            ("base_version", "0"),
            ("max_workers", "3"),
            ("max_scans_per_hour", "55"),
            ("timeout_minutes", "20"),
            ("cooldown_hours", "12"),
            ("listener", "on"),
            ("web", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    let s = nb.settings.snapshot();
    assert_eq!((s.pace.max_workers, s.pace.max_scans_per_hour), (3, 55));
    assert_eq!(s.pace.timeout_secs, 1200);
    assert_eq!(s.cooldown_hours, 12);
    assert!(
        s.roles.listener && s.roles.web && !s.roles.scanner,
        "unchecked role is off"
    );

    // The pace row cannot change b behind the version check.
    let r = admin
        .post(format!("{base}/admin/cluster/pace"))
        .form(&[
            ("key", b.id.to_string()),
            ("max_workers", "1".into()),
            ("max_scans_per_hour", "11".into()),
            ("timeout_minutes", "5".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(nb.settings.snapshot().pace.max_scans_per_hour, 55);

    // An owner action: b blocks c, and the page then lists it.
    let html = text(&admin, b_page.clone()).await;
    let r = admin
        .post(format!("{b_page}/owner"))
        .form(&[
            ("counter", counter_on(&html)),
            ("action", "block".into()),
            ("target", c.id.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(nb.is_blocked(&c.id));
    let html = text(&admin, b_page.clone()).await;
    assert!(html.contains("Blocked there") && html.contains("node-charlie"), "{html}");

    // A stale form (the counter moved on) changes nothing.
    let r = admin
        .post(format!("{b_page}/owner"))
        .form(&[
            ("counter", "0".to_string()),
            ("action", "unblock".to_string()),
            ("target", c.id.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert!(nb.is_blocked(&c.id));

    // This node's own settings from its own page, as before.
    let page = text(&admin, format!("{base}/admin/system/settings")).await;
    let shown = na.settings.snapshot().version;
    assert!(
        page.contains(&format!("name=\"base_version\" value=\"{shown}\"")),
        "own form carries the version"
    );
    let r = admin
        .post(format!("{base}/admin/cluster/settings"))
        .form(&[
            ("base_version", shown.to_string()),
            ("cooldown_hours", "6".into()),
            ("listener", "on".into()),
            ("scanner", "on".into()),
            ("web", "on".into()),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(na.settings.snapshot().cooldown_hours, 6);

    // b stops answering: only the settings card says so.
    drop(nb);
    let r = admin.get(b_page).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let html = r.text().await.unwrap();
    assert!(
        html.contains("did not answer") && html.contains("Contributions"),
        "{html}"
    );
}

/// On a node that does not keep the key, a sibling's page says so and
/// nothing can be sent from it.
#[tokio::test]
async fn a_node_without_the_key_shows_its_siblings_read_only() {
    use peephole::cluster::owner::{self, fleet};
    let (ia, a) = new_node("node-alpha");
    let (ib, b) = new_node("node-bravo");
    let na = boot(ia, &a, &[&b], DEFAULT).await;
    let nb = boot(ib, &b, &[&a], DEFAULT).await;
    let key = owner::create(&na.store, a.id).await.unwrap();
    owner::adopt(&nb.store, b.id, &key, false).await.unwrap();
    eventually("b knows a as a sibling", || async {
        fleet::discover(&nb.node).await.unwrap() == vec![a.id]
    })
    .await;
    let (admin, base) = admin_on(&nb).await;
    let a_page = format!("{base}/admin/cluster/node/{}", a.id);
    let html = text(&admin, a_page.clone()).await;
    assert!(html.contains(">yours<"), "{html}");
    assert!(
        html.contains("The ownership key is not kept on this node"),
        "{html}"
    );
    assert!(!html.contains("name=\"counter\""), "no form without the key");
    // Posted anyway: nothing is sent, nothing changes.
    for (path, form) in [
        (
            a_page.clone(),
            vec![("counter", "0"), ("base_version", "0"), ("cooldown_hours", "1"), ("listener", "on")],
        ),
        (
            format!("{a_page}/owner"),
            vec![("counter", "0"), ("action", "leave")],
        ),
    ] {
        let r = admin.post(path).form(&form).send().await.unwrap();
        assert!(r.status().is_success());
    }
    assert_eq!(owner::counter(&na.store).await.unwrap(), 0);
    assert_eq!(na.settings.snapshot().version, 0);
    assert!(knows(&nb, a.id, true).await);
}
```

In `src/admin/cluster.rs`'s test `only_a_live_member_whose_key_is_held_is_asked`, rename it to `only_a_live_managed_sibling_is_asked` and replace every `key_held: true` with `sibling: true, managed: true` and `key_held: false` with `managed: false`.

- [ ] **Step 2: Run to see them fail**

Run: `cargo test --test cluster old_config_key_requests`
Expected: does not compile yet or FAILS on the reply text; the later steps make all three pass.

- [ ] **Step 3: Remove the config key from the cluster layer**

1. Delete `src/cluster/confkey.rs`; in `src/cluster/mod.rs` remove `pub mod confkey;`.
2. `src/cluster/mod.rs`, `self_info`: `remote_config: false,` with the comment `// Config keys are gone; the field stays for records of earlier versions.`
3. `src/cluster/record.rs:22` doc comment of `MemberInfo.remote_config`: `/// Unused since ownership replaced config keys; always false in new records.` Same wording at `src/cluster/members.rs:92`.
4. `src/cluster/remote.rs`:

```rust
/// What a node of an earlier version is told when it sends a config key
/// request.
pub const CONFIG_KEY_GONE: &str =
    "config keys were replaced by the ownership key (this node runs a newer version)";
```

   In `State`, document `open` as `/// Always false: config keys are gone. Kept so nodes of earlier versions decode the answer.` and set `open: false` in `state()`. In `serve`, add the arm:

```rust
                Msg::ConfigSet { .. } => Some(Msg::ConfigSetReply {
                    version: None,
                    error: Some(CONFIG_KEY_GONE.into()),
                }),
```

5. `src/cluster/msg.rs`: doc comments of `ConfigSet` / `ConfigSetReply` become `/// A config key request of an earlier version. Still decoded; always answered with a refusal that names the ownership key.` and `/// The refusal.`
6. `src/cluster/cli.rs`: remove the three `config-key` usage lines and the whole `Some("config-key") => { … }` arm. `src/main.rs`: remove `config-key|` from the usage line.
7. `src/lib.rs`: remove the `if … remote_config { confkey::ensure … }` block and `cluster::confkey::serve(node, settings.clone());`. In `check_config`, remove the `summary.push_str(if … remote_config …)` statement. Where the node is started (next to `cluster::remote::serve`), add:

```rust
        if cfg.cluster.as_ref().is_some_and(|c| c.remote_config) {
            tracing::warn!(
                "cluster.remote_config is ignored: config keys were replaced by the ownership \
                 key (peephole owner new, peephole owner adopt)"
            );
        }
```

   Replace "a config key holder" by "the owner" in the comments at `src/lib.rs:245`, `:278` and `src/settings.rs:4`.
8. `src/config.rs`, doc comment of `ClusterConfig.remote_config`: `/// Ignored. It switched config keys on, which the ownership key replaced; still accepted so existing config files load.` Add to the config tests:

```rust
    /// A config file from before ownership still loads.
    #[test]
    fn remote_config_is_still_accepted() {
        let cfg: Config = toml::from_str(
            "database_path = \"/x\"\ndata_dir = \"/x\"\ntrap_listen = \"127.0.0.1:1\"\n\
             [cluster]\nnode_name = \"n\"\nlisten = \"127.0.0.1:7443\"\nremote_config = true\n",
        )
        .unwrap();
        assert!(cfg.cluster.unwrap().remote_config);
    }
```

9. Create `src/store/migrations/0011_drop_config_keys.sql` and append it to `MIGRATIONS` in `src/store/mod.rs`:

```sql
-- Config keys were replaced by the ownership key.
DROP TABLE config_keys;

DELETE FROM settings WHERE key = 'cluster.config_key'
```

10. `tests/cluster.rs`: remove `remote_config` from `struct Opts` and `DEFAULT`, keep `remote_config: false,` in the `ClusterConfig` literal of `boot_in`, and remove the `if o.remote_config { … }` block and the `cluster::confkey::serve(&node, settings.clone());` line.
11. `tests/cli.rs`, `cluster_invite_and_members_work_headless`: delete everything from the comment `// The config key exists only with remote configuration switched on.` to the end of the function body.

- [ ] **Step 4: The member view and page**

`src/admin/cluster.rs`:

1. In `MemberView`, replace the fields `remote_config` and `key_held` (with their doc comments) by:

```rust
    /// One of this operator's nodes (same owner as this node).
    pub sibling: bool,
    /// A sibling this node can command: it keeps the ownership key.
    pub managed: bool,
```

2. In `views`, replace `let keys = crate::cluster::confkey::held(&node.store).await?;` by:

```rust
    let sibs = crate::cluster::owner::fleet::siblings(&node.store).await?;
    let managing = crate::cluster::owner::load(&node.store, me)
        .await?
        .is_some_and(|o| o.managing());
```

   In the per-member literal replace `remote_config: m.remote_config, key_held: keys.contains(&m.id),` by `sibling: sibs.contains(&m.id), managed: managing && sibs.contains(&m.id),`; in the fallback literal for this node replace `remote_config: node.cfg.remote_config, key_held: false,` by `sibling: false, managed: false,`.

3. Routes: remove `.route("/admin/cluster/config-key/forget", post(forget_key))` and the `forget_key` handler; add `.route("/admin/cluster/node/{key}/owner", post(node_owner))`.

4. `SettingsForm` gains `counter: Option<u64>,` as its first field.

5. Replace the `Remote` enum, `asks_remote`, the `remote` computation in `node_view` and `node_set`:

```rust
/// The live part of a node page: its settings, for a node of this operator.
enum Remote {
    /// This node: settings live on System.
    Own,
    /// A member that is not one of this operator's nodes.
    NotYours,
    /// A sibling, but the ownership key is not kept on this node.
    NoKey,
    /// Asked, and it answered.
    Settings {
        status: Box<crate::cluster::owner::cmd::Status>,
        timeout_min: String,
        rec: Option<(u32, i64, String)>,
        has: (bool, bool, bool),
        /// `(key, name)` of the peers it blocks.
        blocked: Vec<(String, String)>,
        /// `(key, name)` of the members it could be told to block.
        peers: Vec<(String, String)>,
    },
    /// Asked; no answer.
    Silent(String),
    /// A managed sibling that is offline or blocked here: not asked.
    Offline,
}

/// Whether a node page asks the member for its status: only a live,
/// unblocked sibling this node can command (an offline one would hold the
/// page for the whole request timeout).
fn asks_remote(m: &MemberView) -> bool {
    !m.is_self && m.managed && m.live && !m.blocked
}
```

   In `node_view`, replace from `let (me, members) = views(node, &check).await?;` through the end of the `let remote = …;` statement by:

```rust
    let (me, members) = views(node, &check).await?;
    let all: Vec<MemberView> = std::iter::once(me).chain(members).collect();
    let key = id.to_string();
    let Some(m) = all.iter().find(|m| m.key == key).cloned() else {
        return Err(AppError::NotFound);
    };
    let contrib = contributions(node)
        .await?
        .into_iter()
        .filter(|c| c.key == m.key || (m.is_self && c.key.is_empty()))
        .collect();
    let remote = if m.is_self {
        Remote::Own
    } else if !m.sibling {
        Remote::NotYours
    } else if !m.managed {
        Remote::NoKey
    } else if !asks_remote(&m) {
        Remote::Offline
    } else {
        use crate::cluster::owner::cmd;
        let asked = async {
            let key = cmd::kept_key(node).await?;
            cmd::status(node, &key, id).await
        };
        match asked.await {
            Ok(st) => {
                let minutes = |secs: u64| {
                    if secs.is_multiple_of(60) {
                        (secs / 60).to_string()
                    } else {
                        format!("{:.1}", secs as f64 / 60.0)
                    }
                };
                let has = |r: &str| st.state.roles.iter().any(|x| x == r);
                let name_of = |k: &str| {
                    all.iter()
                        .find(|x| x.key == k)
                        .map(|x| x.name.clone())
                        .unwrap_or_else(|| k.chars().take(20).collect())
                };
                let blocked: Vec<(String, String)> = st
                    .blocked
                    .iter()
                    .map(|b| (b.to_string(), name_of(&b.to_string())))
                    .collect();
                Remote::Settings {
                    timeout_min: minutes(st.state.pace.timeout_secs),
                    rec: st.state.recommended.map(|p| {
                        (
                            p.max_workers,
                            p.max_scans_per_hour,
                            minutes(p.timeout_secs),
                        )
                    }),
                    has: (has("listener"), has("scanner"), has("web")),
                    peers: all
                        .iter()
                        .filter(|x| !x.is_self && x.key != m.key)
                        .filter(|x| !blocked.iter().any(|(k, _)| *k == x.key))
                        .map(|x| (x.key.clone(), x.name.clone()))
                        .collect(),
                    blocked,
                    status: Box::new(st),
                }
            }
            Err(e) => Remote::Silent(format!("{} did not answer: {e:#}", m.name)),
        }
    };
```

   (The earlier `let key = id.to_string();`, the `find` and the `contrib` statements of the function are replaced by the ones above; keep the `render(&NodePage { … })` call.) `MemberView` already derives `Clone`.

   Replace `node_set` and add `node_owner`:

```rust
/// Send `cmd` to sibling `id` with the key this node keeps. Ok: what the
/// node did; Err: why nothing happened, in words for the page.
async fn owner_run(
    node: &Arc<crate::cluster::Node>,
    id: NodeId,
    counter: u64,
    cmd: crate::cluster::owner::cmd::OwnerCmd,
) -> Result<String, String> {
    use crate::cluster::owner::cmd as oc;
    let key = oc::kept_key(node).await.map_err(|e| format!("{e:#}"))?;
    match oc::run(node, &key, id, counter, cmd).await {
        Ok(Ok(note)) => Ok(note),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(format!("{e:#}")),
    }
}

async fn node_set(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<SettingsForm>,
) -> AppResult<Response> {
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let to = format!("/admin/cluster/node/{id}");
    // Post/redirect/get: a reload of the page does not send the form again.
    Ok(match (f.changes(), f.base_version, f.counter) {
        (Err(e), _, _) => back_to(&to, None, Some(e)),
        (Ok(c), Some(base), Some(counter)) => {
            let cmd = crate::cluster::owner::cmd::OwnerCmd::Settings {
                base_version: base,
                changes: c,
            };
            match owner_run(node, id, counter, cmd).await {
                Ok(_) => back_to(
                    &to,
                    Some("Saved. Roles switch within seconds.".into()),
                    None,
                ),
                Err(e) => back_to(&to, None, Some(format!("Not saved: {e}"))),
            }
        }
        _ => back_to(&to, None, Some("reload the page and try again".into())),
    })
}

/// An owner action on a sibling, from its page.
#[derive(serde::Deserialize)]
struct OwnerForm {
    counter: u64,
    action: String,
    /// The peer a block, unblock or purge is about.
    target: Option<String>,
    subtree: Option<String>,
    /// The invite to revoke.
    invite: Option<i64>,
}

async fn node_owner(
    _u: SessionUser,
    State(st): State<Arc<AdminState>>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Form(f): Form<OwnerForm>,
) -> AppResult<Response> {
    use crate::cluster::owner::cmd::OwnerCmd;
    let node = node(&st)?;
    let Ok(id) = NodeId::parse(&key) else {
        return Err(AppError::NotFound);
    };
    let to = format!("/admin/cluster/node/{id}");
    let peer = f.target.as_deref().and_then(|t| NodeId::parse(t).ok());
    let cmd = match (f.action.as_str(), peer, f.invite) {
        ("block", Some(n), _) => OwnerCmd::Block {
            node: n,
            subtree: f.subtree.is_some(),
        },
        ("unblock", Some(n), _) => OwnerCmd::Unblock { node: n },
        ("purge", Some(n), _) => OwnerCmd::Purge { node: n },
        ("invite-revoke", _, Some(i)) => OwnerCmd::InviteRevoke { id: i },
        ("leave", _, _) => OwnerCmd::Leave,
        ("release", _, _) => OwnerCmd::Release,
        _ => return Ok(back_to(&to, None, Some("unknown action".into()))),
    };
    Ok(match owner_run(node, id, f.counter, cmd).await {
        Ok(note) => back_to(&to, Some(format!("Done: {note}.")), None),
        Err(e) => back_to(&to, None, Some(format!("Not done: {e}"))),
    })
}
```

`src/admin/cluster_access.rs`: remove the routes `/admin/cluster/config-key/rotate` and `/add`, the handlers `rotate_key` and `add_key`, the fields `config_key` and `remote_config` of `AccessPage`, and the `config_key` computation in `render_access`; drop imports that become unused (`KeyForm`, `Redirect`).

- [ ] **Step 5: Templates**

`templates/admin_cluster_access.html`: change the subtitle to `Invites, joining and leaving.` and delete the two sections `<section class="card"><h2>This node's config key</h2>…</section>` and `<section class="card"><h2>Configure another node</h2>…</section>`.

`templates/_cluster_pace_row.html` line 12: `{% if m.key_held %}` → `{% if m.managed %}`.

`templates/admin_cluster.html` line 21, after `<span class="mono muted">{{ m.short }}</span>`: add `{% if m.sibling %} <span class="badge badge-status" data-status="done">yours</span>{% endif %}`.

`templates/admin_cluster_node.html`:

- In the `<h1>`, after `<span class="mono muted">{{ m.short }}</span>`: add `{% if m.sibling %} <span class="badge badge-status" data-status="done">yours</span>{% endif %}`.
- Delete the whole line `<dt>Remote configuration</dt><dd>…</dd>`.
- Replace the `<section class="card"><h2>Settings</h2> … </section>` block at the end by:

```html
<section class="card"><h2>Settings</h2>
{% match remote %}
{% when Remote::Own %}<p>This node's settings: <a href="/admin/system/settings">System › Settings</a>; pace on <a href="/admin/scans#pace">Scans</a>.</p>
{% when Remote::NotYours %}<p class="muted">Not one of your nodes. Only its owner can change it.</p>
{% when Remote::NoKey %}<p class="muted">The ownership key is not kept on this node. Manage {{ m.name }} from a node that keeps it (<a href="/admin/cluster/ownership">Ownership</a>).</p>
{% when Remote::Offline %}<p class="muted">Not live{% if m.blocked %} (blocked){% endif %}: its settings were not asked.</p>
{% when Remote::Silent with (msg) %}<div class="banner banner-warning">{{ msg }}</div>
{% when Remote::Settings with { status, timeout_min, rec, has, blocked, peers } %}
  <form method="post" action="/admin/cluster/node/{{ m.key }}" class="filters">
    <input type="hidden" name="counter" value="{{ status.counter }}">
    <input type="hidden" name="base_version" value="{{ status.state.version }}">
    <label>Workers <input type="number" name="max_workers" min="0" max="16" value="{{ status.state.pace.max_workers }}" required></label>
    <label>Scans per hour <input type="number" name="max_scans_per_hour" min="0" max="3600" value="{{ status.state.pace.max_scans_per_hour }}" required></label>
    <label>Timeout (min) <input type="number" name="timeout_minutes" min="1" max="240" step="any" value="{{ timeout_min }}" required></label>
    <label>Rescan cooldown (h) <input type="number" name="cooldown_hours" min="0" max="8760" value="{{ status.state.cooldown_hours }}" required></label>
    <label class="check"><input type="checkbox" name="listener"{% if has.0 %} checked{% endif %}> Trap</label>
    <label class="check"><input type="checkbox" name="scanner"{% if has.1 %} checked{% endif %}> Scanner</label>
    <label class="check"><input type="checkbox" name="web"{% if has.2 %} checked{% endif %}> Web interface</label>
    <button class="btn btn-primary" type="submit">Save</button>
    <span class="muted small">version {{ status.state.version }} · build {{ status.build }}</span>
  </form>
  {% if let Some(r) = rec %}<p class="muted">Recommended: {{ r.0 }} workers, {{ r.1 }} scans/h, {{ r.2 }} min timeout.</p>{% endif %}
  <p class="muted">Web off removes its admin pages; restore: <code>peephole settings reset roles.web</code></p>

  <h3>Blocked there</h3>
  {% if blocked.is_empty() %}<p class="muted">{{ m.name }} blocks nobody.</p>{% else %}
  <div class="table-wrap"><table><tbody>{% for b in blocked %}<tr>
    <td><b>{{ b.1 }}</b></td>
    <td><form method="post" action="/admin/cluster/node/{{ m.key }}/owner"><input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="target" value="{{ b.0 }}">
      <button class="btn btn-sm" type="submit" name="action" value="unblock">Unblock there</button>
      <button class="btn btn-sm btn-danger" type="submit" name="action" value="purge" title="Deletes its data on {{ m.name }}">Purge there</button></form></td>
  </tr>{% endfor %}</tbody></table></div>{% endif %}
  {% if !peers.is_empty() %}
  <form method="post" action="/admin/cluster/node/{{ m.key }}/owner" class="filters">
    <input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="action" value="block">
    <label>Block a peer there <select name="target">{% for p in peers %}<option value="{{ p.0 }}">{{ p.1 }}</option>{% endfor %}</select></label>
    <label class="check"><input type="checkbox" name="subtree"> with all it admitted</label>
    <button class="btn btn-sm btn-danger" type="submit">Block there</button>
  </form>{% endif %}

  <h3>Its invites</h3>
  {% if status.invites.is_empty() %}<p class="muted">None. Invites are created on the node itself: the invite is a secret and would pass through other members.</p>{% else %}
  <div class="table-wrap"><table>
    <thead><tr><th>For</th><th>Uses</th><th>Expires (UTC)</th><th></th></tr></thead>
    <tbody>{% for i in status.invites %}<tr{% if !i.usable %} class="muted"{% endif %}>
      <td>{{ i.label }}</td>
      <td>{{ i.uses }}{% if let Some(x) = i.max_uses %}/{{ x }}{% endif %}</td>
      <td class="ts">{% if let Some(e) = i.expires_at %}{{ e }}{% else %}never{% endif %}</td>
      <td>{% if i.usable %}<form method="post" action="/admin/cluster/node/{{ m.key }}/owner"><input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="invite" value="{{ i.id }}"><button class="btn btn-sm btn-danger" type="submit" name="action" value="invite-revoke">Revoke invite</button></form>{% endif %}</td>
    </tr>{% endfor %}</tbody>
  </table></div>{% endif %}

  <h3>Leave or release</h3>
  <div class="row">
    <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-owner-leave">Leave the cluster</button>
    <dialog id="dlg-owner-leave"><h3>Have {{ m.name }} leave the cluster?</h3><p class="muted">Its syncing stops; its data stays there. Rejoining needs an invite, entered on the node itself.</p>
      <form method="post" action="/admin/cluster/node/{{ m.key }}/owner" class="actions"><input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="action" value="leave"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Leave</button></form></dialog>
    <button class="btn btn-sm btn-danger" type="button" data-confirm="dlg-owner-release">Release</button>
    <dialog id="dlg-owner-release"><h3>Release {{ m.name }}?</h3><p class="muted">It has no owner afterwards. To manage it again, adopt it on the node itself.</p>
      <form method="post" action="/admin/cluster/node/{{ m.key }}/owner" class="actions"><input type="hidden" name="counter" value="{{ status.counter }}"><input type="hidden" name="action" value="release"><button class="btn" type="button" data-close>Cancel</button><button class="btn btn-danger" type="submit">Release</button></form></dialog>
  </div>
{% endmatch %}
</section>
```

Askama resolves `Remote::…` in this template through the `Remote` enum of `src/admin/cluster.rs` as it does today; the field names in `with { … }` must match the enum exactly.

- [ ] **Step 6: The installer**

`install.sh`:

- Line 34, the variable list: replace the `PEEPHOLE_REMOTE_CONFIG=1|0 …` line by
  `#   PEEPHOLE_REMOTE_CONFIG     ignored (config keys were replaced by the ownership key: peephole owner adopt)`
- Lines 840–843: delete the `if [ "$INTERACTIVE" -eq 1 ] && [ -z "${PEEPHOLE_REMOTE_CONFIG:-}" ]; then … fi` block and the `ask_yn PEEPHOLE_REMOTE_CONFIG …` line.
- Lines 1101–1105: delete the `if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then … else … fi` block that writes `remote_config = …`.
- Line 968 `CONFIG_KEY=""` and lines 1134–1136 (the `if [ "$PEEPHOLE_REMOTE_CONFIG" = 1 ]; then CONFIG_KEY=… fi` block): delete.
- Lines 1450–1456: replace the `if [ -n "$CONFIG_KEY" ]; then … elif grep -q '^remote_config = true' … fi` block (through its `fi`) by

```sh
    echo "    Several nodes of your own: create one ownership key with 'peephole owner new' and enter it"
    echo "    on each of the others with 'peephole owner adopt'; then manage them from Cluster › Ownership."
```

Check with `bash -n install.sh` and `grep -n 'REMOTE_CONFIG\|CONFIG_KEY\|config-key' install.sh` (only the one comment line may remain).

`tests/install-smoke.sh`: remove ` PEEPHOLE_REMOTE_CONFIG=1` (line 191) and ` PEEPHOLE_REMOTE_CONFIG=0` (line 408), and delete the line `grep -q '^remote_config = false' /etc/peephole/config.toml`. Check with `bash -n tests/install-smoke.sh`.

- [ ] **Step 7: Run the tests**

Run: `cargo test --lib admin::cluster && cargo test --lib config:: && cargo test --lib store:: && cargo test --lib cluster::remote && cargo test --test cluster old_config_key_requests && cargo test --test cluster admin_manages_a_sibling && cargo test --test cluster a_node_without_the_key && cargo test --test cli`
Expected: PASS. Then `grep -rn 'confkey\|config_key\|config-key\|key_held' src templates tests` must print nothing but `0011_drop_config_keys.sql`, the `CONFIG_KEY_GONE` constant and the migration list.

- [ ] **Step 8: Commit**

```bash
cargo fmt --all
git add -A src templates tests install.sh
git commit -m "Ownership: member pages through owner commands; the config key is removed

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Docs, changelog, and the wider check

**Files:**
- Modify: `docs/cluster.md`, `docs/operations.md`, `deploy/config.example.toml:204-205`, `CHANGELOG.md`
- Test: formatting, clippy and the three test targets this plan touched

- [ ] **Step 1: `docs/cluster.md`**

In the command list at the top, add after the `peephole cluster leave` line:

```sh
peephole owner new                        # an ownership key for your nodes; this node keeps it
peephole owner adopt                      # on each other node of yours: reads the key from standard input
peephole owner show                       # this node's owner and the nodes that share it
```

Replace the section `## Changing another node's settings` (heading and all five bullets) by:

```markdown
## Your own nodes: ownership

Operators in a cluster need not know each other. The nodes of one operator
can still belong together: they share an **ownership key**.

- **Create it once** (`peephole owner new`, or Cluster › Ownership) and
  **enter it on each of your other nodes** (`peephole owner adopt`, or the
  same page there). The key is shown once; `adopt` reads it from standard
  input so it does not end up in the shell history.
- A node stores the owner's public half and a certificate for itself. The
  key itself stays only where you choose to keep it (`--keep`, or the
  checkbox): those are your **managing nodes**. A scanner that gets broken
  into cannot take over your other nodes if it does not keep the key.
- Your nodes find each other on their own and are marked "yours" on the
  cluster pages. Nothing about ownership is replicated: other operators'
  nodes cannot verify who owns what, though a member that relays the
  messages can see which nodes answered each other.
- From a managing node you can change a sibling's scan pace, rescan
  cooldown and roles, block, unblock and purge peers there, revoke its
  invites, have it leave the cluster, and release it. Each of your nodes
  lists the commands it received (Cluster › Ownership).
- **Not possible from outside**, also for the owner: creating an invite
  (the invite is a secret and would pass through other members), and
  everything in the config file (addresses, paths, WebAuthn, API keys,
  `never_scan`, nmap arguments).
- **A leaked key**: rotate it on a managing node (Cluster › Ownership).
  Every node of yours that answers takes the new key; for the rest the page
  offers to retry. On a node you cannot reach that way, run
  `peephole owner adopt` locally.
- Whoever can log in to a node, or run the CLI on it, can always release it
  or give it another owner. Ownership adds a remote door; it does not lock
  the local one. Protecting the key and the nodes is the operator's job.
- A node's own admin (System › Settings and Scans, or
  `peephole settings set|reset|show`) can always change its runtime
  settings, and roles switch without a restart.

Config keys (`cluster.remote_config`, `peephole cluster config-key`) are
gone. `remote_config` in a config file is ignored.
```

- [ ] **Step 2: `docs/operations.md` and the config example**

`docs/operations.md` lines 27–29: replace
`token, and whether holders of this node's **config key** may change its settings;`
by `token;` (keep the sentence's line breaks tidy). In the variable list near line 91, remove `` `PEEPHOLE_REMOTE_CONFIG`, ``.

`deploy/config.example.toml`: delete the two lines `# remote_config  = false …` and `#                                   # scan pace, rescan cooldown and roles (peephole cluster config-key show)`.

- [ ] **Step 3: `CHANGELOG.md`**

Under `## [Unreleased]` add:

```markdown
### Added

- Ownership. One key for all nodes of an operator (`peephole owner new`,
  `peephole owner adopt`, Cluster › Ownership). Your nodes find each other
  and are marked "yours"; from a node that keeps the key you change a
  sibling's pace, cooldown and roles, block and purge peers there, revoke
  its invites, have it leave, release it, and rotate the key. Each node
  lists the commands it received. See docs/cluster.md.

### Changed

- **Breaking:** config keys are gone. `cluster.remote_config`,
  `peephole cluster config-key` and the config-key cards on Cluster ›
  Access no longer exist; `remote_config` in a config file is ignored with
  a warning. After the upgrade no node can be changed from another node
  until you run `peephole owner new` on one node and `peephole owner adopt`
  on the others.
- Cluster protocol version 3. Ownership works between nodes of this
  version; older members keep syncing as before.
```

- [ ] **Step 4: The wider check**

Run `df -h .` first. If less than 8 GB are free, delete stale copies of this project's own test binaries in `target/debug/deps` (keep the newest per name) before going on.

Run, in this order:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --lib
cargo test --test cli
cargo test --test cluster
bash -n install.sh && bash -n tests/install-smoke.sh
```

Expected: no formatting diff, no clippy warning, all tests PASS. Fix what fails and re-run the failing command only.

- [ ] **Step 5: Commit**

```bash
git add docs/cluster.md docs/operations.md deploy/config.example.toml CHANGELOG.md
git commit -m "Docs: ownership replaces the config key

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
