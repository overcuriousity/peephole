//! Replicated records and their signed wire form.
//!
//! Every record is created by exactly one node (its *origin*), numbered by
//! a per-origin sequence and signed with the origin's key over the exact
//! payload bytes. Relays store and forward entries verbatim, so they cannot
//! alter or forge them, and can forward kinds they do not understand.
use super::identity::{Identity, NodeId};
use serde::{Deserialize, Serialize};

const SIG_DOMAIN: &[u8] = b"peephole-repl-v1\0";

/// Self-description of a node, as carried in membership records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub id: NodeId,
    pub name: String,
    /// `host:port` others dial; None for outbound-only nodes.
    pub address: Option<String>,
    pub roles: Vec<String>,
    /// CIDRs this node never scans; every scanner honours them.
    pub never_scan: Vec<String>,
    pub proto_min: u32,
    pub proto_max: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Record {
    /// The origin vouches for a node (config peer, or a redeemed invite).
    MemberAdd(MemberInfo),
    /// A node describes itself; origin must equal `id`.
    MemberUpdate(MemberInfo),
    /// The origin revokes a node cluster-wide.
    MemberRevoke { id: NodeId },
}

impl Record {
    pub fn kind(&self) -> &'static str {
        match self {
            Record::MemberAdd(_) => "member_add",
            Record::MemberUpdate(_) => "member_update",
            Record::MemberRevoke { .. } => "member_revoke",
        }
    }

    /// Subject uid for row-backed records (tombstone targets); none yet.
    pub fn uid(&self) -> Option<String> {
        None
    }
}

/// A log entry as stored and exchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireEntry {
    pub origin: NodeId,
    pub seq: u64,
    pub hlc: u64,
    pub kind: String,
    pub uid: Option<String>,
    /// CBOR of the [`Record`]; None for an entry a tombstone erased.
    #[serde(with = "serde_bytes")]
    pub payload: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub sig: Option<Vec<u8>>,
    /// The tombstone that erased this entry (payload and sig are gone).
    pub erased_by: Option<String>,
}

fn signing_bytes(
    origin: &NodeId,
    seq: u64,
    hlc: u64,
    kind: &str,
    uid: Option<&str>,
    payload: &[u8],
) -> Vec<u8> {
    let uid = uid.unwrap_or("");
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 52 + kind.len() + uid.len() + payload.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(&origin.0);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&hlc.to_be_bytes());
    m.extend_from_slice(&(kind.len() as u16).to_be_bytes());
    m.extend_from_slice(kind.as_bytes());
    m.extend_from_slice(&(uid.len() as u16).to_be_bytes());
    m.extend_from_slice(uid.as_bytes());
    m.extend_from_slice(payload);
    m
}

impl WireEntry {
    /// Encode and sign a record created by `identity`.
    pub fn sign(identity: &Identity, seq: u64, hlc: u64, record: &Record) -> anyhow::Result<Self> {
        let payload = super::rpc::cbor::encode(record)?;
        let kind = record.kind().to_string();
        let uid = record.uid();
        let sig = identity.sign(&signing_bytes(
            &identity.id,
            seq,
            hlc,
            &kind,
            uid.as_deref(),
            &payload,
        ));
        Ok(Self {
            origin: identity.id,
            seq,
            hlc,
            kind,
            uid,
            payload: Some(payload),
            sig: Some(sig),
            erased_by: None,
        })
    }

    /// True if payload and signature are present and the origin signed them.
    pub fn verify(&self) -> bool {
        match (&self.payload, &self.sig) {
            (Some(p), Some(s)) => self.origin.verify(
                &signing_bytes(
                    &self.origin,
                    self.seq,
                    self.hlc,
                    &self.kind,
                    self.uid.as_deref(),
                    p,
                ),
                s,
            ),
            _ => false,
        }
    }

    /// Decode the payload; None for erased entries or kinds this build
    /// does not know.
    pub fn record(&self) -> Option<Record> {
        let r: Record = super::rpc::cbor::decode(self.payload.as_ref()?).ok()?;
        (r.kind() == self.kind).then_some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: NodeId) -> MemberInfo {
        MemberInfo {
            id,
            name: "n".into(),
            address: Some("h:1".into()),
            roles: vec!["listener".into()],
            never_scan: vec![],
            proto_min: 1,
            proto_max: 1,
        }
    }

    #[test]
    fn signed_entry_verifies_and_tampering_breaks_it() {
        let me = Identity::generate().unwrap();
        let e = WireEntry::sign(&me, 7, 42, &Record::MemberUpdate(info(me.id))).unwrap();
        assert!(e.verify());
        assert_eq!(e.record(), Some(Record::MemberUpdate(info(me.id))));
        // Roundtrip through the wire encoding.
        let back: WireEntry =
            super::super::rpc::cbor::decode(&super::super::rpc::cbor::encode(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert!(back.verify());
        for tamper in [
            |e: &mut WireEntry| e.seq += 1,
            |e: &mut WireEntry| e.hlc += 1,
            |e: &mut WireEntry| e.kind = "member_add".into(),
            |e: &mut WireEntry| e.uid = Some("x".into()),
            |e: &mut WireEntry| e.payload.as_mut().unwrap()[3] ^= 1,
            |e: &mut WireEntry| e.origin = Identity::generate().unwrap().id,
        ] {
            let mut t = e.clone();
            tamper(&mut t);
            assert!(!t.verify());
        }
    }

    #[test]
    fn unknown_kinds_decode_to_none() {
        let me = Identity::generate().unwrap();
        let mut e = WireEntry::sign(&me, 1, 1, &Record::MemberRevoke { id: me.id }).unwrap();
        e.kind = "from_the_future".into();
        assert_eq!(e.record(), None);
    }
}
