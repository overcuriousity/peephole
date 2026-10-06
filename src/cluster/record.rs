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
    pub proto_min: u32,
    pub proto_max: u32,
    /// Unused since ownership replaced config keys; always false in new records.
    #[serde(default)]
    pub remote_config: bool,
}

/// A request caught by a trap listener. Timestamps everywhere are UTC
/// `YYYY-MM-DD HH:MM:SS`, as the rows store them.
///
/// Fields added later are optional and left out of the encoding when
/// unset, so a record signed before they existed rebuilds from its row
/// byte for byte.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestRec {
    pub uid: String,
    pub ts: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers_json: String,
    #[serde(with = "serde_bytes")]
    pub body: Option<Vec<u8>>,
    pub labels_json: String,
    pub severity: i64,
    pub scan_level: i64,
    pub is_fp_claim: bool,
    pub page_token: Option<String>,
    /// How the trap answered: `not-found`, `decoy:<name>`, `claim`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
    /// HTTP status sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<i64>,
    /// Requests from this IP answered but not recorded in full since its
    /// previous recorded one (flood sampling).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unrecorded: Option<i64>,
    /// `http` or `https`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// The connection came from a trusted proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_proxy: Option<bool>,
    /// The HTTP/1 request head as received (after TLS), through the blank line.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub raw_head: Option<Vec<u8>>,
    /// The TLS records that carried the ClientHello, as sent.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub tls_client_hello: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4: Option<String>,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
    /// OWASP tags of the hit rules, as a JSON array; absent for records
    /// written before the field existed and for requests with no tags
    /// (both stored as `[]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp_json: Option<String>,
    /// Fingerprint of the rules that classified the request: those built
    /// into the recording binary ([`crate::classify::rules::fingerprint`]).
    /// The recording node's word, like the verdict; absent for claims and
    /// records written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<String>,
    /// Decoy template version of a decoy answer (`crate::canary::DECOY_V`);
    /// absent for other answers and for decoy rows of version 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_v: Option<i64>,
    /// The site word a version-1 decoy was served under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_site: Option<String>,
    /// How long a `tarpit` answer held the client, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_ms: Option<i64>,
    /// What an MCP or LLM decoy was rendered from (compact JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_in: Option<String>,
}

/// One request the flood gate answered without recording it in full.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SkipRow {
    /// Unix time in milliseconds.
    pub ts_ms: i64,
    pub method: String,
    pub path: String,
    /// Set only when the request was answered with a decoy: what renders
    /// and traces it like a full row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_v: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_site: Option<String>,
    /// How long a `tarpit` answer held the client, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_ms: Option<i64>,
    /// What an MCP or LLM decoy was rendered from (compact JSON).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_in: Option<String>,
}

/// Skipped requests of one IP, sent together. `dropped`: requests past
/// the light-row rate that were only counted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkipBatchRec {
    pub uid: String,
    pub ip: String,
    pub dropped: i64,
    pub rows: Vec<SkipRow>,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}

/// One provider's result for an IP (per origin, newest wins by HLC).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpIntelRec {
    pub ip: String,
    /// `maxmind-geolite2`, `tor-exits`; later `shodan`, `abuseipdb`.
    pub provider: String,
    pub fetched_at: String,
    /// Version of the provider's data, if it has one (database build date).
    pub source_version: Option<String>,
    /// Provider-specific fields as a JSON object. `{}`: the provider was
    /// asked and knows nothing.
    pub data_json: String,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}

/// "I landed here by accident" claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FpClaimRec {
    pub uid: String,
    pub request_uid: String,
    pub ip: String,
    pub ts: String,
    pub contact_email: Option<String>,
    pub user_agent: Option<String>,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}

/// Browser fingerprint from the trap page's collector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FingerprintRec {
    pub uid: String,
    pub request_uid: Option<String>,
    pub ip: String,
    pub ts: String,
    pub fp_hash: Option<String>,
    pub visitor_id: Option<String>,
    pub attributes_json: Option<String>,
    pub behavior_summary_json: Option<String>,
    /// zstd-compressed, as stored.
    #[serde(with = "serde_bytes")]
    pub event_blob: Option<Vec<u8>>,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}

/// A queued counter-scan. The origin arbitrates the job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanJobRec {
    pub uid: String,
    pub ip: String,
    pub level: i64,
    pub queued_at: String,
}

/// A job's state (last write wins by HLC; only the arbiter writes it).
/// Statuses: queued, running, done, failed, superseded (a scan of the IP
/// at this level or higher already exists), refused (never_scan).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobStatusRec {
    pub job_uid: String,
    pub status: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub attempts: i64,
    /// The node running (or that ran) the scan.
    #[serde(default)]
    pub scanner: Option<NodeId>,
}

/// Queued jobs taken over from an arbiter that has been unreachable for
/// `cluster.takeover_hours`; the origin becomes their arbiter. When two
/// nodes adopt the same job, the lowest node key wins everywhere.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobAdoptRec {
    pub from: NodeId,
    pub job_uids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortRec {
    pub port: i64,
    pub proto: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// A finished counter-scan with its ports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResultRec {
    pub uid: String,
    pub job_uid: String,
    pub ip: String,
    pub level: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub os_guess: Option<String>,
    /// zstd-compressed nmap XML, as stored.
    #[serde(with = "serde_bytes")]
    pub raw_xml: Option<Vec<u8>>,
    pub ports: Vec<PortRec>,
    /// Source commit of the binary that created the record (provenance);
    /// left out when unset, like every field added later.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
}

/// A new version of a shared intel file, fetched by the origin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntelManifestRec {
    /// Only `tor-exits`; other kinds (old `geolite2-*` announcements) are
    /// ignored.
    pub kind: String,
    pub sha256: String,
    pub size: u64,
    pub fetched_at: String,
}

/// A delete by the node that created the listed records. Wherever it is
/// applied, it only affects entries of the tombstone's own origin; uids of
/// other nodes' records in the list are ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TombstoneRec {
    pub uid: String,
    pub uids: Vec<String>,
    /// Position of each listed record in the origin's log (`seqs[i]` belongs
    /// to `uids[i]`). An erased entry is only accepted at a position its
    /// tombstone names, so a relay cannot pass off another entry as erased.
    /// Empty on a standalone node, which has no log.
    #[serde(default)]
    pub seqs: Vec<u64>,
}

/// What a sealing entry (an offer, a transfer, a `log_seal`) says about
/// its origin's log before it: see `cluster::seal`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Seal {
    /// Sequence number of the origin's previous sealing entry; the entry's
    /// own number for the first one.
    pub from: u64,
    /// SHA-256 over the digests of the origin's entries from `from` up to
    /// the one before this entry.
    #[serde(with = "serde_bytes")]
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "k", rename_all = "snake_case")]
pub enum Record {
    /// The origin vouches for a node (config peer, or a redeemed invite).
    MemberAdd(MemberInfo),
    /// A node describes itself; origin must equal `id`.
    MemberUpdate(MemberInfo),
    /// The origin revokes a node cluster-wide.
    MemberRevoke {
        id: NodeId,
    },
    Request(Box<RequestRec>),
    IpIntel(IpIntelRec),
    FpClaim(FpClaimRec),
    Fingerprint(FingerprintRec),
    ScanJob(ScanJobRec),
    JobStatus(JobStatusRec),
    JobAdopt(JobAdoptRec),
    ScanResult(ScanResultRec),
    Tombstone(TombstoneRec),
    IntelManifest(IntelManifestRec),
    SkipBatch(SkipBatchRec),
    /// Credits set aside for a lookup at `to`: `(day, mc)` of the origin's
    /// lots (see `credits`). Identified by its origin and sequence number.
    CreditOffer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        seal: Seal,
    },
    /// The server's word on an offer: what it charged, and for which
    /// providers. The address looked up is not in it.
    CreditReceipt {
        payer: NodeId,
        offer_seq: u64,
        charged_mc: u32,
        answered: Vec<String>,
    },
    /// Credits sent to another node.
    CreditTransfer {
        to: NodeId,
        parts: Vec<(u32, u32)>,
        seal: Seal,
    },
    /// A seal with nothing else to say (written when many entries have
    /// none yet).
    LogSeal {
        seal: Seal,
    },
    /// Two entries one origin signed for the same position of its log.
    ForkProof {
        a: Box<WireEntry>,
        b: Box<WireEntry>,
    },
}

/// Kinds whose payload is not stored in the log but rebuilt from their row
/// (they are large); see `store::data::rebuild`.
pub const ROW_BACKED: &[&str] = &["request", "fingerprint", "scan_result", "skip_batch"];

impl Record {
    pub fn kind(&self) -> &'static str {
        match self {
            Record::MemberAdd(_) => "member_add",
            Record::MemberUpdate(_) => "member_update",
            Record::MemberRevoke { .. } => "member_revoke",
            Record::Request(_) => "request",
            Record::IpIntel(_) => "ip_intel",
            Record::FpClaim(_) => "fp_claim",
            Record::Fingerprint(_) => "fingerprint",
            Record::ScanJob(_) => "scan_job",
            Record::JobStatus(_) => "job_status",
            Record::JobAdopt(_) => "job_adopt",
            Record::ScanResult(_) => "scan_result",
            Record::Tombstone(_) => "tombstone",
            Record::IntelManifest(_) => "intel_manifest",
            Record::SkipBatch(_) => "skip_batch",
            Record::CreditOffer { .. } => "credit_offer",
            Record::CreditReceipt { .. } => "credit_receipt",
            Record::CreditTransfer { .. } => "credit_transfer",
            Record::LogSeal { .. } => "log_seal",
            Record::ForkProof { .. } => "fork_proof",
        }
    }

    /// The uid of the row this record creates; tombstones erase log
    /// entries by it.
    pub fn uid(&self) -> Option<String> {
        match self {
            Record::Request(r) => Some(r.uid.clone()),
            Record::FpClaim(r) => Some(r.uid.clone()),
            Record::Fingerprint(r) => Some(r.uid.clone()),
            Record::ScanJob(r) => Some(r.uid.clone()),
            Record::ScanResult(r) => Some(r.uid.clone()),
            Record::Tombstone(r) => Some(r.uid.clone()),
            Record::SkipBatch(r) => Some(r.uid.clone()),
            _ => None,
        }
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
        // The entry's kind and uid must match the signed payload, so the
        // envelope columns (which indexes and the stub path rely on) cannot
        // disagree with what was actually signed.
        (r.kind() == self.kind && r.uid() == self.uid).then_some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record signed before `build` existed encodes without it, so it
    /// still rebuilds byte for byte from its row.
    #[test]
    fn an_unset_build_is_left_out_of_the_encoding() {
        let enc = |r: &Record| crate::cluster::rpc::cbor::encode(r).unwrap();
        let has_build = |b: Vec<u8>| b.windows(5).any(|w| w == b"build");
        assert!(!has_build(enc(&Record::Request(Box::default()))));
        let skip = SkipBatchRec {
            uid: "u".into(),
            ip: "203.0.113.1".into(),
            dropped: 0,
            rows: vec![],
            build: String::new(),
        };
        assert!(!has_build(enc(&Record::SkipBatch(skip.clone()))));
        let set = SkipBatchRec {
            build: "0123456789ab".into(),
            ..skip
        };
        assert!(has_build(enc(&Record::SkipBatch(set))));
    }

    #[test]
    fn a_request_record_without_owasp_rebuilds_byte_for_byte() {
        let rec = Record::Request(Box::new(RequestRec {
            uid: "u".into(),
            ts: "2026-10-02 00:00:00".into(),
            ip: "198.51.100.1".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            headers_json: "[]".into(),
            body: None,
            labels_json: "[]".into(),
            severity: 0,
            scan_level: 0,
            is_fp_claim: false,
            page_token: None,
            ..Default::default()
        }));
        let bytes = super::super::rpc::cbor::encode(&rec).unwrap();
        assert!(
            !bytes.windows(10).any(|w| w == b"owasp_json"),
            "None must be left out of the encoding"
        );
        let back: Record = super::super::rpc::cbor::decode(&bytes).unwrap();
        assert_eq!(back, rec);
        assert_eq!(super::super::rpc::cbor::encode(&back).unwrap(), bytes);
    }

    /// A request without a ruleset fingerprint encodes as before; one with
    /// it still decodes where the field is unknown (older nodes), since
    /// fields a build does not know are skipped.
    #[test]
    fn rules_are_optional_and_unknown_fields_are_skipped() {
        let enc = |r: &Record| crate::cluster::rpc::cbor::encode(r).unwrap();
        let plain = Record::Request(Box::default());
        assert!(!enc(&plain).windows(5).any(|w| w == b"rules"));
        let with = Record::Request(Box::new(RequestRec {
            rules: Some("ab".repeat(32)),
            ..Default::default()
        }));
        let bytes = enc(&with);
        assert!(bytes.windows(5).any(|w| w == b"rules"));
        // A field from the future, as an older node sees `rules`.
        let mut v: ciborium::Value = crate::cluster::rpc::cbor::decode(&bytes).unwrap();
        if let ciborium::Value::Map(m) = &mut v {
            m.push(("from_the_future".into(), 7.into()));
        }
        let back: Record =
            crate::cluster::rpc::cbor::decode(&crate::cluster::rpc::cbor::encode(&v).unwrap())
                .unwrap();
        assert_eq!(back, with);
    }

    fn info(id: NodeId) -> MemberInfo {
        MemberInfo {
            id,
            name: "n".into(),
            address: Some("h:1".into()),
            roles: vec!["listener".into()],
            proto_min: 1,
            proto_max: 1,
            remote_config: false,
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

    /// The credit kinds have no uid (no tombstone can erase a payment) and
    /// survive the wire.
    #[test]
    fn credit_records_round_trip_without_a_uid() {
        let id = Identity::generate().unwrap();
        let seal = Seal {
            from: 3,
            digest: vec![7; 32],
        };
        let inner =
            WireEntry::sign(&id, 1, 1 << 16, &Record::LogSeal { seal: seal.clone() }).unwrap();
        for (r, kind) in [
            (
                Record::CreditOffer {
                    to: id.id,
                    parts: vec![(20_000, 250), (20_001, 4_000_000_000)],
                    seal: seal.clone(),
                },
                "credit_offer",
            ),
            (
                Record::CreditReceipt {
                    payer: id.id,
                    offer_seq: 12,
                    charged_mc: 200,
                    answered: vec!["shodan".into()],
                },
                "credit_receipt",
            ),
            (
                Record::CreditTransfer {
                    to: id.id,
                    parts: vec![(20_000, 1)],
                    seal: seal.clone(),
                },
                "credit_transfer",
            ),
            (Record::LogSeal { seal: seal.clone() }, "log_seal"),
            (
                Record::ForkProof {
                    a: Box::new(inner.clone()),
                    b: Box::new(inner.clone()),
                },
                "fork_proof",
            ),
        ] {
            assert_eq!(r.kind(), kind);
            assert_eq!(r.uid(), None);
            let e = WireEntry::sign(&id, 2, 2 << 16, &r).unwrap();
            assert!(e.verify());
            assert_eq!(e.record(), Some(r));
        }
    }
}
