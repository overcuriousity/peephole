//! Chains and the X-ray summary as the dossiers and `/api/v1/chains` serve
//! them. A piece is `value` (the attacker's text, for the sandbox) and
//! `defanged` (for reading); a stager lists its URLs the same way. Never
//! here: the text of a layer or an upload, and key material (a key piece's
//! value is its public fingerprint).
use crate::model::defang::defang;
use crate::model::xray::{Grade, LayerKind, MAX_URLS, OpaqueReason, PieceKind, Role, Xray};
use crate::store::Store;
use crate::store::chains::{Chain, ChainRow};
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

/// Hashes per `IN (…)`: well under SQLite's bound variables.
const BATCH: usize = 400;

/// A value twice: as the attacker wrote it, and defanged.
#[derive(Debug, Serialize)]
pub struct UrlJson {
    pub url: String,
    pub defanged: String,
}

impl UrlJson {
    fn of(url: String) -> Self {
        UrlJson {
            defanged: defang(&url),
            url,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RowJson {
    /// The piece's hash as 16 lowercase hex digits; null for what is not a
    /// piece (a request, an upload's name, a gap).
    pub piece: Option<String>,
    pub kind: Option<String>,
    /// The piece's text as seen. Attacker-controlled; never a link.
    pub value: Option<String>,
    pub defanged: Option<String>,
    /// A stager's URLs, newest first, at most 32.
    pub urls: Vec<UrlJson>,
    /// Defanged, cut short.
    pub label: String,
    pub detail: String,
    /// `seen`, `claimed`, `external`, `gap` or `dead end`.
    pub mark: String,
    pub joiner: bool,
    /// It belongs to what the dossier is about.
    pub here: bool,
    /// The page that shows it on this node.
    pub page: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StageJson {
    pub name: String,
    pub rows: Vec<RowJson>,
}

#[derive(Debug, Serialize)]
pub struct ChainJson {
    /// The oldest joiner's hash; null for what has no joiner. It changes
    /// when chains merge, so it is no permanent id.
    pub key: Option<String>,
    pub ips: i64,
    pub sources: i64,
    pub first_seen: String,
    pub last_seen: String,
    /// Pieces past the 200 a chain lists, in no stage.
    pub more: i64,
    /// `Exploit`, `Command`, `Delivery`, `Payload`, `Follow-up`.
    pub stages: Vec<StageJson>,
}

#[derive(sqlx::FromRow)]
struct Stored {
    hash: i64,
    kind: String,
    value: String,
}

fn hex(hash: i64) -> String {
    format!("{:016x}", hash as u64)
}

fn ids(hashes: &[i64]) -> Vec<String> {
    hashes
        .chunks(BATCH)
        .map(|c| c.iter().map(i64::to_string).collect::<Vec<_>>().join(","))
        .collect()
}

/// The chains as JSON, with the text of each piece read in one pass.
pub async fn chains_json(store: &Store, chains: &[Chain]) -> Result<Vec<ChainJson>> {
    let mut hashes: Vec<i64> = chains
        .iter()
        .flat_map(|c| c.stages.iter())
        .flat_map(|s| s.rows.iter())
        .filter_map(|r| r.piece)
        .collect();
    hashes.sort_unstable();
    hashes.dedup();
    let mut stored: HashMap<i64, Stored> = HashMap::new();
    let mut urls: HashMap<i64, Vec<String>> = HashMap::new();
    for list in ids(&hashes) {
        let rows: Vec<Stored> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT hash, kind, value FROM pieces WHERE hash IN ({list})"
        )))
        .fetch_all(&store.read)
        .await?;
        stored.extend(rows.into_iter().map(|p| (p.hash, p)));
        let rows: Vec<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT piece, url FROM piece_urls WHERE piece IN ({list})
             ORDER BY piece, last_seen DESC, url"
        )))
        .fetch_all(&store.read)
        .await?;
        for (piece, url) in rows {
            let of = urls.entry(piece).or_default();
            if of.len() < MAX_URLS {
                of.push(url);
            }
        }
    }
    Ok(chains
        .iter()
        .map(|c| ChainJson {
            key: c.key.clone(),
            ips: c.ips,
            sources: c.sources,
            first_seen: crate::admin::api_v1::rfc3339(&c.first_seen),
            last_seen: crate::admin::api_v1::rfc3339(&c.last_seen),
            more: c.more,
            stages: c
                .stages
                .iter()
                .map(|s| StageJson {
                    name: s.name.to_string(),
                    rows: s
                        .rows
                        .iter()
                        .map(|r| {
                            let p = r.piece.and_then(|h| stored.get(&h));
                            RowJson {
                                piece: r.piece.map(hex),
                                kind: p.map(|p| p.kind.clone()),
                                value: p.map(|p| p.value.clone()),
                                defanged: p.map(|p| defang(&p.value)),
                                urls: p
                                    .filter(|p| p.kind == "stager")
                                    .and_then(|p| urls.get(&p.hash))
                                    .into_iter()
                                    .flatten()
                                    .cloned()
                                    .map(UrlJson::of)
                                    .collect(),
                                label: r.label.clone(),
                                detail: r.detail.clone(),
                                mark: r.mark.word().to_string(),
                                joiner: r.joiner,
                                here: r.here,
                                page: r.href.clone(),
                            }
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect())
}

/// One line of the Chains list.
#[derive(Debug, Serialize)]
pub struct ChainRowJson {
    pub key: String,
    /// The joiner that names it, defanged.
    pub joiner: Option<String>,
    pub page: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub ips: i64,
    pub sources: i64,
    pub exploits: i64,
    /// Whether uploaded text backs the payload: `seen` or `gap`.
    pub payload: String,
}

impl From<&ChainRow> for ChainRowJson {
    fn from(r: &ChainRow) -> Self {
        ChainRowJson {
            key: r.key.clone(),
            joiner: r.joiner.as_ref().map(|(label, _)| label.clone()),
            page: r.joiner.as_ref().map(|(_, href)| href.clone()),
            first_seen: crate::admin::api_v1::rfc3339(&r.first_seen),
            last_seen: crate::admin::api_v1::rfc3339(&r.last_seen),
            ips: r.ips,
            sources: r.sources,
            exploits: r.exploits,
            payload: r.payload.word().to_string(),
        }
    }
}

// ------------------------------------------------------------------ xray

#[derive(Debug, Serialize)]
pub struct LayerJson {
    pub kind: &'static str,
    pub parent: Option<usize>,
    pub depth: usize,
}

#[derive(Debug, Serialize)]
pub struct XrayPieceJson {
    pub kind: &'static str,
    pub role: &'static str,
    pub grade: &'static str,
    pub value: String,
    pub defanged: String,
    /// The text a stager's value came from.
    pub url: Option<UrlJson>,
}

#[derive(Debug, Serialize)]
pub struct OpaqueJson {
    pub reason: &'static str,
    pub layer: usize,
}

/// What the X-ray found, without any layer's text.
#[derive(Debug, Serialize)]
pub struct XraySummary {
    pub layers: Vec<LayerJson>,
    pub pieces: Vec<XrayPieceJson>,
    pub opaque: Vec<OpaqueJson>,
}

fn layer_kind(k: LayerKind) -> &'static str {
    match k {
        LayerKind::Raw => "raw",
        LayerKind::Path => "path",
        LayerKind::Query => "query",
        LayerKind::Form => "form",
        LayerKind::MultipartField => "multipart_field",
        LayerKind::Json => "json",
        LayerKind::Xml => "xml",
        LayerKind::Php => "php",
        LayerKind::PhpCgi => "php_cgi",
        LayerKind::Base64 => "base64",
        LayerKind::Gzip => "gzip",
        LayerKind::Hex => "hex",
        LayerKind::Escapes => "escapes",
        LayerKind::Shell => "shell",
    }
}

fn piece_kind(k: PieceKind) -> &'static str {
    match k {
        PieceKind::Exploit => "exploit",
        PieceKind::Recipe => "recipe",
        PieceKind::Tag => "tag",
        PieceKind::ShellProfile => "shell-profile",
        PieceKind::Stager => "stager",
        PieceKind::Key => "key",
    }
}

fn role(r: Role) -> &'static str {
    match r {
        Role::Exploit => "exploit",
        Role::Tag => "tag",
        Role::Recipe => "recipe",
        Role::Stager => "stager",
        Role::SelfHosted => "self_hosted",
        Role::Queried => "queried",
        Role::Key => "key",
        Role::File => "file",
        Role::Opaque => "opaque",
    }
}

fn grade(g: Grade) -> &'static str {
    match g {
        Grade::Seen => "seen",
        Grade::Claimed => "claimed",
        Grade::External => "external",
    }
}

fn reason(r: OpaqueReason) -> &'static str {
    match r {
        OpaqueReason::HighEntropy => "high_entropy",
        OpaqueReason::UnknownEncoding => "unknown_encoding",
        OpaqueReason::TooDeep => "too_deep",
        OpaqueReason::OverLimit => "over_limit",
    }
}

pub fn xray_summary(x: &Xray) -> XraySummary {
    XraySummary {
        layers: x
            .layers
            .iter()
            .enumerate()
            .map(|(i, l)| LayerJson {
                kind: layer_kind(l.kind),
                parent: l.parent,
                depth: x.depth(i),
            })
            .collect(),
        pieces: x
            .pieces
            .iter()
            .map(|p| XrayPieceJson {
                kind: piece_kind(p.kind),
                role: role(p.role),
                grade: grade(p.grade),
                defanged: defang(&p.value),
                value: p.value.clone(),
                url: p.url.clone().map(UrlJson::of),
            })
            .collect(),
        opaque: x
            .opaque
            .iter()
            .map(|o| OpaqueJson {
                reason: reason(o.reason),
                layer: o.at.layer,
            })
            .collect(),
    }
}
