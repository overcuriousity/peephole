//! Canaries: credentials served in decoys that name the request they were
//! served to. Every value is derived from the request's page token with a
//! public formula (no secret), so any node and any dataset user can
//! recompute the canaries of any row; a value that comes back in a later
//! request names the request that harvested it.
pub mod cli;
pub mod derive;
pub mod site;
pub mod tokens;

pub use derive::{DECOY_V, ETAG_DECOYS, Kind, hash, served, v0_ref, value};
