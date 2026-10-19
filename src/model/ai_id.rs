//! The AI decoys' per-node identity (`ident`): derived from the node key,
//! stored with the row (`decoy_in` `"i"`), read the same by the decoys
//! (`trap::decoy::{mcp,llm}`) and by the store's decoy tallies. A row
//! without one (decoy version 4 and older) renders the fixed identity
//! every node served before.
use sha2::{Digest, Sha256};

/// The node's `ident`: the first 4 bytes of
/// `SHA-256("peephole-ai-id-v1\0" || node_id)` as 8 lowercase hex. `node_id`
/// None (a standalone node) hashes nothing, like [`crate::canary::site::word`].
pub fn derive(node_id: Option<&[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(b"peephole-ai-id-v1\0");
    h.update(node_id.unwrap_or_default());
    h.finalize()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A parsed `ident`: its 4 bytes and the selection bytes drawn from them,
/// `SHA-256("peephole-ai-sel-v1\0" || ident bytes)`. Who reads which
/// bytes: MCP `sel[0..18]` (`trap::decoy::mcp`), LLM `sel[18..32]`
/// ([`super::llm`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AiId {
    pub raw: [u8; 4],
    pub sel: [u8; 32],
}

impl AiId {
    /// None: absent or not 8 hex characters (the fixed identity).
    pub fn parse(s: Option<&str>) -> Option<Self> {
        let s = s?;
        if s.len() != 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut raw = [0u8; 4];
        for (i, r) in raw.iter_mut().enumerate() {
            *r = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        let mut h = Sha256::new();
        h.update(b"peephole-ai-sel-v1\0");
        h.update(raw);
        Some(AiId {
            raw,
            sel: h.finalize().into(),
        })
    }

    /// `0..n` in an order drawn from `sel[at + 1..at + n]` (Fisher-Yates;
    /// `at + n` ≤ 32).
    pub fn order(&self, at: usize, n: usize) -> Vec<usize> {
        let mut v: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = self.sel[at + i] as usize % (i + 1);
            v.swap(i, j);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_pure_stable_and_standalone_hashes_nothing() {
        let a = derive(Some(&[7; 32]));
        assert_eq!(a, derive(Some(&[7; 32])));
        assert_eq!(a.len(), 8);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(a, derive(Some(&[8; 32])));
        let mut h = Sha256::new();
        h.update(b"peephole-ai-id-v1\0");
        let want: String = h.finalize()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(derive(None), want);
        assert_eq!(derive(None), derive(Some(&[])));
    }

    #[test]
    fn parse_takes_8_hex_only() {
        let a = AiId::parse(Some("a1b2c3d4")).unwrap();
        assert_eq!(a.raw, [0xa1, 0xb2, 0xc3, 0xd4]);
        assert_eq!(Some(a), AiId::parse(Some("A1B2C3D4")));
        for bad in [
            None,
            Some(""),
            Some("a1b2c3"),
            Some("a1b2c3d4e5"),
            Some("zzzzzzzz"),
            Some("é1b2c3d"),
        ] {
            assert_eq!(AiId::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn order_is_a_permutation() {
        let a = AiId::parse(Some("00ff10ee")).unwrap();
        let mut o = a.order(4, 8);
        o.sort();
        assert_eq!(o, (0..8).collect::<Vec<_>>());
    }
}
