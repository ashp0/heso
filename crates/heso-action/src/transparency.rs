//! Pure RFC-6962 SHA-256 Merkle tree verification primitives.
//!
//! This module is the **verify-only** half of HESO's transparency layer. The
//! stateful producer ([`MerkleLog`] with `append` / `inclusion_proof` /
//! `consistency_proof`) lives in `heso-engine::log`; the pure offline
//! verifiers here have no tree state and are callable from any crate that
//! holds only `heso-action`.
//!
//! ## Two hashes, never mixed
//!
//! - **BLAKE3 = WHAT.** Every receipt/audit *content* hash is BLAKE3. A leaf
//!   VALUE here is the raw 32 BLAKE3 bytes of a receipt's `action_hash`.
//! - **SHA-256 = ORDER.** The Merkle *tree* over those leaf values uses RFC 6962
//!   hashing (SHA-256 with domain-separating prefixes). The whole point is
//!   interop: an off-the-shelf RFC-6962 / C2SP / Sigsum witness can verify
//!   inclusion and consistency with NO HESO-specific code.
//!
//! ## RFC 6962 hashing rule (§2.1)
//!
//! ```text
//! leaf_hash(value) = SHA-256(0x00 || value)
//! node_hash(l, r)  = SHA-256(0x01 || l || r)
//! empty tree root  = SHA-256("")
//! ```

use sha2::{Digest, Sha256};

/// The width of a leaf value and of every internal hash: 32 bytes.
pub const HASH_LEN: usize = 32;

/// Decode a receipt's `action_hash` (64 lowercase-hex characters) into the raw
/// 32-byte leaf VALUE the transparency tree commits to.
///
/// # Errors
///
/// Returns [`TransparencyError::BadActionHash`] unless the input is exactly 64
/// characters of lowercase hex.
pub fn leaf_value_from_action_hash(action_hash: &str) -> Result<[u8; HASH_LEN], TransparencyError> {
    let bytes = action_hash.as_bytes();
    if bytes.len() != 64 {
        return Err(TransparencyError::BadActionHash);
    }
    let mut out = [0u8; HASH_LEN];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, TransparencyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(TransparencyError::BadActionHash),
    }
}

// ============================================================================
// RFC 6962 hashing primitives — also used by heso-engine::log (MerkleLog)
// ============================================================================

/// RFC 6962 leaf hash: `SHA-256(0x00 || value)`.
pub fn leaf_hash(value: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(value);
    h.finalize().into()
}

/// RFC 6962 internal-node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// RFC 6962 empty-tree root: `SHA-256("")`.
pub fn empty_root() -> [u8; HASH_LEN] {
    Sha256::new().finalize().into()
}

/// `k` = the largest power of two **strictly less than** `n`. Requires `n >= 2`.
pub fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 6962 Merkle Tree Hash (§2.1) over `leaves` (already-computed leaf VALUES,
/// i.e. the 32-byte BLAKE3 contents — leaf hashing happens here).
/// Used by `heso-engine::log::MerkleLog` to compute subtree roots.
pub fn merkle_tree_hash(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaf_hash(&leaves[0]),
        n => {
            let k = split_point(n);
            node_hash(&merkle_tree_hash(&leaves[..k]), &merkle_tree_hash(&leaves[k..]))
        }
    }
}

// ============================================================================
// Pure offline verification (public API)
// ============================================================================

/// Offline RFC-6962 inclusion verification (§2.1.1): recompute the root from
/// `leaf_value` at `index` in a tree of `size` leaves using `proof`, and compare
/// to `root`. No tree state.
///
/// Returns `true` iff the proof is well-formed and yields exactly `root`.
pub fn verify_inclusion(
    leaf_value: &[u8; HASH_LEN],
    index: usize,
    size: usize,
    root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if index >= size {
        return false;
    }
    let mut fne = index;
    let mut sne = size - 1;
    let mut hash = leaf_hash(leaf_value);
    let mut iter = proof.iter();

    while sne > 0 {
        let Some(sibling) = iter.next() else {
            return false;
        };
        if fne % 2 == 1 || fne == sne {
            hash = node_hash(sibling, &hash);
            if fne.is_multiple_of(2) {
                while fne != 0 && fne.is_multiple_of(2) {
                    fne /= 2;
                    sne /= 2;
                }
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fne /= 2;
        sne /= 2;
    }

    iter.next().is_none() && &hash == root
}

/// Offline RFC-6962 consistency verification (§2.1.2): given the old root over
/// `old_size` leaves and the new root over `new_size` leaves, check that `proof`
/// proves the new tree is an append-only extension of the old one. No tree state.
///
/// Returns `true` iff the proof is well-formed and reproduces BOTH the supplied
/// `old_root` and `new_root`.
pub fn verify_consistency(
    old_size: usize,
    old_root: &[u8; HASH_LEN],
    new_size: usize,
    new_root: &[u8; HASH_LEN],
    proof: &[[u8; HASH_LEN]],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut seed: Vec<[u8; HASH_LEN]> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        seed.push(*old_root);
    }
    seed.extend_from_slice(proof);
    if seed.is_empty() {
        return false;
    }

    let mut fr = seed[0];
    let mut sr = seed[0];
    let mut fne = old_size - 1;
    let mut sne = new_size - 1;
    while fne % 2 == 1 {
        fne /= 2;
        sne /= 2;
    }

    for step in &seed[1..] {
        if sne == 0 {
            return false;
        }
        if fne % 2 == 1 || fne == sne {
            fr = node_hash(step, &fr);
            sr = node_hash(step, &sr);
            while fne != 0 && fne.is_multiple_of(2) {
                fne /= 2;
                sne /= 2;
            }
        } else {
            sr = node_hash(&sr, step);
        }
        fne /= 2;
        sne /= 2;
    }

    sne == 0 && &fr == old_root && &sr == new_root
}

/// Errors from building proofs or decoding a leaf value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransparencyError {
    /// An `action_hash` was not exactly 64 lowercase-hex characters.
    #[error("action_hash must be 64 lowercase-hex characters")]
    BadActionHash,
    /// An inclusion proof was requested for a leaf index at or beyond the tree size.
    #[error("leaf index {index} out of range for a tree of {size} leaves")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// The tree size at the time of the request.
        size: usize,
    },
    /// A consistency proof range was invalid (`old_size == 0`, or `old_size > new_size`).
    #[error("invalid consistency range: old_size {old_size}, new_size {new_size}")]
    BadConsistencyRange {
        /// The requested earlier size.
        old_size: usize,
        /// The current tree size.
        new_size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8; HASH_LEN]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn empty_root_is_sha256_of_empty_string() {
        assert_eq!(
            hx(&empty_root()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn leaf_value_from_action_hash_decodes_64_lowercase_hex() {
        let wh = "d29d0238e8cf7890a26cb89607e28263e875efc6a5502c7b65e74d2aaf99d337";
        let v = leaf_value_from_action_hash(wh).unwrap();
        assert_eq!(hx(&v), wh);
    }

    #[test]
    fn leaf_value_rejects_bad_action_hash() {
        assert_eq!(leaf_value_from_action_hash("dead"), Err(TransparencyError::BadActionHash));
        let upper = "D29D0238E8CF7890A26CB89607E28263E875EFC6A5502C7B65E74D2AAF99D337";
        assert_eq!(leaf_value_from_action_hash(upper), Err(TransparencyError::BadActionHash));
        let nonhex = "z29d0238e8cf7890a26cb89607e28263e875efc6a5502c7b65e74d2aaf99d337";
        assert_eq!(leaf_value_from_action_hash(nonhex), Err(TransparencyError::BadActionHash));
    }
}
