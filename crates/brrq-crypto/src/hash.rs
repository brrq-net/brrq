//! Core hash type used throughout the Brrq protocol.
//!
//! `Hash256` is the fundamental 32-byte hash used for:
//! - Merkle tree nodes
//! - State roots
//! - Transaction IDs
//! - Block hashes

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 256-bit (32-byte) hash value.
///
/// This is the fundamental unit of the Hash-First Architecture.
/// All external-facing commitments use SHA-256.
// Allow derived Hash with manual PartialEq: the manual PartialEq uses constant-time
// comparison to prevent timing side-channels. The derived Hash is safe because it
// only affects HashMap/HashSet bucket placement, not security-sensitive equality.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Clone, Copy, Hash, Serialize, Deserialize, Default)]
pub struct Hash256(pub [u8; 32]);

impl PartialEq for Hash256 {
    /// Constant-time equality comparison to prevent timing side-channel attacks.
    ///
    /// Standard derived PartialEq short-circuits on the first differing byte,
    /// leaking information about how many leading bytes match. This implementation
    /// always processes all 32 bytes regardless of input values.
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Hash256 {}

/// Constant-time ordering to prevent timing side-channel attacks.
///
/// Processes all 32 bytes regardless of input values, unlike the derived
/// `PartialOrd`/`Ord` which short-circuit on the first differing byte.
impl PartialOrd for Hash256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hash256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Constant-time lexicographic comparison for hash digests.
        //
        // Processes all 32 bytes regardless of where the first difference is,
        // preventing timing side-channels that leak the difference position.
        //
        // Uses wider arithmetic (u16) for correct unsigned byte comparison.
        let mut result: i32 = 0; // +1 = Greater, -1 = Less, 0 = Equal
        let mut decided: u32 = 0; // 0 = undecided, 1 = decided

        for i in 0..32 {
            let a = self.0[i] as u16;
            let b = other.0[i] as u16;
            // diff > 0 if a > b, diff < 0 (as i16) if a < b, 0 if equal
            let diff = (a as i16) - (b as i16);
            // is_nonzero = 1 if a != b, 0 if a == b
            let is_nonzero = (((diff as u16) | (diff as u16).wrapping_neg()) >> 15) as u32;
            // Only record the first difference
            let mask = is_nonzero & (1 - decided);
            // Collapse diff to sign: +1 or -1
            let sign = ((diff >> 15) as i32) | 1; // -1 if diff<0, +1 if diff>=0
            let correct_sign = if diff == 0 { 0i32 } else { sign };
            result += (correct_sign * mask as i32);
            decided |= is_nonzero;
        }

        match result.signum() {
            1 => std::cmp::Ordering::Greater,
            -1 => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

impl Hash256 {
    /// The zero hash (all bytes zero).
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create a Hash256 from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create a Hash256 from a byte slice.
    ///
    /// Returns an error if the slice length is not exactly 32 bytes.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() != 32 {
            return Err("Hash256 requires exactly 32 bytes");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Create a Hash256 from a byte slice.
    ///
    /// # Panics
    /// Panics if the slice length is not exactly 32 bytes.
    /// Prefer [`try_from_slice`](Self::try_from_slice) for fallible conversion.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self::try_from_slice(slice).expect("Hash256 requires exactly 32 bytes")
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality comparison.
    ///
    /// Runs in O(32) time regardless of input, preventing timing attacks
    /// on HMAC tag verification, Merkle root comparison, and signature checks.
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }

    /// Check if this is the zero hash (constant-time).
    pub fn is_zero(&self) -> bool {
        self.ct_eq(&Self::ZERO)
    }

    /// Get the hex representation.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// SHA-256 hasher for the Brrq protocol.
///
/// Dual-hash commitment containing both SHA-256 and Poseidon2 hashes.
///
/// Used for quantum-hedged state commitments where the state root is secure
/// even if one of the two hash functions is broken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DualHash {
    /// SHA-256 hash of the data (external-facing, HW-accelerated).
    pub sha256: Hash256,
    /// Poseidon2 hash of the data (ZK-efficient, internal).
    pub poseidon2: Hash256,
    /// Combined commitment: SHA-256(sha256 || poseidon2).
    pub combined: Hash256,
}

impl DualHash {
    /// Get the combined commitment hash.
    pub fn combined(&self) -> &Hash256 {
        &self.combined
    }
}

/// Wraps the `sha2` crate's SHA-256 implementation.
pub struct Hasher {
    inner: Sha256,
}

impl Hasher {
    /// Create a new hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Feed data into the hasher.
    #[inline]
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalize and produce the hash.
    #[inline]
    pub fn finalize(self) -> Hash256 {
        let result = self.inner.finalize();
        Hash256::from_slice(&result)
    }

    /// Hash data in a single call.
    #[inline]
    pub fn hash(data: &[u8]) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Double SHA-256 (used in Bitcoin).
    pub fn double_hash(data: &[u8]) -> Hash256 {
        let first = Self::hash(data);
        Self::hash(first.as_bytes())
    }

    /// Compute dual hash (SHA-256 + Poseidon2) for quantum hedging.
    ///
    /// The dual hash commits to data under two independent hash functions,
    /// so the state root remains secure even if one hash function is broken.
    ///
    /// Returns a `DualHash` struct containing both individual hashes
    /// and the combined commitment.
    pub fn dual_hash(data: &[u8]) -> DualHash {
        let sha256_hash = Hasher::hash(data);
        let poseidon_hash = crate::poseidon2::poseidon2_hash(data);

        // Combined commitment with domain tag to prevent collision with
        // independent SHA-256 calls on 64 arbitrary bytes.
        let mut combined_hasher = Self::new();
        combined_hasher.update(crate::domain_tags::DUAL_HASH_V1);
        combined_hasher.update(sha256_hash.as_bytes());
        combined_hasher.update(poseidon_hash.as_bytes());
        let combined = combined_hasher.finalize();

        DualHash {
            sha256: sha256_hash,
            poseidon2: poseidon_hash,
            combined,
        }
    }

    pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(&[0x03]);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        hasher.finalize()
    }

    /// Hash a Merkle tree leaf with domain separation (prefix 0x00).
    ///
    /// Prevents second-preimage attacks by making leaf hashes
    /// structurally distinct from internal node hashes.
    #[inline]
    pub fn hash_leaf(data: &[u8]) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(crate::domain_tags::MERKLE_LEAF);
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash a Merkle tree internal node with domain separation (prefix 0x01).
    #[inline]
    pub fn hash_node(left: &Hash256, right: &Hash256) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(crate::domain_tags::MERKLE_NODE);
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        hasher.finalize()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_empty() {
        // SHA-256 of empty string
        let hash = Hasher::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_brrq() {
        let hash = Hasher::hash(b"Brrq");
        assert!(!hash.is_zero());
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = Hasher::hash(b"test data");
        let h2 = Hasher::hash(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = Hasher::hash(b"input A");
        let h2 = Hasher::hash(b"input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_double_hash() {
        let single = Hasher::hash(b"data");
        let double = Hasher::double_hash(b"data");
        assert_ne!(single, double);
        // Double hash = hash(hash(data))
        let expected = Hasher::hash(single.as_bytes());
        assert_eq!(double, expected);
    }

    #[test]
    fn test_hash_pair() {
        let left = Hasher::hash(b"left");
        let right = Hasher::hash(b"right");
        let pair = Hasher::hash_pair(&left, &right);
        assert!(!pair.is_zero());

        // Order matters
        let reversed = Hasher::hash_pair(&right, &left);
        assert_ne!(pair, reversed);
    }

    #[test]
    fn test_hex_roundtrip() {
        let hash = Hasher::hash(b"roundtrip test");
        let hex_str = hash.to_hex();
        let recovered = Hash256::from_hex(&hex_str).unwrap();
        assert_eq!(hash, recovered);
    }

    #[test]
    fn test_zero_hash() {
        let zero = Hash256::ZERO;
        assert!(zero.is_zero());
        assert_eq!(zero.0, [0u8; 32]);
    }

    #[test]
    fn test_dual_hash_uses_real_poseidon2() {
        let data = b"dual hash test data";
        let dual = Hasher::dual_hash(data);

        // SHA-256 component matches standalone SHA-256.
        assert_eq!(dual.sha256, Hasher::hash(data));

        // Poseidon2 component matches standalone Poseidon2.
        let expected_p2 = crate::poseidon2::poseidon2_hash(data);
        assert_eq!(dual.poseidon2, expected_p2);

        // SHA-256 and Poseidon2 produce different outputs.
        assert_ne!(dual.sha256, dual.poseidon2);

        // Combined = SHA-256(DUAL_HASH_V1 || sha256 || poseidon2).
        let mut hasher = Hasher::new();
        hasher.update(crate::domain_tags::DUAL_HASH_V1);
        hasher.update(dual.sha256.as_bytes());
        hasher.update(dual.poseidon2.as_bytes());
        let expected_combined = hasher.finalize();
        assert_eq!(dual.combined, expected_combined);
    }

    #[test]
    fn test_dual_hash_deterministic() {
        let data = b"determinism check";
        let d1 = Hasher::dual_hash(data);
        let d2 = Hasher::dual_hash(data);
        assert_eq!(d1.sha256, d2.sha256);
        assert_eq!(d1.poseidon2, d2.poseidon2);
        assert_eq!(d1.combined, d2.combined);
    }

    #[test]
    fn test_dual_hash_different_inputs() {
        let d1 = Hasher::dual_hash(b"input A");
        let d2 = Hasher::dual_hash(b"input B");
        assert_ne!(d1.sha256, d2.sha256);
        assert_ne!(d1.poseidon2, d2.poseidon2);
        assert_ne!(d1.combined, d2.combined);
    }

    #[test]
    fn test_hash256_ord_btreeset_no_collisions() {
        // Verify Hash256::Ord doesn't cause false equality in BTreeSet
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for i in 0u64..10_000 {
            let h = Hasher::hash(&i.to_le_bytes());
            assert!(set.insert(h), "BTreeSet false collision at i={}", i);
        }
        assert_eq!(set.len(), 10_000);
    }

    #[test]
    fn test_hash256_ord_matches_bytes_order() {
        // Verify Hash256::Ord produces same ordering as raw bytes comparison
        let mut hashes: Vec<Hash256> = (0u64..100)
            .map(|i| Hasher::hash(&i.to_le_bytes()))
            .collect();
        let mut by_ord = hashes.clone();
        by_ord.sort(); // Uses Hash256::Ord
        hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes())); // Raw bytes
        assert_eq!(hashes, by_ord, "Ord and bytes ordering must match");
    }
}
