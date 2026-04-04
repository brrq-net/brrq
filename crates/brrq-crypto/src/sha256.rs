//! SHA-256 utilities for the Brrq protocol.
//!
//! SHA-256 is the external-facing hash function used for:
//! - L1-facing state roots
//! - Merkle tree commitments
//! - Transaction hashing
//! - Block hashing
//!
//! Per the Hash-First Architecture, SHA-256 is the backbone
//! of all external cryptographic commitments.

use crate::hash::{Hash256, Hasher};

/// Compute SHA-256 hash of the given data.
pub fn hash(data: &[u8]) -> Hash256 {
    Hasher::hash(data)
}

/// Compute double SHA-256 (Bitcoin convention).
pub fn double_hash(data: &[u8]) -> Hash256 {
    Hasher::double_hash(data)
}

/// Compute SHA-256 hash of two concatenated 32-byte values.
/// Used in Merkle tree construction.
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    Hasher::hash_pair(left, right)
}

/// Compute a tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data).
/// Used in BIP-340 Schnorr signatures and Taproot.
pub fn tagged_hash(tag: &str, data: &[u8]) -> Hash256 {
    let tag_hash = hash(tag.as_bytes());
    let mut hasher = Hasher::new();
    hasher.update(tag_hash.as_bytes());
    hasher.update(tag_hash.as_bytes());
    hasher.update(data);
    hasher.finalize()
}

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Hash256 {
    const BLOCK_SIZE: usize = 64;

    // If key is longer than block size, hash it
    let mut key = if key.len() > BLOCK_SIZE {
        let h = hash(key);
        let mut k = [0u8; BLOCK_SIZE];
        k[..32].copy_from_slice(h.as_bytes());
        k
    } else {
        let mut k = [0u8; BLOCK_SIZE];
        k[..key.len()].copy_from_slice(key);
        k
    };

    // Inner padding
    let mut ipad = [0x36u8; BLOCK_SIZE];
    for (i, b) in ipad.iter_mut().enumerate() {
        *b ^= key[i];
    }

    // Outer padding
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for (i, b) in opad.iter_mut().enumerate() {
        *b ^= key[i];
    }

    // HMAC = H(opad || H(ipad || data))
    let mut inner_hasher = Hasher::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Hasher::new();
    outer_hasher.update(&opad);
    outer_hasher.update(inner_hash.as_bytes());
    let result = outer_hasher.finalize();

    // Zeroize HMAC key-derived material from the stack.
    // key contains the padded secret, ipad/opad contain key XOR constants.
    crate::zeroize::zeroize_bytes(&mut key);
    crate::zeroize::zeroize_bytes(&mut ipad);
    crate::zeroize::zeroize_bytes(&mut opad);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        // NIST test vector: SHA-256("abc")
        let result = hash(b"abc");
        assert_eq!(
            result.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let result = hash(b"");
        assert_eq!(
            result.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_tagged_hash() {
        let h1 = tagged_hash("BIP0340/challenge", b"test");
        let h2 = tagged_hash("BIP0340/challenge", b"test");
        assert_eq!(h1, h2);

        // Different tags produce different hashes
        let h3 = tagged_hash("BIP0340/aux", b"test");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 Test Case 1
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let result = hmac_sha256(&key, data);
        assert_eq!(
            result.to_hex(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
}
