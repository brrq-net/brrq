//! Brrq account addresses.
//!
//! An address is derived from a public key:
//! - Schnorr: SHA-256("BRRQ_ADDR_V1" || pubkey)[0..20] — 20 bytes
//! - SLH-DSA: SHA-256("BRRQ_ADDR_V1" || pubkey)[0..20] — 20 bytes
//!
//! Both signature types produce the same address format,
//! allowing seamless signature upgrades.
//!
//! ## Address Checksum
//!
//! Addresses support a 4-byte SHA-256 checksum suffix to prevent
//! single-character typos from causing irreversible fund loss.
//!
//! **Checksummed format:** `brrq:{40-hex-address}:{8-hex-checksum}`
//! **Legacy format:**      `brrq:{40-hex-address}` (still accepted for backward compatibility)
//!
//! Checksum = SHA-256("BRRQ_ADDR_CHECKSUM" || address_bytes)[0..4]
//!
//! The 4-byte (32-bit) checksum gives a 1-in-4-billion chance of a typo
//! passing validation, which is sufficient for human-entry protection.

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};
use std::fmt;

// ── Checksum error type ──────────────────────────────────────────────────

/// Errors that can occur when parsing a checksummed address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressChecksumError {
    /// Missing the `brrq:` prefix.
    MissingPrefix,
    /// Hex portion has invalid length (expected 40 or 48 hex chars).
    InvalidLength { found: usize },
    /// Hex decoding failed.
    InvalidHex(String),
    /// Checksum mismatch — likely a typo.
    ChecksumMismatch { expected: [u8; 4], found: [u8; 4] },
}

impl fmt::Display for AddressChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => write!(f, "address must start with 'brrq:'"),
            Self::InvalidLength { found } => write!(
                f,
                "expected 40 (legacy) or 49 (checksummed) chars after 'brrq:', found {}",
                found
            ),
            Self::InvalidHex(e) => write!(f, "invalid hex: {}", e),
            Self::ChecksumMismatch { expected, found } => write!(
                f,
                "checksum mismatch: expected {}, found {}",
                hex::encode(expected),
                hex::encode(found),
            ),
        }
    }
}

impl std::error::Error for AddressChecksumError {}

/// A 20-byte Brrq address, derived from a public key hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// The zero address (used for coinbase/system operations).
    pub const ZERO: Self = Self([0u8; 20]);

    /// Length of the checksum in bytes (4 bytes = 8 hex chars).
    /// Provides 2^32 (~4 billion) error-detection strength.
    const CHECKSUM_LEN: usize = 4;

    /// Derive address from a public key's raw bytes.
    ///
    /// Address = SHA-256("BRRQ_ADDR_V1" || public_key)[0..20]
    pub fn from_public_key(public_key_bytes: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::ADDR_V1);
        hasher.update(public_key_bytes);
        let hash = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash.0[..20]);
        Self(addr)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Create from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Get hex representation with "brrq:" prefix (legacy, no checksum).
    pub fn to_brrq_hex(&self) -> String {
        format!("brrq:{}", hex::encode(self.0))
    }

    // ── Checksum methods ──────────────────────────────────────────────

    /// Compute the 4-byte checksum for this address.
    ///
    /// Checksum = SHA-256("BRRQ_ADDR_CHECKSUM" || address_bytes)[0..4]
    ///
    /// Uses a dedicated domain tag to prevent cross-context collisions.
    fn compute_checksum(&self) -> [u8; Self::CHECKSUM_LEN] {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::ADDR_CHECKSUM);
        hasher.update(&self.0);
        let hash = hasher.finalize();
        let mut checksum = [0u8; Self::CHECKSUM_LEN];
        checksum.copy_from_slice(&hash.0[..Self::CHECKSUM_LEN]);
        checksum
    }

    /// Return the address as a checksummed hex string.
    ///
    /// Format: `brrq:{40-hex-address}:{8-hex-checksum}`
    ///
    /// This format protects against single-character typos that would
    /// otherwise cause irreversible loss of funds. Always prefer this
    /// over `to_brrq_hex()` for user-facing display.
    ///
    /// # Example
    /// ```
    /// use brrq_types::address::Address;
    /// let addr = Address::from_bytes([0xAB; 20]);
    /// let s = addr.to_checksummed_hex();
    /// assert!(s.starts_with("brrq:"));
    /// // Format: brrq:<40 hex>:<8 hex checksum>
    /// assert_eq!(s.len(), 5 + 40 + 1 + 8); // "brrq:" + hex + ":" + checksum
    /// ```
    pub fn to_checksummed_hex(&self) -> String {
        let checksum = self.compute_checksum();
        format!("brrq:{}:{}", hex::encode(self.0), hex::encode(checksum),)
    }

    /// Parse an address from a checksummed hex string and verify
    /// the checksum.
    ///
    /// Accepts both formats for backward compatibility:
    /// - Checksummed: `brrq:{40-hex}:{8-hex-checksum}` — checksum is verified
    /// - Legacy:      `brrq:{40-hex}` — accepted without checksum verification
    ///
    /// Returns `Err` if the prefix is wrong, hex is invalid, or the
    /// checksum does not match (typo detected).
    pub fn from_checksummed_hex(s: &str) -> Result<Self, AddressChecksumError> {
        let body = s
            .strip_prefix("brrq:")
            .ok_or(AddressChecksumError::MissingPrefix)?;

        // Checksummed format: 40 hex + ':' + 8 hex = 49 chars
        // Legacy format:      40 hex = 40 chars
        match body.len() {
            49 => {
                // Checksummed: split at the colon separator
                if body.as_bytes()[40] != b':' {
                    return Err(AddressChecksumError::InvalidLength { found: body.len() });
                }
                let addr_hex = &body[..40];
                let checksum_hex = &body[41..49];

                let addr_bytes = hex::decode(addr_hex)
                    .map_err(|e| AddressChecksumError::InvalidHex(e.to_string()))?;
                let checksum_bytes = hex::decode(checksum_hex)
                    .map_err(|e| AddressChecksumError::InvalidHex(e.to_string()))?;

                let mut addr = [0u8; 20];
                addr.copy_from_slice(&addr_bytes);
                let address = Self(addr);

                let mut found = [0u8; Self::CHECKSUM_LEN];
                found.copy_from_slice(&checksum_bytes);

                let expected = address.compute_checksum();
                if found != expected {
                    return Err(AddressChecksumError::ChecksumMismatch { expected, found });
                }

                Ok(address)
            }
            40 => {
                // Legacy format: no checksum — backward compatible
                let addr_bytes = hex::decode(body)
                    .map_err(|e| AddressChecksumError::InvalidHex(e.to_string()))?;
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&addr_bytes);
                Ok(Self(addr))
            }
            other => Err(AddressChecksumError::InvalidLength { found: other }),
        }
    }

    /// Verify that a hex string's checksum is valid.
    ///
    /// Returns:
    /// - `Ok(true)`  — checksummed format with valid checksum
    /// - `Ok(false)` — legacy format (no checksum present)
    /// - `Err(..)`   — invalid format or checksum mismatch
    pub fn verify_checksum(s: &str) -> Result<bool, AddressChecksumError> {
        let body = s
            .strip_prefix("brrq:")
            .ok_or(AddressChecksumError::MissingPrefix)?;

        match body.len() {
            49 => {
                // Parse and verify — from_checksummed_hex does the work
                Self::from_checksummed_hex(s)?;
                Ok(true)
            }
            40 => {
                // Legacy: valid format, but no checksum to verify
                let _bytes = hex::decode(body)
                    .map_err(|e| AddressChecksumError::InvalidHex(e.to_string()))?;
                Ok(false)
            }
            other => Err(AddressChecksumError::InvalidLength { found: other }),
        }
    }

    /// Check if this is the zero address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Compute a full 32-byte hash of this address (for Merkle keys).
    pub fn to_hash(&self) -> Hash256 {
        Hasher::hash(&self.0)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(brrq:{})", hex::encode(&self.0[..6]))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "brrq:{}", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_public_key() {
        let pk = [42u8; 32]; // Mock public key
        let addr = Address::from_public_key(&pk);
        assert!(!addr.is_zero());
        assert_eq!(addr.as_bytes().len(), 20);
    }

    #[test]
    fn test_address_deterministic() {
        let pk = [7u8; 32];
        let addr1 = Address::from_public_key(&pk);
        let addr2 = Address::from_public_key(&pk);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let pk1 = [1u8; 32];
        let pk2 = [2u8; 32];
        let addr1 = Address::from_public_key(&pk1);
        let addr2 = Address::from_public_key(&pk2);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_brrq_hex_format() {
        let addr = Address::from_bytes([0xAB; 20]);
        let hex_str = addr.to_brrq_hex();
        assert!(hex_str.starts_with("brrq:"));
        assert_eq!(hex_str.len(), 5 + 40); // "brrq:" + 40 hex chars
    }

    #[test]
    fn test_zero_address() {
        let zero = Address::ZERO;
        assert!(zero.is_zero());
    }

    // ── Checksum tests ────────────────────────────────────────────────

    /// Checksummed hex round-trip: encode then decode must yield same address.
    #[test]
    fn test_checksummed_hex_roundtrip() {
        let addr = Address::from_bytes([0xAB; 20]);
        let checksummed = addr.to_checksummed_hex();

        // Format: brrq:<40 hex>:<8 hex> = 5 + 40 + 1 + 8 = 54 chars
        assert_eq!(checksummed.len(), 54);
        assert!(checksummed.starts_with("brrq:"));

        let parsed =
            Address::from_checksummed_hex(&checksummed).expect("valid checksummed address");
        assert_eq!(parsed, addr);
    }

    /// Checksum is deterministic: same address always produces same checksum.
    #[test]
    fn test_checksum_deterministic() {
        let addr = Address::from_public_key(&[99u8; 32]);
        let c1 = addr.to_checksummed_hex();
        let c2 = addr.to_checksummed_hex();
        assert_eq!(c1, c2);
    }

    /// Different addresses produce different checksums.
    #[test]
    fn test_different_addresses_different_checksums() {
        let a1 = Address::from_bytes([0x01; 20]);
        let a2 = Address::from_bytes([0x02; 20]);
        let c1 = a1.to_checksummed_hex();
        let c2 = a2.to_checksummed_hex();
        assert_ne!(c1, c2);
    }

    /// A single-character typo in the address hex must fail checksum verification.
    #[test]
    fn test_checksum_detects_typo() {
        let addr = Address::from_bytes([0xAB; 20]);
        let mut checksummed = addr.to_checksummed_hex();

        // Flip one character in the address portion (position 5 = first hex char)
        let bytes = unsafe { checksummed.as_bytes_mut() };
        bytes[5] = if bytes[5] == b'a' { b'b' } else { b'a' };
        let corrupted = std::str::from_utf8(bytes).unwrap();

        let result = Address::from_checksummed_hex(corrupted);
        assert!(
            matches!(result, Err(AddressChecksumError::ChecksumMismatch { .. })),
            "expected ChecksumMismatch, got {:?}",
            result,
        );
    }

    /// A single-character typo in the checksum portion must also fail.
    #[test]
    fn test_checksum_detects_checksum_typo() {
        let addr = Address::from_bytes([0xCD; 20]);
        let mut checksummed = addr.to_checksummed_hex();

        // Flip last character (inside the checksum portion)
        let len = checksummed.len();
        let bytes = unsafe { checksummed.as_bytes_mut() };
        bytes[len - 1] = if bytes[len - 1] == b'0' { b'1' } else { b'0' };
        let corrupted = std::str::from_utf8(bytes).unwrap();

        let result = Address::from_checksummed_hex(corrupted);
        assert!(
            matches!(result, Err(AddressChecksumError::ChecksumMismatch { .. })),
            "expected ChecksumMismatch, got {:?}",
            result,
        );
    }

    /// Legacy format (no checksum) is still accepted for backward compatibility.
    #[test]
    fn test_legacy_format_backward_compatible() {
        let addr = Address::from_bytes([0xEF; 20]);
        let legacy = addr.to_brrq_hex(); // brrq:<40 hex>, no checksum

        let parsed = Address::from_checksummed_hex(&legacy).expect("legacy format accepted");
        assert_eq!(parsed, addr);
    }

    /// verify_checksum returns Ok(true) for checksummed, Ok(false) for legacy.
    #[test]
    fn test_verify_checksum_results() {
        let addr = Address::from_bytes([0x77; 20]);

        let checksummed = addr.to_checksummed_hex();
        assert_eq!(Address::verify_checksum(&checksummed), Ok(true));

        let legacy = addr.to_brrq_hex();
        assert_eq!(Address::verify_checksum(&legacy), Ok(false));
    }

    /// verify_checksum returns Err for missing prefix.
    #[test]
    fn test_verify_checksum_missing_prefix() {
        let result = Address::verify_checksum("0xdeadbeef");
        assert!(matches!(result, Err(AddressChecksumError::MissingPrefix)));
    }

    /// verify_checksum returns Err for wrong length.
    #[test]
    fn test_verify_checksum_bad_length() {
        let result = Address::verify_checksum("brrq:abcd");
        assert!(matches!(
            result,
            Err(AddressChecksumError::InvalidLength { .. })
        ));
    }

    /// Cross-language compatibility test vector.
    /// Must match C11 test_l2_address_cross_language_vector() in Brrq01.
    #[test]
    fn test_cross_language_address_vector() {
        // pubkey = [0x42; 32]
        let pk = [0x42u8; 32];
        let addr = Address::from_public_key(&pk);

        // Print for C comparison
        println!(
            "  [VECTOR] ADDR pubkey=0x42*32 -> brrq:{}",
            hex::encode(addr.0)
        );

        // Also print checksummed format for cross-language verification
        println!(
            "  [VECTOR] ADDR checksummed   -> {}",
            addr.to_checksummed_hex()
        );

        // Verify domain tag is applied: SHA-256("BRRQ_ADDR_V1" || pk)
        let mut hasher = Hasher::new();
        hasher.update(b"BRRQ_ADDR_V1");
        hasher.update(&pk);
        let hash = hasher.finalize();
        assert_eq!(&addr.0, &hash.0[..20]);
    }

    /// Cross-language chain ID compatibility.
    /// Must match C11 BRRQ_L2_CHAIN_* defines in l2.h.
    #[test]
    fn test_cross_language_chain_ids() {
        use crate::transaction::chain_id;
        assert_eq!(chain_id::MAINNET, 0xB77C_0008);
        assert_eq!(chain_id::TESTNET, 0xB77C_0001);
        assert_eq!(chain_id::SIGNET, 0xB77C_0002);
        assert_eq!(chain_id::LOCAL, 0xB77C_FFFF);
    }
}
