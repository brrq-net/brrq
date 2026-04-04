//! Unified signature type supporting both Schnorr and SLH-DSA.
//!
//! Brrq's hybrid signature system:
//! - **Schnorr (BIP-340)**: Default, 64 bytes, Bitcoin-compatible
//! - **SLH-DSA (FIPS 205)**: Optional, ~7,856 bytes, quantum-resistant
//!
//! Users choose their signature type per-transaction.

use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};
use serde::{Deserialize, Serialize};

/// The type of signature used.
///
/// **IMPORTANT**: Discriminant values are used in transaction hashing
/// (`signature_type as u8`). Reordering or reassigning values will
/// break all existing transaction hashes. Always use explicit values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureType {
    /// Classical Schnorr (BIP-340) — 64 bytes, fast, not quantum-resistant.
    Schnorr = 0,
    /// Post-quantum SLH-DSA (FIPS 205) — ~7,856 bytes, quantum-resistant.
    SlhDsa = 1,
    // Reserved.
}

/// A public key that can be either Schnorr or SLH-DSA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Schnorr(SchnorrPublicKey),
    SlhDsa(SlhDsaPublicKey),
}

impl PublicKey {
    /// Get the signature type.
    pub fn signature_type(&self) -> SignatureType {
        match self {
            PublicKey::Schnorr(_) => SignatureType::Schnorr,
            PublicKey::SlhDsa(_) => SignatureType::SlhDsa,
        }
    }

    /// Get the raw bytes of the public key.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Schnorr(pk) => pk.as_bytes(),
            PublicKey::SlhDsa(pk) => pk.as_bytes(),
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> usize {
        match self {
            PublicKey::Schnorr(_) => 32,
            PublicKey::SlhDsa(pk) => pk.as_bytes().len(),
        }
    }
}

/// A signature that can be either Schnorr or SLH-DSA.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Schnorr(SchnorrSignature),
    SlhDsa(SlhDsaSignature),
}

impl Signature {
    /// Get the signature type.
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Signature::Schnorr(_) => SignatureType::Schnorr,
            Signature::SlhDsa(_) => SignatureType::SlhDsa,
        }
    }

    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Signature::Schnorr(s) => s.as_bytes(),
            Signature::SlhDsa(s) => s.as_bytes(),
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> usize {
        match self {
            Signature::Schnorr(_) => 64,
            Signature::SlhDsa(sig) => sig.size(),
        }
    }
}
