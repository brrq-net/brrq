//! Schnorr signature implementation (BIP-340 compatible).
//!
//! Used as the default (classical) signature scheme in Brrq.
//! - 64-byte signatures
//! - ~0.05ms signing/verification
//! - Bitcoin-compatible (BIP-340/Taproot)
//!
//! Note: Not quantum-resistant. Users requiring post-quantum
//! security should use SLH-DSA (see `slh_dsa` module).

use secp256k1::{Keypair, SECP256K1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{Hash256, Hasher};

/// A 32-byte secret that zeroizes itself on drop.
///
/// Prevents secret key copies from lingering on the stack after use.
/// Field is `pub(crate)` so external code cannot bypass zeroize-on-drop.
/// External access uses `Deref` or `AsRef` (which return references,
/// not owned copies that escape zeroization).
pub struct SecretBytes(pub(crate) [u8; 32]);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.0);
    }
}

impl std::ops::Deref for SecretBytes {
    type Target = [u8; 32];
    fn deref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for SecretBytes {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Errors that can occur during Schnorr operations.
#[derive(Debug, Error)]
pub enum SchnorrError {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// A Schnorr public key (x-only, 32 bytes per BIP-340).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchnorrPublicKey(pub(crate) [u8; 32]);

impl SchnorrPublicKey {
    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SchnorrError> {
        if slice.len() != 32 {
            return Err(SchnorrError::InvalidPublicKey(
                "expected 32 bytes".to_string(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Compute the hash of this public key (for address derivation).
    pub fn to_hash(&self) -> Hash256 {
        Hasher::hash(&self.0)
    }
}

impl std::fmt::Debug for SchnorrPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SchnorrPK({})", hex::encode(&self.0[..8]))
    }
}

/// A Schnorr signature (64 bytes per BIP-340).
///
/// Uses `Vec<u8>` internally for serde compatibility while maintaining
/// the invariant that the length is always exactly 64 bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl SchnorrSignature {
    /// Create from raw 64 bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes.to_vec())
    }

    /// Create from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, SchnorrError> {
        if slice.len() != 64 {
            return Err(SchnorrError::InvalidSignature);
        }
        Ok(Self(slice.to_vec()))
    }

    /// Get the raw bytes as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Size in bytes (always 64 for Schnorr).
    pub const SIZE: usize = 64;
}

impl std::fmt::Debug for SchnorrSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SchnorrSig({}...)",
            hex::encode(&self.0[..8.min(self.0.len())])
        )
    }
}

/// A Schnorr keypair for signing.
///
/// Implements `Drop` to securely zeroize secret key material from memory
/// when the keypair is no longer needed.
pub struct SchnorrKeyPair {
    secret_key: SecretKey,
    keypair: Keypair,
    public_key: SchnorrPublicKey,
}

// Compile-time verification that SecretKey and Keypair sizes match expectations.
// If secp256k1 crate changes struct layout, these assertions will catch it at build time.
const _: () = assert!(std::mem::size_of::<SecretKey>() == 32);
const _: () = assert!(std::mem::size_of::<Keypair>() == 96);

impl Drop for SchnorrKeyPair {
    fn drop(&mut self) {
        // Overwrite the structs' memory directly using `write_volatile`
        // because `secret_bytes()` returns a copy — zeroizing the copy
        // would not touch the real key material inside `SecretKey` / `Keypair`.
        unsafe {
            let sk_ptr = &mut self.secret_key as *mut SecretKey as *mut u8;
            let sk_size = std::mem::size_of::<SecretKey>();
            for i in 0..sk_size {
                std::ptr::write_volatile(sk_ptr.add(i), 0u8);
            }

            let kp_ptr = &mut self.keypair as *mut Keypair as *mut u8;
            let kp_size = std::mem::size_of::<Keypair>();
            for i in 0..kp_size {
                std::ptr::write_volatile(kp_ptr.add(i), 0u8);
            }
        }
        // Compiler fence: ensure the volatile writes are not reordered
        // past this point by the CPU or compiler.
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl SchnorrKeyPair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let (secret_key, _public_key) = SECP256K1.generate_keypair(&mut rng);
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (xonly, _parity) = keypair.x_only_public_key();
        let public_key = SchnorrPublicKey::from_bytes(xonly.serialize());

        Self {
            secret_key,
            keypair,
            public_key,
        }
    }

    /// Create from a secret key (32 bytes).
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SchnorrError> {
        let secret_key =
            SecretKey::from_slice(bytes).map_err(|_| SchnorrError::InvalidSecretKey)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret_key);
        let (xonly, _parity) = keypair.x_only_public_key();
        let public_key = SchnorrPublicKey::from_bytes(xonly.serialize());

        Ok(Self {
            secret_key,
            keypair,
            public_key,
        })
    }

    /// Get the public key.
    pub fn public_key(&self) -> &SchnorrPublicKey {
        &self.public_key
    }

    /// Get the secret key bytes.
    ///
    /// Returns a `SecretBytes` wrapper that zeroizes the copy on drop,
    /// preventing secret key material from lingering on the caller's stack.
    pub fn secret_bytes(&self) -> SecretBytes {
        SecretBytes(self.secret_key.secret_bytes())
    }

    /// Sign a message hash (BIP-340 Schnorr).
    pub fn sign(&self, msg_hash: &Hash256) -> Result<SchnorrSignature, SchnorrError> {
        // secp256k1 0.30: sign_schnorr takes &[u8], not Message
        let sig = SECP256K1.sign_schnorr(msg_hash.as_bytes(), &self.keypair);
        let sig_bytes: &[u8] = sig.as_ref();
        SchnorrSignature::from_slice(sig_bytes).map_err(|_| SchnorrError::InvalidSignature)
    }
}

/// Verify a Schnorr signature (BIP-340).
pub fn verify(
    public_key: &SchnorrPublicKey,
    msg_hash: &Hash256,
    signature: &SchnorrSignature,
) -> Result<(), SchnorrError> {
    let xonly = XOnlyPublicKey::from_slice(public_key.as_bytes())?;
    let sig = secp256k1::schnorr::Signature::from_slice(signature.as_bytes())?;
    // secp256k1 0.30: verify_schnorr takes &[u8], not Message
    SECP256K1
        .verify_schnorr(&sig, msg_hash.as_bytes(), &xonly)
        .map_err(|_| SchnorrError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = SchnorrKeyPair::generate();
        assert_eq!(kp.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = SchnorrKeyPair::generate();
        let msg = Hasher::hash(b"test message for Brrq protocol");

        let sig = kp.sign(&msg).unwrap();
        assert_eq!(sig.as_bytes().len(), 64);

        // Verification should succeed
        verify(kp.public_key(), &msg, &sig).unwrap();
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = SchnorrKeyPair::generate();
        let msg1 = Hasher::hash(b"correct message");
        let msg2 = Hasher::hash(b"wrong message");

        let sig = kp.sign(&msg1).unwrap();

        // Verification with wrong message should fail
        assert!(verify(kp.public_key(), &msg2, &sig).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = SchnorrKeyPair::generate();
        let kp2 = SchnorrKeyPair::generate();
        let msg = Hasher::hash(b"test message");

        let sig = kp1.sign(&msg).unwrap();

        // Verification with wrong key should fail
        assert!(verify(kp2.public_key(), &msg, &sig).is_err());
    }

    #[test]
    fn test_deterministic_from_secret() {
        let secret = [42u8; 32];
        let kp1 = SchnorrKeyPair::from_secret_bytes(&secret).unwrap();
        let kp2 = SchnorrKeyPair::from_secret_bytes(&secret).unwrap();
        assert_eq!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_signature_size() {
        assert_eq!(SchnorrSignature::SIZE, 64);
    }
}
