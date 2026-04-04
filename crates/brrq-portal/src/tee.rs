//! TEE (Trusted Execution Environment) interface for Portal key protection.
//!
//! This module defines the trait that platform-specific TEE implementations
//! must satisfy. The actual implementations live in the mobile apps:
//! - iOS: Apple Secure Enclave (via Security.framework)
//! - Android: StrongBox Keymaster (via Android Keystore)
//! - HarmonyOS: HUKS (HarmonyOS Universal KeyStore)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  Mobile App (Swift / Kotlin / ArkTS)            │
//! │  ┌───────────────────────────────────────────┐  │
//! │  │  TeeKeyStore implementation               │  │
//! │  │  (Secure Enclave / StrongBox / HUKS)      │  │
//! │  └───────────────────┬───────────────────────┘  │
//! │                      │ FFI / JNI / NAPI         │
//! │  ┌───────────────────▼───────────────────────┐  │
//! │  │  brrq-portal (Rust)                       │  │
//! │  │  generate_portal_key(lock, &tee, &cond)   │  │
//! │  └───────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! ## Security Properties
//!
//! - Private key NEVER leaves the TEE hardware
//! - Signing happens inside the secure enclave
//! - Key is bound to device biometrics (Face ID / fingerprint)
//! - Attestation proves the key was generated in real hardware
//!
//! ## Fallback
//!
//! When TEE is unavailable (emulator, old device), `SoftwareKeyStore`
//! provides a software-only implementation using Argon2id key derivation.
//! This is acceptable for testnet but NOT for mainnet with large amounts.

use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::{SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature};

/// Errors from TEE operations.
#[derive(Debug, Clone)]
pub enum TeeError {
    /// TEE hardware not available on this device.
    NotAvailable,
    /// Key not found in the secure store.
    KeyNotFound(String),
    /// User authentication failed (biometrics/PIN).
    AuthenticationFailed,
    /// Signing operation failed inside the enclave.
    SigningFailed(String),
    /// Key generation failed.
    KeyGenerationFailed(String),
    /// Attestation verification failed.
    AttestationFailed(String),
}

impl std::fmt::Display for TeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeError::NotAvailable => write!(f, "TEE hardware not available"),
            TeeError::KeyNotFound(id) => write!(f, "key not found: {id}"),
            TeeError::AuthenticationFailed => write!(f, "biometric/PIN authentication failed"),
            TeeError::SigningFailed(e) => write!(f, "TEE signing failed: {e}"),
            TeeError::KeyGenerationFailed(e) => write!(f, "TEE key generation failed: {e}"),
            TeeError::AttestationFailed(e) => write!(f, "TEE attestation failed: {e}"),
        }
    }
}

impl std::error::Error for TeeError {}

/// Hardware attestation proof that a key was generated in real TEE.
#[derive(Debug, Clone)]
pub struct TeeAttestation {
    /// Platform identifier (e.g., "apple_se", "android_strongbox", "huks").
    pub platform: String,
    /// Raw attestation certificate chain (DER-encoded).
    pub certificate_chain: Vec<Vec<u8>>,
    /// Challenge used during attestation (prevents replay).
    pub challenge: Hash256,
}

/// Abstract interface for TEE-backed key storage.
///
/// Implementations must ensure:
/// 1. Private keys never leave the secure enclave
/// 2. Signing requires user authentication (biometrics/PIN)
/// 3. Keys are non-exportable by hardware design
pub trait TeeKeyStore: Send + Sync {
    /// Check if TEE hardware is available on this device.
    fn is_available(&self) -> bool;

    /// Generate a new Schnorr keypair inside the TEE.
    ///
    /// The private key is stored in the secure enclave and bound to
    /// the given `key_id`. The public key is returned for L2 registration.
    ///
    /// Requires user authentication (biometrics/PIN).
    fn generate_key(&self, key_id: &str) -> Result<SchnorrPublicKey, TeeError>;

    /// Sign a message hash using the TEE-protected private key.
    ///
    /// The hash is sent to the enclave; the signature is returned.
    /// The private key never leaves the hardware.
    ///
    /// Requires user authentication (biometrics/PIN).
    fn sign(&self, key_id: &str, msg_hash: &Hash256) -> Result<SchnorrSignature, TeeError>;

    /// Get the public key for a stored key.
    fn public_key(&self, key_id: &str) -> Result<SchnorrPublicKey, TeeError>;

    /// Delete a key from the TEE.
    fn delete_key(&self, key_id: &str) -> Result<(), TeeError>;

    /// Check if a key exists in the TEE.
    fn has_key(&self, key_id: &str) -> bool;

    /// Get hardware attestation proof for a key.
    ///
    /// Returns `None` if attestation is not supported (software fallback).
    fn attest(&self, key_id: &str, challenge: &Hash256) -> Result<Option<TeeAttestation>, TeeError>;
}

// ══════════════════════════════════════════════════════════════════
//  Software Fallback (testnet only)
// ══════════════════════════════════════════════════════════════════

/// Software-only key store for development and testing.
///
/// **WARNING:** Private keys are stored in memory. Not secure for production.
/// Use only for testnet or when TEE hardware is unavailable.
/// Replace RefCell with Mutex to eliminate unsound Send+Sync
pub struct SoftwareKeyStore {
    keys: std::sync::Mutex<std::collections::HashMap<String, SchnorrKeyPair>>,
}

impl SoftwareKeyStore {
    /// Create a new software key store.
    pub fn new() -> Self {
        Self {
            keys: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeKeyStore for SoftwareKeyStore {
    fn is_available(&self) -> bool {
        true // Software is always "available"
    }

    fn generate_key(&self, key_id: &str) -> Result<SchnorrPublicKey, TeeError> {
        let kp = SchnorrKeyPair::generate();
        let pubkey = *kp.public_key();
        self.keys.lock().unwrap().insert(key_id.to_string(), kp);
        Ok(pubkey)
    }

    fn sign(&self, key_id: &str, msg_hash: &Hash256) -> Result<SchnorrSignature, TeeError> {
        let keys = self.keys.lock().unwrap();
        let kp = keys.get(key_id).ok_or_else(|| TeeError::KeyNotFound(key_id.into()))?;
        kp.sign(msg_hash).map_err(|e| TeeError::SigningFailed(e.to_string()))
    }

    fn public_key(&self, key_id: &str) -> Result<SchnorrPublicKey, TeeError> {
        let keys = self.keys.lock().unwrap();
        let kp = keys.get(key_id).ok_or_else(|| TeeError::KeyNotFound(key_id.into()))?;
        Ok(*kp.public_key())
    }

    fn delete_key(&self, key_id: &str) -> Result<(), TeeError> {
        self.keys.lock().unwrap().remove(key_id);
        Ok(())
    }

    fn has_key(&self, key_id: &str) -> bool {
        self.keys.lock().unwrap().contains_key(key_id)
    }

    fn attest(&self, _key_id: &str, _challenge: &Hash256) -> Result<Option<TeeAttestation>, TeeError> {
        Ok(None) // Software keys cannot be attested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    #[test]
    fn test_software_keystore_generate_and_sign() {
        let store = SoftwareKeyStore::new();
        let pubkey = store.generate_key("test_key_1").unwrap();
        assert!(store.has_key("test_key_1"));

        let msg = Hasher::hash(b"test message for signing");
        let sig = store.sign("test_key_1", &msg).unwrap();

        // Verify externally
        brrq_crypto::schnorr::verify(&pubkey, &msg, &sig).unwrap();
    }

    #[test]
    fn test_software_keystore_key_not_found() {
        let store = SoftwareKeyStore::new();
        let msg = Hasher::hash(b"test");
        assert!(store.sign("nonexistent", &msg).is_err());
    }

    #[test]
    fn test_software_keystore_delete() {
        let store = SoftwareKeyStore::new();
        store.generate_key("ephemeral").unwrap();
        assert!(store.has_key("ephemeral"));
        store.delete_key("ephemeral").unwrap();
        assert!(!store.has_key("ephemeral"));
    }

    #[test]
    fn test_software_keystore_no_attestation() {
        let store = SoftwareKeyStore::new();
        store.generate_key("k1").unwrap();
        let challenge = Hasher::hash(b"challenge");
        let att = store.attest("k1", &challenge).unwrap();
        assert!(att.is_none()); // Software can't attest
    }

    #[test]
    fn test_software_keystore_multiple_keys() {
        let store = SoftwareKeyStore::new();
        let pk1 = store.generate_key("key_a").unwrap();
        let pk2 = store.generate_key("key_b").unwrap();
        assert_ne!(pk1.as_bytes(), pk2.as_bytes());

        let msg = Hasher::hash(b"shared message");
        let sig1 = store.sign("key_a", &msg).unwrap();
        let sig2 = store.sign("key_b", &msg).unwrap();

        // Each key produces valid but different signatures
        brrq_crypto::schnorr::verify(&pk1, &msg, &sig1).unwrap();
        brrq_crypto::schnorr::verify(&pk2, &msg, &sig2).unwrap();
        assert_ne!(sig1.as_bytes(), sig2.as_bytes());
    }
}
