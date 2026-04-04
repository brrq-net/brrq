//! EOTS — Extractable One-Time Signatures.
//!
//! Based on Schnorr signatures where reusing a nonce for two different
//! messages reveals the secret key. This is the self-enforcing slashing
//! mechanism used alongside SLH-DSA equivocation in Brrq's dual signing.
//!
//! ## How EOTS Works
//!
//! 1. Sequencer commits to a nonce `R = k·G` for each block height
//! 2. Signs block with `s = k + e·sk` where `e = H(R || pk || msg)`
//! 3. If sequencer signs TWO different blocks with the SAME nonce:
//!    - `s1 = k + e1·sk` and `s2 = k + e2·sk`
//!    - `sk = (s1 - s2) / (e1 - e2)` — **secret key extracted!**
//! 4. Anyone with the extracted key can spend the staking UTXO
//!
//! ## Security Note
//!
//! EOTS is NOT quantum-resistant (based on secp256k1 curve).
//! SLH-DSA equivocation provides the hash-based fraud detection path.

use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{Hash256, Hasher};
use crate::scalar;
use crate::schnorr::SchnorrPublicKey;

/// Domain separation tag for EOTS challenge hashes.
///
/// Prevents cross-protocol forgery attacks where a hash computed in a
/// different context (e.g. BIP-340 Schnorr, another EOTS scheme) could
/// be replayed as a valid EOTS challenge.
///
/// Format: tagged_hash("BRRQ_EOTS/challenge", R || pk || msg)
/// Uses the BIP-340-style double-prefix: SHA-256(SHA-256(tag) || SHA-256(tag) || data)
const EOTS_CHALLENGE_TAG: &[u8] = crate::domain_tags::EOTS_CHALLENGE;

/// Compute the domain-separated EOTS challenge: e = tagged_hash(R || pk || msg).
fn eots_challenge(nonce_commitment: &[u8], public_key: &[u8], message: &Hash256) -> Hash256 {
    // BIP-340 style tagged hash: H(H(tag) || H(tag) || data)
    let tag_hash = Hasher::hash(EOTS_CHALLENGE_TAG);
    let mut hasher = Hasher::new();
    hasher.update(tag_hash.as_bytes());
    hasher.update(tag_hash.as_bytes());
    hasher.update(nonce_commitment);
    hasher.update(public_key);
    hasher.update(message.as_bytes());
    hasher.finalize()
}

/// Errors in EOTS operations.
#[derive(Debug, Error)]
pub enum EotsError {
    #[error("invalid nonce")]
    InvalidNonce,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("nonce reuse detected — secret key extractable")]
    NonceReuseDetected,
    #[error("key extraction failed")]
    KeyExtractionFailed,
    #[error("EOTS signature verification failed")]
    VerificationFailed,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// An EOTS nonce commitment (R = k·G, compressed 33-byte public key).
///
/// Inner field is private -- construction only via validated methods.
/// `from_bytes` validates the point is on the secp256k1 curve.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsNonceCommitment(#[serde(with = "serde_bytes")] Vec<u8>);

impl EotsNonceCommitment {
    /// Create from a 33-byte compressed public key.
    ///
    /// Validates the bytes represent a valid point on secp256k1.
    /// Rejects invalid curve points that could cause verification to behave
    /// unpredictably or enable forgery attacks.
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, EotsError> {
        // Validate the point is on the curve
        PublicKey::from_slice(&bytes).map_err(|_| EotsError::InvalidNonce)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Create from a validated secp256k1 PublicKey (internal use).
    pub(crate) fn from_public_key(pk: &PublicKey) -> Self {
        Self(pk.serialize().to_vec())
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Construct from raw bytes without curve validation.
    ///
    /// # Safety (logical)
    /// Only use for:
    /// - Deserialized data that will be validated at verification time
    /// - Test/mock signatures that are never cryptographically verified
    ///
    /// Production signing paths MUST use `from_bytes()` or `from_public_key()`.
    #[doc(hidden)]
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for EotsNonceCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EotsNonce({})",
            hex::encode(&self.0[..8.min(self.0.len())])
        )
    }
}

/// An EOTS signature (nonce commitment + s-value).
///
/// Fields are private -- construction only via `new()` which validates
/// s_value length, preventing wrong-length scalars that would panic in verify.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsSignature {
    /// The nonce commitment (R)
    nonce_commitment: EotsNonceCommitment,
    /// The s-value (scalar, 32 bytes)
    s_value: Vec<u8>,
}

impl EotsSignature {
    /// Create a new EOTS signature with validated components.
    ///
    /// Enforces s_value is exactly 32 bytes at construction time.
    pub fn new(nonce_commitment: EotsNonceCommitment, s_value: Vec<u8>) -> Result<Self, EotsError> {
        if s_value.len() != 32 {
            return Err(EotsError::InvalidNonce);
        }
        Ok(Self {
            nonce_commitment,
            s_value,
        })
    }

    /// Access the nonce commitment.
    pub fn nonce_commitment(&self) -> &EotsNonceCommitment {
        &self.nonce_commitment
    }

    /// Access the s-value bytes.
    pub fn s_value(&self) -> &[u8] {
        &self.s_value
    }

    /// Construct from raw components without length validation.
    ///
    /// # Safety (logical)
    /// Only use for:
    /// - Deserialized data that will be validated at verification time
    /// - Test/mock signatures that are never cryptographically verified
    ///
    /// Production signing paths MUST use `new()`.
    #[doc(hidden)]
    pub fn new_unchecked(nonce_commitment: EotsNonceCommitment, s_value: Vec<u8>) -> Self {
        Self {
            nonce_commitment,
            s_value,
        }
    }
}

impl std::fmt::Debug for EotsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EotsSig(s={}...)",
            hex::encode(&self.s_value[..8.min(self.s_value.len())])
        )
    }
}

/// EOTS keypair bound to a specific signing session.
///
/// Implements `Drop` to securely zeroize secret key material from memory
/// when the keypair is no longer needed.
pub struct EotsKeyPair {
    secret_key: SecretKey,
    public_key: SchnorrPublicKey,
}

impl Drop for EotsKeyPair {
    fn drop(&mut self) {
        // Overwrite the struct's memory directly using `write_volatile`
        // because `secret_bytes()` returns a copy -- zeroizing the copy
        // would not touch the real key material inside `SecretKey`.
        unsafe {
            let sk_ptr = &mut self.secret_key as *mut SecretKey as *mut u8;
            let sk_size = std::mem::size_of::<SecretKey>();
            for i in 0..sk_size {
                std::ptr::write_volatile(sk_ptr.add(i), 0u8);
            }
        }
        // Compiler fence: ensure the volatile writes are not reordered
        // past this point by the CPU or compiler.
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl EotsKeyPair {
    /// Create from existing Schnorr secret key.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, EotsError> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(bytes).map_err(|_| EotsError::InvalidSecretKey)?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        let public_key = SchnorrPublicKey::from_bytes(xonly.serialize());

        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Get the public key.
    pub fn public_key(&self) -> &SchnorrPublicKey {
        &self.public_key
    }

    /// Get the secret key bytes (32 bytes).
    ///
    /// Returns a `SecretBytes` wrapper that zeroizes the copy on drop.
    pub fn secret_bytes(&self) -> crate::schnorr::SecretBytes {
        crate::schnorr::SecretBytes(self.secret_key.secret_bytes())
    }

    /// Generate a deterministic nonce for a given block height.
    ///
    /// The nonce is derived from: HMAC-SHA256(sk, "EOTS" || height || epoch)
    /// This ensures each height gets a unique nonce, preventing accidental reuse.
    #[deprecated(note = "Use generate_nonce_v2 with prev_block_hash.")]
    pub fn generate_nonce(
        &self,
        height: u64,
        epoch: u64,
    ) -> Result<(SecretKey, EotsNonceCommitment), EotsError> {
        // Delegate to V2 with no prev_block_hash for backwards compatibility
        self.generate_nonce_v2(height, epoch, None)
    }

    /// V2 nonce derivation with prev_block_hash binding.
    ///
    /// Binds the nonce to the previous block hash, preventing an attacker
    /// from pre-computing nonces for future blocks without knowing chain state.
    ///
    /// `nonce = HMAC-SHA256(sk, "EOTS_NONCE_V2" || height || epoch || prev_block_hash)`
    pub fn generate_nonce_v2(
        &self,
        height: u64,
        epoch: u64,
        prev_block_hash: Option<&Hash256>,
    ) -> Result<(SecretKey, EotsNonceCommitment), EotsError> {
        let secp = Secp256k1::new();

        // Deterministic nonce derivation — V2 includes prev_block_hash
        let nonce_input = {
            let mut data = Vec::new();
            if prev_block_hash.is_some() {
                data.extend_from_slice(crate::domain_tags::EOTS_NONCE_V2);
            } else {
                data.extend_from_slice(crate::domain_tags::EOTS_NONCE);
            }
            data.extend_from_slice(&height.to_le_bytes());
            data.extend_from_slice(&epoch.to_le_bytes());
            if let Some(hash) = prev_block_hash {
                data.extend_from_slice(hash.as_bytes());
            }
            data
        };

        let mut nonce_hash =
            crate::sha256::hmac_sha256(&self.secret_key.secret_bytes(), &nonce_input);

        let nonce_sk =
            SecretKey::from_slice(nonce_hash.as_bytes()).map_err(|_| EotsError::InvalidNonce)?;

        // Zeroize the raw nonce hash immediately -- it IS the nonce scalar.
        // Nonce leakage = secret key extraction = loss of staked funds.
        crate::zeroize::zeroize_bytes(&mut nonce_hash.0);

        let nonce_pk = PublicKey::from_secret_key(&secp, &nonce_sk);

        let commitment = EotsNonceCommitment::from_public_key(&nonce_pk);
        Ok((nonce_sk, commitment))
    }

    /// Sign a message using EOTS with a specific nonce.
    ///
    /// **WARNING**: Using the same nonce for two different messages
    /// will reveal the secret key!
    pub fn sign(
        &self,
        message: &Hash256,
        nonce_sk: &SecretKey,
        nonce_commitment: &EotsNonceCommitment,
    ) -> Result<EotsSignature, EotsError> {
        // e = tagged_hash("BRRQ_EOTS/challenge", R || pk || msg)
        let challenge = eots_challenge(&nonce_commitment.0, self.public_key.as_bytes(), message);

        // s = k + e * sk (mod n)
        // Proper 256-bit modular arithmetic on secp256k1 scalar field
        let mut k_bytes = nonce_sk.secret_bytes();
        let mut sk_bytes = self.secret_key.secret_bytes();
        let e_bytes = challenge.0;

        let mut k = scalar::from_bytes(&k_bytes);
        let mut sk = scalar::from_bytes(&sk_bytes);
        let e = scalar::from_bytes(&e_bytes);

        let mut e_sk = scalar::mul_mod(&e, &sk); // e * sk mod n
        let mut s = scalar::add_mod(&k, &e_sk); // k + e*sk mod n
        let s_value = scalar::to_bytes(&s).to_vec();

        // Zeroize all secret scalar intermediates from the stack.
        crate::zeroize::zeroize_bytes(&mut k_bytes);
        crate::zeroize::zeroize_bytes(&mut sk_bytes);
        // Zeroize U256 scalars via their byte representation
        for limb in k.iter_mut() {
            *limb = 0;
        }
        for limb in sk.iter_mut() {
            *limb = 0;
        }
        for limb in e_sk.iter_mut() {
            *limb = 0;
        }
        for limb in s.iter_mut() {
            *limb = 0;
        }
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

        Ok(EotsSignature {
            nonce_commitment: nonce_commitment.clone(),
            s_value,
        })
    }
}

/// Verify an EOTS signature.
///
/// Reconstructs the challenge `e = H(R || pk || msg)` and verifies
/// that `s·G == R + e·P` using secp256k1 point arithmetic.
///
/// Returns `Err(VerificationFailed)` when the signature is invalid.
pub fn verify(
    public_key: &SchnorrPublicKey,
    message: &Hash256,
    signature: &EotsSignature,
) -> Result<(), EotsError> {
    let secp = Secp256k1::new();

    // Parse R from the nonce commitment (33-byte compressed point)
    let r_point = PublicKey::from_slice(&signature.nonce_commitment.0)
        .map_err(|_| EotsError::InvalidNonce)?;

    // Parse P from the public key (reconstruct full public key from x-only)
    // SchnorrPublicKey is 32-byte x-only, need to convert to a full public key
    let pk_xonly = secp256k1::XOnlyPublicKey::from_slice(public_key.as_bytes())
        .map_err(EotsError::Secp256k1)?;

    // Compute challenge e = tagged_hash("BRRQ_EOTS/challenge", R || pk || msg)
    let challenge = eots_challenge(
        &signature.nonce_commitment.0,
        public_key.as_bytes(),
        message,
    );

    // Parse s from signature
    let s_bytes: [u8; 32] = signature
        .s_value
        .as_slice()
        .try_into()
        .map_err(|_| EotsError::InvalidNonce)?;

    // Verify: s·G == R + e·P
    // We try both parities for P since the x-only public key loses parity info.

    let e_scalar =
        secp256k1::Scalar::from_be_bytes(challenge.0).map_err(|_| EotsError::InvalidNonce)?;

    // s*G
    let s_sk = SecretKey::from_slice(&s_bytes).map_err(EotsError::Secp256k1)?;
    let s_g = PublicKey::from_secret_key(&secp, &s_sk);

    // Try both parities for the public key (x-only key doesn't encode parity)
    for parity in [secp256k1::Parity::Even, secp256k1::Parity::Odd] {
        let p_full = PublicKey::from_x_only_public_key(pk_xonly, parity);

        // e*P (mul_tweak does scalar * point)
        let ep = match p_full.mul_tweak(&secp, &e_scalar) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // R + e*P
        let rhs = match PublicKey::combine_keys(&[&r_point, &ep]) {
            Ok(p) => p,
            Err(_) => continue,
        };

        if s_g == rhs {
            return Ok(());
        }
    }

    Err(EotsError::VerificationFailed)
}

/// Attempt to extract the secret key from two EOTS signatures
/// that reused the same nonce on different messages.
///
/// If successful, returns the extracted secret key, enabling
/// self-enforcing slashing (anyone can spend the staking UTXO).
///
/// ## This is the core EOTS slashing mechanism:
/// - sig1: s1 = k + e1·sk
/// - sig2: s2 = k + e2·sk
/// - sk = (s1 - s2) / (e1 - e2)
///   Returns `SecretBytes` to ensure the extracted secret key is zeroized on drop.
pub fn extract_secret_key(
    public_key: &SchnorrPublicKey,
    message1: &Hash256,
    sig1: &EotsSignature,
    message2: &Hash256,
    sig2: &EotsSignature,
) -> Result<crate::schnorr::SecretBytes, EotsError> {
    // Messages must be different
    if message1 == message2 {
        return Err(EotsError::KeyExtractionFailed);
    }

    // Nonces must be the same (reuse condition)
    if sig1.nonce_commitment != sig2.nonce_commitment {
        return Err(EotsError::KeyExtractionFailed);
    }

    // Compute challenges with domain-separated tagged hash
    let e1 = eots_challenge(&sig1.nonce_commitment.0, public_key.as_bytes(), message1);

    let e2 = eots_challenge(&sig2.nonce_commitment.0, public_key.as_bytes(), message2);

    // sk = (s1 - s2) / (e1 - e2) mod n
    // Proper 256-bit modular arithmetic on secp256k1 scalar field
    let s1 = scalar::from_bytes(
        sig1.s_value
            .as_slice()
            .try_into()
            .map_err(|_| EotsError::KeyExtractionFailed)?,
    );
    let s2 = scalar::from_bytes(
        sig2.s_value
            .as_slice()
            .try_into()
            .map_err(|_| EotsError::KeyExtractionFailed)?,
    );
    let e1_scalar = scalar::from_bytes(&e1.0);
    let e2_scalar = scalar::from_bytes(&e2.0);

    let s_diff = scalar::sub_mod(&s1, &s2); // s1 - s2 mod n
    let e_diff = scalar::sub_mod(&e1_scalar, &e2_scalar); // e1 - e2 mod n

    // Check e_diff is not zero (would mean identical challenges — shouldn't happen)
    if e_diff == [0u64; 4] {
        return Err(EotsError::KeyExtractionFailed);
    }

    let e_diff_inv = scalar::inv_mod(&e_diff).ok_or(EotsError::KeyExtractionFailed)?; // (e1 - e2)^(-1) mod n
    let sk_extracted = scalar::mul_mod(&s_diff, &e_diff_inv); // (s1-s2) * (e1-e2)^(-1)

    // Verify extracted key matches the claimed public key.
    let sk_bytes = scalar::to_bytes(&sk_extracted);
    let derived_kp = crate::schnorr::SchnorrKeyPair::from_secret_bytes(&sk_bytes)
        .map_err(|_| EotsError::KeyExtractionFailed)?;
    if derived_kp.public_key().as_bytes() != public_key.as_bytes() {
        return Err(EotsError::KeyExtractionFailed);
    }

    Ok(crate::schnorr::SecretBytes(sk_bytes))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        let (_nonce1, commitment1) = eots.generate_nonce(100, 5).unwrap();
        let (_nonce2, commitment2) = eots.generate_nonce(100, 5).unwrap();

        // Deterministic: same height+epoch = same nonce
        assert_eq!(commitment1, commitment2);

        // Different height = different nonce
        let (_nonce3, commitment3) = eots.generate_nonce(101, 5).unwrap();
        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn test_sign_produces_signature() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        let (nonce_sk, commitment) = eots.generate_nonce(100, 5).unwrap();
        let msg = Hasher::hash(b"block data at height 100");

        let sig = eots.sign(&msg, &nonce_sk, &commitment).unwrap();
        assert_eq!(*sig.nonce_commitment(), commitment);
        assert_eq!(sig.s_value().len(), 32);
    }

    #[test]
    fn test_nonce_reuse_detection() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        // Same nonce used for two different messages
        let (nonce_sk, commitment) = eots.generate_nonce(100, 5).unwrap();

        let msg1 = Hasher::hash(b"block A at height 100");
        let msg2 = Hasher::hash(b"block B at height 100");

        let sig1 = eots.sign(&msg1, &nonce_sk, &commitment).unwrap();
        let sig2 = eots.sign(&msg2, &nonce_sk, &commitment).unwrap();

        // Nonces are the same
        assert_eq!(*sig1.nonce_commitment(), *sig2.nonce_commitment());

        // Secret key should be extractable
        let extracted = extract_secret_key(eots.public_key(), &msg1, &sig1, &msg2, &sig2);
        assert!(extracted.is_ok());

        // Verify extracted key matches the original secret key
        // (SecretBytes derefs to &[u8; 32] via Deref impl)
        let extracted_bytes = extracted.unwrap();
        assert_eq!(*extracted_bytes, sk, "extracted key should match original");
    }

    #[test]
    fn test_eots_verify_valid() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        let (nonce_sk, commitment) = eots.generate_nonce(100, 5).unwrap();
        let msg = Hasher::hash(b"block data at height 100");

        let sig = eots.sign(&msg, &nonce_sk, &commitment).unwrap();

        // Should verify correctly
        verify(eots.public_key(), &msg, &sig).expect("valid EOTS signature should verify");
    }

    #[test]
    fn test_eots_verify_wrong_message() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        let (nonce_sk, commitment) = eots.generate_nonce(100, 5).unwrap();
        let msg = Hasher::hash(b"block data at height 100");
        let wrong_msg = Hasher::hash(b"wrong block data");

        let sig = eots.sign(&msg, &nonce_sk, &commitment).unwrap();

        // Should fail with different message
        assert!(
            verify(eots.public_key(), &wrong_msg, &sig).is_err(),
            "EOTS signature should not verify for wrong message"
        );
    }

    #[test]
    fn test_eots_verify_wrong_key() {
        let sk1 = [42u8; 32];
        let sk2 = [43u8; 32];
        let eots1 = EotsKeyPair::from_secret_bytes(&sk1).unwrap();
        let eots2 = EotsKeyPair::from_secret_bytes(&sk2).unwrap();

        let (nonce_sk, commitment) = eots1.generate_nonce(100, 5).unwrap();
        let msg = Hasher::hash(b"block data");

        let sig = eots1.sign(&msg, &nonce_sk, &commitment).unwrap();

        // Should fail with wrong public key
        assert!(
            verify(eots2.public_key(), &msg, &sig).is_err(),
            "EOTS signature should not verify for wrong key"
        );
    }

    #[test]
    fn test_different_nonces_no_extraction() {
        let sk = [42u8; 32];
        let eots = EotsKeyPair::from_secret_bytes(&sk).unwrap();

        // Different nonces for different heights (correct behavior)
        let (nonce_sk1, commitment1) = eots.generate_nonce(100, 5).unwrap();
        let (nonce_sk2, commitment2) = eots.generate_nonce(101, 5).unwrap();

        let msg1 = Hasher::hash(b"block at height 100");
        let msg2 = Hasher::hash(b"block at height 101");

        let sig1 = eots.sign(&msg1, &nonce_sk1, &commitment1).unwrap();
        let sig2 = eots.sign(&msg2, &nonce_sk2, &commitment2).unwrap();

        // Different nonces — extraction should fail
        let result = extract_secret_key(eots.public_key(), &msg1, &sig1, &msg2, &sig2);
        assert!(result.is_err());
    }
}
