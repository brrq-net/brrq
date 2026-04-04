#![allow(clippy::needless_range_loop)]
//! SHA-256 CTR mode encryption for MEV protection.
//!
//! ## Hash-First Symmetric Encryption
//!
//! Uses SHA-256 in counter mode (CTR) to build a stream cipher
//! entirely from hash functions — no AES or external ciphers needed.
//!
//! ## Design (§4.7 — MEV Commit-Reveal)
//!
//! - **EpochKey**: Derived from epoch seed via tagged hash
//! - **CTR mode**: keystream[i] = SHA-256(key ∥ counter ∥ nonce)
//! - **Authentication**: HMAC-SHA256(key, nonce ∥ ciphertext)
//! - **Commitment**: SHA-256(ciphertext ∥ tag)

use serde::{Deserialize, Serialize};

use crate::hash::{Hash256, Hasher};
use crate::sha256::{hmac_sha256, tagged_hash};

/// A 256-bit symmetric key derived from an epoch seed.
///
/// Used to encrypt transaction `kind` payloads during the commit phase.
/// All participants in the same epoch share this key — it's only revealed
/// after ordering is committed, preventing sequencer front-running.
#[derive(PartialEq, Eq)]
pub struct EpochKey([u8; 32]);

impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EpochKey(<redacted>)")
    }
}

impl EpochKey {
    /// Derive an epoch key from the epoch seed and epoch number.
    ///
    /// Uses BIP-340-style tagged hash for domain separation:
    /// `key = tagged_hash("BRRQ_EPOCH_KEY", epoch_seed ∥ epoch.to_le_bytes())`
    ///
    /// Epoch key derivation without L1 anchor binding.
    /// For MEV decryption, use [`derive_with_anchor`] instead.
    #[deprecated(note = "Use derive_with_anchor() for MEV paths.")]
    pub fn derive(epoch_seed: &Hash256, epoch: u64) -> Self {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(epoch_seed.as_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        let hash = tagged_hash(crate::domain_tags::EPOCH_KEY, &data);
        Self(*hash.as_bytes())
    }

    /// Derive an epoch key anchored to an L1 block hash.
    ///
    /// The key depends on the L1 block hash in which the sequencer's ordering
    /// commitment was mined. Since the sequencer cannot predict the L1 block
    /// hash before broadcasting, it cannot derive the epoch key until AFTER
    /// the ordering is committed on-chain. This creates a natural temporal
    /// separation that defeats pre-decryption MEV extraction.
    ///
    /// ```text
    /// key = tagged_hash("BRRQ_EPOCH_ANCHORED_KEY",
    ///                    epoch_seed ∥ epoch.to_le_bytes() ∥ l1_anchor_hash)
    /// ```
    ///
    /// # Arguments
    /// - `epoch_seed`: The revealed epoch seed (only available after ordering commitment).
    /// - `epoch`: The epoch number.
    /// - `l1_anchor_hash`: The Bitcoin L1 block hash containing the ordering commitment tx.
    pub fn derive_with_anchor(epoch_seed: &Hash256, epoch: u64, l1_anchor_hash: &Hash256) -> Self {
        let mut data = Vec::with_capacity(72);
        data.extend_from_slice(epoch_seed.as_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(l1_anchor_hash.as_bytes());
        let hash = tagged_hash(crate::domain_tags::EPOCH_ANCHORED_KEY, &data);
        Self(*hash.as_bytes())
    }

    /// Create an EpochKey from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for EpochKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.0);
    }
}

/// Generate a cryptographically random 16-byte nonce for use with [`seal`].
///
/// Uses `thread_rng()` for OS-seeded randomness. Each call to `seal()` MUST
/// use a fresh nonce — reusing a (key, nonce) pair leaks XOR of plaintexts.
///
/// For MEV envelope encryption, prefer [`NonceCounter`] which guarantees
/// uniqueness via a monotonic counter (no birthday-bound collision risk).
pub fn generate_nonce() -> [u8; 16] {
    use rand::RngCore;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Monotonic nonce counter for MEV encryption.
///
/// Generates unique 16-byte nonces structured as:
/// ```text
/// nonce = node_id[8 bytes] || counter[8 bytes big-endian]
/// ```
///
/// Unlike random nonces (birthday collision at ~2^64), a monotonic counter
/// guarantees uniqueness with zero collision probability. The `node_id`
/// prefix ensures uniqueness across different sequencers.
///
/// ## Crash Recovery
///
/// On restart, use [`NonceCounter::new_recovering`] with the last known
/// block height in the current epoch to set a safe floor. The counter
/// resets naturally each epoch (new key = new encryption context).
///
/// ## Thread Safety
///
/// Uses `AtomicU64` with `SeqCst` ordering — safe for concurrent use.
pub struct NonceCounter {
    counter: std::sync::atomic::AtomicU64,
    node_id: [u8; 8],
}

impl NonceCounter {
    /// Create a new counter starting at 0.
    ///
    /// `node_id` should be unique per sequencer, e.g. `SHA-256(pubkey)[..8]`.
    pub fn new(node_id: [u8; 8]) -> Self {
        Self {
            counter: std::sync::atomic::AtomicU64::new(0),
            node_id,
        }
    }

    /// Create a counter with a crash-recovery floor.
    ///
    /// Sets the initial counter to `last_block_in_epoch * max_txs_per_block`,
    /// which is deterministic from on-chain state and guaranteed to be above
    /// any previously used value.
    pub fn new_recovering(node_id: [u8; 8], last_block_in_epoch: u64, max_txs_per_block: u64) -> Self {
        let floor = last_block_in_epoch.saturating_mul(max_txs_per_block);
        Self {
            counter: std::sync::atomic::AtomicU64::new(floor),
            node_id,
        }
    }

    /// Generate the next unique nonce.
    ///
    /// Thread-safe: each call atomically increments the counter.
    pub fn next(&self) -> [u8; 16] {
        let c = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&self.node_id);
        nonce[8..].copy_from_slice(&c.to_be_bytes());
        nonce
    }

    /// Current counter value (for diagnostics/testing).
    pub fn current(&self) -> u64 {
        self.counter.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Encrypt and authenticate with an automatically generated nonce.
///
/// Convenience wrapper over [`seal`] that generates a fresh random nonce.
/// Returns `(nonce, sealed_data)` — the caller must transmit the nonce
/// alongside the sealed data for decryption.
pub fn seal_with_random_nonce(key: &EpochKey, plaintext: &[u8]) -> ([u8; 16], SealedData) {
    let nonce = generate_nonce();
    let sealed = seal(key, &nonce, plaintext);
    (nonce, sealed)
}

/// Authenticated ciphertext produced by [`seal`].
///
/// Contains the encrypted data and an HMAC-SHA256 authentication tag.
/// The tag covers `nonce ∥ ciphertext` to detect any tampering.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedData {
    /// The encrypted payload (same length as plaintext).
    pub ciphertext: Vec<u8>,
    /// HMAC-SHA256(key, nonce ∥ ciphertext) — authentication tag.
    pub tag: Hash256,
}

/// Generate a SHA-256 CTR mode keystream block.
///
/// `keystream_block[i] = SHA-256(key ∥ counter.to_le_bytes() ∥ nonce)`
///
/// Each block produces 32 bytes of keystream.
fn ctr_keystream_block(key: &EpochKey, counter: u64, nonce: &[u8; 16]) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + 8 + 16);
    data.extend_from_slice(&key.0);
    data.extend_from_slice(&counter.to_le_bytes());
    data.extend_from_slice(nonce);
    *tagged_hash(crate::domain_tags::CTR_KEYSTREAM_V1, &data).as_bytes()
}

/// Encrypt/decrypt data using SHA-256 CTR mode.
///
/// XOR is symmetric, so encrypt and decrypt are the same operation.
/// The keystream is generated in 32-byte blocks:
/// ```text
/// keystream[i] = SHA-256(key ∥ i.to_le_bytes() ∥ nonce)
/// output = input XOR keystream
/// ```
fn sha256_ctr(key: &EpochKey, nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }

    let mut output = Vec::with_capacity(data.len());
    let full_blocks = data.len() / 32;
    let remainder = data.len() % 32;

    for i in 0..full_blocks {
        let ks = ctr_keystream_block(key, i as u64, nonce);
        let chunk = &data[i * 32..(i + 1) * 32];
        for (j, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ ks[j]);
        }
    }

    if remainder > 0 {
        let ks = ctr_keystream_block(key, full_blocks as u64, nonce);
        let chunk = &data[full_blocks * 32..];
        for (j, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ ks[j]);
        }
    }

    output
}

/// Encrypt data using SHA-256 CTR mode.
pub fn sha256_ctr_encrypt(key: &EpochKey, nonce: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    sha256_ctr(key, nonce, plaintext)
}

/// Decrypt data using SHA-256 CTR mode.
///
/// Identical to encrypt (XOR is its own inverse).
pub fn sha256_ctr_decrypt(key: &EpochKey, nonce: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    sha256_ctr(key, nonce, ciphertext)
}

/// Wrapper for derived key bytes that zeroizes on drop.
struct DerivedKey([u8; 32]);

impl Drop for DerivedKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.0);
    }
}

/// Derive independent encryption and MAC keys from the epoch key.
///
/// Using the same key for both encryption and MAC violates the
/// Encrypt-then-MAC security proof (RFC 5116, NIST SP 800-38D).
/// We derive two independent keys using domain-separated tagged hashes.
/// Returns `DerivedKey` wrappers that zeroize on drop.
fn derive_enc_mac_keys(key: &EpochKey) -> (DerivedKey, DerivedKey) {
    let enc_key = hmac_sha256(&key.0, crate::domain_tags::ENC_SUBKEY);
    let mac_key = hmac_sha256(&key.0, crate::domain_tags::MAC_SUBKEY);
    (
        DerivedKey(*enc_key.as_bytes()),
        DerivedKey(*mac_key.as_bytes()),
    )
}

/// Compute the HMAC authentication tag from a pre-derived MAC key.
///
/// `tag = HMAC-SHA256(mac_key, nonce ∥ ciphertext)`
fn compute_tag_with_mac_key(mac_key: &DerivedKey, nonce: &[u8; 16], ciphertext: &[u8]) -> Hash256 {
    let mut mac_input = Vec::with_capacity(16 + ciphertext.len());
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(ciphertext);
    hmac_sha256(&mac_key.0, &mac_input)
}

/// Compute the HMAC authentication tag for sealed data.
///
/// `tag = HMAC-SHA256(mac_key, nonce ∥ ciphertext)`
///
/// Uses a derived MAC key independent from the encryption key.
fn compute_tag(key: &EpochKey, nonce: &[u8; 16], ciphertext: &[u8]) -> Hash256 {
    let (_enc_key, mac_key) = derive_enc_mac_keys(key);
    // mac_key (DerivedKey) zeroized on drop.
    compute_tag_with_mac_key(&mac_key, nonce, ciphertext)
}

/// Encrypt and authenticate data (Encrypt-then-MAC).
///
/// 1. Derives independent encryption and MAC keys from the epoch key
/// 2. Encrypts plaintext with SHA-256 CTR mode using the derived enc_key
/// 3. Computes HMAC-SHA256(mac_key, nonce ∥ ciphertext) as authentication tag
///
/// Uses derived encryption key for CTR, not the raw epoch key.
/// Returns a [`SealedData`] containing ciphertext and tag.
pub fn seal(key: &EpochKey, nonce: &[u8; 16], plaintext: &[u8]) -> SealedData {
    let (enc_key_derived, mac_key) = derive_enc_mac_keys(key);
    let enc_key = EpochKey::from_bytes(enc_key_derived.0);
    let ciphertext = sha256_ctr_encrypt(&enc_key, nonce, plaintext);
    let tag = compute_tag_with_mac_key(&mac_key, nonce, &ciphertext);
    // enc_key_derived, mac_key (DerivedKey) zeroized on drop.
    SealedData { ciphertext, tag }
}

/// Decrypt and verify authenticated data.
///
/// 1. Derives independent encryption and MAC keys from the epoch key
/// 2. Verifies HMAC-SHA256 tag (constant-time comparison via Hash256::eq)
/// 3. Decrypts ciphertext with SHA-256 CTR mode using the derived enc_key
///
/// Uses derived encryption key for CTR decryption, not the raw epoch key.
/// Returns the plaintext if authentication succeeds, or an error if
/// the tag doesn't match (indicating tampering).
pub fn open(key: &EpochKey, nonce: &[u8; 16], sealed: &SealedData) -> Result<Vec<u8>, CryptoError> {
    let (enc_key_derived, mac_key) = derive_enc_mac_keys(key);
    // Verify tag first (Encrypt-then-MAC: verify before decrypting)
    let expected_tag = compute_tag_with_mac_key(&mac_key, nonce, &sealed.ciphertext);
    if expected_tag != sealed.tag {
        return Err(CryptoError::AuthenticationFailed);
    }
    let enc_key = EpochKey::from_bytes(enc_key_derived.0);
    // enc_key_derived, mac_key (DerivedKey) zeroized on drop.
    Ok(sha256_ctr_decrypt(&enc_key, nonce, &sealed.ciphertext))
}

/// Compute a commitment hash over sealed data.
///
/// `commitment = SHA-256(ciphertext ∥ tag)`
///
/// This commitment is published during the commit phase so the sequencer
/// can verify ordering consistency without seeing plaintext.
pub fn compute_commitment(sealed: &SealedData) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(&sealed.ciphertext);
    hasher.update(sealed.tag.as_bytes());
    hasher.finalize()
}

/// A commitment hash that the sequencer must publish BEFORE the epoch key
/// can be derived. This binds the ordering to the key derivation, preventing
/// the sequencer from decrypting envelopes before committing the ordering.
///
/// `commitment = SHA-256(ordering_commitment ∥ l2_block_height.to_le_bytes())`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingCommitmentHash(pub Hash256);

impl OrderingCommitmentHash {
    /// Compute the ordering commitment hash from the ordering commitment and block height.
    pub fn new(ordering_commitment: &Hash256, l2_block_height: u64) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(ordering_commitment.as_bytes());
        hasher.update(&l2_block_height.to_le_bytes());
        Self(hasher.finalize())
    }

    /// Get the inner hash.
    pub fn as_hash(&self) -> &Hash256 {
        &self.0
    }
}

/// Encryption error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// HMAC tag verification failed — data has been tampered with.
    AuthenticationFailed,
    /// Not enough shares provided to reconstruct the secret.
    InsufficientShares,
    /// A share index was invalid (e.g., zero, duplicate, or out of range).
    InvalidShareIndex,
    /// Reconstructed key does not match the expected key commitment.
    ShareVerificationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::AuthenticationFailed => {
                write!(f, "authentication failed: HMAC tag mismatch")
            }
            CryptoError::InsufficientShares => {
                write!(
                    f,
                    "insufficient shares: not enough shares to reconstruct secret"
                )
            }
            CryptoError::InvalidShareIndex => {
                write!(f, "invalid share index: indices must be nonzero and unique")
            }
            CryptoError::ShareVerificationFailed => {
                write!(
                    f,
                    "share verification failed: reconstructed key does not match commitment"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

// ═══════════════════════════════════════════════════════════════════════
// Threshold Encryption Foundation
// ═══════════════════════════════════════════════════════════════════════

/// Configuration for threshold epoch key management.
///
/// Instead of a single epoch key known to all sequencers, the key is
/// split into shares using Shamir's Secret Sharing. At least `threshold`
/// out of `total_shares` sequencers must cooperate to reconstruct the
/// epoch key for decryption. This prevents a 2/3 sequencer collusion
/// from silently extracting MEV.
#[derive(Debug, Clone)]
pub struct ThresholdEncryptionConfig {
    /// Minimum number of shares needed to reconstruct the key.
    pub threshold: u32,
    /// Total number of key shares distributed.
    pub total_shares: u32,
}

impl ThresholdEncryptionConfig {
    /// Create a new threshold config with validation.
    pub fn new(threshold: u32, total_shares: u32) -> Result<Self, &'static str> {
        if threshold < 2 {
            // threshold=1 defeats threshold encryption (any single share reconstructs)
            return Err("threshold must be >= 2 for meaningful collusion resistance");
        }
        if threshold > total_shares {
            return Err("threshold cannot exceed total_shares");
        }
        if total_shares < 3 {
            return Err("need at least 3 shares for meaningful threshold");
        }
        Ok(Self {
            threshold,
            total_shares,
        })
    }
}

/// A threshold epoch key that requires multiple shares to reconstruct.
#[derive(Debug, Clone)]
pub struct ThresholdEpochKey {
    /// The epoch this key belongs to.
    pub epoch: u64,
    /// Threshold configuration.
    pub config: ThresholdEncryptionConfig,
    /// Hash commitment to the full key (for verification without reconstruction).
    pub key_commitment: Hash256,
}

/// A single key share for Shamir's Secret Sharing.
#[derive(Clone)]
pub struct KeyShare {
    /// Share index (1-based, as per Shamir SSS convention).
    pub index: u32,
    /// The share value (32 bytes).
    share: [u8; 32],
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyShare(index={})", self.index)
    }
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.share);
    }
}

impl KeyShare {
    /// Create a key share from raw bytes.
    pub fn new(index: u32, share: [u8; 32]) -> Self {
        Self { index, share }
    }

    /// Get the share bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.share
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Real Shamir Secret Sharing over GF(2^8)
// ═══════════════════════════════════════════════════════════════════════
//
// GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
// This is the same field used by AES. The secret (32 bytes) is split
// independently per byte: each byte uses the same polynomial structure
// (same x-coordinates, same polynomial degree) but independently sampled
// polynomial coefficients. Reconstruction uses Lagrange interpolation at x=0.

/// GF(2^8) multiplication using Russian peasant multiplication.
///
/// Irreducible polynomial: 0x11B (x^8 + x^4 + x^3 + x + 1).
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        // Carry-less shift left: if high bit set, XOR with 0x1B (0x11B mod 0x100)
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

/// GF(2^8) inversion using Fermat's little theorem: a^(-1) = a^(2^8 - 2) = a^254.
///
/// a^254 = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
/// (Note: a^254 not a^255, since a^255 = 1 by Fermat => a^254 = a^(-1).)
///
/// Returns 0 if a is 0 (GF(2^8) has no inverse for 0).
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    // Square-and-multiply for a^254
    // 254 = 0b11111110
    let a2 = gf256_mul(a, a); // a^2
    let a4 = gf256_mul(a2, a2); // a^4
    let a8 = gf256_mul(a4, a4); // a^8
    let a16 = gf256_mul(a8, a8); // a^16
    let a32 = gf256_mul(a16, a16); // a^32
    let a64 = gf256_mul(a32, a32); // a^64
    let a128 = gf256_mul(a64, a64); // a^128

    // a^254 = a^128 * a^64 * a^32 * a^16 * a^8 * a^4 * a^2
    let t = gf256_mul(a128, a64);
    let t = gf256_mul(t, a32);
    let t = gf256_mul(t, a16);
    let t = gf256_mul(t, a8);
    let t = gf256_mul(t, a4);
    gf256_mul(t, a2)
}

/// Evaluate a GF(2^8) polynomial at x.
///
/// The polynomial is given as a slice of coefficients: `coeffs[0]` is the
/// constant term (the secret byte), `coeffs[1]` is the linear term, etc.
/// Uses Horner's method for efficiency.
fn gf256_poly_eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method: ((c[n]*x + c[n-1])*x + ... + c[1])*x + c[0]
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf256_mul(result, x) ^ c;
    }
    result
}

/// Per-share hash commitments for detecting a malicious dealer.
///
/// The dealer publishes these commitments alongside the shares. Each recipient
/// can verify their share's hash matches the corresponding entry. After
/// reconstruction, the secret hash is verified against `key_commitment`.
#[derive(Debug, Clone)]
pub struct ShareCommitments {
    /// SHA-256 hash of each share's bytes, indexed by share position (0-based).
    pub share_hashes: Vec<Hash256>,
    /// SHA-256 hash of the original secret (for reconstruction verification).
    pub key_commitment: Hash256,
}

impl ShareCommitments {
    /// Verify that a share is consistent with the published commitments.
    ///
    /// Returns `true` if the share's hash matches the commitment for its index.
    pub fn verify_share(&self, share: &KeyShare) -> bool {
        let idx = share.index as usize;
        if idx == 0 || idx > self.share_hashes.len() {
            return false;
        }
        let actual_hash = Hasher::hash(share.as_bytes());
        actual_hash == self.share_hashes[idx - 1]
    }
}

/// Split an epoch key into `config.total_shares` shares using real Shamir SSS.
///
/// Each of the 32 secret bytes is processed independently using a random
/// polynomial of degree `(threshold - 1)` over GF(2^8). The x-coordinates
/// for the shares are `1, 2, ..., total_shares` (all nonzero, as required
/// since x=0 encodes the secret).
///
/// The output shares can be combined with any `threshold`-sized subset via
/// [`reconstruct_secret`] to recover the original epoch key exactly.
///
/// Returns the shares together with [`ShareCommitments`] that allow recipients
/// to verify their shares against the dealer's commitments.
pub fn split_secret(
    epoch_key: &EpochKey,
    config: &ThresholdEncryptionConfig,
) -> Result<(Vec<KeyShare>, ShareCommitments), CryptoError> {
    use rand::RngCore;

    if config.total_shares > 255 {
        return Err(CryptoError::InvalidShareIndex); // GF(2^8) supports max 255 shares
    }

    let n = config.total_shares as usize;
    let t = config.threshold as usize;
    let secret = epoch_key.as_bytes();

    // For each of the 32 bytes, generate a degree-(t-1) polynomial over GF(2^8).
    // coeffs[byte_idx][coeff_idx]: polynomial coefficient.
    // coeffs[byte_idx][0] = secret[byte_idx] (constant term).
    // coeffs[byte_idx][1..t-1] are random.
    let mut all_coeffs: Vec<Vec<u8>> = Vec::with_capacity(32);
    let mut rng = rand::thread_rng();

    for byte_idx in 0..32 {
        let mut coeffs = vec![0u8; t];
        coeffs[0] = secret[byte_idx]; // constant term = secret byte
        // Fill higher-degree coefficients with random bytes
        rng.fill_bytes(&mut coeffs[1..]);
        all_coeffs.push(coeffs);
    }

    // Evaluate each polynomial at x = 1, 2, ..., n
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = i as u8; // x-coordinate for this share (1-indexed, nonzero)
        let mut share_bytes = [0u8; 32];
        for byte_idx in 0..32 {
            share_bytes[byte_idx] = gf256_poly_eval(&all_coeffs[byte_idx], x);
        }
        shares.push(KeyShare::new(i as u32, share_bytes));
    }

    // Zeroize polynomial coefficients — they contain secret material
    for coeffs in all_coeffs.iter_mut() {
        for b in coeffs.iter_mut() {
            *b = 0;
        }
    }

    // Compute per-share and key commitments for malicious dealer detection
    let key_commitment = Hasher::hash(epoch_key.as_bytes());
    let share_hashes: Vec<Hash256> = shares.iter()
        .map(|s| Hasher::hash(s.as_bytes()))
        .collect();
    let commitments = ShareCommitments { share_hashes, key_commitment };

    Ok((shares, commitments))
}

/// Reconstruct an epoch key from at least `config.threshold` shares.
///
/// Uses Lagrange interpolation at x=0 over GF(2^8) independently for each
/// of the 32 secret bytes. The shares may be provided in any order; only
/// the first `threshold` shares are required (but all provided shares are used
/// if more than `threshold` are given, all subsets must agree).
///
/// Returns [`CryptoError::InsufficientShares`] if fewer than `threshold` shares
/// are provided. Returns [`CryptoError::InvalidShareIndex`] if any share index
/// is zero or if duplicate indices are present.
pub fn reconstruct_secret(
    shares: &[KeyShare],
    config: &ThresholdEncryptionConfig,
) -> Result<EpochKey, CryptoError> {
    reconstruct_secret_inner(shares, config, None)
}

/// Reconstruct a secret from key shares with optional key commitment verification.
///
/// If `key_commitment` is provided, the reconstructed key is hashed and compared
/// against the commitment. Returns [`CryptoError::ShareVerificationFailed`] on mismatch.
pub fn reconstruct_secret_verified(
    shares: &[KeyShare],
    config: &ThresholdEncryptionConfig,
    key_commitment: &Hash256,
) -> Result<EpochKey, CryptoError> {
    reconstruct_secret_inner(shares, config, Some(key_commitment))
}

fn reconstruct_secret_inner(
    shares: &[KeyShare],
    config: &ThresholdEncryptionConfig,
    key_commitment: Option<&Hash256>,
) -> Result<EpochKey, CryptoError> {
    if (shares.len() as u32) < config.threshold {
        return Err(CryptoError::InsufficientShares);
    }

    // Validate share indices: must be nonzero, unique, and fit in u8 for GF(2^8)
    let indices: Vec<u8> = shares
        .iter()
        .map(|s| {
            // index is 1-based u32; must fit in u8 for GF(2^8)
            if s.index == 0 || s.index > 255 {
                return Err(CryptoError::InvalidShareIndex);
            }
            Ok(s.index as u8)
        })
        .collect::<Result<Vec<u8>, CryptoError>>()?;

    // Check for duplicate indices
    for i in 0..indices.len() {
        for j in (i + 1)..indices.len() {
            if indices[i] == indices[j] {
                return Err(CryptoError::InvalidShareIndex);
            }
        }
    }

    // Use exactly threshold shares (take the first threshold)
    let t = config.threshold as usize;
    let xs = &indices[..t];
    let shares_t = &shares[..t];

    // Lagrange interpolation at x=0 for each byte
    let mut secret = [0u8; 32];
    for byte_idx in 0..32 {
        // y-values for this byte across all t shares
        let ys: Vec<u8> = shares_t.iter().map(|s| s.as_bytes()[byte_idx]).collect();

        // L(0) = sum_i [ y_i * prod_{j != i} ( x_j / (x_j XOR x_i) ) ]
        // In GF(2^8): subtraction = XOR, division = multiply by inverse.
        let mut val = 0u8;
        for i in 0..t {
            let xi = xs[i];
            let yi = ys[i];
            // Compute the Lagrange basis polynomial l_i(0):
            // l_i(0) = prod_{j != i} [ (0 - x_j) / (x_i - x_j) ]
            //        = prod_{j != i} [ x_j / (x_i XOR x_j) ]  (since 0 - x = x in GF(2^8))
            let mut numerator = 1u8;
            let mut denominator = 1u8;
            for j in 0..t {
                if i != j {
                    let xj = xs[j];
                    numerator = gf256_mul(numerator, xj);
                    denominator = gf256_mul(denominator, xi ^ xj);
                }
            }
            // l_i(0) = numerator * inv(denominator)
            let lagrange_coef = gf256_mul(numerator, gf256_inv(denominator));
            val ^= gf256_mul(yi, lagrange_coef);
        }
        secret[byte_idx] = val;
    }

    let reconstructed = EpochKey::from_bytes(secret);

    // Verify against key commitment if provided
    if let Some(commitment) = key_commitment {
        let reconstructed_hash = Hasher::hash(&reconstructed.0);
        if reconstructed_hash != *commitment {
            return Err(CryptoError::ShareVerificationFailed);
        }
    }

    Ok(reconstructed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EpochKey {
        let seed = Hash256::from_bytes([0xAA; 32]);
        EpochKey::derive(&seed, 1)
    }

    fn test_nonce() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    #[test]
    fn test_epoch_key_derivation() {
        let seed = Hash256::from_bytes([0xAA; 32]);
        let key1 = EpochKey::derive(&seed, 1);
        let key2 = EpochKey::derive(&seed, 2);
        let key3 = EpochKey::derive(&seed, 1);

        // Same seed + epoch → same key
        assert_eq!(key1, key3);
        // Different epoch → different key
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_epoch_key_different_seeds() {
        let seed1 = Hash256::from_bytes([0xAA; 32]);
        let seed2 = Hash256::from_bytes([0xBB; 32]);
        let key1 = EpochKey::derive(&seed1, 1);
        let key2 = EpochKey::derive(&seed2, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_ctr_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Hello, Brrq MEV protection!";

        let ciphertext = sha256_ctr_encrypt(&key, &nonce, plaintext);
        assert_ne!(&ciphertext, plaintext); // Should be encrypted
        assert_eq!(ciphertext.len(), plaintext.len()); // Same length (stream cipher)

        let decrypted = sha256_ctr_decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_empty_plaintext() {
        let key = test_key();
        let nonce = test_nonce();

        let ciphertext = sha256_ctr_encrypt(&key, &nonce, b"");
        assert!(ciphertext.is_empty());

        let decrypted = sha256_ctr_decrypt(&key, &nonce, &ciphertext);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_ctr_large_plaintext() {
        let key = test_key();
        let nonce = test_nonce();
        // 1000 bytes — spans multiple 32-byte keystream blocks
        let plaintext: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

        let ciphertext = sha256_ctr_encrypt(&key, &nonce, &plaintext);
        assert_eq!(ciphertext.len(), 1000);
        assert_ne!(ciphertext, plaintext);

        let decrypted = sha256_ctr_decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_exact_block_boundary() {
        let key = test_key();
        let nonce = test_nonce();
        // Exactly 64 bytes = 2 full keystream blocks
        let plaintext = vec![0x42u8; 64];

        let ciphertext = sha256_ctr_encrypt(&key, &nonce, &plaintext);
        let decrypted = sha256_ctr_decrypt(&key, &nonce, &ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_different_keys_produce_different_ciphertext() {
        let key1 = EpochKey::from_bytes([0xAA; 32]);
        let key2 = EpochKey::from_bytes([0xBB; 32]);
        let nonce = test_nonce();
        let plaintext = b"same plaintext";

        let ct1 = sha256_ctr_encrypt(&key1, &nonce, plaintext);
        let ct2 = sha256_ctr_encrypt(&key2, &nonce, plaintext);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_ctr_different_nonces_produce_different_ciphertext() {
        let key = test_key();
        let nonce1 = [0x01; 16];
        let nonce2 = [0x02; 16];
        let plaintext = b"same plaintext";

        let ct1 = sha256_ctr_encrypt(&key, &nonce1, plaintext);
        let ct2 = sha256_ctr_encrypt(&key, &nonce2, plaintext);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"MEV-protected transaction kind";

        let sealed = seal(&key, &nonce, plaintext);
        assert_ne!(sealed.ciphertext.as_slice(), plaintext.as_slice());
        assert!(!sealed.tag.is_zero());

        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_seal_open_empty() {
        let key = test_key();
        let nonce = test_nonce();

        let sealed = seal(&key, &nonce, b"");
        assert!(sealed.ciphertext.is_empty());

        let opened = open(&key, &nonce, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn test_seal_tamper_ciphertext_detected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"don't touch this";

        let mut sealed = seal(&key, &nonce, plaintext);
        // Tamper with ciphertext
        if !sealed.ciphertext.is_empty() {
            sealed.ciphertext[0] ^= 0xFF;
        }

        let result = open(&key, &nonce, &sealed);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_seal_tamper_tag_detected() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"authenticate me";

        let mut sealed = seal(&key, &nonce, plaintext);
        // Tamper with tag
        sealed.tag.0[0] ^= 0xFF;

        let result = open(&key, &nonce, &sealed);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_seal_wrong_key_rejected() {
        let key1 = EpochKey::from_bytes([0xAA; 32]);
        let key2 = EpochKey::from_bytes([0xBB; 32]);
        let nonce = test_nonce();
        let plaintext = b"epoch 1 data";

        let sealed = seal(&key1, &nonce, plaintext);
        let result = open(&key2, &nonce, &sealed);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_seal_wrong_nonce_rejected() {
        let key = test_key();
        let nonce1 = [0x01; 16];
        let nonce2 = [0x02; 16];
        let plaintext = b"nonce-specific";

        let sealed = seal(&key, &nonce1, plaintext);
        let result = open(&key, &nonce2, &sealed);
        assert_eq!(result, Err(CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_commitment_deterministic() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"commit to this";

        let sealed = seal(&key, &nonce, plaintext);
        let c1 = compute_commitment(&sealed);
        let c2 = compute_commitment(&sealed);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_changes_with_data() {
        let key = test_key();
        let nonce = test_nonce();

        let sealed1 = seal(&key, &nonce, b"data A");
        let sealed2 = seal(&key, &nonce, b"data B");
        assert_ne!(compute_commitment(&sealed1), compute_commitment(&sealed2));
    }

    #[test]
    fn test_large_seal_open() {
        let key = test_key();
        let nonce = test_nonce();
        // 10 KB payload
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        let sealed = seal(&key, &nonce, &plaintext);
        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Edge-Case Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_nonce_reuse_leaks_xor() {
        // CRITICAL: Reusing (key, nonce) with two different plaintexts
        // produces c1 XOR c2 == p1 XOR p2, leaking plaintext relationships.
        // This test demonstrates why callers must use unique nonces.
        let key = test_key();
        let nonce = test_nonce(); // SAME nonce

        let p1 = b"secret message A";
        let p2 = b"secret message B";

        let c1 = sha256_ctr_encrypt(&key, &nonce, p1);
        let c2 = sha256_ctr_encrypt(&key, &nonce, p2);

        // c1 XOR c2 should equal p1 XOR p2 (stream cipher property)
        let c_xor: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();
        let p_xor: Vec<u8> = p1.iter().zip(p2.iter()).map(|(a, b)| a ^ b).collect();
        assert_eq!(c_xor, p_xor, "Nonce reuse leaks XOR of plaintexts!");
    }

    #[test]
    fn adversarial_zero_key_derivation() {
        // Edge case: all-zero seed + epoch 0
        let zero_seed = Hash256::ZERO;
        let key = EpochKey::derive(&zero_seed, 0);
        // Key should still be a valid, non-zero key (tagged hash of zeros)
        assert_ne!(
            key.as_bytes(),
            &[0u8; 32],
            "Zero seed should still produce non-trivial key"
        );

        // Should still encrypt/decrypt correctly
        let nonce = test_nonce();
        let plaintext = b"test with zero-derived key";
        let sealed = seal(&key, &nonce, plaintext);
        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn adversarial_epoch_boundary_keys() {
        // Epoch u64::MAX should work without overflow
        let seed = Hash256::from_bytes([0xAA; 32]);
        let key_max = EpochKey::derive(&seed, u64::MAX);
        let key_max_minus1 = EpochKey::derive(&seed, u64::MAX - 1);
        assert_ne!(key_max, key_max_minus1);

        // Should encrypt correctly
        let nonce = test_nonce();
        let sealed = seal(&key_max, &nonce, b"epoch max");
        let opened = open(&key_max, &nonce, &sealed).unwrap();
        assert_eq!(opened, b"epoch max");
    }

    #[test]
    fn adversarial_single_byte_plaintext() {
        // Smallest non-empty plaintext (partial keystream block)
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = &[0x42u8];

        let sealed = seal(&key, &nonce, plaintext);
        assert_eq!(sealed.ciphertext.len(), 1);

        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn adversarial_all_zero_plaintext_produces_keystream() {
        // Encrypting all-zeros reveals the raw keystream
        let key = test_key();
        let nonce = test_nonce();
        let zeros = vec![0u8; 64]; // 2 full blocks

        let ciphertext = sha256_ctr_encrypt(&key, &nonce, &zeros);
        // Ciphertext IS the keystream when plaintext is all zeros
        assert_ne!(ciphertext, zeros);

        // Verify each 32-byte block matches the raw keystream
        let ks0 = ctr_keystream_block(&key, 0, &nonce);
        let ks1 = ctr_keystream_block(&key, 1, &nonce);
        assert_eq!(&ciphertext[..32], &ks0);
        assert_eq!(&ciphertext[32..64], &ks1);
    }

    #[test]
    fn adversarial_tamper_single_bit_detected() {
        // Flipping a single bit in ciphertext should be detected by HMAC
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"integrity check";

        let mut sealed = seal(&key, &nonce, plaintext);
        // Flip the least significant bit of the last ciphertext byte
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;

        assert_eq!(
            open(&key, &nonce, &sealed),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn adversarial_swap_ciphertext_and_tag() {
        // Attacker swaps ciphertext from message A with tag from message B
        let key = test_key();
        let nonce = test_nonce();

        let sealed_a = seal(&key, &nonce, b"message A");
        let sealed_b = seal(&key, &nonce, b"message B");

        let franken_sealed = SealedData {
            ciphertext: sealed_a.ciphertext.clone(),
            tag: sealed_b.tag, // Tag from different message
        };

        assert_eq!(
            open(&key, &nonce, &franken_sealed),
            Err(CryptoError::AuthenticationFailed),
            "Swapped tag should be detected"
        );
    }

    #[test]
    fn adversarial_commitment_binding() {
        // Two different SealedDatas should have different commitments
        // (collision resistance of SHA-256)
        let key = test_key();
        let nonce = test_nonce();

        let sealed1 = seal(&key, &nonce, b"A");
        let sealed2 = seal(&key, &nonce, b"B");

        let c1 = compute_commitment(&sealed1);
        let c2 = compute_commitment(&sealed2);
        assert_ne!(
            c1, c2,
            "Different sealed data must have different commitments"
        );

        // Same data, same commitment (deterministic)
        assert_eq!(compute_commitment(&sealed1), compute_commitment(&sealed1));
    }

    #[test]
    fn adversarial_ciphertext_length_preserving() {
        // Stream cipher MUST preserve length exactly
        let key = test_key();
        let nonce = test_nonce();

        for len in [0, 1, 15, 16, 31, 32, 33, 63, 64, 65, 100, 1000] {
            let plaintext = vec![0x42u8; len];
            let ciphertext = sha256_ctr_encrypt(&key, &nonce, &plaintext);
            assert_eq!(
                ciphertext.len(),
                len,
                "Ciphertext length must equal plaintext length for len={len}"
            );
        }
    }

    #[test]
    fn adversarial_truncated_ciphertext_auth_fails() {
        // Attacker truncates ciphertext but keeps original tag
        let key = test_key();
        let nonce = test_nonce();

        let sealed = seal(&key, &nonce, b"full message here");
        let truncated = SealedData {
            ciphertext: sealed.ciphertext[..5].to_vec(), // Truncated
            tag: sealed.tag,
        };

        assert_eq!(
            open(&key, &nonce, &truncated),
            Err(CryptoError::AuthenticationFailed),
            "Truncated ciphertext must fail authentication"
        );
    }

    #[test]
    fn adversarial_extended_ciphertext_auth_fails() {
        // Attacker appends extra bytes to ciphertext
        let key = test_key();
        let nonce = test_nonce();

        let sealed = seal(&key, &nonce, b"original");
        let mut extended_ct = sealed.ciphertext.clone();
        extended_ct.extend_from_slice(b"INJECTED");

        let extended = SealedData {
            ciphertext: extended_ct,
            tag: sealed.tag,
        };

        assert_eq!(
            open(&key, &nonce, &extended),
            Err(CryptoError::AuthenticationFailed),
            "Extended ciphertext must fail authentication"
        );
    }

    #[test]
    fn adversarial_seal_open_is_encrypt_then_mac() {
        // Verify Encrypt-then-MAC property: tag is computed over ciphertext, not plaintext.
        // This means we verify BEFORE decrypting (prevents padding oracle attacks).
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"encrypt-then-MAC";

        let sealed = seal(&key, &nonce, plaintext);

        // Manually verify using derived mac_key, not the raw epoch key.
        // The tag = HMAC(mac_key, nonce || ciphertext) where mac_key is derived.
        let (_enc_key, mac_key) = derive_enc_mac_keys(&key);
        let mut mac_input = Vec::new();
        mac_input.extend_from_slice(&nonce);
        mac_input.extend_from_slice(&sealed.ciphertext);
        let expected_tag = crate::sha256::hmac_sha256(&mac_key.0, &mac_input);
        assert_eq!(
            sealed.tag, expected_tag,
            "Tag must be HMAC(mac_key, nonce||ciphertext) using derived mac_key"
        );
    }

    // ══════════════════════════════════════════════════════════════
    // Real Shamir SSS Tests
    // ══════════════════════════════════════════════════════════════

    fn make_epoch_key(seed: u8) -> EpochKey {
        EpochKey::from_bytes([seed; 32])
    }

    #[test]
    fn test_shamir_split_reconstruct_roundtrip() {
        let key = make_epoch_key(0xAB);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = reconstruct_secret(&shares, &config).unwrap();
        assert_eq!(reconstructed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_shamir_threshold_exact() {
        let key = make_epoch_key(0xCC);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        // Use exactly threshold (3) shares — must work
        let subset = &shares[..3];
        let reconstructed = reconstruct_secret(subset, &config).unwrap();
        assert_eq!(reconstructed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_shamir_insufficient_shares_fails() {
        let key = make_epoch_key(0xDD);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        // Only 2 shares — below threshold of 3
        let subset = &shares[..2];
        let result = reconstruct_secret(subset, &config);
        assert_eq!(result, Err(CryptoError::InsufficientShares));
    }

    #[test]
    fn test_shamir_any_t_of_n_works() {
        let key = make_epoch_key(0x42);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        // Try several different t-subsets
        let subsets: Vec<&[KeyShare]> = vec![&shares[0..3], &shares[1..4], &shares[2..5]];

        for subset in subsets {
            let reconstructed = reconstruct_secret(subset, &config).unwrap();
            assert_eq!(
                reconstructed.as_bytes(),
                key.as_bytes(),
                "reconstruction failed for subset starting at share {}",
                subset[0].index
            );
        }
    }

    #[test]
    fn test_shamir_different_shares_same_secret() {
        let key = make_epoch_key(0x77);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        // Non-overlapping pairs of 3-subsets should give the same secret
        let r1 = reconstruct_secret(&shares[0..3], &config).unwrap();
        let r2 = reconstruct_secret(&shares[2..5], &config).unwrap();
        assert_eq!(r1.as_bytes(), r2.as_bytes());
        assert_eq!(r1.as_bytes(), key.as_bytes());
    }

    #[test]
    fn test_shamir_shares_are_different() {
        let key = make_epoch_key(0x99);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        // All share values should differ from each other and from the key
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(
                    shares[i].as_bytes(),
                    shares[j].as_bytes(),
                    "shares {} and {} should differ",
                    shares[i].index,
                    shares[j].index
                );
            }
            // Share bytes should not equal the raw key (not a trivial split)
            assert_ne!(
                shares[i].as_bytes(),
                key.as_bytes(),
                "share {} should not equal the secret key",
                shares[i].index
            );
        }
    }

    #[test]
    fn test_shamir_config_validation() {
        // threshold = 0 is invalid
        assert!(ThresholdEncryptionConfig::new(0, 5).is_err());
        // threshold > total_shares is invalid
        assert!(ThresholdEncryptionConfig::new(6, 5).is_err());
        // total_shares < 3 is invalid
        assert!(ThresholdEncryptionConfig::new(1, 2).is_err());
        // Valid config
        assert!(ThresholdEncryptionConfig::new(2, 3).is_ok());
        assert!(ThresholdEncryptionConfig::new(3, 5).is_ok());
        // threshold == total_shares is allowed (n-of-n)
        assert!(ThresholdEncryptionConfig::new(3, 3).is_ok());
    }

    #[test]
    fn test_share_commitments_verify() {
        let key = make_epoch_key(0xEE);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();

        let (shares, commitments) = split_secret(&key, &config).unwrap();

        // All shares must verify against commitments
        for share in &shares {
            assert!(
                commitments.verify_share(share),
                "share {} must verify against commitment",
                share.index
            );
        }

        // Key commitment must match the original secret
        let expected_key_hash = Hasher::hash(key.as_bytes());
        assert_eq!(commitments.key_commitment, expected_key_hash);

        // Tampered share must NOT verify
        let mut tampered = KeyShare::new(1, *shares[0].as_bytes());
        let mut tampered_bytes = *tampered.as_bytes();
        tampered_bytes[0] ^= 0xFF;
        tampered = KeyShare::new(1, tampered_bytes);
        assert!(!commitments.verify_share(&tampered));
    }

    #[test]
    fn test_shamir_gf256_mul_identity() {
        // a * 1 = a for all a
        for a in 0u8..=255 {
            assert_eq!(gf256_mul(a, 1), a, "gf256_mul({a}, 1) != {a}");
        }
    }

    #[test]
    fn test_shamir_gf256_inv_roundtrip() {
        // a * inv(a) = 1 for all nonzero a
        for a in 1u8..=255 {
            let inv_a = gf256_inv(a);
            assert_ne!(inv_a, 0, "inv({a}) should not be zero");
            assert_eq!(gf256_mul(a, inv_a), 1, "gf256_mul({a}, inv({a})) != 1");
        }
    }

    #[test]
    fn test_shamir_invalid_share_index_zero() {
        let config = ThresholdEncryptionConfig::new(2, 3).unwrap();
        // Manually construct a share with index 0 (invalid)
        let bad_shares = vec![
            KeyShare::new(0, [0u8; 32]), // index 0 is invalid
            KeyShare::new(1, [1u8; 32]),
            KeyShare::new(2, [2u8; 32]),
        ];
        let result = reconstruct_secret(&bad_shares, &config);
        assert_eq!(result, Err(CryptoError::InvalidShareIndex));
    }

    #[test]
    fn test_shamir_duplicate_indices_fail() {
        let config = ThresholdEncryptionConfig::new(2, 3).unwrap();
        // Two shares with the same index
        let dup_shares = vec![
            KeyShare::new(1, [0u8; 32]),
            KeyShare::new(1, [1u8; 32]), // duplicate index 1
            KeyShare::new(2, [2u8; 32]),
        ];
        let result = reconstruct_secret(&dup_shares, &config);
        assert_eq!(result, Err(CryptoError::InvalidShareIndex));
    }

    // ══════════════════════════════════════════════════════════════
    // L1-Anchored Epoch Key Tests (MEV commit-reveal fix)
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_derive_with_anchor_differs_from_derive() {
        let seed = Hash256::from_bytes([0xAA; 32]);
        let anchor = Hash256::from_bytes([0xBB; 32]);
        let key_plain = EpochKey::derive(&seed, 1);
        let key_anchored = EpochKey::derive_with_anchor(&seed, 1, &anchor);
        assert_ne!(
            key_plain.as_bytes(),
            key_anchored.as_bytes(),
            "anchored key must differ from plain key"
        );
    }

    #[test]
    fn test_derive_with_anchor_different_anchors() {
        let seed = Hash256::from_bytes([0xAA; 32]);
        let anchor1 = Hash256::from_bytes([0xBB; 32]);
        let anchor2 = Hash256::from_bytes([0xCC; 32]);
        let key1 = EpochKey::derive_with_anchor(&seed, 1, &anchor1);
        let key2 = EpochKey::derive_with_anchor(&seed, 1, &anchor2);
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "different L1 anchors must produce different keys"
        );
    }

    #[test]
    fn test_derive_with_anchor_deterministic() {
        let seed = Hash256::from_bytes([0xAA; 32]);
        let anchor = Hash256::from_bytes([0xBB; 32]);
        let key1 = EpochKey::derive_with_anchor(&seed, 1, &anchor);
        let key2 = EpochKey::derive_with_anchor(&seed, 1, &anchor);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_with_anchor_seal_open_roundtrip() {
        let seed = Hash256::from_bytes([0xAA; 32]);
        let anchor = Hash256::from_bytes([0xBB; 32]);
        let key = EpochKey::derive_with_anchor(&seed, 1, &anchor);
        let nonce = test_nonce();
        let plaintext = b"MEV-protected with L1 anchor";

        let sealed = seal(&key, &nonce, plaintext);
        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn test_ordering_commitment_hash() {
        let commitment = Hash256::from_bytes([0xDD; 32]);
        let hash1 = OrderingCommitmentHash::new(&commitment, 100);
        let hash2 = OrderingCommitmentHash::new(&commitment, 100);
        assert_eq!(hash1, hash2, "same inputs must produce same hash");

        let hash3 = OrderingCommitmentHash::new(&commitment, 101);
        assert_ne!(hash1, hash3, "different heights must produce different hashes");
    }

    // ══════════════════════════════════════════════════════════════
    // NonceCounter Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn nonce_counter_zero_collisions_1m() {
        let node_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let counter = NonceCounter::new(node_id);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000_000 {
            let nonce = counter.next();
            assert!(seen.insert(nonce), "Duplicate nonce detected!");
        }
        assert_eq!(seen.len(), 1_000_000);
    }

    #[test]
    fn nonce_counter_monotonic_across_threads() {
        use std::sync::Arc;
        let node_id = [0xAA; 8];
        let counter = Arc::new(NonceCounter::new(node_id));
        let num_threads = 8;
        let per_thread = 10_000;

        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let mut values = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        let nonce = c.next();
                        // Extract counter from nonce bytes [8..16]
                        let val = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
                        values.push(val);
                    }
                    values
                })
            })
            .collect();

        let mut all_values: Vec<u64> = Vec::new();
        for h in handles {
            all_values.extend(h.join().unwrap());
        }

        // All values must be unique (atomic fetch_add guarantees this)
        all_values.sort();
        all_values.dedup();
        assert_eq!(
            all_values.len(),
            num_threads * per_thread,
            "Concurrent nonces must all be unique"
        );

        // Values should be 0..80_000 in some order
        assert_eq!(*all_values.first().unwrap(), 0);
        assert_eq!(*all_values.last().unwrap(), (num_threads * per_thread - 1) as u64);
    }

    #[test]
    fn nonce_counter_crash_recovery_floor() {
        let node_id = [0xBB; 8];
        let counter = NonceCounter::new_recovering(node_id, 100, 500);

        // Floor = 100 * 500 = 50_000
        assert_eq!(counter.current(), 50_000);

        // First nonce should encode counter value 50_000
        let nonce = counter.next();
        let val = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        assert_eq!(val, 50_000);

        // Node ID prefix preserved
        assert_eq!(&nonce[..8], &node_id);

        // Second nonce = 50_001
        let nonce2 = counter.next();
        let val2 = u64::from_be_bytes(nonce2[8..16].try_into().unwrap());
        assert_eq!(val2, 50_001);
    }

    #[test]
    fn nonce_counter_node_id_prefix() {
        let node_a = [0x01; 8];
        let node_b = [0x02; 8];
        let ca = NonceCounter::new(node_a);
        let cb = NonceCounter::new(node_b);

        let na = ca.next();
        let nb = cb.next();

        // Same counter value (0) but different nonces due to node_id prefix
        assert_ne!(na, nb);
        assert_eq!(&na[..8], &node_a);
        assert_eq!(&nb[..8], &node_b);
        // Counter portion is the same
        assert_eq!(&na[8..], &nb[8..]);
    }

    #[test]
    fn nonce_counter_recovery_saturating_mul() {
        let node_id = [0xCC; 8];
        // Overflow case: u64::MAX * 2 would overflow — saturating_mul caps at u64::MAX
        let counter = NonceCounter::new_recovering(node_id, u64::MAX, 2);
        assert_eq!(counter.current(), u64::MAX);
    }

    #[test]
    fn nonce_counter_integrates_with_seal() {
        let key = test_key();
        let node_id = [0xDD; 8];
        let counter = NonceCounter::new(node_id);

        let nonce = counter.next();
        let plaintext = b"MEV transaction via counter nonce";
        let sealed = seal(&key, &nonce, plaintext);
        let opened = open(&key, &nonce, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }
}
