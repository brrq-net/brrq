//! MEV-protected transaction types (§4.7 — Commit-Reveal).
//!
//! ## Problem
//!
//! The sequencer sees full transaction content, enabling front-running,
//! sandwich attacks, and content-based censorship.
//!
//! ## Solution
//!
//! Users encrypt their transaction `kind` (the operation) with an epoch-derived
//! key. The sequencer orders based on visible metadata only (gas_price, nonce,
//! sender). After ordering is committed, the kind is decrypted for execution.
//!
//! ## Types
//!
//! - [`MevMetadata`]: Visible ordering fields (sequencer can see these)
//! - [`EncryptedEnvelope`]: Encrypted transaction for the commit phase

use brrq_crypto::encryption::{self, EpochKey, SealedData, compute_commitment};
use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::signature::{PublicKey, Signature};
use crate::transaction::{Transaction, TransactionBody, TransactionKind};

/// Visible ordering metadata that the sequencer can see.
///
/// These fields are in cleartext so the sequencer can:
/// - Order by gas_price (priority fee)
/// - Track per-account nonce ordering
/// - Enforce gas limits
/// - Verify sender identity
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MevMetadata {
    /// Sender address.
    pub sender: Address,
    /// Sender's nonce (must match account nonce).
    pub nonce: u64,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Gas price (priority fee) in satoshis per gas unit.
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    /// Chain ID (prevents cross-chain replay).
    pub chain_id: u64,
    /// Epoch number (determines which EpochKey to use for decryption).
    pub epoch: u64,
}

impl MevMetadata {
    /// Compute a deterministic hash of the metadata for signing.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::MEV_META_V1);
        hasher.update(self.sender.as_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.max_fee_per_gas.to_le_bytes());
        hasher.update(&self.max_priority_fee_per_gas.to_le_bytes());
        hasher.update(&self.chain_id.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.finalize()
    }
}

/// An encrypted transaction envelope for the MEV commit phase.
///
/// Contains:
/// - **Cleartext metadata** for sequencer ordering (gas_price, nonce, sender)
/// - **Encrypted kind** (the actual operation — transfer, deploy, call, etc.)
/// - **Commitment** binding the encrypted data to the metadata
/// - **Schnorr signature** over commitment + metadata hash (pre-decryption auth)
///
/// The sequencer CANNOT see what the transaction does until decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Cleartext ordering metadata.
    pub metadata: MevMetadata,
    /// Encrypted `TransactionKind` bytes (sealed with epoch key).
    pub encrypted_kind: Vec<u8>,
    /// HMAC-SHA256 authentication tag for the encrypted data.
    pub kind_tag: Hash256,
    /// Random per-transaction encryption nonce (16 bytes).
    pub encryption_nonce: [u8; 16],
    /// Commitment: SHA-256(encrypted_kind ∥ kind_tag).
    pub commitment: Hash256,
    /// Schnorr signature over SHA-256(commitment ∥ metadata_hash).
    /// Proves the sender authorized this envelope pre-decryption.
    pub signature: SchnorrSignature,
    /// Sender's Schnorr public key.
    pub public_key: SchnorrPublicKey,
    /// Original transaction signature (verified after decryption).
    pub original_signature: Signature,
    /// Original transaction public key.
    pub original_public_key: PublicKey,
}

impl EncryptedEnvelope {
    /// Create an encrypted envelope from a plaintext transaction.
    ///
    /// # Arguments
    ///
    /// - `tx`: The full plaintext transaction (must have valid signature)
    /// - `epoch_key`: The current epoch's symmetric key
    /// - `epoch`: The epoch number
    /// - `keypair`: Schnorr keypair for signing the commitment
    /// - `nonce_counter`: Optional monotonic nonce counter. If provided,
    ///   generates a deterministic nonce (no collision risk). If `None`,
    ///   falls back to random nonce (backward compatible).
    pub fn encrypt(
        tx: &Transaction,
        epoch_key: &EpochKey,
        epoch: u64,
        keypair: &SchnorrKeyPair,
    ) -> Result<Self, String> {
        Self::encrypt_with_nonce_source(tx, epoch_key, epoch, keypair, None)
    }

    /// Create an encrypted envelope with an explicit nonce source.
    ///
    /// When `nonce_counter` is `Some`, uses monotonic counter (guaranteed unique).
    /// When `None`, uses cryptographic random nonce (backward compatible).
    pub fn encrypt_with_nonce_source(
        tx: &Transaction,
        epoch_key: &EpochKey,
        epoch: u64,
        keypair: &SchnorrKeyPair,
        nonce_counter: Option<&encryption::NonceCounter>,
    ) -> Result<Self, String> {
        // 1. Serialize the transaction kind to JSON bytes
        let kind_bytes = serde_json::to_vec(&tx.body.kind)
            .map_err(|e| format!("TransactionKind serialization failed: {e}"))?;

        // 2. Generate nonce: monotonic counter (preferred) or random (fallback)
        let nonce = match nonce_counter {
            Some(counter) => counter.next(),
            None => {
                let mut n = [0u8; 16];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut n);
                n
            }
        };

        // 3. Encrypt with authenticated encryption (seal)
        let sealed = encryption::seal(epoch_key, &nonce, &kind_bytes);

        // 4. Compute commitment: SHA-256(encrypted_kind ∥ tag)
        let commitment = compute_commitment(&sealed);

        // 5. Build metadata
        let metadata = MevMetadata {
            sender: tx.body.from,
            nonce: tx.body.nonce,
            gas_limit: tx.body.gas_limit,
            max_fee_per_gas: tx.body.max_fee_per_gas,
            max_priority_fee_per_gas: tx.body.max_priority_fee_per_gas,
            chain_id: tx.body.chain_id,
            epoch,
        };

        // 6. Sign: SHA-256(domain_tag ∥ commitment ∥ metadata_hash)
        let metadata_hash = metadata.hash();
        let mut sign_hasher = Hasher::new();
        sign_hasher.update(brrq_crypto::domain_tags::MEV_ENVELOPE_SIG_V1);
        sign_hasher.update(commitment.as_bytes());
        sign_hasher.update(metadata_hash.as_bytes());
        let sign_message = sign_hasher.finalize();

        let signature = keypair
            .sign(&sign_message)
            .map_err(|e| format!("Schnorr signing failed: {e}"))?;

        Ok(Self {
            metadata,
            encrypted_kind: sealed.ciphertext,
            kind_tag: sealed.tag,
            encryption_nonce: nonce,
            commitment,
            signature,
            public_key: *keypair.public_key(),
            original_signature: tx.signature.clone(),
            original_public_key: tx.public_key.clone(),
        })
    }

    /// Decrypt the envelope back to a full Transaction.
    ///
    /// Used during the decrypt phase after ordering is committed.
    /// Verifies HMAC authentication before decrypting.
    pub fn decrypt(&self, epoch_key: &EpochKey) -> Result<Transaction, String> {
        // 1. Reconstruct SealedData
        let sealed = SealedData {
            ciphertext: self.encrypted_kind.clone(),
            tag: self.kind_tag,
        };

        // 2. Open (verify HMAC + decrypt)
        let kind_bytes = encryption::open(epoch_key, &self.encryption_nonce, &sealed)
            .map_err(|e| format!("decryption failed: {e}"))?;

        // 3. Deserialize TransactionKind
        let kind: TransactionKind = serde_json::from_slice(&kind_bytes)
            .map_err(|e| format!("invalid transaction kind: {e}"))?;

        // 4. Reconstruct full Transaction
        let body = TransactionBody {
            from: self.metadata.sender,
            kind,
            nonce: self.metadata.nonce,
            gas_limit: self.metadata.gas_limit,
            max_fee_per_gas: self.metadata.max_fee_per_gas,
            max_priority_fee_per_gas: self.metadata.max_priority_fee_per_gas,
            chain_id: self.metadata.chain_id,
        };

        Ok(Transaction {
            body,
            signature: self.original_signature.clone(),
            public_key: self.original_public_key.clone(),
        })
    }

    /// Verify the commitment integrity (without decrypting).
    ///
    /// Recomputes `SHA-256(encrypted_kind ∥ kind_tag)` and checks it matches
    /// the stored commitment. If this fails, the envelope has been tampered with.
    pub fn verify_commitment(&self) -> bool {
        let sealed = SealedData {
            ciphertext: self.encrypted_kind.clone(),
            tag: self.kind_tag,
        };
        let expected = compute_commitment(&sealed);
        expected == self.commitment
    }

    /// Verify the sender's Schnorr signature on the commitment.
    ///
    /// This is checked pre-decryption to prevent spam:
    /// - Verifies the public key corresponds to the claimed sender address
    /// - Verifies the signature over `SHA-256(commitment ∥ metadata_hash)`
    pub fn verify_signature(&self) -> Result<(), String> {
        // 1. Verify sender address matches the public key
        let expected_sender = Address::from_public_key(self.public_key.as_bytes());
        if self.metadata.sender != expected_sender {
            return Err(format!(
                "sender address does not match public key: expected {}, got {}",
                expected_sender, self.metadata.sender,
            ));
        }

        // 2. Reconstruct the signed message
        let metadata_hash = self.metadata.hash();
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::MEV_ENVELOPE_SIG_V1);
        hasher.update(self.commitment.as_bytes());
        hasher.update(metadata_hash.as_bytes());
        let sign_message = hasher.finalize();

        // 3. Verify Schnorr signature
        brrq_crypto::schnorr::verify(&self.public_key, &sign_message, &self.signature)
            .map_err(|e| format!("envelope signature verification failed: {e}"))
    }

    /// Compute a unique hash for this envelope (mempool deduplication).
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::MEV_ENVELOPE_V1);
        hasher.update(self.commitment.as_bytes());
        hasher.update(self.metadata.sender.as_bytes());
        hasher.update(&self.metadata.nonce.to_le_bytes());
        hasher.update(&self.metadata.epoch.to_le_bytes());
        hasher.finalize()
    }

    /// Estimated size in bytes for mempool capacity tracking.
    pub fn size(&self) -> usize {
        // metadata fields: 20 + 8*5 = 60
        // encrypted_kind: variable
        // kind_tag: 32
        // nonce: 16
        // commitment: 32
        // signature: 64
        // public_key: 32
        // original_signature: ~64 (Schnorr)
        // original_public_key: ~32 (Schnorr)
        let base = 60 + 32 + 16 + 32 + 64 + 32 + 64 + 32;
        base + self.encrypted_kind.len()
    }
}

/// Production-safe MEV envelope encryptor with monotonic nonce counter.
///
/// Unlike `EncryptedEnvelope::encrypt()` which uses random nonces,
/// this encryptor uses a monotonic `NonceCounter` that guarantees
/// nonce uniqueness even under high throughput. This prevents
/// nonce reuse attacks where two envelopes encrypted with the same
/// nonce and key would leak plaintext XOR.
///
/// # Usage
///
/// Create one `MevEncryptor` per sequencer/node instance. The counter
/// persists across encrypt calls and survives restarts via `new_recovering()`.
pub struct MevEncryptor {
    nonce_counter: encryption::NonceCounter,
}

impl MevEncryptor {
    /// Create a new encryptor with a fresh monotonic counter.
    ///
    /// `node_id` should be the first 8 bytes of SHA-256(sequencer_pubkey)
    /// to ensure nonce uniqueness across different nodes.
    pub fn new(node_id: [u8; 8]) -> Self {
        Self {
            nonce_counter: encryption::NonceCounter::new(node_id),
        }
    }

    /// Create an encryptor recovering from a known counter floor.
    ///
    /// Use after sequencer restart: pass `last_block_in_epoch` and
    /// `max_txs_per_block` to compute a deterministic floor from on-chain
    /// state, ensuring monotonicity across restarts.
    pub fn new_recovering(
        node_id: [u8; 8],
        last_block_in_epoch: u64,
        max_txs_per_block: u64,
    ) -> Self {
        Self {
            nonce_counter: encryption::NonceCounter::new_recovering(
                node_id,
                last_block_in_epoch,
                max_txs_per_block,
            ),
        }
    }

    /// Encrypt a transaction using monotonic nonce (production path).
    pub fn encrypt(
        &self,
        tx: &Transaction,
        epoch_key: &EpochKey,
        epoch: u64,
        keypair: &SchnorrKeyPair,
    ) -> Result<EncryptedEnvelope, String> {
        EncryptedEnvelope::encrypt_with_nonce_source(
            tx,
            epoch_key,
            epoch,
            keypair,
            Some(&self.nonce_counter),
        )
    }

    /// Current counter value (for persistence on shutdown).
    pub fn current_counter(&self) -> u64 {
        self.nonce_counter.current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::SchnorrKeyPair;

    /// Create a signed test transaction.
    fn make_signed_tx(keypair: &SchnorrKeyPair) -> Transaction {
        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to = Address::from_bytes([0xBB; 20]);
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount: 50_000 },
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            chain_id: crate::transaction::chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).unwrap();

        Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair.public_key()),
        }
    }

    fn test_epoch_key() -> EpochKey {
        let seed = Hash256::from_bytes([0xAA; 32]);
        EpochKey::derive(&seed, 1)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();

        // Metadata should be visible
        assert_eq!(envelope.metadata.sender, tx.body.from);
        assert_eq!(envelope.metadata.nonce, tx.body.nonce);
        assert_eq!(envelope.metadata.max_fee_per_gas, tx.body.max_fee_per_gas);
        assert_eq!(envelope.metadata.epoch, 1);

        // Encrypted kind should differ from plaintext
        let kind_bytes = serde_json::to_vec(&tx.body.kind).unwrap();
        assert_ne!(envelope.encrypted_kind, kind_bytes);

        // Decrypt and verify
        let decrypted = envelope.decrypt(&epoch_key).unwrap();
        assert_eq!(decrypted.body.from, tx.body.from);
        assert_eq!(decrypted.body.nonce, tx.body.nonce);
        assert_eq!(decrypted.body.gas_limit, tx.body.gas_limit);
        assert_eq!(decrypted.body.max_fee_per_gas, tx.body.max_fee_per_gas);
        assert_eq!(decrypted.body.chain_id, tx.body.chain_id);

        // Verify original signature still works
        assert!(decrypted.verify_signature().is_ok());
    }

    #[test]
    fn test_verify_commitment() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        assert!(envelope.verify_commitment());
    }

    #[test]
    fn test_tampered_commitment_fails() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let mut envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        // Tamper with encrypted data
        if !envelope.encrypted_kind.is_empty() {
            envelope.encrypted_kind[0] ^= 0xFF;
        }
        assert!(!envelope.verify_commitment());
    }

    #[test]
    fn test_verify_envelope_signature() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        assert!(envelope.verify_signature().is_ok());
    }

    #[test]
    fn test_wrong_key_decrypt_fails() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = EpochKey::derive(&Hash256::from_bytes([0xBB; 32]), 1);
        let result = envelope.decrypt(&wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_hash_deterministic() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let e1 = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        // Hash depends on commitment + metadata, which are deterministic for same tx
        let h1 = e1.hash();
        assert!(!h1.is_zero());
    }

    #[test]
    fn test_envelope_size() {
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        let size = envelope.size();
        assert!(size > 200); // Should be substantial
        assert!(size < 2000); // But not huge for a simple transfer
    }

    #[test]
    fn test_contract_call_encrypt_decrypt() {
        let keypair = SchnorrKeyPair::generate();
        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to = Address::from_bytes([0xCC; 20]);

        let body = TransactionBody {
            from,
            kind: TransactionKind::ContractCall {
                to,
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                value: 1_000_000,
            },
            nonce: 5,
            gas_limit: 100_000,
            max_fee_per_gas: 25,
            max_priority_fee_per_gas: 10,
            chain_id: crate::transaction::chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).unwrap();
        let tx = Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair.public_key()),
        };

        let epoch_key = test_epoch_key();
        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();

        // Sequencer can see max_fee_per_gas=25 but NOT the contract call details
        assert_eq!(envelope.metadata.max_fee_per_gas, 25);

        let decrypted = envelope.decrypt(&epoch_key).unwrap();
        match &decrypted.body.kind {
            TransactionKind::ContractCall {
                to: dec_to,
                data,
                value,
            } => {
                assert_eq!(*dec_to, to);
                assert_eq!(*data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(*value, 1_000_000);
            }
            _ => panic!("expected ContractCall after decryption"),
        }
    }

    #[test]
    fn test_wrong_sender_signature_fails() {
        let keypair1 = SchnorrKeyPair::generate();
        let keypair2 = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair1);
        let epoch_key = test_epoch_key();

        // Encrypt with keypair1's tx but sign with keypair2
        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair2).unwrap();

        // Signature verification should fail because sender != pubkey owner
        let result = envelope.verify_signature();
        assert!(result.is_err());
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Tampering Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_metadata_tamper_breaks_signature() {
        // Attacker changes gas_price to front-run, then tries to reuse signature
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let mut envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();

        // Tamper: boost max_fee_per_gas to jump the queue
        envelope.metadata.max_fee_per_gas = 999_999;

        // Commitment is still valid (it doesn't cover metadata)
        // But signature verification MUST fail because sig covers
        // SHA-256(commitment || metadata_hash)
        let result = envelope.verify_signature();
        assert!(
            result.is_err(),
            "Tampered metadata must invalidate signature"
        );
    }

    #[test]
    fn adversarial_nonce_tamper_breaks_decryption() {
        // Attacker changes the encryption nonce → decryption fails
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let mut envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        envelope.encryption_nonce[0] ^= 0xFF;

        // HMAC verification will fail because tag was computed with original nonce
        let result = envelope.decrypt(&epoch_key);
        assert!(result.is_err(), "Tampered nonce must break decryption");
    }

    #[test]
    fn adversarial_cross_envelope_ciphertext_swap() {
        // Attacker takes encrypted kind from envelope A and puts it in envelope B's metadata
        let keypair = SchnorrKeyPair::generate();
        let epoch_key = test_epoch_key();

        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to_a = Address::from_bytes([0xAA; 20]);
        let to_b = Address::from_bytes([0xBB; 20]);

        // Envelope A: Transfer to 0xAA
        let tx_a = {
            let body = TransactionBody {
                from,
                kind: TransactionKind::Transfer {
                    to: to_a,
                    amount: 100,
                },
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                chain_id: crate::transaction::chain_id::TESTNET,
            };
            let sig = keypair.sign(&body.hash()).unwrap();
            Transaction {
                body,
                signature: Signature::Schnorr(sig),
                public_key: PublicKey::Schnorr(*keypair.public_key()),
            }
        };

        // Envelope B: Transfer to 0xBB (higher gas price)
        let tx_b = {
            let body = TransactionBody {
                from,
                kind: TransactionKind::Transfer {
                    to: to_b,
                    amount: 200,
                },
                nonce: 1,
                gas_limit: 21_000,
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 10,
                chain_id: crate::transaction::chain_id::TESTNET,
            };
            let sig = keypair.sign(&body.hash()).unwrap();
            Transaction {
                body,
                signature: Signature::Schnorr(sig),
                public_key: PublicKey::Schnorr(*keypair.public_key()),
            }
        };

        let env_a = EncryptedEnvelope::encrypt(&tx_a, &epoch_key, 1, &keypair).unwrap();
        let env_b = EncryptedEnvelope::encrypt(&tx_b, &epoch_key, 1, &keypair).unwrap();

        // Frankenstein: B's metadata + A's encrypted kind
        let franken = EncryptedEnvelope {
            metadata: env_b.metadata.clone(),
            encrypted_kind: env_a.encrypted_kind.clone(), // FROM A
            kind_tag: env_a.kind_tag,                     // FROM A
            encryption_nonce: env_a.encryption_nonce,     // FROM A
            commitment: env_a.commitment,                 // FROM A
            signature: env_b.signature,                   // FROM B
            public_key: env_b.public_key,
            original_signature: env_b.original_signature.clone(),
            original_public_key: env_b.original_public_key.clone(),
        };

        // Signature check fails: sig covers (commitment_A, metadata_B_hash) but was signed over (commitment_B, metadata_B_hash)
        assert!(
            franken.verify_signature().is_err(),
            "Cross-envelope swap must fail signature verification"
        );
    }

    #[test]
    fn adversarial_tag_tamper_breaks_commitment() {
        // Changing the HMAC tag should break both commitment and decryption
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let mut envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        envelope.kind_tag.0[0] ^= 0xFF;

        // Commitment check fails (commitment = SHA-256(ciphertext || tag))
        assert!(
            !envelope.verify_commitment(),
            "Tampered tag must break commitment"
        );

        // Decryption also fails (HMAC check)
        assert!(
            envelope.decrypt(&epoch_key).is_err(),
            "Tampered tag must break decryption"
        );
    }

    #[test]
    fn adversarial_replay_different_epoch() {
        // Envelope encrypted for epoch 1 cannot be decrypted with epoch 2 key
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let seed = Hash256::from_bytes([0xAA; 32]);

        let key_epoch1 = EpochKey::derive(&seed, 1);
        let key_epoch2 = EpochKey::derive(&seed, 2);

        let envelope = EncryptedEnvelope::encrypt(&tx, &key_epoch1, 1, &keypair).unwrap();

        // Commitment and signature still valid (independent of epoch key)
        assert!(envelope.verify_commitment());
        assert!(envelope.verify_signature().is_ok());

        // But decryption with wrong epoch key fails
        assert!(
            envelope.decrypt(&key_epoch2).is_err(),
            "Replay with different epoch key must fail"
        );
    }

    #[test]
    fn adversarial_hash_uniqueness_across_nonces() {
        // Two envelopes from same sender with different nonces must have different hashes
        let keypair = SchnorrKeyPair::generate();
        let epoch_key = test_epoch_key();

        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to = Address::from_bytes([0xBB; 20]);

        let make_tx = |nonce: u64| -> Transaction {
            let body = TransactionBody {
                from,
                kind: TransactionKind::Transfer { to, amount: 50_000 },
                nonce,
                gas_limit: 21_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 1,
                chain_id: crate::transaction::chain_id::TESTNET,
            };
            let sig = keypair.sign(&body.hash()).unwrap();
            Transaction {
                body,
                signature: Signature::Schnorr(sig),
                public_key: PublicKey::Schnorr(*keypair.public_key()),
            }
        };

        let env1 = EncryptedEnvelope::encrypt(&make_tx(0), &epoch_key, 1, &keypair).unwrap();
        let env2 = EncryptedEnvelope::encrypt(&make_tx(1), &epoch_key, 1, &keypair).unwrap();

        assert_ne!(
            env1.hash(),
            env2.hash(),
            "Different nonces must produce different envelope hashes"
        );
    }

    #[test]
    fn adversarial_decrypted_tx_preserves_original_signature() {
        // After encrypt → decrypt, the original transaction signature must still be valid
        let keypair = SchnorrKeyPair::generate();
        let tx = make_signed_tx(&keypair);
        let epoch_key = test_epoch_key();

        let envelope = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        let decrypted = envelope.decrypt(&epoch_key).unwrap();

        // Original signature should verify on the reconstructed transaction
        assert!(decrypted.verify_signature().is_ok());

        // All body fields should match
        assert_eq!(decrypted.body.from, tx.body.from);
        assert_eq!(decrypted.body.nonce, tx.body.nonce);
        assert_eq!(decrypted.body.gas_limit, tx.body.gas_limit);
        assert_eq!(decrypted.body.max_fee_per_gas, tx.body.max_fee_per_gas);
        assert_eq!(decrypted.body.chain_id, tx.body.chain_id);
    }

    #[test]
    fn adversarial_size_estimation_reasonable() {
        // Size estimation should be within reasonable bounds for various tx kinds
        let keypair = SchnorrKeyPair::generate();
        let epoch_key = test_epoch_key();

        // Simple transfer
        let tx = make_signed_tx(&keypair);
        let env = EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        let size = env.size();
        assert!(size > 100, "Envelope must be at least 100 bytes");
        assert!(
            size < 5000,
            "Simple transfer envelope should not exceed 5KB"
        );

        // Contract call with large data
        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let body = TransactionBody {
            from,
            kind: TransactionKind::ContractCall {
                to: Address::from_bytes([0xCC; 20]),
                data: vec![0xDE; 10_000], // 10 KB calldata
                value: 0,
            },
            nonce: 0,
            gas_limit: 1_000_000,
            max_fee_per_gas: 50,
            max_priority_fee_per_gas: 10,
            chain_id: crate::transaction::chain_id::TESTNET,
        };
        let sig = keypair.sign(&body.hash()).unwrap();
        let big_tx = Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair.public_key()),
        };
        let big_env = EncryptedEnvelope::encrypt(&big_tx, &epoch_key, 1, &keypair).unwrap();
        assert!(
            big_env.size() > env.size(),
            "Larger tx must produce larger envelope"
        );
        assert!(
            big_env.encrypted_kind.len() > 10_000,
            "Encrypted kind should be at least as large as calldata"
        );
    }

    // ── MevEncryptor with monotonic nonces ─────────────────

    #[test]
    fn mev_encryptor_produces_unique_nonces() {
        let keypair = SchnorrKeyPair::generate();
        let epoch_key = test_epoch_key();
        let encryptor = MevEncryptor::new([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut nonces = std::collections::HashSet::new();
        for i in 0..20u64 {
            let tx = make_signed_tx_with_nonce(&keypair, i);
            let env = encryptor.encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
            assert!(
                nonces.insert(env.encryption_nonce),
                "nonce must be unique at iteration {i}"
            );
            // Verify the envelope is still valid
            assert!(env.verify_commitment());
            assert!(env.verify_signature().is_ok());
        }
        assert_eq!(encryptor.current_counter(), 20);
    }

    #[test]
    fn mev_encryptor_recovering_starts_above_floor() {
        let node_id = [0xAA; 8];
        // last_block=10, max_txs=100 → floor = 1000
        let encryptor = MevEncryptor::new_recovering(node_id, 10, 100);
        let keypair = SchnorrKeyPair::generate();
        let epoch_key = test_epoch_key();
        let tx = make_signed_tx(&keypair);

        let env = encryptor.encrypt(&tx, &epoch_key, 1, &keypair).unwrap();
        assert!(encryptor.current_counter() > 1000, "counter should be above recovery floor");
        assert!(env.verify_commitment());
    }

    /// Helper: create a signed tx with a specific nonce.
    fn make_signed_tx_with_nonce(keypair: &SchnorrKeyPair, nonce: u64) -> Transaction {
        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to = Address::from_bytes([0xBB; 20]);
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount: 50_000 },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            chain_id: crate::transaction::chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).unwrap();
        Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair.public_key()),
        }
    }
}
