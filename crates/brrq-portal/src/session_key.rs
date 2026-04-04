//! Delegated Session Keys (BPS-2).
//!
//! Allows a user to delegate a temporary key with spending limits.
//! The TEE signs a delegation proof; the session key signs micro-payments.
//! Settlement verifies the delegation chain: TEE → session → receipts.
//!
//! ## Security constraints
//!
//! - Session key is bounded by: max_amount, expiry_block, specific lock_id
//! - TEE signature covers ALL constraints — cannot be widened
//! - Session key compromise loses at most max_amount (not the full lock)
//!
//! ## Status: Types only (TEE integration required for full implementation)

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

/// Domain tag for delegation proof hashing.
const DELEGATION_DOMAIN: &[u8] = b"BRRQ_SESSION_DELEGATION_V1";

/// A delegation proof signed by the owner's TEE-protected key.
///
/// This authorizes a temporary session key to spend up to `max_amount`
/// from a specific lock, until `expiry_block`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationProof {
    /// The lock this delegation applies to.
    pub lock_id: Hash256,
    /// Public key of the session (temporary) key.
    pub session_pubkey: SchnorrPublicKey,
    /// Maximum cumulative amount the session key can authorize.
    pub max_amount: u64,
    /// L2 block height after which this delegation expires.
    pub expiry_block: u64,
    /// Owner's TEE-backed Schnorr signature over the delegation payload.
    pub owner_signature: SchnorrSignature,
    /// Owner's public key (for verification without lock lookup).
    pub owner_pubkey: SchnorrPublicKey,
}

/// A micro-payment receipt signed by the session key.
///
/// The merchant collects these during a streaming session and settles
/// only the last (highest cumulative_amount) receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReceipt {
    /// Lock ID (must match delegation's lock_id).
    pub lock_id: Hash256,
    /// Cumulative amount authorized so far (monotonically increasing).
    pub cumulative_amount: u64,
    /// Monotonic sequence number (prevents replay).
    pub sequence: u64,
    /// Session key's Schnorr signature over receipt payload.
    pub signature: SchnorrSignature,
}

/// Compute the delegation payload that the TEE signs.
///
/// ```text
/// payload = SHA-256(BRRQ_SESSION_DELEGATION_V1 || lock_id || session_pubkey || max_amount || expiry_block)
/// ```
pub fn compute_delegation_payload(
    lock_id: &Hash256,
    session_pubkey: &SchnorrPublicKey,
    max_amount: u64,
    expiry_block: u64,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(DELEGATION_DOMAIN);
    hasher.update(lock_id.as_bytes());
    hasher.update(session_pubkey.as_bytes());
    hasher.update(&max_amount.to_le_bytes());
    hasher.update(&expiry_block.to_le_bytes());
    hasher.finalize()
}

/// Domain tag for session receipt hashing.
const RECEIPT_DOMAIN: &[u8] = b"BRRQ_SESSION_RECEIPT_V1";

/// Compute the receipt payload that the session key signs.
///
/// ```text
/// payload = SHA-256(BRRQ_SESSION_RECEIPT_V1 || lock_id || cumulative_amount || sequence)
/// ```
/// Added session_pubkey to bind receipt to specific delegation
pub fn compute_receipt_payload(
    lock_id: &Hash256,
    cumulative_amount: u64,
    sequence: u64,
    session_pubkey: &SchnorrPublicKey,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(RECEIPT_DOMAIN);
    hasher.update(lock_id.as_bytes());
    hasher.update(&cumulative_amount.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    hasher.update(session_pubkey.as_bytes());
    hasher.finalize()
}

/// Verify a delegation proof's structure (without TEE — signature check only).
///
/// Returns Ok(()) if the owner's signature is valid over the delegation payload.
pub fn verify_delegation_proof(proof: &DelegationProof) -> Result<(), String> {
    if proof.max_amount == 0 {
        return Err("delegation max_amount must be > 0".into());
    }
    // Reject expired delegations and zero expiry
    if proof.expiry_block == 0 {
        return Err("delegation expiry_block must be > 0".into());
    }
    let payload = compute_delegation_payload(
        &proof.lock_id,
        &proof.session_pubkey,
        proof.max_amount,
        proof.expiry_block,
    );
    brrq_crypto::schnorr::verify(&proof.owner_pubkey, &payload, &proof.owner_signature)
        .map_err(|_| "invalid owner signature on delegation proof".to_string())
}

/// Verify a session receipt's signature and constraints.
///
/// Checks:
/// 1. Receipt lock_id matches delegation lock_id
/// 2. Cumulative amount ≤ delegation max_amount
/// 3. Session key signature is valid
pub fn verify_session_receipt(
    receipt: &SessionReceipt,
    delegation: &DelegationProof,
    current_block: u64,
) -> Result<(), String> {
    // Lock ID must match
    if receipt.lock_id != delegation.lock_id {
        return Err("receipt lock_id does not match delegation".into());
    }
    // Delegation not expired
    if current_block > delegation.expiry_block {
        return Err(format!(
            "delegation expired at block {}, current {}",
            delegation.expiry_block, current_block
        ));
    }
    // Amount within limit
    if receipt.cumulative_amount > delegation.max_amount {
        return Err(format!(
            "receipt cumulative {} exceeds delegation max {}",
            receipt.cumulative_amount, delegation.max_amount
        ));
    }
    // Signature verification
    let payload = compute_receipt_payload(
        &receipt.lock_id,
        receipt.cumulative_amount,
        receipt.sequence,
        &delegation.session_pubkey,
    );
    brrq_crypto::schnorr::verify(
        &delegation.session_pubkey,
        &payload,
        &receipt.signature,
    )
    .map_err(|_| "invalid session key signature on receipt".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::SchnorrKeyPair;

    #[test]
    fn test_delegation_sign_and_verify() {
        let owner_kp = SchnorrKeyPair::generate();
        let session_kp = SchnorrKeyPair::generate();
        let lock_id = Hasher::hash(b"test_lock_for_delegation");

        let payload = compute_delegation_payload(
            &lock_id,
            session_kp.public_key(),
            1_000_000,
            500_000,
        );
        let owner_sig = owner_kp.sign(&payload).unwrap();

        let proof = DelegationProof {
            lock_id,
            session_pubkey: *session_kp.public_key(),
            max_amount: 1_000_000,
            expiry_block: 500_000,
            owner_signature: owner_sig,
            owner_pubkey: *owner_kp.public_key(),
        };

        verify_delegation_proof(&proof).unwrap();
    }

    #[test]
    fn test_delegation_tampered_amount_fails() {
        let owner_kp = SchnorrKeyPair::generate();
        let session_kp = SchnorrKeyPair::generate();
        let lock_id = Hasher::hash(b"test_lock_tamper");

        let payload = compute_delegation_payload(
            &lock_id,
            session_kp.public_key(),
            1_000_000,
            500_000,
        );
        let owner_sig = owner_kp.sign(&payload).unwrap();

        let mut proof = DelegationProof {
            lock_id,
            session_pubkey: *session_kp.public_key(),
            max_amount: 1_000_000,
            expiry_block: 500_000,
            owner_signature: owner_sig,
            owner_pubkey: *owner_kp.public_key(),
        };

        // Tamper: increase max_amount
        proof.max_amount = 99_000_000;
        assert!(verify_delegation_proof(&proof).is_err());
    }

    #[test]
    fn test_session_receipt_sign_and_verify() {
        let owner_kp = SchnorrKeyPair::generate();
        let session_kp = SchnorrKeyPair::generate();
        let lock_id = Hasher::hash(b"streaming_lock");

        // Create delegation
        let del_payload = compute_delegation_payload(
            &lock_id,
            session_kp.public_key(),
            500_000,
            300_000,
        );
        let delegation = DelegationProof {
            lock_id,
            session_pubkey: *session_kp.public_key(),
            max_amount: 500_000,
            expiry_block: 300_000,
            owner_signature: owner_kp.sign(&del_payload).unwrap(),
            owner_pubkey: *owner_kp.public_key(),
        };

        // Create receipt within limits
        let rcpt_payload = compute_receipt_payload(&lock_id, 100_000, 1, session_kp.public_key());
        let receipt = SessionReceipt {
            lock_id,
            cumulative_amount: 100_000,
            sequence: 1,
            signature: session_kp.sign(&rcpt_payload).unwrap(),
        };

        verify_session_receipt(&receipt, &delegation, 200_000).unwrap();
    }

    #[test]
    fn test_session_receipt_exceeds_limit() {
        let owner_kp = SchnorrKeyPair::generate();
        let session_kp = SchnorrKeyPair::generate();
        let lock_id = Hasher::hash(b"limit_test");

        let del_payload = compute_delegation_payload(
            &lock_id,
            session_kp.public_key(),
            100_000, // limit
            300_000,
        );
        let delegation = DelegationProof {
            lock_id,
            session_pubkey: *session_kp.public_key(),
            max_amount: 100_000,
            expiry_block: 300_000,
            owner_signature: owner_kp.sign(&del_payload).unwrap(),
            owner_pubkey: *owner_kp.public_key(),
        };

        // Receipt exceeds max_amount
        let rcpt_payload = compute_receipt_payload(&lock_id, 200_000, 1, session_kp.public_key());
        let receipt = SessionReceipt {
            lock_id,
            cumulative_amount: 200_000,
            sequence: 1,
            signature: session_kp.sign(&rcpt_payload).unwrap(),
        };

        assert!(verify_session_receipt(&receipt, &delegation, 200_000).is_err());
    }

    #[test]
    fn test_session_receipt_expired_delegation() {
        let owner_kp = SchnorrKeyPair::generate();
        let session_kp = SchnorrKeyPair::generate();
        let lock_id = Hasher::hash(b"expiry_test");

        let del_payload = compute_delegation_payload(
            &lock_id,
            session_kp.public_key(),
            500_000,
            100_000, // expires at block 100k
        );
        let delegation = DelegationProof {
            lock_id,
            session_pubkey: *session_kp.public_key(),
            max_amount: 500_000,
            expiry_block: 100_000,
            owner_signature: owner_kp.sign(&del_payload).unwrap(),
            owner_pubkey: *owner_kp.public_key(),
        };

        let rcpt_payload = compute_receipt_payload(&lock_id, 50_000, 1, session_kp.public_key());
        let receipt = SessionReceipt {
            lock_id,
            cumulative_amount: 50_000,
            sequence: 1,
            signature: session_kp.sign(&rcpt_payload).unwrap(),
        };

        // Block 200k > expiry 100k → expired
        assert!(verify_session_receipt(&receipt, &delegation, 200_000).is_err());
    }
}
