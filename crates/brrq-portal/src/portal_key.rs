//! Portal Key generation and verification.
//!
//! The Portal Key is the off-chain payment instrument sent from the user's
//! wallet to the merchant. It contains a Schnorr signature, a nullifier,
//! and public inputs that the merchant can verify locally and against L2.

use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::{self, SchnorrKeyPair};

use crate::error::PortalError;
use crate::types::{
    compute_nullifier, compute_portal_key_payload, PortalKey, PortalKeyPublicInputs, PortalLock,
};

/// Generate a Portal Key for a given lock.
///
/// Called by the user's wallet after creating a lock and receiving
/// a condition_hash from the merchant.
///
/// # Arguments
/// - `lock`: The active lock on L2
/// - `keypair`: The user's Schnorr keypair (same key that owns the lock)
/// - `condition_hash`: H(merchant_secret) provided by the merchant
pub fn generate_portal_key(
    lock: &PortalLock,
    keypair: &SchnorrKeyPair,
    condition_hash: &Hash256,
) -> Result<PortalKey, PortalError> {
    // Compute the signature payload
    let payload = compute_portal_key_payload(&lock.lock_id, condition_hash, lock.timeout_l2_block);

    // Sign with Schnorr
    let signature = keypair
        .sign(&payload)
        .map_err(|_| PortalError::InvalidSignature)?;

    // Compute the extended deterministic nullifier
    let secret_bytes = keypair.secret_bytes();
    let nullifier = compute_nullifier(&secret_bytes, &lock.lock_id, condition_hash);

    Ok(PortalKey {
        protocol: PortalKey::PROTOCOL_V4.to_string(),
        signature,
        nullifier,
        lock_id: lock.lock_id,
        public_inputs: PortalKeyPublicInputs {
            owner: lock.owner,
            owner_pubkey: *keypair.public_key(),
            asset_id: "BTC".to_string(),
            amount: lock.amount,
            condition_hash: *condition_hash,
            timeout_l2_block: lock.timeout_l2_block,
        },
    })
}

/// Verify a Portal Key's signature locally (mathematical verification).
///
/// This is the merchant's first check (~0.05ms). Does NOT query L2.
/// Returns Ok(()) if the signature is valid over the expected payload.
pub fn verify_portal_key_signature(key: &PortalKey) -> Result<(), PortalError> {
    let payload = compute_portal_key_payload(
        &key.lock_id,
        &key.public_inputs.condition_hash,
        key.public_inputs.timeout_l2_block,
    );

    schnorr::verify(&key.public_inputs.owner_pubkey, &payload, &key.signature)
        .map_err(|_| PortalError::InvalidSignature)
}

/// Full Portal Key verification against L2 lock state.
///
/// Performs all merchant-side checks:
/// 1. Signature verification (local, ~0.05ms)
/// 2. Lock existence and Active status
/// 3. Amount and owner match
/// 4. Lock not expired
/// 5. Nullifier not consumed
pub fn verify_portal_key_full(
    key: &PortalKey,
    lock: &PortalLock,
    current_block: u64,
    is_nullifier_consumed: bool,
) -> Result<(), PortalError> {
    // 1. Verify signature
    verify_portal_key_signature(key)?;

    // 1b. Ensure key references the correct lock
    if key.lock_id != lock.lock_id {
        return Err(PortalError::LockNotFound(key.lock_id));
    }

    // 2. Lock must be active
    if lock.status != crate::types::LockStatus::Active {
        return Err(PortalError::LockNotActive(key.lock_id));
    }

    // 3. Amount match
    if lock.amount != key.public_inputs.amount {
        return Err(PortalError::AmountMismatch {
            lock_amount: lock.amount,
            key_amount: key.public_inputs.amount,
        });
    }

    // 4. Owner match
    if lock.owner != key.public_inputs.owner {
        return Err(PortalError::OwnerMismatch {
            lock_owner: lock.owner.to_brrq_hex(),
            key_owner: key.public_inputs.owner.to_brrq_hex(),
        });
    }

    // 4b. Owner pubkey must match lock's pubkey (defense-in-depth)
    // Prevents self-signed forgery where attacker uses their own key mapping to same address
    if lock.owner_pubkey != key.public_inputs.owner_pubkey {
        return Err(PortalError::InvalidSignature);
    }

    // 5. Not expired
    if current_block > lock.timeout_l2_block {
        return Err(PortalError::LockExpired {
            expired_at: lock.timeout_l2_block,
            current: current_block,
        });
    }

    // 6. Nullifier not consumed
    if is_nullifier_consumed {
        return Err(PortalError::NullifierAlreadyConsumed);
    }

    Ok(())
}
