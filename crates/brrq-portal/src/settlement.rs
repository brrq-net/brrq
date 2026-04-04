//! Settlement logic — single and batch settlement of Portal locks.
//!
//! Settlement is the process by which a merchant converts a Portal Key
//! into actual funds on L2. The merchant reveals their secret (preimage
//! of condition_hash), the nullifier is consumed, and funds transfer
//! from escrow to the merchant's address.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr;
use tracing::info;

use crate::error::SettlementError;
use crate::escrow::EscrowManager;
use crate::nullifier::NullifierSet;
use crate::session_key::{self, DelegationProof, SessionReceipt};
use crate::types::{
    compute_portal_key_payload, BatchResult, PortalLock, SettlementClaim, MAX_BATCH_SIZE,
};

/// Compute the effective settlement deadline and validate that the current block
/// has not exceeded it. Shared by `settle_portal_key` and `settle_session_receipt`.
///
/// Returns the effective deadline on success (needed for nullifier expiry tracking).
fn validate_lock_expiry(
    lock: &PortalLock,
    current_block: u64,
) -> Result<u64, SettlementError> {
    let effective_deadline = lock
        .timeout_l2_block
        .saturating_add(crate::types::SETTLEMENT_GRACE_BLOCKS);
    if current_block > effective_deadline {
        return Err(SettlementError::Expired {
            timeout: lock.timeout_l2_block,
            current: current_block,
        });
    }
    Ok(effective_deadline)
}

/// Enforce merchant_address binding: if the lock has a non-zero merchant_address
/// (set during UpdateLockCondition), the claimed address MUST match.
/// Prevents front-running attacks where a searcher redirects funds.
/// Shared by `settle_portal_key` and `settle_session_receipt`.
fn validate_merchant_binding(
    lock: &PortalLock,
    claimed_merchant: &brrq_types::Address,
) -> Result<(), SettlementError> {
    if !lock.merchant_address.is_zero() && *claimed_merchant != lock.merchant_address {
        return Err(SettlementError::Portal(
            crate::error::PortalError::OwnerMismatch {
                lock_owner: format!("{}", lock.merchant_address),
                key_owner: format!("{}", claimed_merchant),
            },
        ));
    }
    Ok(())
}

/// Settle a single Portal Key.
///
/// Validates the merchant's secret, verifies the signature, consumes the
/// nullifier, and transfers funds from escrow to the merchant.
pub fn settle_portal_key(
    escrow: &mut EscrowManager,
    nullifiers: &mut NullifierSet,
    claim: &SettlementClaim,
    current_block: u64,
) -> Result<u64, SettlementError> {
    let lock = escrow
        .get_lock(&claim.lock_id)
        .map_err(SettlementError::Portal)?;

    // Active status check handled atomically by escrow.settle_lock().

    // 1. Check expiration (with grace period for sequencer downtime)
    let effective_deadline = validate_lock_expiry(&lock, current_block)?;

    // 2. Enforce merchant_address binding (prevents front-running)
    validate_merchant_binding(&lock, &claim.merchant_address)?;

    // Reject empty merchant secret
    if claim.merchant_secret.is_empty() {
        return Err(SettlementError::InvalidSecret);
    }
    // Cap merchant_secret to 1KB to prevent OOM from crafted payloads
    if claim.merchant_secret.len() > 1024 {
        return Err(SettlementError::InvalidSecret);
    }

    // Reject settlement if lock has no nullifier commitment
    // (unassigned pool slot — must call UpdateLockCondition first)
    if lock.nullifier_hash.is_zero() {
        return Err(SettlementError::Portal(
            crate::error::PortalError::LockNotActive(claim.lock_id)
        ));
    }

    // 2. Verify merchant secret: sha256(secret) must equal condition_hash
    let computed_condition = Hasher::hash(&claim.merchant_secret);
    if computed_condition != lock.condition_hash {
        return Err(SettlementError::InvalidSecret);
    }

    // 3. Verify signature over (lock_id || condition_hash || timeout)
    let payload = compute_portal_key_payload(
        &lock.lock_id,
        &lock.condition_hash,
        lock.timeout_l2_block,
    );
    schnorr::verify(&lock.owner_pubkey, &payload, &claim.signature)
        .map_err(|_| SettlementError::InvalidSignature)?;

    // 4. Verify nullifier matches lock's stored nullifier_hash (defense-in-depth).
    // If the lock has a non-zero nullifier_hash (set during Portal Key
    // generation via update_lock_condition), verify the claim's nullifier matches.
    // This prevents a merchant from submitting a fabricated nullifier.
    if !lock.nullifier_hash.is_zero() && claim.nullifier != lock.nullifier_hash {
        return Err(SettlementError::DoubleSpend);
    }

    // 5. Consume nullifier BEFORE settling the lock.
    // This ordering is critical: if we settled first and nullifier consumption failed,
    // the lock would be irrecoverably removed with funds lost. By consuming the
    // nullifier first, a failure here leaves the lock intact and retryable.
    if !nullifiers.consume_with_expiry(&claim.nullifier, effective_deadline) {
        return Err(SettlementError::DoubleSpend);
    }

    // 6. Now settle the lock (remove from escrow and decrement total_escrowed).
    // If this fails, the nullifier is consumed but funds remain locked — the lock
    // can be expired normally. This is safe: no fund loss, no double-spend.
    let amount = escrow
        .settle_lock(&claim.lock_id)
        .map_err(SettlementError::Portal)?;

    info!(
        lock_id = %claim.lock_id,
        merchant = %claim.merchant_address,
        amount = amount,
        "settlement completed"
    );

    Ok(amount)
}

/// Batch settlement — settle multiple Portal Keys in a single L2 transaction.
///
/// Processes each claim independently. Failed claims don't affect others.
/// Returns a BatchResult with success/failure counts and failed indices.
///
/// This provides ~100x gas compression vs individual settlements.
pub fn batch_settle(
    escrow: &mut EscrowManager,
    nullifiers: &mut NullifierSet,
    claims: &[SettlementClaim],
    current_block: u64,
) -> Result<BatchResult, SettlementError> {
    if claims.is_empty() {
        return Err(SettlementError::Portal(crate::error::PortalError::EmptyBatch));
    }
    if claims.len() > MAX_BATCH_SIZE {
        return Err(SettlementError::Portal(
            crate::error::PortalError::BatchTooLarge {
                size: claims.len(),
                max: MAX_BATCH_SIZE,
            },
        ));
    }

    let mut result = BatchResult::default();

    for (i, claim) in claims.iter().enumerate() {
        match settle_portal_key(escrow, nullifiers, claim, current_block) {
            Ok(amount) => {
                result.succeeded += 1;
                result.total_settled_amount = result.total_settled_amount.saturating_add(amount);
                result.settled_amounts.push((i, amount));
            }
            Err(e) => {
                let err_msg = e.to_string();
                tracing::warn!(
                    index = i,
                    lock_id = %claim.lock_id,
                    error = %err_msg,
                    "batch settlement: claim failed"
                );
                result.failed += 1;
                result.failed_indices.push(i);
                result.failed_details.push((i, err_msg));
            }
        }
    }

    info!(
        succeeded = result.succeeded,
        failed = result.failed,
        total = claims.len(),
        "batch settlement completed"
    );

    Ok(result)
}

/// Settle a session receipt — delegated micro-payment settlement.
///
/// This bridges the gap between `session_key.rs` (off-chain verification)
/// and the on-chain settlement engine. A merchant holding a valid
/// `DelegationProof` + `SessionReceipt` can settle the cumulative amount
/// (not the full lock amount) against the lock.
///
/// Flow:
/// 1. Verify delegation proof (owner signed it for this lock + session key)
/// 2. Verify session receipt (session key signed it, amount ≤ delegation max)
/// 3. Mark lock as Settled (full amount goes to escrow settlement)
/// 4. Return `receipt.cumulative_amount` — the merchant's actual payout
///
/// The difference (`lock.amount - receipt.cumulative_amount`) is **refunded**
/// to the lock owner by the block builder.
pub fn settle_session_receipt(
    escrow: &mut EscrowManager,
    nullifiers: &mut NullifierSet,
    delegation: &DelegationProof,
    receipt: &SessionReceipt,
    merchant_address: &brrq_types::Address,
    current_block: u64,
) -> Result<(u64, u64), SettlementError> {
    // 1. Get and validate lock
    let lock = escrow
        .get_lock(&delegation.lock_id)
        .map_err(SettlementError::Portal)?;

    if lock.status != crate::types::LockStatus::Active {
        return Err(SettlementError::Portal(
            crate::error::PortalError::LockNotActive(delegation.lock_id),
        ));
    }

    // Check lock expiry (with grace period) — shared with settle_portal_key
    let effective_deadline = validate_lock_expiry(&lock, current_block)?;

    // Enforce merchant_address binding — shared with settle_portal_key
    validate_merchant_binding(&lock, merchant_address)?;

    // 2. Verify delegation proof: owner authorized this session key
    if lock.owner_pubkey != delegation.owner_pubkey {
        return Err(SettlementError::InvalidSignature);
    }
    session_key::verify_delegation_proof(delegation)
        .map_err(|_| SettlementError::InvalidSignature)?;

    // 3. Verify session receipt: session key signed valid receipt
    session_key::verify_session_receipt(receipt, delegation, current_block)
        .map_err(|_| SettlementError::InvalidSignature)?;

    // 4. Validate amounts
    if receipt.cumulative_amount == 0 {
        return Err(SettlementError::InvalidSecret);
    }
    if receipt.cumulative_amount > lock.amount {
        return Err(SettlementError::Portal(
            crate::error::PortalError::AmountOverflow,
        ));
    }

    // 5. Compute a deterministic nullifier for this session settlement
    // to prevent double-settlement of the same receipt.
    let session_nullifier = {
        let mut hasher = Hasher::new();
        hasher.update(b"BRRQ_SESSION_NULLIFIER_V1");
        hasher.update(delegation.lock_id.as_bytes());
        hasher.update(delegation.session_pubkey.as_bytes());
        hasher.update(&receipt.sequence.to_le_bytes());
        hasher.finalize()
    };

    // 5. Consume nullifier BEFORE settling the lock (same ordering rationale as
    // settle_portal_key: settling first would irrecoverably remove the lock on failure).
    if !nullifiers.consume_with_expiry(&session_nullifier, effective_deadline) {
        return Err(SettlementError::DoubleSpend);
    }

    // 6. Now settle the lock — nullifier is already consumed, so no double-spend possible.
    let lock_amount = escrow
        .settle_lock(&delegation.lock_id)
        .map_err(SettlementError::Portal)?;

    let merchant_payout = receipt.cumulative_amount;
    let owner_refund = lock_amount.saturating_sub(merchant_payout);

    info!(
        lock_id = %delegation.lock_id,
        merchant = %merchant_address,
        merchant_payout = merchant_payout,
        owner_refund = owner_refund,
        "session receipt settlement completed"
    );

    Ok((merchant_payout, owner_refund))
}

/// Compute the Merkle root of a batch of settlement claims.
///
/// Used for on-chain commitment to the batch for future verification.
pub fn compute_batch_merkle_root(claims: &[SettlementClaim]) -> Hash256 {
    if claims.is_empty() {
        return Hash256::ZERO;
    }

    // Leaf hashes
    let mut hashes: Vec<Hash256> = claims
        .iter()
        .map(|c| {
            let mut hasher = Hasher::new();
            hasher.update(brrq_crypto::domain_tags::PORTAL_BATCH_V1);
            hasher.update(c.lock_id.as_bytes());
            hasher.update(c.nullifier.as_bytes());
            hasher.update(c.merchant_address.as_bytes());
            hasher.finalize()
        })
        .collect();

    // Build Merkle tree (pad to power of 2 with zero hashes)
    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            hashes.push(Hash256::ZERO);
        }
        hashes = hashes
            .chunks(2)
            .map(|pair| Hasher::hash_node(&pair[0], &pair[1]))
            .collect();
    }

    hashes[0]
}
