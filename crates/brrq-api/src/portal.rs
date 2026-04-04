//! Portal (L3) API services — REST and JSON-RPC handlers.
//!
//! Provides endpoints for:
//! - Querying Portal locks by ID, owner, or status
//! - Querying nullifier status (confirmed + mempool-aware)
//! - Atomic safety check for merchants
//! - Portal statistics

use brrq_portal::types::LockStatus;
use serde_json::json;

use crate::services::ServiceError;
use crate::state::NodeState;

/// Get a Portal lock by its ID.
///
/// Response includes `pending_cancel` (mempool awareness) and `safe_to_accept`
/// (combined advisory field for merchants).
pub fn get_portal_lock(
    ns: &NodeState,
    lock_id_hex: &str,
) -> Result<serde_json::Value, ServiceError> {
    let lock_id = brrq_crypto::hash::Hash256::from_hex(lock_id_hex)
        .map_err(|_| ServiceError::BadRequest("invalid lock_id hex".into()))?;

    let lock = ns
        .portal_escrow
        .get_lock(&lock_id)
        .map_err(|e| ServiceError::NotFound(e.to_string()))?;

    // Check mempool for pending cancel targeting this lock
    let pending_cancel = ns.mempool.has_pending_portal_cancel(&lock_id);
    let safe_to_accept = lock.status == LockStatus::Active && !pending_cancel;

    Ok(json!({
        "lock_id": lock.lock_id.to_hex(),
        "owner": lock.owner.to_brrq_hex(),
        "amount": lock.amount,
        "condition_hash": lock.condition_hash.to_hex(),
        "nullifier_hash": lock.nullifier_hash.to_hex(),
        "timeout_l2_block": lock.timeout_l2_block,
        "status": serde_json::to_value(&lock.status).unwrap_or(serde_json::Value::Null),
        "created_at_block": lock.created_at_block,
        "pending_cancel": pending_cancel,
        "safe_to_accept": safe_to_accept,
    }))
}

/// Check if a nullifier has been consumed.
///
/// Response includes `pending_settlement` (mempool awareness) and `safe`
/// (combined field: not consumed AND no pending settlement).
pub fn check_nullifier(
    ns: &NodeState,
    nullifier_hex: &str,
) -> Result<serde_json::Value, ServiceError> {
    let nullifier = brrq_crypto::hash::Hash256::from_hex(nullifier_hex)
        .map_err(|_| ServiceError::BadRequest("invalid nullifier hex".into()))?;

    let consumed = ns.portal_nullifiers.is_consumed(&nullifier);
    // Check mempool for pending settlement using this nullifier
    let pending_settlement = ns.mempool.has_pending_portal_nullifier(&nullifier);
    let safe = !consumed && !pending_settlement;

    Ok(json!({
        "nullifier": nullifier_hex,
        "consumed": consumed,
        "pending_settlement": pending_settlement,
        "safe": safe,
    }))
}

/// Atomic safety check for merchants.
///
/// Combines ALL Portal safety checks into a single query to eliminate
/// race conditions between separate lock and nullifier queries.
/// Returns a single `safe` boolean plus detailed breakdown.
pub fn check_portal_safety(
    ns: &NodeState,
    lock_id_hex: &str,
    nullifier_hex: &str,
    current_block: u64,
) -> Result<serde_json::Value, ServiceError> {
    let lock_id = brrq_crypto::hash::Hash256::from_hex(lock_id_hex)
        .map_err(|_| ServiceError::BadRequest("invalid lock_id hex".into()))?;
    let nullifier = brrq_crypto::hash::Hash256::from_hex(nullifier_hex)
        .map_err(|_| ServiceError::BadRequest("invalid nullifier hex".into()))?;

    // 1. Lock exists and is Active?
    let lock_result = ns.portal_escrow.get_lock(&lock_id);
    let (lock_exists, lock_active, lock_expired, amount) = match &lock_result {
        Ok(lock) => (
            true,
            lock.status == LockStatus::Active,
            current_block >= lock.timeout_l2_block,
            lock.amount,
        ),
        Err(_) => (false, false, false, 0),
    };

    // 2. Nullifier not consumed?
    let nullifier_consumed = ns.portal_nullifiers.is_consumed(&nullifier);

    // 3. No pending settlement in mempool?
    let pending_settlement = ns.mempool.has_pending_portal_nullifier(&nullifier);

    // 4. No pending cancel in mempool?
    let pending_cancel = ns.mempool.has_pending_portal_cancel(&lock_id);

    // Combined safety: ALL conditions must pass
    let safe = lock_exists
        && lock_active
        && !lock_expired
        && !nullifier_consumed
        && !pending_settlement
        && !pending_cancel;

    // Build rejection reasons for debugging
    let mut reasons = Vec::new();
    if !lock_exists {
        reasons.push("lock_not_found");
    }
    if lock_exists && !lock_active {
        reasons.push("lock_not_active");
    }
    if lock_expired {
        reasons.push("lock_expired");
    }
    if nullifier_consumed {
        reasons.push("nullifier_consumed");
    }
    if pending_settlement {
        reasons.push("pending_settlement_in_mempool");
    }
    if pending_cancel {
        reasons.push("pending_cancel_in_mempool");
    }

    Ok(json!({
        "safe": safe,
        "lock_id": lock_id_hex,
        "nullifier": nullifier_hex,
        "amount": amount,
        "details": {
            "lock_exists": lock_exists,
            "lock_active": lock_active,
            "lock_expired": lock_expired,
            "nullifier_consumed": nullifier_consumed,
            "pending_settlement": pending_settlement,
            "pending_cancel": pending_cancel,
        },
        "rejection_reasons": reasons,
    }))
}

/// Get Portal statistics.
pub fn get_portal_stats(ns: &NodeState) -> Result<serde_json::Value, ServiceError> {
    Ok(json!({
        "active_locks": ns.portal_escrow.active_lock_count(),
        "total_escrowed": ns.portal_escrow.total_escrowed(),
        "nullifiers_consumed": ns.portal_nullifiers.len(),
    }))
}
