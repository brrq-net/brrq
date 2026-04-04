//! Portal maintenance — expiry scanning, pruning, and follower sync.
//!
//! Runs before block building on both producer and follower.

use brrq_api::events::NodeEvent;
use brrq_api::state::NodeState;

/// Run portal maintenance before block building (producer side).
///
/// This MUST be called before `build_block_with_deposits` to ensure
/// expired locks are processed before new transactions reference them.
/// Called from both `produce_block` and `apply_block`.
pub(crate) fn run_portal_maintenance(ns: &mut NodeState, height: u64) {
    // ── Portal maintenance: expire locks past timeout ──
    let expiry_result = brrq_portal::scan_and_expire_locks(&mut ns.portal_escrow, height);
    // CRITICAL: Apply refunds to WorldState — expired funds MUST be returned to owners
    for refund in &expiry_result.refunds {
        let acct = ns.state.get_or_create_account(refund.owner);
        acct.balance = acct.balance.saturating_add(refund.amount);
        ns.state.flush_account(&refund.owner);
        tracing::info!(
            owner = %refund.owner,
            amount = refund.amount,
            lock_id = %refund.lock_id,
            "Portal lock expired — refund credited to owner"
        );
        // Emit WebSocket event for expired lock
        if let Some(ref event_tx) = ns.event_tx {
            let _ = event_tx.send(NodeEvent::PortalLockExpired {
                lock_id: refund.lock_id.to_hex(),
                owner: refund.owner.to_brrq_hex(),
                amount: refund.amount,
            });
        }
    }
    // Prune terminal-state locks every 1000 blocks to bound memory
    if height % 1000 == 0 {
        brrq_portal::prune_old_locks(&mut ns.portal_escrow, height, 10_000);
    }
    // Prune expired nullifiers every block to bound NullifierSet size.
    let nullifiers_pruned = ns.portal_nullifiers.prune_expired(height);
    if nullifiers_pruned > 0 {
        tracing::debug!(pruned = nullifiers_pruned, "Portal nullifiers pruned");
    }
}

/// Mirrors the block builder's `apply_portal_effects` to keep follower
/// portal state synchronized with the sequencer.
/// Follower portal effects with error logging.
/// Errors are logged at error! level since any failure on a committed block
/// indicates state divergence between producer and follower.
pub(crate) fn apply_portal_effects_follower(
    tx: &brrq_types::transaction::Transaction,
    escrow: &mut brrq_portal::EscrowManager,
    nullifiers: &mut brrq_portal::NullifierSet,
    state: &mut brrq_state::WorldState,
    height: u64,
) {
    let sender = *tx.sender();
    match &tx.body.kind {
        brrq_types::TransactionKind::CreatePortalLock {
            amount, condition_hash, nullifier_hash, timeout_l2_block,
        } => {
            if let brrq_types::PublicKey::Schnorr(pk) = &tx.public_key {
                if let Err(e) = escrow.register_lock(
                    sender, *pk, *amount, *condition_hash,
                    *nullifier_hash, *timeout_l2_block, height,
                ) {
                    tracing::error!("FOLLOWER DIVERGENCE: CreatePortalLock failed: {e}");
                }
            }
        }
        brrq_types::TransactionKind::SettlePortalLock {
            lock_id, merchant_secret, portal_signature, nullifier,
        } => {
            match brrq_crypto::schnorr::SchnorrSignature::from_slice(portal_signature) {
                Ok(sig) => {
                    let claim = brrq_portal::SettlementClaim {
                        lock_id: *lock_id,
                        merchant_secret: merchant_secret.clone(),
                        signature: sig,
                        nullifier: *nullifier,
                        merchant_address: sender,
                    };
                    match brrq_portal::settle_portal_key(escrow, nullifiers, &claim, height) {
                        Ok(amount) => {
                            let acct = state.get_or_create_account(sender);
                            acct.balance = acct.balance.saturating_add(amount);
                            state.flush_account(&sender);
                        }
                        Err(e) => tracing::error!("FOLLOWER DIVERGENCE: SettlePortalLock failed: {e}"),
                    }
                }
                Err(e) => tracing::error!("FOLLOWER DIVERGENCE: invalid portal sig format: {e}"),
            }
        }
        brrq_types::TransactionKind::BatchSettlePortal { claims } => {
            let portal_claims: Vec<brrq_portal::SettlementClaim> = claims.iter().filter_map(|c| {
                match brrq_crypto::schnorr::SchnorrSignature::from_slice(&c.portal_signature) {
                    Ok(sig) => Some(brrq_portal::SettlementClaim {
                        lock_id: c.lock_id,
                        merchant_secret: c.merchant_secret.clone(),
                        signature: sig,
                        nullifier: c.nullifier,
                        merchant_address: sender,
                    }),
                    Err(e) => {
                        tracing::error!("FOLLOWER DIVERGENCE: batch claim sig invalid: {e}");
                        None
                    }
                }
            }).collect();
            match brrq_portal::batch_settle(escrow, nullifiers, &portal_claims, height) {
                Ok(result) => {
                    if result.total_settled_amount > 0 {
                        let acct = state.get_or_create_account(sender);
                        acct.balance = acct.balance.saturating_add(result.total_settled_amount);
                        state.flush_account(&sender);
                    }
                }
                Err(e) => tracing::error!("FOLLOWER DIVERGENCE: BatchSettle failed: {e}"),
            }
        }
        brrq_types::TransactionKind::CancelPortalLock { lock_id } => {
            match escrow.cancel_lock(lock_id, &sender, height) {
                Ok(amount) => {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_add(amount);
                    state.flush_account(&sender);
                }
                Err(e) => tracing::error!("FOLLOWER DIVERGENCE: CancelPortalLock failed: {e}"),
            }
        }
        brrq_types::TransactionKind::CreateLockPool { slot_amounts, timeout_l2_block } => {
            if let brrq_types::PublicKey::Schnorr(pk) = &tx.public_key {
                for &amount in slot_amounts {
                    if let Err(e) = escrow.register_lock(
                        sender, *pk, amount, brrq_crypto::hash::Hash256::ZERO,
                        brrq_crypto::hash::Hash256::ZERO, *timeout_l2_block, height,
                    ) {
                        tracing::error!("FOLLOWER DIVERGENCE: CreateLockPool slot failed: {e}");
                    }
                }
            }
        }
        brrq_types::TransactionKind::RefillLockPool { slot_amounts, timeout_l2_block } => {
            if let brrq_types::PublicKey::Schnorr(pk) = &tx.public_key {
                for &amount in slot_amounts {
                    if let Err(e) = escrow.register_lock(
                        sender, *pk, amount, brrq_crypto::hash::Hash256::ZERO,
                        brrq_crypto::hash::Hash256::ZERO, *timeout_l2_block, height,
                    ) {
                        tracing::error!("FOLLOWER DIVERGENCE: RefillLockPool slot failed: {e}");
                    }
                }
            }
        }
        brrq_types::TransactionKind::UpdateLockCondition {
            lock_id, condition_hash, nullifier_hash, merchant_address, merchant_pubkey,
        } => {
            if let Err(e) = escrow.update_lock_condition_with_merchant(
                &sender, lock_id, *condition_hash, *nullifier_hash, *merchant_address,
                brrq_crypto::schnorr::SchnorrPublicKey::from_bytes(*merchant_pubkey),
            ) {
                tracing::error!("FOLLOWER DIVERGENCE: UpdateLockCondition failed: {e}");
            }
        }
        _ => {}
    }
}
