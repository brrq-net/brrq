//! Portal maintenance — lock pruning, expiry scanning, and health checks.
//!
//! Periodic maintenance tasks that keep the Portal state clean and efficient:
//! - **Expiry scanning**: Auto-expire locks past their timeout block
//! - **Lock pruning**: Remove settled/expired/cancelled locks from memory
//! - **Nullifier compaction**: Prune nullifiers for locks that no longer exist
//! - **Health reporting**: Metrics about Portal state

use brrq_crypto::hash::Hash256;

use crate::escrow::EscrowManager;
use crate::nullifier::NullifierSet;
use crate::types::LockStatus;

/// A refund to be credited to an owner's WorldState balance.
#[derive(Debug, Clone)]
pub struct PendingRefund {
    /// Owner address to credit.
    pub owner: brrq_types::Address,
    /// Amount to refund in satoshis.
    pub amount: u64,
    /// Lock ID that was expired.
    pub lock_id: Hash256,
}

/// Result of a maintenance sweep.
#[derive(Debug, Default)]
pub struct MaintenanceResult {
    /// Number of locks auto-expired (funds returned to owners).
    pub locks_expired: u64,
    /// Refunds that MUST be applied to WorldState by the caller.
    /// If these are not applied, user funds are permanently lost.
    pub refunds: Vec<PendingRefund>,
    /// Number of settled/expired/cancelled locks pruned from memory.
    pub locks_pruned: u64,
    /// Errors encountered during maintenance.
    pub errors: Vec<String>,
}

/// Scan for expired locks and auto-expire them (return funds to owners).
///
/// This should be called periodically (e.g., every block) to ensure
/// expired locks are cleaned up and funds are returned.
pub fn scan_and_expire_locks(
    escrow: &mut EscrowManager,
    current_block: u64,
) -> MaintenanceResult {
    let mut result = MaintenanceResult::default();

    // Use expiry index for O(K log N) scan instead of O(N) full scan.
    // Falls back to the lock's own status check (lock may have been settled/cancelled).
    let expired_ids = escrow.locks_expiring_before(current_block);

    for lock_id in expired_ids {
        match escrow.expire_lock(&lock_id, current_block) {
            Ok((owner, amount)) => {
                result.locks_expired += 1;
                result.refunds.push(PendingRefund {
                    owner,
                    amount,
                    lock_id,
                });
            }
            Err(e) => result.errors.push(format!("expire {}: {}", lock_id, e)),
        }
    }

    result
}

/// Prune non-active locks from memory to bound memory usage.
///
/// Removes locks in terminal states (Settled, Expired, Cancelled) that are
/// older than `retention_blocks` blocks. These locks are no longer needed
/// for protocol operation — their effects are committed to WorldState.
///
/// In production, pruned locks would be archived to persistent storage
/// before removal for audit trail purposes.
pub fn prune_old_locks(
    escrow: &mut EscrowManager,
    current_block: u64,
    retention_blocks: u64,
) -> u64 {
    let cutoff = current_block.saturating_sub(retention_blocks);

    let prunable_ids: Vec<Hash256> = escrow
        .all_locks()
        .filter(|lock| {
            matches!(
                lock.status,
                LockStatus::Settled | LockStatus::Expired | LockStatus::Cancelled
            ) && lock.created_at_block < cutoff
        })
        .map(|lock| lock.lock_id)
        .collect();

    let count = prunable_ids.len() as u64;
    for id in prunable_ids {
        escrow.remove_lock(&id);
    }
    count
}

/// Portal health metrics snapshot.
#[derive(Debug, Clone)]
pub struct PortalHealth {
    /// Number of active (unsettled, unexpired) locks.
    pub active_locks: usize,
    /// Number of settled locks still in memory.
    pub settled_locks: usize,
    /// Number of expired locks still in memory.
    pub expired_locks: usize,
    /// Number of cancelled locks still in memory.
    pub cancelled_locks: usize,
    /// Total amount currently held in escrow (satoshis).
    pub total_escrowed: u64,
    /// Number of consumed nullifiers.
    pub nullifiers_consumed: usize,
    /// Total number of unique addresses with escrowed funds.
    pub unique_owners: usize,
}

/// Compute Portal health metrics.
pub fn compute_health(escrow: &EscrowManager, nullifiers: &NullifierSet) -> PortalHealth {
    let mut active = 0;
    let mut settled = 0;
    let mut expired = 0;
    let mut cancelled = 0;
    let mut owners = std::collections::HashSet::new();

    for lock in escrow.all_locks() {
        match lock.status {
            LockStatus::Active => {
                active += 1;
                owners.insert(lock.owner);
            }
            LockStatus::Settled => settled += 1,
            LockStatus::Expired => expired += 1,
            LockStatus::Cancelled => cancelled += 1,
        }
    }

    PortalHealth {
        active_locks: active,
        settled_locks: settled,
        expired_locks: expired,
        cancelled_locks: cancelled,
        total_escrowed: escrow.total_escrowed(),
        nullifiers_consumed: nullifiers.len(),
        unique_owners: owners.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;
    use brrq_crypto::schnorr::SchnorrKeyPair;
    use brrq_types::Address;
    use crate::types::MIN_TIMEOUT_BLOCKS;

    const CURRENT_BLOCK: u64 = 100_000;
    const VALID_TIMEOUT: u64 = CURRENT_BLOCK + MIN_TIMEOUT_BLOCKS + 1_000;
    const GRACE: u64 = crate::types::SETTLEMENT_GRACE_BLOCKS;

    fn make_user() -> (SchnorrKeyPair, Address) {
        let kp = SchnorrKeyPair::generate();
        let addr = Address::from_public_key(kp.public_key().as_bytes());
        (kp, addr)
    }

    #[test]
    fn test_scan_and_expire() {
        let (kp, addr) = make_user();
        let mut escrow = EscrowManager::new();

        // Create 3 locks with different timeouts
        let _l1 = escrow.register_lock(
            addr, *kp.public_key(), 100_000, Hasher::hash(b"a"),
            Hash256::ZERO, VALID_TIMEOUT, CURRENT_BLOCK,
        ).unwrap();

        let short_timeout = CURRENT_BLOCK + MIN_TIMEOUT_BLOCKS + 100;
        let _l2 = escrow.register_lock(
            addr, *kp.public_key(), 200_000, Hasher::hash(b"b"),
            Hash256::ZERO, short_timeout, CURRENT_BLOCK,
        ).unwrap();

        // Scan at a future block past the short timeout
        let result = scan_and_expire_locks(&mut escrow, short_timeout + GRACE + 1);
        assert_eq!(result.locks_expired, 1);
        assert_eq!(result.errors.len(), 0);

        // The other lock is still active
        assert_eq!(escrow.active_lock_count(), 1);
    }

    #[test]
    fn test_prune_old_locks() {
        let (kp, addr) = make_user();
        let mut escrow = EscrowManager::new();

        // Use zero condition_hash so cancel is allowed (C-2: cancel blocked after Portal Key issued)
        let lock_id = escrow.register_lock(
            addr, *kp.public_key(), 100_000, Hash256::ZERO,
            Hash256::ZERO, VALID_TIMEOUT, CURRENT_BLOCK,
        ).unwrap();

        // Cancel the lock (allowed because condition_hash is zero)
        escrow.cancel_lock(&lock_id, &addr, 100_000).unwrap();

        // Prune with retention of 1000 blocks
        let pruned = prune_old_locks(&mut escrow, CURRENT_BLOCK + 2000, 1000);
        // Cancelled locks removed immediately — 0 remain for pruning
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_health_metrics() {
        let (kp, addr) = make_user();
        let mut escrow = EscrowManager::new();
        let nullifiers = NullifierSet::new();

        escrow.register_lock(
            addr, *kp.public_key(), 100_000, Hasher::hash(b"d"),
            Hash256::ZERO, VALID_TIMEOUT, CURRENT_BLOCK,
        ).unwrap();

        let health = compute_health(&escrow, &nullifiers);
        assert_eq!(health.active_locks, 1);
        assert_eq!(health.settled_locks, 0);
        assert_eq!(health.total_escrowed, 100_000);
        assert_eq!(health.unique_owners, 1);
    }
}
