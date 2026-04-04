//! Lock Pools — pre-funded pools of denomination-specific locks.
//!
//! A Lock Pool allows users to create multiple escrow locks in a single L2
//! transaction, dramatically reducing on-chain overhead. Instead of 10 lock
//! transactions per day, a user creates one pool per week.
//!
//! ## How It Works
//!
//! 1. User calls `create_lock_pool(total_amount, slots: [0.001, 0.01, 0.05, ...])`
//! 2. Single L2 transaction deducts `total_amount` from balance
//! 3. Creates N locks (one per slot denomination) — all Active, ready to use
//! 4. When paying: wallet picks the closest slot >= payment amount, signs Portal Key
//! 5. Consumed slots can be refilled asynchronously (background L2 transaction)
//!
//! ## Scaling Impact
//!
//! Without pools: 1M users × 10 payments/day = 10M lock txs/day
//! With pools:    1M users × 1 pool/week ÷ 7  = 143K pool txs/day (70x reduction)

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::error::PortalError;
use crate::escrow::EscrowManager;
use crate::types::MIN_TIMEOUT_BLOCKS;

/// Maximum number of slots in a single lock pool.
pub const MAX_POOL_SLOTS: usize = 20;

/// A pre-funded pool of denomination-specific Portal locks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LockPool {
    /// Unique pool identifier.
    pub pool_id: Hash256,
    /// Pool owner's L2 address.
    pub owner: Address,
    /// Pool owner's public key.
    pub owner_pubkey: SchnorrPublicKey,
    /// Total amount deposited into the pool (sum of all slots).
    pub total_amount: u64,
    /// Denomination slots — each is a lock amount in satoshis.
    /// Sorted ascending for efficient slot selection.
    pub slots: Vec<PoolSlot>,
    /// L2 block height at which all locks in this pool expire.
    pub timeout_l2_block: u64,
    /// L2 block height when this pool was created.
    pub created_at_block: u64,
}

/// A single slot within a Lock Pool.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolSlot {
    /// The denomination amount in satoshis.
    pub amount: u64,
    /// The lock_id for this slot (created in EscrowManager).
    pub lock_id: Hash256,
    /// Whether this slot has been consumed (Portal Key issued).
    pub consumed: bool,
}

/// Compute a deterministic pool_id.
pub fn compute_pool_id(owner: &Address, total_amount: u64, timeout: u64, nonce: u64) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(brrq_crypto::domain_tags::PORTAL_POOL_V1);
    hasher.update(owner.as_bytes());
    hasher.update(&total_amount.to_le_bytes());
    hasher.update(&timeout.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.finalize()
}

/// Create a Lock Pool — single L2 transaction creating multiple denomination locks.
///
/// Deducts the total amount from the owner's balance and creates one lock per slot.
/// Each lock is Active and ready to be used for Portal Key generation.
///
/// # Arguments
/// - `escrow`: The escrow manager (manages individual locks)
/// - `owner`: The pool owner's L2 address
/// - `owner_pubkey`: The pool owner's public key
/// - `slot_amounts`: Denomination amounts for each slot (in satoshis)
/// - `timeout_l2_block`: Expiry block for all locks in the pool
/// - `current_block`: Current L2 block height
///
/// # Returns
/// The created `LockPool` with all slots initialized.
pub fn create_lock_pool(
    escrow: &mut EscrowManager,
    owner: Address,
    owner_pubkey: SchnorrPublicKey,
    slot_amounts: &[u64],
    timeout_l2_block: u64,
    current_block: u64,
) -> Result<LockPool, PortalError> {
    // Validate slot count
    if slot_amounts.is_empty() {
        return Err(PortalError::EmptyBatch);
    }
    if slot_amounts.len() > MAX_POOL_SLOTS {
        return Err(PortalError::BatchTooLarge {
            size: slot_amounts.len(),
            max: MAX_POOL_SLOTS,
        });
    }

    // Validate all amounts are non-zero
    for &amount in slot_amounts {
        if amount == 0 {
            return Err(PortalError::ZeroAmount);
        }
    }

    // Validate timeout
    let remaining = timeout_l2_block.saturating_sub(current_block);
    if remaining < MIN_TIMEOUT_BLOCKS {
        return Err(PortalError::TimeoutTooShort {
            min_blocks: MIN_TIMEOUT_BLOCKS,
            got_blocks: remaining,
        });
    }

    // Compute total amount (for pool metadata only — balance check is caller's responsibility)
    let total_amount: u64 = slot_amounts
        .iter()
        .try_fold(0u64, |acc, &a| acc.checked_add(a))
        .ok_or(PortalError::AmountOverflow)?;

    // Register individual locks for each slot (pure registry — no balance tracking).
    // The caller (executor/block builder) has already deducted total_amount from WorldState.
    let mut slots = Vec::with_capacity(slot_amounts.len());
    let placeholder_condition = Hash256::ZERO;
    let placeholder_nullifier = Hash256::ZERO;

    for &amount in slot_amounts {
        let lock_id = escrow.register_lock(
            owner,
            owner_pubkey,
            amount,
            placeholder_condition,
            placeholder_nullifier,
            timeout_l2_block,
            current_block,
        )?;
        slots.push(PoolSlot {
            amount,
            lock_id,
            consumed: false,
        });
    }

    // Sort slots by amount ascending for efficient selection
    slots.sort_by_key(|s| s.amount);

    // Generate pool_id
    let pool_nonce = slots
        .first()
        .map(|s| {
            // Use first lock_id bytes as nonce for determinism
            u64::from_le_bytes(s.lock_id.as_bytes()[..8].try_into().unwrap_or([0; 8]))
        })
        .unwrap_or(0);
    let pool_id = compute_pool_id(&owner, total_amount, timeout_l2_block, pool_nonce);

    Ok(LockPool {
        pool_id,
        owner,
        owner_pubkey,
        total_amount,
        slots,
        timeout_l2_block,
        created_at_block: current_block,
    })
}

impl LockPool {
    /// Find the best available slot for a given payment amount.
    ///
    /// Returns the index of the smallest unconsumed slot that is >= the
    /// requested amount. Returns None if no suitable slot is available.
    pub fn find_slot(&self, amount: u64) -> Option<usize> {
        // Slots are sorted ascending — find first unconsumed slot >= amount
        self.slots
            .iter()
            .position(|s| !s.consumed && s.amount >= amount)
    }

    /// Consume a slot (mark as used after Portal Key generation).
    ///
    /// Returns the lock_id of the consumed slot.
    pub fn consume_slot(&mut self, index: usize) -> Result<Hash256, PortalError> {
        let slot = self.slots.get_mut(index).ok_or(PortalError::LockNotFound(Hash256::ZERO))?;
        if slot.consumed {
            return Err(PortalError::LockNotActive(slot.lock_id));
        }
        slot.consumed = true;
        Ok(slot.lock_id)
    }

    /// Number of available (unconsumed) slots.
    pub fn available_slots(&self) -> usize {
        self.slots.iter().filter(|s| !s.consumed).count()
    }

    /// Total amount still available in unconsumed slots.
    pub fn available_amount(&self) -> u64 {
        self.slots
            .iter()
            .filter(|s| !s.consumed)
            .map(|s| s.amount)
            .sum()
    }

    /// Whether all slots have been consumed.
    pub fn is_exhausted(&self) -> bool {
        self.slots.iter().all(|s| s.consumed)
    }

    /// Get the list of slot amounts that need refilling (consumed slots).
    pub fn slots_needing_refill(&self) -> Vec<u64> {
        self.slots
            .iter()
            .filter(|s| s.consumed)
            .map(|s| s.amount)
            .collect()
    }
}

/// Refill consumed slots in a Lock Pool.
///
/// Creates new locks for each consumed slot, effectively "topping up"
/// the pool. This is a separate L2 transaction from the original pool creation.
///
/// Returns the number of slots refilled.
pub fn refill_pool(
    pool: &mut LockPool,
    escrow: &mut EscrowManager,
    current_block: u64,
) -> Result<usize, PortalError> {
    let consumed_indices: Vec<usize> = pool
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.consumed)
        .map(|(i, _)| i)
        .collect();

    if consumed_indices.is_empty() {
        return Ok(0);
    }

    // Validate timeout still has enough remaining blocks
    let remaining = pool.timeout_l2_block.saturating_sub(current_block);
    if remaining < MIN_TIMEOUT_BLOCKS {
        return Err(PortalError::TimeoutTooShort {
            min_blocks: MIN_TIMEOUT_BLOCKS,
            got_blocks: remaining,
        });
    }

    let placeholder_condition = Hash256::ZERO;
    let placeholder_nullifier = Hash256::ZERO;
    let mut refilled = 0;

    for idx in consumed_indices {
        let amount = pool.slots[idx].amount;
        match escrow.register_lock(
            pool.owner,
            pool.owner_pubkey,
            amount,
            placeholder_condition,
            placeholder_nullifier,
            pool.timeout_l2_block,
            current_block,
        ) {
            Ok(new_lock_id) => {
                pool.slots[idx].lock_id = new_lock_id;
                pool.slots[idx].consumed = false;
                refilled += 1;
            }
            Err(PortalError::AmountOverflow)
            | Err(PortalError::TooManyLocks { .. })
            | Err(PortalError::LockIdCollision(_)) => {
                // Stop refilling if escrow total would overflow, lock cap hit, or collision
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(refilled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::SchnorrKeyPair;

    const CURRENT_BLOCK: u64 = 100_000;
    const VALID_TIMEOUT: u64 = CURRENT_BLOCK + MIN_TIMEOUT_BLOCKS + 1_000;

    fn make_user() -> (SchnorrKeyPair, Address) {
        let kp = SchnorrKeyPair::generate();
        let addr = Address::from_public_key(kp.public_key().as_bytes());
        (kp, addr)
    }

    #[test]
    fn test_create_lock_pool_basic() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000, 5_000_000, 10_000_000, 20_000_000];
        let pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        assert_eq!(pool.slots.len(), 5);
        assert_eq!(pool.total_amount, 36_100_000);
        assert_eq!(pool.available_slots(), 5);
        assert!(!pool.is_exhausted());

        assert_eq!(escrow.active_lock_count(), 5);
        assert!(escrow.verify_invariant());
    }

    #[test]
    fn test_create_lock_pool_no_balance_check() {
        // register_lock doesn't check balance — caller's responsibility
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 200_000];
        let result = create_lock_pool(&mut escrow, user_addr, *user_kp.public_key(), &slots, VALID_TIMEOUT, CURRENT_BLOCK);
        assert!(result.is_ok());
        assert_eq!(escrow.total_escrowed(), 300_000);
    }

    #[test]
    fn test_create_lock_pool_empty_slots() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let result = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &[],
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_create_lock_pool_too_many_slots() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots: Vec<u64> = (0..25).map(|_| 1_000).collect(); // 25 > MAX_POOL_SLOTS
        let result = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_find_slot_exact_match() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000, 5_000_000];
        let pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        // Exact match
        assert_eq!(pool.find_slot(1_000_000), Some(1));
        // Needs upgrade to next slot
        assert_eq!(pool.find_slot(500_000), Some(1));
        // Smallest slot works
        assert_eq!(pool.find_slot(50_000), Some(0));
        // Too large for any slot
        assert_eq!(pool.find_slot(10_000_000), None);
    }

    #[test]
    fn test_consume_slot() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000, 5_000_000];
        let mut pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        // Consume the middle slot
        let lock_id = pool.consume_slot(1).unwrap();
        assert!(!lock_id.is_zero());
        assert_eq!(pool.available_slots(), 2);

        // Can't consume same slot twice
        assert!(pool.consume_slot(1).is_err());

        // Consume remaining
        pool.consume_slot(0).unwrap();
        pool.consume_slot(2).unwrap();
        assert!(pool.is_exhausted());
    }

    #[test]
    fn test_refill_pool() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000];
        let mut pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        // Consume both slots
        pool.consume_slot(0).unwrap();
        pool.consume_slot(1).unwrap();
        assert!(pool.is_exhausted());

        // Refill
        let refilled = refill_pool(&mut pool, &mut escrow, CURRENT_BLOCK + 100).unwrap();
        assert_eq!(refilled, 2);
        assert_eq!(pool.available_slots(), 2);
        assert!(!pool.is_exhausted());
    }

    #[test]
    fn test_refill_pool_all_slots() {
        // No balance check, so all slots refill successfully
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000];
        let mut pool = create_lock_pool(&mut escrow, user_addr, *user_kp.public_key(), &slots, VALID_TIMEOUT, CURRENT_BLOCK).unwrap();
        pool.consume_slot(0).unwrap();
        pool.consume_slot(1).unwrap();
        let refilled = refill_pool(&mut pool, &mut escrow, CURRENT_BLOCK + 100).unwrap();
        assert_eq!(refilled, 2);
        assert_eq!(pool.available_slots(), 2);
    }

    #[test]
    fn test_available_amount() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000, 5_000_000];
        let mut pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        assert_eq!(pool.available_amount(), 6_100_000);
        pool.consume_slot(1).unwrap();
        assert_eq!(pool.available_amount(), 5_100_000);
    }

    #[test]
    fn test_slots_needing_refill() {
        let (user_kp, user_addr) = make_user();
        let mut escrow = EscrowManager::new();
        let slots = vec![100_000, 1_000_000, 5_000_000];
        let mut pool = create_lock_pool(
            &mut escrow,
            user_addr,
            *user_kp.public_key(),
            &slots,
            VALID_TIMEOUT,
            CURRENT_BLOCK,
        )
        .unwrap();

        assert!(pool.slots_needing_refill().is_empty());
        pool.consume_slot(0).unwrap();
        pool.consume_slot(2).unwrap();
        assert_eq!(pool.slots_needing_refill(), vec![100_000, 5_000_000]);
    }
}
