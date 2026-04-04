//! Escrow Manager — pure lock registry for Portal locks on L2.
//!
//! ## Architecture
//!
//! The EscrowManager is a **pure lock registry**. It does NOT track balances.
//! All balance operations (deduction, credit, refund) are handled by WorldState
//! in the executor and block builder.
//!
//! ## Invariant
//!
//! `total_escrowed == sum(lock.amount for lock in locks where lock.status == Active)`
//!
//! This invariant is maintained by all mutation methods.

use std::collections::{HashMap, HashSet};

use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_types::Address;
use tracing::{info, warn};

use crate::error::PortalError;
use crate::types::{compute_lock_id, LockStatus, PortalLock, MIN_TIMEOUT_BLOCKS, MAX_TIMEOUT_BLOCKS};

/// Manages Portal escrow locks — pure registry, no balance tracking.
///
/// Balance operations are the responsibility of the caller (WorldState/executor).
/// This struct only tracks lock metadata and the total escrowed amount.
pub struct EscrowManager {
    /// Locks indexed by lock_id.
    locks: HashMap<Hash256, PortalLock>,
    /// Total amount held in active escrow locks (satoshis).
    /// Invariant: equals sum of all Active lock amounts.
    total_escrowed: u64,
    /// Number of currently active locks (O(1) query).
    active_count: usize,
    /// Monotonic lock counter for unique lock_id generation.
    lock_nonce: u64,
    /// Expiry index: timeout_block → set of lock_ids expiring at that block.
    /// Enables O(K log N) expiry scanning instead of O(N) full scan.
    expiry_index: std::collections::BTreeMap<u64, HashSet<Hash256>>,
    /// Per-address active lock count for O(1) cap enforcement.
    address_lock_count: HashMap<Address, usize>,
}

impl EscrowManager {
    /// Create a new empty EscrowManager.
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
            total_escrowed: 0,
            active_count: 0,
            lock_nonce: 0,
            expiry_index: std::collections::BTreeMap::new(),
            address_lock_count: HashMap::new(),
        }
    }

    /// Get total amount held in escrow across all active locks.
    pub fn total_escrowed(&self) -> u64 {
        self.total_escrowed
    }

    /// Get the number of active locks (O(1)).
    pub fn active_lock_count(&self) -> usize {
        self.active_count
    }

    /// Total number of locks in memory.
    /// Terminal locks are now removed immediately, so this
    /// effectively equals active_lock_count() for normal operation.
    /// May differ if locks with terminal status are restored from persistence.
    pub(crate) fn total_lock_count(&self) -> usize {
        self.locks.len()
    }

    /// Register a new escrow lock.
    ///
    /// The caller is responsible for deducting the amount from the user's
    /// balance (via WorldState) BEFORE calling this method.
    ///
    /// This method only:
    /// 1. Validates the lock parameters
    /// 2. Generates a unique lock_id
    /// 3. Records the lock in the registry
    /// 4. Updates total_escrowed
    ///
    /// Returns the lock_id.
    pub fn register_lock(
        &mut self,
        owner: Address,
        owner_pubkey: SchnorrPublicKey,
        amount: u64,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        timeout_l2_block: u64,
        current_block: u64,
    ) -> Result<Hash256, PortalError> {
        // Validate amount (enforce dust limit to prevent micro-lock spam)
        if amount == 0 {
            return Err(PortalError::ZeroAmount);
        }
        // Dynamic minimum = max(dust_limit, duration × cost_per_block).
        // Short locks (1 day): min = max(546, 28800 × 1) = 28,800 sats (~$17)
        // Long locks (1 year): min = max(546, 10.5M × 1) = 10.5M sats (~$6,300)
        // This makes year-long dust spam economically impossible.
        let duration_blocks = timeout_l2_block.saturating_sub(current_block);
        let dynamic_min = std::cmp::max(
            crate::types::MIN_LOCK_AMOUNT,
            duration_blocks.saturating_mul(crate::types::STATE_COST_PER_BLOCK_SAT),
        );
        if amount < dynamic_min {
            return Err(PortalError::InsufficientBalance {
                need: dynamic_min,
                have: amount,
            });
        }

        // Per-address lock cap to prevent state bloat
        // O(1) per-address lock count via cached counter (replaces O(N) scan)
        let owner_lock_count = *self.address_lock_count.get(&owner).unwrap_or(&0);
        if owner_lock_count >= crate::types::MAX_LOCKS_PER_ADDRESS {
            return Err(PortalError::TooManyLocks { max: crate::types::MAX_LOCKS_PER_ADDRESS });
        }

        // Validate timeout
        let remaining = timeout_l2_block.saturating_sub(current_block);
        if remaining < MIN_TIMEOUT_BLOCKS {
            return Err(PortalError::TimeoutTooShort {
                min_blocks: MIN_TIMEOUT_BLOCKS,
                got_blocks: remaining,
            });
        }
        // Reject timeouts that are too far in the future (state bloat prevention)
        if remaining > MAX_TIMEOUT_BLOCKS {
            return Err(PortalError::TimeoutTooLong {
                max_blocks: MAX_TIMEOUT_BLOCKS,
                got_blocks: remaining,
            });
        }

        // Generate unique lock_id (nonce used for uniqueness but NOT incremented yet)
        // Defer nonce increment until all validations pass
        let nonce = self.lock_nonce;
        let lock_id = compute_lock_id(&owner, amount, &condition_hash, timeout_l2_block, nonce);

        // Track total escrowed
        self.total_escrowed = self
            .total_escrowed
            .checked_add(amount)
            .ok_or(PortalError::AmountOverflow)?;

        let lock = PortalLock {
            lock_id,
            owner,
            owner_pubkey,
            amount,
            condition_hash,
            nullifier_hash,
            timeout_l2_block,
            status: LockStatus::Active,
            created_at_block: current_block,
            merchant_address: brrq_types::Address::ZERO, // Set during UpdateLockCondition
            merchant_pubkey: brrq_crypto::schnorr::SchnorrPublicKey::from_bytes([0u8; 32]),
        };

        info!(
            lock_id = %lock_id,
            owner = %owner,
            amount = amount,
            timeout = timeout_l2_block,
            "portal lock registered"
        );

        // Check for lock_id collision before insert
        if self.locks.contains_key(&lock_id) {
            // Rollback total_escrowed on collision
            self.total_escrowed = self.total_escrowed.saturating_sub(amount);
            return Err(PortalError::LockIdCollision(lock_id));
        }
        // Only increment nonce AFTER all validations pass
        self.lock_nonce += 1;
        self.locks.insert(lock_id, lock);
        self.active_count += 1;
        *self.address_lock_count.entry(owner).or_insert(0) += 1;
        self.expiry_index
            .entry(timeout_l2_block)
            .or_default()
            .insert(lock_id);
        Ok(lock_id)
    }

    /// Get a lock by ID.
    pub fn get_lock(&self, lock_id: &Hash256) -> Result<&PortalLock, PortalError> {
        self.locks
            .get(lock_id)
            .ok_or(PortalError::LockNotFound(*lock_id))
    }

    /// Update a lock's condition_hash and nullifier_hash.
    ///
    /// Used when a Lock Pool slot is assigned to a specific payment:
    /// the pool creates locks with placeholder hashes, and this method
    /// sets the real merchant condition before Portal Key generation.
    ///
    /// Only Active locks with ZERO condition_hash can be updated.
    pub(crate) fn update_lock_condition(
        &mut self,
        caller: &Address,
        lock_id: &Hash256,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
    ) -> Result<(), PortalError> {
        self.update_lock_condition_with_merchant(
            caller, lock_id, condition_hash, nullifier_hash,
            brrq_types::Address::ZERO,
            brrq_crypto::schnorr::SchnorrPublicKey::from_bytes([0u8; 32]),
        )
    }

    /// Update lock condition with explicit merchant address binding.
    ///
    /// When merchant_address is non-zero, settlement MUST
    /// credit that address. Prevents front-running on RelayedBatchSettle.
    ///
    /// Caller must be the lock owner. Without this check,
    /// anyone who knows a lock_id could set merchant conditions on someone
    /// else's lock.
    pub fn update_lock_condition_with_merchant(
        &mut self,
        caller: &Address,
        lock_id: &Hash256,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        merchant_address: brrq_types::Address,
        merchant_pubkey: brrq_crypto::schnorr::SchnorrPublicKey,
    ) -> Result<(), PortalError> {
        let lock = self.locks.get_mut(lock_id)
            .ok_or(PortalError::LockNotFound(*lock_id))?;
        // Only the lock owner may update conditions.
        if lock.owner != *caller {
            return Err(PortalError::OwnerMismatch {
                lock_owner: lock.owner.to_brrq_hex(),
                key_owner: caller.to_brrq_hex(),
            });
        }
        if lock.status != LockStatus::Active {
            return Err(PortalError::LockNotActive(*lock_id));
        }
        if !lock.condition_hash.is_zero() {
            return Err(PortalError::LockAlreadySettled(*lock_id));
        }
        lock.condition_hash = condition_hash;
        lock.nullifier_hash = nullifier_hash;
        lock.merchant_address = merchant_address;
        lock.merchant_pubkey = merchant_pubkey;
        Ok(())
    }

    /// Remove lock from expiry_index when it leaves Active state.
    fn remove_from_expiry_index(&mut self, lock_id: &Hash256, timeout: u64) {
        if let Some(ids) = self.expiry_index.get_mut(&timeout) {
            ids.remove(lock_id); // O(1) with HashSet (was O(K) with Vec)
            if ids.is_empty() {
                self.expiry_index.remove(&timeout);
            }
        }
    }

    /// Settle a lock — remove from registry and decrement escrowed total.
    ///
    /// Lock is removed from the HashMap immediately upon settlement.
    /// The lock data is no longer needed once terminal — balance transfers and
    /// nullifier consumption are already done by the caller.
    ///
    /// Returns the lock amount (satoshis) to be credited to the merchant.
    pub fn settle_lock(&mut self, lock_id: &Hash256) -> Result<u64, PortalError> {
        let lock = self.locks.get(lock_id)
            .ok_or(PortalError::LockNotFound(*lock_id))?;
        if lock.status != LockStatus::Active {
            return Err(PortalError::LockNotActive(*lock_id));
        }
        let amount = lock.amount;
        let timeout = lock.timeout_l2_block;
        let owner = lock.owner;
        // Remove lock immediately instead of marking terminal status
        self.locks.remove(lock_id);
        // Halt on invariant violation — never continue with corrupted state.
        // In a financial system, silent corruption is worse than a crash.
        self.total_escrowed = self.total_escrowed.checked_sub(amount)
            .ok_or_else(|| {
                tracing::error!("FATAL: total_escrowed ({}) < amount ({}) in settle_lock", self.total_escrowed, amount);
                PortalError::InvariantViolation
            })?;
        self.active_count = self.active_count.checked_sub(1)
            .ok_or_else(|| {
                tracing::error!("FATAL: active_count underflow in settle_lock");
                PortalError::InvariantViolation
            })?;
        // Decrement per-address lock count
        // Remove entry when count reaches 0 to prevent unbounded HashMap growth
        if let Some(count) = self.address_lock_count.get_mut(&owner) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.address_lock_count.remove(&owner);
            }
        }
        self.remove_from_expiry_index(lock_id, timeout);

        info!(lock_id = %lock_id, amount, "portal lock settled");
        Ok(amount)
    }

    /// Expire a lock — remove from registry and decrement escrowed total.
    ///
    /// Lock is removed from the HashMap immediately upon expiry.
    ///
    /// Returns (owner_address, amount) for the caller to refund.
    pub(crate) fn expire_lock(
        &mut self,
        lock_id: &Hash256,
        current_block: u64,
    ) -> Result<(Address, u64), PortalError> {
        let lock = self.locks.get(lock_id)
            .ok_or(PortalError::LockNotFound(*lock_id))?;
        if lock.status != LockStatus::Active {
            return Err(PortalError::LockNotActive(*lock_id));
        }
        // Expiry delayed by SETTLEMENT_GRACE_BLOCKS.
        // This ensures the merchant has time to settle after sequencer downtime
        // before the user can reclaim funds (prevents double-claim).
        let expiry_threshold = lock.timeout_l2_block.saturating_add(crate::types::SETTLEMENT_GRACE_BLOCKS);
        if current_block <= expiry_threshold {
            return Err(PortalError::LockNotExpired {
                timeout: lock.timeout_l2_block,
                current: current_block,
            });
        }
        let amount = lock.amount;
        let owner = lock.owner;
        let timeout = lock.timeout_l2_block;
        // Remove lock immediately instead of marking terminal status
        self.locks.remove(lock_id);
        // Halt on invariant violation
        self.total_escrowed = self.total_escrowed.checked_sub(amount)
            .ok_or_else(|| {
                tracing::error!("FATAL: total_escrowed ({}) < amount ({}) in expire_lock", self.total_escrowed, amount);
                PortalError::InvariantViolation
            })?;
        self.active_count = self.active_count.checked_sub(1)
            .ok_or_else(|| {
                tracing::error!("FATAL: active_count underflow in expire_lock");
                PortalError::InvariantViolation
            })?;
        // Decrement per-address lock count
        // Remove entry when count reaches 0 to prevent unbounded HashMap growth
        if let Some(count) = self.address_lock_count.get_mut(&owner) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.address_lock_count.remove(&owner);
            }
        }
        self.remove_from_expiry_index(lock_id, timeout);

        info!(lock_id = %lock_id, owner = %owner, amount, "portal lock expired");
        Ok((owner, amount))
    }

    /// Cancel a lock — remove from registry and decrement escrowed total.
    ///
    /// Lock is removed from the HashMap immediately upon cancellation.
    ///
    /// Only the lock owner can cancel. Returns the lock amount for refund.
    pub fn cancel_lock(
        &mut self,
        lock_id: &Hash256,
        caller: &Address,
        current_block: u64,
    ) -> Result<u64, PortalError> {
        let lock = self.locks.get(lock_id)
            .ok_or(PortalError::LockNotFound(*lock_id))?;
        if lock.status != LockStatus::Active {
            return Err(PortalError::LockNotActive(*lock_id));
        }
        if lock.owner != *caller {
            return Err(PortalError::OwnerMismatch {
                lock_owner: lock.owner.to_brrq_hex(),
                key_owner: caller.to_brrq_hex(),
            });
        }
        // Reject cancel if a Portal Key has been issued (condition_hash set).
        // Once a merchant has a Portal Key, the lock can only be settled or expire.
        if !lock.condition_hash.is_zero() {
            return Err(PortalError::LockAlreadySettled(*lock_id));
        }
        // Zero-condition locks (session/pool slots) can only be cancelled
        // after timeout. This prevents a user from cancelling a session lock while
        // a merchant holds valid unsubmitted session receipts.
        // Locks with condition_hash == ZERO are either:
        //   a) Pool slots not yet assigned — safe to cancel anytime (no merchant involved)
        //   b) Session locks with active micropayments — must wait for timeout
        // We use timeout as the universal guard since we cannot distinguish a/b here.
        // The merchant's protection window equals the lock's remaining lifetime.
        // Zero-condition locks must respect SETTLEMENT_GRACE_BLOCKS.
        // Without this, owner can cancel at timeout while merchant still has grace to settle.
        let effective_timeout = if lock.condition_hash.is_zero() {
            lock.timeout_l2_block.saturating_add(crate::types::SETTLEMENT_GRACE_BLOCKS)
        } else {
            lock.timeout_l2_block
        };
        if lock.condition_hash.is_zero() && current_block < effective_timeout {
            // Allow early cancel only if lock was JUST created (within 100 blocks)
            // to handle "oops wrong amount" scenarios without waiting full timeout.
            let early_cancel_window = 100u64;
            if current_block > lock.created_at_block.saturating_add(early_cancel_window) {
                return Err(PortalError::LockNotExpired {
                    timeout: effective_timeout,
                    current: current_block,
                });
            }
        }
        let amount = lock.amount;
        let timeout = lock.timeout_l2_block;
        // Remove lock immediately instead of marking terminal status
        self.locks.remove(lock_id);
        // Halt on invariant violation
        self.total_escrowed = self.total_escrowed.checked_sub(amount)
            .ok_or_else(|| {
                tracing::error!("FATAL: total_escrowed ({}) < amount ({}) in cancel_lock", self.total_escrowed, amount);
                PortalError::InvariantViolation
            })?;
        self.active_count = self.active_count.checked_sub(1)
            .ok_or_else(|| {
                tracing::error!("FATAL: active_count underflow in cancel_lock");
                PortalError::InvariantViolation
            })?;
        // Decrement per-address lock count
        // Remove entry when count reaches 0 to prevent unbounded HashMap growth
        if let Some(count) = self.address_lock_count.get_mut(caller) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.address_lock_count.remove(caller);
            }
        }
        self.remove_from_expiry_index(lock_id, timeout);

        warn!(lock_id = %lock_id, amount, "portal lock cancelled");
        Ok(amount)
    }

    /// Remove a lock from memory (for pruning terminal-state locks).
    ///
    /// Only removes locks in terminal states (Settled, Expired, Cancelled).
    /// Returns true if the lock was removed.
    pub(crate) fn remove_lock(&mut self, lock_id: &Hash256) -> bool {
        if let Some(lock) = self.locks.get(lock_id) {
            if matches!(
                lock.status,
                LockStatus::Settled | LockStatus::Expired | LockStatus::Cancelled
            ) {
                self.locks.remove(lock_id);
                return true;
            }
        }
        false
    }

    /// Recompute total_escrowed from lock data (integrity check).
    ///
    /// Use after deserialization to verify the stored total matches reality.
    pub fn verify_invariant(&self) -> bool {
        // Use checked_add to prevent wrapping on overflow
        let computed: Option<u64> = self
            .locks
            .values()
            .filter(|l| l.status == LockStatus::Active)
            .map(|l| l.amount)
            .try_fold(0u64, |acc, a| acc.checked_add(a));
        match computed {
            Some(total) => total == self.total_escrowed,
            None => {
                tracing::error!("INVARIANT CHECK: overflow computing active lock sum");
                false
            }
        }
    }

    // ── Persistence helpers ─────────────────────────────────────────

    /// Iterator over all locks (for serialization).
    pub fn all_locks(&self) -> impl Iterator<Item = &PortalLock> {
        self.locks.values()
    }

    /// Get the current lock nonce counter.
    pub(crate) fn lock_nonce(&self) -> u64 {
        self.lock_nonce
    }

    /// Restore locks from a snapshot (used by persistence layer).
    /// Rebuilds active_count and expiry_index from restored data.
    pub(crate) fn restore_locks(
        &mut self,
        locks: Vec<PortalLock>,
        _total_escrowed: u64,
        lock_nonce: u64,
    ) {
        self.active_count = 0;
        self.total_escrowed = 0;
        self.expiry_index.clear();
        self.address_lock_count.clear();
        for lock in locks {
            if lock.status == LockStatus::Active {
                self.active_count += 1;
                self.total_escrowed = self.total_escrowed.saturating_add(lock.amount);
                *self.address_lock_count.entry(lock.owner).or_insert(0) += 1;
                self.expiry_index
                    .entry(lock.timeout_l2_block)
                    .or_default()
                    .insert(lock.lock_id);
            }
            self.locks.insert(lock.lock_id, lock);
        }
        self.lock_nonce = lock_nonce;
        debug_assert!(
            self.verify_invariant(),
            "restore_locks: escrow invariant violated after restore"
        );
    }

    /// Get lock IDs eligible for expiry at the given block height.
    ///
    /// Accounts for SETTLEMENT_GRACE_BLOCKS — only returns locks
    /// whose timeout + grace period has passed.
    pub(crate) fn locks_expiring_before(&self, block: u64) -> Vec<Hash256> {
        let mut expired = Vec::new();
        // Only consider locks whose timeout + grace <= block
        let grace = crate::types::SETTLEMENT_GRACE_BLOCKS;
        for (&timeout, ids) in self.expiry_index.range(..) {
            // timeout + grace > block means this lock is still in grace period
            if timeout.saturating_add(grace) >= block {
                // BTreeMap is ordered — all subsequent timeouts are larger
                break;
            }
            for id in ids {
                if let Some(lock) = self.locks.get(id) {
                    if lock.status == LockStatus::Active {
                        expired.push(*id);
                    }
                }
            }
        }
        expired
    }
}

impl Default for EscrowManager {
    fn default() -> Self {
        Self::new()
    }
}
