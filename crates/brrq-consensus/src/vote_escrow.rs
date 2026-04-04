//! Vote Escrow — prevents flash-loan governance attacks.
//!
//! ## Design (Article 9.2)
//!
//! Flash-loan governance attack vector:
//! 1. Borrow BTC on another chain
//! 2. Peg-in to brqBTC
//! 3. Vote on a governance proposal
//! 4. Immediately peg-out and return the loan
//!
//! Vote Escrow breaks this by locking the voter's balance for a minimum
//! period after casting a vote. This ensures the voter has genuine economic
//! skin-in-the-game for the duration of the proposal's execution.

use std::collections::HashMap;

use brrq_types::Address;

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Lock duration after voting: 7 days at 3s/block.
///
/// This exceeds the voting period, ensuring the voter's balance is locked
/// until the proposal is finalized and enters the time-lock phase.
pub const VOTE_ESCROW_BLOCKS: u64 = 201_600;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// An active escrow lock on a voter's balance.
#[derive(Debug, Clone)]
pub struct EscrowLock {
    /// The locked amount in satoshis.
    pub amount: u64,
    /// Block height when the lock was created.
    pub locked_at: u64,
    /// Block height when the lock expires.
    pub expires_at: u64,
}

/// Manages vote escrow locks to prevent flash-loan governance attacks.
///
/// When a user votes on a governance proposal, their brqBTC balance
/// is locked for `VOTE_ESCROW_BLOCKS` after the vote. During this
/// period, the user cannot:
/// - Peg-out (withdraw to Bitcoin L1)
/// - Transfer their brqBTC
///
/// The user CAN:
/// - Vote on other proposals (extends the lock if needed)
/// - Rage Quit (which overrides the escrow — exit right is sacred)
/// - Delegate/undelegate (staking operations are not affected)
#[derive(Debug, Clone)]
pub struct VoteEscrowManager {
    /// Active escrow locks keyed by voter address.
    ///
    /// Each address has at most one lock at a time. Voting again
    /// extends the lock if the new expiry is later than the current one.
    pub locks: HashMap<Address, EscrowLock>,
}

impl Default for VoteEscrowManager {
    fn default() -> Self {
        Self::new()
    }
}

impl VoteEscrowManager {
    pub fn new() -> Self {
        Self {
            locks: HashMap::new(),
        }
    }

    /// Lock a voter's balance after casting a vote.
    ///
    /// If the voter already has an active lock, the lock is extended
    /// to whichever expiry is later (the existing one or the new one).
    pub fn lock_after_vote(&mut self, voter: Address, amount: u64, current_height: u64) {
        let new_expires = current_height.saturating_add(VOTE_ESCROW_BLOCKS);

        match self.locks.get_mut(&voter) {
            Some(existing) => {
                // Extend lock if new expiry is later
                if new_expires > existing.expires_at {
                    existing.expires_at = new_expires;
                }
                // Update amount to the latest balance
                existing.amount = amount;
            }
            None => {
                self.locks.insert(
                    voter,
                    EscrowLock {
                        amount,
                        locked_at: current_height,
                        expires_at: new_expires,
                    },
                );
            }
        }
    }

    /// Check if an address has an active escrow lock.
    ///
    /// Returns `true` if the voter's balance is currently locked and
    /// they cannot withdraw or transfer.
    pub fn is_locked(&self, address: &Address, current_height: u64) -> bool {
        self.locks
            .get(address)
            .map(|lock| current_height < lock.expires_at)
            .unwrap_or(false)
    }

    /// Check if a withdrawal is allowed for this address.
    ///
    /// Returns an error if the address has an active escrow lock.
    /// Exception: Rage Quit overrides escrow (exit right is sacred).
    pub fn check_withdrawal(
        &self,
        address: &Address,
        current_height: u64,
        is_rage_quit: bool,
    ) -> Result<(), ConsensusError> {
        // Rage Quit overrides escrow — Law 3 (Unconditional Exit Right)
        if is_rage_quit {
            return Ok(());
        }

        if self.is_locked(address, current_height) {
            let lock = self.locks.get(address).unwrap();
            let remaining = lock.expires_at.saturating_sub(current_height);
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "withdrawal blocked by vote escrow: {} blocks remaining \
                     (vote escrow prevents flash-loan governance attacks). \
                     Rage Quit is exempt from escrow.",
                    remaining,
                ),
            });
        }

        Ok(())
    }

    /// Get remaining lock duration for an address (0 if not locked).
    pub fn remaining_blocks(&self, address: &Address, current_height: u64) -> u64 {
        self.locks
            .get(address)
            .map(|lock| lock.expires_at.saturating_sub(current_height))
            .unwrap_or(0)
    }

    /// Clean up expired locks.
    pub fn cleanup(&mut self, current_height: u64) {
        self.locks
            .retain(|_, lock| current_height < lock.expires_at);
    }

    /// Process block — periodic cleanup of expired locks.
    ///
    /// Called every epoch boundary to keep memory bounded.
    pub fn process_epoch_boundary(&mut self, current_height: u64) {
        self.cleanup(current_height);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = val;
        Address(bytes)
    }

    #[test]
    fn lock_after_vote() {
        let mut mgr = VoteEscrowManager::new();
        let alice = addr(1);

        mgr.lock_after_vote(alice, 1_000_000, 1000);
        assert!(mgr.is_locked(&alice, 1000));
        assert!(mgr.is_locked(&alice, 1000 + VOTE_ESCROW_BLOCKS - 1));
        assert!(!mgr.is_locked(&alice, 1000 + VOTE_ESCROW_BLOCKS));
    }

    #[test]
    fn lock_extends_on_second_vote() {
        let mut mgr = VoteEscrowManager::new();
        let alice = addr(1);

        mgr.lock_after_vote(alice, 1_000_000, 1000);
        let first_expires = 1000 + VOTE_ESCROW_BLOCKS;

        // Vote again later
        mgr.lock_after_vote(alice, 1_000_000, 50_000);
        let second_expires = 50_000 + VOTE_ESCROW_BLOCKS;

        // First lock would have expired, but second extends it
        assert!(second_expires > first_expires);
        assert!(mgr.is_locked(&alice, first_expires + 1));
        assert!(!mgr.is_locked(&alice, second_expires));
    }

    #[test]
    fn withdrawal_blocked_during_escrow() {
        let mut mgr = VoteEscrowManager::new();
        let alice = addr(1);

        mgr.lock_after_vote(alice, 1_000_000, 1000);

        let err = mgr.check_withdrawal(&alice, 2000, false).unwrap_err();
        assert!(err.to_string().contains("vote escrow"));
    }

    #[test]
    fn rage_quit_overrides_escrow() {
        let mut mgr = VoteEscrowManager::new();
        let alice = addr(1);

        mgr.lock_after_vote(alice, 1_000_000, 1000);

        // Normal withdrawal blocked
        assert!(mgr.check_withdrawal(&alice, 2000, false).is_err());

        // Rage Quit is exempt — Law 3 (Unconditional Exit Right)
        assert!(mgr.check_withdrawal(&alice, 2000, true).is_ok());
    }

    #[test]
    fn no_lock_no_restriction() {
        let mgr = VoteEscrowManager::new();
        let alice = addr(1);

        assert!(!mgr.is_locked(&alice, 1000));
        assert!(mgr.check_withdrawal(&alice, 1000, false).is_ok());
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut mgr = VoteEscrowManager::new();
        mgr.lock_after_vote(addr(1), 100, 1000);
        mgr.lock_after_vote(addr(2), 200, 1000);

        assert_eq!(mgr.locks.len(), 2);

        mgr.cleanup(1000 + VOTE_ESCROW_BLOCKS + 1);

        assert_eq!(mgr.locks.len(), 0);
    }

    #[test]
    fn remaining_blocks_calculation() {
        let mut mgr = VoteEscrowManager::new();
        let alice = addr(1);

        mgr.lock_after_vote(alice, 100, 1000);

        assert_eq!(mgr.remaining_blocks(&alice, 1000), VOTE_ESCROW_BLOCKS);
        assert_eq!(
            mgr.remaining_blocks(&alice, 1000 + 50_000),
            VOTE_ESCROW_BLOCKS - 50_000
        );
        assert_eq!(
            mgr.remaining_blocks(&addr(99), 1000),
            0 // unknown address
        );
    }
}
