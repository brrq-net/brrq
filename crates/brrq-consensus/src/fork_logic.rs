//! Fork Logic — soft fork and hard fork activation management.
//!
//! ## Design (Articles 13-15)
//!
//! ### Soft Fork (backward-compatible)
//! - Requires TechnicalUpdate approval (67% sequencers)
//! - 80% miner signaling over 4 epochs
//! - 7-day time-lock
//!
//! ### Hard Fork (breaking change)
//! - Requires ConsensusChange(breaking: true) or Constitutional
//! - 80/80 or 90/90 approval from both chambers
//! - 90% sequencer signaling over 8 epochs
//! - 28-56 day time-lock with Rage Quit
//! - If >33% Rage Quit → fork cancelled
//!
//! ### Emergency Fork
//! - EmergencyPatch with CVE reference
//! - 5/7 Technical Council + 80% sequencers
//! - 72-hour reduced time-lock
//! - Mandatory 30-day post-activation review

use std::collections::HashMap;

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Soft fork signaling threshold: 80% of sequencers.
pub const SOFT_FORK_SIGNALING_BP: u64 = 8_000;

/// Hard fork signaling threshold: 90% of sequencers.
pub const HARD_FORK_SIGNALING_BP: u64 = 9_000;

/// Soft fork signaling window: 4 epochs.
pub const SOFT_FORK_SIGNALING_EPOCHS: u64 = 4;

/// Hard fork signaling window: 8 epochs.
pub const HARD_FORK_SIGNALING_EPOCHS: u64 = 8;

/// Re-export epoch length from the canonical source (epoch.rs).
pub use crate::epoch::DEFAULT_EPOCH_LENGTH as EPOCH_LENGTH_BLOCKS;

/// Maximum signaling attempts before permanent failure.
pub const MAX_SIGNALING_ATTEMPTS: u8 = 2;

/// Deprecation window for old version after hard fork: 6 months.
pub const DEPRECATION_WINDOW_BLOCKS: u64 = 2_592_000;

/// Post-activation review deadline for emergency forks: 30 days.
pub const EMERGENCY_REVIEW_DEADLINE: u64 = 864_000;

/// Maximum emergency forks per 6-month window.
pub const MAX_EMERGENCY_FORKS_PER_WINDOW: u8 = 3;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Type of protocol fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkType {
    /// Backward-compatible change.
    Soft,
    /// Breaking change — old nodes reject new blocks.
    Hard,
    /// Emergency security patch.
    Emergency,
}

/// Current state of a fork activation process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkState {
    /// Proposal approved, waiting for time-lock to expire.
    PendingTimeLock,
    /// Time-lock expired, signaling window is open.
    Signaling,
    /// Enough signals received — locked in for activation.
    LockedIn,
    /// Fork is active on the network.
    Active,
    /// Signaling failed — not enough support.
    Failed,
    /// Cancelled by Rage Quit or other mechanism.
    Cancelled,
}

/// A fork activation entry.
#[derive(Debug, Clone)]
pub struct ForkActivation {
    /// The governance proposal that triggered this fork.
    pub proposal_id: Hash256,
    /// Type of fork.
    pub fork_type: ForkType,
    /// Current state.
    pub state: ForkState,
    /// Code hash of the new version.
    pub code_hash: Hash256,
    /// Activation epoch (when the fork takes effect).
    pub activation_epoch: Option<u64>,
    /// Block height when signaling window opened.
    pub signaling_start: u64,
    /// Block height when signaling window closes.
    pub signaling_end: u64,
    /// Sequencers who have signaled support, keyed by address.
    pub signals: HashMap<Address, u64>, // address → signal block height
    /// Total effective stake that has signaled.
    pub signaled_stake: u64,
    /// Snapshot of total effective stake at signaling start.
    pub total_stake_snapshot: u64,
    /// Number of signaling attempts (max 2 for soft forks).
    pub attempt: u8,
    /// For emergency forks: post-activation review deadline.
    pub review_deadline: Option<u64>,
    /// For emergency forks: whether the review has occurred.
    pub review_completed: bool,
}

// ═══════════════════════════════════════════════════════════════
// ForkManager
// ═══════════════════════════════════════════════════════════════

/// Manages fork activation processes.
#[derive(Debug, Clone)]
pub struct ForkManager {
    /// Active fork activations keyed by proposal ID.
    pub activations: HashMap<Hash256, ForkActivation>,
    /// Count of emergency forks in the current 6-month window.
    pub emergency_fork_count: u8,
    /// Start block of the current 6-month emergency window.
    pub emergency_window_start: u64,
}

impl Default for ForkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ForkManager {
    pub fn new() -> Self {
        Self {
            activations: HashMap::new(),
            emergency_fork_count: 0,
            emergency_window_start: 0,
        }
    }

    /// Initiate a fork activation process after time-lock expires.
    pub fn initiate_fork(
        &mut self,
        proposal_id: Hash256,
        fork_type: ForkType,
        code_hash: Hash256,
        current_height: u64,
        total_effective_stake: u64,
    ) -> Result<(), ConsensusError> {
        if self.activations.contains_key(&proposal_id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("fork activation already exists for {}", proposal_id),
            });
        }

        // Emergency fork rate limit
        if fork_type == ForkType::Emergency {
            self.check_emergency_rate_limit(current_height)?;
        }

        let signaling_epochs = match fork_type {
            ForkType::Soft => SOFT_FORK_SIGNALING_EPOCHS,
            ForkType::Hard => HARD_FORK_SIGNALING_EPOCHS,
            ForkType::Emergency => 1, // Emergency: 1 epoch signaling
        };

        let signaling_window = signaling_epochs.saturating_mul(EPOCH_LENGTH_BLOCKS);

        let activation = ForkActivation {
            proposal_id,
            fork_type,
            state: ForkState::Signaling,
            code_hash,
            activation_epoch: None,
            signaling_start: current_height,
            signaling_end: current_height.saturating_add(signaling_window),
            signals: HashMap::new(),
            signaled_stake: 0,
            total_stake_snapshot: total_effective_stake,
            attempt: 1,
            review_deadline: if fork_type == ForkType::Emergency {
                Some(
                    current_height
                        .saturating_add(signaling_window)
                        .saturating_add(EMERGENCY_REVIEW_DEADLINE),
                )
            } else {
                None
            },
            review_completed: false,
        };

        self.activations.insert(proposal_id, activation);

        if fork_type == ForkType::Emergency {
            self.emergency_fork_count += 1;
        }

        Ok(())
    }

    /// Record a sequencer's signal of support for a fork.
    ///
    /// The caller MUST pass the validator's effective stake at the time the
    /// fork was initiated (snapshot height), NOT the current stake. This
    /// prevents stake-splitting attacks where a validator votes, moves stake
    /// to a new address, and votes again to inflate signaled_stake beyond
    /// the snapshot total.
    pub fn signal_support(
        &mut self,
        proposal_id: &Hash256,
        sequencer: Address,
        effective_stake: u64,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let activation =
            self.activations
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no fork activation for {}", proposal_id),
                })?;

        if activation.state != ForkState::Signaling {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "fork is not in signaling state (current: {:?})",
                    activation.state
                ),
            });
        }

        if current_height > activation.signaling_end {
            return Err(ConsensusError::InvalidBlock {
                reason: "signaling window has closed".to_string(),
            });
        }

        // No double signaling
        if activation.signals.contains_key(&sequencer) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("sequencer {} has already signaled", sequencer),
            });
        }

        // Reject any single validator claiming more stake than the total
        // snapshot. This catches obvious inflation attempts.
        if effective_stake > activation.total_stake_snapshot {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "claimed stake {} exceeds total snapshot {}",
                    effective_stake, activation.total_stake_snapshot,
                ),
            });
        }

        // Cap accumulated signaled_stake at total_stake_snapshot. Even if
        // individual stakes are valid, their sum must not exceed the snapshot
        // total — prevents inflation via stake movement during the signaling
        // window.
        let new_signaled = activation.signaled_stake.saturating_add(effective_stake);
        if new_signaled > activation.total_stake_snapshot {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "total signaled stake {} would exceed snapshot {} — possible stake-splitting attack",
                    new_signaled, activation.total_stake_snapshot,
                ),
            });
        }

        activation.signals.insert(sequencer, current_height);
        activation.signaled_stake = new_signaled;

        Ok(())
    }

    /// Process block — check signaling windows and transition states.
    ///
    /// Returns list of proposal IDs that are now locked-in for activation.
    pub fn process_block(&mut self, current_height: u64) -> Vec<Hash256> {
        let mut locked_in = Vec::new();

        for (id, activation) in self.activations.iter_mut() {
            if activation.state != ForkState::Signaling {
                continue;
            }

            // Check if signaling window has closed
            if current_height < activation.signaling_end {
                continue;
            }

            // Calculate signaling percentage
            let threshold_bp = match activation.fork_type {
                ForkType::Soft => SOFT_FORK_SIGNALING_BP,
                ForkType::Hard => HARD_FORK_SIGNALING_BP,
                ForkType::Emergency => SOFT_FORK_SIGNALING_BP, // 80% for emergency
            };

            let signaled_bp = if activation.total_stake_snapshot > 0 {
                activation.signaled_stake.saturating_mul(10_000) / activation.total_stake_snapshot
            } else {
                0
            };

            if signaled_bp >= threshold_bp {
                // Lock in — set activation at next epoch boundary
                activation.state = ForkState::LockedIn;
                let next_epoch = (current_height / EPOCH_LENGTH_BLOCKS + 1) * EPOCH_LENGTH_BLOCKS;
                activation.activation_epoch = Some(next_epoch / EPOCH_LENGTH_BLOCKS);
                locked_in.push(*id);
            } else {
                // Not enough signals
                if activation.attempt >= MAX_SIGNALING_ATTEMPTS
                    || activation.fork_type == ForkType::Emergency
                {
                    // Final failure
                    activation.state = ForkState::Failed;
                } else {
                    // Retry: reset signaling for next attempt
                    activation.attempt += 1;
                    activation.signals.clear();
                    activation.signaled_stake = 0;
                    activation.signaling_start = current_height;

                    let signaling_epochs = match activation.fork_type {
                        ForkType::Soft => SOFT_FORK_SIGNALING_EPOCHS,
                        ForkType::Hard => HARD_FORK_SIGNALING_EPOCHS,
                        ForkType::Emergency => 1,
                    };
                    let window = signaling_epochs.saturating_mul(EPOCH_LENGTH_BLOCKS);
                    activation.signaling_end = current_height.saturating_add(window);
                }
            }
        }

        locked_in
    }

    /// Activate a locked-in fork at the appropriate epoch boundary.
    pub fn activate_fork(
        &mut self,
        proposal_id: &Hash256,
        current_epoch: u64,
    ) -> Result<(), ConsensusError> {
        let activation =
            self.activations
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no fork activation for {}", proposal_id),
                })?;

        if activation.state != ForkState::LockedIn {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("fork is not locked-in (current: {:?})", activation.state),
            });
        }

        if let Some(target_epoch) = activation.activation_epoch
            && current_epoch < target_epoch
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "activation epoch not reached: current={}, target={}",
                    current_epoch, target_epoch,
                ),
            });
        }

        activation.state = ForkState::Active;
        Ok(())
    }

    /// Cancel a fork (e.g., due to Rage Quit exceeding threshold).
    pub fn cancel_fork(&mut self, proposal_id: &Hash256) -> Result<(), ConsensusError> {
        let activation =
            self.activations
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no fork activation for {}", proposal_id),
                })?;

        if activation.state == ForkState::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: "cannot cancel an already-active fork".to_string(),
            });
        }

        activation.state = ForkState::Cancelled;
        Ok(())
    }

    /// Cancel forks whose associated time-lock was cancelled by Rage Quit exodus.
    ///
    /// The node layer should call this after `timelock.process_block()`. For each
    /// fork in Signaling or LockedIn state, if the associated time-lock has been
    /// cancelled by exodus (>33% rage quit), the fork is also cancelled.
    ///
    /// Returns the list of proposal IDs that were cancelled.
    pub fn cancel_if_exodus(
        &mut self,
        timelock: &crate::timelock::TimeLockManager,
    ) -> Vec<Hash256> {
        let mut cancelled = Vec::new();

        for (id, activation) in self.activations.iter_mut() {
            // Only cancel forks that are still in progress
            if activation.state != ForkState::Signaling && activation.state != ForkState::LockedIn {
                continue;
            }

            // Check if the associated time-lock was cancelled by exodus
            if let Some(entry) = timelock.active_locks.get(id)
                && entry.status == crate::timelock::TimeLockStatus::CancelledByExodus
            {
                activation.state = ForkState::Cancelled;
                cancelled.push(*id);
            }
        }

        cancelled
    }

    /// Check emergency fork rate limit (max 3 per 6-month window).
    fn check_emergency_rate_limit(&mut self, current_height: u64) -> Result<(), ConsensusError> {
        // Reset window if 6 months have passed
        let window_duration = DEPRECATION_WINDOW_BLOCKS; // Reuse 6-month constant
        if current_height >= self.emergency_window_start.saturating_add(window_duration) {
            self.emergency_window_start = current_height;
            self.emergency_fork_count = 0;
        }

        if self.emergency_fork_count >= MAX_EMERGENCY_FORKS_PER_WINDOW {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "emergency fork rate limit reached ({}/{} this window)",
                    self.emergency_fork_count, MAX_EMERGENCY_FORKS_PER_WINDOW,
                ),
            });
        }

        Ok(())
    }

    /// Get signaling progress for a fork (in basis points).
    pub fn signaling_progress_bp(&self, proposal_id: &Hash256) -> Option<u64> {
        self.activations.get(proposal_id).map(|a| {
            if a.total_stake_snapshot == 0 {
                return 0;
            }
            a.signaled_stake.saturating_mul(10_000) / a.total_stake_snapshot
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(val: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        Hash256(bytes)
    }

    fn code(val: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[31] = val;
        Hash256(bytes)
    }

    fn seq(val: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = val;
        Address(bytes)
    }

    #[test]
    fn soft_fork_signaling_and_lockin() {
        let mut mgr = ForkManager::new();
        let total_stake = 100_000_000_000u64; // 1000 BTC total

        mgr.initiate_fork(pid(1), ForkType::Soft, code(1), 0, total_stake)
            .unwrap();

        // Signal 80% of stake
        for i in 0..80 {
            mgr.signal_support(&pid(1), seq(i), total_stake / 100, i as u64 * 10)
                .unwrap();
        }

        // Process after signaling window
        let signaling_end = SOFT_FORK_SIGNALING_EPOCHS * EPOCH_LENGTH_BLOCKS;
        let locked = mgr.process_block(signaling_end);
        assert_eq!(locked.len(), 1);

        let activation = mgr.activations.get(&pid(1)).unwrap();
        assert_eq!(activation.state, ForkState::LockedIn);
    }

    #[test]
    fn soft_fork_signaling_failure_retries() {
        let mut mgr = ForkManager::new();
        let total_stake = 100_000_000_000u64;

        mgr.initiate_fork(pid(1), ForkType::Soft, code(1), 0, total_stake)
            .unwrap();

        // Only 50% signals — not enough
        for i in 0..50 {
            mgr.signal_support(&pid(1), seq(i), total_stake / 100, i as u64 * 10)
                .unwrap();
        }

        let signaling_end = SOFT_FORK_SIGNALING_EPOCHS * EPOCH_LENGTH_BLOCKS;
        let locked = mgr.process_block(signaling_end);
        assert!(locked.is_empty());

        // Should retry (attempt 2)
        let activation = mgr.activations.get(&pid(1)).unwrap();
        assert_eq!(activation.state, ForkState::Signaling);
        assert_eq!(activation.attempt, 2);
    }

    #[test]
    fn soft_fork_permanent_failure_after_two_attempts() {
        let mut mgr = ForkManager::new();
        let total_stake = 100_000_000_000u64;

        mgr.initiate_fork(pid(1), ForkType::Soft, code(1), 0, total_stake)
            .unwrap();

        // Fail attempt 1
        let end1 = SOFT_FORK_SIGNALING_EPOCHS * EPOCH_LENGTH_BLOCKS;
        mgr.process_block(end1);

        // Fail attempt 2
        let end2 = end1 + SOFT_FORK_SIGNALING_EPOCHS * EPOCH_LENGTH_BLOCKS;
        mgr.process_block(end2);

        let activation = mgr.activations.get(&pid(1)).unwrap();
        assert_eq!(activation.state, ForkState::Failed);
    }

    #[test]
    fn hard_fork_needs_90_percent() {
        let mut mgr = ForkManager::new();
        let total_stake = 100_000_000_000u64;

        mgr.initiate_fork(pid(1), ForkType::Hard, code(1), 0, total_stake)
            .unwrap();

        // 85% — not enough for hard fork
        for i in 0..85 {
            mgr.signal_support(&pid(1), seq(i), total_stake / 100, i as u64 * 10)
                .unwrap();
        }

        let signaling_end = HARD_FORK_SIGNALING_EPOCHS * EPOCH_LENGTH_BLOCKS;
        let locked = mgr.process_block(signaling_end);
        assert!(locked.is_empty());
    }

    #[test]
    fn emergency_fork_rate_limit() {
        let mut mgr = ForkManager::new();
        let total_stake = 100_000_000_000u64;

        // Use up the 3 emergency forks
        for i in 0..3 {
            mgr.initiate_fork(
                pid(i),
                ForkType::Emergency,
                code(i),
                i as u64 * 100,
                total_stake,
            )
            .unwrap();
        }

        // 4th should fail
        let err = mgr
            .initiate_fork(pid(10), ForkType::Emergency, code(10), 1000, total_stake)
            .unwrap_err();
        assert!(err.to_string().contains("rate limit"));
    }

    #[test]
    fn cancel_fork_before_activation() {
        let mut mgr = ForkManager::new();
        mgr.initiate_fork(pid(1), ForkType::Soft, code(1), 0, 100)
            .unwrap();

        mgr.cancel_fork(&pid(1)).unwrap();

        let activation = mgr.activations.get(&pid(1)).unwrap();
        assert_eq!(activation.state, ForkState::Cancelled);
    }

    #[test]
    fn cancel_if_exodus_cancels_locked_in_fork() {
        use crate::timelock::{TimeLockManager, TimeLockType};

        let mut fork_mgr = ForkManager::new();
        let mut timelock_mgr = TimeLockManager::new();
        let total_stake = 100u64;

        // Initiate a fork
        fork_mgr
            .initiate_fork(pid(1), ForkType::Hard, code(1), 0, total_stake)
            .unwrap();

        // Force to LockedIn for testing
        fork_mgr.activations.get_mut(&pid(1)).unwrap().state = ForkState::LockedIn;

        // Start a timelock for the same proposal
        timelock_mgr
            .start_timelock(pid(1), TimeLockType::Consensus, 0, 10_000_000_000)
            .unwrap();

        // Trigger exodus (>33% rage quit)
        timelock_mgr
            .record_rage_quit(&pid(1), seq(1), 3_400_000_000, 100)
            .unwrap();
        assert_eq!(
            timelock_mgr.active_locks.get(&pid(1)).unwrap().status,
            crate::timelock::TimeLockStatus::CancelledByExodus,
        );

        // cancel_if_exodus should cancel the fork
        let cancelled = fork_mgr.cancel_if_exodus(&timelock_mgr);
        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0], pid(1));
        assert_eq!(
            fork_mgr.activations.get(&pid(1)).unwrap().state,
            ForkState::Cancelled
        );
    }

    #[test]
    fn cancel_if_exodus_ignores_active_timelock() {
        use crate::timelock::{TimeLockManager, TimeLockType};

        let mut fork_mgr = ForkManager::new();
        let mut timelock_mgr = TimeLockManager::new();

        fork_mgr
            .initiate_fork(pid(1), ForkType::Soft, code(1), 0, 100)
            .unwrap();

        // Start a timelock but don't trigger exodus
        timelock_mgr
            .start_timelock(pid(1), TimeLockType::Technical, 0, 10_000_000_000)
            .unwrap();

        // cancel_if_exodus should NOT cancel the fork
        let cancelled = fork_mgr.cancel_if_exodus(&timelock_mgr);
        assert!(cancelled.is_empty());
        assert_eq!(
            fork_mgr.activations.get(&pid(1)).unwrap().state,
            ForkState::Signaling
        );
    }

    #[test]
    fn cannot_cancel_active_fork() {
        let mut mgr = ForkManager::new();
        let total_stake = 100u64;

        mgr.initiate_fork(pid(1), ForkType::Soft, code(1), 0, total_stake)
            .unwrap();

        // Force to active state for testing
        mgr.activations.get_mut(&pid(1)).unwrap().state = ForkState::Active;

        let err = mgr.cancel_fork(&pid(1)).unwrap_err();
        assert!(err.to_string().contains("already-active"));
    }
}
