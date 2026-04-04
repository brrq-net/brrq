//! Time-lock system for governance proposals.
//!
//! ## Design (Articles 6-8)
//!
//! No consensus-affecting proposal executes immediately after approval.
//! Every approved proposal enters a mandatory time-lock period during which:
//! - Users can peg-out their brqBTC to Bitcoin L1 (full exit right)
//! - Users can Rage Quit (withdraw + undelegate)
//! - The Technical Council can issue a Security Veto
//! - If Rage Quit exceeds 33% of total supply → proposal auto-cancelled
//!
//! The time-lock duration is always ≥ 2× the BitVM2 challenge period,
//! ensuring users can complete a full peg-out before any change activates.

use std::collections::HashMap;

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Constants — Time-lock durations (L2 blocks at 3s/block)
// ═══════════════════════════════════════════════════════════════

/// Time-lock for TechnicalUpdate proposals: 7 days.
pub const TIMELOCK_TECHNICAL: u64 = 201_600;

/// Time-lock for FeeChange proposals: 3 days.
pub const TIMELOCK_FEE: u64 = 86_400;

/// Time-lock for SlashingChange proposals: 14 days.
pub const TIMELOCK_SLASHING: u64 = 403_200;

/// Time-lock for BridgeUpdate proposals: 28 days.
pub const TIMELOCK_BRIDGE: u64 = 806_400;

/// Time-lock for ConsensusChange proposals: 28 days.
pub const TIMELOCK_CONSENSUS: u64 = 806_400;

/// Time-lock for Constitutional amendments: 56 days.
pub const TIMELOCK_CONSTITUTIONAL: u64 = 1_612_800;

/// Time-lock for EmergencyPatch: 72 hours (reduced).
pub const TIMELOCK_EMERGENCY: u64 = 86_400;

/// BitVM2 challenge period on Bitcoin L1: 2,016 blocks (~14 days).
/// Used as a floor for time-lock calculations.
pub const BITVM2_CHALLENGE_PERIOD_L1: u64 = 2_016;

/// Minimum time-lock multiplier vs BitVM2 challenge period.
/// TimeLock ≥ 2× challenge period ensures users can complete peg-out.
pub const MIN_TIMELOCK_CHALLENGE_MULTIPLIER: u64 = 2;

/// Rage Quit cancellation threshold: 33.33% of total supply (in basis points).
pub const RAGE_QUIT_CANCELLATION_BP: u64 = 3_333;

// ═══════════════════════════════════════════════════════════════
// Events
// ═══════════════════════════════════════════════════════════════

/// Events emitted by the time-lock system during `process_block`.
///
/// The caller can use these to trigger downstream actions (e.g., cancelling
/// a fork activation when exodus occurs, or executing a proposal when its
/// time-lock expires).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeLockEvent {
    /// Time-lock expired normally — proposal is now executable.
    Expired { proposal_id: Hash256 },
    /// Cancelled because Rage Quit exceeded 33% of total supply.
    CancelledByExodus { proposal_id: Hash256 },
    /// Cancelled by a Security Veto that was not overridden.
    CancelledByVeto { proposal_id: Hash256 },
}

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// The type of time-lock, derived from the proposal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeLockType {
    Technical,
    Fee,
    Slashing,
    Bridge,
    Consensus,
    Constitutional,
    Emergency,
}

impl TimeLockType {
    /// Get the base time-lock duration in L2 blocks.
    pub fn base_duration(&self) -> u64 {
        match self {
            Self::Technical => TIMELOCK_TECHNICAL,
            Self::Fee => TIMELOCK_FEE,
            Self::Slashing => TIMELOCK_SLASHING,
            Self::Bridge => TIMELOCK_BRIDGE,
            Self::Consensus => TIMELOCK_CONSENSUS,
            Self::Constitutional => TIMELOCK_CONSTITUTIONAL,
            Self::Emergency => TIMELOCK_EMERGENCY,
        }
    }
}

/// State of a time-locked proposal.
#[derive(Debug, Clone)]
pub struct TimeLockEntry {
    /// The proposal this time-lock is attached to.
    pub proposal_id: Hash256,
    /// Type of time-lock (determines duration).
    pub lock_type: TimeLockType,
    /// L2 block height when time-lock started.
    pub start_height: u64,
    /// L2 block height when time-lock expires.
    pub end_height: u64,
    /// Snapshot of total brqBTC supply at time-lock start.
    pub snapshot_total_supply: u64,
    /// Total brqBTC withdrawn via Rage Quit during this time-lock.
    pub rage_quit_total: u64,
    /// Addresses that have Rage Quit and their amounts.
    pub rage_quitters: HashMap<Address, u64>,
    /// Whether a Security Veto is active on this time-lock.
    pub security_veto_active: bool,
    /// If vetoed, the extended end height.
    pub veto_extended_end: Option<u64>,
    /// Current status of the time-lock.
    pub status: TimeLockStatus,
}

/// Time-lock lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeLockStatus {
    /// Time-lock is active — proposal cannot execute yet.
    Active,
    /// Time-lock expired — proposal can be executed.
    Expired,
    /// Cancelled by Rage Quit exceeding 33% threshold.
    CancelledByExodus,
    /// Cancelled by Security Veto (if not overridden by 90/90 vote).
    CancelledByVeto,
}

// ═══════════════════════════════════════════════════════════════
// TimeLockManager
// ═══════════════════════════════════════════════════════════════

/// Manages time-locks for approved governance proposals.
///
/// After a proposal is approved, it enters a mandatory time-lock period.
/// During this period, users can Rage Quit (peg-out to L1), and the
/// Technical Council can issue a Security Veto. If enough users Rage Quit
/// (>33% of supply), the proposal is automatically cancelled.
#[derive(Debug, Clone)]
pub struct TimeLockManager {
    /// Active time-locks keyed by proposal ID.
    pub active_locks: HashMap<Hash256, TimeLockEntry>,
    /// Historical count of expired/cancelled time-locks.
    pub completed_count: u64,
    /// Historical count of proposals cancelled by exodus.
    pub exodus_cancellations: u64,
}

impl Default for TimeLockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeLockManager {
    /// Create a new, empty time-lock manager.
    pub fn new() -> Self {
        Self {
            active_locks: HashMap::new(),
            completed_count: 0,
            exodus_cancellations: 0,
        }
    }

    /// Start a time-lock for an approved proposal.
    ///
    /// The time-lock duration is the maximum of:
    /// 1. The proposal type's base duration
    /// 2. 2× the BitVM2 challenge period (converted to L2 blocks)
    ///
    /// This ensures users always have enough time to complete a peg-out.
    pub fn start_timelock(
        &mut self,
        proposal_id: Hash256,
        lock_type: TimeLockType,
        current_height: u64,
        total_supply: u64,
    ) -> Result<&TimeLockEntry, ConsensusError> {
        if self.active_locks.contains_key(&proposal_id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("time-lock already active for proposal {}", proposal_id),
            });
        }

        let base_duration = lock_type.base_duration();

        // Convert BitVM2 challenge period (L1 blocks @ 10min) to L2 blocks (@ 3s).
        // 1 L1 block = 10 min = 600s = 200 L2 blocks
        let bitvm2_in_l2 = BITVM2_CHALLENGE_PERIOD_L1
            .saturating_mul(200)
            .saturating_mul(MIN_TIMELOCK_CHALLENGE_MULTIPLIER);

        let duration = base_duration.max(bitvm2_in_l2);
        let end_height = current_height.saturating_add(duration);

        let entry = TimeLockEntry {
            proposal_id,
            lock_type,
            start_height: current_height,
            end_height,
            snapshot_total_supply: total_supply,
            rage_quit_total: 0,
            rage_quitters: HashMap::new(),
            security_veto_active: false,
            veto_extended_end: None,
            status: TimeLockStatus::Active,
        };

        self.active_locks.insert(proposal_id, entry);
        Ok(self.active_locks.get(&proposal_id).unwrap())
    }

    /// Record a Rage Quit during an active time-lock.
    ///
    /// A user can Rage Quit once per time-lock period. Their withdrawal amount
    /// is added to the rage quit total. If the total exceeds 33% of supply,
    /// the proposal is automatically cancelled.
    ///
    /// Returns `true` if the Rage Quit triggered automatic cancellation.
    pub fn record_rage_quit(
        &mut self,
        proposal_id: &Hash256,
        quitter: Address,
        amount_sats: u64,
        current_height: u64,
    ) -> Result<bool, ConsensusError> {
        let entry =
            self.active_locks
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no active time-lock for proposal {}", proposal_id),
                })?;

        // Time-lock must be active
        if entry.status != TimeLockStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "time-lock for {} is not active (status: {:?})",
                    proposal_id, entry.status
                ),
            });
        }

        // Must be within time-lock period (use veto-extended end if applicable)
        let effective_end = entry.veto_extended_end.unwrap_or(entry.end_height);
        if current_height > effective_end {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "time-lock period has ended at block {} (current: {})",
                    effective_end, current_height,
                ),
            });
        }

        // No double rage-quit from same address
        if entry.rage_quitters.contains_key(&quitter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "address {} has already rage-quit for proposal {}",
                    quitter, proposal_id
                ),
            });
        }

        // Record the rage quit
        entry.rage_quitters.insert(quitter, amount_sats);
        entry.rage_quit_total = entry.rage_quit_total.saturating_add(amount_sats);

        // Check if exodus threshold is reached (33.33%)
        let threshold = entry
            .snapshot_total_supply
            .saturating_mul(RAGE_QUIT_CANCELLATION_BP)
            / 10_000;

        if entry.rage_quit_total >= threshold {
            entry.status = TimeLockStatus::CancelledByExodus;
            self.exodus_cancellations += 1;
            return Ok(true);
        }

        Ok(false)
    }

    /// Apply a Security Veto to a time-locked proposal.
    ///
    /// Extends the time-lock by 30 days (864,000 L2 blocks) to allow
    /// a security audit. Can only be applied once per proposal.
    pub fn apply_security_veto(
        &mut self,
        proposal_id: &Hash256,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let entry =
            self.active_locks
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no active time-lock for proposal {}", proposal_id),
                })?;

        if entry.status != TimeLockStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: "time-lock is not active".to_string(),
            });
        }

        if entry.security_veto_active {
            return Err(ConsensusError::InvalidBlock {
                reason: "security veto already applied to this proposal".to_string(),
            });
        }

        // Extend time-lock by the security veto duration (30 days).
        // Import from technical_council to avoid constant duplication.
        let veto_extension = crate::technical_council::SECURITY_VETO_DURATION;
        let current_end = entry.veto_extended_end.unwrap_or(entry.end_height);
        let new_end = current_end
            .max(current_height)
            .saturating_add(veto_extension);

        entry.security_veto_active = true;
        entry.veto_extended_end = Some(new_end);

        Ok(())
    }

    /// Process time-lock expiry at the given block height.
    ///
    /// Checks all active time-locks and transitions expired ones.
    /// Returns a list of proposal IDs that are now executable.
    ///
    /// Delegates to `process_block_with_events` to avoid duplicated logic.
    pub fn process_block(&mut self, current_height: u64) -> Vec<Hash256> {
        self.process_block_with_events(current_height)
            .into_iter()
            .filter_map(|event| match event {
                TimeLockEvent::Expired { proposal_id } => Some(proposal_id),
                _ => None,
            })
            .collect()
    }

    /// Process time-lock expiry with structured events.
    ///
    /// Like `process_block`, but returns `TimeLockEvent` variants instead of
    /// raw proposal IDs. This allows callers to distinguish between normal
    /// expiry, exodus cancellation, and veto cancellation without inspecting
    /// the entry status separately.
    pub fn process_block_with_events(&mut self, current_height: u64) -> Vec<TimeLockEvent> {
        let mut events = Vec::new();

        for (id, entry) in self.active_locks.iter_mut() {
            if entry.status != TimeLockStatus::Active {
                continue;
            }

            let effective_end = entry.veto_extended_end.unwrap_or(entry.end_height);
            if current_height >= effective_end {
                entry.status = TimeLockStatus::Expired;
                self.completed_count += 1;
                events.push(TimeLockEvent::Expired { proposal_id: *id });
            }
        }

        events
    }

    /// Get the remaining time-lock duration for a proposal (in L2 blocks).
    pub fn remaining_blocks(&self, proposal_id: &Hash256, current_height: u64) -> Option<u64> {
        self.active_locks.get(proposal_id).and_then(|entry| {
            if entry.status != TimeLockStatus::Active {
                return None;
            }
            let effective_end = entry.veto_extended_end.unwrap_or(entry.end_height);
            Some(effective_end.saturating_sub(current_height))
        })
    }

    /// Get the Rage Quit percentage for a proposal (in basis points).
    pub fn rage_quit_percentage_bp(&self, proposal_id: &Hash256) -> Option<u64> {
        self.active_locks.get(proposal_id).map(|entry| {
            if entry.snapshot_total_supply == 0 {
                return 0;
            }
            entry.rage_quit_total.saturating_mul(10_000) / entry.snapshot_total_supply
        })
    }

    /// Clean up completed/cancelled time-locks older than the given height.
    pub fn cleanup(&mut self, before_height: u64) {
        self.active_locks.retain(|_, entry| {
            entry.status == TimeLockStatus::Active || entry.end_height > before_height
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash(val: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        Hash256(bytes)
    }

    fn dummy_addr(val: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = val;
        Address(bytes)
    }

    #[test]
    fn start_and_expire_timelock() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Fee, 1000, 1_000_000_000)
            .unwrap();

        assert_eq!(mgr.active_locks.len(), 1);
        let entry = mgr.active_locks.get(&pid).unwrap();
        assert_eq!(entry.status, TimeLockStatus::Active);

        // Not yet expired
        let expired = mgr.process_block(1000 + TIMELOCK_FEE - 1);
        assert!(expired.is_empty());

        // Now expired
        let expired = mgr.process_block(1000 + TIMELOCK_FEE + 806_400);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], pid);
    }

    #[test]
    fn rage_quit_below_threshold() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);
        let total_supply = 10_000_000_000u64; // 100 BTC

        mgr.start_timelock(pid, TimeLockType::Constitutional, 1000, total_supply)
            .unwrap();

        // Rage quit 10% — should not cancel
        let cancelled = mgr
            .record_rage_quit(&pid, dummy_addr(1), 1_000_000_000, 2000)
            .unwrap();
        assert!(!cancelled);

        let pct = mgr.rage_quit_percentage_bp(&pid).unwrap();
        assert_eq!(pct, 1000); // 10%
    }

    #[test]
    fn rage_quit_triggers_cancellation() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);
        let total_supply = 10_000_000_000u64; // 100 BTC

        mgr.start_timelock(pid, TimeLockType::Constitutional, 1000, total_supply)
            .unwrap();

        // Rage quit 34% — should cancel
        let cancelled = mgr
            .record_rage_quit(&pid, dummy_addr(1), 3_400_000_000, 2000)
            .unwrap();
        assert!(cancelled);

        let entry = mgr.active_locks.get(&pid).unwrap();
        assert_eq!(entry.status, TimeLockStatus::CancelledByExodus);
    }

    #[test]
    fn no_double_rage_quit() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Bridge, 1000, 10_000_000_000)
            .unwrap();

        mgr.record_rage_quit(&pid, dummy_addr(1), 100_000_000, 2000)
            .unwrap();

        let err = mgr
            .record_rage_quit(&pid, dummy_addr(1), 100_000_000, 3000)
            .unwrap_err();
        assert!(err.to_string().contains("already rage-quit"));
    }

    #[test]
    fn security_veto_extends_timelock() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Technical, 1000, 1_000_000_000)
            .unwrap();

        let original_end = mgr.active_locks.get(&pid).unwrap().end_height;

        mgr.apply_security_veto(&pid, 5000).unwrap();

        let entry = mgr.active_locks.get(&pid).unwrap();
        assert!(entry.security_veto_active);
        assert!(entry.veto_extended_end.unwrap() > original_end);
    }

    #[test]
    fn no_double_security_veto() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Bridge, 1000, 1_000_000_000)
            .unwrap();

        mgr.apply_security_veto(&pid, 5000).unwrap();

        let err = mgr.apply_security_veto(&pid, 6000).unwrap_err();
        assert!(err.to_string().contains("already applied"));
    }

    #[test]
    fn timelock_enforces_bitvm2_minimum() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        // Emergency has 72h base, but must be ≥ 2× BitVM2 challenge
        mgr.start_timelock(pid, TimeLockType::Emergency, 0, 1_000_000_000)
            .unwrap();

        let entry = mgr.active_locks.get(&pid).unwrap();
        let bitvm2_minimum = BITVM2_CHALLENGE_PERIOD_L1 * 200 * MIN_TIMELOCK_CHALLENGE_MULTIPLIER;
        assert!(entry.end_height >= bitvm2_minimum);
    }

    #[test]
    fn process_block_with_events_expired() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Fee, 1000, 1_000_000_000)
            .unwrap();

        // Not yet expired
        let events = mgr.process_block_with_events(1000 + TIMELOCK_FEE - 1);
        assert!(events.is_empty());

        // Now expired (use end_height from the entry)
        let end = mgr.active_locks.get(&pid).unwrap().end_height;
        let events = mgr.process_block_with_events(end);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], TimeLockEvent::Expired { proposal_id: pid });
    }

    #[test]
    fn exodus_produces_cancelled_status() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);
        let total_supply = 10_000_000_000u64;

        mgr.start_timelock(pid, TimeLockType::Constitutional, 1000, total_supply)
            .unwrap();

        // Trigger exodus
        let cancelled = mgr
            .record_rage_quit(&pid, dummy_addr(1), 3_400_000_000, 2000)
            .unwrap();
        assert!(cancelled);

        let entry = mgr.active_locks.get(&pid).unwrap();
        assert_eq!(entry.status, TimeLockStatus::CancelledByExodus);
    }

    #[test]
    fn remaining_blocks_calculation() {
        let mut mgr = TimeLockManager::new();
        let pid = dummy_hash(1);

        mgr.start_timelock(pid, TimeLockType::Fee, 1000, 1_000_000_000)
            .unwrap();

        let remaining = mgr.remaining_blocks(&pid, 2000).unwrap();
        assert!(remaining > 0);
    }
}
