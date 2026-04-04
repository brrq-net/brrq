//! Validator types and management.
//!
//! ## Sequencer Lifecycle
//!
//! 1. Register: Lock BTC in Taproot contract on L1
//! 2. Active: Produce blocks when elected leader
//! 3. Timeout tracking: 3 consecutive → 30min suspension; 10/24h → removal
//! 4. Unbonding: 28-day exit period (must exceed BitVM2 challenge period)
//! 5. Removed: Must wait full unbonding period before re-registering

use brrq_types::Address;

/// Timeout threshold: consecutive timeouts before suspension.
pub const CONSECUTIVE_TIMEOUT_LIMIT: u32 = 3;

/// Suspension duration in blocks (~30 minutes at 3-5s/block).
pub const SUSPENSION_BLOCKS: u64 = 600;

/// Timeout threshold: total in 24h before removal.
pub const DAILY_TIMEOUT_LIMIT: u32 = 10;

/// Apocalyptic Vector Fix: Consecutive missed blocks before autonomous ejection.
/// Prevents a 34% Sybil Total Liveness Chain Halt.
pub const MAX_MISSED_BLOCKS_BEFORE_EJECTION: u32 = 100;

/// Consecutive non-reveal failures before slashing: 2.
/// Value of 1 would punish honest validators with network latency issues.
/// Value of 2 balances: first failure is a warning, second triggers slash.
pub const CONSECUTIVE_RANDAO_LIMIT: u32 = 2;

/// Unbonding period in blocks (~28 days at 3-5s/block).
/// Must exceed BitVM2 challenge period (2016 blocks ~ 14 days) to prevent
/// validators from exiting before challenges can complete.
pub const UNBONDING_PERIOD: u64 = 806_400; // 28 * 24 * 60 * 60 / 3

/// Validator status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    /// Actively participating in consensus.
    Active,
    /// Temporarily suspended due to timeouts.
    Suspended,
    /// Voluntarily exiting (28-day unbonding).
    Unbonding,
    /// Removed from active set (must re-register).
    Removed,
}

/// A consensus validator (sequencer).
#[derive(Debug, Clone)]
pub struct Validator {
    /// Validator's address.
    pub address: Address,
    /// Own stake in satoshis.
    pub stake: u64,
    /// Delegated stake in satoshis.
    pub delegated_stake: u64,
    /// Current status.
    pub status: ValidatorStatus,
    /// Epoch when this validator joined.
    pub join_epoch: u64,
    /// Timeout count in the last 24 hours.
    pub timeout_count_24h: u32,
    /// Consecutive timeouts (resets on successful block).
    pub consecutive_timeouts: u32,
    /// Block height until which the validator is suspended.
    pub suspended_until: u64,
    /// Block height when unbonding started (if any).
    pub unbonding_start: Option<u64>,
    /// Consecutive RANDAO non-reveal count (resets on successful reveal).
    /// After CONSECUTIVE_RANDAO_LIMIT (2) failures, the validator is slashed.
    pub consecutive_randao_failures: u32,
    /// Block height at which this validator becomes eligible for cap calculation.
    /// New validators must wait NEW_VALIDATOR_CAP_COOLDOWN blocks before their stake
    /// is included in the median/cap computation, preventing cap manipulation attacks.
    pub cap_eligible_height: u64,
}

impl Validator {
    /// Total stake (own + delegated). Uses saturating_add to prevent overflow.
    pub fn total_stake(&self) -> u64 {
        self.stake.saturating_add(self.delegated_stake)
    }

    /// Whether this validator can produce blocks.
    pub fn is_eligible(&self, current_height: u64) -> bool {
        match self.status {
            ValidatorStatus::Active => true,
            ValidatorStatus::Suspended => current_height >= self.suspended_until,
            _ => false,
        }
    }

    /// Record a successful block production (resets consecutive timeouts).
    pub fn record_block_produced(&mut self) {
        self.consecutive_timeouts = 0;
    }

    /// Record a timeout. Returns the new status if it changed.
    pub fn record_timeout(&mut self, current_height: u64) -> ValidatorStatus {
        // Use saturating_add to prevent overflow on counters.
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
        self.timeout_count_24h = self.timeout_count_24h.saturating_add(1);

        if self.timeout_count_24h >= DAILY_TIMEOUT_LIMIT {
            self.status = ValidatorStatus::Removed;
        } else if self.consecutive_timeouts >= CONSECUTIVE_TIMEOUT_LIMIT {
            self.status = ValidatorStatus::Suspended;
            // Prevent overflow on suspension deadline.
            self.suspended_until = current_height.saturating_add(SUSPENSION_BLOCKS);
        }

        self.status
    }

    /// Reset the 24-hour timeout counter (called once per day).
    pub fn reset_daily_timeouts(&mut self) {
        self.timeout_count_24h = 0;
    }

    /// Check if unbonding period has completed.
    pub fn is_unbonding_complete(&self, current_height: u64) -> bool {
        match self.unbonding_start {
            // Use checked_add; on overflow, consider unbonding complete
            // (impossibly far-future deadline means it would have passed).
            Some(start) => current_height >= start.saturating_add(UNBONDING_PERIOD),
            None => false,
        }
    }

    /// Apply a reputation penalty (e.g., for failing to reveal RANDAO secret).
    ///
    /// Increments the 24h timeout counter, feeding into the existing
    /// suspension/removal logic.
    pub fn adjust_reputation_penalty(&mut self) {
        self.timeout_count_24h = self.timeout_count_24h.saturating_add(1);
    }

    /// Forcibly unbond a validator (e.g., via L1ZklaAnchor due to 34% network failure).
    /// The validator stops participating in consensus but retains all capital,
    /// which becomes available for manual withdrawal after the standard unbonding period.
    pub fn force_unbond(&mut self, current_height: u64) {
        if self.status != ValidatorStatus::Unbonding && self.status != ValidatorStatus::Removed {
            self.status = ValidatorStatus::Unbonding;
            self.unbonding_start = Some(current_height);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator(stake: u64) -> Validator {
        Validator {
            address: Address([0u8; 20]),
            stake,
            delegated_stake: 0,
            status: ValidatorStatus::Active,
            join_epoch: 0,
            timeout_count_24h: 0,
            consecutive_timeouts: 0,
            suspended_until: 0,
            unbonding_start: None,
            consecutive_randao_failures: 0,
            cap_eligible_height: 0,
        }
    }

    #[test]
    fn test_total_stake() {
        let mut v = test_validator(1000);
        v.delegated_stake = 500;
        assert_eq!(v.total_stake(), 1500);
    }

    #[test]
    fn test_eligible_when_active() {
        let v = test_validator(1000);
        assert!(v.is_eligible(0));
        assert!(v.is_eligible(999999));
    }

    #[test]
    fn test_suspension_after_consecutive_timeouts() {
        let mut v = test_validator(1000);
        v.record_timeout(100);
        assert_eq!(v.status, ValidatorStatus::Active);
        v.record_timeout(101);
        assert_eq!(v.status, ValidatorStatus::Active);
        v.record_timeout(102);
        assert_eq!(v.status, ValidatorStatus::Suspended);
        assert_eq!(v.suspended_until, 102 + SUSPENSION_BLOCKS);
    }

    #[test]
    fn test_removal_after_daily_timeouts() {
        let mut v = test_validator(1000);
        for i in 0..DAILY_TIMEOUT_LIMIT {
            // Reset consecutive count to avoid suspension triggering first
            v.consecutive_timeouts = 0;
            v.record_timeout(i as u64);
        }
        assert_eq!(v.status, ValidatorStatus::Removed);
    }

    #[test]
    fn test_block_produced_resets_consecutive() {
        let mut v = test_validator(1000);
        v.record_timeout(100);
        v.record_timeout(101);
        assert_eq!(v.consecutive_timeouts, 2);
        v.record_block_produced();
        assert_eq!(v.consecutive_timeouts, 0);
    }

    #[test]
    fn test_unbonding_complete() {
        let mut v = test_validator(1000);
        v.unbonding_start = Some(100);
        assert!(!v.is_unbonding_complete(100));
        assert!(!v.is_unbonding_complete(100 + UNBONDING_PERIOD - 1));
        assert!(v.is_unbonding_complete(100 + UNBONDING_PERIOD));
    }

    #[test]
    fn test_suspended_becomes_eligible() {
        let mut v = test_validator(1000);
        v.status = ValidatorStatus::Suspended;
        v.suspended_until = 1000;
        assert!(!v.is_eligible(999));
        assert!(v.is_eligible(1000));
    }

    // ── Overflow safety tests ──

    #[test]
    fn test_record_timeout_near_max_height_no_panic() {
        let mut v = test_validator(1000);
        // Near u64::MAX height — suspension deadline must not overflow.
        let status = v.record_timeout(u64::MAX - 100);
        assert_eq!(status, ValidatorStatus::Active); // only 1 timeout
        v.record_timeout(u64::MAX - 99);
        let status = v.record_timeout(u64::MAX - 98);
        assert_eq!(status, ValidatorStatus::Suspended);
        // suspended_until should saturate at u64::MAX, not wrap to a low number.
        assert_eq!(v.suspended_until, u64::MAX);
    }

    #[test]
    fn test_is_unbonding_complete_near_max_no_panic() {
        let mut v = test_validator(1000);
        v.unbonding_start = Some(u64::MAX - 10);
        // Would overflow without checked_add; should handle gracefully.
        // Since start + UNBONDING_PERIOD overflows, deadline = u64::MAX,
        // and current_height < u64::MAX → not complete.
        assert!(!v.is_unbonding_complete(u64::MAX - 5));
        // At u64::MAX, it IS complete (current >= deadline).
        assert!(v.is_unbonding_complete(u64::MAX));
    }

    #[test]
    fn test_timeout_counter_saturates() {
        let mut v = test_validator(1000);
        v.timeout_count_24h = u32::MAX;
        v.consecutive_timeouts = u32::MAX;
        // Should not wrap to 0 — saturating add keeps them at MAX.
        v.record_timeout(100);
        assert_eq!(v.timeout_count_24h, u32::MAX);
        assert_eq!(v.consecutive_timeouts, u32::MAX);
    }
}
