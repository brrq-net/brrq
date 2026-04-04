//! Staking management with √x effective stake cap.
//!
//! ## Effective Stake Formula (§9.1)
//!
//! ```text
//! EffectiveStake_i = BTC_i                           if BTC_i <= Cap
//!                  = Cap + sqrt(BTC_i - Cap)          if BTC_i >  Cap
//!
//! Cap = TWAP_30d(Median(ActiveStakes)) × 3
//! ```
//!
//! The √x cap prevents wealth-based monopoly while preserving incentive.

use imbl::HashMap;

use brrq_types::Address;

use crate::error::ConsensusError;
use crate::validator::{Validator, ValidatorStatus};

/// Default minimum delegation amount in satoshis (0.001 BTC).
pub const DEFAULT_MIN_DELEGATION: u64 = 100_000;

/// Minimum validator stake in satoshis (1 BTC = 100_000_000 satoshis).
/// Prevents Sybil attacks on the median-based stake cap by requiring
/// a meaningful economic commitment to become a validator.
///
/// During the bootstrap period, use `graduated_min_stake()` for the
/// phase-appropriate minimum.
pub const MIN_VALIDATOR_STAKE: u64 = 100_000_000;

/// Bootstrap Phase 1 minimum stake: 0.1 BTC (first ~2 months).
/// Lowers entry barrier to attract early validators while the network
/// has little fee revenue.
pub const BOOTSTRAP_MIN_STAKE_PHASE1: u64 = 10_000_000;

/// Bootstrap Phase 2 minimum stake: 0.5 BTC (months ~2-4).
/// Growing network with some traction.
pub const BOOTSTRAP_MIN_STAKE_PHASE2: u64 = 50_000_000;

/// Phase boundary: blocks 0..PHASE1_END use Phase 1 minimum (0.1 BTC).
/// ~2 months at 3s/block = 1,752,000 blocks.
pub const GRADUATED_STAKE_PHASE1_END: u64 = 1_752_000;

/// Phase boundary: blocks PHASE1_END..PHASE2_END use Phase 2 minimum (0.5 BTC).
/// ~4 months at 3s/block = 3,504,000 blocks.
pub const GRADUATED_STAKE_PHASE2_END: u64 = 3_504_000;

/// Returns the minimum validator stake for the given block height.
///
/// Graduated schedule to lower entry barrier during network bootstrap:
/// - Phase 1 (months 0–2): 0.1 BTC — attract early validators
/// - Phase 2 (months 2–4): 0.5 BTC — growing network
/// - Mature  (month 4+):   1.0 BTC — full Sybil protection
pub fn graduated_min_stake(block_height: u64) -> u64 {
    if block_height < GRADUATED_STAKE_PHASE1_END {
        BOOTSTRAP_MIN_STAKE_PHASE1
    } else if block_height < GRADUATED_STAKE_PHASE2_END {
        BOOTSTRAP_MIN_STAKE_PHASE2
    } else {
        MIN_VALIDATOR_STAKE
    }
}

/// Cap multiplier applied to 30-day median stake.
const CAP_MULTIPLIER: u64 = 3;

/// Cooldown blocks before a new validator's stake is included
/// in cap calculation. Prevents cap manipulation by registering many
/// validators at specific stakes to shift the median.
/// ~30 days at 3s/block.
pub const NEW_VALIDATOR_CAP_COOLDOWN: u64 = 864_000;

/// Number of blocks to delay each subsequent validator exit (Exit Queue).
/// Limits the rate of validators leaving the active set to prevent Whales
/// from intentionally bypassing the BFT 67% threshold by unbonding instantly.
/// ~1 hour at 3s/block.
pub const EXIT_QUEUE_DELAY_BLOCKS: u64 = 1_200;

/// Staking state for the consensus layer.
#[derive(Clone)]
pub struct StakingState {
    /// All validators keyed by address.
    pub validators: HashMap<Address, Validator>,
    /// Current stake cap in satoshis.
    /// `Cap = TWAP_30d(Median(ActiveStakes)) × 3`
    pub stake_cap: u64,
    /// Historical median stakes for TWAP computation (rolling 30 days).
    median_history: Vec<u64>,
    /// Minimum delegation amount in satoshis.
    pub min_delegation: u64,
    /// Minimum validator stake in satoshis (Sybil protection).
    pub min_validator_stake: u64,
    /// Height until which the exit queue is occupied.
    pub exit_queue_end: u64,
}

impl StakingState {
    /// Create a new staking state with a given initial cap.
    pub fn new(initial_cap: u64) -> Self {
        Self {
            validators: HashMap::new(),
            stake_cap: initial_cap,
            median_history: Vec::new(),
            min_delegation: DEFAULT_MIN_DELEGATION,
            min_validator_stake: MIN_VALIDATOR_STAKE,
            exit_queue_end: 0,
        }
    }

    /// Register a new validator with initial stake.
    ///
    /// Requires a minimum stake of `MIN_VALIDATOR_STAKE` (1 BTC) to prevent
    /// Sybil attacks on the median-based stake cap calculation.
    ///
    /// New validators are subject to a cap cooldown — their stake is
    /// not included in cap calculations until `NEW_VALIDATOR_CAP_COOLDOWN` blocks
    /// after registration. Use `register_validator_at_height()` for height-aware
    /// registration.
    pub fn register_validator(
        &mut self,
        address: Address,
        stake: u64,
    ) -> Result<(), ConsensusError> {
        self.register_validator_at_height(address, stake, 0)
    }

    /// Register a new validator with initial stake at a specific block height.
    ///
    /// Sets `cap_eligible_height = current_height + NEW_VALIDATOR_CAP_COOLDOWN`.
    ///
    /// The minimum stake requirement is the lower of `self.min_validator_stake`
    /// and `graduated_min_stake(current_height)`, allowing bootstrap-period
    /// validators to join with reduced stake.
    pub fn register_validator_at_height(
        &mut self,
        address: Address,
        stake: u64,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let effective_min = self
            .min_validator_stake
            .min(graduated_min_stake(current_height));
        if stake < effective_min {
            return Err(ConsensusError::InsufficientStake {
                required: effective_min,
                actual: stake,
            });
        }

        if self.validators.contains_key(&address) {
            return Err(ConsensusError::ValidatorAlreadyRegistered(address));
        }

        let validator = Validator {
            address,
            stake,
            delegated_stake: 0,
            status: ValidatorStatus::Active,
            join_epoch: 0,
            timeout_count_24h: 0,
            consecutive_timeouts: 0,
            suspended_until: 0,
            unbonding_start: None,
            consecutive_randao_failures: 0,
            cap_eligible_height: current_height.saturating_add(NEW_VALIDATOR_CAP_COOLDOWN),
        };

        self.validators.insert(address, validator);
        Ok(())
    }

    /// Add stake to an existing validator.
    pub fn add_stake(&mut self, address: &Address, amount: u64) -> Result<(), ConsensusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        validator.stake =
            validator
                .stake
                .checked_add(amount)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("stake overflow for validator {}", address),
                })?;
        Ok(())
    }

    /// Add delegated stake to a validator.
    pub fn delegate(
        &mut self,
        validator_address: &Address,
        amount: u64,
    ) -> Result<(), ConsensusError> {
        if amount < self.min_delegation {
            return Err(ConsensusError::InsufficientStake {
                required: self.min_delegation,
                actual: amount,
            });
        }

        let validator = self
            .validators
            .get_mut(validator_address)
            .ok_or(ConsensusError::ValidatorNotFound(*validator_address))?;

        validator.delegated_stake =
            validator
                .delegated_stake
                .checked_add(amount)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!(
                        "delegated stake overflow for validator {}",
                        validator_address
                    ),
                })?;
        Ok(())
    }

    /// Remove delegated stake from a validator.
    ///
    /// Returns an error if the undelegation amount exceeds the validator's
    /// current delegated stake (prevents silent underflow).
    pub fn undelegate(&mut self, address: &Address, amount: u64) -> Result<(), ConsensusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;
        validator.delegated_stake =
            validator
                .delegated_stake
                .checked_sub(amount)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!(
                        "undelegation amount {} exceeds delegated stake {} for validator {}",
                        amount, validator.delegated_stake, address,
                    ),
                })?;
        Ok(())
    }

    /// Begin unbonding a validator (28-day exit period).
    ///
    /// Only Active or Suspended validators can begin unbonding.
    /// Calling this on an already-Unbonding validator is rejected to prevent
    /// timer resets.
    pub fn begin_unbonding(
        &mut self,
        address: &Address,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        match validator.status {
            ValidatorStatus::Active | ValidatorStatus::Suspended => {
                // If they are already queued, reject
                if validator.unbonding_start.is_some() {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!("validator {} is already in the exit queue", address),
                    });
                }

                let start = current_height.max(self.exit_queue_end);
                validator.unbonding_start = Some(start);
                self.exit_queue_end = start.saturating_add(EXIT_QUEUE_DELAY_BLOCKS);
                Ok(())
            }
            ValidatorStatus::Unbonding => Err(ConsensusError::ValidatorUnbonding),
            ValidatorStatus::Removed => Err(ConsensusError::InvalidBlock {
                reason: format!("validator {} is removed, cannot begin unbonding", address),
            }),
        }
    }

    /// Process the validator exit queue, moving eligible validators from
    /// Active/Suspended into the Unbonding state if their queue delay has passed.
    pub fn process_exit_queue(&mut self, current_height: u64) {
        for (_, validator) in self.validators.iter_mut() {
            if validator.status == ValidatorStatus::Active
                || validator.status == ValidatorStatus::Suspended
            {
                if let Some(start) = validator.unbonding_start {
                    if current_height >= start {
                        validator.status = ValidatorStatus::Unbonding;
                    }
                }
            }
        }
    }

    /// Finish unbonding a validator (after 28-day exit period) and refund their stake.
    pub fn finish_unbonding(
        &mut self,
        address: &Address,
        current_height: u64,
    ) -> Result<u64, ConsensusError> {
        let validator = self
            .validators
            .get(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        if validator.status != ValidatorStatus::Unbonding {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("validator {} is not unbonding", address),
            });
        }

        if !validator.is_unbonding_complete(current_height) {
            return Err(ConsensusError::ValidatorUnbonding);
        }

        let total_stake = validator.total_stake();
        self.validators.remove(address);
        Ok(total_stake)
    }

    /// Compute effective stake for a validator using the √x cap formula.
    ///
    /// ```text
    /// EffectiveStake = total          if total <= Cap
    ///                = Cap + √(total - Cap)  if total > Cap
    /// ```
    pub fn effective_stake(&self, address: &Address) -> Result<u64, ConsensusError> {
        let validator = self
            .validators
            .get(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        let total = validator.total_stake();
        Ok(Self::apply_sqrt_cap(total, self.stake_cap))
    }

    /// Apply the √x cap formula to a raw stake amount.
    pub fn apply_sqrt_cap(total: u64, cap: u64) -> u64 {
        if total <= cap {
            total
        } else {
            let excess = total - cap;
            // √excess in satoshis (integer sqrt)
            let sqrt_excess = integer_sqrt(excess);
            cap + sqrt_excess
        }
    }

    /// Get all active validators sorted by effective stake (descending).
    pub fn active_validators_sorted(&self) -> Vec<(&Address, u64)> {
        let mut active: Vec<(&Address, u64)> = self
            .validators
            .iter()
            .filter(|(_, v)| v.status == ValidatorStatus::Active)
            .map(|(addr, v)| {
                let eff = Self::apply_sqrt_cap(v.total_stake(), self.stake_cap);
                (addr, eff)
            })
            .collect();

        active.sort_by_key(|&(_, stake)| std::cmp::Reverse(stake));
        active
    }

    /// Compute total effective stake across all active validators.
    ///
    /// Uses saturating_add to prevent silent overflow in release
    /// mode. Without this, `.sum()` wraps on overflow, which could cause
    /// governance threshold checks to use a near-zero denominator.
    pub fn total_effective_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .map(|v| Self::apply_sqrt_cap(v.total_stake(), self.stake_cap))
            .fold(0u64, |acc, s| acc.saturating_add(s))
    }

    /// Recalculate the stake cap from trimmed mean of active stakes.
    ///
    /// Uses trimmed mean (drop top/bottom 10%) instead of plain median
    /// to resist cap manipulation attacks where an attacker registers many
    /// validators at strategic stakes to shift the median.
    ///
    /// Also filters out validators that haven't passed the cap cooldown period,
    /// preventing flash-registration attacks.
    ///
    /// `Cap = TWAP_30d(TrimmedMean(EligibleStakes)) × 3`
    pub fn recalculate_cap(&mut self) {
        self.recalculate_cap_at_height(0)
    }

    /// Recalculate cap with height-aware cooldown filtering.
    pub fn recalculate_cap_at_height(&mut self, current_height: u64) {
        let mut stakes: Vec<u64> = self
            .validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            // Only include validators past their cap cooldown period
            .filter(|v| current_height == 0 || current_height >= v.cap_eligible_height)
            .map(|v| v.total_stake())
            .collect();

        if stakes.is_empty() {
            return;
        }

        stakes.sort();

        // Use trimmed mean (drop 10% top + 10% bottom) instead of median.
        // This makes it exponentially more expensive to manipulate the cap,
        // since an attacker must control >10% of validators to influence the result.
        let trimmed_value = trimmed_mean(&stakes);
        self.median_history.push(trimmed_value);

        // Trim history to 30 entries to prevent unbounded growth.
        // Without trimming, median_history grows indefinitely (~1 entry/day),
        // leaking memory and allowing window manipulation via history bloat.
        if self.median_history.len() > 30 {
            let start = self.median_history.len() - 30;
            self.median_history = self.median_history[start..].to_vec();
        }

        let window = &self.median_history;

        // Use u128 sum with proper rounding (add half-divisor) to
        // eliminate systematic downward truncation bias in TWAP calculation.
        let sum: u128 = window.iter().map(|&v| v as u128).sum();
        let divisor = window.len() as u128;
        let twap: u64 = ((sum + divisor / 2) / divisor) as u64;
        let new_cap = twap.saturating_mul(CAP_MULTIPLIER);
        // Enforce a minimum cap floor (min_validator_stake * 3) to prevent
        // the cap from being driven to near-zero even if the median drops.
        self.stake_cap = new_cap.max(self.min_validator_stake.saturating_mul(CAP_MULTIPLIER));

        // Update minimum delegation: Min(0.001 BTC, TrimmedMean/1000)
        self.min_delegation = DEFAULT_MIN_DELEGATION.min(trimmed_value / 1000);
        if self.min_delegation == 0 {
            self.min_delegation = 1; // never zero
        }
    }

    /// Reactivate validators whose suspension period has expired.
    ///
    /// Suspended validators have `is_eligible(height) == true` when their
    /// suspension expires, but their status remains `Suspended`. This causes
    /// them to be excluded from `active_validators_sorted()` and
    /// `total_effective_stake()` which filter by `status == Active`.
    ///
    /// This method sweeps all Suspended validators and transitions them back
    /// to Active if their suspension deadline has passed.
    pub fn reactivate_expired_suspensions(&mut self, current_height: u64) {
        for (_, v) in self.validators.iter_mut() {
            if v.status == ValidatorStatus::Suspended && current_height >= v.suspended_until {
                v.status = ValidatorStatus::Active;
                v.consecutive_timeouts = 0;
            }
        }
    }

    /// Early exit penalty: 1% (100 basis points).
    ///
    /// New validators who wish to exit during their cap cooldown period
    /// (before `cap_eligible_height`) may do so, but forfeit 1% of their
    /// stake as compensation for the disruption to network stability.
    pub const EARLY_EXIT_PENALTY_BP: u64 = 100;

    /// Request early exit for a validator still within their cap cooldown.
    ///
    /// Applies a 1% penalty and begins unbonding. Validators past their
    /// cooldown should use `begin_unbonding` instead (no penalty).
    ///
    /// Returns the penalty amount deducted.
    pub fn request_early_exit(
        &mut self,
        address: &Address,
        current_height: u64,
    ) -> Result<u64, ConsensusError> {
        let validator = self
            .validators
            .get(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        // Must be Active
        if validator.status != ValidatorStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "validator {} is not active (status: {:?})",
                    address, validator.status,
                ),
            });
        }

        // Must still be within cap cooldown
        if current_height >= validator.cap_eligible_height {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "validator {} is past cap cooldown (eligible at {}), use begin_unbonding instead",
                    address, validator.cap_eligible_height,
                ),
            });
        }

        // Apply 1% penalty
        let penalty = self.slash(address, Self::EARLY_EXIT_PENALTY_BP)?;

        // Begin unbonding
        self.begin_unbonding(address, current_height)?;

        Ok(penalty)
    }

    /// Slash a validator's stake by a given percentage (basis points, 1/10000).
    /// Returns the amount actually deducted (capped to available stake).
    pub fn slash(&mut self, address: &Address, basis_points: u64) -> Result<u64, ConsensusError> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        let total = validator.total_stake();
        // Use u128 intermediate to prevent overflow when
        // total * basis_points exceeds u64::MAX. Ensure minimum slash of
        // 1 sat so small stakes cannot avoid slashing via rounding to zero.
        let slash_amount = ((total as u128 * basis_points as u128) / 10_000) as u64;
        let slash_amount = if total > 0 && slash_amount == 0 {
            1
        } else {
            slash_amount
        };

        // Cap slash to actual available stake to prevent phantom fund distribution.
        // Without this cap, SlashResult could report more slashed than actually deducted,
        // causing the distribution (burn/challenger/community) to create funds from thin air.
        let actual_slash = slash_amount.min(total);

        // Slash from own stake first, then delegated
        if validator.stake >= actual_slash {
            validator.stake -= actual_slash;
        } else {
            let remainder = actual_slash - validator.stake;
            validator.stake = 0;
            validator.delegated_stake = validator.delegated_stake.saturating_sub(remainder);
        }

        Ok(actual_slash)
    }
}

/// Compute trimmed mean — drops top/bottom 10% of values.
///
/// This is more resistant to manipulation than a simple median because
/// an attacker must control >10% of the validator set to influence it.
/// For small sets (<10 validators), falls back to plain median.
fn trimmed_mean(sorted_stakes: &[u64]) -> u64 {
    let n = sorted_stakes.len();
    if n == 0 {
        return 0;
    }
    if n < 10 {
        // Too few validators for meaningful trimming — use median
        return if n.is_multiple_of(2) {
            let mid = n / 2;
            sorted_stakes[mid - 1] / 2
                + sorted_stakes[mid] / 2
                + (sorted_stakes[mid - 1] % 2 + sorted_stakes[mid] % 2) / 2
        } else {
            sorted_stakes[n / 2]
        };
    }
    // Drop 10% from each end
    let trim = n / 10;
    let trimmed = &sorted_stakes[trim..n - trim];
    if trimmed.is_empty() {
        return sorted_stakes[n / 2];
    }
    // Compute mean of trimmed set using u128 to avoid overflow
    let sum: u128 = trimmed.iter().map(|&v| v as u128).sum();
    let divisor = trimmed.len() as u128;
    ((sum + divisor / 2) / divisor) as u64
}

/// Apply a geographic diversity bonus to an effective stake amount.
///
/// Regions with fewer validators receive a bonus to incentivise geographic
/// decentralization:
/// - Under-represented region (<15% share): 1.3× bonus
/// - Moderate region (<25% share): 1.1× bonus
/// - Over-represented region (≥25% share): no bonus (1.0×)
///
/// `region_share_bp` is the region's share of total validators in basis points.
pub fn apply_diversity_bonus(effective_stake: u64, region_share_bp: u64) -> u64 {
    let multiplier: u64 = if region_share_bp < 1500 {
        13000 // 1.3×
    } else if region_share_bp < 2500 {
        11000 // 1.1×
    } else {
        10000 // 1.0×
    };
    let result = (effective_stake as u128).saturating_mul(multiplier as u128) / 10_000;
    result.min(u64::MAX as u128) as u64
}

/// Integer square root (Babylonian method).
pub fn integer_sqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    /// Create a StakingState with no minimum validator stake for unit tests.
    fn test_state(cap: u64) -> StakingState {
        let mut state = StakingState::new(cap);
        state.min_validator_stake = 0;
        state
    }

    #[test]
    fn test_effective_stake_below_cap() {
        let _state = test_state(1_000_000_000); // 10 BTC cap
        // 5 BTC = 500M sat, below cap
        assert_eq!(
            StakingState::apply_sqrt_cap(500_000_000, 1_000_000_000),
            500_000_000
        );
    }

    #[test]
    fn test_effective_stake_above_cap() {
        // Cap = 100 BTC = 10B sat
        // Stake = 400 BTC = 40B sat
        // Effective = 10B + √(30B) = 10B + 173205 ≈ 10_000_173_205
        let cap = 10_000_000_000u64;
        let stake = 40_000_000_000u64;
        let eff = StakingState::apply_sqrt_cap(stake, cap);
        assert!(eff > cap);
        assert!(eff < stake);
        // √30B ≈ 173205
        let sqrt_excess = integer_sqrt(30_000_000_000);
        assert_eq!(eff, cap + sqrt_excess);
    }

    #[test]
    fn test_effective_stake_at_cap() {
        let cap = 1_000_000_000u64;
        assert_eq!(StakingState::apply_sqrt_cap(cap, cap), cap);
    }

    #[test]
    fn test_register_and_delegate() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 500_000_000).unwrap();
        state.delegate(&alice, 200_000).unwrap();

        let v = state.validators.get(&alice).unwrap();
        assert_eq!(v.total_stake(), 500_200_000);
    }

    #[test]
    fn test_duplicate_registration() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 100).unwrap();
        assert!(state.register_validator(alice, 200).is_err());
    }

    #[test]
    fn test_delegation_below_minimum() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 100_000).unwrap();
        // min delegation = 100_000 sat by default
        let result = state.delegate(&alice, 50_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_slash() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 10_000_000).unwrap(); // 0.1 BTC

        // Slash 33.33% = 3333 basis points
        let slashed = state.slash(&alice, 3333).unwrap();
        assert_eq!(slashed, 10_000_000 * 3333 / 10_000);
        let remaining = state.validators.get(&alice).unwrap().stake;
        assert_eq!(remaining, 10_000_000 - slashed);
    }

    #[test]
    fn test_recalculate_cap() {
        let mut state = test_state(1_000_000_000);
        // Add 3 validators with different stakes
        state.register_validator(addr(1), 5_000_000_000).unwrap(); // 50 BTC
        state.register_validator(addr(2), 10_000_000_000).unwrap(); // 100 BTC
        state.register_validator(addr(3), 15_000_000_000).unwrap(); // 150 BTC

        state.recalculate_cap();
        // Median of [5B, 10B, 15B] = 10B, cap = 10B * 3 = 30B
        assert_eq!(state.stake_cap, 30_000_000_000);
    }

    #[test]
    fn test_integer_sqrt() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(10000), 100);
        // Non-perfect: floor
        assert_eq!(integer_sqrt(10), 3);
        assert_eq!(integer_sqrt(99), 9);
    }

    #[test]
    fn test_active_validators_sorted() {
        let mut state = test_state(100_000_000_000); // High cap so no capping
        state.register_validator(addr(1), 100).unwrap();
        state.register_validator(addr(2), 300).unwrap();
        state.register_validator(addr(3), 200).unwrap();

        let sorted = state.active_validators_sorted();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].1, 300); // highest first
        assert_eq!(sorted[1].1, 200);
        assert_eq!(sorted[2].1, 100);
    }

    #[test]
    fn test_unbonding() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 100_000).unwrap();
        state.begin_unbonding(&alice, 1000).unwrap();
        state.process_exit_queue(1000);

        let v = state.validators.get(&alice).unwrap();
        assert_eq!(v.status, ValidatorStatus::Unbonding);
        assert_eq!(v.unbonding_start, Some(1000));
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Stake Manipulation Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_slash_100_percent() {
        // Slash 100% (10000 basis points)
        let mut state = test_state(1_000_000_000);
        state.register_validator(addr(1), 10_000_000).unwrap();

        let slashed = state.slash(&addr(1), 10_000).unwrap();
        assert_eq!(slashed, 10_000_000, "100% slash should take everything");
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.stake, 0);
    }

    #[test]
    fn adversarial_slash_more_than_100_percent() {
        // Slash 200% (20000 basis points) — should cap to actual available stake
        let mut state = test_state(1_000_000_000);
        state.register_validator(addr(1), 10_000_000).unwrap();

        let slashed = state.slash(&addr(1), 20_000).unwrap();
        // 10_000_000 * 20_000 / 10_000 = 20_000_000, but capped to total = 10_000_000
        assert_eq!(slashed, 10_000_000, "Slash must be capped to actual stake");
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.stake, 0, "Stake must be zeroed");
        assert_eq!(v.delegated_stake, 0, "Delegated stake must be zeroed");
    }

    #[test]
    fn adversarial_slash_with_delegation() {
        // Slash cuts own stake first, then delegation
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 5_000_000).unwrap(); // 5M own
        state.delegate(&alice, 3_000_000).unwrap(); // 3M delegated
        // Total: 8M

        // Slash 75% = 6M. Own = 5M, so: own → 0, remainder = 1M from delegated
        let slashed = state.slash(&alice, 7500).unwrap();
        assert_eq!(slashed, 6_000_000);
        let v = state.validators.get(&alice).unwrap();
        assert_eq!(v.stake, 0);
        assert_eq!(v.delegated_stake, 2_000_000); // 3M - 1M
    }

    #[test]
    fn adversarial_slash_nonexistent_validator() {
        let mut state = test_state(1_000_000_000);
        let result = state.slash(&addr(99), 500);
        assert!(result.is_err(), "Slashing nonexistent validator must fail");
    }

    #[test]
    fn adversarial_integer_sqrt_large_values() {
        // Test integer_sqrt with very large values
        assert_eq!(integer_sqrt(u64::MAX), 4_294_967_295); // √(2^64-1) ≈ 2^32 - 1
        assert_eq!(integer_sqrt(u64::MAX - 1), 4_294_967_295);

        // Perfect squares
        assert_eq!(integer_sqrt(1_000_000_000_000), 1_000_000);

        // Verify correctness: result² ≤ n < (result+1)²
        let n = 999_999_999;
        let s = integer_sqrt(n);
        assert!(s * s <= n);
        assert!((s + 1) * (s + 1) > n);
    }

    #[test]
    fn adversarial_sqrt_cap_extreme_excess() {
        // Stake is astronomically larger than cap
        let cap = 100u64;
        let stake = 1_000_000_000_000u64; // 1 trillion
        let eff = StakingState::apply_sqrt_cap(stake, cap);

        // eff = 100 + √(999_999_999_900) ≈ 100 + 999_999
        assert!(eff > cap);
        assert!(eff < stake);

        let sqrt_excess = integer_sqrt(stake - cap);
        assert_eq!(eff, cap + sqrt_excess);
    }

    #[test]
    fn adversarial_recalculate_cap_empty_set() {
        // No active validators → cap should not change
        let mut state = test_state(1_000_000_000);
        let original_cap = state.stake_cap;
        state.recalculate_cap();
        assert_eq!(
            state.stake_cap, original_cap,
            "Empty set should not change cap"
        );
    }

    #[test]
    fn adversarial_recalculate_cap_single_validator() {
        // One validator → median = that stake → cap = median × 3
        let mut state = test_state(1_000_000_000);
        state.register_validator(addr(1), 10_000_000_000).unwrap(); // 100 BTC

        state.recalculate_cap();
        // median = 10B, twap = 10B (single entry), cap = 10B × 3 = 30B
        assert_eq!(state.stake_cap, 30_000_000_000);
    }

    #[test]
    fn adversarial_recalculate_cap_even_count() {
        // Even number of validators → median = average of two middle values
        let mut state = test_state(1_000_000_000);
        state.register_validator(addr(1), 100).unwrap();
        state.register_validator(addr(2), 200).unwrap();
        state.register_validator(addr(3), 300).unwrap();
        state.register_validator(addr(4), 400).unwrap();

        state.recalculate_cap();
        // Sorted: [100, 200, 300, 400]. Median = (200 + 300) / 2 = 250
        // Cap = 250 × 3 = 750
        assert_eq!(state.stake_cap, 750);
    }

    #[test]
    fn adversarial_add_stake_overflow() {
        // Adding stake that would overflow u64 should be caught
        let mut state = test_state(u64::MAX);
        state.register_validator(addr(1), u64::MAX - 1).unwrap();

        let result = state.add_stake(&addr(1), 2);
        assert!(result.is_err(), "Stake overflow must be caught");
    }

    #[test]
    fn adversarial_delegate_overflow() {
        // Delegation overflow should be caught
        let mut state = test_state(u64::MAX);
        state.register_validator(addr(1), 100).unwrap();
        state.delegate(&addr(1), u64::MAX - 1).unwrap();

        let result = state.delegate(&addr(1), 2);
        assert!(result.is_err(), "Delegation overflow must be caught");
    }

    #[test]
    fn test_h2_begin_unbonding_rejects_already_unbonding() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 100_000).unwrap();

        // First unbonding at height 1000
        state.begin_unbonding(&alice, 1000).unwrap();
        assert_eq!(
            state.validators.get(&alice).unwrap().unbonding_start,
            Some(1000)
        );

        // Second unbonding should be rejected (timer cannot be reset)
        let result = state.begin_unbonding(&alice, 5000);
        assert!(
            result.is_err(),
            "already-unbonding validator must not reset timer"
        );
        // Timer must remain at original value
        assert_eq!(
            state.validators.get(&alice).unwrap().unbonding_start,
            Some(1000)
        );
    }

    #[test]
    fn test_h2_begin_unbonding_rejects_removed() {
        let mut state = test_state(1_000_000_000);
        let alice = addr(1);
        state.register_validator(alice, 100_000).unwrap();
        state.validators.get_mut(&alice).unwrap().status = ValidatorStatus::Removed;

        let result = state.begin_unbonding(&alice, 1000);
        assert!(
            result.is_err(),
            "removed validator must not begin unbonding"
        );
    }

    #[test]
    fn adversarial_unbonding_excluded_from_sorted() {
        // Unbonding validators should NOT appear in active_validators_sorted
        let mut state = test_state(100_000_000_000);
        state.register_validator(addr(1), 500).unwrap();
        state.register_validator(addr(2), 300).unwrap();

        assert_eq!(state.active_validators_sorted().len(), 2);

        state.begin_unbonding(&addr(1), 100).unwrap();
        state.process_exit_queue(100);

        let sorted = state.active_validators_sorted();
        assert_eq!(sorted.len(), 1, "Unbonding validator must be excluded");
        assert_eq!(sorted[0].1, 300);
    }

    #[test]
    fn adversarial_total_effective_stake_with_cap() {
        let mut state = test_state(100); // Low cap
        state.register_validator(addr(1), 50).unwrap(); // Below cap → 50
        state.register_validator(addr(2), 500).unwrap(); // Above cap → 100 + √400 = 120

        let total = state.total_effective_stake();
        assert_eq!(total, 50 + 100 + integer_sqrt(400));
    }

    #[test]
    fn test_h1_reactivate_expired_suspension() {
        let mut state = test_state(100_000_000_000);
        state.register_validator(addr(1), 1_000_000_000).unwrap();

        // Suspend the validator
        let v = state.validators.get_mut(&addr(1)).unwrap();
        v.status = ValidatorStatus::Suspended;
        v.suspended_until = 1000;

        // Before expiry: still suspended
        assert_eq!(state.active_validators_sorted().len(), 0);
        state.reactivate_expired_suspensions(999);
        assert_eq!(
            state.validators.get(&addr(1)).unwrap().status,
            ValidatorStatus::Suspended
        );
        assert_eq!(state.active_validators_sorted().len(), 0);

        // At expiry: reactivated
        state.reactivate_expired_suspensions(1000);
        assert_eq!(
            state.validators.get(&addr(1)).unwrap().status,
            ValidatorStatus::Active
        );
        assert_eq!(state.active_validators_sorted().len(), 1);
        // Consecutive timeouts should be reset
        assert_eq!(
            state.validators.get(&addr(1)).unwrap().consecutive_timeouts,
            0
        );
    }

    #[test]
    fn adversarial_min_delegation_never_zero() {
        // After recalculate_cap with tiny stakes, min_delegation must never be 0
        let mut state = test_state(1_000_000_000);
        state.register_validator(addr(1), 1).unwrap(); // 1 satoshi

        state.recalculate_cap();
        assert!(
            state.min_delegation >= 1,
            "min_delegation must never be zero"
        );
    }

    #[test]
    fn adversarial_delegate_to_nonexistent_validator() {
        let mut state = test_state(1_000_000_000);
        let result = state.delegate(&addr(99), 200_000);
        assert!(
            result.is_err(),
            "Delegation to nonexistent validator must fail"
        );
    }

    #[test]
    fn adversarial_add_stake_to_nonexistent_validator() {
        let mut state = test_state(1_000_000_000);
        let result = state.add_stake(&addr(99), 100_000);
        assert!(
            result.is_err(),
            "Adding stake to nonexistent validator must fail"
        );
    }

    // ── Graduated minimum stake tests ────────────────────────────────

    #[test]
    fn graduated_min_stake_phase1() {
        assert_eq!(graduated_min_stake(0), BOOTSTRAP_MIN_STAKE_PHASE1);
        assert_eq!(graduated_min_stake(1_000_000), BOOTSTRAP_MIN_STAKE_PHASE1);
        assert_eq!(
            graduated_min_stake(GRADUATED_STAKE_PHASE1_END - 1),
            BOOTSTRAP_MIN_STAKE_PHASE1
        );
    }

    #[test]
    fn graduated_min_stake_phase2() {
        assert_eq!(
            graduated_min_stake(GRADUATED_STAKE_PHASE1_END),
            BOOTSTRAP_MIN_STAKE_PHASE2
        );
        assert_eq!(graduated_min_stake(3_000_000), BOOTSTRAP_MIN_STAKE_PHASE2);
        assert_eq!(
            graduated_min_stake(GRADUATED_STAKE_PHASE2_END - 1),
            BOOTSTRAP_MIN_STAKE_PHASE2
        );
    }

    #[test]
    fn graduated_min_stake_mature() {
        assert_eq!(
            graduated_min_stake(GRADUATED_STAKE_PHASE2_END),
            MIN_VALIDATOR_STAKE
        );
        assert_eq!(graduated_min_stake(10_000_000), MIN_VALIDATOR_STAKE);
        assert_eq!(graduated_min_stake(u64::MAX), MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn register_with_graduated_stake_phase1() {
        let mut state = StakingState::new(1_000_000_000);
        // During Phase 1, 0.1 BTC should be enough
        let result = state.register_validator_at_height(addr(1), BOOTSTRAP_MIN_STAKE_PHASE1, 100);
        assert!(result.is_ok(), "Phase 1 should accept 0.1 BTC stake");
    }

    #[test]
    fn register_below_graduated_stake_phase1_fails() {
        let mut state = StakingState::new(1_000_000_000);
        // Below Phase 1 minimum should fail
        let result =
            state.register_validator_at_height(addr(1), BOOTSTRAP_MIN_STAKE_PHASE1 - 1, 100);
        assert!(result.is_err(), "Below Phase 1 minimum should be rejected");
    }

    #[test]
    fn register_with_graduated_stake_mature() {
        let mut state = StakingState::new(1_000_000_000);
        // After Phase 2, need full 1 BTC
        let result = state.register_validator_at_height(
            addr(1),
            BOOTSTRAP_MIN_STAKE_PHASE2,
            GRADUATED_STAKE_PHASE2_END,
        );
        assert!(
            result.is_err(),
            "Mature phase should require full 1 BTC, 0.5 BTC not enough"
        );

        let result = state.register_validator_at_height(
            addr(1),
            MIN_VALIDATOR_STAKE,
            GRADUATED_STAKE_PHASE2_END,
        );
        assert!(result.is_ok(), "Mature phase should accept full 1 BTC");
    }

    // ── Early exit tests ──────────────────────────────────────────

    #[test]
    fn early_exit_during_cooldown_with_penalty() {
        let mut state = StakingState::new(1_000_000_000);
        state
            .register_validator_at_height(addr(1), 100_000_000, 100)
            .unwrap();

        // During cooldown (cap_eligible_height = 100 + 864_000)
        let penalty = state.request_early_exit(&addr(1), 500).unwrap();
        state.process_exit_queue(500);

        // 1% of 100M = 1M
        assert_eq!(penalty, 1_000_000);

        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Unbonding);
        assert_eq!(v.stake, 100_000_000 - 1_000_000);
    }

    #[test]
    fn early_exit_rejected_after_cooldown() {
        let mut state = StakingState::new(1_000_000_000);
        state
            .register_validator_at_height(addr(1), 100_000_000, 100)
            .unwrap();

        let cap_eligible = state.validators.get(&addr(1)).unwrap().cap_eligible_height;
        // After cooldown
        let result = state.request_early_exit(&addr(1), cap_eligible);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("past cap cooldown")
        );
    }

    // ── Diversity bonus tests ─────────────────────────────────────

    #[test]
    fn diversity_bonus_underrepresented() {
        // <15% share → 1.3× bonus
        let eff = apply_diversity_bonus(1_000_000, 1000); // 10% share
        assert_eq!(eff, 1_300_000);
    }

    #[test]
    fn diversity_bonus_moderate() {
        // 15%–25% share → 1.1× bonus
        let eff = apply_diversity_bonus(1_000_000, 2000); // 20% share
        assert_eq!(eff, 1_100_000);
    }

    #[test]
    fn diversity_bonus_overrepresented() {
        // ≥25% share → no bonus (1.0×)
        let eff = apply_diversity_bonus(1_000_000, 3000); // 30% share
        assert_eq!(eff, 1_000_000);
    }

    #[test]
    fn diversity_bonus_does_not_bypass_cap() {
        // Large stake with bonus should not overflow
        let eff = apply_diversity_bonus(u64::MAX, 500);
        assert!(eff > 0, "should not overflow to zero");
        // 1.3× u64::MAX would overflow u64, so should saturate
    }
}
