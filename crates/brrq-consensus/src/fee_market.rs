//! Dynamic fee market adapted from EIP-1559 for Brrq.
//!
//! ## Design (Economic Specification §2)
//!
//! ```text
//! TotalFee = BaseFee(dynamic) + PriorityFee(tip) + ProtocolFee(graduated)
//!
//! BaseFee:     burned (subject to cumulative & per-epoch burn caps)
//! PriorityFee: included in 30/40/20/10 distribution
//! ProtocolFee: included in 30/40/20/10 distribution (graduated_fee)
//! ```
//!
//! The base fee adjusts per block targeting 50% gas utilization:
//! - Block >50% full → base fee increases (up to 12.5%/block)
//! - Block <50% full → base fee decreases (up to 12.5%/block)
//!
//! This creates backpressure under congestion and spam resistance
//! without pricing out normal users during low-demand periods.
//!
//! ## Burn Cap (Deflationary Spiral Prevention)
//!
//! Since brqBTC is a pegged asset with no issuance, uncapped burning
//! creates a deflationary spiral risk. Two caps are enforced:
//! - **Cumulative cap**: total burns <= 5% of initial L2 supply
//! - **Per-epoch cap**: epoch burns <= 0.1% of circulating supply
//!
//! When either cap is reached, excess base fee "burn" is redirected
//! to the protocol treasury instead of being destroyed.
//!
//! ## Bootstrap Economics (Cold Start)
//!
//! During centralized sequencer operation, the single sequencer is operated
//! by the protocol team. Revenue is insufficient to cover costs at low volume,
//! so the sequencer receives a fixed `BOOTSTRAP_REWARD_PER_BLOCK` subsidy
//! (0.001 BTC/block) from the pre-funded protocol treasury (525.6 BTC).
//!
//! This is not token issuance — the treasury is pre-funded by a founder/team
//! deposit at genesis and depletes over the 6-month bootstrap period.
//! Note: this requires 525.6 BTC of external capital. The subsidy covers:
//! - Server costs (~$200/month for sequencer + prover hardware)
//! - L1 anchor posting fees (1-2 OP_RETURN txs per hour)
//! - Prover operational costs (until fee volume sustains them)
//!
//! Transition to decentralized sequencing occurs when fee revenue
//! reliably exceeds operational costs, making the bootstrap subsidy unnecessary.

use serde::{Deserialize, Serialize};

use crate::error::ConsensusError;

// ── Constants ───────────────────────────────────────────────────────

/// Target block gas utilization: 50%.
/// Numerator of the target fraction (50/100).
pub const TARGET_UTILIZATION_NUM: u64 = 50;

/// Denominator of the target utilization fraction.
pub const TARGET_UTILIZATION_DEN: u64 = 100;

/// Maximum base fee change per block: 1/8 = 12.5%.
/// This matches EIP-1559's rate of change for proven stability.
pub const MAX_CHANGE_NUM: u64 = 1;

/// Denominator for max change (1/8).
pub const MAX_CHANGE_DEN: u64 = 8;

/// Minimum base fee in sat/gas (spam floor).
/// At DEFAULT_BLOCK_GAS_LIMIT=30M, minimum block cost = 30M sats = 0.3 BTC.
pub const MIN_BASE_FEE: u64 = 1;

/// Maximum base fee in sat/gas (safety ceiling).
/// Prevents runaway fees during extreme demand spikes.
pub const MAX_BASE_FEE: u64 = 1_000;

/// Initial base fee for genesis / network start.
pub const INITIAL_BASE_FEE: u64 = 10;

// ── Burn cap constants (deflationary spiral prevention) ───────────

/// Maximum cumulative burn as a fraction of initial supply, in basis points.
/// 500 bp = 5% of the initial L2 supply.
///
/// Once cumulative burns reach this cap, further base fee "burns" are
/// redirected to the protocol treasury instead of being destroyed.
/// This prevents a deflationary spiral on a pegged asset with no issuance.
pub const MAX_CUMULATIVE_BURN_RATIO: u64 = 500;

/// Maximum burn per epoch as a fraction of circulating supply, in basis points.
/// 10 bp = 0.1% of circulating supply per epoch.
///
/// Limits the rate of deflation even when cumulative cap is not yet reached.
pub const MAX_EPOCH_BURN_RATIO: u64 = 10;

// ── Fee distribution shares (basis points, total = 10000) ───────────

/// Ordering share: 30% of transaction fees → active sequencer.
pub const ORDERING_SHARE_BP: u64 = 3000;

/// Proof share: 40% of transaction fees → prover pool.
pub const PROOF_SHARE_BP: u64 = 4000;

/// Data availability share: 20% of transaction fees → DA reserve.
pub const DA_SHARE_BP: u64 = 2000;

/// Protocol share: 10% of transaction fees → treasury.
pub const PROTOCOL_SHARE_BP: u64 = 1000;

// ── Bootstrap reward constants ──────────────────────────────────────

/// Bootstrap block reward in satoshis (0.001 BTC per block).
///
/// Paid to the block-producing sequencer during the bootstrap period
/// to cover operational costs before fee revenue is sufficient.
/// Funded from the genesis protocol treasury (requires 525.6 BTC founder/team deposit).
pub const BOOTSTRAP_REWARD_PER_BLOCK: u64 = 100_000; // 0.001 BTC

/// Bootstrap period: ~6 months at 3s/block.
///
/// After this many blocks, bootstrap rewards stop and sequencers
/// rely solely on transaction fee revenue.
pub const BOOTSTRAP_PERIOD_BLOCKS: u64 = 5_256_000; // 182.5 days × 24h × 1200 blocks/h

/// Total bootstrap budget: BOOTSTRAP_REWARD_PER_BLOCK × BOOTSTRAP_PERIOD_BLOCKS.
///
/// 100,000 sat × 5,256,000 blocks = 525.6 BTC.
/// This must be pre-funded in the protocol treasury at genesis.
pub const BOOTSTRAP_TOTAL_BUDGET: u64 = BOOTSTRAP_REWARD_PER_BLOCK * BOOTSTRAP_PERIOD_BLOCKS;

// ── Protocol treasury distribution (basis points, total = 10000) ────

/// Development team share of protocol treasury.
pub const TREASURY_DEV_SHARE_BP: u64 = 4000; // 40%

/// Security fund share (audits, bug bounties).
pub const TREASURY_SECURITY_SHARE_BP: u64 = 2500; // 25%

/// Ecosystem fund share (developer grants, education).
pub const TREASURY_ECOSYSTEM_SHARE_BP: u64 = 2000; // 20%

/// Emergency reserve share.
pub const TREASURY_EMERGENCY_SHARE_BP: u64 = 1500; // 15%

// ── Types ───────────────────────────────────────────────────────────

/// Dynamic fee market state tracked per block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarket {
    /// Current base fee in sat/gas.
    pub base_fee: u64,
    /// Cumulative base fees burned since genesis (in satoshis).
    /// Tracked to enforce the cumulative burn cap (`MAX_CUMULATIVE_BURN_RATIO`).
    pub cumulative_burned: u64,
    /// Base fees burned in the current epoch (in satoshis).
    /// Reset at each epoch boundary. Enforces `MAX_EPOCH_BURN_RATIO`.
    pub epoch_burned: u64,
}

/// Fee breakdown for a single transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionFeeBreakdown {
    /// Base fee portion (burned).
    pub base_fee_cost: u64,
    /// Priority fee portion (tip to sequencer).
    pub priority_fee_cost: u64,
    /// Total fee paid by user.
    pub total_fee: u64,
}

/// Fee distribution for a complete block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockFeeDistribution {
    /// Total fees collected in this block (excluding burned base fee).
    pub total_distributable_fees: u64,
    /// Amount burned (base fee × total gas).
    pub burned: u64,
    /// Sequencer ordering reward (30% of distributable).
    pub sequencer_reward: u64,
    /// Prover pool reward (40% of distributable).
    pub prover_reward: u64,
    /// DA cost reserve (20% of distributable).
    pub da_reserve: u64,
    /// Protocol treasury (10% of distributable).
    pub protocol_treasury: u64,
    /// Bootstrap subsidy paid to sequencer (funded from treasury, not inflation).
    /// Zero after BOOTSTRAP_PERIOD_BLOCKS.
    pub bootstrap_reward: u64,
    /// Base fee amount redirected to treasury instead of burned, due to burn cap.
    /// When cumulative or per-epoch burn limits are reached, excess "burn"
    /// is sent to the protocol treasury to prevent deflationary spiral.
    pub treasury_redirected: u64,
}

/// Result of applying the burn cap to a requested burn amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnCapResult {
    /// Amount actually burned (destroyed).
    pub actual_burned: u64,
    /// Amount redirected to protocol treasury instead of burned.
    pub treasury_redirected: u64,
}

// ── Implementation ──────────────────────────────────────────────────

impl FeeMarket {
    /// Create a new fee market with the initial base fee.
    pub fn new() -> Self {
        Self {
            base_fee: INITIAL_BASE_FEE,
            cumulative_burned: 0,
            epoch_burned: 0,
        }
    }

    /// Create a fee market with a specific base fee (for testing or state recovery).
    pub fn with_base_fee(base_fee: u64) -> Self {
        Self {
            base_fee: base_fee.clamp(MIN_BASE_FEE, MAX_BASE_FEE),
            cumulative_burned: 0,
            epoch_burned: 0,
        }
    }

    /// Reset the per-epoch burn counter. Call at each epoch boundary.
    pub fn reset_epoch_burn(&mut self) {
        self.epoch_burned = 0;
    }

    /// Apply burn cap logic: given a requested burn amount, returns how much
    /// is actually burned vs. redirected to treasury.
    ///
    /// Enforces two limits:
    /// 1. Cumulative burn cap: total burns <= `MAX_CUMULATIVE_BURN_RATIO` bp of `initial_supply`
    /// 2. Per-epoch burn rate: epoch burns <= `MAX_EPOCH_BURN_RATIO` bp of `circulating_supply`
    ///
    /// Excess is redirected to the protocol treasury instead of being destroyed.
    pub fn apply_burn_cap(
        &mut self,
        requested_burn: u64,
        initial_supply: u64,
        circulating_supply: u64,
    ) -> BurnCapResult {
        if requested_burn == 0 {
            return BurnCapResult {
                actual_burned: 0,
                treasury_redirected: 0,
            };
        }

        // Cumulative burn cap: MAX_CUMULATIVE_BURN_RATIO bp of initial supply.
        let cumulative_cap =
            ((initial_supply as u128 * MAX_CUMULATIVE_BURN_RATIO as u128) / 10_000) as u64;
        let remaining_cumulative = cumulative_cap.saturating_sub(self.cumulative_burned);

        // Per-epoch burn cap: MAX_EPOCH_BURN_RATIO bp of circulating supply.
        let epoch_cap =
            ((circulating_supply as u128 * MAX_EPOCH_BURN_RATIO as u128) / 10_000) as u64;
        let remaining_epoch = epoch_cap.saturating_sub(self.epoch_burned);

        // Actual burn is the minimum of requested, cumulative remaining, and epoch remaining.
        let actual_burned = requested_burn.min(remaining_cumulative).min(remaining_epoch);
        let treasury_redirected = requested_burn - actual_burned;

        // Update state.
        self.cumulative_burned = self.cumulative_burned.saturating_add(actual_burned);
        self.epoch_burned = self.epoch_burned.saturating_add(actual_burned);

        BurnCapResult {
            actual_burned,
            treasury_redirected,
        }
    }

    /// Compute the next block's base fee given the parent block's gas usage.
    ///
    /// Algorithm (adapted EIP-1559):
    /// ```text
    /// target = gas_limit × 50%
    /// if gas_used > target: base_fee increases up to 12.5%
    /// if gas_used < target: base_fee decreases up to 12.5%
    /// if gas_used == target: base_fee unchanged
    /// ```
    ///
    /// All arithmetic uses u128 intermediates to prevent overflow.
    /// Result is clamped to [MIN_BASE_FEE, MAX_BASE_FEE].
    pub fn next_base_fee(&self, parent_gas_used: u64, parent_gas_limit: u64) -> u64 {
        if parent_gas_limit == 0 {
            return self.base_fee;
        }

        // Use u128 to prevent overflow when gas_limit × 50 exceeds u64::MAX.
        let target_gas = ((parent_gas_limit as u128 * TARGET_UTILIZATION_NUM as u128)
            / TARGET_UTILIZATION_DEN as u128) as u64;
        if target_gas == 0 {
            return self.base_fee;
        }

        let new_fee = if parent_gas_used == target_gas {
            self.base_fee
        } else if parent_gas_used > target_gas {
            // Demand exceeds target → increase base fee.
            let excess = parent_gas_used - target_gas;
            // delta = base_fee × excess / target_gas / 8
            // Using u128 to prevent overflow: base_fee × excess can exceed u64.
            let delta = (self.base_fee as u128)
                .saturating_mul(excess as u128)
                .saturating_mul(MAX_CHANGE_NUM as u128)
                / (target_gas as u128 * MAX_CHANGE_DEN as u128);
            // Ensure minimum step of 1 sat so fee always moves upward
            // when blocks are over target.
            let delta = (delta as u64).max(1);
            self.base_fee.saturating_add(delta)
        } else {
            // Demand below target → decrease base fee.
            let deficit = target_gas - parent_gas_used;
            let delta = (self.base_fee as u128)
                .saturating_mul(deficit as u128)
                .saturating_mul(MAX_CHANGE_NUM as u128)
                / (target_gas as u128 * MAX_CHANGE_DEN as u128);
            self.base_fee.saturating_sub(delta as u64)
        };

        new_fee.clamp(MIN_BASE_FEE, MAX_BASE_FEE)
    }

    /// Advance the fee market to the next block.
    ///
    /// Updates the internal base fee based on the parent block's usage.
    pub fn advance(&mut self, parent_gas_used: u64, parent_gas_limit: u64) {
        self.base_fee = self.next_base_fee(parent_gas_used, parent_gas_limit);
    }

    /// Compute the effective gas price a user pays for a transaction.
    ///
    /// ```text
    /// effective_gas_price = base_fee + min(priority_fee, max_fee - base_fee)
    /// ```
    ///
    /// Returns `Err` if `max_fee_per_gas < base_fee` (user can't afford base fee).
    pub fn effective_gas_price(
        &self,
        max_fee_per_gas: u64,
        priority_fee_per_gas: u64,
    ) -> Result<u64, ConsensusError> {
        if max_fee_per_gas < self.base_fee {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "max_fee_per_gas ({}) < current base_fee ({})",
                    max_fee_per_gas, self.base_fee,
                ),
            });
        }

        let max_priority = max_fee_per_gas - self.base_fee;
        let effective_priority = priority_fee_per_gas.min(max_priority);
        Ok(self.base_fee.saturating_add(effective_priority))
    }

    /// Compute the fee breakdown for a single transaction.
    pub fn transaction_fee(
        &self,
        gas_used: u64,
        max_fee_per_gas: u64,
        priority_fee_per_gas: u64,
    ) -> Result<TransactionFeeBreakdown, ConsensusError> {
        let effective_price = self.effective_gas_price(max_fee_per_gas, priority_fee_per_gas)?;

        // Use u128 to prevent overflow: gas_used × price can exceed u64.
        // Clamp to u64::MAX to prevent silent truncation on large inputs.
        let base_fee_cost = (gas_used as u128 * self.base_fee as u128).min(u64::MAX as u128) as u64;
        let total_fee = (gas_used as u128 * effective_price as u128).min(u64::MAX as u128) as u64;
        let priority_fee_cost = total_fee.saturating_sub(base_fee_cost);

        Ok(TransactionFeeBreakdown {
            base_fee_cost,
            priority_fee_cost,
            total_fee,
        })
    }

    /// Distribute a block's total fees among protocol participants.
    ///
    /// The base fee portion is burned (subject to burn cap — excess redirected
    /// to treasury). The remaining fees (priority tips + graduated/protocol
    /// fees) are split per the 30/40/20/10 distribution:
    /// - 30% → sequencer (ordering reward)
    /// - 40% → prover pool (proof generation)
    /// - 20% → DA reserve (L1 batch posting)
    /// - 10% → protocol treasury
    ///
    /// During the bootstrap period (first ~6 months), the sequencer also
    /// receives a fixed `BOOTSTRAP_REWARD_PER_BLOCK` funded from the
    /// protocol treasury — this is NOT inflation, it's a pre-funded subsidy.
    ///
    /// Uses u128 intermediates and ensures distribution sums to total.
    pub fn distribute_block_fees(
        total_priority_fees: u64,
        total_graduated_fees: u64,
        total_base_fee_burned: u64,
    ) -> BlockFeeDistribution {
        Self::distribute_block_fees_at_height(
            total_priority_fees,
            total_graduated_fees,
            total_base_fee_burned,
            0,
            u64::MAX,
        )
    }

    /// Height-aware fee distribution with bootstrap rewards and burn cap.
    ///
    /// `total_priority_fees`: sum of priority fees (tips) in the block.
    /// `total_graduated_fees`: sum of graduated/protocol fees in the block.
    /// `treasury_redirected_from_burn`: base fee amount redirected to treasury
    ///     due to burn cap (from `apply_burn_cap`). Added to treasury share.
    /// `block_height`: current L2 block height (0-indexed from genesis).
    ///
    /// The 30/40/20/10 split applies to priority fees + graduated fees
    /// (i.e., all non-base-fee revenue). Base fees are burned or redirected.
    pub fn distribute_block_fees_at_height(
        total_priority_fees: u64,
        total_graduated_fees: u64,
        total_base_fee_burned: u64,
        treasury_redirected_from_burn: u64,
        block_height: u64,
    ) -> BlockFeeDistribution {
        // The distributable pool includes both priority fees (tips) and
        // graduated/protocol fees, per the spec: the 30/40/20/10 split
        // applies to total block fees excluding the burned base fee.
        let distributable = total_priority_fees.saturating_add(total_graduated_fees);

        // Use u128 to prevent overflow in share calculations.
        let sequencer = ((distributable as u128 * ORDERING_SHARE_BP as u128) / 10_000) as u64;
        let prover = ((distributable as u128 * PROOF_SHARE_BP as u128) / 10_000) as u64;
        let da = ((distributable as u128 * DA_SHARE_BP as u128) / 10_000) as u64;
        // Treasury gets the remainder to avoid rounding dust, plus any
        // burn-cap redirected amount.
        let treasury_from_fees = distributable - sequencer - prover - da;
        let treasury = treasury_from_fees.saturating_add(treasury_redirected_from_burn);

        // Bootstrap reward: fixed subsidy during the bootstrap period.
        let bootstrap = if block_height < BOOTSTRAP_PERIOD_BLOCKS {
            BOOTSTRAP_REWARD_PER_BLOCK
        } else {
            0
        };

        BlockFeeDistribution {
            total_distributable_fees: distributable,
            burned: total_base_fee_burned,
            sequencer_reward: sequencer,
            prover_reward: prover,
            da_reserve: da,
            protocol_treasury: treasury,
            bootstrap_reward: bootstrap,
            treasury_redirected: treasury_redirected_from_burn,
        }
    }

    /// Estimate the cost to spam-fill one block at the current base fee.
    ///
    /// ```text
    /// spam_cost = base_fee × block_gas_limit
    /// ```
    pub fn spam_cost_per_block(&self, block_gas_limit: u64) -> u64 {
        (self.base_fee as u128 * block_gas_limit as u128).min(u64::MAX as u128) as u64
    }

    /// Compute the adaptive block gas limit based on prover capacity.
    ///
    /// Economic Specification §3.4:
    /// ```text
    /// adaptive_limit = min(DEFAULT_BLOCK_GAS_LIMIT, prover_capacity × TARGET_PROOF_TIME)
    /// ```
    ///
    /// This prevents the sequencer from producing blocks the prover pool
    /// cannot prove in reasonable time, which would delay finality.
    ///
    /// `prover_gas_per_second`: estimated gas the prover pool can prove per second.
    /// `target_proof_seconds`: maximum time to prove one block (default 10s).
    pub fn adaptive_gas_limit(prover_gas_per_second: u64, target_proof_seconds: u64) -> u64 {
        let prover_limit = prover_gas_per_second.saturating_mul(target_proof_seconds);
        // Clamp between MIN_BLOCK_GAS_LIMIT (ensures at least 1 tx fits)
        // and DEFAULT_BLOCK_GAS_LIMIT (hard upper bound).
        prover_limit.clamp(MIN_BLOCK_GAS_LIMIT, DEFAULT_BLOCK_GAS_LIMIT)
    }
}

/// Default target proof time in seconds.
pub const TARGET_PROOF_TIME_SECONDS: u64 = 10;

/// Minimum gas limit — never go below this regardless of prover capacity.
/// Ensures at least 1 simple transaction can fit per block.
pub const MIN_BLOCK_GAS_LIMIT: u64 = 21_000;

/// Default block gas limit (re-exported from brrq-types for convenience).
pub use brrq_types::gas::DEFAULT_BLOCK_GAS_LIMIT;

impl Default for FeeMarket {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_types::gas::DEFAULT_BLOCK_GAS_LIMIT;

    const GAS_LIMIT: u64 = DEFAULT_BLOCK_GAS_LIMIT; // 30_000_000

    // ── Base fee adjustment tests ──────────────────────────────────

    #[test]
    fn test_base_fee_unchanged_at_target() {
        let market = FeeMarket::with_base_fee(100);
        let target = GAS_LIMIT / 2; // 50%
        let next = market.next_base_fee(target, GAS_LIMIT);
        assert_eq!(
            next, 100,
            "base fee should not change at exactly 50% utilization"
        );
    }

    #[test]
    fn test_base_fee_increases_above_target() {
        let market = FeeMarket::with_base_fee(100);
        // 100% utilization → max increase
        let next = market.next_base_fee(GAS_LIMIT, GAS_LIMIT);
        // delta = 100 × (30M - 15M) / 15M / 8 = 100 × 1.0 / 8 = 12
        assert_eq!(next, 112, "base fee should increase ~12.5% at full block");
    }

    #[test]
    fn test_base_fee_decreases_below_target() {
        let market = FeeMarket::with_base_fee(100);
        // 0% utilization → max decrease
        let next = market.next_base_fee(0, GAS_LIMIT);
        // delta = 100 × 15M / 15M / 8 = 12
        assert_eq!(next, 88, "base fee should decrease ~12.5% at empty block");
    }

    #[test]
    fn test_base_fee_min_floor() {
        let market = FeeMarket::with_base_fee(MIN_BASE_FEE);
        // Even at 0% util, cannot go below MIN_BASE_FEE
        let next = market.next_base_fee(0, GAS_LIMIT);
        assert_eq!(next, MIN_BASE_FEE, "base fee must not drop below minimum");
    }

    #[test]
    fn test_base_fee_max_ceiling() {
        let market = FeeMarket::with_base_fee(MAX_BASE_FEE);
        // Even at 100% util, cannot exceed MAX_BASE_FEE
        let next = market.next_base_fee(GAS_LIMIT, GAS_LIMIT);
        assert_eq!(next, MAX_BASE_FEE, "base fee must not exceed maximum");
    }

    #[test]
    fn test_base_fee_minimum_upward_step() {
        // At very low base fee, ensure minimum step of 1
        let market = FeeMarket::with_base_fee(1);
        let next = market.next_base_fee(GAS_LIMIT, GAS_LIMIT);
        assert!(
            next > 1,
            "base fee must increase by at least 1 at full block"
        );
    }

    #[test]
    fn test_base_fee_convergence() {
        // Under constant 75% utilization, base fee should stabilize
        let mut market = FeeMarket::with_base_fee(10);
        let gas_used = GAS_LIMIT * 75 / 100;

        let _prev = market.base_fee;
        for _ in 0..200 {
            market.advance(gas_used, GAS_LIMIT);
        }
        // After many blocks, changes should be small (converging)
        let final_fee = market.base_fee;
        market.advance(gas_used, GAS_LIMIT);
        let delta = if market.base_fee > final_fee {
            market.base_fee - final_fee
        } else {
            final_fee - market.base_fee
        };
        // Delta should be < 5% of current fee (convergence)
        assert!(
            delta * 20 <= final_fee,
            "fee should converge: delta={} fee={}",
            delta,
            final_fee
        );
    }

    #[test]
    fn test_base_fee_exponential_under_sustained_demand() {
        // Under 100% utilization, base fee grows exponentially
        let mut market = FeeMarket::with_base_fee(MIN_BASE_FEE);
        let mut fees = vec![market.base_fee];

        for _ in 0..50 {
            market.advance(GAS_LIMIT, GAS_LIMIT);
            fees.push(market.base_fee);
        }

        // After 50 full blocks, base fee should be significantly higher
        assert!(
            market.base_fee > 100,
            "base fee should grow exponentially: got {}",
            market.base_fee
        );

        // Verify monotonic increase
        for window in fees.windows(2) {
            assert!(
                window[1] >= window[0],
                "base fee must be monotonically increasing under full blocks"
            );
        }
    }

    // ── Effective gas price tests ──────────────────────────────────

    #[test]
    fn test_effective_gas_price_normal() {
        let market = FeeMarket::with_base_fee(10);
        let price = market.effective_gas_price(20, 5).unwrap();
        // effective = 10 (base) + min(5, 20-10) = 10 + 5 = 15
        assert_eq!(price, 15);
    }

    #[test]
    fn test_effective_gas_price_priority_capped() {
        let market = FeeMarket::with_base_fee(10);
        let price = market.effective_gas_price(12, 100).unwrap();
        // effective = 10 + min(100, 12-10) = 10 + 2 = 12
        assert_eq!(
            price, 12,
            "priority fee should be capped by max_fee - base_fee"
        );
    }

    #[test]
    fn test_effective_gas_price_max_fee_equals_base() {
        let market = FeeMarket::with_base_fee(10);
        let price = market.effective_gas_price(10, 5).unwrap();
        // effective = 10 + min(5, 0) = 10
        assert_eq!(price, 10, "no tip when max_fee == base_fee");
    }

    #[test]
    fn test_effective_gas_price_insufficient() {
        let market = FeeMarket::with_base_fee(10);
        let result = market.effective_gas_price(5, 2);
        assert!(result.is_err(), "should reject when max_fee < base_fee");
    }

    // ── Transaction fee breakdown tests ────────────────────────────

    #[test]
    fn test_transaction_fee_breakdown() {
        let market = FeeMarket::with_base_fee(10);
        let breakdown = market.transaction_fee(42_000, 20, 5).unwrap();

        assert_eq!(breakdown.base_fee_cost, 10 * 42_000); // 420,000
        assert_eq!(breakdown.total_fee, 15 * 42_000); // 630,000
        assert_eq!(breakdown.priority_fee_cost, 5 * 42_000); // 210,000
        assert_eq!(
            breakdown.total_fee,
            breakdown.base_fee_cost + breakdown.priority_fee_cost,
        );
    }

    // ── Block fee distribution tests ───────────────────────────────

    #[test]
    fn test_block_fee_distribution_sums() {
        // priority_fees=800_000, graduated_fees=200_000, burned=500_000
        let dist = FeeMarket::distribute_block_fees(800_000, 200_000, 500_000);

        // distributable = priority + graduated = 1_000_000
        let total =
            dist.sequencer_reward + dist.prover_reward + dist.da_reserve + dist.protocol_treasury;
        assert_eq!(
            total, dist.total_distributable_fees,
            "distribution must sum to total distributable fees"
        );
        assert_eq!(dist.total_distributable_fees, 1_000_000);
        assert_eq!(dist.burned, 500_000);
    }

    #[test]
    fn test_block_fee_distribution_shares() {
        // 10_000 total distributable: 7_000 priority + 3_000 graduated
        let dist = FeeMarket::distribute_block_fees(7_000, 3_000, 0);

        assert_eq!(dist.sequencer_reward, 3_000); // 30%
        assert_eq!(dist.prover_reward, 4_000); // 40%
        assert_eq!(dist.da_reserve, 2_000); // 20%
        assert_eq!(dist.protocol_treasury, 1_000); // 10%
    }

    #[test]
    fn test_block_fee_distribution_zero() {
        let dist = FeeMarket::distribute_block_fees(0, 0, 0);
        assert_eq!(dist.sequencer_reward, 0);
        assert_eq!(dist.prover_reward, 0);
        assert_eq!(dist.da_reserve, 0);
        assert_eq!(dist.protocol_treasury, 0);
    }

    #[test]
    fn test_block_fee_distribution_rounding_dust() {
        // With amounts that don't divide evenly, treasury absorbs dust
        let dist = FeeMarket::distribute_block_fees(7_003, 3_000, 0);
        let total =
            dist.sequencer_reward + dist.prover_reward + dist.da_reserve + dist.protocol_treasury;
        assert_eq!(total, 10_003, "rounding dust must not be lost");
    }

    #[test]
    fn test_block_fee_distribution_includes_graduated_fees() {
        // Verify that graduated fees are included in distributable, not just priority
        let dist_with_graduated = FeeMarket::distribute_block_fees(5_000, 5_000, 0);
        let dist_priority_only = FeeMarket::distribute_block_fees(5_000, 0, 0);

        assert_eq!(dist_with_graduated.total_distributable_fees, 10_000);
        assert_eq!(dist_priority_only.total_distributable_fees, 5_000);
        assert!(
            dist_with_graduated.prover_reward > dist_priority_only.prover_reward,
            "graduated fees must increase prover reward"
        );
    }

    // ── Spam resistance tests ──────────────────────────────────────

    #[test]
    fn test_spam_cost_minimum() {
        let market = FeeMarket::with_base_fee(MIN_BASE_FEE);
        let cost = market.spam_cost_per_block(GAS_LIMIT);
        // 1 sat/gas × 30M gas = 30M sats = 0.3 BTC
        assert_eq!(cost, 30_000_000);
    }

    #[test]
    fn test_spam_cost_escalation() {
        // After 50 blocks of 100% utilization
        let mut market = FeeMarket::with_base_fee(MIN_BASE_FEE);
        for _ in 0..50 {
            market.advance(GAS_LIMIT, GAS_LIMIT);
        }
        let cost = market.spam_cost_per_block(GAS_LIMIT);
        // Should be much more than initial 30M sats
        assert!(
            cost > 1_000_000_000,
            "sustained spam should drive cost above 10 BTC/block: got {} sats",
            cost
        );
    }

    // ── Edge case tests ────────────────────────────────────────────

    #[test]
    fn test_zero_gas_limit() {
        let market = FeeMarket::with_base_fee(100);
        let next = market.next_base_fee(0, 0);
        assert_eq!(next, 100, "zero gas limit should not change fee");
    }

    #[test]
    fn test_gas_used_exceeds_limit() {
        // Should handle gracefully (treat as 100% utilization)
        let market = FeeMarket::with_base_fee(100);
        let next = market.next_base_fee(GAS_LIMIT * 2, GAS_LIMIT);
        assert!(next > 100, "over-limit usage should increase fee");
        assert!(next <= MAX_BASE_FEE, "should be clamped to max");
    }

    #[test]
    fn test_advance_updates_state() {
        let mut market = FeeMarket::new();
        let initial = market.base_fee;
        market.advance(GAS_LIMIT, GAS_LIMIT); // 100% full
        assert!(market.base_fee > initial, "advance should update base_fee");
    }

    #[test]
    fn test_with_base_fee_clamps() {
        let market = FeeMarket::with_base_fee(0);
        assert_eq!(market.base_fee, MIN_BASE_FEE, "should clamp to min");

        let market = FeeMarket::with_base_fee(999_999);
        assert_eq!(market.base_fee, MAX_BASE_FEE, "should clamp to max");
    }

    // ── Adversarial tests ──────────────────────────────────────────

    #[test]
    fn adversarial_overflow_large_gas_used() {
        let market = FeeMarket::with_base_fee(MAX_BASE_FEE);
        // u64::MAX gas used should not panic or overflow
        let next = market.next_base_fee(u64::MAX, u64::MAX);
        assert!(next >= MIN_BASE_FEE && next <= MAX_BASE_FEE);
    }

    #[test]
    fn adversarial_transaction_fee_overflow() {
        let market = FeeMarket::with_base_fee(MAX_BASE_FEE);
        // Very large gas usage — should not overflow
        let result = market.transaction_fee(u64::MAX / 2, MAX_BASE_FEE + 100, 100);
        assert!(result.is_ok(), "should handle large gas without panic");

        // Verify clamping: gas_used × base_fee exceeds u64::MAX → clamped to u64::MAX
        let breakdown = result.unwrap();
        // base_fee_cost = (u64::MAX/2) × 1000, which exceeds u64::MAX → clamped
        assert_eq!(
            breakdown.base_fee_cost,
            u64::MAX,
            "base_fee_cost should be clamped to u64::MAX, not truncated"
        );
    }

    #[test]
    fn adversarial_adaptive_gas_limit_zero_prover() {
        // Zero prover capacity should return MIN_BLOCK_GAS_LIMIT, not 0
        let limit = FeeMarket::adaptive_gas_limit(0, 10);
        assert_eq!(
            limit, MIN_BLOCK_GAS_LIMIT,
            "zero prover capacity must return MIN_BLOCK_GAS_LIMIT"
        );
    }

    #[test]
    fn adversarial_adaptive_gas_limit_huge_prover() {
        // Huge prover capacity should be capped at DEFAULT_BLOCK_GAS_LIMIT
        let limit = FeeMarket::adaptive_gas_limit(u64::MAX, u64::MAX);
        assert_eq!(
            limit, DEFAULT_BLOCK_GAS_LIMIT,
            "huge prover capacity must be capped at DEFAULT_BLOCK_GAS_LIMIT"
        );
    }

    #[test]
    fn adversarial_distribute_max_fees() {
        // u64::MAX distributable fees should not panic
        let dist = FeeMarket::distribute_block_fees(u64::MAX, 0, u64::MAX);
        let total = (dist.sequencer_reward as u128)
            + (dist.prover_reward as u128)
            + (dist.da_reserve as u128)
            + (dist.protocol_treasury as u128);
        assert_eq!(
            total,
            u64::MAX as u128,
            "must sum correctly even at u64::MAX"
        );
    }

    // ── Burn cap tests ────────────────────────────────────────────

    #[test]
    fn test_burn_cap_no_limit_reached() {
        let mut market = FeeMarket::new();
        let result = market.apply_burn_cap(1_000, 100_000_000, 100_000_000);
        assert_eq!(result.actual_burned, 1_000);
        assert_eq!(result.treasury_redirected, 0);
        assert_eq!(market.cumulative_burned, 1_000);
        assert_eq!(market.epoch_burned, 1_000);
    }

    #[test]
    fn test_burn_cap_cumulative_limit() {
        let mut market = FeeMarket::new();
        let initial_supply = 1_000_000; // 1M sats
        // Cumulative cap = 500 bp of 1M = 50,000 sats
        // Epoch cap = 10 bp of 1M = 1,000 sats (smaller — would bottleneck)
        //
        // Pre-fill cumulative to just under the cap so cumulative is the
        // binding constraint, not the epoch cap.
        market.cumulative_burned = 49_500;

        // remaining_cumulative = 500, remaining_epoch = 1,000
        // actual = min(1_000, 500, 1_000) = 500  → cumulative is the limit
        let result = market.apply_burn_cap(1_000, initial_supply, initial_supply);
        assert_eq!(result.actual_burned, 500);
        assert_eq!(result.treasury_redirected, 500);

        // Reset epoch to isolate cumulative cap
        market.reset_epoch_burn();

        // Cumulative is now at 50,000 (cap) — all future burns redirected
        let result = market.apply_burn_cap(1_000, initial_supply, initial_supply);
        assert_eq!(result.actual_burned, 0);
        assert_eq!(result.treasury_redirected, 1_000);
    }

    #[test]
    fn test_burn_cap_epoch_limit() {
        let mut market = FeeMarket::new();
        let supply = 10_000_000; // 10M sats
        // Epoch cap = 0.1% of 10M = 10_000 sats
        let result = market.apply_burn_cap(10_000, supply, supply);
        assert_eq!(result.actual_burned, 10_000);

        // Next burn in same epoch should be redirected
        let result = market.apply_burn_cap(5_000, supply, supply);
        assert_eq!(result.actual_burned, 0);
        assert_eq!(result.treasury_redirected, 5_000);

        // After epoch reset, burning works again
        market.reset_epoch_burn();
        let result = market.apply_burn_cap(5_000, supply, supply);
        assert_eq!(result.actual_burned, 5_000);
        assert_eq!(result.treasury_redirected, 0);
    }

    #[test]
    fn test_burn_cap_zero_requested() {
        let mut market = FeeMarket::new();
        let result = market.apply_burn_cap(0, 100_000_000, 100_000_000);
        assert_eq!(result.actual_burned, 0);
        assert_eq!(result.treasury_redirected, 0);
    }

    #[test]
    fn test_treasury_redirected_in_distribution() {
        // Verify that burn-cap redirected amount flows to treasury
        let dist = FeeMarket::distribute_block_fees_at_height(
            5_000,  // priority fees
            5_000,  // graduated fees
            8_000,  // actual burned (after cap)
            2_000,  // redirected to treasury from burn cap
            u64::MAX,
        );
        assert_eq!(dist.treasury_redirected, 2_000);
        // Treasury = 10% of 10_000 + 2_000 redirected = 1_000 + 2_000 = 3_000
        assert_eq!(dist.protocol_treasury, 3_000);
    }
}
