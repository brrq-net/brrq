//! Gas metering for the Brrq zkVM.
//!
//! Every instruction in the zkVM has a gas cost reflecting its
//! STARK proving cost. Costs from whitepaper §4.4:
//!
//! | Operation                | Gas   | Rationale              |
//! |--------------------------|-------|------------------------|
//! | Simple arithmetic (ADD)  | 1-3   | Single RISC-V cycle    |
//! | Memory access (LOAD)     | 5-10  | Requires access proof   |
//! | SHA-256 (precompile)     | 50    | HW-optimized           |
//! | Schnorr verify           | 100   | One curve operation    |
//! | SLH-DSA verify           | 500   | Large signature (~7.9KB)|
//! | Merkle verify            | 30-60 | Depends on depth       |

use serde::{Deserialize, Serialize};

/// Gas cost constants for zkVM operations.
pub mod costs {
    /// Basic arithmetic operations (ADD, SUB, XOR, etc.)
    pub const ARITHMETIC_BASIC: u64 = 1;

    /// Multiplication (MUL)
    pub const ARITHMETIC_MUL: u64 = 2;

    /// Division (DIV, REM)
    pub const ARITHMETIC_DIV: u64 = 3;

    /// Memory load (LOAD)
    pub const MEMORY_LOAD: u64 = 5;

    /// Memory store (STORE)
    pub const MEMORY_STORE: u64 = 7;

    /// Branch/jump operations
    pub const BRANCH: u64 = 2;

    /// SHA-256 compress (precompile)
    pub const SHA256_COMPRESS: u64 = 50;

    /// Merkle path verification (precompile, per level)
    pub const MERKLE_VERIFY_PER_LEVEL: u64 = 5;

    /// Merkle path verification base cost
    pub const MERKLE_VERIFY_BASE: u64 = 30;

    /// Schnorr signature verification (precompile)
    pub const SCHNORR_VERIFY: u64 = 100;

    /// SLH-DSA signature verification (precompile)
    pub const SLH_DSA_VERIFY: u64 = 500;

    /// System call overhead
    pub const SYSCALL: u64 = 10;

    /// Storage load (SLOAD syscall)
    pub const STORAGE_LOAD: u64 = 200;

    /// Storage store (SSTORE syscall)
    pub const STORAGE_STORE: u64 = 5000;
}

/// Gas meter for tracking execution costs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gas {
    /// Maximum gas allowed for this execution.
    pub limit: u64,
    /// Gas consumed so far.
    pub used: u64,
}

impl Gas {
    /// Create a new gas meter with the given limit.
    #[inline]
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Remaining gas available.
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Try to consume gas. Returns false if insufficient.
    /// Uses checked_add to prevent overflow.
    #[inline]
    pub fn consume(&mut self, amount: u64) -> bool {
        match self.used.checked_add(amount) {
            Some(total) if total <= self.limit => {
                self.used = total;
                true
            }
            _ => false,
        }
    }

    /// Check if there's enough gas without consuming.
    #[inline]
    pub fn has_enough(&self, amount: u64) -> bool {
        self.used
            .checked_add(amount)
            .is_some_and(|total| total <= self.limit)
    }

    /// Check if gas is exhausted.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }

    /// Get the fraction of gas used (0.0 to 1.0).
    pub fn usage_fraction(&self) -> f64 {
        if self.limit == 0 {
            return 1.0;
        }
        self.used as f64 / self.limit as f64
    }
}

/// Default block gas limit.
///
/// Dynamically adjusted based on prover capacity,
/// ensuring every block can be proved in reasonable time.
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Minimum transaction gas (covers basic execution overhead).
pub const MIN_TRANSACTION_GAS: u64 = 21_000;

/// Graduated fee system per whitepaper §9.4.
///
/// Protocol-level transfer fee using a 4-tier logarithmic formula:
///
/// ```text
/// Fee_i = BaseFee_i + Rate_i × log₁₀(Amount_sats)
/// ```
///
/// | Tier | Range (sats)     | BaseFee | Rate |
/// |------|------------------|---------|------|
/// | 1    | < 100,000        | 10      | 8    |
/// | 2    | 100K – 10M       | 50      | 25   |
/// | 3    | 10M – 1B         | 100     | 45   |
/// | 4    | > 1B             | 150     | 50   |
///
/// Cap: 2000 sats.
///
/// **Boundary smoothing (§9.4):** Linear interpolation within ±10% of
/// each tier boundary prevents fee discontinuities at threshold crossings.
pub mod fee_tiers {
    /// Maximum protocol fee (satoshis).
    pub const FEE_CAP: u64 = 2000;

    /// Tier 1 threshold: amounts below 100,000 sats.
    pub const TIER1_THRESHOLD: u64 = 100_000;
    /// Tier 1 base fee.
    pub const TIER1_BASE: u64 = 10;
    /// Tier 1 logarithmic rate.
    pub const TIER1_RATE: u64 = 8;

    /// Tier 2 threshold: amounts below 10,000,000 sats.
    pub const TIER2_THRESHOLD: u64 = 10_000_000;
    /// Tier 2 base fee.
    pub const TIER2_BASE: u64 = 50;
    /// Tier 2 logarithmic rate.
    pub const TIER2_RATE: u64 = 25;

    /// Tier 3 threshold: amounts below 1,000,000,000 sats.
    pub const TIER3_THRESHOLD: u64 = 1_000_000_000;
    /// Tier 3 base fee.
    pub const TIER3_BASE: u64 = 100;
    /// Tier 3 logarithmic rate.
    pub const TIER3_RATE: u64 = 45;

    /// Tier 4 base fee (amounts ≥ 1B sats).
    pub const TIER4_BASE: u64 = 150;
    /// Tier 4 logarithmic rate.
    pub const TIER4_RATE: u64 = 50;

    /// Compute the graduated protocol fee for a transfer amount (in satoshis).
    ///
    /// Uses logarithmic formula: `Fee = BaseFee + Rate x log10(amount)`
    ///
    /// All arithmetic uses integer-only computation (u128 scaled) to ensure
    /// cross-platform determinism.
    ///
    /// Within +/-10% of each tier boundary, applies linear interpolation
    /// to smooth the fee transition (whitepaper S9.4).
    ///
    /// - Returns 0 for zero-value transfers (no fee charged).
    /// - Capped at [`FEE_CAP`] (2000 sats) regardless of transfer size.
    pub fn graduated_fee(amount_sats: u64) -> u64 {
        if amount_sats == 0 {
            return 0;
        }

        // Use integer log10 scaled by SCALE factor.
        let log10_scaled = integer_log10_scaled(amount_sats);

        // Check interpolation zones at tier boundaries (+/-10%).
        // Each boundary smoothly blends the two adjacent tier formulas.
        let fee_scaled = if let Some(f) = interpolate_boundary_int(
            amount_sats,
            log10_scaled,
            TIER1_THRESHOLD,
            TIER1_BASE,
            TIER1_RATE,
            TIER2_BASE,
            TIER2_RATE,
        ) {
            f
        } else if let Some(f) = interpolate_boundary_int(
            amount_sats,
            log10_scaled,
            TIER2_THRESHOLD,
            TIER2_BASE,
            TIER2_RATE,
            TIER3_BASE,
            TIER3_RATE,
        ) {
            f
        } else if let Some(f) = interpolate_boundary_int(
            amount_sats,
            log10_scaled,
            TIER3_THRESHOLD,
            TIER3_BASE,
            TIER3_RATE,
            TIER4_BASE,
            TIER4_RATE,
        ) {
            f
        } else if amount_sats < TIER1_THRESHOLD {
            tier_fee_int(TIER1_BASE, TIER1_RATE, log10_scaled)
        } else if amount_sats < TIER2_THRESHOLD {
            tier_fee_int(TIER2_BASE, TIER2_RATE, log10_scaled)
        } else if amount_sats < TIER3_THRESHOLD {
            tier_fee_int(TIER3_BASE, TIER3_RATE, log10_scaled)
        } else {
            tier_fee_int(TIER4_BASE, TIER4_RATE, log10_scaled)
        };

        // Convert from scaled back to actual fee (truncating = floor).
        let fee = (fee_scaled / SCALE) as u64;
        fee.min(FEE_CAP)
    }

    /// Scale factor for fixed-point integer arithmetic.
    /// 1_000_000 gives 6 decimal digits of precision, sufficient for fee
    /// calculations while staying well within u128 range.
    #[doc(hidden)]
    pub const SCALE: u128 = 1_000_000;

    /// Integer-only log10 approximation, returning result scaled by SCALE.
    ///
    /// Uses integer-only approximation to ensure cross-platform determinism.
    ///
    /// Uses a const lookup table of powers of 10 for O(1) binary-search-style
    /// lookup instead of a loop with checked_mul on every call.
    ///
    /// For amount=1, returns 0. For amount=10, returns 1*SCALE, etc.
    #[doc(hidden)]
    pub fn integer_log10_scaled(amount: u64) -> u128 {
        if amount <= 1 {
            return 0;
        }

        /// Const table of powers of 10 that fit in u64.
        /// 10^0 through 10^19 (10^19 = 10_000_000_000_000_000_000).
        const POW10: [u64; 20] = [
            1,
            10,
            100,
            1_000,
            10_000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
            1_000_000_000,
            10_000_000_000,
            100_000_000_000,
            1_000_000_000_000,
            10_000_000_000_000,
            100_000_000_000_000,
            1_000_000_000_000_000,
            10_000_000_000_000_000,
            100_000_000_000_000_000,
            1_000_000_000_000_000_000,
            10_000_000_000_000_000_000,
        ];

        // Find the integer part: floor(log10(amount)) via table lookup.
        let mut int_part: u32 = 0;
        let mut i = POW10.len() - 1;
        while i > 0 {
            if amount >= POW10[i] {
                int_part = i as u32;
                break;
            }
            i -= 1;
        }

        let lower = POW10[int_part as usize];
        let upper = if (int_part as usize + 1) < POW10.len() {
            POW10[int_part as usize + 1]
        } else {
            // amount is >= 10^19, clamp fractional part to 0.
            lower
        };

        // Linear interpolation for fractional part:
        // frac = (amount - lower) / (upper - lower)
        // log10 ~= int_part + frac
        let frac_scaled = if upper > lower {
            (amount - lower) as u128 * SCALE / (upper - lower) as u128
        } else {
            0
        };

        int_part as u128 * SCALE + frac_scaled
    }

    /// Raw fee for a tier using integer arithmetic:
    ///   fee_scaled = base * SCALE + rate * log10_scaled
    #[inline]
    fn tier_fee_int(base: u64, rate: u64, log10_scaled: u128) -> u128 {
        base as u128 * SCALE + rate as u128 * log10_scaled
    }

    /// Integer linear interpolation within +/-10% of a tier boundary.
    ///
    /// All arithmetic uses u128 scaled values. Returns scaled fee.
    /// Returns `None` if the amount is outside the interpolation zone.
    fn interpolate_boundary_int(
        amount: u64,
        log10_scaled: u128,
        threshold: u64,
        base_low: u64,
        rate_low: u64,
        base_high: u64,
        rate_high: u64,
    ) -> Option<u128> {
        let lower = threshold / 10 * 9; // threshold x 0.9
        let upper = threshold / 10 * 11; // threshold x 1.1

        if amount < lower || amount > upper {
            return None;
        }

        let fee_low = tier_fee_int(base_low, rate_low, log10_scaled);
        let fee_high = tier_fee_int(base_high, rate_high, log10_scaled);

        // Linear interpolation: fee = fee_low + (fee_high - fee_low) * (amount - lower) / (upper - lower)
        let numerator = (amount - lower) as u128;
        let denominator = (upper - lower) as u128;

        if fee_high >= fee_low {
            Some(fee_low + (fee_high - fee_low) * numerator / denominator)
        } else {
            Some(fee_low - (fee_low - fee_high) * numerator / denominator)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_basic() {
        let mut gas = Gas::new(1000);
        assert_eq!(gas.remaining(), 1000);
        assert!(!gas.is_exhausted());

        assert!(gas.consume(500));
        assert_eq!(gas.remaining(), 500);
        assert_eq!(gas.used, 500);
    }

    #[test]
    fn test_gas_exhaustion() {
        let mut gas = Gas::new(100);
        assert!(gas.consume(100));
        assert!(gas.is_exhausted());
        assert!(!gas.consume(1)); // Can't consume more
    }

    #[test]
    fn test_gas_overflow_protection() {
        let mut gas = Gas::new(100);
        assert!(!gas.consume(101)); // Exceeds limit
        assert_eq!(gas.used, 0); // Should not have consumed
    }

    #[test]
    fn test_gas_usage_fraction() {
        let mut gas = Gas::new(1000);
        gas.consume(250);
        assert!((gas.usage_fraction() - 0.25).abs() < f64::EPSILON);
    }

    // ── Graduated Fee System tests ──────────────────────────────────
    // Tests updated for integer arithmetic. Exact values
    // at exact powers of 10 remain unchanged. Non-power-of-10 values
    // may differ by +/-1 from previous f64 results due to linear
    // interpolation of log10 vs true logarithm.

    use fee_tiers::graduated_fee;

    #[test]
    fn test_graduated_fee_zero() {
        assert_eq!(graduated_fee(0), 0);
    }

    #[test]
    fn test_graduated_fee_one_sat() {
        // 1 sat: log10(1) = 0 -> fee = 10 + 8*0 = 10
        assert_eq!(graduated_fee(1), fee_tiers::TIER1_BASE);
    }

    #[test]
    fn test_graduated_fee_tier1() {
        // 10,000 sats: log10(10000) = 4.0 -> fee = 10 + 8*4 = 42
        let fee = graduated_fee(10_000);
        assert_eq!(fee, 10 + 8 * 4); // 42
    }

    #[test]
    fn test_graduated_fee_tier2() {
        // 1,000,000 sats: log10(1_000_000) = 6.0 -> fee = 50 + 25*6 = 200
        let fee = graduated_fee(1_000_000);
        assert_eq!(fee, 50 + 25 * 6); // 200
    }

    #[test]
    fn test_graduated_fee_tier3() {
        // 100,000,000 sats: log10(100_000_000) = 8.0 -> fee = 100 + 45*8 = 460
        let fee = graduated_fee(100_000_000);
        assert_eq!(fee, 100 + 45 * 8); // 460
    }

    #[test]
    fn test_graduated_fee_tier4() {
        // 10,000,000,000 sats: log10 = 10.0 -> fee = 150 + 50*10 = 650
        let fee = graduated_fee(10_000_000_000);
        assert_eq!(fee, 150 + 50 * 10); // 650
    }

    #[test]
    fn test_graduated_fee_cap() {
        // u64::MAX should not exceed FEE_CAP
        let fee = graduated_fee(u64::MAX);
        assert!(fee <= fee_tiers::FEE_CAP);
    }

    #[test]
    fn test_graduated_fee_boundary_tier1_tier2() {
        // With +/-10% interpolation, 100K is at the midpoint of [90K, 110K].
        // Integer log10 of 100_000 = exactly 5.0 * SCALE
        // fee_low (tier1) = 10 + 8*5 = 50, fee_high (tier2) = 50 + 25*5 = 175
        // interpolated = 50 + 0.5 * (175 - 50) = 112.5 -> 112 (truncated)
        let fee_at = graduated_fee(100_000);
        assert_eq!(fee_at, 112);
    }

    #[test]
    fn test_graduated_fee_boundary_tier2_tier3() {
        // 10M: integer log10 = exactly 7.0
        // fee_low (tier2) = 50 + 25*7 = 225, fee_high (tier3) = 100 + 45*7 = 415
        // interpolated = 225 + 0.5 * (415 - 225) = 320
        let fee = graduated_fee(10_000_000);
        assert_eq!(fee, 320);
    }

    #[test]
    fn test_graduated_fee_boundary_tier3_tier4() {
        // 1B: integer log10 = exactly 9.0
        // fee_low (tier3) = 100 + 45*9 = 505, fee_high (tier4) = 150 + 50*9 = 600
        // interpolated = 505 + 0.5 * (600 - 505) = 552.5 -> 552
        let fee = graduated_fee(1_000_000_000);
        assert_eq!(fee, 552);
    }

    #[test]
    fn test_graduated_fee_smooth_tier1_tier2() {
        // Verify smooth (monotonically increasing) transition across [90K, 110K].
        let fee_90k = graduated_fee(90_000);
        let fee_95k = graduated_fee(95_000);
        let fee_100k = graduated_fee(100_000);
        let fee_105k = graduated_fee(105_000);
        let fee_110k = graduated_fee(110_000);

        // Monotonically increasing across the boundary zone
        assert!(fee_95k >= fee_90k, "95K >= 90K");
        assert!(fee_100k >= fee_95k, "100K >= 95K");
        assert!(fee_105k >= fee_100k, "105K >= 100K");
        assert!(fee_110k >= fee_105k, "110K >= 105K");
    }

    #[test]
    fn test_graduated_fee_smooth_tier2_tier3() {
        // Verify smooth transition across [9M, 11M].
        let fee_9m = graduated_fee(9_000_000);
        let fee_10m = graduated_fee(10_000_000);
        let fee_11m = graduated_fee(11_000_000);

        // Monotonically increasing
        assert!(fee_10m >= fee_9m);
        assert!(fee_11m >= fee_10m);
    }

    #[test]
    fn test_graduated_fee_monotonic() {
        // Fees should increase with amount (including through boundaries)
        let amounts = [
            1,
            10,
            100,
            1_000,
            10_000,
            50_000,
            // Through tier 1->2 boundary zone
            89_000,
            90_000,
            95_000,
            100_000,
            105_000,
            110_000,
            111_000,
            500_000,
            1_000_000,
            5_000_000,
            // Through tier 2->3 boundary zone
            8_900_000,
            9_000_000,
            10_000_000,
            11_000_000,
            11_100_000,
            50_000_000,
            100_000_000,
            500_000_000,
            // Through tier 3->4 boundary zone
            899_000_000,
            900_000_000,
            1_000_000_000,
            1_100_000_000,
            1_101_000_000,
            5_000_000_000,
            10_000_000_000,
        ];
        for window in amounts.windows(2) {
            let fee_low = graduated_fee(window[0]);
            let fee_high = graduated_fee(window[1]);
            assert!(
                fee_high >= fee_low,
                "fee({}) = {} should be >= fee({}) = {}",
                window[1],
                fee_high,
                window[0],
                fee_low
            );
        }
    }

    // New test — verify determinism across calls.
    #[test]
    fn test_fee_deterministic() {
        // Same input must always produce same output — critical for consensus.
        let test_amounts = [
            0,
            1,
            42,
            999,
            10_000,
            50_000,
            90_000,
            100_000,
            110_000,
            500_000,
            1_000_000,
            9_000_000,
            10_000_000,
            11_000_000,
            100_000_000,
            900_000_000,
            1_000_000_000,
            1_100_000_000,
            10_000_000_000,
            u64::MAX,
        ];
        for &amount in &test_amounts {
            let fee1 = graduated_fee(amount);
            let fee2 = graduated_fee(amount);
            assert_eq!(
                fee1, fee2,
                "graduated_fee({}) not deterministic: {} vs {}",
                amount, fee1, fee2
            );
        }
    }

    // Verify integer log10 is exact at powers of 10.
    #[test]
    fn test_integer_log10_exact_powers() {
        use fee_tiers::{SCALE, integer_log10_scaled};
        assert_eq!(integer_log10_scaled(1), 0);
        assert_eq!(integer_log10_scaled(10), 1 * SCALE);
        assert_eq!(integer_log10_scaled(100), 2 * SCALE);
        assert_eq!(integer_log10_scaled(1_000), 3 * SCALE);
        assert_eq!(integer_log10_scaled(10_000), 4 * SCALE);
        assert_eq!(integer_log10_scaled(100_000), 5 * SCALE);
        assert_eq!(integer_log10_scaled(1_000_000), 6 * SCALE);
        assert_eq!(integer_log10_scaled(10_000_000), 7 * SCALE);
        assert_eq!(integer_log10_scaled(100_000_000), 8 * SCALE);
        assert_eq!(integer_log10_scaled(1_000_000_000), 9 * SCALE);
        assert_eq!(integer_log10_scaled(10_000_000_000), 10 * SCALE);
    }
}
