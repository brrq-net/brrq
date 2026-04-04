//! Runtime-configurable consensus parameters.
//!
//! ## Design
//!
//! `ConsensusParams` collects all tunable constants from across the consensus
//! modules into a single struct. The default values match the existing `const`
//! constants, ensuring backward compatibility. In the future, governance
//! proposals can update individual parameters at runtime without requiring a
//! hard fork.
//!
//! Modules that read from params should fall back to their own `const` values
//! if no params struct is provided, preserving the existing behaviour for
//! callers that haven't adopted params yet.

use crate::epoch::DEFAULT_EPOCH_LENGTH;
use crate::governance::{
    EXECUTION_WINDOW_BLOCKS, MIN_PROPOSAL_STAKE, MIN_USER_QUORUM, PROPOSAL_COOLDOWN_BLOCKS,
    VOTING_PERIOD_BLOCKS,
};
#[cfg(feature = "sequencer-rotation")]
use crate::rotation::DEFAULT_FINALITY_DEPTH;
#[cfg(not(feature = "sequencer-rotation"))]
const DEFAULT_FINALITY_DEPTH: u64 = 1;
use crate::slashing::{DELAY_PENALTY_BP, DOWNTIME_PENALTY_BP, EQUIVOCATION_PENALTY_BP};

/// Runtime-configurable consensus parameters.
///
/// All fields have defaults matching the existing `const` values from their
/// respective modules. Pass this struct to `SequencerEngine::new()` or
/// individual modules to override defaults.
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    /// Epoch length in L2 blocks.
    pub epoch_length: u64,
    /// Proposal timeout in milliseconds (rotation).
    pub proposal_timeout_ms: u64,
    /// Quorum numerator (default 2 for 2/3 quorum).
    pub quorum_numerator: u64,
    /// Quorum denominator (default 3 for 2/3 quorum).
    pub quorum_denominator: u64,
    /// Finality depth: blocks after quorum before settlement.
    pub finality_depth: u64,
    /// Downtime slashing penalty in basis points.
    pub downtime_penalty_bp: u64,
    /// Delay slashing penalty in basis points.
    pub delay_penalty_bp: u64,
    /// Equivocation slashing penalty in basis points.
    pub equivocation_penalty_bp: u64,
    /// Governance voting period in blocks.
    pub voting_period_blocks: u64,
    /// Governance proposal cooldown in blocks.
    pub proposal_cooldown_blocks: u64,
    /// Minimum proposal stake in satoshis.
    pub min_proposal_stake: u64,
    /// Minimum user quorum for governance.
    pub min_user_quorum: u64,
    /// Execution window for passed proposals in blocks.
    pub execution_window_blocks: u64,
}

impl ConsensusParams {
    /// Validate that all parameters are within safe bounds.
    ///
    /// Returns `Err` with a description of the first invalid parameter found.
    pub fn validate(&self) -> Result<(), String> {
        if self.quorum_denominator == 0 {
            return Err("quorum_denominator must be > 0".into());
        }
        if self.quorum_numerator > self.quorum_denominator {
            return Err(format!(
                "quorum_numerator ({}) must be <= quorum_denominator ({})",
                self.quorum_numerator, self.quorum_denominator
            ));
        }
        // Enforce quorum >= 2/3 to prevent governance from weakening consensus
        // safety. The invariant `num * 3 >= den * 2` is equivalent to
        // `num/den >= 2/3` using only integer arithmetic (no precision loss).
        if self.quorum_numerator * 3 < self.quorum_denominator * 2 {
            return Err(format!(
                "quorum ratio {}/{} is below the minimum 2/3 – \
                 governance cannot reduce the quorum below this threshold",
                self.quorum_numerator, self.quorum_denominator
            ));
        }
        if self.epoch_length == 0 {
            return Err("epoch_length must be > 0".into());
        }
        if self.equivocation_penalty_bp > 10_000 {
            return Err(format!(
                "equivocation_penalty_bp ({}) must be <= 10_000",
                self.equivocation_penalty_bp
            ));
        }
        if self.finality_depth == 0 {
            return Err("finality_depth must be > 0".into());
        }
        Ok(())
    }
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            epoch_length: DEFAULT_EPOCH_LENGTH,
            proposal_timeout_ms: 6_000,
            quorum_numerator: 2,
            quorum_denominator: 3,
            finality_depth: DEFAULT_FINALITY_DEPTH,
            downtime_penalty_bp: DOWNTIME_PENALTY_BP,
            delay_penalty_bp: DELAY_PENALTY_BP,
            equivocation_penalty_bp: EQUIVOCATION_PENALTY_BP,
            voting_period_blocks: VOTING_PERIOD_BLOCKS,
            proposal_cooldown_blocks: PROPOSAL_COOLDOWN_BLOCKS,
            min_proposal_stake: MIN_PROPOSAL_STAKE,
            min_user_quorum: MIN_USER_QUORUM,
            execution_window_blocks: EXECUTION_WINDOW_BLOCKS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_match_constants() {
        let p = ConsensusParams::default();
        assert_eq!(p.epoch_length, DEFAULT_EPOCH_LENGTH);
        assert_eq!(p.quorum_numerator, 2);
        assert_eq!(p.quorum_denominator, 3);
        assert_eq!(p.finality_depth, DEFAULT_FINALITY_DEPTH);
        assert_eq!(p.downtime_penalty_bp, DOWNTIME_PENALTY_BP);
        assert_eq!(p.delay_penalty_bp, DELAY_PENALTY_BP);
        assert_eq!(p.equivocation_penalty_bp, EQUIVOCATION_PENALTY_BP);
        assert_eq!(p.voting_period_blocks, VOTING_PERIOD_BLOCKS);
        assert_eq!(p.proposal_cooldown_blocks, PROPOSAL_COOLDOWN_BLOCKS);
        assert_eq!(p.min_proposal_stake, MIN_PROPOSAL_STAKE);
        assert_eq!(p.min_user_quorum, MIN_USER_QUORUM);
        assert_eq!(p.execution_window_blocks, EXECUTION_WINDOW_BLOCKS);
    }

    // Ensure quorum below 2/3 is rejected by validate().
    #[test]
    fn quorum_below_two_thirds_rejected() {
        // 1/3 is clearly below 2/3 – must be rejected.
        let p = ConsensusParams {
            quorum_numerator: 1,
            quorum_denominator: 3,
            ..Default::default()
        };
        let err = p.validate().unwrap_err();
        assert!(
            err.contains("below the minimum 2/3"),
            "unexpected error: {err}"
        );

        // 1/2 = 0.5 < 2/3 – must be rejected.
        let p2 = ConsensusParams {
            quorum_numerator: 1,
            quorum_denominator: 2,
            ..Default::default()
        };
        assert!(p2.validate().is_err());
    }

    // Exact 2/3 and higher quorums must pass validation.
    #[test]
    fn quorum_at_or_above_two_thirds_accepted() {
        // Exact 2/3 – the minimum allowed.
        let p = ConsensusParams {
            quorum_numerator: 2,
            quorum_denominator: 3,
            ..Default::default()
        };
        assert!(p.validate().is_ok());

        // 3/4 = 0.75 > 2/3 – must pass.
        let p2 = ConsensusParams {
            quorum_numerator: 3,
            quorum_denominator: 4,
            ..Default::default()
        };
        assert!(p2.validate().is_ok());
    }

    #[test]
    fn custom_params_override() {
        let p = ConsensusParams {
            epoch_length: 1000,
            finality_depth: 5,
            equivocation_penalty_bp: 5000,
            ..Default::default()
        };
        assert_eq!(p.epoch_length, 1000);
        assert_eq!(p.finality_depth, 5);
        assert_eq!(p.equivocation_penalty_bp, 5000);
        // Others should remain at defaults
        assert_eq!(p.quorum_numerator, 2);
    }
}
