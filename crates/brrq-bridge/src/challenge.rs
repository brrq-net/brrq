//! Challenge types for the BitVM2 fraud detection protocol.
//!
//! Per whitepaper SS6.4, the challenge mechanism allows any observer to
//! dispute invalid state transitions. The protocol follows the BitVM2
//! Kickoff -> Challenge -> Disprove/Take game:
//!
//! 1. Observer detects fraud (invalid state root, bad SNARK wrapping, etc.)
//! 2. Observer submits a `Challenge` with evidence
//! 3. Operator has `CHALLENGE_RESPONSE_WINDOW` to respond with a valid proof
//! 4. If no response: operator is guilty by default (bond forfeited)
//! 5. If response: ChallengeManager verifies and resolves
//!
//! ## Challenge Types
//!
//! - `InvalidStateRoot`: State root in anchor doesn't match actual execution
//! - `InvalidSnarkWrapping`: SNARK commitment doesn't match the STARK proof
//! - `InvalidWithdrawalProof`: Withdrawal proof doesn't bind to claimed state

use brrq_crypto::hash::Hash256;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

// ── Constants ───────────────────────────────────────────────────────────────

/// Response window for challenges (in L2 blocks).
///
/// ~48 hours at 3 seconds/block = 57,600 blocks.
/// This gives the operator sufficient time to generate and submit a counter-proof.
pub const CHALLENGE_RESPONSE_WINDOW: u64 = 57_600;

/// Minimum bond a challenger must post (satoshis).
///
/// Without a bond, challengers face zero cost for spam challenges.
/// Each challenge forces the operator to generate an expensive STARK proof.
/// Bond is returned if the challenge proves fraud; forfeited if dismissed.
/// 0.01 BTC — high enough to deter spam, low enough for legitimate whistleblowers.
pub const CHALLENGE_BOND: u64 = 1_000_000; // 0.01 BTC

// ── Challenge Types ─────────────────────────────────────────────────────────

/// Types of challenges that an observer can submit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    /// State root in an L1 anchor doesn't match actual execution.
    ///
    /// The challenger provides both the claimed (from the anchor) and the
    /// actual (from re-execution or an alternative full node) state root,
    /// along with the L2 height at which the discrepancy occurred.
    InvalidStateRoot {
        /// State root claimed in the L1 anchor.
        claimed_state_root: Hash256,
        /// Actual state root computed by the challenger.
        actual_state_root: Hash256,
        /// L2 block height where the discrepancy was found.
        l2_height: u64,
    },

    /// SNARK commitment in the L1 anchor doesn't match the STARK proof.
    ///
    /// The challenger has the full STARK proof and can show that hashing
    /// the SNARK wrapper produces a different commitment than what was
    /// posted on L1.
    InvalidSnarkWrapping {
        /// SNARK commitment from the L1 anchor (first 31 bytes of hash).
        anchor_snark_commitment: [u8; 31],
        /// Actual SNARK commitment computed from the STARK proof.
        actual_snark_commitment: [u8; 31],
        /// Block range from the batch (l2_height_start, l2_height_end).
        /// Required for re-wrapping verification against the actual batch range.
        l2_height_start: u64,
        l2_height_end: u64,
    },

    /// Withdrawal proof doesn't bind to the claimed state transition.
    ///
    /// The challenger detected that a withdrawal was verified using a
    /// proof whose state roots don't match the actual chain state.
    InvalidWithdrawalProof {
        /// The disputed withdrawal ID.
        withdrawal_id: Hash256,
        /// State root from the proof used to verify the withdrawal.
        proof_state_root: Hash256,
        /// Actual state root from re-execution.
        claimed_state_root: Hash256,
    },
}

// ── Challenge Status ────────────────────────────────────────────────────────

/// Status of a challenge in the dispute resolution protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Challenge submitted, waiting for operator response.
    Pending,
    /// Operator responded with counter-evidence.
    Responded,
    /// Challenge validated — operator is guilty (fraud proven).
    Proven,
    /// Challenge rejected — operator is innocent (challenge invalid).
    Dismissed,
    /// Challenge expired without response — operator guilty by default.
    Expired,
}

impl ChallengeStatus {
    /// Whether this status is a final resolution.
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Proven | Self::Dismissed | Self::Expired)
    }
}

// ── Challenge Response ──────────────────────────────────────────────────────

/// Operator's response to a challenge.
///
/// The operator must provide a valid STARK proof hash and the correct
/// state root to dismiss the challenge.
///
/// The `responder` field tracks who submitted the response.
/// Enforcement that only registered operators can respond is handled by
/// `BridgeManager::respond_to_challenge()`. Per-operator enforcement
/// (restricting responses to the specific challenged operator) is deferred
/// until challenges are linked to specific operator bonds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// SHA-256 hash of the STARK proof showing correct state transition.
    pub proof_hash: Hash256,
    /// The correct state root (matching the proof).
    pub correct_state_root: Hash256,
    /// Address of the operator who submitted this response.
    ///
    /// Registered-operator enforcement is in
    /// `BridgeManager::respond_to_challenge()`. Per-operator identity
    /// enforcement is deferred until challenges are linked to specific bonds.
    pub responder: Address,
}

// ── Challenge ───────────────────────────────────────────────────────────────

/// A challenge submitted by an observer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID (SHA-256 of challenge type + challenger + height).
    pub challenge_id: Hash256,
    /// The type of fraud and its evidence.
    pub challenge_type: ChallengeType,
    /// Address of the observer who submitted the challenge.
    pub challenger: Address,
    /// L2 height when the challenge was submitted.
    pub submitted_at_height: u64,
    /// Current status of the challenge.
    pub status: ChallengeStatus,
    /// Counter-evidence from the operator (if any).
    pub response: Option<ChallengeResponse>,
    /// Bond posted by the challenger (satoshis).
    /// Returned if challenge proves fraud; forfeited if dismissed.
    pub bond: u64,
}

// ── Statistics ──────────────────────────────────────────────────────────────

/// Aggregate statistics about challenge activity.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChallengeStats {
    /// Total challenges submitted.
    pub total: u64,
    /// Currently pending challenges.
    pub pending: u64,
    /// Challenges that proved fraud.
    pub proven: u64,
    /// Challenges that were dismissed.
    pub dismissed: u64,
    /// Challenges that expired (operator guilty by default).
    pub expired: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_status_is_resolved() {
        assert!(!ChallengeStatus::Pending.is_resolved());
        assert!(!ChallengeStatus::Responded.is_resolved());
        assert!(ChallengeStatus::Proven.is_resolved());
        assert!(ChallengeStatus::Dismissed.is_resolved());
        assert!(ChallengeStatus::Expired.is_resolved());
    }

    #[test]
    fn challenge_stats_default() {
        let stats = ChallengeStats::default();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.proven, 0);
        assert_eq!(stats.dismissed, 0);
        assert_eq!(stats.expired, 0);
    }

    #[test]
    fn challenge_type_equality() {
        let c1 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        let c2 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        assert_eq!(c1, c2);
    }
}
