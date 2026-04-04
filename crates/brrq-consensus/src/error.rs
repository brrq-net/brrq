//! Consensus error types.

use thiserror::Error;

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

/// Consensus-layer errors.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("validator not found: {0}")]
    ValidatorNotFound(Address),

    #[error("validator already registered: {0}")]
    ValidatorAlreadyRegistered(Address),

    #[error("insufficient stake: need {required} sat, have {actual} sat")]
    InsufficientStake { required: u64, actual: u64 },

    #[error("validator is unbonding")]
    ValidatorUnbonding,

    #[error("no active validators")]
    NoActiveValidators,

    #[error("invalid block: {reason}")]
    InvalidBlock { reason: String },

    #[error("equivocation detected at height {height}")]
    Equivocation { height: u64 },

    #[error("leader election failed: {reason}")]
    LeaderElectionFailed { reason: String },

    // ── Governance errors ──────────────────────────────────────────
    #[error("proposal not found: {id}")]
    ProposalNotFound { id: Hash256 },

    // ── Arithmetic safety ────────────────────────────────────────
    #[error("total effective stake overflowed u64")]
    StakeOverflow,

    // ── RANDAO validation ──────────────────────────────────────
    #[error("invalid RANDAO commitment: {reason}")]
    InvalidRandaoCommitment { reason: String },

    // ── Enhanced Governance (Bicameral Constitution) ──────────────
    #[error("doctrine firewall rejected proposal: law {law_number} — {reason}")]
    DoctrineViolation { law_number: u8, reason: String },

    // ── View Sync errors ────────────────────────────────────────
    #[error("stale timeout certificate: round {round} <= highest certified {highest}")]
    StaleTimeoutCertificate { round: u32, highest: u32 },

    #[error(
        "timeout certificate quorum insufficient: {aggregate_stake} of {required_stake} required"
    )]
    TimeoutCertificateQuorumInsufficient {
        aggregate_stake: u64,
        required_stake: u64,
    },

    // ── Execution window ────────────────────────────────────────
    #[error("execution window expired at block {deadline}")]
    ExecutionWindowExpired { deadline: u64 },

    // ── VRF proof verification ─────────────────────────────────
    #[error("invalid VRF proof: cryptographic verification failed")]
    InvalidVrfProof,

    // ── Sequence number replay protection ──────────────────────
    #[error("replayed message from {sender}: sequence {sequence} <= high-water mark")]
    ReplayedMessage { sender: Address, sequence: u64 },
}
