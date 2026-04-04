//! Bridge error types.

use thiserror::Error;

use brrq_crypto::hash::Hash256;

/// Bridge-layer errors.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("deposit not found: {tx_id}")]
    DepositNotFound { tx_id: Hash256 },

    #[error("duplicate deposit: tx_id={tx_id}, vout={vout}")]
    DuplicateDeposit { tx_id: Hash256, vout: u32 },

    #[error("withdrawal not found: {tx_id}")]
    WithdrawalNotFound { tx_id: Hash256 },

    /// Reserved for when SPV deposit verification moves on-chain.
    #[cfg(feature = "phase4-placeholder")]
    #[error("invalid deposit proof")]
    InvalidDepositProof,

    #[error("invalid withdrawal amount: {reason}")]
    InvalidAmount { reason: String },

    #[error("zero amount")]
    ZeroAmount,

    #[error("invalid cryptographic proof: {reason}")]
    InvalidProof { reason: String },

    #[error("challenge period not expired: {remaining_blocks} blocks remaining")]
    ChallengePeriodActive { remaining_blocks: u64 },

    #[error("withdrawal already claimed: {tx_id}")]
    AlreadyClaimed { tx_id: Hash256 },

    #[error("bridge paused")]
    BridgePaused,

    #[error("deposit below minimum: {amount} sat < {min} sat")]
    DepositBelowMinimum { amount: u64, min: u64 },

    #[error("deposit exceeds maximum: {amount} sat > {max} sat")]
    DepositExceedsMaximum { amount: u64, max: u64 },

    #[error("withdrawal exceeds maximum: {amount} sat > {max} sat")]
    WithdrawalExceedsMaximum { amount: u64, max: u64 },

    /// Reject dust withdrawals that would incur zero fee.
    #[error("withdrawal below minimum: {amount} sat < {min} sat")]
    AmountBelowMinimum { amount: u64, min: u64 },

    #[error("duplicate withdrawal ID: {0}")]
    DuplicateWithdrawal(Hash256),

    #[error("bridge cap reached: total_locked {current} + deposit {amount} > cap {cap}")]
    BridgeCapReached { current: u64, amount: u64, cap: u64 },

    #[error("daily volume limit exceeded: {used} + {amount} > {limit} sat/day for address")]
    DailyVolumeLimitExceeded { used: u64, amount: u64, limit: u64 },

    // ── Challenge errors ──────────────────────────────────────────────────
    #[error("challenge not found: {challenge_id}")]
    ChallengeNotFound { challenge_id: Hash256 },

    #[error("challenge already exists for this issue")]
    DuplicateChallenge,

    /// Reserved for when challenge window enforcement moves on-chain.
    #[cfg(feature = "phase4-placeholder")]
    #[error("challenge window expired")]
    ChallengeWindowExpired,

    #[error("invalid challenge evidence: {reason}")]
    InvalidChallengeEvidence { reason: String },

    // ── Operator errors ───────────────────────────────────────────────────
    #[error("operator not found: {address}")]
    OperatorNotFound { address: brrq_types::Address },

    #[error("operator already registered")]
    OperatorAlreadyRegistered,

    #[error("responder is not a registered operator — only operators can respond to challenges")]
    OperatorNotRegistered,

    #[error("invalid status transition from {from} to {to}")]
    InvalidStatusTransition { from: String, to: String },

    #[error("withdrawal already claimed by operator")]
    WithdrawalAlreadyClaimed,

    #[error("operator has {count} active withdrawal(s) — settle before deregistering")]
    OperatorHasActiveWithdrawals { count: usize },

    #[error("operator has {count} pending/eligible reimbursement(s) — claim before deregistering")]
    OperatorHasPendingReimbursements { count: usize },

    #[error("reimbursement not eligible yet: {remaining_blocks} blocks remaining")]
    ReimbursementNotEligible { remaining_blocks: u64 },

    // ── BitVM2 mode transition errors ──────────────────────────────────
    #[error("insufficient operators for BitVM2 mode: need {required}, have {actual}")]
    InsufficientOperators { required: usize, actual: usize },

    #[error("operator missing BitVM2 bond: {address}")]
    OperatorMissingBond { address: brrq_types::Address },

    // ── BitVM2 bond verification errors ─────────────────────────────
    #[error("bond script mismatch: expected Taproot output does not match on-chain UTXO")]
    BondScriptMismatch,

    #[error("invalid operator pubkey: not a valid secp256k1 x-only public key")]
    InvalidOperatorPubkey,

    // ── Rate limiting errors ──────────────────────────────────────────
    #[error("rate limited: retry after {retry_after_blocks} blocks")]
    RateLimited { retry_after_blocks: u64 },

    // ── Authentication errors ────────────────────────────────────────
    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    // ── Multi-UTXO pool errors ────────────────────────
    #[error("UTXO not found in pool: txid={txid}, vout={vout}")]
    UtxoNotFound { txid: String, vout: u32 },

    #[error("UTXO not available: txid={txid}, vout={vout}, current status prevents operation")]
    UtxoNotAvailable { txid: String, vout: u32 },

    #[error(
        "insufficient available balance in UTXO pool: need {required} sat, have {available} sat"
    )]
    InsufficientPoolBalance { required: u64, available: u64 },
}
