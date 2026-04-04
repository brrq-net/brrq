//! Portal error types.

use brrq_crypto::hash::Hash256;
use thiserror::Error;

/// Errors that can occur during Portal operations.
#[derive(Debug, Error)]
pub enum PortalError {
    #[error("insufficient balance: need {need} sats, have {have} sats")]
    InsufficientBalance { need: u64, have: u64 },

    #[error("lock not found: {0}")]
    LockNotFound(Hash256),

    #[error("lock not active: {0}")]
    LockNotActive(Hash256),

    #[error("lock already settled: {0}")]
    LockAlreadySettled(Hash256),

    #[error("lock expired at block {expired_at}, current block {current}")]
    LockExpired { expired_at: u64, current: u64 },

    #[error("lock not yet expired: timeout block {timeout}, current block {current}")]
    LockNotExpired { timeout: u64, current: u64 },

    #[error("invalid signature on portal key")]
    InvalidSignature,

    #[error("nullifier already consumed (double-spend attempt)")]
    NullifierAlreadyConsumed,

    #[error("amount mismatch: lock has {lock_amount} sats, key claims {key_amount} sats")]
    AmountMismatch { lock_amount: u64, key_amount: u64 },

    #[error("owner mismatch: lock owned by {lock_owner}, key claims {key_owner}")]
    OwnerMismatch {
        lock_owner: String,
        key_owner: String,
    },

    #[error("timeout too short: minimum {min_blocks} blocks, got {got_blocks} blocks")]
    TimeoutTooShort { min_blocks: u64, got_blocks: u64 },

    #[error("lock amount must be non-zero")]
    ZeroAmount,

    #[error("lock amount overflow")]
    AmountOverflow,

    #[error("too many active locks for address (max {max})")]
    TooManyLocks { max: usize },

    #[error("timeout too long: maximum {max_blocks} blocks, got {got_blocks} blocks")]
    TimeoutTooLong { max_blocks: u64, got_blocks: u64 },

    #[error("lock ID collision: {0}")]
    LockIdCollision(Hash256),

    #[error("batch is empty")]
    EmptyBatch,

    #[error("batch too large: {size} claims, max {max}")]
    BatchTooLarge { size: usize, max: usize },

    #[error("FATAL: internal accounting invariant violated — node must halt")]
    InvariantViolation,
}

/// Errors specific to settlement operations.
#[derive(Debug, Error)]
pub enum SettlementError {
    #[error("portal error: {0}")]
    Portal(#[from] PortalError),

    #[error("settlement expired: lock timeout at block {timeout}, current block {current}")]
    Expired { timeout: u64, current: u64 },

    #[error("invalid merchant secret: sha256(secret) != condition_hash")]
    InvalidSecret,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("double spend: nullifier already consumed")]
    DoubleSpend,
}
