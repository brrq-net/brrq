//! State management errors.

use thiserror::Error;

/// Errors from state operations.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("account not found: {address}")]
    AccountNotFound { address: String },

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("storage error: {msg}")]
    StorageError { msg: String },

    #[error("balance overflow: {address} balance would exceed u64::MAX")]
    BalanceOverflow { address: String },

    #[error("nonce overflow: {address} nonce would exceed u64::MAX")]
    NonceOverflow { address: String },
}
