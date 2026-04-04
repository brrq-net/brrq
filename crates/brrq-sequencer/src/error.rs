//! Sequencer error types.

use thiserror::Error;

/// Errors that can occur in the sequencer.
#[derive(Debug, Error)]
pub enum SequencerError {
    #[error("transaction validation failed: {reason}")]
    InvalidTransaction { reason: String },

    #[error("mempool full: capacity {capacity}, current {current}")]
    MempoolFull { capacity: usize, current: usize },

    #[error("duplicate transaction: {tx_hash}")]
    DuplicateTransaction { tx_hash: String },

    #[error("nonce too low: expected {expected}, got {got}")]
    NonceTooLow { expected: u64, got: u64 },

    #[error("insufficient gas: need {need}, account has {have}")]
    InsufficientGas { need: u64, have: u64 },

    #[error("state error: {msg}")]
    StateError { msg: String },

    #[error("execution error: {msg}")]
    ExecutionError { msg: String },

    #[error("signing error: {msg}")]
    SigningError { msg: String },
}

impl From<brrq_state::StateError> for SequencerError {
    fn from(e: brrq_state::StateError) -> Self {
        SequencerError::StateError { msg: e.to_string() }
    }
}
