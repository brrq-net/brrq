//! SDK error types.

use thiserror::Error;

/// SDK errors.
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("wallet not initialized")]
    WalletNotInitialized,

    #[error("key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("signing failed: {reason}")]
    SigningFailed { reason: String },

    #[error("transaction build failed: {reason}")]
    TransactionBuildFailed { reason: String },

    #[error("RPC error: {reason}")]
    RpcError { reason: String },

    /// TLS handshake or configuration failure.
    #[error("TLS error: {reason}")]
    TlsError { reason: String },

    #[error("insufficient balance: need {required}, have {available}")]
    InsufficientBalance { required: u64, available: u64 },

    #[error("invalid address: {addr}")]
    InvalidAddress { addr: String },
}
