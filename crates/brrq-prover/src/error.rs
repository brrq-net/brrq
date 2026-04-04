//! Prover error types.

use thiserror::Error;

/// Errors from proof generation or verification.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("empty execution trace")]
    EmptyTrace,

    #[error("trace validation failed: {reason}")]
    InvalidTrace { reason: String },

    #[error("proof generation failed: {reason}")]
    ProofGenerationFailed { reason: String },

    #[error("proof verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("invalid proof format: {reason}")]
    InvalidProof { reason: String },

    #[error("commitment mismatch at index {index}")]
    CommitmentMismatch { index: usize },

    #[error("batch proving error: {reason}")]
    BatchError { reason: String },
}
