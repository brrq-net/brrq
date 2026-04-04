//! Hash backend configuration for the STARK prover.
//!
//! Controls which hash function is used for Merkle commitments in FRI and
//! the execution trace. The default is SHA-256 for L1 compatibility.
//!
//! ## Dual-Commitment Mode
//!
//! When `DualCommitment` is selected, the prover generates BOTH:
//! - SHA-256 Merkle roots (posted to L1 / used in STARK verification)
//! - Poseidon2 Merkle roots (used by the Plonky2 circuit for efficient in-circuit verification)
//!
//! This is critical for Phase B (real Plonky2): verifying SHA-256 in a Plonky2 circuit
//! costs ~27K constraints per hash, while Poseidon2 costs ~300 constraints.

use serde::{Deserialize, Serialize};

/// Hash backend selection for the STARK prover.
///
/// Controls which Merkle tree hash function is used for FRI and trace commitments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProverHashConfig {
    /// SHA-256 only — no Poseidon2 commitments.
    ///
    /// Use when Poseidon2 overhead is not needed (e.g., benchmarking SHA-256 path).
    Sha256,

    /// Dual: both SHA-256 and Poseidon2 commitments generated in parallel (default).
    ///
    /// The SHA-256 commitment is authoritative (posted to L1, used by STARK verifier).
    /// The Poseidon2 commitment enables efficient Plonky2 in-circuit verification
    /// (~300 constraints vs ~27K for SHA-256).
    #[default]
    DualCommitment,
}

impl ProverHashConfig {
    /// Whether this config produces Poseidon2 commitments.
    pub fn has_poseidon2(&self) -> bool {
        matches!(self, Self::DualCommitment)
    }
}
