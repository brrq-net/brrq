//! Brrq prover — STARK proof generation and verification over BabyBear.
//!
//! ## Architecture (§5)
//!
//! The prover takes a zkVM execution trace and produces a ZK-STARK proof
//! that the execution was correct. This proof is:
//! - **Succinct**: ~100KB regardless of execution length
//! - **Transparent**: No trusted setup (hash-based)
//! - **Post-quantum**: Built on SHA-256 + Poseidon2, no elliptic curves
//!
//! ## Pipeline
//!
//! 1. zkVM executes transactions → execution trace
//! 2. Trace is converted to AIR (Algebraic Intermediate Representation)
//! 3. Columns are interpolated to polynomials via NTT over BabyBear
//! 4. Polynomials are evaluated on coset LDE domain (blowup = 4)
//! 5. Coprocessor trace (SHA-256, Merkle, Schnorr, SLH-DSA, EmitLog)
//!    is converted to algebraic form, committed, and linked via LogUp
//! 6. CPU and coprocessor AIR constraints are checked, quotients combined via RLC
//! 7. Register file LogUp validates CPU register reads against an
//!    independent write-tracking table
//! 8. FRI protocol proves low-degree of composition polynomial
//! 9. Fiat-Shamir transcript makes the protocol non-interactive
//! 10. Query proofs with Merkle authentication are assembled
//!
//! ## Field Choice
//!
//! BabyBear (p = 15×2²⁷+1) provides two-adicity 27, supporting power-of-2
//! multiplicative subgroups up to 2²⁷ = 134M elements for NTT and FRI.
//! M31 is retained for Poseidon2 hash in brrq-crypto.

pub mod air;
pub mod batch;
pub mod coprocessor_air;
pub mod error;
pub mod field;
pub mod field_ext;
pub mod fri;
pub mod gpu;
pub mod hash_config;
pub mod lookup;
pub mod plonky2_circuit;
pub mod plonky2_wrapper;
#[cfg(feature = "prover-pools")]
pub mod pool;
pub mod prover;
pub mod snark_wrapper;
pub mod sp1_wrapper;
pub mod trace_converter;
pub mod transcript;
pub mod types;
pub mod verifier;
#[cfg(feature = "prover-pools")]
pub mod zkla;

pub use air::{Air, RiscVAir};
pub use batch::BatchProverConfig;
pub use coprocessor_air::CoprocessorAir;
pub use error::ProverError;
pub use field::{AirField, Fp};
pub use field_ext::Fp4;
pub use hash_config::ProverHashConfig;
pub use lookup::LogUpArgument;
pub use plonky2_wrapper::Plonky2SnarkWrapper;
#[cfg(feature = "prover-pools")]
pub use pool::{
    BondStatus, PoolMember, PoolStats, ProofBond, ProofTask, ProverPool, ProverPoolManager,
    TaskStatus,
};
pub use prover::StarkProver;
pub use snark_wrapper::{ProofSystem, SnarkPublicInputs, WrappedSnarkProof};
pub use types::BatchProofRecord;
pub use verifier::StarkVerifier;
#[cfg(feature = "prover-pools")]
pub use zkla::{LivenessSignatures, UzkhrProver, ZklaAnchorData};
