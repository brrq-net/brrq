//! Proof types for the STARK prover.

use brrq_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

use crate::field::Fp;
use crate::field_ext::Fp4;
use crate::fri::FriProof;
use crate::snark_wrapper::WrappedSnarkProof;

/// A STARK proof of correct zkVM execution.
///
/// ## Structure
///
/// The proof contains:
/// 1. Trace commitment (Merkle root of execution trace columns)
/// 2. OOD Evaluation Frame (trace polynomials at random point z)
/// 3. Composition Polynomial commitment (combined constraint quotients)
/// 4. FRI commitments and queries (low-degree test)
/// 5. Metadata (step count, gas, state roots)
///
/// ## Verification
///
/// The verifier checks:
/// 1. AIR constraints hold at the OOD point
/// 2. FRI proves the composition polynomial is low-degree
/// 3. Query openings are consistent with Merkle commitments
/// 4. All Fiat-Shamir challenges match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// Merkle root of the execution trace columns.
    pub trace_commitment: Hash256,
    /// Merkle root of the composition polynomial evaluations.
    pub composition_commitment: Hash256,
    /// Evaluation of the composition polynomial at the OOD point z ∈ Fp4.
    ///
    /// The OOD challenge z is now sampled from the quartic extension
    /// field BabyBear⁴ = F_p[x]/(x⁴+11), giving ~102-bit OOD security instead
    /// of the previous ~10-bit security from the base field.
    pub composition_at_z: Fp4,
    /// Out-of-Domain evaluation frame for AIR transition constraints.
    ///
    /// Trace polynomials (with Fp coefficients) evaluated at the
    /// extension field OOD point z ∈ Fp4 produce Fp4 values.
    pub ood_frame: OodFrame,
    /// FRI layer commitments (one per folding round).
    pub fri_commitments: Vec<Hash256>,
    /// Query responses with authentication paths.
    pub query_proofs: Vec<QueryProof>,
    /// Number of execution steps proved.
    pub num_steps: u64,
    /// Total gas consumed in the proved execution.
    pub total_gas: u64,
    /// Initial state root (before execution).
    pub initial_state_root: Hash256,
    /// Final state root (after execution).
    pub final_state_root: Hash256,
    /// Hashes of the Coprocessor computations (e.g., SHA256).
    pub coprocessor_hashes: Vec<Hash256>,
    /// Merkle root of the coprocessor trace table.
    pub coprocessor_commitment: Hash256,
    /// Number of coprocessor calls (rows in coprocessor table).
    pub coprocessor_num_rows: usize,
    /// LogUp final sum from the CPU side (round 0, backward compat).
    pub logup_cpu_final_sum: Fp,
    /// LogUp final sum from the coprocessor side (round 0, backward compat).
    pub logup_coproc_final_sum: Fp,
    /// Per-round LogUp sums for multi-round soundness amplification.
    /// Each entry is (cpu_sum, coproc_sum) for one independent LogUp round.
    /// With LOGUP_ROUNDS=4, combined soundness is ~2^-124.
    #[serde(default)]
    pub logup_round_sums: Vec<(Fp, Fp)>,
    /// The trace domain log-size (needed by verifier to reconstruct domain).
    pub trace_log_size: u32,
    /// FRI final constant value (needed by verifier for transcript replay).
    pub fri_final_value: Fp,
    /// Number of FRI queries (needed by verifier for transcript replay).
    pub num_fri_queries: usize,
    /// Full FRI proof data (query openings, Merkle paths, folding consistency).
    /// Required for actual FRI verification (low-degree test).
    #[serde(default)]
    pub fri_proof: Option<FriProof>,

    /// Poseidon2 Merkle root of the execution trace (for Plonky2 circuit).
    /// Present only when `ProverHashConfig::DualCommitment` was used.
    #[serde(default)]
    pub poseidon2_trace_commitment: Option<Hash256>,
    /// Poseidon2 Merkle root of the composition polynomial (for Plonky2 circuit).
    #[serde(default)]
    pub poseidon2_composition_commitment: Option<Hash256>,

    /// Register file LogUp: per-round sums (cpu_total, regfile_total).
    /// Each entry is (cpu_sum, regfile_sum) for one independent LogUp round.
    /// With LOGUP_ROUNDS=4, combined soundness is ~2^-124.
    /// Empty for proofs generated before Phase 1B.
    #[serde(default)]
    pub regfile_logup_round_sums: Vec<(Fp, Fp)>,

    /// Bitwise LogUp: per-round sums (cpu_total, table_total).
    /// Each entry is (cpu_sum, table_sum) for one independent LogUp round.
    /// With BITWISE_LOGUP_ROUNDS=4, combined soundness is ~2^-124.
    /// Proves XOR/OR/AND byte-level correctness.
    #[serde(default)]
    pub bitwise_logup_round_sums: Vec<(Fp, Fp)>,

    /// Running sum Merkle commitments for each LogUp subsystem.
    ///
    /// These bind the prover to specific running sum columns BEFORE
    /// the verifier checks final sum equality. Without these commitments,
    /// a malicious prover can forge matching final sums trivially.
    ///
    /// Each Vec contains one Hash256 per LogUp round (LOGUP_ROUNDS entries).
    #[serde(default)]
    pub logup_running_sum_commitments: Vec<Hash256>,
    #[serde(default)]
    pub regfile_running_sum_commitments: Vec<Hash256>,
    #[serde(default)]
    pub bitwise_running_sum_commitments: Vec<Hash256>,

    /// Out-of-Domain evaluation frame for coprocessor AIR constraints.
    /// Contains coprocessor trace columns evaluated at the OOD point z ∈ Fp4
    /// (current row) and z·ω_coproc (next row). Empty if no coprocessor
    /// calls were made. Used by the verifier to include coprocessor AIR
    /// constraints in the composition_at_z recomputation.
    #[serde(default)]
    pub coproc_ood_frame: Option<OodFrame>,
}

impl StarkProof {
    /// Serialize the proof to bytes (bincode format).
    ///
    /// Returns an error if serialization fails (should not happen in practice).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("StarkProof serialization failed: {e}"))
    }

    /// Deserialize a proof from bytes (bincode format).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("invalid proof bytes: {e}"))
    }

    /// Estimated proof size in bytes.
    pub fn size(&self) -> usize {
        // Fixed: 2 state roots + trace commitment + composition commitment + composition_at_z (Fp4=16B)
        //        + num_steps + gas + log_size + fri_final + fri_queries
        let fixed = 32 * 4 + 16 + 8 + 8 + 4 + 4 + 8;
        // OOD Frame: current and next rows (each width * 16 bytes for Fp4)
        let ood = self.ood_frame.current.len() * 16 * 2;
        // FRI commitments: 32 bytes each
        let fri = self.fri_commitments.len() * 32;
        // FRI proof: query openings with Merkle paths
        let fri_proof_size = self.fri_proof.as_ref().map_or(0, |fp| {
            let layers = fp.layer_commitments.len() * 32;
            let alphas = fp.alphas.len() * 4;
            let openings: usize = fp
                .query_openings
                .iter()
                .map(|o| {
                    8 + o.layer_values.len() * 8
                        + o.merkle_paths_pos
                            .iter()
                            .map(|p| p.len() * 32)
                            .sum::<usize>()
                        + o.merkle_paths_sibling
                            .iter()
                            .map(|p| p.len() * 32)
                            .sum::<usize>()
                })
                .sum();
            layers + alphas + 4 + openings
        });
        // Query proofs: variable size
        let queries: usize = self.query_proofs.iter().map(|q| q.size()).sum();
        let coprocessor = self.coprocessor_hashes.len() * 32;
        // Coprocessor commitment (32) + num_rows (8) + logup sums (2 × 4)
        let coproc_meta = 32 + 8 + 8;
        // LogUp round sums: coprocessor + regfile + bitwise (each: rounds × 2 Fp × 4 bytes)
        let logup_sums = (self.logup_round_sums.len()
            + self.regfile_logup_round_sums.len()
            + self.bitwise_logup_round_sums.len())
            * 2
            * 4;
        fixed + ood + fri + fri_proof_size + queries + coprocessor + coproc_meta + logup_sums
    }
}

/// Out-of-Domain Evaluation Frame in the extension field.
///
/// Holds the evaluations of all trace column polynomials at
/// the OOD point z ∈ Fp4 (current row) and z·ω (next row).
///
/// Trace polynomials have Fp coefficients, but evaluated at z ∈ Fp4
/// they produce Fp4 values. This is the frame used in the proof and
/// verified by the verifier.
///
/// The verifier uses these to check AIR constraints at the OOD point:
/// if constraints hold at a random point outside the domain, they hold
/// on the entire domain with overwhelming probability. By sampling z
/// from Fp4 (|Fp4| ≈ 2¹²⁴), OOD security rises from ~10 to ~102 bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OodFrame {
    /// Column evaluations at OOD point `z ∈ Fp4`.
    pub current: Vec<Fp4>,
    /// Column evaluations at `z · ω` (ω is the base-field domain generator,
    /// embedded into Fp4 via `Fp4::from_base(ω)`).
    pub next: Vec<Fp4>,
}

impl Default for OodFrame {
    fn default() -> Self {
        Self {
            current: Vec::new(),
            next: Vec::new(),
        }
    }
}

/// Evaluation frame in the base field (for LDE-domain composition only).
///
/// Used by the prover during LDE evaluation where all points are in Fp.
/// NOT used in the proof structure or OOD verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationFrame {
    /// Column evaluations at an Fp point.
    pub current: Vec<Fp>,
    /// Column evaluations at the next Fp point.
    pub next: Vec<Fp>,
}

/// A single query proof (Merkle authentication + evaluation data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProof {
    /// Query index in the evaluation domain.
    pub index: usize,
    /// Trace row values at this index (raw u32 to match trace commitment hash).
    pub trace_values: Vec<u32>,
    /// Trace column Merkle paths (to trace_commitment).
    pub trace_merkle_paths: Vec<Hash256>,
    /// Composition polynomial value at this index.
    pub composition_value: Fp,
    /// Composition Merkle path (to composition_commitment).
    pub composition_merkle_path: Vec<Hash256>,
}

impl QueryProof {
    /// Size in bytes.
    pub fn size(&self) -> usize {
        let values_size = self.trace_values.len() * 4 + 4; // trace + 1 composition
        let paths_size = (self.trace_merkle_paths.len() + self.composition_merkle_path.len()) * 32;
        8 + values_size + paths_size
    }
}

/// Proof metadata for submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Block height range [start, end].
    pub block_range: (u64, u64),
    /// Number of transactions in the batch.
    pub tx_count: usize,
    /// Total gas consumed.
    pub total_gas: u64,
    /// Proof generation time in milliseconds.
    pub generation_time_ms: u64,
}

/// A batch proof covering multiple blocks.
///
/// Generated by the batch proving pipeline, this record stores the STARK proof
/// along with its metadata. Used for bridge verification and light client support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProofRecord {
    /// Block range [start, end] inclusive.
    pub block_range: (u64, u64),
    /// Number of transactions in the batch.
    pub tx_count: usize,
    /// Total gas consumed across all blocks in the batch.
    pub total_gas: u64,
    /// State root before the first block in the batch.
    pub initial_state_root: Hash256,
    /// State root after the last block in the batch.
    pub final_state_root: Hash256,
    /// The STARK proof.
    pub proof: StarkProof,
    /// Proof generation time in milliseconds.
    pub generation_time_ms: u64,
    /// Timestamp when the proof was generated (UNIX epoch seconds).
    pub generated_at: u64,
    /// Whether the proof has been verified by `StarkVerifier`.
    pub verified: bool,
    /// Wrapped SNARK proof for L1 posting (None if not yet wrapped).
    ///
    /// Generated automatically during `prove_batch()`. Contains a compact
    /// ~374-byte proof suitable for OP_RETURN or DA layer posting.
    #[serde(default)]
    pub snark_proof: Option<WrappedSnarkProof>,
    /// Whether this proof was generated from a synthetic trace.
    /// Synthetic proofs only commit to a state transition, NOT to actual
    /// execution. They MUST NOT be accepted as proof of correct execution.
    /// Validators and bridge contracts MUST reject proofs where is_synthetic == true.
    #[serde(default)]
    pub is_synthetic: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_size() {
        let proof = StarkProof {
            trace_commitment: Hash256::ZERO,
            composition_commitment: Hash256::ZERO,
            composition_at_z: Fp4::ZERO,
            ood_frame: OodFrame {
                current: vec![Fp4::ZERO; 37],
                next: vec![Fp4::ZERO; 37],
            },
            fri_commitments: vec![Hash256::ZERO; 10],
            query_proofs: vec![QueryProof {
                index: 0,
                trace_values: vec![0; 37],
                trace_merkle_paths: vec![Hash256::ZERO; 20],
                composition_value: Fp::ZERO,
                composition_merkle_path: vec![Hash256::ZERO; 20],
            }],
            num_steps: 1000,
            total_gas: 50000,
            initial_state_root: Hash256::ZERO,
            final_state_root: Hash256::ZERO,
            coprocessor_hashes: Vec::new(),
            coprocessor_commitment: Hash256::ZERO,
            coprocessor_num_rows: 0,
            logup_cpu_final_sum: Fp::ZERO,
            logup_coproc_final_sum: Fp::ZERO,
            logup_round_sums: Vec::new(),
            trace_log_size: 10,
            fri_final_value: Fp::ZERO,
            num_fri_queries: 30,
            fri_proof: None,
            poseidon2_trace_commitment: None,
            poseidon2_composition_commitment: None,
            regfile_logup_round_sums: Vec::new(),
            bitwise_logup_round_sums: Vec::new(),
            logup_running_sum_commitments: Vec::new(),
            regfile_running_sum_commitments: Vec::new(),
            bitwise_running_sum_commitments: Vec::new(),
            coproc_ood_frame: None,
        };
        let size = proof.size();
        assert!(size > 100);
        assert!(size < 10_000);
    }
}
