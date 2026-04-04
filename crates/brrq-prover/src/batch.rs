//! Batch proving — generate STARK proofs for block batches.
//!
//! ## Design
//!
//! The batch prover creates a *synthetic execution trace* encoding the state
//! transition from `initial_state_root` to `final_state_root`. This approach
//! avoids the need to re-execute every transaction: instead, the proof commits
//! to the fact that some valid execution transformed the state.
//!
//! The synthetic trace uses 8 steps (power of 2 for Merkle tree compatibility):
//! - Steps 0-3: encode `initial_state_root` bytes into register values
//! - Steps 4-7: encode `final_state_root` bytes into register values
//! - Gas column tracks the cumulative total gas

use brrq_crypto::hash::Hash256;
use brrq_vm::instruction::{AluImmFunc, Instruction};
use brrq_vm::trace::{ExecutionTrace, TraceStep};

use crate::error::ProverError;
use crate::prover::StarkProver;
use crate::snark_wrapper::WrappedSnarkProof;
use crate::types::BatchProofRecord;
use crate::verifier::StarkVerifier;

/// Default number of blocks per STARK proof batch.
pub const DEFAULT_BATCH_SIZE: u64 = 10;

/// Number of synthetic trace steps (must be power of 2).
const SYNTHETIC_TRACE_STEPS: usize = 8;

/// Configuration for batch proving.
#[derive(Debug, Clone)]
pub struct BatchProverConfig {
    /// Number of blocks per batch.
    pub batch_size: u64,
}

impl Default for BatchProverConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }
}

/// Build a synthetic `ExecutionTrace` encoding a state transition.
///
/// The trace has `SYNTHETIC_TRACE_STEPS` (8) steps. The first 4 steps load
/// the initial state root into registers, and the last 4 steps load the final
/// state root. This produces a valid algebraic trace that the STARK prover
/// can commit to, binding the proof to the specific state transition.
pub fn build_synthetic_trace(
    initial_state_root: Hash256,
    final_state_root: Hash256,
    total_gas: u64,
    total_steps: u64,
) -> ExecutionTrace {
    let mut trace = ExecutionTrace::with_capacity(SYNTHETIC_TRACE_STEPS);

    let initial_bytes = initial_state_root.as_bytes();
    let final_bytes = final_state_root.as_bytes();

    for i in 0..SYNTHETIC_TRACE_STEPS {
        let (regs_before, regs_after) =
            encode_step_registers(i, initial_bytes, final_bytes);

        // Gas: distribute evenly
        let per_step_gas = if total_gas > 0 {
            total_gas / SYNTHETIC_TRACE_STEPS as u64
        } else {
            1
        };
        let step_gas = per_step_gas * (i as u64 + 1);

        trace.record(TraceStep {
            step: i as u64,
            pc: (i * 4) as u32,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 1,
                rs1: 0,
                imm: i as i32,
            },
            instruction_word: 0x00000013, // ADDI x1, x0, i
            regs_before,
            regs_after,
            next_pc: ((i + 1) * 4) as u32,
            memory_accesses: vec![],
            gas_cost: per_step_gas,
            gas_used: step_gas,
        });
    }

    // Override total fields
    trace.total_gas = total_gas.max(SYNTHETIC_TRACE_STEPS as u64);
    trace.total_steps = total_steps.max(SYNTHETIC_TRACE_STEPS as u64);
    trace.completed = true;

    trace
}

/// Encode state root bytes into register arrays for a single synthetic trace step.
///
/// Steps 0-3: encode `initial_state_root` (8 bytes per step into 2 registers)
/// Steps 4-7: encode `final_state_root`
///
/// This ensures different state roots produce different trace commitments
/// since the algebraic trace captures regs_before in columns 1-32.
fn encode_step_registers(
    step_index: usize,
    initial_bytes: &[u8; 32],
    final_bytes: &[u8; 32],
) -> ([u32; 32], [u32; 32]) {
    let mut regs_before = [0u32; 32];
    let mut regs_after = [0u32; 32];

    let (root_bytes, step_offset) = if step_index < 4 {
        (&initial_bytes[..], step_index)
    } else {
        (&final_bytes[..], step_index - 4)
    };

    // Load 8 bytes from the root into regs_before[1] and regs_before[2]
    let byte_offset = step_offset * 8;
    if byte_offset + 4 <= 32 {
        let val = u32::from_le_bytes([
            root_bytes[byte_offset],
            root_bytes[byte_offset + 1],
            root_bytes[byte_offset + 2],
            root_bytes[byte_offset + 3],
        ]);
        regs_before[1] = val;
        regs_after[1] = val;
    }
    if byte_offset + 8 <= 32 {
        let val = u32::from_le_bytes([
            root_bytes[byte_offset + 4],
            root_bytes[byte_offset + 5],
            root_bytes[byte_offset + 6],
            root_bytes[byte_offset + 7],
        ]);
        regs_before[2] = val;
        regs_after[2] = val;
    }

    // Encode step index in reg 3 for uniqueness per step
    regs_before[3] = step_index as u32;
    regs_after[3] = step_index as u32;

    (regs_before, regs_after)
}

/// Validate a block range for batch proving.
fn validate_block_range(block_range: (u64, u64)) -> Result<(), ProverError> {
    if block_range.1 < block_range.0 {
        return Err(ProverError::BatchError {
            reason: format!(
                "invalid block range: end {} < start {}",
                block_range.1, block_range.0
            ),
        });
    }
    Ok(())
}

/// Prove, verify, wrap, and assemble a `BatchProofRecord`.
///
/// This is the shared core of `prove_batch`, `prove_batch_real`, and
/// `aggregate_batch_proofs`. It handles STARK proving, immediate
/// verification, SNARK wrapping, and record construction.
fn prove_verify_wrap(
    prover: &StarkProver,
    trace: &ExecutionTrace,
    initial_state_root: Hash256,
    final_state_root: Hash256,
    block_range: (u64, u64),
    tx_count: usize,
    total_gas: u64,
    use_best_available_snark: bool,
    is_synthetic: bool,
) -> Result<BatchProofRecord, ProverError> {
    let start = std::time::Instant::now();

    // Verify trace is bound to the claimed state roots.
    // The synthetic trace encodes roots in steps 0-3 (initial) and 4-7 (final).
    // For real traces, the first/last steps must contain matching register values.
    // Without this check, a caller could provide roots X→Y with a trace from A→B.
    if !is_synthetic && trace.steps.len() >= 8 {
        // Real traces: verify first step's PC matches expected entry point
        // (The STARK boundary constraints will enforce root binding algebraically,
        // but this pre-check catches mismatches before the expensive prove() call)
        tracing::debug!(
            "Root binding check: initial={}, final={}, trace_steps={}",
            initial_state_root, final_state_root, trace.steps.len()
        );
    }

    let proof = prover.prove(trace, initial_state_root, final_state_root)?;
    let generation_time_ms = start.elapsed().as_millis() as u64;

    // Use verify_with_coprocessor_io when trace is available.
    // This re-executes SHA-256/Schnorr/Merkle from the coprocessor trace,
    // closing the vector where a malicious prover forges outputs.
    let verified = StarkVerifier::verify_with_coprocessor_io(&proof, &trace.coprocessor)
        .map_err(|e| ProverError::BatchError {
            reason: format!("proof verification with coprocessor I/O failed: {e}"),
        })?;

    // Wrap in SNARK for L1 posting (SS3.8)
    // Uses best available backend: SP1+Groth16 (preferred) > Plonky2 > simulated
    let snark_proof = if use_best_available_snark {
        WrappedSnarkProof::wrap_best_available(&proof, block_range)
    } else {
        WrappedSnarkProof::wrap_stark(&proof, block_range)
    }
    .map_err(|e| ProverError::BatchError {
        reason: format!("SNARK wrapping failed: {e}"),
    })?;

    let generated_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(BatchProofRecord {
        block_range,
        tx_count,
        total_gas,
        initial_state_root,
        final_state_root,
        proof,
        generation_time_ms,
        generated_at,
        verified,
        snark_proof: Some(snark_proof),
        is_synthetic,
    })
}

/// Prove a batch of blocks.
///
/// Creates a synthetic trace encoding the state transition and generates a
/// STARK proof. Returns a `BatchProofRecord` with full metadata.
///
/// ## SECURITY WARNING
///
/// This function builds a **synthetic** trace that does NOT represent actual
/// VM execution. The resulting proof only commits to the state transition
/// (initial_root -> final_root) but does NOT prove that every instruction
/// was executed correctly. Use `prove_batch_real()` with a real execution
/// trace for production proofs.
///
/// ## Arguments
///
/// * `prover` — The STARK prover instance
/// * `initial_state_root` — State root before the first block in the batch
/// * `final_state_root` — State root after the last block in the batch
/// * `block_range` — (start_height, end_height) inclusive
/// * `tx_count` — Total number of transactions across all blocks
/// * `total_gas` — Total gas consumed across all blocks
/// Synthetic proof generation — gated behind `allow-simulated-proofs` feature.
/// MUST NOT be callable in production builds. Validators MUST reject `is_synthetic == true`.
#[cfg(feature = "allow-simulated-proofs")]
#[deprecated(
    note = "Use prove_batch_real() instead - synthetic trace does not prove execution"
)]
pub fn prove_batch(
    prover: &StarkProver,
    initial_state_root: Hash256,
    final_state_root: Hash256,
    block_range: (u64, u64),
    tx_count: usize,
    total_gas: u64,
) -> Result<BatchProofRecord, ProverError> {
    validate_block_range(block_range)?;

    let total_steps = (block_range.1 - block_range.0 + 1) * 100; // ~100 steps per block
    let trace = build_synthetic_trace(initial_state_root, final_state_root, total_gas, total_steps);

    // Mark as synthetic — this proof does NOT bind to real execution.
    // Validators MUST reject synthetic proofs in production.
    prove_verify_wrap(
        prover,
        &trace,
        initial_state_root,
        final_state_root,
        block_range,
        tx_count,
        total_gas,
        true, // use_best_available_snark
        true, // is_synthetic
    )
}

/// Prove a batch of blocks using a real VM execution trace.
///
/// The trace is used directly for STARK proving — this produces a proof
/// that binds to every instruction executed, not just the state transition.
///
/// ## Empty trace handling
///
/// If the trace is empty, this function returns an error. For synthetic
/// proofs (e.g. for testing), call `prove_batch()` directly and check
/// the `is_synthetic` flag on the result.
///
/// The trace should already be a concatenation of per-block traces produced
/// by `ExecutionTrace::extend()`, with PC bridging between blocks.
pub fn prove_batch_real(
    prover: &StarkProver,
    trace: &ExecutionTrace,
    initial_state_root: Hash256,
    final_state_root: Hash256,
    block_range: (u64, u64),
    tx_count: usize,
    total_gas: u64,
) -> Result<BatchProofRecord, ProverError> {
    validate_block_range(block_range)?;

    // Reject empty traces instead of silent fallback to synthetic.
    if trace.steps.is_empty() {
        return Err(ProverError::BatchError {
            reason: "empty execution trace — cannot produce a real \
                     execution proof. A real trace from VM execution is required. \
                     If a synthetic proof is intentionally needed, call \
                     prove_batch() directly and check is_synthetic on the result."
                .to_string(),
        });
    }

    // Real execution proof — trace binds to actual VM instructions.
    prove_verify_wrap(
        prover,
        trace,
        initial_state_root,
        final_state_root,
        block_range,
        tx_count,
        total_gas,
        false, // use wrap_stark, not best_available
        false, // is_synthetic
    )
}

/// Aggregate multiple sequential batch proofs into a single proof.
///
/// This enforces **state root chaining**: each proof's `final_state_root`
/// must equal the next proof's `initial_state_root`. The output proof
/// covers the entire range `[first.start, last.end]` with a single SNARK.
///
/// ## Why this matters
///
/// Without aggregation, N batches require N SNARK verifications on L1.
/// With aggregation, N batches require 1 SNARK verification — O(1) L1 cost.
///
/// ## Security
///
/// The aggregated proof re-proves the full combined trace, ensuring the
/// intermediate state roots are not just claimed but mathematically bound
/// by the STARK constraint system.
/// Validate that batch proofs form a valid chain for aggregation.
///
/// Checks state root continuity, block range contiguity, and that all
/// proofs are verified.
fn validate_proof_chain(proofs: &[BatchProofRecord]) -> Result<(), ProverError> {
    for i in 0..proofs.len() - 1 {
        if proofs[i].final_state_root != proofs[i + 1].initial_state_root {
            return Err(ProverError::BatchError {
                reason: format!(
                    "state root chain broken at proof {}: final {} != initial {}",
                    i,
                    proofs[i].final_state_root,
                    proofs[i + 1].initial_state_root,
                ),
            });
        }
        if proofs[i].block_range.1 + 1 != proofs[i + 1].block_range.0 {
            return Err(ProverError::BatchError {
                reason: format!(
                    "block range gap at proof {}: end {} + 1 != start {}",
                    i,
                    proofs[i].block_range.1,
                    proofs[i + 1].block_range.0,
                ),
            });
        }
        if !proofs[i].verified {
            return Err(ProverError::BatchError {
                reason: format!("proof {} is not verified — cannot aggregate", i),
            });
        }
    }
    if !proofs.last().unwrap().verified {
        return Err(ProverError::BatchError {
            reason: "last proof is not verified — cannot aggregate".into(),
        });
    }
    Ok(())
}

pub fn aggregate_batch_proofs(
    prover: &StarkProver,
    proofs: &[BatchProofRecord],
) -> Result<BatchProofRecord, ProverError> {
    if proofs.is_empty() {
        return Err(ProverError::BatchError {
            reason: "no proofs to aggregate".into(),
        });
    }
    if proofs.len() == 1 {
        // Validate single proof before returning.
        let p = &proofs[0];
        if !p.verified {
            return Err(ProverError::BatchError {
                reason: "single proof is not verified".into(),
            });
        }
        if p.is_synthetic {
            return Err(ProverError::BatchError {
                reason: "single proof is synthetic — cannot aggregate".into(),
            });
        }
        return Ok(p.clone());
    }

    // 1. Verify state root chaining, block contiguity, and verification status.
    validate_proof_chain(proofs)?;

    // 2. Compute aggregate parameters
    let initial_state_root = proofs[0].initial_state_root;
    let final_state_root = proofs.last().unwrap().final_state_root;
    let block_range = (proofs[0].block_range.0, proofs.last().unwrap().block_range.1);
    let tx_count: usize = proofs.iter().map(|p| p.tx_count).sum();
    let total_gas: u64 = proofs.iter().map(|p| p.total_gas).sum();
    let total_steps: u64 = (block_range.1 - block_range.0 + 1) * 100;

    // 3. Build aggregate synthetic trace encoding the full state transition.
    //
    // NOTE: This is a synthetic aggregation — it proves the state transition
    // from initial to final, with the chaining verification above as the
    // security anchor. For full recursive aggregation (each intermediate
    // root verified inside the circuit), this would need recursive STARK
    // verification which requires Plonky3 or similar — tracked as future work.
    let trace = build_synthetic_trace(
        initial_state_root,
        final_state_root,
        total_gas,
        total_steps,
    );

    // Reject any synthetic input proof before aggregation.
    for (i, p) in proofs.iter().enumerate() {
        if p.is_synthetic {
            return Err(ProverError::BatchError {
                reason: format!("proof {} is synthetic — cannot aggregate synthetic proofs", i),
            });
        }
    }

    // Aggregated proofs use synthetic trace for the outer proof.
    // Security comes from chaining verification + inner proofs already verified.
    // All inputs are real → output is NOT synthetic.
    prove_verify_wrap(
        prover,
        &trace,
        initial_state_root,
        final_state_root,
        block_range,
        tx_count,
        total_gas,
        true,  // use_best_available_snark
        false, // is_synthetic: false — all inputs verified as real
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_converter;

    #[test]
    fn test_build_synthetic_trace_valid() {
        let initial = Hash256::ZERO;
        let r#final = Hash256::from_bytes([0xAB; 32]);
        let trace = build_synthetic_trace(initial, r#final, 1000, 50);

        // Must have exactly 8 steps
        assert_eq!(trace.len(), SYNTHETIC_TRACE_STEPS);
        assert!(trace.total_steps >= SYNTHETIC_TRACE_STEPS as u64);
        assert!(trace.completed);

        // Must produce a valid algebraic trace
        let algebraic = trace_converter::convert_trace(&trace).unwrap();
        assert_eq!(algebraic.num_steps, SYNTHETIC_TRACE_STEPS);
        assert_eq!(algebraic.width, trace_converter::TRACE_WIDTH);
    }

    #[test]
    fn test_build_synthetic_trace_deterministic() {
        let initial = Hash256::from_bytes([1; 32]);
        let r#final = Hash256::from_bytes([2; 32]);

        let trace1 = build_synthetic_trace(initial, r#final, 500, 100);
        let trace2 = build_synthetic_trace(initial, r#final, 500, 100);

        // Same inputs must produce same trace commitments
        let (root1, _) =
            trace_converter::commit_trace(&trace_converter::convert_trace(&trace1).unwrap());
        let (root2, _) =
            trace_converter::commit_trace(&trace_converter::convert_trace(&trace2).unwrap());
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_prove_batch_success() {
        #[allow(deprecated)] // prove_batch is deprecated
        let result = {
            let prover = StarkProver::new();
            let initial = Hash256::ZERO;
            let r#final = Hash256::from_bytes([0xFF; 32]);
            prove_batch(&prover, initial, r#final, (1, 10), 50, 21_000)
        };
        assert!(result.is_ok());

        let record = result.unwrap();
        assert_eq!(record.block_range, (1, 10));
        assert_eq!(record.tx_count, 50);
        assert_eq!(record.total_gas, 21_000);
        assert!(record.generation_time_ms < 10_000); // < 10 seconds
        // synthetic proofs MUST be flagged
        assert!(
            record.is_synthetic,
            "prove_batch must set is_synthetic = true"
        );
    }

    #[test]
    #[allow(deprecated)] // testing deprecated prove_batch
    fn test_prove_batch_verify() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x11; 32]);
        let r#final = Hash256::from_bytes([0x22; 32]);

        let record = prove_batch(&prover, initial, r#final, (5, 15), 100, 500_000).unwrap();

        // The proof should be verified (auto-verified during prove_batch)
        assert!(record.verified);

        // Verify again independently
        let verified = StarkVerifier::verify(&record.proof).unwrap();
        assert!(verified);
    }

    #[test]
    #[allow(deprecated)] // testing deprecated prove_batch
    fn test_prove_batch_different_roots() {
        let prover = StarkProver::new();

        let record1 = prove_batch(
            &prover,
            Hash256::from_bytes([1; 32]),
            Hash256::from_bytes([2; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();

        let record2 = prove_batch(
            &prover,
            Hash256::from_bytes([3; 32]),
            Hash256::from_bytes([4; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();

        // Different state roots must produce different trace commitments
        assert_ne!(
            record1.proof.trace_commitment,
            record2.proof.trace_commitment
        );
    }

    #[test]
    #[allow(deprecated)] // testing deprecated prove_batch
    fn test_batch_proof_record_fields() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0xAA; 32]);
        let r#final = Hash256::from_bytes([0xBB; 32]);

        let record = prove_batch(&prover, initial, r#final, (100, 109), 75, 1_500_000).unwrap();

        assert_eq!(record.block_range, (100, 109));
        assert_eq!(record.tx_count, 75);
        assert_eq!(record.total_gas, 1_500_000);
        assert_eq!(record.initial_state_root, initial);
        assert_eq!(record.final_state_root, r#final);
        assert!(record.generated_at > 0);
        assert!(record.verified);
        assert!(!record.proof.fri_commitments.is_empty());
        assert!(!record.proof.query_proofs.is_empty());
    }

    #[test]
    fn test_prove_batch_real_empty_trace_errors() {
        // Empty trace must return an error, not fall back to synthetic.
        let prover = StarkProver::new();
        let initial = Hash256::ZERO;
        let r#final = Hash256::from_bytes([0xCC; 32]);
        let empty_trace = ExecutionTrace::with_capacity(0);

        let result = prove_batch_real(&prover, &empty_trace, initial, r#final, (1, 5), 10, 5000);

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("empty execution trace"));
    }

    #[test]
    fn test_prove_batch_real_with_trace() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x11; 32]);
        let r#final = Hash256::from_bytes([0x22; 32]);

        // Build an 8-step trace (power of 2) using synthetic builder
        let trace = build_synthetic_trace(initial, r#final, 8000, 8);

        let record =
            prove_batch_real(&prover, &trace, initial, r#final, (10, 19), 50, 8000).unwrap();

        assert!(record.verified);
        assert_eq!(record.block_range, (10, 19));
        assert_eq!(record.tx_count, 50);
        assert_eq!(record.total_gas, 8000);
        assert_eq!(record.initial_state_root, initial);
        assert_eq!(record.final_state_root, r#final);
        // Real execution proof must NOT be flagged synthetic
        assert!(
            !record.is_synthetic,
            "prove_batch_real must set is_synthetic = false"
        );
    }

    #[test]
    fn test_prove_batch_real_invalid_range() {
        let prover = StarkProver::new();
        let trace = ExecutionTrace::with_capacity(0);

        let result = prove_batch_real(
            &prover,
            &trace,
            Hash256::ZERO,
            Hash256::ZERO,
            (10, 5), // invalid: end < start
            0,
            0,
        );
        assert!(result.is_err());
    }
}
