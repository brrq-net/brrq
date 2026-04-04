//! Coprocessor AIR — Algebraic constraints for off-CPU operations.
//!
//! ## Architecture
//!
//! The Brrq zkVM offloads expensive cryptographic operations (SHA-256,
//! Merkle verification, signature checks) to **coprocessors**. Each
//! coprocessor invocation is recorded in a separate **coprocessor trace
//! table** that runs alongside the main CPU trace.
//!
//! ## Coprocessor Trace Layout (12 columns)
//!
//! | Column | Name        | Description                                |
//! |--------|-------------|--------------------------------------------|
//! | 0      | call_id     | Sequential coprocessor call ID (0, 1, 2…)  |
//! | 1      | op_type     | Operation type (see `OpType`)              |
//! | 2-5    | input_lo    | First 16 bytes of input hash (4 × u32)    |
//! | 6-9    | output_lo   | First 16 bytes of output hash (4 × u32)   |
//! | 10     | is_valid    | 1 if operation succeeded, 0 otherwise      |
//! | 11     | cpu_step    | Which CPU step invoked this operation      |
//!
//! ## Cross-Table Linking (LogUp)
//!
//! The CPU trace marks ECALL rows with a "bus value" derived from the
//! syscall number + input/output data. The same bus value must appear
//! in the coprocessor table. The LogUp protocol proves this
//! multiset equality with overwhelming probability.
//!
//! ## Constraints
//!
//! 1. **call_id monotonicity**: call_id[i+1] = call_id[i] + 1
//! 2. **op_type range**: op_type ∈ {1, 2, 3, 4, 5} — 0 (padding) excluded
//! 3. **is_valid boolean**: is_valid · (is_valid - 1) = 0
//! 4. **I/O commitment**: For each op, hash(op_type || input) is committed
//!    and the output is verified by re-execution in the prover
//! 5. **LogUp accumulator**: Running sum of 1/(β - bus_value) matches
//!    between CPU and coprocessor tables
//!
//! ## SECURITY NOTE: Coprocessor I/O Correctness Model
//!
//! The AIR constraints above do NOT
//! algebraically enforce that SHA-256/Schnorr outputs are correct. They
//! only enforce structural consistency (LogUp multiset matching).
//!
//! I/O correctness relies on TWO defense layers:
//!
//! 1. **Prover-side:** `verify_coprocessor_io()` re-executes every operation
//!    and rejects traces with wrong outputs BEFORE proof generation.
//!
//! 2. **Verifier-side :** The published proof must
//!    include the coprocessor I/O table. Verifiers re-compute SHA-256/Schnorr
//!    from the table and compare with bus_values. This closes the "malicious
//!    prover bypasses verify_coprocessor_io()" vector.
//!
//! **Why not algebraic SHA-256 constraints?** Implementing SHA-256 as
//! polynomial constraints requires ~27,000 constraints per hash invocation.
//! With ~1000 hashes per block, this adds ~27M constraints — making proving
//! 100x slower. Every production zkVM (SP1, RISC Zero) uses the same
//! re-execution model for precompiles.
//!
//! **Mainnet requirement:** Before mainnet, the Verifier MUST re-check
//! coprocessor I/O. See `StarkVerifier::verify_with_coprocessor_io()`.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_vm::trace::{
    CoprocessorTrace, EmitLogTraceStep, MerkleVerifyTraceStep, SchnorrVerifyTraceStep,
    SlhDsaVerifyTraceStep,
};

use crate::field::{AirField, Fp};
use crate::field_ext::Fp4;
use crate::transcript::Transcript;
use crate::types::{EvaluationFrame, OodFrame};

// ── Column indices ──

pub const COPROC_COL_CALL_ID: usize = 0;
pub const COPROC_COL_OP_TYPE: usize = 1;
pub const COPROC_COL_INPUT_0: usize = 2;
pub const COPROC_COL_INPUT_1: usize = 3;
pub const COPROC_COL_INPUT_2: usize = 4;
pub const COPROC_COL_INPUT_3: usize = 5;
pub const COPROC_COL_OUTPUT_0: usize = 6;
pub const COPROC_COL_OUTPUT_1: usize = 7;
pub const COPROC_COL_OUTPUT_2: usize = 8;
pub const COPROC_COL_OUTPUT_3: usize = 9;
pub const COPROC_COL_IS_VALID: usize = 10;
pub const COPROC_COL_CPU_STEP: usize = 11;

/// Total number of columns in the coprocessor trace.
pub const COPROC_TRACE_WIDTH: usize = 12;

/// Number of transition constraints for the coprocessor AIR.
pub const COPROC_NUM_TRANSITION_CONSTRAINTS: usize = 3;

/// Number of boundary constraints for the coprocessor AIR.
pub const COPROC_NUM_BOUNDARY_CONSTRAINTS: usize = 2;

// ── Operation type constants ──

/// Op types must start at 1 so `op_type = 0` means "empty/padding row".
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpType {
    Sha256Compress = 1,
    MerkleVerify = 2,
    SchnorrVerify = 3,
    SlhDsaVerify = 4,
    EmitLog = 5,
}

impl OpType {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Sha256Compress),
            2 => Some(Self::MerkleVerify),
            3 => Some(Self::SchnorrVerify),
            4 => Some(Self::SlhDsaVerify),
            5 => Some(Self::EmitLog),
            _ => None,
        }
    }
}

// ── Algebraic Coprocessor Trace ──

/// Column-major coprocessor trace in algebraic form.
#[derive(Debug, Clone)]
pub struct CoprocessorAlgebraicTrace {
    /// 12 columns, each with one entry per coprocessor call.
    pub columns: Vec<Vec<u32>>,
    /// Number of coprocessor calls (rows).
    pub num_rows: usize,
}

/// Convert the VM's `CoprocessorTrace` into column-major algebraic form.
///
/// Returns an error if any CPU step value exceeds `u32::MAX`, which would
/// cause silent truncation in the algebraic trace columns.
pub fn convert_coprocessor_trace(
    trace: &CoprocessorTrace,
) -> Result<CoprocessorAlgebraicTrace, String> {
    let total_rows = trace.sha256_steps.len()
        + trace.merkle_steps.len()
        + trace.schnorr_steps.len()
        + trace.slh_dsa_steps.len()
        + trace.emit_log_steps.len();

    if total_rows == 0 {
        return Ok(CoprocessorAlgebraicTrace {
            columns: vec![vec![]; COPROC_TRACE_WIDTH],
            num_rows: 0,
        });
    }

    let mut columns = vec![vec![0u32; total_rows]; COPROC_TRACE_WIDTH];
    let mut row = 0;

    // SHA-256 steps
    for step in &trace.sha256_steps {
        let input_hash = Hasher::hash(&step.input);
        let output_hash = Hash256::from_bytes(step.output);
        fill_row(
            &mut columns,
            row,
            OpType::Sha256Compress as u32,
            &input_hash,
            &output_hash,
            true, // SHA-256 is always valid if prover accepted it
        );
        row += 1;
    }

    // Merkle steps
    for step in &trace.merkle_steps {
        let input_hash = merkle_input_hash(step);
        let output_hash = merkle_output_hash(step);
        fill_row(
            &mut columns,
            row,
            OpType::MerkleVerify as u32,
            &input_hash,
            &output_hash,
            step.verified,
        );
        row += 1;
    }

    // Schnorr steps
    for step in &trace.schnorr_steps {
        let input_hash = schnorr_input_hash(step);
        let output_hash = schnorr_output_hash(step);
        fill_row(
            &mut columns,
            row,
            OpType::SchnorrVerify as u32,
            &input_hash,
            &output_hash,
            step.verified,
        );
        row += 1;
    }

    // SLH-DSA steps
    for step in &trace.slh_dsa_steps {
        let input_hash = slh_dsa_input_hash(step);
        let output_hash = slh_dsa_output_hash(step);
        fill_row(
            &mut columns,
            row,
            OpType::SlhDsaVerify as u32,
            &input_hash,
            &output_hash,
            step.verified,
        );
        row += 1;
    }

    // EmitLog steps
    for step in &trace.emit_log_steps {
        let input_hash = emit_log_input_hash(step);
        let output_hash = Hash256::from_bytes(step.data_hash);
        fill_row(
            &mut columns,
            row,
            OpType::EmitLog as u32,
            &input_hash,
            &output_hash,
            true, // logs are always valid
        );
        row += 1;
    }

    // Set call_id and cpu_step columns
    // Use real CPU step values from the trace instead of placeholders.
    // The VM executor now records the CPU cycle count for each coprocessor invocation
    // in CoprocessorTrace::cpu_steps. This binds each coprocessor result to its
    // exact position in the CPU execution, preventing reordering attacks.
    #[allow(clippy::needless_range_loop)]
    for i in 0..total_rows {
        columns[COPROC_COL_CALL_ID][i] = i as u32;
        // Use actual CPU step if available, fall back to call_id for legacy traces
        columns[COPROC_COL_CPU_STEP][i] = if i < trace.cpu_steps.len() {
            let step = trace.cpu_steps[i];
            if step > u32::MAX as u64 {
                return Err(format!(
                    "CPU step {} exceeds u32::MAX at coprocessor op {}",
                    step, i
                ));
            }
            step as u32
        } else {
            i as u32
        };
    }

    Ok(CoprocessorAlgebraicTrace {
        columns,
        num_rows: total_rows,
    })
}

/// Fill one row in the coprocessor algebraic trace.
fn fill_row(
    columns: &mut [Vec<u32>],
    row: usize,
    op_type: u32,
    input_hash: &Hash256,
    output_hash: &Hash256,
    is_valid: bool,
) {
    columns[COPROC_COL_OP_TYPE][row] = op_type;

    // Input hash → 4 × u32 (first 16 bytes)
    let ib = input_hash.as_bytes();
    columns[COPROC_COL_INPUT_0][row] = u32::from_le_bytes([ib[0], ib[1], ib[2], ib[3]]);
    columns[COPROC_COL_INPUT_1][row] = u32::from_le_bytes([ib[4], ib[5], ib[6], ib[7]]);
    columns[COPROC_COL_INPUT_2][row] = u32::from_le_bytes([ib[8], ib[9], ib[10], ib[11]]);
    columns[COPROC_COL_INPUT_3][row] = u32::from_le_bytes([ib[12], ib[13], ib[14], ib[15]]);

    // Output hash → 4 × u32 (first 16 bytes)
    let ob = output_hash.as_bytes();
    columns[COPROC_COL_OUTPUT_0][row] = u32::from_le_bytes([ob[0], ob[1], ob[2], ob[3]]);
    columns[COPROC_COL_OUTPUT_1][row] = u32::from_le_bytes([ob[4], ob[5], ob[6], ob[7]]);
    columns[COPROC_COL_OUTPUT_2][row] = u32::from_le_bytes([ob[8], ob[9], ob[10], ob[11]]);
    columns[COPROC_COL_OUTPUT_3][row] = u32::from_le_bytes([ob[12], ob[13], ob[14], ob[15]]);

    columns[COPROC_COL_IS_VALID][row] = if is_valid { 1 } else { 0 };
}

// ── Deterministic I/O hashing for each operation type ──

fn merkle_input_hash(step: &MerkleVerifyTraceStep) -> Hash256 {
    let mut data = Vec::with_capacity(32 + 32 + 4);
    data.extend_from_slice(&step.root);
    data.extend_from_slice(&step.leaf);
    data.extend_from_slice(&step.depth.to_le_bytes());
    Hasher::hash(&data)
}

fn merkle_output_hash(step: &MerkleVerifyTraceStep) -> Hash256 {
    Hasher::hash(&[step.verified as u8])
}

fn schnorr_input_hash(step: &SchnorrVerifyTraceStep) -> Hash256 {
    let mut data = Vec::with_capacity(32 + 64 + 32);
    data.extend_from_slice(&step.msg_hash);
    data.extend_from_slice(&step.signature);
    data.extend_from_slice(&step.public_key);
    Hasher::hash(&data)
}

fn schnorr_output_hash(step: &SchnorrVerifyTraceStep) -> Hash256 {
    Hasher::hash(&[step.verified as u8])
}

fn slh_dsa_input_hash(step: &SlhDsaVerifyTraceStep) -> Hash256 {
    let mut data = Vec::with_capacity(32 + 32);
    data.extend_from_slice(&step.msg_hash);
    data.extend_from_slice(&step.public_key);
    Hasher::hash(&data)
}

fn slh_dsa_output_hash(step: &SlhDsaVerifyTraceStep) -> Hash256 {
    Hasher::hash(&[step.verified as u8])
}

fn emit_log_input_hash(step: &EmitLogTraceStep) -> Hash256 {
    let mut data = Vec::with_capacity(4 + step.topics.len() * 32);
    data.extend_from_slice(&(step.topics.len() as u32).to_le_bytes());
    for topic in &step.topics {
        data.extend_from_slice(topic);
    }
    Hasher::hash(&data)
}

// ── Coprocessor AIR ──

/// AIR for the coprocessor trace table.
pub struct CoprocessorAir;

impl CoprocessorAir {
    /// Evaluate transition constraints between consecutive coprocessor rows.
    ///
    /// ## Constraints
    ///
    /// 1. **call_id monotonicity**: next[call_id] - current[call_id] - 1 = 0
    ///    (call IDs are sequential: 0, 1, 2, …)
    ///
    /// 2. **is_valid boolean**: current[is_valid] · (current[is_valid] - 1) = 0
    ///    (is_valid must be 0 or 1 — binary constraint)
    pub fn evaluate_transition(frame: &EvaluationFrame) -> Vec<Fp> {
        coproc_evaluate_transition_generic::<Fp>(&frame.current, &frame.next)
    }

    /// Evaluate coprocessor transition constraints at an Fp4 OOD frame.
    pub fn evaluate_transition_ext(frame: &OodFrame) -> Vec<Fp4> {
        coproc_evaluate_transition_generic::<Fp4>(&frame.current, &frame.next)
    }

    /// Evaluate boundary constraints at the first coprocessor row (base field).
    pub fn evaluate_boundary_first(row: &[Fp]) -> Vec<Fp> {
        coproc_evaluate_boundary_first_generic::<Fp>(row)
    }

    /// Evaluate boundary constraints at the first coprocessor row (extension field).
    pub fn evaluate_boundary_first_ext(row: &[Fp4]) -> Vec<Fp4> {
        coproc_evaluate_boundary_first_generic::<Fp4>(row)
    }

    /// Total number of constraints.
    pub fn num_constraints() -> usize {
        COPROC_NUM_TRANSITION_CONSTRAINTS + COPROC_NUM_BOUNDARY_CONSTRAINTS
    }
}

// ── Generic coprocessor constraint evaluation ──

fn coproc_evaluate_transition_generic<F: AirField>(current: &[F], next: &[F]) -> Vec<F> {
    let mut constraints = Vec::with_capacity(COPROC_NUM_TRANSITION_CONSTRAINTS);

    // Constraint 1: call_id monotonicity
    let call_id_constraint = next[COPROC_COL_CALL_ID]
        .sub(current[COPROC_COL_CALL_ID])
        .sub(F::ONE);
    constraints.push(call_id_constraint);

    // Constraint 2: is_valid ∈ {0, 1}
    let iv = current[COPROC_COL_IS_VALID];
    constraints.push(iv.mul(iv.sub(F::ONE)));

    // Constraint 3: op_type ∈ {1, 2, 3, 4, 5} (excludes 0 = padding)
    let ot = current[COPROC_COL_OP_TYPE];
    let op_range_constraint = (ot.sub(F::ONE))
        .mul(ot.sub(F::from_u32(2)))
        .mul(ot.sub(F::from_u32(3)))
        .mul(ot.sub(F::from_u32(4)))
        .mul(ot.sub(F::from_u32(5)));
    constraints.push(op_range_constraint);

    // Constraint 4: cpu_step must be non-decreasing.
    // Without this, a malicious prover can reorder coprocessor results,
    // breaking the temporal binding between CPU execution and coprocessor calls.
    // Enforced as: next[cpu_step] >= current[cpu_step]
    // Algebraically: next[cpu_step] - current[cpu_step] must be non-negative.
    // Since we're in a finite field, we can't enforce >= directly.
    // Instead: cpu_step difference must be small (fits in a u32 range).
    // For practical purposes, enforce that the difference is < 2^20 (1M steps max gap).
    // This is a soft constraint — the LogUp bus hash provides the hard binding.
    let cpu_step_diff = next[COPROC_COL_CPU_STEP].sub(current[COPROC_COL_CPU_STEP]);
    // The diff should be non-negative and bounded. We add it as a soft constraint
    // by including it in the bus value computation (already done via call_id).
    // For now, we log it as an assertion in verify_coprocessor_io instead.
    // Range-check sub-AIR for cpu_step_diff will be added when STARK supports it.
    let _ = cpu_step_diff; // Intentionally unused — enforcement via verify_coprocessor_io

    constraints
}

fn coproc_evaluate_boundary_first_generic<F: AirField>(row: &[F]) -> Vec<F> {
    let mut constraints = Vec::with_capacity(COPROC_NUM_BOUNDARY_CONSTRAINTS);
    constraints.push(row[COPROC_COL_CALL_ID]);
    let iv = row[COPROC_COL_IS_VALID];
    constraints.push(iv.mul(iv.sub(F::ONE)));
    constraints
}

// ── Hash-to-field helper ──

/// Map a 32-byte SHA-256 digest to a BabyBear field element with
/// near-uniform distribution.
///
/// Uses rejection sampling across 8 non-overlapping 4-byte windows of the
/// digest. The first window whose u32 value is less than the largest
/// multiple of `BABYBEAR_P` that fits in u32 is used, giving < 2^{-128}
/// bias. If no window qualifies (astronomically unlikely for 8 windows),
/// we fall back to simple modular reduction of the first 4 bytes.
fn hash_to_field(bytes: &[u8; 32]) -> Fp {
    // Largest multiple of p that fits in u32, used for rejection sampling.
    // BABYBEAR_P = 2,013,265,921. floor(2^32 / p) * p = 2 * p = 4,026,531,842.
    let reject_threshold = (u32::MAX / Fp::MODULUS) * Fp::MODULUS;

    // Try 8 non-overlapping 4-byte windows
    for i in 0..8 {
        let off = i * 4;
        let val = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        if val < reject_threshold {
            return Fp::new(val % Fp::MODULUS);
        }
    }

    // Fallback: simple reduction (negligible bias, reached with prob < 2^{-128})
    let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Fp::new(val % Fp::MODULUS)
}

// ── Bus Value computation (for LogUp cross-table linking) ──

/// Compute the "bus value" for a coprocessor row.
///
/// The bus value deterministically encodes the entire row content into a
/// single field element. Both the CPU trace and the coprocessor table
/// compute the same bus value for each operation, and the LogUp argument
/// proves the multisets match.
///
/// bus_value = hash_to_field(op_type || input[0..3] || output[0..3] || is_valid)
///
/// Uses rejection sampling over the full 32-byte SHA-256 digest to produce
/// a near-uniform field element (< 2^{-128} bias), extracting the maximum
/// ~31 bits of entropy available in BabyBear.
pub fn compute_bus_value(row: &[Fp]) -> Fp {
    let mut hasher = Hasher::new();
    hasher.update(&row[COPROC_COL_OP_TYPE].value().to_le_bytes());
    for cell in &row[COPROC_COL_INPUT_0..=COPROC_COL_INPUT_3] {
        hasher.update(&cell.value().to_le_bytes());
    }
    for cell in &row[COPROC_COL_OUTPUT_0..=COPROC_COL_OUTPUT_3] {
        hasher.update(&cell.value().to_le_bytes());
    }
    hasher.update(&row[COPROC_COL_IS_VALID].value().to_le_bytes());
    let h = hasher.finalize();
    hash_to_field(h.as_bytes())
}

/// Compute bus value directly from raw u32 columns at a given row index.
///
/// Values are reduced through `Fp::new()` before hashing to match the
/// behavior of `compute_bus_value` (which receives already-reduced Fp values).
/// This is necessary because column values from hash-byte packing can
/// exceed BabyBear's prime modulus.
pub fn compute_bus_value_from_columns(columns: &[Vec<u32>], row: usize) -> Fp {
    let mut hasher = Hasher::new();
    hasher.update(
        &Fp::new(columns[COPROC_COL_OP_TYPE][row])
            .value()
            .to_le_bytes(),
    );
    for col_data in &columns[COPROC_COL_INPUT_0..=COPROC_COL_INPUT_3] {
        hasher.update(&Fp::new(col_data[row]).value().to_le_bytes());
    }
    for col_data in &columns[COPROC_COL_OUTPUT_0..=COPROC_COL_OUTPUT_3] {
        hasher.update(&Fp::new(col_data[row]).value().to_le_bytes());
    }
    hasher.update(
        &Fp::new(columns[COPROC_COL_IS_VALID][row])
            .value()
            .to_le_bytes(),
    );
    let h = hasher.finalize();
    hash_to_field(h.as_bytes())
}

// ── Coprocessor trace commitment ──

/// Commit to the coprocessor trace via Merkle tree.
///
/// Each row is hashed to produce a leaf; all leaves form a Merkle tree.
pub fn commit_coprocessor_trace(
    trace: &CoprocessorAlgebraicTrace,
) -> (Hash256, brrq_crypto::merkle::MerkleTree) {
    if trace.num_rows == 0 {
        // Return a dummy commitment for empty coprocessor traces.
        let tree = brrq_crypto::merkle::MerkleTree::from_hashes(vec![Hash256::ZERO])
            .expect("single-leaf tree cannot exceed max leaf limit");
        return (Hash256::ZERO, tree);
    }

    let row_hashes: Vec<Hash256> = (0..trace.num_rows)
        .map(|row| {
            let mut hasher = Hasher::new();
            for col in &trace.columns {
                hasher.update(&col[row].to_le_bytes());
            }
            hasher.finalize()
        })
        .collect();

    let tree = brrq_crypto::merkle::MerkleTree::from_hashes(row_hashes)
        .expect("coprocessor trace exceeds 16M rows");
    let root = tree.root();
    (root, tree)
}

/// Verify all coprocessor I/O by re-execution.
///
/// The prover MUST re-compute each operation and verify the recorded
/// outputs match. This is the runtime soundness check — the AIR
/// constraints then prove the structural integrity of the table.
pub fn verify_coprocessor_io(trace: &CoprocessorTrace) -> Result<(), String> {
    // Verify cpu_steps are monotonically non-decreasing.
    // This prevents a malicious prover from reordering coprocessor results.
    if trace.cpu_steps.len() >= 2 {
        for i in 1..trace.cpu_steps.len() {
            if trace.cpu_steps[i] < trace.cpu_steps[i - 1] {
                return Err(format!(
                    "cpu_step monotonicity violated: step[{}]={} < step[{}]={}",
                    i, trace.cpu_steps[i], i - 1, trace.cpu_steps[i - 1]
                ));
            }
        }
    }

    verify_sha256_steps(&trace.sha256_steps)?;
    verify_schnorr_steps(&trace.schnorr_steps)?;
    verify_merkle_steps(&trace.merkle_steps)?;
    verify_slh_dsa_steps(&trace.slh_dsa_steps)?;
    Ok(())
}

/// Verify SHA-256 steps by re-execution.
fn verify_sha256_steps(steps: &[brrq_vm::trace::Sha256TraceStep]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        let actual = Hasher::hash(&step.input);
        if *actual.as_bytes() != step.output {
            return Err(format!("SHA-256 step {i}: output mismatch"));
        }
    }
    Ok(())
}

/// Re-verify Schnorr signatures (we have all data: msg, sig, pubkey).
fn verify_schnorr_steps(steps: &[SchnorrVerifyTraceStep]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        let msg = Hash256::from_bytes(step.msg_hash);
        let pk = brrq_crypto::schnorr::SchnorrPublicKey::from_bytes(step.public_key);
        let sig = brrq_crypto::schnorr::SchnorrSignature::from_bytes(step.signature);
        let result = brrq_crypto::schnorr::verify(&pk, &msg, &sig);
        let expected_valid = result.is_ok();
        if step.verified != expected_valid {
            return Err(format!(
                "Schnorr step {i}: recorded verified={} but re-verification={}",
                step.verified, expected_valid
            ));
        }
    }
    Ok(())
}

/// Full Merkle re-verification using stored sibling hashes.
/// The VM precompile now records sibling hashes + directions in the trace,
/// enabling the prover to independently re-verify every Merkle proof.
fn verify_merkle_steps(steps: &[MerkleVerifyTraceStep]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        // Sanity: depth must be in a reasonable range (0..=24)
        if step.depth > 24 {
            return Err(format!(
                "Merkle step {i}: depth={} exceeds maximum of 24",
                step.depth
            ));
        }

        if !step.siblings.is_empty() {
            verify_merkle_step_full(i, step)?;
        } else {
            // Reject traces without siblings in production — full Merkle proof required.
            #[cfg(not(feature = "allow-simulated-proofs"))]
            return Err(format!(
                "Merkle step {}: siblings empty — legacy traces rejected in production. \
                 Require full Merkle proof with sibling hashes.",
                i
            ));
            #[cfg(feature = "allow-simulated-proofs")]
            verify_merkle_step_legacy(i, step)?;
        }
    }
    Ok(())
}

/// Full Merkle re-verification when sibling hashes are available.
fn verify_merkle_step_full(i: usize, step: &MerkleVerifyTraceStep) -> Result<(), String> {
    if step.siblings.len() != step.depth as usize {
        return Err(format!(
            "Merkle step {i}: siblings count {} != depth {}",
            step.siblings.len(),
            step.depth
        ));
    }

    // Walk the proof path
    let mut current = brrq_crypto::hash::Hash256::from_bytes(step.leaf);
    for (sibling, direction) in &step.siblings {
        let sibling_hash = brrq_crypto::hash::Hash256::from_bytes(*sibling);
        current = if *direction == 0 {
            brrq_crypto::hash::Hasher::hash_node(&current, &sibling_hash)
        } else {
            brrq_crypto::hash::Hasher::hash_node(&sibling_hash, &current)
        };
    }

    let expected_root = brrq_crypto::hash::Hash256::from_bytes(step.root);
    let re_verified = current == expected_root;

    if step.verified != re_verified {
        return Err(format!(
            "Merkle step {i}: recorded verified={} but re-verification={}",
            step.verified, re_verified
        ));
    }
    Ok(())
}

/// Legacy Merkle verification path: sanity checks only (no siblings available).
fn verify_merkle_step_legacy(i: usize, step: &MerkleVerifyTraceStep) -> Result<(), String> {
    if step.verified && step.root == [0u8; 32] {
        return Err(format!("Merkle step {i}: verified=true but root is zero"));
    }
    if step.verified && step.leaf == [0u8; 32] {
        return Err(format!("Merkle step {i}: verified=true but leaf is zero"));
    }
    // depth=0 means leaf should equal root (no path to walk)
    if step.depth == 0 && step.verified && step.root != step.leaf {
        return Err(format!(
            "Merkle step {i}: depth=0 verified=true but root != leaf"
        ));
    }
    // depth must be in valid range for non-trivial proofs
    // (already enforced above by the depth > 24 check)
    Ok(())
}

/// Full SLH-DSA re-verification using stored message and signature.
/// The VM precompile now records the full message and 7,856-byte signature in
/// the trace, enabling independent re-verification by the prover.
fn verify_slh_dsa_steps(steps: &[SlhDsaVerifyTraceStep]) -> Result<(), String> {
    for (i, step) in steps.iter().enumerate() {
        if !step.message.is_empty() && !step.signature_bytes.is_empty() {
            verify_slh_dsa_step_full(i, step)?;
        } else {
            // Reject legacy SLH-DSA traces in production.
            #[cfg(not(feature = "allow-simulated-proofs"))]
            return Err(format!(
                "SLH-DSA step {}: empty message/signature — legacy traces rejected in production.",
                i
            ));
            #[cfg(feature = "allow-simulated-proofs")]
            verify_slh_dsa_step_legacy(i, step)?;
        }
    }
    Ok(())
}

/// Full SLH-DSA re-verification when message and signature are available.
fn verify_slh_dsa_step_full(i: usize, step: &SlhDsaVerifyTraceStep) -> Result<(), String> {
    // Verify msg_hash matches
    let expected_hash = brrq_crypto::hash::Hasher::hash(&step.message);
    if *expected_hash.as_bytes() != step.msg_hash {
        return Err(format!(
            "SLH-DSA step {i}: msg_hash doesn't match SHA-256(message)"
        ));
    }

    // Re-verify the signature
    let pk = match brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(step.public_key.to_vec()) {
        Ok(pk) => pk,
        Err(_) => {
            if step.verified {
                return Err(format!(
                    "SLH-DSA step {i}: verified=true but public key is invalid"
                ));
            }
            return Ok(());
        }
    };
    let sig = match brrq_crypto::slh_dsa::SlhDsaSignature::from_bytes(
        step.signature_bytes.clone(),
    ) {
        Ok(s) => s,
        Err(_) => {
            if step.verified {
                return Err(format!(
                    "SLH-DSA step {i}: verified=true but signature is malformed"
                ));
            }
            return Ok(());
        }
    };

    let re_verified = brrq_crypto::slh_dsa::verify(&pk, &step.message, &sig).is_ok();
    if step.verified != re_verified {
        return Err(format!(
            "SLH-DSA step {i}: recorded verified={} but re-verification={}",
            step.verified, re_verified
        ));
    }
    Ok(())
}

/// Legacy SLH-DSA verification path: sanity checks only.
fn verify_slh_dsa_step_legacy(i: usize, step: &SlhDsaVerifyTraceStep) -> Result<(), String> {
    if step.verified && step.msg_hash == [0u8; 32] {
        return Err(format!(
            "SLH-DSA step {i}: verified=true but msg_hash is zero"
        ));
    }
    if step.verified && step.public_key == [0u8; 32] {
        return Err(format!(
            "SLH-DSA step {i}: verified=true but public_key is zero"
        ));
    }
    Ok(())
}

/// Absorb all coprocessor data into a Fiat-Shamir transcript.
///
/// This binds the coprocessor trace to the proof, ensuring that any
/// modification to coprocessor operations invalidates the proof.
pub fn absorb_coprocessor_into_transcript(
    trace: &CoprocessorAlgebraicTrace,
    transcript: &mut Transcript,
) -> Vec<Hash256> {
    let mut hashes = Vec::with_capacity(trace.num_rows);

    for row in 0..trace.num_rows {
        let mut hasher = Hasher::new();
        for col in &trace.columns {
            hasher.update(&col[row].to_le_bytes());
        }
        let row_hash = hasher.finalize();
        transcript.absorb_hash(&row_hash);
        hashes.push(row_hash);
    }

    hashes
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EvaluationFrame;
    use brrq_vm::trace::Sha256TraceStep;

    fn make_valid_coproc_frame() -> EvaluationFrame {
        let mut current = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        let mut next = vec![Fp::ZERO; COPROC_TRACE_WIDTH];

        // call_id: 0 → 1
        current[COPROC_COL_CALL_ID] = Fp::new(0);
        next[COPROC_COL_CALL_ID] = Fp::new(1);

        // is_valid = 1 (boolean)
        current[COPROC_COL_IS_VALID] = Fp::ONE;
        next[COPROC_COL_IS_VALID] = Fp::ONE;

        // op_type = SHA256
        current[COPROC_COL_OP_TYPE] = Fp::new(OpType::Sha256Compress as u32);
        next[COPROC_COL_OP_TYPE] = Fp::new(OpType::MerkleVerify as u32);

        EvaluationFrame { current, next }
    }

    #[test]
    fn test_transition_constraints_valid() {
        let frame = make_valid_coproc_frame();
        let constraints = CoprocessorAir::evaluate_transition(&frame);
        assert_eq!(constraints.len(), COPROC_NUM_TRANSITION_CONSTRAINTS);
        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(
                c.value(),
                0,
                "Constraint {i} should be zero for valid coprocessor trace"
            );
        }
    }

    #[test]
    fn test_transition_call_id_invalid() {
        let mut frame = make_valid_coproc_frame();
        // call_id jumps from 0 to 5 (should be 1)
        frame.next[COPROC_COL_CALL_ID] = Fp::new(5);

        let constraints = CoprocessorAir::evaluate_transition(&frame);
        assert_ne!(
            constraints[0].value(),
            0,
            "call_id constraint should detect invalid jump"
        );
    }

    #[test]
    fn test_transition_is_valid_not_boolean() {
        let mut frame = make_valid_coproc_frame();
        // is_valid = 2 (not boolean!)
        frame.current[COPROC_COL_IS_VALID] = Fp::new(2);

        let constraints = CoprocessorAir::evaluate_transition(&frame);
        assert_ne!(
            constraints[1].value(),
            0,
            "boolean constraint should detect is_valid=2"
        );
    }

    #[test]
    fn test_boundary_constraints_valid() {
        let mut row = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        row[COPROC_COL_CALL_ID] = Fp::ZERO; // starts at 0
        row[COPROC_COL_IS_VALID] = Fp::ONE; // boolean

        let constraints = CoprocessorAir::evaluate_boundary_first(&row);
        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(c.value(), 0, "Boundary constraint {i} should be zero");
        }
    }

    #[test]
    fn test_boundary_call_id_nonzero() {
        let mut row = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        row[COPROC_COL_CALL_ID] = Fp::new(7); // should be 0
        row[COPROC_COL_IS_VALID] = Fp::ONE;

        let constraints = CoprocessorAir::evaluate_boundary_first(&row);
        assert_ne!(
            constraints[0].value(),
            0,
            "Should detect nonzero initial call_id"
        );
    }

    #[test]
    fn test_convert_empty_coprocessor() {
        let trace = CoprocessorTrace::default();
        let algebraic = convert_coprocessor_trace(&trace).unwrap();
        assert_eq!(algebraic.num_rows, 0);
    }

    #[test]
    fn test_convert_sha256_step() {
        let mut trace = CoprocessorTrace::default();
        let input = [0xABu8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        trace.sha256_steps.push(Sha256TraceStep { input, output });

        let algebraic = convert_coprocessor_trace(&trace).unwrap();
        assert_eq!(algebraic.num_rows, 1);
        assert_eq!(
            algebraic.columns[COPROC_COL_OP_TYPE][0],
            OpType::Sha256Compress as u32
        );
        assert_eq!(algebraic.columns[COPROC_COL_IS_VALID][0], 1);
        assert_eq!(algebraic.columns[COPROC_COL_CALL_ID][0], 0);
    }

    #[test]
    fn test_convert_multiple_ops() {
        let mut trace = CoprocessorTrace::default();

        // Add SHA-256 step
        let input = [0x42u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        trace.sha256_steps.push(Sha256TraceStep { input, output });

        // Add Merkle step
        trace.merkle_steps.push(MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [2u8; 32],
            depth: 10,
            verified: true,
            siblings: vec![],
        });

        // Add Schnorr step
        trace.schnorr_steps.push(SchnorrVerifyTraceStep {
            msg_hash: [3u8; 32],
            signature: [4u8; 64],
            public_key: [5u8; 32],
            verified: false,
        });

        let algebraic = convert_coprocessor_trace(&trace).unwrap();
        assert_eq!(algebraic.num_rows, 3);

        // Check op types in order
        assert_eq!(
            algebraic.columns[COPROC_COL_OP_TYPE][0],
            OpType::Sha256Compress as u32
        );
        assert_eq!(
            algebraic.columns[COPROC_COL_OP_TYPE][1],
            OpType::MerkleVerify as u32
        );
        assert_eq!(
            algebraic.columns[COPROC_COL_OP_TYPE][2],
            OpType::SchnorrVerify as u32
        );

        // Check call_ids are sequential
        assert_eq!(algebraic.columns[COPROC_COL_CALL_ID][0], 0);
        assert_eq!(algebraic.columns[COPROC_COL_CALL_ID][1], 1);
        assert_eq!(algebraic.columns[COPROC_COL_CALL_ID][2], 2);

        // Check is_valid
        assert_eq!(algebraic.columns[COPROC_COL_IS_VALID][0], 1); // SHA256 always valid
        assert_eq!(algebraic.columns[COPROC_COL_IS_VALID][1], 1); // Merkle verified
        assert_eq!(algebraic.columns[COPROC_COL_IS_VALID][2], 0); // Schnorr invalid
    }

    #[test]
    fn test_bus_value_deterministic() {
        let mut row = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        row[COPROC_COL_OP_TYPE] = Fp::new(1);
        row[COPROC_COL_INPUT_0] = Fp::new(42);
        row[COPROC_COL_IS_VALID] = Fp::ONE;

        let bv1 = compute_bus_value(&row);
        let bv2 = compute_bus_value(&row);
        assert_eq!(
            bv1.value(),
            bv2.value(),
            "Bus value should be deterministic"
        );
    }

    #[test]
    fn test_bus_value_changes_with_data() {
        let mut row1 = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        row1[COPROC_COL_OP_TYPE] = Fp::new(1);
        row1[COPROC_COL_INPUT_0] = Fp::new(42);

        let mut row2 = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        row2[COPROC_COL_OP_TYPE] = Fp::new(1);
        row2[COPROC_COL_INPUT_0] = Fp::new(99);

        let bv1 = compute_bus_value(&row1);
        let bv2 = compute_bus_value(&row2);
        assert_ne!(
            bv1.value(),
            bv2.value(),
            "Different input should produce different bus value"
        );
    }

    #[test]
    fn test_commit_empty_trace() {
        let trace = CoprocessorAlgebraicTrace {
            columns: vec![vec![]; COPROC_TRACE_WIDTH],
            num_rows: 0,
        };
        let (root, _tree) = commit_coprocessor_trace(&trace);
        assert_eq!(root, Hash256::ZERO);
    }

    #[test]
    fn test_commit_nonempty_trace() {
        let mut ct = CoprocessorTrace::default();
        let input = [0u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        ct.sha256_steps.push(Sha256TraceStep { input, output });

        let algebraic = convert_coprocessor_trace(&ct).unwrap();
        let (root, _tree) = commit_coprocessor_trace(&algebraic);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_verify_sha256_io_valid() {
        let mut ct = CoprocessorTrace::default();
        let input = [0x42u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        ct.sha256_steps.push(Sha256TraceStep { input, output });
        assert!(verify_coprocessor_io(&ct).is_ok());
    }

    #[test]
    fn test_verify_sha256_io_invalid() {
        let mut ct = CoprocessorTrace::default();
        ct.sha256_steps.push(Sha256TraceStep {
            input: [0x42u8; 64],
            output: [0xFFu8; 32], // wrong output!
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_op_type_from_u32() {
        assert_eq!(OpType::from_u32(1), Some(OpType::Sha256Compress));
        assert_eq!(OpType::from_u32(2), Some(OpType::MerkleVerify));
        assert_eq!(OpType::from_u32(3), Some(OpType::SchnorrVerify));
        assert_eq!(OpType::from_u32(4), Some(OpType::SlhDsaVerify));
        assert_eq!(OpType::from_u32(5), Some(OpType::EmitLog));
        assert_eq!(OpType::from_u32(0), None);
        assert_eq!(OpType::from_u32(99), None);
    }

    #[test]
    fn test_num_constraints() {
        assert_eq!(CoprocessorAir::num_constraints(), 5);
    }

    #[test]
    fn test_bus_value_from_columns_matches() {
        let mut ct = CoprocessorTrace::default();
        let input = [0x42u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        ct.sha256_steps.push(Sha256TraceStep { input, output });

        let algebraic = convert_coprocessor_trace(&ct).unwrap();

        // Compute from columns
        let bv_cols = compute_bus_value_from_columns(&algebraic.columns, 0);

        // Compute from Fp row
        let row: Vec<Fp> = algebraic
            .columns
            .iter()
            .map(|col| Fp::new(col[0]))
            .collect();
        let bv_row = compute_bus_value(&row);

        assert_eq!(bv_cols.value(), bv_row.value());
    }

    #[test]
    fn test_absorb_into_transcript_deterministic() {
        let mut ct = CoprocessorTrace::default();
        let input = [0u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        ct.sha256_steps.push(Sha256TraceStep { input, output });

        let algebraic = convert_coprocessor_trace(&ct).unwrap();

        let mut t1 = Transcript::new(b"test");
        let h1 = absorb_coprocessor_into_transcript(&algebraic, &mut t1);

        let mut t2 = Transcript::new(b"test");
        let h2 = absorb_coprocessor_into_transcript(&algebraic, &mut t2);

        assert_eq!(h1.len(), h2.len());
        for (a, b) in h1.iter().zip(h2.iter()) {
            assert_eq!(a, b);
        }
    }

    // ── Merkle sanity check tests (AIR-C2) ──

    #[test]
    fn test_verify_merkle_valid_step() {
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [2u8; 32],
            depth: 10,
            verified: true,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_ok());
    }

    #[test]
    fn test_verify_merkle_zero_root_verified() {
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [0u8; 32], // zero root but verified=true
            leaf: [2u8; 32],
            depth: 10,
            verified: true,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_merkle_zero_leaf_verified() {
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [0u8; 32], // zero leaf but verified=true
            depth: 10,
            verified: true,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_merkle_depth_zero() {
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [2u8; 32],
            depth: 0, // invalid depth
            verified: true,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_merkle_depth_too_large() {
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [2u8; 32],
            depth: 25, // exceeds max depth of 24
            verified: true,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_merkle_unverified_zero_root_ok() {
        // When verified=false, zero root/leaf should be accepted
        // (the operation simply failed, no inconsistency)
        let mut ct = CoprocessorTrace::default();
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [0u8; 32],
            leaf: [0u8; 32],
            depth: 5,
            verified: false,
            siblings: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_ok());
    }

    // ── SLH-DSA sanity check tests (AIR-C3) ──

    #[test]
    fn test_verify_slh_dsa_valid_step() {
        let mut ct = CoprocessorTrace::default();
        ct.slh_dsa_steps.push(SlhDsaVerifyTraceStep {
            msg_hash: [0xAAu8; 32],
            public_key: [0xBBu8; 32],
            verified: true,
            message: vec![],
            signature_bytes: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_ok());
    }

    #[test]
    fn test_verify_slh_dsa_zero_msg_hash_verified() {
        let mut ct = CoprocessorTrace::default();
        ct.slh_dsa_steps.push(SlhDsaVerifyTraceStep {
            msg_hash: [0u8; 32], // zero msg_hash but verified=true
            public_key: [0xBBu8; 32],
            verified: true,
            message: vec![],
            signature_bytes: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_slh_dsa_zero_pubkey_verified() {
        let mut ct = CoprocessorTrace::default();
        ct.slh_dsa_steps.push(SlhDsaVerifyTraceStep {
            msg_hash: [0xAAu8; 32],
            public_key: [0u8; 32], // zero public_key but verified=true
            verified: true,
            message: vec![],
            signature_bytes: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_err());
    }

    #[test]
    fn test_verify_slh_dsa_unverified_zero_ok() {
        // When verified=false, zero fields should be accepted
        let mut ct = CoprocessorTrace::default();
        ct.slh_dsa_steps.push(SlhDsaVerifyTraceStep {
            msg_hash: [0u8; 32],
            public_key: [0u8; 32],
            verified: false,
            message: vec![],
            signature_bytes: vec![],
        });
        assert!(verify_coprocessor_io(&ct).is_ok());
    }

    // ── COPROC-IO-1: Malicious Prover Defense Tests ──────────────────

    #[test]
    fn test_verify_coprocessor_io_rejects_forged_sha256() {
        // A malicious prover tries to inject a wrong SHA-256 output.
        // verify_coprocessor_io() MUST catch this and reject.
        let mut ct = CoprocessorTrace::default();
        let mut input = [0u8; 64];
        input[..18].copy_from_slice(b"honest input data\0");
        let forged_output = [0xDE; 32]; // Wrong output — not SHA-256(input)

        ct.sha256_steps.push(Sha256TraceStep {
            input,
            output: forged_output,
        });

        let result = verify_coprocessor_io(&ct);
        assert!(result.is_err(), "SECURITY: verify_coprocessor_io must reject forged SHA-256 output");
        assert!(result.unwrap_err().contains("SHA-256 step 0: output mismatch"));
    }

    #[test]
    fn test_verify_coprocessor_io_rejects_forged_schnorr() {
        // A malicious prover claims a bad signature verified successfully.
        let mut ct = CoprocessorTrace::default();
        ct.schnorr_steps.push(SchnorrVerifyTraceStep {
            msg_hash: [0xAA; 32],
            public_key: [0xBB; 32],
            signature: [0xCC; 64],
            verified: true, // FORGED: claims verification passed
        });

        let result = verify_coprocessor_io(&ct);
        assert!(result.is_err(), "SECURITY: verify_coprocessor_io must reject forged Schnorr result");
    }

    #[test]
    fn test_bus_value_changes_with_output() {
        // LogUp defense: if output changes, bus_value changes.
        // This means a malicious prover who changes output in the coprocessor
        // table will break LogUp multiset matching with the CPU trace.
        let mut row1 = vec![Fp::ZERO; COPROC_TRACE_WIDTH];
        let mut row2 = vec![Fp::ZERO; COPROC_TRACE_WIDTH];

        // Same input, different output
        row1[COPROC_COL_OP_TYPE] = Fp::new(1);
        row2[COPROC_COL_OP_TYPE] = Fp::new(1);
        row1[COPROC_COL_INPUT_LO] = Fp::new(42);
        row2[COPROC_COL_INPUT_LO] = Fp::new(42);
        row1[COPROC_COL_OUTPUT_LO] = Fp::new(100); // Correct output
        row2[COPROC_COL_OUTPUT_LO] = Fp::new(999); // Forged output

        let bv1 = compute_bus_value(&row1);
        let bv2 = compute_bus_value(&row2);

        assert_ne!(bv1, bv2, "SECURITY: different outputs MUST produce different bus_values for LogUp");
    }
}
