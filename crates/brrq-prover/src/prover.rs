//! STARK proof generation over BabyBear using real polynomial arithmetic.
//!
//! ## Pipeline
//!
//! 1. Convert execution trace to algebraic form (76 columns of u32, Phase 1A+1B)
//! 2. Lift each column to BabyBear field elements and interpolate to polynomials
//! 3. Evaluate polynomials on a larger coset domain (LDE)
//! 4. Commit to LDE columns via Merkle tree
//! 5. Draw OOD point z from Fiat-Shamir transcript
//! 6. Evaluate trace polynomials at z and z·ω (OOD frame)
//! 7. Check AIR constraints at the OOD point
//! 8. Combine constraint quotients via Random Linear Combination (RLC)
//! 9. Convert coprocessor trace to algebraic form and commit
//! 10. Build LogUp cross-table argument (CPU ↔ Coprocessor)
//! 11. Commit composition polynomial and apply FRI
//! 12. Generate query proofs with Merkle authentication

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::merkle::{MerkleTree, Poseidon2MerkleTree};
use brrq_vm::trace::ExecutionTrace;

use crate::air::{Air, COL_HAS_COPROCESSOR, RiscVAir, TRACE_WIDTH};
use crate::coprocessor_air::{
    self, CoprocessorAir, CoprocessorAlgebraicTrace, COPROC_NUM_BOUNDARY_CONSTRAINTS,
    COPROC_NUM_TRANSITION_CONSTRAINTS, COPROC_TRACE_WIDTH,
};
use crate::error::ProverError;
use crate::field::{self, Domain, Fp};
use crate::field_ext::{self, Fp4};
use crate::fri::{self, FriConfig};
use crate::hash_config::ProverHashConfig;
use crate::lookup::{LogUpArgument, build_bitwise_logup, build_regfile_logup};
use crate::trace_converter::{self, AlgebraicTrace};
use crate::transcript::Transcript;
use crate::types::{EvaluationFrame, OodFrame, QueryProof, StarkProof};

/// FRI blowup factor (LDE domain = blowup × trace domain).
const BLOWUP_FACTOR: usize = 4;

/// Number of FRI queries for soundness.
///
/// Security level = num_queries × log2(blowup_factor).
/// With blowup = 4: 64 × 2 = 128-bit security.
const NUM_QUERIES: usize = 64;

/// Maximum FRI folding rounds.
const MAX_FRI_ROUNDS: usize = 20;

/// Coset offset for LDE domain (must not be in the trace domain).
/// Using the BabyBear multiplicative generator ensures no overlap.
const COSET_OFFSET: u32 = 31; // = GENERATOR

/// Intermediate result from coprocessor proof building.
struct CoprocessorProofData {
    coprocessor_commitment: Hash256,
    coprocessor_hashes: Vec<Hash256>,
    coprocessor_num_rows: usize,
    logup_cpu_final_sum: Fp,
    logup_coproc_final_sum: Fp,
    logup_round_sums: Vec<(Fp, Fp)>,
    /// Per-round running sum Merkle commitments.
    logup_running_sum_commitments: Vec<Hash256>,
    /// The coprocessor algebraic trace, retained so that
    /// `build_composition_evals` can include coprocessor AIR constraints
    /// in the composition polynomial.
    coproc_algebraic: CoprocessorAlgebraicTrace,
}

/// STARK proof generator.
pub struct StarkProver {
    num_queries: usize,
    max_fri_rounds: usize,
    hash_config: ProverHashConfig,
}

impl StarkProver {
    /// Create a new prover with default parameters.
    pub fn new() -> Self {
        Self {
            num_queries: NUM_QUERIES,
            max_fri_rounds: MAX_FRI_ROUNDS,
            hash_config: ProverHashConfig::default(),
        }
    }

    /// Create a prover with a specific hash configuration.
    pub fn with_hash_config(config: ProverHashConfig) -> Self {
        Self {
            num_queries: NUM_QUERIES,
            max_fri_rounds: MAX_FRI_ROUNDS,
            hash_config: config,
        }
    }

    /// Generate a STARK proof from an execution trace.
    ///
    /// This is the core proving function that produces a proof of computational
    /// integrity: the proof guarantees that some valid RISC-V execution produced
    /// the given state transition, without revealing the execution itself.
    ///
    /// ## Coprocessor Integration
    ///
    /// The prover:
    /// 1. Converts coprocessor trace to a separate algebraic table
    /// 2. Verifies I/O correctness by re-execution
    /// 3. Commits to the coprocessor table via Merkle tree
    /// 4. Builds a LogUp argument linking CPU ECALL rows to coprocessor entries
    /// 5. Includes coprocessor AIR constraints in the composition polynomial
    pub fn prove(
        &self,
        trace: &ExecutionTrace,
        initial_state_root: Hash256,
        final_state_root: Hash256,
    ) -> Result<StarkProof, ProverError> {
        // ── Step 1: Convert CPU trace to algebraic form ──
        let algebraic = trace_converter::convert_trace(trace)?;
        let n = algebraic.num_steps;

        // ── Step 1b: Validate trace integrity ──
        // Catches malicious trace construction before proof generation.
        crate::lookup::validate_trace_integrity(&algebraic)?;

        // Pad to next power of 2 for NTT.
        let log_trace_size = (n as u64).next_power_of_two().trailing_zeros();

        // Prevent shift overflow on extremely large traces.
        if log_trace_size > 30 {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "trace too large: 2^{} steps exceeds maximum 2^30",
                    log_trace_size
                ),
            });
        }

        let trace_size = 1usize << log_trace_size;

        // LDE domain is blowup × trace domain.
        let log_lde_size = log_trace_size + (BLOWUP_FACTOR.trailing_zeros());
        let lde_size = 1usize << log_lde_size;

        // ── Step 2: Create domains ──
        let trace_domain = Domain::new(log_trace_size);
        let lde_domain = Domain::new(log_lde_size);
        let coset_offset = Fp::new(COSET_OFFSET);

        // ── Step 3: Interpolate each trace column to a polynomial ──
        let column_polys = self.interpolate_columns(&algebraic, &trace_domain, trace_size)?;

        // ── Step 4: (LDE evaluation deferred to build_composition_evals) ──

        // ── Step 5: Commit to CPU trace via Merkle tree ──
        let (trace_commitment, trace_tree) = trace_converter::commit_trace(&algebraic);

        // Poseidon2 trace commitment (for Plonky2 in-circuit verification)
        let poseidon2_trace_commitment = if self.hash_config.has_poseidon2() {
            use rayon::prelude::*;
            let row_hashes: Vec<Hash256> = (0..algebraic.num_steps)
                .into_par_iter()
                .map(|row| {
                    use brrq_crypto::poseidon2::poseidon2_hash;
                    let mut row_data = Vec::with_capacity(algebraic.columns.len() * 4);
                    for col in &algebraic.columns {
                        row_data.extend_from_slice(&col[row].to_le_bytes());
                    }
                    poseidon2_hash(&row_data)
                })
                .collect();
            let p2_tree = Poseidon2MerkleTree::from_hashes(row_hashes)
                .expect("Poseidon2 trace exceeds 16M rows");
            Some(p2_tree.root())
        } else {
            None
        };

        // ── Step 6: Initialize Fiat-Shamir transcript ──
        let mut transcript = Transcript::new(brrq_crypto::domain_tags::STARK_TRANSCRIPT_V2);
        transcript.absorb_hash(&trace_commitment);
        // Bind Poseidon2 trace commitment to Fiat-Shamir (prevents swapping).
        if let Some(ref p2_trace) = poseidon2_trace_commitment {
            transcript.absorb_hash(p2_trace);
        }
        transcript.absorb_hash(&initial_state_root);
        transcript.absorb_hash(&final_state_root);
        transcript.absorb_u64(n as u64);

        // ── Step 7: Draw OOD point z from extension field ──
        //
        // z ← Fp4: sampling from BabyBear⁴ gives ~102-bit OOD security.
        let z: Fp4 = transcript.challenge_ext_field();
        let z_next = z.mul(Fp4::from_base(trace_domain.generator));

        // ── Step 8: Evaluate all column polynomials at z and z·ω (in Fp4) ──
        //
        // Trace polynomials have Fp coefficients. poly_eval_ext evaluates them
        // at an Fp4 point, producing Fp4 results via Horner's method.
        use rayon::prelude::*;
        let current_evals: Vec<Fp4> = column_polys
            .par_iter()
            .map(|poly| field_ext::poly_eval_ext(poly, z))
            .collect();
        let next_evals: Vec<Fp4> = column_polys
            .par_iter()
            .map(|poly| field_ext::poly_eval_ext(poly, z_next))
            .collect();

        let ood_frame = OodFrame {
            current: current_evals,
            next: next_evals,
        };

        // Absorb OOD frame into transcript (Fp4 values).
        for eval in &ood_frame.current {
            transcript.absorb_fp4(*eval);
        }
        for eval in &ood_frame.next {
            transcript.absorb_fp4(*eval);
        }

        // ── Step 9: Evaluate AIR constraints at OOD point (in Fp4) ──
        let air = RiscVAir::new(initial_state_root, final_state_root);
        let transition_constraints = air.evaluate_transition_ext(&ood_frame);
        let boundary_constraints = air.evaluate_boundary_first_ext(&ood_frame.current);

        // ── Step 10: Compute constraint quotients (in Fp4) ──
        let domain_size = 1u64 << log_trace_size;
        let last_point = trace_domain.generator.pow((domain_size - 1) as u64);

        let z_trans =
            field_ext::transition_zerofier_eval_ext(z, domain_size, last_point)
                .ok_or_else(|| ProverError::InvalidTrace {
                    reason: "OOD point z is in trace domain (vanishing)".into(),
                })?;
        let z_trans_inv = z_trans.try_inv().ok_or_else(|| ProverError::InvalidTrace {
            reason: "transition zerofier evaluated to zero at OOD point".into(),
        })?;

        let z_bound =
            field_ext::boundary_zerofier_eval_first_ext(z, domain_size)
                .ok_or_else(|| ProverError::InvalidTrace {
                    reason: "OOD point z equals 1 (boundary singularity)".into(),
                })?;
        let z_bound_inv = z_bound.try_inv().ok_or_else(|| ProverError::InvalidTrace {
            reason: "boundary zerofier evaluated to zero at OOD point".into(),
        })?;

        // ── Step 11: Random Linear Combination (RLC) in Fp4 ──
        let mut composition_at_z = Fp4::ZERO;

        for c in &transition_constraints {
            let alpha = transcript.challenge_ext_field();
            let quotient = c.mul(z_trans_inv);
            composition_at_z = composition_at_z.add(alpha.mul(quotient));
        }

        for c in &boundary_constraints {
            let alpha = transcript.challenge_ext_field();
            let quotient = c.mul(z_bound_inv);
            composition_at_z = composition_at_z.add(alpha.mul(quotient));
        }

        // ══════════════════════════════════════════════════════════════
        // Step 12a: COPROCESSOR SYSTEM
        // Build the coprocessor proof FIRST so that its AIR constraints
        // can be folded into the composition polynomial.
        // ══════════════════════════════════════════════════════════════

        let coproc = self.build_coprocessor_proof(trace, &algebraic, &mut transcript)?;

        // ── Step 12a-OOD: Evaluate coprocessor AIR constraints at OOD point ──
        // Interpolate coprocessor columns, evaluate at z/z·ω_coproc, and fold
        // coprocessor constraint quotients into composition_at_z so the verifier
        // can verify coprocessor AIR alongside CPU AIR at the OOD point.
        let coproc_ood_frame = if coproc.coproc_algebraic.num_rows > 0 {
            let coproc_padded_size = (coproc.coproc_algebraic.num_rows as u64)
                .next_power_of_two() as usize;
            let coproc_log_size = coproc_padded_size.trailing_zeros();
            let coproc_domain = Domain::new(coproc_log_size);
            let coproc_domain_size = 1u64 << coproc_log_size;

            // Interpolate coprocessor columns on their domain
            let coproc_polys: Vec<Vec<Fp>> = coproc.coproc_algebraic
                .columns
                .iter()
                .map(|col| {
                    let mut evals = vec![Fp::ZERO; coproc_padded_size];
                    for (i, &val) in col.iter().enumerate() {
                        evals[i] = Fp::new(val);
                    }
                    field::poly_interpolate(&evals, &coproc_domain)
                })
                .collect();

            // Evaluate at z ∈ Fp4 and z·ω_coproc
            let z_next_coproc = z.mul(Fp4::from_base(coproc_domain.generator));
            let coproc_current: Vec<Fp4> = coproc_polys
                .iter()
                .map(|poly| field_ext::poly_eval_ext(poly, z))
                .collect();
            let coproc_next: Vec<Fp4> = coproc_polys
                .iter()
                .map(|poly| field_ext::poly_eval_ext(poly, z_next_coproc))
                .collect();

            let coproc_frame = OodFrame {
                current: coproc_current,
                next: coproc_next,
            };

            // Evaluate coprocessor AIR constraints at OOD point (Fp4)
            let coproc_trans = CoprocessorAir::evaluate_transition_ext(&coproc_frame);
            let coproc_bound = CoprocessorAir::evaluate_boundary_first_ext(&coproc_frame.current);

            // Coprocessor zerofiers at z ∈ Fp4
            let coproc_last_point = coproc_domain.generator.pow((coproc_domain_size - 1) as u64);
            let z_ct_inv = field_ext::transition_zerofier_eval_ext(z, coproc_domain_size, coproc_last_point)
                .and_then(|v| v.try_inv());
            let z_cb_inv = field_ext::boundary_zerofier_eval_first_ext(z, coproc_domain_size)
                .and_then(|v| v.try_inv());

            for c in &coproc_trans {
                let alpha = transcript.challenge_ext_field();
                if let Some(inv) = z_ct_inv {
                    let quotient = c.mul(inv);
                    composition_at_z = composition_at_z.add(alpha.mul(quotient));
                }
            }
            for c in &coproc_bound {
                let alpha = transcript.challenge_ext_field();
                if let Some(inv) = z_cb_inv {
                    let quotient = c.mul(inv);
                    composition_at_z = composition_at_z.add(alpha.mul(quotient));
                }
            }

            Some(coproc_frame)
        } else {
            // Draw coprocessor alphas even when empty (transcript sync)
            for _ in 0..crate::coprocessor_air::COPROC_NUM_TRANSITION_CONSTRAINTS {
                let _ = transcript.challenge_ext_field();
            }
            for _ in 0..crate::coprocessor_air::COPROC_NUM_BOUNDARY_CONSTRAINTS {
                let _ = transcript.challenge_ext_field();
            }
            None
        };

        // ── Step 12: Build composition polynomial on LDE domain ──
        // Now includes BOTH CPU and coprocessor AIR constraints.
        let composition_evals = self.build_composition_evals(
            &column_polys,
            &air,
            &coproc.coproc_algebraic,
            &trace_domain,
            &lde_domain,
            coset_offset,
            &mut transcript,
        )?;

        // Commit to composition polynomial.
        let comp_leaves: Vec<Hash256> = composition_evals
            .iter()
            .map(|&v| Hasher::hash(&v.value().to_le_bytes()))
            .collect();
        let composition_tree = MerkleTree::from_hashes(comp_leaves)
            .expect("composition polynomial exceeds 16M leaves");
        let composition_commitment = composition_tree.root();
        transcript.absorb_hash(&composition_commitment);

        // Poseidon2 composition commitment (for Plonky2 in-circuit verification).
        // Also bound into Fiat-Shamir to prevent commitment swapping.
        let poseidon2_composition_commitment = if self.hash_config.has_poseidon2() {
            use brrq_crypto::poseidon2::poseidon2_hash;
            let p2_leaves: Vec<Hash256> = composition_evals
                .iter()
                .map(|&v| poseidon2_hash(&v.value().to_le_bytes()))
                .collect();
            let p2_tree = Poseidon2MerkleTree::from_hashes(p2_leaves)
                .expect("Poseidon2 composition exceeds 16M leaves");
            let p2_root = p2_tree.root();
            transcript.absorb_hash(&p2_root);
            Some(p2_root)
        } else {
            None
        };

        // ══════════════════════════════════════════════════════════════
        // Step 12c: REGISTER FILE LogUp
        // ══════════════════════════════════════════════════════════════

        let regfile_rounds = build_regfile_logup(&algebraic, &mut transcript)?;
        let regfile_logup_round_sums: Vec<(Fp, Fp)> = regfile_rounds
            .iter()
            .map(|r| (r.cpu_final_sum, r.coproc_final_sum))
            .collect();

        // Commit regfile running sum columns and absorb into transcript.
        let regfile_running_sum_commitments: Vec<Hash256> = regfile_rounds
            .iter()
            .map(|r| {
                let (root, _) =
                    crate::lookup::commit_running_sums(&r.cpu_running_sum, &r.coproc_running_sum);
                transcript.absorb_hash(&root);
                root
            })
            .collect();

        // ══════════════════════════════════════════════════════════════
        // Step 12d: BITWISE LogUp
        // Proves XOR/OR/AND byte-level correctness via 8-bit lookup tables.
        // ══════════════════════════════════════════════════════════════

        let bitwise_rounds = build_bitwise_logup(&algebraic, &mut transcript);
        let bitwise_logup_round_sums: Vec<(Fp, Fp)> = bitwise_rounds
            .iter()
            .map(|r| (r.cpu_final_sum, r.coproc_final_sum))
            .collect();

        // Commit bitwise running sum columns and absorb into transcript.
        let bitwise_running_sum_commitments: Vec<Hash256> = bitwise_rounds
            .iter()
            .map(|r| {
                let (root, _) =
                    crate::lookup::commit_running_sums(&r.cpu_running_sum, &r.coproc_running_sum);
                transcript.absorb_hash(&root);
                root
            })
            .collect();

        // ══════════════════════════════════════════════════════════════
        // Step 13: Apply FRI to composition polynomial
        // ══════════════════════════════════════════════════════════════

        let fri_config = FriConfig {
            num_queries: self.num_queries,
            max_rounds: self.max_fri_rounds,
            hash_config: self.hash_config,
        };
        let fri_domain_gen = lde_domain.generator;
        let fri_proof = fri::fri_prove(
            &composition_evals,
            fri_domain_gen,
            &fri_config,
            &mut transcript,
        )?;

        let fri_commitments = fri_proof.layer_commitments.clone();
        let fri_final_value = fri_proof.final_value;

        // ── Step 14: Generate query proofs ──
        let query_proofs = self.generate_query_proofs(
            &algebraic,
            &trace_tree,
            &composition_evals,
            &composition_tree,
            &mut transcript,
            lde_size,
        )?;

        // ── Assemble proof ──
        Ok(StarkProof {
            trace_commitment,
            composition_commitment,
            composition_at_z,
            ood_frame,
            fri_commitments,
            query_proofs,
            num_steps: n as u64,
            total_gas: trace.total_gas,
            initial_state_root,
            final_state_root,
            coprocessor_hashes: coproc.coprocessor_hashes,
            coprocessor_commitment: coproc.coprocessor_commitment,
            coprocessor_num_rows: coproc.coprocessor_num_rows,
            logup_cpu_final_sum: coproc.logup_cpu_final_sum,
            logup_coproc_final_sum: coproc.logup_coproc_final_sum,
            logup_round_sums: coproc.logup_round_sums,
            trace_log_size: log_trace_size,
            fri_final_value,
            num_fri_queries: self.num_queries,
            fri_proof: Some(fri_proof),
            poseidon2_trace_commitment,
            poseidon2_composition_commitment,
            regfile_logup_round_sums,
            bitwise_logup_round_sums,
            // Running sum Merkle commitments bind the prover to
            // specific running sum columns, closing the forgery surface.
            logup_running_sum_commitments: coproc.logup_running_sum_commitments,
            regfile_running_sum_commitments,
            bitwise_running_sum_commitments,
            coproc_ood_frame,
        })
    }

    /// Build the coprocessor proof: verify I/O, commit trace, build LogUp argument.
    ///
    /// This handles coprocessor integration:
    /// 1. Verify coprocessor I/O by re-execution
    /// 2. Convert coprocessor trace to algebraic form and commit
    /// 3. Build LogUp cross-table argument (CPU ↔ Coprocessor)
    fn build_coprocessor_proof(
        &self,
        trace: &ExecutionTrace,
        algebraic: &AlgebraicTrace,
        transcript: &mut Transcript,
    ) -> Result<CoprocessorProofData, ProverError> {
        // (a) Verify coprocessor I/O by re-execution
        coprocessor_air::verify_coprocessor_io(&trace.coprocessor).map_err(|e| {
            ProverError::InvalidTrace {
                reason: format!("Coprocessor I/O verification failed: {e}"),
            }
        })?;

        // (b) Convert coprocessor trace to algebraic form
        let coproc_algebraic = coprocessor_air::convert_coprocessor_trace(&trace.coprocessor)
            .map_err(|e| ProverError::InvalidTrace {
                reason: format!("Coprocessor trace conversion failed: {e}"),
            })?;

        // (c) Commit to coprocessor trace
        let (coprocessor_commitment, _coproc_tree) =
            coprocessor_air::commit_coprocessor_trace(&coproc_algebraic);
        transcript.absorb_hash(&coprocessor_commitment);
        transcript.absorb_u64(coproc_algebraic.num_rows as u64);

        // (d) Absorb coprocessor row hashes into transcript
        let coprocessor_hashes =
            coprocessor_air::absorb_coprocessor_into_transcript(&coproc_algebraic, transcript);

        // (e) Build LogUp cross-table argument
        //     CPU side: bus values for ECALL rows
        //     Coprocessor side: bus values for every row
        //
        //     The i-th ECALL row in the CPU trace corresponds to the i-th row
        //     in the coprocessor table. Both sides compute the bus value from
        //     the SAME coprocessor table data, ensuring deterministic matching.
        let mut ecall_counter = 0usize;
        let cpu_bus_values: Vec<Option<Fp>> = (0..algebraic.num_steps)
            .map(|row| {
                if algebraic.columns[COL_HAS_COPROCESSOR][row] == 1 {
                    let bus_val = if ecall_counter < coproc_algebraic.num_rows {
                        coprocessor_air::compute_bus_value_from_columns(
                            &coproc_algebraic.columns,
                            ecall_counter,
                        )
                    } else {
                        Fp::new(ecall_counter as u32 + 1)
                    };
                    ecall_counter += 1;
                    Some(bus_val)
                } else {
                    None
                }
            })
            .collect();

        let coproc_bus_values: Vec<Fp> = (0..coproc_algebraic.num_rows)
            .map(|row| {
                coprocessor_air::compute_bus_value_from_columns(&coproc_algebraic.columns, row)
            })
            .collect();

        // Multi-round LogUp for ~2^-124 soundness (LOGUP_ROUNDS=4).
        let logup_rounds =
            LogUpArgument::build_multi_round(&cpu_bus_values, &coproc_bus_values, transcript);

        let logup_cpu_final_sum = logup_rounds.first().map_or(Fp::ZERO, |r| r.cpu_final_sum);
        let logup_coproc_final_sum = logup_rounds
            .first()
            .map_or(Fp::ZERO, |r| r.coproc_final_sum);
        let logup_round_sums: Vec<(Fp, Fp)> = logup_rounds
            .iter()
            .map(|r| (r.cpu_final_sum, r.coproc_final_sum))
            .collect();

        // Commit coprocessor running sum columns and absorb into transcript.
        // This binding prevents the prover from forging matching final sums
        // without actually having equal multisets.
        let logup_running_sum_commitments: Vec<Hash256> = logup_rounds
            .iter()
            .map(|r| {
                let (root, _) =
                    crate::lookup::commit_running_sums(&r.cpu_running_sum, &r.coproc_running_sum);
                transcript.absorb_hash(&root);
                root
            })
            .collect();

        Ok(CoprocessorProofData {
            coprocessor_commitment,
            coprocessor_hashes,
            coprocessor_num_rows: coproc_algebraic.num_rows,
            logup_cpu_final_sum,
            logup_coproc_final_sum,
            logup_round_sums,
            logup_running_sum_commitments,
            coproc_algebraic,
        })
    }

    /// Interpolate each trace column to a polynomial over BabyBear.
    fn interpolate_columns(
        &self,
        trace: &AlgebraicTrace,
        domain: &Domain,
        padded_size: usize,
    ) -> Result<Vec<Vec<Fp>>, ProverError> {
        use rayon::prelude::*;

        let polys: Vec<Vec<Fp>> = trace
            .columns
            .par_iter()
            .map(|col| {
                let mut evals = vec![Fp::ZERO; padded_size];
                for (i, &val) in col.iter().enumerate() {
                    evals[i] = Fp::new(val);
                }
                field::poly_interpolate(&evals, domain)
            })
            .collect();

        Ok(polys)
    }

    /// Evaluate column polynomials on the coset LDE domain.
    #[allow(dead_code)] // Reserved for LDE-based prover path
    fn evaluate_on_coset(
        &self,
        polys: &[Vec<Fp>],
        lde_domain: &Domain,
        offset: Fp,
    ) -> Vec<Vec<Fp>> {
        use rayon::prelude::*;
        polys
            .par_iter()
            .map(|coeffs| field::poly_eval_coset(coeffs, lde_domain, offset))
            .collect()
    }

    /// Build the composition polynomial evaluations on the LDE coset domain.
    ///
    /// Includes both CPU AIR and Coprocessor AIR constraints
    /// in the composition polynomial.
    fn build_composition_evals(
        &self,
        column_polys: &[Vec<Fp>],
        air: &RiscVAir,
        coproc_trace: &CoprocessorAlgebraicTrace,
        trace_domain: &Domain,
        lde_domain: &Domain,
        coset_offset: Fp,
        transcript: &mut Transcript,
    ) -> Result<Vec<Fp>, ProverError> {
        use rayon::prelude::*;

        let lde_size = lde_domain.size;

        // ── CPU AIR composition coefficients ──
        let num_trans = crate::air::NUM_TRANSITION_CONSTRAINTS;
        let num_bound = crate::air::NUM_BOUNDARY_CONSTRAINTS;
        let mut alphas_trans = Vec::with_capacity(num_trans);
        let mut alphas_bound = Vec::with_capacity(num_bound);
        for _ in 0..num_trans {
            alphas_trans.push(transcript.challenge_field());
        }
        for _ in 0..num_bound {
            alphas_bound.push(transcript.challenge_field());
        }

        // ── Coprocessor AIR composition coefficients ──
        let has_coproc = coproc_trace.num_rows > 0;
        let mut alphas_coproc_trans = Vec::with_capacity(COPROC_NUM_TRANSITION_CONSTRAINTS);
        let mut alphas_coproc_bound = Vec::with_capacity(COPROC_NUM_BOUNDARY_CONSTRAINTS);
        for _ in 0..COPROC_NUM_TRANSITION_CONSTRAINTS {
            alphas_coproc_trans.push(transcript.challenge_field());
        }
        for _ in 0..COPROC_NUM_BOUNDARY_CONSTRAINTS {
            alphas_coproc_bound.push(transcript.challenge_field());
        }

        // ── CPU LDE columns ──
        let lde_columns: Vec<Vec<Fp>> = column_polys
            .par_iter()
            .map(|coeffs| field::poly_eval_coset(coeffs, lde_domain, coset_offset))
            .collect();

        // ── Coprocessor LDE columns ──
        // Interpolate the coprocessor trace on its own domain (padded to next
        // power of 2), then evaluate on the same LDE coset domain so that
        // coprocessor constraints can be combined with CPU constraints.
        let (coproc_lde_columns, coproc_domain) = if has_coproc {
            let coproc_log_size = (coproc_trace.num_rows as u64)
                .next_power_of_two()
                .trailing_zeros();
            let coproc_padded_size = 1usize << coproc_log_size;
            let coproc_dom = Domain::new(coproc_log_size);

            let coproc_polys: Vec<Vec<Fp>> = coproc_trace
                .columns
                .par_iter()
                .map(|col| {
                    let mut evals = vec![Fp::ZERO; coproc_padded_size];
                    for (i, &val) in col.iter().enumerate() {
                        evals[i] = Fp::new(val);
                    }
                    field::poly_interpolate(&evals, &coproc_dom)
                })
                .collect();

            let coproc_lde: Vec<Vec<Fp>> = coproc_polys
                .par_iter()
                .map(|coeffs| field::poly_eval_coset(coeffs, lde_domain, coset_offset))
                .collect();

            (coproc_lde, Some(coproc_dom))
        } else {
            (vec![], None)
        };

        let omega_trace = trace_domain.generator;
        let coset_points = lde_domain.coset(coset_offset);
        let last_point = omega_trace.pow(trace_domain.size as u64 - 1);

        // Pre-compute coprocessor domain last point for transition constraint
        // quotients (x - ω_coproc^(n_coproc - 1)).
        let coproc_last_point = coproc_domain
            .as_ref()
            .map(|d| d.generator.pow(d.size as u64 - 1));

        let composition: Vec<Fp> = (0..lde_size)
            .into_par_iter()
            .map(|i| {
                let x = coset_points[i];
                let next_idx = (i + BLOWUP_FACTOR) % lde_size;

                // ── CPU AIR evaluation ──
                let current: Vec<Fp> = lde_columns.iter().map(|col| col[i]).collect();
                let next: Vec<Fp> = lde_columns.iter().map(|col| col[next_idx]).collect();

                if current.len() < TRACE_WIDTH || next.len() < TRACE_WIDTH {
                    return Fp::ZERO;
                }

                let frame = EvaluationFrame {
                    current: current.clone(),
                    next,
                };
                let trans_evals = air.evaluate_transition(&frame);

                let z_h = trace_domain.vanishing_eval(x);
                let denom = x.sub(last_point);

                let mut val = Fp::ZERO;

                let z_h_inv = z_h.try_inv();

                if let Some(z_h_inv) = z_h_inv {
                    if denom != Fp::ZERO {
                        for (j, c_val) in trans_evals.iter().enumerate() {
                            let quotient = c_val.mul(denom).mul(z_h_inv);
                            val = val.add(alphas_trans[j].mul(quotient));
                        }
                    }

                    let bound_evals = air.evaluate_boundary_first(&frame.current);
                    let denom_bound = x.sub(Fp::ONE);
                    if denom_bound != Fp::ZERO {
                        for (j, b_val) in bound_evals.iter().enumerate() {
                            let quotient = b_val.mul(denom_bound).mul(z_h_inv);
                            val = val.add(alphas_bound[j].mul(quotient));
                        }
                    }
                }

                // ── Coprocessor AIR evaluation ──
                // Evaluate the coprocessor's own transition and boundary
                // constraints and fold them into the composition polynomial
                // using the coprocessor's vanishing polynomial.
                if has_coproc {
                    let coproc_dom = coproc_domain.as_ref().unwrap();

                    let coproc_current: Vec<Fp> =
                        coproc_lde_columns.iter().map(|col| col[i]).collect();
                    let coproc_next: Vec<Fp> =
                        coproc_lde_columns.iter().map(|col| col[next_idx]).collect();

                    if coproc_current.len() >= COPROC_TRACE_WIDTH
                        && coproc_next.len() >= COPROC_TRACE_WIDTH
                    {
                        let coproc_frame = EvaluationFrame {
                            current: coproc_current.clone(),
                            next: coproc_next,
                        };

                        // Coprocessor vanishing polynomial on its own domain
                        let z_h_coproc = coproc_dom.vanishing_eval(x);
                        let z_h_coproc_inv = z_h_coproc.try_inv();

                        if let Some(z_h_coproc_inv) = z_h_coproc_inv {
                            // Transition constraints: divide by Z_H_coproc(x) / (x - ω_c^(n-1))
                            let coproc_last = coproc_last_point.unwrap();
                            let denom_coproc = x.sub(coproc_last);
                            if denom_coproc != Fp::ZERO {
                                let coproc_trans_evals =
                                    CoprocessorAir::evaluate_transition(&coproc_frame);
                                for (j, c_val) in coproc_trans_evals.iter().enumerate() {
                                    let quotient =
                                        c_val.mul(denom_coproc).mul(z_h_coproc_inv);
                                    val = val.add(alphas_coproc_trans[j].mul(quotient));
                                }
                            }

                            // Boundary constraints: divide by Z_H_coproc(x) / (x - 1)
                            let denom_bound_coproc = x.sub(Fp::ONE);
                            if denom_bound_coproc != Fp::ZERO {
                                let coproc_bound_evals =
                                    CoprocessorAir::evaluate_boundary_first(&coproc_current);
                                for (j, b_val) in coproc_bound_evals.iter().enumerate() {
                                    let quotient =
                                        b_val.mul(denom_bound_coproc).mul(z_h_coproc_inv);
                                    val = val.add(alphas_coproc_bound[j].mul(quotient));
                                }
                            }
                        }
                    }
                }

                val
            })
            .collect();

        Ok(composition)
    }

    /// Generate query proofs with Merkle authentication paths.
    fn generate_query_proofs(
        &self,
        trace: &AlgebraicTrace,
        trace_tree: &MerkleTree,
        composition_evals: &[Fp],
        composition_tree: &MerkleTree,
        transcript: &mut Transcript,
        lde_size: usize,
    ) -> Result<Vec<QueryProof>, ProverError> {
        if trace.num_steps == 0 {
            return Err(ProverError::EmptyTrace);
        }

        let mut proofs = Vec::with_capacity(self.num_queries);

        for _q in 0..self.num_queries {
            let index = transcript.challenge_index(lde_size);
            let trace_index = index % trace.num_steps;

            let trace_values: Vec<u32> = trace.columns.iter().map(|col| col[trace_index]).collect();

            let trace_merkle_proof = trace_tree.proof(trace_index);
            let trace_merkle_paths = trace_merkle_proof.map(|p| p.siblings).unwrap_or_default();

            let comp_index = index % composition_evals.len();
            let composition_value = composition_evals[comp_index];
            let comp_merkle_proof = composition_tree.proof(comp_index);
            let composition_merkle_path = comp_merkle_proof.map(|p| p.siblings).unwrap_or_default();

            proofs.push(QueryProof {
                index,
                trace_values,
                trace_merkle_paths,
                composition_value,
                composition_merkle_path,
            });
        }

        Ok(proofs)
    }
}

impl Default for StarkProver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_vm::instruction::{AluImmFunc, Instruction};
    use brrq_vm::trace::{ExecutionTrace, Sha256TraceStep, TraceStep};

    fn make_trace(num_steps: usize) -> ExecutionTrace {
        let mut trace = ExecutionTrace::with_capacity(num_steps);
        for i in 0..num_steps {
            let mut regs = [0u32; 32];
            regs[1] = i as u32;
            trace.record(TraceStep {
                step: i as u64,
                pc: (i * 4) as u32,
                instruction: Instruction::AluImm {
                    func: AluImmFunc::Addi,
                    rd: 1,
                    rs1: 0,
                    imm: i as i32,
                },
                instruction_word: 0x00000013,
                regs_before: regs,
                regs_after: regs,
                next_pc: ((i + 1) * 4) as u32,
                memory_accesses: vec![],
                gas_cost: 1,
                gas_used: (i + 1) as u64,
            });
        }
        trace
    }

    #[test]
    fn test_prove_basic() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        assert_ne!(proof.trace_commitment, Hash256::ZERO);
        assert_ne!(proof.composition_commitment, Hash256::ZERO);
        assert!(!proof.fri_commitments.is_empty());
        assert_eq!(proof.query_proofs.len(), NUM_QUERIES);
        assert_eq!(proof.num_steps, 8);
    }

    #[test]
    fn test_prove_deterministic() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof1 = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();
        let proof2 = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        assert_eq!(proof1.trace_commitment, proof2.trace_commitment);
        assert_eq!(proof1.composition_commitment, proof2.composition_commitment);
    }

    #[test]
    fn test_prove_different_state_roots() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof1 = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();
        let proof2 = prover
            .prove(
                &trace,
                Hash256::from_bytes([1; 32]),
                Hash256::from_bytes([2; 32]),
            )
            .unwrap();

        assert_eq!(proof1.trace_commitment, proof2.trace_commitment);
        assert_ne!(proof1.composition_commitment, proof2.composition_commitment);
    }

    #[test]
    fn test_prove_size_16() {
        let trace = make_trace(16);
        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();
        assert_eq!(proof.num_steps, 16);
        assert!(!proof.fri_commitments.is_empty());
    }

    #[test]
    fn test_prove_with_empty_coprocessor() {
        // No coprocessor calls — LogUp should still work (both sides empty)
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        assert_eq!(proof.coprocessor_num_rows, 0);
        assert_eq!(proof.coprocessor_commitment, Hash256::ZERO);
        // LogUp: both sums should be zero (no ECALL rows, no coproc rows)
        assert_eq!(proof.logup_cpu_final_sum, Fp::ZERO);
        assert_eq!(proof.logup_coproc_final_sum, Fp::ZERO);
    }

    #[test]
    fn test_prove_with_coprocessor_sha256() {
        // Build a trace with one ECALL row to match the coprocessor entry
        let mut trace = ExecutionTrace::with_capacity(8);
        for i in 0..8usize {
            let mut regs = [0u32; 32];
            regs[1] = i as u32;
            let instruction_word = if i == 3 {
                0x00000073 // ECALL
            } else {
                0x00000013 // ADDI
            };
            trace.record(TraceStep {
                step: i as u64,
                pc: (i * 4) as u32,
                instruction: Instruction::AluImm {
                    func: AluImmFunc::Addi,
                    rd: 1,
                    rs1: 0,
                    imm: i as i32,
                },
                instruction_word,
                regs_before: regs,
                regs_after: regs,
                next_pc: ((i + 1) * 4) as u32,
                memory_accesses: vec![],
                gas_cost: 1,
                gas_used: (i + 1) as u64,
            });
        }

        // Add a SHA-256 coprocessor trace step
        let input = [0x42u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        trace
            .coprocessor
            .sha256_steps
            .push(Sha256TraceStep { input, output });

        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        assert_eq!(proof.coprocessor_num_rows, 1);
        assert_ne!(proof.coprocessor_commitment, Hash256::ZERO);
        assert_eq!(proof.coprocessor_hashes.len(), 1);
    }

    #[test]
    fn test_prove_rejects_invalid_coprocessor() {
        let mut trace = make_trace(8);
        // Add a SHA-256 step with WRONG output
        trace.coprocessor.sha256_steps.push(Sha256TraceStep {
            input: [0x42u8; 64],
            output: [0xFFu8; 32], // wrong!
        });

        let prover = StarkProver::new();
        let result = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO);
        assert!(result.is_err(), "Should reject invalid coprocessor I/O");
    }

    #[test]
    fn test_prove_dual_commitment_roundtrip() {
        use crate::hash_config::ProverHashConfig;

        let trace = make_trace(8);
        let prover = StarkProver::with_hash_config(ProverHashConfig::DualCommitment);
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Poseidon2 commitments must be present.
        let p2_trace = proof
            .poseidon2_trace_commitment
            .expect("DualCommitment must produce poseidon2_trace_commitment");
        let p2_comp = proof
            .poseidon2_composition_commitment
            .expect("DualCommitment must produce poseidon2_composition_commitment");

        // They must be non-zero.
        assert_ne!(
            p2_trace,
            Hash256::ZERO,
            "Poseidon2 trace root must be non-zero"
        );
        assert_ne!(
            p2_comp,
            Hash256::ZERO,
            "Poseidon2 composition root must be non-zero"
        );

        // They must differ from SHA-256 commitments (different hash functions).
        assert_ne!(
            p2_trace, proof.trace_commitment,
            "Poseidon2 and SHA-256 trace roots should differ"
        );
        assert_ne!(
            p2_comp, proof.composition_commitment,
            "Poseidon2 and SHA-256 composition roots should differ"
        );

        // SHA-256 commitments must still be valid (backward compat).
        assert_ne!(proof.trace_commitment, Hash256::ZERO);
        assert_ne!(proof.composition_commitment, Hash256::ZERO);
        assert!(!proof.fri_commitments.is_empty());
    }

    #[test]
    fn test_prove_sha256_has_no_poseidon2() {
        // Explicit Sha256 mode should NOT produce Poseidon2 commitments.
        let trace = make_trace(8);
        let prover = StarkProver::with_hash_config(ProverHashConfig::Sha256);
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        assert!(
            proof.poseidon2_trace_commitment.is_none(),
            "Sha256 mode must not produce poseidon2_trace_commitment"
        );
        assert!(
            proof.poseidon2_composition_commitment.is_none(),
            "Sha256 mode must not produce poseidon2_composition_commitment"
        );
    }
}
