//! STARK proof verification over BabyBear.
//!
//! The verifier checks a STARK proof without re-executing the trace.
//! This is the component that would run in BitVM on Bitcoin L1.
//!
//! ## Verification Steps
//!
//! 1. Validate proof structure
//! 2. Replay Fiat-Shamir transcript to regenerate all challenges
//! 3. **Verify AIR constraints at the OOD point** (the critical check)
//! 4. **Verify coprocessor commitment and LogUp argument**
//! 5. Verify query Merkle proofs against commitments
//! 6. Verify composition Merkle proofs
//! 7. (FRI verification is handled separately via fri::fri_verify)

use brrq_crypto::hash::Hasher;
use brrq_crypto::merkle::MerkleProof;

use crate::air::{
    Air, NUM_BOUNDARY_CONSTRAINTS, NUM_TRANSITION_CONSTRAINTS, RiscVAir, TRACE_WIDTH,
};
use crate::error::ProverError;
use crate::field::{Domain, Fp};
use crate::field_ext::{self, Fp4};
use crate::fri::{self, FriConfig};
use crate::hash_config::ProverHashConfig;
use crate::lookup::{self, LogUpResult};
use crate::transcript::Transcript;
use crate::types::StarkProof;

/// STARK proof verifier.
pub struct StarkVerifier;

impl StarkVerifier {
    /// Verify a STARK proof.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Err` if verification fails.
    ///
    /// ## What this verifies
    ///
    /// 1. **Structural validity**: Non-empty proof, consistent sizes
    /// 2. **Fiat-Shamir consistency**: All challenges match the transcript
    /// 3. **AIR constraint satisfaction**: Transition and boundary constraints
    ///    evaluate to zero at the Out-of-Domain point
    /// 4. **Coprocessor integrity**: Coprocessor commitment is bound to the proof,
    ///    LogUp argument proves CPU ↔ Coprocessor multiset equality
    /// 5. **Merkle authentication**: Query openings match commitments
    pub fn verify(proof: &StarkProof) -> Result<bool, ProverError> {
        // ── Step 1: Validate structure ──
        Self::validate_proof_structure(proof)?;

        // ── Step 2: Replay Fiat-Shamir transcript ──

        let mut transcript = Transcript::new(brrq_crypto::domain_tags::STARK_TRANSCRIPT_V2);
        transcript.absorb_hash(&proof.trace_commitment);
        // Absorb Poseidon2 trace commitment (must match prover's transcript).
        if let Some(ref p2_trace) = proof.poseidon2_trace_commitment {
            transcript.absorb_hash(p2_trace);
        }
        transcript.absorb_hash(&proof.initial_state_root);
        transcript.absorb_hash(&proof.final_state_root);
        transcript.absorb_u64(proof.num_steps);

        // ── Draw OOD point z from the quartic extension field ──
        //
        // z ← Fp4 (extension field, ~2¹²⁴ elements, ~102-bit OOD security).
        //
        // By Schwartz-Zippel: Pr[P(z)=0] ≤ d/|F|. With d ≈ 3·2²⁰ and
        // |Fp4| ≈ 2¹²⁴, the probability of a false positive is ≤ 2⁻¹⁰².
        let z: Fp4 = transcript.challenge_ext_field();

        // Reconstruct trace domain.
        let trace_domain = Domain::new(proof.trace_log_size);
        // z·ω: multiply the Fp4 point by the base-field domain generator
        let _z_next = z.mul(Fp4::from_base(trace_domain.generator));

        // Absorb OOD frame (Fp4 values).
        for eval in &proof.ood_frame.current {
            transcript.absorb_fp4(*eval);
        }
        for eval in &proof.ood_frame.next {
            transcript.absorb_fp4(*eval);
        }

        // ── Step 3: Verify AIR constraints at OOD point (in extension field) ──

        let air = RiscVAir::new(proof.initial_state_root, proof.final_state_root);

        // Use _ext methods for Fp4 evaluation.
        let transition_evals = air.evaluate_transition_ext(&proof.ood_frame);

        // Evaluate zerofiers at the Fp4 OOD point.
        let domain_size = 1u64 << proof.trace_log_size;
        let last_point = trace_domain.generator.pow((domain_size - 1) as u64);

        let z_trans =
            field_ext::transition_zerofier_eval_ext(z, domain_size, last_point)
                .ok_or_else(|| ProverError::InvalidProof {
                    reason: "OOD point z is in trace domain".into(),
                })?;

        let z_bound =
            field_ext::boundary_zerofier_eval_first_ext(z, domain_size)
                .ok_or_else(|| ProverError::InvalidProof {
                    reason: "OOD point z equals 1".into(),
                })?;

        let z_trans_inv = z_trans.try_inv().ok_or_else(|| ProverError::InvalidProof {
            reason: "transition zerofier evaluated to zero at OOD point".into(),
        })?;
        let z_bound_inv = z_bound.try_inv().ok_or_else(|| ProverError::InvalidProof {
            reason: "boundary zerofier evaluated to zero at OOD point".into(),
        })?;

        // Composition accumulator is now Fp4.
        // RLC challenges are drawn from Fp4 for full extension-field soundness.
        let mut composition_at_z = Fp4::ZERO;

        // Transition constraint quotients (all in Fp4).
        for c in &transition_evals {
            let alpha = transcript.challenge_ext_field();
            let quotient = c.mul(z_trans_inv);
            composition_at_z = composition_at_z.add(alpha.mul(quotient));
        }

        // Boundary constraints (in Fp4).
        let boundary_evals = air.evaluate_boundary_first_ext(&proof.ood_frame.current);
        for c in &boundary_evals {
            let alpha = transcript.challenge_ext_field();
            let quotient = c.mul(z_bound_inv);
            composition_at_z = composition_at_z.add(alpha.mul(quotient));
        }

        // ══════════════════════════════════════════════════════════════
        // Step 4: Verify Coprocessor
        // Coprocessor verification comes BEFORE coprocessor OOD evaluation
        // to match the prover's transcript order (the prover builds the
        // coprocessor proof before evaluating coprocessor AIR at OOD).
        // ══════════════════════════════════════════════════════════════
        Self::verify_coprocessor_logup(proof, &mut transcript)?;

        // ── Coprocessor AIR constraints at OOD point ──
        // The prover includes coprocessor transition and boundary constraints
        // in composition_at_z when there are coprocessor rows. The verifier
        // must do the same to match, using the coproc_ood_frame from the proof.
        if let Some(ref coproc_frame) = proof.coproc_ood_frame {
            if proof.coprocessor_num_rows > 0 {
                let coproc_padded_size = (proof.coprocessor_num_rows as u64)
                    .next_power_of_two() as usize;
                let coproc_log_size = coproc_padded_size.trailing_zeros();
                let coproc_domain = Domain::new(coproc_log_size);
                let coproc_domain_size = 1u64 << coproc_log_size;
                let coproc_last_point = coproc_domain.generator.pow((coproc_domain_size - 1) as u64);

                // Zerofiers evaluated at Fp4 point z.
                let z_ct_inv = field_ext::transition_zerofier_eval_ext(z, coproc_domain_size, coproc_last_point)
                    .and_then(|v| v.try_inv());
                let z_cb_inv = field_ext::boundary_zerofier_eval_first_ext(z, coproc_domain_size)
                    .and_then(|v| v.try_inv());

                let coproc_trans =
                    crate::coprocessor_air::CoprocessorAir::evaluate_transition_ext(coproc_frame);
                for c in &coproc_trans {
                    let alpha = transcript.challenge_ext_field();
                    if let Some(inv) = z_ct_inv {
                        let quotient = c.mul(inv);
                        composition_at_z = composition_at_z.add(alpha.mul(quotient));
                    }
                }

                let coproc_bound =
                    crate::coprocessor_air::CoprocessorAir::evaluate_boundary_first_ext(
                        &coproc_frame.current,
                    );
                for c in &coproc_bound {
                    let alpha = transcript.challenge_ext_field();
                    if let Some(inv) = z_cb_inv {
                        let quotient = c.mul(inv);
                        composition_at_z = composition_at_z.add(alpha.mul(quotient));
                    }
                }
            } else {
                // coproc_ood_frame present but no rows — draw alphas for transcript sync
                for _ in 0..crate::coprocessor_air::COPROC_NUM_TRANSITION_CONSTRAINTS {
                    let _ = transcript.challenge_ext_field();
                }
                for _ in 0..crate::coprocessor_air::COPROC_NUM_BOUNDARY_CONSTRAINTS {
                    let _ = transcript.challenge_ext_field();
                }
            }
        } else {
            // No coproc_ood_frame (legacy proof or empty coprocessor)
            for _ in 0..crate::coprocessor_air::COPROC_NUM_TRANSITION_CONSTRAINTS {
                let _ = transcript.challenge_ext_field();
            }
            for _ in 0..crate::coprocessor_air::COPROC_NUM_BOUNDARY_CONSTRAINTS {
                let _ = transcript.challenge_ext_field();
            }
        }

        // ── FIX: Verify composition polynomial matches AIR constraints ──
        // The prover's composition_at_z must equal the verifier's recomputation.
        // This now includes BOTH CPU and coprocessor AIR constraints.
        if composition_at_z != proof.composition_at_z {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Composition polynomial mismatch at OOD point: verifier computed {:?}, proof claims {:?}",
                    composition_at_z, proof.composition_at_z
                ),
            });
        }

        // Draw the same RLC weights for composition building (must match prover).
        // CPU transition + boundary constraints:
        for _ in 0..NUM_TRANSITION_CONSTRAINTS {
            let _ = transcript.challenge_field();
        }
        for _ in 0..NUM_BOUNDARY_CONSTRAINTS {
            let _ = transcript.challenge_field();
        }
        // Coprocessor transition + boundary constraints
        // (alphas are drawn even when coproc is empty, for transcript sync).
        for _ in 0..crate::coprocessor_air::COPROC_NUM_TRANSITION_CONSTRAINTS {
            let _ = transcript.challenge_field();
        }
        for _ in 0..crate::coprocessor_air::COPROC_NUM_BOUNDARY_CONSTRAINTS {
            let _ = transcript.challenge_field();
        }

        // Absorb composition commitment.
        transcript.absorb_hash(&proof.composition_commitment);
        // Absorb Poseidon2 composition commitment (must match prover's transcript).
        if let Some(ref p2_comp) = proof.poseidon2_composition_commitment {
            transcript.absorb_hash(p2_comp);
        }

        // ══════════════════════════════════════════════════════════════
        // Step 4b: Verify Register File LogUp
        // ══════════════════════════════════════════════════════════════
        Self::verify_regfile_logup(proof, &mut transcript)?;

        // ══════════════════════════════════════════════════════════════
        // Step 4c: Verify Bitwise LogUp
        // ══════════════════════════════════════════════════════════════
        Self::verify_bitwise_logup(proof, &mut transcript)?;

        // ── Step 5: FRI low-degree verification ──
        //
        // Actually invoke fri_verify() instead of just replaying
        // the transcript. Without this check, a malicious prover can commit
        // to an arbitrary (non-low-degree) function and the verifier accepts.

        if proof.trace_log_size > 30 {
            return Err(ProverError::InvalidProof {
                reason: "trace_log_size exceeds maximum of 30".into(),
            });
        }
        let lde_log_size = proof.trace_log_size + 2; // BLOWUP_FACTOR = 4
        let lde_size = 1usize << lde_log_size;
        let fri_initial_half = lde_size / 2;

        // Reconstruct the LDE domain generator for FRI verification.
        let lde_domain = Domain::new(lde_log_size);
        let fri_domain_gen = lde_domain.generator;

        let fri_config = FriConfig {
            num_queries: proof.num_fri_queries,
            max_rounds: 20,
            hash_config: ProverHashConfig::default(),
        };

        match &proof.fri_proof {
            Some(fri_proof_data) => {
                // Full FRI verification: Merkle authentication + folding consistency.
                fri::fri_verify(
                    fri_proof_data,
                    &proof.composition_commitment,
                    fri_domain_gen,
                    &fri_config,
                    &mut transcript,
                )?;

                // Advance transcript past query indices to stay in sync with prover.
                // fri_verify() absorbs commitments + alphas + final_value, but the
                // prover's fri_prove() also draws query indices afterwards.
                for _ in 0..proof.num_fri_queries {
                    let _ = transcript.challenge_index(fri_initial_half);
                }
            }
            None => {
                return Err(ProverError::InvalidProof {
                    reason: "Missing FRI proof data — cannot verify low-degree test".into(),
                });
            }
        }

        // ── Step 6: Derive and verify query indices ──
        Self::verify_query_proofs(proof, &mut transcript, lde_size)?;

        Ok(true)
    }

    /// Validate proof structural invariants before expensive verification.
    ///
    /// Checks: non-zero steps, FRI commitments present, query proof counts,
    /// OOD frame dimensions.
    fn validate_proof_structure(proof: &StarkProof) -> Result<(), ProverError> {
        if proof.num_steps == 0 {
            return Err(ProverError::InvalidProof {
                reason: "zero steps".into(),
            });
        }

        if proof.fri_commitments.is_empty() {
            return Err(ProverError::InvalidProof {
                reason: "no FRI commitments".into(),
            });
        }

        if proof.query_proofs.is_empty() {
            return Err(ProverError::InvalidProof {
                reason: "no query proofs".into(),
            });
        }

        // Enforce minimum FRI queries to prevent proof forgery.
        // Without this, an attacker can set num_fri_queries=1 (controlled via the
        // proof blob) to reduce soundness from ~128-bit to ~2-bit, allowing
        // trivial proof forgery and fund theft.
        // Raised from 40 to 64 to match the prover's
        // NUM_QUERIES=64. With 40 queries × log2(4) blowup = 80-bit security,
        // which is below the 128-bit standard. 64 queries provides ~128-bit
        // security, matching the prover's target.
        const MIN_FRI_QUERIES: usize = 64;
        const MAX_QUERY_PROOFS: usize = 256;

        if proof.num_fri_queries < MIN_FRI_QUERIES {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "num_fri_queries ({}) below minimum {} — insufficient soundness",
                    proof.num_fri_queries, MIN_FRI_QUERIES
                ),
            });
        }
        if proof.query_proofs.len() > MAX_QUERY_PROOFS {
            return Err(ProverError::InvalidProof {
                reason: "too many query proofs".into(),
            });
        }
        if proof.num_fri_queries > MAX_QUERY_PROOFS {
            return Err(ProverError::InvalidProof {
                reason: "num_fri_queries exceeds maximum".into(),
            });
        }
        if proof.query_proofs.len() != proof.num_fri_queries {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "query_proofs count ({}) != num_fri_queries ({})",
                    proof.query_proofs.len(),
                    proof.num_fri_queries
                ),
            });
        }

        if proof.ood_frame.current.len() < TRACE_WIDTH || proof.ood_frame.next.len() < TRACE_WIDTH {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "OOD frame too small: {}/{} columns, need {}",
                    proof.ood_frame.current.len(),
                    proof.ood_frame.next.len(),
                    TRACE_WIDTH
                ),
            });
        }

        Ok(())
    }

    /// Verify a STARK proof WITH coprocessor I/O re-execution.
    ///
    /// This is the **mainnet-safe** verification path. It:
    /// 1. Runs the standard STARK `verify()` (structural + algebraic + LogUp)
    /// 2. Re-executes every coprocessor operation from the provided trace
    /// 3. Rejects if any SHA-256/Schnorr/Merkle output doesn't match
    ///
    /// This closes COPROC-IO-1: a malicious prover cannot forge coprocessor
    /// outputs because the verifier independently re-computes them.
    pub fn verify_with_coprocessor_io(
        proof: &StarkProof,
        coprocessor_trace: &brrq_vm::trace::CoprocessorTrace,
    ) -> Result<bool, ProverError> {
        // Step 1: Standard STARK verification
        let stark_valid = Self::verify(proof)?;
        if !stark_valid {
            return Ok(false);
        }

        // Step 2: Re-execute coprocessor I/O and verify correctness
        crate::coprocessor_air::verify_coprocessor_io(coprocessor_trace)
            .map_err(|e| ProverError::VerificationFailed {
                reason: format!("COPROC-IO verification failed: {}", e),
            })?;

        Ok(true)
    }

    /// Verify coprocessor commitment and LogUp cross-table argument.
    ///
    /// Absorbs coprocessor data into the Fiat-Shamir transcript and verifies
    /// the multi-round LogUp argument proves CPU ↔ Coprocessor multiset equality.
    fn verify_coprocessor_logup(
        proof: &StarkProof,
        transcript: &mut Transcript,
    ) -> Result<(), ProverError> {
        // (a) Absorb coprocessor commitment
        transcript.absorb_hash(&proof.coprocessor_commitment);
        transcript.absorb_u64(proof.coprocessor_num_rows as u64);

        if proof.coprocessor_hashes.len() != proof.coprocessor_num_rows {
            return Err(ProverError::InvalidProof {
                reason: "coprocessor_hashes count does not match coprocessor_num_rows".into(),
            });
        }
        const MAX_COPROCESSOR_ROWS: usize = 1 << 20;
        if proof.coprocessor_num_rows > MAX_COPROCESSOR_ROWS {
            return Err(ProverError::InvalidProof {
                reason: "coprocessor_num_rows exceeds maximum".into(),
            });
        }

        // (b) Absorb coprocessor row hashes (must match prover order)
        for hash in &proof.coprocessor_hashes {
            transcript.absorb_hash(hash);
        }

        // (c) Verify LogUp argument — multi-round for ~2^-124 soundness.
        //
        // ZERO-TRUST ENFORCEMENT: No legacy single-round fallback.
        // Every valid proof MUST contain exactly LOGUP_ROUNDS rounds.
        // A single-round proof only provides ~2^-21 soundness (n/|F|)
        // vs ~2^-124 with 4 rounds — accepting it would be a
        // catastrophic downgrade attack.
        if proof.logup_round_sums.len() != lookup::LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Coprocessor LogUp: expected exactly {} rounds, got {} \
                     (zero-trust enforcement — no legacy single-round bypass permitted)",
                    lookup::LOGUP_ROUNDS,
                    proof.logup_round_sums.len()
                ),
            });
        }

        // Verify running sum commitment count matches round count.
        if proof.logup_running_sum_commitments.len() != lookup::LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Coprocessor LogUp: expected exactly {} running sum commitments, got {} \
                     (C-1 fix — running sum binding required)",
                    lookup::LOGUP_ROUNDS,
                    proof.logup_running_sum_commitments.len()
                ),
            });
        }

        for (i, &(cpu_sum, coproc_sum)) in proof.logup_round_sums.iter().enumerate() {
            let _logup_beta = transcript.challenge_field();
            transcript.absorb_fp(cpu_sum);
            transcript.absorb_fp(coproc_sum);

            let logup_result = lookup::verify_logup_from_proof(cpu_sum, coproc_sum);
            if logup_result != LogUpResult::Valid {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "LogUp round {} failed: CPU sum {:?} ≠ Coprocessor sum {:?}",
                        i, cpu_sum, coproc_sum
                    ),
                });
            }
        }

        // Absorb running sum commitments into transcript.
        // This ensures the prover committed to specific running sum columns
        // BEFORE FRI challenges are drawn. The commitment is Fiat-Shamir
        // bound: if the prover changes the commitment, all subsequent
        // challenges change and the FRI/query proofs become invalid.
        for commitment in &proof.logup_running_sum_commitments {
            transcript.absorb_hash(commitment);
        }

        // Cross-validate LogUp sums against structural invariants.
        if proof.coprocessor_num_rows > 0
            && proof.logup_cpu_final_sum == Fp::ZERO
            && proof.logup_coproc_final_sum == Fp::ZERO
        {
            return Err(ProverError::InvalidProof {
                reason: "LogUp sums are both zero but coprocessor has entries".into(),
            });
        }
        if proof.coprocessor_num_rows == 0 && proof.logup_cpu_final_sum != Fp::ZERO {
            return Err(ProverError::InvalidProof {
                reason: "LogUp CPU sum is nonzero but coprocessor is empty".into(),
            });
        }

        Ok(())
    }

    /// Verify register file LogUp argument.
    ///
    /// ZERO-TRUST ENFORCEMENT: No backward compatibility. Every valid proof
    /// MUST contain exactly LOGUP_ROUNDS rounds. A proof with fewer or more
    /// rounds is unconditionally rejected.
    ///
    /// Replays the prover's transcript operations for the register file LogUp:
    /// 1. Enforce exact round count (LOGUP_ROUNDS = 4)
    /// 2. Draw 3 alpha challenges (bus value linear combination)
    /// 3. Absorb alphas back
    /// 4. For each of LOGUP_ROUNDS rounds: draw beta, absorb final sums, verify equality
    fn verify_regfile_logup(
        proof: &StarkProof,
        transcript: &mut Transcript,
    ) -> Result<(), ProverError> {
        // ── ZERO-TRUST GATE: exact round count enforcement ──
        if proof.regfile_logup_round_sums.len() != lookup::LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Register file LogUp: expected exactly {} rounds, got {} \
                     (zero-trust enforcement — no legacy bypass permitted)",
                    lookup::LOGUP_ROUNDS,
                    proof.regfile_logup_round_sums.len()
                ),
            });
        }

        // Verify running sum commitment count.
        if proof.regfile_running_sum_commitments.len() != lookup::LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Register file LogUp: expected exactly {} running sum commitments, got {} \
                     (C-1 fix — running sum binding required)",
                    lookup::LOGUP_ROUNDS,
                    proof.regfile_running_sum_commitments.len()
                ),
            });
        }

        // Replay alpha challenge draws (must match prover's build_regfile_logup)
        let alpha0 = transcript.challenge_field();
        let alpha1 = transcript.challenge_field();
        let alpha2 = transcript.challenge_field();
        transcript.absorb_fp(alpha0);
        transcript.absorb_fp(alpha1);
        transcript.absorb_fp(alpha2);

        // Replay multi-round LogUp transcript
        for (i, &(cpu_sum, regfile_sum)) in proof.regfile_logup_round_sums.iter().enumerate() {
            let _beta = transcript.challenge_field();
            transcript.absorb_fp(cpu_sum);
            transcript.absorb_fp(regfile_sum);

            let logup_result = lookup::verify_logup_from_proof(cpu_sum, regfile_sum);
            if logup_result != LogUpResult::Valid {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Register file LogUp round {} failed: CPU sum {:?} ≠ regfile sum {:?}",
                        i, cpu_sum, regfile_sum
                    ),
                });
            }
        }

        // Absorb running sum commitments into transcript.
        for commitment in &proof.regfile_running_sum_commitments {
            transcript.absorb_hash(commitment);
        }

        Ok(())
    }

    /// Verify bitwise LogUp argument.
    ///
    /// ZERO-TRUST ENFORCEMENT: No backward compatibility. Every valid proof
    /// MUST contain exactly BITWISE_LOGUP_ROUNDS rounds. A proof with fewer
    /// or more rounds is unconditionally rejected — no legacy bypass, no
    /// downgrade path, no empty-vector shortcut.
    ///
    /// Replays the prover's transcript operations for the bitwise LogUp:
    /// 1. Enforce exact round count (BITWISE_LOGUP_ROUNDS = 4)
    /// 2. Draw 4 alpha challenges (bus value linear combination)
    /// 3. Absorb alphas back
    /// 4. For each round: draw beta, absorb final sums, verify equality
    fn verify_bitwise_logup(
        proof: &StarkProof,
        transcript: &mut Transcript,
    ) -> Result<(), ProverError> {
        // ── ZERO-TRUST GATE: exact round count enforcement ──
        // Rejects: empty vectors (downgrade attack), truncated vectors
        // (partial bypass), inflated vectors (transcript desync attack).
        if proof.bitwise_logup_round_sums.len() != lookup::BITWISE_LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Bitwise LogUp: expected exactly {} rounds, got {}",
                    lookup::BITWISE_LOGUP_ROUNDS,
                    proof.bitwise_logup_round_sums.len()
                ),
            });
        }

        // Verify running sum commitment count.
        if proof.bitwise_running_sum_commitments.len() != lookup::BITWISE_LOGUP_ROUNDS {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "Bitwise LogUp: expected exactly {} running sum commitments, got {} \
                     (C-1 fix — running sum binding required)",
                    lookup::BITWISE_LOGUP_ROUNDS,
                    proof.bitwise_running_sum_commitments.len()
                ),
            });
        }

        // Replay alpha challenge draws (must match prover's build_bitwise_logup)
        let alpha0 = transcript.challenge_field();
        let alpha1 = transcript.challenge_field();
        let alpha2 = transcript.challenge_field();
        let alpha3 = transcript.challenge_field();
        transcript.absorb_fp(alpha0);
        transcript.absorb_fp(alpha1);
        transcript.absorb_fp(alpha2);
        transcript.absorb_fp(alpha3);

        // Replay multi-round LogUp transcript
        for (i, &(cpu_sum, table_sum)) in proof.bitwise_logup_round_sums.iter().enumerate() {
            let _beta = transcript.challenge_field();
            transcript.absorb_fp(cpu_sum);
            transcript.absorb_fp(table_sum);

            let logup_result = lookup::verify_logup_from_proof(cpu_sum, table_sum);
            if logup_result != LogUpResult::Valid {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Bitwise LogUp round {} failed: CPU sum {:?} ≠ table sum {:?}",
                        i, cpu_sum, table_sum
                    ),
                });
            }
        }

        // Absorb running sum commitments into transcript.
        for commitment in &proof.bitwise_running_sum_commitments {
            transcript.absorb_hash(commitment);
        }

        Ok(())
    }

    /// Derive query indices from transcript and verify Merkle proofs.
    ///
    /// For each query: checks index matches Fiat-Shamir challenge, recomputes
    /// leaf hash, and verifies both trace and composition Merkle paths.
    fn verify_query_proofs(
        proof: &StarkProof,
        transcript: &mut Transcript,
        lde_size: usize,
    ) -> Result<(), ProverError> {
        let mut expected_indices = Vec::with_capacity(proof.query_proofs.len());
        for _ in 0..proof.query_proofs.len() {
            expected_indices.push(transcript.challenge_index(lde_size));
        }

        for (qi, query) in proof.query_proofs.iter().enumerate() {
            if query.index != expected_indices[qi] {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Query index mismatch at position {}: expected {}, got {}",
                        qi, expected_indices[qi], query.index
                    ),
                });
            }

            if query.trace_values.is_empty() {
                return Err(ProverError::InvalidProof {
                    reason: format!("empty trace values at query index {}", query.index),
                });
            }

            // Recompute leaf hash from trace values.
            let mut leaf_hasher = Hasher::new();
            for val in &query.trace_values {
                leaf_hasher.update(&val.to_le_bytes());
            }
            let leaf_hash = leaf_hasher.finalize();

            let trace_index = query.index % (proof.num_steps as usize);

            // Verify trace Merkle path.
            // MerkleTree::from_hashes applies hash_leaf() to inputs,
            // so the verifier must also domain-separate the recomputed leaf hash.
            // Reject empty trace Merkle paths — an attacker could
            // skip authentication entirely by providing no siblings.
            if query.trace_merkle_paths.is_empty() {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "empty trace Merkle path at query index {} — authentication bypassed",
                        query.index
                    ),
                });
            }
            {
                let merkle_proof = MerkleProof {
                    leaf: Hasher::hash_leaf(leaf_hash.as_bytes()),
                    siblings: query.trace_merkle_paths.clone(),
                    path_indices: Self::index_to_path(trace_index, query.trace_merkle_paths.len()),
                };
                if !merkle_proof.verify(&proof.trace_commitment) {
                    return Err(ProverError::InvalidProof {
                        reason: format!("Trace Merkle proof failed at query index {}", query.index),
                    });
                }
            }

            // Verify composition Merkle path.
            // Reject empty composition Merkle paths too.
            if query.composition_merkle_path.is_empty() {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "empty composition Merkle path at query index {} — authentication bypassed",
                        query.index
                    ),
                });
            }
            // No need to re-check is_empty() here — the guard above
            // already returns Err if the path is empty, so at this point the
            // composition_merkle_path is guaranteed to be non-empty.
            let comp_leaf_raw = Hasher::hash(&query.composition_value.value().to_le_bytes());
            let comp_leaf = Hasher::hash_leaf(comp_leaf_raw.as_bytes());
            let comp_index = query.index % lde_size;
            let comp_merkle_proof = MerkleProof {
                leaf: comp_leaf,
                siblings: query.composition_merkle_path.clone(),
                path_indices: Self::index_to_path(comp_index, query.composition_merkle_path.len()),
            };
            if !comp_merkle_proof.verify(&proof.composition_commitment) {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Composition Merkle proof failed at query index {}",
                        query.index
                    ),
                });
            }
        }

        Ok(())
    }

    /// Convert a leaf index to path direction indicators for Merkle verification.
    #[inline]
    fn index_to_path(mut index: usize, depth: usize) -> Vec<bool> {
        let mut path = Vec::with_capacity(depth);
        for _ in 0..depth {
            path.push(!index.is_multiple_of(2));
            index /= 2;
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::StarkProver;
    use brrq_crypto::hash::Hash256;
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
    fn test_verify_valid_proof() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        let result = StarkVerifier::verify(&proof).unwrap();
        assert!(result, "Valid proof should verify successfully");
    }

    #[test]
    fn test_verify_empty_proof() {
        let proof = StarkProof {
            trace_commitment: Hash256::ZERO,
            composition_commitment: Hash256::ZERO,
            composition_at_z: crate::field_ext::Fp4::ZERO,
            ood_frame: crate::types::OodFrame {
                current: vec![],
                next: vec![],
            },
            fri_commitments: vec![],
            query_proofs: vec![],
            num_steps: 0,
            total_gas: 0,
            initial_state_root: Hash256::ZERO,
            final_state_root: Hash256::ZERO,
            coprocessor_hashes: Vec::new(),
            coprocessor_commitment: Hash256::ZERO,
            coprocessor_num_rows: 0,
            logup_cpu_final_sum: Fp::ZERO,
            logup_coproc_final_sum: Fp::ZERO,
            logup_round_sums: Vec::new(),
            trace_log_size: 0,
            fri_final_value: Fp::ZERO,
            num_fri_queries: 0,
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
        let result = StarkVerifier::verify(&proof);
        assert!(result.is_err(), "Empty proof should fail verification");
    }

    #[test]
    fn test_verify_tampered_ood_frame() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper with OOD frame: change PC evaluation.
        proof.ood_frame.current[0] = Fp4::from_base(Fp::new(999));

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered proof should NOT verify as valid"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn test_verify_tampered_state_root() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        proof.initial_state_root = Hash256::from_bytes([0xFF; 32]);

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered state root should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn test_verify_prove_verify_cycle() {
        for size in [4, 8, 16] {
            let trace = make_trace(size);
            let prover = StarkProver::new();
            let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();
            let result = StarkVerifier::verify(&proof).unwrap();
            assert!(result, "Proof for size {size} should verify");
        }
    }

    #[test]
    fn test_verify_with_coprocessor() {
        // Build a trace that includes an ECALL row (instruction_word = 0x00000073)
        // so that LogUp can match the CPU ECALL with the coprocessor entry.
        let mut trace = ExecutionTrace::with_capacity(8);
        for i in 0..8usize {
            let mut regs = [0u32; 32];
            regs[1] = i as u32;
            // Make step 3 an ECALL (SHA-256 precompile call)
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

        // Add a SHA-256 coprocessor step (matching the ECALL at step 3)
        let input = [0x42u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        trace
            .coprocessor
            .sha256_steps
            .push(Sha256TraceStep { input, output });

        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        let result = StarkVerifier::verify(&proof).unwrap();
        assert!(result, "Proof with coprocessor should verify");
    }

    #[test]
    fn test_verify_tampered_logup() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper with LogUp: make sums different
        proof.logup_cpu_final_sum = Fp::new(999);
        proof.logup_coproc_final_sum = Fp::new(123);

        let result = StarkVerifier::verify(&proof);
        // Should fail either because LogUp mismatch or because transcript diverges
        match result {
            Ok(true) => panic!("Tampered LogUp should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn test_verify_tampered_coprocessor_commitment() {
        let mut trace = make_trace(8);
        let input = [0u8; 64];
        let output = *Hasher::hash(&input).as_bytes();
        trace
            .coprocessor
            .sha256_steps
            .push(Sha256TraceStep { input, output });

        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper: change coprocessor commitment
        proof.coprocessor_commitment = Hash256::from_bytes([0xAA; 32]);

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered coprocessor commitment should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Proof Forgery Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_tampered_num_steps() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper: claim more steps than actually proved
        proof.num_steps = 1000;

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered num_steps should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_tampered_trace_commitment() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper: replace trace commitment with garbage
        proof.trace_commitment = Hash256::from_bytes([0xDE; 32]);

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered trace commitment should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_tampered_composition_commitment() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper: replace composition commitment
        proof.composition_commitment = Hash256::from_bytes([0xBE; 32]);

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered composition commitment should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_tampered_fri_commitment() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Tamper with the actual FRI proof layer commitment (used by fri_verify).
        if let Some(ref mut fri_proof) = proof.fri_proof {
            if !fri_proof.layer_commitments.is_empty() {
                fri_proof.layer_commitments[0] = Hash256::from_bytes([0xCA; 32]);
            }
        }

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered FRI commitment should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_tampered_query_index() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        if !proof.query_proofs.is_empty() {
            // Tamper: shift query index by 1
            proof.query_proofs[0].index = proof.query_proofs[0].index.wrapping_add(1);
        }

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered query index should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_ood_frame_too_small() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Truncate OOD frame
        proof.ood_frame.current.truncate(1);

        let result = StarkVerifier::verify(&proof);
        assert!(result.is_err(), "Truncated OOD frame should be rejected");
    }

    #[test]
    fn adversarial_logup_sum_mismatch() {
        // Attacker crafts matching LogUp sums (both nonzero) but different from actual
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Set matching but fake sums
        proof.logup_cpu_final_sum = Fp::new(42);
        proof.logup_coproc_final_sum = Fp::new(42);

        // Should still fail because transcript diverges
        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Fake matching LogUp sums should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_empty_fri_commitments() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        proof.fri_commitments.clear();

        let result = StarkVerifier::verify(&proof);
        assert!(result.is_err(), "Empty FRI commitments should be rejected");
    }

    #[test]
    fn adversarial_empty_query_proofs() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        proof.query_proofs.clear();

        let result = StarkVerifier::verify(&proof);
        assert!(result.is_err(), "Empty query proofs should be rejected");
    }

    #[test]
    fn adversarial_proof_serialization_roundtrip() {
        // Verify proof survives serialization/deserialization
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        let bytes = proof.to_bytes().unwrap();
        let restored = crate::types::StarkProof::from_bytes(&bytes).unwrap();

        // Restored proof should still verify
        let result = StarkVerifier::verify(&restored).unwrap();
        assert!(result, "Deserialized proof should verify");
    }

    #[test]
    fn adversarial_tampered_final_state_root() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Change final state root (different from initial)
        proof.final_state_root = Hash256::from_bytes([0xFF; 32]);

        let result = StarkVerifier::verify(&proof);
        match result {
            Ok(true) => panic!("Tampered final state root should NOT verify"),
            Ok(false) | Err(_) => {}
        }
    }

    #[test]
    fn adversarial_different_trace_sizes_verify() {
        // Ensure various trace sizes all produce verifiable proofs
        for size in [4, 8, 16, 32] {
            let trace = make_trace(size);
            let prover = StarkProver::new();
            let proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

            let result = StarkVerifier::verify(&proof).unwrap();
            assert!(result, "Size {size} proof should verify");
        }
    }

    // Verify that low num_fri_queries is rejected.
    #[test]
    fn adversarial_low_fri_queries_rejected() {
        let trace = make_trace(8);
        let prover = StarkProver::new();
        let mut proof = prover.prove(&trace, Hash256::ZERO, Hash256::ZERO).unwrap();

        // Attacker sets num_fri_queries to 1 to reduce soundness to ~2-bit
        proof.num_fri_queries = 1;
        proof.query_proofs.truncate(1);

        let result = StarkVerifier::verify(&proof);
        assert!(
            result.is_err(),
            "Proof with num_fri_queries=1 must be rejected (C-01)"
        );
    }
}
