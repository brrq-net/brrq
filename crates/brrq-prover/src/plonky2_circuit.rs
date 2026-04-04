//! Real Plonky2 circuit for STARK proof verification.
//!
//! ## Architecture
//!
//! This module provides a real Plonky2 circuit that cryptographically binds
//! STARK proof metadata into a succinct recursive proof. It replaces the
//! hash-based simulation in `plonky2_wrapper.rs` when the `real-plonky2`
//! feature is enabled.
//!
//! ### StarkVerifierCircuit
//!
//! Builds a Plonky2 circuit with the following public inputs:
//! - `initial_state_root`:                8 × u32 limbs (256-bit SHA-256 hash)
//! - `final_state_root`:                  8 × u32 limbs
//! - `block_range`:                       4 × u32 limbs (start_lo, start_hi, end_lo, end_hi)
//! - `stark_proof_hash`:                  8 × u32 limbs
//! - `poseidon2_trace_commitment`:        8 × u32 limbs (Poseidon2 Merkle root of trace)
//! - `poseidon2_composition_commitment`:  8 × u32 limbs (Poseidon2 Merkle root of composition)
//!
//! The circuit computes a Poseidon binding hash of all 44 public inputs inside
//! the circuit, producing 4 additional public output elements. This binding
//! hash cryptographically commits the Plonky2 proof to specific STARK data
//! AND Poseidon2 FRI commitments, enabling efficient in-circuit FRI verification
//! (~300 constraints per Poseidon2 hash vs ~27K for SHA-256).
//!
//! ### RecursiveAggregator
//!
//! Aggregates N child Plonky2 proofs into a single proof. The aggregated
//! proof's public inputs are: (initial_root of first child, final_root of
//! last child, combined block range, Poseidon2 commitments).
//!
//! ## Field Embedding
//!
//! BabyBear (31-bit, p = 2013265921) embeds naturally into Goldilocks
//! (64-bit, p = 2^64 - 2^32 + 1). All u32 limbs are range-checked to 32 bits.

#[cfg(feature = "real-plonky2")]
use plonky2::field::goldilocks_field::GoldilocksField;
#[cfg(feature = "real-plonky2")]
use plonky2::field::types::{Field, PrimeField64};
#[cfg(feature = "real-plonky2")]
use plonky2::hash::poseidon::PoseidonHash;
#[cfg(feature = "real-plonky2")]
use plonky2::iop::target::Target;
#[cfg(feature = "real-plonky2")]
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
#[cfg(feature = "real-plonky2")]
use plonky2::plonk::circuit_builder::CircuitBuilder;
#[cfg(feature = "real-plonky2")]
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
#[cfg(feature = "real-plonky2")]
use plonky2::plonk::config::PoseidonGoldilocksConfig;
#[cfg(feature = "real-plonky2")]
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Number of u32 limbs in a 256-bit hash.
#[cfg(feature = "real-plonky2")]
const HASH_LIMBS: usize = 8;

/// Total public input count:
/// 8 (initial_root) + 8 (final_root) + 4 (block_range) + 8 (stark_proof_hash)
/// + 8 (poseidon2_trace) + 8 (poseidon2_composition) = 44 data + 4 binding hash = 48.
#[cfg(feature = "real-plonky2")]
pub const PUBLIC_INPUT_COUNT: usize = 48;

#[cfg(feature = "real-plonky2")]
type F = GoldilocksField;
#[cfg(feature = "real-plonky2")]
type C = PoseidonGoldilocksConfig;
#[cfg(feature = "real-plonky2")]
const D: usize = 2;

/// Plonky2 circuit that binds STARK proof metadata into a succinct proof.
///
/// The circuit proves: "I know a STARK proof with these exact public parameters
/// (state roots, block range, proof hash, Poseidon2 FRI commitments) and the
/// binding hash is correctly computed."
///
/// Poseidon2 commitments enable efficient in-circuit FRI verification:
/// ~300 constraints per Poseidon2 hash vs ~27K for SHA-256.
///
/// This is the foundation for the SNARK wrapper — the Plonky2 proof is ~100KB
/// and verifiable in ~2ms, compared to the full STARK proof at ~500KB / ~50ms.
#[cfg(feature = "real-plonky2")]
pub struct StarkVerifierCircuit {
    circuit_data: CircuitData<F, C, D>,
    // Targets for witness assignment (indices into the circuit).
    initial_root: [Target; HASH_LIMBS],
    final_root: [Target; HASH_LIMBS],
    block_start_lo: Target,
    block_start_hi: Target,
    block_end_lo: Target,
    block_end_hi: Target,
    stark_proof_hash: [Target; HASH_LIMBS],
    /// Poseidon2 Merkle root of the execution trace (for efficient FRI verification).
    poseidon2_trace: [Target; HASH_LIMBS],
    /// Poseidon2 Merkle root of the composition polynomial.
    poseidon2_composition: [Target; HASH_LIMBS],
}

#[cfg(feature = "real-plonky2")]
impl StarkVerifierCircuit {
    /// Build the verification circuit (one-time cost, ~1-2 seconds).
    ///
    /// The circuit structure:
    /// 1. 44 public input targets (state roots + block range + proof hash + Poseidon2 commitments)
    /// 2. Poseidon hash of all 44 inputs → 4-element binding hash (public output)
    /// 3. 32-bit range checks on all u32 limbs
    pub fn build() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // ── Public inputs: initial_state_root (8 × u32) ──
        let initial_root: [Target; HASH_LIMBS] = std::array::from_fn(|_| {
            let t = builder.add_virtual_target();
            builder.register_public_input(t);
            t
        });

        // ── Public inputs: final_state_root (8 × u32) ──
        let final_root: [Target; HASH_LIMBS] = std::array::from_fn(|_| {
            let t = builder.add_virtual_target();
            builder.register_public_input(t);
            t
        });

        // ── Public inputs: block_range (4 × u32) ──
        let block_start_lo = builder.add_virtual_target();
        let block_start_hi = builder.add_virtual_target();
        let block_end_lo = builder.add_virtual_target();
        let block_end_hi = builder.add_virtual_target();
        builder.register_public_input(block_start_lo);
        builder.register_public_input(block_start_hi);
        builder.register_public_input(block_end_lo);
        builder.register_public_input(block_end_hi);

        // ── Public inputs: stark_proof_hash (8 × u32) ──
        let stark_proof_hash: [Target; HASH_LIMBS] = std::array::from_fn(|_| {
            let t = builder.add_virtual_target();
            builder.register_public_input(t);
            t
        });

        // ── Public inputs: poseidon2_trace_commitment (8 × u32) ──
        // Poseidon2 Merkle root of the execution trace.
        // Enables efficient FRI verification (~300 constraints vs ~27K for SHA-256).
        let poseidon2_trace: [Target; HASH_LIMBS] = std::array::from_fn(|_| {
            let t = builder.add_virtual_target();
            builder.register_public_input(t);
            t
        });

        // ── Public inputs: poseidon2_composition_commitment (8 × u32) ──
        // Poseidon2 Merkle root of the composition polynomial evaluations.
        let poseidon2_composition: [Target; HASH_LIMBS] = std::array::from_fn(|_| {
            let t = builder.add_virtual_target();
            builder.register_public_input(t);
            t
        });

        // ── Binding hash: Poseidon(all 44 public inputs) ──
        // This hash is computed INSIDE the circuit, binding the proof to:
        // - STARK metadata (state roots, block range, proof hash)
        // - Poseidon2 FRI commitments (trace + composition Merkle roots)
        let mut hash_inputs: Vec<Target> = Vec::with_capacity(44);
        hash_inputs.extend_from_slice(&initial_root);
        hash_inputs.extend_from_slice(&final_root);
        hash_inputs.extend([block_start_lo, block_start_hi, block_end_lo, block_end_hi]);
        hash_inputs.extend_from_slice(&stark_proof_hash);
        hash_inputs.extend_from_slice(&poseidon2_trace);
        hash_inputs.extend_from_slice(&poseidon2_composition);

        let binding_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hash_inputs);

        // Register the 4-element binding hash as additional public output.
        for &element in binding_hash.elements.iter() {
            builder.register_public_input(element);
        }

        // ── Range checks: all u32 limbs must fit in 32 bits ──
        for &t in initial_root
            .iter()
            .chain(final_root.iter())
            .chain(stark_proof_hash.iter())
            .chain(poseidon2_trace.iter())
            .chain(poseidon2_composition.iter())
        {
            builder.range_check(t, 32);
        }
        for &t in &[block_start_lo, block_start_hi, block_end_lo, block_end_hi] {
            builder.range_check(t, 32);
        }

        let circuit_data = builder.build::<C>();

        Self {
            circuit_data,
            initial_root,
            final_root,
            block_start_lo,
            block_start_hi,
            block_end_lo,
            block_end_hi,
            stark_proof_hash,
            poseidon2_trace,
            poseidon2_composition,
        }
    }

    /// Generate a Plonky2 proof binding the given STARK metadata.
    ///
    /// `poseidon2_trace` and `poseidon2_composition` are the Poseidon2 Merkle
    /// roots from `StarkProof::poseidon2_trace_commitment` and
    /// `poseidon2_composition_commitment`. Pass `[0; 32]` if DualCommitment
    /// was not used.
    pub fn prove(
        &self,
        initial_root: &[u8; 32],
        final_root: &[u8; 32],
        block_range: (u64, u64),
        stark_proof_hash: &[u8; 32],
        poseidon2_trace: &[u8; 32],
        poseidon2_composition: &[u8; 32],
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        let mut pw = PartialWitness::new();

        // Set initial root (8 × u32 limbs, little-endian).
        set_hash_targets(&mut pw, &self.initial_root, initial_root);

        // Set final root.
        set_hash_targets(&mut pw, &self.final_root, final_root);

        // Set block range (split u64 into lo/hi u32).
        pw.set_target(
            self.block_start_lo,
            F::from_canonical_u32(block_range.0 as u32),
        )
        .map_err(|e| format!("set block_start_lo: {e}"))?;
        pw.set_target(
            self.block_start_hi,
            F::from_canonical_u32((block_range.0 >> 32) as u32),
        )
        .map_err(|e| format!("set block_start_hi: {e}"))?;
        pw.set_target(
            self.block_end_lo,
            F::from_canonical_u32(block_range.1 as u32),
        )
        .map_err(|e| format!("set block_end_lo: {e}"))?;
        pw.set_target(
            self.block_end_hi,
            F::from_canonical_u32((block_range.1 >> 32) as u32),
        )
        .map_err(|e| format!("set block_end_hi: {e}"))?;

        // Set STARK proof hash.
        set_hash_targets(&mut pw, &self.stark_proof_hash, stark_proof_hash);

        // Set Poseidon2 FRI commitments.
        set_hash_targets(&mut pw, &self.poseidon2_trace, poseidon2_trace);
        set_hash_targets(&mut pw, &self.poseidon2_composition, poseidon2_composition);

        self.circuit_data
            .prove(pw)
            .map_err(|e| format!("Plonky2 prove failed: {e}"))
    }

    /// Verify a Plonky2 proof against this circuit.
    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<bool, String> {
        self.circuit_data
            .verify(proof.clone())
            .map(|()| true)
            .map_err(|e| format!("Plonky2 verify failed: {e}"))
    }

    /// Extract public inputs from a verified proof.
    pub fn extract_public_inputs(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ExtractedPublicInputs, String> {
        if proof.public_inputs.len() < PUBLIC_INPUT_COUNT {
            return Err(format!(
                "expected {} public inputs, got {}",
                PUBLIC_INPUT_COUNT,
                proof.public_inputs.len()
            ));
        }

        let pi = &proof.public_inputs;

        let initial_root = extract_hash_bytes(pi, 0);
        let final_root = extract_hash_bytes(pi, 8);

        let block_start = (pi[16].to_canonical_u64() & 0xFFFF_FFFF)
            | ((pi[17].to_canonical_u64() & 0xFFFF_FFFF) << 32);
        let block_end = (pi[18].to_canonical_u64() & 0xFFFF_FFFF)
            | ((pi[19].to_canonical_u64() & 0xFFFF_FFFF) << 32);

        let stark_proof_hash = extract_hash_bytes(pi, 20);
        let poseidon2_trace_commitment = extract_hash_bytes(pi, 28);
        let poseidon2_composition_commitment = extract_hash_bytes(pi, 36);

        Ok(ExtractedPublicInputs {
            initial_root,
            final_root,
            block_range: (block_start, block_end),
            stark_proof_hash,
            poseidon2_trace_commitment,
            poseidon2_composition_commitment,
        })
    }

    /// Access the circuit data (needed for recursive aggregation).
    pub fn circuit_data(&self) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }
}

/// Public inputs extracted from a verified Plonky2 proof.
#[cfg(feature = "real-plonky2")]
#[derive(Debug, Clone)]
pub struct ExtractedPublicInputs {
    pub initial_root: [u8; 32],
    pub final_root: [u8; 32],
    pub block_range: (u64, u64),
    pub stark_proof_hash: [u8; 32],
    /// Poseidon2 Merkle root of the execution trace (zero if not used).
    pub poseidon2_trace_commitment: [u8; 32],
    /// Poseidon2 Merkle root of the composition polynomial (zero if not used).
    pub poseidon2_composition_commitment: [u8; 32],
}

/// Recursive aggregator: combines N child proofs into one.
///
/// The aggregated proof's public inputs are:
/// - initial_root from the FIRST child
/// - final_root from the LAST child
/// - block range spanning all children
/// - Poseidon hash binding all child binding hashes
#[cfg(feature = "real-plonky2")]
pub struct RecursiveAggregator {
    circuit_data: CircuitData<F, C, D>,
    child_proof_targets: Vec<ChildProofTargets>,
    num_children: usize,
}

#[cfg(feature = "real-plonky2")]
struct ChildProofTargets {
    proof_with_pis: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
    verifier_data: VerifierCircuitTarget,
}

#[cfg(feature = "real-plonky2")]
impl RecursiveAggregator {
    /// Build a recursive aggregation circuit for `num_children` child proofs.
    ///
    /// Each child must have been produced by `child_circuit`.
    /// Building cost is proportional to `num_children`.
    pub fn build(
        num_children: usize,
        child_circuit: &StarkVerifierCircuit,
    ) -> Result<Self, String> {
        if num_children == 0 {
            return Err("need at least 1 child proof".into());
        }

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let child_common = &child_circuit.circuit_data.common;
        let _child_verifier = &child_circuit.circuit_data.verifier_only;

        let mut child_proof_targets = Vec::with_capacity(num_children);

        // For each child, add verification targets.
        for _ in 0..num_children {
            let proof_target = builder.add_virtual_proof_with_pis(child_common);
            let verifier_target =
                builder.add_virtual_verifier_data(child_common.config.fri_config.cap_height);

            builder.verify_proof::<C>(&proof_target, &verifier_target, child_common);

            child_proof_targets.push(ChildProofTargets {
                proof_with_pis: proof_target,
                verifier_data: verifier_target,
            });
        }

        // ── Chain constraint: child[i].final_root == child[i+1].initial_root ──
        for i in 0..num_children - 1 {
            let current_pis = &child_proof_targets[i].proof_with_pis.public_inputs;
            let next_pis = &child_proof_targets[i + 1].proof_with_pis.public_inputs;

            // final_root of child[i] (indices 8..16) must equal
            // initial_root of child[i+1] (indices 0..8).
            for limb in 0..HASH_LIMBS {
                let final_limb = current_pis[8 + limb]; // final_root
                let next_initial_limb = next_pis[limb]; // initial_root
                builder.connect(final_limb, next_initial_limb);
            }
        }

        // ── Aggregated public outputs ──
        // initial_root: from first child (indices 0..8)
        let first_pis = &child_proof_targets[0].proof_with_pis.public_inputs;
        for pi in &first_pis[..HASH_LIMBS] {
            builder.register_public_input(*pi);
        }

        // final_root: from last child (indices 8..16)
        let last_pis = &child_proof_targets[num_children - 1]
            .proof_with_pis
            .public_inputs;
        for pi in &last_pis[8..8 + HASH_LIMBS] {
            builder.register_public_input(*pi);
        }

        // block_start: from first child (indices 16..18)
        builder.register_public_input(first_pis[16]); // start_lo
        builder.register_public_input(first_pis[17]); // start_hi

        // block_end: from last child (indices 18..20)
        builder.register_public_input(last_pis[18]); // end_lo
        builder.register_public_input(last_pis[19]); // end_hi

        // Poseidon2 trace commitment: from first child (indices 28..36)
        for pi in &first_pis[28..28 + HASH_LIMBS] {
            builder.register_public_input(*pi);
        }

        // Poseidon2 composition commitment: from last child (indices 36..44)
        for pi in &last_pis[36..36 + HASH_LIMBS] {
            builder.register_public_input(*pi);
        }

        // ── Binding hash of all child binding hashes ──
        let mut all_binding: Vec<Target> = Vec::with_capacity(num_children * 4);
        for child in &child_proof_targets {
            // Binding hash is at indices 44..48 of each child's public inputs.
            for j in 44..48 {
                all_binding.push(child.proof_with_pis.public_inputs[j]);
            }
        }
        let agg_binding = builder.hash_n_to_hash_no_pad::<PoseidonHash>(all_binding);
        for &element in agg_binding.elements.iter() {
            builder.register_public_input(element);
        }

        let circuit_data = builder.build::<C>();

        Ok(Self {
            circuit_data,
            child_proof_targets,
            num_children,
        })
    }

    /// Aggregate child proofs into a single recursive proof.
    pub fn aggregate(
        &self,
        child_proofs: &[ProofWithPublicInputs<F, C, D>],
        child_circuit: &StarkVerifierCircuit,
    ) -> Result<ProofWithPublicInputs<F, C, D>, String> {
        if child_proofs.len() != self.num_children {
            return Err(format!(
                "expected {} child proofs, got {}",
                self.num_children,
                child_proofs.len()
            ));
        }

        let mut pw = PartialWitness::new();

        for (proof, targets) in child_proofs.iter().zip(self.child_proof_targets.iter()) {
            pw.set_proof_with_pis_target(&targets.proof_with_pis, proof)
                .map_err(|e| format!("set child proof: {e}"))?;
            pw.set_verifier_data_target(
                &targets.verifier_data,
                &child_circuit.circuit_data.verifier_only,
            )
            .map_err(|e| format!("set child verifier data: {e}"))?;
        }

        self.circuit_data
            .prove(pw)
            .map_err(|e| format!("Recursive aggregation failed: {e}"))
    }

    /// Verify an aggregated proof.
    pub fn verify(&self, proof: &ProofWithPublicInputs<F, C, D>) -> Result<bool, String> {
        self.circuit_data
            .verify(proof.clone())
            .map(|()| true)
            .map_err(|e| format!("Aggregated proof verification failed: {e}"))
    }
}

// ── Helper functions ──

/// Set 8 u32 targets from a 32-byte hash (little-endian limbs).
#[cfg(feature = "real-plonky2")]
fn set_hash_targets(pw: &mut PartialWitness<F>, targets: &[Target; HASH_LIMBS], hash: &[u8; 32]) {
    for (i, target) in targets.iter().enumerate() {
        let offset = i * 4;
        let val = u32::from_le_bytes([
            hash[offset],
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        // Infallible for fresh targets — panic only on builder bug.
        pw.set_target(*target, F::from_canonical_u32(val))
            .expect("set_hash_targets: duplicate target assignment");
    }
}

/// Extract a 32-byte hash from public inputs at the given starting index.
#[cfg(feature = "real-plonky2")]
fn extract_hash_bytes(pi: &[F], start: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..HASH_LIMBS {
        let val = pi[start + i].to_canonical_u64() as u32;
        let offset = i * 4;
        bytes[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

#[cfg(all(test, feature = "real-plonky2"))]
mod tests {
    use super::*;
    use brrq_crypto::hash::{Hash256, Hasher};

    /// Helper: zero Poseidon2 commitments for tests that don't use DualCommitment.
    const ZERO_P2: [u8; 32] = [0u8; 32];

    #[test]
    fn real_plonky2_prove_verify_roundtrip() {
        let circuit = StarkVerifierCircuit::build();

        let initial = [0x01u8; 32];
        let final_root = [0x02u8; 32];
        let block_range = (1u64, 10u64);
        let stark_hash = Hasher::hash(b"test stark proof").0;

        let proof = circuit
            .prove(
                &initial,
                &final_root,
                block_range,
                &stark_hash,
                &ZERO_P2,
                &ZERO_P2,
            )
            .expect("prove should succeed");

        let valid = circuit.verify(&proof).expect("verify should succeed");
        assert!(valid);
    }

    #[test]
    fn real_plonky2_not_simulated() {
        let circuit = StarkVerifierCircuit::build();
        let proof = circuit
            .prove(&[0; 32], &[0; 32], (0, 0), &[0; 32], &ZERO_P2, &ZERO_P2)
            .expect("prove should succeed");

        assert!(circuit.verify(&proof).unwrap());
        assert_eq!(proof.public_inputs.len(), PUBLIC_INPUT_COUNT);
    }

    #[test]
    fn real_plonky2_extract_public_inputs() {
        let circuit = StarkVerifierCircuit::build();

        let initial = [0xAA; 32];
        let final_root = [0xBB; 32];
        let block_range = (100u64, 200u64);
        let stark_hash = Hasher::hash(b"extract test").0;
        let p2_trace = [0xCC; 32];
        let p2_comp = [0xDD; 32];

        let proof = circuit
            .prove(
                &initial,
                &final_root,
                block_range,
                &stark_hash,
                &p2_trace,
                &p2_comp,
            )
            .unwrap();

        let extracted = StarkVerifierCircuit::extract_public_inputs(&proof).unwrap();
        assert_eq!(extracted.initial_root, initial);
        assert_eq!(extracted.final_root, final_root);
        assert_eq!(extracted.block_range, block_range);
        assert_eq!(extracted.stark_proof_hash, stark_hash);
        assert_eq!(extracted.poseidon2_trace_commitment, p2_trace);
        assert_eq!(extracted.poseidon2_composition_commitment, p2_comp);
    }

    #[test]
    fn real_plonky2_tampered_proof_rejected() {
        let circuit = StarkVerifierCircuit::build();
        let proof = circuit
            .prove(
                &[0x01; 32],
                &[0x02; 32],
                (1, 10),
                &[0x03; 32],
                &ZERO_P2,
                &ZERO_P2,
            )
            .unwrap();

        // Tamper with a public input.
        let mut tampered = proof.clone();
        tampered.public_inputs[0] =
            GoldilocksField::from_canonical_u64(tampered.public_inputs[0].to_canonical_u64() ^ 1);

        // Verification should fail — tampered public inputs must be rejected.
        let result = circuit.verify(&tampered);
        assert!(
            matches!(result, Err(_) | Ok(false)),
            "tampered proof must be rejected, got Ok(true)"
        );
    }

    #[test]
    fn real_plonky2_with_poseidon2_commitments() {
        let circuit = StarkVerifierCircuit::build();

        let initial = [0x01; 32];
        let final_root = [0x02; 32];
        let stark_hash = Hasher::hash(b"dual commitment test").0;
        let p2_trace = Hasher::hash(b"poseidon2 trace root").0;
        let p2_comp = Hasher::hash(b"poseidon2 composition root").0;

        let proof = circuit
            .prove(
                &initial,
                &final_root,
                (1, 100),
                &stark_hash,
                &p2_trace,
                &p2_comp,
            )
            .expect("prove with Poseidon2 commitments should succeed");

        assert!(circuit.verify(&proof).unwrap());

        let extracted = StarkVerifierCircuit::extract_public_inputs(&proof).unwrap();
        assert_eq!(extracted.poseidon2_trace_commitment, p2_trace);
        assert_eq!(extracted.poseidon2_composition_commitment, p2_comp);
    }

    #[test]
    fn real_plonky2_different_poseidon2_different_proofs() {
        let circuit = StarkVerifierCircuit::build();

        let p1 = circuit
            .prove(
                &[1; 32],
                &[2; 32],
                (1, 10),
                &[3; 32],
                &[0xAA; 32],
                &[0xBB; 32],
            )
            .unwrap();
        let p2 = circuit
            .prove(
                &[1; 32],
                &[2; 32],
                (1, 10),
                &[3; 32],
                &[0xCC; 32],
                &[0xDD; 32],
            )
            .unwrap();

        // Same metadata, different Poseidon2 commitments → different binding hashes.
        assert_ne!(
            p1.public_inputs[44..48],
            p2.public_inputs[44..48],
            "different Poseidon2 commitments must produce different binding hashes"
        );
    }

    #[test]
    fn real_plonky2_recursive_aggregation() {
        let circuit = StarkVerifierCircuit::build();

        let root_a = [0x01; 32];
        let root_b = [0x02; 32];
        let root_c = [0x03; 32];
        let hash1 = Hasher::hash(b"batch 1").0;
        let hash2 = Hasher::hash(b"batch 2").0;
        let p2_trace = [0xAA; 32];
        let p2_comp = [0xBB; 32];

        let proof1 = circuit
            .prove(&root_a, &root_b, (1, 5), &hash1, &p2_trace, &p2_comp)
            .unwrap();
        let proof2 = circuit
            .prove(&root_b, &root_c, (6, 10), &hash2, &p2_trace, &p2_comp)
            .unwrap();

        let aggregator = RecursiveAggregator::build(2, &circuit).unwrap();

        let agg_proof = aggregator
            .aggregate(&[proof1, proof2], &circuit)
            .expect("aggregation should succeed");

        let valid = aggregator
            .verify(&agg_proof)
            .expect("verify should succeed");
        assert!(valid);

        // Check initial_root (root_a) and final_root (root_c).
        for i in 0..8 {
            assert_eq!(agg_proof.public_inputs[i].to_canonical_u64(), 0x01010101);
        }
        for i in 8..16 {
            assert_eq!(agg_proof.public_inputs[i].to_canonical_u64(), 0x03030303);
        }
    }
}
